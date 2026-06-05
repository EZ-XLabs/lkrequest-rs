//! Low-overhead operational telemetry: bandwidth, connections, request counts.
//!
//! Feature-gated behind `telemetry`; when the feature is off this module does
//! not exist and the transport carries no instrumentation at all (truly zero
//! cost). The design keeps the **per-I/O hot path free of atomics**:
//!
//! - [`Metered`] wraps a transport stream and accumulates byte counts in plain
//!   per-connection `u64` fields (no atomics, no contention) inside `poll_read`
//!   / `poll_write`. It [`flush`](Metered::flush)es those locals into the
//!   global [`Counters`] only at request/connection boundaries (and on drop).
//! - [`Counters`] holds **sharded, cache-line-padded** atomics so the rare
//!   flushes never contend on a single hot line, even at high QPS.
//! - Reading metrics is pull-only via [`metrics_snapshot`]; it costs nothing in
//!   steady state.
//!
//! Hosts consume the data however they like (Prometheus exporter, OTel, custom)
//! — this module only produces neutral numbers.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Number of counter shards. Power of two so `& (SHARDS - 1)` selects a shard.
const SHARDS: usize = 16;

/// A cache-line-aligned `AtomicU64` to avoid false sharing between shards.
#[repr(align(64))]
#[derive(Default)]
struct Padded(AtomicU64);

fn new_shards() -> [Padded; SHARDS] {
    std::array::from_fn(|_| Padded::default())
}

/// Global, sharded operational counters.
///
/// Cheap to share via [`Arc`]; flushes touch one shard each so concurrent
/// connections rarely hit the same cache line.
pub struct Counters {
    bytes_in: [Padded; SHARDS],
    bytes_out: [Padded; SHARDS],
    requests_total: [Padded; SHARDS],
    requests_failed: [Padded; SHARDS],
    /// Currently-open connections (gauge): `+1` on establish, `-1` on close.
    active_connections: AtomicU64,
    /// Cumulative connections ever opened.
    total_connections: AtomicU64,
    /// Round-robin shard assigner (touched only at connection/request edges).
    next_shard: AtomicUsize,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            bytes_in: new_shards(),
            bytes_out: new_shards(),
            requests_total: new_shards(),
            requests_failed: new_shards(),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            next_shard: AtomicUsize::new(0),
        }
    }
}

impl Counters {
    /// Pick the next shard index, round-robin. Called at connection/request
    /// edges, never per-I/O.
    fn pick_shard(&self) -> usize {
        self.next_shard.fetch_add(1, Relaxed) & (SHARDS - 1)
    }

    /// Record a completed request (and whether it failed). One flush-class op.
    pub fn record_request(&self, failed: bool) {
        let s = self.pick_shard();
        self.requests_total[s].0.fetch_add(1, Relaxed);
        if failed {
            self.requests_failed[s].0.fetch_add(1, Relaxed);
        }
    }

    /// Record a newly established connection (gauge `+1`, cumulative `+1`).
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Relaxed);
        self.total_connections.fetch_add(1, Relaxed);
    }

    /// Record a closed connection (gauge `-1`).
    pub fn connection_closed(&self) {
        // saturating: never wrap below zero if open/close are unbalanced
        let mut cur = self.active_connections.load(Relaxed);
        while cur > 0 {
            match self
                .active_connections
                .compare_exchange_weak(cur, cur - 1, Relaxed, Relaxed)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    fn sum(shards: &[Padded; SHARDS]) -> u64 {
        shards.iter().map(|p| p.0.load(Relaxed)).sum()
    }

    /// Take a consistent-enough snapshot (relaxed reads; for monitoring, not
    /// for exact-at-an-instant accounting).
    ///
    /// Note: bytes still buffered in live [`Metered`] streams that have not yet
    /// flushed are not included until their next flush (request boundary) or
    /// drop.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_in: Self::sum(&self.bytes_in),
            bytes_out: Self::sum(&self.bytes_out),
            requests_total: Self::sum(&self.requests_total),
            requests_failed: Self::sum(&self.requests_failed),
            active_connections: self.active_connections.load(Relaxed),
            total_connections: self.total_connections.load(Relaxed),
        }
    }
}

/// A point-in-time view of the global counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total wire bytes received (incl. TLS/HTTP framing overhead).
    pub bytes_in: u64,
    /// Total wire bytes sent.
    pub bytes_out: u64,
    /// Completed requests.
    pub requests_total: u64,
    /// Completed requests that ended in an error.
    pub requests_failed: u64,
    /// Currently-open transport connections.
    pub active_connections: u64,
    /// Cumulative connections opened.
    pub total_connections: u64,
}

/// Process-global counters, lazily initialized.
fn global() -> &'static Arc<Counters> {
    static GLOBAL: OnceLock<Arc<Counters>> = OnceLock::new();
    GLOBAL.get_or_init(|| Arc::new(Counters::default()))
}

/// Handle to the process-global counters (shareable, cheap to clone).
pub fn counters() -> Arc<Counters> {
    Arc::clone(global())
}

/// Snapshot the process-global counters. Pull-only; near-free.
pub fn metrics_snapshot() -> MetricsSnapshot {
    global().snapshot()
}

// ---------------------------------------------------------------------------
// Metered<S> — per-connection byte counter wrapping a transport stream
// ---------------------------------------------------------------------------

/// Wraps a transport stream and counts wire bytes with **no atomics on the
/// per-I/O path**: `poll_read`/`poll_write` only do a plain `u64 +=` into local
/// fields. The locals are flushed into the sharded global [`Counters`] at
/// request/connection boundaries via [`flush`](Self::flush) and on drop.
pub struct Metered<S> {
    // `Option` so `into_inner` can move the stream out without `unsafe`; the
    // per-I/O branch is predictable and dwarfed by the I/O syscall itself.
    inner: Option<S>,
    local_in: u64,
    local_out: u64,
    sink: Arc<Counters>,
    shard: usize,
}

impl<S> Metered<S> {
    /// Wrap `inner`, routing flushed bytes to `sink` on a round-robin shard.
    pub fn new(inner: S, sink: Arc<Counters>) -> Self {
        let shard = sink.pick_shard();
        Self {
            inner: Some(inner),
            local_in: 0,
            local_out: 0,
            sink,
            shard,
        }
    }

    /// Wrap `inner` using the process-global counters.
    pub fn global(inner: S) -> Self {
        Self::new(inner, counters())
    }

    /// Flush locally-accumulated byte counts into the global counters.
    ///
    /// Call at request boundaries (e.g. connection check-in) for live-ish
    /// aggregate visibility on long-lived multiplexed connections.
    pub fn flush(&mut self) {
        if self.local_in > 0 {
            self.sink.bytes_in[self.shard]
                .0
                .fetch_add(self.local_in, Relaxed);
            self.local_in = 0;
        }
        if self.local_out > 0 {
            self.sink.bytes_out[self.shard]
                .0
                .fetch_add(self.local_out, Relaxed);
            self.local_out = 0;
        }
    }

    /// Flush and return the wrapped stream (e.g. to hand the raw socket to a
    /// WebSocket upgrade).
    pub fn into_inner(mut self) -> S {
        self.flush();
        self.inner.take().expect("Metered inner already taken")
    }

    fn inner_mut(&mut self) -> &mut S {
        self.inner
            .as_mut()
            .expect("Metered polled after into_inner")
    }
}

impl<S> Drop for Metered<S> {
    fn drop(&mut self) {
        self.flush();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(me.inner_mut()).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                me.local_in += (buf.filled().len() - before) as u64; // plain add
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match Pin::new(me.inner_mut()).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                me.local_out += n as u64; // plain add
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(me.inner_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(me.inner_mut()).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn snapshot_sums_shards_and_tracks_gauges() {
        let c = Counters::default();
        // Spread across shards via record_request's round-robin.
        for _ in 0..10 {
            c.record_request(false);
        }
        c.record_request(true);
        c.connection_opened();
        c.connection_opened();
        c.connection_closed();

        let s = c.snapshot();
        assert_eq!(s.requests_total, 11);
        assert_eq!(s.requests_failed, 1);
        assert_eq!(s.active_connections, 1);
        assert_eq!(s.total_connections, 2);
    }

    #[test]
    fn connection_closed_saturates_at_zero() {
        let c = Counters::default();
        c.connection_closed(); // underflow guard: stays at 0
        c.connection_closed();
        assert_eq!(c.snapshot().active_connections, 0);
        c.connection_opened();
        assert_eq!(c.snapshot().active_connections, 1);
    }

    #[tokio::test]
    async fn metered_counts_wire_bytes_after_flush() {
        let sink = Arc::new(Counters::default());
        let (a, mut b) = tokio::io::duplex(64);
        let mut metered = Metered::new(a, Arc::clone(&sink));

        // write 5 bytes through the metered side
        metered.write_all(b"hello").await.unwrap();
        // read 3 bytes that the peer sends
        b.write_all(b"hey").await.unwrap();
        let mut buf = [0u8; 3];
        metered.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hey");

        // Local counts not yet visible globally.
        assert_eq!(sink.snapshot().bytes_out, 0);
        assert_eq!(sink.snapshot().bytes_in, 0);

        metered.flush();
        let s = sink.snapshot();
        assert_eq!(s.bytes_out, 5);
        assert_eq!(s.bytes_in, 3);
    }

    #[tokio::test]
    async fn drop_flushes_remaining_bytes() {
        let sink = Arc::new(Counters::default());
        let (a, mut b) = tokio::io::duplex(64);
        {
            let mut metered = Metered::new(a, Arc::clone(&sink));
            metered.write_all(b"abcd").await.unwrap();
            // no explicit flush; drop should flush
        }
        assert_eq!(sink.snapshot().bytes_out, 4);
        let _ = &mut b; // keep peer alive until here
    }

    #[tokio::test]
    async fn into_inner_flushes_and_returns_stream() {
        let sink = Arc::new(Counters::default());
        let (a, mut b) = tokio::io::duplex(64);
        let mut metered = Metered::new(a, Arc::clone(&sink));
        metered.write_all(b"xyz").await.unwrap();

        let mut inner = metered.into_inner(); // flushes
        assert_eq!(sink.snapshot().bytes_out, 3);

        // the returned raw stream still works
        inner.write_all(b"!").await.unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"xyz!");
    }
}
