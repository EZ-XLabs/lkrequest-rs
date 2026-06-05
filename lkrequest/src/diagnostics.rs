use std::cell::RefCell;
use std::future::Future;
use std::time::Instant;

/// Lightweight per-request diagnostics snapshot.
#[derive(Debug, Clone, Default)]
pub struct RequestDiagnostics {
    /// DNS resolution time in milliseconds, if measured.
    pub dns_ms: Option<u64>,
    /// TCP connect time in milliseconds, if measured.
    pub tcp_ms: Option<u64>,
    /// TLS handshake time in milliseconds, if measured.
    pub tls_ms: Option<u64>,
    /// Time-to-first-byte in milliseconds, if measured.
    pub ttfb_ms: Option<u64>,
    /// Total request wall-clock time in milliseconds.
    pub total_ms: Option<u64>,
    /// Remote peer socket address (`ip:port`) the request connected to.
    pub remote_addr: Option<String>,
    /// Negotiated application protocol (e.g. `"h2"`, `"http/1.1"`, `"h3"`).
    pub protocol: Option<String>,
    /// Negotiated TLS cipher suite name, if available.
    pub cipher_suite: Option<String>,
}

tokio::task_local! {
    static REQUEST_DIAGNOSTICS: RefCell<RequestDiagnostics>;
}

fn with_diagnostics_mut(f: impl FnOnce(&mut RequestDiagnostics)) {
    let _ = REQUEST_DIAGNOSTICS.try_with(|cell| f(&mut cell.borrow_mut()));
}

/// Record DNS resolution time (ms) into the active diagnostics scope (no-op outside one).
pub fn record_dns_ms(ms: u64) {
    with_diagnostics_mut(|diag| diag.dns_ms = Some(ms));
}

/// Record TCP connect time (ms) into the active diagnostics scope (no-op outside one).
pub fn record_tcp_ms(ms: u64) {
    with_diagnostics_mut(|diag| diag.tcp_ms = Some(ms));
}

/// Record TLS handshake time (ms) into the active diagnostics scope (no-op outside one).
pub fn record_tls_ms(ms: u64) {
    with_diagnostics_mut(|diag| diag.tls_ms = Some(ms));
}

/// Record time-to-first-byte (ms); only the first value recorded in a scope is kept.
pub fn record_ttfb_ms(ms: u64) {
    with_diagnostics_mut(|diag| {
        if diag.ttfb_ms.is_none() {
            diag.ttfb_ms = Some(ms);
        }
    });
}

/// Record the remote peer address into the active diagnostics scope (no-op outside one).
pub fn record_remote_addr(addr: impl Into<String>) {
    with_diagnostics_mut(|diag| diag.remote_addr = Some(addr.into()));
}

/// Record the negotiated protocol into the active diagnostics scope (no-op outside one).
pub fn record_protocol(protocol: impl Into<String>) {
    with_diagnostics_mut(|diag| diag.protocol = Some(protocol.into()));
}

/// Record the negotiated cipher suite into the active diagnostics scope (no-op outside one).
pub fn record_cipher_suite(cipher_suite: impl Into<String>) {
    with_diagnostics_mut(|diag| diag.cipher_suite = Some(cipher_suite.into()));
}

/// Run a future with request diagnostics collection enabled.
pub async fn capture_request_diagnostics<Fut, T>(future: Fut) -> (T, RequestDiagnostics)
where
    Fut: Future<Output = T>,
{
    REQUEST_DIAGNOSTICS
        .scope(RefCell::new(RequestDiagnostics::default()), async move {
            let started_at = Instant::now();
            let output = future.await;
            let mut diagnostics = REQUEST_DIAGNOSTICS.with(|cell| cell.borrow().clone());
            diagnostics.total_ms = Some(started_at.elapsed().as_millis() as u64);
            (output, diagnostics)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_diagnostics_is_all_none() {
        let d = RequestDiagnostics::default();
        assert!(d.dns_ms.is_none());
        assert!(d.tcp_ms.is_none());
        assert!(d.tls_ms.is_none());
        assert!(d.ttfb_ms.is_none());
        assert!(d.total_ms.is_none());
        assert!(d.remote_addr.is_none());
        assert!(d.protocol.is_none());
        assert!(d.cipher_suite.is_none());
    }

    #[tokio::test]
    async fn record_outside_scope_is_a_noop_and_does_not_leak() {
        // Outside `capture_request_diagnostics` the task-local is absent, so every
        // recorder must be a silent no-op (exercises the `try_with` Err arm) and
        // must not leak into a later capture scope.
        record_dns_ms(1);
        record_tcp_ms(2);
        record_remote_addr("203.0.113.1:443");
        record_protocol("h2");
        record_cipher_suite("TLS_AES_128_GCM_SHA256");

        let (_, diag) = capture_request_diagnostics(async {
            record_tcp_ms(20); // only this in-scope record should be visible
        })
        .await;

        assert_eq!(diag.dns_ms, None, "out-of-scope dns record must not leak");
        assert_eq!(diag.remote_addr, None);
        assert_eq!(diag.protocol, None);
        assert_eq!(diag.cipher_suite, None);
        assert_eq!(diag.tcp_ms, Some(20));
    }

    #[tokio::test]
    async fn capture_collects_every_recorded_field() {
        let (output, diag) = capture_request_diagnostics(async {
            record_dns_ms(10);
            record_tcp_ms(20);
            record_tls_ms(30);
            record_ttfb_ms(40);
            record_remote_addr("198.51.100.7:443");
            record_protocol("h2");
            record_cipher_suite("TLS_AES_256_GCM_SHA384");
            "done"
        })
        .await;

        assert_eq!(output, "done");
        assert_eq!(diag.dns_ms, Some(10));
        assert_eq!(diag.tcp_ms, Some(20));
        assert_eq!(diag.tls_ms, Some(30));
        assert_eq!(diag.ttfb_ms, Some(40));
        assert_eq!(diag.remote_addr.as_deref(), Some("198.51.100.7:443"));
        assert_eq!(diag.protocol.as_deref(), Some("h2"));
        assert_eq!(diag.cipher_suite.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        // total_ms is always stamped by the harness, independent of recorders.
        assert!(diag.total_ms.is_some());
    }

    #[tokio::test]
    async fn ttfb_records_only_the_first_value() {
        let (_, diag) = capture_request_diagnostics(async {
            record_ttfb_ms(7);
            record_ttfb_ms(99); // must be ignored: TTFB is set once, on first byte
        })
        .await;
        assert_eq!(diag.ttfb_ms, Some(7));
    }
}
