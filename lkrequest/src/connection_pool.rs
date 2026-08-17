//! Connection pool — manages reusable connections per Session.
//!
//! Each [`Session`](crate::session::Session) owns an independent connection pool.
//! Connections are keyed by `(scheme, host, port, route)` and are **never
//! shared** between Sessions.
//!
//! - **HTTP/2**: Connections support multiplexing — multiple tasks share one
//!   connection via `lkh2::H2Sender::clone()`.
//! - **HTTP/1.1**: Connections are exclusive — borrowed from the pool, used,
//!   then returned. Uses hyper's `SendRequest` with keep-alive.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use http_body_util::Full;

use crate::protocol::RouteKey;

/// Key that identifies a group of reusable connections.
///
/// Uses `Arc<str>` for the host to make `clone()` O(1) — connection keys
/// are cloned frequently during pool insert/lookup operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub scheme: Scheme,
    pub host: Arc<str>,
    pub port: u16,
    pub route: RouteKey,
}

/// HTTP scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

/// Reservation for one physical connection owned by a Session.
///
/// The reservation is acquired before dialing and released automatically when
/// connection establishment fails or the physical connection is discarded.
pub(crate) struct ConnectionPermit {
    in_use: Arc<AtomicUsize>,
}

/// Cloneable handle used by a dial attempt to reserve a temporary physical
/// connection slot without evicting an existing pooled connection.
#[derive(Clone)]
pub(crate) struct ConnectionBudget {
    in_use: Arc<AtomicUsize>,
    max_total: usize,
}

impl ConnectionBudget {
    pub(crate) fn try_reserve_speculative(&self) -> Option<ConnectionPermit> {
        try_reserve_counter(&self.in_use, self.max_total)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

struct AbortTaskOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortTaskOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn track_connection_task<T: Send + 'static>(
    task: tokio::task::JoinHandle<T>,
    permit: ConnectionPermit,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _permit = permit;
        let mut task = AbortTaskOnDrop(task);
        let _ = (&mut task.0).await;
    })
}

#[cfg(feature = "quic-h3")]
fn track_shared_h3_task(
    task: Arc<tokio::task::JoinHandle<Result<(), lkh3::H3Error>>>,
    permit: ConnectionPermit,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _permit = permit;
        while !task.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
}

#[cfg(feature = "quic-h3")]
enum H3DriverTask {
    Tracked(Arc<tokio::task::JoinHandle<()>>),
    Legacy {
        task: Arc<tokio::task::JoinHandle<Result<(), lkh3::H3Error>>>,
        permit_task: Arc<tokio::task::JoinHandle<()>>,
    },
}

#[cfg(feature = "quic-h3")]
impl H3DriverTask {
    fn is_finished(&self) -> bool {
        match self {
            Self::Tracked(task) => task.is_finished(),
            Self::Legacy { task, .. } => task.is_finished(),
        }
    }

    fn abort(&self) {
        match self {
            Self::Tracked(task) => task.abort(),
            Self::Legacy { task, permit_task } => {
                task.abort();
                permit_task.abort();
            }
        }
    }
}

struct LegacyH1Permit {
    task: Weak<tokio::task::JoinHandle<()>>,
    permit: ConnectionPermit,
}

/// A pooled connection returned by the deprecated low-level pool API.
pub enum PooledConnection {
    H2(lkh2::H2Sender),
    #[cfg(feature = "quic-h3")]
    H3(lkh3::H3Sender),
    H1 {
        sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: Arc<tokio::task::JoinHandle<()>>,
    },
}

/// Internal pooled connection carrying the physical-connection reservation.
pub(crate) enum AcquiredConnection {
    /// An HTTP/2 sender — the pool retains its own clone.
    H2(lkh2::H2Sender),
    /// An HTTP/3 sender — the pool retains its own clone.
    #[cfg(feature = "quic-h3")]
    H3(lkh3::H3Sender),
    /// An HTTP/1.1 sender — exclusively borrowed from the pool.
    /// The `Arc<JoinHandle>` keeps the connection driver alive.
    H1 {
        sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: Arc<tokio::task::JoinHandle<()>>,
        permit: ConnectionPermit,
    },
}

/// The connection pool for a single Session.
///
/// Protected by a `Mutex` in `SessionInner`; lock hold time is always
/// sub-microsecond (lookup / insert / remove only).
pub struct ConnectionPool {
    /// Permits held while deprecated callers have an H1 connection checked out.
    legacy_h1_permits: HashMap<usize, LegacyH1Permit>,
    /// Pool of active H2 connections, keyed by origin + proxy.
    h2_connections: HashMap<ConnectionKey, H2PoolEntry>,
    /// Pool of active H3 connections, keyed by origin + proxy.
    #[cfg(feature = "quic-h3")]
    h3_connections: HashMap<ConnectionKey, H3PoolEntry>,
    /// Pool of idle H1.1 connections, keyed by origin + proxy.
    /// Unlike H2 (multiplexed), H1.1 connections are exclusive.
    /// Multiple idle connections per key are supported.
    h1_connections: HashMap<ConnectionKey, VecDeque<H1PoolEntry>>,
    /// Maximum total connections per key (idle + active).
    pub max_per_key: usize,
    /// Maximum total physical connections across all keys (hard upper limit).
    pub max_total: usize,
    /// Number of physical connections currently connecting, active, or idle.
    connections_in_use: Arc<AtomicUsize>,
    /// Maximum time a connection can be idle before eviction (default: 300s).
    pub idle_timeout: Duration,
}

/// An HTTP/2 pool entry — holds a clonable sender for multiplexing.
pub struct H2PoolEntry {
    /// The send half of the H2 connection. `Clone + Send`.
    sender: lkh2::H2Sender,
    /// The connection driver task handle.
    /// Kept alive so the connection isn't dropped.
    _conn_task: Arc<tokio::task::JoinHandle<()>>,
    /// When this connection was last used (for idle eviction).
    last_used: Instant,
}

/// An HTTP/3 pool entry — holds a clonable sender for multiplexing.
///
/// The `_driver_task` field is symmetric with `H2PoolEntry::_conn_task`:
/// it keeps a handle to the background H3 driver so [`ConnectionPool::clear`]
/// can abort it deterministically rather than leak a detached tokio task.
#[cfg(feature = "quic-h3")]
pub struct H3PoolEntry {
    sender: lkh3::H3Sender,
    _driver_task: H3DriverTask,
    last_used: Instant,
}

/// An HTTP/1.1 pool entry — holds an exclusive sender for keep-alive reuse.
pub struct H1PoolEntry {
    /// The send half of the HTTP/1.1 connection. NOT Clone — exclusive access.
    sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
    /// The connection driver task handle.
    /// Kept alive so the connection isn't dropped.
    conn_task: Arc<tokio::task::JoinHandle<()>>,
    /// Reservation held while this H1 connection is idle in the pool.
    permit: ConnectionPermit,
    /// When this connection was last used (for idle eviction).
    last_used: Instant,
}

impl ConnectionPool {
    /// Create a new empty connection pool.
    pub fn new() -> Self {
        Self {
            legacy_h1_permits: HashMap::new(),
            h2_connections: HashMap::new(),
            #[cfg(feature = "quic-h3")]
            h3_connections: HashMap::new(),
            h1_connections: HashMap::new(),
            max_per_key: 16,
            max_total: 64,
            connections_in_use: Arc::new(AtomicUsize::new(0)),
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Create a new connection pool with a custom total connection limit.
    pub fn with_max_total(max_total: usize) -> Self {
        Self {
            legacy_h1_permits: HashMap::new(),
            h2_connections: HashMap::new(),
            #[cfg(feature = "quic-h3")]
            h3_connections: HashMap::new(),
            h1_connections: HashMap::new(),
            max_per_key: 16,
            max_total,
            connections_in_use: Arc::new(AtomicUsize::new(0)),
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Reserve one physical connection slot before dialing.
    ///
    /// If the hard limit is reached, one idle H1 connection is evicted before
    /// returning failure so an unrelated origin is not blocked by idle state.
    pub(crate) fn try_reserve_connection(&mut self) -> Option<ConnectionPermit> {
        self.evict_closed();
        if let Some(permit) = self.try_reserve_without_eviction() {
            return Some(permit);
        }

        if self.evict_one_idle_h1() {
            return self.try_reserve_without_eviction();
        }

        None
    }

    fn try_reserve_without_eviction(&self) -> Option<ConnectionPermit> {
        try_reserve_counter(&self.connections_in_use, self.max_total)
    }

    fn adopt_existing_connection(&self) -> ConnectionPermit {
        self.connections_in_use.fetch_add(1, Ordering::AcqRel);
        ConnectionPermit {
            in_use: Arc::clone(&self.connections_in_use),
        }
    }

    pub(crate) fn connection_budget(&self) -> ConnectionBudget {
        ConnectionBudget {
            in_use: Arc::clone(&self.connections_in_use),
            max_total: self.max_total,
        }
    }

    fn evict_closed(&mut self) {
        self.legacy_h1_permits.retain(|_, tracked| {
            tracked
                .task
                .upgrade()
                .is_some_and(|task| !task.is_finished())
        });
        self.h2_connections
            .retain(|_, entry| !entry._conn_task.is_finished());
        #[cfg(feature = "quic-h3")]
        self.h3_connections
            .retain(|_, entry| !entry._driver_task.is_finished());
        self.h1_connections.retain(|_, entries| {
            entries.retain(|entry| !entry.conn_task.is_finished());
            !entries.is_empty()
        });
    }

    fn evict_one_idle_h1(&mut self) -> bool {
        let oldest_key = self
            .h1_connections
            .iter()
            .filter_map(|(key, entries)| {
                entries.front().map(|entry| (key.clone(), entry.last_used))
            })
            .min_by_key(|(_, last_used)| *last_used)
            .map(|(key, _)| key);

        let Some(key) = oldest_key else {
            return false;
        };

        let mut remove_key = false;
        let evicted = if let Some(entries) = self.h1_connections.get_mut(&key) {
            let entry = entries.pop_front();
            remove_key = entries.is_empty();
            entry
        } else {
            None
        };
        if remove_key {
            self.h1_connections.remove(&key);
        }
        if let Some(entry) = evicted {
            entry.conn_task.abort();
            drop(entry);
            true
        } else {
            false
        }
    }

    /// Returns `true` if the physical connection budget is exhausted.
    pub fn is_at_capacity(&self) -> bool {
        self.connections_in_use.load(Ordering::Acquire) >= self.max_total
    }

    // -----------------------------------------------------------------------
    // Protocol-agnostic API
    // -----------------------------------------------------------------------

    fn has_h2_connection_inner(&self, key: &ConnectionKey) -> bool {
        self.h2_connections.contains_key(key)
    }

    fn has_h3_connection_inner(&self, key: &ConnectionKey) -> bool {
        #[cfg(feature = "quic-h3")]
        {
            self.h3_connections.contains_key(key)
        }
        #[cfg(not(feature = "quic-h3"))]
        {
            let _ = key;
            false
        }
    }

    fn has_h1_connection_inner(&self, key: &ConnectionKey) -> bool {
        self.h1_connections
            .get(key)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Check whether a usable H2 connection exists for the given key,
    /// without removing it from the pool.
    pub fn has_h2_connection(&mut self, key: &ConnectionKey) -> bool {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        self.has_h2_connection_inner(key)
    }

    /// Check whether a usable H3 connection exists for the given key,
    /// without removing it from the pool.
    pub fn has_h3_connection(&mut self, key: &ConnectionKey) -> bool {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        self.has_h3_connection_inner(key)
    }

    /// Check whether a usable H1 connection exists for the given key,
    /// without removing it from the pool.
    pub fn has_h1_connection(&mut self, key: &ConnectionKey) -> bool {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        self.has_h1_connection_inner(key)
    }

    /// Check whether a usable connection exists for the given key,
    /// **without** removing it from the pool.
    ///
    /// For H2 this is a cheap clone-based peek; for H1 it checks the deque
    /// without popping. Opportunistically evicts idle connections first.
    pub fn has_connection(&mut self, key: &ConnectionKey) -> bool {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        self.has_h2_connection_inner(key)
            || self.has_h1_connection_inner(key)
            || self.has_h3_connection_inner(key)
    }

    pub(crate) fn try_acquire_internal(
        &mut self,
        key: &ConnectionKey,
    ) -> Option<AcquiredConnection> {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);

        #[cfg(feature = "quic-h3")]
        if let Some(h3) = self.try_acquire_h3_pooled_internal(key) {
            return Some(h3);
        }
        if let Some(h2) = self.try_acquire_h2_pooled_internal(key) {
            return Some(h2);
        }
        self.try_acquire_h1_pooled_internal(key)
    }

    pub(crate) fn try_acquire_h3_pooled_internal(
        &mut self,
        key: &ConnectionKey,
    ) -> Option<AcquiredConnection> {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        #[cfg(feature = "quic-h3")]
        {
            self.try_acquire_h3(key).map(AcquiredConnection::H3)
        }
        #[cfg(not(feature = "quic-h3"))]
        {
            let _ = key;
            None
        }
    }

    pub(crate) fn try_acquire_h2_pooled_internal(
        &mut self,
        key: &ConnectionKey,
    ) -> Option<AcquiredConnection> {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        self.try_acquire_h2(key).map(AcquiredConnection::H2)
    }

    pub(crate) fn try_acquire_h1_pooled_internal(
        &mut self,
        key: &ConnectionKey,
    ) -> Option<AcquiredConnection> {
        let timeout = self.idle_timeout;
        self.evict_idle(timeout);
        self.try_acquire_h1(key).map(|h1| AcquiredConnection::H1 {
            sender: h1.sender,
            conn_task: h1.conn_task,
            permit: h1.permit,
        })
    }

    fn convert_legacy_connection(&mut self, connection: AcquiredConnection) -> PooledConnection {
        match connection {
            AcquiredConnection::H2(sender) => PooledConnection::H2(sender),
            #[cfg(feature = "quic-h3")]
            AcquiredConnection::H3(sender) => PooledConnection::H3(sender),
            AcquiredConnection::H1 {
                sender,
                conn_task,
                permit,
            } => {
                let task_key = Arc::as_ptr(&conn_task) as usize;
                let previous = self.legacy_h1_permits.insert(
                    task_key,
                    LegacyH1Permit {
                        task: Arc::downgrade(&conn_task),
                        permit,
                    },
                );
                debug_assert!(previous.is_none());
                PooledConnection::H1 { sender, conn_task }
            }
        }
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool acquisition will be removed in 0.3.0"
    )]
    pub fn try_acquire(&mut self, key: &ConnectionKey) -> Option<PooledConnection> {
        let connection = self.try_acquire_internal(key)?;
        Some(self.convert_legacy_connection(connection))
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool acquisition will be removed in 0.3.0"
    )]
    pub fn try_acquire_h3_pooled(&mut self, key: &ConnectionKey) -> Option<PooledConnection> {
        let connection = self.try_acquire_h3_pooled_internal(key)?;
        Some(self.convert_legacy_connection(connection))
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool acquisition will be removed in 0.3.0"
    )]
    pub fn try_acquire_h2_pooled(&mut self, key: &ConnectionKey) -> Option<PooledConnection> {
        let connection = self.try_acquire_h2_pooled_internal(key)?;
        Some(self.convert_legacy_connection(connection))
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool acquisition will be removed in 0.3.0"
    )]
    pub fn try_acquire_h1_pooled(&mut self, key: &ConnectionKey) -> Option<PooledConnection> {
        let connection = self.try_acquire_h1_pooled_internal(key)?;
        Some(self.convert_legacy_connection(connection))
    }

    /// Remove all connections (both H2 and H1.1) for the given key.
    pub fn remove(&mut self, key: &ConnectionKey) {
        #[cfg(feature = "quic-h3")]
        self.h3_connections.remove(key);
        self.h2_connections.remove(key);
        self.h1_connections.remove(key);
    }

    // -----------------------------------------------------------------------
    // HTTP/3 API
    // -----------------------------------------------------------------------

    #[cfg(feature = "quic-h3")]
    pub fn try_acquire_h3(&mut self, key: &ConnectionKey) -> Option<lkh3::H3Sender> {
        self.h3_connections.get_mut(key).map(|entry| {
            entry.last_used = Instant::now();
            entry.sender.clone()
        })
    }

    /// Pool an HTTP/3 connection.
    ///
    /// Callers must pass the driver's [`tokio::task::JoinHandle`] so the pool
    /// retains ownership of the background task. Dropping a `JoinHandle`
    /// detaches the task in tokio — it does NOT abort it — so without this
    /// handle a pool `clear()` would silently leak driver tasks that
    /// continue consuming QUIC events until idle timeout. Use
    /// [`lkh3::H3Connection::into_parts`] to split a freshly built
    /// connection into `(sender, driver)`.
    #[cfg(feature = "quic-h3")]
    pub(crate) fn insert_h3_reserved(
        &mut self,
        key: ConnectionKey,
        sender: lkh3::H3Sender,
        driver: tokio::task::JoinHandle<Result<(), lkh3::H3Error>>,
        permit: ConnectionPermit,
    ) {
        // Insert-if-absent. H3 is muxed, so the invariant is one pooled
        // connection per key. A lost establishment race (two callers both
        // missed the acquire before either pooled) must NOT clobber the
        // already-pooled connection: overwriting detaches its driver task while
        // in-flight streams may still depend on it, and transiently inflates the
        // pool count. The stale-connection replace path removes the dead entry
        // first (see the connection-closed handling in transport/streaming), so
        // a present entry here is always a live one worth keeping. The losing
        // connection is aborted so it cannot outlive the reservation that is
        // released when this function returns.
        if self.h3_connections.contains_key(&key) {
            driver.abort();
            return;
        }
        let driver = Arc::new(track_connection_task(driver, permit));
        self.h3_connections.insert(
            key,
            H3PoolEntry {
                sender,
                _driver_task: H3DriverTask::Tracked(driver),
                last_used: Instant::now(),
            },
        );
    }

    #[cfg(feature = "quic-h3")]
    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool mutation will be removed in 0.3.0"
    )]
    pub fn insert_h3(
        &mut self,
        key: ConnectionKey,
        sender: lkh3::H3Sender,
        driver: Arc<tokio::task::JoinHandle<Result<(), lkh3::H3Error>>>,
    ) {
        let permit = self.adopt_existing_connection();
        if self.h3_connections.contains_key(&key) {
            drop(track_shared_h3_task(driver, permit));
            return;
        }
        let permit_task = Arc::new(track_shared_h3_task(Arc::clone(&driver), permit));
        self.h3_connections.insert(
            key,
            H3PoolEntry {
                sender,
                _driver_task: H3DriverTask::Legacy {
                    task: driver,
                    permit_task,
                },
                last_used: Instant::now(),
            },
        );
    }

    // -----------------------------------------------------------------------
    // HTTP/2 API
    // -----------------------------------------------------------------------

    /// Try to acquire an existing H2 connection for the given key.
    ///
    /// Returns a cloned `H2Sender` if a connection exists, or `None`.
    /// The H2 sender is `Clone`, so multiple tasks can use the same connection.
    /// Also updates the `last_used` timestamp.
    pub fn try_acquire_h2(&mut self, key: &ConnectionKey) -> Option<lkh2::H2Sender> {
        self.h2_connections.get_mut(key).map(|entry| {
            entry.last_used = Instant::now();
            entry.sender.clone()
        })
    }

    /// Insert a new H2 connection into the pool.
    ///
    /// Insert-if-absent: see `insert_h3` for the rationale. H2 is
    /// likewise muxed (one pooled connection per key), and the stale-connection
    /// replace path removes the dead entry before re-establishing, so a present
    /// entry is always live and must not be clobbered by a lost race.
    pub(crate) fn insert_h2_reserved(
        &mut self,
        key: ConnectionKey,
        sender: lkh2::H2Sender,
        conn_task: tokio::task::JoinHandle<()>,
        permit: ConnectionPermit,
    ) {
        if self.h2_connections.contains_key(&key) {
            // The first request may already be in flight when another connection wins
            // the pool insertion race. Keep this unpooled driver alive until that
            // request completes; it will exit once its sender is dropped and then
            // release the physical-connection permit.
            drop(track_connection_task(conn_task, permit));
            return;
        }
        self.h2_connections.insert(
            key,
            H2PoolEntry {
                sender,
                _conn_task: Arc::new(track_connection_task(conn_task, permit)),
                last_used: Instant::now(),
            },
        );
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool mutation will be removed in 0.3.0"
    )]
    pub fn insert_h2(
        &mut self,
        key: ConnectionKey,
        sender: lkh2::H2Sender,
        conn_task: tokio::task::JoinHandle<()>,
    ) {
        let permit = self.adopt_existing_connection();
        self.insert_h2_reserved(key, sender, conn_task, permit);
    }

    // -----------------------------------------------------------------------
    // HTTP/1.1 API
    // -----------------------------------------------------------------------

    /// Try to acquire an idle H1.1 connection for the given key.
    ///
    /// Pops the most recently used connection from the stack.
    /// Returns `None` if no idle connections are available.
    pub fn try_acquire_h1(&mut self, key: &ConnectionKey) -> Option<H1PoolEntry> {
        let entries = self.h1_connections.get_mut(key)?;
        let entry = entries.pop_back();
        if entries.is_empty() {
            self.h1_connections.remove(key);
        }
        entry
    }

    /// Return an H1.1 connection to the pool after use.
    ///
    /// The connection will be available for the next request to the same origin.
    /// If the pool already has `max_per_key` connections for this key,
    /// the oldest one is dropped.
    pub(crate) fn return_h1_reserved(
        &mut self,
        key: ConnectionKey,
        sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: Arc<tokio::task::JoinHandle<()>>,
        permit: ConnectionPermit,
    ) {
        let entries = self.h1_connections.entry(key).or_default();
        if entries.len() >= self.max_per_key {
            if let Some(entry) = entries.pop_front() {
                entry.conn_task.abort();
            }
        }
        entries.push_back(H1PoolEntry {
            sender,
            conn_task,
            permit,
            last_used: Instant::now(),
        });
    }

    /// Insert a brand new H1.1 connection into the pool.
    pub(crate) fn insert_h1_reserved(
        &mut self,
        key: ConnectionKey,
        sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: tokio::task::JoinHandle<()>,
        permit: ConnectionPermit,
    ) {
        let entries = self.h1_connections.entry(key).or_default();
        entries.push_back(H1PoolEntry {
            sender,
            conn_task: Arc::new(conn_task),
            permit,
            last_used: Instant::now(),
        });
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool mutation will be removed in 0.3.0"
    )]
    pub fn return_h1(
        &mut self,
        key: ConnectionKey,
        sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: Arc<tokio::task::JoinHandle<()>>,
    ) {
        let task_key = Arc::as_ptr(&conn_task) as usize;
        let permit = self
            .legacy_h1_permits
            .remove(&task_key)
            .map(|tracked| tracked.permit)
            .unwrap_or_else(|| self.adopt_existing_connection());
        self.return_h1_reserved(key, sender, conn_task, permit);
    }

    #[deprecated(
        since = "0.2.1",
        note = "use Session-managed pooling; direct ConnectionPool mutation will be removed in 0.3.0"
    )]
    pub fn insert_h1(
        &mut self,
        key: ConnectionKey,
        sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: tokio::task::JoinHandle<()>,
    ) {
        let permit = self.adopt_existing_connection();
        self.insert_h1_reserved(key, sender, conn_task, permit);
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    /// Remove connections that have been idle longer than `max_idle`.
    ///
    /// Returns the number of connections evicted.
    pub fn evict_idle(&mut self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut evicted = 0;

        // Evict idle H2 connections
        let before_h2 = self.h2_connections.len();
        self.h2_connections.retain(|key, entry| {
            let idle_for = now.duration_since(entry.last_used);
            if idle_for > max_idle {
                tracing::debug!(
                    "Evicting idle H2 connection to {}:{} (idle {:?})",
                    key.host,
                    key.port,
                    idle_for,
                );
                false
            } else {
                true
            }
        });
        evicted += before_h2 - self.h2_connections.len();

        #[cfg(feature = "quic-h3")]
        {
            let before_h3 = self.h3_connections.len();
            self.h3_connections.retain(|key, entry| {
                let idle_for = now.duration_since(entry.last_used);
                if idle_for > max_idle {
                    tracing::debug!(
                        "Evicting idle H3 connection to {}:{} (idle {:?})",
                        key.host,
                        key.port,
                        idle_for,
                    );
                    false
                } else {
                    true
                }
            });
            evicted += before_h3 - self.h3_connections.len();
        }

        // Evict idle H1.1 connections
        for (key, entries) in self.h1_connections.iter_mut() {
            let before = entries.len();
            entries.retain(|entry| {
                let idle_for = now.duration_since(entry.last_used);
                if idle_for > max_idle {
                    tracing::debug!(
                        "Evicting idle H1 connection to {}:{} (idle {:?})",
                        key.host,
                        key.port,
                        idle_for,
                    );
                    false
                } else {
                    true
                }
            });
            evicted += before - entries.len();
        }
        // Clean up empty vecs
        self.h1_connections.retain(|_, entries| !entries.is_empty());

        evicted
    }

    /// Remove all connections from the pool, aborting their driver tasks.
    ///
    /// Useful for benchmarks or tests that need to force fresh connections
    /// without creating a new Session (which would leak spawned tasks and
    /// accumulate TIME_WAIT sockets).
    pub fn clear(&mut self) {
        self.evict_closed();
        for (_, entry) in self.h2_connections.drain() {
            entry._conn_task.abort();
        }
        #[cfg(feature = "quic-h3")]
        for (_, entry) in self.h3_connections.drain() {
            entry._driver_task.abort();
        }
        for (_, mut entries) in self.h1_connections.drain() {
            for entry in entries.drain(..) {
                entry.conn_task.abort();
            }
        }
    }

    /// Number of connections currently in the pool.
    pub fn len(&self) -> usize {
        let h3 = {
            #[cfg(feature = "quic-h3")]
            {
                self.h3_connections.len()
            }
            #[cfg(not(feature = "quic-h3"))]
            {
                0
            }
        };
        h3 + self.h2_connections.len()
            + self.h1_connections.values().map(|v| v.len()).sum::<usize>()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.h2_connections.is_empty() && self.h1_connections.is_empty() && {
            #[cfg(feature = "quic-h3")]
            {
                self.h3_connections.is_empty()
            }
            #[cfg(not(feature = "quic-h3"))]
            {
                true
            }
        }
    }

    /// Return a snapshot of pool statistics.
    pub fn stats(&self) -> PoolStats {
        let h3 = {
            #[cfg(feature = "quic-h3")]
            {
                self.h3_connections.len()
            }
            #[cfg(not(feature = "quic-h3"))]
            {
                0
            }
        };
        let h2 = self.h2_connections.len();
        let h1: usize = self.h1_connections.values().map(|v| v.len()).sum();
        let total = self.connections_in_use.load(Ordering::Acquire);
        PoolStats {
            h3_connections: h3,
            h2_connections: h2,
            h1_connections: h1,
            total,
            max_total: self.max_total,
            at_capacity: total >= self.max_total,
        }
    }
}

fn try_reserve_counter(in_use: &Arc<AtomicUsize>, max_total: usize) -> Option<ConnectionPermit> {
    let mut current = in_use.load(Ordering::Acquire);
    loop {
        if current >= max_total {
            return None;
        }
        match in_use.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(ConnectionPermit {
                    in_use: Arc::clone(in_use),
                });
            }
            Err(actual) => current = actual,
        }
    }
}

/// Snapshot of connection pool statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub h3_connections: usize,
    pub h2_connections: usize,
    pub h1_connections: usize,
    pub total: usize,
    pub max_total: usize,
    pub at_capacity: bool,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    /// Set the maximum total connections for this pool.
    pub fn set_max_total(&mut self, max_total: usize) {
        self.max_total = max_total;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(host: &str) -> ConnectionKey {
        ConnectionKey {
            scheme: Scheme::Https,
            host: host.into(),
            port: 443,
            route: RouteKey::direct(),
        }
    }

    #[test]
    fn pool_new_is_empty() {
        let pool = ConnectionPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert!(!pool.is_at_capacity());
    }

    #[test]
    fn pool_default_limits() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.max_per_key, 16);
        assert_eq!(pool.max_total, 64);
    }

    #[test]
    fn pool_with_max_total() {
        let pool = ConnectionPool::with_max_total(8);
        assert_eq!(pool.max_total, 8);
    }

    #[test]
    fn pool_set_max_total() {
        let mut pool = ConnectionPool::new();
        pool.set_max_total(32);
        assert_eq!(pool.max_total, 32);
    }

    #[test]
    fn try_acquire_empty_pool_returns_none() {
        let mut pool = ConnectionPool::new();
        let key = test_key("example.com");
        assert!(pool.try_acquire_internal(&key).is_none());
    }

    #[test]
    fn try_acquire_h2_empty_returns_none() {
        let mut pool = ConnectionPool::new();
        let key = test_key("example.com");
        assert!(pool.try_acquire_h2(&key).is_none());
    }

    #[test]
    fn try_acquire_h1_empty_returns_none() {
        let mut pool = ConnectionPool::new();
        let key = test_key("example.com");
        assert!(pool.try_acquire_h1(&key).is_none());
    }

    #[test]
    fn connection_key_equality() {
        let k1 = test_key("example.com");
        let k2 = test_key("example.com");
        let k3 = test_key("other.com");

        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn connection_key_different_scheme() {
        let k1 = ConnectionKey {
            scheme: Scheme::Http,
            host: "example.com".into(),
            port: 80,
            route: RouteKey::direct(),
        };
        let k2 = ConnectionKey {
            scheme: Scheme::Https,
            host: "example.com".into(),
            port: 443,
            route: RouteKey::direct(),
        };
        assert_ne!(k1, k2);
    }

    #[test]
    fn connection_key_different_proxy() {
        let k1 = ConnectionKey {
            scheme: Scheme::Https,
            host: "example.com".into(),
            port: 443,
            route: RouteKey::direct(),
        };
        let k2 = ConnectionKey {
            scheme: Scheme::Https,
            host: "example.com".into(),
            port: 443,
            route: crate::protocol::RouteKey::from_proxy(Some(
                &crate::proxy::ProxyConfig::parse("socks5h://127.0.0.1:8080").unwrap(),
            )),
        };
        assert_ne!(k1, k2);
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut pool = ConnectionPool::new();
        let key = test_key("example.com");
        pool.remove(&key); // should not panic
        assert!(pool.is_empty());
    }

    #[test]
    fn evict_idle_empty_pool() {
        let mut pool = ConnectionPool::new();
        let evicted = pool.evict_idle(Duration::from_secs(60));
        assert_eq!(evicted, 0);
    }

    #[test]
    fn pool_default_idle_timeout() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn pool_custom_idle_timeout() {
        let mut pool = ConnectionPool::new();
        pool.idle_timeout = Duration::from_secs(30);
        assert_eq!(pool.idle_timeout, Duration::from_secs(30));
    }

    #[test]
    fn pool_with_max_total_has_default_idle_timeout() {
        let pool = ConnectionPool::with_max_total(8);
        assert_eq!(pool.idle_timeout, Duration::from_secs(300));
        assert_eq!(pool.max_total, 8);
    }

    #[tokio::test]
    async fn abandoned_legacy_h1_checkout_releases_permit_on_cleanup() {
        let mut pool = ConnectionPool::with_max_total(1);
        let permit = pool.try_reserve_connection().expect("reservation");
        let task = Arc::new(tokio::spawn(std::future::pending::<()>()));
        let task_key = Arc::as_ptr(&task) as usize;
        pool.legacy_h1_permits.insert(
            task_key,
            LegacyH1Permit {
                task: Arc::downgrade(&task),
                permit,
            },
        );

        assert!(pool.is_at_capacity());
        task.abort();
        drop(task);
        pool.evict_closed();

        assert!(!pool.is_at_capacity());
        assert!(pool.try_reserve_connection().is_some());
    }

    #[tokio::test]
    async fn clear_preserves_checked_out_legacy_h1_permit() {
        let mut pool = ConnectionPool::with_max_total(1);
        let permit = pool.try_reserve_connection().expect("reservation");
        let task = Arc::new(tokio::spawn(std::future::pending::<()>()));
        let task_key = Arc::as_ptr(&task) as usize;
        pool.legacy_h1_permits.insert(
            task_key,
            LegacyH1Permit {
                task: Arc::downgrade(&task),
                permit,
            },
        );

        pool.clear();

        assert!(pool.is_at_capacity());
        task.abort();
        drop(task);
        pool.evict_closed();
        assert!(!pool.is_at_capacity());
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn dropping_tracked_h3_entry_does_not_abort_driver() {
        let task = tokio::spawn(std::future::pending::<()>());
        let abort_handle = task.abort_handle();
        let tracked = H3DriverTask::Tracked(Arc::new(task));

        drop(tracked);
        tokio::task::yield_now().await;

        assert!(!abort_handle.is_finished());
        abort_handle.abort();
    }

    #[test]
    fn adopted_existing_connection_is_counted_even_above_limit() {
        let mut pool = ConnectionPool::with_max_total(1);
        let reserved = pool.try_reserve_connection().expect("reservation");
        let adopted = pool.adopt_existing_connection();

        assert_eq!(pool.stats().total, 2);
        assert!(pool.is_at_capacity());

        drop(adopted);
        drop(reserved);
        assert_eq!(pool.stats().total, 0);
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn dropped_legacy_h3_entry_holds_permit_until_driver_stops() {
        let pool = ConnectionPool::with_max_total(1);
        let permit = pool.adopt_existing_connection();
        let driver = Arc::new(tokio::spawn(std::future::pending::<
            Result<(), lkh3::H3Error>,
        >()));
        let abort_handle = driver.abort_handle();
        let permit_task = Arc::new(track_shared_h3_task(Arc::clone(&driver), permit));
        let tracked = H3DriverTask::Legacy {
            task: driver,
            permit_task,
        };

        drop(tracked);
        tokio::task::yield_now().await;
        assert_eq!(pool.stats().total, 1);
        assert!(!abort_handle.is_finished());

        abort_handle.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.stats().total != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("legacy H3 permit should release after driver termination");
        assert_eq!(pool.stats().total, 0);
    }

    #[test]
    fn physical_connection_reservation_is_atomic_and_released_on_drop() {
        let mut pool = ConnectionPool::with_max_total(1);

        let permit = pool.try_reserve_connection().expect("first reservation");
        let budget = pool.connection_budget();
        assert!(pool.try_reserve_connection().is_none());
        assert!(budget.try_reserve_speculative().is_none());
        assert_eq!(pool.stats().total, 1);
        assert!(pool.is_at_capacity());

        drop(permit);
        let speculative = budget
            .try_reserve_speculative()
            .expect("released primary slot should be reusable speculatively");
        assert_eq!(pool.stats().total, 1);
        drop(speculative);
        assert!(pool.try_reserve_connection().is_some());
    }
}
