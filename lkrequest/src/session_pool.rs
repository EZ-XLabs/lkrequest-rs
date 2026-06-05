//! SessionPool — manages multiple Sessions with proxy rotation.
//!
//! `SessionPool` is designed for high-concurrency, multi-proxy scraping
//! scenarios.  It maintains a pool of [`Session`]s, each bound to a different
//! proxy, and distributes them to concurrent tasks via `acquire()` / `release()`.
//!
//! A RAII [`SessionGuard`] is returned from `acquire()` to ensure Sessions are
//! always returned to the pool, even if a task panics.
//!
//! ## Features
//!
//! - **Pluggable proxy provider**: [`ProxyProvider`]
//!   trait supports fixed lists ([`ProxyRotator`](crate::proxy::ProxyRotator)),
//!   closures ([`FnProxyProvider`](crate::proxy::FnProxyProvider)), and buffered
//!   pre-generation ([`BufferedProxyProvider`](crate::proxy::BufferedProxyProvider)).
//! - **Idle Session eviction**: background task periodically removes Sessions
//!   that have been idle longer than `idle_timeout`, releasing semaphore permits.
//! - **Sliding window failure counting**: `mark_bad()` tracks failures per proxy
//!   within a configurable time window. Only when the threshold is reached does
//!   the proxy enter a cooldown period.
//! - **Automatic cooldown recovery**: expired cooldown entries are cleaned up
//!   by the background maintenance task; proxies become eligible again.
//! - **Permanent removal**: proxies that enter cooldown too many times
//!   (`max_cooldowns`) are permanently removed from rotation.
//!
//! Internally, `SessionPool` delegates all proxy management to
//! [`ProxyPool`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::client::Client;
use crate::proxy::{ProxyConfig, ProxyProvider, RotationStrategy};
use crate::proxy_pool::{ProxyGuard, ProxyPool, ProxyPoolBuilder};
use crate::session::Session;

// Re-export from proxy_pool for backward compatibility.
pub use crate::proxy_pool::{BadProxyConfig, HealthCheckConfig};

// ---------------------------------------------------------------------------
// Idle queue entry — wraps a Session + ProxyGuard with a timestamp
// ---------------------------------------------------------------------------

struct IdleEntry {
    session: Session,
    proxy_guard: ProxyGuard,
    returned_at: Instant,
}

// ---------------------------------------------------------------------------
// SessionPool
// ---------------------------------------------------------------------------

/// A pool of Sessions with automatic proxy rotation and lifecycle management.
///
/// # Example — Fixed proxy list (classic)
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let proxy_configs = vec![lkrequest::proxy::ProxyConfig::parse("http://proxy:8080").unwrap()];
/// use lkrequest::session_pool::SessionPool;
/// use lkrequest::proxy::RotationStrategy;
///
/// let pool = SessionPool::builder()
///     .client(&client)
///     .proxies(proxy_configs)
///     .max_sessions(100)
///     .rotation(RotationStrategy::RoundRobin)
///     .build();
///
/// let guard = pool.acquire().await;
/// let resp = guard.get("https://target.com").send().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Example — Dynamic proxy generation (residential proxies)
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use std::sync::Arc;
/// use lkrequest::session_pool::SessionPool;
///
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// let counter = Arc::new(AtomicU64::new(0));
/// let pool = SessionPool::builder()
///     .client(&client)
///     .proxy_fn(move || {
///         let id = counter.fetch_add(1, Ordering::Relaxed);
///         format!("http://user-sid-{id:06}-sesstime=5:pass@gateway.com:7777")
///     })
///     .proxy_buffer(50) // pre-generate 50 proxy configs
///     .max_sessions(50)
///     .build();
/// ```
pub struct SessionPool {
    inner: Arc<SessionPoolInner>,
}

struct SessionPoolInner {
    /// The client template for creating new Sessions.
    client: Client,

    /// Proxy management — selection, health, cooldown, concurrency.
    proxy_pool: ProxyPool,

    /// Queue of idle Sessions (paired with their ProxyGuards) ready for reuse.
    idle: Mutex<VecDeque<IdleEntry>>,

    /// How long a Session can sit idle before being evicted.
    idle_timeout: Duration,

    /// Signal for the idle-eviction background task to stop.
    shutdown: AtomicBool,
}

/// Snapshot of session pool statistics.
#[derive(Debug, Clone)]
pub struct SessionPoolStats {
    /// Number of idle sessions ready for reuse.
    pub idle_sessions: usize,
    /// Maximum concurrent sessions allowed.
    pub max_sessions: usize,
}

impl SessionPool {
    /// Start building a new `SessionPool`.
    pub fn builder() -> SessionPoolBuilder {
        SessionPoolBuilder::new()
    }

    /// Acquire a Session from the pool.
    ///
    /// If an idle Session is available, it is reused immediately.  Otherwise,
    /// a new proxy permit is acquired from the underlying
    /// [`ProxyPool`] (which may **await** if
    /// the pool is at capacity) and a fresh Session is created.
    ///
    /// Returns a [`SessionGuard`] that automatically returns the Session
    /// to the pool when dropped.
    pub async fn acquire(&self) -> SessionGuard {
        tracing::trace!("session_pool.acquiring");

        // 1. Try to take an idle Session (skip expired ones).
        //    Idle entries hold ProxyGuards, so no semaphore wait needed.
        let idle_entry = {
            let mut idle = self.inner.idle.lock().await;
            let timeout = self.inner.idle_timeout;
            let now = Instant::now();
            loop {
                match idle.pop_front() {
                    Some(entry) if now.duration_since(entry.returned_at) < timeout => {
                        break Some(entry);
                    }
                    // Expired: drop entry (ProxyGuard drops → permit released)
                    Some(_expired) => continue,
                    None => break None,
                }
            }
        };

        match idle_entry {
            Some(entry) => {
                tracing::debug!(reused = true, "session_pool.acquired");
                SessionGuard {
                    session: Some(entry.session),
                    proxy_guard: Some(entry.proxy_guard),
                    pool: Arc::clone(&self.inner),
                }
            }
            None => {
                // 2. No idle Session — acquire proxy permit + create new Session.
                let proxy_guard = self.inner.proxy_pool.acquire().await;
                let session = Self::create_session(&self.inner.client, &proxy_guard);

                tracing::debug!(reused = false, "session_pool.acquired");
                SessionGuard {
                    session: Some(session),
                    proxy_guard: Some(proxy_guard),
                    pool: Arc::clone(&self.inner),
                }
            }
        }
    }

    /// Mark a Session's proxy as "bad" (e.g. after repeated 403s or connection
    /// resets).
    ///
    /// For **static** providers (fixed proxy lists), this feeds the sliding-window
    /// failure counter that triggers cooldown / permanent removal.
    ///
    /// For **dynamic** providers (closure-based), this is a no-op because each
    /// session has a unique, ephemeral proxy identity.
    pub fn mark_bad(&self, session_guard: &SessionGuard) {
        if let Some(session) = session_guard.session.as_ref() {
            if let Some(proxy) = &session.inner.proxy {
                self.inner.proxy_pool.mark_bad_proxy(&proxy.identity());
            }
        }
    }

    /// Create a new Session using the proxy from a ProxyGuard.
    fn create_session(client: &Client, proxy_guard: &ProxyGuard) -> Session {
        let mut builder = client.session();
        if let Some(proxy) = proxy_guard.proxy() {
            builder = builder.proxy_config(proxy.clone());
        }
        builder.build()
    }

    /// Acquire a fresh Session with a different proxy (for retry scenarios).
    ///
    /// Marks the current session's proxy as bad and acquires a new session
    /// with a different proxy. Useful for retry-on-failure with proxy switching.
    pub async fn acquire_fresh(&self, bad_guard: &SessionGuard) -> SessionGuard {
        self.mark_bad(bad_guard);
        self.acquire().await
    }

    /// Returns a reference to the underlying [`ProxyPool`].
    pub fn proxy_pool(&self) -> &ProxyPool {
        &self.inner.proxy_pool
    }

    /// Return a snapshot of session pool statistics.
    pub async fn stats(&self) -> SessionPoolStats {
        let idle = self.inner.idle.lock().await.len();
        SessionPoolStats {
            idle_sessions: idle,
            max_sessions: self.inner.proxy_pool.max_concurrent(),
        }
    }

    /// Spawn the background task that evicts idle Sessions.
    ///
    /// Cooldown cleanup and health checks are handled by `ProxyPool`'s own
    /// maintenance task.
    fn spawn_maintenance_task(inner: Arc<SessionPoolInner>) {
        let check_interval = (inner.idle_timeout / 2).max(Duration::from_secs(5));
        let idle_timeout = inner.idle_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;

                if inner.shutdown.load(Ordering::Relaxed) {
                    tracing::debug!("session_pool.maintenance_task_shutdown");
                    break;
                }

                // Evict idle Sessions.
                // Dropped IdleEntry's ProxyGuard releases its semaphore permit.
                {
                    let mut idle = inner.idle.lock().await;
                    let now = Instant::now();
                    let before = idle.len();
                    idle.retain(|entry| now.duration_since(entry.returned_at) < idle_timeout);
                    let evicted = before - idle.len();
                    if evicted > 0 {
                        tracing::info!(evicted = evicted, "session_pool.evicted_idle_sessions");
                    }
                }
            }
        });
    }
}

impl Clone for SessionPool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) <= 2 {
            self.inner.shutdown.store(true, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// SessionGuard — RAII auto-return
// ---------------------------------------------------------------------------

/// A guard that holds a borrowed Session.
///
/// When the guard is dropped, the Session is automatically returned to the
/// pool.  This prevents Session leaks even if a task panics.
///
/// Use `Deref` to access the underlying `Session` methods.
pub struct SessionGuard {
    session: Option<Session>,
    proxy_guard: Option<ProxyGuard>,
    pool: Arc<SessionPoolInner>,
}

impl std::ops::Deref for SessionGuard {
    type Target = Session;

    fn deref(&self) -> &Session {
        self.session
            .as_ref()
            .expect("SessionGuard already consumed")
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if let Some(proxy_guard) = self.proxy_guard.take() {
                tracing::trace!("session_pool.released");
                let pool = Arc::clone(&self.pool);
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(async move {
                            let mut idle = pool.idle.lock().await;
                            idle.push_back(IdleEntry {
                                session,
                                proxy_guard,
                                returned_at: Instant::now(),
                            });
                        });
                    }
                    Err(_) => {
                        tracing::warn!(
                            "session_pool.drop_outside_runtime — \
                             session not returned to pool"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`SessionPool`].
pub struct SessionPoolBuilder {
    client: Option<Client>,
    idle_timeout: Duration,
    proxy_builder: ProxyPoolBuilder,
}

impl SessionPoolBuilder {
    fn new() -> Self {
        Self {
            client: None,
            idle_timeout: Duration::from_secs(300),
            proxy_builder: ProxyPoolBuilder::new(),
        }
    }

    /// Set the client template (required).
    pub fn client(mut self, client: &Client) -> Self {
        self.client = Some(client.clone());
        self
    }

    /// Set the proxy list (creates a [`ProxyRotator`](crate::proxy::ProxyRotator) internally).
    ///
    /// This is the classic API for fixed proxy lists.  Combine with
    /// [`rotation()`](Self::rotation) to control the selection strategy.
    pub fn proxies(mut self, proxies: Vec<ProxyConfig>) -> Self {
        self.proxy_builder = self.proxy_builder.proxies(proxies);
        self
    }

    /// Set the maximum number of concurrent Sessions (default: 100).
    pub fn max_sessions(mut self, n: usize) -> Self {
        self.proxy_builder = self.proxy_builder.max_proxies(n);
        self
    }

    /// Set the idle timeout for Sessions (default: 300s).
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the proxy rotation strategy (default: RoundRobin).
    ///
    /// Only applies when using `.proxies()`.  Ignored if a custom
    /// provider is set via `.proxy_provider()` or `.proxy_fn()`.
    pub fn rotation(mut self, strategy: RotationStrategy) -> Self {
        self.proxy_builder = self.proxy_builder.rotation(strategy);
        self
    }

    /// Configure the bad-proxy detection mechanism.
    pub fn bad_proxy_config(mut self, config: BadProxyConfig) -> Self {
        self.proxy_builder = self.proxy_builder.bad_proxy_config(config);
        self
    }

    /// Enable active proxy health checking.
    pub fn health_check(mut self, config: HealthCheckConfig) -> Self {
        self.proxy_builder = self.proxy_builder.health_check(config);
        self
    }

    /// Set a custom [`ProxyProvider`] implementation.
    ///
    /// This overrides any proxy list set via `.proxies()`.  Use this for
    /// advanced proxy selection logic (geo-routing, weighted selection, etc.).
    pub fn proxy_provider(mut self, provider: impl ProxyProvider + 'static) -> Self {
        self.proxy_builder = self.proxy_builder.proxy_provider(provider);
        self
    }

    /// Set a closure-based proxy provider.
    ///
    /// The closure is called each time a new Session needs a proxy.  It
    /// should return a proxy URL string (e.g.
    /// `"http://user-sid-123:pass@gateway.com:7777"`).
    ///
    /// This is a convenience wrapper around [`FnProxyProvider`](crate::proxy::FnProxyProvider).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// use std::sync::atomic::{AtomicU64, Ordering};
    /// use std::sync::Arc;
    /// use lkrequest::session_pool::SessionPool;
    ///
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// let counter = Arc::new(AtomicU64::new(0));
    /// let pool = SessionPool::builder()
    ///     .client(&client)
    ///     .proxy_fn(move || {
    ///         let id = counter.fetch_add(1, Ordering::Relaxed);
    ///         format!("http://user-sid-{id:06}-sesstime=5:pass@gw.com:7777")
    ///     })
    ///     .build();
    /// ```
    pub fn proxy_fn(mut self, f: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.proxy_builder = self.proxy_builder.proxy_fn(f);
        self
    }

    /// Enable proxy config pre-generation with a buffer of the given capacity.
    ///
    /// A background thread will continuously call the provider's `next_proxy()`
    /// to fill a buffer of pre-generated `ProxyConfig`s.  When `acquire()` creates
    /// a new Session, it pops from the buffer instead of generating on the fly.
    ///
    /// Most useful with dynamic providers (`.proxy_fn()`) where the generation
    /// might involve network calls or expensive computation.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// use lkrequest::session_pool::SessionPool;
    ///
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # fn generate_proxy() -> String { "http://proxy:8080".into() }
    /// let pool = SessionPool::builder()
    ///     .client(&client)
    ///     .proxy_fn(|| generate_proxy())
    ///     .proxy_buffer(50) // pre-generate 50 configs
    ///     .build();
    /// ```
    pub fn proxy_buffer(mut self, capacity: usize) -> Self {
        self.proxy_builder = self.proxy_builder.proxy_buffer(capacity);
        self
    }

    /// Build the `SessionPool`.
    ///
    /// # Panics
    ///
    /// Panics if no client was set.
    pub fn build(self) -> SessionPool {
        let client = self
            .client
            .expect("SessionPool requires a Client (.client())");

        let proxy_pool = self.proxy_builder.build();

        let inner = Arc::new(SessionPoolInner {
            client,
            proxy_pool,
            idle: Mutex::new(VecDeque::new()),
            idle_timeout: self.idle_timeout,
            shutdown: AtomicBool::new(false),
        });

        SessionPool::spawn_maintenance_task(Arc::clone(&inner));

        SessionPool { inner }
    }
}
