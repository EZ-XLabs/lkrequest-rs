//! ProxyPool — manages proxy allocation with concurrency control and health tracking.
//!
//! `ProxyPool` decouples proxy management from session management, providing
//! a standalone pool of proxies that can be acquired and released independently.
//!
//! ## Features
//!
//! - **Pluggable proxy provider**: same [`ProxyProvider`]
//!   ecosystem as [`SessionPool`](crate::session_pool::SessionPool).
//! - **Concurrency control**: semaphore-based limit on concurrent proxy usage.
//! - **Sliding window failure counting**: `mark_bad()` tracks failures per proxy.
//! - **Automatic cooldown recovery**: background task cleans up expired cooldowns.
//! - **Permanent removal**: proxies that enter cooldown too many times are removed.
//! - **Health checking**: optional active TCP probes for static proxy lists.
//!
//! ## Use Cases
//!
//! Use `ProxyPool` when you need proxy lifecycle management without session reuse —
//! for example, captcha solving where each task requires a fresh
//! [`Session`](crate::session::Session) but shares a managed proxy pool.
//!
//! For traditional scraping where session reuse (cookies, connections) is desired,
//! use [`SessionPool`](crate::session_pool::SessionPool) which builds on `ProxyPool`
//! internally.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};

use crate::proxy::{
    BufferedProxyProvider, FnProxyProvider, ProxyConfig, ProxyProvider, ProxyRotator,
    RotationStrategy,
};

// ---------------------------------------------------------------------------
// ProxyPool
// ---------------------------------------------------------------------------

/// A pool of proxies with concurrency control and health management.
///
/// `ProxyPool` provides a standalone proxy management layer that can be used
/// independently of [`SessionPool`](crate::session_pool::SessionPool).  Each
/// call to [`acquire()`](ProxyPool::acquire) returns a [`ProxyGuard`] holding
/// a proxy configuration and a semaphore permit.  When the guard is dropped,
/// the permit is released, allowing another caller to proceed.
///
/// # Example — Standalone use (captcha solver)
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use std::sync::Arc;
/// use lkrequest::proxy_pool::ProxyPool;
///
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// let counter = Arc::new(AtomicU64::new(0));
/// let pool = ProxyPool::builder()
///     .proxy_fn(move || {
///         let id = counter.fetch_add(1, Ordering::Relaxed);
///         format!("http://user-sid-{id:06}:pass@gateway.com:7777")
///     })
///     .max_proxies(50)
///     .build();
///
/// let guard = pool.acquire().await;
/// let session = client.session()
///     .proxy_config(guard.proxy().unwrap().clone())
///     .build();
/// let resp = session.get("https://example.com/captcha/solve").send().await?;
/// // guard dropped → permit released
/// # Ok(())
/// # }
/// ```
pub struct ProxyPool {
    pub(crate) inner: Arc<ProxyPoolInner>,
}

pub(crate) struct ProxyPoolInner {
    pub(crate) proxy_provider: Box<dyn ProxyProvider>,
    semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    max_proxies: usize,
    cooldown: Mutex<HashMap<String, Instant>>,
    failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    permanently_removed: Mutex<HashSet<String>>,
    cooldown_counts: Mutex<HashMap<String, u32>>,
    pub(crate) bad_proxy_config: BadProxyConfig,
    health_check: Option<HealthCheckConfig>,
    pub(crate) shutdown: AtomicBool,
}

impl ProxyPool {
    /// Start building a new `ProxyPool`.
    pub fn builder() -> ProxyPoolBuilder {
        ProxyPoolBuilder::new()
    }

    /// Acquire a proxy from the pool.
    ///
    /// Waits for a semaphore permit if the pool is at capacity, then selects
    /// the next usable proxy from the provider (skipping proxies in cooldown
    /// or permanently removed).
    ///
    /// Returns a [`ProxyGuard`] that releases the permit on drop.
    pub async fn acquire(&self) -> ProxyGuard {
        tracing::trace!("proxy_pool.acquiring");

        let permit = self
            .inner
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");

        let proxy = self.next_usable_proxy().await;

        tracing::debug!("proxy_pool.acquired");

        ProxyGuard {
            proxy,
            pool: Arc::clone(&self.inner),
            _permit: permit,
        }
    }

    /// Mark a proxy as bad and acquire a fresh one.
    ///
    /// Note: `bad_guard` still holds its permit. If the pool is at capacity,
    /// this will block until another permit is released elsewhere.
    pub async fn acquire_fresh(&self, bad_guard: &ProxyGuard) -> ProxyGuard {
        bad_guard.mark_bad();
        self.acquire().await
    }

    /// Returns the maximum number of concurrent proxy permits.
    pub fn max_concurrent(&self) -> usize {
        self.inner.max_proxies
    }

    /// Mark a proxy as bad by its identity string.
    ///
    /// Feeds the sliding-window failure counter.  When the threshold is reached,
    /// the proxy enters cooldown.  After too many cooldowns, permanent removal.
    ///
    /// No-op for dynamic providers (ephemeral identities).
    pub fn mark_bad_proxy(&self, identity: &str) {
        record_bad_proxy(&self.inner, identity.to_string());
    }

    /// Select the next usable proxy, skipping those in cooldown or removed.
    pub(crate) async fn next_usable_proxy(&self) -> Option<ProxyConfig> {
        let provider = &self.inner.proxy_provider;

        if provider.is_dynamic() {
            return provider.next_proxy();
        }

        let proxy_count = provider.len();
        for _ in 0..proxy_count.max(1) {
            if let Some(proxy) = provider.next_proxy() {
                let identity = proxy.identity();

                {
                    let removed = self.inner.permanently_removed.lock().await;
                    if removed.contains(&identity) {
                        tracing::trace!(
                            proxy = %identity,
                            "proxy_pool.skipping_removed_proxy"
                        );
                        continue;
                    }
                }

                let in_cooldown = {
                    let map = self.inner.cooldown.lock().await;
                    map.get(&identity)
                        .is_some_and(|expires| Instant::now() < *expires)
                };

                if !in_cooldown {
                    return Some(proxy);
                }
                tracing::debug!(
                    proxy = %identity,
                    "proxy_pool.skipping_cooldown_proxy",
                );
            } else {
                break;
            }
        }
        None
    }

    fn spawn_maintenance_task(inner: Arc<ProxyPoolInner>) {
        let check_interval = Duration::from_secs(30);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            let mut health_check_due = Instant::now();
            loop {
                interval.tick().await;

                if inner.shutdown.load(Ordering::Relaxed) {
                    tracing::debug!("proxy_pool.maintenance_task_shutdown");
                    break;
                }

                // 1. Clean up expired cooldown entries
                {
                    let mut cooldown = inner.cooldown.lock().await;
                    let now = Instant::now();
                    let before = cooldown.len();
                    cooldown.retain(|_, expires| now < *expires);
                    let recovered = before - cooldown.len();
                    if recovered > 0 {
                        tracing::info!(
                            recovered = recovered,
                            "proxy_pool.cooldown_proxies_recovered",
                        );
                    }
                }

                // 2. Active health checking (static providers only)
                if !inner.proxy_provider.is_dynamic() {
                    if let Some(ref hc_config) = inner.health_check {
                        let now = Instant::now();
                        if now >= health_check_due {
                            health_check_due = now + hc_config.interval;
                            run_health_checks(&inner, hc_config).await;
                        }
                    }
                }
            }
        });
    }
}

impl Clone for ProxyPool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for ProxyPool {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) <= 2 {
            self.inner.shutdown.store(true, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// ProxyGuard — RAII permit holder
// ---------------------------------------------------------------------------

/// A guard that holds a proxy configuration and its pool permit.
///
/// When dropped, the semaphore permit is released, allowing another
/// [`ProxyPool::acquire`] call to proceed.
pub struct ProxyGuard {
    proxy: Option<ProxyConfig>,
    pool: Arc<ProxyPoolInner>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl ProxyGuard {
    /// Get the proxy configuration held by this guard.
    ///
    /// Returns `None` if no proxy was available from the provider (direct
    /// connection scenario).
    pub fn proxy(&self) -> Option<&ProxyConfig> {
        self.proxy.as_ref()
    }

    /// Mark this guard's proxy as bad.
    ///
    /// Feeds the sliding-window failure counter.  No-op if the proxy is `None`
    /// or the provider is dynamic.
    pub fn mark_bad(&self) {
        if let Some(proxy) = &self.proxy {
            record_bad_proxy(&self.pool, proxy.identity());
        }
    }
}

// ---------------------------------------------------------------------------
// Bad-proxy recording (shared by ProxyPool::mark_bad_proxy and ProxyGuard)
// ---------------------------------------------------------------------------

fn record_bad_proxy(inner: &Arc<ProxyPoolInner>, identity: String) {
    if inner.proxy_provider.is_dynamic() {
        return;
    }

    let pool_inner = Arc::clone(inner);
    tokio::spawn(async move {
        {
            let removed = pool_inner.permanently_removed.lock().await;
            if removed.contains(&identity) {
                return;
            }
        }

        let config = &pool_inner.bad_proxy_config;
        let now = Instant::now();
        let window_start = now - config.window;

        let failure_count = {
            let mut failures = pool_inner.failures.lock().await;
            let entries = failures.entry(identity.clone()).or_default();
            entries.retain(|t| *t > window_start);
            entries.push_back(now);
            entries.len() as u32
        };

        if failure_count >= config.failure_threshold {
            {
                let mut failures = pool_inner.failures.lock().await;
                if let Some(entries) = failures.get_mut(&identity) {
                    entries.clear();
                }
            }

            let mut cooldown_map = pool_inner.cooldown.lock().await;
            let expires = now + config.cooldown_duration;
            cooldown_map.insert(identity.clone(), expires);

            let cumulative = {
                let mut counts = pool_inner.cooldown_counts.lock().await;
                let count = counts.entry(identity.clone()).or_insert(0);
                *count += 1;
                *count
            };

            if cumulative >= config.max_cooldowns {
                let mut removed = pool_inner.permanently_removed.lock().await;
                removed.insert(identity.clone());
                tracing::error!(
                    proxy = %identity,
                    total_cooldowns = cumulative,
                    "proxy_pool.proxy_permanently_removed",
                );
            } else {
                tracing::warn!(
                    proxy = %identity,
                    cooldown_secs = config.cooldown_duration.as_secs(),
                    failures_in_window = failure_count,
                    total_cooldowns = cumulative,
                    "proxy_pool.proxy_entered_cooldown",
                );
            }
        } else {
            tracing::debug!(
                proxy = %identity,
                failures_in_window = failure_count,
                threshold = config.failure_threshold,
                "proxy_pool.proxy_failure_recorded",
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

async fn run_health_checks(inner: &Arc<ProxyPoolInner>, config: &HealthCheckConfig) {
    let removed = inner.permanently_removed.lock().await;
    let proxies: Vec<_> = inner
        .proxy_provider
        .all_proxies()
        .into_iter()
        .filter(|p| !removed.contains(&p.identity()))
        .collect();
    drop(removed);

    if proxies.is_empty() {
        return;
    }

    tracing::debug!(
        proxy_count = proxies.len(),
        target = %format_args!("{}:{}", config.target_host, config.target_port),
        "proxy_pool.health_check_starting",
    );

    let resolver = crate::dns::SystemDns;
    for proxy in &proxies {
        let identity = proxy.identity();
        let result = tokio::time::timeout(
            config.timeout,
            proxy.connect(&config.target_host, config.target_port, None, &resolver),
        )
        .await;

        match result {
            Ok(Ok(_stream)) => {
                let was_in_cooldown = {
                    let mut cooldown = inner.cooldown.lock().await;
                    cooldown.remove(&identity).is_some()
                };
                if was_in_cooldown {
                    tracing::info!(
                        proxy = %identity,
                        "proxy_pool.health_check_recovered_proxy",
                    );
                } else {
                    tracing::trace!(proxy = %identity, "proxy_pool.health_check_ok");
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    proxy = %identity,
                    error = %e,
                    "proxy_pool.health_check_failed",
                );
                let bp = &inner.bad_proxy_config;
                let now = Instant::now();
                let window_start = now - bp.window;
                let mut failures = inner.failures.lock().await;
                let entries = failures.entry(identity).or_default();
                entries.retain(|t| *t > window_start);
                entries.push_back(now);
            }
            Err(_timeout) => {
                tracing::debug!(proxy = %identity, "proxy_pool.health_check_timeout");
                let bp = &inner.bad_proxy_config;
                let now = Instant::now();
                let window_start = now - bp.window;
                let mut failures = inner.failures.lock().await;
                let entries = failures.entry(identity).or_default();
                entries.retain(|t| *t > window_start);
                entries.push_back(now);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BadProxyConfig
// ---------------------------------------------------------------------------

/// Configuration for automatic bad-proxy detection and cooldown.
#[derive(Debug, Clone)]
pub struct BadProxyConfig {
    /// Number of failures within `window` to trigger cooldown.
    pub failure_threshold: u32,
    /// Time window for counting failures.
    pub window: Duration,
    /// How long a bad proxy stays in cooldown before being retried.
    pub cooldown_duration: Duration,
    /// Number of times a proxy can enter cooldown before permanent removal.
    /// Set to `u32::MAX` to disable permanent removal.
    pub max_cooldowns: u32,
}

impl Default for BadProxyConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            window: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(300),
            max_cooldowns: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// HealthCheckConfig
// ---------------------------------------------------------------------------

/// Configuration for active proxy health checking.
///
/// When enabled, the pool periodically tests each proxy's connectivity
/// by attempting a TCP connection to a configurable target.  Unhealthy proxies
/// are fed into the bad-proxy detection pipeline, while healthy proxies in
/// cooldown are recovered early.
///
/// Health checks only apply to **static** providers (fixed proxy lists).
/// Dynamic providers (closures) skip health checks since their identities
/// are ephemeral.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// How often to run health checks (default: 60s).
    pub interval: Duration,
    /// Timeout for a single health check probe (default: 5s).
    pub timeout: Duration,
    /// Target host for health check TCP connection.
    pub target_host: String,
    /// Target port for health check (typically 443 or 80).
    pub target_port: u16,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            target_host: "www.google.com".into(),
            target_port: 443,
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`ProxyPool`].
pub struct ProxyPoolBuilder {
    proxies: Vec<ProxyConfig>,
    max_proxies: usize,
    rotation: RotationStrategy,
    bad_proxy_config: BadProxyConfig,
    health_check: Option<HealthCheckConfig>,
    custom_provider: Option<Box<dyn ProxyProvider>>,
    buffer_capacity: Option<usize>,
}

impl ProxyPoolBuilder {
    pub(crate) fn new() -> Self {
        Self {
            proxies: Vec::new(),
            max_proxies: 100,
            rotation: RotationStrategy::RoundRobin,
            bad_proxy_config: BadProxyConfig::default(),
            health_check: None,
            custom_provider: None,
            buffer_capacity: None,
        }
    }

    /// Set the proxy list (creates a [`ProxyRotator`] internally).
    ///
    /// This is the classic API for fixed proxy lists.  Combine with
    /// [`rotation()`](Self::rotation) to control the selection strategy.
    pub fn proxies(mut self, proxies: Vec<ProxyConfig>) -> Self {
        self.proxies = proxies;
        self
    }

    /// Set the maximum number of concurrent proxy permits (default: 100).
    pub fn max_proxies(mut self, n: usize) -> Self {
        self.max_proxies = n;
        self
    }

    /// Set the proxy rotation strategy (default: RoundRobin).
    ///
    /// Only applies when using `.proxies()`.  Ignored if a custom
    /// provider is set via `.proxy_provider()` or `.proxy_fn()`.
    pub fn rotation(mut self, strategy: RotationStrategy) -> Self {
        self.rotation = strategy;
        self
    }

    /// Configure the bad-proxy detection mechanism.
    pub fn bad_proxy_config(mut self, config: BadProxyConfig) -> Self {
        self.bad_proxy_config = config;
        self
    }

    /// Enable active proxy health checking.
    pub fn health_check(mut self, config: HealthCheckConfig) -> Self {
        self.health_check = Some(config);
        self
    }

    /// Set a custom [`ProxyProvider`] implementation.
    ///
    /// This overrides any proxy list set via `.proxies()`.  Use this for
    /// advanced proxy selection logic (geo-routing, weighted selection, etc.).
    pub fn proxy_provider(mut self, provider: impl ProxyProvider + 'static) -> Self {
        self.custom_provider = Some(Box::new(provider));
        self
    }

    /// Set a closure-based proxy provider.
    ///
    /// The closure is called each time a new proxy is needed.  It should
    /// return a proxy URL string (e.g.
    /// `"http://user-sid-123:pass@gateway.com:7777"`).
    ///
    /// This is a convenience wrapper around
    /// [`FnProxyProvider`].
    pub fn proxy_fn(mut self, f: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.custom_provider = Some(Box::new(FnProxyProvider::new(f)));
        self
    }

    /// Enable proxy config pre-generation with a buffer of the given capacity.
    ///
    /// A background thread will continuously call the provider's `next_proxy()`
    /// to fill a buffer of pre-generated `ProxyConfig`s.  When [`acquire()`](ProxyPool::acquire)
    /// needs a proxy, it pops from the buffer instead of generating on the fly.
    ///
    /// Most useful with dynamic providers (`.proxy_fn()`) where the generation
    /// might involve expensive computation.
    pub fn proxy_buffer(mut self, capacity: usize) -> Self {
        self.buffer_capacity = Some(capacity);
        self
    }

    /// Build the `ProxyPool`.
    pub fn build(self) -> ProxyPool {
        let provider: Box<dyn ProxyProvider> = if let Some(p) = self.custom_provider {
            p
        } else {
            Box::new(ProxyRotator::new(self.proxies, self.rotation))
        };

        let provider: Box<dyn ProxyProvider> = if let Some(cap) = self.buffer_capacity {
            Box::new(BufferedProxyProvider::new(provider, cap))
        } else {
            provider
        };

        let inner = Arc::new(ProxyPoolInner {
            proxy_provider: provider,
            semaphore: Arc::new(Semaphore::new(self.max_proxies)),
            max_proxies: self.max_proxies,
            cooldown: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            permanently_removed: Mutex::new(HashSet::new()),
            cooldown_counts: Mutex::new(HashMap::new()),
            bad_proxy_config: self.bad_proxy_config,
            health_check: self.health_check,
            shutdown: AtomicBool::new(false),
        });

        ProxyPool::spawn_maintenance_task(Arc::clone(&inner));

        ProxyPool { inner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(url: &str) -> ProxyConfig {
        ProxyConfig::parse(url).expect("valid proxy url")
    }

    /// Yield to the runtime until `pred` holds or we exhaust the budget.
    /// `record_bad_proxy` does its work on a spawned task, so observable state
    /// only settles after the current task yields a few times.
    async fn yield_until(mut pred: impl FnMut() -> bool) -> bool {
        for _ in 0..2000 {
            if pred() {
                return true;
            }
            tokio::task::yield_now().await;
        }
        pred()
    }

    #[test]
    fn bad_proxy_config_has_sane_defaults() {
        let c = BadProxyConfig::default();
        assert_eq!(c.failure_threshold, 3);
        assert_eq!(c.window, Duration::from_secs(60));
        assert_eq!(c.cooldown_duration, Duration::from_secs(300));
        assert_eq!(c.max_cooldowns, 5);
    }

    #[test]
    fn health_check_config_has_sane_defaults() {
        let c = HealthCheckConfig::default();
        assert_eq!(c.interval, Duration::from_secs(60));
        assert_eq!(c.timeout, Duration::from_secs(5));
        assert_eq!(c.target_host, "www.google.com");
        assert_eq!(c.target_port, 443);
    }

    #[tokio::test]
    async fn builder_reports_max_concurrent() {
        let pool = ProxyPool::builder()
            .proxies(vec![proxy("http://a.example.com:8080")])
            .max_proxies(7)
            .rotation(RotationStrategy::RoundRobin)
            .build();
        assert_eq!(pool.max_concurrent(), 7);
    }

    #[tokio::test]
    async fn acquire_returns_a_proxy_from_a_static_list() {
        let proxies = vec![
            proxy("http://a.example.com:8080"),
            proxy("http://b.example.com:8080"),
        ];
        let identities: HashSet<String> = proxies.iter().map(|p| p.identity()).collect();
        let pool = ProxyPool::builder().proxies(proxies).build();

        let guard = pool.acquire().await;
        let got = guard.proxy().expect("static list yields a proxy");
        assert!(identities.contains(&got.identity()));
    }

    #[tokio::test]
    async fn acquire_yields_none_for_empty_list() {
        let pool = ProxyPool::builder().proxies(vec![]).build();
        let guard = pool.acquire().await;
        assert!(guard.proxy().is_none(), "empty list => direct connection");
    }

    #[tokio::test]
    async fn dropping_a_guard_releases_its_permit() {
        // Capacity of one: the second acquire can only succeed after the first
        // guard is dropped and its permit returns to the semaphore.
        let pool = ProxyPool::builder()
            .proxies(vec![proxy("http://a.example.com:8080")])
            .max_proxies(1)
            .build();

        let g1 = pool.acquire().await;
        assert!(
            pool.inner.semaphore.try_acquire().is_err(),
            "permit is held"
        );
        drop(g1);
        let _g2 = pool.acquire().await; // would block forever if the permit leaked
    }

    #[tokio::test]
    async fn next_usable_proxy_skips_permanently_removed() {
        let p = proxy("http://only.example.com:8080");
        let id = p.identity();
        let pool = ProxyPool::builder().proxies(vec![p]).build();

        pool.inner.permanently_removed.lock().await.insert(id);
        assert!(pool.next_usable_proxy().await.is_none());
    }

    #[tokio::test]
    async fn next_usable_proxy_skips_only_while_in_cooldown() {
        let p = proxy("http://only.example.com:8080");
        let id = p.identity();
        let pool = ProxyPool::builder().proxies(vec![p]).build();

        // Future expiry => still cooling down => skipped.
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(id.clone(), Instant::now() + Duration::from_secs(60));
        assert!(pool.next_usable_proxy().await.is_none());

        // Past expiry => recovered => returned again.
        pool.inner
            .cooldown
            .lock()
            .await
            .insert(id, Instant::now() - Duration::from_secs(1));
        assert!(pool.next_usable_proxy().await.is_some());
    }

    #[tokio::test]
    async fn dynamic_provider_ignores_bad_proxy_marks() {
        let pool = ProxyPool::builder()
            .proxy_fn(|| "http://user:pass@gateway.example.com:7777".to_string())
            .build();

        // Dynamic identities are ephemeral, so marking is a no-op: nothing should
        // ever land in the cooldown map.
        pool.mark_bad_proxy("http://user:pass@gateway.example.com:7777");
        // Give any (erroneously) spawned task a chance to run, then confirm
        // nothing ever landed in the cooldown map.
        yield_until(|| false).await;
        assert!(pool.inner.cooldown.try_lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn repeated_failures_move_a_proxy_through_cooldown_then_removal() {
        let p = proxy("http://flaky.example.com:8080");
        let id = p.identity();
        let pool = ProxyPool::builder()
            .proxies(vec![p])
            .bad_proxy_config(BadProxyConfig {
                failure_threshold: 3,
                window: Duration::from_secs(60),
                cooldown_duration: Duration::from_secs(300),
                max_cooldowns: 2,
            })
            .build();

        // First 3 failures within the window => one cooldown.
        for _ in 0..3 {
            pool.mark_bad_proxy(&id);
        }
        let cooled = {
            let id = id.clone();
            let pool = pool.clone();
            yield_until(move || {
                pool.inner
                    .cooldown
                    .try_lock()
                    .is_ok_and(|m| m.contains_key(&id))
            })
            .await
        };
        assert!(cooled, "threshold failures should trigger a cooldown");

        // 3 more failures => second cooldown reaches max_cooldowns => permanent removal.
        for _ in 0..3 {
            pool.mark_bad_proxy(&id);
        }
        let removed = {
            let id = id.clone();
            let pool = pool.clone();
            yield_until(move || {
                pool.inner
                    .permanently_removed
                    .try_lock()
                    .is_ok_and(|s| s.contains(&id))
            })
            .await
        };
        assert!(
            removed,
            "max_cooldowns reached should permanently remove the proxy"
        );
    }
}
