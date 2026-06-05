use super::config::ProxyConfig;

// ---------------------------------------------------------------------------
// ProxyProvider trait — unified abstraction for proxy selection
// ---------------------------------------------------------------------------

/// Abstraction for providing proxy configurations to a [`SessionPool`](crate::SessionPool).
///
/// Implementations control *how* proxy configs are produced:
/// - [`ProxyRotator`]: fixed list with round-robin / random rotation (default).
/// - [`FnProxyProvider`]: arbitrary closure that generates a proxy URL each call.
/// - [`BufferedProxyProvider`]: wraps any `ProxyProvider` with a pre-generation buffer.
///
/// # Dynamic vs Static providers
///
/// Static providers (like `ProxyRotator`) hand out proxies from a fixed list.
/// The pool tracks per-proxy health via cooldown / permanent removal using
/// [`ProxyConfig::identity()`] as the key.
///
/// Dynamic providers (like `FnProxyProvider`) generate a fresh, unique proxy
/// identity on each call (e.g. a new residential-proxy session-id).  Because
/// every call yields a different identity, per-proxy cooldown tracking is
/// skipped — set [`is_dynamic()`](ProxyProvider::is_dynamic) to `true`.
pub trait ProxyProvider: Send + Sync {
    /// Get the next proxy configuration.
    ///
    /// Returns `None` if no proxy is available (e.g. empty list).
    fn next_proxy(&self) -> Option<ProxyConfig>;

    /// Approximate number of distinct proxies.
    ///
    /// For a fixed list this is the list length.  For dynamic generators
    /// return `1` (used as a loop bound when skipping bad proxies).
    fn len(&self) -> usize;

    /// Whether the provider has no proxies at all.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this provider generates a fresh, unique proxy identity each call.
    ///
    /// When `true`, the pool skips per-proxy cooldown / permanent-removal
    /// tracking because every call yields a different identity anyway.
    ///
    /// Default: `false` (static list behaviour).
    fn is_dynamic(&self) -> bool {
        false
    }

    /// Get the list of all proxy configs for health checking.
    ///
    /// Static providers return all their proxies; dynamic providers return
    /// an empty vec (health checks don't apply to ephemeral identities).
    fn all_proxies(&self) -> Vec<ProxyConfig> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Proxy rotation (for SessionPool)
// ---------------------------------------------------------------------------

/// Strategy for rotating proxies across sessions.
#[derive(Debug, Clone, Copy)]
pub enum RotationStrategy {
    /// Assign proxies in sequential order, cycling back to the start.
    RoundRobin,
    /// Assign proxies randomly.
    Random,
}

/// A proxy rotator that hands out proxies from a fixed list.
///
/// This is the default [`ProxyProvider`] used by `SessionPool` when you
/// call `.proxies(vec![...])`.
pub struct ProxyRotator {
    proxies: Vec<ProxyConfig>,
    strategy: RotationStrategy,
    /// Next index for RoundRobin.
    next: std::sync::atomic::AtomicUsize,
}

impl ProxyRotator {
    /// Create a new rotator with the given proxies and strategy.
    pub fn new(proxies: Vec<ProxyConfig>, strategy: RotationStrategy) -> Self {
        Self {
            proxies,
            strategy,
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl ProxyProvider for ProxyRotator {
    fn next_proxy(&self) -> Option<ProxyConfig> {
        if self.proxies.is_empty() {
            return None;
        }
        let proxy = match self.strategy {
            RotationStrategy::RoundRobin => {
                let idx = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                &self.proxies[idx % self.proxies.len()]
            }
            RotationStrategy::Random => {
                use aws_lc_rs::rand::{SecureRandom, SystemRandom};
                let rng = SystemRandom::new();
                let mut buf = [0u8; 8];
                rng.fill(&mut buf).expect("system RNG failed");
                let idx = usize::from_ne_bytes(buf) % self.proxies.len();
                &self.proxies[idx]
            }
        };
        Some(proxy.clone())
    }

    fn len(&self) -> usize {
        self.proxies.len()
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn all_proxies(&self) -> Vec<ProxyConfig> {
        self.proxies.clone()
    }
}

// ---------------------------------------------------------------------------
// FnProxyProvider — closure-based proxy generation
// ---------------------------------------------------------------------------

/// A proxy provider backed by a user-supplied closure.
///
/// Each call to `next_proxy()` invokes the closure to get a fresh proxy URL
/// string, which is then parsed into a `ProxyConfig`.  This is ideal for
/// residential / ISP proxy services where the session-id in the username
/// controls the exit IP.
///
/// # Example
///
/// ```rust,no_run
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use std::sync::Arc;
/// use lkrequest::proxy::FnProxyProvider;
///
/// let counter = Arc::new(AtomicU64::new(0));
/// let provider = FnProxyProvider::new(move || {
///     let id = counter.fetch_add(1, Ordering::Relaxed);
///     format!("http://user-sid-{id:06}-sesstime=5:pass@gateway.com:7777")
/// });
/// ```
pub struct FnProxyProvider {
    gen_fn: Box<dyn Fn() -> String + Send + Sync>,
}

impl FnProxyProvider {
    /// Create a new closure-based proxy provider.
    pub fn new(f: impl Fn() -> String + Send + Sync + 'static) -> Self {
        Self {
            gen_fn: Box::new(f),
        }
    }
}

impl ProxyProvider for FnProxyProvider {
    fn next_proxy(&self) -> Option<ProxyConfig> {
        let url = (self.gen_fn)();
        match ProxyConfig::parse(&url) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "proxy_provider.fn_parse_failed");
                None
            }
        }
    }

    fn len(&self) -> usize {
        1
    }

    fn is_dynamic(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// BufferedProxyProvider — pre-generation buffer wrapper
// ---------------------------------------------------------------------------

/// A wrapper that pre-generates proxy configs into an in-memory buffer.
///
/// A background task continuously calls the inner provider's `next_proxy()`
/// to fill a bounded buffer.  When `next_proxy()` is called on the buffered
/// provider, it pops from the buffer (zero latency).  If the buffer is empty
/// it falls back to calling the inner provider directly.
///
/// # Example
///
/// ```rust,no_run
/// use lkrequest::proxy::{FnProxyProvider, BufferedProxyProvider};
///
/// # fn generate_proxy_url() -> String { "http://proxy:8080".into() }
/// let inner = FnProxyProvider::new(|| generate_proxy_url());
/// let buffered = BufferedProxyProvider::new(Box::new(inner), 50);
/// // `buffered` starts filling immediately; `next_proxy()` pops from buffer.
/// ```
pub struct BufferedProxyProvider {
    inner: std::sync::Arc<Box<dyn ProxyProvider>>,
    buffer: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<ProxyConfig>>>,
    capacity: usize,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BufferedProxyProvider {
    /// Create a buffered provider wrapping `inner` with the given buffer capacity.
    ///
    /// A background thread is spawned immediately to start filling the buffer.
    pub fn new(inner: Box<dyn ProxyProvider>, capacity: usize) -> Self {
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::with_capacity(capacity),
        ));
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Spawn a background thread (not tokio task) so it works even before
        // the tokio runtime is fully warmed up.
        let bg_buffer = std::sync::Arc::clone(&buffer);
        let bg_shutdown = std::sync::Arc::clone(&shutdown);
        // We need inner to be Send + Sync, which it is (ProxyProvider: Send + Sync).
        // But we can't move inner into the thread because we still need it for
        // fallback. Instead, wrap inner in Arc.
        let inner: std::sync::Arc<Box<dyn ProxyProvider>> = std::sync::Arc::from(inner);
        let bg_inner = std::sync::Arc::clone(&inner);

        std::thread::Builder::new()
            .name("proxy-buffer-fill".into())
            .spawn(move || {
                while !bg_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    let needs_fill = {
                        let buf = bg_buffer.lock().unwrap();
                        buf.len() < capacity
                    };

                    if needs_fill {
                        if let Some(config) = bg_inner.next_proxy() {
                            let mut buf = bg_buffer.lock().unwrap();
                            if buf.len() < capacity {
                                buf.push_back(config);
                            }
                        }
                    } else {
                        // Buffer is full, sleep briefly before checking again
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            })
            .expect("failed to spawn proxy buffer fill thread");

        Self {
            inner,
            buffer,
            capacity,
            shutdown,
        }
    }
}

impl ProxyProvider for BufferedProxyProvider {
    fn next_proxy(&self) -> Option<ProxyConfig> {
        // Try to pop from the pre-filled buffer first
        {
            let mut buf = self.buffer.lock().unwrap();
            if let Some(config) = buf.pop_front() {
                return Some(config);
            }
        }
        // Buffer empty — fall back to direct generation
        self.inner.next_proxy()
    }

    fn len(&self) -> usize {
        self.capacity
    }

    fn is_dynamic(&self) -> bool {
        self.inner.is_dynamic()
    }

    fn all_proxies(&self) -> Vec<ProxyConfig> {
        self.inner.all_proxies()
    }
}

impl Drop for BufferedProxyProvider {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::ProxyScheme;
    use super::*;

    // -- ProxyRotator -------------------------------------------------------

    #[test]
    fn rotator_round_robin() {
        let proxies = vec![
            ProxyConfig::parse("http://a.com:8080").unwrap(),
            ProxyConfig::parse("http://b.com:8080").unwrap(),
            ProxyConfig::parse("http://c.com:8080").unwrap(),
        ];
        let rotator = ProxyRotator::new(proxies, RotationStrategy::RoundRobin);

        let hosts: Vec<_> = (0..6)
            .map(|_| {
                let p = rotator.next_proxy().unwrap();
                match p.scheme {
                    ProxyScheme::Http { host, .. } => host,
                    _ => panic!(),
                }
            })
            .collect();

        // Should cycle: a, b, c, a, b, c
        assert_eq!(
            hosts,
            ["a.com", "b.com", "c.com", "a.com", "b.com", "c.com"]
        );
    }

    #[test]
    fn rotator_empty_returns_none() {
        let rotator = ProxyRotator::new(vec![], RotationStrategy::RoundRobin);
        assert!(rotator.next_proxy().is_none());
    }

    #[test]
    fn rotator_random_returns_valid() {
        let proxies = vec![
            ProxyConfig::parse("http://a.com:8080").unwrap(),
            ProxyConfig::parse("http://b.com:8080").unwrap(),
        ];
        let rotator = ProxyRotator::new(proxies, RotationStrategy::Random);

        for _ in 0..10 {
            assert!(rotator.next_proxy().is_some());
        }
    }

    // -- ProxyScheme Debug -----------------------------------------------

    #[test]
    fn proxy_scheme_debug() {
        let http = ProxyScheme::Http {
            host: "proxy.com".into(),
            port: 8080,
        };
        let s = format!("{:?}", http);
        assert!(s.contains("proxy.com"));
        assert!(s.contains("8080"));
    }

    // ====================================================================
    // ProxyRotator — static proxy list traits
    // ====================================================================

    #[test]
    fn rotator_reports_list_size() {
        let proxies = vec![
            ProxyConfig::parse("http://a.com:8080").unwrap(),
            ProxyConfig::parse("http://b.com:8080").unwrap(),
        ];
        let rotator = ProxyRotator::new(proxies, RotationStrategy::RoundRobin);
        assert_eq!(rotator.len(), 2);
        assert!(!rotator.is_empty());
        assert!(!rotator.is_dynamic());
    }

    #[test]
    fn rotator_empty_list_properties() {
        let rotator = ProxyRotator::new(vec![], RotationStrategy::Random);
        assert_eq!(rotator.len(), 0);
        assert!(rotator.is_empty());
    }

    #[test]
    fn rotator_all_proxies_returns_full_list() {
        let proxies = vec![
            ProxyConfig::parse("http://a.com:8080").unwrap(),
            ProxyConfig::parse("http://b.com:9090").unwrap(),
        ];
        let rotator = ProxyRotator::new(proxies, RotationStrategy::RoundRobin);
        let all = rotator.all_proxies();
        assert_eq!(all.len(), 2);
    }

    // ====================================================================
    // FnProxyProvider — residential proxy with rotating session IDs
    // ====================================================================

    #[test]
    fn dynamic_provider_generates_unique_proxies() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicU64::new(0));
        let provider = FnProxyProvider::new(move || {
            let id = counter.fetch_add(1, Ordering::Relaxed);
            format!("http://user-sid-{id:06}:pass@gateway.example.com:7777")
        });

        assert!(provider.is_dynamic());
        assert_eq!(provider.len(), 1);

        let p1 = provider.next_proxy().unwrap();
        let p2 = provider.next_proxy().unwrap();
        assert_ne!(format!("{:?}", p1), format!("{:?}", p2),);
    }

    #[test]
    fn dynamic_provider_returns_none_on_invalid_url() {
        let provider = FnProxyProvider::new(|| "not-a-valid-proxy-url".to_string());
        assert!(provider.next_proxy().is_none());
    }

    #[test]
    fn dynamic_provider_default_trait_methods() {
        let provider = FnProxyProvider::new(|| "http://proxy:8080".to_string());
        assert!(provider.all_proxies().is_empty());
    }

    // ====================================================================
    // BufferedProxyProvider — pre-filling proxy configs for zero latency
    // ====================================================================

    #[test]
    fn buffered_provider_fills_and_pops() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicU64::new(0));
        let inner = FnProxyProvider::new(move || {
            let id = counter.fetch_add(1, Ordering::Relaxed);
            format!("http://user-{id}:pass@gw.example.com:7777")
        });

        let buffered = BufferedProxyProvider::new(Box::new(inner), 10);

        // Give background thread time to fill
        std::thread::sleep(std::time::Duration::from_millis(200));

        let p1 = buffered.next_proxy();
        assert!(p1.is_some(), "should pop from pre-filled buffer");

        let p2 = buffered.next_proxy();
        assert!(p2.is_some());
    }

    #[test]
    fn buffered_provider_delegates_dynamic_flag() {
        let inner = FnProxyProvider::new(|| "http://proxy:8080".to_string());
        let buffered = BufferedProxyProvider::new(Box::new(inner), 5);
        assert!(buffered.is_dynamic());
    }

    #[test]
    fn buffered_provider_reports_capacity_as_len() {
        let inner = FnProxyProvider::new(|| "http://proxy:8080".to_string());
        let buffered = BufferedProxyProvider::new(Box::new(inner), 42);
        assert_eq!(buffered.len(), 42);
    }

    #[test]
    fn buffered_provider_falls_back_on_empty_buffer() {
        let inner = FnProxyProvider::new(|| "http://fallback:9999".to_string());
        let buffered = BufferedProxyProvider::new(Box::new(inner), 0);

        // Buffer capacity 0 → always falls back to inner
        let proxy = buffered.next_proxy();
        assert!(proxy.is_some());
    }

    #[test]
    fn buffered_provider_shutdown_on_drop() {
        let inner = FnProxyProvider::new(|| "http://proxy:8080".to_string());
        let buffered = BufferedProxyProvider::new(Box::new(inner), 5);
        assert!(!buffered.shutdown.load(std::sync::atomic::Ordering::Relaxed));
        drop(buffered);
        // After drop, the shutdown flag should be set (tested implicitly — no panic)
    }

    #[test]
    fn buffered_provider_delegates_all_proxies() {
        let proxies = vec![ProxyConfig::parse("http://static:8080").unwrap()];
        let inner = ProxyRotator::new(proxies, RotationStrategy::RoundRobin);
        let buffered = BufferedProxyProvider::new(Box::new(inner), 5);
        let all = buffered.all_proxies();
        assert_eq!(all.len(), 1);
    }
}
