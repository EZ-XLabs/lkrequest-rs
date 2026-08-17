//! DNS resolver abstraction — pluggable DNS resolution for lkrequest.
//!
//! By default, lkrequest uses the operating system's DNS resolver
//! ([`SystemDns`]).  For advanced use cases — custom DNS servers, DNS over
//! HTTPS (DoH), DNS over TLS (DoT), or automatic ECH configuration via
//! HTTPS resource records — use [`HickoryDns`].
//!
//! ## Architecture
//!
//! ```text
//! DnsResolver (trait)
//! ├── SystemDns     — tokio::net::lookup_host (OS resolver)
//! └── HickoryDns    — hickory-resolver (custom servers, DoH/DoT, HTTPS RR)
//! ```
//!
//! The resolver is configured at the [`Client`](crate::Client) level and
//! shared by all [`Session`](crate::Session)s created from that client.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::config::ConnectionConfig;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DnsResolver trait
// ---------------------------------------------------------------------------

/// Trait for pluggable DNS resolution.
///
/// Implement this trait to provide custom DNS resolution behavior.
/// The default implementation ([`SystemDns`]) delegates to the OS resolver.
#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    /// Exposes the concrete resolver implementation name for diagnostics/tests.
    #[doc(hidden)]
    fn resolver_impl_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    /// Resolve a hostname to a list of socket addresses.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;

    /// Query DNS HTTPS resource records (type 65) for a hostname.
    ///
    /// Returns structured data from the HTTPS/SVCB record, including
    /// ECH configuration if present.  The default implementation returns
    /// `Ok(None)` — only resolvers that support arbitrary record types
    /// (like [`HickoryDns`]) can provide this.
    ///
    /// **Note:** Implementations may map lookup failures to `Ok(None)` so that
    /// a missing record is indistinguishable from a resolver error. Enable
    /// `tracing` at `debug` for `HickoryDns` (`dns.https_lookup_failed`) when
    /// troubleshooting ECH or HTTPS RR behavior.
    async fn lookup_https(&self, _host: &str) -> io::Result<Option<HttpsRecord>> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// HttpsRecord
// ---------------------------------------------------------------------------

/// Parsed data from a DNS HTTPS resource record (type 65, RFC 9460).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpsRecord {
    /// ECHConfigList binary data (from the `ech` SvcParam).
    /// Ready to pass directly to `lktls::ech::config::parse_ech_config_list()`.
    pub ech_config_list: Option<Vec<u8>>,
    /// ALPN protocol identifiers (from the `alpn` SvcParam).
    pub alpn: Vec<String>,
    /// Target name (from the SVCB TargetName field), if not `.` (alias mode).
    pub target: Option<String>,
    /// Alternative port from the `port` SvcParam.
    pub port: Option<u16>,
    /// IPv4 hints from the `ipv4hint` SvcParam.
    pub ipv4_hints: Vec<Ipv4Addr>,
    /// IPv6 hints from the `ipv6hint` SvcParam.
    pub ipv6_hints: Vec<Ipv6Addr>,
}

impl HttpsRecord {
    /// Returns `true` if the HTTPS RR advertises HTTP/3 support.
    pub fn supports_h3(&self) -> bool {
        self.alpn
            .iter()
            .any(|proto| proto == "h3" || proto.starts_with("h3-"))
    }
}

// ---------------------------------------------------------------------------
// DnsConfig — convenience enum for ClientBuilder
// ---------------------------------------------------------------------------

/// DNS resolver configuration presets.
///
/// Used with [`ClientBuilder::dns()`](crate::client::ClientBuilder::dns) to
/// select a DNS resolver without constructing one manually.
///
/// # Example
///
/// ```rust,no_run
/// use lkrequest::{Client, DnsConfig};
///
/// let client = Client::builder()
///     .dns(DnsConfig::CloudflareHttps)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub enum DnsConfig {
    /// Use the operating system's DNS resolver (default).
    System,
    /// Google Public DNS (8.8.8.8 / 8.8.4.4, UDP).
    Google,
    /// Google Public DNS over HTTPS.
    GoogleHttps,
    /// Cloudflare DNS (1.1.1.1 / 1.0.0.1, UDP).
    Cloudflare,
    /// Cloudflare DNS over HTTPS.
    CloudflareHttps,
    /// Quad9 DNS (9.9.9.9, UDP, DNSSEC-validating).
    Quad9,
    /// Quad9 DNS over HTTPS.
    Quad9Https,
    /// Custom DNS server (plain UDP/TCP).
    Custom(SocketAddr),
}

impl DnsConfig {
    /// Build an `Arc<dyn DnsResolver>` from this config.
    pub fn build_resolver(&self) -> Arc<dyn DnsResolver> {
        match self {
            DnsConfig::System => Arc::new(SystemDns),
            _ => Arc::new(HickoryDns::from_config(self)),
        }
    }
}

// ---------------------------------------------------------------------------
// SystemDns — OS resolver (default)
// ---------------------------------------------------------------------------

/// DNS resolver that delegates to the operating system via
/// `tokio::net::lookup_host` (which calls `getaddrinfo`).
///
/// This is the default resolver and matches the behavior of lkrequest
/// before custom DNS support was added. Concurrent lookups for the same
/// `(host, port)` are coalesced process-wide, but completed results are not
/// cached. It does **not** support HTTPS record queries or custom DNS servers.
#[derive(Debug, Clone, Copy)]
pub struct SystemDns;

impl SystemDns {
    /// Create a system resolver with an instance-local positive-result cache.
    ///
    /// The underlying operating-system lookup still uses the process-wide
    /// singleflight group. Only successful, non-empty address lists are cached.
    pub fn with_cache(config: SystemDnsCacheConfig) -> CachedSystemDns {
        CachedSystemDns::new(config)
    }
}

/// Configuration for the optional [`SystemDns`] positive-result cache.
///
/// `SystemDns` does not cache by default. A zero TTL or zero capacity disables
/// this cache while retaining process-wide in-flight lookup coalescing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemDnsCacheConfig {
    positive_ttl: Duration,
    max_entries: usize,
}

impl SystemDnsCacheConfig {
    /// Create a positive-result cache with a default capacity of 1024 entries.
    pub fn positive(positive_ttl: Duration) -> Self {
        Self {
            positive_ttl,
            max_entries: 1024,
        }
    }

    /// Set the maximum number of cached `(host, port)` entries.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Return the configured positive-result TTL.
    pub fn positive_ttl(&self) -> Duration {
        self.positive_ttl
    }

    /// Return the maximum cache capacity.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    fn is_enabled(&self) -> bool {
        !self.positive_ttl.is_zero() && self.max_entries > 0
    }
}

#[derive(Debug, Clone)]
struct CachedSystemDnsEntry {
    addresses: Arc<[SocketAddr]>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct SystemDnsCache {
    entries: HashMap<SystemDnsLookupKey, CachedSystemDnsEntry>,
}

/// A [`SystemDns`] resolver with an instance-local positive-result cache.
///
/// Share this resolver through `Arc<dyn DnsResolver>` when multiple clients
/// should use the same cache. Errors and empty results are never cached.
#[derive(Debug)]
pub struct CachedSystemDns {
    config: SystemDnsCacheConfig,
    cache: Mutex<SystemDnsCache>,
}

impl CachedSystemDns {
    fn new(config: SystemDnsCacheConfig) -> Self {
        Self {
            config,
            cache: Mutex::new(SystemDnsCache::default()),
        }
    }

    fn get_cached(&self, key: &SystemDnsLookupKey) -> Option<Arc<[SocketAddr]>> {
        if !self.config.is_enabled() {
            return None;
        }

        let now = Instant::now();
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match cache.entries.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.addresses.clone()),
            Some(_) => {
                tracing::trace!(
                    host = %key.host,
                    port = key.port,
                    "dns.resolve_cache_expired"
                );
                cache.entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn insert_cached(&self, key: SystemDnsLookupKey, addresses: Arc<[SocketAddr]>) {
        if !self.config.is_enabled() || addresses.is_empty() {
            return;
        }

        let now = Instant::now();
        let Some(expires_at) = now.checked_add(self.config.positive_ttl) else {
            tracing::debug!(
                host = %key.host,
                port = key.port,
                ttl_ms = self.config.positive_ttl.as_millis() as u64,
                "dns.resolve_cache_ttl_overflow"
            );
            return;
        };
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.entries.retain(|_, entry| entry.expires_at > now);

        if cache.entries.len() >= self.config.max_entries && !cache.entries.contains_key(&key) {
            if let Some(oldest_key) = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                tracing::trace!(
                    host = %oldest_key.host,
                    port = oldest_key.port,
                    "dns.resolve_cache_evicted"
                );
                cache.entries.remove(&oldest_key);
            }
        }

        cache.entries.insert(
            key,
            CachedSystemDnsEntry {
                addresses,
                expires_at,
            },
        );
    }

    async fn resolve_with<F, Fut>(
        &self,
        host: &str,
        port: u16,
        lookup: F,
    ) -> io::Result<Vec<SocketAddr>>
    where
        F: FnOnce(String, u16) -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'static,
    {
        let key = SystemDnsLookupKey::new(host, port);
        if let Some(addresses) = self.get_cached(&key) {
            tracing::debug!(
                host = %host,
                port,
                resolver = "system",
                addr_count = addresses.len(),
                "dns.resolve_cache_hit"
            );
            return Ok(addresses.as_ref().to_vec());
        }

        tracing::debug!(host = %host, port, resolver = "system", "dns.resolve_cache_miss");
        let addresses = system_dns_flight_group()
            .resolve_with(host, port, lookup)
            .await?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DNS resolution returned no addresses for {host}"),
            ));
        }

        let addresses: Arc<[SocketAddr]> = Arc::from(addresses);
        self.insert_cached(key, addresses.clone());
        tracing::debug!(
            host = %host,
            port,
            resolver = "system",
            addr_count = addresses.len(),
            "dns.resolve_success"
        );
        Ok(addresses.as_ref().to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SystemDnsLookupKey {
    host: Arc<str>,
    port: u16,
}

impl SystemDnsLookupKey {
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: Arc::from(host),
            port,
        }
    }
}

#[derive(Debug, Clone)]
struct SharedLookupError {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: Arc<str>,
}

impl SharedLookupError {
    fn from_io_error(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: Arc::from(error.to_string()),
        }
    }

    fn to_io_error(&self) -> io::Error {
        if let Some(code) = self.raw_os_error {
            let error = io::Error::from_raw_os_error(code);
            if error.to_string() == self.message.as_ref() {
                return error;
            }
        }

        io::Error::new(self.kind, self.message.to_string())
    }
}

type SharedLookupResult = Result<Arc<[SocketAddr]>, SharedLookupError>;

#[derive(Debug)]
struct InFlightLookup {
    result: tokio::sync::watch::Receiver<Option<SharedLookupResult>>,
    waiter_count: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Default)]
struct SystemDnsFlightGroup {
    entries: Mutex<HashMap<SystemDnsLookupKey, Arc<InFlightLookup>>>,
}

struct InFlightTaskGuard {
    group: Arc<SystemDnsFlightGroup>,
    key: SystemDnsLookupKey,
    entry: Arc<InFlightLookup>,
    sender: Option<tokio::sync::watch::Sender<Option<SharedLookupResult>>>,
}

impl InFlightTaskGuard {
    fn complete(mut self, result: SharedLookupResult) {
        if let Some(sender) = self.sender.take() {
            sender.send_replace(Some(result));
        }
        self.remove_entry();
    }

    fn remove_entry(&self) {
        let mut entries = self
            .group
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.entry))
        {
            entries.remove(&self.key);
        }
    }
}

impl Drop for InFlightTaskGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            tracing::debug!(
                host = %self.key.host,
                port = self.key.port,
                waiter_count = self
                    .entry
                    .waiter_count
                    .load(std::sync::atomic::Ordering::Relaxed),
                "dns.system_lookup_cancelled"
            );
            sender.send_replace(Some(Err(SharedLookupError::from_io_error(io::Error::new(
                io::ErrorKind::Interrupted,
                "system DNS lookup task cancelled",
            )))));
            self.remove_entry();
        }
    }
}

impl SystemDnsFlightGroup {
    async fn resolve_with<F, Fut>(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        lookup: F,
    ) -> io::Result<Vec<SocketAddr>>
    where
        F: FnOnce(String, u16) -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'static,
    {
        let key = SystemDnsLookupKey::new(host, port);
        let mut lookup = Some(lookup);
        let (entry, leader_sender) = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = entries.get(&key) {
                entry
                    .waiter_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                (entry.clone(), None)
            } else {
                let (sender, receiver) = tokio::sync::watch::channel(None);
                let entry = Arc::new(InFlightLookup {
                    result: receiver,
                    waiter_count: std::sync::atomic::AtomicUsize::new(0),
                });
                entries.insert(key.clone(), entry.clone());
                (entry, Some(sender))
            }
        };

        if let Some(sender) = leader_sender {
            let group = self.clone();
            let task_key = key.clone();
            let task_entry = entry.clone();
            let lookup = lookup.take().expect("singleflight leader owns lookup");
            tokio::spawn(async move {
                let started_at = Instant::now();
                let guard = InFlightTaskGuard {
                    group,
                    key: task_key.clone(),
                    entry: task_entry.clone(),
                    sender: Some(sender),
                };
                let result = lookup(task_key.host.to_string(), task_key.port)
                    .await
                    .map(Arc::<[SocketAddr]>::from)
                    .map_err(SharedLookupError::from_io_error);
                let elapsed_ms = started_at.elapsed().as_millis() as u64;
                let waiter_count = task_entry
                    .waiter_count
                    .load(std::sync::atomic::Ordering::Relaxed);
                match &result {
                    Ok(addresses) => tracing::debug!(
                        host = %task_key.host,
                        port = task_key.port,
                        addr_count = addresses.len(),
                        waiter_count,
                        elapsed_ms,
                        "dns.system_lookup_success"
                    ),
                    Err(error) => tracing::debug!(
                        host = %task_key.host,
                        port = task_key.port,
                        error_kind = ?error.kind,
                        error = %error.message,
                        waiter_count,
                        elapsed_ms,
                        "dns.system_lookup_failed"
                    ),
                }
                guard.complete(result);
            });
            tracing::trace!(host, port, role = "leader", "dns.system_singleflight");
        } else {
            tracing::trace!(host, port, role = "waiter", "dns.system_singleflight");
        }

        let mut receiver = entry.result.clone();
        loop {
            if let Some(result) = { receiver.borrow().clone() } {
                return result
                    .map(|addresses| addresses.as_ref().to_vec())
                    .map_err(|error| error.to_io_error());
            }

            if receiver.changed().await.is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "system DNS lookup task ended without a result",
                ));
            }
        }
    }
}

fn system_dns_flight_group() -> &'static Arc<SystemDnsFlightGroup> {
    static GROUP: OnceLock<Arc<SystemDnsFlightGroup>> = OnceLock::new();
    GROUP.get_or_init(|| Arc::new(SystemDnsFlightGroup::default()))
}

async fn perform_system_lookup(host: String, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addr = format!("{host}:{port}");
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host(addr).await?.collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("DNS resolution returned no addresses for {host}"),
        ));
    }
    Ok(addresses)
}

#[async_trait]
impl DnsResolver for SystemDns {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        tracing::debug!(host = %host, port, resolver = "system", "dns.resolve_start");
        let addrs = system_dns_flight_group()
            .resolve_with(host, port, perform_system_lookup)
            .await?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DNS resolution returned no addresses for {host}"),
            ));
        }
        tracing::debug!(
            host = %host,
            port,
            resolver = "system",
            addr_count = addrs.len(),
            "dns.resolve_success"
        );
        Ok(addrs)
    }
}

#[async_trait]
impl DnsResolver for CachedSystemDns {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.resolve_with(host, port, perform_system_lookup).await
    }
}

// ---------------------------------------------------------------------------
// HickoryDns — hickory-resolver based resolver
// ---------------------------------------------------------------------------

use hickory_resolver::config::{
    NameServerConfig, ResolverConfig, ResolverOpts, CLOUDFLARE, GOOGLE, QUAD9,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

/// Panic message used by the infallible constructors when resolver
/// initialization fails. The fallible `try_*` variants surface the real error.
const RESOLVER_INIT_PANIC_MSG: &str = "hickory resolver init failed (platform certificate store?)";

/// DNS resolver backed by [`hickory-resolver`](https://docs.rs/hickory-resolver).
///
/// Supports custom DNS servers, DNS over HTTPS (DoH), DNS over TLS (DoT),
/// built-in caching, and HTTPS resource record queries (for ECH auto-config).
pub struct HickoryDns {
    resolver: TokioResolver,
}

impl std::fmt::Debug for HickoryDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryDns").finish_non_exhaustive()
    }
}

impl HickoryDns {
    /// Create a `HickoryDns` resolver from a [`DnsConfig`] preset.
    ///
    /// # Panics
    ///
    /// Panics if the underlying resolver cannot be initialized; see
    /// [`with_config`](Self::with_config) for the conditions. Use
    /// [`try_from_config`](Self::try_from_config) for a non-panicking variant.
    pub fn from_config(config: &DnsConfig) -> Self {
        Self::try_from_config(config).expect(RESOLVER_INIT_PANIC_MSG)
    }

    /// Fallible variant of [`from_config`](Self::from_config).
    ///
    /// Returns an error instead of panicking when the resolver cannot be
    /// initialized (typically a platform certificate-store load failure).
    /// Prefer this in long-running services that must not crash on a transient
    /// environment fault.
    pub fn try_from_config(config: &DnsConfig) -> Result<Self, hickory_resolver::net::NetError> {
        let resolver_config = match config {
            DnsConfig::System => {
                // Shouldn't normally reach here, but handle gracefully
                ResolverConfig::default()
            }
            DnsConfig::Google => ResolverConfig::udp_and_tcp(&GOOGLE),
            DnsConfig::GoogleHttps => ResolverConfig::https(&GOOGLE),
            DnsConfig::Cloudflare => ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            DnsConfig::CloudflareHttps => ResolverConfig::https(&CLOUDFLARE),
            DnsConfig::Quad9 => ResolverConfig::udp_and_tcp(&QUAD9),
            DnsConfig::Quad9Https => ResolverConfig::https(&QUAD9),
            DnsConfig::Custom(addr) => {
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = addr.port();
                let name_server = NameServerConfig::new(addr.ip(), true, vec![udp, tcp]);
                ResolverConfig::from_parts(None, vec![], vec![name_server])
            }
        };

        Self::try_with_config(resolver_config, ResolverOpts::default())
    }

    /// Create a `HickoryDns` resolver with explicit config and options.
    ///
    /// # Panics
    ///
    /// Panics if the resolver cannot be initialized. In practice this only
    /// happens when the platform certificate store fails to load — which is
    /// attempted even for plain UDP configurations, because the DoH/DoT
    /// transport features are enabled in this build. Use
    /// [`try_with_config`](Self::try_with_config) to handle this failure
    /// instead of panicking.
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Self {
        Self::try_with_config(config, opts).expect(RESOLVER_INIT_PANIC_MSG)
    }

    /// Fallible variant of [`with_config`](Self::with_config).
    ///
    /// Returns an error instead of panicking when the resolver cannot be
    /// initialized (e.g. the platform certificate store fails to load). Prefer
    /// this in long-running services that must not crash on a transient
    /// environment fault.
    pub fn try_with_config(
        config: ResolverConfig,
        opts: ResolverOpts,
    ) -> Result<Self, hickory_resolver::net::NetError> {
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()?;
        Ok(Self { resolver })
    }

    /// Create a `HickoryDns` from a pre-built `TokioResolver`.
    pub fn from_resolver(resolver: TokioResolver) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl DnsResolver for HickoryDns {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        tracing::debug!(host = %host, port, resolver = "hickory", "dns.resolve_start");
        let response = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| io::Error::other(format!("DNS resolution failed for {host}: {e}")))?;

        let addrs: Vec<SocketAddr> = response
            .iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();

        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DNS resolution returned no addresses for {host}"),
            ));
        }

        tracing::debug!(
            host = %host,
            port,
            resolver = "hickory",
            addr_count = addrs.len(),
            "dns.resolve_success"
        );
        Ok(addrs)
    }

    async fn lookup_https(&self, host: &str) -> io::Result<Option<HttpsRecord>> {
        tracing::debug!(host = %host, resolver = "hickory", "dns.https_lookup_start");
        let response = match self.resolver.lookup(host, RecordType::HTTPS).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(host = %host, error = %e, "dns.https_lookup_failed");
                let e_dbg = format!("{e:?}");
                if e_dbg.contains("NoRecordsFound") || e.to_string().contains("no record found") {
                    return Ok(None);
                }
                return Err(io::Error::other(e.to_string()));
            }
        };

        let mut candidates = Vec::new();

        for record in response.answers() {
            let RData::HTTPS(https) = &record.data else {
                continue;
            };

            let svcb = &https.0;
            let mut result = HttpsRecord::default();

            let target = svcb.target_name.to_string();
            if let Some(target) = normalize_https_target(&target) {
                result.target = Some(target);
            }

            for (_, value) in svcb.svc_params.iter() {
                apply_https_svc_param(&mut result, value);
            }

            candidates.push((svcb.svc_priority, result));
        }

        let selected = select_https_record(candidates);
        tracing::debug!(
            host = %host,
            has_record = selected.is_some(),
            alpn = ?selected.as_ref().map(|record| &record.alpn),
            target = ?selected.as_ref().and_then(|record| record.target.as_deref()),
            port = ?selected.as_ref().and_then(|record| record.port),
            "dns.https_lookup_complete"
        );
        Ok(selected)
    }
}

fn apply_https_svc_param(result: &mut HttpsRecord, value: &SvcParamValue) {
    match value {
        SvcParamValue::EchConfigList(ech) => {
            result.ech_config_list = Some(ech.0.clone());
        }
        SvcParamValue::Alpn(alpn) => {
            result.alpn = alpn.0.iter().map(|s| s.to_string()).collect();
        }
        SvcParamValue::Port(port) => {
            result.port = Some(*port);
        }
        SvcParamValue::Ipv4Hint(hints) => {
            result.ipv4_hints = hints.0.iter().copied().map(Into::into).collect();
        }
        SvcParamValue::Ipv6Hint(hints) => {
            result.ipv6_hints = hints.0.iter().copied().map(Into::into).collect();
        }
        _ => {}
    }
}

fn normalize_https_target(target: &str) -> Option<String> {
    let normalized = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn select_https_record(mut candidates: Vec<(u16, HttpsRecord)>) -> Option<HttpsRecord> {
    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by_key(|(priority, _)| *priority);
    let best_priority = candidates[0].0;
    let mut merged = HttpsRecord::default();

    for (_, record) in candidates
        .into_iter()
        .take_while(|(priority, _)| *priority == best_priority)
    {
        merge_https_record(&mut merged, record);
    }

    Some(merged)
}

fn merge_https_record(target: &mut HttpsRecord, candidate: HttpsRecord) {
    if target.ech_config_list.is_none() {
        target.ech_config_list = candidate.ech_config_list;
    }
    if target.target.is_none() {
        target.target = candidate.target;
    }
    if target.port.is_none() {
        target.port = candidate.port;
    }

    for alpn in candidate.alpn {
        if !target.alpn.contains(&alpn) {
            target.alpn.push(alpn);
        }
    }
    for hint in candidate.ipv4_hints {
        if !target.ipv4_hints.contains(&hint) {
            target.ipv4_hints.push(hint);
        }
    }
    for hint in candidate.ipv6_hints {
        if !target.ipv6_hints.contains(&hint) {
            target.ipv6_hints.push(hint);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::rdata::{svcb::IpHint, A, AAAA};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn system_dns_resolves_localhost() {
        let dns = SystemDns;
        let addrs = dns.resolve("localhost", 80).await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 80));
    }

    #[tokio::test]
    async fn system_dns_lookup_https_returns_none() {
        let dns = SystemDns;
        let result = dns.lookup_https("example.com").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn system_dns_coalesces_concurrent_identical_lookups() {
        let group = Arc::new(SystemDnsFlightGroup::default());
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..100 {
            let group = group.clone();
            let lookup_count = lookup_count.clone();
            tasks.spawn(async move {
                group
                    .resolve_with("singleflight.test", 443, move |_host, port| async move {
                        lookup_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
                    })
                    .await
            });
        }

        while let Some(result) = tasks.join_next().await {
            assert_eq!(
                result.unwrap().unwrap(),
                vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
            );
        }

        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn system_dns_removes_completed_and_failed_flights() {
        let group = Arc::new(SystemDnsFlightGroup::default());
        let lookup_count = Arc::new(AtomicUsize::new(0));

        let first_count = lookup_count.clone();
        let first = group
            .resolve_with("cleanup.test", 443, move |_host, _port| async move {
                first_count.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
            })
            .await
            .unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::NotFound);

        let second_count = lookup_count.clone();
        let second = group
            .resolve_with("cleanup.test", 443, move |_host, port| async move {
                second_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
            })
            .await
            .unwrap();

        assert_eq!(
            second,
            vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
        );
        assert_eq!(lookup_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn system_dns_does_not_cache_completed_successes() {
        let group = Arc::new(SystemDnsFlightGroup::default());
        let lookup_count = Arc::new(AtomicUsize::new(0));

        let first_count = lookup_count.clone();
        let first = group
            .resolve_with("no-cache.test", 443, move |_host, port| async move {
                first_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
            })
            .await
            .unwrap();
        assert_eq!(
            first,
            vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
        );

        let second_count = lookup_count.clone();
        let second = group
            .resolve_with("no-cache.test", 443, move |_host, port| async move {
                second_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(
                    Ipv4Addr::new(192, 0, 2, 10).into(),
                    port,
                )])
            })
            .await
            .unwrap();
        assert_eq!(
            second,
            vec![SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 443)]
        );
        assert_eq!(lookup_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn system_dns_keeps_different_ports_in_separate_flights() {
        let group = Arc::new(SystemDnsFlightGroup::default());
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for port in [80, 443] {
            let group = group.clone();
            let lookup_count = lookup_count.clone();
            tasks.spawn(async move {
                group
                    .resolve_with("key.test", port, move |_host, port| async move {
                        lookup_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
                    })
                    .await
            });
        }

        let mut resolved_ports = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let addresses = result.unwrap().unwrap();
            assert_eq!(addresses.len(), 1);
            resolved_ports.push(addresses[0].port());
        }
        resolved_ports.sort_unstable();
        assert_eq!(resolved_ports, vec![80, 443]);
        assert_eq!(lookup_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn system_dns_coalesces_concurrent_errors() {
        let group = Arc::new(SystemDnsFlightGroup::default());
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..32 {
            let group = group.clone();
            let lookup_count = lookup_count.clone();
            tasks.spawn(async move {
                group
                    .resolve_with(
                        "singleflight-error.test",
                        443,
                        move |_host, _port| async move {
                            lookup_count.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(30)).await;
                            Err(io::Error::new(io::ErrorKind::TimedOut, "dns timeout"))
                        },
                    )
                    .await
            });
        }

        while let Some(result) = tasks.join_next().await {
            let error = result.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), "dns timeout");
        }
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelling_leader_waiter_does_not_cancel_shared_lookup() {
        let group = Arc::new(SystemDnsFlightGroup::default());
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));

        let leader = {
            let group = group.clone();
            let lookup_count = lookup_count.clone();
            let started = started.clone();
            let release = release.clone();
            tokio::spawn(async move {
                group
                    .resolve_with("cancel.test", 443, move |_host, port| async move {
                        lookup_count.fetch_add(1, Ordering::SeqCst);
                        started.add_permits(1);
                        let permit = release.acquire().await.unwrap();
                        permit.forget();
                        Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
                    })
                    .await
            })
        };

        let started_permit = started.acquire().await.unwrap();
        started_permit.forget();
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());

        let waiter = {
            let group = group.clone();
            let lookup_count = lookup_count.clone();
            tokio::spawn(async move {
                group
                    .resolve_with("cancel.test", 443, move |_host, port| async move {
                        lookup_count.fetch_add(1, Ordering::SeqCst);
                        Ok(vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)])
                    })
                    .await
            })
        };

        tokio::task::yield_now().await;
        release.add_permits(1);
        assert_eq!(
            waiter.await.unwrap().unwrap(),
            vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
        );
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn system_dns_positive_cache_reuses_successful_results() {
        let resolver = Arc::new(CachedSystemDns::new(
            SystemDnsCacheConfig::positive(Duration::from_secs(60)).with_max_entries(8),
        ));
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..32 {
            let resolver = resolver.clone();
            let lookup_count = lookup_count.clone();
            tasks.spawn(async move {
                resolver
                    .resolve_with("cache-hit.test", 443, move |_host, port| async move {
                        lookup_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
                    })
                    .await
            });
        }

        while let Some(result) = tasks.join_next().await {
            let addresses = result.unwrap().unwrap();
            assert_eq!(
                addresses,
                vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
            );
        }
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);

        let cached_count = lookup_count.clone();
        let cached = resolver
            .resolve_with("cache-hit.test", 443, move |_host, port| async move {
                cached_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)])
            })
            .await
            .unwrap();
        assert_eq!(
            cached,
            vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
        );
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn system_dns_positive_cache_expires_and_does_not_cache_errors() {
        let resolver = CachedSystemDns::new(
            SystemDnsCacheConfig::positive(Duration::from_millis(20)).with_max_entries(8),
        );
        let lookup_count = Arc::new(AtomicUsize::new(0));

        let failed_count = lookup_count.clone();
        let error = resolver
            .resolve_with("cache-expiry.test", 443, move |_host, _port| async move {
                failed_count.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::new(io::ErrorKind::TimedOut, "temporary"))
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let success_count = lookup_count.clone();
        resolver
            .resolve_with("cache-expiry.test", 443, move |_host, port| async move {
                success_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
            })
            .await
            .unwrap();
        assert_eq!(lookup_count.load(Ordering::SeqCst), 2);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let expired_count = lookup_count.clone();
        let expired = resolver
            .resolve_with("cache-expiry.test", 443, move |_host, port| async move {
                expired_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)])
            })
            .await
            .unwrap();
        assert_eq!(
            expired,
            vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 443)]
        );
        assert_eq!(lookup_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn system_dns_positive_cache_does_not_cache_empty_results() {
        let resolver = CachedSystemDns::new(
            SystemDnsCacheConfig::positive(Duration::from_secs(60)).with_max_entries(8),
        );
        let lookup_count = Arc::new(AtomicUsize::new(0));

        let empty_count = lookup_count.clone();
        let error = resolver
            .resolve_with("cache-empty.test", 443, move |_host, _port| async move {
                empty_count.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);

        let success_count = lookup_count.clone();
        let addresses = resolver
            .resolve_with("cache-empty.test", 443, move |_host, port| async move {
                success_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
            })
            .await
            .unwrap();
        assert_eq!(
            addresses,
            vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443)]
        );
        assert_eq!(lookup_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn system_dns_positive_cache_enforces_capacity() {
        let resolver = CachedSystemDns::new(
            SystemDnsCacheConfig::positive(Duration::from_secs(60)).with_max_entries(1),
        );
        let lookup_count = Arc::new(AtomicUsize::new(0));

        for host in ["cache-a.test", "cache-b.test", "cache-a.test"] {
            let lookup_count = lookup_count.clone();
            resolver
                .resolve_with(host, 443, move |host, port| async move {
                    lookup_count.fetch_add(1, Ordering::SeqCst);
                    let ip = if host == "cache-b.test" {
                        Ipv4Addr::UNSPECIFIED
                    } else {
                        Ipv4Addr::LOCALHOST
                    };
                    Ok(vec![SocketAddr::new(ip.into(), port)])
                })
                .await
                .unwrap();
        }

        assert_eq!(lookup_count.load(Ordering::SeqCst), 3);
        let cache = resolver
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(cache.entries.len(), 1);
        assert!(cache
            .entries
            .contains_key(&SystemDnsLookupKey::new("cache-a.test", 443)));
    }

    #[test]
    fn system_dns_cache_config_exposes_effective_values() {
        let config = SystemDnsCacheConfig::positive(Duration::from_secs(30)).with_max_entries(4096);
        assert_eq!(config.positive_ttl(), Duration::from_secs(30));
        assert_eq!(config.max_entries(), 4096);
        assert!(config.is_enabled());
        assert!(!SystemDnsCacheConfig::positive(Duration::ZERO).is_enabled());
        assert!(!SystemDnsCacheConfig::positive(Duration::from_secs(30))
            .with_max_entries(0)
            .is_enabled());
    }

    #[test]
    fn dns_config_build_system_resolver() {
        let resolver = DnsConfig::System.build_resolver();
        assert!(resolver.resolver_impl_name().ends_with("SystemDns"));
    }

    #[test]
    fn dns_config_build_cloudflare_resolver() {
        let resolver = DnsConfig::Cloudflare.build_resolver();
        assert!(resolver.resolver_impl_name().ends_with("HickoryDns"));
    }

    #[test]
    fn dns_config_build_custom_resolver() {
        let addr: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();
        let resolver = DnsConfig::Custom(addr).build_resolver();
        assert!(resolver.resolver_impl_name().ends_with("HickoryDns"));
    }

    #[test]
    fn try_from_config_initializes_doh_preset() {
        // The fallible path must succeed for a known-good DoH preset; this also
        // exercises the platform certificate-store load that `from_config`
        // would otherwise reach via `.expect()`.
        let resolver = HickoryDns::try_from_config(&DnsConfig::CloudflareHttps);
        assert!(
            resolver.is_ok(),
            "DoH preset should initialize: {resolver:?}"
        );
    }

    #[test]
    fn https_svc_param_parser_extracts_quic_metadata() {
        let mut record = HttpsRecord {
            ech_config_list: None,
            alpn: Vec::new(),
            target: None,
            port: None,
            ipv4_hints: Vec::new(),
            ipv6_hints: Vec::new(),
        };

        apply_https_svc_param(&mut record, &SvcParamValue::Port(8443));
        apply_https_svc_param(
            &mut record,
            &SvcParamValue::Ipv4Hint(IpHint(vec![A::from(Ipv4Addr::new(192, 0, 2, 10))])),
        );
        apply_https_svc_param(
            &mut record,
            &SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::from(Ipv6Addr::LOCALHOST)])),
        );

        assert_eq!(record.port, Some(8443));
        assert_eq!(record.ipv4_hints, vec![Ipv4Addr::new(192, 0, 2, 10)]);
        assert_eq!(record.ipv6_hints, vec![Ipv6Addr::LOCALHOST]);
    }

    #[test]
    fn https_record_supports_h3_variants() {
        let record = HttpsRecord {
            ech_config_list: None,
            alpn: vec!["h2".into(), "h3-29".into(), "h3".into()],
            target: None,
            port: Some(443),
            ipv4_hints: vec![],
            ipv6_hints: vec![],
        };

        assert!(record.supports_h3());
    }

    #[test]
    fn select_https_record_merges_same_priority_records() {
        let selected = select_https_record(vec![
            (
                1,
                HttpsRecord {
                    alpn: vec!["h2".into()],
                    target: Some("svc.example".into()),
                    ..HttpsRecord::default()
                },
            ),
            (
                1,
                HttpsRecord {
                    alpn: vec!["h3".into()],
                    port: Some(8443),
                    ipv4_hints: vec![Ipv4Addr::new(192, 0, 2, 1)],
                    ..HttpsRecord::default()
                },
            ),
        ])
        .unwrap();

        assert_eq!(selected.target.as_deref(), Some("svc.example"));
        assert_eq!(selected.port, Some(8443));
        assert_eq!(selected.alpn, vec!["h2", "h3"]);
        assert_eq!(selected.ipv4_hints, vec![Ipv4Addr::new(192, 0, 2, 1)]);
    }

    #[test]
    fn select_https_record_preserves_alias_mode_target() {
        let selected = select_https_record(vec![
            (
                0,
                HttpsRecord {
                    target: Some("alias.example".into()),
                    ..HttpsRecord::default()
                },
            ),
            (
                1,
                HttpsRecord {
                    alpn: vec!["h3".into()],
                    ..HttpsRecord::default()
                },
            ),
        ])
        .unwrap();

        assert_eq!(selected.target.as_deref(), Some("alias.example"));
        assert!(selected.alpn.is_empty());
    }
}
