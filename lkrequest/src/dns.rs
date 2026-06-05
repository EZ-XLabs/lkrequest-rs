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

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

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
/// before custom DNS support was added.  It does **not** support HTTPS
/// record queries or custom DNS servers.
#[derive(Debug, Clone, Copy)]
pub struct SystemDns;

#[async_trait]
impl DnsResolver for SystemDns {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addr = format!("{host}:{port}");
        tracing::debug!(host = %host, port, resolver = "system", "dns.resolve_start");
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(addr).await?.collect();
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
