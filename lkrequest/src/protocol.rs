use std::{fmt, time::Duration};

use crate::error::{Error, Result};
use crate::proxy::{ProxyConfig, ProxyScheme};

/// High-level desired HTTP protocol behavior.
///
/// This models the user's protocol intent without mixing in wire-format
/// fingerprint data from TLS / QUIC / H2 / H3 profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpIntent {
    /// Disable QUIC / HTTP/3 and stay on TCP-based HTTP.
    H2Only,
    /// Require QUIC / HTTP/3 and do not silently downgrade.
    H3Only,
    /// Acquire QUIC / HTTP/3 when it is advertised or otherwise viable.
    AcquireH3WhenViable,
    /// Reuse the currently healthy protocol and avoid extra H3 acquisition
    /// work unless another policy axis explicitly upgrades.
    ReuseExistingProtocol,
    /// Prefer QUIC / HTTP/3 when it is available and worthwhile.
    #[deprecated(since = "0.3.0", note = "use `AcquireH3WhenViable`")]
    PreferH3,
    /// Reuse what already works; avoid extra H3 acquisition cost by default.
    #[deprecated(since = "0.3.0", note = "use `ReuseExistingProtocol`")]
    Auto,
}

/// How a request should acquire a usable transport when no pooled connection
/// is already selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionPolicy {
    /// Reuse a healthy existing connection first; otherwise stay conservative
    /// and avoid creating a brand-new H3 path just for the upgrade.
    ReuseExistingFirst,
    /// Establish the best currently known protocol for a new connection.
    EstablishBestAvailable,
    /// Allow a TCP/QUIC race with explicit timing parameters.
    Race(RacePolicy),
}

/// Parameters for a TCP-vs-QUIC acquisition race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RacePolicy {
    /// Whether to start a TCP/H2 connection attempt.
    pub enable_tcp: bool,
    /// Whether to start a QUIC/H3 connection attempt.
    pub enable_quic: bool,
    /// Delay before launching the TCP attempt (gives QUIC a head start).
    pub tcp_delay: Duration,
    /// Delay before launching the QUIC attempt (gives TCP a head start).
    pub quic_delay: Duration,
    /// Only race QUIC when the route has already advertised H3 (e.g. via Alt-Svc).
    pub only_when_h3_advertised: bool,
}

impl RacePolicy {
    /// Conservative Chromium-like defaults:
    /// QUIC starts immediately; TCP is released after a short delay and only
    /// when the route has already advertised H3.
    pub fn chrome_like() -> Self {
        Self {
            enable_tcp: true,
            enable_quic: true,
            tcp_delay: Duration::from_millis(300),
            quic_delay: Duration::ZERO,
            only_when_h3_advertised: true,
        }
    }

    /// Return a copy with TCP delayed by `delay`.
    pub fn with_tcp_delay(mut self, delay: Duration) -> Self {
        self.tcp_delay = delay;
        self
    }

    /// Return a copy with QUIC delayed by `delay`.
    pub fn with_quic_delay(mut self, delay: Duration) -> Self {
        self.quic_delay = delay;
        self
    }
}

/// How the client should upgrade from TCP-based HTTP to H3 once it learns the
/// route might support QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpgradePolicy {
    /// Never upgrade; stay on the current TCP-based protocol.
    Off,
    /// Probe for H3 in the background but keep serving requests over TCP.
    ProbeOnly,
    /// Probe for H3 and migrate new requests once it is confirmed healthy.
    ProbeAndMigrate,
    /// Force new requests onto H3 as soon as the route is known to support it.
    ForceForNewRequests,
    /// Deprecated alias for [`Off`](Self::Off).
    #[deprecated(since = "0.3.0", note = "use `Off`")]
    Disabled,
    /// Deprecated alias for [`ProbeOnly`](Self::ProbeOnly).
    #[deprecated(since = "0.3.0", note = "use `ProbeOnly`")]
    BackgroundProbe,
    /// Deprecated alias for [`ProbeAndMigrate`](Self::ProbeAndMigrate).
    #[deprecated(since = "0.3.0", note = "use `ProbeAndMigrate`")]
    BackgroundProbeAndMigrate,
    /// Deprecated alias for [`ForceForNewRequests`](Self::ForceForNewRequests).
    #[deprecated(since = "0.3.0", note = "use `ForceForNewRequests`")]
    ForceUpgradeForNewRequests,
}

/// How QUIC/H3 failures may fall back to TCP-based HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FallbackPolicy {
    /// Fall back to TCP-based HTTP on any QUIC/H3 failure.
    AllowFallback,
    /// Fall back only on network-level QUIC failures, not on protocol errors.
    AllowFallbackOnNetworkErrors,
    /// Never fall back; surface the QUIC/H3 failure to the caller.
    NoFallback,
}

/// Runtime protocol behavior policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolPolicy {
    /// Desired high-level protocol behavior (H2-only, H3-only, acquire-H3, …).
    pub intent: HttpIntent,
    /// How a new connection's transport is acquired (reuse / best / race).
    pub acquisition: AcquisitionPolicy,
    /// How and when to upgrade an established TCP connection to H3.
    pub upgrade: UpgradePolicy,
    /// How QUIC/H3 failures may fall back to TCP-based HTTP.
    pub fallback: FallbackPolicy,
}

impl Default for ProtocolPolicy {
    fn default() -> Self {
        Self::crawler_throughput()
    }
}

impl ProtocolPolicy {
    /// Construct a policy from its four axes without validation.
    ///
    /// Use [`try_new`](Self::try_new) to reject contradictory combinations up front.
    pub fn new(
        intent: HttpIntent,
        acquisition: AcquisitionPolicy,
        upgrade: UpgradePolicy,
        fallback: FallbackPolicy,
    ) -> Self {
        Self {
            intent,
            acquisition,
            upgrade,
            fallback,
        }
    }

    /// Construct a policy and reject contradictory combinations.
    pub fn try_new(
        intent: HttpIntent,
        acquisition: AcquisitionPolicy,
        upgrade: UpgradePolicy,
        fallback: FallbackPolicy,
    ) -> Result<Self> {
        let policy = Self::new(intent, acquisition, upgrade, fallback);
        policy.validate()?;
        Ok(policy)
    }

    /// Validate that the policy's axes describe one coherent protocol choice.
    ///
    /// Builder APIs still return plain values for backwards compatibility, so
    /// request execution calls this before using the resolved policy.
    #[allow(deprecated)]
    pub fn validate(&self) -> Result<()> {
        if matches!(self.intent, HttpIntent::H2Only)
            && !matches!(self.fallback, FallbackPolicy::NoFallback)
        {
            return Err(Error::InvalidConfig(
                "ProtocolPolicy conflict: H2Only disables H3, so fallback must be NoFallback"
                    .into(),
            ));
        }

        if matches!(self.intent, HttpIntent::H2Only)
            && !matches!(self.upgrade, UpgradePolicy::Off | UpgradePolicy::Disabled)
        {
            return Err(Error::InvalidConfig(
                "ProtocolPolicy conflict: H2Only disables H3, so upgrade policy must be Off".into(),
            ));
        }

        if matches!(self.intent, HttpIntent::H3Only)
            && !matches!(self.fallback, FallbackPolicy::NoFallback)
        {
            return Err(Error::InvalidConfig(
                "ProtocolPolicy conflict: H3Only requires NoFallback".into(),
            ));
        }

        if let AcquisitionPolicy::Race(race) = &self.acquisition {
            if !race.enable_tcp && !race.enable_quic {
                return Err(Error::InvalidConfig(
                    "ProtocolPolicy conflict: RacePolicy must enable TCP, QUIC, or both".into(),
                ));
            }
            if matches!(self.intent, HttpIntent::H2Only) && race.enable_quic {
                return Err(Error::InvalidConfig(
                    "ProtocolPolicy conflict: H2Only cannot race a QUIC job".into(),
                ));
            }
            if matches!(self.intent, HttpIntent::H3Only) && race.enable_tcp {
                return Err(Error::InvalidConfig(
                    "ProtocolPolicy conflict: H3Only cannot race a TCP fallback job".into(),
                ));
            }
        }

        Ok(())
    }

    /// Return a copy with `intent` set, normalizing the other axes to stay coherent.
    pub fn with_intent(mut self, intent: HttpIntent) -> Self {
        self.intent = intent;
        self.normalize_for_intent();
        self
    }

    /// Return a copy with the acquisition policy replaced.
    pub fn with_acquisition(mut self, acquisition: AcquisitionPolicy) -> Self {
        self.acquisition = acquisition;
        self
    }

    /// Return a copy with the upgrade policy replaced.
    pub fn with_upgrade(mut self, upgrade: UpgradePolicy) -> Self {
        self.upgrade = upgrade;
        self
    }

    /// Return a copy with the fallback policy replaced.
    pub fn with_fallback(mut self, fallback: FallbackPolicy) -> Self {
        self.fallback = fallback;
        self
    }

    /// Chrome-like default: acquire H3 when viable, race TCP/QUIC, and fall back
    /// on network errors.
    pub fn chrome_standard() -> Self {
        Self::new(
            HttpIntent::AcquireH3WhenViable,
            AcquisitionPolicy::Race(RacePolicy::chrome_like()),
            UpgradePolicy::ProbeAndMigrate,
            FallbackPolicy::AllowFallbackOnNetworkErrors,
        )
    }

    /// Conservative Chrome-like policy: reuse the existing protocol and only
    /// probe for H3.
    pub fn chrome_conservative() -> Self {
        Self::new(
            HttpIntent::ReuseExistingProtocol,
            AcquisitionPolicy::ReuseExistingFirst,
            UpgradePolicy::ProbeOnly,
            FallbackPolicy::AllowFallbackOnNetworkErrors,
        )
    }

    /// Throughput-oriented default for crawling: reuse the existing protocol,
    /// skip H3 upgrades, and allow fallback.
    pub fn crawler_throughput() -> Self {
        Self::new(
            HttpIntent::ReuseExistingProtocol,
            AcquisitionPolicy::ReuseExistingFirst,
            UpgradePolicy::Off,
            FallbackPolicy::AllowFallback,
        )
    }

    /// Strict HTTP/3: H3-only with no fallback to TCP.
    pub fn h3_strict() -> Self {
        Self::new(
            HttpIntent::H3Only,
            AcquisitionPolicy::EstablishBestAvailable,
            UpgradePolicy::ForceForNewRequests,
            FallbackPolicy::NoFallback,
        )
    }

    #[allow(deprecated)]
    fn normalize_for_intent(&mut self) {
        match self.intent {
            HttpIntent::H2Only => {
                self.fallback = FallbackPolicy::NoFallback;
                self.upgrade = UpgradePolicy::Off;
                if matches!(self.acquisition, AcquisitionPolicy::Race(_)) {
                    self.acquisition = AcquisitionPolicy::EstablishBestAvailable;
                }
            }
            HttpIntent::H3Only => {
                self.fallback = FallbackPolicy::NoFallback;
                if let AcquisitionPolicy::Race(race) = &self.acquisition {
                    if race.enable_tcp {
                        self.acquisition = AcquisitionPolicy::EstablishBestAvailable;
                    }
                }
            }
            HttpIntent::AcquireH3WhenViable
            | HttpIntent::ReuseExistingProtocol
            | HttpIntent::PreferH3
            | HttpIntent::Auto => {}
        }
    }
}

/// Proxy type encoded into a route-aware cache key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyRouteKind {
    /// No proxy — a direct connection to the target.
    Direct,
    /// HTTP CONNECT tunnel proxy.
    HttpConnect,
    /// SOCKS5 proxy.
    Socks5,
}

/// Where target DNS resolution happens for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsResolutionMode {
    /// The client resolves the target hostname locally before connecting.
    Local,
    /// The proxy resolves the target hostname (remote DNS).
    Remote,
}

/// Route traits that affect whether learned H3 state is reusable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// Proxy category for this route.
    pub proxy_kind: ProxyRouteKind,
    /// Stable proxy identity (host/port/auth), or `None` for a direct route.
    pub proxy_identity: Option<String>,
    /// Where target DNS resolution happens on this route.
    pub dns_mode: DnsResolutionMode,
}

impl RouteKey {
    /// The route key for a direct (no-proxy) connection.
    pub fn direct() -> Self {
        Self {
            proxy_kind: ProxyRouteKind::Direct,
            proxy_identity: None,
            dns_mode: DnsResolutionMode::Local,
        }
    }

    /// Derive the route key for an optional proxy configuration.
    pub fn from_proxy(proxy: Option<&ProxyConfig>) -> Self {
        match proxy {
            None => Self::direct(),
            Some(proxy) => match &proxy.scheme {
                ProxyScheme::Http { .. } => Self {
                    proxy_kind: ProxyRouteKind::HttpConnect,
                    proxy_identity: Some(proxy.identity()),
                    dns_mode: DnsResolutionMode::Remote,
                },
                ProxyScheme::Socks5 { remote_dns, .. } => Self {
                    proxy_kind: ProxyRouteKind::Socks5,
                    proxy_identity: Some(proxy.identity()),
                    dns_mode: if *remote_dns {
                        DnsResolutionMode::Remote
                    } else {
                        DnsResolutionMode::Local
                    },
                },
            },
        }
    }
}

/// Whether `proxy` resolves the target's DNS remotely, meaning the client must
/// perform **no** local DNS for the target — neither A/AAAA nor HTTPS/SVCB
/// discovery. Doing so would leak the target hostname out-of-band from the
/// proxy. Mirrors [`RouteKey::from_proxy`]'s [`DnsResolutionMode`]: HTTP CONNECT
/// and `socks5h` resolve remotely; a direct route and plain `socks5` resolve
/// locally.
pub(crate) fn proxy_uses_remote_dns(proxy: Option<&ProxyConfig>) -> bool {
    RouteKey::from_proxy(proxy).dns_mode == DnsResolutionMode::Remote
}

impl fmt::Display for RouteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.proxy_kind {
            ProxyRouteKind::Direct => "direct",
            ProxyRouteKind::HttpConnect => "http_connect",
            ProxyRouteKind::Socks5 => "socks5",
        };
        let dns = match self.dns_mode {
            DnsResolutionMode::Local => "local_dns",
            DnsResolutionMode::Remote => "remote_dns",
        };
        match self.proxy_identity.as_deref() {
            Some(identity) => write!(f, "{kind}:{dns}:{identity}"),
            None => write!(f, "{kind}:{dns}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_templates_match_expected_shape() {
        let chrome = ProtocolPolicy::chrome_standard();
        assert_eq!(chrome.intent, HttpIntent::AcquireH3WhenViable);
        assert_eq!(chrome.upgrade, UpgradePolicy::ProbeAndMigrate);
        assert_eq!(
            chrome.fallback,
            FallbackPolicy::AllowFallbackOnNetworkErrors
        );
        assert!(matches!(chrome.acquisition, AcquisitionPolicy::Race(_)));

        let crawler = ProtocolPolicy::crawler_throughput();
        assert_eq!(crawler.intent, HttpIntent::ReuseExistingProtocol);
        assert!(matches!(
            crawler.acquisition,
            AcquisitionPolicy::ReuseExistingFirst
        ));
        assert_eq!(crawler.upgrade, UpgradePolicy::Off);
    }

    #[test]
    fn race_policy_uses_duration_delays() {
        let race = RacePolicy::chrome_like();
        assert_eq!(race.tcp_delay, Duration::from_millis(300));
        assert_eq!(race.quic_delay, Duration::ZERO);
    }

    #[test]
    fn validate_rejects_contradictory_protocol_policy() {
        let h2_with_fallback = ProtocolPolicy::new(
            HttpIntent::H2Only,
            AcquisitionPolicy::EstablishBestAvailable,
            UpgradePolicy::Off,
            FallbackPolicy::AllowFallback,
        );
        assert!(h2_with_fallback.validate().is_err());

        let empty_race = ProtocolPolicy::new(
            HttpIntent::AcquireH3WhenViable,
            AcquisitionPolicy::Race(RacePolicy {
                enable_tcp: false,
                enable_quic: false,
                tcp_delay: Duration::ZERO,
                quic_delay: Duration::ZERO,
                only_when_h3_advertised: false,
            }),
            UpgradePolicy::Off,
            FallbackPolicy::AllowFallbackOnNetworkErrors,
        );
        assert!(empty_race.validate().is_err());
    }

    #[test]
    fn route_key_distinguishes_socks5_and_socks5h() {
        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let socks5h = ProxyConfig::parse("socks5h://proxy.example.com:1080").unwrap();
        let http = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();

        assert_eq!(RouteKey::from_proxy(None), RouteKey::direct());
        assert_ne!(
            RouteKey::from_proxy(Some(&socks5)),
            RouteKey::from_proxy(Some(&socks5h))
        );
        assert_ne!(
            RouteKey::from_proxy(Some(&http)),
            RouteKey::from_proxy(Some(&socks5))
        );
    }

    #[test]
    fn default_policy_is_crawler_throughput() {
        assert_eq!(
            ProtocolPolicy::default(),
            ProtocolPolicy::crawler_throughput()
        );
    }

    #[test]
    fn conservative_and_strict_templates_are_coherent() {
        let c = ProtocolPolicy::chrome_conservative();
        assert_eq!(c.intent, HttpIntent::ReuseExistingProtocol);
        assert_eq!(c.acquisition, AcquisitionPolicy::ReuseExistingFirst);
        assert_eq!(c.upgrade, UpgradePolicy::ProbeOnly);
        assert!(c.validate().is_ok());

        let s = ProtocolPolicy::h3_strict();
        assert_eq!(s.intent, HttpIntent::H3Only);
        assert_eq!(s.acquisition, AcquisitionPolicy::EstablishBestAvailable);
        assert_eq!(s.upgrade, UpgradePolicy::ForceForNewRequests);
        assert_eq!(s.fallback, FallbackPolicy::NoFallback);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn try_new_accepts_coherent_and_rejects_conflicting() {
        assert!(ProtocolPolicy::try_new(
            HttpIntent::H3Only,
            AcquisitionPolicy::EstablishBestAvailable,
            UpgradePolicy::ForceForNewRequests,
            FallbackPolicy::NoFallback,
        )
        .is_ok());

        assert!(ProtocolPolicy::try_new(
            HttpIntent::H3Only,
            AcquisitionPolicy::EstablishBestAvailable,
            UpgradePolicy::Off,
            FallbackPolicy::AllowFallback, // H3Only requires NoFallback
        )
        .is_err());
    }

    #[test]
    fn validate_catches_every_conflict_axis() {
        // H2Only with a non-Off upgrade policy.
        assert!(ProtocolPolicy::new(
            HttpIntent::H2Only,
            AcquisitionPolicy::EstablishBestAvailable,
            UpgradePolicy::ProbeOnly,
            FallbackPolicy::NoFallback,
        )
        .validate()
        .is_err());

        // H3Only with fallback enabled.
        assert!(ProtocolPolicy::new(
            HttpIntent::H3Only,
            AcquisitionPolicy::EstablishBestAvailable,
            UpgradePolicy::ForceForNewRequests,
            FallbackPolicy::AllowFallback,
        )
        .validate()
        .is_err());

        // H2Only racing a QUIC job.
        assert!(ProtocolPolicy::new(
            HttpIntent::H2Only,
            AcquisitionPolicy::Race(RacePolicy::chrome_like()), // enable_quic = true
            UpgradePolicy::Off,
            FallbackPolicy::NoFallback,
        )
        .validate()
        .is_err());

        // H3Only racing a TCP fallback job.
        assert!(ProtocolPolicy::new(
            HttpIntent::H3Only,
            AcquisitionPolicy::Race(RacePolicy::chrome_like()), // enable_tcp = true
            UpgradePolicy::ForceForNewRequests,
            FallbackPolicy::NoFallback,
        )
        .validate()
        .is_err());
    }

    #[test]
    fn with_intent_normalizes_h2_only_into_a_coherent_policy() {
        // chrome_standard races + allows fallback + probes; switching intent to
        // H2Only must force every axis back to a TCP-only-coherent shape.
        let p = ProtocolPolicy::chrome_standard().with_intent(HttpIntent::H2Only);
        assert_eq!(p.fallback, FallbackPolicy::NoFallback);
        assert_eq!(p.upgrade, UpgradePolicy::Off);
        assert_eq!(p.acquisition, AcquisitionPolicy::EstablishBestAvailable);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn with_intent_normalizes_h3_only_dropping_the_tcp_race() {
        let p = ProtocolPolicy::chrome_standard().with_intent(HttpIntent::H3Only);
        assert_eq!(p.fallback, FallbackPolicy::NoFallback);
        // chrome_like race enables TCP, which H3Only cannot keep.
        assert_eq!(p.acquisition, AcquisitionPolicy::EstablishBestAvailable);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn builder_setters_thread_each_axis_through() {
        let p = ProtocolPolicy::crawler_throughput()
            .with_acquisition(AcquisitionPolicy::EstablishBestAvailable)
            .with_upgrade(UpgradePolicy::ProbeOnly)
            .with_fallback(FallbackPolicy::NoFallback);
        assert_eq!(p.acquisition, AcquisitionPolicy::EstablishBestAvailable);
        assert_eq!(p.upgrade, UpgradePolicy::ProbeOnly);
        assert_eq!(p.fallback, FallbackPolicy::NoFallback);
    }

    #[test]
    fn race_policy_delay_builders_override_in_place() {
        let r = RacePolicy::chrome_like()
            .with_tcp_delay(Duration::from_millis(50))
            .with_quic_delay(Duration::from_millis(10));
        assert_eq!(r.tcp_delay, Duration::from_millis(50));
        assert_eq!(r.quic_delay, Duration::from_millis(10));
    }

    #[test]
    fn route_key_display_encodes_kind_dns_and_identity() {
        assert_eq!(RouteKey::direct().to_string(), "direct:local_dns");

        let http = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();
        assert!(RouteKey::from_proxy(Some(&http))
            .to_string()
            .starts_with("http_connect:remote_dns:"));

        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        assert!(RouteKey::from_proxy(Some(&socks5))
            .to_string()
            .starts_with("socks5:local_dns:"));

        let socks5h = ProxyConfig::parse("socks5h://proxy.example.com:1080").unwrap();
        assert!(RouteKey::from_proxy(Some(&socks5h))
            .to_string()
            .starts_with("socks5:remote_dns:"));
    }
}
