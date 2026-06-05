use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::protocol::RouteKey;
use crate::proxy::{ProxyConfig, ProxyScheme};

/// Upper bound on `ma=` values parsed from Alt-Svc responses.
///
/// RFC 7838 does not mandate a ceiling, but accepting arbitrarily large
/// values lets a malicious response pin a poisoned route until the process
/// restarts. Mainstream browsers cap around a week; we match that.
const ALT_SVC_MAX_AGE_CEILING: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Origin scheme for Alt-Svc and broken-QUIC tracking.
///
/// RFC 7838 §2.1 defines an origin as the tuple (scheme, host, port). Keying
/// Alt-Svc state without the scheme would allow a plaintext HTTP response to
/// pollute the H3 routing of the corresponding HTTPS origin, which is a
/// cross-protocol cache-poisoning vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// Origin identifier for Alt-Svc / broken-QUIC tracking.
///
/// An origin is a (scheme, host, port) triple per RFC 7838 §2.1. Two
/// requests that differ in any component target different origins.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn new(scheme: Scheme, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme,
            host: normalize_host(&host.into()),
            port,
        }
    }

    pub fn https(host: impl Into<String>, port: u16) -> Self {
        Self::new(Scheme::Https, host, port)
    }

    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self::new(Scheme::Http, host, port)
    }
}

/// Route-aware origin key for learned H3 state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteOriginKey {
    pub route: RouteKey,
    pub origin: Origin,
}

impl RouteOriginKey {
    pub fn new(route: RouteKey, origin: Origin) -> Self {
        Self { route, origin }
    }
}

/// Cache of Alt-Svc advertisements keyed by origin.
#[derive(Debug, Default)]
pub struct AltSvcCache {
    entries: RwLock<HashMap<RouteOriginKey, Vec<AltSvcEntry>>>,
    validated: RwLock<HashMap<RouteOriginKey, Instant>>,
}

impl AltSvcCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn route_key(route: &RouteKey, origin: &Origin) -> RouteOriginKey {
        RouteOriginKey::new(route.clone(), origin.clone())
    }

    /// Parse and store Alt-Svc header values for the given origin.
    ///
    /// Only HTTPS origins are accepted — Alt-Svc from a plaintext HTTP
    /// response MUST NOT poison the corresponding HTTPS origin's H3 routing.
    pub fn store_from_header(&self, origin: &Origin, header_value: &str) {
        self.store_from_header_for_route(&RouteKey::direct(), origin, header_value);
    }

    /// Parse and store Alt-Svc header values for a specific route.
    pub fn store_from_header_for_route(
        &self,
        route: &RouteKey,
        origin: &Origin,
        header_value: &str,
    ) {
        if origin.scheme != Scheme::Https {
            tracing::debug!(
                route = %route,
                host = %origin.host,
                port = origin.port,
                scheme = origin.scheme.as_str(),
                "alt_svc.ignored_non_https_origin"
            );
            return;
        }

        let trimmed = header_value.trim();
        if trimmed.eq_ignore_ascii_case("clear") {
            let key = Self::route_key(route, origin);
            tracing::debug!(
                route = %route,
                host = %origin.host,
                port = origin.port,
                "alt_svc.cleared"
            );
            self.entries.write().remove(&key);
            self.validated.write().remove(&key);
            return;
        }

        let now = Instant::now();
        let parsed_entries: Vec<_> = split_unquoted(trimmed, ',')
            .into_iter()
            .filter_map(|item| parse_alt_svc_item(item, now))
            .collect();

        if parsed_entries.is_empty() {
            tracing::debug!(
                route = %route,
                host = %origin.host,
                port = origin.port,
                header = %trimmed,
                "alt_svc.no_usable_entries"
            );
            return;
        }

        tracing::debug!(
            route = %route,
            host = %origin.host,
            port = origin.port,
            entries = parsed_entries.len(),
            "alt_svc.stored"
        );
        self.entries
            .write()
            .insert(Self::route_key(route, origin), parsed_entries);
    }

    /// Find a currently usable HTTP/3 Alt-Svc entry for the origin.
    pub fn find_h3(&self, origin: &Origin) -> Option<AltSvcEntry> {
        self.find_h3_for_route(&RouteKey::direct(), origin)
    }

    /// Find a currently usable HTTP/3 Alt-Svc entry for the origin on the
    /// specified route.
    pub fn find_h3_for_route(&self, route: &RouteKey, origin: &Origin) -> Option<AltSvcEntry> {
        let key = Self::route_key(route, origin);
        let mut entries = self.entries.write();
        let origin_entries = entries.get_mut(&key)?;
        let before = origin_entries.len();
        origin_entries.retain(|entry| !entry.is_expired());
        let found = select_h3(origin_entries);
        tracing::debug!(
            route = %route,
            host = %origin.host,
            port = origin.port,
            cached_entries = before,
            fresh_entries = origin_entries.len(),
            hit = found.is_some(),
            "alt_svc.lookup"
        );
        if origin_entries.is_empty() {
            entries.remove(&key);
            self.validated.write().remove(&key);
        }
        found
    }

    pub fn mark_h3_validated(&self, origin: &Origin) {
        self.mark_h3_validated_for_route(&RouteKey::direct(), origin);
    }

    pub fn mark_h3_validated_for_route(&self, route: &RouteKey, origin: &Origin) {
        let key = Self::route_key(route, origin);
        let now = Instant::now();
        self.validated.write().insert(key, now);
        tracing::debug!(
            route = %route,
            host = %origin.host,
            port = origin.port,
            "alt_svc.h3_validated"
        );
    }

    pub fn clear_h3_validation(&self, origin: &Origin) {
        self.clear_h3_validation_for_route(&RouteKey::direct(), origin);
    }

    pub fn clear_h3_validation_for_route(&self, route: &RouteKey, origin: &Origin) {
        let key = Self::route_key(route, origin);
        if self.validated.write().remove(&key).is_some() {
            tracing::debug!(
                route = %route,
                host = %origin.host,
                port = origin.port,
                "alt_svc.h3_validation_cleared"
            );
        }
    }

    pub fn last_validated_at(&self, origin: &Origin) -> Option<Instant> {
        self.last_validated_at_for_route(&RouteKey::direct(), origin)
    }

    pub fn last_validated_at_for_route(
        &self,
        route: &RouteKey,
        origin: &Origin,
    ) -> Option<Instant> {
        let key = Self::route_key(route, origin);
        self.validated.read().get(&key).copied()
    }

    /// Remove all expired Alt-Svc entries.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.write();
        let mut validated = self.validated.write();
        let before = entries.len();
        entries.retain(|key, per_origin| {
            per_origin.retain(|entry| !entry.is_expired());
            let keep = !per_origin.is_empty();
            if !keep {
                validated.remove(key);
            }
            keep
        });
        let removed = before.saturating_sub(entries.len());
        if removed > 0 {
            tracing::debug!(
                removed,
                remaining = entries.len(),
                "alt_svc.evicted_expired"
            );
        }
    }
}

/// Parsed Alt-Svc entry for an origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvcEntry {
    /// Protocol identifier such as `h3`.
    pub protocol: String,
    /// Alternative host. `None` means "same origin host".
    pub host: Option<String>,
    /// Alternative port.
    pub port: u16,
    /// Lifetime advertised by the server.
    pub max_age: Duration,
    /// When this entry was stored.
    pub stored_at: Instant,
}

impl AltSvcEntry {
    pub fn is_expired(&self) -> bool {
        self.stored_at.elapsed() > self.max_age
    }
}

/// Learned QUIC / H3 reachability on a specific route to an origin.
#[derive(Debug, Clone)]
pub struct LearnedProtocolState {
    pub alt_svc: Option<AltSvcEntry>,
    pub h3_status: H3Reachability,
    pub last_validated_at: Option<Instant>,
}

/// H3 reachability status observed for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Reachability {
    Unknown,
    Advertised,
    Validated,
    FailedTransiently,
    FailedPersistently,
}

/// Why a [`BrokenQuicTracker`] entry was created. Drives both the cache
/// layer (per-origin vs per-route) and the cooldown duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrokenReason {
    /// Origin's QUIC/H3 path failed (handshake reset, stream error, idle
    /// timeout, …). Recorded **per-(route, origin)** because the same proxy
    /// route may still work for a different origin.
    OriginH3Failure,
    /// The proxy itself cannot relay UDP — typically a SOCKS5 server that
    /// rejects `CMD=UDP ASSOCIATE` or whose UDP relay is not reachable from
    /// the client. Recorded **per-route** because it taints every origin
    /// tunneled through that proxy, not just the one currently being
    /// attempted.
    ProxyUdpUnavailable,
}

/// Tunable behavior for [`BrokenQuicTracker`].
#[derive(Debug, Clone)]
pub struct BrokenQuicConfig {
    /// Hard cap on tracked **per-origin** entries. Additional failures
    /// evict the entry with the oldest `failed_at` timestamp
    /// (approximate-LRU).
    pub max_entries: usize,
    /// Cooldown applied on the first per-origin failure.
    pub initial_cooldown: Duration,
    /// Hard upper bound after repeated escalations.
    pub max_cooldown: Duration,
    /// Number of consecutive failures that triggers the longest cooldown.
    pub failure_escalation_threshold: u32,
    /// When `false`, [`BrokenQuicTracker::is_broken_for_route`] always
    /// reports the origin as healthy regardless of any prior `mark_broken`
    /// calls — equivalent to disabling the quarantine entirely.
    pub enabled: bool,
    /// Cooldown applied to **per-route** failures
    /// ([`BrokenReason::ProxyUdpUnavailable`] today). Independent of the
    /// per-origin escalation curve because proxy capability is binary —
    /// "failed twice" doesn't mean "wait twice as long".
    pub route_cooldown: Duration,
    /// Hard cap on tracked per-route entries.
    pub max_route_entries: usize,
}

impl Default for BrokenQuicConfig {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            initial_cooldown: Duration::from_secs(5 * 60),
            max_cooldown: Duration::from_secs(60 * 60),
            failure_escalation_threshold: 4,
            enabled: true,
            route_cooldown: Duration::from_secs(30 * 60),
            max_route_entries: 256,
        }
    }
}

/// Quarantine strategy for QUIC failures, exposed to users as a high-level
/// preset on top of [`BrokenQuicConfig`].
///
/// On every failed QUIC handshake or H3 request, lkrequest records the
/// origin in a per-session [`BrokenQuicTracker`] so that subsequent requests
/// temporarily skip H3 and use H2/H1 instead. The default `Strict` cooldown
/// is **5 minutes**, escalating up to 1 hour after repeated failures —
/// sensible for a stable home network but punishingly long when QUIC
/// failures are caused by a transparent proxy (mihomo / clash / sing-box) or
/// a flaky upstream UDP path that recovers within seconds.
///
/// # Example
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// use lkrequest::BrokenQuicPolicy;
/// # let client = Client::builder().fingerprint(presets::chrome_146()).build();
/// // Behind a transparent proxy: forgive QUIC failures and keep retrying H3.
/// let session = client
///     .session()
///     .broken_quic_policy(BrokenQuicPolicy::Resilient)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub enum BrokenQuicPolicy {
    /// Library default. 5 min initial cooldown, escalates up to 1 h after
    /// 4 consecutive failures. Best for stable networks; matches the
    /// persistence model used by Chrome's `QuicSessionPool`.
    #[default]
    Strict,
    /// 1 s initial cooldown, capped at 10 s, no escalation. Recommended
    /// when running behind a transparent proxy (mihomo / clash / sing-box /
    /// V2Ray TUN) or a sticky-session UDP relay where individual failures
    /// are usually transient upstream blips rather than evidence of a
    /// permanently broken QUIC path.
    Resilient,
    /// Never quarantine an origin — every request retries H3 from scratch.
    /// Strictest fingerprint preservation, at the cost of forcing the
    /// caller to handle every transient H3 error in application code.
    Disabled,
    /// Bring your own [`BrokenQuicConfig`] for full control.
    Custom(BrokenQuicConfig),
}

impl BrokenQuicPolicy {
    /// Materialize the policy into a concrete [`BrokenQuicConfig`].
    pub fn resolve(self) -> BrokenQuicConfig {
        match self {
            BrokenQuicPolicy::Strict => BrokenQuicConfig::default(),
            BrokenQuicPolicy::Resilient => BrokenQuicConfig {
                initial_cooldown: Duration::from_secs(1),
                max_cooldown: Duration::from_secs(10),
                failure_escalation_threshold: u32::MAX,
                route_cooldown: Duration::from_secs(60),
                ..BrokenQuicConfig::default()
            },
            BrokenQuicPolicy::Disabled => BrokenQuicConfig {
                enabled: false,
                ..BrokenQuicConfig::default()
            },
            BrokenQuicPolicy::Custom(cfg) => cfg,
        }
    }
}

/// Track origins whose QUIC path is temporarily considered broken.
#[derive(Debug)]
pub struct BrokenQuicTracker {
    broken: RwLock<HashMap<RouteOriginKey, BrokenEntry>>,
    /// Per-route failures (e.g. SOCKS5 proxy that rejects UDP ASSOCIATE).
    /// Taints every origin tunneled through this route until the cooldown
    /// expires — strictly stronger than the per-(route, origin) `broken`
    /// table.
    broken_routes: RwLock<HashMap<RouteKey, BrokenRouteEntry>>,
    config: BrokenQuicConfig,
}

impl Default for BrokenQuicTracker {
    fn default() -> Self {
        Self::with_config(BrokenQuicConfig::default())
    }
}

#[derive(Debug, Clone)]
struct BrokenEntry {
    failed_at: Instant,
    cooldown: Duration,
    failure_count: u32,
}

#[derive(Debug, Clone)]
struct BrokenRouteEntry {
    failed_at: Instant,
    cooldown: Duration,
    reason: BrokenReason,
}

impl BrokenQuicTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: BrokenQuicConfig) -> Self {
        Self {
            broken: RwLock::new(HashMap::new()),
            broken_routes: RwLock::new(HashMap::new()),
            config,
        }
    }

    pub fn mark_broken(&self, origin: &Origin) {
        self.mark_broken_for_route(&RouteKey::direct(), origin);
    }

    pub fn mark_broken_for_route(&self, route: &RouteKey, origin: &Origin) {
        let key = RouteOriginKey::new(route.clone(), origin.clone());
        let mut broken = self.broken.write();

        // Decide the new failure count: if the previous cooldown has already
        // expired, treat this as a fresh failure; otherwise escalate.
        let next_count = broken
            .get(&key)
            .map(|entry| {
                if entry.failed_at.elapsed() >= entry.cooldown {
                    1
                } else {
                    entry.failure_count.saturating_add(1)
                }
            })
            .unwrap_or(1);
        let cooldown = self.cooldown_for_failure(next_count);

        // Enforce the cap BEFORE inserting, so a host of distinct malicious
        // origins can't blow up memory. Evict the oldest-failing entry to
        // approximate LRU without paying for a linked hash map.
        if !broken.contains_key(&key) && broken.len() >= self.config.max_entries {
            if let Some(victim) = broken
                .iter()
                .min_by_key(|(_, entry)| entry.failed_at)
                .map(|(key, _)| key.clone())
            {
                broken.remove(&victim);
                tracing::debug!(
                    route = %victim.route,
                    evicted_host = %victim.origin.host,
                    evicted_port = victim.origin.port,
                    tracked = broken.len(),
                    "quic.broken_tracker_evicted"
                );
            }
        }

        broken.insert(
            key,
            BrokenEntry {
                failed_at: Instant::now(),
                cooldown,
                failure_count: next_count,
            },
        );
        tracing::warn!(
            route = %route,
            host = %origin.host,
            port = origin.port,
            failure_count = next_count,
            cooldown_secs = cooldown.as_secs(),
            "quic.origin_marked_broken"
        );
    }

    pub fn is_broken(&self, origin: &Origin) -> bool {
        self.is_broken_for_route(&RouteKey::direct(), origin)
    }

    pub fn is_broken_for_route(&self, route: &RouteKey, origin: &Origin) -> bool {
        if !self.config.enabled {
            return false;
        }
        // The route-level table strictly subsumes per-origin entries: if the
        // proxy itself can't relay UDP, no origin behind it is reachable
        // over H3 — short-circuit before even hashing the origin.
        if self.is_route_broken(route) {
            return true;
        }
        let key = RouteOriginKey::new(route.clone(), origin.clone());
        let mut broken = self.broken.write();
        let Some(entry) = broken.get(&key) else {
            return false;
        };
        if entry.failed_at.elapsed() < entry.cooldown {
            tracing::debug!(
                route = %route,
                host = %origin.host,
                port = origin.port,
                failure_count = entry.failure_count,
                cooldown_secs = entry.cooldown.as_secs(),
                "quic.origin_still_in_cooldown"
            );
            return true;
        }
        broken.remove(&key);
        tracing::debug!(
            route = %route,
            host = %origin.host,
            port = origin.port,
            "quic.origin_cooldown_expired"
        );
        false
    }

    pub fn mark_working(&self, origin: &Origin) {
        self.mark_working_for_route(&RouteKey::direct(), origin);
    }

    pub fn mark_working_for_route(&self, route: &RouteKey, origin: &Origin) {
        let key = RouteOriginKey::new(route.clone(), origin.clone());
        if self.broken.write().remove(&key).is_some() {
            tracing::debug!(
                route = %route,
                host = %origin.host,
                port = origin.port,
                "quic.origin_recovered"
            );
        }
    }

    /// Mark the entire **route** as unable to carry H3 — used when the
    /// failure is a property of the proxy itself (e.g. SOCKS5
    /// `UDP ASSOCIATE` rejected) rather than of any individual origin.
    ///
    /// The cooldown is taken from
    /// [`BrokenQuicConfig::route_cooldown`], independent of the per-origin
    /// escalation curve.
    pub fn mark_route_broken(&self, route: &RouteKey, reason: BrokenReason) {
        let mut broken_routes = self.broken_routes.write();

        if !broken_routes.contains_key(route)
            && broken_routes.len() >= self.config.max_route_entries
        {
            if let Some(victim) = broken_routes
                .iter()
                .min_by_key(|(_, entry)| entry.failed_at)
                .map(|(key, _)| key.clone())
            {
                broken_routes.remove(&victim);
                tracing::debug!(
                    evicted_route = %victim,
                    tracked = broken_routes.len(),
                    "quic.broken_route_tracker_evicted"
                );
            }
        }

        broken_routes.insert(
            route.clone(),
            BrokenRouteEntry {
                failed_at: Instant::now(),
                cooldown: self.config.route_cooldown,
                reason,
            },
        );
        tracing::warn!(
            route = %route,
            reason = ?reason,
            cooldown_secs = self.config.route_cooldown.as_secs(),
            "quic.route_marked_broken"
        );
    }

    /// Whether this route is currently quarantined at the route level.
    ///
    /// Cheaper than [`Self::is_broken_for_route`] because no origin lookup
    /// is performed, but does not consider per-origin entries.
    pub fn is_route_broken(&self, route: &RouteKey) -> bool {
        if !self.config.enabled {
            return false;
        }
        let mut broken_routes = self.broken_routes.write();
        let Some(entry) = broken_routes.get(route) else {
            return false;
        };
        if entry.failed_at.elapsed() < entry.cooldown {
            tracing::debug!(
                route = %route,
                reason = ?entry.reason,
                cooldown_secs = entry.cooldown.as_secs(),
                "quic.route_still_in_cooldown"
            );
            return true;
        }
        broken_routes.remove(route);
        tracing::debug!(
            route = %route,
            "quic.route_cooldown_expired"
        );
        false
    }

    /// Clear the route-level quarantine — used when a request succeeded
    /// over H3 through this route, proving the proxy can carry UDP.
    pub fn mark_route_working(&self, route: &RouteKey) {
        if self.broken_routes.write().remove(route).is_some() {
            tracing::debug!(route = %route, "quic.route_recovered");
        }
    }

    pub fn h3_reachability(&self, origin: &Origin) -> Option<H3Reachability> {
        self.h3_reachability_for_route(&RouteKey::direct(), origin)
    }

    pub fn h3_reachability_for_route(
        &self,
        route: &RouteKey,
        origin: &Origin,
    ) -> Option<H3Reachability> {
        let key = RouteOriginKey::new(route.clone(), origin.clone());
        let mut broken = self.broken.write();
        let entry = broken.get(&key)?;
        if entry.failed_at.elapsed() >= entry.cooldown {
            broken.remove(&key);
            return None;
        }
        Some(
            if entry.failure_count >= self.config.failure_escalation_threshold.max(1) {
                H3Reachability::FailedPersistently
            } else {
                H3Reachability::FailedTransiently
            },
        )
    }

    fn cooldown_for_failure(&self, failure_count: u32) -> Duration {
        let threshold = self.config.failure_escalation_threshold.max(1);
        let clamped = failure_count.min(threshold);
        if clamped <= 1 {
            return self.config.initial_cooldown.min(self.config.max_cooldown);
        }
        // Linearly interpolate from initial to max across the escalation
        // threshold. At `failure_count == threshold` we hit `max_cooldown`.
        let initial = self.config.initial_cooldown;
        let max = self.config.max_cooldown.max(initial);
        let span = max.saturating_sub(initial);
        let numerator = (clamped - 1) as u128 * span.as_nanos();
        let denominator = (threshold - 1).max(1) as u128;
        let step = Duration::from_nanos((numerator / denominator) as u64);
        (initial + step).min(max)
    }
}

/// Whether QUIC should be skipped before any protocol decision is attempted.
///
/// SOCKS5 proxies can relay UDP via UDP ASSOCIATE, so only HTTP proxies force
/// a skip.
pub fn should_skip_quic(
    proxy: Option<&ProxyConfig>,
    broken_tracker: &BrokenQuicTracker,
    origin: &Origin,
) -> bool {
    let is_http_proxy = proxy.is_some_and(|p| matches!(p.scheme, ProxyScheme::Http { .. }));
    let route = RouteKey::from_proxy(proxy);
    is_http_proxy || broken_tracker.is_broken_for_route(&route, origin)
}

pub fn learned_protocol_state_for_route(
    alt_svc_cache: &AltSvcCache,
    broken_tracker: &BrokenQuicTracker,
    route: &RouteKey,
    origin: &Origin,
) -> LearnedProtocolState {
    let alt_svc = alt_svc_cache.find_h3_for_route(route, origin);
    let last_validated_at = alt_svc_cache.last_validated_at_for_route(route, origin);
    let h3_status = broken_tracker
        .h3_reachability_for_route(route, origin)
        .or_else(|| {
            if last_validated_at.is_some() {
                Some(H3Reachability::Validated)
            } else if alt_svc.is_some() {
                Some(H3Reachability::Advertised)
            } else {
                None
            }
        })
        .unwrap_or(H3Reachability::Unknown);

    LearnedProtocolState {
        alt_svc,
        h3_status,
        last_validated_at,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_matches('.').to_ascii_lowercase()
}

fn parse_alt_svc_item(item: &str, stored_at: Instant) -> Option<AltSvcEntry> {
    let parts: Vec<_> = split_unquoted(item, ';').into_iter().collect();
    let (protocol_raw, authority_raw) = parts.first()?.split_once('=')?;
    let protocol = protocol_raw.trim().to_ascii_lowercase();
    let authority_raw = authority_raw.trim();
    let authority = unquote_owned(authority_raw).unwrap_or_else(|| authority_raw.to_string());
    let (host, port) = parse_alt_authority(&authority)?;

    let max_age = parts
        .iter()
        .skip(1)
        .find_map(|param| parse_max_age(param))
        .unwrap_or_else(|| Duration::from_secs(24 * 60 * 60));

    Some(AltSvcEntry {
        protocol,
        host,
        port,
        max_age,
        stored_at,
    })
}

fn parse_max_age(param: &str) -> Option<Duration> {
    let (name, value) = param.split_once('=')?;
    if !name.trim().eq_ignore_ascii_case("ma") {
        return None;
    }
    let value = value.trim();
    let seconds_str = unquote_owned(value).unwrap_or_else(|| value.to_string());
    let seconds = seconds_str.parse::<u64>().ok()?;
    let duration = Duration::from_secs(seconds);
    Some(duration.min(ALT_SVC_MAX_AGE_CEILING))
}

fn parse_alt_authority(authority: &str) -> Option<(Option<String>, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(port) = authority.strip_prefix(':') {
        return port.parse::<u16>().ok().map(|port| (None, port));
    }

    let (host, port) = authority.rsplit_once(':')?;
    let host = host.trim();
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = normalize_host(host);
    let port = port.parse::<u16>().ok()?;
    Some((Some(host), port))
}

/// Strip a surrounding `"..."` and unescape RFC 7230 quoted-pair `\X` sequences.
///
/// Returns `None` if the input isn't a quoted string. Allocates only when an
/// escape is actually present so the common "unquoted plain value" path stays
/// cheap.
fn unquote_owned(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    if !inner.contains('\\') {
        return Some(inner.to_string());
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

fn split_unquoted(input: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escape = false;

    for (idx, ch) in input.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escape = true,
            '"' => in_quotes = !in_quotes,
            _ if ch == delimiter && !in_quotes => {
                let part = input[start..idx].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }

    let tail = input[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }

    parts
}

fn select_h3(entries: &[AltSvcEntry]) -> Option<AltSvcEntry> {
    entries
        .iter()
        .find(|entry| entry.protocol == "h3")
        .cloned()
        .or_else(|| {
            entries
                .iter()
                .find(|entry| entry.protocol.starts_with("h3-"))
                .cloned()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_key(origin: &Origin) -> RouteOriginKey {
        RouteOriginKey::new(RouteKey::direct(), origin.clone())
    }

    #[test]
    fn alt_svc_parses_h3_authority() {
        let cache = AltSvcCache::new();
        let origin = Origin::https("Example.com", 443);

        cache.store_from_header(&origin, r#"h3=":443"; ma=86400"#);

        let entry = cache.find_h3(&origin).unwrap();
        assert_eq!(entry.protocol, "h3");
        assert_eq!(entry.host, None);
        assert_eq!(entry.port, 443);
        assert_eq!(entry.max_age, Duration::from_secs(86400));
    }

    #[test]
    fn alt_svc_rejects_http_origin() {
        let cache = AltSvcCache::new();
        let http_origin = Origin::http("example.com", 80);
        cache.store_from_header(&http_origin, r#"h3=":443"; ma=86400"#);
        assert!(cache.find_h3(&http_origin).is_none());

        // And an HTTPS lookup must not see the HTTP entry either.
        let https_origin = Origin::https("example.com", 443);
        assert!(cache.find_h3(&https_origin).is_none());
    }

    #[test]
    fn alt_svc_separates_http_and_https_origins() {
        // Even if a hypothetical bug later accepts HTTP origins, the cache
        // key distinguishes them so HTTP state cannot leak into HTTPS lookups.
        let cache = AltSvcCache::new();
        let https_origin = Origin::https("example.com", 443);
        cache.store_from_header(&https_origin, r#"h3=":443"; ma=86400"#);
        let http_origin = Origin::http("example.com", 443);
        assert!(cache.find_h3(&http_origin).is_none());
        assert!(cache.find_h3(&https_origin).is_some());
    }

    #[test]
    fn alt_svc_clear_removes_origin_entries() {
        let cache = AltSvcCache::new();
        let origin = Origin::https("example.com", 443);

        cache.store_from_header(&origin, r#"h3=":443"; ma=86400"#);
        assert!(cache.find_h3(&origin).is_some());

        cache.store_from_header(&origin, "clear");
        assert!(cache.find_h3(&origin).is_none());
    }

    #[test]
    fn alt_svc_evicts_expired_entries() {
        let cache = AltSvcCache::new();
        let origin = Origin::https("example.com", 443);

        cache.store_from_header(&origin, r#"h3=":443"; ma=0"#);

        assert!(cache.find_h3(&origin).is_none());
        assert!(!cache.entries.read().contains_key(&direct_key(&origin)));
    }

    #[test]
    fn alt_svc_prefers_final_h3_over_draft() {
        let cache = AltSvcCache::new();
        let origin = Origin::https("example.com", 443);

        cache.store_from_header(
            &origin,
            r#"h3-29=":443"; ma=86400, h3="alt.example.com:8443"; ma=60"#,
        );

        let entry = cache.find_h3(&origin).unwrap();
        assert_eq!(entry.protocol, "h3");
        assert_eq!(entry.host.as_deref(), Some("alt.example.com"));
        assert_eq!(entry.port, 8443);
    }

    #[test]
    fn alt_svc_caps_oversized_ma() {
        let cache = AltSvcCache::new();
        let origin = Origin::https("example.com", 443);

        cache.store_from_header(&origin, r#"h3=":443"; ma=99999999999"#);

        let entry = cache.find_h3(&origin).unwrap();
        assert_eq!(entry.max_age, ALT_SVC_MAX_AGE_CEILING);
    }

    #[test]
    fn alt_svc_unquote_handles_escaped_quote() {
        // The inner `\"` is a literal quote inside the quoted authority.
        // The parser should treat the closing `"` after `8443` as the end.
        assert_eq!(unquote_owned(r#""he\"llo""#).as_deref(), Some("he\"llo"),);
        // And a plain unquoted value still returns None.
        assert_eq!(unquote_owned("86400"), None);
    }

    #[test]
    fn broken_quic_tracker_escalates_then_caps() {
        let tracker = BrokenQuicTracker::new();
        let origin = Origin::https("example.com", 443);

        tracker.mark_broken(&origin);
        let first = tracker
            .broken
            .read()
            .get(&direct_key(&origin))
            .unwrap()
            .cooldown;
        tracker.mark_broken(&origin);
        tracker.mark_broken(&origin);
        tracker.mark_broken(&origin);
        let fourth = tracker
            .broken
            .read()
            .get(&direct_key(&origin))
            .unwrap()
            .cooldown;

        assert_eq!(first, BrokenQuicConfig::default().initial_cooldown);
        assert!(fourth >= first);
        assert!(fourth <= BrokenQuicConfig::default().max_cooldown);
    }

    #[test]
    fn broken_quic_tracker_clears_on_success() {
        let tracker = BrokenQuicTracker::new();
        let origin = Origin::https("example.com", 443);

        tracker.mark_broken(&origin);
        assert!(tracker.is_broken(&origin));

        tracker.mark_working(&origin);
        assert!(!tracker.is_broken(&origin));
    }

    #[test]
    fn broken_quic_policy_strict_matches_default_cooldown() {
        let cfg = BrokenQuicPolicy::Strict.resolve();
        let default = BrokenQuicConfig::default();
        assert_eq!(cfg.initial_cooldown, default.initial_cooldown);
        assert_eq!(cfg.max_cooldown, default.max_cooldown);
        assert!(cfg.enabled);
    }

    #[test]
    fn broken_quic_policy_resilient_uses_short_cooldown_no_escalation() {
        let cfg = BrokenQuicPolicy::Resilient.resolve();
        assert_eq!(cfg.initial_cooldown, Duration::from_secs(1));
        assert_eq!(cfg.max_cooldown, Duration::from_secs(10));
        assert_eq!(cfg.failure_escalation_threshold, u32::MAX);
        assert!(cfg.enabled);
    }

    #[test]
    fn broken_quic_policy_disabled_makes_origin_always_healthy() {
        let tracker = BrokenQuicTracker::with_config(BrokenQuicPolicy::Disabled.resolve());
        let origin = Origin::https("example.com", 443);
        tracker.mark_broken(&origin);
        assert!(
            !tracker.is_broken(&origin),
            "Disabled policy must report origin as healthy even after mark_broken"
        );
    }

    #[test]
    fn route_quarantine_taints_every_origin_via_that_proxy() {
        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let route = RouteKey::from_proxy(Some(&socks5));
        let direct = RouteKey::direct();

        let tracker = BrokenQuicTracker::new();
        let origin_a = Origin::https("a.example.com", 443);
        let origin_b = Origin::https("b.example.com", 443);
        let origin_c = Origin::https("c.example.com", 443);

        tracker.mark_route_broken(&route, BrokenReason::ProxyUdpUnavailable);

        assert!(tracker.is_route_broken(&route));
        assert!(tracker.is_broken_for_route(&route, &origin_a));
        assert!(tracker.is_broken_for_route(&route, &origin_b));
        assert!(tracker.is_broken_for_route(&route, &origin_c));

        assert!(!tracker.is_route_broken(&direct));
        assert!(
            !tracker.is_broken_for_route(&direct, &origin_a),
            "direct route is unaffected by SOCKS5 proxy quarantine"
        );
    }

    #[test]
    fn route_quarantine_clears_via_mark_route_working() {
        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let route = RouteKey::from_proxy(Some(&socks5));
        let origin = Origin::https("example.com", 443);

        let tracker = BrokenQuicTracker::new();
        tracker.mark_route_broken(&route, BrokenReason::ProxyUdpUnavailable);
        assert!(tracker.is_broken_for_route(&route, &origin));

        tracker.mark_route_working(&route);
        assert!(!tracker.is_route_broken(&route));
        assert!(!tracker.is_broken_for_route(&route, &origin));
    }

    #[test]
    fn route_quarantine_uses_route_cooldown_not_origin_cooldown() {
        let cfg = BrokenQuicConfig {
            initial_cooldown: Duration::from_secs(60 * 60),
            route_cooldown: Duration::from_millis(50),
            ..BrokenQuicConfig::default()
        };
        let tracker = BrokenQuicTracker::with_config(cfg);
        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let route = RouteKey::from_proxy(Some(&socks5));

        tracker.mark_route_broken(&route, BrokenReason::ProxyUdpUnavailable);
        assert!(tracker.is_route_broken(&route));

        std::thread::sleep(Duration::from_millis(80));
        assert!(
            !tracker.is_route_broken(&route),
            "route_cooldown (50ms) drives expiry, NOT initial_cooldown (1h)"
        );
    }

    #[test]
    fn route_quarantine_disabled_when_policy_disabled() {
        let tracker = BrokenQuicTracker::with_config(BrokenQuicPolicy::Disabled.resolve());
        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let route = RouteKey::from_proxy(Some(&socks5));

        tracker.mark_route_broken(&route, BrokenReason::ProxyUdpUnavailable);
        assert!(
            !tracker.is_route_broken(&route),
            "Disabled policy must short-circuit route quarantine too"
        );
    }

    #[test]
    fn route_quarantine_evicts_when_max_route_entries_reached() {
        let cfg = BrokenQuicConfig {
            max_route_entries: 2,
            ..BrokenQuicConfig::default()
        };
        let tracker = BrokenQuicTracker::with_config(cfg);

        let p1 = ProxyConfig::parse("socks5://p1.example.com:1080").unwrap();
        let p2 = ProxyConfig::parse("socks5://p2.example.com:1080").unwrap();
        let p3 = ProxyConfig::parse("socks5://p3.example.com:1080").unwrap();

        tracker.mark_route_broken(
            &RouteKey::from_proxy(Some(&p1)),
            BrokenReason::ProxyUdpUnavailable,
        );
        std::thread::sleep(Duration::from_millis(2));
        tracker.mark_route_broken(
            &RouteKey::from_proxy(Some(&p2)),
            BrokenReason::ProxyUdpUnavailable,
        );
        std::thread::sleep(Duration::from_millis(2));
        tracker.mark_route_broken(
            &RouteKey::from_proxy(Some(&p3)),
            BrokenReason::ProxyUdpUnavailable,
        );

        // p1 is the oldest entry → evicted; p2, p3 remain.
        assert!(!tracker.is_route_broken(&RouteKey::from_proxy(Some(&p1))));
        assert!(tracker.is_route_broken(&RouteKey::from_proxy(Some(&p2))));
        assert!(tracker.is_route_broken(&RouteKey::from_proxy(Some(&p3))));
    }

    #[test]
    fn resilient_policy_uses_short_route_cooldown() {
        let cfg = BrokenQuicPolicy::Resilient.resolve();
        assert_eq!(
            cfg.route_cooldown,
            Duration::from_secs(60),
            "Resilient should keep route quarantine to ~1 minute, not 30 minutes"
        );
    }

    #[test]
    fn strict_policy_uses_long_route_cooldown() {
        let cfg = BrokenQuicPolicy::Strict.resolve();
        assert_eq!(
            cfg.route_cooldown,
            Duration::from_secs(30 * 60),
            "Strict default should pin a UDP-incapable proxy for 30 minutes"
        );
    }

    #[test]
    fn broken_quic_policy_custom_round_trips_user_config() {
        let custom = BrokenQuicConfig {
            initial_cooldown: Duration::from_millis(250),
            max_cooldown: Duration::from_secs(2),
            failure_escalation_threshold: 7,
            max_entries: 64,
            enabled: true,
            route_cooldown: Duration::from_millis(500),
            max_route_entries: 32,
        };
        let resolved = BrokenQuicPolicy::Custom(custom.clone()).resolve();
        assert_eq!(resolved.initial_cooldown, custom.initial_cooldown);
        assert_eq!(resolved.max_cooldown, custom.max_cooldown);
        assert_eq!(
            resolved.failure_escalation_threshold,
            custom.failure_escalation_threshold
        );
        assert_eq!(resolved.max_entries, custom.max_entries);
    }

    #[test]
    fn broken_quic_tracker_resets_backoff_after_cooldown_elapsed() {
        let tracker = BrokenQuicTracker::new();
        let origin = Origin::https("example.com", 443);

        tracker.mark_broken(&origin);
        {
            let mut broken = tracker.broken.write();
            let entry = broken.get_mut(&direct_key(&origin)).unwrap();
            entry.failure_count = 3;
            entry.cooldown = Duration::from_secs(0);
        }

        tracker.mark_broken(&origin);

        let entry = tracker
            .broken
            .read()
            .get(&direct_key(&origin))
            .unwrap()
            .clone();
        assert_eq!(entry.failure_count, 1);
        assert_eq!(entry.cooldown, BrokenQuicConfig::default().initial_cooldown);
    }

    #[test]
    fn broken_quic_tracker_evicts_at_cap() {
        let tracker = BrokenQuicTracker::with_config(BrokenQuicConfig {
            max_entries: 2,
            ..BrokenQuicConfig::default()
        });

        let a = Origin::https("a.example.com", 443);
        let b = Origin::https("b.example.com", 443);
        let c = Origin::https("c.example.com", 443);

        tracker.mark_broken(&a);
        std::thread::sleep(Duration::from_millis(2));
        tracker.mark_broken(&b);
        std::thread::sleep(Duration::from_millis(2));
        tracker.mark_broken(&c);

        // `a` is the oldest entry and should have been evicted to make room
        // for `c`.
        let broken = tracker.broken.read();
        assert_eq!(broken.len(), 2);
        assert!(!broken.contains_key(&direct_key(&a)));
        assert!(broken.contains_key(&direct_key(&b)));
        assert!(broken.contains_key(&direct_key(&c)));
    }

    #[test]
    fn should_skip_quic_for_http_proxy_or_broken_origin() {
        let tracker = BrokenQuicTracker::new();
        let origin = Origin::https("example.com", 443);
        let http_proxy = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();

        assert!(should_skip_quic(Some(&http_proxy), &tracker, &origin));

        tracker.mark_broken(&origin);
        assert!(should_skip_quic(None, &tracker, &origin));

        tracker.mark_working(&origin);
        assert!(!should_skip_quic(None, &tracker, &origin));
    }

    #[test]
    fn socks5_proxy_does_not_skip_quic() {
        let tracker = BrokenQuicTracker::new();
        let origin = Origin::https("example.com", 443);
        let socks5_proxy = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();

        assert!(!should_skip_quic(Some(&socks5_proxy), &tracker, &origin));
    }

    #[test]
    fn route_aware_cache_does_not_leak_between_proxy_modes() {
        let cache = AltSvcCache::new();
        let tracker = BrokenQuicTracker::new();
        let origin = Origin::https("example.com", 443);
        let socks5 = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let socks5h = ProxyConfig::parse("socks5h://proxy.example.com:1080").unwrap();
        let socks5_route = RouteKey::from_proxy(Some(&socks5));
        let socks5h_route = RouteKey::from_proxy(Some(&socks5h));

        cache.store_from_header_for_route(&socks5_route, &origin, r#"h3=":443"; ma=86400"#);
        tracker.mark_broken_for_route(&socks5h_route, &origin);

        assert!(cache.find_h3_for_route(&socks5_route, &origin).is_some());
        assert!(cache.find_h3_for_route(&socks5h_route, &origin).is_none());
        assert!(!tracker.is_broken_for_route(&socks5_route, &origin));
        assert!(tracker.is_broken_for_route(&socks5h_route, &origin));
    }
}
