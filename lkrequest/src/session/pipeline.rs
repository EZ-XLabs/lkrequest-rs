//! Shared connection pipeline — common infrastructure for buffered and
//! streaming request paths.
//!
//! Eliminates code duplication between `transport.rs` and `streaming.rs` by
//! extracting URL parsing, connection config building, H1 handshake,
//! ALPN-based protocol selection, H2 establishment + pooling, URI/Host
//! construction, cookie storage, and pool acquisition into reusable functions.

use std::sync::Arc;

use http::HeaderMap;
use http_body_util::Full;
use url::Url;

use crate::alt_svc::{
    self, learned_protocol_state_for_route, H3Reachability, LearnedProtocolState, Origin,
    Scheme as OriginScheme,
};
use crate::client::Client;
use crate::connection_pool::{AcquiredConnection, ConnectionKey, ConnectionPermit, Scheme};
use crate::dns::HttpsRecord;
use crate::error::{Error, Result};
#[cfg(any(feature = "quic-h3", test))]
use crate::protocol::FallbackPolicy;
#[cfg(feature = "quic-h3")]
use crate::protocol::RacePolicy;
use crate::protocol::{
    AcquisitionPolicy, DnsResolutionMode, HttpIntent, ProtocolPolicy, RouteKey, UpgradePolicy,
};
use crate::proxy::ProxyConfig;

#[cfg(feature = "quic-h3")]
use super::ChromeLikeProtocolConfig;
use super::{PreferredHttpVersion, Session};

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// Parsed components of a request URL, ready for connection lookup/establishment.
pub(crate) struct ParsedTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub conn_key: ConnectionKey,
    pub parsed_url: Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicDiscoverySource {
    AltSvc,
    DnsHttps,
}

impl QuicDiscoverySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AltSvc => "alt-svc",
            Self::DnsHttps => "dns-https",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicSkipReason {
    CleartextHttp,
    HttpVersionPreference,
    /// HTTP CONNECT proxy cannot relay UDP — must use TCP.
    HttpProxyConfigured,
    BrokenOrigin,
    /// The proxy route's UDP relay is quarantined (e.g. SOCKS5
    /// `UDP ASSOCIATE` failed). Applies to every origin behind the proxy
    /// until the route cooldown expires.
    ProxyUdpUnavailable,
    MissingProfile,
}

impl QuicSkipReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CleartextHttp => "cleartext_http",
            Self::HttpVersionPreference => "http_version_preference",
            Self::HttpProxyConfigured => "http_proxy_configured",
            Self::BrokenOrigin => "broken_origin_cooldown",
            Self::ProxyUdpUnavailable => "proxy_udp_unavailable",
            Self::MissingProfile => "missing_quic_profile",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QuicDiscovery {
    pub route: RouteKey,
    pub origin: Origin,
    pub learned_state: LearnedProtocolState,
    pub source: Option<QuicDiscoverySource>,
    pub force_attempt: bool,
    pub advertised_host: Option<String>,
    pub advertised_port: Option<u16>,
    pub dns_https: Option<HttpsRecord>,
    pub skip_reason: Option<QuicSkipReason>,
}

impl QuicDiscovery {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn should_attempt_quic(&self) -> bool {
        (self.force_attempt || self.source.is_some()) && self.skip_reason.is_none()
    }

    pub(crate) fn advertised_authority(&self) -> Option<String> {
        let port = self.advertised_port?;
        let host = self.advertised_host.as_deref().unwrap_or(&self.origin.host);
        Some(format!("{host}:{port}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolDecision {
    Tcp,
    Quic,
    Race,
}

impl ProtocolDecision {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::Race => "race",
        }
    }
}

#[allow(deprecated)]
pub(crate) fn decide_protocol(
    http_version: PreferredHttpVersion,
    policy: &ProtocolPolicy,
    discovery: &QuicDiscovery,
) -> ProtocolDecision {
    if http_version == PreferredHttpVersion::Http1Only {
        return ProtocolDecision::Tcp;
    }

    if matches!(policy.intent, HttpIntent::H2Only)
        || http_version == PreferredHttpVersion::Http2Only
    {
        return ProtocolDecision::Tcp;
    }

    if matches!(policy.intent, HttpIntent::H3Only)
        || http_version == PreferredHttpVersion::Http3Only
    {
        return ProtocolDecision::Quic;
    }

    if discovery.skip_reason.is_some() {
        return ProtocolDecision::Tcp;
    }

    let h3_ready = matches!(
        discovery.learned_state.h3_status,
        H3Reachability::Advertised | H3Reachability::Validated
    ) || discovery.force_attempt;

    if !h3_ready {
        return ProtocolDecision::Tcp;
    }

    match policy.intent {
        HttpIntent::AcquireH3WhenViable | HttpIntent::PreferH3 => match &policy.acquisition {
            AcquisitionPolicy::Race(race) if race.enable_quic && race.enable_tcp => {
                ProtocolDecision::Race
            }
            AcquisitionPolicy::ReuseExistingFirst
                if matches!(
                    policy.upgrade,
                    UpgradePolicy::ForceForNewRequests | UpgradePolicy::ForceUpgradeForNewRequests
                ) && matches!(discovery.learned_state.h3_status, H3Reachability::Validated) =>
            {
                ProtocolDecision::Quic
            }
            AcquisitionPolicy::ReuseExistingFirst => ProtocolDecision::Tcp,
            _ => ProtocolDecision::Quic,
        },
        HttpIntent::ReuseExistingProtocol | HttpIntent::Auto => {
            let can_force_upgrade =
                matches!(
                    policy.upgrade,
                    UpgradePolicy::ProbeAndMigrate
                        | UpgradePolicy::ForceForNewRequests
                        | UpgradePolicy::BackgroundProbeAndMigrate
                        | UpgradePolicy::ForceUpgradeForNewRequests
                ) && matches!(discovery.learned_state.h3_status, H3Reachability::Validated);

            match &policy.acquisition {
                AcquisitionPolicy::Race(race)
                    if race.enable_quic
                        && race.enable_tcp
                        && (!race.only_when_h3_advertised
                            || matches!(
                                discovery.learned_state.h3_status,
                                H3Reachability::Advertised | H3Reachability::Validated
                            )) =>
                {
                    ProtocolDecision::Race
                }
                AcquisitionPolicy::EstablishBestAvailable if can_force_upgrade => {
                    ProtocolDecision::Quic
                }
                AcquisitionPolicy::ReuseExistingFirst if can_force_upgrade => {
                    ProtocolDecision::Quic
                }
                _ => ProtocolDecision::Tcp,
            }
        }
        HttpIntent::H2Only => ProtocolDecision::Tcp,
        HttpIntent::H3Only => ProtocolDecision::Quic,
    }
}

#[cfg(feature = "quic-h3")]
pub(crate) fn is_connection_limit_error(error: &Error) -> bool {
    matches!(error, Error::Pool(message) if message.starts_with("session connection limit reached"))
}

#[cfg(feature = "quic-h3")]
pub(crate) fn protocol_race_error(tcp_error: Error, quic_error: Error) -> Error {
    Error::connection(
        crate::error::ConnectionPhase::QuicFallback,
        format!("protocol race failed (tcp: {tcp_error}; quic: {quic_error})"),
        None,
    )
}

pub(crate) fn log_protocol_policy(
    route: &RouteKey,
    host: &str,
    port: u16,
    policy: &ProtocolPolicy,
    http_version: PreferredHttpVersion,
) {
    tracing::debug!(
        route = %route,
        host = host,
        port,
        http_version = ?http_version,
        intent = ?policy.intent,
        acquisition = ?policy.acquisition,
        upgrade = ?policy.upgrade,
        fallback = ?policy.fallback,
        "protocol.policy_selected",
    );
}

pub(crate) fn log_protocol_decision(
    discovery: &QuicDiscovery,
    policy: &ProtocolPolicy,
    decision: ProtocolDecision,
) {
    tracing::debug!(
        route = %discovery.route,
        host = %discovery.origin.host,
        port = discovery.origin.port,
        intent = ?policy.intent,
        acquisition = ?policy.acquisition,
        upgrade = ?policy.upgrade,
        fallback = ?policy.fallback,
        decision = decision.as_str(),
        source = discovery.source.map(QuicDiscoverySource::as_str),
        skip_reason = discovery.skip_reason.map(QuicSkipReason::as_str),
        h3_status = ?discovery.learned_state.h3_status,
        authority = discovery.advertised_authority().as_deref(),
        "protocol.decision",
    );
}

#[allow(deprecated)]
pub(crate) fn should_background_probe(policy: &ProtocolPolicy, discovery: &QuicDiscovery) -> bool {
    matches!(
        policy.upgrade,
        UpgradePolicy::ProbeOnly
            | UpgradePolicy::ProbeAndMigrate
            | UpgradePolicy::ForceForNewRequests
            | UpgradePolicy::BackgroundProbe
            | UpgradePolicy::BackgroundProbeAndMigrate
            | UpgradePolicy::ForceUpgradeForNewRequests
    ) && matches!(
        discovery.learned_state.h3_status,
        H3Reachability::Advertised
    ) && discovery.skip_reason.is_none()
}

pub(crate) fn log_background_probe_decision(
    route: &RouteKey,
    host: &str,
    port: u16,
    policy: &ProtocolPolicy,
    discovery: &QuicDiscovery,
    scheduled: bool,
) {
    let levelled = (
        route,
        host,
        port,
        policy,
        discovery.source.map(QuicDiscoverySource::as_str),
        discovery.skip_reason.map(QuicSkipReason::as_str),
        discovery.learned_state.h3_status,
    );
    if scheduled {
        tracing::debug!(
            route = %levelled.0,
            host = levelled.1,
            port = levelled.2,
            upgrade = ?levelled.3.upgrade,
            source = levelled.4,
            skip_reason = levelled.5,
            h3_status = ?levelled.6,
            "quic.background_probe_scheduled",
        );
    } else {
        tracing::trace!(
            route = %levelled.0,
            host = levelled.1,
            port = levelled.2,
            upgrade = ?levelled.3.upgrade,
            source = levelled.4,
            skip_reason = levelled.5,
            h3_status = ?levelled.6,
            "quic.background_probe_skipped",
        );
    }
}

#[cfg(any(feature = "quic-h3", test))]
pub(crate) fn fallback_permitted(policy: &ProtocolPolicy, error: &Error) -> bool {
    match policy.fallback {
        FallbackPolicy::AllowFallback => true,
        FallbackPolicy::AllowFallbackOnNetworkErrors => {
            error.is_quic_handshake_failure() || error.is_timeout() || error.is_proxy_tunnel()
        }
        FallbackPolicy::NoFallback => false,
    }
}

/// Parse a URL string into scheme, host, port, path, and a connection pool key.
pub(crate) fn parse_request_target(url: &str, proxy: Option<&ProxyConfig>) -> Result<ParsedTarget> {
    let parsed_url = Url::parse(url).map_err(|e| Error::UrlParse(format!("{url}: {e}")))?;

    let scheme = match parsed_url.scheme() {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        other => return Err(Error::UrlParse(format!("unsupported scheme: {other}"))),
    };

    let host = parsed_url
        .host_str()
        .ok_or_else(|| Error::UrlParse("missing host".into()))?
        .to_string();

    let port = parsed_url.port_or_known_default().unwrap_or(match scheme {
        Scheme::Https => 443,
        Scheme::Http => 80,
    });

    let path = if let Some(query) = parsed_url.query() {
        format!("{}?{}", parsed_url.path(), query)
    } else {
        parsed_url.path().to_string()
    };

    let conn_key = ConnectionKey {
        scheme,
        host: Arc::from(host.as_str()),
        port,
        route: RouteKey::from_proxy(proxy),
    };

    Ok(ParsedTarget {
        scheme,
        host,
        port,
        path,
        conn_key,
        parsed_url,
    })
}

// ---------------------------------------------------------------------------
// ALPN list adjustment
// ---------------------------------------------------------------------------

/// Strip `h2` from the ALPN list, ensuring at least `http/1.1` remains.
///
/// All protocol-selection decisions live in lkrequest — lktls only
/// encodes whatever list it receives.  This helper is the single place
/// that produces an H1-only ALPN list from a profile's base list.
pub(crate) fn alpn_for_h1_only(base: &[String]) -> Vec<String> {
    let filtered: Vec<String> = base.iter().filter(|p| *p != "h2").cloned().collect();
    if filtered.is_empty() {
        vec!["http/1.1".to_string()]
    } else {
        filtered
    }
}

// ---------------------------------------------------------------------------
// ConnectConfig builders
// ---------------------------------------------------------------------------

/// Build a [`crate::connect::ConnectConfig`] with TLS profile and ALPS payload appropriate
/// for the given HTTP version preference and scheme.
pub(crate) fn build_connect_config(
    client: &Client,
    http_version_pref: PreferredHttpVersion,
    scheme: Scheme,
) -> crate::connect::ConnectConfig {
    let mut tls_profile = client.tls_profile().clone();
    if http_version_pref == PreferredHttpVersion::Http1Only {
        tls_profile.alpn_protocols = alpn_for_h1_only(&tls_profile.alpn_protocols);
    }

    // ALPS: real Chrome advertises `application_settings: h2` in the ClientHello
    // but sends an EMPTY client-settings payload in its Client EncryptedExtensions
    // (verified from a real Chrome capture). Advertise iff the profile declares
    // ALPS support; never for the H1-only path. `Some(empty)` = advertise + empty.
    let alps_payload = if http_version_pref == PreferredHttpVersion::Http1Only {
        None
    } else if tls_profile.alps_protocols.is_some() {
        Some(Vec::new())
    } else {
        None
    };

    let config = crate::connect::ConnectConfig::https(tls_profile, alps_payload);
    if scheme == Scheme::Http {
        config.into_http()
    } else {
        config
    }
}

/// Build a [`crate::connect::ConnectConfig`] with H1-only ALPN (used for H2→H1 fallback).
pub(crate) fn build_h1_only_connect_config(
    client: &Client,
    scheme: Scheme,
) -> crate::connect::ConnectConfig {
    let mut h1_profile = client.tls_profile().clone();
    h1_profile.alpn_protocols = alpn_for_h1_only(&h1_profile.alpn_protocols);
    let config = crate::connect::ConnectConfig::https(h1_profile, None);
    if scheme == Scheme::Http {
        config.into_http()
    } else {
        config
    }
}

// ---------------------------------------------------------------------------
// H1 handshake
// ---------------------------------------------------------------------------

/// Perform HTTP/1.1 handshake on a transport stream and spawn the connection
/// driver task.
pub(crate) async fn handshake_h1(
    stream: crate::connect::TransportStream,
) -> Result<(
    hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
    Arc<tokio::task::JoinHandle<()>>,
)> {
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.title_case_headers(true).preserve_header_case(true);
    let (sender, conn) = builder
        .handshake::<crate::connect::TransportStream, Full<bytes::Bytes>>(stream)
        .await
        .map_err(|e| Error::Http(format!("HTTP/1.1 handshake failed: {e}")))?;

    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            let err_str = e.to_string();
            if err_str.contains("connection closed") || err_str.contains("EOF") {
                tracing::debug!(error = %e, "h1.connection_closed");
            } else {
                tracing::error!(error = %e, "h1.connection_error");
            }
        }
    });

    Ok((sender, Arc::new(conn_task)))
}

// ---------------------------------------------------------------------------
// ALPN protocol selection
// ---------------------------------------------------------------------------

/// Decide whether to use HTTP/2 based on ALPN negotiation result and the
/// caller's version preference. Returns `Err` when `Http2Only` is required
/// but the server did not negotiate h2.
pub(crate) fn should_use_h2(
    negotiated_alpn: Option<&str>,
    http_version_pref: PreferredHttpVersion,
) -> Result<bool> {
    match (negotiated_alpn, http_version_pref) {
        (_, PreferredHttpVersion::Http1Only) => Ok(false),
        (Some("h2"), _) => Ok(true),
        (_, PreferredHttpVersion::Http2Only) => Err(Error::Http(
            "HTTP/2 required but server did not negotiate h2 via ALPN".into(),
        )),
        _ => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// H2 connection establishment + pooling
// ---------------------------------------------------------------------------

/// Perform H2 handshake, insert the connection into the pool, and return
/// a ready sender.
pub(crate) async fn establish_h2_and_pool(
    stream: crate::connect::TransportStream,
    client: &Client,
    session: &Session,
    conn_key: &ConnectionKey,
    permit: ConnectionPermit,
) -> Result<lkh2::H2ReadySender> {
    let h2_conn = crate::h2::connect_h2_with_config(
        stream,
        client.h2_profile(),
        None,
        client.max_pending_h2_requests(),
    )
    .await?;
    let sender = h2_conn.clone_sender();

    {
        let mut pool = session.inner.pool.lock();
        pool.insert_h2_reserved(
            conn_key.clone(),
            h2_conn.clone_sender(),
            h2_conn.into_task(),
            permit,
        );
    }

    sender
        .ready()
        .await
        .map_err(|e| Error::H2(format!("H2 connection not ready: {e}")))
}

/// Establish an H2 connection with the first request sent back-to-back with
/// the connection preface (matching Chrome's TLS record pattern).
///
/// Returns `(h2_response, pool_sender)`:
/// - `h2_response`: the response future for the piggybacked first request
/// - `pool_sender`: a ready sender for subsequent requests on this connection
///
/// Uses the native H2 backend.
pub(crate) async fn establish_h2_with_first_request(
    stream: crate::connect::TransportStream,
    client: &Client,
    session: &Session,
    conn_key: &ConnectionKey,
    first_request: http::Request<Option<bytes::Bytes>>,
    permit: ConnectionPermit,
) -> Result<(lkh2::driver::FirstRequestResponse, lkh2::H2ReadySender)> {
    let mut h2_conn = crate::h2::connect_h2_with_config(
        stream,
        client.h2_profile(),
        Some(first_request),
        client.max_pending_h2_requests(),
    )
    .await?;

    let first_resp = h2_conn
        .take_first_response()
        .ok_or_else(|| Error::H2("first_request response channel missing".into()))?;

    let sender = h2_conn.clone_sender();

    {
        let mut pool = session.inner.pool.lock();
        pool.insert_h2_reserved(
            conn_key.clone(),
            h2_conn.clone_sender(),
            h2_conn.into_task(),
            permit,
        );
    }

    let ready_sender = sender
        .ready()
        .await
        .map_err(|e| Error::H2(format!("H2 connection not ready: {e}")))?;

    Ok((first_resp, ready_sender))
}

// ---------------------------------------------------------------------------
// URI / Host header helpers
// ---------------------------------------------------------------------------

/// Build an absolute URI for HTTP/2 `:path` + `:authority` pseudo-headers.
pub(crate) fn build_h2_uri(scheme: Scheme, host: &str, port: u16, path: &str) -> String {
    let scheme_str = match scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    if (scheme == Scheme::Https && port == 443) || (scheme == Scheme::Http && port == 80) {
        format!("{scheme_str}://{host}{path}")
    } else {
        format!("{scheme_str}://{host}:{port}{path}")
    }
}

/// Build the `Host` header value, omitting the port when it matches the
/// scheme's default (443 for HTTPS, 80 for HTTP).
pub(crate) fn build_host_value(scheme: Scheme, host: &str, port: u16) -> String {
    if (scheme == Scheme::Https && port == 443) || (scheme == Scheme::Http && port == 80) {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Build the `Host` header value from a parsed URL.
///
/// Extracts scheme, host, and port from the `Url` and delegates to
/// [`build_host_value`].
pub(crate) fn build_host_value_from_url(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let scheme = match url.scheme() {
        "https" => Scheme::Https,
        _ => Scheme::Http,
    };
    let port = url
        .port_or_known_default()
        .unwrap_or(if scheme == Scheme::Https { 443 } else { 80 });
    Some(build_host_value(scheme, host, port))
}

// ---------------------------------------------------------------------------
// Content-Length auto-insert
// ---------------------------------------------------------------------------

/// Auto-insert `Content-Length` when the request has a body and the header
/// is not already present. Matches the behavior of curl, reqwest, and browsers.
pub(crate) fn auto_insert_content_length(headers: &mut HeaderMap, body: Option<&bytes::Bytes>) {
    if let Some(data) = body {
        if !headers.contains_key(http::header::CONTENT_LENGTH) {
            let len = data.len().to_string();
            if let Ok(hv) = http::header::HeaderValue::from_str(&len) {
                headers.insert(http::header::CONTENT_LENGTH, hv);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cookie storage
// ---------------------------------------------------------------------------

/// Store Set-Cookie headers from a response in the session's cookie jar.
///
/// Uses ArcSwap's `rcu()` (read-copy-update) for safe concurrent writes.
pub(crate) fn store_cookies(session: &Session, resp_headers: &HeaderMap, parsed_url: &Url) {
    let set_cookies: Vec<_> = resp_headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    if !set_cookies.is_empty() {
        tracing::trace!(
            count = set_cookies.len(),
            url = %parsed_url,
            "http.cookies_received",
        );
        let url = parsed_url.clone();
        session.inner.cookie_jar.rcu(move |old| {
            let mut new_jar = (**old).clone();
            for raw_cookie in &set_cookies {
                if let Ok(set_cookie) = cookie_store::RawCookie::parse(raw_cookie.as_str()) {
                    let _ = new_jar.insert_raw(&set_cookie, &url);
                }
            }
            new_jar
        });
    }
}

/// Store `Alt-Svc` advertisements from response headers.
/// Translate the connection-layer [`Scheme`] into the origin-layer
/// [`OriginScheme`] used by Alt-Svc and broken-QUIC tracking.
pub(crate) fn origin_scheme_from(scheme: Scheme) -> OriginScheme {
    match scheme {
        Scheme::Http => OriginScheme::Http,
        Scheme::Https => OriginScheme::Https,
    }
}

pub(crate) fn store_alt_svc(
    session: &Session,
    resp_headers: &HeaderMap,
    proxy: Option<&ProxyConfig>,
    scheme: Scheme,
    host: &str,
    port: u16,
) {
    let alt_svc: Vec<_> = resp_headers
        .get_all("alt-svc")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();

    if !alt_svc.is_empty() {
        let origin = Origin::new(origin_scheme_from(scheme), host, port);
        let route = RouteKey::from_proxy(proxy);
        session
            .alt_svc_cache()
            .store_from_header_for_route(&route, &origin, &alt_svc.join(", "));
    }
}

// ---------------------------------------------------------------------------
// Header merging
// ---------------------------------------------------------------------------

/// Merge default headers, request headers, and cookies into `target`.
///
/// Thin wrapper around [`super::transport::merge_headers_common`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_headers(
    target: &mut HeaderMap,
    client: &Client,
    extra_headers: &HeaderMap,
    parsed_url: &Url,
    is_h1: bool,
    session: &Session,
    extra_cookies: &[(String, String)],
    cookie_overrides: &[String],
    header_order: &[http::header::HeaderName],
    cookie_order: Option<&[Box<str>]>,
) {
    super::transport::merge_headers_common(
        target,
        client,
        extra_headers,
        parsed_url,
        is_h1,
        &session.inner.cookie_jar,
        extra_cookies,
        cookie_overrides,
        header_order,
        cookie_order,
    );
}

// ---------------------------------------------------------------------------
// Pool acquisition
// ---------------------------------------------------------------------------

/// Try to acquire a pooled connection, filtering by HTTP version preference.
pub(crate) fn try_acquire_pooled(
    session: &Session,
    conn_key: &ConnectionKey,
    http_version: PreferredHttpVersion,
) -> Option<AcquiredConnection> {
    let mut pool = session.inner.pool.lock();
    match http_version {
        PreferredHttpVersion::Auto => pool.try_acquire_internal(conn_key),
        PreferredHttpVersion::Http1Only => pool.try_acquire_h1_pooled_internal(conn_key),
        PreferredHttpVersion::Http2Only => pool.try_acquire_h2_pooled_internal(conn_key),
        PreferredHttpVersion::Http3Only | PreferredHttpVersion::Http3WithFallback => {
            pool.try_acquire_h3_pooled_internal(conn_key)
        }
    }
}

// ---------------------------------------------------------------------------
// Effective config resolution
// ---------------------------------------------------------------------------

/// Resolve the effective header order: request → session → client → insertion order.
pub(crate) fn effective_header_order<'a>(
    request_explicit: Option<&'a [http::header::HeaderName]>,
    session_explicit: Option<&'a [http::header::HeaderName]>,
    client_explicit: Option<&'a [http::header::HeaderName]>,
    request_insertion_order: &'a [http::header::HeaderName],
) -> &'a [http::header::HeaderName] {
    request_explicit
        .or(session_explicit)
        .or(client_explicit)
        .unwrap_or(request_insertion_order)
}

/// Resolve the effective HTTP/3 header order:
/// request H3-specific → request generic → session H3-specific → session generic
/// → client H3-specific → client generic → insertion order.
#[cfg(feature = "quic-h3")]
pub(crate) fn effective_h3_header_order<'a>(
    request_h3: Option<&'a [http::header::HeaderName]>,
    request_explicit: Option<&'a [http::header::HeaderName]>,
    session_h3: Option<&'a [http::header::HeaderName]>,
    session_explicit: Option<&'a [http::header::HeaderName]>,
    client_h3: Option<&'a [http::header::HeaderName]>,
    client_explicit: Option<&'a [http::header::HeaderName]>,
    request_insertion_order: &'a [http::header::HeaderName],
) -> &'a [http::header::HeaderName] {
    request_h3
        .or(request_explicit)
        .or(session_h3)
        .or(session_explicit)
        .or(client_h3)
        .or(client_explicit)
        .unwrap_or(request_insertion_order)
}

/// Resolve the effective cookie order: request → session → client.
pub(crate) fn effective_cookie_order<'a>(
    request_explicit: Option<&'a [Box<str>]>,
    session_explicit: Option<&'a [Box<str>]>,
    client_explicit: Option<&'a [Box<str>]>,
) -> Option<&'a [Box<str>]> {
    request_explicit.or(session_explicit).or(client_explicit)
}

/// Resolve the effective RFC 9218 request priority.
///
/// Precedence: explicit `.priority()` → a `priority` request/default header →
/// derived from `Sec-Fetch-Dest` (Chrome's resource-type mapping) → `None`
/// (caller applies its own default). Headers are looked up per-request first,
/// then in the client defaults.
pub(crate) fn resolve_request_priority(
    explicit: Option<lkh2::RequestPriority>,
    request_headers: &http::HeaderMap,
    default_headers: &http::HeaderMap,
) -> Option<lkh2::RequestPriority> {
    if explicit.is_some() {
        return explicit;
    }
    let lookup = |name: &str| {
        request_headers
            .get(name)
            .or_else(|| default_headers.get(name))
            .and_then(|v| v.to_str().ok())
    };
    if let Some(hv) = lookup("priority") {
        return lkh2::RequestPriority::from_header_value(hv);
    }
    if let Some(dest) = lookup("sec-fetch-dest") {
        return lkh2::RequestPriority::from_sec_fetch_dest(dest);
    }
    None
}

/// Resolve the effective proxy: per-request override → session default.
pub(crate) fn effective_proxy<'a>(
    proxy_override: Option<&'a ProxyConfig>,
    session: &'a Session,
) -> Option<&'a ProxyConfig> {
    proxy_override.or(session.inner.proxy.as_ref())
}

/// Resolve the effective protocol policy: request override → session default.
pub(crate) fn effective_protocol_policy(
    request_policy_override: Option<&ProtocolPolicy>,
    session: &Session,
) -> ProtocolPolicy {
    request_policy_override
        .cloned()
        .unwrap_or_else(|| session.inner.protocol_policy.clone())
}

#[allow(deprecated)]
pub(crate) fn protocol_policy_http_version(policy: &ProtocolPolicy) -> PreferredHttpVersion {
    match policy.intent {
        HttpIntent::H2Only => PreferredHttpVersion::Http2Only,
        HttpIntent::H3Only => PreferredHttpVersion::Http3Only,
        HttpIntent::AcquireH3WhenViable | HttpIntent::PreferH3 => {
            PreferredHttpVersion::Http3WithFallback
        }
        HttpIntent::ReuseExistingProtocol | HttpIntent::Auto => PreferredHttpVersion::Auto,
    }
}

#[cfg(feature = "quic-h3")]
#[allow(deprecated)]
pub(crate) fn protocol_policy_chrome_like_config(
    policy: &ProtocolPolicy,
    legacy_override: ChromeLikeProtocolConfig,
) -> ChromeLikeProtocolConfig {
    match &policy.acquisition {
        AcquisitionPolicy::Race(RacePolicy { tcp_delay, .. }) => ChromeLikeProtocolConfig {
            tcp_main_job_delay: *tcp_delay,
            keep_quic_probe_after_tcp_win: matches!(
                policy.upgrade,
                UpgradePolicy::ProbeOnly
                    | UpgradePolicy::ProbeAndMigrate
                    | UpgradePolicy::ForceForNewRequests
                    | UpgradePolicy::BackgroundProbe
                    | UpgradePolicy::BackgroundProbeAndMigrate
                    | UpgradePolicy::ForceUpgradeForNewRequests
            ),
            keep_tcp_probe_after_quic_win: false,
        },
        _ => legacy_override,
    }
}

/// Resolve the effective HTTP version: per-request override → policy-derived
/// session default, with legacy H1-only compatibility preserved.
pub(crate) fn effective_http_version(
    version_override: Option<PreferredHttpVersion>,
    policy: &ProtocolPolicy,
    session: &Session,
) -> PreferredHttpVersion {
    version_override
        .or({
            if session.inner.preferred_http_version == PreferredHttpVersion::Http1Only {
                Some(PreferredHttpVersion::Http1Only)
            } else {
                None
            }
        })
        .unwrap_or_else(|| protocol_policy_http_version(policy))
}

/// Determine whether QUIC should be skipped before protocol selection.
#[allow(dead_code)]
pub(crate) fn should_skip_quic(
    proxy: Option<&ProxyConfig>,
    session: &Session,
    origin: &Origin,
) -> bool {
    alt_svc::should_skip_quic(proxy, session.broken_quic_tracker(), origin)
}

pub(crate) async fn discover_quic_support(
    session: &Session,
    scheme: Scheme,
    host: &str,
    port: u16,
    proxy: Option<&ProxyConfig>,
    policy: &ProtocolPolicy,
    http_version: PreferredHttpVersion,
) -> QuicDiscovery {
    let origin = Origin::new(origin_scheme_from(scheme), host, port);
    let route = RouteKey::from_proxy(proxy);
    if scheme != Scheme::Https {
        return QuicDiscovery {
            route,
            origin,
            learned_state: LearnedProtocolState {
                alt_svc: None,
                h3_status: H3Reachability::Unknown,
                last_validated_at: None,
            },
            source: None,
            force_attempt: false,
            advertised_host: None,
            advertised_port: None,
            dns_https: None,
            skip_reason: Some(QuicSkipReason::CleartextHttp),
        };
    }

    if matches!(
        http_version,
        PreferredHttpVersion::Http1Only | PreferredHttpVersion::Http2Only
    ) {
        return QuicDiscovery {
            route,
            origin,
            learned_state: LearnedProtocolState {
                alt_svc: None,
                h3_status: H3Reachability::Unknown,
                last_validated_at: None,
            },
            source: None,
            force_attempt: false,
            advertised_host: None,
            advertised_port: None,
            dns_https: None,
            skip_reason: Some(QuicSkipReason::HttpVersionPreference),
        };
    }

    if session.client().quic_profile().is_none() {
        return QuicDiscovery {
            route,
            origin,
            learned_state: LearnedProtocolState {
                alt_svc: None,
                h3_status: H3Reachability::Unknown,
                last_validated_at: None,
            },
            source: None,
            force_attempt: false,
            advertised_host: None,
            advertised_port: None,
            dns_https: None,
            skip_reason: Some(QuicSkipReason::MissingProfile),
        };
    }

    let learned_state = learned_protocol_state_for_route(
        session.alt_svc_cache(),
        session.broken_quic_tracker(),
        &route,
        &origin,
    );
    let alt_svc = learned_state.alt_svc.clone();
    // DNS-based H3 discovery only on routes where we resolve locally. On
    // remote-DNS routes (socks5h / HTTP CONNECT) the proxy resolves the target,
    // so a local HTTPS-RR (SVCB) query here would leak the target hostname
    // out-of-band from the proxy — skip it.
    let dns_https = if route.dns_mode == DnsResolutionMode::Local {
        session
            .client()
            .resolver()
            .lookup_https(host)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let (source, advertised_host, advertised_port) = if let Some(entry) = alt_svc {
        (
            Some(QuicDiscoverySource::AltSvc),
            entry.host,
            Some(entry.port),
        )
    } else if let Some(record) = dns_https.as_ref().filter(|record| record.supports_h3()) {
        (
            Some(QuicDiscoverySource::DnsHttps),
            record.target.clone(),
            Some(record.port.unwrap_or(port)),
        )
    } else {
        (None, None, None)
    };

    let force = matches!(http_version, PreferredHttpVersion::Http3Only)
        || matches!(policy.intent, HttpIntent::H3Only);

    let is_http_proxy =
        proxy.is_some_and(|p| matches!(p.scheme, crate::proxy::ProxyScheme::Http { .. }));

    // A route-level quarantine (e.g. the proxy's SOCKS5 UDP ASSOCIATE failed)
    // makes QUIC impossible for *every* origin behind that proxy, regardless of
    // what Alt-Svc/DNS advertised. Consult it before the per-origin signals so a
    // broken relay short-circuits to TCP instead of re-incurring the UDP timeout
    // on each request.
    let route_udp_broken = session.broken_quic_tracker().is_route_broken(&route);

    let skip_reason = if route_udp_broken && !force {
        Some(QuicSkipReason::ProxyUdpUnavailable)
    } else if source.is_none() {
        None
    } else if is_http_proxy && !force {
        Some(QuicSkipReason::HttpProxyConfigured)
    } else if matches!(
        learned_state.h3_status,
        H3Reachability::FailedTransiently | H3Reachability::FailedPersistently
    ) && !force
    {
        Some(QuicSkipReason::BrokenOrigin)
    } else {
        None
    };

    QuicDiscovery {
        route,
        origin,
        learned_state,
        source,
        force_attempt: force,
        advertised_host,
        advertised_port,
        dns_https,
        skip_reason,
    }
}

pub(crate) fn log_quic_discovery(discovery: &QuicDiscovery) {
    match (discovery.source, discovery.skip_reason) {
        (Some(source), None) => {
            tracing::debug!(
                route = %discovery.route,
                host = %discovery.origin.host,
                port = discovery.origin.port,
                source = source.as_str(),
                h3_status = ?discovery.learned_state.h3_status,
                last_validated = ?discovery.learned_state.last_validated_at,
                authority = discovery.advertised_authority().as_deref(),
                "quic.discovery_candidate",
            );
        }
        (Some(source), Some(reason)) => {
            tracing::debug!(
                route = %discovery.route,
                host = %discovery.origin.host,
                port = discovery.origin.port,
                source = source.as_str(),
                h3_status = ?discovery.learned_state.h3_status,
                skip_reason = reason.as_str(),
                "quic.discovery_skipped",
            );
        }
        (None, Some(reason)) => {
            tracing::trace!(
                route = %discovery.route,
                host = %discovery.origin.host,
                port = discovery.origin.port,
                skip_reason = reason.as_str(),
                "quic.discovery_unavailable",
            );
        }
        (None, None) => {
            if let Some(record) = discovery.dns_https.as_ref() {
                tracing::trace!(
                    route = %discovery.route,
                    host = %discovery.origin.host,
                    port = discovery.origin.port,
                    advertises_h3 = record.supports_h3(),
                    "quic.discovery_dns_record",
                );
            } else {
                tracing::trace!(
                    route = %discovery.route,
                    host = %discovery.origin.host,
                    port = discovery.origin.port,
                    h3_status = ?discovery.learned_state.h3_status,
                    "quic.discovery_none",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::io;
    use std::sync::Arc;

    fn test_client_builder() -> crate::client::ClientBuilder {
        let builder = crate::Client::builder().fingerprint(lktls::profile::presets::chrome_144());
        #[cfg(feature = "quic-h3")]
        let builder = builder.quic_profile(lkh3::chrome_quic());
        builder
    }

    fn test_session() -> Session {
        test_client_builder().build().session().build()
    }

    fn test_policy() -> ProtocolPolicy {
        ProtocolPolicy::chrome_standard()
    }

    #[test]
    fn resolve_request_priority_precedence() {
        use lkh2::RequestPriority as RP;
        let mk = |pairs: &[(&str, &str)]| {
            let mut h = http::HeaderMap::new();
            for (k, v) in pairs {
                h.insert(
                    http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    http::HeaderValue::from_str(v).unwrap(),
                );
            }
            h
        };
        let empty = http::HeaderMap::new();

        // Explicit `.priority()` wins over everything.
        assert_eq!(
            resolve_request_priority(
                Some(RP::image()),
                &mk(&[("priority", "u=5"), ("sec-fetch-dest", "document")]),
                &empty,
            ),
            Some(RP::image()),
        );
        // `priority` header beats sec-fetch-dest.
        assert_eq!(
            resolve_request_priority(
                None,
                &mk(&[("priority", "u=5"), ("sec-fetch-dest", "document")]),
                &empty,
            ),
            RP::from_header_value("u=5"),
        );
        // sec-fetch-dest derivation when no explicit/header.
        assert_eq!(
            resolve_request_priority(None, &mk(&[("sec-fetch-dest", "style")]), &empty),
            Some(RP::css()),
        );
        // sec-fetch-dest in client defaults is honoured.
        assert_eq!(
            resolve_request_priority(None, &empty, &mk(&[("sec-fetch-dest", "image")])),
            Some(RP::image()),
        );
        // Nothing set → None (caller applies its own default).
        assert_eq!(resolve_request_priority(None, &empty, &empty), None);
    }

    fn discovery_with_state(
        origin: Origin,
        source: Option<QuicDiscoverySource>,
        force_attempt: bool,
        h3_status: H3Reachability,
    ) -> QuicDiscovery {
        QuicDiscovery {
            route: RouteKey::direct(),
            origin,
            learned_state: LearnedProtocolState {
                alt_svc: None,
                h3_status,
                last_validated_at: None,
            },
            source,
            force_attempt,
            advertised_host: None,
            advertised_port: None,
            dns_https: None,
            skip_reason: None,
        }
    }

    #[derive(Clone)]
    struct StubDnsResolver {
        https: Option<HttpsRecord>,
    }

    #[async_trait]
    impl crate::dns::DnsResolver for StubDnsResolver {
        async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
            Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
        }

        async fn lookup_https(&self, _host: &str) -> io::Result<Option<HttpsRecord>> {
            Ok(self.https.clone())
        }
    }

    /// Resolver that records every host passed to `resolve` / `lookup_https`, so
    /// tests can assert that remote-DNS routes perform **no** local DNS for the
    /// target (DNS-leak regression guard — see the gate in `discover_quic_support`
    /// and `Session::build_tls_connector`).
    #[derive(Clone, Default)]
    struct RecordingDns {
        resolve_calls: Arc<std::sync::Mutex<Vec<String>>>,
        https_calls: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl crate::dns::DnsResolver for RecordingDns {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
            self.resolve_calls.lock().unwrap().push(host.to_string());
            Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
        }

        async fn lookup_https(&self, host: &str) -> io::Result<Option<HttpsRecord>> {
            self.https_calls.lock().unwrap().push(host.to_string());
            Ok(None)
        }
    }

    /// A local HTTPS-RR (SVCB) query for the target is a DNS leak on remote-DNS
    /// routes (socks5h / HTTP CONNECT): the proxy resolves the target, so any
    /// local lookup reveals the target hostname out-of-band from the proxy. The
    /// H3-discovery path must skip it there, but still run it on direct routes.
    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn discover_quic_support_does_not_leak_dns_https_on_remote_dns_routes() {
        let rec = RecordingDns::default();
        let session = test_client_builder()
            .dns_resolver(Arc::new(rec.clone()))
            .quic_profile(lkh3::chrome_quic())
            .build()
            .session()
            .build();

        let socks5h = ProxyConfig::parse("socks5h://proxy.example.com:1080").unwrap();
        let _ = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            Some(&socks5h),
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;
        let http = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();
        let _ = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            Some(&http),
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;
        assert!(
            rec.https_calls.lock().unwrap().is_empty(),
            "remote-DNS routes must not perform a local DNS HTTPS-RR lookup (DNS leak); got {:?}",
            rec.https_calls.lock().unwrap()
        );

        // Direct route resolves locally → DNS-based H3 discovery is expected.
        let _ = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            None,
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;
        assert_eq!(
            rec.https_calls.lock().unwrap().as_slice(),
            ["example.com"],
            "direct route should attempt DNS HTTPS-RR discovery exactly once",
        );
    }

    /// DNS-based ECH discovery (an HTTPS-RR lookup) must be skipped on remote-DNS
    /// routes (`is_remote_dns = true`), where a local lookup would leak the target
    /// hostname out-of-band from the proxy; it must still run on local routes.
    #[tokio::test]
    async fn build_tls_connector_does_not_leak_dns_ech_on_remote_dns_routes() {
        let rec = RecordingDns::default();
        let session = test_client_builder()
            .dns_resolver(Arc::new(rec.clone()))
            .build()
            .session()
            .build();
        let profile = lktls::profile::presets::chrome_144();

        let _ = session
            .build_tls_connector(profile.clone(), None, "example.com", true)
            .await;
        assert!(
            rec.https_calls.lock().unwrap().is_empty(),
            "remote-DNS mode must not leak the target via a local DNS ECH lookup; got {:?}",
            rec.https_calls.lock().unwrap()
        );

        let _ = session
            .build_tls_connector(profile, None, "example.com", false)
            .await;
        assert_eq!(
            rec.https_calls.lock().unwrap().as_slice(),
            ["example.com"],
            "local-DNS mode should attempt DNS-based ECH discovery exactly once",
        );
    }

    #[cfg(feature = "quic-h3")]
    fn session_with_dns(https: Option<HttpsRecord>) -> Session {
        test_client_builder()
            .dns_resolver(Arc::new(StubDnsResolver { https }))
            .build()
            .session()
            .build()
    }

    #[test]
    fn store_alt_svc_caches_h3_header() {
        let session = test_session();
        let mut headers = HeaderMap::new();
        headers.insert("alt-svc", r#"h3=":443"; ma=86400"#.parse().unwrap());

        store_alt_svc(&session, &headers, None, Scheme::Https, "example.com", 443);

        assert!(session
            .alt_svc_cache()
            .find_h3(&Origin::https("example.com", 443))
            .is_some());
    }

    #[test]
    fn store_alt_svc_merges_multiple_header_lines() {
        let session = test_session();
        let mut headers = HeaderMap::new();
        headers.append("alt-svc", r#"h3-29=":443"; ma=86400"#.parse().unwrap());
        headers.append(
            "alt-svc",
            r#"h3="alt.example:8443"; ma=60"#.parse().unwrap(),
        );

        store_alt_svc(&session, &headers, None, Scheme::Https, "example.com", 443);

        let entry = session
            .alt_svc_cache()
            .find_h3(&Origin::https("example.com", 443))
            .unwrap();
        assert_eq!(entry.protocol, "h3");
        assert_eq!(entry.host.as_deref(), Some("alt.example"));
        assert_eq!(entry.port, 8443);
    }

    #[test]
    fn should_skip_quic_uses_proxy_and_broken_tracker() {
        let session = test_session();
        let origin = Origin::https("example.com", 443);
        let proxy = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();

        assert!(should_skip_quic(Some(&proxy), &session, &origin));

        session.broken_quic_tracker().mark_broken(&origin);
        assert!(should_skip_quic(None, &session, &origin));

        session.broken_quic_tracker().mark_working(&origin);
        assert!(!should_skip_quic(None, &session, &origin));
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn discover_quic_support_prefers_alt_svc_over_dns_https() {
        let session = session_with_dns(Some(HttpsRecord {
            alpn: vec!["h3".into()],
            target: Some("dns.example".into()),
            port: Some(8443),
            ..HttpsRecord::default()
        }));
        let origin = Origin::https("example.com", 443);
        session
            .alt_svc_cache()
            .store_from_header(&origin, r#"h3="alt.example:9443"; ma=86400"#);

        let discovery = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            None,
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;

        assert_eq!(discovery.source, Some(QuicDiscoverySource::AltSvc));
        assert_eq!(
            discovery.advertised_authority().as_deref(),
            Some("alt.example:9443")
        );
        assert!(discovery.should_attempt_quic());
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn discover_quic_support_uses_dns_https_when_alt_svc_missing() {
        let session = session_with_dns(Some(HttpsRecord {
            alpn: vec!["h2".into(), "h3".into()],
            target: Some("svc.example".into()),
            port: Some(8443),
            ..HttpsRecord::default()
        }));

        let discovery = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            None,
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;

        assert_eq!(discovery.source, Some(QuicDiscoverySource::DnsHttps));
        assert_eq!(
            discovery.advertised_authority().as_deref(),
            Some("svc.example:8443")
        );
        assert!(discovery.should_attempt_quic());
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn discover_quic_support_respects_proxy_and_version_guards() {
        let session = session_with_dns(Some(HttpsRecord {
            alpn: vec!["h3".into()],
            ..HttpsRecord::default()
        }));
        let proxy = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();
        let route = RouteKey::from_proxy(Some(&proxy));
        let origin = Origin::https("example.com", 443);
        session.alt_svc_cache().store_from_header_for_route(
            &route,
            &origin,
            r#"h3=":443"; ma=86400"#,
        );

        let with_proxy = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            Some(&proxy),
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;
        assert_eq!(
            with_proxy.skip_reason,
            Some(QuicSkipReason::HttpProxyConfigured)
        );
        assert!(!with_proxy.should_attempt_quic());

        let forced_h2 = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            None,
            &test_policy(),
            PreferredHttpVersion::Http2Only,
        )
        .await;
        assert_eq!(
            forced_h2.skip_reason,
            Some(QuicSkipReason::HttpVersionPreference)
        );
        assert!(forced_h2.source.is_none());
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn discover_quic_support_skips_when_route_udp_quarantined() {
        use crate::alt_svc::BrokenReason;

        let session = session_with_dns(None);
        let proxy = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        let route = RouteKey::from_proxy(Some(&proxy));
        let origin = Origin::https("example.com", 443);
        session.alt_svc_cache().store_from_header_for_route(
            &route,
            &origin,
            r#"h3=":443"; ma=86400"#,
        );

        let policy = test_policy();

        // SOCKS5 can relay UDP, so by default H3 is attempted.
        let before = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            Some(&proxy),
            &policy,
            PreferredHttpVersion::Auto,
        )
        .await;
        assert!(before.skip_reason.is_none());
        assert!(before.should_attempt_quic());

        // Once the proxy's UDP relay is quarantined, every origin behind it must
        // skip QUIC instead of re-incurring the UDP timeout on each request.
        session
            .broken_quic_tracker()
            .mark_route_broken(&route, BrokenReason::ProxyUdpUnavailable);
        let after = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            Some(&proxy),
            &policy,
            PreferredHttpVersion::Auto,
        )
        .await;
        assert_eq!(after.skip_reason, Some(QuicSkipReason::ProxyUdpUnavailable));
        assert!(!after.should_attempt_quic());

        // Recovery clears the quarantine and H3 becomes eligible again.
        session.broken_quic_tracker().mark_route_working(&route);
        let recovered = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            Some(&proxy),
            &policy,
            PreferredHttpVersion::Auto,
        )
        .await;
        assert!(recovered.skip_reason.is_none());
        assert!(recovered.should_attempt_quic());
    }

    #[tokio::test]
    async fn discover_quic_support_skips_when_client_has_no_quic_profile() {
        let session = crate::Client::builder()
            .disable_http3()
            .dns_resolver(Arc::new(StubDnsResolver {
                https: Some(HttpsRecord {
                    alpn: vec!["h3".into()],
                    ..HttpsRecord::default()
                }),
            }))
            .build()
            .session()
            .build();

        let discovery = discover_quic_support(
            &session,
            Scheme::Https,
            "example.com",
            443,
            None,
            &test_policy(),
            PreferredHttpVersion::Auto,
        )
        .await;

        assert_eq!(discovery.skip_reason, Some(QuicSkipReason::MissingProfile));
        assert!(!discovery.should_attempt_quic());
    }

    #[test]
    fn decide_protocol_matches_preference_and_discovery() {
        let origin = Origin::https("example.com", 443);
        let no_quic = discovery_with_state(origin.clone(), None, false, H3Reachability::Unknown);
        assert_eq!(
            decide_protocol(PreferredHttpVersion::Auto, &test_policy(), &no_quic),
            ProtocolDecision::Tcp
        );

        let discovered = discovery_with_state(
            origin.clone(),
            Some(QuicDiscoverySource::AltSvc),
            false,
            H3Reachability::Advertised,
        );
        assert_eq!(
            decide_protocol(
                PreferredHttpVersion::Auto,
                &ProtocolPolicy::chrome_conservative(),
                &discovered
            ),
            ProtocolDecision::Tcp
        );
        assert_eq!(
            decide_protocol(PreferredHttpVersion::Http3Only, &test_policy(), &discovered),
            ProtocolDecision::Quic
        );
        assert_eq!(
            decide_protocol(PreferredHttpVersion::Auto, &test_policy(), &discovered),
            ProtocolDecision::Race
        );

        let forced = discovery_with_state(origin, None, true, H3Reachability::Unknown);
        assert_eq!(
            decide_protocol(
                PreferredHttpVersion::Http3WithFallback,
                &ProtocolPolicy::h3_strict(),
                &forced
            ),
            ProtocolDecision::Quic
        );
    }

    #[test]
    fn fallback_policy_distinguishes_network_fallback_and_no_fallback() {
        let handshake_error = Error::quic(crate::error::QuicPhase::Handshake, "handshake failed");
        assert!(fallback_permitted(
            &ProtocolPolicy::chrome_standard(),
            &handshake_error
        ));
        assert!(!fallback_permitted(
            &ProtocolPolicy::h3_strict(),
            &handshake_error
        ));
    }

    #[test]
    fn fallback_policy_network_only_rejects_non_network_h3_errors() {
        let request_error = Error::Http3Request("stream reset".into());
        assert!(!fallback_permitted(
            &ProtocolPolicy::chrome_standard(),
            &request_error
        ));
        assert!(fallback_permitted(
            &ProtocolPolicy::crawler_throughput(),
            &request_error
        ));
    }

    #[test]
    fn background_probe_requires_advertised_state_and_upgrade_policy() {
        let advertised = discovery_with_state(
            Origin::https("example.com", 443),
            Some(QuicDiscoverySource::AltSvc),
            false,
            H3Reachability::Advertised,
        );
        let validated = discovery_with_state(
            Origin::https("example.com", 443),
            Some(QuicDiscoverySource::AltSvc),
            false,
            H3Reachability::Validated,
        );
        let mut skipped = advertised.clone();
        skipped.skip_reason = Some(QuicSkipReason::BrokenOrigin);

        assert!(should_background_probe(
            &ProtocolPolicy::chrome_standard(),
            &advertised
        ));
        assert!(!should_background_probe(
            &ProtocolPolicy::chrome_standard(),
            &validated
        ));
        assert!(!should_background_probe(
            &ProtocolPolicy::crawler_throughput(),
            &advertised
        ));
        assert!(!should_background_probe(
            &ProtocolPolicy::chrome_standard(),
            &skipped
        ));
    }

    #[test]
    fn validated_force_upgrade_prefers_quic_for_new_auto_requests() {
        let validated = discovery_with_state(
            Origin::https("example.com", 443),
            Some(QuicDiscoverySource::AltSvc),
            false,
            H3Reachability::Validated,
        );
        let policy =
            ProtocolPolicy::crawler_throughput().with_upgrade(UpgradePolicy::ForceForNewRequests);
        assert_eq!(
            decide_protocol(PreferredHttpVersion::Auto, &policy, &validated),
            ProtocolDecision::Quic
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn effective_h3_header_order_prefers_h3_specific_over_generic() {
        let req_h3 = [http::header::HeaderName::from_static("x-req-h3")];
        let req_generic = [http::header::HeaderName::from_static("x-req")];
        let session_h3 = [http::header::HeaderName::from_static("x-session-h3")];
        let session_generic = [http::header::HeaderName::from_static("x-session")];
        let client_h3 = [http::header::HeaderName::from_static("x-client-h3")];
        let client_generic = [http::header::HeaderName::from_static("x-client")];
        let insertion = [http::header::HeaderName::from_static("x-inserted")];

        assert_eq!(
            effective_h3_header_order(
                Some(&req_h3),
                Some(&req_generic),
                Some(&session_h3),
                Some(&session_generic),
                Some(&client_h3),
                Some(&client_generic),
                &insertion,
            ),
            &req_h3
        );

        assert_eq!(
            effective_h3_header_order(
                None,
                Some(&req_generic),
                Some(&session_h3),
                Some(&session_generic),
                Some(&client_h3),
                Some(&client_generic),
                &insertion,
            ),
            &req_generic
        );

        assert_eq!(
            effective_h3_header_order(
                None,
                None,
                Some(&session_h3),
                Some(&session_generic),
                Some(&client_h3),
                Some(&client_generic),
                &insertion,
            ),
            &session_h3
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn effective_h3_header_order_falls_back_to_generic_and_insertion_order() {
        let session_generic = [http::header::HeaderName::from_static("x-session")];
        let client_generic = [http::header::HeaderName::from_static("x-client")];
        let insertion = [http::header::HeaderName::from_static("x-inserted")];

        assert_eq!(
            effective_h3_header_order(
                None,
                None,
                None,
                Some(&session_generic),
                None,
                Some(&client_generic),
                &insertion,
            ),
            &session_generic
        );

        assert_eq!(
            effective_h3_header_order(
                None,
                None,
                None,
                None,
                None,
                Some(&client_generic),
                &insertion,
            ),
            &client_generic
        );

        assert_eq!(
            effective_h3_header_order(None, None, None, None, None, None, &insertion),
            &insertion
        );
    }
}
