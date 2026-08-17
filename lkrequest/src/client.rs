//! Client — the fingerprint template.
//!
//! A `Client` holds the TLS fingerprint profile, HTTP/2 profile, and default
//! headers.  It is **immutable** after creation, cheap to clone (`Arc`-based),
//! and safe to share across threads and tasks.
//!
//! One `Client` per fingerprint type is sufficient — create multiple
//! [`Session`](crate::session::Session)s from the same `Client` to represent
//! different "virtual users".

use std::sync::Arc;
use std::time::Duration;

use crate::QuicProfile;
use http::header::HeaderName;
use http::HeaderMap;
#[cfg(feature = "quic-h3")]
use lkquic::{
    ChromeConnectionIdGenerator, QuicEndpointManager, QuicEndpointStrategy, QuinnBackend,
};
use lktls::profile::types::TlsProfile;
use lktls::session_store::InMemorySessionStore;
use lktls::KeyLogCallback;
use rustls_pki_types::TrustAnchor;

use crate::dns::{DnsConfig, DnsResolver, SystemDns, SystemDnsCacheConfig};
use crate::h2::H2Profile;
use crate::protocol::ProtocolPolicy;
use crate::session::SessionBuilder;
use crate::tcp_fingerprint::TcpFingerprint;

#[cfg(feature = "quic-h3")]
type SharedQuicEndpointManager =
    tokio::sync::Mutex<QuicEndpointManager<QuinnBackend, ChromeConnectionIdGenerator>>;

// ---------------------------------------------------------------------------
// TimeoutConfig
// ---------------------------------------------------------------------------

/// Fine-grained timeout configuration for each phase of a request.
///
/// Each timeout controls a specific phase of the request lifecycle.
/// All timeouts are optional — when `None`, reasonable defaults are used.
///
/// The **total timeout** acts as an overall deadline that supersedes all
/// phase-level timeouts.
///
/// # Defaults
///
/// | Phase              | Default   |
/// |--------------------|-----------|
/// | DNS resolution     | 5 seconds |
/// | TCP connect        | 10 seconds |
/// | TLS handshake      | 10 seconds |
/// | QUIC handshake     | 10 seconds |
/// | TTFB (first byte)  | 30 seconds |
/// | Total request      | 60 seconds |
///
/// # Example
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use lkrequest::{Client, TimeoutConfig};
/// use lktls::profile::presets;
/// use std::time::Duration;
///
/// let timeouts = TimeoutConfig::default()
///     .with_dns_timeout(Duration::from_secs(2))
///     .with_tls_handshake_timeout(Duration::from_secs(5));
///
/// let client = Client::builder()
///     .fingerprint(presets::chrome_144())
///     .timeout_config(timeouts)
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// DNS resolution timeout.
    pub dns_timeout: Option<Duration>,
    /// TCP connection timeout (SYN → SYN-ACK).
    pub tcp_connect_timeout: Option<Duration>,
    /// TLS handshake timeout (ClientHello → Finished).
    pub tls_handshake_timeout: Option<Duration>,
    /// QUIC connection timeout (Initial → Handshake Complete).
    pub quic_connect_timeout: Option<Duration>,
    /// Time to first byte (TTFB): from request sent to first response byte.
    pub ttfb_timeout: Option<Duration>,
    /// Total request timeout (overall deadline for the entire request).
    pub total_timeout: Option<Duration>,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            dns_timeout: Some(Duration::from_secs(5)),
            tcp_connect_timeout: Some(Duration::from_secs(10)),
            tls_handshake_timeout: Some(Duration::from_secs(10)),
            quic_connect_timeout: Some(Duration::from_secs(10)),
            ttfb_timeout: Some(Duration::from_secs(30)),
            total_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl TimeoutConfig {
    /// Create a config with no timeouts (infinite).
    pub fn none() -> Self {
        Self {
            dns_timeout: None,
            tcp_connect_timeout: None,
            tls_handshake_timeout: None,
            quic_connect_timeout: None,
            ttfb_timeout: None,
            total_timeout: None,
        }
    }

    /// Set DNS resolution timeout.
    pub fn with_dns_timeout(mut self, t: Duration) -> Self {
        self.dns_timeout = Some(t);
        self
    }

    /// Set TCP connect timeout.
    pub fn with_tcp_connect_timeout(mut self, t: Duration) -> Self {
        self.tcp_connect_timeout = Some(t);
        self
    }

    /// Set TLS handshake timeout.
    pub fn with_tls_handshake_timeout(mut self, t: Duration) -> Self {
        self.tls_handshake_timeout = Some(t);
        self
    }

    /// Set QUIC connection timeout (Initial packet → handshake complete).
    pub fn with_quic_connect_timeout(mut self, t: Duration) -> Self {
        self.quic_connect_timeout = Some(t);
        self
    }

    /// Set TTFB (time to first byte) timeout.
    pub fn with_ttfb_timeout(mut self, t: Duration) -> Self {
        self.ttfb_timeout = Some(t);
        self
    }

    /// Set total request timeout.
    pub fn with_total_timeout(mut self, t: Duration) -> Self {
        self.total_timeout = Some(t);
        self
    }

    /// DNS timeout with fallback to a default.
    #[allow(dead_code)]
    pub(crate) fn dns_timeout_or(&self, default: Duration) -> Duration {
        self.dns_timeout.unwrap_or(default)
    }

    /// TCP connect timeout with fallback.
    pub(crate) fn tcp_connect_timeout_or(&self, default: Duration) -> Duration {
        self.tcp_connect_timeout.unwrap_or(default)
    }

    /// TLS handshake timeout with fallback.
    pub(crate) fn tls_handshake_timeout_or(&self, default: Duration) -> Duration {
        self.tls_handshake_timeout.unwrap_or(default)
    }

    /// TTFB timeout with fallback.
    #[allow(dead_code)]
    pub(crate) fn ttfb_timeout_or(&self, default: Duration) -> Duration {
        self.ttfb_timeout.unwrap_or(default)
    }

    /// Total timeout with fallback.
    pub(crate) fn total_timeout_or(&self, default: Duration) -> Duration {
        self.total_timeout.unwrap_or(default)
    }

    /// Merge `other` into `self`: fields set in `other` override those in `self`.
    #[allow(dead_code)]
    pub(crate) fn merge_overrides(&self, overrides: &TimeoutConfig) -> TimeoutConfig {
        TimeoutConfig {
            dns_timeout: overrides.dns_timeout.or(self.dns_timeout),
            tcp_connect_timeout: overrides.tcp_connect_timeout.or(self.tcp_connect_timeout),
            tls_handshake_timeout: overrides
                .tls_handshake_timeout
                .or(self.tls_handshake_timeout),
            quic_connect_timeout: overrides.quic_connect_timeout.or(self.quic_connect_timeout),
            ttfb_timeout: overrides.ttfb_timeout.or(self.ttfb_timeout),
            total_timeout: overrides.total_timeout.or(self.total_timeout),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceLimits
// ---------------------------------------------------------------------------

/// Resource limits to protect against denial-of-service and memory exhaustion.
///
/// These limits apply to individual HTTP responses and connections within
/// a session. They provide a safety net in production environments.
///
/// # Defaults
///
/// | Limit                       | Default    |
/// |-----------------------------|------------|
/// | Max response body size      | 100 MB     |
/// | Max header count            | 256        |
/// | Max single header size      | 16 KB      |
/// | Max total headers size      | 1 MB       |
/// | Max connections per session | 64         |
/// | Min transfer rate           | None       |
/// | Transfer rate window        | 10 seconds |
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum response body size in bytes.
    /// Responses exceeding this limit will be aborted.
    pub max_response_body_size: usize,
    /// Maximum number of headers in a response.
    pub max_header_count: usize,
    /// Maximum size of a single header (name + value, in bytes).
    pub max_header_size: usize,
    /// Maximum total size of all headers combined (in bytes).
    pub max_headers_total_size: usize,
    /// Maximum number of connections per session (hard upper limit).
    pub max_connections_per_session: usize,
    /// Minimum transfer rate in bytes/second.
    /// If the transfer rate falls below this for the duration of
    /// `transfer_rate_window`, the connection is aborted (slowloris protection).
    pub min_transfer_rate: Option<usize>,
    /// Window over which the minimum transfer rate is measured.
    pub transfer_rate_window: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_response_body_size: 100 * 1024 * 1024, // 100 MB
            max_header_count: 256,
            max_header_size: 16 * 1024,          // 16 KB
            max_headers_total_size: 1024 * 1024, // 1 MB
            max_connections_per_session: 64,
            min_transfer_rate: None,
            transfer_rate_window: Duration::from_secs(10),
        }
    }
}

impl ResourceLimits {
    /// Create limits with no restrictions.
    pub fn none() -> Self {
        Self {
            max_response_body_size: usize::MAX,
            max_header_count: usize::MAX,
            max_header_size: usize::MAX,
            max_headers_total_size: usize::MAX,
            max_connections_per_session: usize::MAX,
            min_transfer_rate: None,
            transfer_rate_window: Duration::from_secs(10),
        }
    }

    /// Set maximum response body size.
    pub fn with_max_response_body_size(mut self, size: usize) -> Self {
        self.max_response_body_size = size;
        self
    }

    /// Set maximum connections per session.
    pub fn with_max_connections_per_session(mut self, n: usize) -> Self {
        self.max_connections_per_session = n;
        self
    }

    /// Set minimum transfer rate for slowloris protection.
    pub fn with_min_transfer_rate(mut self, bytes_per_sec: usize, window: Duration) -> Self {
        self.min_transfer_rate = Some(bytes_per_sec);
        self.transfer_rate_window = window;
        self
    }

    /// Check response headers against limits.
    pub(crate) fn check_response_headers(
        &self,
        headers: &http::HeaderMap,
    ) -> crate::error::Result<()> {
        if headers.len() > self.max_header_count {
            return Err(crate::error::Error::ResourceLimitExceeded(format!(
                "response has {} headers, limit is {}",
                headers.len(),
                self.max_header_count,
            )));
        }

        let mut total_size = 0usize;
        for (name, value) in headers.iter() {
            let header_size = name.as_str().len() + value.len();
            if header_size > self.max_header_size {
                return Err(crate::error::Error::ResourceLimitExceeded(format!(
                    "header '{}' is {} bytes, limit is {} bytes",
                    name, header_size, self.max_header_size,
                )));
            }
            total_size += header_size;
        }

        if total_size > self.max_headers_total_size {
            return Err(crate::error::Error::ResourceLimitExceeded(format!(
                "total headers size is {} bytes, limit is {} bytes",
                total_size, self.max_headers_total_size,
            )));
        }

        Ok(())
    }

    /// Check cumulative body size against limits.
    pub(crate) fn check_body_size(&self, current_size: usize) -> crate::error::Result<()> {
        if current_size > self.max_response_body_size {
            return Err(crate::error::Error::ResourceLimitExceeded(format!(
                "response body exceeded limit: {} > {} bytes",
                current_size, self.max_response_body_size,
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FallbackConfig
// ---------------------------------------------------------------------------

/// Configuration for automatic protocol/connection fallback.
///
/// Controls how the client handles certain connection failures by
/// automatically falling back to alternative protocols or connection modes.
///
/// # Safety Note
///
/// `proxy_to_direct` is `false` by default.  Enabling it can cause
/// requests to bypass the proxy and reveal the client's real IP address.
/// Only enable if you understand the privacy implications.
#[derive(Debug, Clone)]
pub struct FallbackConfig {
    /// When true, if HTTP/2 connection setup fails after ALPN negotiation,
    /// the client will automatically retry with HTTP/1.1.
    ///
    /// Default: `true`
    pub h2_to_h1: bool,

    /// When true, if the proxy connection fails, the client will fall back
    /// to a direct connection (bypassing the proxy).
    ///
    /// **Default: `false`** — for safety, proxy bypass is opt-in.
    pub proxy_to_direct: bool,

    /// When true, if a request on a **reused** (pooled) connection fails due
    /// to the connection being closed (reset / EOF / GOAWAY), the client
    /// automatically evicts the dead connection and retries on a fresh one.
    ///
    /// This mirrors the behaviour of Chrome's `ShouldResendRequest()` and
    /// Go's `net/http` Transport: a stale pooled connection is not a fatal
    /// error — the request is transparently retried.
    ///
    /// Default: `true`
    pub retry_on_connection_close: bool,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            h2_to_h1: true,
            proxy_to_direct: false,
            retry_on_connection_close: true,
        }
    }
}

/// An HTTP client with a specific TLS + H2 fingerprint.
///
/// `Client` is `Clone + Send + Sync`.  Cloning is cheap (Arc reference count).
///
/// # Zero-config usage
///
/// `Client` implements `Default`, producing a Chrome 144 TLS + H2 fingerprint
/// — ready to use out of the box for HTTP/1.1 and HTTP/2.
///
/// QUIC/HTTP3 is **opt-in**: set a QUIC profile via [`ClientBuilder::quic_profile`]
/// or use a preset that includes one (e.g. [`crate::preset::chrome_146()`]).
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use lkrequest::Client;
///
/// let client = Client::default();
/// let session = client.session().build();
/// # Ok(())
/// # }
/// ```
///
/// # Custom configuration
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use lkrequest::Client;
/// use lktls::profile::presets;
/// use lkrequest::h2::profile;
/// use std::time::Duration;
///
/// let client = Client::builder()
///     .fingerprint(presets::chrome_144())
///     .h2_profile(profile::chrome_144_h2())
///     .default_header("Accept-Language", "en-US,en;q=0.9")
///     .connect_timeout(Duration::from_secs(10))
///     .build();
///
/// // Create sessions from this client
/// let session = client.session().build();
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
    /// The wire fingerprint this client emits. Held in its own `Arc` so a
    /// session can present a distinct fingerprint (via randomization) while
    /// still sharing all of `inner`'s transport machinery (resolver, QUIC
    /// endpoint, ticket cache). Cloning a `Client` stays two `Arc` bumps.
    pub(crate) fingerprint: Arc<Fingerprint>,
}

impl Default for Client {
    /// Creates a `Client` with Chrome 144 TLS + H2 defaults.
    ///
    /// QUIC/HTTP3 is not enabled by default. Use [`Client::builder()`] with
    /// [`ClientBuilder::quic_profile`] or [`ClientBuilder::preset`] to enable it.
    fn default() -> Self {
        Client::builder().build()
    }
}

/// The wire fingerprint a [`Client`] emits across every layer.
///
/// Grouped apart from [`ClientInner`] on purpose: randomization varies the
/// fingerprint **per session**, whereas everything in `ClientInner` (resolver,
/// QUIC endpoint, ticket cache, middleware, …) is shared across all sessions of
/// a client and must never be duplicated. Keeping the two in separate `Arc`s
/// lets a session swap its fingerprint while sharing the machinery.
pub(crate) struct Fingerprint {
    /// TLS fingerprint profile (drives ClientHello construction).
    pub tls_profile: TlsProfile,

    /// Optional QUIC-specific TLS fingerprint profile.
    pub quic_tls_profile: Option<TlsProfile>,

    /// HTTP/2 fingerprint profile (drives SETTINGS order, pseudo-header order, etc.).
    pub h2_profile: H2Profile,

    /// QUIC / HTTP3 fingerprint profile.
    ///
    /// `None` means this client should not attempt HTTP/3.
    pub quic_profile: Option<QuicProfile>,
}

/// Immutable transport machinery shared by all clones (and all sessions) of a
/// `Client`. The wire fingerprint lives separately in [`Fingerprint`].
pub(crate) struct ClientInner {
    /// Default headers sent with every request (e.g. User-Agent, Accept).
    pub default_headers: HeaderMap,

    /// Header sending order template.
    pub header_order: Option<Vec<HeaderName>>,

    /// HTTP/3-specific header sending order template.
    ///
    /// When set, H3 requests prefer this template over the generic
    /// `header_order`, while request/session-level explicit overrides still win.
    pub h3_header_order: Option<Vec<HeaderName>>,

    /// Cookie sending order template (immutable after creation, uses `Box<str>`
    /// instead of `String` to avoid excess capacity overhead).
    pub cookie_order: Option<Vec<Box<str>>>,

    /// ECHConfigList for real ECH (raw DER bytes).
    pub ech_config: Option<Vec<u8>>,

    /// Custom CA trust anchors (merged with Mozilla root store).
    pub custom_ca_anchors: Option<Arc<Vec<TrustAnchor<'static>>>>,

    /// TCP fingerprint configuration (JA4T).
    pub tcp_fingerprint: Option<TcpFingerprint>,

    /// Fallback configuration (H2→H1.1, proxy→direct).
    pub fallback: FallbackConfig,

    /// Default runtime protocol behavior for sessions created from this client.
    pub default_protocol_policy: ProtocolPolicy,

    /// Client-level middleware stack (applied to all sessions).
    pub middlewares: crate::middleware::MiddlewareStack,

    /// Fine-grained timeout configuration.
    pub timeouts: TimeoutConfig,

    /// Resource limits (body size, header limits, connection caps, etc.).
    pub resource_limits: ResourceLimits,

    /// Optional bound for HTTP/2 requests waiting on remote stream capacity.
    pub max_pending_h2_requests: Option<usize>,

    /// Optional TLS key log callback for SSLKEYLOGFILE output.
    pub keylog_callback: Option<KeyLogCallback>,

    /// Whether to verify TLS certificates. Default: `true`.
    /// Set to `false` to skip certificate verification (insecure, for dev/testing only).
    pub verify: bool,

    /// DNS resolver used for all connections from this client.
    pub resolver: Arc<dyn DnsResolver>,

    /// Shared QUIC endpoint manager for real QUIC/H3 connections.
    #[cfg(feature = "quic-h3")]
    pub quic_endpoint_manager: SharedQuicEndpointManager,

    /// Shared TLS/QUIC session ticket cache for sessions created from this
    /// client. Browsers cache QUIC PSKs at the profile/client level, not per
    /// request session, so H3 resumption and 0-RTT need to cross Session
    /// boundaries.
    pub session_store: Arc<InMemorySessionStore>,

    /// Fingerprint randomization policy. Read at session build to decide
    /// whether each session materializes its own synthetic identity.
    #[cfg(feature = "synthetic-fp")]
    pub randomize: crate::randomize::Randomize,
}

impl Client {
    /// Start building a new `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Create a [`SessionBuilder`] from this client.
    ///
    /// The Session will inherit this client's fingerprint and default config.
    pub fn session(&self) -> SessionBuilder {
        SessionBuilder::new(self.clone())
    }

    /// Returns a reference to the TLS profile.
    pub fn tls_profile(&self) -> &TlsProfile {
        &self.fingerprint.tls_profile
    }

    /// Returns the QUIC-specific TLS profile, if configured.
    pub fn quic_tls_profile(&self) -> Option<&TlsProfile> {
        self.fingerprint.quic_tls_profile.as_ref()
    }

    /// Returns a reference to the H2 profile.
    pub fn h2_profile(&self) -> &H2Profile {
        &self.fingerprint.h2_profile
    }

    /// Returns a reference to the QUIC fingerprint profile.
    pub fn quic_profile(&self) -> Option<&QuicProfile> {
        self.fingerprint.quic_profile.as_ref()
    }

    /// The fingerprint randomization policy this client was built with.
    #[cfg(feature = "synthetic-fp")]
    pub(crate) fn randomize(&self) -> &crate::randomize::Randomize {
        &self.inner.randomize
    }

    /// Derive a session-scoped client that emits a freshly synthesized
    /// fingerprint for the layers selected by `layers`, while sharing **all**
    /// transport machinery (resolver, QUIC endpoint, ticket cache, middleware,
    /// policy) with `self`. Unselected layers keep `self`'s real preset.
    ///
    /// When the TLS layer is synthesized its profile is reused for QUIC-native
    /// TLS (browsers do the same), so `quic_tls_profile` is dropped to fall back
    /// to it. The synthesized QUIC profile is applied only if this client
    /// already had QUIC enabled — randomization never silently turns on H3.
    #[cfg(feature = "synthetic-fp")]
    pub(crate) fn with_synthesized_fingerprint(
        &self,
        id: crate::randomize::FingerprintIdentity,
        layers: crate::randomize::Layers,
    ) -> Client {
        use crate::randomize::Layers;
        Client {
            inner: Arc::clone(&self.inner),
            fingerprint: Arc::new(Fingerprint {
                tls_profile: if layers.contains(Layers::TLS) {
                    id.tls
                } else {
                    self.fingerprint.tls_profile.clone()
                },
                h2_profile: if layers.contains(Layers::H2) {
                    id.h2
                } else {
                    self.fingerprint.h2_profile.clone()
                },
                quic_tls_profile: if layers.contains(Layers::TLS) {
                    None
                } else {
                    self.fingerprint.quic_tls_profile.clone()
                },
                #[cfg(feature = "quic-h3")]
                quic_profile: if layers.contains(Layers::QUIC) {
                    self.fingerprint.quic_profile.as_ref().and(id.quic)
                } else {
                    self.fingerprint.quic_profile.clone()
                },
                #[cfg(not(feature = "quic-h3"))]
                quic_profile: self.fingerprint.quic_profile.clone(),
            }),
        }
    }

    /// Returns the client's default runtime protocol behavior.
    pub fn protocol_policy(&self) -> &ProtocolPolicy {
        &self.inner.default_protocol_policy
    }

    /// Returns a reference to the default headers.
    pub fn default_headers(&self) -> &HeaderMap {
        &self.inner.default_headers
    }

    /// Returns the timeout configuration.
    pub fn timeouts(&self) -> &TimeoutConfig {
        &self.inner.timeouts
    }

    /// Returns the resource limits configuration.
    pub fn resource_limits(&self) -> &ResourceLimits {
        &self.inner.resource_limits
    }

    /// Returns the configured HTTP/2 pending-request bound.
    ///
    /// None means requests waiting for remote stream capacity are unbounded.
    pub fn max_pending_h2_requests(&self) -> Option<usize> {
        self.inner.max_pending_h2_requests
    }

    /// Returns the connect timeout (TCP + TLS combined, for backward compat).
    ///
    /// Computed as `tcp_connect_timeout + tls_handshake_timeout`.
    pub fn connect_timeout(&self) -> Duration {
        let t = &self.inner.timeouts;
        let tcp = t.tcp_connect_timeout.unwrap_or(Duration::from_secs(10));
        let tls = t.tls_handshake_timeout.unwrap_or(Duration::from_secs(10));
        tcp + tls
    }

    /// Returns the read/total timeout (for backward compat).
    pub fn read_timeout(&self) -> Duration {
        self.inner
            .timeouts
            .total_timeout
            .unwrap_or(Duration::from_secs(60))
    }

    /// Returns the header order template, if set.
    pub fn header_order(&self) -> Option<&[HeaderName]> {
        self.inner.header_order.as_deref()
    }

    /// Returns the HTTP/3-specific header order template, if set.
    pub fn h3_header_order(&self) -> Option<&[HeaderName]> {
        self.inner.h3_header_order.as_deref()
    }

    /// Returns the cookie order template, if set.
    pub fn cookie_order(&self) -> Option<&[Box<str>]> {
        self.inner.cookie_order.as_deref()
    }

    /// Returns the ECHConfigList, if set.
    pub fn ech_config(&self) -> Option<&[u8]> {
        self.inner.ech_config.as_deref()
    }

    /// Returns the custom CA trust anchors, if set.
    pub fn custom_ca_anchors(&self) -> Option<&Arc<Vec<TrustAnchor<'static>>>> {
        self.inner.custom_ca_anchors.as_ref()
    }

    /// Returns the TCP fingerprint configuration, if set.
    pub fn tcp_fingerprint(&self) -> Option<&TcpFingerprint> {
        self.inner.tcp_fingerprint.as_ref()
    }

    /// Returns the TLS key log callback, if set.
    pub fn keylog_callback(&self) -> Option<&KeyLogCallback> {
        self.inner.keylog_callback.as_ref()
    }

    /// Returns the fallback configuration.
    pub fn fallback(&self) -> &FallbackConfig {
        &self.inner.fallback
    }

    /// Returns the client-level middleware stack.
    pub(crate) fn middlewares(&self) -> &crate::middleware::MiddlewareStack {
        &self.inner.middlewares
    }

    /// Returns whether TLS certificate verification is enabled.
    pub fn verify(&self) -> bool {
        self.inner.verify
    }

    /// Returns a reference to the DNS resolver.
    pub fn resolver(&self) -> &dyn DnsResolver {
        &*self.inner.resolver
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn quic_endpoint_manager(&self) -> &SharedQuicEndpointManager {
        &self.inner.quic_endpoint_manager
    }

    // -------------------------------------------------------------------
    // Convenience methods (auto-create temporary session)
    // -------------------------------------------------------------------

    /// Start building a GET request using a temporary session.
    ///
    /// This is a convenience shortcut that creates a one-off session
    /// internally. For repeated requests, create a `Session` explicitly
    /// to benefit from connection pooling and cookie persistence.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_144()).build();
    /// let resp = client.get("https://example.com").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().get(url)
    }

    /// Start building a POST request using a temporary session.
    pub fn post(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().post(url)
    }

    /// Start building a PUT request using a temporary session.
    pub fn put(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().put(url)
    }

    /// Start building a DELETE request using a temporary session.
    pub fn delete(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().delete(url)
    }

    /// Start building a HEAD request using a temporary session.
    pub fn head(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().head(url)
    }

    /// Start building a PATCH request using a temporary session.
    pub fn patch(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().patch(url)
    }

    /// Start building an OPTIONS request using a temporary session.
    pub fn options(&self, url: &str) -> crate::session::RequestBuilder {
        self.session().build().options(url)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`Client`].
pub struct ClientBuilder {
    tls_profile: Option<TlsProfile>,
    quic_tls_profile: Option<Option<TlsProfile>>,
    h2_profile: Option<H2Profile>,
    quic_profile: Option<Option<QuicProfile>>,
    default_headers: HeaderMap,
    header_order: Option<Vec<HeaderName>>,
    h3_header_order: Option<Vec<HeaderName>>,
    cookie_order: Option<Vec<Box<str>>>,
    ech_config: Option<Vec<u8>>,
    custom_ca_anchors: Vec<TrustAnchor<'static>>,
    tcp_fingerprint: Option<TcpFingerprint>,
    fallback: FallbackConfig,
    protocol_policy: Option<ProtocolPolicy>,
    middlewares: crate::middleware::MiddlewareStack,
    timeouts: TimeoutConfig,
    resource_limits: ResourceLimits,
    max_pending_h2_requests: Option<usize>,
    keylog_callback: Option<KeyLogCallback>,
    verify: bool,
    resolver: Option<Arc<dyn DnsResolver>>,
    randomize: crate::randomize::Randomize,
}

impl ClientBuilder {
    fn new() -> Self {
        Self {
            tls_profile: None,
            quic_tls_profile: None,
            h2_profile: None,
            quic_profile: None,
            default_headers: HeaderMap::new(),
            header_order: None,
            h3_header_order: None,
            cookie_order: None,
            ech_config: None,
            custom_ca_anchors: Vec::new(),
            tcp_fingerprint: None,
            fallback: FallbackConfig::default(),
            protocol_policy: None,
            middlewares: Vec::new(),
            timeouts: TimeoutConfig::default(),
            resource_limits: ResourceLimits::default(),
            max_pending_h2_requests: None,
            keylog_callback: None,
            verify: true,
            resolver: None,
            randomize: crate::randomize::Randomize::off(),
        }
    }

    /// Set the fingerprint randomization policy.
    ///
    /// Defaults to [`Randomize::off`](crate::randomize::Randomize::off) — the
    /// preset's fingerprint as-is (its own authentic per-connection behavior
    /// still applies). See [`Randomize`](crate::randomize::Randomize) for the
    /// tier model.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lkrequest::{Client, Randomize};
    ///
    /// let client = Client::builder()
    ///     .randomize(Randomize::extension_order())
    ///     .build();
    /// ```
    pub fn randomize(mut self, policy: crate::randomize::Randomize) -> Self {
        self.randomize = policy;
        self
    }

    /// Set the TLS fingerprint profile.
    ///
    /// If not set, defaults to Chrome 144.
    pub fn fingerprint(mut self, profile: TlsProfile) -> Self {
        self.tls_profile = Some(profile);
        self
    }

    /// Set a QUIC-specific TLS fingerprint profile used only for HTTP/3.
    pub fn quic_fingerprint(mut self, profile: TlsProfile) -> Self {
        self.quic_tls_profile = Some(Some(profile));
        self
    }

    /// Use the normal TLS fingerprint profile for HTTP/3 as well.
    pub fn clear_quic_fingerprint(mut self) -> Self {
        self.quic_tls_profile = Some(None);
        self
    }

    /// Apply a high-level client preset bundle.
    ///
    /// Presets can set multiple fingerprint dimensions at once:
    /// TLS, H2, optional QUIC/H3, header order, and cookie order.
    ///
    /// Later builder calls can still override any individual field.
    pub fn preset(self, preset: crate::preset::ClientPreset) -> Self {
        preset.apply(self)
    }

    /// Set the HTTP/2 fingerprint profile.
    ///
    /// Controls SETTINGS order, pseudo-header order, WINDOW_UPDATE, etc.
    /// If not set, defaults to Chrome 144 H2 profile.
    pub fn h2_profile(mut self, profile: H2Profile) -> Self {
        self.h2_profile = Some(profile);
        self
    }

    /// Bound the number of HTTP/2 requests waiting for a remote stream slot.
    ///
    /// The default is unbounded. Once this positive limit is reached, later
    /// requests wait asynchronously until an earlier request is assigned a
    /// stream; they do not fail with a local capacity error.
    pub fn max_pending_h2_requests(mut self, max: usize) -> Self {
        assert!(max > 0, "max_pending_h2_requests must be greater than zero");
        self.max_pending_h2_requests = Some(max);
        self
    }

    /// Restore the default unbounded HTTP/2 pending-request queue.
    pub fn unbounded_pending_h2_requests(mut self) -> Self {
        self.max_pending_h2_requests = None;
        self
    }

    /// Set the QUIC / HTTP/3 fingerprint profile.
    pub fn quic_profile(mut self, profile: QuicProfile) -> Self {
        self.quic_profile = Some(Some(profile));
        self
    }

    /// Disable QUIC / HTTP/3 for this client explicitly.
    ///
    /// Without a QUIC profile, `http3_only()` sessions will fail with
    /// `InvalidConfig`. This is the default when no profile or preset is set,
    /// but calling this explicitly is useful to override a previously applied
    /// preset.
    pub fn disable_http3(mut self) -> Self {
        self.quic_profile = Some(None);
        self
    }

    /// Add a default header that will be included in every request.
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        match (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                self.default_headers.insert(n, v);
            }
            (Err(e), _) => {
                tracing::warn!(header_name = %name, error = %e, "client.default_header: invalid header name, ignored");
            }
            (_, Err(e)) => {
                tracing::warn!(header_name = %name, error = %e, "client.default_header: invalid header value, ignored");
            }
        }
        self
    }

    /// Add a default header using pre-parsed `HeaderName` and `HeaderValue`.
    ///
    /// Avoids the parsing overhead of [`default_header()`](Self::default_header)
    /// when the caller already has typed header values.
    pub fn default_header_typed(
        mut self,
        name: HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        self.default_headers.insert(name, value);
        self
    }

    /// Set the header sending order for requests.
    ///
    /// Headers are reordered before sending to match this template.
    /// Headers not in the template are appended after the ordered ones.
    ///
    /// Different browsers send headers in different orders; this is a
    /// fingerprint dimension that some anti-bot systems check.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::Client;
    /// use lktls::profile::presets;
    ///
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .header_order(vec![
    ///         "user-agent", "accept", "accept-language",
    ///         "accept-encoding", "cookie",
    ///     ])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<HeaderName> = order
            .into_iter()
            .filter_map(|s| HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.header_order = Some(names);
        }
        self
    }

    /// Set the header sending order from a vector of `HeaderName`.
    pub fn header_order_from_names(mut self, order: Vec<HeaderName>) -> Self {
        if !order.is_empty() {
            self.header_order = Some(order);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order for requests.
    pub fn h3_header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<HeaderName> = order
            .into_iter()
            .filter_map(|s| HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.h3_header_order = Some(names);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order from a vector of `HeaderName`.
    pub fn h3_header_order_from_names(mut self, order: Vec<HeaderName>) -> Self {
        if !order.is_empty() {
            self.h3_header_order = Some(order);
        }
        self
    }

    /// Set the cookie sending order within the `Cookie` header.
    ///
    /// Cookies matching names in this template are placed first, in the
    /// template's order.  Remaining cookies are appended after.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::Client;
    /// use lktls::profile::presets;
    ///
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .cookie_order(vec!["session_id", "csrf_token", "_ga"])
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<Box<str>> = order.into_iter().map(Box::from).collect();
        if !names.is_empty() {
            self.cookie_order = Some(names);
        }
        self
    }

    /// Set the cookie sending order from owned strings.
    pub fn cookie_order_from_strings(mut self, order: Vec<String>) -> Self {
        if !order.is_empty() {
            self.cookie_order = Some(order.into_iter().map(String::into_boxed_str).collect());
        }
        self
    }

    /// Set an ECHConfigList for real ECH (Encrypted Client Hello).
    ///
    /// When set, every TLS connection made by sessions of this client will
    /// include this ECHConfig.  The data is raw ECHConfigList bytes (DER),
    /// typically obtained from DNS HTTPS resource records.
    ///
    /// Can be overridden per-session via [`SessionBuilder::ech_config`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # fn fetch_ech_config_from_dns(_: &str) -> Vec<u8> { vec![] }
    /// use lkrequest::Client;
    /// use lktls::profile::presets;
    ///
    /// // ECHConfigList obtained from DNS HTTPS record
    /// let ech_config_list: Vec<u8> = fetch_ech_config_from_dns("example.com");
    ///
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .ech_config(ech_config_list)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.ech_config = Some(config_list);
        self
    }

    /// Add a custom CA certificate in DER format.
    ///
    /// The certificate is parsed into a trust anchor and merged with the
    /// built-in Mozilla root store during TLS certificate verification.
    /// Useful for enterprise environments with internal CAs, or for
    /// debugging with tools like mitmproxy/Charles.
    ///
    /// Can be called multiple times to add multiple CA certificates.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::Client;
    /// use lktls::profile::presets;
    ///
    /// let ca_der = std::fs::read("my-ca.der").unwrap();
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .add_ca_cert_der(&ca_der)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_ca_cert_der(mut self, der: &[u8]) -> Self {
        match lktls::verify::certchain::parse_trust_anchor_from_der(der) {
            Ok(anchor) => self.custom_ca_anchors.push(anchor),
            Err(e) => {
                tracing::warn!(error = %e, "client.add_ca_cert_der: failed to parse DER certificate")
            }
        }
        self
    }

    /// Add custom CA certificates from a PEM-encoded string or file contents.
    ///
    /// Parses all certificates in the PEM data and adds them as trust
    /// anchors.  Supports PEM files containing multiple certificates
    /// (delimited by `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::Client;
    /// use lktls::profile::presets;
    ///
    /// let pem_data = std::fs::read("my-ca-bundle.pem").unwrap();
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .add_ca_certs_pem(&pem_data)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_ca_certs_pem(mut self, pem_data: &[u8]) -> Self {
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::CertificateDer;

        for cert_result in CertificateDer::pem_slice_iter(pem_data) {
            match cert_result {
                Ok(cert) => {
                    let der_bytes: &[u8] = cert.as_ref();
                    match lktls::verify::certchain::parse_trust_anchor_from_der(der_bytes) {
                        Ok(anchor) => self.custom_ca_anchors.push(anchor),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "client.add_ca_certs_pem: failed to parse certificate"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "client.add_ca_certs_pem: failed to parse PEM item"
                ),
            }
        }
        self
    }

    /// Set the TCP fingerprint for JA4T anti-detection.
    ///
    /// Configures TCP socket parameters (Window Size, MSS, Window Scale,
    /// TTL, etc.) to match the JA4T fingerprint of a target browser.
    /// Parameters are applied to the socket **before** `connect()`, so they
    /// influence the SYN packet.
    ///
    /// This is **optional** — most users behind a proxy do not need this,
    /// since the proxy's own TCP stack determines the JA4T seen by the
    /// target server. TCP fingerprint is only applied to **direct**
    /// connections by default.
    ///
    /// # Examples
    ///
    /// Using a browser preset (auto-detects OS):
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::{Client, TcpFingerprint};
    /// use lktls::profile::presets;
    ///
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .tcp_fingerprint(TcpFingerprint::chrome())
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Parsing from a JA4T string:
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::{Client, TcpFingerprint};
    /// use lktls::profile::presets;
    ///
    /// // JA4T format: window_size_options_mss_scale
    /// let fp = TcpFingerprint::from_ja4t("64240_2-1-3-1-1-4_1460_8")?
    ///     .with_ttl(128)
    ///     .with_tcp_nodelay(true);
    ///
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .tcp_fingerprint(fp)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn tcp_fingerprint(mut self, fp: TcpFingerprint) -> Self {
        self.tcp_fingerprint = Some(fp);
        self
    }

    /// Set the full fallback configuration.
    pub fn fallback_config(mut self, config: FallbackConfig) -> Self {
        self.fallback = config;
        self
    }

    /// Set the default runtime protocol behavior for sessions created from
    /// this client.
    pub fn protocol_policy(mut self, policy: ProtocolPolicy) -> Self {
        self.protocol_policy = Some(policy);
        self
    }

    /// Enable or disable H2→H1.1 automatic fallback.
    ///
    /// When enabled (default), if HTTP/2 connection setup fails after ALPN
    /// negotiated h2, the client automatically retries with HTTP/1.1.
    pub fn h2_fallback_h1(mut self, enabled: bool) -> Self {
        self.fallback.h2_to_h1 = enabled;
        self
    }

    /// Enable or disable proxy→direct automatic fallback.
    ///
    /// **Default: `false`**.  When enabled, if the proxy connection fails,
    /// the client falls back to a direct connection.
    ///
    /// **Warning**: this can leak the client's real IP address.
    pub fn proxy_fallback_direct(mut self, enabled: bool) -> Self {
        self.fallback.proxy_to_direct = enabled;
        self
    }

    /// Enable or disable automatic retry on stale pooled connections.
    ///
    /// **Default: `true`**.  When enabled, if a request sent on a reused
    /// (pooled) connection fails because the connection was closed by the
    /// peer (e.g. server idle timeout, GOAWAY, TCP RST), the client
    /// automatically evicts the dead connection and retries on a fresh one.
    pub fn retry_on_connection_close(mut self, enabled: bool) -> Self {
        self.fallback.retry_on_connection_close = enabled;
        self
    }

    /// Add a middleware to the client-level middleware stack.
    ///
    /// Client middlewares are applied to **all** requests from **all** sessions
    /// created by this client.  They execute before session-level middlewares
    /// on the request path, and after them on the response path (onion model).
    ///
    /// Multiple calls append to the stack in order.
    ///
    /// # Example
    ///
    /// ```text
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .middleware(LoggingMiddleware)
    ///     .middleware(RateLimiter::new(10))
    ///     .build();
    /// ```
    pub fn middleware(mut self, mw: impl crate::middleware::Middleware + 'static) -> Self {
        self.middlewares.push(std::sync::Arc::new(mw));
        self
    }

    /// Set the connect timeout (backward compat convenience).
    ///
    /// **Important**: this is a combined budget that is split evenly
    /// between TCP connect and TLS handshake (each phase gets `timeout / 2`).
    /// The two timeouts are enforced **independently** — unused budget from
    /// one phase does *not* carry over to the other.
    ///
    /// For precise control, use [`tcp_connect_timeout()`](Self::tcp_connect_timeout)
    /// and [`tls_handshake_timeout()`](Self::tls_handshake_timeout) instead.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        let half = timeout / 2;
        self.timeouts.tcp_connect_timeout = Some(half);
        self.timeouts.tls_handshake_timeout = Some(timeout - half);
        self
    }

    /// Set the read/response timeout (backward compat convenience).
    ///
    /// Maps to `total_timeout` in the new timeout config.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.total_timeout = Some(timeout);
        self
    }

    /// Set the full timeout configuration.
    ///
    /// This provides fine-grained control over each phase of the request:
    /// DNS, TCP, TLS, TTFB, and total.
    pub fn timeout_config(mut self, config: TimeoutConfig) -> Self {
        self.timeouts = config;
        self
    }

    /// Set the DNS resolution timeout.
    pub fn dns_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.dns_timeout = Some(timeout);
        self
    }

    /// Set the TCP connect timeout (separate from TLS handshake).
    pub fn tcp_connect_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.tcp_connect_timeout = Some(timeout);
        self
    }

    /// Set the TLS handshake timeout.
    pub fn tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.tls_handshake_timeout = Some(timeout);
        self
    }

    /// Set the time-to-first-byte (TTFB) timeout.
    pub fn ttfb_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.ttfb_timeout = Some(timeout);
        self
    }

    /// Set the total request timeout.
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.total_timeout = Some(timeout);
        self
    }

    /// Set resource limits.
    pub fn resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// Set the maximum response body size.
    pub fn max_response_body_size(mut self, size: usize) -> Self {
        self.resource_limits.max_response_body_size = size;
        self
    }

    /// Set the maximum connections per session.
    pub fn max_connections_per_session(mut self, n: usize) -> Self {
        self.resource_limits.max_connections_per_session = n;
        self
    }

    /// Set a TLS key log callback for SSLKEYLOGFILE-compatible output.
    ///
    /// This enables Wireshark decryption of captured TLS traffic.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use lkrequest::Client;
    /// use lkrequest::keylog_to_file;
    ///
    /// let client = Client::builder()
    ///     .keylog(keylog_to_file("sslkeys.log").unwrap())
    ///     .build();
    /// ```
    pub fn keylog(mut self, callback: KeyLogCallback) -> Self {
        self.keylog_callback = Some(callback);
        self
    }

    /// Configure TLS session resumption behaviour.
    ///
    /// Controls whether and how TLS session tickets / PSK are used.
    /// This affects the TLS fingerprint — some anti-bot systems check
    /// whether resumption is attempted consistently.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use lkrequest::Client;
    /// use lktls::profile::presets;
    /// use lktls::profile::types::SessionResumptionConfig;
    ///
    /// // Disable session resumption entirely
    /// let client = Client::builder()
    ///     .fingerprint(presets::chrome_144())
    ///     .session_resumption(SessionResumptionConfig::disabled())
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn session_resumption(
        mut self,
        config: lktls::profile::types::SessionResumptionConfig,
    ) -> Self {
        if let Some(ref mut profile) = self.tls_profile {
            profile.session_resumption = config;
        } else {
            let mut profile = lktls::profile::presets::chrome_144();
            profile.session_resumption = config;
            self.tls_profile = Some(profile);
        }
        self
    }

    // TODO: uncomment when H2BehaviorConfig is implemented in lkh2
    // pub fn h2_behavior_config(mut self, config: crate::h2::profile::H2BehaviorConfig) -> Self {
    //     ...
    // }

    /// Enable or disable TLS certificate verification.
    ///
    /// **Default: `true`**. Set to `false` to skip all certificate
    /// verification. **For development/testing only -- insecure!**
    pub fn verify(mut self, enabled: bool) -> Self {
        self.verify = enabled;
        self
    }

    /// Load the operating system's native CA certificates and add them
    /// as trusted roots, in addition to the built-in Mozilla root store.
    pub fn use_native_certs(mut self) -> Self {
        let result = rustls_native_certs::load_native_certs();
        for cert in result.certs {
            let der_bytes: &[u8] = cert.as_ref();
            if let Ok(anchor) = lktls::verify::certchain::parse_trust_anchor_from_der(der_bytes) {
                self.custom_ca_anchors.push(anchor)
            }
        }
        self
    }

    /// Set the DNS resolver via a [`DnsConfig`] preset.
    ///
    /// If you chain both [`.dns()`](Self::dns) and
    /// [`.dns_resolver()`](Self::dns_resolver), **the last call wins**—each
    /// sets the same underlying resolver slot on the builder.
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
    pub fn dns(mut self, config: DnsConfig) -> Self {
        self.resolver = Some(config.build_resolver());
        self
    }

    /// Use the operating-system DNS resolver with a positive-result cache.
    ///
    /// The default system resolver already coalesces concurrent identical
    /// lookups process-wide and does not cache completed results. This method
    /// additionally enables an instance-local cache for successful lookups.
    /// Errors and empty results are never cached.
    ///
    /// Like [`.dns()`](Self::dns) and [`.dns_resolver()`](Self::dns_resolver),
    /// this replaces the resolver currently configured on the builder, so the
    /// last resolver-setting call wins.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::time::Duration;
    /// use lkrequest::{Client, SystemDnsCacheConfig};
    ///
    /// let client = Client::builder()
    ///     .system_dns_cache(
    ///         SystemDnsCacheConfig::positive(Duration::from_secs(30))
    ///             .with_max_entries(4096),
    ///     )
    ///     .build();
    /// ```
    pub fn system_dns_cache(mut self, config: SystemDnsCacheConfig) -> Self {
        self.resolver = Some(Arc::new(SystemDns::with_cache(config)));
        self
    }

    /// Set a custom DNS resolver implementation.
    ///
    /// Use this for full control over DNS resolution. The resolver must
    /// implement [`DnsResolver`].
    ///
    /// If you chain both [`.dns()`](Self::dns) and
    /// [`.dns_resolver()`](Self::dns_resolver), **the last call wins**—each
    /// sets the same underlying resolver slot on the builder.
    ///
    /// [`HickoryDns::from_config`](crate::dns::HickoryDns::from_config) panics
    /// if the resolver cannot be initialized (e.g. the platform certificate
    /// store fails to load). Use
    /// [`HickoryDns::try_from_config`](crate::dns::HickoryDns::try_from_config)
    /// instead when you need to handle that failure gracefully.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use lkrequest::Client;
    /// use lkrequest::dns::{HickoryDns, DnsResolver};
    ///
    /// let resolver: Arc<dyn DnsResolver> = Arc::new(
    ///     HickoryDns::from_config(&lkrequest::DnsConfig::Cloudflare)
    /// );
    /// let client = Client::builder()
    ///     .dns_resolver(resolver)
    ///     .build();
    /// ```
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Build the `Client`.
    ///
    /// If no TLS fingerprint was set via [`.fingerprint()`](Self::fingerprint),
    /// Chrome 144 is used as the default.  HTTP/2 profile and header order
    /// also default to Chrome 144 when not explicitly configured.
    ///
    /// This means `Client::builder().build()` produces a fully functional
    /// client with Chrome 144 fingerprints out of the box.
    pub fn build(self) -> Client {
        let mut tls_profile = self
            .tls_profile
            .unwrap_or_else(lktls::profile::presets::chrome_144);
        // Apply the randomization policy to the resolved TLS profile. Tier 1
        // (ExtensionOrder) forces per-connection extension-order permutation;
        // Tier 0 (Off) leaves the preset's own behavior untouched.
        if self.randomize.mode() == crate::randomize::RandomizeMode::ExtensionOrder {
            tls_profile
                .randomization
                .get_or_insert_with(Default::default)
                .shuffle_extensions = true;
        }
        let quic_tls_profile = self.quic_tls_profile.unwrap_or(None);

        // Default to Chrome 144 H2 profile if not explicitly set
        let h2_profile = self
            .h2_profile
            .unwrap_or_else(crate::h2::profile::chrome_144_h2);
        let quic_profile = self.quic_profile.unwrap_or_default();

        let header_order = self.header_order;
        let h3_header_order = self.h3_header_order;

        let custom_ca_anchors = if self.custom_ca_anchors.is_empty() {
            None
        } else {
            Some(Arc::new(self.custom_ca_anchors))
        };

        let resolver = self.resolver.unwrap_or_else(|| Arc::new(SystemDns));
        let default_protocol_policy = self.protocol_policy.unwrap_or_default();

        #[cfg(feature = "quic-h3")]
        let endpoint_manager = {
            let (
                cid_len,
                initial_destination_cid_len,
                max_udp_payload_size,
                grease_transport_params,
            ) = quic_profile
                .as_ref()
                .map(|profile| {
                    (
                        profile.connection_id_length,
                        profile.initial_destination_connection_id_length,
                        profile.transport_params.max_udp_payload_size,
                        profile.transport_params.grease_transport_params,
                    )
                })
                .unwrap_or((ChromeConnectionIdGenerator::DEFAULT_LEN, None, None, true));
            let mut manager = QuicEndpointManager::with_backend(
                QuinnBackend::default(),
                ChromeConnectionIdGenerator::new(cid_len)
                    .expect("quic profile connection_id_length must be valid"),
            )
            .grease_quic_bit(grease_transport_params)
            .with_initial_destination_cid_len(initial_destination_cid_len);
            if cid_len == 0 {
                tracing::debug!(
                    "client.build: using per-session QUIC endpoints for zero-length connection IDs"
                );
                manager = manager.strategy(QuicEndpointStrategy::PerSession);
            }
            if let Some(value) = max_udp_payload_size {
                let value = u16::try_from(value)
                    .expect("quic profile max_udp_payload_size must fit into u16");
                manager = manager.max_udp_payload_size(value);
            }
            manager
        };

        Client {
            fingerprint: Arc::new(Fingerprint {
                tls_profile,
                quic_tls_profile,
                h2_profile,
                quic_profile,
            }),
            inner: Arc::new(ClientInner {
                default_headers: self.default_headers,
                header_order,
                h3_header_order,
                cookie_order: self.cookie_order,
                ech_config: self.ech_config,
                custom_ca_anchors,
                tcp_fingerprint: self.tcp_fingerprint,
                fallback: self.fallback,
                default_protocol_policy,
                middlewares: self.middlewares,
                timeouts: self.timeouts,
                resource_limits: self.resource_limits,
                max_pending_h2_requests: self.max_pending_h2_requests,
                keylog_callback: self.keylog_callback,
                verify: self.verify,
                resolver,
                #[cfg(feature = "quic-h3")]
                quic_endpoint_manager: tokio::sync::Mutex::new(endpoint_manager),
                session_store: Arc::new(InMemorySessionStore::new()),
                #[cfg(feature = "synthetic-fp")]
                randomize: self.randomize,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_h2_requests_default_to_unbounded() {
        let client = Client::builder().build();
        assert_eq!(client.max_pending_h2_requests(), None);
    }

    #[test]
    fn pending_h2_request_limit_can_be_set_and_cleared() {
        let bounded = Client::builder().max_pending_h2_requests(128).build();
        assert_eq!(bounded.max_pending_h2_requests(), Some(128));

        let unbounded = Client::builder()
            .max_pending_h2_requests(128)
            .unbounded_pending_h2_requests()
            .build();
        assert_eq!(unbounded.max_pending_h2_requests(), None);
    }

    #[test]
    #[should_panic(expected = "max_pending_h2_requests must be greater than zero")]
    fn zero_pending_h2_request_limit_is_rejected() {
        let _ = Client::builder().max_pending_h2_requests(0);
    }

    // -- TimeoutConfig -----------------------------------------------------

    #[test]
    fn timeout_config_defaults() {
        let tc = TimeoutConfig::default();
        assert_eq!(tc.dns_timeout, Some(Duration::from_secs(5)));
        assert_eq!(tc.tcp_connect_timeout, Some(Duration::from_secs(10)));
        assert_eq!(tc.tls_handshake_timeout, Some(Duration::from_secs(10)));
        assert_eq!(tc.quic_connect_timeout, Some(Duration::from_secs(10)));
        assert_eq!(tc.ttfb_timeout, Some(Duration::from_secs(30)));
        assert_eq!(tc.total_timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn timeout_config_none() {
        let tc = TimeoutConfig::none();
        assert!(tc.dns_timeout.is_none());
        assert!(tc.tcp_connect_timeout.is_none());
        assert!(tc.tls_handshake_timeout.is_none());
        assert!(tc.quic_connect_timeout.is_none());
        assert!(tc.ttfb_timeout.is_none());
        assert!(tc.total_timeout.is_none());
    }

    #[test]
    fn timeout_config_builder_chain() {
        let tc = TimeoutConfig::none()
            .with_dns_timeout(Duration::from_secs(1))
            .with_tcp_connect_timeout(Duration::from_secs(2))
            .with_tls_handshake_timeout(Duration::from_secs(3))
            .with_quic_connect_timeout(Duration::from_secs(4))
            .with_ttfb_timeout(Duration::from_secs(5))
            .with_total_timeout(Duration::from_secs(6));

        assert_eq!(tc.dns_timeout, Some(Duration::from_secs(1)));
        assert_eq!(tc.tcp_connect_timeout, Some(Duration::from_secs(2)));
        assert_eq!(tc.tls_handshake_timeout, Some(Duration::from_secs(3)));
        assert_eq!(tc.quic_connect_timeout, Some(Duration::from_secs(4)));
        assert_eq!(tc.ttfb_timeout, Some(Duration::from_secs(5)));
        assert_eq!(tc.total_timeout, Some(Duration::from_secs(6)));
    }

    #[test]
    fn timeout_config_or_fallback() {
        let tc = TimeoutConfig::none();
        let default = Duration::from_secs(99);
        assert_eq!(tc.tcp_connect_timeout_or(default), default);

        let tc2 = TimeoutConfig::default();
        assert_eq!(tc2.tcp_connect_timeout_or(default), Duration::from_secs(10));
    }

    #[test]
    fn timeout_config_merge_overrides() {
        let base = TimeoutConfig::default();
        let overrides = TimeoutConfig::none().with_dns_timeout(Duration::from_secs(1));
        let merged = base.merge_overrides(&overrides);

        assert_eq!(merged.dns_timeout, Some(Duration::from_secs(1)));
        assert_eq!(merged.tcp_connect_timeout, Some(Duration::from_secs(10)));
    }

    // -- ResourceLimits ---------------------------------------------------

    #[test]
    fn resource_limits_defaults() {
        let rl = ResourceLimits::default();
        assert_eq!(rl.max_response_body_size, 100 * 1024 * 1024);
        assert_eq!(rl.max_header_count, 256);
        assert_eq!(rl.max_connections_per_session, 64);
    }

    #[test]
    fn resource_limits_none() {
        let rl = ResourceLimits::none();
        assert_eq!(rl.max_response_body_size, usize::MAX);
        assert_eq!(rl.max_header_count, usize::MAX);
        assert!(rl.min_transfer_rate.is_none());
    }

    #[test]
    fn resource_limits_builder_chain() {
        let rl = ResourceLimits::default()
            .with_max_response_body_size(1024)
            .with_max_connections_per_session(8)
            .with_min_transfer_rate(100, Duration::from_secs(5));

        assert_eq!(rl.max_response_body_size, 1024);
        assert_eq!(rl.max_connections_per_session, 8);
        assert_eq!(rl.min_transfer_rate, Some(100));
        assert_eq!(rl.transfer_rate_window, Duration::from_secs(5));
    }

    #[test]
    fn resource_limits_check_headers_ok() {
        let rl = ResourceLimits::default();
        let headers = http::HeaderMap::new();
        assert!(rl.check_response_headers(&headers).is_ok());
    }

    #[test]
    fn resource_limits_check_too_many_headers() {
        let rl = ResourceLimits::default().with_max_response_body_size(1024);
        let rl = ResourceLimits {
            max_header_count: 2,
            ..rl
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-a", "1".parse().unwrap());
        headers.insert("x-b", "2".parse().unwrap());
        headers.insert("x-c", "3".parse().unwrap());
        assert!(rl.check_response_headers(&headers).is_err());
    }

    // -- ClientBuilder ----------------------------------------------------

    #[test]
    fn client_builder_creates_client() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build();

        let c2 = client.clone();
        assert!(Arc::ptr_eq(&client.inner, &c2.inner));
    }

    #[test]
    fn client_builder_default_header() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .default_header("user-agent", "Test/1.0")
            .build();

        assert!(client.inner.default_headers.contains_key("user-agent"));
    }

    #[test]
    fn client_session_creates_session_builder() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build();

        let sb: SessionBuilder = client.session();
        let session = sb.build();
        assert!(Arc::ptr_eq(&client.inner, &session.inner.client.inner));
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn quic_endpoint_manager_uses_profile_max_udp_payload_size() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_146())
            .quic_profile(lkh3::chrome_146_quic())
            .build();

        let manager = client.inner.quic_endpoint_manager.lock().await;

        assert_eq!(manager.cid_len(), 0);
        assert_eq!(
            manager.endpoint_strategy(),
            QuicEndpointStrategy::PerSession
        );
        assert_eq!(manager.endpoint_max_udp_payload_size(), Some(1472));
        assert!(!manager.grease_quic_bit_enabled());
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn quic_endpoint_manager_uses_profile_grease_transport_params() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .quic_profile(lkh3::chrome_quic())
            .build();

        let manager = client.inner.quic_endpoint_manager.lock().await;

        assert!(!manager.grease_quic_bit_enabled());
    }

    // -- Builder dimensions → getters -------------------------------------

    #[test]
    fn builder_threads_all_dimensions_into_getters() {
        use http::header::{HeaderName, HeaderValue};
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_146())
            .quic_fingerprint(lktls::profile::presets::chrome_146_quic())
            .h2_profile(crate::h2::profile::chrome_146_h2())
            .protocol_policy(ProtocolPolicy::h3_strict())
            .tcp_fingerprint(TcpFingerprint::chrome())
            .ech_config(vec![1, 2, 3, 4])
            .default_header("accept-language", "en-US")
            .default_header_typed(
                HeaderName::from_static("x-test"),
                HeaderValue::from_static("1"),
            )
            .header_order(vec!["user-agent", "accept", "cookie"])
            .h3_header_order(vec!["accept", "cookie"])
            .cookie_order(vec!["sid", "uid"])
            .verify(false)
            .build();

        assert_eq!(client.tls_profile().name, "Chrome 146");
        assert_eq!(client.quic_tls_profile().unwrap().name, "Chrome 146 QUIC");
        assert_eq!(client.protocol_policy(), &ProtocolPolicy::h3_strict());
        assert!(client.tcp_fingerprint().is_some());
        assert_eq!(client.ech_config(), Some([1u8, 2, 3, 4].as_slice()));
        assert!(client.default_headers().contains_key("accept-language"));
        assert!(client.default_headers().contains_key("x-test"));
        assert_eq!(
            client.header_order().unwrap().first().unwrap().as_str(),
            "user-agent"
        );
        assert_eq!(
            client.h3_header_order().unwrap().first().unwrap().as_str(),
            "accept"
        );
        assert_eq!(client.cookie_order().unwrap().len(), 2);
        assert!(!client.verify());
        assert!(client.keylog_callback().is_none());
        assert!(client.custom_ca_anchors().is_none());
    }

    #[test]
    fn disable_http3_clears_quic_profile() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_146())
            .disable_http3()
            .build();
        assert!(client.quic_profile().is_none());
    }

    #[test]
    fn clear_quic_fingerprint_falls_back_to_main_tls() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_146())
            .quic_fingerprint(lktls::profile::presets::chrome_146_quic())
            .clear_quic_fingerprint()
            .build();
        assert!(client.quic_tls_profile().is_none());
    }

    #[test]
    fn client_default_is_chrome_144_without_quic() {
        let client = Client::default();
        assert_eq!(client.tls_profile().name, "Chrome 144");
        assert!(client.quic_profile().is_none());
    }

    // -- Timeouts ----------------------------------------------------------

    #[test]
    fn builder_timeout_setters_and_getters() {
        let client = Client::builder()
            .dns_timeout(Duration::from_secs(1))
            .tcp_connect_timeout(Duration::from_secs(2))
            .tls_handshake_timeout(Duration::from_secs(3))
            .ttfb_timeout(Duration::from_secs(4))
            .total_timeout(Duration::from_secs(5))
            .build();
        let t = client.timeouts();
        assert_eq!(t.dns_timeout, Some(Duration::from_secs(1)));
        assert_eq!(t.tcp_connect_timeout, Some(Duration::from_secs(2)));
        assert_eq!(t.tls_handshake_timeout, Some(Duration::from_secs(3)));
        assert_eq!(t.ttfb_timeout, Some(Duration::from_secs(4)));
        assert_eq!(t.total_timeout, Some(Duration::from_secs(5)));
        assert_eq!(client.connect_timeout(), Duration::from_secs(5)); // tcp + tls
        assert_eq!(client.read_timeout(), Duration::from_secs(5)); // total
    }

    #[test]
    fn connect_timeout_builder_splits_budget_evenly() {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(20))
            .build();
        assert_eq!(
            client.timeouts().tcp_connect_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            client.timeouts().tls_handshake_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(client.read_timeout(), Duration::from_secs(20));
    }

    #[test]
    fn timeout_config_none_falls_back_in_getters() {
        let client = Client::builder()
            .timeout_config(TimeoutConfig::none())
            .build();
        assert!(client.timeouts().total_timeout.is_none());
        assert_eq!(client.connect_timeout(), Duration::from_secs(20)); // 10 + 10 fallback
        assert_eq!(client.read_timeout(), Duration::from_secs(60)); // total fallback
    }

    #[test]
    fn timeout_or_helpers_use_fallback_when_none() {
        let none = TimeoutConfig::none();
        let d = Duration::from_secs(42);
        assert_eq!(none.dns_timeout_or(d), d);
        assert_eq!(none.tls_handshake_timeout_or(d), d);
        assert_eq!(none.ttfb_timeout_or(d), d);
        assert_eq!(none.total_timeout_or(d), d);
        assert_eq!(
            TimeoutConfig::default().total_timeout_or(d),
            Duration::from_secs(60)
        );
    }

    // -- Resource limits ---------------------------------------------------

    #[test]
    fn builder_resource_limit_setters() {
        let client = Client::builder()
            .max_response_body_size(2048)
            .max_connections_per_session(4)
            .build();
        assert_eq!(client.resource_limits().max_response_body_size, 2048);
        assert_eq!(client.resource_limits().max_connections_per_session, 4);

        let client2 = Client::builder()
            .resource_limits(ResourceLimits::none())
            .build();
        assert_eq!(client2.resource_limits().max_response_body_size, usize::MAX);
    }

    #[test]
    fn resource_limits_check_body_size() {
        let rl = ResourceLimits::default().with_max_response_body_size(100);
        assert!(rl.check_body_size(50).is_ok());
        assert!(rl.check_body_size(101).is_err());
    }

    #[test]
    fn resource_limits_reject_oversized_single_and_total_headers() {
        let rl = ResourceLimits {
            max_header_size: 4,
            ..ResourceLimits::default()
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-long", "aaaaaaaa".parse().unwrap()); // 6 + 8 > 4
        assert!(rl.check_response_headers(&headers).is_err());

        let rl2 = ResourceLimits {
            max_headers_total_size: 5,
            ..ResourceLimits::default()
        };
        let mut headers2 = http::HeaderMap::new();
        headers2.insert("x-a", "1234".parse().unwrap()); // 3 + 4 = 7 > 5
        assert!(rl2.check_response_headers(&headers2).is_err());
    }

    // -- Fallback ----------------------------------------------------------

    #[test]
    fn builder_fallback_toggles() {
        let client = Client::builder()
            .h2_fallback_h1(false)
            .proxy_fallback_direct(true)
            .retry_on_connection_close(false)
            .build();
        let f = client.fallback();
        assert!(!f.h2_to_h1);
        assert!(f.proxy_to_direct);
        assert!(!f.retry_on_connection_close);

        let client2 = Client::builder()
            .fallback_config(FallbackConfig {
                h2_to_h1: false,
                proxy_to_direct: true,
                retry_on_connection_close: true,
            })
            .build();
        assert!(client2.fallback().proxy_to_direct);
    }

    #[test]
    fn fallback_config_defaults() {
        let f = FallbackConfig::default();
        assert!(f.h2_to_h1);
        assert!(!f.proxy_to_direct);
        assert!(f.retry_on_connection_close);
    }

    // -- Header / cookie order variants ------------------------------------

    #[test]
    fn header_and_cookie_order_from_typed_inputs() {
        use http::header::HeaderName;
        let client = Client::builder()
            .header_order_from_names(vec![HeaderName::from_static("accept")])
            .h3_header_order_from_names(vec![HeaderName::from_static("cookie")])
            .cookie_order_from_strings(vec!["a".to_string(), "b".to_string()])
            .build();
        assert_eq!(client.header_order().unwrap().len(), 1);
        assert_eq!(client.h3_header_order().unwrap().len(), 1);
        assert_eq!(client.cookie_order().unwrap().len(), 2);
    }

    #[test]
    fn empty_order_inputs_are_ignored() {
        let client = Client::builder()
            .header_order(vec![])
            .h3_header_order(vec![])
            .cookie_order(vec![])
            .header_order_from_names(vec![])
            .cookie_order_from_strings(vec![])
            .build();
        assert!(client.header_order().is_none());
        assert!(client.h3_header_order().is_none());
        assert!(client.cookie_order().is_none());
    }

    #[test]
    fn invalid_default_header_is_ignored() {
        let client = Client::builder()
            .default_header("invalid name", "v") // space in name → rejected
            .default_header("x-ok", "\u{007f}bad") // control char in value → rejected
            .build();
        // Both the invalid name and the invalid value are rejected, so the
        // default header map ends up empty.
        assert!(client.default_headers().is_empty());
    }

    // -- CA certs / TLS knobs ----------------------------------------------

    #[test]
    fn invalid_ca_certs_are_skipped() {
        let client = Client::builder()
            .add_ca_cert_der(&[0xDE, 0xAD, 0xBE, 0xEF]) // not a valid DER cert
            .add_ca_certs_pem(
                b"-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n",
            )
            .build();
        assert!(client.custom_ca_anchors().is_none());
    }

    #[test]
    fn randomize_extension_order_forces_shuffle_on() {
        use lktls::profile::presets;
        // Start from a profile with no randomization, then force Tier 1 on.
        let mut base = presets::chrome_146();
        base.randomization = None;
        let client = Client::builder()
            .fingerprint(base)
            .randomize(crate::randomize::Randomize::extension_order())
            .build();
        assert!(
            client
                .tls_profile()
                .randomization
                .as_ref()
                .is_some_and(|r| r.shuffle_extensions),
            "extension_order policy must force shuffle_extensions on"
        );
    }

    #[test]
    fn randomize_off_leaves_profile_untouched() {
        use lktls::profile::presets;
        let mut base = presets::chrome_146();
        base.randomization = None;
        let client = Client::builder()
            .fingerprint(base)
            .randomize(crate::randomize::Randomize::off())
            .build();
        // Off adds nothing: the profile's (absent) randomization stays absent.
        assert!(client.tls_profile().randomization.is_none());
    }

    #[test]
    fn session_resumption_mutates_an_existing_profile() {
        use lktls::profile::types::SessionResumptionConfig;
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_146())
            .session_resumption(SessionResumptionConfig::disabled())
            .build();
        // The existing Chrome 146 profile is mutated, not replaced.
        assert_eq!(client.tls_profile().name, "Chrome 146");
    }

    #[test]
    fn session_resumption_applies_default_profile_when_unset() {
        use lktls::profile::types::SessionResumptionConfig;
        let client = Client::builder()
            .session_resumption(SessionResumptionConfig::disabled())
            .build();
        // No fingerprint set → falls back to the Chrome 144 default.
        assert_eq!(client.tls_profile().name, "Chrome 144");
    }

    // -- DNS resolver setters ----------------------------------------------

    #[tokio::test]
    async fn dns_and_resolver_setters_build() {
        // No public accessor reveals which resolver is installed, so assert the
        // setters produce a well-formed client (other defaults intact) and that
        // the resolver getter is wired, without panicking.
        let client = Client::builder().dns(DnsConfig::Cloudflare).build();
        assert!(client.verify());
        let _ = client.resolver();

        let client2 = Client::builder()
            .dns_resolver(std::sync::Arc::new(SystemDns))
            .build();
        assert_eq!(client2.tls_profile().name, "Chrome 144");
        let _ = client2.resolver();

        let cached = Client::builder()
            .system_dns_cache(SystemDnsCacheConfig::positive(Duration::from_secs(30)))
            .build();
        assert!(cached
            .resolver()
            .resolver_impl_name()
            .ends_with("CachedSystemDns"));
    }

    // -- Convenience request builders --------------------------------------

    #[test]
    fn convenience_methods_build_request_builders() {
        let client = Client::builder().build();
        // These verbs are thin delegators to `session().build().<verb>()` and the
        // returned RequestBuilder exposes no inspectable method/URL, so this guards
        // that all seven construct without panicking and leave the (immutable)
        // client untouched.
        let _ = client.get("https://example.com/");
        let _ = client.post("https://example.com/");
        let _ = client.put("https://example.com/");
        let _ = client.delete("https://example.com/");
        let _ = client.head("https://example.com/");
        let _ = client.patch("https://example.com/");
        let _ = client.options("https://example.com/");
        assert_eq!(client.tls_profile().name, "Chrome 144");
    }
}
