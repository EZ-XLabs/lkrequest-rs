//! Session — a virtual browser user.
//!
//! A `Session` holds its own Cookie Jar, connection pool, and proxy config.
//! It represents a single "identity" — all requests from the same Session
//! share cookies and reuse connections.
//!
//! `Session` is `Clone + Send + Sync`.  Cloning is cheap (Arc reference count).
//! Multiple tasks can send requests through the same Session concurrently.

pub(crate) mod pipeline;
mod prefetch;
mod request;
mod streaming;
mod transport;

pub use prefetch::PrefetchResult;
pub use request::RequestBuilder;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use url::Url;

use crate::alt_svc::{AltSvcCache, BrokenQuicPolicy, BrokenQuicTracker};
use crate::client::Client;
use crate::connection_pool::ConnectionPool;
use crate::error::Error;
#[cfg(feature = "quic-h3")]
use crate::error::QuicPhase;
use crate::protocol::{AcquisitionPolicy, FallbackPolicy, HttpIntent, ProtocolPolicy, RacePolicy};
use crate::proxy::ProxyConfig;
use crate::response::HttpVersion;
use crate::retry::RetryPolicy;

use lktls::session_store::InMemorySessionStore;

#[cfg(feature = "quic-h3")]
pub(crate) enum H3ConnectOutcome {
    Handshake(lkh3::H3Connection),
    ZeroRtt(lkh3::H3ZeroRttConnection),
}

#[cfg(feature = "quic-h3")]
impl H3ConnectOutcome {
    fn into_handshake(self) -> crate::error::Result<lkh3::H3Connection> {
        match self {
            Self::Handshake(connection) => Ok(connection),
            Self::ZeroRtt(_) => Err(Error::InvalidConfig(
                "internal error: unexpected HTTP/3 0-RTT connection".into(),
            )),
        }
    }
}

#[cfg(feature = "quic-h3")]
fn decode_extra_transport_parameters(
    parameters: &[(u64, String)],
) -> crate::error::Result<Vec<(quinn::VarInt, Vec<u8>)>> {
    parameters
        .iter()
        .map(|(id, value_hex)| {
            let id = quinn::VarInt::from_u64(*id).map_err(|_| {
                Error::InvalidConfig(format!(
                    "extra QUIC transport parameter id {id:#x} does not fit QUIC varint"
                ))
            })?;
            let value = decode_hex(value_hex)?;
            Ok((id, value))
        })
        .collect()
}

#[cfg(feature = "quic-h3")]
fn decode_transport_parameter_order(order: &[u64]) -> crate::error::Result<Vec<quinn::VarInt>> {
    order
        .iter()
        .map(|id| {
            quinn::VarInt::from_u64(*id).map_err(|_| {
                Error::InvalidConfig(format!(
                    "QUIC transport parameter order id {id:#x} does not fit QUIC varint"
                ))
            })
        })
        .collect()
}

/// Unbiased Fisher-Yates (Durstenfeld) shuffle of the QUIC transport-parameter
/// wire order, applied per connection. Chrome/BoringSSL randomizes the order of
/// its transport parameters on every connection (capture-verified), so a fixed
/// order is itself a fingerprint tell across connections.
#[cfg(feature = "quic-h3")]
fn shuffle_transport_parameter_order(order: &mut [quinn::VarInt]) {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let n = order.len();
    if n <= 1 {
        return;
    }
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    for i in (1..n).rev() {
        if rng.fill(&mut buf).is_err() {
            break;
        }
        let j = u32::from_le_bytes(buf) as usize % (i + 1);
        order.swap(i, j);
    }
}

/// Map 4 random bytes to a Chrome-style reserved GREASE transport-parameter id.
///
/// The returned id always satisfies the RFC 9000 §18.1 reserved form
/// `31*N + 27`, and is constrained so that it:
/// - is always encoded as an **8-byte** QUIC varint (value in `[2^30, 2^62)`),
///   matching the captured Chrome reserved id's on-wire width on every
///   connection — a sub-`2^30` id would encode shorter and shift the byte
///   layout, itself a fingerprint tell; and
/// - is **never** a transport parameter Quinn encodes locally (`0x00..=0x10`,
///   `0x20`, `0xb6`, `0x2ab2`, `0xff04de1a`), which `extra_transport_parameters`
///   rejects with `LocallyEncoded` (a connection-setup failure). All of those
///   are `< 2^30` except `0xff04de1a`, which is not of the `31*N + 27` form, so
///   none are reachable from this generator.
#[cfg(feature = "quic-h3")]
fn grease_reserved_tp_id(rand: u32) -> quinn::VarInt {
    // Smallest N whose id (= 31*N + 27) reaches the 8-byte-varint threshold 2^30.
    let n_min = ((1u64 << 30) - 27).div_ceil(31);
    let id = 27 + 31 * (n_min + rand as u64);
    // id ∈ [2^30, 2^30 + 31·2^32) ⊂ [2^30, 2^62) → always an 8-byte varint.
    quinn::VarInt::from_u64(id).expect("reserved GREASE id fits a QUIC varint")
}

/// Per-connection GREASE randomization of QUIC transport parameters, matching
/// Chrome/BoringSSL (capture-verified against Chrome 148):
/// - the reserved GREASE transport parameter (id `31*N + 27`, RFC 9000 §18.1)
///   gets a fresh random reserved id + random-length random value (the profile
///   stores a fixed placeholder; Chrome's is random per connection);
/// - `version_information` (0x11) gets a fresh random GREASE version
///   (`0x?a?a?a?a`, RFC 9000 §15.1) in its first available-version slot.
///
/// The `order` list's reference to the GREASE id is patched to the new id so the
/// (subsequently shuffled) wire order stays consistent.
#[cfg(feature = "quic-h3")]
fn randomize_quic_grease_params(
    extra: &mut [(quinn::VarInt, Vec<u8>)],
    order: &mut [quinn::VarInt],
) {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let fill = |b: &mut [u8]| {
        let _ = rng.fill(b);
    };

    for (id, value) in extra.iter_mut() {
        let id_v = id.into_inner();
        if id_v == 0x11 {
            // version_information = chosen(4) | available[GREASE(4), v1(4), …].
            // Randomize the GREASE version (first available slot, bytes 4..8).
            if value.len() >= 8 {
                let mut g = [0u8; 4];
                fill(&mut g);
                for b in g.iter_mut() {
                    *b = (*b & 0xf0) | 0x0a; // 0x?a?a?a?a reserved-version pattern
                }
                value[4..8].copy_from_slice(&g);
            }
        } else if id_v >= 27 && (id_v - 27) % 31 == 0 {
            // Reserved GREASE TP → fresh random reserved id + random-length value.
            // `grease_reserved_tp_id` guarantees an 8-byte-varint, non-locally-
            // encoded id, so the encode below cannot be rejected.
            let mut n = [0u8; 4];
            fill(&mut n);
            let new_id = grease_reserved_tp_id(u32::from_le_bytes(n));
            let mut lb = [0u8; 1];
            fill(&mut lb);
            let mut val = vec![0u8; 1 + (lb[0] as usize % 16)];
            fill(&mut val);
            for slot in order.iter_mut() {
                if *slot == *id {
                    *slot = new_id;
                }
            }
            *id = new_id;
            *value = val;
        }
    }
}

#[cfg(feature = "quic-h3")]
fn build_initial_frame_layout_config(
    layout: &lkh3::InitialFrameLayoutProfile,
) -> quinn::InitialFrameLayoutConfig {
    quinn::InitialFrameLayoutConfig {
        target_udp_payload_size: layout.target_udp_payload_size,
        packets: layout
            .packets
            .iter()
            .map(|packet| quinn::InitialPacketLayoutConfig {
                packet_number: packet.packet_number,
                frames: packet
                    .frames
                    .iter()
                    .map(|element| match *element {
                        lkh3::InitialFrameElement::Crypto { offset, length } => {
                            quinn::InitialFrameElementConfig::Crypto { offset, length }
                        }
                        lkh3::InitialFrameElement::Padding { length } => {
                            quinn::InitialFrameElementConfig::Padding { length }
                        }
                        lkh3::InitialFrameElement::Ping => quinn::InitialFrameElementConfig::Ping,
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(feature = "quic-h3")]
fn decode_hex(value: &str) -> crate::error::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::InvalidConfig(
            "extra QUIC transport parameter value must be even-length hex".into(),
        ));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

#[cfg(feature = "quic-h3")]
fn hex_nibble(byte: u8) -> crate::error::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidConfig(
            "extra QUIC transport parameter value must be hex".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// RedirectPolicy
// ---------------------------------------------------------------------------

/// Controls how HTTP redirects (3xx) are handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Do not follow redirects; return the 3xx response as-is.
    None,
    /// Follow redirects up to the specified number of hops.
    ///
    /// Exceeding the limit returns [`Error::TooManyRedirects`].
    /// The default is `Follow(10)`.
    Follow(u32),
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::Follow(10)
    }
}

impl RedirectPolicy {
    /// Returns the maximum number of redirects to follow, or `None` if
    /// redirects are disabled.
    pub(crate) fn max_redirects(&self) -> Option<u32> {
        match self {
            Self::None => Option::None,
            Self::Follow(n) => Some(*n),
        }
    }
}

// ---------------------------------------------------------------------------
// Idempotency (per-request 0-RTT opt-in, Chrome model)
// ---------------------------------------------------------------------------

/// Whether a request may be sent in QUIC 0-RTT / TLS early data.
///
/// Mirrors the tri-state `HttpRequestInfo::idempotency` flag in Chromium
/// (`net/base/idempotency.h`) so that QUIC 0-RTT follows the same replay
/// safety rules as Chrome.
///
/// ## Semantics
///
/// | Value | 0-RTT allowed? |
/// |-------|----------------|
/// | [`Idempotency::Default`] | only for RFC 9110 §9.2.1 *safe* methods: `GET`, `HEAD`, `OPTIONS`, `TRACE` |
/// | [`Idempotency::Idempotent`] | yes — caller asserts the request is safe to replay (e.g. POST with an Idempotency-Key header) |
/// | [`Idempotency::NotIdempotent`] | no — caller explicitly opts out even for safe methods |
///
/// The defaults align with Chrome's `HttpNetworkTransaction::Start()` and
/// RFC 8470 §4 ("clients MAY send requests with safe HTTP methods ... in
/// early data when it is available and MUST NOT send unsafe methods ... in
/// early data"). Methods whose safety is not known (custom extension
/// methods) fall through the [`Idempotency::Default`] arm as "not safe",
/// matching the "MUST NOT" clause.
///
/// ## Current state
///
/// lkrequest attempts QUIC 0-RTT only when a resumable H3 session exists and
/// [`can_send_early_data`] says the request is replay-safe. If the server
/// rejects early data, the client drops the speculative H3 request and replays
/// it after the normal handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Idempotency {
    /// Decide automatically based on the HTTP method (RFC 9110 safe methods).
    #[default]
    Default,
    /// Caller asserts the request is safe to replay. Allows 0-RTT for any
    /// method, including POST/PUT/DELETE.
    Idempotent,
    /// Caller declares the request is unsafe to replay. Disables 0-RTT
    /// even for methods that would otherwise be considered safe.
    NotIdempotent,
}

/// Decide whether a request may be sent in QUIC 0-RTT / TLS early data.
///
/// See [`Idempotency`] for the rules. This is the public form of Chrome's
/// `HttpNetworkTransaction::Start()` logic:
///
/// ```text
/// can_send_early_data = idempotency == IDEMPOTENT
///   || (idempotency == DEFAULT && HttpUtil::IsMethodSafe(method))
/// ```
pub fn can_send_early_data(method: &http::Method, idempotency: Idempotency) -> bool {
    match idempotency {
        Idempotency::Idempotent => true,
        Idempotency::NotIdempotent => false,
        Idempotency::Default => matches!(
            *method,
            http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
        ),
    }
}

// ---------------------------------------------------------------------------
// AcceptEncoding bitflags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Flags controlling which content encodings to advertise in `Accept-Encoding`
    /// and which decompression algorithms to apply on the response.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use lkrequest::AcceptEncoding;
    ///
    /// // Only advertise gzip
    /// let resp = session.get("https://example.com")
    ///     .accept_encoding(AcceptEncoding::GZIP)
    ///     .send().await?;
    ///
    /// // Advertise br + gzip (common for modern browsers)
    /// let resp = session.get("https://example.com")
    ///     .accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
    ///     .send().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AcceptEncoding: u8 {
        /// gzip encoding.
        const GZIP    = 0b0001;
        /// Brotli (br) encoding.
        const BR      = 0b0010;
        /// deflate encoding.
        const DEFLATE = 0b0100;
        /// Zstandard (zstd) encoding.
        const ZSTD    = 0b1000;
        /// All supported encodings (gzip + br + deflate + zstd).
        const ALL     = 0b1111;
    }
}

impl AcceptEncoding {
    /// Chrome default: `gzip, deflate, br, zstd`
    pub const CHROME_DEFAULT: Self = Self::ALL;

    /// Firefox default: `gzip, deflate, br, zstd`
    pub const FIREFOX_DEFAULT: Self = Self::ALL;

    /// Safari default: `gzip, deflate, br`
    pub const SAFARI_DEFAULT: Self = Self::GZIP.union(Self::DEFLATE).union(Self::BR);

    /// Convert to an `Accept-Encoding` header value string.
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        if self.contains(Self::GZIP) {
            parts.push("gzip");
        }
        if self.contains(Self::DEFLATE) {
            parts.push("deflate");
        }
        if self.contains(Self::BR) {
            parts.push("br");
        }
        if self.contains(Self::ZSTD) {
            parts.push("zstd");
        }
        parts.join(", ")
    }
}

/// Global monotonic request ID counter.
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_request_id() -> u64 {
    REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub use cookie_store::CookieStore;

/// A session representing a single virtual browser user.
///
/// # Example
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// let session = client.session().build();
///
/// // Concurrent requests share the session's cookie jar and connections.
/// let resp = session.get("https://example.com").send().await?;
/// println!("Status: {}", resp.status());
/// println!("Body: {}", resp.text()?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Session {
    pub(crate) inner: Arc<SessionInner>,
}

/// Inner state of a Session, shared across clones.
#[allow(dead_code)]
pub(crate) struct SessionInner {
    /// The client this session was created from (fingerprint config).
    pub client: Client,

    /// Cookie jar — per-session, lock-free reads via ArcSwap.
    ///
    /// Reads (every request, to inject Cookie header) are lock-free via `load()`.
    /// Writes (Set-Cookie responses) use `rcu()` for safe copy-on-write.
    pub cookie_jar: ArcSwap<CookieStore>,

    /// Connection pool — per-session, protected by Mutex (short critical sections).
    pub pool: Mutex<ConnectionPool>,

    /// Proxy configuration for this session (immutable after creation).
    pub proxy: Option<ProxyConfig>,

    /// Redirect policy for this session.
    pub redirect_policy: RedirectPolicy,

    /// TLS session ticket store for session resumption (shared across connections).
    pub session_store: Arc<InMemorySessionStore>,

    /// Optional retry policy for failed requests.
    pub retry_policy: Option<Arc<dyn RetryPolicy>>,

    /// Per-session ECHConfigList override (raw DER bytes).
    /// Takes precedence over the client's `ech_config`.
    pub ech_config: Option<Vec<u8>>,

    /// Session-level middleware stack (applied after client middlewares).
    pub middlewares: crate::middleware::MiddlewareStack,

    /// Effective runtime protocol behavior for this session.
    pub protocol_policy: ProtocolPolicy,

    /// Preferred HTTP version for this session.
    pub preferred_http_version: PreferredHttpVersion,

    /// How `Auto` mode chooses between TCP and QUIC when both are viable.
    pub protocol_selection_policy: ProtocolSelectionPolicy,

    /// Tunables for the Chrome-like TCP/QUIC racing policy.
    pub chrome_like_protocol_config: ChromeLikeProtocolConfig,

    /// Default Accept-Encoding for requests in this session.
    pub default_accept_encoding: Option<AcceptEncoding>,

    /// Session-level header sending order template.
    pub header_order: Option<Vec<http::header::HeaderName>>,

    /// Session-level HTTP/3-specific header sending order template.
    pub h3_header_order: Option<Vec<http::header::HeaderName>>,

    /// Session-level cookie sending order template.
    pub cookie_order: Option<Vec<Box<str>>>,

    /// Cached Alt-Svc advertisements observed from responses.
    pub alt_svc_cache: AltSvcCache,

    /// Cooldown tracker for origins whose QUIC path is currently considered broken.
    pub broken_quic_tracker: BrokenQuicTracker,

    /// QUIC handshakes currently in-flight, keyed by connection key.
    ///
    /// When two concurrent requests target the same origin and neither has
    /// a pooled H3 connection yet, we want only one of them to run the
    /// handshake; the other should wait and then reuse the pooled sender
    /// instead of racing a second full QUIC handshake (and getting its
    /// connection silently dropped when the pool inserts the first one's
    /// sender over it). Each entry is an [`Arc<tokio::sync::Notify>`] that
    /// the handshaking task will `notify_waiters()` on completion.
    #[cfg(feature = "quic-h3")]
    pub quic_in_flight: Mutex<
        std::collections::HashMap<crate::connection_pool::ConnectionKey, Arc<tokio::sync::Notify>>,
    >,
}

impl Session {
    /// Returns a reference to the underlying client.
    pub fn client(&self) -> &Client {
        &self.inner.client
    }

    /// Returns the session-level header order, if set.
    pub fn header_order(&self) -> Option<&[http::header::HeaderName]> {
        self.inner.header_order.as_deref()
    }

    /// Returns the session-level HTTP/3-specific header order, if set.
    pub fn h3_header_order(&self) -> Option<&[http::header::HeaderName]> {
        self.inner.h3_header_order.as_deref()
    }

    /// Returns the session-level cookie order, if set.
    pub fn cookie_order(&self) -> Option<&[Box<str>]> {
        self.inner.cookie_order.as_deref()
    }

    pub(crate) fn alt_svc_cache(&self) -> &AltSvcCache {
        &self.inner.alt_svc_cache
    }

    pub(crate) fn broken_quic_tracker(&self) -> &BrokenQuicTracker {
        &self.inner.broken_quic_tracker
    }

    pub fn protocol_policy(&self) -> &ProtocolPolicy {
        &self.inner.protocol_policy
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn chrome_like_protocol_config(&self) -> ChromeLikeProtocolConfig {
        self.inner.chrome_like_protocol_config
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn spawn_background_quic_probe(
        &self,
        host: String,
        port: u16,
        conn_key: crate::connection_pool::ConnectionKey,
        discovery: crate::session::pipeline::QuicDiscovery,
        proxy: Option<crate::proxy::ProxyConfig>,
    ) {
        let session = self.clone();
        tokio::spawn(async move {
            match session
                .establish_h3_connection(
                    &host,
                    port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy.as_ref(),
                )
                .await
            {
                Ok(h3_conn) => {
                    session
                        .broken_quic_tracker()
                        .mark_working_for_route(&discovery.route, &discovery.origin);
                    session
                        .broken_quic_tracker()
                        .mark_route_working(&discovery.route);
                    session
                        .alt_svc_cache()
                        .mark_h3_validated_for_route(&discovery.route, &discovery.origin);
                    let (sender, driver) = h3_conn.into_parts();
                    let driver = std::sync::Arc::new(driver);
                    let mut pool = session.inner.pool.lock();
                    pool.insert_h3(conn_key, sender, driver);
                    tracing::debug!(host = %host, port, "quic.background_probe_succeeded");
                }
                Err(error) => {
                    if error.is_quic_handshake_failure() {
                        session
                            .broken_quic_tracker()
                            .mark_broken_for_route(&discovery.route, &discovery.origin);
                        session
                            .alt_svc_cache()
                            .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    }
                    tracing::debug!(
                        host = %host,
                        port,
                        error = %error,
                        "quic.background_probe_failed"
                    );
                }
            }
        });
    }

    #[cfg(not(feature = "quic-h3"))]
    pub(crate) fn spawn_background_quic_probe(
        &self,
        _host: String,
        _port: u16,
        _conn_key: crate::connection_pool::ConnectionKey,
        _discovery: crate::session::pipeline::QuicDiscovery,
        _proxy: Option<crate::proxy::ProxyConfig>,
    ) {
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) fn spawn_background_tcp_probe(
        &self,
        host: String,
        port: u16,
        scheme: crate::connection_pool::Scheme,
        conn_key: crate::connection_pool::ConnectionKey,
        proxy: Option<crate::proxy::ProxyConfig>,
        preferred_http_version: PreferredHttpVersion,
    ) {
        let session = self.clone();
        tokio::spawn(async move {
            if let Err(error) = session
                .preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    proxy,
                    preferred_http_version,
                )
                .await
            {
                tracing::debug!(
                    host = %host,
                    port,
                    error = %error,
                    "tcp.background_probe_failed"
                );
            } else {
                tracing::debug!(host = %host, port, "tcp.background_probe_succeeded");
            }
        });
    }

    // -------------------------------------------------------------------
    // Cookie management (session-level)
    // -------------------------------------------------------------------

    /// Set a cookie in the session's cookie jar.
    ///
    /// The cookie is associated with `url` and will be sent on subsequent
    /// requests to matching domains/paths according to standard cookie rules.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.set_cookie("https://example.com", "session_id", "abc123");
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cookie(&self, url: &str, name: &str, value: &str) {
        match Url::parse(url) {
            Ok(parsed) => {
                let raw = cookie_store::RawCookie::new(name.to_string(), value.to_string());
                self.inner.cookie_jar.rcu(move |old| {
                    let mut jar = (**old).clone();
                    let _ = jar.insert_raw(&raw, &parsed);
                    jar
                });
            }
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.set_cookie: invalid URL, cookie not set");
            }
        }
    }

    /// Set a cookie with full attributes (path, domain, etc.).
    ///
    /// This allows setting cookies that are scoped to specific paths, which
    /// enables multiple cookies with the **same name** but different paths —
    /// a common pattern with real browsers.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// // Same name, different paths — both will be sent for /api/users
    /// session.set_cookie_with_attrs(
    ///     "https://example.com",
    ///     "token", "root_val",
    ///     Some("/"), None, false, false,
    /// );
    /// session.set_cookie_with_attrs(
    ///     "https://example.com",
    ///     "token", "api_val",
    ///     Some("/api"), None, false, false,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn set_cookie_with_attrs(
        &self,
        url: &str,
        name: &str,
        value: &str,
        path: Option<&str>,
        domain: Option<&str>,
        secure: bool,
        http_only: bool,
    ) {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.set_cookie_with_attrs: invalid URL, cookie not set");
                return;
            }
        };
        let mut builder = cookie_store::RawCookie::build(cookie_store::RawCookie::new(
            name.to_string(),
            value.to_string(),
        ));
        if let Some(p) = path {
            builder = builder.path(p);
        }
        if let Some(d) = domain {
            builder = builder.domain(d);
        }
        if secure {
            builder = builder.secure(true);
        }
        if http_only {
            builder = builder.http_only(true);
        }
        let built = builder.build();
        self.inner.cookie_jar.rcu(move |old| {
            let mut jar = (**old).clone();
            let _ = jar.insert_raw(&built, &parsed);
            jar
        });
    }

    /// Set a cookie from a raw `Set-Cookie` header string.
    ///
    /// This is the most flexible way to set cookies, supporting all cookie
    /// attributes (path, domain, expires, max-age, secure, httponly, samesite).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.set_cookie_raw(
    ///     "https://example.com",
    ///     "id=abc; Path=/; Domain=example.com; Secure; HttpOnly",
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cookie_raw(&self, url: &str, set_cookie_header: &str) {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.set_cookie_raw: invalid URL, cookie not set");
                return;
            }
        };
        match cookie_store::RawCookie::parse(set_cookie_header.to_string()) {
            Ok(raw) => {
                self.inner.cookie_jar.rcu(move |old| {
                    let mut jar = (**old).clone();
                    let _ = jar.insert_raw(&raw, &parsed);
                    jar
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "session.set_cookie_raw: failed to parse Set-Cookie header");
            }
        }
    }

    /// Get all cookies that would be sent for the given URL.
    ///
    /// Returns a list of `(name, value)` pairs matching the URL's domain and
    /// path.  **May contain duplicate names** if the same cookie name exists
    /// at different paths/domains.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let cookies = session.get_cookies("https://example.com/api/users");
    /// // Could contain: [("token", "api_val"), ("token", "root_val"), ("session", "xyz")]
    /// for (name, value) in &cookies {
    ///     println!("{name}={value}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_cookies(&self, url: &str) -> Vec<(String, String)> {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let jar = self.inner.cookie_jar.load();
        jar.matches(&parsed)
            .into_iter()
            .map(|c| (c.name().to_string(), c.value().to_string()))
            .collect()
    }

    /// Get the value of a specific cookie by name for the given URL.
    ///
    /// If multiple cookies with the same name match (different paths),
    /// returns the most specific one (longest path match, per RFC 6265).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// if let Some(value) = session.get_cookie("https://example.com/api", "token") {
    ///     println!("token = {value}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_cookie(&self, url: &str, name: &str) -> Option<String> {
        let parsed = Url::parse(url).ok()?;
        let jar = self.inner.cookie_jar.load();
        // CookieStore::matches returns cookies sorted by path specificity
        // (most specific first, per RFC 6265 Section 5.4)
        jar.matches(&parsed)
            .into_iter()
            .find(|c| c.name() == name)
            .map(|c| c.value().to_string())
    }

    /// Get all values for a specific cookie name matching the given URL.
    ///
    /// Returns multiple values when the same cookie name exists at different
    /// paths or domains.  Values are ordered by path specificity (most
    /// specific first).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// // If "token" exists at "/" and "/api":
    /// let values = session.get_cookie_values("https://example.com/api", "token");
    /// // Returns: ["api_val", "root_val"]
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_cookie_values(&self, url: &str, name: &str) -> Vec<String> {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let jar = self.inner.cookie_jar.load();
        jar.matches(&parsed)
            .into_iter()
            .filter(|c| c.name() == name)
            .map(|c| c.value().to_string())
            .collect()
    }

    /// Remove all cookies matching the given name for the specified URL's domain.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.remove_cookie("https://example.com", "session_id");
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_cookie(&self, url: &str, name: &str) {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "session.remove_cookie: invalid URL, cookie not removed");
                return;
            }
        };
        let name = name.to_string();
        self.inner.cookie_jar.rcu(move |old| {
            let mut jar = (**old).clone();
            let removal =
                cookie_store::RawCookie::build(cookie_store::RawCookie::new(name.clone(), ""))
                    .max_age(cookie::time::Duration::ZERO)
                    .path("/")
                    .build();
            let _ = jar.insert_raw(&removal, &parsed);
            jar
        });
    }

    /// Remove all cookies from the session's cookie jar.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// session.clear_cookies();
    /// assert!(session.get_cookies("https://example.com").is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear_cookies(&self) {
        self.inner.cookie_jar.store(Arc::new(CookieStore::new()));
    }

    /// Get the cookie header string that would be sent for the given URL.
    ///
    /// Returns `None` if no cookies match.  May contain duplicate names
    /// (from different paths/domains).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// if let Some(header) = session.cookie_header("https://example.com") {
    ///     println!("Cookie: {header}");  // "session_id=abc123; theme=dark"
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie_header(&self, url: &str) -> Option<String> {
        let parsed = Url::parse(url).ok()?;
        let jar = self.inner.cookie_jar.load();
        let cookies: Vec<String> = jar
            .matches(&parsed)
            .into_iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect();
        if cookies.is_empty() {
            None
        } else {
            Some(cookies.join("; "))
        }
    }

    // -------------------------------------------------------------------
    // Connection pool monitoring
    // -------------------------------------------------------------------

    /// Return a snapshot of the connection pool statistics.
    pub fn pool_stats(&self) -> crate::connection_pool::PoolStats {
        self.inner.pool.lock().stats()
    }

    /// Remove all connections from the pool, aborting their driver tasks.
    ///
    /// Subsequent requests will establish fresh connections.  This is
    /// primarily useful for benchmarks that need to measure cold-start
    /// latency without leaking spawned tasks and TIME_WAIT sockets.
    pub fn pool_clear(&self) {
        self.inner.pool.lock().clear();
    }

    // -------------------------------------------------------------------
    // TLS connector construction
    // -------------------------------------------------------------------

    /// Build a fully configured [`crate::tls::TlsConnector`] from Client + Session settings.
    ///
    /// Applies verify, custom CA, keylog, and ECH (session > client > DNS auto)
    /// configurations. Each call site only needs to provide the TLS profile
    /// and ALPS payload (which vary depending on protocol context).
    pub(crate) async fn build_tls_connector(
        &self,
        tls_profile: lktls::profile::types::TlsProfile,
        alps_payload: Vec<u8>,
        host: &str,
    ) -> crate::tls::TlsConnector {
        let client = &self.inner.client;
        let mut connector = crate::tls::TlsConnector::new(tls_profile)
            .alps_payload(alps_payload)
            .session_store(self.inner.session_store.clone()
                as std::sync::Arc<dyn lktls::session_store::SessionStore>);

        if client.verify() {
            // verify=true → Strict: every chain/hostname/signature failure
            // aborts the handshake. verify=false → Insecure (explicit opt-out).
            // (webpki cannot distinguish a missing-intermediate from an untrusted
            // root — both are UnknownIssuer — so tolerating incomplete chains
            // would require AIA fetching; that is a separate feature.)
            connector =
                connector.verification_policy(lktls::verify::policy::VerificationPolicy::Strict);
        } else {
            connector = connector.insecure_skip_verify(true);
        }
        if let Some(anchors) = client.custom_ca_anchors() {
            connector = connector.custom_ca_anchors(std::sync::Arc::clone(anchors));
        }
        if let Some(cb) = client.keylog_callback() {
            connector = connector.keylog(cb.clone());
        }

        if let Some(ref ech_config) = self.inner.ech_config {
            connector = connector.ech_config(ech_config.clone());
        } else if let Some(ech_config) = client.ech_config() {
            connector = connector.ech_config(ech_config.to_vec());
        } else if let Ok(Some(https_rr)) = client.resolver().lookup_https(host).await {
            if let Some(ech_bytes) = https_rr.ech_config_list {
                tracing::debug!(
                    host = %host,
                    ech_len = ech_bytes.len(),
                    "ech.auto_configured_from_dns",
                );
                connector = connector.ech_config(ech_bytes);
            }
        }

        connector
    }

    // -------------------------------------------------------------------
    // Unified connection establishment
    // -------------------------------------------------------------------

    /// Establish a transport connection: TCP → optional TLS → ALPN.
    ///
    /// This is the single entry point for all connection establishment,
    /// used by `establish_and_send`, `streaming`, `preconnect`, and
    /// `websocket`. Each caller provides a [`crate::connect::ConnectConfig`] with the
    /// per-request parameters that vary.
    pub(crate) async fn establish_connection(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&crate::proxy::ProxyConfig>,
        config: &crate::connect::ConnectConfig,
    ) -> crate::error::Result<crate::connect::EstablishedConnection> {
        let client = &self.inner.client;
        let timeouts = client.timeouts();

        // Phase 1: TCP connect (direct or through proxy, with optional fallback)
        let tcp_start = std::time::Instant::now();
        let tcp_timeout = timeouts.tcp_connect_timeout_or(std::time::Duration::from_secs(10));
        let tcp = crate::connect::connect_tcp(
            host,
            port,
            proxy,
            client.tcp_fingerprint(),
            client.resolver(),
            tcp_timeout,
            config,
        )
        .await?;
        let tcp_duration = tcp_start.elapsed();

        tracing::debug!(
            phase = "tcp_connect",
            duration_ms = tcp_duration.as_millis() as u64,
            "http.connect.phase_complete",
        );

        // Phase 2: TLS handshake (only for HTTPS)
        match config.scheme {
            crate::connection_pool::Scheme::Https => {
                let tls_timeout =
                    timeouts.tls_handshake_timeout_or(std::time::Duration::from_secs(10));
                let tls_connector = self
                    .build_tls_connector(
                        config.tls_profile.clone(),
                        config.alps_payload.clone(),
                        host,
                    )
                    .await;

                crate::connect::wrap_tls(tcp, host, port, &tls_connector, tls_timeout).await
            }
            crate::connection_pool::Scheme::Http => {
                let remote_addr = tcp.peer_addr().ok();
                if let Some(addr) = remote_addr {
                    crate::diagnostics::record_remote_addr(addr.to_string());
                }
                Ok(crate::connect::EstablishedConnection::Tcp {
                    stream: crate::connect::TransportStream::plain(tcp),
                    negotiated_alpn: None,
                    remote_addr,
                    negotiated_cipher_suite: None,
                })
            }
        }
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) async fn establish_h3_connection(
        &self,
        host: &str,
        port: u16,
        advertised_host: Option<&str>,
        advertised_port: Option<u16>,
        proxy: Option<&crate::proxy::ProxyConfig>,
    ) -> crate::error::Result<lkh3::H3Connection> {
        self.establish_h3_connection_with_0rtt(
            host,
            port,
            advertised_host,
            advertised_port,
            proxy,
            false,
        )
        .await?
        .into_handshake()
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn establish_h3_connection_with_0rtt(
        &self,
        host: &str,
        port: u16,
        advertised_host: Option<&str>,
        advertised_port: Option<u16>,
        proxy: Option<&crate::proxy::ProxyConfig>,
        allow_0rtt: bool,
    ) -> crate::error::Result<H3ConnectOutcome> {
        let client = &self.inner.client;
        let quic_profile = client.quic_profile().ok_or_else(|| {
            Error::InvalidConfig("HTTP/3 requested but client has no QUIC/H3 profile".into())
        })?;
        let dial_host = advertised_host.unwrap_or(host);
        let dial_port = advertised_port.unwrap_or(port);
        let server_name = advertised_host.unwrap_or(host);
        tracing::debug!(
            host = %host,
            port,
            dial_host = %dial_host,
            dial_port,
            server_name = %server_name,
            via_proxy = proxy.is_some(),
            "session.h3_connect_start"
        );

        // socks5h: proxy resolves DNS, skip local resolution
        let is_remote_dns = proxy.is_some_and(|p| {
            matches!(
                p.scheme,
                crate::proxy::ProxyScheme::Socks5 {
                    remote_dns: true,
                    ..
                }
            )
        });

        let remote_addr = if is_remote_dns {
            None
        } else {
            Some(
                client
                    .resolver()
                    .resolve(dial_host, dial_port)
                    .await
                    .map_err(Error::Io)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        Error::connection(
                            crate::error::ConnectionPhase::DnsResolution,
                            format!(
                                "DNS resolution returned no addresses for {dial_host}:{dial_port}"
                            ),
                            None,
                        )
                    })?,
            )
        };

        let mut tls_profile = client
            .quic_tls_profile()
            .unwrap_or_else(|| client.tls_profile())
            .clone();
        tls_profile.alpn_protocols = vec!["h3".to_string()];
        let alps_payload = if tls_profile.alps_protocols.is_some() {
            tls_profile.alps_protocols = Some(vec!["h3".to_string()]);
            Some(lkh3::encode_alps_h3_settings(&quic_profile.h3))
        } else {
            None
        };

        let mut crypto = lktls_quic::LktlsQuicClientConfig::new(tls_profile)
            .port(dial_port)
            .session_store(self.inner.session_store.clone());
        if let Some(alps_payload) = alps_payload {
            crypto = crypto.alps_payload(alps_payload);
        }
        if client.verify() {
            // See the TCP path above: verify=true → Strict (enforce), verify=false
            // → Insecure (explicit opt-out).
            crypto = crypto.verification_policy(lktls::verify::policy::VerificationPolicy::Strict);
        } else {
            crypto =
                crypto.verification_policy(lktls::verify::policy::VerificationPolicy::Insecure);
        }
        if let Some(anchors) = client.custom_ca_anchors().cloned() {
            crypto = crypto.custom_ca_anchors(anchors);
        }
        if let Some(ech) = client.ech_config() {
            crypto = crypto.ech_config(ech.to_vec());
        }
        if let Some(cb) = client.keylog_callback().cloned() {
            crypto = crypto.keylog(cb);
        }

        let mut quinn_config = crypto.into_quinn();
        let tp = &quic_profile.transport_params;
        let mut transport_config = quinn::TransportConfig::default();
        if tp.max_idle_timeout > 0 {
            transport_config.max_idle_timeout(Some(
                std::time::Duration::from_millis(tp.max_idle_timeout)
                    .try_into()
                    .expect("max_idle_timeout fits in IdleTimeout"),
            ));
        }
        if tp.initial_max_stream_data_bidi_local != tp.initial_max_stream_data_bidi_remote
            || tp.initial_max_stream_data_bidi_local != tp.initial_max_stream_data_uni
        {
            tracing::warn!(
                bidi_local = tp.initial_max_stream_data_bidi_local,
                bidi_remote = tp.initial_max_stream_data_bidi_remote,
                uni = tp.initial_max_stream_data_uni,
                "session.h3_connect: quinn uses a single stream_receive_window for all stream \
                 types; using initial_max_stream_data_bidi_local as the common value"
            );
        }
        transport_config
            .receive_window(
                quinn::VarInt::from_u64(tp.initial_max_data).unwrap_or(quinn::VarInt::MAX),
            )
            .stream_receive_window(
                quinn::VarInt::from_u64(tp.initial_max_stream_data_bidi_local)
                    .unwrap_or(quinn::VarInt::MAX),
            )
            .max_concurrent_bidi_streams(
                quinn::VarInt::from_u64(tp.initial_max_streams_bidi).unwrap_or(quinn::VarInt::MAX),
            )
            .max_concurrent_uni_streams(
                quinn::VarInt::from_u64(tp.initial_max_streams_uni).unwrap_or(quinn::VarInt::MAX),
            );
        if let Some(max_datagram_frame_size) = tp.max_datagram_frame_size {
            let value = usize::try_from(max_datagram_frame_size).unwrap_or(usize::MAX);
            transport_config.datagram_receive_buffer_size(Some(value));
        }
        transport_config
            .send_reserved_transport_parameter(tp.send_reserved_transport_parameter)
            .send_min_ack_delay_transport_parameter(tp.send_min_ack_delay);
        let mut extra_transport_parameters =
            decode_extra_transport_parameters(&tp.extra_transport_parameters)?;
        let mut transport_parameter_order =
            decode_transport_parameter_order(&tp.transport_parameter_order)?;
        if tp.shuffle_transport_parameters {
            // Chrome/BoringSSL randomizes both the GREASE params and the wire
            // order on every connection (capture-verified). Randomize first
            // (patches the order's GREASE-id reference), then shuffle the order.
            randomize_quic_grease_params(
                &mut extra_transport_parameters,
                &mut transport_parameter_order,
            );
            shuffle_transport_parameter_order(&mut transport_parameter_order);
        }
        transport_config
            .extra_transport_parameters(extra_transport_parameters)
            .map_err(|err| {
                Error::InvalidConfig(format!("invalid extra QUIC transport parameter: {err}"))
            })?;
        transport_config
            .transport_parameter_order(transport_parameter_order)
            .map_err(|err| {
                Error::InvalidConfig(format!("invalid QUIC transport parameter order: {err}"))
            })?;
        let packetization = &quic_profile.packetization;
        if let Some(initial_mtu) = packetization.initial_mtu {
            transport_config.initial_mtu(initial_mtu);
        }
        if let Some(initial_datagram_size) = packetization.initial_datagram_size {
            transport_config.initial_datagram_size(initial_datagram_size);
        }
        if packetization.disable_mtu_discovery {
            transport_config.mtu_discovery_config(None);
        }
        transport_config.enable_segmentation_offload(packetization.enable_segmentation_offload);
        transport_config.enable_ecn(packetization.enable_ecn);
        if let Some(layout) = &packetization.initial_frame_layout {
            transport_config.initial_frame_layout(Some(build_initial_frame_layout_config(layout)));
        }
        let actual_active_connection_id_limit = if quic_profile.connection_id_length == 0 {
            2_u64
        } else {
            5_u64
        };
        if tp.active_connection_id_limit != actual_active_connection_id_limit {
            tracing::warn!(
                configured = tp.active_connection_id_limit,
                actual = actual_active_connection_id_limit,
                "session.h3_connect: quinn derives active_connection_id_limit from its CID queue \
                 based on the configured local connection ID length"
            );
        }
        quinn_config.transport_config(Arc::new(transport_config));

        let tcp_timeout = client
            .timeouts()
            .tcp_connect_timeout_or(std::time::Duration::from_secs(10));
        let quic_timeout = client
            .timeouts()
            .quic_connect_timeout
            .unwrap_or(std::time::Duration::from_secs(5));

        let quic_conn = match proxy {
            Some(proxy_cfg)
                if matches!(proxy_cfg.scheme, crate::proxy::ProxyScheme::Socks5 { .. }) =>
            {
                // Keep SOCKS5 UDP ASSOCIATE under the proxy/TCP budget. The
                // QUIC budget should start only once the relay exists and the
                // first QUIC Initial can actually be sent. 0-RTT through this
                // per-relay endpoint is intentionally left for a follow-up.
                self.connect_quic_via_socks5(
                    proxy_cfg,
                    remote_addr,
                    dial_host,
                    dial_port,
                    server_name,
                    quinn_config,
                    client,
                    tcp_timeout,
                    quic_timeout,
                )
                .await?
            }
            Some(proxy_cfg) => {
                // A non-SOCKS5 proxy (e.g. HTTP CONNECT) cannot relay UDP, so
                // there is no way to carry QUIC/H3 through it. Fail loudly rather
                // than silently dialing the origin directly — a direct UDP
                // connection would bypass the proxy and leak the real client IP.
                return Err(Error::InvalidConfig(format!(
                    "HTTP/3 requires a SOCKS5 proxy to relay UDP; proxy scheme {:?} cannot carry QUIC",
                    proxy_cfg.scheme
                )));
            }
            None => {
                let addr = remote_addr.ok_or_else(|| {
                    Error::InvalidConfig(
                        "remote DNS (socks5h) requires a SOCKS5 proxy for QUIC".into(),
                    )
                })?;
                let started = {
                    let mut manager = client.quic_endpoint_manager().lock().await;
                    manager
                        .start_connect(lkquic::ConnectRequest::new(addr, server_name, quinn_config))
                        .await
                        .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?
                };
                let (connecting, endpoint_guard) = started.into_parts();

                if allow_0rtt {
                    match connecting.into_0rtt() {
                        Ok((quic_conn, accepted)) => {
                            drop(endpoint_guard);
                            tracing::debug!(
                                host = %host,
                                port,
                                "session.h3_connect_0rtt_available"
                            );
                            let h3_conn = tokio::time::timeout(
                                quic_timeout,
                                lkh3::connect_h3_0rtt(quic_conn, &quic_profile.h3, accepted),
                            )
                            .await
                            .map_err(|_| {
                                Error::timeout(
                                    format!(
                                        "HTTP/3 0-RTT control setup to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                                    ),
                                    Some(crate::error::ConnectionPhase::H3Negotiation),
                                    Some(quic_timeout),
                                )
                            })?
                            .map_err(|e| {
                                Error::quic(
                                    QuicPhase::Handshake,
                                    format!("H3 0-RTT control setup: {e}"),
                                )
                            })?;
                            return Ok(H3ConnectOutcome::ZeroRtt(h3_conn));
                        }
                        Err(connecting) => {
                            tracing::trace!(
                                host = %host,
                                port,
                                "session.h3_connect_0rtt_unavailable"
                            );
                            tokio::time::timeout(quic_timeout, connecting)
                                .await
                                .map_err(|_| {
                                    Error::timeout(
                                        format!(
                                            "QUIC handshake to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                                        ),
                                        Some(crate::error::ConnectionPhase::QuicHandshake),
                                        Some(quic_timeout),
                                    )
                                })?
                                .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?
                        }
                    }
                } else {
                    tokio::time::timeout(quic_timeout, connecting)
                        .await
                        .map_err(|_| {
                            Error::timeout(
                                format!(
                                    "QUIC handshake to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                                ),
                                Some(crate::error::ConnectionPhase::QuicHandshake),
                                Some(quic_timeout),
                            )
                        })?
                        .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?
                }
            }
        };

        let h3_conn = tokio::time::timeout(quic_timeout, lkh3::connect_h3(quic_conn, &quic_profile.h3))
            .await
            .map_err(|_| {
                Error::timeout(
                    format!(
                        "HTTP/3 control setup to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                    ),
                    Some(crate::error::ConnectionPhase::QuicHandshake),
                    Some(quic_timeout),
                )
            })?
            .map_err(|e| Error::quic(QuicPhase::Handshake, format!("H3 control setup: {e}")))?;
        tracing::debug!(
            host = %host,
            port,
            remote = ?remote_addr,
            pseudo_order = %quic_profile.h3.pseudo_header_order_token(),
            "session.h3_connect_ready"
        );
        Ok(H3ConnectOutcome::Handshake(h3_conn))
    }

    /// Establish a QUIC connection through a SOCKS5 UDP relay.
    ///
    /// The TCP control connection from UDP ASSOCIATE is owned by the
    /// `Socks5UdpSocket` which is held by `Arc` inside the quinn `Endpoint`.
    /// When the QUIC connection (and its endpoint) is dropped, the control
    /// connection is closed automatically, invalidating the relay.
    ///
    /// For `socks5h://` (remote DNS), `remote_addr` may be `None` — DNS is
    /// resolved by the proxy and the domain name is embedded in every UDP
    /// datagram header (ATYP=0x03).
    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    async fn connect_quic_via_socks5(
        &self,
        proxy_cfg: &crate::proxy::ProxyConfig,
        remote_addr: Option<std::net::SocketAddr>,
        dial_host: &str,
        dial_port: u16,
        server_name: &str,
        quinn_config: quinn::ClientConfig,
        client: &crate::client::Client,
        proxy_timeout: std::time::Duration,
        quic_timeout: std::time::Duration,
    ) -> crate::error::Result<quinn::Connection> {
        use crate::proxy::socks5_udp::{Socks5UdpSocket, SocksTarget};

        let tcp_fp = client.tcp_fingerprint();
        let resolver = client.resolver();
        let (proxy_host, proxy_port) = proxy_cfg.host_port();

        tracing::debug!(
            proxy = %format_args!("{proxy_host}:{proxy_port}"),
            target = %format_args!("{dial_host}:{dial_port}"),
            server_name = %server_name,
            remote_dns = remote_addr.is_none(),
            proxy_timeout_ms = proxy_timeout.as_millis() as u64,
            quic_timeout_ms = quic_timeout.as_millis() as u64,
            "quic.socks5_connect_prepare"
        );

        let associate = tokio::time::timeout(proxy_timeout, proxy_cfg.udp_associate(tcp_fp, resolver))
            .await
            .map_err(|_| {
                Error::timeout(
                    format!(
                        "SOCKS5 UDP ASSOCIATE to {proxy_host}:{proxy_port} timed out after {proxy_timeout:?}"
                    ),
                    Some(crate::error::ConnectionPhase::ProxyTunnel),
                    Some(proxy_timeout),
                )
            })
            .and_then(|inner| inner);

        let (control_conn, relay_addr) = match associate {
            Ok(value) => value,
            Err(error) => {
                // UDP ASSOCIATE failed *before* any QUIC bytes ever hit the
                // wire — this is a property of the proxy, not the origin.
                // Quarantine the entire route so the next request to *any*
                // origin via this proxy skips H3 immediately and falls
                // through to H2 without paying another ~proxy_timeout.
                let route = crate::protocol::RouteKey::from_proxy(Some(proxy_cfg));
                self.broken_quic_tracker()
                    .mark_route_broken(&route, crate::alt_svc::BrokenReason::ProxyUdpUnavailable);
                tracing::warn!(
                    proxy = %format_args!("{proxy_host}:{proxy_port}"),
                    target = %format_args!("{dial_host}:{dial_port}"),
                    error = %error,
                    "quic.socks5_udp_associate_failed_route_quarantined"
                );
                return Err(error);
            }
        };

        let relay_addr = if relay_addr.ip().is_unspecified() {
            let proxy_ip = control_conn.peer_addr().map_err(|e| {
                Error::proxy(
                    crate::error::ProxyErrorKind::IoError,
                    format!("failed to get proxy peer address: {e}"),
                    Some(Box::new(e)),
                )
            })?;
            std::net::SocketAddr::new(proxy_ip.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        let bind_addr: std::net::SocketAddr = if relay_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let local_udp = tokio::net::UdpSocket::bind(bind_addr).await.map_err(|e| {
            Error::quic(
                QuicPhase::Handshake,
                format!("failed to bind local UDP for SOCKS5 relay: {e}"),
            )
        })?;
        let local_udp_addr = local_udp.local_addr().ok();

        let target = match remote_addr {
            Some(addr) => SocksTarget::Ip(addr),
            None => SocksTarget::Domain {
                host: dial_host.to_string(),
                port: dial_port,
            },
        };

        let socks5_socket = Arc::new(Socks5UdpSocket::new(
            local_udp,
            relay_addr,
            target,
            control_conn,
        ));

        let quinn_addr = socks5_socket.quinn_addr();

        tracing::debug!(
            local_udp = ?local_udp_addr,
            relay = %relay_addr,
            quinn_addr = %quinn_addr,
            remote_dns = remote_addr.is_none(),
            "quic.socks5_relay_ready"
        );

        let manager = client.quic_endpoint_manager().lock().await;
        let backend = manager.backend();
        let endpoint = backend
            .create_endpoint_with_socket(
                socks5_socket as Arc<dyn quinn::AsyncUdpSocket>,
                manager.cid_len(),
                manager.endpoint_max_udp_payload_size(),
                manager.grease_quic_bit_enabled(),
                manager.endpoint_initial_destination_cid_len(),
            )
            .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?;

        tracing::debug!(
            quinn_addr = %quinn_addr,
            relay = %relay_addr,
            remote_dns = remote_addr.is_none(),
            "quic.socks5_connect_start"
        );

        let connecting = endpoint
            .connect_with(quinn_config, quinn_addr, server_name)
            .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))?;

        tracing::debug!(
            target = %format_args!("{dial_host}:{dial_port}"),
            server_name = %server_name,
            "quic.socks5_handshake_waiting"
        );

        tokio::time::timeout(quic_timeout, connecting)
            .await
            .map_err(|_| {
                tracing::warn!(
                    target = %format_args!("{dial_host}:{dial_port}"),
                    server_name = %server_name,
                    timeout_ms = quic_timeout.as_millis() as u64,
                    "quic.socks5_handshake_timeout"
                );
                Error::timeout(
                    format!(
                        "QUIC handshake to {dial_host}:{dial_port} timed out after {quic_timeout:?}"
                    ),
                    Some(crate::error::ConnectionPhase::QuicHandshake),
                    Some(quic_timeout),
                )
            })?
            .inspect(|_| {
                tracing::debug!(
                    target = %format_args!("{dial_host}:{dial_port}"),
                    server_name = %server_name,
                    "quic.socks5_connect_established"
                );
            })
            .map_err(|e| Error::quic(QuicPhase::Handshake, e.to_string()))
    }

    #[cfg(feature = "quic-h3")]
    fn preconnect_h3<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        conn_key: &'a crate::connection_pool::ConnectionKey,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a crate::proxy::ProxyConfig>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::error::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            let h3_conn = match self
                .establish_h3_connection(
                    host,
                    port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy,
                )
                .await
            {
                Ok(h3_conn) => h3_conn,
                Err(error) => {
                    self.broken_quic_tracker()
                        .mark_broken_for_route(&discovery.route, &discovery.origin);
                    self.alt_svc_cache()
                        .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    return Err(error);
                }
            };

            self.broken_quic_tracker()
                .mark_working_for_route(&discovery.route, &discovery.origin);
            // Successful H3 over this route also proves the proxy can
            // carry UDP, so clear any prior `ProxyUdpUnavailable` mark.
            self.broken_quic_tracker()
                .mark_route_working(&discovery.route);
            self.alt_svc_cache()
                .mark_h3_validated_for_route(&discovery.route, &discovery.origin);
            let (sender, driver) = h3_conn.into_parts();
            let driver = std::sync::Arc::new(driver);
            let mut pool = self.inner.pool.lock();
            pool.insert_h3(conn_key.clone(), sender, driver);
            Ok(())
        })
    }

    fn preconnect_tcp<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        scheme: crate::connection_pool::Scheme,
        conn_key: &'a crate::connection_pool::ConnectionKey,
        proxy: Option<crate::proxy::ProxyConfig>,
        preferred_http_version: PreferredHttpVersion,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::error::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            let client = &self.inner.client;
            let connect_config =
                pipeline::build_connect_config(client, preferred_http_version, scheme);

            let conn = self
                .establish_connection(host, port, proxy.as_ref(), &connect_config)
                .await?;

            let use_h2 = pipeline::should_use_h2(conn.negotiated_alpn(), preferred_http_version)?;

            if use_h2 {
                let h2_conn =
                    crate::h2::connect_h2(conn.into_tcp_stream()?, client.h2_profile(), None)
                        .await?;
                let mut pool = self.inner.pool.lock();
                pool.insert_h2(
                    conn_key.clone(),
                    h2_conn.clone_sender(),
                    h2_conn.into_task(),
                );
            } else {
                let mut builder = hyper::client::conn::http1::Builder::new();
                builder.title_case_headers(true).preserve_header_case(true);
                let (sender, conn_driver) = builder
                    .handshake::<
                        crate::connect::TransportStream,
                        http_body_util::Full<bytes::Bytes>,
                    >(conn.into_tcp_stream()?)
                    .await
                    .map_err(|e| {
                        crate::error::Error::Http(format!(
                            "preconnect HTTP/1.1 handshake failed: {e}"
                        ))
                    })?;

                let conn_task = tokio::spawn(async move {
                    if let Err(e) = conn_driver.await {
                        tracing::debug!(error = %e, "preconnect.h1_connection_closed");
                    }
                });
                let mut pool = self.inner.pool.lock();
                pool.insert_h1(conn_key.clone(), sender, conn_task);
            }

            Ok(())
        })
    }

    // -------------------------------------------------------------------
    // Request builders
    // -------------------------------------------------------------------

    /// Start building a GET request.
    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::GET, url)
    }

    /// Start building a request with an explicit HTTP method.
    pub fn request(&self, method: http::Method, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, url)
    }

    /// Start building a POST request.
    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::POST, url)
    }

    /// Start building a PUT request.
    pub fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::PUT, url)
    }

    /// Start building a DELETE request.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::DELETE, url)
    }

    /// Start building a HEAD request.
    pub fn head(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::HEAD, url)
    }

    /// Start building a PATCH request.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::PATCH, url)
    }

    /// Start building an OPTIONS request.
    pub fn options(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), http::Method::OPTIONS, url)
    }

    /// Pre-establish a connection to the given URL.
    ///
    /// Completes DNS resolution, TCP connect, TLS handshake (for HTTPS),
    /// and HTTP/2 SETTINGS exchange (if applicable), then stores the ready
    /// connection in the session's connection pool.  Subsequent requests to
    /// the same `host:port` will reuse this connection, eliminating
    /// cold-start latency.
    ///
    /// If a pooled connection for this origin already exists, this method
    /// returns immediately without creating a new one.
    ///
    /// Both `https://` and `http://` URLs are supported. For HTTP, only a
    /// TCP connect and HTTP/1.1 handshake are performed (no TLS).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # let client = Client::default();
    /// # let session = client.session().build();
    /// session.preconnect("https://api.example.com").await?;
    /// session.preconnect("http://legacy-api.example.com").await?;
    /// // subsequent requests reuse the pre-warmed connections
    /// let resp = session.get("https://api.example.com/data").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn preconnect(&self, url: &str) -> crate::error::Result<()> {
        use crate::connection_pool::{ConnectionKey, Scheme};

        let parsed =
            Url::parse(url).map_err(|e| crate::error::Error::UrlParse(format!("{url}: {e}")))?;

        let scheme = match parsed.scheme() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            other => {
                return Err(crate::error::Error::UrlParse(format!(
                    "preconnect: unsupported scheme: {other}"
                )));
            }
        };

        let host = parsed
            .host_str()
            .ok_or_else(|| crate::error::Error::UrlParse("missing host".into()))?
            .to_string();

        let port = parsed.port_or_known_default().unwrap_or(match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        });

        let route = crate::protocol::RouteKey::from_proxy(self.inner.proxy.as_ref());
        let conn_key = ConnectionKey {
            scheme,
            host: Arc::from(host.as_str()),
            port,
            route,
        };

        // Skip if a connection already exists — uses has_connection() to
        // avoid the H1 connection leak that try_acquire() would cause.
        let protocol_policy = self.inner.protocol_policy.clone();
        let preferred_http_version = pipeline::effective_http_version(None, &protocol_policy, self);
        pipeline::log_protocol_policy(
            &conn_key.route,
            &host,
            port,
            &protocol_policy,
            preferred_http_version,
        );
        {
            let mut pool = self.inner.pool.lock();
            let already_warmed = match preferred_http_version {
                PreferredHttpVersion::Auto => pool.has_connection(&conn_key),
                PreferredHttpVersion::Http1Only => pool.has_h1_connection(&conn_key),
                PreferredHttpVersion::Http2Only => pool.has_h2_connection(&conn_key),
                PreferredHttpVersion::Http3Only | PreferredHttpVersion::Http3WithFallback => {
                    pool.has_h3_connection(&conn_key)
                }
            };
            if already_warmed {
                return Ok(());
            }
        }

        let effective_proxy = self.inner.proxy.clone();
        if preferred_http_version == PreferredHttpVersion::Http3Only
            && self.inner.client.quic_profile().is_none()
        {
            return Err(Error::InvalidConfig(
                "HTTP/3 requested but client has no QUIC/H3 profile".into(),
            ));
        }
        let quic_discovery = pipeline::discover_quic_support(
            self,
            scheme,
            &host,
            port,
            effective_proxy.as_ref(),
            &protocol_policy,
            preferred_http_version,
        )
        .await;
        pipeline::log_quic_discovery(&quic_discovery);
        let decision =
            pipeline::decide_protocol(preferred_http_version, &protocol_policy, &quic_discovery);
        pipeline::log_protocol_decision(&quic_discovery, &protocol_policy, decision);

        match decision {
            pipeline::ProtocolDecision::Tcp => {
                self.preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    effective_proxy,
                    preferred_http_version,
                )
                .await?;
                let schedule_probe =
                    pipeline::should_background_probe(&protocol_policy, &quic_discovery);
                pipeline::log_background_probe_decision(
                    &conn_key.route,
                    &host,
                    port,
                    &protocol_policy,
                    &quic_discovery,
                    schedule_probe,
                );
                if schedule_probe {
                    self.spawn_background_quic_probe(
                        host.clone(),
                        port,
                        conn_key.clone(),
                        quic_discovery.clone(),
                        self.inner.proxy.clone(),
                    );
                }
            }
            #[cfg(feature = "quic-h3")]
            pipeline::ProtocolDecision::Quic => {
                self.preconnect_h3(
                    &host,
                    port,
                    &conn_key,
                    &quic_discovery,
                    effective_proxy.as_ref(),
                )
                .await?;
            }
            #[cfg(feature = "quic-h3")]
            pipeline::ProtocolDecision::Race => {
                let race_cfg = pipeline::protocol_policy_chrome_like_config(
                    &protocol_policy,
                    self.chrome_like_protocol_config(),
                );
                let quic_proxy = effective_proxy.clone();
                let mut quic_future = self.preconnect_h3(
                    &host,
                    port,
                    &conn_key,
                    &quic_discovery,
                    quic_proxy.as_ref(),
                );

                if !race_cfg.tcp_main_job_delay.is_zero() {
                    let mut tcp_delay =
                        std::pin::pin!(tokio::time::sleep(race_cfg.tcp_main_job_delay));
                    tokio::select! {
                        biased;

                        quic_result = &mut quic_future => match quic_result {
                            Ok(()) => {
                                if race_cfg.keep_tcp_probe_after_quic_win {
                                    self.spawn_background_tcp_probe(
                                        host.clone(),
                                        port,
                                        scheme,
                                        conn_key.clone(),
                                        effective_proxy.clone(),
                                        preferred_http_version,
                                    );
                                }
                                tracing::debug!(host = %host, port = port, "session.preconnect_complete");
                                return Ok(());
                            }
                            Err(quic_error) => {
                                tracing::warn!(
                                    error = %quic_error,
                                    fallback = "quic_to_tcp",
                                    "preconnect.h3_race_failed_before_tcp_release",
                                );
                                match self.preconnect_tcp(
                                    &host,
                                    port,
                                    scheme,
                                    &conn_key,
                                    effective_proxy,
                                    preferred_http_version,
                                )
                                .await {
                                    Ok(()) => {
                                        tracing::debug!(host = %host, port = port, "session.preconnect_complete");
                                        return Ok(());
                                    }
                                    Err(tcp_error) => {
                                        return Err(pipeline::protocol_race_error(tcp_error, quic_error));
                                    }
                                }
                            }
                        },
                        _ = &mut tcp_delay => {}
                    }
                }

                let mut tcp_future = self.preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    effective_proxy.clone(),
                    preferred_http_version,
                );

                tokio::select! {
                    biased;

                    quic_result = &mut quic_future => match quic_result {
                        Ok(()) => {
                            if race_cfg.keep_tcp_probe_after_quic_win {
                                self.spawn_background_tcp_probe(
                                    host.clone(),
                                    port,
                                    scheme,
                                    conn_key.clone(),
                                    effective_proxy.clone(),
                                    preferred_http_version,
                                );
                            }
                        }
                        Err(quic_error) => {
                            tracing::warn!(
                                error = %quic_error,
                                fallback = "quic_to_tcp",
                                "preconnect.h3_race_failed_waiting_for_tcp",
                            );
                            match tcp_future.await {
                                Ok(()) => {}
                                Err(tcp_error) => {
                                    return Err(pipeline::protocol_race_error(tcp_error, quic_error));
                                }
                            }
                        }
                    },
                    tcp_result = &mut tcp_future => match tcp_result {
                        Ok(()) => {
                            if race_cfg.keep_quic_probe_after_tcp_win {
                                self.spawn_background_quic_probe(
                                    host.clone(),
                                    port,
                                    conn_key.clone(),
                                    quic_discovery.clone(),
                                    effective_proxy.clone(),
                                );
                            }
                        }
                        Err(tcp_error) => match quic_future.await {
                            Ok(()) => {}
                            Err(quic_error) => {
                                return Err(pipeline::protocol_race_error(tcp_error, quic_error));
                            }
                        },
                    },
                }
            }
            #[cfg(not(feature = "quic-h3"))]
            pipeline::ProtocolDecision::Race => {
                self.preconnect_tcp(
                    &host,
                    port,
                    scheme,
                    &conn_key,
                    effective_proxy,
                    preferred_http_version,
                )
                .await?;
            }
            #[cfg(not(feature = "quic-h3"))]
            pipeline::ProtocolDecision::Quic => {
                return Err(Error::InvalidConfig(
                    "QUIC/H3 support is not compiled in; enable the `quic-h3` feature".into(),
                ));
            }
        }

        tracing::debug!(host = %host, port = port, "session.preconnect_complete");
        Ok(())
    }

    /// Pre-establish connections to multiple URLs concurrently.
    ///
    /// Each URL is preconnected independently.  Errors for individual URLs
    /// do not affect the others.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # let client = Client::default();
    /// # let session = client.session().build();
    /// let results = session.preconnect_many(&[
    ///     "https://api.example.com",
    ///     "https://cdn.example.com",
    /// ]).await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn preconnect_many(&self, urls: &[&str]) -> Vec<crate::error::Result<()>> {
        let mut handles = Vec::with_capacity(urls.len());
        for url in urls {
            let session = self.clone();
            let url = url.to_string();
            handles.push(tokio::spawn(async move { session.preconnect(&url).await }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.unwrap_or_else(|e| {
                Err(crate::error::Error::Http(format!(
                    "preconnect task panicked: {e}"
                )))
            }));
        }
        results
    }

    /// Start building a WebSocket connection.
    ///
    /// Supports both `wss://` (TLS) and `ws://` schemes, and automatically
    /// selects HTTP/1.1 Upgrade or HTTP/2 Extended CONNECT based on ALPN.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_144()).build();
    /// # let session = client.session().build();
    /// let mut ws = session.websocket("wss://echo.websocket.events")
    ///     .header("Origin", "https://echo.websocket.events")
    ///     .connect()
    ///     .await?;
    ///
    /// ws.send_text("hello").await?;
    /// let msg = ws.recv().await?;
    /// ws.close(None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn websocket(&self, url: &str) -> crate::ws::builder::WsBuilder {
        crate::ws::builder::WsBuilder::new_with_session(url, self.clone())
    }
}

// ---------------------------------------------------------------------------
// Session Builder
// ---------------------------------------------------------------------------

/// Preferred HTTP version for a session or request.
///
/// This is a request-side preference type. For the version observed on a
/// response, use [`crate::NegotiatedHttpVersion`] via
/// [`crate::Response::negotiated_version`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredHttpVersion {
    /// Use whatever the server negotiates via ALPN and policy defaults.
    Auto,
    /// Force HTTP/1.1 only (do not use HTTP/2 even if negotiated).
    Http1Only,
    /// Force HTTP/2 only (fail if server doesn't support H2).
    Http2Only,
    /// Force HTTP/3 only.
    Http3Only,
    /// Prefer HTTP/3 and fall back to TCP-based HTTP if QUIC fails.
    Http3WithFallback,
}

impl From<HttpVersion> for PreferredHttpVersion {
    fn from(version: HttpVersion) -> Self {
        match version {
            HttpVersion::Http10 | HttpVersion::Http11 => Self::Http1Only,
            HttpVersion::H2 => Self::Http2Only,
            HttpVersion::H3 => Self::Http3Only,
            HttpVersion::Unknown => Self::Auto,
        }
    }
}

/// How lkrequest chooses between TCP-based HTTP and QUIC/H3 when both are viable.
///
/// This only affects mixed-protocol selection in [`PreferredHttpVersion::Auto`].
/// Explicit session/request overrides such as `http1_only()`, `http2_only()`,
/// `http3_only()`, and `http3_with_fallback()` keep their existing semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolSelectionPolicy {
    /// Current lkrequest behavior: once QUIC/H3 is discovered as usable, go
    /// straight to QUIC instead of racing a TCP connection.
    #[default]
    Deterministic,
    /// Chrome-like behavior: when `Auto` mode has a viable H3 candidate
    /// (Alt-Svc / HTTPS DNS), race TCP and QUIC and use whichever path
    /// completes first.
    ChromeLike,
}

/// Tunables for [`ProtocolSelectionPolicy::ChromeLike`].
///
/// Chromium's "main TCP job" delay is dynamic and context-dependent. lkrequest
/// models it with a fixed QUIC head-start and explicit loser-probe toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChromeLikeProtocolConfig {
    /// Fixed delay before the TCP path is allowed to compete with QUIC.
    ///
    /// If QUIC fails before this delay expires, TCP starts immediately.
    pub tcp_main_job_delay: std::time::Duration,
    /// When TCP wins the race, keep probing QUIC in the background and update
    /// the broken-QUIC tracker / H3 pool from that outcome.
    pub keep_quic_probe_after_tcp_win: bool,
    /// When QUIC wins the race, optionally keep probing the TCP path in the
    /// background to warm the H1/H2 pool.
    pub keep_tcp_probe_after_quic_win: bool,
}

impl Default for ChromeLikeProtocolConfig {
    fn default() -> Self {
        Self {
            tcp_main_job_delay: std::time::Duration::from_millis(300),
            keep_quic_probe_after_tcp_win: true,
            keep_tcp_probe_after_quic_win: false,
        }
    }
}

fn apply_legacy_protocol_policy_overrides(
    policy: &mut ProtocolPolicy,
    preferred_http_version: PreferredHttpVersion,
    protocol_selection_policy: ProtocolSelectionPolicy,
    chrome_like_protocol_config: ChromeLikeProtocolConfig,
) {
    match preferred_http_version {
        PreferredHttpVersion::Http1Only | PreferredHttpVersion::Http2Only => {
            policy.intent = HttpIntent::H2Only;
            policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            policy.upgrade = crate::protocol::UpgradePolicy::Off;
            policy.fallback = FallbackPolicy::NoFallback;
        }
        PreferredHttpVersion::Http3Only => {
            policy.intent = HttpIntent::H3Only;
            policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            policy.fallback = FallbackPolicy::NoFallback;
        }
        PreferredHttpVersion::Http3WithFallback => {
            policy.intent = HttpIntent::AcquireH3WhenViable;
            policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            if matches!(policy.fallback, FallbackPolicy::NoFallback) {
                policy.fallback = FallbackPolicy::AllowFallbackOnNetworkErrors;
            }
        }
        PreferredHttpVersion::Auto => {}
    }

    match protocol_selection_policy {
        ProtocolSelectionPolicy::Deterministic => {
            if matches!(policy.acquisition, AcquisitionPolicy::Race(_))
                && preferred_http_version == PreferredHttpVersion::Auto
            {
                policy.acquisition = AcquisitionPolicy::EstablishBestAvailable;
            }
        }
        ProtocolSelectionPolicy::ChromeLike => {
            policy.acquisition = AcquisitionPolicy::Race(RacePolicy {
                enable_tcp: true,
                enable_quic: true,
                tcp_delay: chrome_like_protocol_config.tcp_main_job_delay,
                quic_delay: std::time::Duration::ZERO,
                only_when_h3_advertised: true,
            });
        }
    }
}

/// Builder for constructing a [`Session`].
pub struct SessionBuilder {
    client: Client,
    proxy: Option<ProxyConfig>,
    redirect_policy: RedirectPolicy,
    retry_policy: Option<Arc<dyn RetryPolicy>>,
    ech_config: Option<Vec<u8>>,
    middlewares: crate::middleware::MiddlewareStack,
    protocol_policy: Option<ProtocolPolicy>,
    preferred_http_version: Option<PreferredHttpVersion>,
    protocol_selection_policy: Option<ProtocolSelectionPolicy>,
    chrome_like_protocol_config: Option<ChromeLikeProtocolConfig>,
    default_accept_encoding: Option<AcceptEncoding>,
    max_connections_override: Option<usize>,
    idle_timeout: Option<std::time::Duration>,
    header_order: Option<Vec<http::header::HeaderName>>,
    h3_header_order: Option<Vec<http::header::HeaderName>>,
    cookie_order: Option<Vec<Box<str>>>,
    broken_quic_policy: Option<BrokenQuicPolicy>,
}

impl SessionBuilder {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            proxy: None,
            redirect_policy: RedirectPolicy::default(),
            retry_policy: None,
            ech_config: None,
            middlewares: Vec::new(),
            protocol_policy: None,
            preferred_http_version: None,
            protocol_selection_policy: None,
            chrome_like_protocol_config: None,
            default_accept_encoding: None,
            max_connections_override: None,
            idle_timeout: None,
            header_order: None,
            h3_header_order: None,
            cookie_order: None,
            broken_quic_policy: None,
        }
    }

    /// Set the proxy for this session from a URL string.
    ///
    /// All requests from this session will go through this proxy by default.
    pub fn proxy(mut self, proxy_url: &str) -> Self {
        match ProxyConfig::parse(proxy_url) {
            Ok(config) => self.proxy = Some(config),
            Err(e) => {
                tracing::warn!(url = %proxy_url, error = %e, "session.invalid_proxy_url");
            }
        }
        self
    }

    /// Set the proxy from a `ProxyConfig`.
    pub fn proxy_config(mut self, config: ProxyConfig) -> Self {
        self.proxy = Some(config);
        self
    }

    /// Set the maximum number of redirects to follow (default: 10).
    ///
    /// Equivalent to `redirect_policy(RedirectPolicy::Follow(n))`.
    /// Use `redirect_policy(RedirectPolicy::None)` to disable redirect following.
    pub fn max_redirects(mut self, n: u32) -> Self {
        self.redirect_policy = RedirectPolicy::Follow(n);
        self
    }

    /// Set the redirect policy for this session.
    ///
    /// - `RedirectPolicy::Follow(n)` — automatically follow up to `n` redirects (default: 10).
    /// - [`RedirectPolicy::None`] — do not follow redirects; return the 3xx response as-is.
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Set a retry policy for failed requests.
    ///
    /// When set, requests that fail with retryable errors or return retryable
    /// status codes will be automatically retried according to the policy.
    pub fn retry_policy(mut self, policy: impl RetryPolicy + 'static) -> Self {
        self.retry_policy = Some(Arc::new(policy));
        self
    }

    /// Add a middleware to the session-level middleware stack.
    ///
    /// Session middlewares are applied after client-level middlewares on the
    /// request path, and before them on the response path (onion model).
    ///
    /// # Example
    ///
    /// ```text
    /// let session = client.session()
    ///     .middleware(AuthInjector::new("Bearer xxx"))
    ///     .build();
    /// ```
    pub fn middleware(mut self, mw: impl crate::middleware::Middleware + 'static) -> Self {
        self.middlewares.push(Arc::new(mw));
        self
    }

    /// Set an ECHConfigList for this session (raw DER bytes).
    ///
    /// When set, all TLS connections from this session will use this
    /// ECHConfig, overriding the client-level `ech_config`.
    ///
    /// Typical use: store `ech_retry_configs` from a previous connection
    /// and apply them to the same session for subsequent requests.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let ech_config_from_dns = vec![];
    /// let session = client.session()
    ///     .ech_config(ech_config_from_dns)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.ech_config = Some(config_list);
        self
    }

    /// Override the session's runtime protocol behavior.
    pub fn protocol_policy(mut self, policy: ProtocolPolicy) -> Self {
        self.protocol_policy = Some(policy);
        self
    }

    /// Override only the session's high-level H2/H3 intent.
    pub fn http_intent(mut self, intent: HttpIntent) -> Self {
        let policy = self
            .protocol_policy
            .take()
            .unwrap_or_else(|| self.client.protocol_policy().clone())
            .with_intent(intent);
        self.protocol_policy = Some(policy);
        self
    }

    /// Force this session to only use HTTP/1.1.
    ///
    /// Even if the server negotiates HTTP/2 via ALPN, requests will be
    /// sent using HTTP/1.1. Useful when a target site has stricter
    /// fingerprint checks on H2 or when H1.1 is required for compatibility.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// let session = client.session()
    ///     .http1_only()
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn http1_only(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http1Only);
        self
    }

    /// Force this session to only use HTTP/2.
    ///
    /// If the server does not negotiate HTTP/2 via ALPN, the connection
    /// will fail. Useful when you know the target supports H2 and want
    /// consistent H2 fingerprinting.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// let session = client.session()
    ///     .http2_only()
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn http2_only(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http2Only);
        self
    }

    /// Force this session to only use HTTP/3.
    pub fn http3_only(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http3Only);
        self
    }

    /// Prefer HTTP/3 but fall back to TCP-based HTTP on QUIC failure.
    pub fn http3_with_fallback(mut self) -> Self {
        self.preferred_http_version = Some(PreferredHttpVersion::Http3WithFallback);
        self
    }

    /// Set how `Auto` mode chooses between TCP and QUIC when both are viable.
    ///
    /// The default is [`ProtocolSelectionPolicy::Deterministic`]. Use
    /// [`ProtocolSelectionPolicy::ChromeLike`] to mimic Chromium's
    /// "main TCP job + alternative QUIC job" racing model when H3 has already
    /// been discovered via Alt-Svc or HTTPS DNS records.
    pub fn protocol_selection_policy(mut self, policy: ProtocolSelectionPolicy) -> Self {
        self.protocol_selection_policy = Some(policy);
        self
    }

    /// Set tunables for [`ProtocolSelectionPolicy::ChromeLike`].
    pub fn chrome_like_protocol_config(mut self, config: ChromeLikeProtocolConfig) -> Self {
        self.chrome_like_protocol_config = Some(config);
        self
    }

    /// Set the default `Accept-Encoding` for all requests in this session.
    ///
    /// When set, the `Accept-Encoding` header will be automatically added
    /// to requests (unless overridden per-request). Response bodies will
    /// be decompressed accordingly.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// use lkrequest::AcceptEncoding;
    ///
    /// let session = client.session()
    ///     .default_accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn default_accept_encoding(mut self, encoding: AcceptEncoding) -> Self {
        self.default_accept_encoding = Some(encoding);
        self
    }

    /// Set the maximum connections for this session (overrides client-level).
    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections_override = Some(n);
        self
    }

    /// Set the idle connection timeout (default: 90 seconds).
    ///
    /// Connections that have been idle longer than this duration are
    /// automatically evicted from the pool on the next acquire/check.
    pub fn idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Set the header sending order template for this session.
    ///
    /// Overrides the client-level header_order for all requests in this session.
    pub fn header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.header_order = Some(names);
        }
        self
    }

    /// Set the header sending order from pre-parsed HeaderNames.
    pub fn header_order_from_names(mut self, order: Vec<http::header::HeaderName>) -> Self {
        if !order.is_empty() {
            self.header_order = Some(order);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order template for this session.
    ///
    /// Overrides the client-level `h3_header_order` for H3 requests only.
    pub fn h3_header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.h3_header_order = Some(names);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order from pre-parsed HeaderNames.
    pub fn h3_header_order_from_names(mut self, order: Vec<http::header::HeaderName>) -> Self {
        if !order.is_empty() {
            self.h3_header_order = Some(order);
        }
        self
    }

    /// Set the cookie sending order template for this session.
    pub fn cookie_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<Box<str>> = order.into_iter().map(|s| s.into()).collect();
        if !names.is_empty() {
            self.cookie_order = Some(names);
        }
        self
    }

    /// Choose how aggressively this session quarantines an origin after a
    /// QUIC handshake or H3 request failure.
    ///
    /// See [`BrokenQuicPolicy`] for the full menu — the most useful presets
    /// are [`BrokenQuicPolicy::Strict`] (default, Chrome-like persistence)
    /// and [`BrokenQuicPolicy::Resilient`] (recommended when running behind
    /// a transparent proxy such as mihomo / clash / sing-box, where 5-minute
    /// quarantine windows would silently keep H3 disabled long after the
    /// upstream actually recovered).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// use lkrequest::BrokenQuicPolicy;
    ///
    /// # let client = Client::builder().fingerprint(presets::chrome_146()).build();
    /// // Keep Chrome's H2 → alt-svc → H3 upgrade path, but recover from
    /// // transient QUIC failures within ~1s instead of being pinned to H2
    /// // for 5 minutes.
    /// let session = client
    ///     .session()
    ///     .broken_quic_policy(BrokenQuicPolicy::Resilient)
    ///     .build();
    /// ```
    pub fn broken_quic_policy(mut self, policy: BrokenQuicPolicy) -> Self {
        self.broken_quic_policy = Some(policy);
        self
    }

    /// Build the [`Session`].
    ///
    /// If no TLS fingerprint was set on the `Client`, Chrome 144 defaults
    /// are used (TLS + H2 + header order).
    pub fn build(self) -> Session {
        let SessionBuilder {
            client,
            proxy,
            redirect_policy,
            retry_policy,
            ech_config,
            middlewares,
            protocol_policy: protocol_policy_override,
            preferred_http_version,
            protocol_selection_policy,
            chrome_like_protocol_config,
            default_accept_encoding,
            max_connections_override,
            idle_timeout,
            header_order,
            h3_header_order,
            cookie_order,
            broken_quic_policy,
        } = self;

        let preferred_http_version = preferred_http_version.unwrap_or(PreferredHttpVersion::Auto);
        let protocol_selection_policy =
            protocol_selection_policy.unwrap_or(ProtocolSelectionPolicy::Deterministic);
        let chrome_like_protocol_config =
            chrome_like_protocol_config.unwrap_or_else(ChromeLikeProtocolConfig::default);
        let protocol_policy = protocol_policy_override.unwrap_or_else(|| {
            let mut policy = client.protocol_policy().clone();
            apply_legacy_protocol_policy_overrides(
                &mut policy,
                preferred_http_version,
                protocol_selection_policy,
                chrome_like_protocol_config,
            );
            policy
        });
        let max_conn = max_connections_override
            .unwrap_or(client.resource_limits().max_connections_per_session);
        let mut pool = ConnectionPool::with_max_total(max_conn);
        if let Some(idle_timeout) = idle_timeout {
            pool.idle_timeout = idle_timeout;
        }
        // Per-session fingerprint materialization. When the client carries a
        // synthetic randomization policy, each session draws its own identity
        // from a fresh OS seed and presents a distinct (capability-safe)
        // fingerprint; the transport machinery stays shared inside the derived
        // client. Real-preset clients pass through unchanged.
        #[cfg(feature = "synthetic-fp")]
        let (client, session_store) = materialize_session_fingerprint(client);
        #[cfg(not(feature = "synthetic-fp"))]
        let session_store = client.inner.session_store.clone();
        Session {
            inner: Arc::new(SessionInner {
                client,
                cookie_jar: ArcSwap::from_pointee(CookieStore::new()),
                pool: Mutex::new(pool),
                proxy,
                redirect_policy,
                session_store,
                retry_policy,
                ech_config,
                middlewares,
                protocol_policy,
                preferred_http_version,
                protocol_selection_policy,
                chrome_like_protocol_config,
                default_accept_encoding,
                header_order,
                h3_header_order,
                cookie_order,
                alt_svc_cache: AltSvcCache::new(),
                broken_quic_tracker: broken_quic_policy
                    .map(|policy| BrokenQuicTracker::with_config(policy.resolve()))
                    .unwrap_or_else(BrokenQuicTracker::new),
                #[cfg(feature = "quic-h3")]
                quic_in_flight: Mutex::new(std::collections::HashMap::new()),
            }),
        }
    }
}

/// Materialize a session's wire fingerprint from the client's randomization
/// policy, returning the (possibly re-fingerprinted) client and the ticket
/// store the session should use.
///
/// A synthetic session also gets its **own** PSK/ticket cache: resuming another
/// identity's ticket would betray that two distinct fingerprints are the same
/// caller, so synthetic sessions never share the client-level cache. Real-preset
/// sessions keep sharing it (matching browser PSK-caching behavior).
#[cfg(feature = "synthetic-fp")]
fn materialize_session_fingerprint(client: Client) -> (Client, Arc<InMemorySessionStore>) {
    use crate::randomize::{Layers, RandomizeMode};
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let mode = client.randomize().mode();
    let layers = match mode {
        RandomizeMode::Recombine(l) | RandomizeMode::Full(l) => l,
        // Off / ExtensionOrder: no per-session materialization.
        _ => {
            let store = client.inner.session_store.clone();
            return (client, store);
        }
    };

    let mut seed = [0u8; 32];
    // OS entropy. On the vanishingly rare RNG failure, fall through to the base
    // fingerprint rather than panicking inside session construction.
    if SystemRandom::new().fill(&mut seed).is_ok() {
        let id = if matches!(mode, RandomizeMode::Full(_)) {
            crate::randomize::resolve_full_identity(seed)
        } else {
            crate::randomize::resolve_recombine_identity(seed)
        };
        let client = client.with_synthesized_fingerprint(id, layers);
        // Only isolate the PSK/ticket cache when a crypto-bearing layer (TLS or
        // QUIC) is synthesized; an H2-only synthetic identity keeps the real
        // TLS/QUIC, so sharing the client cache stays consistent.
        let store = if layers.intersects(Layers::TLS | Layers::QUIC) {
            Arc::new(InMemorySessionStore::new())
        } else {
            client.inner.session_store.clone()
        };
        return (client, store);
    }
    let store = client.inner.session_store.clone();
    (client, store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> Client {
        Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build()
    }

    fn test_session() -> Session {
        test_client().session().build()
    }

    // ====================================================================
    // AcceptEncoding — browser encoding negotiation
    // ====================================================================

    #[test]
    fn session_builder_defaults_to_strict_broken_quic_policy() {
        let session = test_client().session().build();
        let entry = crate::Origin::https("example.com", 443);
        let tracker = session.broken_quic_tracker();
        tracker.mark_broken(&entry);
        assert!(
            tracker.is_broken(&entry),
            "default policy should be Strict — origin must stay quarantined"
        );
    }

    #[test]
    fn session_builder_resilient_policy_recovers_within_a_few_seconds() {
        use crate::alt_svc::BrokenQuicPolicy;
        use std::thread::sleep;
        use std::time::Duration;

        let session = test_client()
            .session()
            .broken_quic_policy(BrokenQuicPolicy::Resilient)
            .build();
        let origin = crate::Origin::https("example.com", 443);
        let tracker = session.broken_quic_tracker();
        tracker.mark_broken(&origin);
        assert!(
            tracker.is_broken(&origin),
            "Resilient still quarantines briefly — should be true immediately after mark_broken"
        );
        sleep(Duration::from_millis(1100));
        assert!(
            !tracker.is_broken(&origin),
            "Resilient policy must let the origin recover after ~1s"
        );
    }

    #[test]
    fn session_builder_disabled_policy_never_quarantines() {
        use crate::alt_svc::BrokenQuicPolicy;
        let session = test_client()
            .session()
            .broken_quic_policy(BrokenQuicPolicy::Disabled)
            .build();
        let origin = crate::Origin::https("example.com", 443);
        let tracker = session.broken_quic_tracker();
        tracker.mark_broken(&origin);
        assert!(
            !tracker.is_broken(&origin),
            "Disabled policy must report origin as healthy even after mark_broken"
        );
    }

    #[test]
    fn early_data_gate_matches_chrome_idempotency_rules() {
        assert!(can_send_early_data(
            &http::Method::GET,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::HEAD,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::OPTIONS,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::TRACE,
            Idempotency::Default
        ));
        assert!(!can_send_early_data(
            &http::Method::POST,
            Idempotency::Default
        ));
        assert!(can_send_early_data(
            &http::Method::POST,
            Idempotency::Idempotent
        ));
        assert!(!can_send_early_data(
            &http::Method::GET,
            Idempotency::NotIdempotent
        ));
    }

    #[test]
    fn gzip_only_header() {
        assert_eq!(AcceptEncoding::GZIP.to_header_value(), "gzip");
    }

    #[test]
    fn brotli_only_header() {
        assert_eq!(AcceptEncoding::BR.to_header_value(), "br");
    }

    #[test]
    fn chrome_default_advertises_all_encodings() {
        let hdr = AcceptEncoding::CHROME_DEFAULT.to_header_value();
        assert!(hdr.contains("gzip"));
        assert!(hdr.contains("br"));
        assert!(hdr.contains("deflate"));
        assert!(hdr.contains("zstd"));
    }

    #[test]
    fn safari_default_excludes_zstd() {
        let hdr = AcceptEncoding::SAFARI_DEFAULT.to_header_value();
        assert!(hdr.contains("gzip"));
        assert!(hdr.contains("br"));
        assert!(!hdr.contains("zstd"));
    }

    #[test]
    fn combining_two_encodings() {
        let hdr = (AcceptEncoding::GZIP | AcceptEncoding::ZSTD).to_header_value();
        assert!(hdr.contains("gzip"));
        assert!(hdr.contains("zstd"));
        assert!(!hdr.contains("br"));
    }

    // ====================================================================
    // Cookie jar — simulating a browser user
    // ====================================================================

    #[test]
    fn login_sets_session_cookie() {
        let session = test_session();
        session.set_cookie("https://app.example.com", "session_id", "abc123");

        assert_eq!(
            session.get_cookie("https://app.example.com", "session_id"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn cookies_scoped_by_domain() {
        let session = test_session();
        session.set_cookie("https://a.example.com", "token", "aaa");
        session.set_cookie("https://b.example.com", "token", "bbb");

        assert_eq!(
            session.get_cookie("https://a.example.com", "token"),
            Some("aaa".to_string())
        );
        assert_eq!(
            session.get_cookie("https://b.example.com", "token"),
            Some("bbb".to_string())
        );
    }

    #[test]
    fn same_name_different_paths() {
        let session = test_session();
        session.set_cookie_with_attrs(
            "https://example.com",
            "token",
            "root_val",
            Some("/"),
            None,
            false,
            false,
        );
        session.set_cookie_with_attrs(
            "https://example.com",
            "token",
            "api_val",
            Some("/api"),
            None,
            false,
            false,
        );

        let values = session.get_cookie_values("https://example.com/api/users", "token");
        assert!(values.len() >= 2);
        assert!(values.contains(&"api_val".to_string()));
        assert!(values.contains(&"root_val".to_string()));
    }

    #[test]
    fn set_cookie_raw_from_server_header() {
        let session = test_session();
        session.set_cookie_raw(
            "https://example.com",
            "tracking=xyz789; Path=/; Domain=example.com; Secure; HttpOnly",
        );
        assert_eq!(
            session.get_cookie("https://example.com", "tracking"),
            Some("xyz789".to_string())
        );
    }

    #[test]
    fn cookie_header_format() {
        let session = test_session();
        session.set_cookie("https://example.com", "a", "1");
        session.set_cookie("https://example.com", "b", "2");

        let header = session.cookie_header("https://example.com").unwrap();
        assert!(header.contains("a=1"));
        assert!(header.contains("b=2"));
        assert!(header.contains("; "));
    }

    #[test]
    fn no_cookies_returns_none() {
        let session = test_session();
        assert!(session.cookie_header("https://example.com").is_none());
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn logout_clears_all_cookies() {
        let session = test_session();
        session.set_cookie("https://example.com", "a", "1");
        session.set_cookie("https://example.com", "b", "2");
        assert!(!session.get_cookies("https://example.com").is_empty());

        session.clear_cookies();
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn remove_specific_cookie() {
        let session = test_session();
        session.set_cookie("https://example.com", "keep", "yes");
        session.set_cookie("https://example.com", "remove_me", "bye");

        session.remove_cookie("https://example.com", "remove_me");

        assert!(session.get_cookie("https://example.com", "keep").is_some());
        assert!(session
            .get_cookie("https://example.com", "remove_me")
            .is_none());
    }

    #[test]
    fn invalid_url_is_warned_and_ignored() {
        let session = test_session();
        session.set_cookie("not-a-url", "k", "v");
        assert!(session.get_cookies("not-a-url").is_empty());
        assert!(session.get_cookie("not-a-url", "k").is_none());
    }

    #[test]
    fn set_cookie_with_attrs_invalid_url_no_panic() {
        let session = test_session();
        session.set_cookie_with_attrs("not-a-url", "k", "v", Some("/"), None, false, false);
        assert!(session.get_cookies("not-a-url").is_empty());
    }

    #[test]
    fn set_cookie_raw_invalid_url_no_panic() {
        let session = test_session();
        session.set_cookie_raw("not-a-url", "k=v; Path=/");
        assert!(session.get_cookies("not-a-url").is_empty());
    }

    #[test]
    fn set_cookie_raw_invalid_header_no_panic() {
        let session = test_session();
        session.set_cookie_raw("https://example.com", "");
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn remove_cookie_invalid_url_no_panic() {
        let session = test_session();
        session.remove_cookie("not-a-url", "k");
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    #[test]
    fn cookie_with_secure_and_httponly_attrs() {
        let session = test_session();
        session.set_cookie_with_attrs(
            "https://secure.example.com",
            "secret",
            "val",
            Some("/"),
            Some("secure.example.com"),
            true,
            true,
        );
        assert_eq!(
            session.get_cookie("https://secure.example.com/path", "secret"),
            Some("val".to_string())
        );
    }

    // ====================================================================
    // SessionBuilder — configuring a session for different use cases
    // ====================================================================

    #[test]
    fn build_session_with_defaults() {
        let session = test_session();
        assert!(session.inner.proxy.is_none());
        assert_eq!(session.inner.redirect_policy, RedirectPolicy::default());
        assert!(session.inner.ech_config.is_none());
        assert_eq!(
            session.inner.preferred_http_version,
            PreferredHttpVersion::Auto
        );
        assert_eq!(
            session.inner.protocol_selection_policy,
            ProtocolSelectionPolicy::Deterministic
        );
        assert_eq!(
            session.inner.chrome_like_protocol_config,
            ChromeLikeProtocolConfig::default()
        );
        assert_eq!(
            session.protocol_policy(),
            &ProtocolPolicy::crawler_throughput()
        );
    }

    #[test]
    fn build_session_inherits_client_protocol_policy() {
        let client = Client::builder()
            .protocol_policy(ProtocolPolicy::h3_strict())
            .build();
        let session = client.session().build();
        assert_eq!(session.protocol_policy(), &ProtocolPolicy::h3_strict());
    }

    #[test]
    fn build_session_protocol_policy_overrides_client_default() {
        let client = Client::builder()
            .protocol_policy(ProtocolPolicy::crawler_throughput())
            .build();
        let session = client
            .session()
            .protocol_policy(ProtocolPolicy::chrome_standard())
            .build();
        assert_eq!(
            session.protocol_policy(),
            &ProtocolPolicy::chrome_standard()
        );
    }

    #[test]
    fn build_session_http_intent_override_normalizes_conflicting_axes() {
        let client = Client::builder()
            .protocol_policy(ProtocolPolicy::chrome_standard())
            .build();
        let session = client.session().http_intent(HttpIntent::H2Only).build();
        assert_eq!(session.protocol_policy().intent, HttpIntent::H2Only);
        assert_eq!(
            session.protocol_policy().fallback,
            FallbackPolicy::NoFallback
        );
        assert_eq!(
            session.protocol_policy().upgrade,
            crate::protocol::UpgradePolicy::Off
        );
    }

    #[test]
    fn build_session_for_scraping_with_proxy() {
        let client = test_client();
        let session = client
            .session()
            .proxy("http://proxy.example.com:8080")
            .max_redirects(3)
            .build();

        assert!(session.inner.proxy.is_some());
        assert_eq!(session.inner.redirect_policy, RedirectPolicy::Follow(3));
    }

    #[test]
    fn build_session_forced_http1() {
        let client = test_client();
        let session = client.session().http1_only().build();
        assert_eq!(
            session.inner.preferred_http_version,
            PreferredHttpVersion::Http1Only
        );
    }

    #[test]
    fn build_session_forced_http2() {
        let client = test_client();
        let session = client.session().http2_only().build();
        assert_eq!(
            session.inner.preferred_http_version,
            PreferredHttpVersion::Http2Only
        );
    }

    #[test]
    fn build_session_with_encoding_preference() {
        let client = test_client();
        let session = client
            .session()
            .default_accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
            .build();
        assert_eq!(
            session.inner.default_accept_encoding,
            Some(AcceptEncoding::GZIP | AcceptEncoding::BR)
        );
    }

    #[test]
    fn build_session_with_chrome_like_protocol_policy() {
        let client = test_client();
        let session = client
            .session()
            .protocol_selection_policy(ProtocolSelectionPolicy::ChromeLike)
            .build();
        assert_eq!(
            session.inner.protocol_selection_policy,
            ProtocolSelectionPolicy::ChromeLike
        );
    }

    #[test]
    fn build_session_with_custom_chrome_like_protocol_config() {
        let client = test_client();
        let config = ChromeLikeProtocolConfig {
            tcp_main_job_delay: std::time::Duration::from_secs(1),
            keep_quic_probe_after_tcp_win: false,
            keep_tcp_probe_after_quic_win: true,
        };
        let session = client.session().chrome_like_protocol_config(config).build();
        assert_eq!(session.inner.chrome_like_protocol_config, config);
    }

    #[test]
    fn build_session_with_ech_config() {
        let client = test_client();
        let ech_data = vec![0xFE, 0x0D, 0x00, 0x10];
        let session = client.session().ech_config(ech_data.clone()).build();
        assert_eq!(session.inner.ech_config, Some(ech_data));
    }

    #[test]
    fn build_session_with_custom_connection_limit() {
        let client = test_client();
        let session = client.session().max_connections(5).build();
        let lock = session.inner.pool.try_lock().unwrap();
        assert_eq!(lock.max_total, 5);
    }

    #[test]
    fn invalid_proxy_url_is_logged_but_not_fatal() {
        let client = test_client();
        let session = client.session().proxy("not-a-valid-proxy").build();
        assert!(session.inner.proxy.is_none());
    }

    #[test]
    fn session_is_clone_and_shares_state() {
        let session = test_session();
        session.set_cookie("https://example.com", "shared", "yes");

        let clone = session.clone();
        assert_eq!(
            clone.get_cookie("https://example.com", "shared"),
            Some("yes".to_string())
        );

        clone.set_cookie("https://example.com", "from_clone", "val");
        assert_eq!(
            session.get_cookie("https://example.com", "from_clone"),
            Some("val".to_string())
        );
    }

    #[test]
    fn client_accessible_from_session() {
        let session = test_session();
        let client = session.client();
        assert!(!client.tls_profile().cipher_suites.is_empty());
    }

    // ====================================================================
    // QUIC transport-parameter per-connection randomization (quic-h3)
    //
    // Wire-fidelity guards for the per-connection shuffle + GREASE
    // randomization that `establish_quic_connection` applies when
    // `shuffle_transport_parameters` is set. These run the real RNG-backed
    // functions offline (no network): structural invariants hold on every
    // iteration; the uniformity sanity check holds statistically with an
    // astronomically small false-failure probability. The offline
    // `fingerprint_regression` gate cannot see this path (it compares the
    // static profile), so these are its on-host counterpart.
    // ====================================================================
    #[cfg(feature = "quic-h3")]
    mod quic_tp_randomization {
        use super::*;

        /// Transport parameters Quinn encodes itself. An *extra* TP carrying one
        /// of these ids is rejected by `extra_transport_parameters` with
        /// `LocallyEncoded`, failing connection setup. Kept in sync with
        /// `deps/quinn/quinn-proto/src/config.rs::is_locally_encoded_transport_parameter`.
        const LOCALLY_ENCODED: &[u64] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x20, 0xb6, 0x2ab2, 0xff04de1a,
        ];

        fn vi(v: u64) -> quinn::VarInt {
            quinn::VarInt::from_u64(v).unwrap()
        }

        // version_information value from chrome_146_quic:
        // chosen(0x00000001) | available[GREASE(0x9a9aca7a), v1(0x00000001)].
        fn version_info_value() -> Vec<u8> {
            vec![
                0x00, 0x00, 0x00, 0x01, 0x9a, 0x9a, 0xca, 0x7a, 0x00, 0x00, 0x00, 0x01,
            ]
        }

        #[test]
        fn grease_id_is_reserved_pattern_8byte_and_never_locally_encoded() {
            // Boundary + adversarial inputs, including the value (5) that the old
            // `27 + 31*k` generator mapped to 0xb6, a Quinn-local TP.
            let samples = [
                0u32,
                1,
                2,
                5,
                31,
                1000,
                u32::MAX / 2,
                u32::MAX - 1,
                u32::MAX,
            ];
            for &r in &samples {
                let id = grease_reserved_tp_id(r).into_inner();
                assert_eq!(
                    (id - 27) % 31,
                    0,
                    "id {id:#x} must be reserved-pattern 31*N+27"
                );
                assert!(
                    id >= (1 << 30),
                    "id {id:#x} must encode as an 8-byte varint (>= 2^30)"
                );
                assert!(
                    id < (1u64 << 62),
                    "id {id:#x} must fit a QUIC varint (< 2^62)"
                );
                assert!(
                    !LOCALLY_ENCODED.contains(&id),
                    "id {id:#x} collides with a Quinn-local TP (would be rejected as LocallyEncoded)"
                );
            }
        }

        #[test]
        fn grease_id_old_collision_input_is_now_safe() {
            // Regression: `27 + 31*5 == 0xb6` (a Quinn-local TP) in the old
            // generator. The remapped generator must never produce it.
            assert_ne!(grease_reserved_tp_id(5).into_inner(), 0xb6);
        }

        #[test]
        fn randomize_rewrites_grease_id_in_extra_and_order_consistently() {
            let grease = vi(0x17af394a4ef8da0a); // chrome_146_quic captured reserved GREASE
            for _ in 0..2_000 {
                let mut extra = vec![
                    (vi(0x11), version_info_value()),
                    (grease, Vec::new()),
                    (vi(0x3127), vec![0x80, 0x09, 0xdf, 0x94]), // google_initial_rtt
                ];
                let mut order = vec![vi(0x03), vi(0x11), grease, vi(0x3127), vi(0x07)];
                randomize_quic_grease_params(&mut extra, &mut order);

                let new_id = extra[1].0;
                assert_ne!(new_id, grease, "GREASE id must be rerandomized");
                assert!(
                    !LOCALLY_ENCODED.contains(&new_id.into_inner()),
                    "rerandomized GREASE id must never be Quinn-local"
                );
                // The order list's reference must be patched to the new id, with
                // no stale reference left (else the wire order is inconsistent).
                assert!(
                    order.contains(&new_id),
                    "order must reference the new GREASE id"
                );
                assert!(
                    !order.contains(&grease),
                    "order must drop the stale GREASE id"
                );
                // GREASE value is rewritten to a non-empty, bounded-length blob.
                assert!(
                    (1..=16).contains(&extra[1].1.len()),
                    "GREASE value length {} out of expected 1..=16 \
                     (revisit if the capture shows Chrome sends an empty value)",
                    extra[1].1.len()
                );
                // google_initial_rtt (0x3127) is NOT a GREASE param — untouched.
                assert_eq!(extra[2].0, vi(0x3127));
                assert_eq!(extra[2].1, vec![0x80, 0x09, 0xdf, 0x94]);
            }
        }

        #[test]
        fn randomize_only_touches_grease_version_slot_of_version_information() {
            for _ in 0..2_000 {
                let mut extra = vec![(vi(0x11), version_info_value())];
                let mut order = vec![vi(0x11)];
                randomize_quic_grease_params(&mut extra, &mut order);
                let v = &extra[0].1;
                assert_eq!(v.len(), 12, "length unchanged");
                assert_eq!(
                    &v[0..4],
                    &[0, 0, 0, 1],
                    "chosen version (bytes 0..4) unchanged"
                );
                assert_eq!(
                    &v[8..12],
                    &[0, 0, 0, 1],
                    "trailing real version (bytes 8..) unchanged"
                );
                for (i, b) in v[4..8].iter().enumerate() {
                    assert_eq!(
                        b & 0x0f,
                        0x0a,
                        "GREASE version byte {i} must match 0x?a pattern"
                    );
                }
            }
        }

        #[test]
        fn shuffle_is_always_a_permutation() {
            let base: Vec<quinn::VarInt> = [0x03u64, 0x11, 0x09, 0x08, 0x20, 0x01, 0x06]
                .iter()
                .map(|&v| vi(v))
                .collect();
            for _ in 0..5_000 {
                let mut order = base.clone();
                shuffle_transport_parameter_order(&mut order);
                let mut got: Vec<u64> = order.iter().map(|v| v.into_inner()).collect();
                let mut want: Vec<u64> = base.iter().map(|v| v.into_inner()).collect();
                got.sort_unstable();
                want.sort_unstable();
                assert_eq!(got, want, "shuffle must preserve the exact multiset of ids");
            }
        }

        #[test]
        fn shuffle_is_identity_for_trivial_lengths() {
            let mut empty: Vec<quinn::VarInt> = vec![];
            shuffle_transport_parameter_order(&mut empty);
            assert!(empty.is_empty());

            let mut one = vec![vi(0x03)];
            shuffle_transport_parameter_order(&mut one);
            assert_eq!(one, vec![vi(0x03)]);
        }

        #[test]
        fn shuffle_reaches_every_position_for_every_element() {
            // Uniformity sanity: over many runs each id must reach each index at
            // least once. A Fisher-Yates with a loop-bound off-by-one would pin
            // an element, leaving some (id, position) cell at zero. With a
            // uniform permutation P(cell hit per run) = 1/n, so P(missed over
            // 20k runs) = (3/4)^20000 ≈ 0 for n = 4 — not flaky.
            let ids = [0x03u64, 0x11, 0x09, 0x08];
            let n = ids.len();
            let mut seen = vec![vec![false; n]; n]; // seen[id_index][position]
            for _ in 0..20_000 {
                let mut order: Vec<quinn::VarInt> = ids.iter().map(|&v| vi(v)).collect();
                shuffle_transport_parameter_order(&mut order);
                for (pos, v) in order.iter().enumerate() {
                    let id_idx = ids.iter().position(|&x| x == v.into_inner()).unwrap();
                    seen[id_idx][pos] = true;
                }
            }
            for (id_idx, row) in seen.iter().enumerate() {
                for (pos, &hit) in row.iter().enumerate() {
                    assert!(hit, "id {:#x} never reached position {pos}", ids[id_idx]);
                }
            }
        }
    }

    /// Normal use (no randomization): a session shares the client's exact
    /// fingerprint `Arc` and ticket cache. Guards the `Fingerprint`/
    /// `ClientInner` split against changing default behavior.
    #[test]
    fn default_session_shares_client_fingerprint_and_cache() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build();
        let session = client.session().build();
        assert!(Arc::ptr_eq(
            &session.inner.client.fingerprint,
            &client.fingerprint
        ));
        assert!(Arc::ptr_eq(
            &session.inner.session_store,
            &client.inner.session_store
        ));
    }

    /// Per-session synthetic-fingerprint materialization (Tier 3a).
    #[cfg(feature = "synthetic-fp")]
    mod synthetic_fp {
        use super::*;
        use crate::randomize::{Layers, Randomize};

        fn recombine_client() -> Client {
            Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::recombine())
                .build()
        }

        /// A session from a Recombine client materializes a synthesized identity
        /// that is structurally valid on both layers (TLS + H2).
        #[test]
        fn recombine_session_identity_is_valid() {
            let client = recombine_client();
            let session = client.session().build();
            let sc = &session.inner.client;
            assert!(
                lktls::profile::synthesis::validate(sc.tls_profile()).is_ok(),
                "synthesized TLS invalid"
            );
            assert!(
                lkh2::synthesis::validate(sc.h2_profile()).is_ok(),
                "synthesized H2 invalid"
            );
        }

        /// Each session draws its own per-session identity: across many sessions
        /// from one client the TLS fingerprint actually varies.
        #[test]
        fn recombine_sessions_have_distinct_identities() {
            let client = recombine_client();
            let mut sigs = std::collections::HashSet::new();
            for _ in 0..30 {
                let session = client.session().build();
                sigs.insert(session.inner.client.tls_profile().cipher_suites.clone());
            }
            assert!(sigs.len() > 1, "sessions not varied: {}", sigs.len());
        }

        /// A synthetic session must not share the client-level PSK/ticket cache:
        /// resuming another identity's ticket would link two fingerprints.
        #[test]
        fn recombine_session_isolates_psk_cache() {
            let client = recombine_client();
            let session = client.session().build();
            assert!(
                !Arc::ptr_eq(&session.inner.session_store, &client.inner.session_store),
                "synthetic session shared the client ticket cache"
            );
            // Its fingerprint is also a fresh Arc, not the base client's.
            assert!(!Arc::ptr_eq(
                &session.inner.client.fingerprint,
                &client.fingerprint
            ));
        }

        /// `Layers::TLS` synthesizes only TLS — H2 stays byte-identical to the
        /// real base preset, and the PSK cache is isolated (TLS is crypto).
        #[test]
        fn recombine_tls_only_keeps_real_h2() {
            let base_h2 = serde_json::to_string(
                Client::builder()
                    .fingerprint(lktls::profile::presets::chrome_144())
                    .build()
                    .h2_profile(),
            )
            .unwrap();
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::recombine_layers(Layers::TLS))
                .build();
            for _ in 0..20 {
                let s = client.session().build();
                let sc = &s.inner.client;
                assert_eq!(
                    serde_json::to_string(sc.h2_profile()).unwrap(),
                    base_h2,
                    "H2 must be untouched when only TLS is synthesized"
                );
                assert!(lktls::profile::synthesis::validate(sc.tls_profile()).is_ok());
                assert!(
                    !Arc::ptr_eq(&s.inner.session_store, &client.inner.session_store),
                    "synthesizing TLS must isolate the PSK cache"
                );
            }
        }

        /// `Layers::H2` synthesizes only H2 — TLS stays the real preset and the
        /// PSK cache is shared (no crypto-bearing layer synthesized).
        #[test]
        fn recombine_h2_only_keeps_real_tls_and_shares_cache() {
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::recombine_layers(Layers::H2))
                .build();
            let s = client.session().build();
            let sc = &s.inner.client;
            assert_eq!(
                sc.tls_profile().name,
                "Chrome 144",
                "TLS must stay the real preset when only H2 is synthesized"
            );
            assert!(lkh2::synthesis::validate(sc.h2_profile()).is_ok());
            assert!(
                Arc::ptr_eq(&s.inner.session_store, &client.inner.session_store),
                "H2-only synthesis must share the client PSK cache"
            );
        }

        /// Tier 3b `full_layers(Layers::H2)` perturbs H2 SETTINGS values to novel
        /// numbers — across sessions the value space is far larger than the
        /// handful of fixed values the real presets carry (which is what
        /// `recombine` would reproduce).
        #[test]
        fn full_perturbs_h2_values_per_session() {
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .randomize(Randomize::full_layers(Layers::H2))
                .build();
            let mut values = std::collections::HashSet::new();
            for _ in 0..50 {
                let s = client.session().build();
                assert!(lkh2::synthesis::validate(s.inner.client.h2_profile()).is_ok());
                for st in &s.inner.client.h2_profile().settings {
                    values.insert((st.id.as_u16(), st.value));
                }
            }
            assert!(
                values.len() > 30,
                "Full did not perturb H2 values: {}",
                values.len()
            );
        }

        /// A QUIC-enabled Recombine client materializes a synthesized QUIC layer
        /// per session (no layer left constant), valid and varied across
        /// sessions. The QUIC-TLS falls back to the synthesized TLS.
        #[cfg(feature = "quic-h3")]
        #[test]
        fn recombine_session_synthesizes_quic_layer() {
            let client = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .quic_profile(lkh3::chrome_146_quic())
                .randomize(Randomize::recombine())
                .build();
            let mut sigs = std::collections::HashSet::new();
            for _ in 0..30 {
                let session = client.session().build();
                let sc = &session.inner.client;
                let q = sc.quic_profile().expect("quic stays enabled");
                assert!(lkh3::synthesis::validate(q).is_ok(), "QUIC invalid");
                // QUIC-TLS reuses the synthesized TLS (no separate profile).
                assert!(sc.quic_tls_profile().is_none());
                sigs.insert((
                    q.h3.settings.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
                    q.h3.pseudo_header_order_token(),
                ));
            }
            assert!(
                sigs.len() > 1,
                "QUIC not varied per session: {}",
                sigs.len()
            );
        }
    }
}
