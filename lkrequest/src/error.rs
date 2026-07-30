//! Unified error types for lkrequest.
//!
//! This module provides:
//! - [`enum@Error`] — the top-level error enum covering TLS, HTTP, proxy, timeout, and more.
//! - [`ConnectionError`] — error with [`ConnectionPhase`] information for precise diagnostics.
//! - [`ProxyError`] / [`ProxyErrorKind`] — structured proxy failure details.
//!
//! ## Error Handling Patterns
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! # use lkrequest::Client;
//! # use lktls::profile::presets;
//! # let client = Client::builder().fingerprint(presets::chrome_131()).build();
//! # let session = client.session().build();
//! match session.get("https://example.com").send().await {
//!     Ok(resp) => println!("OK: {}", resp.status()),
//!     Err(e) if e.is_timeout() => println!("Timed out at {:?}", e.phase()),
//!     Err(e) if e.is_tls_handshake() => println!("TLS error: {e}"),
//!     Err(e) if e.is_retryable() => println!("Retryable: {e}"),
//!     Err(e) => println!("Fatal: {e}"),
//! }
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::time::Duration;

use http::StatusCode;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Connection phase diagnostics
// ---------------------------------------------------------------------------

/// The phase of the connection lifecycle where an error occurred.
///
/// This allows callers to pinpoint exactly which step failed in the
/// DNS -> TCP -> Proxy -> TLS -> H2 -> HTTP pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionPhase {
    /// DNS resolution.
    DnsResolution,
    /// TCP connect (SYN / SYN-ACK).
    TcpConnect,
    /// Proxy tunnel establishment (HTTP CONNECT / SOCKS5).
    ProxyTunnel,
    /// TLS handshake.
    TlsHandshake,
    /// HTTP/2 connection negotiation (SETTINGS exchange).
    H2Negotiation,
    /// HTTP/1.1 → HTTP/2 cleartext upgrade (RFC 7540 §3.2).
    H2cUpgrade,
    /// QUIC transport handshake.
    QuicHandshake,
    /// HTTP/3 connection negotiation.
    H3Negotiation,
    /// Fallback from QUIC/H3 to TCP-based HTTP.
    QuicFallback,
    /// HTTP request / response cycle.
    HttpRequest,
}

impl fmt::Display for ConnectionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionPhase::DnsResolution => write!(f, "DNS resolution"),
            ConnectionPhase::TcpConnect => write!(f, "TCP connect"),
            ConnectionPhase::ProxyTunnel => write!(f, "proxy tunnel"),
            ConnectionPhase::TlsHandshake => write!(f, "TLS handshake"),
            ConnectionPhase::H2Negotiation => write!(f, "H2 negotiation"),
            ConnectionPhase::H2cUpgrade => write!(f, "h2c upgrade"),
            ConnectionPhase::QuicHandshake => write!(f, "QUIC handshake"),
            ConnectionPhase::H3Negotiation => write!(f, "H3 negotiation"),
            ConnectionPhase::QuicFallback => write!(f, "QUIC fallback"),
            ConnectionPhase::HttpRequest => write!(f, "HTTP request"),
        }
    }
}

/// Machine-readable reason a previously usable connection can no longer carry
/// a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionClosedKind {
    /// Peer or transport reset the connection.
    Reset,
    /// End-of-file / empty response while a response was still expected.
    Eof,
    /// HTTP/2 or HTTP/3 GOAWAY told the client to stop using the connection.
    Goaway,
    /// HTTP/2 refused the stream and the request can be retried elsewhere.
    RefusedStream,
    /// Local write failed because the connection was already closed.
    BrokenPipe,
    /// The socket / channel is no longer connected.
    NotConnected,
    /// Internal request/response channel closed.
    ChannelClosed,
    /// Closed state is known, but no narrower category is available.
    Generic,
}

impl fmt::Display for ConnectionClosedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reset => write!(f, "reset"),
            Self::Eof => write!(f, "eof"),
            Self::Goaway => write!(f, "goaway"),
            Self::RefusedStream => write!(f, "refused stream"),
            Self::BrokenPipe => write!(f, "broken pipe"),
            Self::NotConnected => write!(f, "not connected"),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::Generic => write!(f, "closed"),
        }
    }
}

/// QUIC lifecycle phase where a transport error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicPhase {
    /// Connection establishment before application data can be sent.
    Handshake,
    /// Request or stream work after QUIC is established.
    Established,
    /// Connection migration / path validation work.
    Migration,
}

impl fmt::Display for QuicPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake => write!(f, "handshake"),
            Self::Established => write!(f, "established"),
            Self::Migration => write!(f, "migration"),
        }
    }
}

/// Structured QUIC transport error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicError {
    /// QUIC lifecycle phase where the error occurred.
    pub phase: QuicPhase,
    /// Human-readable description.
    pub message: String,
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} phase failed: {}", self.phase, self.message)
    }
}

impl std::error::Error for QuicError {}

/// A connection error with phase information.
///
/// Wraps an underlying error with the specific phase in which it occurred,
/// enabling callers to distinguish between e.g. a DNS timeout and a TLS
/// handshake timeout.
#[derive(Debug)]
pub struct ConnectionError {
    /// Which phase failed.
    pub phase: ConnectionPhase,
    /// Human-readable description of what went wrong.
    pub message: String,
    /// The underlying error, if any.
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: {}", self.phase, self.message)
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// ---------------------------------------------------------------------------
// Proxy error details
// ---------------------------------------------------------------------------

/// Structured proxy error with a machine-readable kind.
#[derive(Debug)]
pub struct ProxyError {
    /// What kind of proxy failure occurred.
    pub kind: ProxyErrorKind,
    /// Human-readable description.
    pub message: String,
    /// The underlying I/O or protocol error, if any.
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// The category of proxy failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyErrorKind {
    /// TCP connection to the proxy server failed.
    TcpConnectFailed,
    /// Proxy requires authentication but no credentials were provided.
    AuthenticationRequired,
    /// Proxy rejected the provided credentials.
    AuthenticationFailed,
    /// Proxy refused to establish the tunnel (HTTP CONNECT returned non-200).
    TunnelRefused {
        /// The HTTP status code from the proxy's CONNECT response.
        status_code: u16,
    },
    /// SOCKS5 protocol-level error.
    Socks5Error {
        /// SOCKS5 reply code.
        code: u8,
    },
    /// A protocol-level error (malformed response, version mismatch, etc.).
    ProtocolError,
    /// Sending data to the proxy failed.
    IoError,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl ProxyError {
    /// Returns `true` if this is an authentication-related failure.
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self.kind,
            ProxyErrorKind::AuthenticationRequired | ProxyErrorKind::AuthenticationFailed
        )
    }
}

// ---------------------------------------------------------------------------
// Top-level Error enum
// ---------------------------------------------------------------------------

/// Top-level error type for all lkrequest operations.
///
/// Marked `#[non_exhaustive]` so new variants (e.g. finer-grained transport
/// failures) can be added without breaking `match` blocks in downstream code.
/// Add a `_` arm when pattern-matching.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An error from the TLS engine.
    #[error("TLS error: {0}")]
    Tls(#[from] lktls::error::TlsError),

    /// An HTTP protocol error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// A response body processing error.
    #[error("response body error: {0}")]
    Body(String),

    /// An HTTP/2 protocol error.
    #[error("H2 error: {0}")]
    H2(String),

    /// A pooled connection was closed, reset, or refused before the request
    /// completed.
    #[error("connection closed during {phase}: {kind}: {message}")]
    ConnectionClosed {
        /// Phase where the closed connection was observed.
        phase: ConnectionPhase,
        /// Machine-readable closed reason.
        kind: ConnectionClosedKind,
        /// Human-readable details.
        message: String,
    },

    /// A QUIC transport error that is not specifically tied to a handshake.
    ///
    /// Legacy string-only QUIC transport error.
    ///
    /// Internal code should prefer [`Error::QuicTransport`] so the lifecycle
    /// phase is machine-readable.
    #[error("QUIC error: {0}")]
    Quic(String),

    /// Structured QUIC transport error with lifecycle phase.
    #[error("QUIC error: {0}")]
    QuicTransport(Box<QuicError>),

    /// A QUIC handshake / connect-time failure.
    ///
    /// This is the exact class of error that the `http3_with_fallback`
    /// session mode is allowed to treat as "QUIC is broken, fall back to H2"
    /// and that the broken-QUIC tracker should record. Errors raised *after*
    /// the handshake completes MUST NOT use this variant — otherwise a
    /// transient request-level hiccup would force an origin into long
    /// H2-only cooldown.
    #[error("QUIC handshake failed: {0}")]
    QuicHandshake(String),

    /// An HTTP/3 protocol error that is not tied to a single in-flight request.
    ///
    /// Used for control-stream / SETTINGS / GOAWAY issues. Per-request
    /// failures should use [`Error::Http3Request`] instead.
    #[error("H3 error: {0}")]
    H3(String),

    /// An HTTP/3 request-level failure (after the QUIC handshake succeeded).
    ///
    /// This includes stream errors, header decode errors, and body transport
    /// errors. These MUST NOT trigger H2 fallback — the QUIC path is fine,
    /// the request itself just didn't complete.
    #[error("H3 request failed: {0}")]
    Http3Request(String),

    /// A network / I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A proxy connection error (structured).
    #[error("proxy error: {0}")]
    Proxy(Box<ProxyError>),

    /// A connection error with phase information.
    ///
    /// Indicates which step in the connection pipeline (DNS, TCP, TLS, etc.)
    /// failed, making diagnostics easier.
    #[error("{0}")]
    Connection(Box<ConnectionError>),

    /// A timeout was reached.
    ///
    /// When the `phase` field is present, it tells you *which* timeout
    /// fired (DNS, TCP, TLS, TTFB, or total).
    #[error("timeout: {message}")]
    Timeout {
        /// Human-readable description of the timeout.
        message: String,
        /// The phase that timed out, if applicable.
        phase: Option<ConnectionPhase>,
        /// The timeout duration that was exceeded.
        duration: Option<Duration>,
    },

    /// Redirect limit exceeded.
    #[error("too many redirects (limit: {0})")]
    TooManyRedirects(u32),

    /// The session pool is exhausted or shutting down.
    #[error("session pool error: {0}")]
    Pool(String),

    /// An invalid configuration was provided.
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// URL parsing error.
    #[error("invalid URL: {0}")]
    UrlParse(String),

    /// Resource limit exceeded (body too large, too many headers, etc.).
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// HTTP status code error (4xx or 5xx).
    ///
    /// Returned by [`crate::response::Response::error_for_status()`] when the response has
    /// a client error (4xx) or server error (5xx) status code.
    #[error("HTTP status error {status} for url ({url})")]
    Status {
        /// The HTTP status code.
        status: StatusCode,
        /// The URL that returned this status.
        url: String,
    },
}

impl Error {
    /// Whether this error is potentially transient and the request could succeed on retry.
    ///
    /// Returns `true` for:
    /// - `Timeout` — transient network issues
    /// - `Io` — connection resets, refused connections, etc.
    /// - `Proxy` — proxy failures (transient)
    /// - `Tls` — handshake failures (may succeed with different proxy or timing)
    /// - `H2` — HTTP/2 protocol errors (connection-level)
    /// - `Connection` — connection phase failures (transient)
    /// - `Status` with 5xx — server errors are often transient
    ///
    /// Returns `false` for:
    /// - `InvalidConfig` — configuration error, won't fix itself
    /// - `UrlParse` — malformed URL
    /// - `TooManyRedirects` — logic error
    /// - `Http` — usually indicates a bug in request construction
    /// - `Body` — response body decoding failed and retrying the same
    ///   response would not change the bytes
    /// - `Status` with 4xx — client errors won't fix themselves
    /// - `ResourceLimitExceeded` — won't change on retry
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Timeout { .. }
                | Error::Io(_)
                | Error::Proxy(_)
                | Error::Tls(_)
                | Error::H2(_)
                | Error::ConnectionClosed { .. }
                | Error::Quic(_)
                | Error::QuicTransport(_)
                | Error::QuicHandshake(_)
                | Error::H3(_)
                | Error::Http3Request(_)
                | Error::Connection(_)
        ) || matches!(self, Error::Status { status, .. } if status.is_server_error())
    }

    /// `true` if this error proves the request was **not processed** by the
    /// origin server, so re-sending it cannot duplicate a side effect — even
    /// for a non-idempotent method such as `POST`/`PUT`/`PATCH`/`DELETE`.
    ///
    /// This is a strict subset of [`Self::is_retryable`]. It covers:
    /// - failures during connection establishment (DNS/TCP/proxy/TLS/QUIC
    ///   handshake), where the request bytes were never written; and
    /// - HTTP/2 `REFUSED_STREAM`, where the server explicitly declined the
    ///   stream before processing it.
    ///
    /// Ambiguous post-transmission failures — a response timeout, a mid-stream
    /// reset, a GOAWAY after the stream opened, or a 5xx status — are
    /// deliberately excluded: the server may already have applied the request,
    /// so those are only retried for idempotent/safe requests. The retry
    /// pipeline combines this with the request's method/idempotency via
    /// [`crate::retry::retry_is_replay_safe`].
    pub fn is_safe_to_replay(&self) -> bool {
        match self {
            // Connection establishment failed before the request was sent.
            Error::Tls(_) | Error::Proxy(_) | Error::QuicHandshake(_) => true,
            Error::QuicTransport(e) => e.phase == QuicPhase::Handshake,
            Error::Connection(c) => !matches!(c.phase, ConnectionPhase::HttpRequest),
            // The server refused the stream before processing the request.
            Error::ConnectionClosed { kind, .. } => {
                matches!(kind, ConnectionClosedKind::RefusedStream)
            }
            _ => false,
        }
    }

    /// `true` if the error is a QUIC-handshake / connect-time failure that
    /// justifies marking the origin as broken-QUIC and falling back to H2.
    ///
    /// This is intentionally narrow: post-handshake errors do NOT qualify —
    /// if an H3 request fails after the QUIC handshake succeeded, the path
    /// is fine and fallback would just mask a request-level bug.
    pub fn is_quic_handshake_failure(&self) -> bool {
        match self {
            Error::QuicHandshake(_) => true,
            Error::QuicTransport(err) => err.phase == QuicPhase::Handshake,
            // TLS failures over QUIC surface as Tls; the caller only treats
            // them as handshake failures if they happen on the QUIC path,
            // which is the context where this classifier is consulted.
            Error::Tls(_) => true,
            Error::Connection(err) => matches!(
                err.phase,
                ConnectionPhase::DnsResolution
                    | ConnectionPhase::TcpConnect
                    | ConnectionPhase::TlsHandshake
                    | ConnectionPhase::ProxyTunnel
            ),
            _ => false,
        }
    }

    /// `true` if the error happened after a QUIC connection was established —
    /// i.e. a per-request or per-stream failure that should NOT trigger H2
    /// fallback or broken-QUIC tracking.
    pub fn is_h3_request_failure(&self) -> bool {
        matches!(self, Error::Http3Request(_))
    }

    /// Returns the QUIC lifecycle phase, if this error is QUIC-specific.
    pub fn quic_phase(&self) -> Option<QuicPhase> {
        match self {
            Error::QuicHandshake(_) => Some(QuicPhase::Handshake),
            Error::Quic(_) => None,
            Error::QuicTransport(err) => Some(err.phase),
            _ => None,
        }
    }

    /// Returns `true` if this is a `Status` error.
    pub fn is_status(&self) -> bool {
        matches!(self, Error::Status { .. })
    }

    /// Returns `true` if this is a `Timeout` error.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout { .. })
    }

    /// Returns `true` if this error occurred during DNS resolution.
    pub fn is_dns(&self) -> bool {
        self.phase() == Some(ConnectionPhase::DnsResolution)
    }

    /// Returns `true` if this error occurred during TCP connect.
    pub fn is_tcp(&self) -> bool {
        self.phase() == Some(ConnectionPhase::TcpConnect)
    }

    /// Returns `true` if this error occurred during TLS handshake.
    pub fn is_tls_handshake(&self) -> bool {
        self.phase() == Some(ConnectionPhase::TlsHandshake)
    }

    /// Returns `true` if this error occurred during proxy tunnel establishment.
    pub fn is_proxy_tunnel(&self) -> bool {
        self.phase() == Some(ConnectionPhase::ProxyTunnel)
    }

    /// Returns the connection phase where the error occurred, if applicable.
    pub fn phase(&self) -> Option<ConnectionPhase> {
        match self {
            Error::Connection(ce) => Some(ce.phase),
            Error::Timeout { phase, .. } => *phase,
            Error::Proxy(_) => Some(ConnectionPhase::ProxyTunnel),
            Error::Tls(_) => Some(ConnectionPhase::TlsHandshake),
            Error::Quic(_) => Some(ConnectionPhase::QuicHandshake),
            Error::QuicHandshake(_) => Some(ConnectionPhase::QuicHandshake),
            Error::QuicTransport(err) => Some(match err.phase {
                QuicPhase::Handshake => ConnectionPhase::QuicHandshake,
                QuicPhase::Established => ConnectionPhase::HttpRequest,
                QuicPhase::Migration => ConnectionPhase::QuicFallback,
            }),
            Error::H3(_) => Some(ConnectionPhase::H3Negotiation),
            Error::ConnectionClosed { phase, .. } => Some(*phase),
            _ => None,
        }
    }

    /// Returns the status code if this is a `Status` error.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Error::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns the TLS alert if this error originated from a TLS alert.
    pub fn as_tls_alert(&self) -> Option<&lktls::error::TlsAlert> {
        match self {
            Error::Tls(tls_err) => tls_err.as_alert(),
            _ => None,
        }
    }

    /// Returns the proxy error details if this is a proxy error.
    pub fn as_proxy_error(&self) -> Option<&ProxyError> {
        match self {
            Error::Proxy(pe) => Some(pe),
            _ => None,
        }
    }

    /// Returns `true` if this error indicates a connection that was closed,
    /// reset, or aborted by the peer — i.e. the kind of error that can happen
    /// on a **reused** (pooled) connection and should be retried on a fresh one.
    ///
    /// Modelled after Chromium's `GetRetryReasonForIOError` which covers
    /// `ERR_CONNECTION_RESET`, `ERR_CONNECTION_CLOSED`, `ERR_CONNECTION_ABORTED`,
    /// `ERR_SOCKET_NOT_CONNECTED`, `ERR_EMPTY_RESPONSE`,
    /// `ERR_HTTP2_SERVER_REFUSED_STREAM`, etc.
    ///
    /// Also covers H2 `stream reset` (RST_STREAM) which commonly occurs
    /// when a server closes an idle connection before the client's pool
    /// eviction timeout.
    pub(crate) fn is_connection_closed(&self) -> bool {
        match self {
            Error::ConnectionClosed { .. } => true,
            Error::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ),
            Error::Http(msg)
            | Error::H2(msg)
            | Error::Quic(msg)
            | Error::QuicHandshake(msg)
            | Error::H3(msg)
            | Error::Http3Request(msg) => classify_connection_closed_message(msg).is_some(),
            Error::QuicTransport(err) => classify_connection_closed_message(&err.message).is_some(),
            _ => false,
        }
    }

    /// Returns the typed closed-connection category, if this error carries
    /// one or can be classified from a legacy string-only variant.
    pub fn connection_closed_kind(&self) -> Option<ConnectionClosedKind> {
        match self {
            Error::ConnectionClosed { kind, .. } => Some(*kind),
            Error::Io(e) => match e.kind() {
                std::io::ErrorKind::ConnectionReset => Some(ConnectionClosedKind::Reset),
                std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::UnexpectedEof => {
                    Some(ConnectionClosedKind::Eof)
                }
                std::io::ErrorKind::BrokenPipe => Some(ConnectionClosedKind::BrokenPipe),
                std::io::ErrorKind::NotConnected => Some(ConnectionClosedKind::NotConnected),
                _ => None,
            },
            Error::Http(msg)
            | Error::H2(msg)
            | Error::Quic(msg)
            | Error::QuicHandshake(msg)
            | Error::H3(msg)
            | Error::Http3Request(msg) => classify_connection_closed_message(msg),
            Error::QuicTransport(err) => classify_connection_closed_message(&err.message),
            _ => None,
        }
    }

    /// Helper to create a timeout error with phase and duration info.
    pub(crate) fn timeout(
        message: impl Into<String>,
        phase: Option<ConnectionPhase>,
        duration: Option<Duration>,
    ) -> Self {
        Error::Timeout {
            message: message.into(),
            phase,
            duration,
        }
    }

    /// Helper to create a connection error.
    pub(crate) fn connection(
        phase: ConnectionPhase,
        message: impl Into<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Error::Connection(Box::new(ConnectionError {
            phase,
            message: message.into(),
            source,
        }))
    }

    /// Helper to create a typed closed-connection error.
    pub(crate) fn connection_closed(
        phase: ConnectionPhase,
        kind: ConnectionClosedKind,
        message: impl Into<String>,
    ) -> Self {
        Error::ConnectionClosed {
            phase,
            kind,
            message: message.into(),
        }
    }

    /// Helper for adapters that still receive string-only transport errors.
    pub(crate) fn h2_or_connection_closed(
        phase: ConnectionPhase,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        match classify_connection_closed_message(&message) {
            Some(kind) => Self::connection_closed(phase, kind, message),
            None => Error::H2(message),
        }
    }

    /// Helper for HTTP/1 adapters that still receive string-only transport errors.
    pub(crate) fn http_or_connection_closed(
        phase: ConnectionPhase,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        match classify_connection_closed_message(&message) {
            Some(kind) => Self::connection_closed(phase, kind, message),
            None => Error::Http(message),
        }
    }

    /// Helper for HTTP/3 adapters that still receive string-only transport errors.
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub(crate) fn http3_or_connection_closed(
        phase: ConnectionPhase,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        match classify_connection_closed_message(&message) {
            Some(kind) => Self::connection_closed(phase, kind, message),
            None => Error::Http3Request(message),
        }
    }

    /// Helper to create a structured QUIC transport error.
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub(crate) fn quic(phase: QuicPhase, message: impl Into<String>) -> Self {
        Error::QuicTransport(Box::new(QuicError {
            phase,
            message: message.into(),
        }))
    }

    /// Helper to create a proxy error.
    pub(crate) fn proxy(
        kind: ProxyErrorKind,
        message: impl Into<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Error::Proxy(Box::new(ProxyError {
            kind,
            message: message.into(),
            source,
        }))
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

fn classify_connection_closed_message(message: &str) -> Option<ConnectionClosedKind> {
    let m = message.to_ascii_lowercase();
    if m.contains("refused stream") {
        Some(ConnectionClosedKind::RefusedStream)
    } else if m.contains("goaway") {
        Some(ConnectionClosedKind::Goaway)
    } else if m.contains("stream reset") || m.contains("connection reset") {
        Some(ConnectionClosedKind::Reset)
    } else if m.contains("broken pipe") || m.contains("pipe broken") {
        Some(ConnectionClosedKind::BrokenPipe)
    } else if m.contains("not connected") || m.contains("connection shut down") {
        Some(ConnectionClosedKind::NotConnected)
    } else if m.contains("channel closed") {
        Some(ConnectionClosedKind::ChannelClosed)
    } else if m.contains("unexpected eof") || m.contains("empty response") {
        Some(ConnectionClosedKind::Eof)
    } else if m.contains("connection closed")
        || m.contains("closed connection")
        || m.contains("stale connection")
    {
        Some(ConnectionClosedKind::Generic)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ConnectionPhase ---------------------------------------------------

    #[test]
    fn connection_phase_display() {
        assert_eq!(ConnectionPhase::DnsResolution.to_string(), "DNS resolution");
        assert_eq!(ConnectionPhase::TcpConnect.to_string(), "TCP connect");
        assert_eq!(ConnectionPhase::ProxyTunnel.to_string(), "proxy tunnel");
        assert_eq!(ConnectionPhase::TlsHandshake.to_string(), "TLS handshake");
        assert_eq!(ConnectionPhase::H2Negotiation.to_string(), "H2 negotiation");
        assert_eq!(ConnectionPhase::H2cUpgrade.to_string(), "h2c upgrade");
        assert_eq!(ConnectionPhase::QuicHandshake.to_string(), "QUIC handshake");
        assert_eq!(ConnectionPhase::H3Negotiation.to_string(), "H3 negotiation");
        assert_eq!(ConnectionPhase::QuicFallback.to_string(), "QUIC fallback");
        assert_eq!(ConnectionPhase::HttpRequest.to_string(), "HTTP request");
    }

    // -- Error::is_retryable -----------------------------------------------

    #[test]
    fn timeout_is_retryable() {
        let err = Error::Timeout {
            message: "test".into(),
            phase: None,
            duration: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn io_error_is_retryable() {
        let err = Error::Io(std::io::Error::other("test"));
        assert!(err.is_retryable());
    }

    #[test]
    fn invalid_config_is_not_retryable() {
        let err = Error::InvalidConfig("bad".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn url_parse_is_not_retryable() {
        let err = Error::UrlParse("bad url".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn too_many_redirects_is_not_retryable() {
        let err = Error::TooManyRedirects(10);
        assert!(!err.is_retryable());
    }

    #[test]
    fn resource_limit_is_not_retryable() {
        let err = Error::ResourceLimitExceeded("too big".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn status_5xx_is_retryable() {
        let err = Error::Status {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            url: "https://example.com".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn status_4xx_is_not_retryable() {
        let err = Error::Status {
            status: StatusCode::NOT_FOUND,
            url: "https://example.com".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn h2_error_is_retryable() {
        let err = Error::H2("stream reset".into());
        assert!(err.is_retryable());
    }

    #[test]
    fn quic_and_h3_errors_are_retryable() {
        assert!(Error::Quic("handshake timeout".into()).is_retryable());
        assert!(Error::quic(QuicPhase::Handshake, "handshake timeout").is_retryable());
        assert!(Error::H3("peer closed control stream".into()).is_retryable());
    }

    #[test]
    fn http_error_connection_closed_is_detected() {
        assert!(Error::Http("stale pooled connection closed by peer".into()).is_connection_closed());
        assert!(Error::Http("write failed: connection reset by peer".into()).is_connection_closed());
        assert!(!Error::Http("invalid response header".into()).is_connection_closed());
    }

    #[test]
    fn h2_stream_reset_is_connection_closed() {
        assert!(
            Error::H2("failed to receive H2 response: stream reset: error_code=1".into())
                .is_connection_closed()
        );
        assert!(Error::H2("stream reset: error_code=8".into()).is_connection_closed());
        assert_eq!(
            Error::H2("stream reset: error_code=8".into()).connection_closed_kind(),
            Some(ConnectionClosedKind::Reset)
        );
    }

    #[test]
    fn typed_connection_closed_is_detected_without_message_sniffing() {
        let err = Error::connection_closed(
            ConnectionPhase::HttpRequest,
            ConnectionClosedKind::Goaway,
            "server sent GOAWAY",
        );
        assert!(err.is_connection_closed());
        assert_eq!(
            err.connection_closed_kind(),
            Some(ConnectionClosedKind::Goaway)
        );
        assert_eq!(err.phase(), Some(ConnectionPhase::HttpRequest));
        assert!(err.is_retryable());
    }

    // -- Error::phase ------------------------------------------------------

    #[test]
    fn timeout_with_phase() {
        let err = Error::Timeout {
            message: "test".into(),
            phase: Some(ConnectionPhase::DnsResolution),
            duration: Some(Duration::from_secs(5)),
        };
        assert_eq!(err.phase(), Some(ConnectionPhase::DnsResolution));
        assert!(err.is_dns());
        assert!(err.is_timeout());
    }

    #[test]
    fn connection_error_phase() {
        let err = Error::connection(ConnectionPhase::TcpConnect, "connection refused", None);
        assert_eq!(err.phase(), Some(ConnectionPhase::TcpConnect));
        assert!(err.is_tcp());
    }

    #[test]
    fn tls_error_phase() {
        let err = Error::Tls(lktls::error::TlsError::HandshakeFailure("test".into()));
        assert_eq!(err.phase(), Some(ConnectionPhase::TlsHandshake));
        assert!(err.is_tls_handshake());
    }

    #[test]
    fn proxy_error_phase() {
        let err = Error::proxy(ProxyErrorKind::TcpConnectFailed, "failed", None);
        assert_eq!(err.phase(), Some(ConnectionPhase::ProxyTunnel));
        assert!(err.is_proxy_tunnel());
    }

    #[test]
    fn quic_and_h3_errors_expose_phases() {
        assert_eq!(
            Error::Quic("transport error".into()).phase(),
            Some(ConnectionPhase::QuicHandshake)
        );
        let structured = Error::quic(QuicPhase::Handshake, "transport error");
        assert_eq!(structured.quic_phase(), Some(QuicPhase::Handshake));
        assert_eq!(structured.phase(), Some(ConnectionPhase::QuicHandshake));
        assert!(structured.is_quic_handshake_failure());

        let established = Error::quic(QuicPhase::Established, "stream timed out");
        assert_eq!(established.quic_phase(), Some(QuicPhase::Established));
        assert_eq!(established.phase(), Some(ConnectionPhase::HttpRequest));
        assert!(!established.is_quic_handshake_failure());

        assert_eq!(
            Error::H3("stream error".into()).phase(),
            Some(ConnectionPhase::H3Negotiation)
        );
    }

    #[test]
    fn http_error_has_no_phase() {
        let err = Error::Http("bad response".into());
        assert_eq!(err.phase(), None);
    }

    // -- Error::status / is_status -----------------------------------------

    #[test]
    fn status_error_accessors() {
        let err = Error::Status {
            status: StatusCode::FORBIDDEN,
            url: "https://example.com".into(),
        };
        assert!(err.is_status());
        assert_eq!(err.status(), Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn non_status_error() {
        let err = Error::Http("test".into());
        assert!(!err.is_status());
        assert_eq!(err.status(), None);
    }

    // -- ProxyError --------------------------------------------------------

    #[test]
    fn proxy_error_is_auth() {
        let pe = ProxyError {
            kind: ProxyErrorKind::AuthenticationRequired,
            message: "need auth".into(),
            source: None,
        };
        assert!(pe.is_auth_error());

        let pe2 = ProxyError {
            kind: ProxyErrorKind::AuthenticationFailed,
            message: "bad creds".into(),
            source: None,
        };
        assert!(pe2.is_auth_error());
    }

    #[test]
    fn proxy_error_not_auth() {
        let pe = ProxyError {
            kind: ProxyErrorKind::TcpConnectFailed,
            message: "can't connect".into(),
            source: None,
        };
        assert!(!pe.is_auth_error());
    }

    // -- Error Display ----------------------------------------------------

    #[test]
    fn error_display_variants() {
        let timeout = Error::Timeout {
            message: "DNS timed out".into(),
            phase: None,
            duration: None,
        };
        assert!(timeout.to_string().contains("DNS timed out"));

        let redirects = Error::TooManyRedirects(10);
        assert!(redirects.to_string().contains("10"));

        let pool = Error::Pool("exhausted".into());
        assert!(pool.to_string().contains("exhausted"));

        let url = Error::UrlParse("missing scheme".into());
        assert!(url.to_string().contains("missing scheme"));

        let quic = Error::Quic("handshake failed".into());
        assert!(quic.to_string().contains("handshake failed"));

        let h3 = Error::H3("settings frame invalid".into());
        assert!(h3.to_string().contains("settings frame invalid"));
    }
}
