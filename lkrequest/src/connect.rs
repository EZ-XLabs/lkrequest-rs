//! Connection establishment pipeline — decouples transport from TLS.
//!
//! Provides [`TransportStream`], a unified stream type that abstracts over
//! TLS-encrypted and plaintext TCP connections, and `Session::establish_connection`
//! which encapsulates the full TCP → optional-TLS → ALPN pipeline.
//!
//! This module eliminates code duplication across `transport.rs`, `streaming.rs`,
//! `session/mod.rs` (preconnect), and `ws/builder.rs`, each of which previously
//! had their own copy of the connection establishment logic.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use hyper::rt::{Read as HyperRead, Write as HyperWrite};

use crate::connection_pool::Scheme;
use crate::error::{ConnectionPhase, Error, Result};
use crate::proxy::ProxyConfig;
use crate::tls::{TlsConnector, TlsStream};

// ---------------------------------------------------------------------------
// TransportStream
// ---------------------------------------------------------------------------

/// A transport stream that is either TLS-encrypted or plaintext TCP.
///
/// Implements `AsyncRead + AsyncWrite` (tokio) and `Read + Write` (hyper),
/// so it can be used directly with both hyper HTTP/1.1 and lkh2 HTTP/2
/// connection handshakes.
/// Raw transport: a TLS-encrypted or plaintext TCP stream.
///
/// Implements the tokio I/O traits; [`TransportStream`] wraps this, optionally
/// with byte-counting telemetry.
pub(crate) enum TransportKind {
    /// TLS-encrypted stream (HTTPS, boxed to reduce enum size).
    Tls(Box<TlsStream<TcpStream>>),
    /// Plaintext TCP stream (HTTP).
    Plain(TcpStream),
}

impl std::fmt::Debug for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(s) => f.debug_tuple("Tls").field(s).finish(),
            Self::Plain(_) => f.debug_tuple("Plain").finish(),
        }
    }
}

impl AsyncRead for TransportKind {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => AsyncRead::poll_read(Pin::new(s.as_mut()), cx, buf),
            Self::Plain(s) => AsyncRead::poll_read(Pin::new(s), cx, buf),
        }
    }
}

impl AsyncWrite for TransportKind {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(s) => AsyncWrite::poll_write(Pin::new(s.as_mut()), cx, buf),
            Self::Plain(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => AsyncWrite::poll_flush(Pin::new(s.as_mut()), cx),
            Self::Plain(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => AsyncWrite::poll_shutdown(Pin::new(s.as_mut()), cx),
            Self::Plain(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
        }
    }
}

/// RAII guard for the active-connection gauge: `+1` on construction, `-1` on
/// drop. Held by [`TransportStream`] so the gauge tracks live transports.
#[cfg(feature = "telemetry")]
struct ConnActiveGuard;

#[cfg(feature = "telemetry")]
impl ConnActiveGuard {
    fn new() -> Self {
        crate::telemetry::counters().connection_opened();
        Self
    }
}

#[cfg(feature = "telemetry")]
impl Drop for ConnActiveGuard {
    fn drop(&mut self) {
        crate::telemetry::counters().connection_closed();
    }
}

/// A transport stream that is either TLS-encrypted or plaintext TCP.
///
/// Implements `AsyncRead + AsyncWrite` (tokio) and `Read + Write` (hyper), so it
/// can be used directly with both hyper HTTP/1.1 and lkh2 HTTP/2 handshakes.
///
/// With the `telemetry` feature it transparently counts wire bytes into the
/// process-global counters and tracks the active-connection gauge; without the
/// feature it is a zero-overhead newtype over `TransportKind`.
pub struct TransportStream {
    #[cfg(feature = "telemetry")]
    inner: crate::telemetry::Metered<TransportKind>,
    #[cfg(not(feature = "telemetry"))]
    inner: TransportKind,
    #[cfg(feature = "telemetry")]
    _conn: ConnActiveGuard,
}

impl TransportStream {
    /// Wrap a TLS transport.
    pub(crate) fn tls(stream: Box<TlsStream<TcpStream>>) -> Self {
        Self::wrap(TransportKind::Tls(stream))
    }

    /// Wrap a plaintext TCP transport.
    pub(crate) fn plain(stream: TcpStream) -> Self {
        Self::wrap(TransportKind::Plain(stream))
    }

    fn wrap(kind: TransportKind) -> Self {
        #[cfg(feature = "telemetry")]
        {
            Self {
                inner: crate::telemetry::Metered::global(kind),
                _conn: ConnActiveGuard::new(),
            }
        }
        #[cfg(not(feature = "telemetry"))]
        {
            Self { inner: kind }
        }
    }

    fn into_kind(self) -> TransportKind {
        #[cfg(feature = "telemetry")]
        {
            // Destructure: move `inner` out, drop `_conn` (decrements the gauge).
            // `TransportStream` itself has no `Drop` impl, so this is allowed.
            let Self { inner, _conn } = self;
            drop(_conn);
            inner.into_inner()
        }
        #[cfg(not(feature = "telemetry"))]
        {
            self.inner
        }
    }

    /// Extract the raw plaintext `TcpStream` (e.g. for h2c prior-knowledge or a
    /// WebSocket upgrade), flushing any telemetry. Returns `None` for TLS.
    pub(crate) fn into_plain_tcp(self) -> Option<TcpStream> {
        match self.into_kind() {
            TransportKind::Plain(tcp) => Some(tcp),
            TransportKind::Tls(_) => None,
        }
    }

    /// Flush telemetry byte counters at a request boundary (no-op without the
    /// `telemetry` feature).
    #[allow(dead_code)]
    pub(crate) fn flush_telemetry(&mut self) {
        #[cfg(feature = "telemetry")]
        self.inner.flush();
    }
}

impl std::fmt::Debug for TransportStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportStream").finish_non_exhaustive()
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl HyperRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut tokio_buf = ReadBuf::uninit(unsafe { buf.as_mut() });
        match <Self as AsyncRead>::poll_read(self, cx, &mut tokio_buf) {
            Poll::Ready(Ok(())) => {
                let n = tokio_buf.filled().len();
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl HyperWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        <Self as AsyncWrite>::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWrite>::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWrite>::poll_shutdown(self, cx)
    }
}

// ---------------------------------------------------------------------------
// EstablishedConnection
// ---------------------------------------------------------------------------

/// Result of the connection establishment pipeline.
///
/// Contains the transport stream (TLS or plain) and the ALPN negotiation
/// result (only available for TLS connections).
pub enum EstablishedConnection {
    /// TCP / TLS-based connection.
    Tcp {
        /// The transport stream, ready for HTTP protocol handshake.
        stream: TransportStream,
        /// ALPN protocol negotiated during TLS handshake.
        negotiated_alpn: Option<String>,
        /// Connected remote socket address.
        remote_addr: Option<std::net::SocketAddr>,
        /// Negotiated TLS cipher suite, if TLS was used.
        negotiated_cipher_suite: Option<u16>,
    },
    /// QUIC-based connection.
    #[cfg(feature = "quic-h3")]
    Quic {
        /// Underlying QUIC connection.
        connection: quinn::Connection,
        /// Connected remote socket address.
        remote_addr: Option<std::net::SocketAddr>,
    },
}

impl EstablishedConnection {
    pub fn negotiated_alpn(&self) -> Option<&str> {
        match self {
            Self::Tcp {
                negotiated_alpn, ..
            } => negotiated_alpn.as_deref(),
            #[cfg(feature = "quic-h3")]
            Self::Quic { .. } => None,
        }
    }

    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Tcp { remote_addr, .. } => *remote_addr,
            #[cfg(feature = "quic-h3")]
            Self::Quic { remote_addr, .. } => *remote_addr,
        }
    }

    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        match self {
            Self::Tcp {
                negotiated_cipher_suite,
                ..
            } => *negotiated_cipher_suite,
            #[cfg(feature = "quic-h3")]
            Self::Quic { .. } => None,
        }
    }

    pub fn into_tcp_stream(self) -> Result<TransportStream> {
        match self {
            Self::Tcp { stream, .. } => Ok(stream),
            #[cfg(feature = "quic-h3")]
            Self::Quic { .. } => Err(Error::InvalidConfig(
                "expected TCP/TLS transport, got QUIC connection".into(),
            )),
        }
    }

    #[cfg(feature = "quic-h3")]
    pub fn quic_connection(&self) -> Option<&quinn::Connection> {
        match self {
            Self::Quic { connection, .. } => Some(connection),
            Self::Tcp { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectConfig
// ---------------------------------------------------------------------------

/// Configuration for a single connection establishment attempt.
///
/// Groups the per-request parameters that vary between call sites
/// (transport, streaming, preconnect, websocket, H2→H1 fallback).
pub(crate) struct ConnectConfig {
    /// Target scheme (Http or Https).
    pub scheme: Scheme,
    /// TLS fingerprint profile (ignored for Http scheme).
    pub tls_profile: lktls::profile::types::TlsProfile,
    /// ALPS state for the TLS handshake (ignored for Http scheme).
    ///
    /// `None` => do not advertise ALPS (e.g. H1-only). `Some(bytes)` => advertise
    /// `application_settings` in the ClientHello and send `bytes` (commonly empty,
    /// matching real Chrome) as the Client EncryptedExtensions payload.
    pub alps_payload: Option<Vec<u8>>,
    /// Whether to fall back to direct TCP if proxy connection fails.
    pub proxy_to_direct_fallback: bool,
    /// Time budget for proxy fallback calculation.
    /// `(connect_start, total_timeout)` — used to cap the proxy timeout
    /// so the direct-connect path still has time budget remaining.
    pub fallback_time_budget: Option<(Instant, Duration)>,
}

impl ConnectConfig {
    /// Create config for a standard HTTPS connection.
    pub fn https(
        tls_profile: lktls::profile::types::TlsProfile,
        alps_payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            scheme: Scheme::Https,
            tls_profile,
            alps_payload,
            proxy_to_direct_fallback: false,
            fallback_time_budget: None,
        }
    }

    /// Convert to cleartext HTTP config (no TLS handshake).
    pub fn into_http(mut self) -> Self {
        self.scheme = Scheme::Http;
        self
    }

    /// Enable proxy→direct fallback with the given time budget.
    pub fn with_proxy_fallback(mut self, connect_start: Instant, total_timeout: Duration) -> Self {
        self.proxy_to_direct_fallback = true;
        self.fallback_time_budget = Some((connect_start, total_timeout));
        self
    }
}

// ---------------------------------------------------------------------------
// TCP connect helpers
// ---------------------------------------------------------------------------

/// Establish a TCP connection, direct or through a proxy.
///
/// This is the shared implementation for all call sites. The proxy→direct
/// fallback is controlled by `config.proxy_to_direct_fallback`.
pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    proxy: Option<&ProxyConfig>,
    tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
    resolver: &dyn crate::dns::DnsResolver,
    tcp_timeout: Duration,
    config: &ConnectConfig,
) -> Result<TcpStream> {
    if let Some(proxy_cfg) = proxy {
        let proxy_timeout = if config.proxy_to_direct_fallback {
            if let Some((start, total)) = config.fallback_time_budget {
                let remaining = total.saturating_sub(start.elapsed());
                tcp_timeout.min(remaining / 2)
            } else {
                tcp_timeout
            }
        } else {
            tcp_timeout
        };

        tracing::debug!(
            proxy = %proxy_cfg,
            phase = "proxy_tunnel",
            timeout_ms = proxy_timeout.as_millis() as u64,
            "http.connect.phase_start",
        );

        let proxy_result = tokio::time::timeout(
            proxy_timeout,
            proxy_cfg.connect(host, port, tcp_fingerprint, resolver),
        )
        .await
        .map_err(|_| {
            Error::timeout(
                format!("proxy tunnel timed out after {proxy_timeout:?}"),
                Some(ConnectionPhase::ProxyTunnel),
                Some(proxy_timeout),
            )
        })
        .and_then(|r| r);

        match proxy_result {
            Ok(tcp) => Ok(tcp),
            Err(e) if config.proxy_to_direct_fallback => {
                tracing::warn!(
                    error = %e,
                    fallback = "proxy_to_direct",
                    "http.proxy_failed_falling_back_to_direct",
                );
                connect_tcp_direct(host, port, tcp_fingerprint, resolver, tcp_timeout).await
            }
            Err(e) => Err(e),
        }
    } else {
        connect_tcp_direct(host, port, tcp_fingerprint, resolver, tcp_timeout).await
    }
}

/// Direct TCP connect (no proxy).
async fn connect_tcp_direct(
    host: &str,
    port: u16,
    tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
    resolver: &dyn crate::dns::DnsResolver,
    tcp_timeout: Duration,
) -> Result<TcpStream> {
    tracing::debug!(
        addr = %format_args!("{}:{}", host, port),
        phase = "tcp_connect",
        timeout_ms = tcp_timeout.as_millis() as u64,
        "http.connect.phase_start",
    );

    tokio::time::timeout(
        tcp_timeout,
        crate::tcp_fingerprint::connect_tcp_with_fingerprint(host, port, tcp_fingerprint, resolver),
    )
    .await
    .map_err(|_| {
        Error::timeout(
            format!("TCP connect timed out after {tcp_timeout:?}"),
            Some(ConnectionPhase::TcpConnect),
            Some(tcp_timeout),
        )
    })?
    .map_err(|e| {
        Error::connection(
            ConnectionPhase::TcpConnect,
            format!("TCP connect to {host}:{port} failed: {e}"),
            Some(Box::new(e)),
        )
    })
}

/// Perform TLS handshake on a TCP stream and return an `EstablishedConnection`.
pub(crate) async fn wrap_tls(
    tcp: TcpStream,
    host: &str,
    port: u16,
    tls_connector: &TlsConnector,
    tls_timeout: Duration,
) -> Result<EstablishedConnection> {
    let remote_addr = tcp.peer_addr().ok();
    let tls_start = Instant::now();
    tracing::debug!(
        phase = "tls_handshake",
        timeout_ms = tls_timeout.as_millis() as u64,
        "http.connect.phase_start",
    );

    let tls_stream = tokio::time::timeout(tls_timeout, tls_connector.connect(host, port, tcp))
        .await
        .map_err(|_| {
            Error::timeout(
                format!("TLS handshake timed out after {tls_timeout:?}"),
                Some(ConnectionPhase::TlsHandshake),
                Some(tls_timeout),
            )
        })?
        .map_err(Error::Tls)?;

    let negotiated_alpn = tls_stream.negotiated_alpn().map(|s| s.to_string());
    let negotiated_cipher_suite = tls_stream.negotiated_cipher_suite();
    crate::diagnostics::record_tls_ms(tls_start.elapsed().as_millis() as u64);
    if let Some(addr) = remote_addr {
        crate::diagnostics::record_remote_addr(addr.to_string());
    }
    if let Some(cipher_suite) = negotiated_cipher_suite {
        crate::diagnostics::record_cipher_suite(format!("0x{cipher_suite:04x}"));
    }

    tracing::debug!(
        phase = "tls_handshake",
        alpn = ?negotiated_alpn,
        "http.connect.phase_complete",
    );

    Ok(EstablishedConnection::Tcp {
        stream: TransportStream::tls(Box::new(tls_stream)),
        negotiated_alpn,
        remote_addr,
        negotiated_cipher_suite,
    })
}
