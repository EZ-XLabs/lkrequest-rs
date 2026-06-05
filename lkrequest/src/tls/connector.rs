//! TLS connector — wraps a TCP stream with the lktls TLS engine.
//!
//! This module provides [`TlsConnector`] that:
//! 1. Takes a [`TlsProfile`] and a TCP stream
//! 2. Performs the TLS handshake (TLS 1.3 or 1.2, driven by the profile)
//! 3. Returns a [`TlsStream`] that implements `AsyncRead` + `AsyncWrite`
//!
//! The heavy protocol logic lives in [`lktls::handshake::driver::HandshakeDriver`].
//! This module is a thin async I/O adapter.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::Instrument;

use hyper::rt::{Read as HyperRead, Write as HyperWrite};

use lktls::error::{Result, TlsError};
use lktls::handshake::content_type;
use lktls::handshake::driver::{
    HandshakeConfig, HandshakeDriver, HandshakeOutput, PostHandshakeState, SessionTicketContext,
};
use lktls::profile::types::TlsProfile;
use lktls::record::reader::RecordReader;
use lktls::record::writer::RecordWriter;
use lktls::session_store::SessionStore;
use lktls::verify::policy::VerificationPolicy;
use lktls::KeyLogCallback;

/// Trait alias for stream types accepted by [`TlsConnector::connect`].
pub trait TlsTransport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsTransport for T {}

/// Create a [`KeyLogCallback`] that appends lines to the given file path.
pub fn keylog_to_file(path: impl Into<std::path::PathBuf>) -> io::Result<KeyLogCallback> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::Mutex;

    let path = path.into();
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let file = Arc::new(Mutex::new(file));

    Ok(Arc::new(move |line: &str| {
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "{line}");
        }
    }))
}

// ---------------------------------------------------------------------------
// TlsConnector
// ---------------------------------------------------------------------------

/// Connector that establishes TLS connections with a specific fingerprint.
///
/// Wraps an [`lktls::handshake::driver::HandshakeConfig`] with a builder
/// API and provides the async I/O adapter for the TLS handshake.
pub struct TlsConnector {
    config: HandshakeConfig,
}

impl TlsConnector {
    pub fn new(profile: TlsProfile) -> Self {
        Self {
            config: HandshakeConfig {
                profile,
                hostname: String::new(),
                port: 0,
                verification_policy: VerificationPolicy::default(),
                alps_payload: None,
                session_store: None,
                ech_config_list: None,
                custom_ca_anchors: None,
                keylog_callback: None,
            },
        }
    }

    pub fn profile(&self) -> &TlsProfile {
        &self.config.profile
    }

    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        self.config.verification_policy = policy;
        self
    }

    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        if skip {
            self.config.verification_policy = VerificationPolicy::Insecure;
        }
        self
    }

    pub fn alps_payload(mut self, payload: Vec<u8>) -> Self {
        self.config.alps_payload = Some(payload);
        self
    }

    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.config.session_store = Some(store);
        self
    }

    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.config.ech_config_list = Some(config_list);
        self
    }

    pub fn ech_config_list(&self) -> Option<&[u8]> {
        self.config.ech_config_list.as_deref()
    }

    pub fn custom_ca_anchors(
        mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) -> Self {
        self.config.custom_ca_anchors = Some(anchors);
        self
    }

    pub fn keylog(mut self, callback: KeyLogCallback) -> Self {
        self.config.keylog_callback = Some(callback);
        self
    }

    pub async fn connect_tcp(
        &self,
        hostname: &str,
        port: u16,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>> {
        self.connect(hostname, port, stream).await
    }

    pub async fn connect<S: TlsTransport + 'static>(
        &self,
        hostname: &str,
        port: u16,
        stream: S,
    ) -> Result<TlsStream<S>> {
        let span = tracing::debug_span!("tls.handshake", sni = %hostname);
        self.connect_inner(hostname, port, stream)
            .instrument(span)
            .await
    }

    /// Perform the TLS handshake using the Sans-I/O [`HandshakeDriver`].
    fn connect_inner<'a, S: TlsTransport + 'static>(
        &'a self,
        hostname: &'a str,
        port: u16,
        mut stream: S,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<TlsStream<S>>> + Send + 'a>> {
        Box::pin(async move {
            let mut config = self.config.clone();
            config.hostname = hostname.to_string();
            config.port = port;

            let mut driver = HandshakeDriver::new(config);

            let ch_bytes = driver.start()?;
            stream.write_all(&ch_bytes).await.map_err(TlsError::Io)?;

            loop {
                match driver.progress()? {
                    HandshakeOutput::SendData(data) => {
                        stream.write_all(&data).await.map_err(TlsError::Io)?;
                    }
                    HandshakeOutput::NeedData => {
                        let mut buf = [0u8; 16384];
                        let n = stream.read(&mut buf).await.map_err(TlsError::Io)?;
                        if n == 0 {
                            return Err(TlsError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed during TLS handshake",
                            )));
                        }
                        driver.feed(&buf[..n]);
                    }
                    HandshakeOutput::Done { to_send, result } => {
                        if !to_send.is_empty() {
                            stream.write_all(&to_send).await.map_err(TlsError::Io)?;
                        }
                        return Ok(TlsStream::from_handshake(stream, *result));
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// TlsStream
// ---------------------------------------------------------------------------

pub struct TlsStream<S: TlsTransport = TcpStream> {
    inner: S,
    reader: RecordReader,
    writer: RecordWriter,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
    closed: bool,
    negotiated_alpn: Option<String>,
    negotiated_cipher_suite: Option<u16>,
    post_handshake: Option<PostHandshakeState>,
    session_ticket_ctx: Option<SessionTicketContext>,
}

impl<S: TlsTransport> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("closed", &self.closed)
            .finish()
    }
}

impl<S: TlsTransport> TlsStream<S> {
    /// Construct a `TlsStream` from a completed handshake result and the
    /// underlying transport stream.
    fn from_handshake(inner: S, result: lktls::handshake::driver::HandshakeResult) -> Self {
        Self {
            inner,
            reader: result.reader,
            writer: result.writer,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            closed: false,
            negotiated_alpn: result.negotiated_alpn,
            negotiated_cipher_suite: result.negotiated_cipher_suite,
            post_handshake: result.post_handshake,
            session_ticket_ctx: result.session_ticket_ctx,
        }
    }

    pub fn inner_stream(&self) -> &S {
        &self.inner
    }

    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.negotiated_cipher_suite
    }

    fn handle_post_handshake(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() < 4 {
            return Ok(());
        }
        let msg_type = payload[0];
        match msg_type {
            0x18 => {
                if let Some(ref mut ph) = self.post_handshake {
                    // Update read-side keys (server's new key).
                    let new_read_aead = ph
                        .process_key_update()
                        .map_err(|e| io::Error::other(format!("KeyUpdate failed: {e}")))?;
                    self.reader.set_keys(new_read_aead);

                    // Check if the server requested us to update our keys too.
                    // KeyUpdate body: update_requested(1 byte).
                    // 0x00 = update_not_requested, 0x01 = update_requested
                    let update_requested = payload.get(4).copied().unwrap_or(0) == 0x01;
                    if update_requested {
                        let (ku_msg, new_write_aead) =
                            ph.build_key_update_response().map_err(|e| {
                                io::Error::other(format!("KeyUpdate response failed: {e}"))
                            })?;
                        // Encrypt the KeyUpdate message with the current write key,
                        // then install the new write key.
                        let record = self
                            .writer
                            .write_record(lktls::handshake::content_type::HANDSHAKE, &ku_msg)
                            .map_err(|e| {
                                io::Error::other(format!("KeyUpdate write failed: {e}"))
                            })?;
                        self.write_buf.extend_from_slice(&record);
                        self.writer.set_keys(new_write_aead);
                    }
                }
            }
            0x04 => {
                if let Some(ref ctx) = self.session_ticket_ctx {
                    ctx.process_new_session_ticket(payload);
                } else {
                    tracing::trace!("tls.session_ticket_received_no_store");
                }
            }
            other => {
                tracing::trace!(
                    msg_type = format_args!("0x{:02x}", other),
                    "tls.post_handshake_ignored"
                );
            }
        }
        Ok(())
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut buf = [0u8; 16384];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    Poll::Ready(Ok(0))
                } else {
                    self.reader.feed(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn try_read_app_data(&mut self) -> io::Result<bool> {
        loop {
            match self.reader.next_record() {
                Ok(Some(record)) => {
                    if record.content_type == content_type::APPLICATION_DATA {
                        self.read_buf = record.payload;
                        self.read_pos = 0;
                        return Ok(true);
                    } else if record.content_type == content_type::ALERT {
                        let level = record.payload.first().copied().unwrap_or(0);
                        let desc = record.payload.get(1).copied().unwrap_or(0);
                        let alert = lktls::error::TlsAlert::from_bytes(level, desc);
                        if alert.is_close_notify() {
                            return Ok(false);
                        } else if alert.level == lktls::error::AlertLevel::Warning {
                            continue;
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!("TLS {}", alert),
                            ));
                        }
                    } else if record.content_type == content_type::HANDSHAKE {
                        self.handle_post_handshake(&record.payload)?;
                        continue;
                    } else {
                        continue;
                    }
                }
                Ok(None) => return Ok(false),
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncRead / AsyncWrite for TlsStream
// ---------------------------------------------------------------------------

impl<S: TlsTransport> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        match self.try_read_app_data() {
            Ok(true) => {
                let available = &self.read_buf[self.read_pos..];
                let to_copy = available.len().min(buf.remaining());
                buf.put_slice(&available[..to_copy]);
                self.read_pos += to_copy;
                return Poll::Ready(Ok(()));
            }
            Err(e) => return Poll::Ready(Err(e)),
            Ok(false) => {}
        }

        loop {
            match self.poll_read_inner(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(_)) => match self.try_read_app_data() {
                    Ok(true) => {
                        let available = &self.read_buf[self.read_pos..];
                        let to_copy = available.len().min(buf.remaining());
                        buf.put_slice(&available[..to_copy]);
                        self.read_pos += to_copy;
                        return Poll::Ready(Ok(()));
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                    Ok(false) => continue,
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Maximum write buffer size before applying back-pressure (256 KB).
const MAX_WRITE_BUF: usize = 256 * 1024;

impl<S: TlsTransport> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS stream is closed",
            )));
        }

        // Back-pressure: if the write buffer is already large, try to drain
        // it first before accepting more data.
        if self.write_buf.len() >= MAX_WRITE_BUF {
            let this = &mut *self;
            flush_write_buf(&mut this.inner, &mut this.write_buf, cx)?;
            if self.write_buf.len() >= MAX_WRITE_BUF {
                return Poll::Pending;
            }
        }

        let records = self
            .writer
            .write_record(content_type::APPLICATION_DATA, buf)
            .map_err(|e| io::Error::other(e.to_string()))?;

        if records.is_empty() {
            return Poll::Ready(Ok(buf.len()));
        }

        self.write_buf.extend_from_slice(&records);

        let this = &mut *self;
        flush_write_buf(&mut this.inner, &mut this.write_buf, cx)?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let coalesced = self.writer.flush();
        if !coalesced.is_empty() {
            self.write_buf.extend_from_slice(&coalesced);
        }

        let this = &mut *self;
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            let close_notify: &[u8] = &[0x01, 0x00];
            if let Ok(alert_record) = self.writer.write_record(content_type::ALERT, close_notify) {
                self.write_buf.extend_from_slice(&alert_record);
            }
        }

        let coalesced = self.writer.flush();
        if !coalesced.is_empty() {
            self.write_buf.extend_from_slice(&coalesced);
        }

        let this = &mut *self;
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Hyper trait adapters
// ---------------------------------------------------------------------------

impl<S: TlsTransport> HyperRead for TlsStream<S> {
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

impl<S: TlsTransport> HyperWrite for TlsStream<S> {
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
// Helpers
// ---------------------------------------------------------------------------

/// Try to flush a write buffer to a transport stream.
fn flush_write_buf<S: TlsTransport>(
    stream: &mut S,
    write_buf: &mut Vec<u8>,
    cx: &mut Context<'_>,
) -> io::Result<()> {
    while !write_buf.is_empty() {
        match Pin::new(&mut *stream).poll_write(cx, write_buf) {
            Poll::Ready(Ok(n)) => {
                write_buf.drain(..n);
            }
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => break,
        }
    }
    Ok(())
}
