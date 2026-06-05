//! Async connection driver — bridges the Sans-I/O `H2Engine` with Tokio I/O.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐    mpsc     ┌─────────────────────┐
//! │NativeSendReq │ ──────────► │  ConnectionDriver   │
//! │  (cloneable) │    cmds     │  ┌───────────────┐  │ ◄── TLS read
//! └──────────────┘             │  │   H2Engine    │  │ ──► TLS write
//!                              │  └───────────────┘  │
//!                              └─────────────────────┘
//! ```

use crate::engine::{H2Engine, H2Event};
use crate::frame::H2Frame;
use crate::policy::{FrameWritePolicy, H2Behavior};
use crate::profile::H2Profile;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

// ─── Channel messages ────────────────────────────────────────────────────────

/// Command sent from NativeSendRequest to the driver task.
#[derive(Debug)]
pub(crate) enum DriverCommand {
    SendRequest {
        request: Box<http::Request<Option<Bytes>>>,
        /// Sends back the response headers.
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        /// Sends body chunks as they arrive; dropped when stream ends.
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
    },
    #[allow(dead_code)]
    SendNativeRequest {
        request: Box<crate::adapter::NativeH2Request>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
    },
    #[allow(dead_code)]
    Shutdown,
}

/// Response headers from the native engine.
#[derive(Debug, Clone)]
pub struct NativeResponseHeaders {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

// ─── First Request (piggybacked on connection setup) ─────────────────────────

/// First request to send immediately after the connection preface.
///
/// By passing this into the driver at spawn time, the HEADERS frame is
/// written in the same async task as the preface — back-to-back,
/// guaranteeing they land in separate TLS records (matching Chrome).
pub struct FirstRequest {
    pub request: http::Request<Option<Bytes>>,
    pub headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
    pub body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
}

/// Channels returned to the caller for the piggybacked first request.
pub struct FirstRequestResponse {
    pub headers_rx: oneshot::Receiver<Result<NativeResponseHeaders, DriverError>>,
    pub body_rx: mpsc::UnboundedReceiver<Result<Bytes, DriverError>>,
}

impl FirstRequest {
    /// Build a `FirstRequest` + `FirstRequestResponse` pair from an
    /// `http::Request<Option<Bytes>>`.
    pub fn new(request: http::Request<Option<Bytes>>) -> (Self, FirstRequestResponse) {
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        (
            Self {
                request,
                headers_tx,
                body_tx,
            },
            FirstRequestResponse {
                headers_rx,
                body_rx,
            },
        )
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DriverError {
    Io(String),
    Protocol(String),
    StreamReset(u32),
    GoAway(String),
    Shutdown,
    ChannelClosed,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::StreamReset(code) => write!(f, "stream reset: error_code={code}"),
            Self::GoAway(msg) => write!(f, "GOAWAY: {msg}"),
            Self::Shutdown => write!(f, "connection shut down"),
            Self::ChannelClosed => write!(f, "channel closed"),
        }
    }
}

impl std::error::Error for DriverError {}

impl From<std::io::Error> for DriverError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── NativeSendRequest ───────────────────────────────────────────────────────

/// Cloneable handle to send HTTP/2 requests through a native H2 connection.
#[derive(Clone)]
pub struct NativeSendRequest {
    cmd_tx: mpsc::Sender<DriverCommand>,
}

impl NativeSendRequest {
    /// Check that the connection is alive.
    pub async fn ready(&mut self) -> Result<(), DriverError> {
        if self.cmd_tx.is_closed() {
            return Err(DriverError::Shutdown);
        }
        Ok(())
    }

    /// Send a request and receive a streaming response.
    ///
    /// Returns `(NativeResponseHeaders, mpsc::UnboundedReceiver<Result<Bytes, DriverError>>)`.
    /// The receiver yields body chunks; when it returns `None` the body is complete.
    pub async fn send_request(
        &mut self,
        request: http::Request<Option<Bytes>>,
    ) -> Result<
        (
            NativeResponseHeaders,
            mpsc::UnboundedReceiver<Result<Bytes, DriverError>>,
        ),
        DriverError,
    > {
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();

        let cmd = DriverCommand::SendRequest {
            request: Box::new(request),
            headers_tx,
            body_tx,
        };

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| DriverError::ChannelClosed)?;

        let resp_headers = headers_rx.await.map_err(|_| DriverError::ChannelClosed)??;

        Ok((resp_headers, body_rx))
    }

    /// Send a request using a pre-ordered `NativeH2Request` and receive a streaming response.
    #[allow(dead_code)]
    pub(crate) async fn send_native_request(
        &mut self,
        request: crate::adapter::NativeH2Request,
    ) -> Result<
        (
            NativeResponseHeaders,
            mpsc::UnboundedReceiver<Result<Bytes, DriverError>>,
        ),
        DriverError,
    > {
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();

        let cmd = DriverCommand::SendNativeRequest {
            request: Box::new(request),
            headers_tx,
            body_tx,
        };

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| DriverError::ChannelClosed)?;

        let resp_headers = headers_rx.await.map_err(|_| DriverError::ChannelClosed)??;

        Ok((resp_headers, body_rx))
    }
}

impl fmt::Debug for NativeSendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSendRequest").finish()
    }
}

// ─── Pending response state ─────────────────────────────────────────────────

struct PendingStream {
    /// Sends response headers (used once, then becomes None).
    headers_tx: Option<oneshot::Sender<Result<NativeResponseHeaders, DriverError>>>,
    /// Streams body data chunks to the consumer.
    body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
}

// ─── Driver ──────────────────────────────────────────────────────────────────

/// Spawn the connection driver task with default behaviour.
pub async fn spawn_driver<S>(
    stream: S,
    profile: &H2Profile,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request(stream, profile, None, None).await
}

/// Spawn the connection driver task with custom behaviour.
pub async fn spawn_driver_with_behavior<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request(stream, profile, behavior, None).await
}

/// Spawn the connection driver with an optional first request that is
/// written back-to-back with the connection preface (matching Chrome).
///
/// The caller creates a `FirstRequest` via `FirstRequest::new()` and
/// keeps the corresponding `FirstRequestResponse` to await the result.
pub async fn spawn_driver_with_first_request<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
    first_request: Option<FirstRequest>,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::channel::<DriverCommand>(64);

    let behavior = behavior.unwrap_or_else(H2Behavior::default_behavior);

    tracing::info!(
        write_policy = ?behavior.write_policy,
        flow_control = ?behavior.flow_control,
        hpack_policy = ?behavior.hpack_policy,
        "h2.native.behavior_applied"
    );

    let (engine, preface_frames) = H2Engine::client_with_policies(
        profile,
        behavior.flow_control.box_clone(),
        Some(behavior.hpack_policy.box_clone()),
    );

    let write_policy = behavior.write_policy;

    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), DriverError>>();

    let handle = tokio::spawn(driver_loop(
        stream,
        engine,
        preface_frames,
        cmd_rx,
        write_policy,
        ready_tx,
        first_request,
    ));

    ready_rx
        .await
        .map_err(|_| DriverError::ChannelClosed)?
        .map_err(|e| DriverError::Io(e.to_string()))?;

    Ok((NativeSendRequest { cmd_tx }, handle))
}

async fn driver_loop<S>(
    mut stream: S,
    mut engine: H2Engine,
    preface_frames: Vec<H2Frame>,
    mut cmd_rx: mpsc::Receiver<DriverCommand>,
    write_policy: Box<dyn FrameWritePolicy>,
    ready_tx: oneshot::Sender<Result<(), DriverError>>,
    first_request: Option<FirstRequest>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // ── Send connection preface ──────────────────────────────────────
    // The 24-byte connection magic is always the first thing on the wire,
    // written together with the first frame group to form a single TLS record
    // (matching Chrome's observed behavior: magic + SETTINGS + WINDOW_UPDATE
    // in one record).
    //
    // Subsequent groups (e.g. PRIORITY frames) get their own TLS records,
    // controlled by the FrameWritePolicy.
    {
        let groups = write_policy.group_frames(preface_frames);
        for (i, group) in groups.into_iter().enumerate() {
            let mut buf = BytesMut::new();
            if i == 0 {
                buf.extend_from_slice(crate::CONNECTION_PREFACE);
            }
            engine.encode_frames(&group, &mut buf);
            if let Err(e) = stream.write_all(&buf).await {
                tracing::error!(error = %e, "h2.native.write_preface_failed");
                let _ = ready_tx.send(Err(DriverError::Io(e.to_string())));
                return;
            }
            if let Err(e) = stream.flush().await {
                tracing::error!(error = %e, "h2.native.flush_preface_failed");
                let _ = ready_tx.send(Err(DriverError::Io(e.to_string())));
                return;
            }
        }
    }
    tracing::debug!("h2.native.preface_sent");

    let mut read_buf = BytesMut::with_capacity(16384);
    let mut pending: HashMap<u32, PendingStream> = HashMap::new();

    // ── Write the first request directly after the preface ───────────
    // Real browsers (Chrome) send HEADERS ~40μs after the preface as a
    // separate TLS record, without waiting for the server's SETTINGS.
    //
    // After flush(), the preface TLS record has been written to the OS
    // TCP send buffer. The write_all(HEADERS) below creates a separate
    // TLS record. With TCP_NODELAY enabled (set via TcpFingerprint),
    // the OS sends the preface segment immediately, and HEADERS follows
    // as an independent TCP segment — matching Chrome's behavior.
    if let Some(first_req) = first_request {
        if let Err(e) = write_first_request(
            &mut stream,
            &mut engine,
            &*write_policy,
            &mut pending,
            first_req,
        )
        .await
        {
            let _ = ready_tx.send(Err(e));
            return;
        }
    }

    let _ = ready_tx.send(Ok(()));

    // ── Main loop ────────────────────────────────────────────────────
    let mut shutdown = false;
    let mut shutdown_deadline: Option<tokio::time::Instant> = None;

    loop {
        let sleep_fut = async {
            if let Some(deadline) = shutdown_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            biased;

            result = stream.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        notify_all_error(&mut pending, DriverError::Io("connection closed".into()));
                        break;
                    }
                    Ok(_n) => {
                        let (mut events, outbound_frames) = engine.process(&mut read_buf);

                        if !outbound_frames.is_empty() {
                            if let Err(e) = encode_and_write_frames(
                                &mut stream, &engine, &*write_policy, outbound_frames,
                            ).await {
                                tracing::error!(error = %e, "h2.native.write_error");
                                break;
                            }
                        }

                        for event in events.drain(..) {
                            handle_event(event, &mut pending);
                        }

                        engine.recycle_buffers(events, Vec::new());
                    }
                    Err(e) => {
                        notify_all_error(&mut pending, DriverError::Io(e.to_string()));
                        break;
                    }
                }
            }

            cmd = cmd_rx.recv(), if !shutdown => {
                match cmd {
                    Some(DriverCommand::SendRequest { request, headers_tx, body_tx }) => {
                        if !engine.can_open_stream() {
                            let _ = headers_tx.send(Err(DriverError::Protocol(
                                "MAX_CONCURRENT_STREAMS exceeded".into(),
                            )));
                            continue;
                        }
                        let stream_id = engine.open_stream();
                        let frames = engine.build_request(stream_id, *request);

                        pending.insert(stream_id, PendingStream {
                            headers_tx: Some(headers_tx),
                            body_tx,
                        });

                        if let Err(e) = encode_and_write_frames(&mut stream, &engine, &*write_policy, frames).await {
                            tracing::error!(error = %e, "h2.native.write_error");
                            if let Some(ps) = pending.remove(&stream_id) {
                                if let Some(tx) = ps.headers_tx {
                                    let _ = tx.send(Err(DriverError::Io(e.to_string())));
                                }
                            }
                            break;
                        }
                    }
                    Some(DriverCommand::SendNativeRequest { request, headers_tx, body_tx }) => {
                        if !engine.can_open_stream() {
                            let _ = headers_tx.send(Err(DriverError::Protocol(
                                "MAX_CONCURRENT_STREAMS exceeded".into(),
                            )));
                            continue;
                        }
                        let stream_id = engine.open_stream();
                        let frames = engine.build_native_request(stream_id, *request);

                        pending.insert(stream_id, PendingStream {
                            headers_tx: Some(headers_tx),
                            body_tx,
                        });

                        if let Err(e) = encode_and_write_frames(&mut stream, &engine, &*write_policy, frames).await {
                            tracing::error!(error = %e, "h2.native.write_error");
                            if let Some(ps) = pending.remove(&stream_id) {
                                if let Some(tx) = ps.headers_tx {
                                    let _ = tx.send(Err(DriverError::Io(e.to_string())));
                                }
                            }
                        }
                    }
                    Some(DriverCommand::Shutdown) | None => {
                        shutdown = true;
                        if pending.is_empty() {
                            break;
                        }
                        if shutdown_deadline.is_none() {
                            shutdown_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
                        }
                    }
                }
            }

            _ = sleep_fut, if shutdown_deadline.is_some() => {
                tracing::warn!(pending = pending.len(), "h2.native.shutdown_timeout");
                notify_all_error(&mut pending, DriverError::Shutdown);
                break;
            }
        }

        if shutdown && pending.is_empty() {
            break;
        }
    }

    tracing::debug!("h2.native.driver_exited");
}

/// Group, encode, and flush frames via write policy.
///
/// Each group returned by `FrameWritePolicy::group_frames` is encoded
/// into a single buffer and flushed as one TLS record, giving the
/// policy full control over the wire framing.
async fn encode_and_write_frames<S>(
    stream: &mut S,
    engine: &H2Engine,
    write_policy: &dyn FrameWritePolicy,
    frames: Vec<H2Frame>,
) -> Result<(), std::io::Error>
where
    S: AsyncWrite + Unpin,
{
    let groups = write_policy.group_frames(frames);
    for group in groups {
        let mut output = BytesMut::new();
        engine.encode_frames(&group, &mut output);
        if !output.is_empty() {
            stream.write_all(&output).await?;
            stream.flush().await?;
        }
    }
    Ok(())
}

/// Write the piggybacked first request directly to the stream.
async fn write_first_request<S>(
    stream: &mut S,
    engine: &mut H2Engine,
    write_policy: &dyn FrameWritePolicy,
    pending: &mut HashMap<u32, PendingStream>,
    first_req: FirstRequest,
) -> Result<(), DriverError>
where
    S: AsyncWrite + Unpin,
{
    let stream_id = engine.open_stream();
    let (parts, body) = first_req.request.into_parts();
    let priority = parts
        .extensions
        .get::<crate::profile::RequestPriority>()
        .copied();
    let native_req = crate::adapter::NativeH2Request {
        method: parts.method,
        uri: parts.uri,
        ordered_headers: parts
            .headers
            .iter()
            .filter(|(name, _)| !name.as_str().starts_with(':'))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_owned(), v.to_owned()))
            })
            .collect(),
        body,
        priority,
    };
    let frames = engine.build_native_request(stream_id, native_req);

    pending.insert(
        stream_id,
        PendingStream {
            headers_tx: Some(first_req.headers_tx),
            body_tx: first_req.body_tx,
        },
    );

    if let Err(e) = encode_and_write_frames(stream, engine, write_policy, frames).await {
        tracing::error!(error = %e, "h2.native.write_first_request_failed");
        if let Some(ps) = pending.remove(&stream_id) {
            if let Some(tx) = ps.headers_tx {
                let _ = tx.send(Err(DriverError::Io(e.to_string())));
            }
        }
        return Err(DriverError::Io(e.to_string()));
    }

    tracing::debug!(stream_id, "h2.native.first_request_sent");
    Ok(())
}

fn handle_event(event: H2Event, pending: &mut HashMap<u32, PendingStream>) {
    match event {
        H2Event::ResponseHeaders {
            stream_id,
            headers,
            end_stream,
        } => {
            if let Some(ps) = pending.get_mut(&stream_id) {
                let status = crate::hpack::get_status(&headers).unwrap_or(0);
                if let Some(tx) = ps.headers_tx.take() {
                    let _ = tx.send(Ok(NativeResponseHeaders { status, headers }));
                }
                if end_stream {
                    // No body — drop body_tx to signal EOF.
                    pending.remove(&stream_id);
                }
            }
        }
        H2Event::ResponseData {
            stream_id,
            data,
            end_stream,
        } => {
            if let Some(ps) = pending.get_mut(&stream_id) {
                if !data.is_empty() {
                    if let Err(e) = ps.body_tx.send(Ok(data)) {
                        tracing::warn!(stream_id, error = %e, "h2.native.body_receiver_dropped");
                    }
                }
                if end_stream {
                    pending.remove(&stream_id);
                }
            }
        }
        H2Event::StreamReset {
            stream_id,
            error_code,
        } => {
            if let Some(ps) = pending.remove(&stream_id) {
                let err = DriverError::StreamReset(error_code);
                if let Some(tx) = ps.headers_tx {
                    let _ = tx.send(Err(err.clone()));
                }
                let _ = ps.body_tx.send(Err(err));
            }
        }
        H2Event::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            if error_code != 0 {
                let msg = format!(
                    "error_code={error_code}, debug={}",
                    String::from_utf8_lossy(&debug_data)
                );
                notify_all_error(pending, DriverError::GoAway(msg));
            } else {
                // Graceful GOAWAY (error_code=0): only fail streams that
                // the server will NOT process (stream_id > last_stream_id).
                let stale: Vec<u32> = pending
                    .keys()
                    .filter(|&&sid| sid > last_stream_id)
                    .copied()
                    .collect();
                for sid in stale {
                    if let Some(ps) = pending.remove(&sid) {
                        if let Some(tx) = ps.headers_tx {
                            let _ = tx
                                .send(Err(DriverError::GoAway("stream rejected by GOAWAY".into())));
                        }
                    }
                }
            }
        }
        H2Event::Error(msg) => {
            tracing::error!(msg = %msg, "h2.native.engine_error");
        }
        _ => {}
    }
}

fn notify_all_error(pending: &mut HashMap<u32, PendingStream>, err: DriverError) {
    for (_, ps) in pending.drain() {
        if let Some(tx) = ps.headers_tx {
            let _ = tx.send(Err(err.clone()));
        }
        let _ = ps.body_tx.send(Err(err.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // DriverError — user-facing error messages
    // ====================================================================

    #[test]
    fn io_error_message() {
        let err = DriverError::Io("connection reset".to_string());
        assert_eq!(err.to_string(), "I/O error: connection reset");
    }

    #[test]
    fn protocol_error_message() {
        let err = DriverError::Protocol("invalid frame".to_string());
        assert_eq!(err.to_string(), "protocol error: invalid frame");
    }

    #[test]
    fn stream_reset_shows_error_code() {
        let err = DriverError::StreamReset(8); // CANCEL
        assert!(err.to_string().contains("error_code=8"));
    }

    #[test]
    fn goaway_message() {
        let err = DriverError::GoAway("server shutting down".to_string());
        assert!(err.to_string().contains("server shutting down"));
    }

    #[test]
    fn shutdown_and_channel_closed_messages() {
        assert_eq!(DriverError::Shutdown.to_string(), "connection shut down");
        assert_eq!(DriverError::ChannelClosed.to_string(), "channel closed");
    }

    #[test]
    fn io_error_converts_from_std() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let driver_err: DriverError = io_err.into();
        assert!(driver_err.to_string().contains("pipe broken"));
    }

    #[test]
    fn driver_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(DriverError::Shutdown);
        assert_eq!(err.to_string(), "connection shut down");
    }

    // ====================================================================
    // NativeSendRequest — connection readiness check
    // ====================================================================

    #[tokio::test]
    async fn ready_returns_ok_when_channel_open() {
        let (tx, _rx) = mpsc::channel::<DriverCommand>(1);
        let mut sender = NativeSendRequest { cmd_tx: tx };
        assert!(sender.ready().await.is_ok());
    }

    #[tokio::test]
    async fn ready_returns_err_when_connection_dropped() {
        let (tx, rx) = mpsc::channel::<DriverCommand>(1);
        drop(rx);
        let mut sender = NativeSendRequest { cmd_tx: tx };
        assert!(sender.ready().await.is_err());
    }

    #[tokio::test]
    async fn send_request_fails_when_driver_gone() {
        let (tx, rx) = mpsc::channel::<DriverCommand>(1);
        drop(rx);
        let mut sender = NativeSendRequest { cmd_tx: tx };
        let req = http::Request::builder()
            .uri("https://example.com/")
            .body(None)
            .unwrap();
        let result = sender.send_request(req).await;
        assert!(result.is_err());
    }

    // ====================================================================
    // FirstRequest — channel pair creation
    // ====================================================================

    #[test]
    fn first_request_creates_channel_pair() {
        let req = http::Request::builder()
            .uri("https://example.com/")
            .body(None)
            .unwrap();
        let (first_req, mut response) = FirstRequest::new(req);
        assert!(!first_req.headers_tx.is_closed());
        drop(first_req);
        assert!(response.headers_rx.try_recv().is_err());
    }

    // ====================================================================
    // NativeSendRequest — debug formatting
    // ====================================================================

    #[test]
    fn native_send_request_debug() {
        let (tx, _rx) = mpsc::channel::<DriverCommand>(1);
        let sender = NativeSendRequest { cmd_tx: tx };
        let debug = format!("{:?}", sender);
        assert!(debug.contains("NativeSendRequest"));
    }

    // ====================================================================
    // notify_all_error — notifying all pending streams on failure
    // ====================================================================

    #[test]
    fn notify_all_error_sends_to_all_pending() {
        let (h_tx, mut h_rx) = oneshot::channel();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel();

        let mut pending = HashMap::new();
        pending.insert(
            1,
            PendingStream {
                headers_tx: Some(h_tx),
                body_tx: b_tx,
            },
        );

        notify_all_error(&mut pending, DriverError::Shutdown);

        assert!(pending.is_empty());
        let header_result = h_rx.try_recv().unwrap();
        assert!(header_result.is_err());
        let body_result = b_rx.try_recv().unwrap();
        assert!(body_result.is_err());
    }
}
