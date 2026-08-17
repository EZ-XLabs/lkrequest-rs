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
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

// ─── Channel messages ────────────────────────────────────────────────────────

/// Command sent from NativeSendRequest to the driver task.
#[derive(Debug)]
pub(crate) enum DriverCommand {
    SendRequest {
        request_id: u64,
        request: Box<http::Request<Option<Bytes>>>,
        /// Sends back the response headers.
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        /// Sends body chunks as they arrive; dropped when stream ends.
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
    #[allow(dead_code)]
    SendNativeRequest {
        request_id: u64,
        request: Box<crate::adapter::NativeH2Request>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
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

/// Runtime controls for the native HTTP/2 connection driver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H2DriverConfig {
    /// Maximum requests that may wait for a remote stream slot.
    ///
    /// None keeps the default unbounded queue. A positive value applies
    /// asynchronous backpressure before additional requests enter the driver.
    pub max_pending_requests: Option<usize>,
}

/// Cloneable handle to send HTTP/2 requests through a native H2 connection.
#[derive(Clone)]
pub struct NativeSendRequest {
    cmd_tx: mpsc::Sender<DriverCommand>,
    cancel_tx: mpsc::UnboundedSender<u64>,
    next_request_id: Arc<AtomicU64>,
    pending_slots: Option<Arc<Semaphore>>,
}

struct RequestCancelGuard {
    request_id: u64,
    cancel_tx: mpsc::UnboundedSender<u64>,
    armed: bool,
}

impl RequestCancelGuard {
    fn new(request_id: u64, cancel_tx: mpsc::UnboundedSender<u64>) -> Self {
        Self {
            request_id,
            cancel_tx,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RequestCancelGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cancel_tx.send(self.request_id);
        }
    }
}

impl NativeSendRequest {
    async fn acquire_pending_permit(&self) -> Result<Option<OwnedSemaphorePermit>, DriverError> {
        match &self.pending_slots {
            Some(slots) => Arc::clone(slots)
                .acquire_owned()
                .await
                .map(Some)
                .map_err(|_| DriverError::Shutdown),
            None => Ok(None),
        }
    }

    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

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
        let pending_permit = self.acquire_pending_permit().await?;
        let request_id = self.next_request_id();
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();

        let cmd = DriverCommand::SendRequest {
            request_id,
            request: Box::new(request),
            headers_tx,
            body_tx,
            pending_permit,
        };

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| DriverError::ChannelClosed)?;

        let mut cancel_guard = RequestCancelGuard::new(request_id, self.cancel_tx.clone());
        let response = headers_rx.await.map_err(|_| DriverError::ChannelClosed)?;
        cancel_guard.disarm();
        let resp_headers = response?;

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
        let pending_permit = self.acquire_pending_permit().await?;
        let request_id = self.next_request_id();
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::unbounded_channel();

        let cmd = DriverCommand::SendNativeRequest {
            request_id,
            request: Box::new(request),
            headers_tx,
            body_tx,
            pending_permit,
        };

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| DriverError::ChannelClosed)?;

        let mut cancel_guard = RequestCancelGuard::new(request_id, self.cancel_tx.clone());
        let response = headers_rx.await.map_err(|_| DriverError::ChannelClosed)?;
        cancel_guard.disarm();
        let resp_headers = response?;

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

#[derive(Debug)]
enum QueuedRequest {
    Request {
        request_id: u64,
        request: Box<http::Request<Option<Bytes>>>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
    NativeRequest {
        request_id: u64,
        request: Box<crate::adapter::NativeH2Request>,
        headers_tx: oneshot::Sender<Result<NativeResponseHeaders, DriverError>>,
        body_tx: mpsc::UnboundedSender<Result<Bytes, DriverError>>,
        pending_permit: Option<OwnedSemaphorePermit>,
    },
}

impl QueuedRequest {
    fn is_canceled(&self) -> bool {
        match self {
            Self::Request {
                headers_tx,
                body_tx,
                ..
            }
            | Self::NativeRequest {
                headers_tx,
                body_tx,
                ..
            } => headers_tx.is_closed() && body_tx.is_closed(),
        }
    }

    fn request_id(&self) -> u64 {
        match self {
            Self::Request { request_id, .. } | Self::NativeRequest { request_id, .. } => {
                *request_id
            }
        }
    }
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
    spawn_driver_with_config(stream, profile, H2DriverConfig::default()).await
}

/// Spawn the connection driver task with runtime queue configuration.
pub async fn spawn_driver_with_config<S>(
    stream: S,
    profile: &H2Profile,
    config: H2DriverConfig,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request_and_config(stream, profile, None, None, config).await
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
    spawn_driver_with_first_request_and_config(
        stream,
        profile,
        behavior,
        None,
        H2DriverConfig::default(),
    )
    .await
}

/// Spawn the connection driver with an optional first request that is
/// written back-to-back with the connection preface (matching Chrome).
///
/// The caller creates a FirstRequest via FirstRequest::new() and keeps the
/// corresponding FirstRequestResponse to await the result.
pub async fn spawn_driver_with_first_request<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
    first_request: Option<FirstRequest>,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_driver_with_first_request_and_config(
        stream,
        profile,
        behavior,
        first_request,
        H2DriverConfig::default(),
    )
    .await
}

/// Spawn the connection driver with fingerprint behaviour, an optional first
/// request, and runtime pending-request backpressure configuration.
pub async fn spawn_driver_with_first_request_and_config<S>(
    stream: S,
    profile: &H2Profile,
    behavior: Option<H2Behavior>,
    first_request: Option<FirstRequest>,
    config: H2DriverConfig,
) -> Result<(NativeSendRequest, tokio::task::JoinHandle<()>), DriverError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if config.max_pending_requests == Some(0) {
        return Err(DriverError::Protocol(
            "max_pending_requests must be greater than zero".into(),
        ));
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<DriverCommand>(64);
    let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();
    let pending_slots = config
        .max_pending_requests
        .map(|max| Arc::new(Semaphore::new(max)));

    let behavior = behavior.unwrap_or_else(H2Behavior::default_behavior);

    tracing::info!(
        write_policy = ?behavior.write_policy,
        flow_control = ?behavior.flow_control,
        hpack_policy = ?behavior.hpack_policy,
        max_pending_requests = ?config.max_pending_requests,
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
        DriverRuntime {
            cmd_rx,
            cancel_rx,
            write_policy,
            ready_tx,
            first_request,
            pending_slots: pending_slots.clone(),
        },
    ));

    ready_rx
        .await
        .map_err(|_| DriverError::ChannelClosed)?
        .map_err(|e| DriverError::Io(e.to_string()))?;

    Ok((
        NativeSendRequest {
            cmd_tx,
            cancel_tx,
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending_slots,
        },
        handle,
    ))
}

struct DriverRuntime {
    cmd_rx: mpsc::Receiver<DriverCommand>,
    cancel_rx: mpsc::UnboundedReceiver<u64>,
    write_policy: Box<dyn FrameWritePolicy>,
    ready_tx: oneshot::Sender<Result<(), DriverError>>,
    first_request: Option<FirstRequest>,
    pending_slots: Option<Arc<Semaphore>>,
}

struct PendingSlotsCloseGuard(Option<Arc<Semaphore>>);

impl Drop for PendingSlotsCloseGuard {
    fn drop(&mut self) {
        if let Some(slots) = &self.0 {
            slots.close();
        }
    }
}

async fn driver_loop<S>(
    mut stream: S,
    mut engine: H2Engine,
    preface_frames: Vec<H2Frame>,
    runtime: DriverRuntime,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let DriverRuntime {
        mut cmd_rx,
        mut cancel_rx,
        write_policy,
        ready_tx,
        first_request,
        pending_slots,
    } = runtime;
    let _pending_slots_guard = PendingSlotsCloseGuard(pending_slots);

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
    let mut waiting: VecDeque<QueuedRequest> = VecDeque::new();

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
    let mut cancel_rx_open = true;
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

            cancelled = cancel_rx.recv(), if cancel_rx_open => {
                match cancelled {
                    Some(request_id) => {
                        remove_waiting_request(&mut waiting, request_id);
                    }
                    None => cancel_rx_open = false,
                }
            }

            result = stream.read_buf(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        let error = DriverError::Io("connection closed".into());
                        notify_all_error(&mut pending, error.clone());
                        notify_waiting_error(&mut waiting, error);
                        break;
                    }
                    Ok(_n) => {
                        let (mut events, outbound_frames) = engine.process(&mut read_buf);

                        if !outbound_frames.is_empty() {
                            if let Err(e) = encode_and_write_frames(
                                &mut stream, &engine, &*write_policy, outbound_frames,
                            ).await {
                                let error = DriverError::Io(e.to_string());
                                tracing::error!(error = %error, "h2.native.write_error");
                                notify_all_error(&mut pending, error.clone());
                                notify_waiting_error(&mut waiting, error);
                                break;
                            }
                        }

                        for event in events.drain(..) {
                            handle_event(event, &mut pending);
                        }

                        engine.recycle_buffers(events, Vec::new());
                    }
                    Err(e) => {
                        let error = DriverError::Io(e.to_string());
                        notify_all_error(&mut pending, error.clone());
                        notify_waiting_error(&mut waiting, error);
                        break;
                    }
                }
            }

            cmd = cmd_rx.recv(), if !shutdown => {
                match cmd {
                    Some(DriverCommand::SendRequest {
                        request_id,
                        request,
                        headers_tx,
                        body_tx,
                        pending_permit,
                    }) => {
                        let request = QueuedRequest::Request {
                            request_id,
                            request,
                            headers_tx,
                            body_tx,
                            pending_permit,
                        };
                        if !request.is_canceled() {
                            waiting.push_back(request);
                        }
                    }
                    Some(DriverCommand::SendNativeRequest {
                        request_id,
                        request,
                        headers_tx,
                        body_tx,
                        pending_permit,
                    }) => {
                        let request = QueuedRequest::NativeRequest {
                            request_id,
                            request,
                            headers_tx,
                            body_tx,
                            pending_permit,
                        };
                        if !request.is_canceled() {
                            waiting.push_back(request);
                        }
                    }
                    Some(DriverCommand::Shutdown) | None => {
                        shutdown = true;
                        if pending.is_empty() && waiting.is_empty() {
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
                notify_waiting_error(&mut waiting, DriverError::Shutdown);
                break;
            }
        }

        if let Err(error) = dispatch_waiting_requests(
            &mut stream,
            &mut engine,
            &*write_policy,
            &mut pending,
            &mut waiting,
        )
        .await
        {
            tracing::error!(error = %error, "h2.native.write_error");
            notify_all_error(&mut pending, error.clone());
            notify_waiting_error(&mut waiting, error);
            break;
        }

        if shutdown && pending.is_empty() && waiting.is_empty() {
            break;
        }
    }

    tracing::debug!("h2.native.driver_exited");
}

async fn dispatch_waiting_requests<S>(
    stream: &mut S,
    engine: &mut H2Engine,
    write_policy: &dyn FrameWritePolicy,
    pending: &mut HashMap<u32, PendingStream>,
    waiting: &mut VecDeque<QueuedRequest>,
) -> Result<(), DriverError>
where
    S: AsyncWrite + Unpin,
{
    if engine.is_goaway() {
        notify_waiting_error(
            waiting,
            DriverError::GoAway("connection is draining".into()),
        );
        return Ok(());
    }

    while engine.can_open_stream() {
        let Some(request) = waiting.pop_front() else {
            break;
        };
        if request.is_canceled() {
            continue;
        }

        let stream_id = engine.open_stream();
        let (frames, headers_tx, body_tx, pending_permit) = match request {
            QueuedRequest::Request {
                request,
                headers_tx,
                body_tx,
                pending_permit,
                ..
            } => (
                engine.build_request(stream_id, *request),
                headers_tx,
                body_tx,
                pending_permit,
            ),
            QueuedRequest::NativeRequest {
                request,
                headers_tx,
                body_tx,
                pending_permit,
                ..
            } => (
                engine.build_native_request(stream_id, *request),
                headers_tx,
                body_tx,
                pending_permit,
            ),
        };
        drop(pending_permit);

        pending.insert(
            stream_id,
            PendingStream {
                headers_tx: Some(headers_tx),
                body_tx,
            },
        );

        if let Err(error) = encode_and_write_frames(stream, engine, write_policy, frames).await {
            let error = DriverError::Io(error.to_string());
            if let Some(pending_stream) = pending.remove(&stream_id) {
                if let Some(headers_tx) = pending_stream.headers_tx {
                    let _ = headers_tx.send(Err(error.clone()));
                }
                let _ = pending_stream.body_tx.send(Err(error.clone()));
            }
            return Err(error);
        }
    }

    Ok(())
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

/// Whether `status` is a 1xx informational (interim) status code.
///
/// Per RFC 9110 §15.2 / RFC 9113 §8.1 an informational response
/// (100 Continue, 103 Early Hints, …) is one or more HEADERS blocks that
/// *precede* the final response — it is never the final response itself. A
/// conforming client must keep reading until a final (non-1xx) HEADERS block
/// arrives.
fn is_interim_status(status: u16) -> bool {
    (100..200).contains(&status)
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

                // 1xx interim responses (e.g. 103 Early Hints, which servers
                // like Cloudflare send ahead of the final 200) are NOT the
                // final response. Skip the interim HEADERS block and keep
                // `headers_tx` in place so the subsequent final (non-1xx)
                // HEADERS is delivered to the caller instead.
                //
                // An interim response must not carry END_STREAM (RFC 9113
                // §8.1), so `end_stream` is intentionally ignored here; the
                // pending stream is left open to await the final response.
                if is_interim_status(status) {
                    tracing::debug!(stream_id, status, "h2.native.interim_response_skipped");
                    return;
                }

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

fn remove_waiting_request(waiting: &mut VecDeque<QueuedRequest>, request_id: u64) -> bool {
    let Some(index) = waiting
        .iter()
        .position(|request| request.request_id() == request_id)
    else {
        return false;
    };
    waiting.remove(index);
    true
}

fn notify_waiting_error(waiting: &mut VecDeque<QueuedRequest>, err: DriverError) {
    for request in waiting.drain(..) {
        match request {
            QueuedRequest::Request {
                headers_tx,
                body_tx,
                ..
            }
            | QueuedRequest::NativeRequest {
                headers_tx,
                body_tx,
                ..
            } => {
                let _ = headers_tx.send(Err(err.clone()));
                let _ = body_tx.send(Err(err.clone()));
            }
        }
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
    use std::time::Duration;

    fn test_sender(
        cmd_tx: mpsc::Sender<DriverCommand>,
        max_pending_requests: Option<usize>,
    ) -> NativeSendRequest {
        let (cancel_tx, _cancel_rx) = mpsc::unbounded_channel();
        NativeSendRequest {
            cmd_tx,
            cancel_tx,
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending_slots: max_pending_requests.map(|max| Arc::new(Semaphore::new(max))),
        }
    }

    fn request(path: &str) -> http::Request<Option<Bytes>> {
        http::Request::builder()
            .uri(format!("https://example.test/{path}"))
            .body(None)
            .unwrap()
    }

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
        let mut sender = test_sender(tx, None);
        assert!(sender.ready().await.is_ok());
    }

    #[tokio::test]
    async fn ready_returns_err_when_connection_dropped() {
        let (tx, rx) = mpsc::channel::<DriverCommand>(1);
        drop(rx);
        let mut sender = test_sender(tx, None);
        assert!(sender.ready().await.is_err());
    }

    #[tokio::test]
    async fn send_request_fails_when_driver_gone() {
        let (tx, rx) = mpsc::channel::<DriverCommand>(1);
        drop(rx);
        let mut sender = test_sender(tx, None);
        let req = http::Request::builder()
            .uri("https://example.com/")
            .body(None)
            .unwrap();
        let result = sender.send_request(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn driver_config_defaults_to_unbounded_pending_requests() {
        assert_eq!(H2DriverConfig::default().max_pending_requests, None);
    }

    #[tokio::test]
    async fn zero_pending_request_limit_is_rejected() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let result = spawn_driver_with_config(
            client_io,
            &crate::profile::chrome_146_h2(),
            H2DriverConfig {
                max_pending_requests: Some(0),
            },
        )
        .await;
        assert!(matches!(result, Err(DriverError::Protocol(_))));
    }

    #[tokio::test]
    async fn bounded_pending_requests_apply_async_backpressure() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<DriverCommand>(4);
        let sender = test_sender(cmd_tx, Some(1));

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("first")).await }
        });
        let first_command = tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("second")).await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), cmd_rx.recv())
                .await
                .is_err(),
            "second request entered the driver before a pending permit was released"
        );

        drop(first_command);
        let second_command = tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();
        drop(second_command);

        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn cancellation_removes_waiting_request_and_releases_backpressure() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_ready_tx, server_ready_rx) = oneshot::channel();
        let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
        let (release_first_tx, release_first_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.max_concurrent_streams(1);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
            let mut ping_pong = connection.ping_pong().unwrap();
            let ping = ping_pong.ping(h2::Ping::opaque());
            tokio::pin!(ping);
            tokio::select! {
                result = &mut ping => { result.unwrap(); }
                request = connection.accept() => {
                    panic!("request arrived before server SETTINGS were observed: {request:?}");
                }
            }
            let _ = server_ready_tx.send(());

            let (_first_request, mut first_response) = connection.accept().await.unwrap().unwrap();
            let _ = first_accepted_tx.send(());
            let _ = release_first_rx.await;
            first_response
                .send_response(http::Response::new(()), true)
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(50), connection.accept()).await;
        });

        let profile = crate::profile::chrome_146_h2();
        let (sender, driver_task) = spawn_driver_with_config(
            client_io,
            &profile,
            H2DriverConfig {
                max_pending_requests: Some(1),
            },
        )
        .await
        .unwrap();
        let pending_slots = sender.pending_slots.as_ref().unwrap().clone();
        server_ready_rx.await.unwrap();

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("first")).await }
        });
        first_accepted_rx.await.unwrap();

        let second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move { sender.send_request(request("second")).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pending_slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        second_task.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while pending_slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled queued request did not release its pending permit");

        release_first_tx.send(()).unwrap();
        first_task.await.unwrap().unwrap();
        server_task.await.unwrap();
        driver_task.abort();
    }

    #[tokio::test]
    async fn requests_wait_for_remote_stream_capacity() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_ready_tx, server_ready_rx) = oneshot::channel();
        let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
        let (release_first_tx, release_first_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.max_concurrent_streams(1);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
            let mut ping_pong = connection.ping_pong().unwrap();
            let ping = ping_pong.ping(h2::Ping::opaque());
            tokio::pin!(ping);
            tokio::select! {
                result = &mut ping => { result.unwrap(); }
                request = connection.accept() => {
                    panic!("request arrived before server SETTINGS were observed: {request:?}");
                }
            }
            let _ = server_ready_tx.send(());

            let (_first_request, mut first_response) = connection.accept().await.unwrap().unwrap();
            let _ = first_accepted_tx.send(());
            let _ = release_first_rx.await;
            first_response
                .send_response(http::Response::new(()), true)
                .unwrap();

            let (_second_request, mut second_response) =
                connection.accept().await.unwrap().unwrap();
            second_response
                .send_response(http::Response::new(()), true)
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_millis(50), connection.accept()).await;
        });

        let profile = crate::profile::chrome_146_h2();
        let (sender, driver_task) = spawn_driver(client_io, &profile).await.unwrap();
        server_ready_rx.await.unwrap();

        let first_task = tokio::spawn({
            let mut sender = sender.clone();
            async move {
                sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://example.test/first")
                            .body(None)
                            .unwrap(),
                    )
                    .await
            }
        });
        first_accepted_rx.await.unwrap();

        let mut second_task = tokio::spawn({
            let mut sender = sender.clone();
            async move {
                sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://example.test/second")
                            .body(None)
                            .unwrap(),
                    )
                    .await
            }
        });

        if let Ok(result) = tokio::time::timeout(Duration::from_millis(50), &mut second_task).await
        {
            panic!(
                "second request must wait while the only remote stream slot is occupied: {result:?}"
            );
        }

        release_first_tx.send(()).unwrap();
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
        server_task.await.unwrap();
        driver_task.abort();
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
        let sender = test_sender(tx, None);
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

    // ====================================================================
    // handle_event — 1xx interim responses (100 Continue / 103 Early Hints)
    // must be skipped; the final (non-1xx) response is what reaches the caller.
    // Regression: Cloudflare emits 103 Early Hints before its 200, and the
    // native driver used to surface the 103 as the final response.
    // ====================================================================

    fn status_headers_event(stream_id: u32, status: u16, end_stream: bool) -> H2Event {
        H2Event::ResponseHeaders {
            stream_id,
            headers: vec![(":status".to_string(), status.to_string())],
            end_stream,
        }
    }

    type HeadersRx = oneshot::Receiver<Result<NativeResponseHeaders, DriverError>>;
    type BodyRx = mpsc::UnboundedReceiver<Result<Bytes, DriverError>>;

    fn pending_with_channels() -> (HashMap<u32, PendingStream>, HeadersRx, BodyRx) {
        let (h_tx, h_rx) = oneshot::channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let mut pending = HashMap::new();
        pending.insert(
            1,
            PendingStream {
                headers_tx: Some(h_tx),
                body_tx: b_tx,
            },
        );
        (pending, h_rx, b_rx)
    }

    #[test]
    fn is_interim_status_classifies_1xx_only() {
        assert!(is_interim_status(100));
        assert!(is_interim_status(103));
        assert!(is_interim_status(199));
        assert!(!is_interim_status(200));
        assert!(!is_interim_status(204));
        assert!(!is_interim_status(304));
        assert!(!is_interim_status(500));
        // Missing/unparsed :status maps to 0 upstream — not interim.
        assert!(!is_interim_status(0));
    }

    #[test]
    fn interim_103_is_skipped_and_final_200_delivered() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();

        // 103 Early Hints arrives first — must NOT be delivered as the
        // response, and the stream must stay pending awaiting the final one.
        handle_event(status_headers_event(1, 103, false), &mut pending);
        assert!(
            h_rx.try_recv().is_err(),
            "103 interim response must not be surfaced as the final response"
        );
        assert!(
            pending.contains_key(&1),
            "stream must remain pending after an interim 103"
        );

        // Final 200 arrives — this is what the caller receives.
        handle_event(status_headers_event(1, 200, false), &mut pending);
        let delivered = h_rx
            .try_recv()
            .expect("final 200 headers must be delivered")
            .expect("delivered headers must be Ok");
        assert_eq!(delivered.status, 200);
    }

    #[test]
    fn multiple_interim_blocks_then_final() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();

        // A server may emit several 1xx blocks (100 Continue + repeated
        // 103 Early Hints) before the final response.
        handle_event(status_headers_event(1, 100, false), &mut pending);
        handle_event(status_headers_event(1, 103, false), &mut pending);
        handle_event(status_headers_event(1, 103, false), &mut pending);
        assert!(h_rx.try_recv().is_err());
        assert!(pending.contains_key(&1));

        // Final 204 with END_STREAM (no body) — delivered and stream removed.
        handle_event(status_headers_event(1, 204, true), &mut pending);
        let delivered = h_rx.try_recv().unwrap().unwrap();
        assert_eq!(delivered.status, 204);
        assert!(
            !pending.contains_key(&1),
            "END_STREAM on the final headers must remove the pending stream"
        );
    }

    #[test]
    fn trailing_headers_after_final_are_ignored() {
        let (mut pending, mut h_rx, _b_rx) = pending_with_channels();

        // Final headers (body follows).
        handle_event(status_headers_event(1, 200, false), &mut pending);
        assert_eq!(h_rx.try_recv().unwrap().unwrap().status, 200);

        // HTTP trailers arrive as a HEADERS block with no :status and
        // END_STREAM set. They must not re-deliver headers or panic, and the
        // stream is cleaned up.
        let trailers = H2Event::ResponseHeaders {
            stream_id: 1,
            headers: vec![("grpc-status".to_string(), "0".to_string())],
            end_stream: true,
        };
        handle_event(trailers, &mut pending);
        assert!(!pending.contains_key(&1));
    }

    // ====================================================================
    // Full-stack regression: a local H2 server that emits 103 then 200.
    // Drives the real client driver against a hand-rolled server over an
    // in-memory duplex stream and asserts the caller sees the final 200.
    // ====================================================================

    /// Frame a raw HTTP/2 frame (9-byte header + payload).
    fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut buf = Vec::with_capacity(9 + len);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
        buf.push(frame_type);
        buf.push(flags);
        buf.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// HPACK "Literal Header Field without Indexing — Indexed Name" (`0000 NNNN`).
    /// `:status` is static-table index 8; values here are short (<128, no Huffman).
    fn hpack_indexed_name(name_index: u8, value: &str) -> Vec<u8> {
        let mut out = vec![name_index & 0x0f];
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
        out
    }

    /// HPACK "Literal Header Field without Indexing — New Name" (`0000 0000`).
    fn hpack_new_name(name: &str, value: &str) -> Vec<u8> {
        let mut out = vec![0x00];
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
        out
    }

    /// Minimal fake H2 server: sends SETTINGS, waits for the client's request
    /// HEADERS, then replies 103 Early Hints (with a preload Link header)
    /// followed by the final 200 + "ok" body. Keeps reading until the client
    /// closes so all client-side outbound writes succeed.
    async fn fake_server_103_then_200<S>(mut server: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        const HEADERS: u8 = 0x1;
        const SETTINGS: u8 = 0x4;
        const DATA: u8 = 0x0;
        const END_STREAM: u8 = 0x1;
        const END_HEADERS: u8 = 0x4;

        // Our (empty) SETTINGS is the server's first frame.
        server
            .write_all(&h2_frame(SETTINGS, 0, 0, &[]))
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Skip the 24-byte client connection preface.
        let mut preface = [0u8; 24];
        server.read_exact(&mut preface).await.unwrap();

        // Read frames until the client's request HEADERS; capture its stream id.
        // Frame header layout (RFC 9113 §4.1): [0..3] length, [3] type,
        // [4] flags, [5..9] R-bit + 31-bit stream id.
        let sid = loop {
            let mut hdr = [0u8; 9];
            server.read_exact(&mut hdr).await.unwrap();
            let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
            let ftype = hdr[3];
            let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
            let mut payload = vec![0u8; len];
            server.read_exact(&mut payload).await.unwrap();
            if ftype == HEADERS {
                break sid;
            }
        };

        // 103 Early Hints (interim) carrying a preload Link header.
        let mut block_103 = hpack_indexed_name(8, "103");
        block_103.extend(hpack_new_name("link", "</s.css>; rel=preload"));
        server
            .write_all(&h2_frame(HEADERS, END_HEADERS, sid, &block_103))
            .await
            .unwrap();

        // Final 200 with a marker header.
        let mut block_200 = hpack_indexed_name(8, "200");
        block_200.extend(hpack_new_name("x-final", "yes"));
        server
            .write_all(&h2_frame(HEADERS, END_HEADERS, sid, &block_200))
            .await
            .unwrap();

        // Body + END_STREAM.
        server
            .write_all(&h2_frame(DATA, END_STREAM, sid, b"ok"))
            .await
            .unwrap();
        server.flush().await.unwrap();

        // Keep the connection open (draining client frames) until the client
        // shuts the connection down, so client-side writes never hit a broken
        // pipe before its read loop dispatches our response events.
        let mut scratch = [0u8; 512];
        while let Ok(n) = server.read(&mut scratch).await {
            if n == 0 {
                break;
            }
        }
    }

    #[tokio::test]
    async fn early_hints_103_skipped_end_to_end() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_server_103_then_200(server_io));

        let profile = crate::profile::chrome_144_h2();
        let (mut sender, task) = spawn_driver(client_io, &profile).await.unwrap();

        let req = http::Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(None)
            .unwrap();

        // Timeout guards so a future regression fails fast instead of hanging CI.
        let (headers, mut body_rx) =
            tokio::time::timeout(std::time::Duration::from_secs(10), sender.send_request(req))
                .await
                .expect("send_request timed out — final response was never delivered")
                .unwrap();

        // The caller must see the final 200, not the interim 103.
        assert_eq!(
            headers.status, 200,
            "expected final 200, got interim status {}",
            headers.status
        );
        // Final response headers pass through; interim Link header does not leak.
        assert!(
            headers
                .headers
                .iter()
                .any(|(n, v)| n == "x-final" && v == "yes"),
            "final response headers should be present"
        );
        assert!(
            !headers.headers.iter().any(|(n, _)| n == "link"),
            "interim 103 Early Hints headers must not leak into the final response"
        );

        // Body reads "ok" then EOF.
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), body_rx.recv())
            .await
            .expect("body recv timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&chunk[..], b"ok");
        assert!(body_rx.recv().await.is_none());

        // Shut the client driver down so the server task can finish.
        drop(sender);
        let _ = task.await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server task timed out");
    }
}
