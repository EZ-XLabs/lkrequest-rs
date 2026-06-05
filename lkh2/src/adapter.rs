//! Unified H2 sender for the native backend.
//!
//! The downstream call sequence:
//! 1. `sender.ready().await` → `Result<H2ReadySender>`
//! 2. `ready.send_request(req, end_stream)` → `(H2ResponseFuture, H2SendStream)`
//! 3. `send_stream.send_data(body, true)` (optional, if has body)
//! 4. `response_future.await_response()` → `http::Response<H2RecvStream>`
//! 5. `recv_stream.data().await` → `Option<Result<Bytes>>` (streaming!)
//! 6. `recv_stream.flow_control().release_capacity(len)`

use bytes::Bytes;

use tokio::sync::oneshot;

// ─── NativeH2Request ─────────────────────────────────────────────────────────

/// Internal request type for the native H2 backend.
/// Uses Vec instead of HeaderMap for deterministic header ordering.
#[derive(Debug)]
pub(crate) struct NativeH2Request {
    pub method: http::Method,
    pub uri: http::Uri,
    pub ordered_headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
    pub priority: Option<crate::profile::RequestPriority>,
}

// ─── H2 Sender (Clone, pool-compatible) ──────────────────────────────────────

/// Unified cloneable H2 sender for the connection pool.
#[derive(Clone)]
pub enum H2Sender {
    Native(crate::driver::NativeSendRequest),
}

impl H2Sender {
    /// Wait for the connection to be ready to accept a new request.
    pub async fn ready(self) -> Result<H2ReadySender, H2SendError> {
        match self {
            Self::Native(mut sender) => {
                sender.ready().await.map_err(H2SendError::from_native)?;
                Ok(H2ReadySender::Native(sender))
            }
        }
    }
}

impl std::fmt::Debug for H2Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(_) => write!(f, "H2Sender::Native"),
        }
    }
}

// ─── Ready Sender ────────────────────────────────────────────────────────────

pub enum H2ReadySender {
    Native(crate::driver::NativeSendRequest),
}

impl H2ReadySender {
    /// Send an HTTP/2 request.
    ///
    /// The actual network send is deferred to
    /// `H2ResponseFuture::await_response()`.  `H2SendStream::send_data()`
    /// stores the body in shared state so it can be included.
    pub fn send_request(
        self,
        request: http::Request<()>,
        end_stream: bool,
    ) -> Result<(H2ResponseFuture, H2SendStream), H2SendError> {
        match self {
            Self::Native(sender) => {
                let (body_tx, body_rx) = oneshot::channel::<Option<Bytes>>();
                Ok((
                    H2ResponseFuture::Native {
                        sender,
                        request: Box::new(Some(request)),
                        end_stream,
                        body_rx: Some(body_rx),
                    },
                    H2SendStream::Native {
                        body_tx: Some(body_tx),
                    },
                ))
            }
        }
    }
}

// ─── Response Future ─────────────────────────────────────────────────────────

pub enum H2ResponseFuture {
    Native {
        sender: crate::driver::NativeSendRequest,
        request: Box<Option<http::Request<()>>>,
        end_stream: bool,
        body_rx: Option<oneshot::Receiver<Option<Bytes>>>,
    },
}

impl H2ResponseFuture {
    /// Await the HTTP response headers and obtain a streaming body.
    pub async fn await_response(self) -> Result<http::Response<H2RecvStream>, H2SendError> {
        match self {
            Self::Native {
                mut sender,
                request,
                end_stream,
                body_rx,
            } => {
                let orig_req =
                    (*request).ok_or_else(|| H2SendError("request already consumed".into()))?;
                let body = if end_stream {
                    None
                } else {
                    match body_rx {
                        Some(rx) => rx.await.unwrap_or(None),
                        None => None,
                    }
                };
                let (parts, _) = orig_req.into_parts();

                let http_req = build_native_request(&parts, body);
                let (resp_headers, body_rx) = sender
                    .send_native_request(http_req)
                    .await
                    .map_err(H2SendError::from_native)?;

                let recv = H2RecvStream::Native { body_rx };
                build_native_response(resp_headers, recv)
            }
        }
    }
}

/// Await the first request's response (piggybacked on connection setup).
///
/// Converts a `FirstRequestResponse` into the same `http::Response<H2RecvStream>`
/// that the normal `H2ResponseFuture::await_response()` path produces.
pub async fn await_first_response(
    resp: crate::driver::FirstRequestResponse,
) -> Result<http::Response<H2RecvStream>, H2SendError> {
    let resp_headers = resp
        .headers_rx
        .await
        .map_err(|_| H2SendError("first request channel closed".into()))?
        .map_err(H2SendError::from_native)?;

    let recv = H2RecvStream::Native {
        body_rx: resp.body_rx,
    };
    build_native_response(resp_headers, recv)
}

fn build_native_request(parts: &http::request::Parts, body: Option<Bytes>) -> NativeH2Request {
    let ordered_headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(name, _)| !name.as_str().starts_with(':'))
        .filter_map(|(name, value)| match value.to_str() {
            Ok(v) => Some((name.as_str().to_owned(), v.to_owned())),
            Err(_) => {
                tracing::warn!(
                    header = %name,
                    "h2.native.non_utf8_header_value_skipped"
                );
                None
            }
        })
        .collect();

    let priority = parts
        .extensions
        .get::<crate::profile::RequestPriority>()
        .copied();

    NativeH2Request {
        method: parts.method.clone(),
        uri: parts.uri.clone(),
        ordered_headers,
        body,
        priority,
    }
}

fn build_native_response(
    resp_headers: crate::driver::NativeResponseHeaders,
    recv: H2RecvStream,
) -> Result<http::Response<H2RecvStream>, H2SendError> {
    let status = http::StatusCode::from_u16(resp_headers.status)
        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = http::Response::builder().status(status);
    for (name, value) in &resp_headers.headers {
        if name.starts_with(':') {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            http::header::HeaderName::try_from(name.as_str()),
            http::header::HeaderValue::from_str(value),
        ) {
            builder = builder.header(hn, hv);
        }
    }

    builder
        .body(recv)
        .map_err(|e| H2SendError(format!("failed to build response: {e}")))
}

// ─── Send Stream ─────────────────────────────────────────────────────────────

pub enum H2SendStream {
    Native {
        body_tx: Option<oneshot::Sender<Option<Bytes>>>,
    },
}

impl H2SendStream {
    pub fn send_data(&mut self, data: Bytes, _end_stream: bool) -> Result<(), H2SendError> {
        match self {
            Self::Native { body_tx } => {
                let tx = body_tx
                    .take()
                    .ok_or_else(|| H2SendError("body already sent".into()))?;
                tx.send(Some(data))
                    .map_err(|_| H2SendError("response future dropped".into()))
            }
        }
    }
}

impl Drop for H2SendStream {
    fn drop(&mut self) {
        match self {
            Self::Native { body_tx } => {
                if let Some(tx) = body_tx.take() {
                    let _ = tx.send(None);
                }
            }
        }
    }
}

// ─── Recv Stream ─────────────────────────────────────────────────────────────

pub enum H2RecvStream {
    Native {
        body_rx: tokio::sync::mpsc::UnboundedReceiver<Result<Bytes, crate::driver::DriverError>>,
    },
}

impl H2RecvStream {
    /// Read the next data chunk from the body.
    ///
    /// Returns `None` when the body is complete (EOF).
    pub async fn data(&mut self) -> Option<Result<Bytes, H2SendError>> {
        match self {
            Self::Native { body_rx } => match body_rx.recv().await {
                Some(Ok(data)) => Some(Ok(data)),
                Some(Err(e)) => Some(Err(H2SendError::from_native(e))),
                None => None,
            },
        }
    }

    pub fn flow_control(&mut self) -> H2FlowControl<'_> {
        H2FlowControl { stream: self }
    }
}

/// Flow control handle.
pub struct H2FlowControl<'a> {
    stream: &'a mut H2RecvStream,
}

impl H2FlowControl<'_> {
    pub fn release_capacity(&mut self, _amount: usize) -> Result<(), H2SendError> {
        match self.stream {
            H2RecvStream::Native { .. } => Ok(()),
        }
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct H2SendError(pub String);

impl H2SendError {
    fn from_native(e: crate::driver::DriverError) -> Self {
        Self(e.to_string())
    }
}

impl std::fmt::Display for H2SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for H2SendError {}

// ─── Unified H2Connection ───────────────────────────────────────────────────

/// Unified H2 connection.
pub struct UnifiedH2Connection {
    sender: H2Sender,
    conn_task: tokio::task::JoinHandle<()>,
    first_response: Option<crate::driver::FirstRequestResponse>,
}

impl UnifiedH2Connection {
    pub(crate) fn from_native(
        sender: crate::driver::NativeSendRequest,
        conn_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            sender: H2Sender::Native(sender),
            conn_task,
            first_response: None,
        }
    }

    pub(crate) fn from_native_with_first(
        sender: crate::driver::NativeSendRequest,
        conn_task: tokio::task::JoinHandle<()>,
        first_response: crate::driver::FirstRequestResponse,
    ) -> Self {
        Self {
            sender: H2Sender::Native(sender),
            conn_task,
            first_response: Some(first_response),
        }
    }

    /// Take the first request's response channels, if available.
    /// Only meaningful when a first request was piggybacked on connection setup.
    pub fn take_first_response(&mut self) -> Option<crate::driver::FirstRequestResponse> {
        self.first_response.take()
    }

    pub fn clone_sender(&self) -> H2Sender {
        self.sender.clone()
    }

    pub fn into_task(self) -> tokio::task::JoinHandle<()> {
        self.conn_task
    }
}
