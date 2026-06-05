//! WebSocket support — fingerprint-consistent WebSocket connections.
//!
//! Provides WebSocket connectivity through HTTP/1.1 Upgrade with full TLS
//! fingerprint control.
//!
//! # Usage
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! use lkrequest::Client;
//! use lktls::profile::presets;
//!
//! let client = Client::builder()
//!     .fingerprint(presets::chrome_144())
//!     .build();
//! let session = client.session().build();
//!
//! let mut ws = session.websocket("wss://echo.websocket.events")
//!     .header("Origin", "https://echo.websocket.events")
//!     .connect()
//!     .await?;
//!
//! ws.send_text("hello").await?;
//! let msg = ws.recv().await?;
//! ws.close(None).await?;
//! # Ok(())
//! # }
//! ```

pub mod builder;
pub(crate) mod upgrade;

use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, Role, WebSocket};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};

/// A WebSocket message received from or sent to the peer.
#[derive(Debug, Clone)]
pub enum WsMessage {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping frame with optional payload.
    Ping(Vec<u8>),
    /// A pong frame with optional payload.
    Pong(Vec<u8>),
    /// A close frame with optional (code, reason).
    Close(Option<u16>, String),
}

/// An active WebSocket connection.
///
/// Wraps a `fastwebsockets::FragmentCollector` over an HTTP/1.1 upgraded
/// stream. Provides `send_text`, `send_binary`, `recv`, and `close` methods.
///
/// By default, incoming Ping frames are automatically answered with Pong
/// (`auto_pong` is enabled).
pub struct WsConnection<S: AsyncRead + AsyncWrite + Unpin> {
    inner: FragmentCollector<S>,
    url: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsConnection<S> {
    /// Create a new WsConnection wrapping a stream that has already completed
    /// the WebSocket handshake.
    pub(crate) fn new(stream: S, url: String) -> Self {
        let mut ws = WebSocket::after_handshake(stream, Role::Client);
        ws.set_auto_pong(true);
        ws.set_auto_close(true);
        ws.set_writev(false);
        let collector = FragmentCollector::new(ws);
        Self {
            inner: collector,
            url,
        }
    }

    /// Returns the URL of this WebSocket connection.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send a text message.
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        let frame = Frame::text(Payload::Borrowed(text.as_bytes()));
        self.inner
            .write_frame(frame)
            .await
            .map_err(|e| Error::Http(format!("WebSocket send_text error: {e}")))?;
        Ok(())
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        let frame = Frame::binary(Payload::Borrowed(data));
        self.inner
            .write_frame(frame)
            .await
            .map_err(|e| Error::Http(format!("WebSocket send_binary error: {e}")))?;
        Ok(())
    }

    /// Send a raw [`WsMessage`].
    pub async fn send(&mut self, msg: WsMessage) -> Result<()> {
        match msg {
            WsMessage::Text(s) => self.send_text(&s).await,
            WsMessage::Binary(b) => self.send_binary(&b).await,
            WsMessage::Ping(data) => {
                let frame = Frame::new(true, OpCode::Ping, None, Payload::Owned(data));
                self.inner
                    .write_frame(frame)
                    .await
                    .map_err(|e| Error::Http(format!("WebSocket send ping error: {e}")))?;
                Ok(())
            }
            WsMessage::Pong(data) => {
                let frame = Frame::new(true, OpCode::Pong, None, Payload::Owned(data));
                self.inner
                    .write_frame(frame)
                    .await
                    .map_err(|e| Error::Http(format!("WebSocket send pong error: {e}")))?;
                Ok(())
            }
            WsMessage::Close(code, reason) => self.close(code.map(|c| (c, reason.as_str()))).await,
        }
    }

    /// Receive the next message from the WebSocket.
    ///
    /// Ping frames are automatically answered with Pong when `auto_pong` is
    /// enabled (default). This method blocks until a data or close frame is
    /// received.
    pub async fn recv(&mut self) -> Result<WsMessage> {
        loop {
            let frame = self
                .inner
                .read_frame()
                .await
                .map_err(|e| Error::Http(format!("WebSocket recv error: {e}")))?;

            match frame.opcode {
                OpCode::Text => {
                    let text = String::from_utf8(frame.payload.to_vec())
                        .map_err(|e| Error::Http(format!("WebSocket invalid UTF-8: {e}")))?;
                    return Ok(WsMessage::Text(text));
                }
                OpCode::Binary => {
                    return Ok(WsMessage::Binary(frame.payload.to_vec()));
                }
                OpCode::Close => {
                    let (code, reason) = if frame.payload.len() >= 2 {
                        let code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                        let reason = String::from_utf8_lossy(&frame.payload[2..]).into_owned();
                        (Some(code), reason)
                    } else {
                        (None, String::new())
                    };
                    return Ok(WsMessage::Close(code, reason));
                }
                OpCode::Ping => {
                    // auto_pong handles this; yield Ping to caller anyway
                    return Ok(WsMessage::Ping(frame.payload.to_vec()));
                }
                OpCode::Pong => {
                    return Ok(WsMessage::Pong(frame.payload.to_vec()));
                }
                OpCode::Continuation => {
                    // FragmentCollector should reassemble; skip if leaked
                    continue;
                }
            }
        }
    }

    /// Close the WebSocket connection.
    ///
    /// Optionally send a close code and reason string. If `None`, sends a
    /// normal close (code 1000).
    pub async fn close(&mut self, close_info: Option<(u16, &str)>) -> Result<()> {
        let frame = if let Some((code, reason)) = close_info {
            Frame::close(code, reason.as_bytes())
        } else {
            Frame::close(1000, b"")
        };
        self.inner
            .write_frame(frame)
            .await
            .map_err(|e| Error::Http(format!("WebSocket close error: {e}")))?;
        Ok(())
    }
}
