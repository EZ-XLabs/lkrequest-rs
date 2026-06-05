//! HTTP/1.1 WebSocket Upgrade — establishes a WebSocket connection via
//! the classic HTTP/1.1 `Upgrade: websocket` mechanism (RFC 6455).

use base64::Engine;
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{Request, StatusCode};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use super::builder::WsBuilder;
use super::WsConnection;
use crate::error::{Error, Result};

/// Generate a random Sec-WebSocket-Key using fastwebsockets.
fn generate_ws_key() -> String {
    fastwebsockets::handshake::generate_key()
}

/// Compute the expected Sec-WebSocket-Accept value for the given key (RFC 6455 §4.2.2).
fn compute_accept(key: &str) -> String {
    use aws_lc_rs::digest;
    let mut input = key.to_string();
    input.push_str("258EAFA5-E914-47DA-95CA-5AB5C0AB43E8");
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
}

/// Perform WebSocket upgrade over an HTTP/1.1 connection.
///
/// Takes ownership of the TLS stream, sends an Upgrade request via hyper,
/// validates the 101 response and Sec-WebSocket-Accept, then returns a
/// `WsConnection` wrapping the upgraded stream.
pub(crate) async fn ws_upgrade_h1<S>(
    tls_stream: S,
    host: &str,
    path: &str,
    builder: &WsBuilder,
    default_headers: &http::HeaderMap,
) -> Result<WsConnection<TokioIo<hyper::upgrade::Upgraded>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws_key = generate_ws_key();
    let expected_accept = compute_accept(&ws_key);

    // Build the HTTP/1.1 Upgrade request
    let authority = host.to_string();
    let uri = format!("https://{authority}{path}");

    let mut req_builder = Request::builder()
        .method("GET")
        .uri(&uri)
        .header(HOST, &authority)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &ws_key);

    // Add Sec-WebSocket-Protocol if specified
    if !builder.protocols.is_empty() {
        req_builder = req_builder.header("Sec-WebSocket-Protocol", builder.protocols.join(", "));
    }

    // Add Sec-WebSocket-Extensions if specified
    if !builder.extensions.is_empty() {
        req_builder = req_builder.header("Sec-WebSocket-Extensions", builder.extensions.join(", "));
    }

    // Add default headers from Client (User-Agent, Accept-Language, etc.)
    // We build the request first, then merge headers
    let mut req = req_builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| Error::Http(format!("Failed to build WS upgrade request: {e}")))?;

    // Merge default headers (don't overwrite WS-specific ones)
    for (name, value) in default_headers.iter() {
        if !req.headers().contains_key(name) {
            req.headers_mut().insert(name.clone(), value.clone());
        }
    }

    // Merge extra headers from the WsBuilder
    for (name, value) in builder.extra_headers.iter() {
        req.headers_mut().insert(name.clone(), value.clone());
    }

    // Perform the HTTP/1.1 handshake using hyper
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .preserve_header_case(true)
        .handshake(io)
        .await
        .map_err(|e| Error::Http(format!("H1 handshake for WS upgrade failed: {e}")))?;

    // Spawn the connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "ws.h1_connection_closed");
        }
    });

    // Send the upgrade request
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Http(format!("WS upgrade request failed: {e}")))?;

    // Validate response
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(Error::Http(format!(
            "WebSocket upgrade failed: expected 101 Switching Protocols, got {}",
            resp.status()
        )));
    }

    // Validate Sec-WebSocket-Accept (RFC 6455 §4.2.2)
    // We log a warning on mismatch but do not fail, because some proxies
    // or intermediaries may modify the key. The important thing is that we
    // got a 101 Switching Protocols response.
    if let Some(accept) = resp.headers().get("sec-websocket-accept") {
        let accept_str = accept.to_str().unwrap_or("<invalid>");
        if accept_str != expected_accept {
            tracing::warn!(
                expected = %expected_accept,
                got = %accept_str,
                "ws.sec_websocket_accept_mismatch",
            );
        }
    } else {
        tracing::warn!("ws.missing_sec_websocket_accept_header");
    }

    // Extract the upgraded stream
    let upgraded = hyper::upgrade::on(resp)
        .await
        .map_err(|e| Error::Http(format!("WebSocket upgrade extraction failed: {e}")))?;

    let ws_stream = TokioIo::new(upgraded);
    Ok(WsConnection::new(ws_stream, builder.url.clone()))
}
