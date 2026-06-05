//! Embedded WSS (WebSocket over TLS) echo server for Tier-0 tests.
//!
//! - Accepts wss:// connections on 127.0.0.1 with a self-signed cert
//! - Echoes back text and binary messages
//! - Responds to close frames correctly

use std::net::SocketAddr;
use std::sync::Arc;

use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, Role, WebSocket};
use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

/// Running local WSS echo server. Drop to stop.
pub struct LocalWssServer {
    /// Base URL, e.g. `wss://127.0.0.1:12345`.
    pub url: String,
    pub port: u16,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for LocalWssServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

fn build_certified_key() -> CertifiedKey<KeyPair> {
    rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
        .expect("rcgen self-signed")
}

fn tls_acceptor(cert: &CertifiedKey<KeyPair>) -> TlsAcceptor {
    let cert_chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .expect("rustls server certificate");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

/// Compute the WebSocket accept key from the client key.
fn ws_accept_key(client_key: &str) -> String {
    use aws_lc_rs::digest;
    let mut input = client_key.trim().to_string();
    input.push_str("258EAFA5-E914-47DA-95CA-5AB5DC175B18");
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash.as_ref())
}

/// Handle a single WSS connection: manual HTTP/1.1 upgrade + echo loop.
async fn handle_wss_connection(
    tls_stream: TlsStream<tokio::net::TcpStream>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf_reader = BufReader::new(tls_stream);

    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let mut ws_key = String::new();
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("sec-websocket-key:") {
            ws_key = line
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
        }
    }

    if ws_key.is_empty() {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        buf_reader.get_mut().write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let accept = ws_accept_key(&ws_key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    );
    buf_reader.get_mut().write_all(response.as_bytes()).await?;

    let stream = buf_reader.into_inner();
    let ws = WebSocket::after_handshake(stream, Role::Server);
    let mut ws = FragmentCollector::new(ws);

    loop {
        let frame = match ws.read_frame().await {
            Ok(f) => f,
            Err(_) => break,
        };

        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                let echo = Frame::new(
                    true,
                    frame.opcode,
                    None,
                    Payload::Owned(frame.payload.to_vec()),
                );
                if ws.write_frame(echo).await.is_err() {
                    break;
                }
            }
            OpCode::Close => {
                let close = Frame::close(1000, b"");
                let _ = ws.write_frame(close).await;
                break;
            }
            OpCode::Ping => {
                let pong = Frame::pong(Payload::Owned(frame.payload.to_vec()));
                if ws.write_frame(pong).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Start a local WSS echo server.
pub async fn start_local_wss_server() -> LocalWssServer {
    let certified = build_certified_key();
    let acceptor = tls_acceptor(&certified);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind wss");
    let addr = listener.local_addr().expect("local_addr");
    let port = addr.port();
    let url = format!("wss://127.0.0.1:{port}");

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let acc = acceptor.clone();
                    tokio::spawn(async move {
                        let tls = match acc.accept(stream).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                        let _ = handle_wss_connection(tls).await;
                    });
                }
            }
        }
    });

    tokio::task::yield_now().await;

    LocalWssServer {
        url,
        port,
        shutdown: Some(shutdown_tx),
    }
}
