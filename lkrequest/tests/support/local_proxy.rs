//! Embedded HTTP CONNECT proxy for Tier-0 proxy integration tests.
//!
//! Supports:
//! - Plain HTTP CONNECT tunnelling (forwards TCP to any target)
//! - Optional Basic auth (`Proxy-Authorization` header)
//! - Configurable rejection (always-reject mode for error testing)

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Configuration for the local proxy server.
#[derive(Default)]
pub struct ProxyConfig {
    /// If set, only accept connections with this Basic auth.
    pub required_auth: Option<(String, String)>,
    /// If true, reject all CONNECT requests with 403.
    pub reject_all: bool,
}

/// Running local HTTP CONNECT proxy. Drop to stop.
pub struct LocalProxy {
    pub addr: SocketAddr,
    pub url: String,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Start a local HTTP CONNECT proxy on 127.0.0.1 with a random port.
pub async fn start_local_proxy(config: ProxyConfig) -> LocalProxy {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind proxy");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://127.0.0.1:{}", addr.port());

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let config = Arc::new(config);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let cfg = config.clone();
                    tokio::spawn(async move {
                        let _ = handle_proxy_connection(stream, &cfg).await;
                    });
                }
            }
        }
    });

    tokio::task::yield_now().await;

    LocalProxy {
        addr,
        url,
        shutdown: Some(shutdown_tx),
    }
}

/// Start a proxy that requires Basic auth.
pub async fn start_local_proxy_with_auth(username: &str, password: &str) -> LocalProxy {
    start_local_proxy(ProxyConfig {
        required_auth: Some((username.to_string(), password.to_string())),
        ..Default::default()
    })
    .await
}

/// Start a proxy that rejects all CONNECT requests.
pub async fn start_rejecting_proxy() -> LocalProxy {
    start_local_proxy(ProxyConfig {
        reject_all: true,
        ..Default::default()
    })
    .await
}

async fn handle_proxy_connection(
    stream: TcpStream,
    config: &ProxyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        reader.get_mut().write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let target = parts[1].to_string();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        headers.push(line);
    }

    if config.reject_all {
        let response = "HTTP/1.1 403 Forbidden\r\n\r\n";
        reader.get_mut().write_all(response.as_bytes()).await?;
        return Ok(());
    }

    if let Some((expected_user, expected_pass)) = &config.required_auth {
        let auth_header = headers
            .iter()
            .find(|h| h.to_ascii_lowercase().starts_with("proxy-authorization:"));

        let authenticated = if let Some(auth_line) = auth_header {
            let value = auth_line.split_once(':').map(|x| x.1).unwrap_or("").trim();
            if let Some(encoded) = value.strip_prefix("Basic ") {
                use base64::Engine;
                if let Ok(decoded) =
                    base64::engine::general_purpose::STANDARD.decode(encoded.trim())
                {
                    let decoded_str = String::from_utf8_lossy(&decoded);
                    let expected = format!("{expected_user}:{expected_pass}");
                    decoded_str == expected
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if !authenticated {
            let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
            reader.get_mut().write_all(response.as_bytes()).await?;
            return Ok(());
        }
    }

    let target_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(_) => {
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            reader.get_mut().write_all(response.as_bytes()).await?;
            return Ok(());
        }
    };

    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    reader.get_mut().write_all(response.as_bytes()).await?;

    let mut client_stream = reader.into_inner();
    let mut target_stream = target_stream;

    let (mut cr, mut cw) = client_stream.split();
    let (mut tr, mut tw) = target_stream.split();

    tokio::select! {
        r = tokio::io::copy(&mut cr, &mut tw) => { r?; }
        r = tokio::io::copy(&mut tr, &mut cw) => { r?; }
    }

    Ok(())
}
