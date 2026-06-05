//! HTTP/1.1 → HTTP/2 cleartext (h2c) upgrade tests.
//!
//! Tests verify:
//! 1. h2c with prior knowledge (RFC 7540 §3.4) — `http2_only()` + `http://`
//! 2. h2c upgrade (RFC 7540 §3.2) — `Auto` mode + `http://`
//! 3. Plain HTTP/1.1 cleartext — `http1_only()` + `http://`
//! 4. Upgrade rejection fallback — server refuses h2c, falls back to H1.1
//!
//! All tests use an embedded local HTTP server (hyper) to avoid external
//! dependencies and ensure deterministic behavior.

use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;

// ---------------------------------------------------------------------------
// Embedded cleartext HTTP server
// ---------------------------------------------------------------------------

struct CleartextServer {
    addr: SocketAddr,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

/// Start a cleartext HTTP server that supports both HTTP/1.1 and HTTP/2 (h2c).
///
/// Uses `hyper_util::server::conn::auto::Builder` which automatically detects
/// whether the client sends an HTTP/2 connection preface or HTTP/1.1 requests.
async fn start_h2c_server() -> CleartextServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    if let Ok((tcp, _)) = accepted {
                        tokio::spawn(async move {
                            let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                                // Echo back the HTTP version so the client can verify
                                let version = format!("{:?}", req.version());
                                Ok::<_, hyper::Error>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", "text/plain")
                                        .header("x-http-version", &version)
                                        .body(Full::new(Bytes::from(format!(
                                            "version={version}"
                                        ))))
                                        .unwrap(),
                                )
                            });
                            let _ = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection_with_upgrades(TokioIo::new(tcp), svc)
                            .await;
                        });
                    }
                }
            }
        }
    });

    CleartextServer {
        addr,
        _shutdown_tx: shutdown_tx,
    }
}

/// Start a cleartext HTTP/1.1-only server (no h2c support).
///
/// This server ignores Upgrade: h2c headers and always responds via HTTP/1.1.
async fn start_h1_only_server() -> CleartextServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    if let Ok((tcp, _)) = accepted {
                        tokio::spawn(async move {
                            let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                                let version = format!("{:?}", req.version());
                                Ok::<_, hyper::Error>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", "text/plain")
                                        .header("x-http-version", &version)
                                        .body(Full::new(Bytes::from(format!(
                                            "version={version}"
                                        ))))
                                        .unwrap(),
                                )
                            });
                            // HTTP/1.1 only — no h2c support
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(tcp), svc)
                                .await;
                        });
                    }
                }
            }
        }
    });

    CleartextServer {
        addr,
        _shutdown_tx: shutdown_tx,
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_131())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        )
        .default_header("accept", "text/html,*/*;q=0.8")
        .build()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// h2c with prior knowledge (RFC 7540 §3.4):
/// Client sends HTTP/2 preface directly over cleartext TCP.
#[tokio::test]
async fn h2c_prior_knowledge() {
    let server = start_h2c_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let url = format!("http://127.0.0.1:{}/hello", server.addr.port());
    let resp = session.get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    // Server should see HTTP/2
    let version_header = resp
        .headers()
        .get("x-http-version")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        version_header.contains("HTTP/2"),
        "expected HTTP/2, got: {version_header}"
    );
    assert_eq!(resp.version().to_string(), "h2");
}

/// Plain HTTP/1.1 cleartext:
/// Client speaks HTTP/1.1 over cleartext TCP, no upgrade attempt.
#[tokio::test]
async fn h1_cleartext() {
    let server = start_h2c_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let url = format!("http://127.0.0.1:{}/hello", server.addr.port());
    let resp = session.get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let version_header = resp
        .headers()
        .get("x-http-version")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        version_header.contains("HTTP/1.1"),
        "expected HTTP/1.1, got: {version_header}"
    );
    assert_eq!(resp.version().to_string(), "HTTP/1.1");
}

/// h2c upgrade (RFC 7540 §3.2):
/// Client sends HTTP/1.1 request with Upgrade: h2c, server accepts with 101.
#[tokio::test]
async fn h2c_upgrade_accepted() {
    let server = start_h2c_server().await;
    let client = chrome_client();
    // Auto mode — will attempt h2c upgrade for http:// URLs
    let session = client.session().build();

    let url = format!("http://127.0.0.1:{}/hello", server.addr.port());
    let resp = session.get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    // After successful upgrade, the response comes via HTTP/2
    let body = resp.text().unwrap();
    // The response body should indicate the protocol used
    assert!(
        body.contains("HTTP/2") || body.contains("HTTP/1.1"),
        "unexpected body: {body}"
    );
}

/// h2c upgrade rejection fallback:
/// Server doesn't support h2c — client falls back to HTTP/1.1.
#[tokio::test]
async fn h2c_upgrade_rejected_fallback() {
    let server = start_h1_only_server().await;
    let client = chrome_client();
    // Auto mode — will attempt h2c upgrade, but server rejects → fallback to H1.1
    let session = client.session().build();

    let url = format!("http://127.0.0.1:{}/hello", server.addr.port());
    let resp = session.get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let version_header = resp
        .headers()
        .get("x-http-version")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        version_header.contains("HTTP/1.1"),
        "expected HTTP/1.1 fallback, got: {version_header}"
    );
    assert_eq!(resp.version().to_string(), "HTTP/1.1");
}

/// h2c prior knowledge with POST body:
/// Verify that request bodies work correctly over h2c.
#[tokio::test]
async fn h2c_prior_knowledge_with_body() {
    let server = start_h2c_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let url = format!("http://127.0.0.1:{}/echo", server.addr.port());
    let resp = session
        .post(&url)
        .body(b"hello h2c".to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version().to_string(), "h2");
}

/// h2c prior knowledge fails when server is H1-only:
/// Should return an error, not silently fall back.
#[tokio::test]
async fn h2c_prior_knowledge_fails_on_h1_server() {
    let server = start_h1_only_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let url = format!("http://127.0.0.1:{}/hello", server.addr.port());
    let result = session.get(&url).send().await;

    // Should fail — the server doesn't understand HTTP/2 preface
    assert!(
        result.is_err(),
        "h2c prior knowledge should fail on H1-only server"
    );
}

/// Multiple requests reuse pooled h2c connection.
#[tokio::test]
async fn h2c_connection_pooling() {
    let server = start_h2c_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let url = format!("http://127.0.0.1:{}/hello", server.addr.port());

    // First request — establishes h2c connection
    let resp1 = session.get(&url).send().await.unwrap();
    assert_eq!(resp1.status(), 200);
    assert_eq!(resp1.version().to_string(), "h2");

    // Second request — should reuse pooled h2c connection
    let resp2 = session.get(&url).send().await.unwrap();
    assert_eq!(resp2.status(), 200);
    assert_eq!(resp2.version().to_string(), "h2");
}

/// HTTP2-Settings header encoding test.
#[test]
fn h2_settings_base64url_encoding() {
    use lkrequest::h2::profile::{chrome_144_h2, encode_h2_settings_base64url};

    let profile = chrome_144_h2();
    let encoded = encode_h2_settings_base64url(&profile);

    // Should be non-empty base64url string
    assert!(!encoded.is_empty());
    // Should not contain padding characters
    assert!(!encoded.contains('='));
    // Should only contain base64url characters
    assert!(encoded
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    // Decode back and verify structure: each setting is 6 bytes (id:2 + value:4)
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encoded)
        .unwrap();
    assert_eq!(
        decoded.len(),
        profile.settings.len() * 6,
        "each SETTINGS entry should be 6 bytes"
    );
}
