//! End-to-end test: native H2 engine → real server → verify Akamai fingerprint.
//!
//! Originally from lkh2/tests/e2e_native.rs, moved here because the I/O
//! layer (TlsConnector) now lives in lkrequest.
//!
//! Requires network access and a local HTTP proxy (default 127.0.0.1:7897).
//! Override via `TEST_PROXY` env var.

#![cfg(feature = "h2-native")]

use lkh2::profile::*;
use lkrequest::TlsConnector;
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn proxy_addr() -> Option<String> {
    std::env::var("TEST_PROXY").ok()
}

const MAX_RETRIES: u32 = 3;

async fn tcp_connect(target_host: &str, target_port: u16) -> TcpStream {
    let mut last_err = String::new();
    for attempt in 1..=MAX_RETRIES {
        let result = match proxy_addr() {
            Some(ref proxy) => {
                let proxy_url: url::Url = proxy.parse().expect("invalid proxy URL");
                let proxy_host = proxy_url
                    .host_str()
                    .expect("proxy missing host")
                    .to_string();
                let proxy_port = proxy_url.port().unwrap_or(7897);

                let stream = match TcpStream::connect((&*proxy_host, proxy_port)).await {
                    Ok(s) => s,
                    Err(e) => {
                        last_err = format!("proxy connect: {e}");
                        if attempt < MAX_RETRIES {
                            eprintln!("  [retry {attempt}/{MAX_RETRIES}] {last_err}");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        continue;
                    }
                };

                proxy_tunnel(stream, target_host, target_port).await
            }
            None => TcpStream::connect((target_host, target_port))
                .await
                .map_err(|e| format!("direct connect: {e}")),
        };

        match result {
            Ok(stream) => return stream,
            Err(e) => {
                last_err = e;
                if attempt < MAX_RETRIES {
                    eprintln!("  [retry {attempt}/{MAX_RETRIES}] {last_err}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("tcp_connect to {target_host}:{target_port} failed after {MAX_RETRIES} attempts: {last_err}");
}

async fn proxy_tunnel(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    let connect_req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    );
    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| format!("send CONNECT: {e}"))?;

    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("read CONNECT response: {e}"))?;
    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.contains("200") {
        return Err(format!("proxy CONNECT failed: {response}"));
    }

    Ok(stream)
}

async fn native_h2_get(
    host: &str,
    tls_profile: lktls::profile::TlsProfile,
    h2_profile: H2Profile,
    user_agent: &str,
) -> serde_json::Value {
    let tcp = tcp_connect(host, 443).await;
    let connector = TlsConnector::new(tls_profile);
    let tls_stream = connector
        .connect(host, 443, tcp)
        .await
        .expect("TLS handshake failed");

    let h2_conn = lkh2::connect_h2_native(tls_stream, &h2_profile, None)
        .await
        .expect("H2 native connection failed");

    let sender = h2_conn.clone_sender();
    let ready = sender.ready().await.expect("H2 ready failed");

    let uri = format!("https://{host}/json");
    let request = http::Request::builder()
        .method("GET")
        .uri(&uri)
        .header("user-agent", user_agent)
        .header("accept", "application/json, text/plain, */*")
        .header("accept-language", "en-US,en;q=0.9")
        .body(())
        .unwrap();

    let (resp_future, _send_stream) = ready
        .send_request(request, true)
        .expect("send_request failed");

    let response = resp_future
        .await_response()
        .await
        .expect("await_response failed");

    let status = response.status().as_u16();
    assert_eq!(status, 200, "expected HTTP 200, got {status}");

    let mut recv = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = recv.data().await {
        let data = chunk.expect("body data error");
        body.extend_from_slice(&data);
    }

    serde_json::from_slice(&body).expect("response is not valid JSON")
}

#[tokio::test]
#[ignore = "requires network + proxy (set TEST_PROXY)"]
async fn test_native_chrome144_akamai() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lkh2=debug")
        .try_init();

    let json = native_h2_get(
        "tls.browserleaks.com",
        presets::chrome_144(),
        chrome_144_h2(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    ).await;

    let akamai_text = json["akamai_text"].as_str().expect("missing akamai_text");
    let akamai_hash = json["akamai_hash"].as_str().expect("missing akamai_hash");
    println!("Chrome 144 — Akamai text: {akamai_text}");
    println!("Chrome 144 — Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        "Chrome 144 Akamai text mismatch"
    );
    assert_eq!(
        akamai_hash, "52d84b11737d980aef856699f885ca86",
        "Chrome 144 Akamai hash mismatch"
    );
}

#[tokio::test]
#[ignore = "requires network + proxy (set TEST_PROXY)"]
async fn test_native_firefox147_akamai() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lkh2=debug")
        .try_init();

    let json = native_h2_get(
        "tls.browserleaks.com",
        presets::firefox_147(),
        firefox_147_h2(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
    )
    .await;

    let akamai_text = json["akamai_text"].as_str().expect("missing akamai_text");
    let akamai_hash = json["akamai_hash"].as_str().expect("missing akamai_hash");
    println!("Firefox 147 — Akamai text: {akamai_text}");
    println!("Firefox 147 — Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
        "Firefox 147 Akamai text mismatch"
    );
    assert_eq!(
        akamai_hash, "6ea73faa8fc5aac76bded7bd238f6433",
        "Firefox 147 Akamai hash mismatch"
    );
}

#[tokio::test]
#[ignore = "requires network + proxy (set TEST_PROXY)"]
async fn test_native_safari26_akamai() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lkh2=debug")
        .try_init();

    let json = native_h2_get(
        "tls.browserleaks.com",
        presets::safari_26(),
        safari_26_h2(),
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
    ).await;

    let akamai_text = json["akamai_text"].as_str().expect("missing akamai_text");
    let akamai_hash = json["akamai_hash"].as_str().expect("missing akamai_hash");
    println!("Safari 26 — Akamai text: {akamai_text}");
    println!("Safari 26 — Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
        "Safari 26 Akamai text mismatch"
    );
    assert_eq!(
        akamai_hash, "c52879e43202aeb92740be6e8c86ea96",
        "Safari 26 Akamai hash mismatch"
    );
}
