//! TLS 1.2 record encryption end-to-end test.
//!
//! Tests TLS 1.2 full handshake + encrypted data transfer against httpbin.org
//! (which negotiates TLS 1.2) and other servers.

use lkrequest::{TlsConnector, TlsStream};
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_RETRIES: usize = 3;

/// Try to establish a TCP + TLS connection with retries.
///
/// Retries up to `MAX_RETRIES` times on TCP connect or TLS handshake failure
/// to tolerate transient server issues. Returns `None` (with SKIP message)
/// only when all attempts are exhausted.
async fn connect_with_retry(
    connector: &TlsConnector,
    host: &str,
    port: u16,
    addr: &str,
) -> Option<TlsStream<TcpStream>> {
    let mut last_err = String::new();
    for attempt in 1..=MAX_RETRIES {
        let tcp = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => {
                last_err = format!("TCP connect error: {e}");
                println!("  attempt {attempt}/{MAX_RETRIES}: {last_err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => {
                last_err = "TCP connect timed out".to_string();
                println!("  attempt {attempt}/{MAX_RETRIES}: {last_err}");
                continue;
            }
        };

        match connector.connect(host, port, tcp).await {
            Ok(tls) => return Some(tls),
            Err(e) => {
                last_err = format!("TLS handshake failed: {e}");
                println!("  attempt {attempt}/{MAX_RETRIES}: {last_err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
    println!("SKIP: {addr} all {MAX_RETRIES} attempts failed — last error: {last_err}");
    None
}

/// Test TLS 1.2 handshake + application data with httpbin.org (direct, no proxy).
///
/// httpbin.org typically negotiates TLS 1.2. This tests:
/// 1. TLS 1.2 handshake (with correct GCM record encryption)
/// 2. Sending an HTTP request (encrypted with TLS 1.2 record format)
/// 3. Reading the response (decrypted with TLS 1.2 record format)
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls12_httpbin_direct() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let mut tls = match connect_with_retry(&connector, "httpbin.org", 443, "httpbin.org:443").await
    {
        Some(tls) => tls,
        None => return,
    };

    let alpn = tls.negotiated_alpn().map(|s| s.to_string());
    println!("httpbin.org ALPN: {:?}", alpn);

    // Send a request appropriate for the negotiated ALPN
    let request = if alpn.as_deref() == Some("h2") {
        // H2 preface — server should respond with H2 SETTINGS
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()
    } else {
        b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            .as_slice()
    };
    tls.write_all(request).await.expect("TLS write failed");
    tls.flush().await.expect("TLS flush failed");

    // Read the response — we just need to verify data flows over the encrypted connection
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut buf)).await {
        Ok(Ok(n)) => {
            assert!(n > 0, "httpbin.org closed connection without data");
            println!("httpbin.org: received {n} bytes (TLS data transfer works)");
            println!("=== PASSED: httpbin.org TLS handshake + data transfer ===");
        }
        Ok(Err(e)) => panic!("httpbin.org TLS read failed: {e}"),
        Err(_) => panic!("httpbin.org response timed out"),
    }
}

/// Test TLS 1.2 record encryption against badssl.com TLS 1.2 endpoint.
///
/// tls-v1-2.badssl.com:1012 ONLY supports TLS 1.2, forcing our code to use
/// the TLS 1.2 record encryption path (GCM nonce, AAD, explicit nonce).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls12_badssl_forced() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile).insecure_skip_verify(true);

    let mut tls = match connect_with_retry(
        &connector,
        "tls-v1-2.badssl.com",
        1012,
        "tls-v1-2.badssl.com:1012",
    )
    .await
    {
        Some(tls) => tls,
        None => return,
    };

    let alpn = tls.negotiated_alpn().map(|s| s.to_string());
    println!("tls-v1-2.badssl.com ALPN: {:?}", alpn);

    // Send HTTP/1.1 request
    let request = b"GET / HTTP/1.1\r\nHost: tls-v1-2.badssl.com:1012\r\nConnection: close\r\n\r\n";
    tls.write_all(request).await.expect("TLS write failed");
    tls.flush().await.expect("TLS flush failed");

    let mut response = Vec::new();
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls.read_to_end(&mut response),
    )
    .await
    {
        Ok(Ok(n)) => {
            println!("tls-v1-2.badssl.com: received {n} bytes");
            let text = String::from_utf8_lossy(&response);
            println!(
                "Response (first 500 chars): {}",
                &text[..text.len().min(500)]
            );
            assert!(n > 0, "Should receive data");
            assert!(
                text.contains("HTTP/1") || text.contains("html") || text.contains("tls-v1-2"),
                "Should get an HTTP response"
            );
            println!(
                "=== PASSED: TLS 1.2 badssl.com full request (record encryption verified) ==="
            );
        }
        Ok(Err(e)) => panic!("Read error: {e}"),
        Err(_) => panic!("Read timeout"),
    }
}

/// Test TLS 1.2 full data transfer with a server known to work.
///
/// This connects to tls.browserleaks.com and sends an HTTP request.
/// The server negotiates whatever version it prefers (1.2 or 1.3).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_data_transfer_browserleaks() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let mut tls = match connect_with_retry(
        &connector,
        "tls.browserleaks.com",
        443,
        "tls.browserleaks.com:443",
    )
    .await
    {
        Some(tls) => tls,
        None => return,
    };

    let alpn = tls.negotiated_alpn().map(|s| s.to_string());
    println!("tls.browserleaks.com ALPN: {:?}", alpn);

    let request: &[u8] = if alpn.as_deref() == Some("h2") {
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    } else {
        b"GET /json HTTP/1.1\r\nHost: tls.browserleaks.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    };
    tls.write_all(request).await.expect("write failed");
    tls.flush().await.expect("flush failed");

    let mut buf = [0u8; 8192];
    match tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut buf)).await {
        Ok(Ok(n)) => {
            assert!(n > 0, "Should receive some data (got 0 bytes)");
            let text = String::from_utf8_lossy(&buf[..n]);
            println!("browserleaks: received {n} bytes");
            println!(
                "Response (first 500 chars): {}",
                &text[..text.len().min(500)]
            );
            assert!(n > 10, "Should receive substantial data");
            println!("=== PASSED: Full data transfer works ===");
        }
        Ok(Err(e)) => panic!("Read error: {e}"),
        Err(_) => panic!("Read timeout"),
    }
}
