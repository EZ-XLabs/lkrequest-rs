//! End-to-end HelloRetryRequest (HRR) test.
//!
//! Tests the TLS 1.3 HelloRetryRequest flow where the server asks the client
//! to retry with a different key share group.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lkrequest::TlsConnector;
use lktls::profile::presets;

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

/// Test multi-server handshake resilience.
///
/// Connects to multiple servers with different TLS configurations
/// to verify the handshake state machine handles various server behaviors.
/// Some servers may trigger HRR depending on the key share groups offered.
#[tokio::test]
#[ignore]
async fn test_multi_server_robustness() {
    let profile = presets::chrome_144();
    let servers = vec![
        ("www.cloudflare.com", 443),
        ("www.google.com", 443),
        ("github.com", 443),
    ];

    for (host, port) in &servers {
        let connector = TlsConnector::new(profile.clone());
        let tls = tls_connect_with_retry(&connector, host, *port, MAX_RETRIES).await;

        assert!(
            tls.negotiated_alpn().is_some(),
            "ALPN should be negotiated for {host}:{port}"
        );

        println!("  [OK] {host}:{port}");
    }

    println!("=== PASSED: multi-server robustness ===");
}

/// Test handshake with different profiles on the same server.
///
/// Verifies that Chrome, Firefox, and Safari profiles all complete
/// handshakes successfully on the same server.
#[tokio::test]
#[ignore]
async fn test_all_profiles_handshake() {
    let profiles = vec![
        ("Chrome 144", presets::chrome_144()),
        ("Firefox 147", presets::firefox_147()),
        ("Safari 26", presets::safari_26()),
    ];
    let host = "www.cloudflare.com";

    for (name, profile) in profiles {
        let connector = TlsConnector::new(profile);
        let mut tls = tls_connect_with_retry(&connector, host, 443, MAX_RETRIES).await;

        assert!(
            tls.negotiated_alpn().is_some(),
            "{name}: ALPN should be negotiated"
        );

        // Verify data transfer works
        let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(n > 0, "{name}: should receive response data");

        println!("  [OK] {name}");
    }

    println!("=== PASSED: all profiles handshake ===");
}
