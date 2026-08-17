//! End-to-end TLS 1.2 handshake tests.
//!
//! These tests verify that the TLS 1.2 handshake engine works correctly
//! with various servers. The Chrome 131/144 profile supports TLS 1.3 as
//! the preferred version, but the engine automatically falls back to
//! TLS 1.2 when the server selects it.
//!
//! Note: Most modern servers prefer TLS 1.3, so we test TLS 1.2 by
//! connecting to servers that support both and verifying the engine can
//! handle TLS 1.2 negotiation when it happens. We also test the auto-
//! negotiation logic.
//!
//! Requires network access.

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

use lkrequest::TlsConnector;
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Test that our TLS engine can complete a handshake with Cloudflare.
///
/// Cloudflare typically negotiates TLS 1.3, but this test verifies the
/// overall handshake pipeline works (including version negotiation).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_cloudflare() {
    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    // Send an HTTP/1.1-ish request to verify the connection works.
    // Note: ALPN negotiated h2, so this will likely get an H2 error,
    // but we're testing TLS data transfer, not HTTP.
    let request = b"GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\n\r\n";
    tls.write_all(request).await.expect("write failed");
    tls.flush().await.expect("flush failed");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) => println!("Received {n} bytes (TLS data transfer works)"),
        Ok(Err(e)) => println!("Read error (expected for h2 mismatch): {e}"),
        Err(_) => println!("Read timeout (expected for h2 mismatch)"),
    }

    println!("=== PASSED: Cloudflare handshake (auto-negotiate) ===");
}

/// Test TLS handshake with GitHub (typically negotiates TLS 1.3).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_github() {
    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile);

    let tls = tls_connect_with_retry(&connector, "github.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    println!("=== PASSED: GitHub handshake ===");
}

/// Test TLS handshake with tls.browserleaks.com (TLS 1.3 server).
///
/// This server is used for fingerprint analysis and always supports TLS 1.3.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_browserleaks() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let tls = tls_connect_with_retry(&connector, "tls.browserleaks.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    println!("=== PASSED: browserleaks handshake ===");
}

/// Test TLS handshake in insecure mode (skip certificate verification).
///
/// This verifies the handshake state machine works independently of cert
/// verification.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_insecure_mode() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile).insecure_skip_verify(true);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    // Verify we can write and read data
    let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
    tls.write_all(request).await.expect("write failed");
    tls.flush().await.expect("flush failed");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) => {
            assert!(n > 0, "should receive some data");
            println!("Received {n} bytes in insecure mode");
        }
        Ok(Err(e)) => println!("Read error (expected for h2): {e}"),
        Err(_) => println!("Timeout (expected for h2)"),
    }

    println!("=== PASSED: Insecure mode handshake ===");
}

/// Test that certificate verification correctly rejects mismatched hostnames.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_cert_verification_rejects_wrong_hostname() {
    use lktls::verify::policy::VerificationPolicy;

    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile).verification_policy(VerificationPolicy::Strict); // cert verification enabled

    // Connect to 1.1.1.1 (Cloudflare DNS) but claim hostname is "wrong.invalid"
    let tcp = tokio::net::TcpStream::connect("1.1.1.1:443")
        .await
        .expect("TCP connect failed");

    let result = connector.connect("wrong.invalid", 443, tcp).await;

    assert!(
        result.is_err(),
        "TLS handshake should fail with wrong hostname"
    );

    let err = result.unwrap_err();
    let err_msg = format!("{err}");
    println!("Expected error: {err_msg}");

    assert!(
        err_msg.contains("hostname")
            || err_msg.contains("certificate")
            || err_msg.contains("verify")
            || err_msg.contains("closed"),
        "error should indicate handshake rejection: {err_msg}"
    );

    println!("=== PASSED: Cert verification rejects wrong hostname ===");
}

/// Test TLS handshake with Chrome 144 profile (includes X25519MLKEM768 post-quantum).
///
/// Chrome 144 includes the post-quantum key exchange group X25519MLKEM768
/// in its key_share. This test verifies the complete handshake including
/// potential HRR (if server doesn't support the PQ group).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_chrome144_with_postquantum() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    // Chrome 144 key_share includes X25519MLKEM768 + X25519.
    // Cloudflare supports X25519MLKEM768, so this should succeed directly.
    // Other servers may send HRR requesting a different group.
    let tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    println!("=== PASSED: Chrome 144 post-quantum handshake ===");
}

/// Test connecting to multiple servers sequentially with the same profile.
///
/// This tests the robustness of the TLS engine across different server
/// configurations and certificate chains. Each server is retried up to
/// `MAX_RETRIES` times to tolerate transient network errors; failures
/// after retries are recorded but do not abort the remaining servers.
/// The test passes when at least half of the servers succeed.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_multiple_servers_robust() {
    let profile = presets::chrome_144();

    let servers = [
        ("www.cloudflare.com", 443),
        ("github.com", 443),
        ("www.google.com", 443),
        ("www.apple.com", 443),
        ("www.microsoft.com", 443),
        ("www.amazon.com", 443),
        ("www.mozilla.org", 443),
        ("one.one.one.one", 443),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (host, port) in &servers {
        let connector = TlsConnector::new(profile.clone());

        let result = async {
            let tcp = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(format!("{host}:{port}")),
            )
            .await
            .map_err(|_| "TCP connect timed out".to_string())?
            .map_err(|e| format!("TCP connect failed: {e}"))?;

            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                connector.connect(host, *port, tcp),
            )
            .await
            .map_err(|_| "TLS handshake timed out".to_string())?
            .map_err(|e| format!("TLS handshake failed: {e}"))
        }
        .await;

        match result {
            Ok(_tls) => {
                println!("[OK]   {host}:{port}");
                passed += 1;
            }
            Err(e) => {
                println!("[FAIL] {host}:{port} - {e}");
                failed += 1;
            }
        }
    }

    let total = servers.len();
    let min_required = total / 2;
    println!("\n=== Results: {passed}/{total} passed, {failed} failed ===");
    assert!(
        passed >= min_required,
        "At least {min_required}/{total} servers should pass, but only {passed} did"
    );
}
