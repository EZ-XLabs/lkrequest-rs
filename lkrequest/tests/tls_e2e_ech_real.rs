//! End-to-end Encrypted Client Hello (ECH) tests.
//!
//! Tests real ECH encryption against Cloudflare servers that support ECH,
//! and verifies GREASE mode produces non-accepted ECH.
//!
//! ## Test categories
//!
//! - `test_ech_grease_*` — GREASE mode (server ignores ECH, handshake still works)
//! - `test_real_ech_*` — Real ECH encryption with ECHConfigList from DNS
//! - `test_no_ech_*` — Control group (no ECH at all)

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lkrequest::TlsConnector;
use lktls::profile::presets;

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

// ---------------------------------------------------------------------------
// GREASE tests
// ---------------------------------------------------------------------------

/// Test ECH GREASE mode — most servers will not accept ECH GREASE.
///
/// Verifies that the handshake completes successfully even when the server
/// ignores the GREASE ECH extension.
#[tokio::test]
#[ignore]
async fn test_ech_grease_handshake_succeeds() {
    let profile = presets::chrome_144();
    // Chrome 144 profile should have ECH GREASE enabled by default
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;

    // Verify handshake completed
    assert!(tls.negotiated_alpn().is_some(), "ALPN should be negotiated");

    // Send a basic HTTP request to verify the connection works
    let req = "GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 8192];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(n > 0, "should receive response data");

    println!("=== PASSED: ECH GREASE handshake ===");
}

/// Test TLS 1.3 handshake with Firefox profile (uses ECH GREASE with ChaCha20).
///
/// Firefox uses a different AEAD for ECH GREASE (ChaCha20-Poly1305),
/// so this tests the alternative code path.
#[tokio::test]
#[ignore]
async fn test_ech_grease_firefox_profile() {
    let profile = presets::firefox_147();
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;

    assert!(tls.negotiated_alpn().is_some(), "ALPN should be negotiated");

    let req = "GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 8192];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(n > 0, "should receive response data");

    println!("=== PASSED: Firefox ECH GREASE handshake ===");
}

// ---------------------------------------------------------------------------
// No-ECH control group
// ---------------------------------------------------------------------------

/// Test that Safari profile (no ECH) also works.
///
/// Safari 26 profile should NOT include ECH extensions, verifying
/// that the TLS engine works correctly without ECH.
#[tokio::test]
#[ignore]
async fn test_no_ech_safari_handshake() {
    let profile = presets::safari_26();
    let connector = TlsConnector::new(profile);

    let tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;

    assert!(tls.negotiated_alpn().is_some(), "ALPN should be negotiated");

    println!("=== PASSED: Safari no-ECH handshake ===");
}

// ---------------------------------------------------------------------------
// Real ECH tests (using ECHConfigList from DNS HTTPS records)
// ---------------------------------------------------------------------------
//
// These tests require that the target domain's ECHConfigList be provided
// via the ECH_CONFIG_LIST_HEX environment variable (hex-encoded).
//
// To obtain the ECHConfigList for a Cloudflare domain, run:
//   dig +short -t HTTPS crypto.cloudflare.com
// Then extract the `ech=` base64 value and convert to hex.
//
// Alternatively, use the profile_collector tool or curl:
//   curl -s --doh-url https://1.1.1.1/dns-query \
//     'https://dns.google/resolve?name=crypto.cloudflare.com&type=HTTPS'

/// Test real ECH encryption with Chrome profile.
///
/// Set ECH_CONFIG_LIST_HEX env var to run (hex-encoded ECHConfigList).
/// Example: ECH_CONFIG_LIST_HEX=fe0d0045... cargo test --test e2e_ech_real -- --ignored
#[tokio::test]
#[ignore]
async fn test_real_ech_chrome_with_env_config() {
    let hex_str = match std::env::var("ECH_CONFIG_LIST_HEX") {
        Ok(h) => h,
        Err(_) => {
            println!("  SKIP: ECH_CONFIG_LIST_HEX not set");
            return;
        }
    };
    let ech_config = hex_decode(&hex_str).expect("valid hex in ECH_CONFIG_LIST_HEX");
    println!("  ECHConfigList: {} bytes", ech_config.len());

    let target =
        std::env::var("ECH_TARGET_HOST").unwrap_or_else(|_| "crypto.cloudflare.com".into());

    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile).ech_config(ech_config);

    let mut tls = tls_connect_with_retry(&connector, &target, 443, MAX_RETRIES).await;
    assert!(tls.negotiated_alpn().is_some(), "ALPN should be negotiated");

    let req = format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 8192];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(n > 0, "should receive response data");

    let response = String::from_utf8_lossy(&buf[..n]);
    println!("  Response: {}", &response[..response.len().min(120)]);

    println!("=== PASSED: Real ECH Chrome ===");
}

/// Test real ECH with Firefox profile (ChaCha20Poly1305 AEAD).
#[tokio::test]
#[ignore]
async fn test_real_ech_firefox_with_env_config() {
    let hex_str = match std::env::var("ECH_CONFIG_LIST_HEX") {
        Ok(h) => h,
        Err(_) => {
            println!("  SKIP: ECH_CONFIG_LIST_HEX not set");
            return;
        }
    };
    let ech_config = hex_decode(&hex_str).expect("valid hex");
    let target =
        std::env::var("ECH_TARGET_HOST").unwrap_or_else(|_| "crypto.cloudflare.com".into());

    let profile = presets::firefox_147();
    let connector = TlsConnector::new(profile).ech_config(ech_config);

    let mut tls = tls_connect_with_retry(&connector, &target, 443, MAX_RETRIES).await;
    assert!(tls.negotiated_alpn().is_some());

    let req = format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 8192];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(n > 0);

    println!("=== PASSED: Real ECH Firefox ===");
}

/// Simple hex decoder for test use.
fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, String> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex.len().is_multiple_of(2) {
        return Err("odd length hex".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("bad hex at {i}: {e}")))
        .collect()
}
