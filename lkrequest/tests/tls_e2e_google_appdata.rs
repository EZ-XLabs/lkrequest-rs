//!
//! This test isolates whether Google's `unexpected_message` alert is
//! caused by our TLS record layer or by the HTTP/2 layer above it.
//!
//! - If this test PASSES: the issue is in the H2 integration layer
//! - If this test FAILS with the same alert: the issue is in lktls itself

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

use lkrequest::TlsConnector;
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Send a simple HTTP/1.1 request to Google after TLS 1.3 handshake.
///
/// Google negotiates h2 via ALPN, so the HTTP/1.1 request will likely
/// get an h2 protocol error. But the KEY question is: does Google
/// accept our application data at the TLS level, or does it send
/// `unexpected_message` (desc=10)?
///
/// Expected outcomes:
/// - If TLS layer is fine: we get some response bytes (even if garbled
///   due to h2/h1 mismatch), or a clean connection close
/// - If TLS layer is broken: we get `TLS alert: level=2 desc=10`
#[tokio::test]
#[ignore = "Tier-2: google.com"]
async fn test_google_raw_appdata_chrome144() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    // Send a simple HTTP/1.1 request (NOT H2 preface)
    // This will be wrong for the h2-negotiated ALPN, but we're testing
    // whether Google accepts our TLS application data records at all.
    let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    tls.write_all(request).await.expect("write should succeed");
    tls.flush().await.expect("flush should succeed");

    // Try to read response
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("SUCCESS: Received {n} bytes from Google (TLS app data works!)");
            println!("First bytes: {:02x?}", &buf[..n.min(32)]);
        }
        Ok(Ok(_)) => {
            println!("Google closed connection (EOF) — TLS layer accepted our data");
        }
        Ok(Err(e)) => {
            let err_msg = format!("{e}");
            if err_msg.contains("TLS alert") && err_msg.contains("desc=10") {
                panic!("CONFIRMED: TLS layer rejects our application data! Error: {e}");
            } else {
                // Other errors (like h2 protocol mismatch) are expected
                println!("Read error (may be expected for h2 mismatch): {e}");
            }
        }
        Err(_) => {
            println!("Timeout (server may not respond to HTTP/1.1 on h2 connection)");
        }
    }
}

/// Same test with Chrome 131 profile for comparison.
#[tokio::test]
#[ignore = "Tier-2: google.com"]
async fn test_google_raw_appdata_chrome131() {
    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    tls.write_all(request).await.expect("write should succeed");
    tls.flush().await.expect("flush should succeed");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("SUCCESS: Received {n} bytes from Google (TLS app data works!)");
            println!("First bytes: {:02x?}", &buf[..n.min(32)]);
        }
        Ok(Ok(_)) => {
            println!("Google closed connection (EOF) — TLS layer accepted our data");
        }
        Ok(Err(e)) => {
            let err_msg = format!("{e}");
            if err_msg.contains("TLS alert") && err_msg.contains("desc=10") {
                panic!("CONFIRMED: TLS layer rejects our application data! Error: {e}");
            } else {
                println!("Read error (may be expected for h2 mismatch): {e}");
            }
        }
        Err(_) => {
            println!("Timeout (server may not respond to HTTP/1.1 on h2 connection)");
        }
    }
}

/// CRITICAL: Test with ALPN set to http/1.1 ONLY (no h2).
///
/// curl succeeds with http/1.1 ALPN. If this test passes, the issue is
/// that Google rejects our application data when h2 is negotiated via ALPN
/// (possibly due to ALPS or H2 compliance expectations).
#[tokio::test]
#[ignore = "Tier-2: google.com"]
async fn test_google_http11_alpn_only() {
    let mut profile = presets::chrome_131();
    // Override ALPN to only offer http/1.1 (like curl does)
    profile.alpn_protocols = vec!["http/1.1".to_string()];

    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    tls.write_all(request).await.expect("write should succeed");
    tls.flush().await.expect("flush should succeed");

    let mut buf = [0u8; 8192];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n.min(200)]);
            println!("SUCCESS with http/1.1 ALPN: Got {n} bytes");
            println!("Response start: {text}");
            // If we get here, the issue is H2-related, not fundamental TLS
        }
        Ok(Ok(_)) => {
            println!("EOF — connection closed cleanly");
        }
        Ok(Err(e)) => {
            let err_msg = format!("{e}");
            if err_msg.contains("desc=10") {
                panic!("STILL fails with http/1.1 ALPN! TLS engine bug confirmed: {e}");
            } else {
                println!("Error (may be expected): {e}");
            }
        }
        Err(_) => {
            println!("Timeout");
        }
    }
}

/// CRITICAL: Test with h2 ALPN but WITHOUT ALPS extension.
///
/// If this passes, ALPS is the root cause. ALPS advertises H2 settings
/// in the ClientHello, and Google may reject connections where ALPS is
/// offered but not properly handled.
#[tokio::test]
#[ignore = "Tier-2: google.com"]
async fn test_google_h2_alpn_without_alps() {
    let mut profile = presets::chrome_131();
    // Keep h2 in ALPN but REMOVE ALPS
    profile.alps_protocols = None; // No ALPS

    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    tls.write_all(request).await.expect("write should succeed");
    tls.flush().await.expect("flush should succeed");

    let mut buf = [0u8; 8192];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n.min(200)]);
            println!("SUCCESS with h2 ALPN but NO ALPS: Got {n} bytes");
            println!("Response start: {text}");
        }
        Ok(Ok(_)) => println!("EOF"),
        Ok(Err(e)) => {
            let err_msg = format!("{e}");
            if err_msg.contains("desc=10") {
                panic!("STILL fails without ALPS! Error: {e}");
            } else {
                println!("Error: {e}");
            }
        }
        Err(_) => println!("Timeout"),
    }
}

/// Send the actual H2 connection preface to Google to test H2-specific issue.
#[tokio::test]
#[ignore = "Tier-2: google.com"]
async fn test_google_h2_preface_raw() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    // Send H2 connection preface only.
    let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tls.write_all(h2_preface)
        .await
        .expect("write should succeed");
    tls.flush().await.expect("flush should succeed");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("SUCCESS: Received {n} bytes from Google after H2 preface");
            println!("First bytes: {:02x?}", &buf[..n.min(32)]);
        }
        Ok(Ok(_)) => {
            println!("EOF after H2 preface");
        }
        Ok(Err(e)) => {
            let err_msg = format!("{e}");
            if err_msg.contains("TLS alert") && err_msg.contains("desc=10") {
                panic!("H2 preface triggers TLS alert! Error: {e}");
            } else {
                println!("Error after H2 preface: {e}");
            }
        }
        Err(_) => {
            println!("Timeout after H2 preface (server waiting for SETTINGS)");
        }
    }
}
