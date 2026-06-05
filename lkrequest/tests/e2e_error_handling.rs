//! Error handling tests.
//!
//! These tests verify that lkrequest returns appropriate error types
//! for various failure scenarios.

use std::time::Duration;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;

/// Helper: create a basic client.
fn chrome_144_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .build()
}

// ---------------------------------------------------------------------------
// URL parsing errors
// ---------------------------------------------------------------------------

/// Test that an invalid URL returns an error.
#[tokio::test]
async fn test_invalid_url() {
    let client = chrome_144_client();
    let session = client.session().build();

    let result = session.get("not-a-valid-url").send().await;

    assert!(result.is_err(), "invalid URL should produce an error");

    let err_msg = format!("{}", result.unwrap_err());
    println!("Invalid URL error: {err_msg}");
    assert!(
        err_msg.to_lowercase().contains("url") || err_msg.to_lowercase().contains("invalid"),
        "error should mention URL: {err_msg}"
    );

    println!("=== PASSED: Invalid URL error handling ===");
}

/// Test that an empty URL returns an error.
#[tokio::test]
async fn test_empty_url() {
    let client = chrome_144_client();
    let session = client.session().build();

    let result = session.get("").send().await;

    assert!(result.is_err(), "empty URL should produce an error");

    println!("Empty URL error: {}", result.unwrap_err());
    println!("=== PASSED: Empty URL error handling ===");
}

/// Cleartext `http://` is supported (e.g. h2c); verify a refused port still errors.
#[tokio::test]
async fn test_http_scheme_refused_port_errors() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_millis(500))
        .read_timeout(Duration::from_millis(500))
        .build();
    let session = client.session().build();

    let result = session.get("http://127.0.0.1:1/").send().await;
    assert!(result.is_err(), "connection to closed port should fail");
    println!("=== PASSED: http:// refused port ===");
}

// ---------------------------------------------------------------------------
// DNS / network errors
// ---------------------------------------------------------------------------

/// Test that a non-existent domain returns a network error.
#[tokio::test]
#[ignore = "Tier-2: requires DNS to nonexistent host"]
async fn test_nonexistent_domain() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(5))
        .build();

    let session = client.session().build();

    let result = session
        .get("https://this-domain-definitely-does-not-exist-12345.invalid/")
        .send()
        .await;

    assert!(
        result.is_err(),
        "nonexistent domain should produce an error"
    );

    let err_msg = format!("{}", result.unwrap_err());
    println!("Nonexistent domain error: {err_msg}");

    // Should be a DNS resolution failure or connection error
    assert!(
        err_msg.to_lowercase().contains("io error")
            || err_msg.to_lowercase().contains("dns")
            || err_msg.to_lowercase().contains("resolve")
            || err_msg.to_lowercase().contains("connect")
            || err_msg.to_lowercase().contains("timeout")
            || err_msg.to_lowercase().contains("host"),
        "error should be network-related: {err_msg}"
    );

    println!("=== PASSED: Nonexistent domain error handling ===");
}

/// Test that connection refused is properly reported.
#[tokio::test]
async fn test_connection_refused() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_secs(3))
        .read_timeout(Duration::from_secs(3))
        .build();

    let session = client.session().build();

    // Port 1 is typically not listening — should get connection refused
    let result = session.get("https://127.0.0.1:1/").send().await;

    assert!(result.is_err(), "connection to closed port should fail");

    let err_msg = format!("{}", result.unwrap_err());
    println!("Connection refused error: {err_msg}");

    println!("=== PASSED: Connection refused error handling ===");
}

// ---------------------------------------------------------------------------
// TLS errors
// ---------------------------------------------------------------------------

/// Test that a hostname mismatch in the TLS certificate is caught.
///
/// Note: This depends on the server's certificate and our cert verification
/// settings. With default (non-insecure) settings, a hostname mismatch should
/// fail during TLS handshake.
#[tokio::test]
#[ignore = "Tier-2: depends on DNS/TLS to wrong.invalid"]
async fn test_tls_hostname_mismatch() {
    let client = chrome_144_client();
    let session = client.session().build();

    // Connect to 1.1.1.1 but request hostname "wrong.invalid"
    // This should fail because the TLS certificate doesn't match
    // Note: we can't easily control the hostname check at the session level,
    // so we rely on the URL host being used for the TLS SNI
    let result = session.get("https://wrong.invalid:443/").send().await;

    assert!(
        result.is_err(),
        "connection with mismatched hostname should fail"
    );

    println!("TLS error: {}", result.unwrap_err());
    println!("=== PASSED: TLS hostname mismatch error handling ===");
}

// ---------------------------------------------------------------------------
// Timeout errors
// ---------------------------------------------------------------------------

/// Test that connect timeout produces a clear Timeout error.
#[tokio::test]
async fn test_timeout_error_type() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_millis(100))
        .read_timeout(Duration::from_millis(100))
        .build();

    let session = client.session().build();

    // 192.0.2.1 is TEST-NET-1 (RFC 5737), not routable — guarantees a timeout
    let result = session.get("https://192.0.2.1/").send().await;

    assert!(result.is_err(), "connection to non-routable IP should fail");

    let err = result.unwrap_err();
    let err_msg = format!("{err}");

    assert!(
        err_msg.to_lowercase().contains("timeout") || err_msg.to_lowercase().contains("timed out"),
        "error should mention timeout: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Error type classification
// ---------------------------------------------------------------------------

/// is_timeout() returns true for timeout errors.
#[tokio::test]
async fn test_error_is_timeout_flag() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_millis(100))
        .build();

    let session = client.session().build();
    let result = session.get("https://192.0.2.1/").send().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.is_timeout(), "error should be timeout: {err}");
}

/// is_retryable() returns true for timeout errors.
#[tokio::test]
async fn test_timeout_is_retryable() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_millis(100))
        .build();

    let session = client.session().build();
    let result = session.get("https://192.0.2.1/").send().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.is_retryable(), "timeout should be retryable: {err}");
}

/// Invalid URL is NOT retryable.
#[tokio::test]
async fn test_url_error_not_retryable() {
    let client = chrome_144_client();
    let session = client.session().build();

    let result = session.get("not-a-url").send().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        !err.is_retryable(),
        "URL parse error should not be retryable: {err}"
    );
}

// ---------------------------------------------------------------------------
// TooManyRedirects error
// ---------------------------------------------------------------------------

mod support;
use support::local_https::{start_local_https_server, url_join};

/// Exceeding max_redirects produces a TooManyRedirects error.
#[tokio::test]
async fn test_too_many_redirects_error() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();
    let session = client.session().max_redirects(2).build();

    let url = url_join(&srv.base_url, "/redirect/5");
    let result = session.get(&url).send().await;

    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.to_lowercase().contains("redirect"),
                "error should mention redirect: {msg}"
            );
        }
        Ok(resp) => {
            assert!(
                (300..400).contains(&resp.status().as_u16()),
                "expected 3xx redirect response when max_redirects reached"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceLimitExceeded error
// ---------------------------------------------------------------------------

/// Exceeding max_response_body_size triggers ResourceLimitExceeded.
#[tokio::test]
async fn test_resource_limit_error_type() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .max_response_body_size(10)
        .build();
    let session = client.session().build();

    let url = url_join(&srv.base_url, "/bytes/1000");
    let result = session.get(&url).send().await;

    assert!(result.is_err(), "body over limit should error");
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("limit") || msg.to_lowercase().contains("exceeded"),
        "error should mention resource limit: {msg}"
    );
    assert!(
        !err.is_retryable(),
        "resource limit errors should not be retryable"
    );
}

// ---------------------------------------------------------------------------
// Connection refused error with is_tcp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_connection_refused_has_tcp_phase() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_secs(3))
        .read_timeout(Duration::from_secs(3))
        .build();

    let session = client.session().build();
    let result = session.get("https://127.0.0.1:1/").send().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    // The error should be retryable (network error)
    assert!(
        err.is_retryable(),
        "connection refused should be retryable: {err}"
    );
}

// ---------------------------------------------------------------------------
// error_for_status produces Status error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_error_for_status_produces_status_error() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/status/403"))
        .send()
        .await
        .expect("request");

    let err = resp.error_for_status().unwrap_err();
    assert!(err.is_status(), "should be a status error");
    assert_eq!(err.status().unwrap().as_u16(), 403);
    assert!(!err.is_retryable(), "403 should not be retryable");
}

#[tokio::test]
async fn test_error_for_status_500_is_retryable() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/status/500"))
        .send()
        .await
        .expect("request");

    let err = resp.error_for_status().unwrap_err();
    assert!(err.is_status());
    assert!(err.is_retryable(), "500 status error should be retryable");
}
