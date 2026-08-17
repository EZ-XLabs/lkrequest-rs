//! Full-stack TLS + H2 combined fingerprint verification tests.
//!
//! These tests exercise the **complete** lkrequest pipeline:
//!   Client -> Session -> session.get(url).send().await -> Response
//!
//! and verify that TLS-layer fingerprint (JA4) and HTTP/2-layer fingerprint
//! (Akamai H2 hash) match real Chrome 144.
//!
//! **Note on JA3**: Chrome 108+ enables `shuffle_extensions`, so the extension
//! order varies per connection and JA3 hash changes every time.  We verify
//! JA4 prefix instead (JA4 sorts extensions before hashing, making it
//! stable across shuffled connections).
//!
//! Requires network access to tls.browserleaks.com (via local proxy).

#[macro_use]
mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lkrequest::Session;
use lktls::profile::presets;
use support::MAX_RETRIES;

/// Local proxy for accessing external sites.
/// Override via `TEST_PROXY` env var (e.g. in CI: `TEST_PROXY=http://proxy.example.com:8080`).
fn proxy() -> String {
    support::test_proxy()
}

/// Helper: create a Chrome 144 client with standard User-Agent.
fn chrome_144_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "application/json, text/plain, */*")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build()
}

/// Helper: create a session with proxy configured.
fn proxied_session(client: &Client) -> Session {
    client.session().proxy(&proxy()).build()
}

/// Full-stack fingerprint verification: TLS (JA4) AND H2 (Akamai).
///
/// JA3 is not asserted because `shuffle_extensions` (Chrome 108+) randomizes
/// extension order per connection, making JA3 non-deterministic by design.
/// JA4 sorts extensions before hashing and remains stable.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_full_stack_chrome144_fingerprint() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200, "expected HTTP 200");

    let json: serde_json::Value = resp.json().expect("should deserialize as JSON");

    let ja3_hash = json["ja3_hash"]
        .as_str()
        .expect("response missing 'ja3_hash'");
    let ja4 = json["ja4"].as_str().expect("response missing 'ja4'");

    println!("JA3 hash: {ja3_hash} (varies per connection due to shuffle_extensions)");
    println!("JA4:      {ja4}");

    // JA4 prefix is stable across shuffled connections.
    // Format: t13d1516h2_<sorted-extension-hash>_<sorted-sigalg-hash>
    assert!(
        ja4.starts_with("t13d1516h2"),
        "JA4 prefix mismatch — expected t13d1516h2..., got: {ja4}"
    );

    let akamai_text = json["akamai_text"]
        .as_str()
        .expect("response missing 'akamai_text'");
    let akamai_hash = json["akamai_hash"]
        .as_str()
        .expect("response missing 'akamai_hash'");

    println!("Akamai FP:   {akamai_text}");
    println!("Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        "Akamai H2 fingerprint text does not match Chrome 144"
    );
    assert_eq!(
        akamai_hash, "52d84b11737d980aef856699f885ca86",
        "Akamai H2 hash does not match Chrome 144"
    );

    println!("\n=== PASSED: Full-stack Chrome 144 fingerprint (JA4 + H2) verified! ===");
}

/// Verify that the JA3 full string contains expected cipher suite and extension info.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_ja3_full_string_contains_expected_components() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    let json: serde_json::Value = resp.json().expect("should deserialize as JSON");

    let ja3_text = json["ja3_text"].as_str().unwrap_or("N/A");
    println!("JA3 full: {ja3_text}");

    assert!(
        !ja3_text.is_empty() && ja3_text != "N/A",
        "JA3 text should not be empty"
    );
    assert!(
        ja3_text.starts_with("771,"),
        "JA3 should start with record version 771, got: {ja3_text}"
    );

    let ja4 = json["ja4"].as_str().unwrap_or("N/A");
    println!("JA4: {ja4}");
    assert!(
        ja4.starts_with("t13"),
        "JA4 should indicate TLS 1.3 (prefix 't13'), got: {ja4}"
    );
}

/// Verify fingerprint is stable across multiple requests on the same session.
///
/// With `shuffle_extensions` enabled, JA3 may differ if the proxy creates
/// separate TLS connections for each request.  We verify Akamai H2 hash
/// stability (same H2 connection) and JA4 prefix stability (shuffle-resistant).
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_fingerprint_stable_across_requests() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp1 = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "first request should succeed"
    );
    let json1: serde_json::Value = resp1.json().expect("should be JSON");

    let resp2 = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "second request should succeed"
    );
    let json2: serde_json::Value = resp2.json().expect("should be JSON");

    let hash1 = json1["akamai_hash"].as_str().unwrap_or("N/A");
    let hash2 = json2["akamai_hash"].as_str().unwrap_or("N/A");

    println!("Request 1 Akamai hash: {hash1}");
    println!("Request 2 Akamai hash: {hash2}");

    assert_eq!(
        hash1, hash2,
        "Akamai H2 hash should be identical across requests"
    );

    // JA4 prefix should be stable even with shuffle_extensions — JA4 sorts
    // extensions before hashing.
    let ja4_1 = json1["ja4"].as_str().unwrap_or("N/A");
    let ja4_2 = json2["ja4"].as_str().unwrap_or("N/A");
    let prefix_len = "t13d1516h2".len();
    assert_eq!(
        &ja4_1[..prefix_len.min(ja4_1.len())],
        &ja4_2[..prefix_len.min(ja4_2.len())],
        "JA4 prefix should be identical across requests"
    );

    println!("=== PASSED: Fingerprint is stable across requests ===");
}
