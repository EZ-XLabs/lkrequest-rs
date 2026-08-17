//! Firefox 147 full-stack TLS + H2 fingerprint verification tests.
//!
//! Verifies JA3/JA4 (TLS-layer) and Akamai H2 hash against real Firefox 147
//! reference data captured from `tlsleak/firefox147.0.3_tlsleak.json`.
//!
//! Requires network access to tls.browserleaks.com.

#[macro_use]
mod support;

use lkrequest::h2::profile::firefox_147_h2;
use lkrequest::Client;
use lkrequest::Session;
use lktls::profile::presets;
use support::MAX_RETRIES;

/// Override via `TEST_PROXY` env var (e.g. in CI: `TEST_PROXY=http://proxy.example.com:8080`).
fn proxy() -> String {
    support::test_proxy()
}

/// Reference fingerprints from real Firefox 147.0.3 (captured via browserleaks).
const EXPECTED_JA3_HASH: &str = "6f7889b9fb1a62a9577e685c1fcfa919";
const EXPECTED_JA4_PREFIX: &str = "t13d1717h2";
const EXPECTED_AKAMAI_TEXT: &str = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s";
const EXPECTED_AKAMAI_HASH: &str = "6ea73faa8fc5aac76bded7bd238f6433";

fn firefox_147_client() -> Client {
    Client::builder()
        .fingerprint(presets::firefox_147())
        .h2_profile(firefox_147_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .default_header("accept-language", "en-US,en;q=0.5")
        .build()
}

fn proxied_session(client: &Client) -> Session {
    client.session().proxy(&proxy()).build()
}

/// Full-stack fingerprint: JA3 + JA4 + Akamai H2 for Firefox 147.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_firefox147_full_stack_fingerprint() {
    let client = firefox_147_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200, "expected HTTP 200");

    let json: serde_json::Value = resp.json().expect("should deserialize as JSON");

    // TLS fingerprint (JA3)
    let ja3_hash = json["ja3_hash"]
        .as_str()
        .expect("response missing 'ja3_hash'");
    println!("Firefox 147 JA3 hash: {ja3_hash}");
    assert_eq!(
        ja3_hash, EXPECTED_JA3_HASH,
        "JA3 hash mismatch — TLS fingerprint does not match Firefox 147"
    );

    // TLS fingerprint (JA4)
    let ja4 = json["ja4"].as_str().expect("response missing 'ja4'");
    println!("Firefox 147 JA4:      {ja4}");
    assert!(
        ja4.starts_with(EXPECTED_JA4_PREFIX),
        "JA4 prefix mismatch — expected {EXPECTED_JA4_PREFIX}..., got: {ja4}"
    );

    // HTTP/2 fingerprint (Akamai)
    let akamai_text = json["akamai_text"]
        .as_str()
        .expect("response missing 'akamai_text'");
    let akamai_hash = json["akamai_hash"]
        .as_str()
        .expect("response missing 'akamai_hash'");
    println!("Firefox 147 Akamai FP:   {akamai_text}");
    println!("Firefox 147 Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, EXPECTED_AKAMAI_TEXT,
        "Akamai H2 fingerprint text does not match Firefox 147"
    );
    assert_eq!(
        akamai_hash, EXPECTED_AKAMAI_HASH,
        "Akamai H2 hash does not match Firefox 147"
    );

    println!("\n=== PASSED: Full-stack Firefox 147 fingerprint (TLS + H2) verified! ===");
}

/// Verify JA3 full string structure.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_firefox147_ja3_full_string() {
    let client = firefox_147_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    let json: serde_json::Value = resp.json().expect("should be JSON");

    let ja3_text = json["ja3_text"].as_str().unwrap_or("N/A");
    println!("Firefox 147 JA3 full: {ja3_text}");

    assert!(
        ja3_text.starts_with("771,"),
        "JA3 should start with version 771"
    );
    // Firefox should include CBC suites (47=AES_128_CBC_SHA, 53=AES_256_CBC_SHA)
    assert!(
        ja3_text.contains("47") || ja3_text.contains("53"),
        "Firefox JA3 should include legacy CBC cipher suites"
    );
}
