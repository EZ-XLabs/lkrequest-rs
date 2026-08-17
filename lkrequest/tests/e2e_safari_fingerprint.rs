//! Safari 26.2 full-stack TLS + H2 fingerprint verification tests.
//!
//! Verifies JA3/JA4 (TLS-layer) and Akamai H2 hash against real Safari 26.2
//! reference data captured from `tlsleak/safari26.2_tlsleak.json`.
//!
//! Requires network access to tls.browserleaks.com.

#[macro_use]
mod support;

use lkrequest::h2::profile::safari_26_h2;
use lkrequest::Client;
use lkrequest::Session;
use lktls::profile::presets;
use support::MAX_RETRIES;

/// Override via `TEST_PROXY` env var (e.g. in CI: `TEST_PROXY=http://proxy.example.com:8080`).
fn proxy() -> String {
    support::test_proxy()
}

/// Reference fingerprints from real Safari 26.2 (captured via browserleaks).
const EXPECTED_JA3_HASH: &str = "ecdf4f49dd59effc439639da29186671";
const EXPECTED_JA4_PREFIX: &str = "t13d2013h2";
const EXPECTED_AKAMAI_TEXT: &str = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p";
const EXPECTED_AKAMAI_HASH: &str = "c52879e43202aeb92740be6e8c86ea96";

fn safari_26_client() -> Client {
    Client::builder()
        .fingerprint(presets::safari_26())
        .h2_profile(safari_26_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .default_header("accept-language", "en-US,en;q=0.9")
        .build()
}

fn proxied_session(client: &Client) -> Session {
    client.session().proxy(&proxy()).build()
}

/// Full-stack fingerprint: JA3 + JA4 + Akamai H2 for Safari 26.2.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_safari26_full_stack_fingerprint() {
    let client = safari_26_client();
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
    println!("Safari 26.2 JA3 hash: {ja3_hash}");
    assert_eq!(
        ja3_hash, EXPECTED_JA3_HASH,
        "JA3 hash mismatch — TLS fingerprint does not match Safari 26.2"
    );

    // TLS fingerprint (JA4)
    let ja4 = json["ja4"].as_str().expect("response missing 'ja4'");
    println!("Safari 26.2 JA4:      {ja4}");
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
    println!("Safari 26.2 Akamai FP:   {akamai_text}");
    println!("Safari 26.2 Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, EXPECTED_AKAMAI_TEXT,
        "Akamai H2 fingerprint text does not match Safari 26.2"
    );
    assert_eq!(
        akamai_hash, EXPECTED_AKAMAI_HASH,
        "Akamai H2 hash does not match Safari 26.2"
    );

    println!("\n=== PASSED: Full-stack Safari 26.2 fingerprint (TLS + H2) verified! ===");
}

/// Verify JA3 full string structure for Safari.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_safari26_ja3_full_string() {
    let client = safari_26_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    let json: serde_json::Value = resp.json().expect("should be JSON");

    let ja3_text = json["ja3_text"].as_str().unwrap_or("N/A");
    println!("Safari 26.2 JA3 full: {ja3_text}");

    assert!(
        ja3_text.starts_with("771,"),
        "JA3 should start with version 771"
    );
    // Safari includes 3DES suite (TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10 = 0x000A)
    assert!(
        ja3_text.contains("-10,") || ja3_text.contains("-10-") || ja3_text.ends_with("-10"),
        "Safari JA3 should include 3DES cipher suite (id 10)"
    );
}
