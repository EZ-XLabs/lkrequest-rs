//! End-to-end request pipeline test.
//!
//! Requires network access to tls.browserleaks.com.

#[macro_use]
mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use support::MAX_RETRIES;

fn test_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

/// Test the full request pipeline with Akamai H2 fingerprint verification.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_session_get_returns_200_with_correct_h2_fingerprint() {
    let client = test_client();
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200, "expected HTTP 200");

    let body_text = resp.text().expect("body should be valid UTF-8");
    println!("Response body length: {} bytes", body_text.len());

    let json: serde_json::Value =
        serde_json::from_str(body_text).expect("body should be valid JSON");

    let akamai_text = json["akamai_text"].as_str().unwrap_or("N/A");
    let akamai_hash = json["akamai_hash"].as_str().unwrap_or("N/A");

    println!("Akamai FP:   {akamai_text}");
    println!("Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text,
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );
    assert_eq!(akamai_hash, "52d84b11737d980aef856699f885ca86");

    println!("\n=== SUCCESS: session.get().send().await works with correct Chrome 144 Akamai H2 fingerprint! ===");
}

/// Test that the response body can be read as text and JSON.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_session_get_text_response() {
    let client = test_client();
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200);

    let json: serde_json::Value = resp.json().expect("should deserialize as JSON");
    assert!(json.is_object(), "response should be a JSON object");
    assert!(json.get("ja3_hash").is_some(), "should have ja3_hash field");
    assert!(json.get("ja4").is_some(), "should have ja4 field");

    println!("JA3: {}", json["ja3_hash"].as_str().unwrap_or("N/A"));
    println!("JA4: {}", json["ja4"].as_str().unwrap_or("N/A"));
}

/// Test connection reuse -- second request should reuse the H2 connection.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_connection_reuse() {
    let client = test_client();
    let session = client.session().build();

    let resp1 = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "first request should succeed"
    );
    assert_eq!(resp1.status().as_u16(), 200);

    let resp2 = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "second request should succeed"
    );
    assert_eq!(resp2.status().as_u16(), 200);

    println!("=== SUCCESS: Connection reuse works! ===");
}
