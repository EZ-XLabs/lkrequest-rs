//! End-to-end wire test: real Chrome 149 preset → real H2 request → browserleaks.
//!
//! This is a genuine packet-sending test (TCP → TLS → H2 → GET), not an
//! in-memory assertion. `tls.browserleaks.com/json` reflects back the
//! fingerprint it *actually received on the wire* (TLS JA3/JA4 + HTTP/2 Akamai
//! fingerprint), so it independently verifies the byte-level output of the
//! `chrome_149` preset — in particular the H2 pseudo-header order (`m,a,s,p`).
//!
//! Tier-2 (public network), so `#[ignore]`d by default. Run with:
//!   TEST_PROXY=http://127.0.0.1:7897 \
//!     cargo test -p lkrequest --test e2e_chrome149_wire_fingerprint -- --include-ignored --nocapture
//!
//! `TEST_PROXY` is optional; without it the request goes direct.

#![cfg(feature = "h2-native")]

use lkrequest::{preset, Client, HttpVersion};

/// chrome_149 H2 fingerprint is identical to 144/146/147/148 (same `chrome_144_h2()`).
const EXPECTED_AKAMAI: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
const EXPECTED_AKAMAI_HASH: &str = "52d84b11737d980aef856699f885ca86";

#[tokio::test]
#[ignore = "Tier-2: hits tls.browserleaks.com; run with --include-ignored (set TEST_PROXY if needed)"]
async fn chrome149_wire_fingerprint_matches_on_browserleaks() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lkh2=debug")
        .try_init();

    use std::time::Duration;
    let client = Client::builder()
        .preset(preset::chrome_149())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        )
        .default_header("accept", "application/json, text/plain, */*")
        .default_header("accept-language", "en-US,en;q=0.9")
        .tcp_connect_timeout(Duration::from_secs(20))
        .tls_handshake_timeout(Duration::from_secs(30))
        .total_timeout(Duration::from_secs(60))
        .build();

    let mut builder = client.session();
    if let Ok(proxy) = std::env::var("TEST_PROXY") {
        if !proxy.is_empty() {
            builder = builder.proxy(&proxy);
        }
    }
    let session = builder.build();

    let mut resp_opt = None;
    for attempt in 1..=3 {
        match session
            .get("https://tls.browserleaks.com/json")
            .send()
            .await
        {
            Ok(r) => {
                resp_opt = Some(r);
                break;
            }
            Err(e) => {
                eprintln!("[attempt {attempt}/3] request to browserleaks failed: {e}");
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }
    let resp = resp_opt.expect("request to tls.browserleaks.com failed after 3 attempts");

    assert_eq!(resp.status().as_u16(), 200, "expected HTTP 200");
    assert_eq!(
        resp.version(),
        HttpVersion::H2,
        "expected the request to be negotiated over HTTP/2"
    );

    let json: serde_json::Value = resp
        .json()
        .expect("browserleaks response is not valid JSON");
    println!("{}", json);
    // browserleaks /json reflects the fingerprint it received, flat top-level keys.
    let akamai = json["akamai_text"].as_str().unwrap_or("");
    let akamai_hash = json["akamai_hash"].as_str().unwrap_or("");
    let ja3 = json["ja3_hash"].as_str().unwrap_or("");
    let ja4 = json["ja4"].as_str().unwrap_or("");
    // The pseudo-header order is the tail segment of the Akamai fingerprint.
    let pseudo_order = akamai.rsplit('|').next().unwrap_or("");

    println!("\n===== chrome_149 — what tls.browserleaks.com actually received =====");
    println!("negotiated proto      : {:?}", resp.version());
    println!("h2 akamai             : {akamai}");
    println!("h2 akamai hash        : {akamai_hash}");
    println!("h2 pseudo-header order: {pseudo_order}");
    println!("tls ja3_hash          : {ja3}");
    println!("tls ja4               : {ja4}");
    println!("====================================================================\n");

    // --- Hard assertions: the H2 wire fingerprint (incl. pseudo-header order) ---
    assert_eq!(
        pseudo_order, "m,a,s,p",
        "pseudo-header order on the wire is not :method,:authority,:scheme,:path"
    );
    assert_eq!(
        akamai, EXPECTED_AKAMAI,
        "H2 Akamai fingerprint mismatch on the wire"
    );
    assert_eq!(
        akamai_hash, EXPECTED_AKAMAI_HASH,
        "H2 Akamai fingerprint hash mismatch on the wire"
    );
}
