//! Real-world website tests.
//!
//! These tests verify that lkrequest can successfully access popular websites
//! protected by various anti-bot / CDN systems (Cloudflare, Akamai, etc.)
//! without being blocked by TLS or H2 fingerprint detection.
//!
//! All tests use Chrome 144 full-stack fingerprint (TLS + H2).
//!
//! Requires network access (via local proxy).

#[macro_use]
mod support;

use lkrequest::h2::profile::{chrome_144_h2, chrome_150_h2};
use lkrequest::Client;
use lkrequest::Session;
use lktls::profile::presets;
use support::MAX_RETRIES;

/// Local proxy for accessing external sites.
/// Override via `TEST_PROXY` env var (e.g. in CI: `TEST_PROXY=http://proxy.example.com:8080`).
fn proxy() -> String {
    support::test_proxy()
}

/// Helper: create a Chrome 144 client with realistic headers.
fn chrome_144_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .default_header("accept-language", "en-US,en;q=0.9")
        .build()
}

/// Helper: create a session with proxy configured.
fn proxied_session(client: &Client) -> Session {
    client.session().proxy(&proxy()).build()
}

/// Test accessing Cloudflare's main site.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_cloudflare_main_site() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://www.cloudflare.com/").send(),
        "Cloudflare request should succeed"
    );

    let status = resp.status().as_u16();
    println!("Cloudflare status: {status}");

    assert!(
        status == 200 || (300..400).contains(&status),
        "Cloudflare returned unexpected status: {status}"
    );

    if status == 200 {
        let body = resp.text().unwrap_or("[binary]");
        assert!(
            body.contains("Cloudflare") || body.contains("cloudflare") || body.len() > 1000,
            "Cloudflare response body seems empty or unexpected"
        );
    }

    println!("=== PASSED: Cloudflare access OK ===");
}

/// Test accessing GitHub's main page.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_github_main_page() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://github.com/").send(),
        "GitHub request should succeed"
    );

    let status = resp.status().as_u16();
    println!("GitHub status: {status}");
    assert_eq!(status, 200, "GitHub should return 200");

    let body = resp.text().unwrap_or("[binary]");
    assert!(
        body.contains("GitHub") || body.contains("github"),
        "GitHub response should contain 'GitHub'"
    );

    println!("=== PASSED: GitHub access OK ===");
}

/// Test accessing Google's main page.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_google_main_page() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://www.google.com/").send(),
        "Google request should succeed"
    );

    let status = resp.status().as_u16();
    println!("Google status: {status}");
    assert!(
        status == 200 || (300..400).contains(&status),
        "Google returned unexpected status: {status}"
    );

    println!("=== PASSED: Google access OK ===");
}

/// Test accessing Cloudflare's 1.1.1.1 site.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_cloudflare_one_one_one_one() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://one.one.one.one/").send(),
        "1.1.1.1 request should succeed"
    );

    let status = resp.status().as_u16();
    println!("one.one.one.one status: {status}");
    assert!(
        status == 200 || (300..400).contains(&status),
        "one.one.one.one returned unexpected status: {status}"
    );

    println!("=== PASSED: one.one.one.one access OK ===");
}

/// Test accessing multiple sites sequentially with the same session.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_multiple_sites_same_session() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let sites = [
        ("https://www.cloudflare.com/", "Cloudflare"),
        ("https://github.com/", "GitHub"),
        ("https://www.google.com/", "Google"),
    ];

    for (url, name) in &sites {
        let resp = retry!(
            MAX_RETRIES,
            session.get(url).send(),
            &format!("{name} request should succeed")
        );
        let status = resp.status().as_u16();
        println!("[OK] {name}: HTTP {status}");
        assert!(
            status == 200 || (300..400).contains(&status),
            "{name} returned unexpected status: {status}"
        );
    }

    println!("=== PASSED: Multiple sites accessed with same session ===");
}

/// Test accessing a site that returns JSON (tls.browserleaks.com).
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_json_api_response() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "browserleaks request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200);

    let json: serde_json::Value = resp.json().expect("should be valid JSON");
    assert!(json.is_object(), "response should be a JSON object");
    assert!(json.get("ja3_hash").is_some(), "missing ja3_hash");
    assert!(json.get("ja4").is_some(), "missing ja4");
    assert!(json.get("akamai_hash").is_some(), "missing akamai_hash");

    println!("=== PASSED: JSON API response parsed correctly ===");
}

/// Helper: create a Chrome 150 client with a faithful top-level-navigation
/// header set (client hints + `sec-fetch-*` + `upgrade-insecure-requests`), as
/// a real Chrome sends when navigating to a document.
fn chrome_150_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_150())
        .h2_profile(chrome_150_h2())
        .default_header(
            "sec-ch-ua",
            "\"Not(A:Brand\";v=\"24\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
        )
        .default_header("sec-ch-ua-mobile", "?0")
        .default_header("sec-ch-ua-platform", "\"Windows\"")
        .default_header("upgrade-insecure-requests", "1")
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,\
             image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        )
        .default_header("sec-fetch-site", "none")
        .default_header("sec-fetch-mode", "navigate")
        .default_header("sec-fetch-user", "?1")
        .default_header("sec-fetch-dest", "document")
        .default_header("accept-encoding", "gzip, deflate, br, zstd")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build()
}

/// Access Facebook's home page with the Chrome 150 full-stack fingerprint.
///
/// Facebook serves its login/landing page to anonymous clients over its own
/// edge (not a generic CDN), and challenges or blocks mismatched TLS/H2
/// fingerprints. A `200` (or a redirect to a locale/login URL) proves the
/// Chrome 150 ClientHello (incl. the ML-DSA signature algorithms added in 150)
/// plus the H2 SETTINGS/pseudo-header order negotiated cleanly with Facebook.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_facebook_home_chrome_150() {
    let client = chrome_150_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://www.facebook.com/").send(),
        "Facebook request should succeed"
    );

    let status = resp.status().as_u16();
    let version = resp.version();
    println!("Facebook status: {status}  version: {version:?}");
    assert!(
        status == 200 || (300..400).contains(&status),
        "Facebook returned unexpected status: {status} (fingerprint may be blocked)"
    );

    if status == 200 {
        let body = resp.text().unwrap_or("[binary]");
        assert!(
            body.to_lowercase().contains("facebook"),
            "Facebook 200 body should contain 'facebook'"
        );
    }

    println!("=== PASSED: Facebook access with Chrome 150 OK ({version:?}) ===");
}
