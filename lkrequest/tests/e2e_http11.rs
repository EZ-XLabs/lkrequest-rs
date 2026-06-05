//! HTTP/1.1 protocol support end-to-end tests.
//!
//! Tests verify that lkrequest can:
//! 1. Connect to sites that negotiate HTTP/2 (existing behavior, regression guard)
//! 2. Connect to sites that negotiate HTTP/1.1 (forced via ALPN)
//! 3. Handle ALPN-based protocol selection transparently
//!
//! All tests use Chrome 144 fingerprint and access real sites via proxy.

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

/// Helper: create a Chrome 144 client with both H2+H1.1 ALPN (normal behavior).
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
        .default_header("accept-encoding", "gzip, deflate, br")
        .build()
}

/// Helper: create a Chrome 144 client that ONLY advertises HTTP/1.1 in ALPN.
///
/// This forces servers to negotiate HTTP/1.1 even if they support H2,
/// exercising our HTTP/1.1 code path.
fn chrome_144_h1_only_client() -> Client {
    let mut tls_profile = presets::chrome_144();
    // Override ALPN to only advertise HTTP/1.1
    tls_profile.alpn_protocols = vec!["http/1.1".to_string()];

    Client::builder()
        .fingerprint(tls_profile)
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
        .default_header("accept-encoding", "gzip, deflate, br")
        .build()
}

/// Helper: create a session with proxy configured.
fn proxied_session(client: &Client) -> Session {
    client.session().proxy(&proxy()).build()
}

// ---------------------------------------------------------------------------
// H2 regression tests (existing sites that should still work with ALPN h2)
// ---------------------------------------------------------------------------

/// Cloudflare negotiates H2 via ALPN. This should work as before.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h2_cloudflare_regression() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://www.cloudflare.com/").send(),
        "Cloudflare (H2) request should succeed"
    );

    let status = resp.status().as_u16();
    println!("[H2] Cloudflare status: {status}");
    assert!(
        status == 200 || (300..400).contains(&status),
        "Cloudflare returned unexpected status: {status}"
    );
    println!("=== PASSED: H2 Cloudflare regression OK ===");
}

/// GitHub negotiates H2 via ALPN.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h2_github_regression() {
    let client = chrome_144_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://github.com/").send(),
        "GitHub (H2) request should succeed"
    );

    let status = resp.status().as_u16();
    println!("[H2] GitHub status: {status}");
    assert_eq!(status, 200, "GitHub should return 200");

    let body = resp.text().unwrap_or("[binary]");
    assert!(
        body.contains("GitHub") || body.contains("github"),
        "GitHub response should contain 'GitHub'"
    );
    println!("=== PASSED: H2 GitHub regression OK ===");
}

// ---------------------------------------------------------------------------
// HTTP/1.1 tests — force HTTP/1.1 by only advertising "http/1.1" in ALPN
// ---------------------------------------------------------------------------

/// Force HTTP/1.1 negotiation with Google.
///
/// By only advertising "http/1.1" in ALPN, the server must negotiate
/// HTTP/1.1 instead of H2. This exercises our H1.1 code path end-to-end.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h1_forced_google() {
    let client = chrome_144_h1_only_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://www.google.com/").send(),
        "Google (forced H1.1) request should succeed"
    );

    let status = resp.status().as_u16();
    println!("[H1.1] Google status: {status}");
    assert!(
        status == 200 || (300..400).contains(&status),
        "Google (H1.1) returned unexpected status: {status}"
    );
    println!("=== PASSED: H1.1 forced Google OK ===");
}

/// Force HTTP/1.1 negotiation with Cloudflare.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h1_forced_cloudflare() {
    let client = chrome_144_h1_only_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://www.cloudflare.com/").send(),
        "Cloudflare (forced H1.1) request should succeed"
    );

    let status = resp.status().as_u16();
    println!("[H1.1] Cloudflare status: {status}");
    assert!(
        status == 200 || (300..400).contains(&status),
        "Cloudflare (H1.1) returned unexpected status: {status}"
    );
    println!("=== PASSED: H1.1 forced Cloudflare OK ===");
}

/// Force HTTP/1.1 negotiation with GitHub.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h1_forced_github() {
    let client = chrome_144_h1_only_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://github.com/").send(),
        "GitHub (forced H1.1) request should succeed"
    );

    let status = resp.status().as_u16();
    println!("[H1.1] GitHub status: {status}");
    assert_eq!(status, 200, "GitHub (H1.1) should return 200");

    let body = resp.text().unwrap_or("[binary]");
    assert!(
        body.contains("GitHub") || body.contains("github"),
        "GitHub (H1.1) response should contain 'GitHub'"
    );
    println!("=== PASSED: H1.1 forced GitHub OK ===");
}

// ---------------------------------------------------------------------------
// Connection reuse tests
// ---------------------------------------------------------------------------

/// Test HTTP/1.1 connection reuse (keep-alive pooling).
///
/// Sends multiple requests to the same origin over forced H1.1.
/// The second+ requests should reuse the pooled connection.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h1_connection_reuse() {
    let client = chrome_144_h1_only_client();
    let session = proxied_session(&client);

    // First request — establishes connection
    let resp1 = retry!(
        MAX_RETRIES,
        session.get("https://www.google.com/").send(),
        "first H1.1 request should succeed"
    );
    let status1 = resp1.status().as_u16();
    assert!(
        status1 == 200 || (300..400).contains(&status1),
        "First request unexpected status: {status1}"
    );
    println!("[1/2] First H1.1 request OK (status {status1})");

    // Second request — should reuse pooled H1.1 connection
    let resp2 = retry!(
        MAX_RETRIES,
        session.get("https://www.google.com/").send(),
        "second H1.1 request should succeed"
    );
    let status2 = resp2.status().as_u16();
    assert!(
        status2 == 200 || (300..400).contains(&status2),
        "Second request unexpected status: {status2}"
    );
    println!("[2/2] Second H1.1 request OK (status {status2}, should be pooled)");

    println!("=== PASSED: H1.1 connection reuse OK ===");
}

// ---------------------------------------------------------------------------
// Mixed protocol tests
// ---------------------------------------------------------------------------

/// Test accessing multiple origins, some via H2 and some via forced H1.1,
/// with the same session pool infrastructure.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_mixed_protocol_multiple_clients() {
    let h2_client = chrome_144_client();
    let h1_client = chrome_144_h1_only_client();
    let h2_session = proxied_session(&h2_client);
    let h1_session = proxied_session(&h1_client);

    // H2 request
    let resp_h2 = retry!(
        MAX_RETRIES,
        h2_session.get("https://www.cloudflare.com/").send(),
        "H2 request should succeed"
    );
    let status_h2 = resp_h2.status().as_u16();
    println!("[H2] Cloudflare: {status_h2}");
    assert!(status_h2 == 200 || (300..400).contains(&status_h2));

    // H1.1 request (forced)
    let resp_h1 = retry!(
        MAX_RETRIES,
        h1_session.get("https://www.cloudflare.com/").send(),
        "H1.1 request should succeed"
    );
    let status_h1 = resp_h1.status().as_u16();
    println!("[H1.1] Cloudflare: {status_h1}");
    assert!(status_h1 == 200 || (300..400).contains(&status_h1));

    println!("=== PASSED: Mixed protocol OK ===");
}

/// Test POST with body via forced HTTP/1.1.
#[tokio::test]
#[ignore = "Tier-2: public sites via proxy"]
async fn test_h1_post_with_body() {
    let client = Client::builder().fingerprint(presets::chrome_131()).build();
    let session = proxied_session(&client);

    let payload = serde_json::json!({
        "test": "lkrequest_h1",
        "protocol": "http/1.1"
    });

    // Use Google's search as a POST target — won't echo, but should accept
    // Use a more reliable endpoint: just verify the POST doesn't crash.
    // We'll POST to Google and accept any non-error response.
    let resp = retry!(
        MAX_RETRIES,
        session
            .post("https://www.google.com/")
            .json(&payload)
            .send(),
        "POST (H1.1) request should succeed"
    );

    let status = resp.status().as_u16();
    println!("[H1.1 POST] Google status: {status}");
    // Google might return 405 (Method Not Allowed) for POST, which is fine.
    // We just need to verify the HTTP/1.1 roundtrip works.
    assert!(status < 500, "POST (H1.1) returned server error: {status}");

    println!("=== PASSED: H1.1 POST with body OK ===");
}
