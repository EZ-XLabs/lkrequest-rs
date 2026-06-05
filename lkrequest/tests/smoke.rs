//! Smoke tests — minimal, fast sanity checks for core functionality.
//!
//! These tests verify that critical paths don't panic and produce expected results.
//! Network-dependent tests are marked with `#[ignore]` so they can be run separately.
//!
//! Run offline smoke tests:
//!   cargo test --test smoke
//!
//! Run all smoke tests including network:
//!   cargo test --test smoke -- --include-ignored

#[macro_use]
mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;

/// Helper: create a Chrome 144 client for tests.
fn chrome_client() -> Client {
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

// ===========================================================================
// Offline smoke tests (no network required)
// ===========================================================================

/// Verify that all built-in TLS profiles load without panic.
#[test]
fn smoke_profiles_load() {
    let profiles = [
        presets::chrome_131(),
        presets::chrome_144(),
        presets::firefox_133(),
        presets::firefox_147(),
        presets::safari_18(),
        presets::safari_26(),
    ];

    assert_eq!(profiles.len(), 6);
    assert!(
        profiles.iter().all(|profile| !profile.name.is_empty()),
        "all presets should have a non-empty name"
    );
    assert!(
        profiles
            .iter()
            .all(|profile| !profile.cipher_suites.is_empty()),
        "all presets should contain cipher suites"
    );
}

/// Verify that Client/Session construction doesn't panic.
#[test]
fn smoke_client_session_construction() {
    let client = chrome_client();
    let session = client.session().build();
    let session2 = client.session().build();

    assert_eq!(
        session.client().tls_profile().name,
        client.tls_profile().name
    );
    assert_eq!(
        session2.client().h2_profile().settings.len(),
        client.h2_profile().settings.len()
    );
    assert_eq!(session.pool_stats().total, 0);
    assert_eq!(session2.pool_stats().total, 0);
}

/// Verify that invalid URL returns an error, not a panic.
#[tokio::test]
async fn smoke_invalid_url_returns_error() {
    let client = chrome_client();
    let session = client.session().build();

    let result = session.get("not-a-url").send().await;
    assert!(result.is_err());
}

/// Verify that empty URL returns an error.
#[tokio::test]
async fn smoke_empty_url_returns_error() {
    let client = chrome_client();
    let session = client.session().build();

    let result = session.get("").send().await;
    assert!(result.is_err());
}

/// Verify blocking API module loads and client can be built.
#[test]
fn smoke_blocking_client_construction() {
    let inner = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .build();
    let client = lkrequest::blocking::Client::new(inner);
    let session = client.session().build();
    assert_eq!(
        session.client().tls_profile().name,
        client.inner().tls_profile().name
    );
    assert_eq!(session.inner().pool_stats().total, 0);
}

/// Verify JSON profile loading works for all profiles.
#[test]
fn smoke_json_profile_loading() {
    let profiles = [
        "profiles/chrome_131.json",
        "profiles/chrome_144.json",
        "profiles/firefox_133.json",
        "profiles/firefox_147.json",
        "profiles/safari_18.json",
        "profiles/safari_26.json",
    ];
    for path in &profiles {
        let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("lktls")
            .join(path);
        let profile = lktls::profile::loader::from_json_file(&full);
        assert!(
            profile.is_ok(),
            "failed to load {}: {:?}",
            path,
            profile.err()
        );
    }
}

/// Verify that lkh2 crate exports are accessible through lkrequest.
#[test]
fn smoke_lkh2_reexport() {
    // Access H2Profile through lkrequest's re-export
    let profile = lkrequest::h2::profile::chrome_144_h2();
    assert_eq!(profile.settings.len(), 4);
    assert_eq!(profile.window_update, 15663105);

    // Access through lkh2 direct re-export
    let profile2 = lkrequest::lkh2::profile::firefox_147_h2();
    assert_eq!(profile2.settings.len(), 4);
}

/// Verify that WebSocket builder rejects invalid schemes without panic.
#[tokio::test]
async fn smoke_ws_invalid_scheme() {
    let client = chrome_client();
    let session = client.session().build();

    let result = session.websocket("ftp://example.com").connect().await;
    assert!(result.is_err(), "ftp:// should be rejected");
}

/// Verify that WebSocket builder rejects non-TLS ws:// scheme.
#[tokio::test]
async fn smoke_ws_non_tls_rejected() {
    let client = chrome_client();
    let session = client.session().build();

    let result = session.websocket("ws://example.com").connect().await;
    assert!(
        result.is_err(),
        "ws:// should be rejected (only wss:// supported)"
    );
}

// ===========================================================================
// Network smoke tests (require connectivity)
// ===========================================================================

/// TLS 1.3 handshake to Cloudflare — verifies the TLS engine works at all.
#[tokio::test]
#[ignore]
async fn smoke_tls13_handshake() {
    use std::time::Duration;

    let connector = lkrequest::TlsConnector::new(presets::chrome_144());

    let mut last_err = String::new();
    for attempt in 1..=support::MAX_RETRIES {
        let tcp = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect("www.cloudflare.com:443"),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                last_err = format!("TCP connect: {e}");
                if attempt < support::MAX_RETRIES {
                    eprintln!("  [retry {attempt}/{}] {last_err}", support::MAX_RETRIES);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
            Err(_) => {
                last_err = "TCP connect timed out after 10s".into();
                if attempt < support::MAX_RETRIES {
                    eprintln!("  [retry {attempt}/{}] {last_err}", support::MAX_RETRIES);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        let tls = connector
            .connect("www.cloudflare.com", 443, tcp)
            .await
            .expect("TLS handshake failed");

        assert_eq!(tls.negotiated_alpn(), Some("h2"));
        return;
    }
    panic!(
        "TLS handshake failed after {} attempts: {last_err}",
        support::MAX_RETRIES
    );
}

/// Basic HTTP GET returning 200.
#[tokio::test]
#[ignore]
async fn smoke_http_get_200() {
    let client = chrome_client();
    let session = client.session().build();

    let resp = retry!(
        support::MAX_RETRIES,
        session.get("https://httpbingo.org/get").send(),
        "GET request should succeed"
    );
    assert_eq!(resp.status().as_u16(), 200);
}

/// Session cookie persistence across requests.
#[tokio::test]
#[ignore]
async fn smoke_cookie_persistence() {
    let client = chrome_client();

    let mut last_err = String::new();
    for attempt in 1..=support::MAX_RETRIES {
        // Fresh session per attempt so a prior timeout can't leave stale state.
        let session = client.session().build();

        // Set a cookie (httpbingo uses query-param format, not path segments)
        if let Err(e) = session
            .get("https://httpbingo.org/cookies/set?smoke_test=hello")
            .send()
            .await
        {
            last_err = format!("cookie set: {e}");
            if attempt < support::MAX_RETRIES {
                eprintln!("  [retry {attempt}/{}] {last_err}", support::MAX_RETRIES);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            continue;
        }

        // Read cookies back
        let resp = match session.get("https://httpbingo.org/cookies").send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("cookie read: {e}");
                if attempt < support::MAX_RETRIES {
                    eprintln!("  [retry {attempt}/{}] {last_err}", support::MAX_RETRIES);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        let body = resp.text().expect("body should be UTF-8");
        if body.contains("smoke_test") {
            return;
        }

        last_err = format!("cookies not found in response: {body}");
        if attempt < support::MAX_RETRIES {
            eprintln!("  [retry {attempt}/{}] {last_err}", support::MAX_RETRIES);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    panic!(
        "cookie should persist after {} attempts: {last_err}",
        support::MAX_RETRIES
    );
}

/// Connection reuse — second request should reuse the connection.
#[tokio::test]
#[ignore]
async fn smoke_connection_reuse() {
    let client = chrome_client();
    let session = client.session().build();

    // First request establishes the connection
    let resp1 = retry!(
        support::MAX_RETRIES,
        session.get("https://httpbingo.org/get").send(),
        "first request should succeed"
    );
    assert_eq!(resp1.status().as_u16(), 200);

    // Second request should reuse the connection (H2 multiplexing)
    let resp2 = retry!(
        support::MAX_RETRIES,
        session.get("https://httpbingo.org/get").send(),
        "second request should succeed"
    );
    assert_eq!(resp2.status().as_u16(), 200);
}

/// Blocking API basic GET.
#[test]
#[ignore]
fn smoke_blocking_get() {
    let inner = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build();
    let client = lkrequest::blocking::Client::new(inner);
    let session = client.session().build();

    let resp = session
        .get("https://httpbingo.org/get")
        .send()
        .expect("blocking GET should succeed");
    assert_eq!(resp.status().as_u16(), 200);
}
