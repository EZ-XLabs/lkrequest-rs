//! End-to-end TLS fingerprint verification tests.
//!
//! These tests connect to tls.browserleaks.com using the Chrome 144 profile,
//! perform an HTTP/2 request to `/json`, and verify the TLS fingerprint
//! (JA3/JA4 hash) matches real Chrome 144.

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

use lkrequest::{TlsConnector, TlsStream};
use lktls::profile::presets;

// ---------------------------------------------------------------------------
// H2 request helper (Plan Step 5)
// ---------------------------------------------------------------------------

/// Perform an HTTP/2 GET request over an established TLS stream.
///
/// This function takes ownership of the `TlsStream`, performs the h2 handshake
/// (connection preface + SETTINGS), sends a GET request, and returns the
/// HTTP status code and response body as a string.
///
/// # Arguments
///
/// * `tls` — an already-connected `TlsStream` (TLS handshake must be complete)
/// * `host` — the `Host` header / `:authority` pseudo-header value
/// * `path` — the request path (e.g. `/json`)
///
/// # Returns
///
/// `(status_code, response_body)` on success.
async fn h2_get(
    tls: TlsStream,
    host: &str,
    path: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    // Perform the HTTP/2 handshake (sends connection preface + SETTINGS).
    let (h2, conn) = h2::client::handshake(tls).await?;

    // Spawn a task to drive the connection (reads frames in background).
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("h2 connection error: {e}");
        }
    });

    // Wait until we can send a request.
    let mut h2 = h2.ready().await?;

    // Build and send the GET request.
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .body(())
        .unwrap();

    let (resp, _send_stream) = h2.send_request(req, true /* end of stream */)?;

    // Await the response headers.
    let resp = resp.await?;
    let status = resp.status().as_u16();

    // Read the response body.
    let mut body_stream = resp.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk?;
        let len = chunk.len();
        data.extend_from_slice(&chunk);
        // Release flow-control capacity so the server can send more data.
        let _ = body_stream.flow_control().release_capacity(len);
    }

    Ok((status, String::from_utf8(data)?))
}

// ---------------------------------------------------------------------------
// Fingerprint verification test (Plan Step 6)
// ---------------------------------------------------------------------------

/// Test that Chrome 144 profile produces TLS fingerprints matching real Chrome 144.
///
/// Connects to tls.browserleaks.com with the Chrome 144 profile, sends an
/// HTTP/2 request to `/json`, and verifies:
/// - JA3 hash matches `991d71ee69967b7325077b71bad10393`
/// - JA4 starts with `t13d1516h2`
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com"]
async fn test_chrome144_fingerprint_browserleaks() {
    let profile = presets::chrome_144();
    // Set ALPS payload so the ALPS extension is included in the ClientHello
    // (required for Chrome 144 JA3/JA4 fingerprint accuracy).
    let alps_payload = {
        let settings: &[(u16, u32)] = &[(0x01, 65536), (0x02, 0), (0x04, 6291456), (0x06, 262144)];
        let mut buf = Vec::with_capacity(settings.len() * 6);
        for &(id, val) in settings {
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&val.to_be_bytes());
        }
        buf
    };
    let connector = TlsConnector::new(profile).alps_payload(alps_payload);

    // --- TLS connect with retry (Chrome 144 fingerprint) ---
    let tls = tls_connect_with_retry(&connector, "tls.browserleaks.com", 443, MAX_RETRIES).await;

    // --- HTTP/2 GET /json ---
    let (status, body) = h2_get(tls, "tls.browserleaks.com", "/json")
        .await
        .expect("HTTP/2 GET /json failed");

    assert_eq!(status, 200, "Expected HTTP 200, got {status}");

    // --- Parse JSON response ---
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("Failed to parse browserleaks JSON response");

    // Print full response for debugging
    println!("=== tls.browserleaks.com /json response ===");
    println!("{}", serde_json::to_string_pretty(&json).unwrap());

    // --- Verify JA3N hash (normalized/sorted — stable across extension permutations) ---
    let ja3n_hash = json["ja3n_hash"]
        .as_str()
        .expect("Response missing 'ja3n_hash' field");
    println!("JA3N hash: {ja3n_hash}");
    assert_eq!(
        ja3n_hash, "8e19337e7524d2573be54efb2b0784c9",
        "JA3N hash does not match real Chrome 144"
    );

    // --- Verify JA4 fingerprint ---
    let ja4 = json["ja4"].as_str().expect("Response missing 'ja4' field");
    println!("JA4: {ja4}");
    assert!(
        ja4.starts_with("t13d1516h2"),
        "JA4 prefix mismatch — expected t13d1516h2..., got: {ja4}"
    );

    println!("=== Chrome 144 fingerprint verification PASSED ===");
}
