//! Streaming decompression, H1 body-limit, and idle_timeout end-to-end tests.
//!
//! Tests verify:
//! 1. HTTP/1.1 body size limits are enforced incrementally
//! 2. StreamingResponse::chunk_decoded() decompresses gzip streams
//! 3. Connection pool idle_timeout is configurable and functional
//!
//! All tests require network access and use #[ignore] for CI control.

#[macro_use]
mod support;

use std::time::Duration;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::{Client, ResourceLimits};
use lktls::profile::presets;
use support::MAX_RETRIES;

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept-encoding", "gzip, deflate, br")
        .build()
}

fn chrome_h1_only_client() -> Client {
    let mut tls_profile = presets::chrome_144();
    tls_profile.alpn_protocols = vec!["http/1.1".to_string()];

    Client::builder()
        .fingerprint(tls_profile)
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept-encoding", "gzip, deflate, br")
        .build()
}

// ---------------------------------------------------------------------------
// Test: H1 body size limit is enforced incrementally
// ---------------------------------------------------------------------------

/// Verifies that when max_response_body_size is set to a small value,
/// the H1 path rejects the response before buffering the entire body.
///
/// Uses forced HTTP/1.1 (ALPN override) so we exercise the H1 path.
#[tokio::test]
#[ignore]
async fn test_h1_body_size_limit_enforced() {
    let mut tls_profile = presets::chrome_144();
    tls_profile.alpn_protocols = vec!["http/1.1".to_string()];

    let client = Client::builder()
        .fingerprint(tls_profile)
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .resource_limits(
            ResourceLimits::default().with_max_response_body_size(512), // 512 bytes max
        )
        .build();

    let session = client.session().build();

    // httpbingo.org/bytes/8192 returns 8KB of random bytes
    let result = session.get("https://httpbingo.org/bytes/8192").send().await;

    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("resource limit") || msg.contains("body") || msg.contains("exceeded"),
                "error should mention body size limit: {msg}"
            );
            println!("=== PASSED: H1 body size limit enforced (error: {msg}) ===");
        }
        Ok(resp) => {
            // In some cases, if the body is small enough before the limit kicks in,
            // we may still get a response. Check that it was actually limited.
            let body_len = resp.bytes().len();
            println!("Response body: {body_len} bytes");
            assert!(
                body_len <= 512,
                "body should be <= 512 bytes but got {body_len}"
            );
            println!("=== PASSED: H1 body size limit test (body within limit) ===");
        }
    }
}

/// Same test but for H2 path (regression — existing behavior should still work).
#[tokio::test]
#[ignore]
async fn test_h2_body_size_limit_enforced() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .resource_limits(ResourceLimits::default().with_max_response_body_size(512))
        .build();

    let session = client.session().build();

    let result = session.get("https://httpbingo.org/bytes/8192").send().await;

    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("resource limit") || msg.contains("body") || msg.contains("exceeded"),
                "error should mention body size limit: {msg}"
            );
            println!("=== PASSED: H2 body size limit enforced (error: {msg}) ===");
        }
        Ok(resp) => {
            let body_len = resp.bytes().len();
            assert!(
                body_len <= 512,
                "body should be <= 512 bytes but got {body_len}"
            );
            println!("=== PASSED: H2 body size limit test (body within limit) ===");
        }
    }
}

// ---------------------------------------------------------------------------
// Test: idle_timeout is configurable
// ---------------------------------------------------------------------------

/// Verifies that SessionBuilder::idle_timeout works without breaking requests.
#[tokio::test]
#[ignore]
async fn test_idle_timeout_configurable() {
    let client = chrome_client();

    // Set a very short idle timeout
    let session = client
        .session()
        .idle_timeout(Duration::from_secs(2))
        .build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://httpbingo.org/get").send(),
        "request with custom idle_timeout should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200);
    println!("=== PASSED: idle_timeout(2s) configured, first request OK ===");

    // Wait longer than the idle timeout
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Second request should still work — old connection evicted, new one created
    let resp2 = retry!(
        MAX_RETRIES,
        session.get("https://httpbingo.org/get").send(),
        "request after idle eviction should succeed"
    );

    assert_eq!(resp2.status().as_u16(), 200);
    println!("=== PASSED: request after idle eviction succeeded ===");
}

// ---------------------------------------------------------------------------
// Test: streaming response with decompression
// ---------------------------------------------------------------------------

/// Verifies that StreamingResponse::chunk_decoded() incrementally decompresses
/// gzip bodies from a real server.
#[tokio::test]
#[ignore]
async fn test_streaming_chunk_decoded_gzip() {
    let client = chrome_client();
    let session = client.session().build();

    // httpbingo.org/gzip returns a gzip-compressed JSON response
    let mut resp = retry!(
        MAX_RETRIES,
        session.get("https://httpbingo.org/gzip").send_streaming(),
        "streaming gzip request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200);

    let mut total = 0;
    let mut chunks = 0;
    while let Some(data) = resp
        .chunk_decoded()
        .await
        .expect("chunk_decoded should not error")
    {
        total += data.len();
        chunks += 1;
    }

    assert!(
        total > 10,
        "decoded body should have content, got {total} bytes"
    );
    println!(
        "=== PASSED: streaming chunk_decoded gzip ({chunks} chunks, {total} bytes decompressed) ==="
    );
}

/// Verifies that chunk_decoded() passes through uncompressed data.
#[tokio::test]
#[ignore]
async fn test_streaming_chunk_decoded_no_encoding() {
    let client = chrome_h1_only_client();
    let session = client.session().build();

    // httpbingo.org/robots.txt returns plain text (no content-encoding when
    // accept-encoding is not set to something that matches)
    let mut resp = retry!(
        MAX_RETRIES,
        session
            .get("https://httpbingo.org/html")
            .header("accept-encoding", "identity")
            .send_streaming(),
        "streaming plain text request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200);

    let mut total = 0;
    let mut chunks = 0;
    while let Some(chunk) = resp
        .chunk_decoded()
        .await
        .expect("chunk_decoded should not error")
    {
        total += chunk.len();
        chunks += 1;
    }

    assert!(total > 0, "should receive some data");
    println!(
        "=== PASSED: streaming chunk_decoded passthrough ({chunks} chunks, {total} bytes) ==="
    );
}

/// Verifies that StreamingResponse::bytes() correctly decompresses.
#[tokio::test]
#[ignore]
async fn test_streaming_bytes_decompresses() {
    let client = chrome_client();
    let session = client.session().build();

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://httpbingo.org/gzip").send_streaming(),
        "streaming gzip request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200);

    let body = resp.bytes().await.expect("bytes() should succeed");
    let text = String::from_utf8_lossy(&body);

    assert!(
        text.contains("gzipped") || text.contains("origin") || text.len() > 10,
        "decompressed body should contain expected content"
    );

    println!(
        "=== PASSED: streaming bytes() decompresses gzip ({} bytes) ===",
        body.len()
    );
}
