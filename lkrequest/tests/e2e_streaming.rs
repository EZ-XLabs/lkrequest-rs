//! Streaming body tests — local HTTPS server (Tier 0).

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::{AcceptEncoding, Client};
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

// ============================================================================
// H1 streaming — small bodies (single TLS record)
// ============================================================================

#[tokio::test]
async fn test_streaming_h1_1kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/1024"))
        .send_streaming()
        .await
        .expect("stream 1 KB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 1024);
}

#[tokio::test]
async fn test_streaming_h1_4kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/4096"))
        .send_streaming()
        .await
        .expect("stream 4 KB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 4096);
}

#[tokio::test]
async fn test_streaming_h1_8kb_collect() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/8192"))
        .send_streaming()
        .await
        .expect("stream 8 KB");
    let data = resp.bytes().await.expect("bytes");
    assert_eq!(data.len(), 8192);
}

#[tokio::test]
async fn test_streaming_h1_empty() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/0"))
        .send_streaming()
        .await
        .expect("stream empty");
    assert!(resp.status().is_success());
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 0);
}

// ============================================================================
// H1 streaming — large bodies (multi TLS record, requires multi_thread)
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_h1_64kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/65536"))
        .send_streaming()
        .await
        .expect("stream 64 KB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 65_536);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_h1_1mb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/1048576"))
        .send_streaming()
        .await
        .expect("stream 1 MB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 1_048_576);
}

// ============================================================================
// H2 streaming (requires multi_thread for the same conn-task deadlock reason)
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_h2_64kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/65536"))
        .send_streaming()
        .await
        .expect("H2 stream 64 KB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 65_536);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_h2_256kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let _ = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/262144"))
        .send_streaming()
        .await
        .expect("H2 stream 256 KB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 262_144);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_http1_only_does_not_create_h2_connection() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/1024"))
        .send_streaming()
        .await
        .expect("stream request");
    let body = resp.bytes().await.expect("stream bytes");
    assert_eq!(body.len(), 1024);

    let stats = session.pool_stats();
    assert_eq!(
        stats.h2_connections, 0,
        "http1_only streaming must not create h2 connections: {stats:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_accept_encoding_override_is_sent() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/echo-headers"))
        .accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
        .send_streaming()
        .await
        .expect("stream request");
    let body = resp.bytes().await.expect("stream body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");

    assert_eq!(
        json["headers"]["accept-encoding"].as_str(),
        Some("gzip, br")
    );
}
