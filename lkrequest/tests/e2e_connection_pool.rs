//! Connection pool tests — local HTTPS server (Tier 0).
//!
//! Covers: pool_stats, connection reuse verification, capacity tracking.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::{Client, HttpVersion, PreferredHttpVersion};
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

// ---------------------------------------------------------------------------
// pool_stats after requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pool_stats_after_h2_request() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200);

    let stats = session.pool_stats();
    assert!(
        stats.h2_connections > 0 || stats.total > 0,
        "pool should have at least 1 connection after request, stats={stats:?}"
    );
}

#[tokio::test]
async fn test_pool_stats_after_h1_request() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200);

    let stats = session.pool_stats();
    assert!(
        stats.total > 0,
        "pool should have at least 1 connection, stats={stats:?}"
    );
}

// ---------------------------------------------------------------------------
// Connection reuse (multiple requests, same pool)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pool_connection_reuse_h2() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    for i in 0..5 {
        let resp = session
            .get(&url_join(&srv.base_url, "/get"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
    }

    let stats = session.pool_stats();
    assert!(
        stats.h2_connections <= 2,
        "H2 should multiplex on ≤2 connections, got {stats:?}"
    );
}

#[tokio::test]
async fn test_pool_connection_reuse_h1() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    for i in 0..3 {
        let resp = session
            .get(&url_join(&srv.base_url, "/get"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
    }

    let stats = session.pool_stats();
    assert!(
        stats.total >= 1,
        "H1 pool should have connections, stats={stats:?}"
    );
}

// ---------------------------------------------------------------------------
// Pool stats initially empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pool_stats_empty_initially() {
    let client = chrome_client();
    let session = client.session().build();

    let stats = session.pool_stats();
    assert_eq!(stats.total, 0, "pool starts empty");
}

// ---------------------------------------------------------------------------
// Preconnect warms pool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_preconnect_increases_pool_stats() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let stats_before = session.pool_stats();
    assert_eq!(stats_before.total, 0);

    session.preconnect(&srv.base_url).await.expect("preconnect");

    let stats_after = session.pool_stats();
    assert!(
        stats_after.total > 0,
        "preconnect should warm the pool, stats={stats_after:?}"
    );
}

#[tokio::test]
async fn test_preconnect_http1_only_warms_h1_pool() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    session.preconnect(&srv.base_url).await.expect("preconnect");

    let stats = session.pool_stats();
    assert_eq!(
        stats.h2_connections, 0,
        "http1_only preconnect must not warm h2: {stats:?}"
    );
    assert!(
        stats.h1_connections > 0,
        "http1_only preconnect should warm an h1 connection: {stats:?}"
    );
}

#[tokio::test]
async fn test_request_http11_override_ignores_pooled_h2() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");

    let warmup = session.get(&url).send().await.expect("warmup h2 request");
    assert_eq!(warmup.version(), HttpVersion::H2);
    assert!(
        session.pool_stats().h2_connections > 0,
        "expected pooled h2 connection after warmup"
    );

    let resp = session
        .get(&url)
        .preferred_http_version(PreferredHttpVersion::Http1Only)
        .send()
        .await
        .expect("http/1.1 override request");

    assert_eq!(resp.version(), HttpVersion::Http11);
}
