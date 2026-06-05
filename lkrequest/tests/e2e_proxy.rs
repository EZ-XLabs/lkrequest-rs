//! Proxy tests — local HTTP CONNECT proxy + local HTTPS server (Tier 0).
//!
//! Covers: HTTP CONNECT tunnelling, proxy authentication (407),
//! proxy rejection, proxy error types.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};
use support::local_proxy::{
    start_local_proxy, start_local_proxy_with_auth, start_rejecting_proxy, ProxyConfig,
};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build()
}

// ---------------------------------------------------------------------------
// Basic HTTP CONNECT proxy
// ---------------------------------------------------------------------------

/// Request through a local HTTP CONNECT proxy to a local HTTPS server.
#[tokio::test]
async fn test_proxy_http_connect_get() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let client = chrome_client();
    let session = client.session().proxy(&proxy.url).build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("proxy GET");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("127.0.0.1"), "body={body}");
}

/// Request through a two-hop **proxychain** (client → proxy1 → proxy2 → server).
///
/// Both hops are local HTTP CONNECT proxies; proxy1 CONNECTs to proxy2, then
/// over that tunnel proxy2 CONNECTs to the HTTPS server. Validates the full
/// session path (`connect_tcp` → `ProxyConfig::connect` chain → TLS → GET).
#[tokio::test]
async fn test_proxy_chain_two_hops_get() {
    let srv = start_local_https_server().await;
    let proxy1 = start_local_proxy(ProxyConfig::default()).await;
    let proxy2 = start_local_proxy(ProxyConfig::default()).await;

    // parse_chain: last URL is the final hop (→ server); earlier ones first.
    let chain =
        lkrequest::proxy::ProxyConfig::parse_chain([proxy1.url.as_str(), proxy2.url.as_str()])
            .expect("build proxy chain");
    assert_eq!(chain.hop_count(), 2);

    let client = chrome_client();
    let session = client.session().proxy_config(chain).build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("chained proxy GET");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("127.0.0.1"), "body={body}");
}

/// POST through proxy.
#[tokio::test]
async fn test_proxy_http_connect_post() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let client = chrome_client();
    let session = client.session().proxy(&proxy.url).build();

    let resp = session
        .post(&url_join(&srv.base_url, "/post"))
        .text_body("proxied-body")
        .send()
        .await
        .expect("proxy POST");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("proxied-body"), "body={body}");
}

/// Multiple requests through the same proxy session reuse the connection.
#[tokio::test]
async fn test_proxy_connection_reuse() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let client = chrome_client();
    let session = client.session().proxy(&proxy.url).build();

    for i in 0..3 {
        let resp = session
            .get(&url_join(&srv.base_url, "/get"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
    }
}

// ---------------------------------------------------------------------------
// Proxy with authentication
// ---------------------------------------------------------------------------

/// Proxy with correct Basic auth credentials succeeds.
#[tokio::test]
async fn test_proxy_auth_success() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy_with_auth("testuser", "testpass").await;
    let client = chrome_client();

    let proxy_url = format!("http://YOUR_PROXY_USER:YOUR_PROXY_PASS@proxy.example.com:1080:{}", proxy.addr.port());
    let session = client.session().proxy(&proxy_url).build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("proxy auth GET");

    assert_eq!(resp.status().as_u16(), 200);
}

/// Proxy with wrong credentials returns an error (407).
#[tokio::test]
async fn test_proxy_auth_failure() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy_with_auth("testuser", "testpass").await;
    let client = chrome_client();

    let proxy_url = format!("http://YOUR_PROXY_USER:YOUR_PROXY_PASS@proxy.example.com:1080:{}", proxy.addr.port());
    let session = client.session().proxy(&proxy_url).build();

    let result = session.get(&url_join(&srv.base_url, "/get")).send().await;

    assert!(result.is_err(), "wrong proxy auth should fail");
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("auth") || msg.contains("407") || err.is_proxy_tunnel(),
        "expected auth error, got: {msg}"
    );
}

/// Proxy without credentials when auth is required returns 407 error.
#[tokio::test]
async fn test_proxy_auth_required_no_creds() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy_with_auth("testuser", "testpass").await;
    let client = chrome_client();
    let session = client.session().proxy(&proxy.url).build();

    let result = session.get(&url_join(&srv.base_url, "/get")).send().await;

    assert!(result.is_err(), "no auth should fail when required");
    let err = result.unwrap_err();
    assert!(
        err.is_proxy_tunnel(),
        "expected proxy tunnel error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Proxy rejection / errors
// ---------------------------------------------------------------------------

/// Proxy that rejects all connections returns a proxy error.
#[tokio::test]
async fn test_proxy_rejection() {
    let srv = start_local_https_server().await;
    let proxy = start_rejecting_proxy().await;
    let client = chrome_client();
    let session = client.session().proxy(&proxy.url).build();

    let result = session.get(&url_join(&srv.base_url, "/get")).send().await;

    assert!(result.is_err(), "rejected proxy should fail");
    let err = result.unwrap_err();
    assert!(
        err.is_proxy_tunnel() || err.is_retryable(),
        "expected proxy error, got: {err}"
    );
}

/// Proxy error for unreachable proxy.
#[tokio::test]
async fn test_proxy_unreachable() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(std::time::Duration::from_millis(500))
        .build();

    let session = client.session().proxy("http://127.0.0.1:1").build();

    let result = session.get("https://example.com/").send().await;

    assert!(result.is_err(), "unreachable proxy should fail");
    let err = result.unwrap_err();
    assert!(
        err.is_retryable(),
        "proxy connection error should be retryable: {err}"
    );
}

// ---------------------------------------------------------------------------
// Proxy error type inspection
// ---------------------------------------------------------------------------

/// Proxy error should have correct ProxyErrorKind.
#[tokio::test]
async fn test_proxy_error_kind_auth_required() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy_with_auth("user", "pass").await;
    let client = chrome_client();
    let session = client.session().proxy(&proxy.url).build();

    let result = session.get(&url_join(&srv.base_url, "/get")).send().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    if let Some(pe) = err.as_proxy_error() {
        assert!(
            pe.is_auth_error(),
            "expected auth error kind, got: {:?}",
            pe.kind
        );
    }
}

// ---------------------------------------------------------------------------
// Per-request proxy override
// ---------------------------------------------------------------------------

/// RequestBuilder::proxy() overrides the session-level proxy.
#[tokio::test]
async fn test_per_request_proxy_override() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let client = chrome_client();
    // Session has no proxy configured
    let session = client.session().build();

    // Use per-request proxy override to route through the local proxy
    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .proxy(&proxy.url)
        .send()
        .await
        .expect("per-request proxy GET");

    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// ProxyPool with real requests
// ---------------------------------------------------------------------------

/// ProxyPool::acquire() returns a usable proxy for real requests.
#[tokio::test]
async fn test_proxy_pool_acquire_real_request() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let client = chrome_client();

    let proxy_config = lkrequest::proxy::ProxyConfig::parse(&proxy.url).expect("parse proxy");
    let pool = lkrequest::ProxyPool::builder()
        .proxies(vec![proxy_config])
        .max_proxies(2)
        .build();

    let guard = pool.acquire().await;
    let proxy_cfg = guard.proxy().expect("should have proxy");

    let session = client.session().proxy_config(proxy_cfg.clone()).build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("proxy pool request");

    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// SessionPool with real requests
// ---------------------------------------------------------------------------

/// SessionPool::acquire() returns a session that can make real requests.
#[tokio::test]
async fn test_session_pool_acquire_real_request() {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let client = chrome_client();

    let pool = lkrequest::SessionPool::builder()
        .client(&client)
        .proxy_fn(move || proxy.url.clone())
        .max_sessions(2)
        .build();

    let guard = pool.acquire().await;
    let resp = guard
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("session pool request");

    assert_eq!(resp.status().as_u16(), 200);
}

/// SessionPool::stats() reflects pool state.
#[tokio::test]
async fn test_session_pool_stats() {
    let proxy = start_local_proxy(ProxyConfig::default()).await;
    let proxy_url = proxy.url.clone();
    let client = chrome_client();

    let pool = lkrequest::SessionPool::builder()
        .client(&client)
        .proxy_fn(move || proxy_url.clone())
        .max_sessions(5)
        .build();

    let stats = pool.stats().await;
    assert_eq!(stats.idle_sessions, 0);
    assert_eq!(stats.max_sessions, 5);
}
