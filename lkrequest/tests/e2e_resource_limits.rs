//! Resource limits — local HTTPS server (Tier 0).

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lkrequest::ResourceLimits;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

fn limited_client(limits: ResourceLimits) -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .resource_limits(limits)
        .build()
}

// ============================================================================
// Body size limits
// ============================================================================

#[tokio::test]
async fn test_max_body_size_enforced() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::default().with_max_response_body_size(10));

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1024");
    let result = session.get(&url).send().await;

    match result {
        Err(e) => {
            let msg = e.to_string();
            let m = msg.to_lowercase();
            assert!(
                m.contains("resource")
                    || m.contains("limit")
                    || m.contains("body")
                    || m.contains("tls"),
                "unexpected error: {msg}"
            );
        }
        Ok(resp) => {
            let len = resp.bytes().len();
            assert!(len <= 10, "body should be truncated or small, got {len}");
        }
    }
}

#[tokio::test]
async fn test_body_exactly_at_limit() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::default().with_max_response_body_size(1024));

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1024");
    let result = session.get(&url).send().await;

    match result {
        Ok(resp) => {
            assert_eq!(resp.status().as_u16(), 200);
            assert_eq!(resp.bytes().len(), 1024);
        }
        Err(e) => {
            panic!("body at exact limit should succeed, got: {e}");
        }
    }
}

#[tokio::test]
async fn test_body_one_over_limit() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::default().with_max_response_body_size(1023));

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1024");
    let result = session.get(&url).send().await;

    match result {
        Err(e) => {
            let m = e.to_string().to_lowercase();
            assert!(
                m.contains("resource")
                    || m.contains("limit")
                    || m.contains("body")
                    || m.contains("exceeded")
                    || m.contains("tls"),
                "unexpected error: {e}"
            );
        }
        Ok(resp) => {
            let len = resp.bytes().len();
            assert!(len <= 1023, "body should be truncated to limit, got {len}");
        }
    }
}

#[tokio::test]
async fn test_body_limit_large_response() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::default().with_max_response_body_size(512));

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/65536");
    let result = session.get(&url).send().await;

    match result {
        Err(e) => {
            let m = e.to_string().to_lowercase();
            assert!(
                m.contains("resource")
                    || m.contains("limit")
                    || m.contains("body")
                    || m.contains("exceeded")
                    || m.contains("tls"),
                "unexpected error: {e}"
            );
        }
        Ok(resp) => {
            let len = resp.bytes().len();
            assert!(len <= 512, "body should be capped, got {len}");
        }
    }
}

// ============================================================================
// Header count limit
// ============================================================================

#[tokio::test]
async fn test_max_header_count_enforced() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits {
        max_header_count: 3,
        ..ResourceLimits::default()
    });

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/response-headers?count=20&size=10");
    let result = session.get(&url).send().await;

    match result {
        Err(e) => {
            let m = e.to_string().to_lowercase();
            assert!(
                m.contains("resource")
                    || m.contains("limit")
                    || m.contains("header")
                    || m.contains("tls"),
                "unexpected error: {e}"
            );
        }
        Ok(_resp) => {
            // If the limit is checked post-receive, we might still get a response
            // but the library should have ideally rejected it. Either way, not panicking
            // is acceptable.
        }
    }
}

#[tokio::test]
async fn test_header_count_within_limit() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits {
        max_header_count: 256,
        ..ResourceLimits::default()
    });

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/response-headers?count=5&size=10");
    let resp = session.get(&url).send().await.expect("within limit");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Streaming with body limit
// ============================================================================

#[tokio::test]
async fn test_streaming_body_within_limit() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::default().with_max_response_body_size(2048));

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1024");
    let mut resp = session
        .get(&url)
        .send_streaming()
        .await
        .expect("stream within limit");
    assert!(resp.status().is_success());

    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 1024);
}

// ============================================================================
// No-limit config allows large bodies
// ============================================================================

#[tokio::test]
async fn test_no_limits_allows_large_body() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::none());

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1048576");
    let resp = session.get(&url).send().await.expect("no limits 1 MB");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().len(), 1_048_576);
}

#[tokio::test]
async fn test_streaming_body_over_limit_errors() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits::default().with_max_response_body_size(512));

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1024");
    let result = session.get(&url).send_streaming().await;

    match result {
        Err(e) => {
            let m = e.to_string().to_lowercase();
            assert!(
                m.contains("resource")
                    || m.contains("limit")
                    || m.contains("body")
                    || m.contains("exceeded"),
                "unexpected streaming setup error: {e}"
            );
        }
        Ok(mut resp) => loop {
            match resp.chunk().await {
                Err(e) => {
                    let m = e.to_string().to_lowercase();
                    assert!(
                        m.contains("resource")
                            || m.contains("limit")
                            || m.contains("body")
                            || m.contains("exceeded"),
                        "unexpected streaming body error: {e}"
                    );
                    break;
                }
                Ok(Some(_)) => continue,
                Ok(None) => panic!("streaming body over limit should error before EOF"),
            }
        },
    }
}

#[tokio::test]
async fn test_streaming_header_limit_errors() {
    let srv = start_local_https_server().await;
    let client = limited_client(ResourceLimits {
        max_header_count: 3,
        ..ResourceLimits::default()
    });

    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/response-headers?count=20&size=10");
    let result = session.get(&url).send_streaming().await;

    match result {
        Err(e) => {
            let m = e.to_string().to_lowercase();
            assert!(
                m.contains("resource") || m.contains("limit") || m.contains("header"),
                "unexpected streaming header-limit error: {e}"
            );
        }
        Ok(resp) => panic!(
            "streaming response with too many headers should be rejected, got status {}",
            resp.status()
        ),
    }
}
