//! Edge-case and boundary-condition tests — local HTTPS server (Tier 0).
//!
//! Covers: large bodies (H1/H2), empty bodies, binary payloads, various HTTP
//! status codes, long URLs, many/large headers, H2 multiplexing with version
//! assertion, H2 connection reuse, H2 concurrent data integrity, rapid
//! sequential requests, streaming large bodies, and interleaved scenarios.

mod support;

use std::time::Duration;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
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
// H2 large response body (warm connection to avoid debug-mode cold-start timeout)
// ============================================================================

#[tokio::test]
async fn test_h2_large_response_256kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let _ = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/262144"))
        .send()
        .await
        .expect("H2 256 KB");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.version().to_string(), "h2");
    assert_eq!(resp.bytes().len(), 262_144);
}

#[tokio::test]
async fn test_h2_large_response_1mb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let _ = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/1048576"))
        .send()
        .await
        .expect("H2 1 MB");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.version().to_string(), "h2");
    assert_eq!(resp.bytes().len(), 1_048_576);
}

// ============================================================================
// H2 large request body (POST)
// ============================================================================

#[tokio::test]
async fn test_h2_large_post_256kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let _ = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");

    let large_body = vec![b'B'; 262_144];
    let resp = session
        .post(&url_join(&srv.base_url, "/post"))
        .body(large_body)
        .send()
        .await
        .expect("H2 POST 256 KB");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.version().to_string(), "h2");
}

// ============================================================================
// H1 large body (non-streaming)
// ============================================================================

#[tokio::test]
async fn test_h1_large_response_1mb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/1048576");

    let resp = session.get(&url).send().await.expect("H1 1 MB");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.version().to_string(), "HTTP/1.1");
    assert_eq!(resp.bytes().len(), 1_048_576);
}

#[tokio::test]
async fn test_h1_large_response_5mb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/5242880");

    let resp = session.get(&url).send().await.expect("H1 5 MB");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().len(), 5_242_880);
}

#[tokio::test]
async fn test_h1_large_post_1mb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let resp = session
        .post(&url)
        .body(vec![b'A'; 1_048_576])
        .send()
        .await
        .expect("H1 POST 1 MB");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Streaming large body (H1 / H2)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_h1_streaming_64kb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/65536"))
        .send_streaming()
        .await
        .expect("H1 stream 64 KB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 65_536);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_h1_streaming_1mb() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/bytes/1048576"))
        .send_streaming()
        .await
        .expect("H1 stream 1 MB");
    let mut total = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk") {
        total += chunk.len();
    }
    assert_eq!(total, 1_048_576);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_h2_streaming_64kb() {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_h2_streaming_256kb() {
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

// ============================================================================
// Empty body
// ============================================================================

#[tokio::test]
async fn test_empty_response_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/bytes/0");

    let resp = session.get(&url).send().await.expect("empty body");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().len(), 0);
}

#[tokio::test]
async fn test_post_empty_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/post");

    let resp = session
        .post(&url)
        .body(Vec::new())
        .send()
        .await
        .expect("POST empty");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_streaming_empty_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/bytes/0");

    let mut resp = session
        .get(&url)
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
// Binary (non-UTF-8) response
// ============================================================================

#[tokio::test]
async fn test_binary_response_bytes() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/bytes/256");

    let resp = session.get(&url).send().await.expect("binary");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().len(), 256);
}

// ============================================================================
// HTTP status codes
// ============================================================================

#[tokio::test]
async fn test_status_204_no_content() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/status/204"))
        .send()
        .await
        .expect("204");
    assert_eq!(resp.status().as_u16(), 204);
    assert_eq!(resp.bytes().len(), 0);
}

#[tokio::test]
async fn test_status_400() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/status/400"))
        .send()
        .await
        .expect("400");
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn test_status_404() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/status/404"))
        .send()
        .await
        .expect("404");
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn test_status_429() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/status/429"))
        .send()
        .await
        .expect("429");
    assert_eq!(resp.status().as_u16(), 429);
}

#[tokio::test]
async fn test_status_500() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/status/500"))
        .send()
        .await
        .expect("500");
    assert_eq!(resp.status().as_u16(), 500);
}

#[tokio::test]
async fn test_status_502() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/status/502"))
        .send()
        .await
        .expect("502");
    assert_eq!(resp.status().as_u16(), 502);
}

// ============================================================================
// Long URL / many query parameters
// ============================================================================

#[tokio::test]
async fn test_long_url_query_string() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let long_value = "a".repeat(4000);
    let url = format!("{}/get?long={}", srv.base_url, long_value);
    let result = session.get(&url).send().await;
    if let Ok(resp) = result {
        assert!(resp.status().as_u16() < 600)
    }
}

#[tokio::test]
async fn test_many_query_parameters() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let params: Vec<String> = (0..100).map(|i| format!("p{i}=v{i}")).collect();
    let url = format!("{}/get?{}", srv.base_url, params.join("&"));
    let resp = session.get(&url).send().await.expect("many params");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Many / large request headers
// ============================================================================

#[tokio::test]
async fn test_many_request_headers() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/headers");
    let mut builder = session.get(&url);
    for i in 0..100 {
        builder = builder.header(&format!("x-hdr-{i}"), &format!("value-{i}"));
    }
    let resp = builder.send().await.expect("100 headers");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("text");
    assert!(body.contains("x-hdr-0"), "body={body}");
    assert!(body.contains("x-hdr-99"), "body={body}");
}

#[tokio::test]
async fn test_large_header_value() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/headers");
    let large_value = "x".repeat(8192);
    let resp = session
        .get(&url)
        .header("x-large-header", &large_value)
        .send()
        .await
        .expect("large header value");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// H2 multiplexing — concurrent requests with version + data integrity
// ============================================================================

#[tokio::test]
async fn test_h2_multiplex_concurrent_get() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");

    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = session.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move { s.get(&u).send().await }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        let resp = h
            .await
            .expect("join")
            .unwrap_or_else(|e| panic!("concurrent GET #{i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.version().to_string(), "h2");
    }
}

#[tokio::test]
async fn test_h2_multiplex_concurrent_post() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/post");

    let mut handles = Vec::new();
    for i in 0..10 {
        let s = session.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move {
            s.post(&u)
                .text_body(&format!("concurrent-{i}"))
                .send()
                .await
        }));
    }
    for (i, h) in handles.into_iter().enumerate() {
        let resp = h
            .await
            .expect("join")
            .unwrap_or_else(|e| panic!("concurrent POST #{i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.version().to_string(), "h2");
    }
}

#[tokio::test]
async fn test_h2_multiplex_data_integrity() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let sizes = [1024usize, 4096, 8192, 16384, 32768];
    let mut handles = Vec::new();
    for &size in &sizes {
        let s = session.clone();
        let u = url_join(&srv.base_url, &format!("/bytes/{size}"));
        handles.push(tokio::spawn(async move { (size, s.get(&u).send().await) }));
    }
    for h in handles {
        let (expected, result) = h.await.expect("join");
        let resp = result.unwrap_or_else(|e| panic!("size {expected}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.version().to_string(), "h2");
        assert_eq!(resp.bytes().len(), expected, "body mismatch for {expected}");
    }
}

#[tokio::test]
async fn test_h2_multiplex_mixed_methods() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let base = srv.base_url.clone();

    let s1 = session.clone();
    let b1 = base.clone();
    let h_get = tokio::spawn(async move { s1.get(&url_join(&b1, "/get")).send().await });

    let s2 = session.clone();
    let b2 = base.clone();
    let h_post = tokio::spawn(async move {
        s2.post(&url_join(&b2, "/post"))
            .text_body("mixed-post")
            .send()
            .await
    });

    let s3 = session.clone();
    let b3 = base.clone();
    let h_put = tokio::spawn(async move {
        s3.put(&url_join(&b3, "/put"))
            .text_body("mixed-put")
            .send()
            .await
    });

    let resp_get = h_get.await.expect("join").expect("GET");
    let resp_post = h_post.await.expect("join").expect("POST");
    let resp_put = h_put.await.expect("join").expect("PUT");

    assert_eq!(resp_get.version().to_string(), "h2");
    assert_eq!(resp_post.version().to_string(), "h2");
    assert_eq!(resp_put.version().to_string(), "h2");
    assert_eq!(resp_get.status().as_u16(), 200);
    assert_eq!(resp_post.status().as_u16(), 200);
    assert_eq!(resp_put.status().as_u16(), 200);

    let post_body = resp_post.text().expect("text");
    assert!(post_body.contains("mixed-post"), "body={post_body}");
}

// ============================================================================
// H2 connection reuse (sequential)
// ============================================================================

#[tokio::test]
async fn test_h2_connection_reuse() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");

    for i in 0..3 {
        let resp = session
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("#{i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.version().to_string(), "h2");
    }
}

#[tokio::test]
async fn test_h2_reuse_then_large_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");
    assert_eq!(resp.version().to_string(), "h2");

    let resp2 = session
        .get(&url_join(&srv.base_url, "/bytes/262144"))
        .send()
        .await
        .expect("256 KB on reused H2");
    assert_eq!(resp2.version().to_string(), "h2");
    assert_eq!(resp2.bytes().len(), 262_144);
}

// ============================================================================
// H2 rapid sequential
// ============================================================================

#[tokio::test]
async fn test_h2_rapid_sequential() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");

    for i in 0..30 {
        let resp = session
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("H2 #{i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.version().to_string(), "h2");
    }
}

// ============================================================================
// H2 interleaved small + large
// ============================================================================

#[tokio::test]
async fn test_h2_interleaved_small_large() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let base = &srv.base_url;

    for _ in 0..5 {
        let r = session
            .get(&url_join(base, "/get"))
            .send()
            .await
            .expect("small");
        assert_eq!(r.version().to_string(), "h2");

        let r = session
            .get(&url_join(base, "/bytes/65536"))
            .send()
            .await
            .expect("64 KB");
        assert_eq!(r.version().to_string(), "h2");
        assert_eq!(r.bytes().len(), 65_536);
    }
}

// ============================================================================
// H1 rapid sequential + connection reuse
// ============================================================================

#[tokio::test]
async fn test_h1_rapid_sequential() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/get");

    for i in 0..20 {
        let resp = session
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("H1 #{i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
    }
}

#[tokio::test]
async fn test_h1_reuse_then_large_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let _ = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/2097152"))
        .send()
        .await
        .expect("2 MB on reused H1");
    assert_eq!(resp.bytes().len(), 2_097_152);
}

#[tokio::test]
async fn test_h1_reuse_then_large_post() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let _ = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("warmup");

    let resp = session
        .post(&url_join(&srv.base_url, "/post"))
        .body(vec![b'Z'; 1_048_576])
        .send()
        .await
        .expect("POST 1 MB on reused H1");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Timeout boundary
// ============================================================================

#[tokio::test]
async fn test_timeout_boundary_within() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/delay/1");

    let resp = session
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("within timeout");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// H1 mixed methods on same connection
// ============================================================================

#[tokio::test]
async fn test_h1_mixed_methods() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let base = &srv.base_url;

    let r = session
        .get(&url_join(base, "/get"))
        .send()
        .await
        .expect("GET");
    assert_eq!(r.status().as_u16(), 200);

    let r = session
        .post(&url_join(base, "/post"))
        .text_body("hello")
        .send()
        .await
        .expect("POST");
    assert_eq!(r.status().as_u16(), 200);

    let r = session
        .put(&url_join(base, "/put"))
        .text_body("put")
        .send()
        .await
        .expect("PUT");
    assert_eq!(r.status().as_u16(), 200);

    let r = session
        .delete(&url_join(base, "/delete"))
        .send()
        .await
        .expect("DELETE");
    assert_eq!(r.status().as_u16(), 200);

    let r = session
        .patch(&url_join(base, "/patch"))
        .text_body("patch")
        .send()
        .await
        .expect("PATCH");
    assert_eq!(r.status().as_u16(), 200);

    let r = session
        .get(&url_join(base, "/bytes/1024"))
        .send()
        .await
        .expect("final GET");
    assert_eq!(r.bytes().len(), 1024);
}

// ============================================================================
// Large JSON body
// ============================================================================

#[tokio::test]
async fn test_h1_large_json_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let items: Vec<serde_json::Value> = (0..2000)
        .map(|i| serde_json::json!({"id": i, "name": format!("item-{i}"), "data": "x".repeat(100)}))
        .collect();
    let payload = serde_json::json!({ "items": items });

    let resp = session
        .post(&url)
        .json(&payload)
        .send()
        .await
        .expect("large JSON");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Interleaved small and large (H1)
// ============================================================================

#[tokio::test]
async fn test_h1_interleaved_small_large() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let base = &srv.base_url;

    for _ in 0..5 {
        let r = session
            .get(&url_join(base, "/get"))
            .send()
            .await
            .expect("small GET");
        assert_eq!(r.status().as_u16(), 200);

        let r = session
            .get(&url_join(base, "/bytes/524288"))
            .send()
            .await
            .expect("512 KB");
        assert_eq!(r.bytes().len(), 524_288);
    }
}
