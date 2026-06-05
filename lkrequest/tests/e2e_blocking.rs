//! Blocking API — local HTTPS (Tier 0). Run blocking `send()` off the async runtime via `spawn_blocking`.

mod support;

use std::time::Duration;

use lkrequest::blocking::{Client, Session};
use lkrequest::h2::profile::chrome_144_h2;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

fn chrome_144_blocking_client() -> Client {
    Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .h2_profile(chrome_144_h2())
            .verify(false)
            .default_header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            )
            .build(),
    )
}

fn session(client: &Client) -> Session {
    client.session().build()
}

#[tokio::test]
async fn test_blocking_get() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send().expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("127.0.0.1"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_post_json() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let payload = serde_json::json!({
            "name": "lkrequest",
            "blocking": true,
        });
        let url = url_join(&base, "/post");
        let resp = session.post(&url).json(&payload).send().expect("post");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("lkrequest"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_cookies() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        session.set_cookie(&base, "test_key", "test_value");
        assert_eq!(
            session.get_cookie(&base, "test_key"),
            Some("test_value".to_string())
        );
        let header = session.cookie_header(&base);
        assert!(header.unwrap().contains("test_key=test_value"));
        session.clear_cookies();
        assert!(session.get_cookies(&base).is_empty());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_builder_chain() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/headers");
        let resp = session
            .get(&url)
            .header("X-Custom-Header", "test-value")
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(15))
            .send()
            .expect("chain");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(
            body.contains("X-Custom-Header") || body.contains("x-custom-header"),
            "body={body}"
        );
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_convenience() {
    let inner_client = lkrequest::Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .build();
    let client = Client::new(inner_client);
    assert!(!client.inner().tls_profile().cipher_suites.is_empty());
}

#[tokio::test]
async fn test_blocking_session_builder() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().max_redirects(5).http1_only().build();
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send().expect("get");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_response_into_text() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send().expect("get");
        let body: String = resp.into_text().expect("into_text");
        assert!(body.contains("127.0.0.1"));
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_streaming() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let url = url_join(&base, "/get");
        let mut resp = session.get(&url).send_streaming().expect("stream");
        assert!(resp.status().is_success());
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().expect("chunk") {
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(body).expect("utf8");
        assert!(text.contains("127.0.0.1"));
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_error_propagation() {
    let client = Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .connect_timeout(Duration::from_millis(100))
            .read_timeout(Duration::from_millis(200))
            .build(),
    );
    tokio::task::spawn_blocking(move || {
        let session = client.session().build();
        let result = session
            .get("https://192.0.2.1/test")
            .timeout(Duration::from_millis(200))
            .send();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_timeout() || err.is_retryable(), "{err}");
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Client HTTP methods
// ============================================================================

#[tokio::test]
async fn test_blocking_client_post() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let url = url_join(&base, "/post");
        let resp = client.post(&url).text_body("hello").send().expect("post");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("hello"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_put() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let url = url_join(&base, "/put");
        let resp = client.put(&url).text_body("put-data").send().expect("put");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("put-data"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_delete() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let url = url_join(&base, "/delete");
        let resp = client.delete(&url).send().expect("delete");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_head() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let url = url_join(&base, "/status/200");
        let resp = client.head(&url).send().expect("head");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_patch() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let url = url_join(&base, "/patch");
        let resp = client
            .patch(&url)
            .text_body("patch-data")
            .send()
            .expect("patch");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("patch-data"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_options() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let url = url_join(&base, "/status/200");
        let resp = client.options(&url).send().expect("options");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_client_builder() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();
    assert!(!client.inner().tls_profile().cipher_suites.is_empty());
}

// ============================================================================
// Session HTTP methods
// ============================================================================

#[tokio::test]
async fn test_blocking_session_put() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/put");
        let resp = session.put(&url).text_body("put-data").send().expect("put");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_delete() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/delete");
        let resp = session.delete(&url).send().expect("delete");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_head() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/status/200");
        let resp = session.head(&url).send().expect("head");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_patch() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/patch");
        let resp = session
            .patch(&url)
            .text_body("patch-data")
            .send()
            .expect("patch");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_options() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/status/200");
        let resp = session.options(&url).send().expect("options");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// SessionBuilder complete chain
// ============================================================================

#[tokio::test]
async fn test_blocking_session_builder_h2_only() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().http2_only().build();
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send().expect("get");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_builder_accept_encoding() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client
            .session()
            .default_accept_encoding(lkrequest::session::AcceptEncoding::GZIP)
            .build();
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send().expect("get");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Session cookie methods
// ============================================================================

#[tokio::test]
async fn test_blocking_session_set_cookie_with_attrs() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        session.set_cookie_with_attrs(&base, "attr_key", "attr_val", Some("/"), None, true, true);
        assert_eq!(
            session.get_cookie(&base, "attr_key"),
            Some("attr_val".to_string())
        );
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_set_cookie_raw() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        session.set_cookie_raw(&base, "raw_key=raw_val; Path=/; HttpOnly");
        assert_eq!(
            session.get_cookie(&base, "raw_key"),
            Some("raw_val".to_string())
        );
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_get_cookie_values() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        session.set_cookie(&base, "multi", "v1");
        let values = session.get_cookie_values(&base, "multi");
        assert!(!values.is_empty());
        assert!(values.contains(&"v1".to_string()));
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_remove_cookie() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        session.set_cookie(&base, "removeme", "value");
        assert!(session.get_cookie(&base, "removeme").is_some());
        session.remove_cookie(&base, "removeme");
        assert!(session.get_cookie(&base, "removeme").is_none());
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Session inner/client accessors
// ============================================================================

#[tokio::test]
async fn test_blocking_session_inner_and_client() {
    let client = chrome_144_blocking_client();
    let session = session(&client);
    let inner = session.inner();
    let client_ref = session.client();
    assert_eq!(
        inner.client().tls_profile().name,
        client.inner().tls_profile().name
    );
    assert_eq!(
        client_ref.h2_profile().settings.len(),
        client.inner().h2_profile().settings.len()
    );
}

// ============================================================================
// RequestBuilder options
// ============================================================================

#[tokio::test]
async fn test_blocking_request_basic_auth() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/headers");
        let resp = session
            .get(&url)
            .basic_auth("user", Some("pass"))
            .send()
            .expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.to_lowercase().contains("authorization"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_bearer_auth() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/headers");
        let resp = session
            .get(&url)
            .bearer_auth("my-token-123")
            .send()
            .expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("my-token-123"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_body() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/post");
        let resp = session
            .post(&url)
            .body(b"raw-bytes".to_vec())
            .send()
            .expect("post");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("raw-bytes"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_text_body() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/post");
        let resp = session
            .post(&url)
            .text_body("hello-text")
            .send()
            .expect("post");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("hello-text"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_form() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/post");
        let resp = session
            .post(&url)
            .form(&[("key", "val")])
            .send()
            .expect("post");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("key=val"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_query() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/get");
        let resp = session
            .get(&url)
            .query(&[("search", "test")])
            .send()
            .expect("get");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_cookie() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/cookies");
        let resp = session.get(&url).cookie("ck", "cv").send().expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("ck"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_cookie_override() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        session.set_cookie(&base, "ov", "original");
        let url = url_join(&base, "/cookies");
        let resp = session
            .get(&url)
            .cookie_override("ov", "overridden")
            .send()
            .expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("overridden"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_headers_map() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/headers");
        let mut hm = http::HeaderMap::new();
        hm.insert("X-Batch-1", "val1".parse().unwrap());
        hm.insert("X-Batch-2", "val2".parse().unwrap());
        let resp = session.get(&url).headers(hm).send().expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.to_lowercase().contains("x-batch-1"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_request_no_auto_decompress() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/get");
        let resp = session.get(&url).no_auto_decompress().send().expect("get");
        assert!(resp.status().is_success());
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// StreamingResponse complete
// ============================================================================

#[tokio::test]
async fn test_blocking_streaming_headers() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send_streaming().expect("stream");
        assert!(resp.headers().contains_key("content-type"));
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_streaming_bytes() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let url = url_join(&base, "/bytes/512");
        let resp = session.get(&url).send_streaming().expect("stream");
        assert!(resp.status().is_success());
        let data = resp.bytes().expect("bytes");
        assert_eq!(data.len(), 512);
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_streaming_text() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send_streaming().expect("stream");
        let text = resp.text().expect("text");
        assert!(!text.is_empty());
        assert!(text.contains("127.0.0.1"));
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_streaming_debug() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send_streaming().expect("stream");
        let debug = format!("{:?}", resp);
        assert!(debug.contains("StreamingResponse"));
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Session preconnect
// ============================================================================

#[tokio::test]
async fn test_blocking_preconnect() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let result = session.preconnect(&base);
        assert!(result.is_ok(), "preconnect failed: {result:?}");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_preconnect_many() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let results = session.preconnect_many(&[&base]);
        assert!(!results.is_empty());
        assert!(results[0].is_ok());
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// SessionPool / SessionGuard
// ============================================================================

#[tokio::test]
async fn test_blocking_session_pool_construction() {
    use lkrequest::blocking::SessionPool;

    let async_client = lkrequest::Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();

    tokio::task::spawn_blocking(move || {
        let pool = SessionPool::build(
            lkrequest::session_pool::SessionPool::builder()
                .client(&async_client)
                .proxy_fn(|| "http://dummy:8080".to_string()),
        );
        assert!(pool.inner().proxy_pool().max_concurrent() > 0);
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_pool_new() {
    let async_client = lkrequest::Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();

    let async_pool = lkrequest::session_pool::SessionPool::builder()
        .client(&async_client)
        .proxy_fn(|| "http://dummy:8080".to_string())
        .build();

    let pool = lkrequest::blocking::SessionPool::new(async_pool);
    assert!(pool.inner().proxy_pool().max_concurrent() > 0);
}

#[tokio::test]
async fn test_blocking_session_guard_methods() {
    use lkrequest::blocking::SessionPool;

    let async_client = lkrequest::Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();

    tokio::task::spawn_blocking(move || {
        let pool = SessionPool::build(
            lkrequest::session_pool::SessionPool::builder()
                .client(&async_client)
                .proxy_fn(|| "http://dummy:8080".to_string()),
        );
        let guard = pool.acquire();
        // Just verify the RequestBuilder is created (don't send - no real proxy)
        let _get = guard.get("https://example.com");
        let _post = guard.post("https://example.com");
        let _put = guard.put("https://example.com");
        let _delete = guard.delete("https://example.com");
        let _head = guard.head("https://example.com");
        let _patch = guard.patch("https://example.com");
        let _options = guard.options("https://example.com");
        assert!(pool.inner().proxy_pool().max_concurrent() > 0);
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_session_pool_mark_bad_and_acquire_fresh() {
    use lkrequest::blocking::SessionPool;

    let async_client = lkrequest::Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build();

    tokio::task::spawn_blocking(move || {
        let pool = SessionPool::build(
            lkrequest::session_pool::SessionPool::builder()
                .client(&async_client)
                .proxy_fn(|| "http://dummy:8080".to_string()),
        );
        let guard = pool.acquire();
        pool.mark_bad(&guard);
        let fresh_guard = pool.acquire_fresh(&guard);
        let _get = fresh_guard.get("https://example.com");
        assert!(pool.inner().proxy_pool().max_concurrent() > 0);
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: retry
// ============================================================================

#[tokio::test]
async fn test_blocking_retry_on_503() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .h2_profile(chrome_144_h2())
            .verify(false)
            .build(),
    );
    tokio::task::spawn_blocking(move || {
        let session = client
            .session()
            .retry_policy(lkrequest::retry::ExponentialBackoff {
                max_retries: 1,
                base_delay: Duration::from_millis(50),
                max_delay: Duration::from_millis(200),
                jitter: false,
            })
            .build();
        let url = url_join(&base, "/status/503");
        let start = std::time::Instant::now();
        let _ = session.get(&url).send();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(30),
            "retry should add delay, elapsed={elapsed:?}"
        );
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: multipart
// ============================================================================

#[tokio::test]
async fn test_blocking_multipart() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/post");
        let form = lkrequest::multipart::Multipart::new()
            .text("field1", "value1")
            .text("field2", "value2")
            .file("upload", "test.txt", "text/plain", b"file-content".to_vec());

        let resp = session
            .post(&url)
            .multipart(form)
            .send()
            .expect("multipart");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        assert!(body.contains("value1"), "body={body}");
        assert!(body.contains("file-content"), "body={body}");
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: middleware
// ============================================================================

#[tokio::test]
async fn test_blocking_middleware() {
    use lkrequest::middleware::{Middleware, MiddlewareRequest, MiddlewareResponse};

    struct TestMiddleware;

    impl Middleware for TestMiddleware {
        fn on_request(
            &self,
            mut req: MiddlewareRequest,
        ) -> Result<MiddlewareRequest, lkrequest::error::Error> {
            req.headers.insert(
                http::header::HeaderName::from_bytes(b"x-blocking-mw").unwrap(),
                http::header::HeaderValue::from_static("works"),
            );
            Ok(req)
        }

        fn on_response(
            &self,
            resp: MiddlewareResponse,
        ) -> Result<MiddlewareResponse, lkrequest::error::Error> {
            Ok(resp)
        }
    }

    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .h2_profile(chrome_144_h2())
            .verify(false)
            .middleware(TestMiddleware)
            .build(),
    );
    tokio::task::spawn_blocking(move || {
        let session = client.session().build();
        let url = url_join(&base, "/headers");
        let resp = session.get(&url).send().expect("get");
        assert!(resp.status().is_success());
        let body = resp.text().expect("text");
        let lower = body.to_lowercase();
        assert!(
            lower.contains("x-blocking-mw"),
            "middleware header missing: {body}"
        );
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: compression
// ============================================================================

#[tokio::test]
async fn test_blocking_auto_decompress_gzip() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/compress/gzip");
        let resp = session.get(&url).send().expect("gzip");
        assert!(resp.status().is_success());
        let text = resp.text().expect("text");
        assert!(
            text.contains("Hello, compressed world!"),
            "gzip decompression failed: {text}"
        );
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: redirect with history
// ============================================================================

#[tokio::test]
async fn test_blocking_redirect_history() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/redirect/2");
        let resp = session.get(&url).send().expect("redirect");
        assert_eq!(resp.status().as_u16(), 200);
        assert!(resp.was_redirected());
        let history = resp.redirect_history();
        assert_eq!(history.len(), 2, "expected 2 hops");
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: error_for_status
// ============================================================================

#[tokio::test]
async fn test_blocking_error_for_status() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/status/404");
        let resp = session.get(&url).send().expect("request");
        let err = resp.error_for_status().unwrap_err();
        assert!(err.is_status());
        assert_eq!(err.status().unwrap().as_u16(), 404);
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: JSON response
// ============================================================================

#[tokio::test]
async fn test_blocking_json_response() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/get");
        let resp = session.get(&url).send().expect("request");
        let body: serde_json::Value = resp.json().expect("json");
        assert!(body.get("url").is_some());
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: basic auth
// ============================================================================

#[tokio::test]
async fn test_blocking_basic_auth_endpoint() {
    let srv = start_local_https_server().await;
    let base = srv.base_url.clone();
    let client = chrome_144_blocking_client();
    tokio::task::spawn_blocking(move || {
        let session = session(&client);
        let url = url_join(&base, "/basic-auth/user/pass");
        let resp = session
            .get(&url)
            .basic_auth("user", Some("pass"))
            .send()
            .expect("basic auth");
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().expect("json");
        assert_eq!(body["authenticated"].as_bool(), Some(true));
    })
    .await
    .expect("spawn_blocking");
}

// ============================================================================
// Blocking: WebSocket
// ============================================================================

#[tokio::test]
async fn test_blocking_websocket_text_echo() {
    use support::local_wss::start_local_wss_server;

    let wss = start_local_wss_server().await;
    let wss_url = wss.url.clone();
    let client = Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .verify(false)
            .build(),
    );
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let mut ws = session.websocket(&wss_url).connect().expect("ws connect");

        ws.send_text("blocking hello").expect("send_text");
        let msg = ws.recv().expect("recv");
        match msg {
            lkrequest::ws::WsMessage::Text(t) => assert_eq!(t, "blocking hello"),
            other => panic!("expected text, got: {other:?}"),
        }

        ws.close(None).expect("close");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_websocket_binary_echo() {
    use support::local_wss::start_local_wss_server;

    let wss = start_local_wss_server().await;
    let wss_url = wss.url.clone();
    let client = Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .verify(false)
            .build(),
    );
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let mut ws = session.websocket(&wss_url).connect().expect("ws connect");

        let data = vec![0x01, 0x02, 0x03, 0xFF];
        ws.send_binary(&data).expect("send_binary");
        let msg = ws.recv().expect("recv");
        match msg {
            lkrequest::ws::WsMessage::Binary(b) => assert_eq!(b, data),
            other => panic!("expected binary, got: {other:?}"),
        }

        ws.close(None).expect("close");
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test]
async fn test_blocking_websocket_url_accessor() {
    use support::local_wss::start_local_wss_server;

    let wss = start_local_wss_server().await;
    let wss_url = wss.url.clone();
    let client = Client::new(
        lkrequest::Client::builder()
            .fingerprint(presets::chrome_144())
            .verify(false)
            .build(),
    );
    tokio::task::spawn_blocking(move || {
        let session = client.session().http1_only().build();
        let ws = session.websocket(&wss_url).connect().expect("ws connect");
        assert!(ws.url().starts_with("wss://127.0.0.1:"));
    })
    .await
    .expect("spawn_blocking");
}
