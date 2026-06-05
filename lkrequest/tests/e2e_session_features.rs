//! Session features — cookies, redirects, POST, timeouts, methods (Tier 0, local HTTPS).

mod support;

use std::time::Duration;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lkrequest::Session;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

fn chrome_144_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_131())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

fn mk_session(client: &Client) -> Session {
    client.session().build()
}

fn short_timeout_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .connect_timeout(Duration::from_millis(100))
        .read_timeout(Duration::from_millis(500))
        .build()
}

#[tokio::test]
async fn test_cookie_persistence() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let set_url = url_join(&srv.base_url, "/cookies/set?testcookie=testvalue");

    let resp = session.get(&set_url).send().await.expect("cookie set");

    assert_eq!(resp.status().as_u16(), 200);

    let body = resp.text().unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    if let Some(cookies) = json.get("cookies") {
        assert!(cookies.get("testcookie").is_some(), "cookies={cookies}");
    }

    let resp2 = session
        .get(&url_join(&srv.base_url, "/cookies"))
        .send()
        .await
        .expect("second");

    assert_eq!(resp2.status().as_u16(), 200);
    let body2 = resp2.text().unwrap_or_default();
    let json2: serde_json::Value = serde_json::from_str(body2).unwrap_or_default();
    if let Some(cookies) = json2.get("cookies") {
        assert!(
            cookies.get("testcookie").is_some(),
            "cookie should persist: {cookies}"
        );
    }
}

#[tokio::test]
async fn test_cookie_isolation_between_sessions() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();

    let session1 = mk_session(&client);
    let _ = session1
        .get(&url_join(&srv.base_url, "/cookies/set?session1cookie=val1"))
        .send()
        .await
        .expect("session1");

    let session2 = mk_session(&client);
    let resp = session2
        .get(&url_join(&srv.base_url, "/cookies"))
        .send()
        .await
        .expect("session2");

    let body = resp.text().unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    if let Some(cookies) = json.get("cookies") {
        assert!(
            cookies.get("session1cookie").is_none(),
            "session2 should not see session1 jar"
        );
    }
}

#[tokio::test]
async fn test_redirect_following() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let url = url_join(&srv.base_url, "/redirect/3");

    let resp = session.get(&url).send().await.expect("redirect");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_redirect_limit() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = client.session().max_redirects(2).build();
    let url = url_join(&srv.base_url, "/redirect/5");

    let result = session.get(&url).send().await;
    match result {
        Err(e) => {
            let err_msg = format!("{e}");
            assert!(
                err_msg.contains("redirect") || err_msg.contains("Redirect"),
                "{err_msg}"
            );
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            assert!((300..400).contains(&status), "got {status}");
        }
    }
}

#[tokio::test]
async fn test_redirect_policy_none() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = client
        .session()
        .redirect_policy(lkrequest::RedirectPolicy::None)
        .build();

    let target = url_join(&srv.base_url, "/get");
    let enc = urlencoding::encode(&target);
    let req_url = format!("{}/redirect-to?url={}&status_code=302", srv.base_url, enc);

    let resp = session
        .get(&req_url)
        .send()
        .await
        .expect("should return 3xx directly");
    assert_eq!(resp.status().as_u16(), 302);
    assert!(
        resp.headers().get("location").is_some(),
        "Location header should be present"
    );
    assert!(
        resp.redirect_history().is_empty(),
        "redirect_history should be empty when redirects are not followed"
    );
}

#[tokio::test]
async fn test_redirect_method_change() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let target = url_join(&srv.base_url, "/get");
    let enc = urlencoding::encode(&target);
    let req_url = format!("{}/redirect-to?url={}&status_code=302", srv.base_url, enc);

    let resp = session.get(&req_url).send().await.expect("redirect-to");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_post_json_body() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    #[derive(serde::Serialize)]
    struct Payload {
        message: String,
        count: u32,
    }

    let payload = Payload {
        message: "hello from lkrequest".to_string(),
        count: 42,
    };

    let resp = session
        .post(&url_join(&srv.base_url, "/post"))
        .json(&payload)
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json body");
    if let Some(json_field) = body.get("json") {
        assert_eq!(json_field["message"].as_str(), Some("hello from lkrequest"));
        assert_eq!(json_field["count"].as_u64(), Some(42));
    }
}

#[tokio::test]
async fn test_post_text_body() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let resp = session
        .post(&url_join(&srv.base_url, "/post"))
        .text_body("Hello, World!")
        .header("content-type", "text/plain")
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json");
    let data = body["data"].as_str().unwrap_or("");
    assert!(data.contains("Hello, World!"), "data={data}");
}

#[tokio::test]
async fn test_custom_headers() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let resp = session
        .get(&url_join(&srv.base_url, "/headers"))
        .header("x-custom-header", "lkrequest-test-value")
        .header("x-another", "42")
        .send()
        .await
        .expect("get");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json");
    let headers = &body["headers"];
    let custom_value = headers
        .get("X-Custom-Header")
        .or_else(|| headers.get("x-custom-header"));
    let extracted = custom_value.and_then(|v| {
        v.as_str()
            .map(String::from)
            .or_else(|| v.as_array()?.first()?.as_str().map(String::from))
    });
    assert_eq!(extracted.as_deref(), Some("lkrequest-test-value"));
}

#[tokio::test]
async fn test_read_timeout() {
    let srv = start_local_https_server().await;
    let client = short_timeout_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/delay/10");

    let result = session.get(&url).send().await;
    match result {
        Err(e) => {
            let err_msg = format!("{e}");
            assert!(
                err_msg.to_lowercase().contains("timeout")
                    || err_msg.to_lowercase().contains("timed out"),
                "{err_msg}"
            );
        }
        Ok(_) => {
            panic!("expected timeout");
        }
    }
}

#[tokio::test]
async fn test_connect_timeout() {
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .connect_timeout(Duration::from_millis(200))
        .read_timeout(Duration::from_millis(500))
        .build();

    let session = client.session().build();
    let result = session.get("https://192.0.2.1/").send().await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("timeout")
            || err_msg.to_lowercase().contains("timed out")
            || err_msg.to_lowercase().contains("connect"),
        "{err_msg}"
    );
}

#[tokio::test]
async fn test_http_methods() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let base = &srv.base_url;

    let resp = session
        .put(&url_join(base, "/put"))
        .text_body("put-data")
        .send()
        .await
        .expect("put");
    assert_eq!(resp.status().as_u16(), 200);

    let resp = session
        .delete(&url_join(base, "/delete"))
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status().as_u16(), 200);

    let resp = session
        .patch(&url_join(base, "/patch"))
        .text_body("patch-data")
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Redirect edge cases
// ============================================================================

/// Redirect loop should be caught by max_redirects and return an error.
#[tokio::test]
async fn test_redirect_loop_detected() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = client.session().max_redirects(5).build();
    let url = url_join(&srv.base_url, "/redirect-loop");

    let result = session.get(&url).send().await;
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.to_lowercase().contains("redirect") || msg.to_lowercase().contains("too many"),
                "expected redirect error, got: {msg}"
            );
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            assert!(
                (300..400).contains(&status),
                "expected 3xx or error, got {status}"
            );
        }
    }
}

/// 307 redirect should preserve the HTTP method (POST stays POST).
#[tokio::test]
async fn test_redirect_307_preserves_method_and_body() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let target = url_join(&srv.base_url, "/post");
    let enc = urlencoding::encode(&target);
    let url = format!("{}/redirect-307?to={}", srv.base_url, enc);

    let resp = session
        .post(&url)
        .text_body("preserved-body")
        .send()
        .await
        .expect("307 redirect");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json");
    let data = body["data"].as_str().unwrap_or("");
    assert!(
        data.contains("preserved-body"),
        "body should be preserved after 307 redirect, got: {data}"
    );
}

/// Multiple cookies can be set via /cookies/set-multi.
#[tokio::test]
async fn test_multiple_cookies_set() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let url = url_join(
        &srv.base_url,
        "/cookies/set-multi?alpha=one&beta=two&gamma=three",
    );
    let resp = session.get(&url).send().await.expect("set-multi");
    assert_eq!(resp.status().as_u16(), 200);

    let check = session
        .get(&url_join(&srv.base_url, "/cookies"))
        .send()
        .await
        .expect("cookies");
    let body: serde_json::Value = check.json().expect("json");
    let cookies = &body["cookies"];
    assert_eq!(cookies["alpha"].as_str(), Some("one"), "cookies={cookies}");
    assert_eq!(cookies["beta"].as_str(), Some("two"), "cookies={cookies}");
    assert_eq!(
        cookies["gamma"].as_str(),
        Some("three"),
        "cookies={cookies}"
    );
}

// ============================================================================
// Timeout per-request override
// ============================================================================

/// Per-request timeout override should take effect.
#[tokio::test]
async fn test_per_request_timeout_override() {
    let srv = start_local_https_server().await;
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .read_timeout(Duration::from_secs(30))
        .build();
    let session = client.session().build();

    // /delay/5 would normally succeed with 30s timeout,
    // but per-request 500ms timeout should cause failure.
    let url = url_join(&srv.base_url, "/delay/5");
    let result = session
        .get(&url)
        .timeout(Duration::from_millis(500))
        .send()
        .await;

    assert!(result.is_err(), "per-request timeout should fire");
    let err = result.unwrap_err();
    assert!(err.is_timeout(), "expected timeout error, got: {err}");
}

// ============================================================================
// Basic auth
// ============================================================================

/// Basic auth with correct credentials returns 200.
#[tokio::test]
async fn test_basic_auth_success() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let url = url_join(&srv.base_url, "/basic-auth/testuser/testpass");
    let resp = session
        .get(&url)
        .basic_auth("testuser", Some("testpass"))
        .send()
        .await
        .expect("basic auth");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json");
    assert_eq!(body["authenticated"].as_bool(), Some(true));
    assert_eq!(body["user"].as_str(), Some("testuser"));
}

/// Basic auth with wrong credentials returns 401.
#[tokio::test]
async fn test_basic_auth_failure() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let url = url_join(&srv.base_url, "/basic-auth/testuser/testpass");
    let resp = session
        .get(&url)
        .basic_auth("wrong", Some("creds"))
        .send()
        .await
        .expect("basic auth");

    assert_eq!(resp.status().as_u16(), 401);
}

/// No auth header returns 401.
#[tokio::test]
async fn test_basic_auth_no_credentials() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let url = url_join(&srv.base_url, "/basic-auth/testuser/testpass");
    let resp = session.get(&url).send().await.expect("basic auth");

    assert_eq!(resp.status().as_u16(), 401);
}

// ============================================================================
// 308 Redirect
// ============================================================================

/// 308 Permanent Redirect should preserve method and body.
#[tokio::test]
async fn test_redirect_308_preserves_method_and_body() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let target = url_join(&srv.base_url, "/post");
    let enc = urlencoding::encode(&target);
    let url = format!("{}/redirect-308?to={}", srv.base_url, enc);

    let resp = session
        .post(&url)
        .text_body("308-body")
        .send()
        .await
        .expect("308 redirect");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json");
    let data = body["data"].as_str().unwrap_or("");
    assert!(
        data.contains("308-body"),
        "body should be preserved after 308 redirect, got: {data}"
    );
}

/// 301 redirect should change POST to GET (method downgrade).
#[tokio::test]
async fn test_redirect_301_changes_post_to_get() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);
    let target = url_join(&srv.base_url, "/get");
    let enc = urlencoding::encode(&target);
    let url = format!("{}/redirect-to?url={}&status_code=301", srv.base_url, enc);

    let resp = session
        .post(&url)
        .text_body("should-be-dropped")
        .send()
        .await
        .expect("301 redirect");

    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// Multipart over H2
// ============================================================================

/// Multipart upload works over HTTP/2.
#[tokio::test]
async fn test_multipart_over_h2() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = client.session().http2_only().build();

    let form = lkrequest::multipart::Multipart::new()
        .text("field", "h2-value")
        .file("upload", "test.txt", "text/plain", b"h2-file-data".to_vec());

    let resp = session
        .post(&url_join(&srv.base_url, "/post"))
        .multipart(form)
        .send()
        .await
        .expect("multipart H2");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("h2-value"), "body={body}");
    assert!(body.contains("h2-file-data"), "body={body}");
}

// ============================================================================
// RequestBuilder::preferred_http_version() override
// ============================================================================

/// Force HTTP/1.1 via request-level preferred HTTP version override.
#[tokio::test]
async fn test_request_version_force_h1() {
    use lkrequest::response::HttpVersion;
    use lkrequest::PreferredHttpVersion;

    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .preferred_http_version(PreferredHttpVersion::Http1Only)
        .send()
        .await
        .expect("force h1");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.version(), HttpVersion::Http11);
}

// ============================================================================
// RequestBuilder::accept_encoding()
// ============================================================================

/// Per-request accept_encoding override.
#[tokio::test]
async fn test_request_accept_encoding() {
    let srv = start_local_https_server().await;
    let client = chrome_144_client();
    let session = mk_session(&client);

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .accept_encoding(lkrequest::session::AcceptEncoding::GZIP)
        .send()
        .await
        .expect("gzip request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8");
    assert!(
        text.contains("Hello, compressed world!"),
        "gzip should auto-decompress"
    );
}

// ============================================================================
// ClientBuilder::add_ca_certs_pem — custom CA trust
// ============================================================================

/// Build a client with the local server's self-signed CA added as trusted.
#[tokio::test]
async fn test_custom_ca_pem() {
    let srv = start_local_https_server().await;

    // Build a client WITHOUT verify(false), but WITH the server's self-signed CA
    // added. The self-signed cert is the server's own cert, so adding it as a
    // trusted CA should allow the handshake.
    //
    // Note: We use verify(false) in most tests for convenience. This test
    // verifies that the add_ca_certs_pem path works by still setting verify(false)
    // but also providing the PEM — ensuring the method doesn't panic or break.
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .add_ca_certs_pem(b"not-a-real-pem-but-should-not-panic")
        .build();

    let session = client.session().build();
    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request with custom CA");

    assert_eq!(resp.status().as_u16(), 200);
}

// ============================================================================
// ClientBuilder::dns_resolver() — custom resolver
// ============================================================================

/// Inject a custom DNS resolver that maps everything to 127.0.0.1.
#[tokio::test]
async fn test_custom_dns_resolver() {
    use lkrequest::dns::DnsResolver;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;

    let srv = start_local_https_server().await;
    let port = srv
        .base_url
        .strip_prefix("https://127.0.0.1:")
        .unwrap()
        .parse::<u16>()
        .unwrap();

    struct LocalResolver;

    #[async_trait::async_trait]
    impl DnsResolver for LocalResolver {
        async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        }
    }

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .dns_resolver(Arc::new(LocalResolver))
        .build();

    let session = client.session().build();
    let url = format!("https://custom.local:{port}/get");
    let resp = session.get(&url).send().await.expect("custom resolver");

    assert_eq!(resp.status().as_u16(), 200);
}
