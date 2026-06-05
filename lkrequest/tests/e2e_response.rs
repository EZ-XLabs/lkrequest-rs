//! Response API tests — local HTTPS server (Tier 0).
//!
//! Covers: error_for_status, redirect_history, cookies(), json(),
//! url(), version(), content_length(), was_redirected().

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::response::HttpVersion;
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

// ---------------------------------------------------------------------------
// error_for_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_error_for_status_ok_passes() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    let resp = resp.error_for_status().expect("200 should pass");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_error_for_status_404() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/status/404"))
        .send()
        .await
        .expect("request");

    let err = resp.error_for_status().unwrap_err();
    assert!(err.is_status());
    assert_eq!(err.status().unwrap().as_u16(), 404);
}

#[tokio::test]
async fn test_error_for_status_500() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/status/500"))
        .send()
        .await
        .expect("request");

    let err = resp.error_for_status().unwrap_err();
    assert!(err.is_status());
    assert_eq!(err.status().unwrap().as_u16(), 500);
}

#[tokio::test]
async fn test_error_for_status_ref_does_not_consume() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    resp.error_for_status_ref().expect("200 should pass");
    let text = resp.text().expect("still accessible");
    assert!(
        text.contains("\"url\":\"https://127.0.0.1/get\""),
        "response body should still be readable after error_for_status_ref, body={text}"
    );
}

// ---------------------------------------------------------------------------
// redirect_history / was_redirected / url()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_redirect_history_populated() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/redirect/3"))
        .send()
        .await
        .expect("redirect");

    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.was_redirected(), "should be redirected");

    let history = resp.redirect_history();
    assert_eq!(history.len(), 3, "3 hops expected, got {}", history.len());

    assert!(history[0].url().contains("/redirect/3"));
    assert_eq!(history[0].status().as_u16(), 302);
    assert!(history[0].redirect_to().contains("/redirect/2"));

    assert!(history[1].url().contains("/redirect/2"));
    assert!(history[2].url().contains("/redirect/1"));
}

#[tokio::test]
async fn test_no_redirect_empty_history() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    assert!(!resp.was_redirected());
    assert!(resp.redirect_history().is_empty());
}

#[tokio::test]
async fn test_disabled_redirects_3xx_is_not_marked_redirected() {
    // Regression: with redirects disabled, a 3xx returned as-is must NOT report
    // was_redirected() (nothing was followed), consistent with redirect_count==0
    // and an empty per-hop history.
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .redirect_policy(lkrequest::RedirectPolicy::None)
        .build();

    let resp = session
        .get(&url_join(&srv.base_url, "/redirect/1"))
        .send()
        .await
        .expect("request");

    assert!(
        resp.status().is_redirection(),
        "should receive the 3xx as-is, got {}",
        resp.status().as_u16()
    );
    assert_eq!(
        resp.redirect_history().len(),
        0,
        "no hop should be followed"
    );
    assert!(
        !resp.was_redirected(),
        "was_redirected() must be false when redirects are disabled"
    );
}

#[tokio::test]
async fn test_url_after_redirect() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/redirect/1"))
        .send()
        .await
        .expect("redirect");

    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        resp.url().contains("/redirect/0"),
        "final url should be /redirect/0, got {}",
        resp.url()
    );
}

// ---------------------------------------------------------------------------
// cookies()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_cookies_parsing() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .redirect_policy(lkrequest::RedirectPolicy::None)
        .build();

    let resp = session
        .get(&url_join(
            &srv.base_url,
            "/cookies/set?testcookie=testvalue",
        ))
        .send()
        .await
        .expect("request with RedirectPolicy::None should always return Ok");

    let cookies = resp.cookies();
    assert!(
        cookies
            .iter()
            .any(|(n, v)| *n == "testcookie" && *v == "testvalue"),
        "cookies: {:?}",
        cookies
    );
}

// ---------------------------------------------------------------------------
// json() deserialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_json_deserialize_typed() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    #[derive(serde::Deserialize)]
    struct GetResponse {
        url: String,
    }

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    let body: GetResponse = resp.json().expect("json deserialize");
    assert!(body.url.contains("/get"));
}

#[tokio::test]
async fn test_response_json_deserialize_value() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    let body: serde_json::Value = resp.json().expect("json");
    assert!(body.get("url").is_some());
}

// ---------------------------------------------------------------------------
// version()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_version_h2() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.version(), HttpVersion::H2);
}

#[tokio::test]
async fn test_response_version_h1() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.version(), HttpVersion::Http11);
}

// ---------------------------------------------------------------------------
// into_text / into_bytes / into_vec
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_into_text() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    let body: String = resp.into_text().expect("into_text");
    assert!(body.contains("url"));
}

#[tokio::test]
async fn test_response_into_bytes() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/100"))
        .send()
        .await
        .expect("request");

    let data = resp.into_bytes();
    assert_eq!(data.len(), 100);
}

#[tokio::test]
async fn test_response_into_vec() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/50"))
        .send()
        .await
        .expect("request");

    let data: Vec<u8> = resp.into_vec();
    assert_eq!(data.len(), 50);
}

// ---------------------------------------------------------------------------
// Debug impl
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_debug_format() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");

    let debug = format!("{:?}", resp);
    assert!(debug.contains("Response"));
    assert!(debug.contains("status"));
}

// ---------------------------------------------------------------------------
// content_length()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_content_length() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/bytes/256"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().len(), 256);
}

// ---------------------------------------------------------------------------
// text() error on non-UTF-8 body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_text_non_utf8_error() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/binary"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let result = resp.text();
    assert!(result.is_err(), "non-UTF-8 body should fail text()");
}

// ---------------------------------------------------------------------------
// json() error on non-JSON body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_json_parse_error() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/text-plain"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let result: Result<serde_json::Value, _> = resp.json();
    assert!(result.is_err(), "plain text should fail json()");
}

// ---------------------------------------------------------------------------
// json() success on valid JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_json_success() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/json"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().expect("json parse");
    assert_eq!(body["message"].as_str(), Some("hello"));
    assert_eq!(body["number"].as_u64(), Some(42));
    assert_eq!(body["nested"]["key"].as_str(), Some("value"));
}
