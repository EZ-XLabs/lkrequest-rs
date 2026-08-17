//! Redirect-handling tests against a local HTTPS server (Tier 0).
//!
//! Covers behavior validated against the Fetch Standard / Chromium net stack:
//! - 303 See Other is followed as GET (previously not followed at all).
//! - The opt-in `https_only` knob refuses a scheme-downgrade redirect, while
//!   the default still follows it (Chrome-faithful).
//! - A total timeout bounds the entire redirect chain, not each hop.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use std::time::{Duration, Instant};
use support::local_https::{start_local_https_server, url_join};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build()
}

async fn run_h1_redirect_server(listener: TcpListener) {
    let (mut first, _) = listener.accept().await.expect("accept POST connection");
    let mut request = vec![0_u8; 4096];
    let request_len = first.read(&mut request).await.expect("read POST");
    let request_text = String::from_utf8_lossy(&request[..request_len]);
    assert!(request_text.starts_with("POST /submit HTTP/1.1\r\n"));
    first
        .write_all(b"HTTP/1.1 302 Found\r\nLocation: /result\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("write redirect");
    first.shutdown().await.expect("close POST connection");

    let (mut second, _) = listener.accept().await.expect("accept redirect connection");
    let request_len = second.read(&mut request).await.expect("read redirect GET");
    let request_text = String::from_utf8_lossy(&request[..request_len]);
    assert!(request_text.starts_with("GET /result HTTP/1.1\r\n"));
    second
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        .await
        .expect("write final response");
}

/// 303 See Other must be followed, rewriting the method to GET.
#[tokio::test]
async fn redirect_303_is_followed_as_get() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().build();

    // POST to a 303 whose Location is /get (GET-only on the server). If the 303
    // is followed as GET, the final response is 200; before the fix the 303 was
    // returned verbatim.
    let url = url_join(&srv.base_url, "/redirect-to?url=/get&status_code=303");
    let resp = session
        .post(&url)
        .text_body("payload")
        .send()
        .await
        .expect("303 should be followed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "303 must be followed to GET /get, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn redirect_reconnects_when_pooled_h1_was_closed_after_302() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let server = tokio::spawn(run_h1_redirect_server(listener));

    let client = Client::builder()
        .total_timeout(Duration::from_secs(2))
        .build();
    let session = client.session().http1_only().build();
    let response = session
        .post(&format!("http://{address}/submit"))
        .text_body("payload")
        .send()
        .await
        .expect("redirect should retry on a fresh H1 connection");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().expect("response text"), "OK");
    server.await.expect("server task");
}

/// With `https_only`, a redirect that downgrades to http:// is refused.
#[tokio::test]
async fn https_only_refuses_downgrade_redirect() {
    let srv = start_local_https_server().await;

    // Server 302-redirects to an http:// URL (same host, downgraded scheme).
    let http_target = format!("{}/get", srv.base_url.replacen("https://", "http://", 1));
    let path = format!("/redirect-to?url={http_target}&status_code=302");
    let url = url_join(&srv.base_url, &path);

    let session = chrome_client().session().https_only(true).build();
    let err = session
        .get(&url)
        .send()
        .await
        .expect_err("https_only must refuse the downgrade redirect");

    let msg = format!("{err}");
    assert!(
        msg.contains("https_only") || msg.to_lowercase().contains("non-https"),
        "expected an https_only refusal, got: {msg}"
    );
}

/// A total timeout must bound the whole redirect chain, not reset per hop.
#[tokio::test]
async fn total_timeout_spans_redirect_chain() {
    let srv = start_local_https_server().await;

    // 6 hops, each sleeping ~300ms (~1.8s total). With a 500ms total timeout,
    // a per-hop timer would let every hop through (each < 500ms) and succeed
    // after ~1.8s; a correct total deadline fails at ~500ms.
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .total_timeout(Duration::from_millis(500))
        .build();
    let session = client.session().build();

    let url = url_join(&srv.base_url, "/slow-redirect/5");
    let start = Instant::now();
    let result = session.get(&url).send().await;
    let elapsed = start.elapsed();

    let err = result.expect_err("expected a total-timeout error");
    assert!(err.is_timeout(), "expected a timeout error, got: {err}");
    assert!(
        elapsed < Duration::from_millis(1200),
        "total timeout must bound the chain (~500ms), elapsed={elapsed:?}"
    );
}
