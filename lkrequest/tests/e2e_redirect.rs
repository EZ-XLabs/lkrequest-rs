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

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build()
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
