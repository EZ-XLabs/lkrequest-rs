//! HSTS / scheme-upgrade policy tests against a local HTTPS server (Tier 0).
//!
//! The server speaks TLS only, so an `http://` request succeeds *only if* it is
//! upgraded to `https://` before connecting — which is exactly what an
//! `HstsPolicy` controls.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::hsts::StaticHsts;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::start_local_https_server;

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build()
}

/// Build the http:// form of the server's base URL (same host/port, downgraded).
fn http_base(base_url: &str) -> String {
    base_url.replacen("https://", "http://", 1)
}

/// An HSTS policy upgrades an http:// request to https:// before connecting.
#[tokio::test]
async fn hsts_policy_upgrades_http_to_https() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .hsts_policy(StaticHsts::new(["127.0.0.1"]))
        .build();

    // Request the cleartext URL; the policy must upgrade it to https, so the
    // TLS-only server answers 200.
    let url = format!("{}/get", http_base(&srv.base_url));
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("HSTS upgrade should make the https request succeed");
    assert_eq!(resp.status().as_u16(), 200);
}

/// A closure policy works the same way.
#[tokio::test]
async fn hsts_closure_policy_upgrades() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .hsts_policy(|host: &str| host == "127.0.0.1")
        .build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("closure HSTS upgrade");
    assert_eq!(resp.status().as_u16(), 200);
}

/// The default (NoHsts) does not upgrade: a cleartext request to the TLS-only
/// server fails.
#[tokio::test]
async fn default_no_hsts_does_not_upgrade() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let result = session.get(&url).send().await;
    assert!(
        result.is_err(),
        "without an HSTS policy the cleartext request must not be upgraded, got {:?}",
        result.map(|r| r.status())
    );
}

/// HSTS upgrade runs *before* the https_only gate: an upgraded host is allowed.
#[tokio::test]
async fn hsts_upgrade_runs_before_https_only() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .https_only(true)
        .hsts_policy(StaticHsts::new(["127.0.0.1"]))
        .build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("HSTS should upgrade before https_only rejects");
    assert_eq!(resp.status().as_u16(), 200);
}

/// https_only refuses an http:// initial request when nothing upgrades it.
#[tokio::test]
async fn https_only_refuses_http_initial_request() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().https_only(true).build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let err = session
        .get(&url)
        .send()
        .await
        .expect_err("https_only must refuse a non-HTTPS initial request");
    let msg = format!("{err}");
    assert!(
        msg.contains("https_only") || msg.to_lowercase().contains("non-https"),
        "expected an https_only refusal, got: {msg}"
    );
}
