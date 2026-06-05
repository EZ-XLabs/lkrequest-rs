//! Session pool tests — local HTTPS server (Tier 0).

mod support;

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

#[tokio::test]
async fn test_concurrent_sessions_independent() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let url = url_join(&srv.base_url, "/get");

    let guard = client.session().build();
    let guard2 = client.session().build();

    let (a, b) = tokio::join!(async { guard.get(&url).send().await }, async {
        guard2.get(&url).send().await
    },);

    assert_eq!(a.expect("a").status().as_u16(), 200);
    assert_eq!(b.expect("b").status().as_u16(), 200);
}

#[tokio::test]
async fn test_session_pool_stress() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let url = url_join(&srv.base_url, "/get");

    // Few concurrent handshakes: local BoringSSL server can reject under burst load.
    let mut handles = vec![];
    for _ in 0..3 {
        let c = client.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move {
            let s = c.session().build();
            s.get(&u).send().await
        }));
    }

    for h in handles {
        let r = h.await.expect("join");
        assert_eq!(r.expect("req").status().as_u16(), 200);
    }
}
