//! DNS resolver config (offline) and preconnect against local HTTPS/HTTP (Tier 0).
//!
//! Hickory / public DNS tests remain `#[ignore]` (Tier 2).

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::{Client, DnsConfig, DnsResolver};
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

fn chrome_client_with_dns(dns: DnsConfig) -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .dns(dns)
        .build()
}

#[test]
fn dns_config_system_default() {
    let client = chrome_client();
    let session = client.session().build();
    assert!(std::ptr::eq(session.client().resolver(), client.resolver()));
    assert_eq!(session.pool_stats().total, 0);
}

#[test]
fn dns_config_cloudflare() {
    let client = chrome_client_with_dns(DnsConfig::Cloudflare);
    let session = client.session().build();
    assert!(std::ptr::eq(session.client().resolver(), client.resolver()));
    assert_eq!(session.pool_stats().total, 0);
}

#[test]
fn dns_config_google_https() {
    let client = chrome_client_with_dns(DnsConfig::GoogleHttps);
    let session = client.session().build();
    assert!(std::ptr::eq(session.client().resolver(), client.resolver()));
    assert_eq!(session.pool_stats().total, 0);
}

#[test]
fn dns_config_custom() {
    use std::net::SocketAddr;
    let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let client = chrome_client_with_dns(DnsConfig::Custom(addr));
    let session = client.session().build();
    assert!(std::ptr::eq(session.client().resolver(), client.resolver()));
    assert_eq!(session.pool_stats().total, 0);
}

#[tokio::test]
async fn preconnect_warms_pool() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    session.preconnect(&srv.base_url).await.expect("preconnect");

    session
        .preconnect(&srv.base_url)
        .await
        .expect("second preconnect");

    let url = url_join(&srv.base_url, "/get");
    let resp = session.get(&url).send().await.expect("get");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn preconnect_invalid_url_returns_error() {
    let client = chrome_client();
    let session = client.session().build();
    let result = session.preconnect("not-a-url").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn preconnect_http_warms_pool() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind plain http listener");
    let addr = listener.local_addr().expect("listener addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|_req| async {
                    Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                        bytes::Bytes::from("ok"),
                    )))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let client = chrome_client();
    let session = client.session().build();
    let url = format!("http://127.0.0.1:{}", addr.port());

    session
        .preconnect(&url)
        .await
        .expect("http preconnect should succeed");
    assert!(
        session.pool_stats().total > 0,
        "http preconnect should warm the pool"
    );

    session
        .preconnect(&url)
        .await
        .expect("second http preconnect should succeed (already warmed)");

    let resp_url = format!("{}/get", url);
    let resp = session.get(&resp_url).send().await.expect("get");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn preconnect_http_connects_tcp_no_tls() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind plain http listener");
    let addr = listener.local_addr().expect("listener addr");
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let io = hyper_util::rt::TokioIo::new(stream);
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(|_req| async {
                            Ok::<_, hyper::Error>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from("ok")),
                            ))
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await;
                    });
                }
            }
        }
    });

    let client = chrome_client();
    let session = client.session().build();
    let url = format!("http://127.0.0.1:{}/", addr.port());

    let result = session.preconnect(&url).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(());

    assert!(
        result.is_ok(),
        "http preconnect should succeed: {:?}",
        result.err()
    );
    assert!(
        accepts.load(Ordering::Relaxed) > 0,
        "http preconnect should open a TCP connection"
    );
    assert!(
        session.pool_stats().total > 0,
        "http preconnect should warm the pool"
    );
    assert_eq!(
        session.pool_stats().h2_connections,
        0,
        "http preconnect should not create H2 connections"
    );
}

#[tokio::test]
async fn preconnect_many_works() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let a = srv.base_url.clone();
    let b = srv.base_url.clone();
    let results = session.preconnect_many(&[a.as_str(), b.as_str()]).await;
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "preconnect_many[{i}]: {result:?}");
    }
}

#[tokio::test]
#[ignore = "Tier-2: requires DNS resolution to httpbingo.org"]
async fn hickory_dns_resolve_and_request() {
    let client = chrome_client_with_dns(DnsConfig::Cloudflare);
    let session = client.session().build();

    let resp = session
        .get("https://httpbingo.org/get")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
#[ignore = "Tier-2: public DNS HTTPS record lookup"]
async fn hickory_dns_https_record_lookup() {
    use lkrequest::dns::HickoryDns;

    let resolver = HickoryDns::from_config(&DnsConfig::CloudflareHttps);
    let result = resolver
        .lookup_https("crypto.cloudflare.com")
        .await
        .expect("lookup");

    if let Some(record) = result {
        if let Some(ref ech) = record.ech_config_list {
            assert!(!ech.is_empty());
        }
    }
}
