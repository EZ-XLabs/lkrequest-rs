//! Benchmark suite for lkrequest — network layer.
//!
//! Uses an embedded local TLS server (hyper + rustls) with a dynamically
//! generated self-signed certificate.
//!
//! The bench uses `chrome_131()` profile instead of `chrome_144()` because
//! the benchmark keeps historical results comparable with earlier runs.
//!
//! Run with:
//!   cargo bench -p lkrequest --bench request_bench
//!

use std::net::SocketAddr;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use lkrequest::Client;

// ---------------------------------------------------------------------------
// Embedded TLS server
// ---------------------------------------------------------------------------

struct TestServer {
    addr: SocketAddr,
    ca_cert_der: Vec<u8>,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

fn start_test_server(rt: &tokio::runtime::Runtime) -> TestServer {
    let cert_key =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();

    let ca_cert_der = cert_key.cert.der().to_vec();
    let cert_chain = vec![cert_key.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert_key.signing_key.serialize_der(),
    ));
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let addr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        if let Ok((tcp, _)) = accepted {
                            let acceptor = acceptor.clone();
                            tokio::spawn(async move {
                                let stream = match acceptor.accept(tcp).await {
                                    Ok(s) => s,
                                    Err(_) => return,
                                };
                                let svc = service_fn(|_req| async {
                                    Ok::<_, hyper::Error>(
                                        hyper::Response::builder()
                                            .status(200)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from_static(
                                                br#"{"status":"ok"}"#,
                                            )))
                                            .unwrap(),
                                    )
                                });
                                let _ = hyper_util::server::conn::auto::Builder::new(
                                    TokioExecutor::new(),
                                )
                                .serve_connection(TokioIo::new(stream), svc)
                                .await;
                            });
                        }
                    }
                }
            }
        });

        addr
    });

    TestServer {
        addr,
        ca_cert_der,
        _shutdown_tx: shutdown_tx,
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn test_client(ca_cert_der: &[u8]) -> Client {
    Client::builder()
        .fingerprint(lktls::profile::presets::chrome_131())
        .add_ca_cert_der(ca_cert_der)
        .tls_handshake_timeout(std::time::Duration::from_secs(60))
        .build()
}

fn base_url(addr: SocketAddr) -> String {
    format!("https://127.0.0.1:{}", addr.port())
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Single full GET request (TLS + H2 handshake + request + response).
///
/// Reuses one Session across iterations and clears its connection pool
/// before each request, forcing a fresh TLS + H2 handshake every time
/// while properly aborting old connection tasks (avoids TIME_WAIT socket
/// exhaustion on Windows — OS error 10055).
fn bench_single_request(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = start_test_server(&rt);
    let client = test_client(&server.ca_cert_der);
    let url = base_url(server.addr);
    let session = client.session().build();

    rt.block_on(async {
        session
            .get(&url)
            .send()
            .await
            .expect("warmup request failed");
    });

    c.bench_function("single_request_fresh", |b| {
        b.to_async(&rt).iter(|| {
            let session = session.clone();
            let url = url.clone();
            async move {
                session.pool_clear();
                let resp = session.get(&url).send().await.expect("request failed");
                assert_eq!(resp.status().as_u16(), 200);
            }
        });
    });
}

/// Connection reuse (second request reuses existing H2 connection).
fn bench_connection_reuse(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = start_test_server(&rt);
    let client = test_client(&server.ca_cert_der);
    let url = base_url(server.addr);

    let session = rt.block_on(async {
        let session = client.session().build();
        session
            .get(&url)
            .send()
            .await
            .expect("warmup request failed");
        session
    });

    c.bench_function("request_connection_reuse", |b| {
        b.to_async(&rt).iter(|| {
            let session = session.clone();
            let url = url.clone();
            async move {
                let resp = session
                    .get(&url)
                    .send()
                    .await
                    .expect("reuse request failed");
                assert_eq!(resp.status().as_u16(), 200);
            }
        });
    });
}

/// Concurrent requests via H2 multiplexing on the same connection.
fn bench_concurrent_requests(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = start_test_server(&rt);
    let client = test_client(&server.ca_cert_der);
    let url = base_url(server.addr);

    let session = rt.block_on(async {
        let session = client.session().build();
        session
            .get(&url)
            .send()
            .await
            .expect("warmup request failed");
        session
    });

    let mut group = c.benchmark_group("concurrent_requests");

    for n in [2, 5, 10] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.to_async(&rt).iter(|| {
                let session = session.clone();
                let url = url.clone();
                async move {
                    let mut handles = Vec::with_capacity(n);
                    for _ in 0..n {
                        let s = session.clone();
                        let u = url.clone();
                        handles.push(tokio::spawn(async move {
                            s.get(&u).send().await.expect("concurrent request failed")
                        }));
                    }
                    for handle in handles {
                        let resp = handle.await.expect("task panicked");
                        assert_eq!(resp.status().as_u16(), 200);
                    }
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion configuration
// ---------------------------------------------------------------------------

criterion_group! {
    name = fresh_connection;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(5))
        .warm_up_time(std::time::Duration::from_secs(1));
    targets = bench_single_request
}

criterion_group! {
    name = connection_reuse;
    config = Criterion::default()
        .sample_size(50)
        .measurement_time(std::time::Duration::from_secs(10))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets =
        bench_connection_reuse,
        bench_concurrent_requests
}

criterion_main!(fresh_connection, connection_reuse);
