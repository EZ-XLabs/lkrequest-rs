use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::Once;

use async_trait::async_trait;
use h3::server;
use http::StatusCode;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{mpsc, oneshot};

fn localhost_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Clone)]
struct LocalIpv4Dns;

#[async_trait]
impl lkrequest::DnsResolver for LocalIpv4Dns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![localhost_addr(port)])
    }
}

#[tokio::test]
async fn lkrequest_http3_only_reaches_local_h3_server() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"hello-h3"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/test", server_addr.port());
    let response = session.get(&url).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    assert_eq!(response.text().unwrap(), "hello-h3");

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_template_injects_default_priority_header() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    let (priority_tx, priority_rx) = oneshot::channel();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                let priority = request
                    .headers()
                    .get("priority")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = priority_tx.send(priority);

                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let mut preset = lkrequest::preset::chrome_146();
    preset
        .quic_profile
        .as_mut()
        .expect("chrome_146 preset should include QUIC profile")
        .h3
        .priority_updates
        .clear();

    let client = lkrequest::Client::builder()
        .preset(preset)
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/priority", server_addr.port());
    let response = session.get(&url).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        priority_rx.await.unwrap(),
        Some("u=1, i".to_string()),
        "chrome_146 HTTP/3 template should inject fetch-style priority header"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_get_replays_when_zero_rtt_is_rejected() {
    ensure_rustls_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| {
            "lkrequest=trace,lktls_quic=trace,lkh3=trace,lkquic=trace,h3=debug,quinn=debug".into()
        }))
        .with_test_writer()
        .try_init();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    server_tls.max_early_data_size = u32::MAX;
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    let (stream_tx, mut stream_rx) = mpsc::channel(3);
    let (event_tx, mut event_rx) = mpsc::channel(32);

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            for idx in 0..3 {
                let _ = event_tx.send(format!("accept_wait_{idx}")).await;
                let incoming = server.accept().await.unwrap();
                let _ = event_tx.send(format!("incoming_{idx}")).await;
                let conn = incoming.await.unwrap();
                let _ = event_tx.send(format!("connected_{idx}")).await;
                let Ok(mut h3_conn) =
                    server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                else {
                    let _ = event_tx.send(format!("h3_rejected_{idx}")).await;
                    continue;
                };
                let _ = event_tx.send(format!("h3_ready_{idx}")).await;

                let resolver = match h3_conn.accept().await {
                    Ok(Some(resolver)) => resolver,
                    Ok(None) => {
                        let _ = event_tx.send(format!("h3_closed_{idx}")).await;
                        continue;
                    }
                    Err(error) if error.is_h3_no_error() => {
                        let _ = event_tx.send(format!("h3_no_error_{idx}")).await;
                        continue;
                    }
                    Err(error) => panic!("server h3 accept failed: {error}"),
                };
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                let _ = event_tx.send(format!("request_{idx}")).await;
                let _ = stream_tx
                    .send((idx, request.method().clone(), stream.is_0rtt()))
                    .await;
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"zero-rtt-ok"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/zerortt", server_addr.port());

    let first = session.get(&url).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.text().unwrap(), "zero-rtt-ok");
    let first_seen = stream_rx.recv().await.unwrap();
    assert_eq!(first_seen.0, 0);
    assert_eq!(first_seen.1, http::Method::GET);
    assert!(
        !first_seen.2,
        "first full handshake request must not be 0-RTT"
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(session);

    let session = client.session().http3_only().build();
    let second = session.get(&url).send().await.unwrap_or_else(|error| {
        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        panic!("second h3 request failed: {error}; server events: {events:?}");
    });
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(second.version(), lkrequest::HttpVersion::H3);
    assert_eq!(second.text().unwrap(), "zero-rtt-ok");
    let second_seen = stream_rx.recv().await.unwrap();
    assert_eq!(second_seen.0, 2);
    assert_eq!(second_seen.1, http::Method::GET);
    assert!(
        !second_seen.2,
        "replayed request must be sent after the server rejects 0-RTT"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn http3_only_without_quic_profile_fails_fast() {
    let client = lkrequest::Client::builder()
        .preset(lkrequest::preset::firefox_147())
        .build();

    let session = client.session().http3_only().build();
    let err = session
        .get("https://example.com/")
        .send()
        .await
        .expect_err("http3_only should fail when the preset has no QUIC/H3 profile");

    assert!(matches!(err, lkrequest::error::Error::InvalidConfig(_)));
    assert!(
        err.to_string().contains("no QUIC/H3 profile"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn lkrequest_http3_streaming_reads_chunks() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"hello-"))
                    .await
                    .unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"stream"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/stream", server_addr.port());
    let mut response = session.get(&url).send_streaming().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"hello-stream");

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_preconnect_warms_h3_pool() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"preconnected-h3"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/preconnect", server_addr.port());

    session.preconnect(&url).await.unwrap();
    assert!(
        session.pool_stats().h3_connections > 0,
        "http3 preconnect should warm the h3 pool"
    );

    let response = session.get(&url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    assert_eq!(response.text().unwrap(), "preconnected-h3");

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_preconnect_is_idempotent() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            drop(conn);
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/preconnect", server_addr.port());

    session.preconnect(&url).await.unwrap();
    let warmed = session.pool_stats().h3_connections;
    session.preconnect(&url).await.unwrap();
    let rewarmed = session.pool_stats().h3_connections;

    assert_eq!(warmed, 1, "first preconnect should warm one h3 connection");
    assert_eq!(
        rewarmed, 1,
        "second preconnect should reuse the warmed h3 connection instead of opening another"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}

/// Wire-level regression for the Chrome HTTP/3 control-stream fingerprint.
///
/// Chrome sends, after SETTINGS on the control stream, a reserved GREASE frame
/// followed by a default RFC 9218 PRIORITY_UPDATE (`element_id=0`,
/// `field_value="u=1, i"`) — browserleaks renders this as `…;GREASE|GREASE|984832|…`.
/// This test drives a *raw* QUIC server (no h3 layer) so it can read the exact
/// bytes lkrequest's `chrome_146` template writes on its control stream and
/// guards several regressions:
///
///  1. **PRIORITY_UPDATE emission** — the frame must actually be sent
///     (profile → builder → control stream), not silently dropped.
///  2. **encode duplication** — `field_value` used to be written into the frame
///     header buffer *and* streamed again as the payload, emitting `"u=1, i"`
///     twice and corrupting every control-stream frame boundary after it.
///  3. **GREASE frame emission + ordering** — a reserved GREASE frame must be
///     present and precede the PRIORITY_UPDATE (Chrome's order).
#[tokio::test]
async fn lkrequest_http3_emits_chrome_control_stream_frames() {
    use std::time::Duration;

    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    let (control_tx, control_rx) = oneshot::channel::<Vec<u8>>();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();

            // Read client-initiated unidirectional streams until we find the H3
            // control stream (stream type 0x00) and capture its leading bytes.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut captured = Vec::new();
            while let Ok(Ok(mut recv)) = tokio::time::timeout_at(deadline, conn.accept_uni()).await
            {
                let mut bytes = Vec::new();
                let mut buf = [0u8; 256];
                // The control stream is never closed, so bound the read by size
                // and a short idle timeout rather than reading to end.
                while bytes.len() < 64 {
                    match tokio::time::timeout(Duration::from_millis(500), recv.read(&mut buf))
                        .await
                    {
                        Ok(Ok(Some(n))) => bytes.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                if bytes.first() == Some(&0x00) {
                    captured = bytes;
                    break;
                }
            }
            let _ = control_tx.send(captured);
        }
    });

    let client = lkrequest::Client::builder()
        .preset(lkrequest::preset::chrome_146())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    // Sanity: the template really does carry the PRIORITY_UPDATE we expect on
    // the wire. If this ever changes, the byte assertions below must too.
    assert_eq!(
        client
            .quic_profile()
            .expect("chrome_146 has a QUIC profile")
            .h3
            .priority_updates,
        vec![(0, "u=1, i".to_string())],
    );

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/priority", server_addr.port());
    // The raw server never answers H3, so the request itself will not complete;
    // we only care about the control-stream bytes it wrote during connect.
    let client_task = tokio::spawn(async move {
        let _ = session.get(&url).send().await;
    });

    let control = tokio::time::timeout(Duration::from_secs(8), control_rx)
        .await
        .expect("server should observe the H3 control stream")
        .expect("control-stream bytes channel");
    client_task.abort();

    // PRIORITY_UPDATE_REQUEST frame type 0xF0700 == varint [80, 0F, 07, 00].
    const PU_TYPE: [u8; 4] = [0x80, 0x0F, 0x07, 0x00];
    let pu_pos = control
        .windows(PU_TYPE.len())
        .position(|w| w == PU_TYPE)
        .unwrap_or_else(|| {
            panic!("no PRIORITY_UPDATE frame on control stream; bytes={control:02x?}")
        });
    let after = &control[pu_pos + PU_TYPE.len()..];

    // length(=7) | element_id(=0) | field_value("u=1, i")
    assert_eq!(
        after.first(),
        Some(&0x07),
        "PRIORITY_UPDATE length must be 7"
    );
    assert_eq!(
        &after[1..8],
        b"\x00u=1, i",
        "PRIORITY_UPDATE payload must be element_id=0 + \"u=1, i\""
    );
    // The frame is exactly 7 payload bytes: the next byte must NOT start a
    // duplicated field_value (the encode-duplication regression).
    assert_ne!(
        after.get(8),
        Some(&b'u'),
        "field_value must not be emitted twice (control stream would be corrupted)"
    );

    // A reserved GREASE frame (payload `b"grease"`) must precede PRIORITY_UPDATE.
    let grease_pos = control
        .windows(6)
        .position(|w| w == b"grease")
        .unwrap_or_else(|| panic!("no control-stream GREASE frame; bytes={control:02x?}"));
    assert!(
        grease_pos < pu_pos,
        "GREASE frame must come before PRIORITY_UPDATE (grease@{grease_pos} pu@{pu_pos})"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}
