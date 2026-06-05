use bytes::{Buf, Bytes};
use h3::client;
use h3_quinn::{self, quinn};
use http::HeaderMap;

use crate::profile::{H3Profile, PseudoHeaderId};
use crate::sender::H3Sender;

type QuinnRequestStream = client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type QuinnSendRequest = client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Receive side of a live HTTP/3 request stream.
pub struct H3RecvStream {
    pub(crate) inner: QuinnRequestStream,
}

impl H3RecvStream {
    /// Receive one response body chunk.
    pub async fn data(&mut self) -> Option<Result<Bytes, H3Error>> {
        match self.inner.recv_data().await {
            Ok(Some(mut chunk)) => {
                let data = chunk.copy_to_bytes(chunk.remaining());
                tracing::trace!(bytes = data.len(), "h3.recv_body_chunk");
                Some(Ok(data))
            }
            Ok(None) => {
                tracing::trace!("h3.recv_body_eof");
                None
            }
            Err(error) => {
                tracing::debug!(error = %error, "h3.recv_body_error");
                Some(Err(H3Error::from(error)))
            }
        }
    }

    /// Receive trailing headers if present.
    pub async fn trailers(&mut self) -> Result<Option<HeaderMap>, H3Error> {
        let trailers = self.inner.recv_trailers().await.map_err(H3Error::from)?;
        tracing::trace!(has_trailers = trailers.is_some(), "h3.recv_trailers");
        Ok(trailers)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    #[error("invalid H3 profile: {0}")]
    InvalidProfile(String),
    #[error("h3 connection error: {0}")]
    Connection(#[from] h3::error::ConnectionError),
    #[error("h3 stream error: {0}")]
    Stream(#[from] h3::error::StreamError),
    #[error("driver task join error: {0}")]
    DriverJoin(#[from] tokio::task::JoinError),
}

impl H3Error {
    pub(crate) fn invalid_profile(message: impl Into<String>) -> Self {
        Self::InvalidProfile(message.into())
    }
}

/// Live HTTP/3 connection wrapper backed by `h3` + `h3-quinn`.
pub struct H3Connection {
    profile: H3Profile,
    quic_conn: quinn::Connection,
    sender: H3Sender,
    driver: tokio::task::JoinHandle<Result<(), H3Error>>,
}

fn h3_builder(h3_profile: &H3Profile) -> client::Builder {
    let mut builder = client::builder();
    builder.send_grease(h3_profile.grease_settings);
    builder.control_grease_frame(h3_profile.send_control_grease_frame);
    builder.ordered_settings(h3_profile.effective_settings());
    builder.pseudo_header_order(
        h3_profile
            .pseudo_header_order
            .iter()
            .copied()
            .map(into_h3_pseudo_header)
            .collect(),
    );
    if let Some(max_field_section_size) = h3_profile.max_field_section_size {
        builder.max_field_section_size(max_field_section_size);
    }
    if !h3_profile.priority_updates.is_empty() {
        builder.priority_updates(
            h3_profile
                .priority_updates
                .iter()
                .map(|(id, fv)| (*id, fv.as_bytes().to_vec()))
                .collect(),
        );
    }
    builder
}

/// Build an HTTP/3 connection wrapper on top of a QUIC connection.
pub async fn connect_h3(
    quic_conn: quinn::Connection,
    h3_profile: &H3Profile,
) -> Result<H3Connection, H3Error> {
    h3_profile.validate().map_err(H3Error::invalid_profile)?;
    tracing::debug!(
        remote = %quic_conn.remote_address(),
        settings = h3_profile.settings.len(),
        pseudo_order = %h3_profile.pseudo_header_order_token(),
        grease_settings = h3_profile.grease_settings,
        "h3.connect_start"
    );

    let mut builder = h3_builder(h3_profile);

    let (mut driver, sender) = builder
        .build(h3_quinn::Connection::new(quic_conn.clone()))
        .await?;

    let driver = tokio::spawn(async move {
        let error = driver.wait_idle().await;
        if error.is_h3_no_error() {
            tracing::debug!("h3.driver_idle");
            Ok(())
        } else {
            tracing::debug!(error = %error, "h3.driver_error");
            Err(H3Error::from(error))
        }
    });

    tracing::debug!(remote = %quic_conn.remote_address(), "h3.connect_ready");
    Ok(H3Connection {
        profile: h3_profile.clone(),
        quic_conn,
        sender: H3Sender::new(h3_profile.clone(), sender),
        driver,
    })
}

/// Build an HTTP/3 sender on a QUIC connection that may still be handshaking.
///
/// Callers use this after `quinn::Connecting::into_0rtt()` so H3 control
/// streams and the first request can be written before handshake completion.
pub async fn connect_h3_0rtt(
    quic_conn: quinn::Connection,
    h3_profile: &H3Profile,
    accepted: quinn::ZeroRttAccepted,
) -> Result<H3ZeroRttConnection, H3Error> {
    h3_profile.validate().map_err(H3Error::invalid_profile)?;
    tracing::debug!(
        remote = %quic_conn.remote_address(),
        settings = h3_profile.settings.len(),
        pseudo_order = %h3_profile.pseudo_header_order_token(),
        grease_settings = h3_profile.grease_settings,
        "h3.connect_0rtt_start"
    );

    let mut builder = h3_builder(h3_profile);
    let (mut driver, sender) = builder
        .build(h3_quinn::Connection::new(quic_conn.clone()))
        .await?;

    let driver = tokio::spawn(async move {
        let error = driver.wait_idle().await;
        if error.is_h3_no_error() {
            tracing::debug!("h3.driver_idle");
            Ok(())
        } else {
            tracing::debug!(error = %error, "h3.driver_error");
            Err(H3Error::from(error))
        }
    });

    tracing::debug!(remote = %quic_conn.remote_address(), "h3.connect_0rtt_ready");
    Ok(H3ZeroRttConnection {
        inner: H3Connection {
            profile: h3_profile.clone(),
            quic_conn,
            sender: H3Sender::new(h3_profile.clone(), sender),
            driver,
        },
        accepted,
    })
}

/// HTTP/3 connection created from Quinn 0-RTT state.
pub struct H3ZeroRttConnection {
    inner: H3Connection,
    accepted: quinn::ZeroRttAccepted,
}

impl H3ZeroRttConnection {
    pub fn sender(&self) -> H3Sender {
        self.inner.sender()
    }

    pub async fn accepted(self) -> (H3Connection, bool) {
        let accepted = self.accepted.await;
        (self.inner, accepted)
    }
}

impl H3Connection {
    /// Returns the static profile captured at connection creation time.
    pub fn profile(&self) -> &H3Profile {
        &self.profile
    }

    /// Returns the underlying QUIC connection.
    pub fn quic_connection(&self) -> &quinn::Connection {
        &self.quic_conn
    }

    /// Creates a cloneable sender handle.
    pub fn sender(&self) -> H3Sender {
        self.sender.clone()
    }

    /// Mirrors the `lkh2` naming style for pool code.
    pub fn clone_sender(&self) -> H3Sender {
        self.sender()
    }

    /// Waits for the background HTTP/3 driver to finish.
    pub async fn wait_idle(self) -> Result<(), H3Error> {
        self.driver.await?
    }

    /// Consume the connection and return its reusable parts.
    ///
    /// Callers who pool H3 connections need ownership of **both** the
    /// cloneable [`H3Sender`] (for multiplexing new requests) and the
    /// background driver's [`tokio::task::JoinHandle`] (so the pool can
    /// abort the driver when the pool is cleared, instead of leaking a
    /// detached task).
    ///
    /// The underlying QUIC connection is kept alive by `h3-quinn`'s
    /// internal clone, so dropping the `H3Connection` shell here does not
    /// close the wire.
    pub fn into_parts(self) -> (H3Sender, tokio::task::JoinHandle<Result<(), H3Error>>) {
        (self.sender, self.driver)
    }
}
fn into_h3_pseudo_header(id: PseudoHeaderId) -> h3::PseudoHeader {
    match id {
        PseudoHeaderId::Method => h3::PseudoHeader::Method,
        PseudoHeaderId::Authority => h3::PseudoHeader::Authority,
        PseudoHeaderId::Scheme => h3::PseudoHeader::Scheme,
        PseudoHeaderId::Path => h3::PseudoHeader::Path,
        PseudoHeaderId::Protocol => h3::PseudoHeader::Protocol,
    }
}

pub(crate) type LiveSendRequest = QuinnSendRequest;

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::{Arc, Once},
    };

    use bytes::Bytes;
    use h3::server;
    use http::{Request, Response, StatusCode};
    use quinn::{
        crypto::rustls::{QuicClientConfig, QuicServerConfig},
        Endpoint,
    };
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::chrome_h3;

    fn ensure_rustls_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[tokio::test]
    async fn connect_h3_accepts_valid_profile() {
        ensure_rustls_provider();
        let mut pair = EndpointPair::new().await;
        let quic_conn = pair.connect().await;
        let connection = connect_h3(quic_conn, &chrome_h3()).await.unwrap();
        assert_eq!(connection.profile().settings[0], (0x01, 65_536));
        assert_eq!(
            connection
                .clone_sender()
                .profile()
                .pseudo_header_order_token(),
            "masp"
        );
    }

    #[tokio::test]
    async fn connect_h3_rejects_empty_pseudo_header_order() {
        ensure_rustls_provider();
        let mut pair = EndpointPair::new().await;
        let quic_conn = pair.connect().await;

        let mut profile = chrome_h3();
        profile.pseudo_header_order.clear();

        let error = match connect_h3(quic_conn, &profile).await {
            Ok(_) => panic!("expected invalid profile"),
            Err(error) => error,
        };
        assert!(matches!(error, H3Error::InvalidProfile(_)));
    }

    #[tokio::test]
    async fn sender_sends_real_request() {
        ensure_rustls_provider();
        let mut pair = EndpointPair::new().await;
        let quic_conn = pair.connect().await;
        let connection = connect_h3(quic_conn, &chrome_h3()).await.unwrap();
        let mut sender = connection.sender();

        let request = Request::builder()
            .uri("https://localhost/test")
            .body(None)
            .unwrap();

        let mut response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), http::Version::HTTP_3);
        assert!(response.body_mut().data().await.is_none());
        assert!(response.body_mut().trailers().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn connect_h3_with_priority_updates_exposes_connection_handles() {
        ensure_rustls_provider();
        let mut pair = EndpointPair::new().await;
        let server_addr = pair.server_addr;
        let quic_conn = pair.connect().await;

        // chrome_146_h3 carries a non-empty priority_updates list, exercising the
        // PRIORITY_UPDATE branch of `h3_builder` that chrome_h3 leaves untouched.
        let profile = crate::profile::chrome_146_h3();
        assert!(!profile.priority_updates.is_empty());

        let connection = connect_h3(quic_conn, &profile).await.unwrap();

        // Getters wired correctly: the QUIC connection points at the dialed server.
        assert_eq!(connection.quic_connection().remote_address(), server_addr);
        assert_eq!(connection.profile().pseudo_header_order_token(), "masp");

        // into_parts yields a wired sender plus the driver handle.
        let (sender, driver) = connection.into_parts();
        assert!(sender.is_backend_wired());
        driver.abort();
    }

    struct EndpointPair {
        client: Endpoint,
        server: Endpoint,
        server_addr: SocketAddr,
    }

    impl EndpointPair {
        async fn new() -> Self {
            let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = CertificateDer::from(cert.cert.der().to_vec());
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

            let mut server_tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .unwrap();
            server_tls.alpn_protocols = vec![b"h3".to_vec()];

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_tls).unwrap(),
            ));
            let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
            let server = Endpoint::server(server_config, server_addr).unwrap();
            let server_addr = server.local_addr().unwrap();

            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der).unwrap();

            let mut client_tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_tls.alpn_protocols = vec![b"h3".to_vec()];
            let client_config =
                quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));

            let mut client =
                Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                    .unwrap();
            client.set_default_client_config(client_config);

            let server_task_endpoint = server.clone();
            tokio::spawn(async move {
                let incoming = server_task_endpoint.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let mut h3_conn =
                    server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                if let Some(resolver) = h3_conn.accept().await.unwrap() {
                    let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    stream.send_response(response).await.unwrap();
                    stream.finish().await.unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            });

            Self {
                client,
                server,
                server_addr,
            }
        }

        async fn connect(&mut self) -> quinn::Connection {
            self.client
                .connect(self.server_addr, "localhost")
                .unwrap()
                .await
                .unwrap()
        }
    }

    impl Drop for EndpointPair {
        fn drop(&mut self) {
            self.client.close(0u32.into(), b"test complete");
            self.server.close(0u32.into(), b"test complete");
        }
    }
}
