use crate::backend::{BackendConnectRequest, EndpointBootstrap, QuicBackend};
use crate::cid::{ChromeConnectionIdGenerator, ConnectionIdError, ConnectionIdGenerator as _};
use quinn::{ConfigError, ConnectError, ConnectionError, Endpoint};
use quinn_proto::{ConnectionId as QuinnConnectionId, ConnectionIdGenerator as QuinnCidGenerator};
use std::future::Future;
use std::io;
use std::net::UdpSocket;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Once;
use std::task::{Context, Poll};
use thiserror::Error;

fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = quinn::rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Clone)]
pub struct QuinnBackend {
    runtime: Arc<dyn quinn::Runtime>,
}

impl QuinnBackend {
    pub fn new(runtime: Arc<dyn quinn::Runtime>) -> Self {
        ensure_rustls_crypto_provider();
        Self { runtime }
    }

    pub fn tokio() -> Self {
        Self::new(Arc::new(quinn::TokioRuntime))
    }
}

impl Default for QuinnBackend {
    fn default() -> Self {
        Self::tokio()
    }
}

#[derive(Debug)]
pub struct QuinnConnecting {
    inner: quinn::Connecting,
}

impl QuinnConnecting {
    fn new(inner: quinn::Connecting) -> Self {
        Self { inner }
    }

    pub fn into_0rtt(self) -> Result<(quinn::Connection, quinn::ZeroRttAccepted), Self> {
        self.inner.into_0rtt().map_err(QuinnConnecting::new)
    }
}

impl Future for QuinnConnecting {
    type Output = Result<quinn::Connection, QuinnBackendError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(Ok(connection)) => {
                tracing::debug!(remote = %connection.remote_address(), "quic.quinn_connect_ready");
                Poll::Ready(Ok(connection))
            }
            Poll::Ready(Err(error)) => {
                tracing::debug!(error = %error, "quic.quinn_connect_failed");
                Poll::Ready(Err(QuinnBackendError::Connection(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Error)]
pub enum QuinnBackendError {
    #[error("invalid connection ID configuration: {0}")]
    ConnectionId(#[from] ConnectionIdError),
    #[error("invalid QUIC endpoint configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("failed to create QUIC endpoint: {0}")]
    Io(#[from] io::Error),
    #[error("failed to start QUIC connection: {0}")]
    Connect(#[from] ConnectError),
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] ConnectionError),
}

impl QuinnBackend {
    /// Create an endpoint using a pre-constructed abstract socket instead of
    /// binding a new OS UDP socket. Used for SOCKS5 UDP relay sockets.
    pub fn create_endpoint_with_socket(
        &self,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        cid_len: usize,
        max_udp_payload_size: Option<u16>,
        grease_quic_bit: bool,
        initial_destination_cid_len: Option<usize>,
    ) -> Result<Endpoint, QuinnBackendError> {
        tracing::debug!(
            local_addr = %socket.local_addr().unwrap_or_else(|_| "unknown".parse().unwrap()),
            cid_len,
            max_udp_payload_size,
            grease_quic_bit,
            initial_destination_cid_len,
            "quic.quinn_endpoint_create_with_socket"
        );
        let endpoint_config = quinn_endpoint_config(
            cid_len,
            max_udp_payload_size,
            grease_quic_bit,
            initial_destination_cid_len,
        )?;

        Ok(quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            socket,
            Arc::clone(&self.runtime),
        )?)
    }
}

impl QuicBackend for QuinnBackend {
    type Endpoint = Endpoint;
    type ClientConfig = quinn::ClientConfig;
    type Connecting = QuinnConnecting;
    type Connection = quinn::Connection;
    type Error = QuinnBackendError;

    fn create_endpoint(&self, bootstrap: EndpointBootstrap) -> Result<Self::Endpoint, Self::Error> {
        tracing::debug!(
            bind_addr = %bootstrap.bind_addr,
            cid_len = bootstrap.cid_len,
            max_udp_payload_size = ?bootstrap.max_udp_payload_size,
            grease_quic_bit = bootstrap.grease_quic_bit,
            initial_destination_cid_len = ?bootstrap.initial_destination_cid_len,
            strategy = ?bootstrap.strategy,
            "quic.quinn_endpoint_create"
        );
        let socket = UdpSocket::bind(bootstrap.bind_addr)?;
        let endpoint_config = quinn_endpoint_config(
            bootstrap.cid_len,
            bootstrap.max_udp_payload_size,
            bootstrap.grease_quic_bit,
            bootstrap.initial_destination_cid_len,
        )?;

        Ok(quinn::Endpoint::new(
            endpoint_config,
            None,
            socket,
            Arc::clone(&self.runtime),
        )?)
    }

    fn connect(
        &self,
        endpoint: &Self::Endpoint,
        request: BackendConnectRequest<Self::ClientConfig>,
    ) -> Result<Self::Connecting, Self::Error> {
        let _ = request.local_connection_id;
        tracing::debug!(
            remote = %request.remote_addr,
            server_name = %request.server_name,
            "quic.quinn_connect_start"
        );
        let connecting = endpoint.connect_with(
            request.client_config,
            request.remote_addr,
            &request.server_name,
        )?;
        Ok(QuinnConnecting::new(connecting))
    }
}

fn quinn_endpoint_config(
    cid_len: usize,
    max_udp_payload_size: Option<u16>,
    grease_quic_bit: bool,
    initial_destination_cid_len: Option<usize>,
) -> Result<quinn::EndpointConfig, QuinnBackendError> {
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.cid_generator(move || {
        Box::new(
            ChromeConnectionIdGenerator::new(cid_len)
                .expect("manager validates CID length before endpoint creation"),
        )
    });
    endpoint_config.grease_quic_bit(grease_quic_bit);
    if let Some(value) = initial_destination_cid_len {
        endpoint_config.initial_destination_cid_len(value)?;
    }
    if let Some(value) = max_udp_payload_size {
        endpoint_config.max_udp_payload_size(value)?;
    }
    Ok(endpoint_config)
}

impl QuinnCidGenerator for ChromeConnectionIdGenerator {
    fn generate_cid(&mut self) -> QuinnConnectionId {
        QuinnConnectionId::new(self.generate().as_bytes())
    }

    fn validate(&self, cid: &QuinnConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        if cid.len() == crate::cid::ConnectionIdGenerator::cid_len(self) {
            Ok(())
        } else {
            Err(quinn_proto::InvalidCid)
        }
    }

    fn cid_len(&self) -> usize {
        crate::cid::ConnectionIdGenerator::cid_len(self)
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        crate::cid::ConnectionIdGenerator::cid_lifetime(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChromeConnectionIdGenerator;
    use crate::endpoint::{ConnectRequest, QuicEndpointManager};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn loopback_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn endpoint_pair() -> (quinn::Endpoint, quinn::ClientConfig) {
        ensure_rustls_crypto_provider();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let mut server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.cert.der().clone()], key).unwrap();
        let transport = Arc::new(quinn::TransportConfig::default());
        server_config.transport_config(Arc::clone(&transport));

        let mut roots = quinn::rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();

        let mut client_config =
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config.transport_config(transport);

        let endpoint = quinn::Endpoint::server(server_config, loopback_addr(0)).unwrap();
        (endpoint, client_config)
    }

    #[tokio::test]
    async fn quinn_backend_creates_real_endpoint() {
        let backend = QuinnBackend::default();
        let mut manager =
            QuicEndpointManager::with_backend(backend, ChromeConnectionIdGenerator::default());

        let endpoint = Arc::clone(manager.get_or_init().await.unwrap());
        assert_ne!(endpoint.local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn quinn_backend_connects_to_loopback_server() {
        let (server, client_config) = endpoint_pair();
        let server_addr = server.local_addr().unwrap();
        let backend = QuinnBackend::default();
        let mut manager =
            QuicEndpointManager::with_backend(backend, ChromeConnectionIdGenerator::default());

        let accept = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });

        let client = manager
            .connect(ConnectRequest::new(server_addr, "localhost", client_config))
            .await
            .unwrap();
        let server = accept.await.unwrap();

        assert_eq!(client.remote_address(), server_addr);
        assert_eq!(server.remote_address().ip(), loopback_addr(0).ip());
    }

    #[test]
    fn quinn_endpoint_config_applies_max_udp_payload_size() {
        let config = super::quinn_endpoint_config(8, Some(1472), true, Some(8)).unwrap();

        assert_eq!(config.get_max_udp_payload_size(), 1472);
    }

    #[test]
    fn quinn_endpoint_config_accepts_disabled_grease_quic_bit() {
        let config = super::quinn_endpoint_config(8, None, false, None).unwrap();

        assert_eq!(config.get_max_udp_payload_size(), 1472);
    }
}
