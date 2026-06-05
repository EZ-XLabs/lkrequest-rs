use crate::cid::ConnectionId;
use crate::endpoint::QuicEndpointStrategy;
use std::fmt;
use std::future::{Ready, ready};
use std::net::SocketAddr;

/// Backend-facing endpoint creation parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointBootstrap {
    pub bind_addr: SocketAddr,
    pub cid_len: usize,
    pub strategy: QuicEndpointStrategy,
    pub max_udp_payload_size: Option<u16>,
    pub grease_quic_bit: bool,
    pub initial_destination_cid_len: Option<usize>,
}

impl EndpointBootstrap {
    pub fn new(bind_addr: SocketAddr, cid_len: usize, strategy: QuicEndpointStrategy) -> Self {
        Self {
            bind_addr,
            cid_len,
            strategy,
            max_udp_payload_size: None,
            grease_quic_bit: true,
            initial_destination_cid_len: None,
        }
    }

    pub fn max_udp_payload_size(mut self, value: u16) -> Self {
        self.max_udp_payload_size = Some(value);
        self
    }

    pub fn with_max_udp_payload_size(mut self, value: Option<u16>) -> Self {
        self.max_udp_payload_size = value;
        self
    }

    pub fn grease_quic_bit(mut self, value: bool) -> Self {
        self.grease_quic_bit = value;
        self
    }

    pub fn with_initial_destination_cid_len(mut self, value: Option<usize>) -> Self {
        self.initial_destination_cid_len = value;
        self
    }
}

/// Parameters forwarded to a concrete QUIC backend for connection establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendConnectRequest<C> {
    pub remote_addr: SocketAddr,
    pub server_name: String,
    pub client_config: C,
    pub local_connection_id: ConnectionId,
}

/// Minimal transport surface needed by the local endpoint manager.
///
/// A future Quinn adapter should implement this trait and map:
/// - `Endpoint` to `quinn::Endpoint`
/// - `ClientConfig` to the lktls-backed Quinn client config
/// - `Connection` to `quinn::Connection`
pub trait QuicBackend {
    type Endpoint;
    type ClientConfig;
    type Connecting: Future<Output = Result<Self::Connection, Self::Error>>;
    type Connection;
    type Error;

    fn create_endpoint(&self, bootstrap: EndpointBootstrap) -> Result<Self::Endpoint, Self::Error>;

    fn connect(
        &self,
        endpoint: &Self::Endpoint,
        request: BackendConnectRequest<Self::ClientConfig>,
    ) -> Result<Self::Connecting, Self::Error>;
}

/// Default backend used until `deps/quinn` can be wired into the repository.
#[derive(Debug, Clone, Default)]
pub struct StubQuicBackend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubEndpoint {
    bind_addr: SocketAddr,
    cid_len: usize,
    strategy: QuicEndpointStrategy,
    max_udp_payload_size: Option<u16>,
    grease_quic_bit: bool,
    initial_destination_cid_len: Option<usize>,
}

impl StubEndpoint {
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn cid_len(&self) -> usize {
        self.cid_len
    }

    pub fn strategy(&self) -> QuicEndpointStrategy {
        self.strategy
    }

    pub fn max_udp_payload_size(&self) -> Option<u16> {
        self.max_udp_payload_size
    }

    pub fn grease_quic_bit(&self) -> bool {
        self.grease_quic_bit
    }

    pub fn initial_destination_cid_len(&self) -> Option<usize> {
        self.initial_destination_cid_len
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StubClientConfig {
    pub alpn_protocols: Vec<Vec<u8>>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubConnection {
    endpoint: StubEndpoint,
    remote_addr: SocketAddr,
    server_name: String,
    client_config: StubClientConfig,
    local_connection_id: ConnectionId,
}

impl StubConnection {
    pub fn endpoint(&self) -> &StubEndpoint {
        &self.endpoint
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn client_config(&self) -> &StubClientConfig {
        &self.client_config
    }

    pub fn local_connection_id(&self) -> &ConnectionId {
        &self.local_connection_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubQuicError {
    EmptyServerName,
}

impl fmt::Display for StubQuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyServerName => write!(f, "server name must not be empty"),
        }
    }
}

impl std::error::Error for StubQuicError {}

impl QuicBackend for StubQuicBackend {
    type Endpoint = StubEndpoint;
    type ClientConfig = StubClientConfig;
    type Connecting = Ready<Result<Self::Connection, Self::Error>>;
    type Connection = StubConnection;
    type Error = StubQuicError;

    fn create_endpoint(&self, bootstrap: EndpointBootstrap) -> Result<Self::Endpoint, Self::Error> {
        tracing::debug!(
            bind_addr = %bootstrap.bind_addr,
            cid_len = bootstrap.cid_len,
            strategy = ?bootstrap.strategy,
            grease_quic_bit = bootstrap.grease_quic_bit,
            "quic.stub_endpoint_created"
        );
        Ok(StubEndpoint {
            bind_addr: bootstrap.bind_addr,
            cid_len: bootstrap.cid_len,
            strategy: bootstrap.strategy,
            max_udp_payload_size: bootstrap.max_udp_payload_size,
            grease_quic_bit: bootstrap.grease_quic_bit,
            initial_destination_cid_len: bootstrap.initial_destination_cid_len,
        })
    }

    fn connect(
        &self,
        endpoint: &Self::Endpoint,
        request: BackendConnectRequest<Self::ClientConfig>,
    ) -> Result<Self::Connecting, Self::Error> {
        if request.server_name.trim().is_empty() {
            tracing::debug!("quic.stub_connect_rejected_empty_server_name");
            return Err(StubQuicError::EmptyServerName);
        }

        tracing::debug!(
            remote = %request.remote_addr,
            server_name = %request.server_name,
            cid_len = request.local_connection_id.len(),
            "quic.stub_connect_ready"
        );
        Ok(ready(Ok(StubConnection {
            endpoint: endpoint.clone(),
            remote_addr: request.remote_addr,
            server_name: request.server_name,
            client_config: request.client_config,
            local_connection_id: request.local_connection_id,
        })))
    }
}
