use crate::backend::{BackendConnectRequest, EndpointBootstrap, QuicBackend, StubQuicBackend};
use crate::cid::{ChromeConnectionIdGenerator, ConnectionIdError, ConnectionIdGenerator};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

/// Endpoint sharing policy derived from the Track D design notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuicEndpointStrategy {
    /// Recommended default: one browser-like client instance shares one UDP socket.
    #[default]
    PerClient,
    /// Highest isolation: each connection attempt creates its own endpoint and socket.
    PerSession,
    /// Reserved for a future process-wide registry; currently behaves like `PerClient`.
    Global,
}

impl QuicEndpointStrategy {
    pub fn recommended() -> Self {
        Self::PerClient
    }

    pub fn shares_udp_socket(self) -> bool {
        matches!(self, Self::PerClient | Self::Global)
    }
}

/// User-facing connection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest<C> {
    pub remote_addr: SocketAddr,
    pub server_name: String,
    pub client_config: C,
}

impl<C> ConnectRequest<C> {
    pub fn new(remote_addr: SocketAddr, server_name: impl Into<String>, client_config: C) -> Self {
        Self {
            remote_addr,
            server_name: server_name.into(),
            client_config,
        }
    }
}

/// A connection attempt that has been started but not awaited yet.
///
/// The owned endpoint keeps per-session endpoints alive while callers decide
/// whether to await the normal handshake future or convert the backend-specific
/// connecting object into a 0-RTT connection.
pub struct StartedConnection<B>
where
    B: QuicBackend,
{
    connecting: B::Connecting,
    _endpoint: Arc<B::Endpoint>,
}

impl<B> StartedConnection<B>
where
    B: QuicBackend,
{
    pub fn new(connecting: B::Connecting, endpoint: Arc<B::Endpoint>) -> Self {
        Self {
            connecting,
            _endpoint: endpoint,
        }
    }

    pub fn into_connecting(self) -> B::Connecting {
        self.connecting
    }

    pub fn into_parts(self) -> (B::Connecting, Arc<B::Endpoint>) {
        (self.connecting, self._endpoint)
    }
}

#[derive(Debug)]
pub enum QuicManagerError<E> {
    ConnectionId(ConnectionIdError),
    Backend(E),
}

impl<E: fmt::Display> fmt::Display for QuicManagerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionId(error) => write!(f, "{error}"),
            Self::Backend(error) => write!(f, "{error}"),
        }
    }
}

impl<E> std::error::Error for QuicManagerError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectionId(error) => Some(error),
            Self::Backend(error) => Some(error),
        }
    }
}

/// Lazy endpoint owner that keeps higher-level policy code independent from Quinn.
pub struct QuicEndpointManager<B = StubQuicBackend, G = ChromeConnectionIdGenerator>
where
    B: QuicBackend,
{
    backend: B,
    endpoint: Option<Arc<B::Endpoint>>,
    bind_addr: SocketAddr,
    strategy: QuicEndpointStrategy,
    max_udp_payload_size: Option<u16>,
    grease_quic_bit: bool,
    initial_destination_cid_len: Option<usize>,
    cid_generator: G,
}

impl QuicEndpointManager<StubQuicBackend, ChromeConnectionIdGenerator> {
    pub fn new(cid_length: usize) -> Result<Self, ConnectionIdError> {
        let generator = ChromeConnectionIdGenerator::new(cid_length)?;
        Ok(Self::with_backend(StubQuicBackend, generator))
    }
}

impl Default for QuicEndpointManager<StubQuicBackend, ChromeConnectionIdGenerator> {
    fn default() -> Self {
        Self::new(ChromeConnectionIdGenerator::DEFAULT_LEN)
            .expect("default stub QUIC manager configuration is valid")
    }
}

impl<B, G> QuicEndpointManager<B, G>
where
    B: QuicBackend,
    G: ConnectionIdGenerator,
{
    pub fn with_backend(backend: B, cid_generator: G) -> Self {
        Self {
            backend,
            endpoint: None,
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            strategy: QuicEndpointStrategy::recommended(),
            max_udp_payload_size: None,
            grease_quic_bit: true,
            initial_destination_cid_len: None,
            cid_generator,
        }
    }

    pub fn bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.bind_addr = bind_addr;
        self
    }

    pub fn strategy(mut self, strategy: QuicEndpointStrategy) -> Self {
        self.strategy = strategy;
        self
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

    pub fn initial_destination_cid_len(mut self, value: usize) -> Self {
        self.initial_destination_cid_len = Some(value);
        self
    }

    pub fn with_initial_destination_cid_len(mut self, value: Option<usize>) -> Self {
        self.initial_destination_cid_len = value;
        self
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn endpoint_strategy(&self) -> QuicEndpointStrategy {
        self.strategy
    }

    pub fn cached_endpoint(&self) -> Option<&Arc<B::Endpoint>> {
        self.endpoint.as_ref()
    }

    pub fn cid_len(&self) -> usize {
        self.cid_generator.cid_len()
    }

    pub fn endpoint_max_udp_payload_size(&self) -> Option<u16> {
        self.max_udp_payload_size
    }

    pub fn grease_quic_bit_enabled(&self) -> bool {
        self.grease_quic_bit
    }

    pub fn endpoint_initial_destination_cid_len(&self) -> Option<usize> {
        self.initial_destination_cid_len
    }

    pub async fn get_or_init(&mut self) -> Result<&Arc<B::Endpoint>, QuicManagerError<B::Error>> {
        if self.endpoint.is_none() {
            tracing::debug!(
                bind_addr = %self.bind_addr,
                cid_len = self.cid_generator.cid_len(),
                max_udp_payload_size = ?self.max_udp_payload_size,
                grease_quic_bit = self.grease_quic_bit,
                initial_destination_cid_len = ?self.initial_destination_cid_len,
                strategy = ?self.strategy,
                "quic.endpoint_create"
            );
            let endpoint = self.create_endpoint()?;
            self.endpoint = Some(Arc::new(endpoint));
        } else {
            tracing::trace!(strategy = ?self.strategy, "quic.endpoint_reuse");
        }

        Ok(self
            .endpoint
            .as_ref()
            .expect("endpoint is initialized before returning"))
    }

    pub async fn connect(
        &mut self,
        request: ConnectRequest<B::ClientConfig>,
    ) -> Result<B::Connection, QuicManagerError<B::Error>> {
        tracing::debug!(
            remote = %request.remote_addr,
            server_name = %request.server_name,
            strategy = ?self.strategy,
            "quic.connect_start"
        );
        let connect_request = BackendConnectRequest {
            remote_addr: request.remote_addr,
            server_name: request.server_name,
            client_config: request.client_config,
            local_connection_id: self.cid_generator.generate(),
        };

        match self.strategy {
            QuicEndpointStrategy::PerSession => {
                let endpoint = self.create_endpoint()?;
                let connection = self
                    .backend
                    .connect(&endpoint, connect_request)
                    .map_err(QuicManagerError::Backend)?
                    .await
                    .map_err(QuicManagerError::Backend)?;
                tracing::debug!(remote = %request.remote_addr, "quic.connect_complete");
                Ok(connection)
            }
            QuicEndpointStrategy::PerClient | QuicEndpointStrategy::Global => {
                let endpoint = Arc::clone(self.get_or_init().await?);
                let connection = self
                    .backend
                    .connect(endpoint.as_ref(), connect_request)
                    .map_err(QuicManagerError::Backend)?
                    .await
                    .map_err(QuicManagerError::Backend)?;
                tracing::debug!(remote = %request.remote_addr, "quic.connect_complete");
                Ok(connection)
            }
        }
    }

    /// Start a QUIC connection and return the backend connecting future
    /// without awaiting handshake completion.
    ///
    /// This is used by HTTP/3 callers that need to call Quinn's
    /// `Connecting::into_0rtt()` before awaiting the handshake.
    pub async fn start_connect(
        &mut self,
        request: ConnectRequest<B::ClientConfig>,
    ) -> Result<StartedConnection<B>, QuicManagerError<B::Error>> {
        tracing::debug!(
            remote = %request.remote_addr,
            server_name = %request.server_name,
            strategy = ?self.strategy,
            "quic.connect_start"
        );
        let remote_addr = request.remote_addr;
        let connect_request = BackendConnectRequest {
            remote_addr,
            server_name: request.server_name,
            client_config: request.client_config,
            local_connection_id: self.cid_generator.generate(),
        };

        match self.strategy {
            QuicEndpointStrategy::PerSession => {
                let endpoint = Arc::new(self.create_endpoint()?);
                let connecting = self
                    .backend
                    .connect(endpoint.as_ref(), connect_request)
                    .map_err(QuicManagerError::Backend)?;
                Ok(StartedConnection::new(connecting, endpoint))
            }
            QuicEndpointStrategy::PerClient | QuicEndpointStrategy::Global => {
                let endpoint = Arc::clone(self.get_or_init().await?);
                let connecting = self
                    .backend
                    .connect(endpoint.as_ref(), connect_request)
                    .map_err(QuicManagerError::Backend)?;
                Ok(StartedConnection::new(connecting, endpoint))
            }
        }
    }

    fn create_endpoint(&self) -> Result<B::Endpoint, QuicManagerError<B::Error>> {
        self.backend
            .create_endpoint(
                EndpointBootstrap::new(self.bind_addr, self.cid_generator.cid_len(), self.strategy)
                    .with_max_udp_payload_size(self.max_udp_payload_size)
                    .grease_quic_bit(self.grease_quic_bit)
                    .with_initial_destination_cid_len(self.initial_destination_cid_len),
            )
            .map_err(QuicManagerError::Backend)
    }

    /// Return a reference to the underlying backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Return the CID generator reference (for creating endpoints externally).
    pub fn cid_generator(&self) -> &G {
        &self.cid_generator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{StubClientConfig, StubConnection, StubQuicError};
    use std::convert::Infallible;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    #[test]
    fn recommended_strategy_is_per_client() {
        assert_eq!(
            QuicEndpointStrategy::recommended(),
            QuicEndpointStrategy::PerClient
        );
        assert!(QuicEndpointStrategy::Global.shares_udp_socket());
        assert!(!QuicEndpointStrategy::PerSession.shares_udp_socket());
    }

    #[test]
    fn chrome_connection_id_generator_defaults_to_eight_bytes() {
        let mut generator = ChromeConnectionIdGenerator::default();
        let cid = generator.generate();

        assert_eq!(generator.len(), 8);
        assert_eq!(cid.len(), 8);
    }

    #[test]
    fn chrome_connection_id_generator_accepts_custom_lengths() {
        let mut generator = ChromeConnectionIdGenerator::new(12).unwrap();
        let cid = generator.generate();

        assert_eq!(generator.cid_len(), 12);
        assert_eq!(cid.len(), 12);
    }

    #[test]
    fn chrome_connection_id_generator_accepts_empty_connection_ids() {
        let mut generator = ChromeConnectionIdGenerator::new(0).unwrap();
        let cid = generator.generate();

        assert_eq!(generator.cid_len(), 0);
        assert!(cid.is_empty());
    }

    #[test]
    fn manager_lazily_initializes_shared_endpoint_once() {
        let backend = CountingBackend::default();
        let counters = backend.counters();
        let mut manager =
            QuicEndpointManager::with_backend(backend, ChromeConnectionIdGenerator::default());

        let first = Arc::clone(block_on(manager.get_or_init()).unwrap());
        let second = Arc::clone(block_on(manager.get_or_init()).unwrap());

        assert_eq!(counters.endpoint_creations.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn per_session_strategy_creates_fresh_endpoints() {
        let backend = CountingBackend::default();
        let counters = backend.counters();
        let mut manager =
            QuicEndpointManager::with_backend(backend, ChromeConnectionIdGenerator::default())
                .strategy(QuicEndpointStrategy::PerSession);

        let first =
            block_on(manager.connect(ConnectRequest::new(server_addr(443), "a.example", ())))
                .unwrap();
        let second =
            block_on(manager.connect(ConnectRequest::new(server_addr(443), "b.example", ())))
                .unwrap();

        assert_eq!(counters.endpoint_creations.load(Ordering::SeqCst), 2);
        assert_eq!(counters.connect_calls.load(Ordering::SeqCst), 2);
        assert_ne!(first, second);
        assert!(manager.cached_endpoint().is_none());
    }

    #[test]
    fn endpoint_manager_forwards_max_udp_payload_size_to_backend() {
        let backend = CountingBackend::default();
        let mut manager =
            QuicEndpointManager::with_backend(backend, ChromeConnectionIdGenerator::default())
                .max_udp_payload_size(1472)
                .grease_quic_bit(false)
                .initial_destination_cid_len(8);

        let connection =
            block_on(manager.connect(ConnectRequest::new(server_addr(443), "a.example", ())))
                .unwrap();

        assert_eq!(connection.max_udp_payload_size, Some(1472));
        assert!(!connection.grease_quic_bit);
        assert_eq!(connection.initial_destination_cid_len, Some(8));
        assert_eq!(manager.endpoint_max_udp_payload_size(), Some(1472));
        assert!(!manager.grease_quic_bit_enabled());
        assert_eq!(manager.endpoint_initial_destination_cid_len(), Some(8));
    }

    #[test]
    fn stub_manager_returns_connection_details_and_chrome_sized_cids() {
        let mut manager = QuicEndpointManager::new(8)
            .unwrap()
            .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .max_udp_payload_size(1472);

        let connection: StubConnection = block_on(manager.connect(ConnectRequest::new(
            server_addr(443),
            "example.com",
            StubClientConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                profile: Some("chrome".to_string()),
            },
        )))
        .unwrap();

        assert_eq!(connection.server_name(), "example.com");
        assert_eq!(connection.local_connection_id().len(), 8);
        assert_eq!(
            connection.endpoint().strategy(),
            QuicEndpointStrategy::PerClient
        );
        assert_eq!(connection.endpoint().max_udp_payload_size(), Some(1472));
        assert!(connection.endpoint().grease_quic_bit());
        assert_eq!(
            connection.client_config().profile.as_deref(),
            Some("chrome")
        );
    }

    #[test]
    fn stub_backend_rejects_empty_server_name() {
        let mut manager = QuicEndpointManager::default();
        let error = block_on(manager.connect(ConnectRequest::new(
            server_addr(443),
            "  ",
            StubClientConfig::default(),
        )))
        .unwrap_err();

        assert!(matches!(
            error,
            QuicManagerError::Backend(StubQuicError::EmptyServerName)
        ));
    }

    #[derive(Clone, Default)]
    struct CountingBackend {
        counters: Arc<Counters>,
    }

    #[derive(Default)]
    struct Counters {
        endpoint_creations: AtomicUsize,
        connect_calls: AtomicUsize,
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    struct CountingEndpoint {
        id: usize,
        max_udp_payload_size: Option<u16>,
        grease_quic_bit: bool,
        initial_destination_cid_len: Option<usize>,
    }

    impl CountingBackend {
        fn counters(&self) -> Arc<Counters> {
            Arc::clone(&self.counters)
        }
    }

    impl QuicBackend for CountingBackend {
        type Endpoint = CountingEndpoint;
        type ClientConfig = ();
        type Connecting = std::future::Ready<Result<Self::Connection, Self::Error>>;
        type Connection = CountingEndpoint;
        type Error = Infallible;

        fn create_endpoint(
            &self,
            bootstrap: EndpointBootstrap,
        ) -> Result<Self::Endpoint, Self::Error> {
            let id = self
                .counters
                .endpoint_creations
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            Ok(CountingEndpoint {
                id,
                max_udp_payload_size: bootstrap.max_udp_payload_size,
                grease_quic_bit: bootstrap.grease_quic_bit,
                initial_destination_cid_len: bootstrap.initial_destination_cid_len,
            })
        }

        fn connect(
            &self,
            endpoint: &Self::Endpoint,
            _request: BackendConnectRequest<Self::ClientConfig>,
        ) -> Result<Self::Connecting, Self::Error> {
            self.counters.connect_calls.fetch_add(1, Ordering::SeqCst);
            Ok(std::future::ready(Ok(*endpoint)))
        }
    }

    fn server_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), port)
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut future = Pin::from(Box::new(future));
        let mut context = Context::from_waker(&waker);

        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("future unexpectedly yielded pending"),
        }
    }

    unsafe fn noop_raw_waker() -> RawWaker {
        RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)
    }

    unsafe fn noop_clone(_: *const ()) -> RawWaker {
        unsafe { noop_raw_waker() }
    }

    unsafe fn noop(_: *const ()) {}

    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
}
