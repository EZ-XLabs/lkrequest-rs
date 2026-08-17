use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

use crate::abi::lk_status_t;
use crate::diagnostics::FfiDiagnostics;
use crate::error::FfiError;
use crate::runtime::runtime;
use crate::types::{lk_dns_resolver_t, lk_proxy_provider_t};

type CookieValueCache = HashMap<(String, String), Box<[u8]>>;

#[derive(Clone, Copy, Debug, Default)]
pub enum PresetKind {
    Chrome131,
    #[default]
    Chrome144,
    Chrome145,
    Chrome146,
    Chrome147,
    Chrome148,
    Chrome149,
    Chrome150,
    Chrome151,
    Firefox133,
    Firefox147,
    Safari18,
    Safari26,
}

pub struct ClientBuilderState {
    pub preset: PresetKind,
    pub h2_preset: Option<PresetKind>,
    pub dns_timeout_ms: Option<u64>,
    pub tcp_connect_timeout_ms: Option<u64>,
    pub tls_handshake_timeout_ms: Option<u64>,
    pub quic_connect_timeout_ms: Option<u64>,
    pub ttfb_timeout_ms: Option<u64>,
    pub total_timeout_ms: Option<u64>,
    pub verify: bool,
    pub use_native_certs: bool,
    pub dns_source: Option<ClientDnsSource>,
    pub max_outstanding_ops: usize,
    pub ca_der_certs: Vec<Vec<u8>>,
    pub default_headers: Vec<(String, String)>,
    pub header_order: Vec<String>,
    pub h3_header_order: Vec<String>,
    pub cookie_order: Vec<String>,
    pub ech_config: Option<Vec<u8>>,
    pub quic_profile_json: Option<Option<String>>,
    pub session_resumption: Option<lkrequest::lktls::profile::types::SessionResumptionConfig>,
    pub tcp_fingerprint_ja4t: Option<String>,
    pub max_response_body_size: Option<usize>,
    pub max_header_count: Option<usize>,
    pub max_header_size: Option<usize>,
    pub max_headers_total_size: Option<usize>,
    pub min_transfer_rate: Option<usize>,
    pub transfer_rate_window_ms: Option<u64>,
    pub max_connections_per_session: Option<usize>,
    pub fallback_h2_to_h1: Option<bool>,
    pub fallback_proxy_to_direct: Option<bool>,
    pub fallback_retry_on_connection_close: Option<bool>,
    pub keylog_file: Option<String>,
    /// Randomization tier: 0=off, 1=extension_order, 2=recombine, 3=full.
    pub randomize_mode: u8,
    /// Layer bitmask for synthetic modes (TLS=1, H2=2, QUIC=4; 0=all).
    pub randomize_layers: u32,
}

impl Default for ClientBuilderState {
    fn default() -> Self {
        Self {
            preset: PresetKind::default(),
            h2_preset: None,
            dns_timeout_ms: None,
            tcp_connect_timeout_ms: None,
            tls_handshake_timeout_ms: None,
            quic_connect_timeout_ms: None,
            ttfb_timeout_ms: None,
            total_timeout_ms: None,
            verify: true,
            use_native_certs: true,
            dns_source: None,
            max_outstanding_ops: 4096,
            ca_der_certs: Vec::new(),
            default_headers: Vec::new(),
            header_order: Vec::new(),
            h3_header_order: Vec::new(),
            cookie_order: Vec::new(),
            ech_config: None,
            quic_profile_json: None,
            session_resumption: None,
            tcp_fingerprint_ja4t: None,
            max_response_body_size: None,
            max_header_count: None,
            max_header_size: None,
            max_headers_total_size: None,
            min_transfer_rate: None,
            transfer_rate_window_ms: None,
            max_connections_per_session: None,
            fallback_h2_to_h1: None,
            fallback_proxy_to_direct: None,
            fallback_retry_on_connection_close: None,
            keylog_file: None,
            randomize_mode: 0,
            randomize_layers: 0,
        }
    }
}

pub enum ClientDnsSource {
    Config(lkrequest::DnsConfig),
    Callback(Arc<FfiDnsResolver>),
}

pub struct ClientShared {
    pub client: lkrequest::Client,
    pub outstanding_ops: AtomicUsize,
    pub max_outstanding_ops: usize,
}

impl ClientShared {
    pub fn try_reserve_outstanding(&self) -> bool {
        loop {
            let current = self.outstanding_ops.load(Ordering::Relaxed);
            if current >= self.max_outstanding_ops {
                return false;
            }
            if self
                .outstanding_ops
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub fn release_outstanding(&self) {
        self.outstanding_ops.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct ClientHandle {
    pub shared: Arc<ClientShared>,
    pub fingerprint_json: std::sync::OnceLock<Vec<u8>>,
}

pub struct ClientBuilderHandle {
    pub state: ClientBuilderState,
}

pub struct SessionShared {
    pub session: lkrequest::Session,
    pub client: Arc<ClientShared>,
}

pub struct SessionHandle {
    pub shared: Arc<SessionShared>,
    pub cookie_json_cache: Mutex<HashMap<String, Box<[u8]>>>,
    pub cookie_value_cache: Mutex<CookieValueCache>,
}

impl SessionHandle {
    pub fn new(shared: Arc<SessionShared>) -> Self {
        Self {
            shared,
            cookie_json_cache: Mutex::new(HashMap::new()),
            cookie_value_cache: Mutex::new(HashMap::new()),
        }
    }
}

pub struct SessionBuilderState {
    pub client: Arc<ClientShared>,
    pub proxy: Option<String>,
    pub redirect_policy: lkrequest::RedirectPolicy,
    pub ech_config: Option<Vec<u8>>,
    pub preferred_http_version: SessionHttpVersionPreference,
    pub default_accept_encoding: Option<lkrequest::AcceptEncoding>,
    pub max_connections: Option<usize>,
    pub idle_timeout_ms: Option<u64>,
    pub retry_policy: SessionRetryPolicy,
    pub header_order: Vec<String>,
    pub h3_header_order: Vec<String>,
    pub cookie_order: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionHttpVersionPreference {
    Auto,
    Http1Only,
    Http2Only,
    Http3Only,
    Http3WithFallback,
}

pub enum SessionRetryPolicy {
    None,
    Fixed {
        max_retries: u32,
        interval_ms: u64,
    },
    Exponential {
        max_retries: u32,
        base_delay_ms: u64,
        max_delay_ms: u64,
        jitter: bool,
    },
}

impl SessionBuilderState {
    pub fn new(client: Arc<ClientShared>) -> Self {
        Self {
            client,
            proxy: None,
            redirect_policy: lkrequest::RedirectPolicy::default(),
            ech_config: None,
            preferred_http_version: SessionHttpVersionPreference::Auto,
            default_accept_encoding: None,
            max_connections: None,
            idle_timeout_ms: None,
            retry_policy: SessionRetryPolicy::None,
            header_order: Vec::new(),
            h3_header_order: Vec::new(),
            cookie_order: Vec::new(),
        }
    }
}

pub struct MultipartHandle {
    pub multipart: lkrequest::multipart::Multipart,
}

pub enum RequestBody {
    None,
    Bytes(Vec<u8>),
    Text(String),
    JsonText(String),
    Form(Vec<(String, String)>),
    Multipart(lkrequest::multipart::Multipart),
}

pub struct RequestConfig {
    pub method: http::Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub body: RequestBody,
    pub timeout_ms: Option<u64>,
    pub auto_decompress: bool,
    pub cookies: Vec<(String, String)>,
    pub cookie_overrides: Vec<(String, String)>,
    pub basic_auth: Option<(String, Option<String>)>,
    pub bearer_auth: Option<String>,
    pub accept_encoding_header_present: bool,
    pub proxy_override: Option<String>,
    pub version_override: Option<lkrequest::PreferredHttpVersion>,
    pub accept_encoding_override: Option<lkrequest::AcceptEncoding>,
    pub header_order: Vec<String>,
    pub h3_header_order: Vec<String>,
    pub cookie_order: Vec<String>,
}

impl RequestConfig {
    pub fn new(method: http::Method, url: String) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            query: Vec::new(),
            body: RequestBody::None,
            timeout_ms: None,
            auto_decompress: true,
            cookies: Vec::new(),
            cookie_overrides: Vec::new(),
            basic_auth: None,
            bearer_auth: None,
            accept_encoding_header_present: false,
            proxy_override: None,
            version_override: None,
            accept_encoding_override: None,
            header_order: Vec::new(),
            h3_header_order: Vec::new(),
            cookie_order: Vec::new(),
        }
    }
}

pub enum RequestLifecycle {
    Building,
    Consumed,
}

pub struct RequestState {
    pub lifecycle: RequestLifecycle,
    pub config: RequestConfig,
}

pub struct SessionPoolGuardShared {
    pub guard: Mutex<Option<lkrequest::session_pool::SessionGuard>>,
}

impl Drop for SessionPoolGuardShared {
    fn drop(&mut self) {
        let Some(guard) = self.guard.get_mut().take() else {
            return;
        };

        if tokio::runtime::Handle::try_current().is_ok() {
            drop(guard);
            return;
        }

        runtime().block_on(async move {
            drop(guard);
            tokio::task::yield_now().await;
        });
    }
}

pub enum RequestOwner {
    Direct(Arc<SessionShared>),
    Pooled(Arc<SessionPoolGuardShared>),
}

pub struct RequestHandle {
    pub client: Arc<ClientShared>,
    pub owner: RequestOwner,
    pub state: Mutex<RequestState>,
}

pub struct ResponseHandle {
    pub response: lkrequest::Response,
    pub diagnostics: FfiDiagnostics,
    pub diagnostics_json: std::sync::OnceLock<Vec<u8>>,
    pub cookies: std::sync::OnceLock<Vec<(String, String)>>,
}

pub enum StreamLifecycle {
    Open,
    Eof,
    Failed,
    Closed,
}

pub struct StreamingState {
    pub lifecycle: StreamLifecycle,
    pub response: Option<lkrequest::StreamingResponse>,
    pub last_chunk: Vec<u8>,
    pub last_is_final: bool,
    pub last_error: Option<FfiError>,
    pub active_read_op: bool,
}

pub struct StreamingShared {
    pub state: Mutex<StreamingState>,
}

pub struct StreamingResponseHandle {
    pub client: Arc<ClientShared>,
    pub shared: Arc<StreamingShared>,
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub auto_decompress: bool,
    pub diagnostics: FfiDiagnostics,
    pub diagnostics_json: std::sync::OnceLock<Vec<u8>>,
}

pub struct ErrorHandle {
    pub error: FfiError,
    pub diagnostics: FfiDiagnostics,
    pub diagnostics_json: std::sync::OnceLock<Vec<u8>>,
}

pub struct StreamChunk {
    pub stream: Arc<StreamingShared>,
    pub data: Vec<u8>,
    pub is_final: bool,
}

pub struct FfiDnsResolver {
    pub resolver: lk_dns_resolver_t,
}

impl FfiDnsResolver {
    pub fn validate(&self) -> Result<(), FfiError> {
        if self.resolver.resolve.is_none() {
            return Err(FfiError::invalid_argument(
                "dns resolver resolve callback is null",
            ));
        }
        Ok(())
    }

    fn parse_socket_addrs_json(&self, bytes: &[u8]) -> io::Result<Vec<SocketAddr>> {
        let values: Vec<String> = serde_json::from_slice(bytes).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("custom DNS resolver returned invalid resolve JSON: {err}"),
            )
        })?;

        let mut addrs = Vec::with_capacity(values.len());
        for value in values {
            let addr: SocketAddr = value.parse().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("custom DNS resolver returned invalid socket address '{value}': {err}"),
                )
            })?;
            addrs.push(addr);
        }
        Ok(addrs)
    }

    fn parse_https_record_json(
        &self,
        bytes: &[u8],
    ) -> io::Result<Option<lkrequest::dns::HttpsRecord>> {
        serde_json::from_slice(bytes).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("custom DNS resolver returned invalid HTTPS record JSON: {err}"),
            )
        })
    }
}

impl Drop for FfiDnsResolver {
    fn drop(&mut self) {
        if let Some(destroy) = self.resolver.destroy {
            unsafe {
                destroy(self.resolver.context);
            }
        }
    }
}

unsafe impl Send for FfiDnsResolver {}
unsafe impl Sync for FfiDnsResolver {}

#[async_trait::async_trait]
impl lkrequest::DnsResolver for FfiDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let callback = self
            .resolver
            .resolve
            .ok_or_else(|| io::Error::other("custom DNS resolver resolve callback missing"))?;

        let mut json_ptr = std::ptr::null();
        let mut json_len = 0usize;
        let status = unsafe {
            callback(
                self.resolver.context,
                host.as_ptr().cast(),
                host.len(),
                port,
                &mut json_ptr,
                &mut json_len,
            )
        };

        if status != lk_status_t::LK_OK {
            return Err(io::Error::other(format!(
                "custom DNS resolver resolve callback failed for {host}:{port}",
            )));
        }

        if json_ptr.is_null() || json_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("custom DNS resolver returned no addresses for {host}:{port}"),
            ));
        }

        let bytes = unsafe { std::slice::from_raw_parts(json_ptr.cast::<u8>(), json_len) };
        let addrs = self.parse_socket_addrs_json(bytes)?;
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("custom DNS resolver returned no addresses for {host}:{port}"),
            ));
        }
        Ok(addrs)
    }

    async fn lookup_https(&self, host: &str) -> io::Result<Option<lkrequest::dns::HttpsRecord>> {
        let Some(callback) = self.resolver.lookup_https else {
            return Ok(None);
        };

        let mut json_ptr = std::ptr::null();
        let mut json_len = 0usize;
        let status = unsafe {
            callback(
                self.resolver.context,
                host.as_ptr().cast(),
                host.len(),
                &mut json_ptr,
                &mut json_len,
            )
        };

        if status != lk_status_t::LK_OK {
            return Err(io::Error::other(format!(
                "custom DNS resolver HTTPS lookup callback failed for {host}",
            )));
        }

        if json_ptr.is_null() || json_len == 0 {
            return Ok(None);
        }

        let bytes = unsafe { std::slice::from_raw_parts(json_ptr.cast::<u8>(), json_len) };
        self.parse_https_record_json(bytes)
    }
}

pub struct FfiProxyProvider {
    pub provider: lk_proxy_provider_t,
}

impl FfiProxyProvider {
    pub fn validate(&self) -> Result<(), FfiError> {
        if self.provider.next_proxy.is_none() {
            return Err(FfiError::invalid_argument(
                "proxy provider next_proxy callback is null",
            ));
        }
        Ok(())
    }
}

impl Drop for FfiProxyProvider {
    fn drop(&mut self) {
        if let Some(destroy) = self.provider.destroy {
            unsafe {
                destroy(self.provider.context);
            }
        }
    }
}

unsafe impl Send for FfiProxyProvider {}
unsafe impl Sync for FfiProxyProvider {}

impl lkrequest::proxy::ProxyProvider for FfiProxyProvider {
    fn next_proxy(&self) -> Option<lkrequest::proxy::ProxyConfig> {
        let callback = self.provider.next_proxy?;
        let mut url_ptr = std::ptr::null();
        let mut url_len = 0usize;
        let status = unsafe { callback(self.provider.context, &mut url_ptr, &mut url_len) };
        if status != lk_status_t::LK_OK || url_ptr.is_null() {
            return None;
        }

        let bytes = unsafe { std::slice::from_raw_parts(url_ptr.cast::<u8>(), url_len) };
        let url = std::str::from_utf8(bytes).ok()?;
        lkrequest::proxy::ProxyConfig::parse(url).ok()
    }

    fn len(&self) -> usize {
        self.provider
            .len
            .map(|callback| unsafe { callback(self.provider.context) })
            .unwrap_or_default()
    }

    fn is_dynamic(&self) -> bool {
        self.provider
            .is_dynamic
            .map(|callback| unsafe { callback(self.provider.context) })
            .unwrap_or(false)
    }
}

pub struct PoolBuilderState {
    pub proxies: Vec<lkrequest::proxy::ProxyConfig>,
    pub rotation: lkrequest::proxy::RotationStrategy,
    pub bad_proxy_config: lkrequest::session_pool::BadProxyConfig,
    pub health_check: Option<lkrequest::session_pool::HealthCheckConfig>,
    pub provider: Option<FfiProxyProvider>,
    pub proxy_buffer: Option<usize>,
}

pub struct ProxyPoolBuilderHandle {
    pub max_proxies: usize,
    pub state: PoolBuilderState,
}

impl Default for ProxyPoolBuilderHandle {
    fn default() -> Self {
        Self {
            max_proxies: 100,
            state: PoolBuilderState::default(),
        }
    }
}

pub struct ProxyPoolHandle {
    pub pool: lkrequest::ProxyPool,
}

pub struct ProxyGuardHandle {
    pub guard: lkrequest::ProxyGuard,
    pub url: Option<Vec<u8>>,
}

pub struct Socks5UdpProbeReportHandle {
    pub report: lkrequest::proxy::Socks5UdpProbeReport,
    pub json: std::sync::OnceLock<Vec<u8>>,
    pub proxy: Vec<u8>,
    pub relay_addr: Option<Vec<u8>>,
    pub error: Option<Vec<u8>>,
}

impl Socks5UdpProbeReportHandle {
    pub fn new(report: lkrequest::proxy::Socks5UdpProbeReport) -> Self {
        Self {
            proxy: report.proxy.as_bytes().to_vec(),
            relay_addr: report.relay_addr.map(|addr| addr.to_string().into_bytes()),
            error: report.error.as_ref().map(|error| error.as_bytes().to_vec()),
            report,
            json: std::sync::OnceLock::new(),
        }
    }
}

pub struct SessionPoolBuilderHandle {
    pub client: Option<Arc<ClientShared>>,
    pub max_sessions: usize,
    pub idle_timeout_ms: u64,
    pub state: PoolBuilderState,
}

impl Default for SessionPoolBuilderHandle {
    fn default() -> Self {
        Self {
            client: None,
            max_sessions: 100,
            idle_timeout_ms: 300_000,
            state: PoolBuilderState::default(),
        }
    }
}

pub struct SessionPoolHandle {
    pub pool: lkrequest::SessionPool,
    pub client: Arc<ClientShared>,
}

pub struct SessionPoolGuardHandle {
    pub shared: Arc<SessionPoolGuardShared>,
    pub client: Arc<ClientShared>,
}

pub fn proxy_url_bytes(proxy: &lkrequest::proxy::ProxyConfig) -> Vec<u8> {
    let auth = proxy
        .auth
        .as_ref()
        .map(|auth| format!("{}:{}@", auth.username, auth.password))
        .unwrap_or_default();

    match &proxy.scheme {
        lkrequest::proxy::ProxyScheme::Http { host, port } => {
            format!("http://{auth}{host}:{port}").into_bytes()
        }
        lkrequest::proxy::ProxyScheme::Socks5 {
            host,
            port,
            remote_dns,
        } => {
            let scheme = if *remote_dns { "socks5h" } else { "socks5" };
            format!("{scheme}://{auth}{host}:{port}").into_bytes()
        }
    }
}

pub enum OpSuccess {
    Response(ResponseHandle),
    Streaming(StreamingResponseHandle),
    Chunk(StreamChunk),
    ProxyGuard(ProxyGuardHandle),
    SessionPoolGuard(SessionPoolGuardHandle),
    Socks5UdpProbeReport(Socks5UdpProbeReportHandle),
}

pub enum OpResult {
    InProgress,
    CompletedOk(Option<OpSuccess>),
    CompletedErr(Option<ErrorHandle>),
    Cancelled,
    Consumed,
}

pub struct OpState {
    pub result: OpResult,
    pub join: Option<tokio::task::JoinHandle<()>>,
}

impl Default for OpState {
    fn default() -> Self {
        Self {
            result: OpResult::InProgress,
            join: None,
        }
    }
}

pub struct OpShared {
    pub state: Mutex<OpState>,
    pub cv: Condvar,
}

impl Default for OpShared {
    fn default() -> Self {
        Self {
            state: Mutex::new(OpState::default()),
            cv: Condvar::new(),
        }
    }
}

pub struct OpHandle {
    pub client: Option<Arc<ClientShared>>,
    pub shared: Arc<OpShared>,
    pub counted: bool,
    pub cleanup: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Drop for OpHandle {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        let should_cleanup = matches!(state.result, OpResult::InProgress);
        if let Some(join) = state.join.take() {
            join.abort();
        }
        drop(state);
        if should_cleanup {
            if let Some(cleanup) = self.cleanup.take() {
                cleanup();
            }
        }
        if self.counted {
            if let Some(client) = &self.client {
                client.release_outstanding();
            }
        }
    }
}

impl Default for PoolBuilderState {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            rotation: lkrequest::proxy::RotationStrategy::RoundRobin,
            bad_proxy_config: lkrequest::session_pool::BadProxyConfig {
                failure_threshold: 3,
                window: std::time::Duration::from_secs(60),
                cooldown_duration: std::time::Duration::from_secs(300),
                max_cooldowns: 5,
            },
            health_check: None,
            provider: None,
            proxy_buffer: None,
        }
    }
}
