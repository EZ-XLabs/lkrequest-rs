//! # lkrequest — HTTP Client with TLS Fingerprint Control
//!
//! `lkrequest` is a high-level HTTP client library built on top of [`lktls`]
//! and [`hyper`], providing fine-grained TLS/H2 fingerprint control for
//! anti-bot evasion scenarios.
//!
//! ## Architecture: Client / Session / Request
//!
//! ```text
//! Client (fingerprint template, immutable, Arc-shared)
//!   └── Session (virtual user: Cookie Jar + connection pool + proxy)
//!         └── Request (single HTTP request)
//!
//! ProxyPool  (proxy management: rotation, health, cooldown, concurrency)
//! SessionPool (multi-session management, built on ProxyPool)
//! ```
//!
//! - **`Client`**: Holds the TLS fingerprint profile, H2 profile, QUIC/H3
//!   profile, and default headers. Immutable after creation, cheap to clone
//!   (`Arc`-based), safe to share across threads and tasks. One per
//!   fingerprint type.
//!
//! - **`Session`**: Represents a single "virtual browser user". Holds its own
//!   Cookie Jar, connection pool, and proxy config. Connections within a Session
//!   are reused (HTTP/2 multiplexing); connections between Sessions are never
//!   shared.
//!
//! - **`SessionPool`**: Manages multiple Sessions with different proxies.
//!   Supports acquire/release with RAII guards, idle timeout, and proxy
//!   rotation strategies. Best for high-concurrency multi-proxy scenarios.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! use lkrequest::Client;
//! use lktls::profile::presets;
//!
//! let client = Client::builder()
//!     .fingerprint(presets::chrome_131())
//!     .default_header("Accept-Language", "en-US,en;q=0.9")
//!     .build();
//!
//! let session = client.session()
//!     .proxy("socks5://proxy1:1080")
//!     .build();
//!
//! let resp = session.get("https://example.com").send().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## High-Concurrency with Proxy Rotation
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! use lkrequest::{Client, SessionPool};
//! use lkrequest::proxy::RotationStrategy;
//! use lktls::profile::presets;
//! use std::time::Duration;
//!
//! let client = Client::builder()
//!     .fingerprint(presets::chrome_131())
//!     .build();
//!
//! let pool = SessionPool::builder()
//!     .client(&client)
//!     .proxies(vec![])
//!     .max_sessions(100)
//!     .idle_timeout(Duration::from_secs(300))
//!     .rotation(RotationStrategy::RoundRobin)
//!     .build();
//!
//! // SessionGuard auto-returns Session to pool on drop
//! let guard = pool.acquire().await;
//! let resp = guard.get("https://target.com").send().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`client`] | `Client` — immutable fingerprint template (TLS + H2 + QUIC/H3 + headers) |
//! | [`session`] | `Session` — virtual browser user (cookie jar + connection pool + proxy) |
//! | [`proxy_pool`] | `ProxyPool` — standalone proxy management with concurrency control |
//! | [`session_pool`] | `SessionPool` — multi-session management with proxy rotation (built on `ProxyPool`) |
//! | [`response`] | `Response` / `StreamingResponse` — HTTP response with auto-decompression |
//! | [`error`] | Unified error types with connection phase diagnostics |
//! | [`proxy`] | Proxy configuration, SOCKS5/HTTP CONNECT, and rotation strategies |
//! | [`preset`] | High-level client preset bundles (TLS + H2 + optional QUIC/H3 + header order) |
//! | [`randomize`] | Fingerprint randomization policy (extension-order jitter; synthetic recombine/full behind `synthetic-fp`) |
//! | [`h2`] | HTTP/2 fingerprint profiles and connection setup |
//! | [`middleware`] | Request/response interceptor chain (onion model) |
//! | [`retry`] | Retry policies — exponential backoff, fixed interval |
//! | [`multipart`] | Multipart/form-data body builder for file uploads |
//! | [`ws`] | WebSocket support — HTTP/1.1 Upgrade (RFC 6455) + H2 Extended CONNECT (RFC 8441) |
//! | [`blocking`] | Synchronous (non-async) API wrapper (includes blocking WebSocket) |
//! | [`dns`] | Pluggable DNS resolution — custom servers, DoH/DoT, HTTPS RR for ECH auto-config |
//! | [`tcp_fingerprint`] | TCP-level fingerprint (JA4T) — window size, TCP options, MSS, window scale, TTL |
//! | [`connection_pool`] | Per-session connection pool with H2 multiplexing |

pub mod alt_svc;
pub mod blocking;
pub mod client;
pub mod connect;
pub mod connection_pool;
pub mod diagnostics;
pub mod dns;
pub mod error;
pub mod h2;
pub mod hsts;
pub mod middleware;
pub mod multipart;
pub mod preset;
pub mod protocol;
pub mod proxy;
pub mod proxy_pool;
pub mod randomize;
pub mod response;
pub mod retry;
pub mod session;
pub mod session_pool;
pub mod tcp_fingerprint;
#[cfg(feature = "telemetry")]
pub mod telemetry;
pub mod tls;
pub mod ws;

// Re-exports for convenience
pub use alt_svc::{
    should_skip_quic, AltSvcCache, AltSvcEntry, BrokenQuicConfig, BrokenQuicPolicy,
    BrokenQuicTracker, BrokenReason, Origin, Scheme as AltSvcScheme,
};
pub use client::{Client, FallbackConfig, ResourceLimits, TimeoutConfig};
pub use connect::{EstablishedConnection, TransportStream};
pub use connection_pool::PoolStats;
pub use dns::{CachedSystemDns, DnsConfig, DnsResolver, HttpsRecord, SystemDnsCacheConfig};
pub use error::{
    ConnectionClosedKind, ConnectionError, ConnectionPhase, ProxyError, ProxyErrorKind, QuicError,
    QuicPhase,
};
pub use hsts::{DynamicHsts, HstsPolicy, NoHsts, StaticHsts};
pub use middleware::Middleware;
pub use preset::ClientPreset;
pub use protocol::{
    AcquisitionPolicy, DnsResolutionMode, FallbackPolicy, HttpIntent, ProtocolPolicy,
    ProxyRouteKind, RacePolicy, RouteKey, UpgradePolicy,
};
pub use proxy_pool::{ProxyGuard, ProxyPool};
#[cfg(feature = "synthetic-fp")]
pub use randomize::Layers;
#[cfg(feature = "synthetic-fp")]
pub use randomize::NegotiabilityFloor;
pub use randomize::Randomize;
pub use response::{
    HttpVersion, NegotiatedHttpVersion, RedirectRecord, Response, StreamingResponse,
};
pub use retry::{ExponentialBackoff, FixedInterval, RetryPolicy};
pub use session::{
    can_send_early_data, AcceptEncoding, ChromeLikeProtocolConfig, Idempotency,
    PreferredHttpVersion, PrefetchResult, ProtocolSelectionPolicy, RedirectPolicy, Session,
};
pub use session_pool::{
    BadProxyConfig, HealthCheckConfig, SessionGuard, SessionPool, SessionPoolStats,
};
pub use tcp_fingerprint::{Ja4tParseError, TcpFingerprint, TcpOption};
pub use tls::{keylog_to_file, ClientHelloCallback, KeyLogCallback, TlsConnector, TlsStream};

// Profile configuration types
// TODO: uncomment when these types are implemented in lkh2
// pub use lkh2::{
//     FlowControlConfig, FrameWritePolicyConfig, H2BehaviorConfig, HpackPolicyConfig,
// };
// pub use lktls::profile::types::SessionResumptionConfig;

/// Re-export lktls for access to profiles and low-level TLS types.
pub use lktls;

/// Re-export lkh2 for access to H2 profiles and connection types.
pub use lkh2;

/// QUIC / HTTP/3 profile type used by `lkrequest`.
#[cfg(feature = "quic-h3")]
pub use lkh3::QuicProfile;
#[cfg(not(feature = "quic-h3"))]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QuicProfile {
    _private: (),
}

/// Re-export lkh3 for access to QUIC/H3 profiles and connection types.
#[cfg(feature = "quic-h3")]
pub use lkh3;
