//! Proxy configuration, connection, and rotation.
//!
//! Supports:
//! - HTTP CONNECT proxies (`http://host:port`, `https://host:port`)
//! - SOCKS5 proxies (`socks5://host:port`)
//! - Optional authentication (`user:pass@host:port`)
//! - Proxy rotation strategies for [`SessionPool`](crate::session_pool::SessionPool)

mod config;
mod connect;
mod probe;
mod provider;
pub(crate) mod socks5_udp;

pub use config::{ProxyAuth, ProxyConfig, ProxyScheme};
pub use probe::{
    Socks5UdpProbeConfig, Socks5UdpProbeMode, Socks5UdpProbePhase, Socks5UdpProbeReport,
    Socks5UdpProbeSupport, Socks5UdpProbeTarget,
};
pub use provider::{
    BufferedProxyProvider, FnProxyProvider, ProxyProvider, ProxyRotator, RotationStrategy,
};
