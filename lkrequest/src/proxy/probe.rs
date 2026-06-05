use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::dns::{DnsResolver, SystemDns};
use crate::error::{Error, ProxyErrorKind, Result};
use crate::proxy::config::{ProxyConfig, ProxyScheme};
use crate::proxy::socks5_udp::{
    decode_socks5_udp, encode_socks5_udp_target, packet_source_matches_relay, SocksTarget,
};

/// SOCKS5 UDP probe depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Socks5UdpProbeMode {
    /// Only perform the SOCKS5 `UDP ASSOCIATE` command.
    AssociateOnly,
    /// Perform `UDP ASSOCIATE`, then verify relay traffic with a DNS UDP query.
    DnsRoundTrip,
}

/// Target used for relay round-trip validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Socks5UdpProbeTarget {
    /// Send a plain DNS UDP query through the SOCKS5 UDP relay.
    DnsUdp {
        server: SocketAddr,
        query: String,
        /// Use ATYP=domain in the SOCKS5 UDP header and let a `socks5h`
        /// proxy resolve the DNS server hostname. When unset, `server` is
        /// used as an IP target.
        server_name: Option<String>,
    },
}

/// Configuration for SOCKS5 UDP capability probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5UdpProbeConfig {
    pub mode: Socks5UdpProbeMode,
    pub timeout: Duration,
    pub target: Socks5UdpProbeTarget,
}

impl Default for Socks5UdpProbeConfig {
    fn default() -> Self {
        Self {
            mode: Socks5UdpProbeMode::DnsRoundTrip,
            timeout: Duration::from_secs(5),
            target: Socks5UdpProbeTarget::DnsUdp {
                server: SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
                query: "example.com".into(),
                server_name: None,
            },
        }
    }
}

/// Probe phase where the result was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Socks5UdpProbePhase {
    NotSocks5,
    UdpAssociate,
    UdpRoundTrip,
}

/// Machine-readable SOCKS5 UDP probe verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Socks5UdpProbeSupport {
    NotSocks5,
    AssociateOk,
    RelayOk,
    Unsupported,
    Failed,
}

/// Structured SOCKS5 UDP probe result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5UdpProbeReport {
    pub proxy: String,
    pub support: Socks5UdpProbeSupport,
    pub phase: Socks5UdpProbePhase,
    pub relay_addr: Option<SocketAddr>,
    pub elapsed: Duration,
    pub error: Option<String>,
}

impl Socks5UdpProbeReport {
    /// Returns `true` only when UDP relay traffic was verified end-to-end.
    pub fn relay_supported(&self) -> bool {
        matches!(self.support, Socks5UdpProbeSupport::RelayOk)
    }

    /// Returns `true` when the proxy accepted the SOCKS5 UDP ASSOCIATE command.
    pub fn associate_supported(&self) -> bool {
        matches!(
            self.support,
            Socks5UdpProbeSupport::AssociateOk | Socks5UdpProbeSupport::RelayOk
        )
    }
}

impl ProxyConfig {
    /// Probe whether this proxy supports SOCKS5 UDP using the system resolver.
    pub async fn probe_socks5_udp(
        &self,
        config: Socks5UdpProbeConfig,
    ) -> Result<Socks5UdpProbeReport> {
        self.probe_socks5_udp_with_resolver(config, &SystemDns)
            .await
    }

    /// Probe whether this proxy supports SOCKS5 UDP.
    ///
    /// `AssociateOnly` confirms that the proxy accepts `UDP ASSOCIATE`.
    /// `DnsRoundTrip` additionally verifies that UDP datagrams can be relayed
    /// by sending a DNS query and waiting for a response.
    pub async fn probe_socks5_udp_with_resolver(
        &self,
        config: Socks5UdpProbeConfig,
        resolver: &dyn DnsResolver,
    ) -> Result<Socks5UdpProbeReport> {
        self.probe_socks5_udp_inner(config, None, resolver).await
    }

    /// Probe SOCKS5 UDP using a client configuration for DNS resolution and
    /// TCP fingerprinting.
    pub async fn probe_socks5_udp_with_client(
        &self,
        config: Socks5UdpProbeConfig,
        client: &crate::Client,
    ) -> Result<Socks5UdpProbeReport> {
        self.probe_socks5_udp_inner(config, client.tcp_fingerprint(), client.resolver())
            .await
    }

    async fn probe_socks5_udp_inner(
        &self,
        config: Socks5UdpProbeConfig,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn DnsResolver,
    ) -> Result<Socks5UdpProbeReport> {
        let started = Instant::now();
        let proxy_id = self.identity();

        if !matches!(self.scheme, ProxyScheme::Socks5 { .. }) {
            return Ok(Socks5UdpProbeReport {
                proxy: proxy_id,
                support: Socks5UdpProbeSupport::NotSocks5,
                phase: Socks5UdpProbePhase::NotSocks5,
                relay_addr: None,
                elapsed: started.elapsed(),
                error: Some("proxy is not SOCKS5".into()),
            });
        }

        let associate = tokio::time::timeout(
            config.timeout,
            self.udp_associate(tcp_fingerprint, resolver),
        )
        .await
        .map_err(|_| {
            Error::timeout(
                format!(
                    "SOCKS5 UDP ASSOCIATE probe timed out after {:?}",
                    config.timeout
                ),
                Some(crate::error::ConnectionPhase::ProxyTunnel),
                Some(config.timeout),
            )
        });

        let (control_conn, relay_addr) = match associate {
            Ok(Ok((control_conn, relay_addr))) => (control_conn, relay_addr),
            Ok(Err(error)) => {
                let support = match error.as_proxy_error().map(|err| err.kind) {
                    Some(ProxyErrorKind::Socks5Error { code: 0x07 }) => {
                        Socks5UdpProbeSupport::Unsupported
                    }
                    _ => Socks5UdpProbeSupport::Failed,
                };
                return Ok(Socks5UdpProbeReport {
                    proxy: proxy_id,
                    support,
                    phase: Socks5UdpProbePhase::UdpAssociate,
                    relay_addr: None,
                    elapsed: started.elapsed(),
                    error: Some(error.to_string()),
                });
            }
            Err(error) => {
                return Ok(Socks5UdpProbeReport {
                    proxy: proxy_id,
                    support: Socks5UdpProbeSupport::Failed,
                    phase: Socks5UdpProbePhase::UdpAssociate,
                    relay_addr: None,
                    elapsed: started.elapsed(),
                    error: Some(error.to_string()),
                });
            }
        };

        let relay_addr = if relay_addr.ip().is_unspecified() {
            let proxy_ip = control_conn.peer_addr().map_err(|e| {
                Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("failed to get proxy peer address: {e}"),
                    Some(Box::new(e)),
                )
            })?;
            SocketAddr::new(proxy_ip.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        if matches!(config.mode, Socks5UdpProbeMode::AssociateOnly) {
            drop(control_conn);
            return Ok(Socks5UdpProbeReport {
                proxy: proxy_id,
                support: Socks5UdpProbeSupport::AssociateOk,
                phase: Socks5UdpProbePhase::UdpAssociate,
                relay_addr: Some(relay_addr),
                elapsed: started.elapsed(),
                error: None,
            });
        }

        let round_trip = tokio::time::timeout(
            config.timeout,
            dns_udp_round_trip_through_socks5(relay_addr, &config.target),
        )
        .await;
        drop(control_conn);

        match round_trip {
            Ok(Ok(())) => Ok(Socks5UdpProbeReport {
                proxy: proxy_id,
                support: Socks5UdpProbeSupport::RelayOk,
                phase: Socks5UdpProbePhase::UdpRoundTrip,
                relay_addr: Some(relay_addr),
                elapsed: started.elapsed(),
                error: None,
            }),
            Ok(Err(error)) => Ok(Socks5UdpProbeReport {
                proxy: proxy_id,
                support: Socks5UdpProbeSupport::Failed,
                phase: Socks5UdpProbePhase::UdpRoundTrip,
                relay_addr: Some(relay_addr),
                elapsed: started.elapsed(),
                error: Some(error.to_string()),
            }),
            Err(_) => Ok(Socks5UdpProbeReport {
                proxy: proxy_id,
                support: Socks5UdpProbeSupport::Failed,
                phase: Socks5UdpProbePhase::UdpRoundTrip,
                relay_addr: Some(relay_addr),
                elapsed: started.elapsed(),
                error: Some(format!(
                    "SOCKS5 UDP relay round-trip timed out after {:?}",
                    config.timeout
                )),
            }),
        }
    }
}

async fn dns_udp_round_trip_through_socks5(
    relay_addr: SocketAddr,
    target: &Socks5UdpProbeTarget,
) -> Result<()> {
    let Socks5UdpProbeTarget::DnsUdp {
        server,
        query,
        server_name,
    } = target;
    let target = match server_name {
        Some(host) => SocksTarget::Domain {
            host: host.clone(),
            port: server.port(),
        },
        None => SocksTarget::Ip(*server),
    };

    let socket = UdpSocket::bind(match relay_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .await?;

    let dns_query = build_dns_query(query)?;
    let mut frame = vec![0u8; 512 + dns_query.len()];
    let frame_len = encode_socks5_udp_target(&target, &dns_query, &mut frame).map_err(|e| {
        Error::proxy(
            ProxyErrorKind::ProtocolError,
            format!("failed to encode SOCKS5 UDP probe frame: {e}"),
            Some(Box::new(e)),
        )
    })?;
    socket.send_to(&frame[..frame_len], relay_addr).await?;

    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        if !packet_source_matches_relay(from, relay_addr) {
            tracing::debug!(
                from = %from,
                relay = %relay_addr,
                "socks5_udp_probe.foreign_source_dropped"
            );
            continue;
        }

        let (_, payload) = decode_socks5_udp(&buf[..n]).map_err(|e| {
            Error::proxy(
                ProxyErrorKind::ProtocolError,
                format!("failed to decode SOCKS5 UDP probe response: {e}"),
                Some(Box::new(e)),
            )
        })?;
        validate_dns_response(payload)?;
        return Ok(());
    }
}

fn build_dns_query(name: &str) -> Result<Vec<u8>> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Err(Error::InvalidConfig(
            "SOCKS5 UDP DNS probe query name is empty".into(),
        ));
    }

    let mut out = Vec::with_capacity(12 + name.len() + 6);
    out.extend_from_slice(&0x4c4bu16.to_be_bytes()); // ID
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::InvalidConfig(format!(
                "invalid DNS probe label '{label}' in query '{name}'"
            )));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

fn validate_dns_response(payload: &[u8]) -> Result<()> {
    if payload.len() < 12 {
        return Err(Error::proxy(
            ProxyErrorKind::ProtocolError,
            "DNS probe response too short",
            None,
        ));
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    if id != 0x4c4b {
        return Err(Error::proxy(
            ProxyErrorKind::ProtocolError,
            format!("DNS probe response ID mismatch: 0x{id:04x}"),
            None,
        ));
    }
    if payload[2] & 0x80 == 0 {
        return Err(Error::proxy(
            ProxyErrorKind::ProtocolError,
            "DNS probe received a non-response packet",
            None,
        ));
    }
    let rcode = payload[3] & 0x0f;
    if rcode != 0 {
        return Err(Error::proxy(
            ProxyErrorKind::ProtocolError,
            format!("DNS probe response returned RCODE {rcode}"),
            None,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_probe_uses_dns_round_trip() {
        let cfg = Socks5UdpProbeConfig::default();
        assert_eq!(cfg.mode, Socks5UdpProbeMode::DnsRoundTrip);
    }

    #[test]
    fn dns_query_builder_rejects_empty_name() {
        assert!(build_dns_query(".").is_err());
    }

    #[test]
    fn dns_response_validator_accepts_success_response() {
        let mut payload = [0u8; 12];
        payload[0..2].copy_from_slice(&0x4c4bu16.to_be_bytes());
        payload[2] = 0x81;
        payload[3] = 0x80;
        assert!(validate_dns_response(&payload).is_ok());
    }
}
