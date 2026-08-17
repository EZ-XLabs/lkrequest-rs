use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::Instrument;

use crate::error::{Error, ProxyErrorKind, Result};

use super::config::{ProxyAuth, ProxyConfig, ProxyScheme};
use super::socks5_udp::SocksTarget;

impl ProxyConfig {
    /// Establish a TCP connection through this proxy to the given target.
    ///
    /// Returns a `TcpStream` that is tunneled through the proxy to `target_host:target_port`.
    /// The returned stream is ready for TLS handshake.
    ///
    /// If `tcp_fingerprint` is provided, the TCP socket parameters (TTL, window
    /// size, MSS, etc.) are configured before the SYN packet is sent to the proxy
    /// server. This ensures the JA4T fingerprint is consistent even when connecting
    /// through a proxy.
    pub async fn connect(
        &self,
        target_host: &str,
        target_port: u16,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
    ) -> Result<TcpStream> {
        self.connect_with_budget(
            target_host,
            target_port,
            tcp_fingerprint,
            resolver,
            std::time::Duration::from_secs(10),
            None,
        )
        .await
    }

    pub(crate) async fn connect_with_budget(
        &self,
        target_host: &str,
        target_port: u16,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
        connect_timeout: std::time::Duration,
        connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    ) -> Result<TcpStream> {
        if !self.chain.is_empty() {
            return self
                .connect_chain(
                    target_host,
                    target_port,
                    tcp_fingerprint,
                    resolver,
                    connect_timeout,
                    connection_budget,
                )
                .await;
        }
        match &self.scheme {
            ProxyScheme::Http { host, port } => {
                self.connect_http(
                    host,
                    *port,
                    target_host,
                    target_port,
                    tcp_fingerprint,
                    resolver,
                    connect_timeout,
                    connection_budget,
                )
                .await
            }
            ProxyScheme::Socks5 {
                host,
                port,
                remote_dns,
            } => {
                self.connect_socks5(
                    host,
                    *port,
                    target_host,
                    target_port,
                    *remote_dns,
                    tcp_fingerprint,
                    resolver,
                    connect_timeout,
                    connection_budget,
                )
                .await
            }
        }
    }
    /// Establish a TCP tunnel through a multi-hop **proxychain** to the target.
    ///
    /// Physical path: TCP-connect to the first hop, then CONNECT-tunnel through
    /// each hop to the next; the final hop tunnels to the real target. The whole
    /// chain rides a single TCP connection because CONNECT relays bytes
    /// transparently over the established stream. The TCP fingerprint applies
    /// only to the first-hop SYN — the only SYN this client emits (every
    /// downstream SYN is emitted by a proxy's own kernel).
    async fn connect_chain(
        &self,
        target_host: &str,
        target_port: u16,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
        connect_timeout: std::time::Duration,
        connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    ) -> Result<TcpStream> {
        let hops: Vec<&ProxyConfig> = self.chain.iter().chain(std::iter::once(self)).collect();
        let (first_host, first_port) = hops[0].host_port();
        let first_host = first_host.to_string();
        let final_targets = if matches!(
            self.scheme,
            ProxyScheme::Socks5 {
                remote_dns: false,
                ..
            }
        ) {
            let addresses =
                resolver
                    .resolve(target_host, target_port)
                    .await
                    .map_err(|error| {
                        Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("SOCKS5 chain target DNS resolution failed for {target_host}: {error}"),
                    Some(Box::new(error)),
                )
                    })?;
            crate::tcp_fingerprint::interleave_address_families(addresses)
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>()
        } else {
            vec![None]
        };
        if final_targets.is_empty() {
            return Err(Error::proxy(
                ProxyErrorKind::IoError,
                format!("SOCKS5 chain target DNS returned no addresses for {target_host}"),
                None,
            ));
        }

        let mut failures = Vec::new();
        for final_target in final_targets {
            let mut stream = connect_tcp_to_proxy_with_budget(
                &first_host,
                first_port,
                tcp_fingerprint,
                resolver,
                connect_timeout,
                connection_budget.clone(),
            )
            .await?;

            let mut failed = None;
            for i in 0..hops.len() {
                let result = if i + 1 == hops.len() {
                    match final_target {
                        Some(target) => hops[i].negotiate_over_address(&mut stream, target).await,
                        None => {
                            hops[i]
                                .negotiate_over(&mut stream, target_host, target_port, resolver)
                                .await
                        }
                    }
                } else {
                    let (next_host, next_port) = hops[i + 1].host_port();
                    hops[i]
                        .negotiate_over(&mut stream, next_host, next_port, resolver)
                        .await
                };
                if let Err(error) = result {
                    failed = Some((i, error));
                    break;
                }
            }

            match failed {
                None => return Ok(stream),
                Some((failed_hop, error))
                    if failed_hop + 1 == hops.len()
                        && final_target.is_some()
                        && is_retryable_socks5_target_error(&error) =>
                {
                    failures.push(format!("{}: {error}", final_target.unwrap()));
                }
                Some((_, error)) => return Err(error),
            }
        }

        Err(Error::proxy(
            ProxyErrorKind::IoError,
            format!(
                "SOCKS5 chain target connect failed for all addresses: {}",
                failures.join("; ")
            ),
            None,
        ))
    }
    /// Negotiate this proxy's CONNECT to `(host, port)` over an already-open
    /// stream (one hop of a chain). Unlike the single-hop HTTP path this does
    /// not retry on 407 by reconnecting — a mid-chain TCP cannot be re-opened,
    /// so credentials must be supplied up front.
    async fn negotiate_over_address(
        &self,
        stream: &mut TcpStream,
        target: SocketAddr,
    ) -> Result<()> {
        if !matches!(self.scheme, ProxyScheme::Socks5 { .. }) {
            return Err(Error::proxy(
                ProxyErrorKind::ProtocolError,
                "address-specific negotiation requires a SOCKS5 hop",
                None,
            ));
        }
        socks5_handshake(stream, self.auth.as_ref()).await?;
        socks5_send_connect_address(stream, target).await?;
        socks5_read_response(stream, "connect").await?;
        Ok(())
    }
    async fn negotiate_over(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
        resolver: &dyn crate::dns::DnsResolver,
    ) -> Result<()> {
        match &self.scheme {
            ProxyScheme::Http { .. } => {
                let target = format!("{host}:{port}");
                let (status_code, response_bytes) =
                    send_connect_request(stream, &target, self.auth.as_ref()).await?;
                match status_code {
                    200 => Ok(()),
                    407 => Err(Error::proxy(
                        ProxyErrorKind::AuthenticationRequired,
                        format!("proxy chain hop {self} requires authentication (407)"),
                        None,
                    )),
                    other => {
                        let line = String::from_utf8_lossy(&response_bytes);
                        let line = line.lines().next().unwrap_or("");
                        Err(Error::proxy(
                            ProxyErrorKind::TunnelRefused { status_code: other },
                            format!("proxy chain hop {self} CONNECT failed: {line}"),
                            None,
                        ))
                    }
                }
            }
            ProxyScheme::Socks5 { remote_dns, .. } => {
                socks5_handshake(stream, self.auth.as_ref()).await?;
                socks5_send_connect(stream, host, port, *remote_dns, resolver).await?;
                socks5_read_response(stream, "connect").await?;
                Ok(())
            }
        }
    }

    /// HTTP CONNECT tunnel.
    ///
    /// 1. TCP connect to proxy
    /// 2. Send `CONNECT target:port HTTP/1.1` (+ optional Proxy-Authorization)
    /// 3. Read `HTTP/1.1 200 Connection Established` (byte-by-byte to avoid over-reading)
    /// 4. Return the TCP stream (now tunneled)
    ///
    /// **Important**: The HTTP response is read one byte at a time until `\r\n\r\n`
    /// is found. This ensures we never consume bytes belonging to the tunneled
    /// TLS handshake that follows. A bulk `read()` could pull in TLS data beyond
    /// the HTTP header boundary, causing the subsequent TLS handshake to fail
    /// (the over-read bytes would be lost from the stream).
    #[allow(clippy::too_many_arguments)]
    async fn connect_http(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
        connect_timeout: std::time::Duration,
        connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    ) -> Result<TcpStream> {
        let span = tracing::debug_span!(
            "proxy.tunnel",
            proxy_type = "http_connect",
            proxy_addr = %format_args!("{}:{}", proxy_host, proxy_port),
            target = %format_args!("{}:{}", target_host, target_port),
        );

        async {
            let proxy_addr = format!("{}:{}", proxy_host, proxy_port);
            let target = format!("{}:{}", target_host, target_port);

            let mut stream = connect_tcp_to_proxy_with_budget(
                proxy_host,
                proxy_port,
                tcp_fingerprint,
                resolver,
                connect_timeout,
                connection_budget.clone(),
            )
            .await?;

            tracing::debug!("proxy.tcp_connected");

            let (status_code, response_bytes) =
                send_connect_request(&mut stream, &target, self.auth.as_ref()).await?;

            if status_code == 200 {
                tracing::debug!("proxy.tunnel_established");
                return Ok(stream);
            }

            if status_code == 407 {
                let response_str_full = String::from_utf8_lossy(&response_bytes);
                let supports_basic = response_str_full.lines().any(|l| {
                    let lower = l.to_ascii_lowercase();
                    lower.starts_with("proxy-authenticate:") && lower.contains("basic")
                });

                if self.auth.is_some() && supports_basic {
                    tracing::warn!(
                        status = 407,
                        "proxy.407_retrying_with_auth — reconnecting with credentials"
                    );

                    drop(stream);
                    let mut stream2 = connect_tcp_to_proxy_with_budget(
                        proxy_host,
                        proxy_port,
                        tcp_fingerprint,
                        resolver,
                        connect_timeout,
                        connection_budget.clone(),
                    )
                    .await
                    .map_err(|e| {
                        Error::proxy(
                            ProxyErrorKind::TcpConnectFailed,
                            format!("failed to reconnect to proxy {proxy_addr} for 407 retry: {e}"),
                            Some(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
                        )
                    })?;

                    let (retry_code, _) =
                        send_connect_request(&mut stream2, &target, self.auth.as_ref()).await?;

                    if retry_code == 200 {
                        tracing::debug!("proxy.tunnel_established_after_407_retry");
                        return Ok(stream2);
                    }

                    tracing::warn!(status = retry_code, "proxy.407_retry_failed");
                    return Err(Error::proxy(
                        ProxyErrorKind::AuthenticationFailed,
                        format!("proxy authentication failed after retry (status {retry_code})"),
                        None,
                    ));
                }

                let status_line = String::from_utf8_lossy(&response_bytes);
                let status_line = status_line.lines().next().unwrap_or("");
                tracing::warn!(status = 407, "proxy.auth_required");
                return Err(Error::proxy(
                    ProxyErrorKind::AuthenticationRequired,
                    format!("proxy requires authentication (407): {status_line}"),
                    None,
                ));
            }

            let status_line = String::from_utf8_lossy(&response_bytes);
            let status_line = status_line.lines().next().unwrap_or("");
            tracing::warn!(status = status_code, "proxy.connect_failed");
            Err(Error::proxy(
                ProxyErrorKind::TunnelRefused { status_code },
                format!("proxy CONNECT failed: {status_line}"),
                None,
            ))
        }
        .instrument(span)
        .await
    }

    /// SOCKS5 tunnel.
    ///
    /// Performs the SOCKS5 handshake to create a tunnel to the target.
    #[allow(clippy::too_many_arguments)]
    async fn connect_socks5(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        remote_dns: bool,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
        connect_timeout: std::time::Duration,
        connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    ) -> Result<TcpStream> {
        let span = tracing::debug_span!(
            "proxy.tunnel",
            proxy_type = if remote_dns { "socks5h" } else { "socks5" },
            proxy_addr = %format_args!("{}:{}", proxy_host, proxy_port),
            target = %format_args!("{}:{}", target_host, target_port),
        );

        self.connect_socks5_inner(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            remote_dns,
            tcp_fingerprint,
            resolver,
            connect_timeout,
            connection_budget,
        )
        .instrument(span)
        .await
    }

    /// Inner SOCKS5 tunnel implementation (instrumented by `connect_socks5`).
    #[allow(clippy::too_many_arguments)]
    async fn connect_socks5_inner(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        remote_dns: bool,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
        connect_timeout: std::time::Duration,
        connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    ) -> Result<TcpStream> {
        if remote_dns {
            let mut stream = connect_tcp_to_proxy_with_budget(
                proxy_host,
                proxy_port,
                tcp_fingerprint,
                resolver,
                connect_timeout,
                connection_budget,
            )
            .await?;
            socks5_handshake(&mut stream, self.auth.as_ref()).await?;
            socks5_send_connect(&mut stream, target_host, target_port, true, resolver).await?;
            socks5_read_response(&mut stream, "connect").await?;
            return Ok(stream);
        }

        let addresses = crate::tcp_fingerprint::interleave_address_families(
            resolver
                .resolve(target_host, target_port)
                .await
                .map_err(|error| {
                    Error::proxy(
                        ProxyErrorKind::IoError,
                        format!("SOCKS5 local DNS resolution failed for {target_host}: {error}"),
                        Some(Box::new(error)),
                    )
                })?,
        );
        if addresses.is_empty() {
            return Err(Error::proxy(
                ProxyErrorKind::IoError,
                format!("SOCKS5 local DNS resolution returned no addresses for {target_host}"),
                None,
            ));
        }

        let mut failures = Vec::new();
        for target in addresses {
            let mut stream = connect_tcp_to_proxy_with_budget(
                proxy_host,
                proxy_port,
                tcp_fingerprint,
                resolver,
                connect_timeout,
                connection_budget.clone(),
            )
            .await?;
            socks5_handshake(&mut stream, self.auth.as_ref()).await?;
            socks5_send_connect_address(&mut stream, target).await?;
            match socks5_read_response(&mut stream, "connect").await {
                Ok(_) => return Ok(stream),
                Err(error) if is_retryable_socks5_target_error(&error) => {
                    failures.push(format!("{target}: {error}"));
                }
                Err(error) => return Err(error),
            }
        }

        Err(Error::proxy(
            ProxyErrorKind::IoError,
            format!(
                "SOCKS5 target connect failed for all locally resolved addresses: {}",
                failures.join("; ")
            ),
            None,
        ))
    }
    /// Establish a SOCKS5 UDP ASSOCIATE session through this proxy (single hop
    /// or a nested **proxy chain**).
    ///
    /// Returns a [`UdpAssociation`]: one TCP control connection per hop (all
    /// must be kept alive) and the UDP relay address of each hop. For a single
    /// hop the returned vecs have length 1 and datagrams are sent to
    /// `relays[0]` with plain SOCKS5 UDP framing. For a chain, datagrams are
    /// sent to `relays[0]` (hop1's relay) wrapped in one nested SOCKS5 UDP
    /// header per subsequent hop — see [`UdpAssociation`] and
    /// `encode_socks5_udp_nested`.
    pub(crate) async fn udp_associate(
        &self,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
    ) -> Result<UdpAssociation> {
        if !self.chain.is_empty() {
            return self.udp_associate_chain(tcp_fingerprint, resolver).await;
        }

        let (proxy_host, proxy_port) = self.host_port();
        let proxy_host = proxy_host.to_string();

        let span = tracing::debug_span!(
            "proxy.udp_associate",
            proxy_addr = %format_args!("{}:{}", proxy_host, proxy_port),
        );

        async {
            let mut stream =
                connect_tcp_to_proxy(&proxy_host, proxy_port, tcp_fingerprint, resolver)
                    .await
                    .map_err(|e| {
                        Error::proxy(
                            ProxyErrorKind::TcpConnectFailed,
                            format!(
                                "failed to connect to SOCKS5 proxy {proxy_host}:{proxy_port}: {e}"
                            ),
                            Some(Box::new(e)),
                        )
                    })?;

            tracing::debug!("proxy.tcp_connected");

            socks5_handshake(&mut stream, self.auth.as_ref()).await?;

            let raw_relay = send_udp_associate(&mut stream).await?;
            let first_relay = resolve_first_relay(raw_relay, &stream)?;

            tracing::debug!(relay_addr = %first_relay, "proxy.udp_associate_established");
            Ok(UdpAssociation {
                control_conns: vec![stream],
                first_relay,
                inner_relays: Vec::new(),
            })
        }
        .instrument(span)
        .await
    }

    /// Establish UDP ASSOCIATE across a multi-hop SOCKS5 **chain** by nesting
    /// one association per hop.
    ///
    /// For a chain `client → hop1 → … → hopN → target`, only hop1 is reachable
    /// by the client's UDP directly; the inner hops are reached over TCP
    /// tunnels. UDP ASSOCIATE cannot ride a CONNECT tunnel (CONNECT relays TCP,
    /// not datagrams), so each hop gets its **own** control connection: hop `i`
    /// is reached by CONNECT-tunnelling through `hop1..hop_{i-1}` and issuing
    /// UDP ASSOCIATE there. The resulting relay addresses are later stacked as
    /// nested per-datagram headers so each hop forwards to the next.
    ///
    /// Every hop must be SOCKS5 — UDP ASSOCIATE is a SOCKS5-only command, and an
    /// HTTP CONNECT hop cannot relay datagrams.
    async fn udp_associate_chain(
        &self,
        tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
        resolver: &dyn crate::dns::DnsResolver,
    ) -> Result<UdpAssociation> {
        // Ordered hops: the upstream chain, then `self` (final hop → target).
        let hops: Vec<&ProxyConfig> = self.chain.iter().chain(std::iter::once(self)).collect();

        for hop in &hops {
            if !matches!(hop.scheme, ProxyScheme::Socks5 { .. }) {
                return Err(Error::proxy(
                    ProxyErrorKind::ProtocolError,
                    format!(
                        "QUIC over a proxy chain requires every hop to be SOCKS5 \
                         (UDP ASSOCIATE is SOCKS5-only); hop {hop} is not SOCKS5 — \
                         use a single SOCKS5 hop for QUIC, or fall back to H2 over the chain"
                    ),
                    None,
                ));
            }
        }

        let span = tracing::debug_span!("proxy.udp_associate.chain", hops = hops.len());

        async move {
            let mut control_conns = Vec::with_capacity(hops.len());
            let mut first_relay: Option<SocketAddr> = None;
            let mut inner_relays: Vec<SocksTarget> = Vec::with_capacity(hops.len() - 1);

            for i in 0..hops.len() {
                // Fresh TCP to hop1 (the only SYN we emit), then CONNECT-tunnel
                // through hop1..hop_{i-1} to reach hop i's SOCKS listener.
                let (first_host, first_port) = hops[0].host_port();
                let mut stream =
                    connect_tcp_to_proxy(first_host, first_port, tcp_fingerprint, resolver)
                        .await
                        .map_err(|e| {
                            Error::proxy(
                                ProxyErrorKind::TcpConnectFailed,
                                format!(
                                    "failed to connect to first chain hop {first_host}:{first_port} \
                                     for UDP ASSOCIATE: {e}"
                                ),
                                Some(Box::new(e)),
                            )
                        })?;

                for j in 0..i {
                    let (next_host, next_port) = hops[j + 1].host_port();
                    hops[j]
                        .negotiate_over(&mut stream, next_host, next_port, resolver)
                        .await?;
                }

                // At hop i: SOCKS5 handshake + UDP ASSOCIATE over the tunnel.
                socks5_handshake(&mut stream, hops[i].auth.as_ref()).await?;
                let raw_relay = send_udp_associate(&mut stream).await?;

                if i == 0 {
                    let relay = resolve_first_relay(raw_relay, &stream)?;
                    tracing::debug!(hop = 0, relay = %relay, "proxy.udp_associate.chain.hop_established");
                    first_relay = Some(relay);
                } else {
                    let relay = resolve_inner_relay(raw_relay, hops[i]);
                    tracing::debug!(hop = i, relay = %relay, "proxy.udp_associate.chain.hop_established");
                    inner_relays.push(relay);
                }
                control_conns.push(stream);
            }

            tracing::debug!("proxy.udp_associate.chain.established");
            Ok(UdpAssociation {
                control_conns,
                first_relay: first_relay.expect("a chain always has at least the final hop"),
                inner_relays,
            })
        }
        .instrument(span)
        .await
    }
}

/// A live SOCKS5 UDP association — a single hop or a nested proxy **chain**.
///
/// `control_conns` is ordered hop1..hopN and every entry must be kept alive for
/// the association's lifetime — dropping one tears down its relay.
///
/// `first_relay` is hop1's relay: the only address the client sends UDP
/// datagrams to directly. `inner_relays` holds `relay2..relayN` — each reachable
/// only *through* the previous hop, stacked as a nested SOCKS5 UDP header so
/// that hop forwards the datagram onward. Each inner relay is an IP, or a
/// **domain** when the hop advertised an unspecified BND (so the previous,
/// adjacent hop resolves it in its own network context). `inner_relays` is
/// empty for a single hop.
pub(crate) struct UdpAssociation {
    pub control_conns: Vec<TcpStream>,
    pub first_relay: SocketAddr,
    // Only consumed by the quic-h3 `Socks5UdpSocket`; write-only without it.
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub inner_relays: Vec<SocksTarget>,
}

/// SOCKS5 greeting + authentication negotiation (shared by CONNECT and UDP ASSOCIATE).
async fn socks5_handshake(stream: &mut TcpStream, auth: Option<&ProxyAuth>) -> Result<()> {
    if auth.is_some() {
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|e| {
                Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("SOCKS5 greeting failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| {
            Error::proxy(
                ProxyErrorKind::IoError,
                format!("SOCKS5 greeting failed: {e}"),
                Some(Box::new(e)),
            )
        })?;
    }

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await.map_err(|e| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("SOCKS5 method response failed: {e}"),
            Some(Box::new(e)),
        )
    })?;

    if method_resp[0] != 0x05 {
        return Err(Error::proxy(
            ProxyErrorKind::ProtocolError,
            format!(
                "SOCKS5 protocol error: expected version 5, got {}",
                method_resp[0]
            ),
            None,
        ));
    }

    match method_resp[1] {
        0x00 => {
            tracing::trace!(method = "none", "socks5.auth_negotiated");
        }
        0x02 => {
            tracing::trace!(method = "username_password", "socks5.auth_negotiated");
            let auth = auth.ok_or_else(|| {
                Error::proxy(
                    ProxyErrorKind::AuthenticationRequired,
                    "SOCKS5 proxy requires auth but no credentials provided",
                    None,
                )
            })?;

            if auth.username.len() > 255 || auth.password.len() > 255 {
                return Err(Error::proxy(
                    ProxyErrorKind::ProtocolError,
                    format!(
                        "SOCKS5 auth credentials too long (username: {} bytes, password: {} bytes, max: 255)",
                        auth.username.len(),
                        auth.password.len(),
                    ),
                    None,
                ));
            }

            let mut auth_req = Vec::new();
            auth_req.push(0x01);
            auth_req.push(auth.username.len() as u8);
            auth_req.extend_from_slice(auth.username.as_bytes());
            auth_req.push(auth.password.len() as u8);
            auth_req.extend_from_slice(auth.password.as_bytes());

            stream.write_all(&auth_req).await.map_err(|e| {
                Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("SOCKS5 auth request failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await.map_err(|e| {
                Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("SOCKS5 auth response failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

            if auth_resp[1] != 0x00 {
                return Err(Error::proxy(
                    ProxyErrorKind::AuthenticationFailed,
                    "SOCKS5 authentication failed",
                    None,
                ));
            }
        }
        0xFF => {
            return Err(Error::proxy(
                ProxyErrorKind::AuthenticationRequired,
                "SOCKS5 proxy rejected all authentication methods",
                None,
            ));
        }
        other => {
            return Err(Error::proxy(
                ProxyErrorKind::ProtocolError,
                format!("SOCKS5 unsupported auth method: 0x{other:02x}"),
                None,
            ));
        }
    }
    Ok(())
}

/// Send a SOCKS5 CONNECT (CMD=0x01) command for the given target.
async fn socks5_send_connect(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    remote_dns: bool,
    resolver: &dyn crate::dns::DnsResolver,
) -> Result<()> {
    let mut req = Vec::new();
    req.push(0x05); // VER
    req.push(0x01); // CMD: CONNECT
    req.push(0x00); // RSV

    if remote_dns {
        if target_host.len() > 255 {
            return Err(Error::proxy(
                ProxyErrorKind::ProtocolError,
                format!(
                    "SOCKS5 target hostname too long ({} bytes, max: 255)",
                    target_host.len(),
                ),
                None,
            ));
        }
        req.push(0x03); // ATYP: domain
        req.push(target_host.len() as u8);
        req.extend_from_slice(target_host.as_bytes());
    } else {
        let resolved = resolver
            .resolve(target_host, target_port)
            .await
            .map_err(|e| {
                Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("SOCKS5 local DNS resolution failed for {target_host}: {e}"),
                    Some(Box::new(e)),
                )
            })?
            .into_iter()
            .next()
            .ok_or_else(|| {
                Error::proxy(
                    ProxyErrorKind::IoError,
                    format!("SOCKS5 local DNS resolution returned no addresses for {target_host}"),
                    None,
                )
            })?;

        match resolved {
            std::net::SocketAddr::V4(addr) => {
                req.push(0x01);
                req.extend_from_slice(&addr.ip().octets());
            }
            std::net::SocketAddr::V6(addr) => {
                req.push(0x04);
                req.extend_from_slice(&addr.ip().octets());
            }
        }
    }

    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xFF) as u8);

    stream.write_all(&req).await.map_err(|e| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("SOCKS5 connect request failed: {e}"),
            Some(Box::new(e)),
        )
    })?;
    Ok(())
}

async fn socks5_send_connect_address(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let mut request = vec![0x05, 0x01, 0x00];
    match target {
        SocketAddr::V4(address) => {
            request.push(0x01);
            request.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            request.push(0x04);
            request.extend_from_slice(&address.ip().octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.map_err(|error| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("SOCKS5 connect request failed: {error}"),
            Some(Box::new(error)),
        )
    })
}

fn is_retryable_socks5_target_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Proxy(proxy_error)
            if matches!(
                proxy_error.kind,
                ProxyErrorKind::Socks5Error { code: 0x01 | 0x03 | 0x04 | 0x05 | 0x06 | 0x08 }
            )
    )
}
/// Read and validate a SOCKS5 command response, returning the bound address.
async fn socks5_read_response(stream: &mut TcpStream, cmd_name: &str) -> Result<SocketAddr> {
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await.map_err(|e| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("SOCKS5 {cmd_name} response failed: {e}"),
            Some(Box::new(e)),
        )
    })?;

    if resp_header[0] != 0x05 {
        return Err(Error::proxy(
            ProxyErrorKind::ProtocolError,
            format!(
                "SOCKS5 protocol error: expected version 5, got {}",
                resp_header[0]
            ),
            None,
        ));
    }

    if resp_header[1] != 0x00 {
        let err_msg = match resp_header[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(Error::proxy(
            ProxyErrorKind::Socks5Error {
                code: resp_header[1],
            },
            format!(
                "SOCKS5 {cmd_name} failed: {err_msg} (0x{:02x})",
                resp_header[1]
            ),
            None,
        ));
    }

    let io_err = |e: std::io::Error| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("SOCKS5 address read failed: {e}"),
            Some(Box::new(e)),
        )
    };

    let bound_addr = match resp_header[3] {
        0x01 => {
            let mut buf = [0u8; 6]; // 4 addr + 2 port
            stream.read_exact(&mut buf).await.map_err(io_err)?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            SocketAddr::from((ip, port))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.map_err(io_err)?;
            let mut domain_and_port = vec![0u8; len_buf[0] as usize + 2];
            stream
                .read_exact(&mut domain_and_port)
                .await
                .map_err(io_err)?;
            let port_start = domain_and_port.len() - 2;
            let port =
                u16::from_be_bytes([domain_and_port[port_start], domain_and_port[port_start + 1]]);
            // Domain-based BND address: use 0.0.0.0 with the port
            SocketAddr::from(([0, 0, 0, 0], port))
        }
        0x04 => {
            let mut buf = [0u8; 18]; // 16 addr + 2 port
            stream.read_exact(&mut buf).await.map_err(io_err)?;
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            SocketAddr::from((ip, port))
        }
        other => {
            return Err(Error::proxy(
                ProxyErrorKind::ProtocolError,
                format!("SOCKS5 unsupported address type: 0x{other:02x}"),
                None,
            ));
        }
    };

    Ok(bound_addr)
}

/// Send a SOCKS5 UDP ASSOCIATE command and return the raw BND relay address
/// from the reply (may be unspecified — see [`substitute_udp_relay`]).
async fn send_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
    // CMD=0x03 (UDP ASSOCIATE), DST.ADDR = 0.0.0.0:0 ("I don't know my source
    // yet"): the relay binds a socket and returns its BND address.
    let udp_req: [u8; 10] = [
        0x05, // VER
        0x03, // CMD: UDP ASSOCIATE
        0x00, // RSV
        0x01, // ATYP: IPv4
        0x00, 0x00, 0x00, 0x00, // DST.ADDR: 0.0.0.0
        0x00, 0x00, // DST.PORT: 0
    ];
    stream.write_all(&udp_req).await.map_err(|e| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("SOCKS5 UDP ASSOCIATE request failed: {e}"),
            Some(Box::new(e)),
        )
    })?;
    socks5_read_response(stream, "udp_associate").await
}

/// Resolve hop1's (directly connected) relay BND to a concrete address that the
/// client sends datagrams to. An unspecified BND (`0.0.0.0:<port>`, meaning
/// "reach me on whatever address you connected on") becomes the control
/// connection's peer IP with the advertised port. A concrete BND is used as-is.
fn resolve_first_relay(raw: SocketAddr, control_conn: &TcpStream) -> Result<SocketAddr> {
    if !raw.ip().is_unspecified() {
        return Ok(raw);
    }
    let ip = control_conn
        .peer_addr()
        .map_err(|e| {
            Error::proxy(
                ProxyErrorKind::IoError,
                format!("failed to read proxy peer address for UDP relay: {e}"),
                Some(Box::new(e)),
            )
        })?
        .ip();
    Ok(SocketAddr::new(ip, raw.port()))
}

/// Resolve an inner chain hop's relay BND to a nested-header DST.
///
/// A concrete BND is used as-is — the relay told us a reachable address. An
/// unspecified BND ("reach me on whatever address you connected on") is
/// addressed by the hop's *own configured host*: a **domain** is kept as a
/// domain (ATYP=0x03) so the previous, adjacent hop resolves it in its own
/// network context — the client can't, because it never reaches this relay
/// directly and NAT could make a client-side resolution wrong. An IP-literal
/// host is used directly (there is nothing more the client can infer).
fn resolve_inner_relay(raw: SocketAddr, hop: &ProxyConfig) -> SocksTarget {
    if !raw.ip().is_unspecified() {
        return SocksTarget::Ip(raw);
    }
    let (host, _port) = hop.host_port();
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SocksTarget::Ip(SocketAddr::new(ip, raw.port())),
        Err(_) => SocksTarget::Domain {
            host: host.to_string(),
            port: raw.port(),
        },
    }
}

/// TCP connect to a proxy server, mapping errors to proxy-specific types.
async fn connect_tcp_to_proxy(
    proxy_host: &str,
    proxy_port: u16,
    tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
    resolver: &dyn crate::dns::DnsResolver,
) -> Result<TcpStream> {
    connect_tcp_to_proxy_with_budget(
        proxy_host,
        proxy_port,
        tcp_fingerprint,
        resolver,
        std::time::Duration::from_secs(10),
        None,
    )
    .await
}

async fn connect_tcp_to_proxy_with_budget(
    proxy_host: &str,
    proxy_port: u16,
    tcp_fingerprint: Option<&crate::tcp_fingerprint::TcpFingerprint>,
    resolver: &dyn crate::dns::DnsResolver,
    connect_timeout: std::time::Duration,
    connection_budget: Option<crate::connection_pool::ConnectionBudget>,
) -> Result<TcpStream> {
    crate::tcp_fingerprint::connect_tcp_with_fingerprint(
        proxy_host,
        proxy_port,
        tcp_fingerprint,
        resolver,
        connect_timeout,
        connection_budget,
    )
    .await
    .map_err(|e| {
        Error::proxy(
            ProxyErrorKind::TcpConnectFailed,
            format!("failed to connect to proxy {proxy_host}:{proxy_port}: {e}"),
            Some(Box::new(e)),
        )
    })
}
/// Send an HTTP CONNECT request and read the response headers byte-by-byte.
///
/// Returns `(status_code, raw_response_bytes)`. The byte-by-byte read ensures
/// we never consume bytes belonging to the tunneled TLS handshake that follows.
async fn send_connect_request(
    stream: &mut TcpStream,
    target: &str,
    auth: Option<&super::config::ProxyAuth>,
) -> Result<(u16, Vec<u8>)> {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");

    if let Some(auth) = auth {
        use std::fmt::Write;
        let credentials = format!("{}:{}", auth.username, auth.password);
        let encoded = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
        };
        let _ = write!(request, "Proxy-Authorization: Basic {encoded}\r\n");
        tracing::trace!("proxy.auth_header_added");
    }

    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await.map_err(|e| {
        Error::proxy(
            ProxyErrorKind::IoError,
            format!("failed to send CONNECT request: {e}"),
            Some(Box::new(e)),
        )
    })?;

    let mut response_bytes = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.map_err(|e| {
            Error::proxy(
                ProxyErrorKind::IoError,
                format!("failed to read proxy response: {e}"),
                Some(Box::new(e)),
            )
        })?;

        response_bytes.push(byte[0]);

        if response_bytes.len() >= 4 && response_bytes[response_bytes.len() - 4..] == *b"\r\n\r\n" {
            break;
        }

        if response_bytes.len() > 4096 {
            return Err(Error::proxy(
                ProxyErrorKind::ProtocolError,
                "proxy response headers too large",
                None,
            ));
        }
    }

    let response_str = String::from_utf8_lossy(&response_bytes);
    let status_line = response_str.lines().next().unwrap_or("");
    let status_code = super::config::parse_http_status(status_line).unwrap_or(0);

    Ok((status_code, response_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticResolver {
        addresses: Vec<SocketAddr>,
    }

    #[async_trait::async_trait]
    impl crate::dns::DnsResolver for StaticResolver {
        async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            if host == "127.0.0.1" {
                return Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
            }
            Ok(self
                .addresses
                .iter()
                .map(|address| SocketAddr::new(address.ip(), port))
                .collect())
        }
    }

    async fn serve_socks_attempt(listener: &tokio::net::TcpListener, reply: u8) -> u8 {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let address_len = match header[3] {
            0x01 => 4,
            0x03 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await.unwrap();
                length[0] as usize
            }
            0x04 => 16,
            other => panic!("unexpected ATYP {other:#x}"),
        };
        let mut address_and_port = vec![0u8; address_len + 2];
        stream.read_exact(&mut address_and_port).await.unwrap();
        stream
            .write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        header[3]
    }

    #[tokio::test]
    async fn socks5_local_dns_retries_next_address() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            assert_eq!(serve_socks_attempt(&listener, 0x03).await, 0x04);
            assert_eq!(serve_socks_attempt(&listener, 0x00).await, 0x01);
        });
        let proxy = ProxyConfig::parse(&format!("socks5://127.0.0.1:{port}")).unwrap();
        let resolver = StaticResolver {
            addresses: vec![
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)),
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
            ],
        };

        let stream = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect("SOCKS5 should reconnect with the next locally resolved address");

        drop(stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5h_sends_domain_without_local_target_resolution() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { serve_socks_attempt(&listener, 0x00).await });
        let proxy = ProxyConfig::parse(&format!("socks5h://127.0.0.1:{port}")).unwrap();
        let resolver = StaticResolver {
            addresses: Vec::new(),
        };

        let stream = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect("socks5h should send the hostname to the proxy");

        drop(stream);
        assert_eq!(server.await.unwrap(), 0x03);
    }

    fn socks_error(code: u8) -> Error {
        Error::proxy(
            ProxyErrorKind::Socks5Error { code },
            format!("SOCKS5 error {code:#x}"),
            None,
        )
    }

    #[test]
    fn socks5_retryable_error_matrix() {
        for code in [0x01, 0x03, 0x04, 0x05, 0x06, 0x08] {
            assert!(is_retryable_socks5_target_error(&socks_error(code)));
        }
        for code in [0x02, 0x07, 0x09] {
            assert!(!is_retryable_socks5_target_error(&socks_error(code)));
        }
    }

    #[test]
    fn socks5_candidates_interleave_address_families() {
        let addresses = vec![
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)),
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 443)),
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
        ];
        let interleaved = crate::tcp_fingerprint::interleave_address_families(addresses);
        assert!(interleaved[0].is_ipv6());
        assert!(interleaved[1].is_ipv4());
        assert!(interleaved[2].is_ipv6());
    }

    #[tokio::test]
    async fn socks5_all_candidates_fail_with_aggregate_error() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            serve_socks_attempt(&listener, 0x03).await;
            serve_socks_attempt(&listener, 0x05).await;
        });
        let proxy = ProxyConfig::parse(&format!("socks5://127.0.0.1:{port}")).unwrap();
        let resolver = StaticResolver {
            addresses: vec![
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)),
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
            ],
        };

        let error = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect_err("all target candidates should fail");
        let message = error.to_string();
        assert!(message.contains("network unreachable"));
        assert!(message.contains("connection refused"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_non_retryable_error_stops_after_first_attempt() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { serve_socks_attempt(&listener, 0x02).await });
        let proxy = ProxyConfig::parse(&format!("socks5://127.0.0.1:{port}")).unwrap();
        let resolver = StaticResolver {
            addresses: vec![
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)),
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
            ],
        };

        let error = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect_err("ruleset denial must not retry another target");
        assert!(error
            .to_string()
            .contains("connection not allowed by ruleset"));
        assert_eq!(server.await.unwrap(), 0x04);
    }

    struct FailingResolver;

    #[async_trait::async_trait]
    impl crate::dns::DnsResolver for FailingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Err(std::io::Error::other("synthetic DNS failure"))
        }
    }

    #[tokio::test]
    async fn socks5_local_dns_empty_result_fails_before_proxy_connect() {
        let proxy = ProxyConfig::parse("socks5://127.0.0.1:9").unwrap();
        let resolver = StaticResolver {
            addresses: Vec::new(),
        };

        let error = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect_err("empty local DNS results must fail explicitly");

        assert!(error.to_string().contains("returned no addresses"));
    }

    #[tokio::test]
    async fn socks5_local_dns_error_preserves_resolution_context() {
        let proxy = ProxyConfig::parse("socks5://127.0.0.1:9").unwrap();

        let error = proxy
            .connect("target.test", 443, None, &FailingResolver)
            .await
            .expect_err("local DNS errors must be reported before proxy connect");

        let message = error.to_string();
        assert!(message.contains("local DNS resolution failed"));
        assert!(message.contains("synthetic DNS failure"));
    }

    #[tokio::test]
    async fn socks5_chain_does_not_retry_target_after_intermediate_hop_failure() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let first_port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { serve_socks_attempt(&listener, 0x03).await });
        let proxy = ProxyConfig::parse_chain(&[
            format!("socks5://127.0.0.1:{first_port}"),
            "socks5://127.0.0.1:1081".to_string(),
        ])
        .unwrap();
        let resolver = StaticResolver {
            addresses: vec![
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)),
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
            ],
        };

        let error = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect_err("an intermediate hop failure must stop the chain");

        assert!(error.to_string().contains("network unreachable"));
        assert_eq!(server.await.unwrap(), 0x01);
    }

    async fn serve_socks_relay_attempt(
        listener: &tokio::net::TcpListener,
        next_hop: SocketAddr,
    ) -> u8 {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        client.read_exact(&mut greeting).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[3], 0x01);
        let mut address_and_port = [0u8; 6];
        client.read_exact(&mut address_and_port).await.unwrap();
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut upstream = TcpStream::connect(next_hop).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        header[3]
    }

    #[tokio::test]
    async fn socks5_chain_rebuilds_for_next_final_target_address() {
        let first_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let final_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let first_port = first_listener.local_addr().unwrap().port();
        let final_addr = final_listener.local_addr().unwrap();
        let first_server = tokio::spawn(async move {
            assert_eq!(
                serve_socks_relay_attempt(&first_listener, final_addr).await,
                0x01
            );
            assert_eq!(
                serve_socks_relay_attempt(&first_listener, final_addr).await,
                0x01
            );
        });
        let final_server = tokio::spawn(async move {
            assert_eq!(serve_socks_attempt(&final_listener, 0x03).await, 0x04);
            assert_eq!(serve_socks_attempt(&final_listener, 0x00).await, 0x01);
        });
        let proxy = ProxyConfig::parse_chain(&[
            format!("socks5://127.0.0.1:{first_port}"),
            format!("socks5://127.0.0.1:{}", final_addr.port()),
        ])
        .unwrap();
        let resolver = StaticResolver {
            addresses: vec![
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)),
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
            ],
        };

        let stream = proxy
            .connect("target.test", 443, None, &resolver)
            .await
            .expect("the full SOCKS5 chain should be rebuilt for the next target address");

        drop(stream);
        first_server.await.unwrap();
        final_server.await.unwrap();
    }
}
