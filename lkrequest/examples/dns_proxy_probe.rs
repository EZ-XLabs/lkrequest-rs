//! DNS-over-Proxy probe.
//!
//! Measures support and latency of five DNS-resolution scenarios per proxy:
//!   1. baseline-direct-udp     — local hickory over plain UDP/53 to 1.1.1.1
//!   2. baseline-direct-doh     — local hickory DoH to cloudflare-dns.com
//!   3. socks5-udp-dns          — DNS UDP packets relayed through SOCKS5 UDP ASSOCIATE
//!   4. doh-over-socks5         — DoH HTTPS connection tunnelled through SOCKS5 CONNECT
//!   5. doh-over-http-connect   — DoH HTTPS connection tunnelled through HTTP CONNECT
//!
//! Per (proxy, scenario, query, run) tuple it records elapsed time, success / error
//! kind, returned IP count, and whether a DNS HTTPS RR (type 65) was obtained.
//!
//! Usage:
//!
//! ```bash
//! cargo run --example dns_proxy_probe -- \
//!   --proxy socks5h://user:pass@host:1080 \
//!   --proxy http://user:pass@host:8080 \
//!   --query cloudflare.com --query www.google.com \
//!   --runs 5 \
//!   --json out.json
//! ```
//!
//! With no `--proxy` flags, the demo falls back to `SOCKS5_PROXY` / `HTTP_PROXY`
//! env vars.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{
    RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime,
};
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use lkrequest::proxy::{ProxyAuth, ProxyConfig, ProxyScheme};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const DEFAULT_QUERIES: &[&str] = &[
    "cloudflare.com",
    "www.google.com",
    "github.com",
    "example.com",
];

#[derive(Debug)]
struct Cli {
    proxies: Vec<ProxyConfig>,
    queries: Vec<String>,
    runs: u32,
    timeout: Duration,
    upstream_udp: SocketAddr,
    /// Optional domain name to use as the SOCKS5 UDP target (ATYP=0x03).
    /// Falls back to upstream_udp's IP (ATYP=0x01) when None.
    upstream_udp_domain: Option<String>,
    doh_url: String,
    doh_tls_name: String,
    doh_bootstrap: Vec<IpAddr>,
    json_path: Option<String>,
    skip_baseline: bool,
    verbose: bool,
    /// When true, share a single SOCKS5 UDP ASSOCIATE across all queries
    /// instead of opening a new one per query.
    socks5_udp_reuse: bool,
    /// When true, dump SOCKS5 UDP diagnostics (frame hex, src port,
    /// every received datagram with its source address).
    debug_udp: bool,
}

impl Cli {
    fn parse() -> Result<Self, String> {
        let mut proxies: Vec<String> = Vec::new();
        let mut queries: Vec<String> = Vec::new();
        let mut runs: u32 = 5;
        let mut timeout_ms: u64 = 5000;
        let mut upstream_udp = "1.1.1.1:53".to_string();
        let mut upstream_udp_domain: Option<String> = None;
        let mut doh_url = "https://cloudflare-dns.com/dns-query".to_string();
        let mut doh_tls_name = "cloudflare-dns.com".to_string();
        let mut doh_bootstrap: Vec<IpAddr> = vec![];
        let mut json_path: Option<String> = None;
        let mut skip_baseline = false;
        let mut verbose = false;
        let mut socks5_udp_reuse = false;
        let mut debug_udp = false;

        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            let take_val = |idx: &mut usize| -> Result<String, String> {
                *idx += 1;
                args.get(*idx)
                    .cloned()
                    .ok_or_else(|| format!("missing value for {a}", a = args[*idx - 1]))
            };
            match a.as_str() {
                "--proxy" => proxies.push(take_val(&mut i)?),
                "--query" => queries.push(take_val(&mut i)?),
                "--runs" => {
                    runs = take_val(&mut i)?
                        .parse()
                        .map_err(|e| format!("--runs: {e}"))?
                }
                "--timeout" => {
                    timeout_ms = take_val(&mut i)?
                        .parse()
                        .map_err(|e| format!("--timeout: {e}"))?
                }
                "--upstream-udp" => upstream_udp = take_val(&mut i)?,
                "--socks5-udp-domain" => upstream_udp_domain = Some(take_val(&mut i)?),
                "--socks5-udp-reuse" => socks5_udp_reuse = true,
                "--debug-udp" => debug_udp = true,
                "--doh-url" => doh_url = take_val(&mut i)?,
                "--doh-tls-name" => doh_tls_name = take_val(&mut i)?,
                "--doh-bootstrap" => {
                    let v = take_val(&mut i)?;
                    let ip: IpAddr = v.parse().map_err(|e| format!("--doh-bootstrap: {e}"))?;
                    doh_bootstrap.push(ip);
                }
                "--json" => json_path = Some(take_val(&mut i)?),
                "--skip-baseline" => skip_baseline = true,
                "--verbose" | "-v" => verbose = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }

        if proxies.is_empty() {
            for k in ["SOCKS5_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
                if let Ok(v) = std::env::var(k) {
                    if !v.is_empty() {
                        proxies.push(v);
                    }
                }
            }
        }

        let parsed_proxies: Vec<ProxyConfig> = proxies
            .into_iter()
            .map(|s| ProxyConfig::parse(&s).map_err(|e| format!("proxy '{s}': {e}")))
            .collect::<Result<_, _>>()?;

        if queries.is_empty() {
            queries = DEFAULT_QUERIES.iter().map(|s| s.to_string()).collect();
        }

        if doh_bootstrap.is_empty() {
            doh_bootstrap = vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ];
        }

        Ok(Cli {
            proxies: parsed_proxies,
            queries,
            runs,
            timeout: Duration::from_millis(timeout_ms),
            upstream_udp: upstream_udp
                .parse()
                .map_err(|e| format!("--upstream-udp: {e}"))?,
            upstream_udp_domain,
            doh_url,
            doh_tls_name,
            doh_bootstrap,
            json_path,
            skip_baseline,
            verbose,
            socks5_udp_reuse,
            debug_udp,
        })
    }
}

fn print_help() {
    eprintln!(
        "DNS-over-Proxy probe.\n\n\
         Usage: dns_proxy_probe [OPTIONS]\n\n\
         Options:\n\
           --proxy <url>           Repeatable. Proxy URL (socks5://, socks5h://, http://).\n\
                                   Falls back to SOCKS5_PROXY / HTTP_PROXY env vars.\n\
           --query <domain>        Repeatable. DNS query name.\n\
           --runs <N>              Iterations per (scenario, query). Default 5.\n\
           --timeout <ms>          Per-query timeout. Default 5000.\n\
           --upstream-udp <addr>   Plain UDP DNS upstream. Default 1.1.1.1:53.\n\
           --socks5-udp-domain <h> Use ATYP=domain for SOCKS5 UDP target (let proxy resolve).\n\
                                   Mutually informative with --upstream-udp; port comes from <addr>.\n\
           --socks5-udp-reuse      Share one ASSOCIATE across all queries.\n\
           --debug-udp             Verbose SOCKS5 UDP diagnostics: frame hex, src port,\n\
                                   every received datagram and its source address.\n\
           --doh-url <url>         DoH endpoint URL. Default https://cloudflare-dns.com/dns-query.\n\
           --doh-tls-name <host>   TLS SNI for DoH. Default cloudflare-dns.com.\n\
           --doh-bootstrap <ip>    Repeatable. DoH bootstrap IP. Default 1.1.1.1, 1.0.0.1.\n\
           --json <path>           Write raw samples + summary to a JSON file.\n\
           --skip-baseline         Skip direct (no-proxy) baseline scenarios.\n\
           --verbose, -v           Print every query trace.\n\
           --help, -h              Show this message.\n"
    );
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Scenario {
    BaselineDirectUdp,
    BaselineDirectDoh,
    Socks5UdpDns,
    DohOverSocks5,
    DohOverHttpConnect,
}

impl Scenario {
    fn id(self) -> &'static str {
        match self {
            Self::BaselineDirectUdp => "baseline-direct-udp",
            Self::BaselineDirectDoh => "baseline-direct-doh",
            Self::Socks5UdpDns => "socks5-udp-dns",
            Self::DohOverSocks5 => "doh-over-socks5",
            Self::DohOverHttpConnect => "doh-over-http-connect",
        }
    }
}

#[derive(Clone, Debug)]
struct Sample {
    proxy_id: String,
    scenario: Scenario,
    query: String,
    record: &'static str,
    elapsed: Duration,
    outcome: Outcome,
}

#[derive(Clone, Debug)]
enum Outcome {
    Ok {
        ip_count: usize,
        has_https_rr: bool,
        has_h3_alpn: bool,
    },
    Skipped(String),
    Timeout,
    Error(String),
}

// ---------------------------------------------------------------------------
// Capability probe
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Capability {
    proxy_id: String,
    tcp_connect: ProbeResult,
    udp_associate: Option<ProbeResult>,
    relay_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
enum ProbeResult {
    Ok(Duration),
    Failed(String),
}

impl ProbeResult {
    fn ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
    fn label(&self) -> String {
        match self {
            Self::Ok(d) => format!("OK ({:.0} ms)", d.as_secs_f64() * 1000.0),
            Self::Failed(e) => format!("FAILED: {e}"),
        }
    }
}

async fn probe_capability(proxy: &ProxyConfig, doh_target: SocketAddr) -> Capability {
    let proxy_id = proxy.identity();
    let tcp_connect = match probe_tcp_connect(proxy, doh_target).await {
        Ok(d) => ProbeResult::Ok(d),
        Err(e) => ProbeResult::Failed(e.to_string()),
    };

    let (udp_associate, relay_addr) = if matches!(proxy.scheme, ProxyScheme::Socks5 { .. }) {
        match probe_udp_associate(proxy).await {
            Ok((d, addr)) => (Some(ProbeResult::Ok(d)), Some(addr)),
            Err(e) => (Some(ProbeResult::Failed(e.to_string())), None),
        }
    } else {
        (None, None)
    };

    Capability {
        proxy_id,
        tcp_connect,
        udp_associate,
        relay_addr,
    }
}

async fn probe_tcp_connect(proxy: &ProxyConfig, target: SocketAddr) -> io::Result<Duration> {
    let start = Instant::now();
    let resolver = lkrequest::dns::SystemDns;
    // Probe by attempting a CONNECT to the DoH bootstrap IP/port.
    let target_ip = target.ip().to_string();
    let target_port = target.port();
    let _stream = proxy
        .connect(&target_ip, target_port, None, &resolver)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(start.elapsed())
}

async fn probe_udp_associate(proxy: &ProxyConfig) -> io::Result<(Duration, SocketAddr)> {
    let start = Instant::now();
    let (proxy_host, proxy_port) = proxy.host_port();
    let mut tcp = TcpStream::connect((proxy_host, proxy_port)).await?;
    socks5_handshake(&mut tcp, proxy.auth.as_ref()).await?;
    let req: [u8; 10] = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    tcp.write_all(&req).await?;
    let relay = socks5_read_command_response(&mut tcp).await?;
    // Resolve any unspecified relay address onto the proxy's IP.
    let relay = normalize_relay_addr(relay, proxy_host, proxy_port).await?;
    // Keep TCP alive until end of probe; drop it after we measure.
    drop(tcp);
    Ok((start.elapsed(), relay))
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake / framing (handwritten for the demo)
// ---------------------------------------------------------------------------

async fn socks5_handshake(tcp: &mut TcpStream, auth: Option<&ProxyAuth>) -> io::Result<()> {
    if auth.is_some() {
        tcp.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut method = [0u8; 2];
    tcp.read_exact(&mut method).await?;
    if method[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad SOCKS5 version 0x{:02x}", method[0]),
        ));
    }
    match method[1] {
        0x00 => Ok(()),
        0x02 => {
            let auth = auth.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "proxy requested user/pass auth but no credentials configured",
                )
            })?;
            if auth.username.len() > 255 || auth.password.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 user/pass exceeds 255 bytes",
                ));
            }
            let mut buf = Vec::with_capacity(3 + auth.username.len() + auth.password.len());
            buf.push(0x01);
            buf.push(auth.username.len() as u8);
            buf.extend_from_slice(auth.username.as_bytes());
            buf.push(auth.password.len() as u8);
            buf.extend_from_slice(auth.password.as_bytes());
            tcp.write_all(&buf).await?;
            let mut resp = [0u8; 2];
            tcp.read_exact(&mut resp).await?;
            if resp[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 auth rejected",
                ));
            }
            Ok(())
        }
        0xFF => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 server rejected all auth methods",
        )),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unexpected SOCKS5 auth method 0x{other:02x}"),
        )),
    }
}

async fn socks5_read_command_response(tcp: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad SOCKS5 version 0x{:02x}", hdr[0]),
        ));
    }
    if hdr[1] != 0x00 {
        let msg = match hdr[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown",
        };
        return Err(io::Error::other(format!(
            "SOCKS5 reply 0x{:02x}: {msg}",
            hdr[1]
        )));
    }
    match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            tcp.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x04 => {
            let mut b = [0u8; 18];
            tcp.read_exact(&mut b).await?;
            let octets: [u8; 16] = b[..16].try_into().unwrap();
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut tail = vec![0u8; len[0] as usize + 2];
            tcp.read_exact(&mut tail).await?;
            let port = u16::from_be_bytes([tail[tail.len() - 2], tail[tail.len() - 1]]);
            Ok(SocketAddr::from(([0, 0, 0, 0], port)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported ATYP 0x{other:02x}"),
        )),
    }
}

async fn normalize_relay_addr(
    relay: SocketAddr,
    proxy_host: &str,
    proxy_port: u16,
) -> io::Result<SocketAddr> {
    if !relay.ip().is_unspecified() {
        return Ok(relay);
    }
    // Some servers return 0.0.0.0:<port> meaning "use the IP you connected to".
    let resolver = lkrequest::dns::SystemDns;
    use lkrequest::DnsResolver;
    let addrs = resolver
        .resolve(proxy_host, proxy_port)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let addr = addrs
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other(format!("could not resolve proxy host {proxy_host}")))?;
    Ok(SocketAddr::new(addr.ip(), relay.port()))
}

/// Encode a SOCKS5 UDP datagram with target = (host, port) using ATYP=domain.
fn encode_socks5_udp_domain(host: &str, port: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    if host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host > 255 bytes",
        ));
    }
    let mut buf = Vec::with_capacity(7 + host.len() + payload.len());
    buf.push(0x00); // RSV
    buf.push(0x00);
    buf.push(0x00); // FRAG
    buf.push(0x03); // ATYP = domain
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Encode a SOCKS5 UDP datagram with target = SocketAddr (IPv4 or IPv6).
fn encode_socks5_udp_ip(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22 + payload.len());
    buf.push(0x00);
    buf.push(0x00);
    buf.push(0x00);
    match target {
        SocketAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    buf.extend_from_slice(payload);
    buf
}

/// Strip a SOCKS5 UDP datagram header and return the payload offset.
fn parse_socks5_udp_header(buf: &[u8]) -> io::Result<usize> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too short",
        ));
    }
    if buf[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP not supported",
        ));
    }
    let offset = match buf[3] {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => {
            if buf.len() < 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "domain frame too short",
                ));
            }
            4 + 1 + buf[4] as usize + 2
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported ATYP 0x{other:02x}"),
            ))
        }
    };
    if buf.len() < offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame shorter than declared header",
        ));
    }
    Ok(offset)
}

// ---------------------------------------------------------------------------
// Direct UDP DNS (baseline + raw client used by SOCKS5 UDP scenario)
// ---------------------------------------------------------------------------

/// Build a wire-format DNS query message for `name` / `record_type` with a
/// random transaction id. Returns (id, bytes).
fn build_dns_query(name: &str, record_type: RecordType) -> io::Result<(u16, Vec<u8>)> {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::Name;
    use hickory_resolver::proto::serialize::binary::BinEncodable;

    let id: u16 = rand_u16();
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let parsed: Name = name
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad name: {e}")))?;
    msg.add_query(Query::query(parsed, record_type));
    let bytes = msg
        .to_bytes()
        .map_err(|e| io::Error::other(format!("encode: {e}")))?;
    Ok((id, bytes))
}

fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16).wrapping_add(0x4242)
}

/// Parse a DNS response into (ip_count, has_https_rr, has_h3_alpn).
fn analyze_dns_response(
    response: &[u8],
    expected_id: u16,
    record_type: RecordType,
) -> io::Result<(usize, bool, bool)> {
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::RData;
    use hickory_resolver::proto::serialize::binary::BinDecodable;

    let msg = Message::from_bytes(response)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse: {e}")))?;
    if msg.metadata.id != expected_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "DNS id mismatch: expected {expected_id:#06x}, got {:#06x}",
                msg.metadata.id
            ),
        ));
    }
    let mut ip_count = 0usize;
    let mut has_https_rr = false;
    let mut has_h3_alpn = false;
    for rr in &msg.answers {
        match &rr.data {
            RData::A(_) | RData::AAAA(_) => ip_count += 1,
            RData::HTTPS(https) => {
                has_https_rr = true;
                for (_, value) in https.0.svc_params.iter() {
                    if let SvcParamValue::Alpn(alpn) = value {
                        if alpn.0.iter().any(|s| {
                            let s = s.to_string();
                            s == "h3" || s.starts_with("h3-")
                        }) {
                            has_h3_alpn = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // For HTTPS-RR queries the upstream may NXDOMAIN/NoData; treat as "no record"
    // rather than a fatal error.
    let _ = record_type;
    Ok((ip_count, has_https_rr, has_h3_alpn))
}

async fn baseline_direct_udp_query(
    upstream: SocketAddr,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
) -> io::Result<(usize, bool, bool)> {
    let (id, query_bytes) = build_dns_query(name, record_type)?;
    let bind_addr: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(upstream).await?;
    socket.send(&query_bytes).await?;
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp recv timed out"))??;
    analyze_dns_response(&buf[..n], id, record_type)
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP DNS scenario
// ---------------------------------------------------------------------------

/// SOCKS5 UDP target spec for the demo. Mirrors the framing distinction in
/// RFC 1928 §7 so a probe can compare ATYP=0x01 (IP) against ATYP=0x03 (domain).
#[derive(Clone, Debug)]
enum UdpTarget {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl UdpTarget {
    fn label(&self) -> String {
        match self {
            Self::Ip(a) => format!("ip={a}"),
            Self::Domain { host, port } => format!("domain={host}:{port}"),
        }
    }
}

fn encode_udp_frame(target: &UdpTarget, payload: &[u8]) -> io::Result<Vec<u8>> {
    match target {
        UdpTarget::Ip(addr) => Ok(encode_socks5_udp_ip(*addr, payload)),
        UdpTarget::Domain { host, port } => encode_socks5_udp_domain(host, *port, payload),
    }
}

struct Socks5UdpDnsClient {
    _tcp: TcpStream,
    udp: UdpSocket,
    relay: SocketAddr,
    debug: bool,
}

impl Socks5UdpDnsClient {
    async fn open(proxy: &ProxyConfig, debug: bool) -> io::Result<Self> {
        let (proxy_host, proxy_port) = proxy.host_port();
        let mut tcp = TcpStream::connect((proxy_host, proxy_port)).await?;
        socks5_handshake(&mut tcp, proxy.auth.as_ref()).await?;
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let relay = socks5_read_command_response(&mut tcp).await?;
        let relay = normalize_relay_addr(relay, proxy_host, proxy_port).await?;

        let bind_addr: SocketAddr = if relay.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let udp = UdpSocket::bind(bind_addr).await?;

        if debug {
            let local = udp
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|e| format!("?({e})"));
            eprintln!("  [debug-udp] ASSOCIATE ok: relay={relay} local_src={local}");
        }

        // NOTE: deliberately *not* calling `udp.connect(relay)` so that we can
        // observe datagrams whose source address differs from BND.ADDR
        // (which some proxy implementations emit). User-space filtering below
        // matches lkrequest's main `Socks5UdpSocket::packet_source_matches_relay`.
        Ok(Self {
            _tcp: tcp,
            udp,
            relay,
            debug,
        })
    }

    async fn query(
        &self,
        target: &UdpTarget,
        name: &str,
        record_type: RecordType,
        timeout: Duration,
    ) -> io::Result<(usize, bool, bool)> {
        let (id, dns_bytes) = build_dns_query(name, record_type)?;
        let frame = encode_udp_frame(target, &dns_bytes)?;

        if self.debug {
            eprintln!(
                "  [debug-udp] -> send {nb} B to relay={relay}, target={tlabel}, query={name}/{rt:?}",
                nb = frame.len(),
                relay = self.relay,
                tlabel = target.label(),
                rt = record_type,
            );
            eprintln!("  [debug-udp]    frame hex: {}", hex_preview(&frame, 64));
        }

        self.udp.send_to(&frame, self.relay).await?;

        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 4096];
        let mut foreign_drops = 0u32;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if self.debug {
                    eprintln!(
                        "  [debug-udp] <- timeout after {timeout:?} \
                         (relay={relay}, foreign_drops={foreign_drops})",
                        relay = self.relay,
                    );
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "socks5-udp recv timed out",
                ));
            }
            let recv = tokio::time::timeout(remaining, self.udp.recv_from(&mut buf)).await;
            let (n, src) = match recv {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    if self.debug {
                        eprintln!("  [debug-udp] <- timeout (foreign_drops={foreign_drops})");
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "socks5-udp recv timed out",
                    ));
                }
            };

            if self.debug {
                eprintln!(
                    "  [debug-udp] <- recv {n} B from {src} \
                     (relay was {relay})",
                    relay = self.relay
                );
                eprintln!("  [debug-udp]    frame hex: {}", hex_preview(&buf[..n], 64));
            }

            // User-space source filter: accept exact relay match, or
            // (when relay IP is unspecified) port match only.
            let accept = if self.relay.ip().is_unspecified() {
                src.port() == self.relay.port()
            } else {
                src == self.relay
            };
            if !accept {
                foreign_drops += 1;
                if self.debug {
                    eprintln!(
                        "  [debug-udp]    DROP: src {src} != relay {relay}",
                        relay = self.relay
                    );
                }
                continue; // keep waiting; another datagram may arrive
            }

            let off = match parse_socks5_udp_header(&buf[..n]) {
                Ok(o) => o,
                Err(e) => {
                    if self.debug {
                        eprintln!("  [debug-udp]    DROP: bad SOCKS5 UDP header: {e}");
                    }
                    continue;
                }
            };
            return analyze_dns_response(&buf[off..n], id, record_type);
        }
    }
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut out = String::with_capacity(take * 3 + 8);
    for b in &bytes[..take] {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x} ");
    }
    if bytes.len() > max {
        out.push_str(&format!("... ({} B total)", bytes.len()));
    }
    out
}

// ---------------------------------------------------------------------------
// ProxyRuntimeProvider for hickory DoH-over-proxy
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ProxyRuntimeProvider {
    proxy: Arc<ProxyConfig>,
    handle: TokioHandle,
}

impl ProxyRuntimeProvider {
    fn new(proxy: ProxyConfig) -> Self {
        Self {
            proxy: Arc::new(proxy),
            handle: TokioHandle::default(),
        }
    }
}

impl RuntimeProvider for ProxyRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let proxy = self.proxy.clone();
        Box::pin(async move {
            let target_host = server_addr.ip().to_string();
            let target_port = server_addr.port();
            let resolver = lkrequest::dns::SystemDns;
            let fut = proxy.connect(&target_host, target_port, None, &resolver);
            let wait = wait_for.unwrap_or_else(|| Duration::from_secs(8));
            let stream = tokio::time::timeout(wait, fut)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("proxy connect to {server_addr} timed out after {wait:?}"),
                    )
                })?
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        // UDP is never used for DoH, but the trait requires a concrete impl.
        Box::pin(UdpSocket::bind(local_addr))
    }
}

// ---------------------------------------------------------------------------
// DoH-over-proxy scenario
// ---------------------------------------------------------------------------

fn build_doh_resolver(
    bootstrap: &[IpAddr],
    tls_dns_name: &str,
    provider: ProxyRuntimeProvider,
) -> Resolver<ProxyRuntimeProvider> {
    let config = doh_resolver_config(bootstrap, tls_dns_name);
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.attempts = 1;
    Resolver::builder_with_config(config, provider)
        .with_options(opts)
        .build()
        .expect("DoH resolver config should be valid")
}

async fn doh_query(
    resolver: &Resolver<ProxyRuntimeProvider>,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
) -> io::Result<(usize, bool, bool)> {
    let lookup = tokio::time::timeout(timeout, resolver.lookup(name, record_type))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "doh lookup timed out"))?;
    let lookup = match lookup {
        Ok(l) => l,
        Err(e) => {
            // Treat NXDOMAIN / NoRecords as "no record" rather than fatal.
            let s = e.to_string();
            if s.contains("no record found") || s.contains("NoRecordsFound") {
                return Ok((0, false, false));
            }
            return Err(io::Error::other(s));
        }
    };

    let mut ip_count = 0usize;
    let mut has_https_rr = false;
    let mut has_h3_alpn = false;
    for record in lookup.answers() {
        match &record.data {
            hickory_resolver::proto::rr::RData::A(_)
            | hickory_resolver::proto::rr::RData::AAAA(_) => ip_count += 1,
            hickory_resolver::proto::rr::RData::HTTPS(https) => {
                has_https_rr = true;
                for (_, value) in https.0.svc_params.iter() {
                    if let SvcParamValue::Alpn(alpn) = value {
                        if alpn.0.iter().any(|s| {
                            let s = s.to_string();
                            s == "h3" || s.starts_with("h3-")
                        }) {
                            has_h3_alpn = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((ip_count, has_https_rr, has_h3_alpn))
}

// ---------------------------------------------------------------------------
// Stats / report
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Stats {
    n_total: u32,
    n_ok: u32,
    n_skip: u32,
    n_err: u32,
    /// HTTPS-record-type queries that succeeded.
    n_https_query_ok: u32,
    /// HTTPS-record-type queries that came back with at least one HTTPS RR.
    n_https_rr_hit: u32,
    n_h3_alpn_hit: u32,
    elapsed_ms: Vec<f64>,
    error_breakdown: BTreeMap<String, u32>,
}

impl Stats {
    fn add(&mut self, sample: &Sample) {
        self.n_total += 1;
        let is_https_query = sample.record == "HTTPS";
        match &sample.outcome {
            Outcome::Ok {
                has_https_rr,
                has_h3_alpn,
                ..
            } => {
                self.n_ok += 1;
                if is_https_query {
                    self.n_https_query_ok += 1;
                    if *has_https_rr {
                        self.n_https_rr_hit += 1;
                    }
                    if *has_h3_alpn {
                        self.n_h3_alpn_hit += 1;
                    }
                }
                self.elapsed_ms.push(sample.elapsed.as_secs_f64() * 1000.0);
            }
            Outcome::Skipped(_) => self.n_skip += 1,
            Outcome::Timeout => {
                self.n_err += 1;
                *self.error_breakdown.entry("timeout".into()).or_default() += 1;
            }
            Outcome::Error(s) => {
                self.n_err += 1;
                let key = error_kind(s);
                *self.error_breakdown.entry(key).or_default() += 1;
            }
        }
    }

    fn success_rate(&self) -> f64 {
        let denom = self.n_total.saturating_sub(self.n_skip);
        if denom == 0 {
            0.0
        } else {
            self.n_ok as f64 / denom as f64
        }
    }

    fn percentile(&self, p: f64) -> Option<f64> {
        if self.elapsed_ms.is_empty() {
            return None;
        }
        let mut v = self.elapsed_ms.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
        Some(v[idx.min(v.len() - 1)])
    }

    /// Hit-rate of HTTPS RR among successful HTTPS-type queries.
    /// Returns `None` when no HTTPS-type queries succeeded (avoid lying with 0%).
    fn https_rr_rate(&self) -> Option<f64> {
        if self.n_https_query_ok == 0 {
            None
        } else {
            Some(self.n_https_rr_hit as f64 / self.n_https_query_ok as f64)
        }
    }
}

fn error_kind(msg: &str) -> String {
    let lower = msg.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "timeout".into()
    } else if lower.contains("refused") {
        "refused".into()
    } else if lower.contains("command not supported") || lower.contains("0x07") {
        "udp_unsupported".into()
    } else if lower.contains("not allowed") {
        "not_allowed".into()
    } else if lower.contains("no record") {
        "no_record".into()
    } else if lower.contains("auth") {
        "auth".into()
    } else if lower.contains("unreachable") {
        "unreachable".into()
    } else {
        "other".into()
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = match Cli::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n");
            print_help();
            std::process::exit(2);
        }
    };

    if cli.proxies.is_empty() && cli.skip_baseline {
        eprintln!("error: no --proxy provided and --skip-baseline is set; nothing to do");
        std::process::exit(2);
    }

    let mut samples: Vec<Sample> = Vec::new();
    let mut capabilities: Vec<Capability> = Vec::new();

    // ---------------- Baseline (no proxy) --------------------------------
    if !cli.skip_baseline {
        eprintln!("== running baseline (no proxy) ==");
        run_baseline(&cli, &mut samples).await;
    }

    // ---------------- Per-proxy scenarios --------------------------------
    let doh_target = SocketAddr::new(cli.doh_bootstrap[0], 443);
    for proxy in &cli.proxies {
        eprintln!("== probing proxy {proxy} ==");
        let cap = probe_capability(proxy, doh_target).await;
        eprintln!(
            "   TCP CONNECT to {doh_target}: {}",
            cap.tcp_connect.label()
        );
        if let Some(udp) = &cap.udp_associate {
            eprintln!(
                "   SOCKS5 UDP ASSOCIATE       : {}{}",
                udp.label(),
                cap.relay_addr
                    .map(|a| format!(" relay={a}"))
                    .unwrap_or_default()
            );
        }

        run_proxy_scenarios(&cli, proxy, &cap, &mut samples).await;
        capabilities.push(cap);
    }

    print_report(&cli, &capabilities, &samples);

    if let Some(path) = &cli.json_path {
        if let Err(e) = write_json(path, &capabilities, &samples) {
            eprintln!("warning: failed to write JSON to {path}: {e}");
        }
    }
}

async fn run_baseline(cli: &Cli, samples: &mut Vec<Sample>) {
    let baseline_id = "(direct)".to_string();

    for query in &cli.queries {
        for run in 0..cli.runs {
            for record in [("A", RecordType::A), ("HTTPS", RecordType::HTTPS)] {
                let start = Instant::now();
                let res =
                    baseline_direct_udp_query(cli.upstream_udp, query, record.1, cli.timeout).await;
                samples.push(Sample {
                    proxy_id: baseline_id.clone(),
                    scenario: Scenario::BaselineDirectUdp,
                    query: query.clone(),
                    record: record.0,
                    elapsed: start.elapsed(),
                    outcome: outcome_from_io(res),
                });
                if cli.verbose {
                    eprintln!(
                        "   [run {run}] direct-udp {query} {} -> {:?}",
                        record.0,
                        samples.last().map(|s| &s.outcome)
                    );
                }
            }
        }
    }

    // direct DoH baseline via system tokio resolver (no proxy)
    let resolver = build_direct_doh_resolver(&cli.doh_bootstrap, &cli.doh_tls_name);
    for query in &cli.queries {
        for _ in 0..cli.runs {
            for record in [("A", RecordType::A), ("HTTPS", RecordType::HTTPS)] {
                let start = Instant::now();
                let res = direct_doh_query(&resolver, query, record.1, cli.timeout).await;
                samples.push(Sample {
                    proxy_id: baseline_id.clone(),
                    scenario: Scenario::BaselineDirectDoh,
                    query: query.clone(),
                    record: record.0,
                    elapsed: start.elapsed(),
                    outcome: outcome_from_io(res),
                });
            }
        }
    }
}

fn build_direct_doh_resolver(
    bootstrap: &[IpAddr],
    tls_dns_name: &str,
) -> hickory_resolver::TokioResolver {
    let config = doh_resolver_config(bootstrap, tls_dns_name);
    let mut opts = ResolverOpts::default();
    opts.cache_size = 0;
    opts.attempts = 1;
    hickory_resolver::TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .expect("direct DoH resolver config should be valid")
}

fn doh_resolver_config(bootstrap: &[IpAddr], tls_dns_name: &str) -> ResolverConfig {
    let name_servers = bootstrap
        .iter()
        .copied()
        .map(|ip| NameServerConfig::https(ip, Arc::from(tls_dns_name), None))
        .collect();
    ResolverConfig::from_parts(None, vec![], name_servers)
}

async fn direct_doh_query(
    resolver: &hickory_resolver::TokioResolver,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
) -> io::Result<(usize, bool, bool)> {
    let lookup = tokio::time::timeout(timeout, resolver.lookup(name, record_type))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct doh timed out"))?;
    let lookup = match lookup {
        Ok(l) => l,
        Err(e) => {
            let s = e.to_string();
            if s.contains("no record found") || s.contains("NoRecordsFound") {
                return Ok((0, false, false));
            }
            return Err(io::Error::other(s));
        }
    };
    let mut ip_count = 0usize;
    let mut has_https_rr = false;
    let mut has_h3_alpn = false;
    for record in lookup.answers() {
        match &record.data {
            hickory_resolver::proto::rr::RData::A(_)
            | hickory_resolver::proto::rr::RData::AAAA(_) => ip_count += 1,
            hickory_resolver::proto::rr::RData::HTTPS(https) => {
                has_https_rr = true;
                for (_, value) in https.0.svc_params.iter() {
                    if let SvcParamValue::Alpn(alpn) = value {
                        if alpn.0.iter().any(|s| {
                            let s = s.to_string();
                            s == "h3" || s.starts_with("h3-")
                        }) {
                            has_h3_alpn = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((ip_count, has_https_rr, has_h3_alpn))
}

async fn run_proxy_scenarios(
    cli: &Cli,
    proxy: &ProxyConfig,
    cap: &Capability,
    samples: &mut Vec<Sample>,
) {
    let proxy_id = proxy.identity();
    let is_socks5 = matches!(proxy.scheme, ProxyScheme::Socks5 { .. });
    let is_http = matches!(proxy.scheme, ProxyScheme::Http { .. });

    // ---- Scenario: socks5-udp-dns -----
    if is_socks5 {
        let supported = cap.udp_associate.as_ref().map(|p| p.ok()).unwrap_or(false);
        if !supported {
            for query in &cli.queries {
                for record in ["A", "HTTPS"] {
                    samples.push(Sample {
                        proxy_id: proxy_id.clone(),
                        scenario: Scenario::Socks5UdpDns,
                        query: query.clone(),
                        record,
                        elapsed: Duration::ZERO,
                        outcome: Outcome::Skipped("udp associate not supported by proxy".into()),
                    });
                }
            }
        } else {
            run_socks5_udp_dns(cli, proxy, &proxy_id, samples).await;
        }
    }

    // ---- Scenario: doh-over-socks5 ----
    if is_socks5 {
        if cap.tcp_connect.ok() {
            run_doh_over_proxy(cli, proxy, &proxy_id, Scenario::DohOverSocks5, samples).await;
        } else {
            for query in &cli.queries {
                for record in ["A", "HTTPS"] {
                    samples.push(Sample {
                        proxy_id: proxy_id.clone(),
                        scenario: Scenario::DohOverSocks5,
                        query: query.clone(),
                        record,
                        elapsed: Duration::ZERO,
                        outcome: Outcome::Skipped("tcp connect probe failed".into()),
                    });
                }
            }
        }
    }

    // ---- Scenario: doh-over-http-connect ----
    if is_http {
        if cap.tcp_connect.ok() {
            run_doh_over_proxy(cli, proxy, &proxy_id, Scenario::DohOverHttpConnect, samples).await;
        } else {
            for query in &cli.queries {
                for record in ["A", "HTTPS"] {
                    samples.push(Sample {
                        proxy_id: proxy_id.clone(),
                        scenario: Scenario::DohOverHttpConnect,
                        query: query.clone(),
                        record,
                        elapsed: Duration::ZERO,
                        outcome: Outcome::Skipped("tcp connect probe failed".into()),
                    });
                }
            }
        }
    }
}

async fn run_socks5_udp_dns(
    cli: &Cli,
    proxy: &ProxyConfig,
    proxy_id: &str,
    samples: &mut Vec<Sample>,
) {
    let target = match &cli.upstream_udp_domain {
        Some(host) => UdpTarget::Domain {
            host: host.clone(),
            port: cli.upstream_udp.port(),
        },
        None => UdpTarget::Ip(cli.upstream_udp),
    };

    if cli.debug_udp {
        eprintln!(
            "  [debug-udp] mode reuse={} target={}",
            cli.socks5_udp_reuse,
            target.label()
        );
    }

    let shared_client: Option<Socks5UdpDnsClient> = if cli.socks5_udp_reuse {
        match Socks5UdpDnsClient::open(proxy, cli.debug_udp).await {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("   socks5-udp shared open failed: {e}");
                None
            }
        }
    } else {
        None
    };

    for query in &cli.queries {
        for run in 0..cli.runs {
            for (record_label, record_type) in [("A", RecordType::A), ("HTTPS", RecordType::HTTPS)]
            {
                let start = Instant::now();
                let outcome = if cli.socks5_udp_reuse {
                    match shared_client.as_ref() {
                        Some(client) => outcome_from_io(
                            client.query(&target, query, record_type, cli.timeout).await,
                        ),
                        None => Outcome::Error("shared ASSOCIATE not available".into()),
                    }
                } else {
                    match Socks5UdpDnsClient::open(proxy, cli.debug_udp).await {
                        Ok(client) => outcome_from_io(
                            client.query(&target, query, record_type, cli.timeout).await,
                        ),
                        Err(e) => Outcome::Error(format!("open: {e}")),
                    }
                };
                samples.push(Sample {
                    proxy_id: proxy_id.to_string(),
                    scenario: Scenario::Socks5UdpDns,
                    query: query.clone(),
                    record: record_label,
                    elapsed: start.elapsed(),
                    outcome: outcome.clone(),
                });
                if cli.verbose {
                    eprintln!("   [run {run}] socks5-udp {query} {record_label} -> {outcome:?}");
                }
            }
        }
    }

    drop(shared_client);
}

async fn run_doh_over_proxy(
    cli: &Cli,
    proxy: &ProxyConfig,
    proxy_id: &str,
    scenario: Scenario,
    samples: &mut Vec<Sample>,
) {
    let provider = ProxyRuntimeProvider::new(proxy.clone());
    let resolver = build_doh_resolver(&cli.doh_bootstrap, &cli.doh_tls_name, provider);

    for query in &cli.queries {
        for run in 0..cli.runs {
            for (record_label, record_type) in [("A", RecordType::A), ("HTTPS", RecordType::HTTPS)]
            {
                let start = Instant::now();
                let outcome =
                    outcome_from_io(doh_query(&resolver, query, record_type, cli.timeout).await);
                samples.push(Sample {
                    proxy_id: proxy_id.to_string(),
                    scenario,
                    query: query.clone(),
                    record: record_label,
                    elapsed: start.elapsed(),
                    outcome: outcome.clone(),
                });
                if cli.verbose {
                    eprintln!(
                        "   [run {run}] {} {query} {record_label} -> {outcome:?}",
                        scenario.id()
                    );
                }
            }
        }
    }
}

fn outcome_from_io(res: io::Result<(usize, bool, bool)>) -> Outcome {
    match res {
        Ok((ip_count, has_https_rr, has_h3_alpn)) => {
            if ip_count == 0 && !has_https_rr {
                // upstream returned an empty answer — count as ok-but-empty
                Outcome::Ok {
                    ip_count,
                    has_https_rr,
                    has_h3_alpn,
                }
            } else {
                Outcome::Ok {
                    ip_count,
                    has_https_rr,
                    has_h3_alpn,
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Outcome::Timeout,
        Err(e) => Outcome::Error(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn print_report(cli: &Cli, capabilities: &[Capability], samples: &[Sample]) {
    println!();
    println!("============================================================");
    println!("DNS-over-Proxy probe report");
    println!("============================================================");
    println!(
        "queries={}  runs/scenario/record={}  timeout={}ms",
        cli.queries.len(),
        cli.runs,
        cli.timeout.as_millis()
    );
    println!("upstream-udp={}  doh-url={}", cli.upstream_udp, cli.doh_url);
    println!();

    let proxy_ids: Vec<String> = {
        let mut ids: Vec<String> = samples.iter().map(|s| s.proxy_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    };

    for proxy_id in &proxy_ids {
        println!("---- Proxy: {proxy_id} ----");
        if let Some(cap) = capabilities.iter().find(|c| c.proxy_id == *proxy_id) {
            println!("  capability:");
            println!(
                "    tcp connect to doh bootstrap : {}",
                cap.tcp_connect.label()
            );
            if let Some(udp) = &cap.udp_associate {
                println!(
                    "    socks5 udp associate         : {}{}",
                    udp.label(),
                    cap.relay_addr
                        .map(|a| format!(" (relay {a})"))
                        .unwrap_or_default()
                );
            }
        }

        let mut by_scenario: BTreeMap<&str, Stats> = BTreeMap::new();
        for s in samples.iter().filter(|s| s.proxy_id == *proxy_id) {
            by_scenario.entry(s.scenario.id()).or_default().add(s);
        }

        println!();
        println!(
            "  {:<22} {:>8} {:>9} {:>9} {:>9} {:>12}",
            "scenario", "samples", "success", "p50_ms", "p95_ms", "https_rr_hit"
        );
        for (id, stats) in &by_scenario {
            let p50 = stats
                .percentile(0.5)
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "-".into());
            let p95 = stats
                .percentile(0.95)
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "-".into());
            let succ = if stats.n_total - stats.n_skip == 0 {
                "skip".to_string()
            } else {
                format!("{:>5.1}%", stats.success_rate() * 100.0)
            };
            let https_rr = match stats.https_rr_rate() {
                Some(r) => format!(
                    "{}/{} ({:.0}%)",
                    stats.n_https_rr_hit,
                    stats.n_https_query_ok,
                    r * 100.0
                ),
                None => "n/a".to_string(),
            };
            println!(
                "  {:<22} {:>8} {:>9} {:>9} {:>9} {:>12}",
                id, stats.n_total, succ, p50, p95, https_rr
            );
            if !stats.error_breakdown.is_empty() {
                let parts: Vec<String> = stats
                    .error_breakdown
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                println!("    errors: {}", parts.join(", "));
            }
        }
        println!();
    }
}

fn write_json(path: &str, capabilities: &[Capability], samples: &[Sample]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Write as _;

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"capabilities\": [\n");
    for (i, c) in capabilities.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "    {{\"proxy_id\":{:?},\"tcp_connect\":{:?},\"udp_associate\":{:?},\"relay_addr\":{:?}}}",
            c.proxy_id,
            probe_to_string(&c.tcp_connect),
            c.udp_associate.as_ref().map(probe_to_string),
            c.relay_addr.map(|a| a.to_string()),
        ));
    }
    out.push_str("\n  ],\n");
    out.push_str("  \"samples\": [\n");
    for (i, s) in samples.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        let outcome = match &s.outcome {
            Outcome::Ok {
                ip_count,
                has_https_rr,
                has_h3_alpn,
            } => format!(
                "{{\"kind\":\"ok\",\"ip_count\":{ip_count},\"https_rr\":{has_https_rr},\"h3_alpn\":{has_h3_alpn}}}"
            ),
            Outcome::Skipped(reason) => format!("{{\"kind\":\"skipped\",\"reason\":{reason:?}}}"),
            Outcome::Timeout => "{\"kind\":\"timeout\"}".to_string(),
            Outcome::Error(e) => format!("{{\"kind\":\"error\",\"message\":{e:?}}}"),
        };
        out.push_str(&format!(
            "    {{\"proxy_id\":{:?},\"scenario\":{:?},\"query\":{:?},\"record\":{:?},\"elapsed_ms\":{:.3},\"outcome\":{outcome}}}",
            s.proxy_id,
            s.scenario.id(),
            s.query,
            s.record,
            s.elapsed.as_secs_f64() * 1000.0,
        ));
    }
    out.push_str("\n  ]\n}\n");

    let mut f = File::create(path)?;
    f.write_all(out.as_bytes())?;
    Ok(())
}

fn probe_to_string(p: &ProbeResult) -> String {
    match p {
        ProbeResult::Ok(d) => format!("ok:{:.1}", d.as_secs_f64() * 1000.0),
        ProbeResult::Failed(e) => format!("failed:{e}"),
    }
}
