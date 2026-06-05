//! SOCKS5 UDP relay: framing (RFC 1928 §7) and Quinn socket adapter.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(feature = "quic-h3")]
use std::future::Future;
#[cfg(feature = "quic-h3")]
use std::io::IoSliceMut;
#[cfg(feature = "quic-h3")]
use std::pin::Pin;
#[cfg(feature = "quic-h3")]
use std::sync::Arc;
#[cfg(feature = "quic-h3")]
use std::task::{ready, Context, Poll};

#[cfg(feature = "quic-h3")]
use quinn::udp;
#[cfg(feature = "quic-h3")]
use tokio::net::TcpStream;
#[cfg(feature = "quic-h3")]
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// SOCKS5 UDP target address (IP or domain for socks5h)
// ---------------------------------------------------------------------------

/// Target address for SOCKS5 UDP datagrams.
///
/// `Ip` is used with `socks5://` — the client resolves DNS locally.
/// `Domain` is used with `socks5h://` — the proxy resolves DNS.
#[derive(Debug, Clone)]
pub enum SocksTarget {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl SocksTarget {
    /// Port the target is reachable on. Part of the public API for consumers
    /// that construct `SocksTarget` values directly.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    /// Return a `SocketAddr` suitable for quinn connection tracking.
    ///
    /// For `Ip` targets this is the real address. For `Domain` targets
    /// a synthetic placeholder (`127.0.0.2:<port>`) is returned — quinn
    /// never sends packets to this address directly because all I/O is
    /// intercepted by `Socks5UdpSocket`.
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub fn quinn_addr(&self) -> SocketAddr {
        match self {
            Self::Ip(addr) => *addr,
            Self::Domain { port, .. } => SocketAddr::from(([127, 0, 0, 2], *port)),
        }
    }
}

impl fmt::Display for SocksTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP header encode / decode  (RFC 1928 §7)
//
// +------+------+------+----------+----------+----------+
// | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// | 2B   |  1B  |  1B  | variable |    2B    | variable |
// +------+------+------+----------+----------+----------+
// ---------------------------------------------------------------------------

/// Overhead bytes for an IPv4 SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
pub const SOCKS5_UDP_HEADER_IPV4: usize = 10;
/// Overhead bytes for an IPv6 SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22
pub const SOCKS5_UDP_HEADER_IPV6: usize = 22;

/// Encode a SOCKS5 UDP datagram with a `SocksTarget` destination.
/// Returns the total number of bytes written.
pub fn encode_socks5_udp_target(
    target: &SocksTarget,
    payload: &[u8],
    out: &mut [u8],
) -> io::Result<usize> {
    let hdr_len = socks5_udp_target_header_len(target);
    let total = hdr_len + payload.len();
    if out.len() < total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output buffer too small for SOCKS5 UDP frame",
        ));
    }

    out[0] = 0x00; // RSV
    out[1] = 0x00; // RSV
    out[2] = 0x00; // FRAG

    match target {
        SocksTarget::Ip(addr) => match addr {
            SocketAddr::V4(v4) => {
                out[3] = 0x01;
                out[4..8].copy_from_slice(&v4.ip().octets());
                out[8..10].copy_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                out[3] = 0x04;
                out[4..20].copy_from_slice(&v6.ip().octets());
                out[20..22].copy_from_slice(&v6.port().to_be_bytes());
            }
        },
        SocksTarget::Domain { host, port } => {
            let host_bytes = host.as_bytes();
            out[3] = 0x03; // ATYP: domain
            out[4] = host_bytes.len() as u8;
            out[5..5 + host_bytes.len()].copy_from_slice(host_bytes);
            let port_offset = 5 + host_bytes.len();
            out[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
        }
    }

    out[hdr_len..total].copy_from_slice(payload);
    Ok(total)
}

/// Convenience wrapper: encode with a plain `SocketAddr` target (socks5 mode).
#[allow(dead_code)]
pub fn encode_socks5_udp(target: SocketAddr, payload: &[u8], out: &mut [u8]) -> io::Result<usize> {
    encode_socks5_udp_target(&SocksTarget::Ip(target), payload, out)
}

/// Decode a SOCKS5 UDP datagram from `buf`. Returns `(source_addr, payload_slice)`.
pub fn decode_socks5_udp(buf: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP frame too short",
        ));
    }

    if buf[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS5 UDP fragmentation not supported",
        ));
    }

    match buf[3] {
        0x01 => {
            if buf.len() < SOCKS5_UDP_HEADER_IPV4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP IPv4 frame too short",
                ));
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((SocketAddr::from((ip, port)), &buf[SOCKS5_UDP_HEADER_IPV4..]))
        }
        0x04 => {
            if buf.len() < SOCKS5_UDP_HEADER_IPV6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP IPv6 frame too short",
                ));
            }
            let octets: [u8; 16] = buf[4..20].try_into().unwrap();
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((SocketAddr::from((ip, port)), &buf[SOCKS5_UDP_HEADER_IPV6..]))
        }
        0x03 => {
            if buf.len() < 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP domain frame too short",
                ));
            }
            let dlen = buf[4] as usize;
            // RFC 1928 §4: the domain name field is preceded by an octet
            // specifying its length; a length of zero is malformed.
            if dlen == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP domain length is zero",
                ));
            }
            let port_offset = 5 + dlen;
            if buf.len() < port_offset + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP domain frame too short for port",
                ));
            }
            let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
            let payload_offset = port_offset + 2;
            Ok((
                SocketAddr::from(([0, 0, 0, 0], port)),
                &buf[payload_offset..],
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 UDP unsupported ATYP: 0x{other:02x}"),
        )),
    }
}

/// Return `true` if a UDP packet whose source is `from` was plausibly sent by
/// the SOCKS5 relay at `relay`.
///
/// When the proxy's BND address is unspecified (e.g. `0.0.0.0:<port>`, which
/// some servers return to mean "use whatever IP you connected to"), only the
/// port is compared — the client has no reliable IP to match against.
pub(crate) fn packet_source_matches_relay(from: SocketAddr, relay: SocketAddr) -> bool {
    if relay.ip().is_unspecified() {
        return from.port() == relay.port();
    }
    from == relay
}

pub(crate) fn socks5_udp_target_header_len(target: &SocksTarget) -> usize {
    match target {
        SocksTarget::Ip(SocketAddr::V4(_)) => SOCKS5_UDP_HEADER_IPV4,
        SocksTarget::Ip(SocketAddr::V6(_)) => SOCKS5_UDP_HEADER_IPV6,
        // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + domain + PORT(2)
        SocksTarget::Domain { host, .. } => 5 + host.len() + 2,
    }
}

// ---------------------------------------------------------------------------
// Socks5UdpSocket — quinn::AsyncUdpSocket adapter
// ---------------------------------------------------------------------------

/// A UDP socket that transparently wraps every datagram with SOCKS5 UDP
/// framing, sending through a relay address obtained via UDP ASSOCIATE.
///
/// The embedded `_control_conn` keeps the SOCKS5 control TCP connection
/// alive; dropping it invalidates the relay.
#[cfg(feature = "quic-h3")]
pub struct Socks5UdpSocket {
    io: UdpSocket,
    relay_addr: SocketAddr,
    target: SocksTarget,
    /// The address quinn uses for connection tracking.
    /// For IP targets this equals the real address; for domain targets
    /// it is a synthetic placeholder (see `SocksTarget::quinn_addr`).
    quinn_addr: SocketAddr,
    _control_conn: TcpStream,
}

#[cfg(feature = "quic-h3")]
impl fmt::Debug for Socks5UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5UdpSocket")
            .field("relay", &self.relay_addr)
            .field("target", &self.target)
            .finish()
    }
}

#[cfg(feature = "quic-h3")]
impl Socks5UdpSocket {
    /// Create a new adapter.
    ///
    /// * `io` — local UDP socket (already bound)
    /// * `relay_addr` — the BND address returned by SOCKS5 UDP ASSOCIATE
    /// * `target` — the QUIC peer: IP address (socks5) or domain (socks5h)
    /// * `control_conn` — the TCP control connection (kept alive for the relay lifetime)
    pub fn new(
        io: UdpSocket,
        relay_addr: SocketAddr,
        target: SocksTarget,
        control_conn: TcpStream,
    ) -> Self {
        let quinn_addr = target.quinn_addr();
        Self {
            io,
            relay_addr,
            target,
            quinn_addr,
            _control_conn: control_conn,
        }
    }

    /// The `SocketAddr` that quinn should use for `connect_with()`.
    pub fn quinn_addr(&self) -> SocketAddr {
        self.quinn_addr
    }
}

#[cfg(feature = "quic-h3")]
impl quinn::AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        let socket = self.clone();
        Box::pin(Socks5UdpPoller { fut: None, socket })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        let hdr_len = socks5_udp_target_header_len(&self.target);
        let total = hdr_len + transmit.contents.len();

        let mut stack_buf = [0u8; 2048];
        let buf = if total <= stack_buf.len() {
            &mut stack_buf[..total]
        } else {
            let mut heap = vec![0u8; total];
            encode_socks5_udp_target(&self.target, transmit.contents, &mut heap)?;
            return self.io.try_send_to(&heap, self.relay_addr).map(|_| ());
        };

        encode_socks5_udp_target(&self.target, transmit.contents, buf)?;
        self.io
            .try_send_to(&buf[..total], self.relay_addr)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        debug_assert!(!meta.is_empty());

        loop {
            ready!(self.io.poll_recv_ready(cx))?;

            let buf = &mut *bufs[0];
            match self.io.try_recv_from(buf) {
                Ok((n, from)) => {
                    // RFC 1928 §6: the SOCKS proxy is the only legitimate
                    // source of UDP responses for this association. Accepting
                    // packets from any other address would let any host on the
                    // local network inject forged QUIC datagrams — the AEAD
                    // layer rejects them eventually but the side effects of
                    // processing them (state transitions, CONNECTION_CLOSE on
                    // stateless reset, version negotiation probes) are still
                    // reachable.
                    if !packet_source_matches_relay(from, self.relay_addr) {
                        tracing::debug!(
                            from = %from,
                            relay = %self.relay_addr,
                            "socks5_udp.foreign_source_dropped"
                        );
                        continue;
                    }

                    let data = &buf[..n];
                    let (_src_addr, payload) = match decode_socks5_udp(data) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::trace!(error = %e, "socks5_udp.decode_skip");
                            continue;
                        }
                    };

                    let payload_len = payload.len();
                    let header_len = n - payload_len;

                    if header_len > 0 {
                        buf.copy_within(header_len..n, 0);
                    }

                    meta[0] = udp::RecvMeta {
                        addr: self.quinn_addr,
                        len: payload_len,
                        stride: payload_len,
                        ecn: None,
                        dst_ip: None,
                    };

                    return Poll::Ready(Ok(1));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1 // no GSO through SOCKS5
    }

    fn max_receive_segments(&self) -> usize {
        1 // no GRO through SOCKS5
    }

    fn may_fragment(&self) -> bool {
        true // SOCKS5 header overhead makes fragmentation more likely
    }
}

// UdpPoller that delegates to the underlying tokio socket's writability
#[cfg(feature = "quic-h3")]
struct Socks5UdpPoller {
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
    socket: Arc<Socks5UdpSocket>,
}

#[cfg(feature = "quic-h3")]
impl fmt::Debug for Socks5UdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5UdpPoller").finish_non_exhaustive()
    }
}

// SAFETY: The inner future is Send + Sync and Socks5UdpSocket is Send + Sync.
#[cfg(feature = "quic-h3")]
unsafe impl Send for Socks5UdpPoller {}
#[cfg(feature = "quic-h3")]
unsafe impl Sync for Socks5UdpPoller {}

#[cfg(feature = "quic-h3")]
impl quinn::UdpPoller for Socks5UdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        if this.fut.is_none() {
            let socket = this.socket.clone();
            this.fut = Some(Box::pin(async move { socket.io.writable().await }));
        }

        let result = Future::poll(Pin::new(this.fut.as_mut().unwrap()), cx);
        if result.is_ready() {
            this.fut = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn encode_decode_ipv4() {
        let target = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let payload = b"hello QUIC";
        let mut buf = [0u8; 128];
        let n = encode_socks5_udp(target, payload, &mut buf).unwrap();

        assert_eq!(n, SOCKS5_UDP_HEADER_IPV4 + payload.len());
        assert_eq!(buf[0], 0x00); // RSV
        assert_eq!(buf[1], 0x00); // RSV
        assert_eq!(buf[2], 0x00); // FRAG
        assert_eq!(buf[3], 0x01); // ATYP IPv4

        let (decoded_addr, decoded_payload) = decode_socks5_udp(&buf[..n]).unwrap();
        assert_eq!(decoded_addr, target);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn encode_decode_ipv6() {
        let target = SocketAddr::from((Ipv6Addr::LOCALHOST, 8443));
        let payload = b"quic over socks5";
        let mut buf = [0u8; 128];
        let n = encode_socks5_udp(target, payload, &mut buf).unwrap();

        assert_eq!(n, SOCKS5_UDP_HEADER_IPV6 + payload.len());
        assert_eq!(buf[3], 0x04); // ATYP IPv6

        let (decoded_addr, decoded_payload) = decode_socks5_udp(&buf[..n]).unwrap();
        assert_eq!(decoded_addr, target);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn decode_too_short() {
        assert!(decode_socks5_udp(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn decode_fragmented_rejected() {
        let buf = [0x00, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0];
        assert!(decode_socks5_udp(&buf).is_err());
    }

    #[test]
    fn encode_buffer_too_small() {
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 80));
        let mut buf = [0u8; 5]; // too small
        assert!(encode_socks5_udp(target, b"data", &mut buf).is_err());
    }

    #[test]
    fn encode_decode_domain() {
        let target = SocksTarget::Domain {
            host: "example.com".into(),
            port: 443,
        };
        let payload = b"quic over socks5h";
        let mut buf = [0u8; 256];
        let n = encode_socks5_udp_target(&target, payload, &mut buf).unwrap();

        // header: RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + "example.com"(11) + PORT(2) = 18
        let expected_hdr = 2 + 1 + 1 + 1 + 11 + 2;
        assert_eq!(n, expected_hdr + payload.len());
        assert_eq!(buf[3], 0x03); // ATYP: domain
        assert_eq!(buf[4], 11); // domain length

        let (decoded_addr, decoded_payload) = decode_socks5_udp(&buf[..n]).unwrap();
        assert_eq!(decoded_addr.port(), 443);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn socks_target_quinn_addr_domain_is_placeholder() {
        let t = SocksTarget::Domain {
            host: "example.com".into(),
            port: 443,
        };
        let addr = t.quinn_addr();
        assert_eq!(addr, SocketAddr::from(([127, 0, 0, 2], 443)));
    }

    #[test]
    fn socks_target_quinn_addr_ip_is_real() {
        let real = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443));
        let t = SocksTarget::Ip(real);
        assert_eq!(t.quinn_addr(), real);
    }

    #[test]
    fn decode_rejects_zero_length_domain() {
        // ATYP=0x03 with dlen=0 + port bytes — syntactically a valid frame
        // layout but semantically malformed per RFC 1928 §4.
        let buf = [0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0xbb];
        assert!(decode_socks5_udp(&buf).is_err());
    }

    #[test]
    fn source_match_requires_exact_when_relay_specified() {
        let relay = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1080));
        let same = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1080));
        let wrong_ip = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 1080));
        let wrong_port = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 9999));

        assert!(packet_source_matches_relay(same, relay));
        assert!(!packet_source_matches_relay(wrong_ip, relay));
        assert!(!packet_source_matches_relay(wrong_port, relay));
    }

    #[test]
    fn source_match_port_only_when_relay_unspecified() {
        let relay = SocketAddr::from(([0, 0, 0, 0], 1080));
        let any_ip_same_port = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1080));
        let any_ip_wrong_port = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 9999));

        assert!(packet_source_matches_relay(any_ip_same_port, relay));
        assert!(!packet_source_matches_relay(any_ip_wrong_port, relay));
    }
}
