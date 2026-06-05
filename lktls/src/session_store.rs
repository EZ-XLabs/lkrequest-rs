//! TLS Session Ticket Store for Session Resumption.
//!
//! Stores NewSessionTicket data (TLS 1.3 PSK / TLS 1.2 Session Ticket) per-host
//! so that subsequent connections can perform abbreviated handshakes instead of
//! full ones. This is a critical anti-detection feature — real browsers always
//! use session resumption on repeat connections.
//!
//! # Architecture
//!
//! ```text
//! SessionStore (trait)
//!   └── InMemorySessionStore (HashMap<String, VecDeque<SessionTicketData>>)
//!         └── per-host FIFO queue (max N tickets per host)
//! ```
//!
//! # Usage
//!
//! ```rust
//! use lktls::session_store::InMemorySessionStore;
//! use std::sync::Arc;
//!
//! let store = Arc::new(InMemorySessionStore::new());
//! // Pass `store` to the TLS connector (in lkrequest) for session resumption.
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hkdf::HkdfAlgorithm;

// ---------------------------------------------------------------------------
// Session ticket data
// ---------------------------------------------------------------------------

/// Data stored for a single TLS session ticket.
///
/// Supports both TLS 1.3 (PSK-based) and TLS 1.2 (session ticket) resumption.
#[derive(Clone, Debug)]
pub struct SessionTicketData {
    /// The opaque ticket bytes sent by the server.
    pub ticket: Vec<u8>,

    /// TLS 1.3: the resumption PSK derived from `resumption_master_secret`.
    /// TLS 1.2: not used (set to empty).
    pub resumption_psk: Vec<u8>,

    /// TLS version this ticket was issued under.
    pub tls_version: TicketTlsVersion,

    /// The cipher suite negotiated when this ticket was issued.
    /// For TLS 1.3 PSK: used to determine the hash algorithm for binder calculation.
    pub cipher_suite: u16,

    /// Ticket lifetime in seconds (server-specified).
    pub lifetime_secs: u32,

    /// TLS 1.3: `ticket_age_add` — a random value the server uses to obscure
    /// the real ticket age. Added to the actual age when computing
    /// `obfuscated_ticket_age` in the `pre_shared_key` extension.
    pub age_add: u32,

    /// When this ticket was received (local monotonic clock).
    pub received_at: Instant,

    /// The ALPN protocol negotiated when this ticket was issued.
    pub alpn: Option<String>,

    /// The HKDF algorithm for this ticket's cipher suite.
    pub hkdf_algorithm: HkdfAlgorithm,

    /// The AEAD algorithm for this ticket's cipher suite.
    pub aead_algorithm: AeadAlgorithm,

    /// TLS 1.2: the master secret from the original handshake.
    /// TLS 1.3: not used (set to empty).
    pub master_secret: Vec<u8>,

    /// TLS 1.3: max_early_data_size from the ticket extensions (0 if not present).
    pub max_early_data_size: u32,

    /// Cached peer QUIC transport parameters associated with this ticket.
    pub peer_transport_parameters: Option<Vec<u8>>,
}

/// Which TLS version issued this ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketTlsVersion {
    Tls13,
    Tls12,
}

impl SessionTicketData {
    /// Check if this ticket has expired.
    pub fn is_expired(&self) -> bool {
        let age = self.received_at.elapsed();
        age > Duration::from_secs(self.lifetime_secs as u64)
    }

    /// Compute the obfuscated ticket age for TLS 1.3 `pre_shared_key` extension.
    ///
    /// `obfuscated_ticket_age = (age_in_ms + ticket_age_add) mod 2^32`
    pub fn obfuscated_ticket_age(&self) -> u32 {
        let age_ms = self.received_at.elapsed().as_millis() as u32;
        age_ms.wrapping_add(self.age_add)
    }
}

// ---------------------------------------------------------------------------
// SessionStore trait
// ---------------------------------------------------------------------------

/// Trait for storing and retrieving TLS session tickets.
///
/// Implementations must be `Send + Sync` for use across async tasks.
pub trait SessionStore: Send + Sync + std::fmt::Debug {
    /// Store a session ticket for the given host.
    ///
    /// `host` is typically `hostname:port` (e.g. `"example.com:443"`).
    fn store(&self, host: &str, ticket: SessionTicketData);

    /// Take a session ticket for the given host, removing it from the store.
    ///
    /// Returns `None` if no valid (non-expired) ticket is available.
    /// Expired tickets are silently discarded.
    fn take(&self, host: &str) -> Option<SessionTicketData>;
}

// ---------------------------------------------------------------------------
// InMemorySessionStore
// ---------------------------------------------------------------------------

/// In-memory session ticket store using a concurrent hash map.
///
/// Each host has a FIFO queue of tickets. The most recently stored ticket
/// is returned first (LIFO within the queue — Chrome behavior).
///
/// Thread-safe and suitable for concurrent use across multiple tasks.
#[derive(Debug)]
pub struct InMemorySessionStore {
    /// Per-host ticket queues.
    store: std::sync::Mutex<std::collections::HashMap<String, VecDeque<SessionTicketData>>>,
    /// Maximum tickets stored per host (default: 2, matching Chrome).
    max_tickets_per_host: usize,
}

impl InMemorySessionStore {
    /// Create a new in-memory session store with default settings.
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_tickets_per_host: 2,
        }
    }

    /// Create a new store with a custom per-host ticket limit.
    pub fn with_max_tickets(max_tickets_per_host: usize) -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_tickets_per_host,
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn store(&self, host: &str, ticket: SessionTicketData) {
        let mut map = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let queue = map.entry(host.to_string()).or_default();

        // Evict oldest tickets if at capacity
        while queue.len() >= self.max_tickets_per_host {
            queue.pop_front();
        }

        queue.push_back(ticket);

        tracing::debug!(
            host = host,
            queue_len = queue.len(),
            "session_store.ticket_stored",
        );
    }

    fn take(&self, host: &str) -> Option<SessionTicketData> {
        let mut map = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let queue = map.get_mut(host)?;

        // Pop from back (most recent ticket first) and skip expired ones
        while let Some(ticket) = queue.pop_back() {
            if !ticket.is_expired() {
                tracing::debug!(
                    host = host,
                    remaining = queue.len(),
                    "session_store.ticket_taken",
                );
                return Some(ticket);
            }
            tracing::debug!(host = host, "session_store.ticket_expired_discarded",);
        }

        // All tickets expired; remove the empty queue
        map.remove(host);
        None
    }
}

/// A shared session store reference (Arc-wrapped for multi-task use).
pub type SharedSessionStore = Arc<dyn SessionStore>;

// ---------------------------------------------------------------------------
// Session ticket parsing (Sans-I/O)
// ---------------------------------------------------------------------------

/// Parse a TLS 1.3 NewSessionTicket message into a [`SessionTicketData`].
///
/// `payload` is the raw handshake message (type byte + length + body).
/// The caller provides the cryptographic context from the completed handshake.
pub fn parse_tls13_new_session_ticket(
    payload: &[u8],
    resumption_master_secret: &[u8],
    hkdf_algorithm: HkdfAlgorithm,
    aead_algorithm: AeadAlgorithm,
    cipher_suite: u16,
    alpn: Option<String>,
) -> std::result::Result<SessionTicketData, String> {
    use crate::crypto::hkdf::hkdf_expand_label;

    let data = if payload.len() > 4 && payload[0] == 0x04 {
        &payload[4..]
    } else {
        payload
    };

    if data.len() < 12 {
        return Err("NewSessionTicket too short".into());
    }

    let mut pos = 0;

    let lifetime = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    let age_add = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    if pos >= data.len() {
        return Err("NewSessionTicket truncated at nonce length".into());
    }
    let nonce_len = data[pos] as usize;
    pos += 1;
    if pos + nonce_len > data.len() {
        return Err("NewSessionTicket truncated at nonce data".into());
    }
    let ticket_nonce = &data[pos..pos + nonce_len];
    pos += nonce_len;

    if pos + 2 > data.len() {
        return Err("NewSessionTicket truncated at ticket length".into());
    }
    let ticket_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + ticket_len > data.len() {
        return Err("NewSessionTicket truncated at ticket data".into());
    }
    let ticket = data[pos..pos + ticket_len].to_vec();
    pos += ticket_len;

    let mut max_early_data_size = 0u32;
    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                break;
            }
            if ext_type == 0x002a && ext_len >= 4 {
                max_early_data_size =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            }
            pos += ext_len;
        }
    }

    let hash_len = hkdf_algorithm.hash_len();
    let resumption_psk = hkdf_expand_label(
        hkdf_algorithm,
        resumption_master_secret,
        "resumption",
        ticket_nonce,
        hash_len,
    )
    .map_err(|e| format!("failed to derive resumption PSK: {e}"))?;

    Ok(SessionTicketData {
        ticket,
        resumption_psk,
        tls_version: TicketTlsVersion::Tls13,
        cipher_suite,
        lifetime_secs: lifetime,
        age_add,
        received_at: Instant::now(),
        alpn,
        hkdf_algorithm,
        aead_algorithm,
        master_secret: Vec::new(),
        max_early_data_size,
        peer_transport_parameters: None,
    })
}

/// Parse a TLS 1.2 NewSessionTicket message into a [`SessionTicketData`].
///
/// `payload` is the raw handshake message (type byte + length + body).
pub fn parse_tls12_new_session_ticket(
    payload: &[u8],
    master_secret: &[u8],
    alpn: Option<String>,
    negotiated_suite: Option<crate::crypto::tls12_cipher::Tls12CipherSuite>,
) -> std::result::Result<SessionTicketData, String> {
    let data = if payload.len() > 4 && payload[0] == 0x04 {
        &payload[4..]
    } else {
        payload
    };

    if data.len() < 6 {
        return Err("TLS 1.2 NewSessionTicket too short".into());
    }

    let lifetime_hint = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let ticket_len = u16::from_be_bytes([data[4], data[5]]) as usize;

    if 6 + ticket_len > data.len() {
        return Err("TLS 1.2 NewSessionTicket truncated".into());
    }

    let ticket = data[6..6 + ticket_len].to_vec();

    let (cipher_suite_code, hkdf_alg, aead_alg) = match negotiated_suite {
        Some(suite) => {
            use crate::crypto::prf::PrfAlgorithm;
            let hkdf = match suite.prf_algorithm() {
                PrfAlgorithm::Sha256 => HkdfAlgorithm::Sha256,
                PrfAlgorithm::Sha384 => HkdfAlgorithm::Sha384,
            };
            let aead = if suite.is_aead() {
                match suite.enc_key_len() {
                    32 if matches!(
                        suite,
                        crate::crypto::tls12_cipher::Tls12CipherSuite::EcdheEcdsaChacha20Poly1305
                            | crate::crypto::tls12_cipher::Tls12CipherSuite::EcdheRsaChacha20Poly1305
                    ) => AeadAlgorithm::Chacha20Poly1305,
                    32 => AeadAlgorithm::Aes256Gcm,
                    _ => AeadAlgorithm::Aes128Gcm,
                }
            } else {
                AeadAlgorithm::Aes128Gcm
            };
            (suite.code_point(), hkdf, aead)
        }
        None => (0u16, HkdfAlgorithm::Sha256, AeadAlgorithm::Aes128Gcm),
    };

    Ok(SessionTicketData {
        ticket,
        resumption_psk: Vec::new(),
        tls_version: TicketTlsVersion::Tls12,
        cipher_suite: cipher_suite_code,
        lifetime_secs: lifetime_hint,
        age_add: 0,
        received_at: Instant::now(),
        alpn,
        hkdf_algorithm: hkdf_alg,
        aead_algorithm: aead_alg,
        master_secret: master_secret.to_vec(),
        max_early_data_size: 0,
        peer_transport_parameters: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ticket(lifetime_secs: u32) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x01, 0x02, 0x03],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs,
            age_add: 12345,
            received_at: Instant::now(),
            alpn: Some("h2".to_string()),
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
        }
    }

    #[test]
    fn test_store_and_take() {
        let store = InMemorySessionStore::new();
        let ticket = make_ticket(3600);

        store.store("example.com:443", ticket.clone());
        let taken = store.take("example.com:443");
        assert!(taken.is_some());

        // Should be empty now
        let taken2 = store.take("example.com:443");
        assert!(taken2.is_none());
    }

    #[test]
    fn test_max_tickets_per_host() {
        let store = InMemorySessionStore::with_max_tickets(2);
        let t1 = make_ticket(3600);
        let mut t2 = make_ticket(3600);
        t2.ticket = vec![0x04, 0x05, 0x06];
        let mut t3 = make_ticket(3600);
        t3.ticket = vec![0x07, 0x08, 0x09];

        store.store("example.com:443", t1);
        store.store("example.com:443", t2);
        store.store("example.com:443", t3.clone());

        // Only 2 tickets should remain (t2 and t3, t1 evicted)
        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.ticket, t3.ticket); // Most recent first
    }

    #[test]
    fn test_expired_tickets_discarded() {
        let store = InMemorySessionStore::new();
        let mut ticket = make_ticket(0); // 0-second lifetime = immediately expired
        ticket.received_at = Instant::now() - Duration::from_secs(1);

        store.store("example.com:443", ticket);
        let taken = store.take("example.com:443");
        assert!(taken.is_none());
    }

    #[test]
    fn test_obfuscated_ticket_age() {
        let ticket = SessionTicketData {
            ticket: vec![],
            resumption_psk: vec![],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0xFFFF_0000,
            received_at: Instant::now(),
            alpn: None,
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
        };
        // Age is ~0ms, so obfuscated_age ≈ age_add
        let age = ticket.obfuscated_ticket_age();
        // Should be close to age_add (within a few ms)
        assert!(age >= 0xFFFF_0000);
    }

    #[test]
    fn test_different_hosts_independent() {
        let store = InMemorySessionStore::new();
        store.store("a.com:443", make_ticket(3600));
        store.store("b.com:443", make_ticket(3600));

        assert!(store.take("a.com:443").is_some());
        assert!(store.take("b.com:443").is_some());
        assert!(store.take("a.com:443").is_none());
    }

    fn make_tls12_ticket(lifetime_secs: u32) -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x10, 0x20, 0x30],
            resumption_psk: Vec::new(),
            tls_version: TicketTlsVersion::Tls12,
            cipher_suite: 0xC02F,
            lifetime_secs,
            age_add: 0,
            received_at: Instant::now(),
            alpn: Some("http/1.1".to_string()),
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: vec![0xBB; 48],
            max_early_data_size: 0,
            peer_transport_parameters: None,
        }
    }

    #[test]
    fn test_tls12_ticket_version_preserved() {
        let store = InMemorySessionStore::new();
        let ticket = make_tls12_ticket(3600);
        store.store("example.com:443", ticket);

        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.tls_version, TicketTlsVersion::Tls12);
        assert!(!taken.master_secret.is_empty());
        assert!(taken.resumption_psk.is_empty());
    }

    #[test]
    fn test_tls13_ticket_version_preserved() {
        let store = InMemorySessionStore::new();
        let ticket = make_ticket(3600);
        store.store("example.com:443", ticket);

        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.tls_version, TicketTlsVersion::Tls13);
        assert!(!taken.resumption_psk.is_empty());
        assert!(taken.master_secret.is_empty());
    }

    #[test]
    fn test_ticket_alpn_stored_correctly() {
        let store = InMemorySessionStore::new();
        let mut ticket = make_ticket(3600);
        ticket.alpn = Some("h2".to_string());
        store.store("example.com:443", ticket);

        let taken = store.take("example.com:443").unwrap();
        assert_eq!(taken.alpn, Some("h2".to_string()));
    }
}
