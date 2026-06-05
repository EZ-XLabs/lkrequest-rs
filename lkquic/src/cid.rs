use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const MAX_CONNECTION_ID_LEN: usize = 20;
const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const SPLITMIX_MUL1: u64 = 0xBF58_476D_1CE4_E5B9;
const SPLITMIX_MUL2: u64 = 0x94D0_49BB_1331_11EB;

static GENERATOR_SEED: AtomicU64 = AtomicU64::new(0xC4B9_5A27_6D83_19EF);

/// QUIC connection ID bytes with RFC-compatible length checks.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(Box<[u8]>);

impl ConnectionId {
    pub const MAX_LEN: usize = MAX_CONNECTION_ID_LEN;

    pub fn new(bytes: &[u8]) -> Result<Self, ConnectionIdError> {
        validate_connection_id_len(bytes.len())?;
        Ok(Self(bytes.into()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId(")?;
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Errors surfaced while building local QUIC identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionIdError {
    Empty,
    TooLong { len: usize, max: usize },
}

impl fmt::Display for ConnectionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "connection ID must not be empty"),
            Self::TooLong { len, max } => {
                write!(f, "connection ID length {len} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for ConnectionIdError {}

pub trait ConnectionIdGenerator {
    fn generate_len(&self) -> usize;

    fn generate(&mut self) -> ConnectionId;

    fn cid_len(&self) -> usize {
        self.generate_len()
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Chrome currently uses 8-byte connection IDs for client-initiated QUIC.
///
/// The generator uses a small SplitMix64 state so tests and local stub
/// connections do not need an external RNG dependency.
#[derive(Debug, Clone)]
pub struct ChromeConnectionIdGenerator {
    len: usize,
    state: u64,
}

impl ChromeConnectionIdGenerator {
    pub const DEFAULT_LEN: usize = 8;

    pub fn new(len: usize) -> Result<Self, ConnectionIdError> {
        validate_connection_id_len(len)?;

        let seed = GENERATOR_SEED.fetch_add(SPLITMIX_GAMMA ^ (len as u64), Ordering::Relaxed);
        Ok(Self { len, state: seed })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_GAMMA);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(SPLITMIX_MUL1);
        value = (value ^ (value >> 27)).wrapping_mul(SPLITMIX_MUL2);
        value ^ (value >> 31)
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(std::mem::size_of::<u64>()) {
            let sample = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&sample[..len]);
        }
    }
}

impl Default for ChromeConnectionIdGenerator {
    fn default() -> Self {
        Self::new(Self::DEFAULT_LEN).expect("default CID length is valid")
    }
}

impl ConnectionIdGenerator for ChromeConnectionIdGenerator {
    fn generate_len(&self) -> usize {
        self.len
    }

    fn generate(&mut self) -> ConnectionId {
        let mut bytes = vec![0u8; self.len];
        self.fill_bytes(&mut bytes);
        ConnectionId::new(&bytes).expect("generator preserves validated CID length")
    }
}

fn validate_connection_id_len(len: usize) -> Result<(), ConnectionIdError> {
    if len > MAX_CONNECTION_ID_LEN {
        return Err(ConnectionIdError::TooLong {
            len,
            max: MAX_CONNECTION_ID_LEN,
        });
    }

    Ok(())
}
