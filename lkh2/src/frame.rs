//! HTTP/2 frame definitions (RFC 7540).
//!
//! All 10 frame types with header parsing/encoding. This module is pure data
//! structures — no I/O, no async, no external protocol dependencies.
//!
//! ## Wire format
//!
//! ```text
//! +-----------------------------------------------+
//! |                 Length (24)                   |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+-------------------------------+
//! |R|                 Stream Identifier (31)                      |
//! +=+=============================================================+
//! |                   Frame Payload (0...)                      ...
//! +---------------------------------------------------------------+
//! ```

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// HTTP/2 frame header size (9 bytes).
pub const FRAME_HEADER_SIZE: usize = 9;

// ─── Frame Type ──────────────────────────────────────────────────────────────

/// HTTP/2 frame types (RFC 7540 Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum H2FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl H2FrameType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Data),
            0x1 => Some(Self::Headers),
            0x2 => Some(Self::Priority),
            0x3 => Some(Self::RstStream),
            0x4 => Some(Self::Settings),
            0x5 => Some(Self::PushPromise),
            0x6 => Some(Self::Ping),
            0x7 => Some(Self::GoAway),
            0x8 => Some(Self::WindowUpdate),
            0x9 => Some(Self::Continuation),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for H2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data => write!(f, "DATA"),
            Self::Headers => write!(f, "HEADERS"),
            Self::Priority => write!(f, "PRIORITY"),
            Self::RstStream => write!(f, "RST_STREAM"),
            Self::Settings => write!(f, "SETTINGS"),
            Self::PushPromise => write!(f, "PUSH_PROMISE"),
            Self::Ping => write!(f, "PING"),
            Self::GoAway => write!(f, "GOAWAY"),
            Self::WindowUpdate => write!(f, "WINDOW_UPDATE"),
            Self::Continuation => write!(f, "CONTINUATION"),
        }
    }
}

// ─── Frame Flags ─────────────────────────────────────────────────────────────

/// HTTP/2 frame flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct H2FrameFlags(u8);

impl H2FrameFlags {
    pub const NONE: H2FrameFlags = H2FrameFlags(0);

    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
    pub const ACK: u8 = 0x1;

    pub fn new(value: u8) -> Self {
        H2FrameFlags(value)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn is_end_stream(self) -> bool {
        self.0 & Self::END_STREAM != 0
    }

    pub fn is_end_headers(self) -> bool {
        self.0 & Self::END_HEADERS != 0
    }

    pub fn is_padded(self) -> bool {
        self.0 & Self::PADDED != 0
    }

    pub fn is_priority(self) -> bool {
        self.0 & Self::PRIORITY != 0
    }

    pub fn is_ack(self) -> bool {
        self.0 & Self::ACK != 0
    }

    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

// ─── Frame Header ────────────────────────────────────────────────────────────

/// HTTP/2 frame header (9 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2FrameHeader {
    pub length: u32,
    pub frame_type: H2FrameType,
    pub flags: H2FrameFlags,
    pub stream_id: u32,
}

impl H2FrameHeader {
    pub fn new(frame_type: H2FrameType, flags: H2FrameFlags, stream_id: u32, length: u32) -> Self {
        Self {
            length,
            frame_type,
            flags,
            stream_id: stream_id & 0x7FFFFFFF,
        }
    }

    pub fn parse(data: &[u8; 9]) -> Option<Self> {
        let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = H2FrameType::from_u8(data[3])?;
        let flags = H2FrameFlags::new(data[4]);
        let stream_id = ((data[5] as u32) << 24)
            | ((data[6] as u32) << 16)
            | ((data[7] as u32) << 8)
            | (data[8] as u32);
        let stream_id = stream_id & 0x7FFFFFFF;

        Some(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    pub fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;
        buf[3] = self.frame_type.as_u8();
        buf[4] = self.flags.bits();
        buf[5] = (self.stream_id >> 24) as u8;
        buf[6] = (self.stream_id >> 16) as u8;
        buf[7] = (self.stream_id >> 8) as u8;
        buf[8] = self.stream_id as u8;
        buf
    }

    pub fn total_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.length as usize
    }
}

// ─── Frame Enum ──────────────────────────────────────────────────────────────

/// HTTP/2 frame with payload.
#[derive(Debug, Clone)]
pub enum H2Frame {
    Data(DataFrame),
    Headers(HeadersFrame),
    Priority(PriorityFrame),
    RstStream(RstStreamFrame),
    Settings(SettingsFrame),
    PushPromise(PushPromiseFrame),
    Ping(PingFrame),
    GoAway(GoAwayFrame),
    WindowUpdate(WindowUpdateFrame),
    Continuation(ContinuationFrame),
    Unknown(UnknownFrame),
}

impl H2Frame {
    pub fn stream_id(&self) -> u32 {
        match self {
            Self::Data(f) => f.stream_id,
            Self::Headers(f) => f.stream_id,
            Self::Priority(f) => f.stream_id,
            Self::RstStream(f) => f.stream_id,
            Self::Settings(_) => 0,
            Self::PushPromise(f) => f.stream_id,
            Self::Ping(_) => 0,
            Self::GoAway(_) => 0,
            Self::WindowUpdate(f) => f.stream_id,
            Self::Continuation(f) => f.stream_id,
            Self::Unknown(f) => f.stream_id,
        }
    }

    pub fn frame_type(&self) -> H2FrameType {
        match self {
            Self::Data(_) => H2FrameType::Data,
            Self::Headers(_) => H2FrameType::Headers,
            Self::Priority(_) => H2FrameType::Priority,
            Self::RstStream(_) => H2FrameType::RstStream,
            Self::Settings(_) => H2FrameType::Settings,
            Self::PushPromise(_) => H2FrameType::PushPromise,
            Self::Ping(_) => H2FrameType::Ping,
            Self::GoAway(_) => H2FrameType::GoAway,
            Self::WindowUpdate(_) => H2FrameType::WindowUpdate,
            Self::Continuation(_) => H2FrameType::Continuation,
            Self::Unknown(f) => H2FrameType::from_u8(f.frame_type).unwrap_or(H2FrameType::Data),
        }
    }

    pub fn is_end_stream(&self) -> bool {
        match self {
            Self::Data(f) => f.end_stream,
            Self::Headers(f) => f.end_stream,
            _ => false,
        }
    }
}

// ─── Frame Payloads ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataFrame {
    pub stream_id: u32,
    pub data: Bytes,
    pub end_stream: bool,
    pub padding: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct HeadersFrame {
    pub stream_id: u32,
    pub header_block: Bytes,
    pub end_stream: bool,
    pub end_headers: bool,
    /// Priority data embedded in HEADERS frame (PRIORITY flag 0x20).
    /// This is the RFC 7540 §6.2 mechanism — distinct from the HTTP
    /// `priority` request header (RFC 9218).
    pub priority: Option<PrioritySpec>,
    pub padding: Option<u8>,
}

/// Priority specification — the 5-byte wire format shared by HEADERS (with
/// PRIORITY flag) and standalone PRIORITY frames.
///
/// ```text
/// +-+-------------------------------------------------------------+
/// |E|                  Stream Dependency (31)                     |
/// +-+-------------+-----------------------------------------------+
/// |   Weight (8)  |
/// +-+-------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrioritySpec {
    pub exclusive: bool,
    pub stream_dependency: u32,
    /// Wire-level weight 0–255, representing priority 1–256.
    pub weight: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct PriorityFrame {
    pub stream_id: u32,
    pub priority: PrioritySpec,
}

#[derive(Debug, Clone, Copy)]
pub struct RstStreamFrame {
    pub stream_id: u32,
    pub error_code: u32,
}

#[derive(Debug, Clone)]
pub struct SettingsFrame {
    pub ack: bool,
    pub settings: Vec<SettingsParameter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsParameter {
    pub id: u16,
    pub value: u32,
}

/// Well-known SETTINGS parameter identifiers (RFC 7540 Section 6.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingsId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
    EnableConnectProtocol = 0x8,
    NoRfc7540Priorities = 0x9,
}

impl SettingsId {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x1 => Some(Self::HeaderTableSize),
            0x2 => Some(Self::EnablePush),
            0x3 => Some(Self::MaxConcurrentStreams),
            0x4 => Some(Self::InitialWindowSize),
            0x5 => Some(Self::MaxFrameSize),
            0x6 => Some(Self::MaxHeaderListSize),
            0x8 => Some(Self::EnableConnectProtocol),
            0x9 => Some(Self::NoRfc7540Priorities),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PushPromiseFrame {
    pub stream_id: u32,
    pub promised_stream_id: u32,
    pub header_block: Bytes,
    pub end_headers: bool,
    pub padding: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct PingFrame {
    pub ack: bool,
    pub data: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct GoAwayFrame {
    pub last_stream_id: u32,
    pub error_code: u32,
    pub debug_data: Bytes,
}

#[derive(Debug, Clone, Copy)]
pub struct WindowUpdateFrame {
    pub stream_id: u32,
    pub increment: u32,
}

#[derive(Debug, Clone)]
pub struct ContinuationFrame {
    pub stream_id: u32,
    pub header_block: Bytes,
    pub end_headers: bool,
}

#[derive(Debug, Clone)]
pub struct UnknownFrame {
    pub frame_type: u8,
    pub stream_id: u32,
    pub flags: u8,
    pub payload: Bytes,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_conversion() {
        assert_eq!(H2FrameType::from_u8(0x0), Some(H2FrameType::Data));
        assert_eq!(H2FrameType::from_u8(0x1), Some(H2FrameType::Headers));
        assert_eq!(H2FrameType::from_u8(0x9), Some(H2FrameType::Continuation));
        assert_eq!(H2FrameType::from_u8(0xff), None);
        assert_eq!(H2FrameType::Data.as_u8(), 0x0);
        assert_eq!(H2FrameType::Headers.as_u8(), 0x1);
    }

    #[test]
    fn test_frame_flags() {
        let mut flags = H2FrameFlags::NONE;
        assert!(!flags.is_end_stream());

        flags.set(H2FrameFlags::END_STREAM);
        assert!(flags.is_end_stream());

        flags.set(H2FrameFlags::END_HEADERS);
        assert!(flags.is_end_headers());

        flags.clear(H2FrameFlags::END_STREAM);
        assert!(!flags.is_end_stream());
        assert!(flags.is_end_headers());
    }

    #[test]
    fn test_frame_header_parse_encode() {
        let header = H2FrameHeader::new(
            H2FrameType::Headers,
            H2FrameFlags::new(H2FrameFlags::END_HEADERS),
            1,
            42,
        );
        let encoded = header.encode();
        let parsed = H2FrameHeader::parse(&encoded).unwrap();

        assert_eq!(parsed.length, 42);
        assert_eq!(parsed.frame_type, H2FrameType::Headers);
        assert!(parsed.flags.is_end_headers());
        assert_eq!(parsed.stream_id, 1);
    }

    #[test]
    fn test_frame_header_parse_data() {
        let data = [0x00, 0x12, 0x34, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05];
        let header = H2FrameHeader::parse(&data).unwrap();

        assert_eq!(header.length, 0x1234);
        assert_eq!(header.frame_type, H2FrameType::Data);
        assert!(header.flags.is_end_stream());
        assert_eq!(header.stream_id, 5);
    }

    #[test]
    fn test_frame_header_reserved_bit() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01];
        let header = H2FrameHeader::parse(&data).unwrap();
        assert_eq!(header.stream_id, 1);
    }

    #[test]
    fn test_settings_id_extended() {
        assert_eq!(
            SettingsId::from_u16(0x8),
            Some(SettingsId::EnableConnectProtocol)
        );
        assert_eq!(
            SettingsId::from_u16(0x9),
            Some(SettingsId::NoRfc7540Priorities)
        );
        assert_eq!(SettingsId::from_u16(0x7), None);
        assert_eq!(SettingsId::from_u16(0xa), None);
    }
}
