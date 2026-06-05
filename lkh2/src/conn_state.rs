//! HTTP/2 connection state management.
//!
//! Manages streams, HPACK contexts, flow control, and settings negotiation.
//! Sans-I/O: no async, no network — pure state machine.

use crate::frame::{SettingsFrame, SettingsParameter};
use crate::hpack::{HeaderDecoder, HeaderEncoder, HpackError};
use crate::policy::HpackEncodePolicy;
use crate::profile::H2Setting;
use crate::stream::{H2Stream, StreamError};
use bytes::Bytes;
use std::collections::HashMap;
use tracing::debug;

const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;
const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;

// ─── Settings ────────────────────────────────────────────────────────────────

/// HTTP/2 connection settings (RFC 7540 Section 6.5).
#[derive(Debug, Clone)]
pub struct H2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
}

impl Default for H2Settings {
    fn default() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: 16384,
            max_header_list_size: None,
        }
    }
}

impl H2Settings {
    pub fn client() -> Self {
        Self {
            enable_push: false,
            ..Default::default()
        }
    }

    pub fn apply(&mut self, param: &SettingsParameter) -> Result<(), SettingsError> {
        use crate::frame::SettingsId;
        match SettingsId::from_u16(param.id) {
            Some(SettingsId::HeaderTableSize) => {
                self.header_table_size = param.value;
            }
            Some(SettingsId::EnablePush) => {
                if param.value > 1 {
                    return Err(SettingsError {
                        id: param.id,
                        value: param.value,
                        reason: "ENABLE_PUSH must be 0 or 1".into(),
                    });
                }
                self.enable_push = param.value == 1;
            }
            Some(SettingsId::MaxConcurrentStreams) => {
                self.max_concurrent_streams = Some(param.value);
            }
            Some(SettingsId::InitialWindowSize) => {
                if param.value > 0x7FFF_FFFF {
                    return Err(SettingsError {
                        id: param.id,
                        value: param.value,
                        reason: "INITIAL_WINDOW_SIZE must not exceed 2^31-1".into(),
                    });
                }
                self.initial_window_size = param.value;
            }
            Some(SettingsId::MaxFrameSize) => {
                if !(16384..=16_777_215).contains(&param.value) {
                    return Err(SettingsError {
                        id: param.id,
                        value: param.value,
                        reason: "MAX_FRAME_SIZE must be between 16384 and 16777215".into(),
                    });
                }
                self.max_frame_size = param.value;
            }
            Some(SettingsId::MaxHeaderListSize) => {
                self.max_header_list_size = Some(param.value);
            }
            _ => { /* unknown settings are ignored per RFC 7540 §6.5.2 */ }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SettingsError {
    pub id: u16,
    pub value: u32,
    pub reason: String,
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid setting 0x{:04x}={}: {}",
            self.id, self.value, self.reason
        )
    }
}

impl std::error::Error for SettingsError {}

// ─── Error Codes ─────────────────────────────────────────────────────────────

/// HTTP/2 error codes (RFC 7540 Section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum H2ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

impl H2ErrorCode {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => Self::InternalError,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl std::fmt::Display for H2ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NoError => "NO_ERROR",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::InternalError => "INTERNAL_ERROR",
            Self::FlowControlError => "FLOW_CONTROL_ERROR",
            Self::SettingsTimeout => "SETTINGS_TIMEOUT",
            Self::StreamClosed => "STREAM_CLOSED",
            Self::FrameSizeError => "FRAME_SIZE_ERROR",
            Self::RefusedStream => "REFUSED_STREAM",
            Self::Cancel => "CANCEL",
            Self::CompressionError => "COMPRESSION_ERROR",
            Self::ConnectError => "CONNECT_ERROR",
            Self::EnhanceYourCalm => "ENHANCE_YOUR_CALM",
            Self::InadequateSecurity => "INADEQUATE_SECURITY",
            Self::Http11Required => "HTTP_1_1_REQUIRED",
        };
        write!(f, "{s}")
    }
}

// ─── Connection State ────────────────────────────────────────────────────────

/// HTTP/2 connection state (Sans-I/O).
#[derive(Debug)]
pub struct ConnState {
    is_client: bool,
    local_settings: H2Settings,
    remote_settings: H2Settings,
    streams: HashMap<u32, H2Stream>,
    next_stream_id: u32,
    hpack_decoder: HeaderDecoder,
    hpack_encoder: HeaderEncoder,
    send_window: i32,
    recv_window: i32,
    preface_received: bool,
    settings_acked: bool,
    pending_settings: Vec<H2Settings>,
    error: Option<H2ErrorCode>,
    goaway_received: bool,
    goaway_last_stream_id: Option<u32>,
}

impl ConnState {
    pub fn client() -> Self {
        Self::new(true)
    }

    pub fn server() -> Self {
        Self::new(false)
    }

    fn new(is_client: bool) -> Self {
        let local_settings = if is_client {
            H2Settings::client()
        } else {
            H2Settings::default()
        };

        Self {
            is_client,
            local_settings: local_settings.clone(),
            remote_settings: H2Settings::default(),
            streams: HashMap::new(),
            next_stream_id: if is_client { 1 } else { 2 },
            hpack_decoder: HeaderDecoder::new(local_settings.header_table_size as usize),
            hpack_encoder: HeaderEncoder::new(local_settings.header_table_size as usize),
            send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            recv_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            preface_received: false,
            settings_acked: false,
            pending_settings: Vec::new(),
            error: None,
            goaway_received: false,
            goaway_last_stream_id: None,
        }
    }

    pub fn is_client(&self) -> bool {
        self.is_client
    }

    pub fn local_settings(&self) -> &H2Settings {
        &self.local_settings
    }

    pub fn remote_settings(&self) -> &H2Settings {
        &self.remote_settings
    }

    pub fn send_window(&self) -> i32 {
        self.send_window
    }

    pub fn send_window_available(&self) -> u32 {
        self.send_window.max(0) as u32
    }

    pub fn recv_window(&self) -> i32 {
        self.recv_window
    }

    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn error(&self) -> Option<H2ErrorCode> {
        self.error
    }

    pub fn mark_preface_received(&mut self) {
        self.preface_received = true;
    }

    pub fn preface_received(&self) -> bool {
        self.preface_received
    }

    pub fn get_or_create_stream(&mut self, stream_id: u32) -> &mut H2Stream {
        let send_window = self.remote_settings.initial_window_size;
        let recv_window = self.effective_local_initial_window_size();
        self.streams
            .entry(stream_id)
            .or_insert_with(|| H2Stream::new_with_windows(stream_id, send_window, recv_window))
    }

    pub fn get_stream(&self, stream_id: u32) -> Option<&H2Stream> {
        self.streams.get(&stream_id)
    }

    pub fn get_stream_mut(&mut self, stream_id: u32) -> Option<&mut H2Stream> {
        self.streams.get_mut(&stream_id)
    }

    fn effective_local_initial_window_size(&self) -> u32 {
        self.pending_settings
            .last()
            .map(|s| s.initial_window_size)
            .unwrap_or(self.local_settings.initial_window_size)
    }

    pub fn can_open_stream(&self) -> bool {
        match self.remote_settings.max_concurrent_streams {
            Some(max) => self.active_stream_count() < max as usize,
            None => true,
        }
    }

    pub fn open_stream(&mut self) -> u32 {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        let send_window = self.remote_settings.initial_window_size;
        let recv_window = self.effective_local_initial_window_size();
        let mut stream = H2Stream::new_with_windows(stream_id, send_window, recv_window);
        let _ = stream.open();
        self.streams.insert(stream_id, stream);

        debug!(stream_id, is_client = self.is_client, "opened new stream");
        stream_id
    }

    pub fn active_stream_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| s.state().is_active())
            .count()
    }

    /// Apply local settings from an H2 profile.
    ///
    /// This updates `local_settings` to reflect what we advertise in our
    /// SETTINGS frame, and pushes the new settings into `pending_settings`
    /// so they become active once the remote ACKs them.  The HPACK decoder
    /// is **not** resized here — that happens in the ACK path.
    pub fn apply_profile_settings(&mut self, settings: &[H2Setting]) {
        let mut pending = self.local_settings.clone();
        for s in settings {
            let param = SettingsParameter {
                id: s.id.as_u16(),
                value: s.value,
            };
            // Validation errors are impossible for well-formed profiles,
            // but apply() already ignores unknown IDs.
            let _ = pending.apply(&param);
        }
        self.pending_settings.push(pending);
    }

    pub fn apply_remote_settings(
        &mut self,
        settings: &SettingsFrame,
    ) -> Result<(), ConnectionError> {
        if settings.ack {
            if !self.pending_settings.is_empty() {
                let pending = self.pending_settings.remove(0);
                // P1: sync decoder table size when our SETTINGS is ACKed
                if pending.header_table_size != self.local_settings.header_table_size {
                    self.hpack_decoder
                        .set_max_table_size(pending.header_table_size as usize);
                }
                self.local_settings = pending;
                self.settings_acked = true;
            }
            return Ok(());
        }

        for param in &settings.settings {
            self.remote_settings
                .apply(param)
                .map_err(|e| ConnectionError::SettingsError(e.to_string()))?;
        }

        let new_window = self.remote_settings.initial_window_size;
        for stream in self.streams.values_mut() {
            stream
                .apply_initial_window_size(new_window)
                .map_err(|e| ConnectionError::FlowControlError(e.to_string()))?;
        }

        Ok(())
    }

    pub fn decode_header_block(
        &mut self,
        block: &[u8],
    ) -> Result<Vec<(String, String)>, ConnectionError> {
        let headers = self
            .hpack_decoder
            .decode(block)
            .map_err(ConnectionError::HpackError)?;

        // RFC 7540 §6.5.2: enforce max_header_list_size (default 256KB)
        let max_size = self
            .local_settings
            .max_header_list_size
            .unwrap_or(256 * 1024) as usize;
        let total: usize = headers.iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        if total > max_size {
            return Err(ConnectionError::HpackError(
                crate::hpack::HpackError::DecodingError(format!(
                    "header list size {total} exceeds limit {max_size}"
                )),
            ));
        }

        Ok(headers)
    }

    pub fn set_encoder_table_size(&mut self, size: usize) {
        self.hpack_encoder.set_max_table_size(size);
    }

    pub fn encode_headers<N: AsRef<str>, V: AsRef<str>>(&mut self, headers: &[(N, V)]) -> Bytes {
        Bytes::from(self.hpack_encoder.encode_owned(headers))
    }

    pub fn encode_headers_with_policy<N: AsRef<str>, V: AsRef<str>>(
        &mut self,
        headers: &[(N, V)],
        policy: &dyn HpackEncodePolicy,
    ) -> Bytes {
        Bytes::from(self.hpack_encoder.encode_with_policy(headers, policy))
    }

    pub fn consume_send_window(&mut self, amount: u32) -> u32 {
        let available = self.send_window.max(0) as u32;
        let consumed = amount.min(available);
        self.send_window -= consumed as i32;
        consumed
    }

    pub fn consume_recv_window(&mut self, amount: u32) -> Result<(), ConnectionError> {
        if self.recv_window < 0 || (self.recv_window as u32) < amount {
            return Err(ConnectionError::FlowControlError(format!(
                "connection receive window exhausted: window={}, requested={}",
                self.recv_window, amount
            )));
        }
        self.recv_window -= amount as i32;
        Ok(())
    }

    pub fn update_send_window(&mut self, increment: u32) -> Result<(), ConnectionError> {
        let new_window = self.send_window as i64 + increment as i64;
        if new_window > i32::MAX as i64 {
            return Err(ConnectionError::FlowControlError(
                "connection send window overflow".into(),
            ));
        }
        self.send_window = new_window as i32;
        Ok(())
    }

    pub fn update_recv_window(&mut self, increment: u32) -> Result<(), ConnectionError> {
        let new_window = self.recv_window as i64 + increment as i64;
        if new_window > i32::MAX as i64 {
            return Err(ConnectionError::FlowControlError(
                "connection receive window overflow".into(),
            ));
        }
        self.recv_window = new_window as i32;
        Ok(())
    }

    pub fn handle_goaway(&mut self, last_stream_id: u32, error_code: u32) {
        self.goaway_received = true;
        self.goaway_last_stream_id = Some(last_stream_id);
        if error_code != 0 {
            self.error = Some(H2ErrorCode::from_u32(error_code));
        }
        debug!(last_stream_id, error_code, error = ?self.error, "received GOAWAY");
    }

    pub fn cleanup_closed_streams(&mut self) {
        self.streams.retain(|_, stream| !stream.state().is_closed());
    }
}

// ─── Connection Error ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConnectionError {
    SettingsError(String),
    HpackError(HpackError),
    FlowControlError(String),
    StreamError(StreamError),
    ProtocolError(String),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SettingsError(msg) => write!(f, "settings error: {msg}"),
            Self::HpackError(e) => write!(f, "HPACK error: {e}"),
            Self::FlowControlError(msg) => write!(f, "flow control error: {msg}"),
            Self::StreamError(e) => write!(f, "stream error: {e}"),
            Self::ProtocolError(msg) => write!(f, "protocol error: {msg}"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<StreamError> for ConnectionError {
    fn from(e: StreamError) -> Self {
        Self::StreamError(e)
    }
}

impl From<HpackError> for ConnectionError {
    fn from(e: HpackError) -> Self {
        Self::HpackError(e)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_connection() {
        let conn = ConnState::client();
        assert!(conn.is_client());
        assert_eq!(conn.active_stream_count(), 0);
    }

    #[test]
    fn test_open_stream() {
        let mut conn = ConnState::client();
        let id1 = conn.open_stream();
        assert_eq!(id1, 1);
        let id2 = conn.open_stream();
        assert_eq!(id2, 3);
        assert_eq!(conn.active_stream_count(), 2);
    }

    #[test]
    fn test_connection_flow_control() {
        let mut conn = ConnState::client();
        let consumed = conn.consume_send_window(1000);
        assert_eq!(consumed, 1000);
        conn.update_send_window(500).unwrap();
        assert_eq!(
            conn.send_window(),
            DEFAULT_INITIAL_WINDOW_SIZE as i32 - 1000 + 500
        );
    }

    #[test]
    fn test_header_encoding() {
        let mut conn = ConnState::client();
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
        ];
        let encoded = conn.encode_headers(&headers);
        assert!(!encoded.is_empty());
        let decoded = conn.decode_header_block(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, ":method");
        assert_eq!(decoded[0].1, "GET");
    }

    #[test]
    fn test_error_code_roundtrip() {
        assert_eq!(H2ErrorCode::from_u32(0x0), H2ErrorCode::NoError);
        assert_eq!(H2ErrorCode::from_u32(0x8), H2ErrorCode::Cancel);
        assert_eq!(H2ErrorCode::NoError.as_u32(), 0x0);
    }
}
