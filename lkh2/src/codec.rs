//! HTTP/2 frame codec — encode/decode frames from byte buffers.
//!
//! Sans-I/O: operates purely on `BytesMut` buffers, no async, no network.

use crate::frame::*;
use bytes::{Bytes, BytesMut};
use std::fmt;

// ─── Codec Error / Result ────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CodecError {
    InvalidFormat(String),
    TooLarge { size: usize, max: usize },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid frame: {msg}"),
            Self::TooLarge { size, max } => {
                write!(f, "frame too large: {size} bytes (max {max})")
            }
        }
    }
}

impl std::error::Error for CodecError {}

#[derive(Debug)]
pub enum DecodeResult {
    Frame(H2Frame),
    NeedMoreData { min_bytes: usize },
    Error(CodecError),
}

// ─── Constants ───────────────────────────────────────────────────────────────

pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;
pub const MAX_FRAME_SIZE_LIMIT: u32 = 16_777_215;

// ─── Codec ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct H2Codec {
    max_frame_size: u32,
}

impl H2Codec {
    pub fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    pub fn set_max_frame_size(&mut self, size: u32) {
        self.max_frame_size = size.clamp(DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT);
    }

    pub fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    // ── Decode ───────────────────────────────────────────────────────────

    pub fn decode(&mut self, buf: &mut BytesMut) -> DecodeResult {
        if buf.len() < FRAME_HEADER_SIZE {
            return DecodeResult::NeedMoreData {
                min_bytes: FRAME_HEADER_SIZE - buf.len(),
            };
        }

        let header_bytes: [u8; 9] = buf[..9].try_into().unwrap();

        // Extract raw fields before full header parse for unknown-type handling.
        let raw_length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let raw_type = buf[3];
        let raw_flags = buf[4];
        let raw_stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7FFF_FFFF;

        let header = match H2FrameHeader::parse(&header_bytes) {
            Some(h) => h,
            None => {
                // RFC 7540 §4.1: unknown frame types MUST be ignored and discarded.
                let total_skip = FRAME_HEADER_SIZE + raw_length as usize;
                if buf.len() < total_skip {
                    return DecodeResult::NeedMoreData {
                        min_bytes: total_skip - buf.len(),
                    };
                }
                let _ = buf.split_to(total_skip);
                tracing::trace!(
                    frame_type = raw_type,
                    length = raw_length,
                    "h2.ignored_unknown_frame"
                );
                return DecodeResult::Frame(H2Frame::Unknown(UnknownFrame {
                    frame_type: raw_type,
                    stream_id: raw_stream_id,
                    flags: raw_flags,
                    payload: Bytes::new(),
                }));
            }
        };

        if header.length > self.max_frame_size {
            return DecodeResult::Error(CodecError::TooLarge {
                size: header.length as usize,
                max: self.max_frame_size as usize,
            });
        }

        let total_size = header.total_size();
        if buf.len() < total_size {
            return DecodeResult::NeedMoreData {
                min_bytes: total_size - buf.len(),
            };
        }

        let _ = buf.split_to(FRAME_HEADER_SIZE);
        let payload = buf.split_to(header.length as usize).freeze();

        let frame = match header.frame_type {
            H2FrameType::Data => Self::decode_data(&header, payload),
            H2FrameType::Headers => Self::decode_headers(&header, payload),
            H2FrameType::Priority => Self::decode_priority(&header, payload),
            H2FrameType::RstStream => Self::decode_rst_stream(&header, payload),
            H2FrameType::Settings => Self::decode_settings(&header, payload),
            H2FrameType::PushPromise => Self::decode_push_promise(&header, payload),
            H2FrameType::Ping => Self::decode_ping(&header, payload),
            H2FrameType::GoAway => Self::decode_goaway(&header, payload),
            H2FrameType::WindowUpdate => Self::decode_window_update(&header, payload),
            H2FrameType::Continuation => Self::decode_continuation(&header, payload),
        };

        match frame {
            Ok(f) => DecodeResult::Frame(f),
            Err(e) => DecodeResult::Error(e),
        }
    }

    fn decode_data(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id == 0 {
            return Err(CodecError::InvalidFormat(
                "DATA frame with stream ID 0".into(),
            ));
        }
        let (data, padding) = if header.flags.is_padded() {
            if payload.is_empty() {
                return Err(CodecError::InvalidFormat("missing pad length".into()));
            }
            let pad_len = payload[0] as usize;
            if pad_len >= payload.len() {
                return Err(CodecError::InvalidFormat("padding too large".into()));
            }
            (payload.slice(1..payload.len() - pad_len), Some(payload[0]))
        } else {
            (payload, None)
        };

        Ok(H2Frame::Data(DataFrame {
            stream_id: header.stream_id,
            data,
            end_stream: header.flags.is_end_stream(),
            padding,
        }))
    }

    fn decode_headers(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id == 0 {
            return Err(CodecError::InvalidFormat(
                "HEADERS frame with stream ID 0".into(),
            ));
        }

        let mut offset = 0;
        let mut padding: Option<u8> = None;

        if header.flags.is_padded() {
            if payload.is_empty() {
                return Err(CodecError::InvalidFormat("missing pad length".into()));
            }
            padding = Some(payload[0]);
            offset = 1;
        }

        let priority = if header.flags.is_priority() {
            if payload.len() < offset + 5 {
                return Err(CodecError::InvalidFormat(
                    "HEADERS: missing priority data".into(),
                ));
            }
            let dep = u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]);
            let exclusive = (dep & 0x8000_0000) != 0;
            let stream_dependency = dep & 0x7FFF_FFFF;
            let weight = payload[offset + 4];
            offset += 5;
            Some(PrioritySpec {
                exclusive,
                stream_dependency,
                weight,
            })
        } else {
            None
        };

        let pad_len = padding.unwrap_or(0) as usize;
        if offset + pad_len > payload.len() {
            return Err(CodecError::InvalidFormat("invalid padding".into()));
        }
        let header_block = payload.slice(offset..payload.len() - pad_len);

        Ok(H2Frame::Headers(HeadersFrame {
            stream_id: header.stream_id,
            header_block,
            end_stream: header.flags.is_end_stream(),
            end_headers: header.flags.is_end_headers(),
            priority,
            padding,
        }))
    }

    fn decode_priority(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id == 0 {
            return Err(CodecError::InvalidFormat(
                "PRIORITY frame with stream ID 0".into(),
            ));
        }
        if payload.len() != 5 {
            return Err(CodecError::InvalidFormat(format!(
                "PRIORITY frame must be 5 bytes, got {}",
                payload.len()
            )));
        }
        let dep = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let exclusive = (dep & 0x8000_0000) != 0;
        let stream_dependency = dep & 0x7FFF_FFFF;

        Ok(H2Frame::Priority(PriorityFrame {
            stream_id: header.stream_id,
            priority: PrioritySpec {
                exclusive,
                stream_dependency,
                weight: payload[4],
            },
        }))
    }

    fn decode_rst_stream(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id == 0 {
            return Err(CodecError::InvalidFormat(
                "RST_STREAM frame with stream ID 0".into(),
            ));
        }
        if payload.len() != 4 {
            return Err(CodecError::InvalidFormat(format!(
                "RST_STREAM must be 4 bytes, got {}",
                payload.len()
            )));
        }
        let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        Ok(H2Frame::RstStream(RstStreamFrame {
            stream_id: header.stream_id,
            error_code,
        }))
    }

    fn decode_settings(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id != 0 {
            return Err(CodecError::InvalidFormat(
                "SETTINGS frame must have stream ID 0".into(),
            ));
        }
        let ack = header.flags.is_ack();
        if ack && !payload.is_empty() {
            return Err(CodecError::InvalidFormat(
                "SETTINGS ACK must have empty payload".into(),
            ));
        }
        if !payload.len().is_multiple_of(6) {
            return Err(CodecError::InvalidFormat(
                "SETTINGS payload must be multiple of 6 bytes".into(),
            ));
        }

        let mut settings = Vec::with_capacity(payload.len() / 6);
        let mut offset = 0;
        while offset < payload.len() {
            let id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let value = u32::from_be_bytes([
                payload[offset + 2],
                payload[offset + 3],
                payload[offset + 4],
                payload[offset + 5],
            ]);
            settings.push(SettingsParameter { id, value });
            offset += 6;
        }
        Ok(H2Frame::Settings(SettingsFrame { ack, settings }))
    }

    fn decode_push_promise(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id == 0 {
            return Err(CodecError::InvalidFormat(
                "PUSH_PROMISE frame with stream ID 0".into(),
            ));
        }

        let mut offset = 0;
        let mut padding: Option<u8> = None;

        if header.flags.is_padded() {
            if payload.is_empty() {
                return Err(CodecError::InvalidFormat("missing pad length".into()));
            }
            padding = Some(payload[0]);
            offset = 1;
        }

        if payload.len() < offset + 4 {
            return Err(CodecError::InvalidFormat(
                "PUSH_PROMISE: missing promised stream ID".into(),
            ));
        }

        let promised_stream_id = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) & 0x7FFF_FFFF;
        offset += 4;

        let pad_len = padding.unwrap_or(0) as usize;
        if offset + pad_len > payload.len() {
            return Err(CodecError::InvalidFormat("invalid padding".into()));
        }
        let header_block = payload.slice(offset..payload.len() - pad_len);

        Ok(H2Frame::PushPromise(PushPromiseFrame {
            stream_id: header.stream_id,
            promised_stream_id,
            header_block,
            end_headers: header.flags.is_end_headers(),
            padding,
        }))
    }

    fn decode_ping(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id != 0 {
            return Err(CodecError::InvalidFormat(
                "PING frame must have stream ID 0".into(),
            ));
        }
        if payload.len() != 8 {
            return Err(CodecError::InvalidFormat(format!(
                "PING must be 8 bytes, got {}",
                payload.len()
            )));
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(&payload[..8]);
        Ok(H2Frame::Ping(PingFrame {
            ack: header.flags.is_ack(),
            data,
        }))
    }

    fn decode_goaway(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id != 0 {
            return Err(CodecError::InvalidFormat(
                "GOAWAY frame must have stream ID 0".into(),
            ));
        }
        if payload.len() < 8 {
            return Err(CodecError::InvalidFormat(format!(
                "GOAWAY must be at least 8 bytes, got {}",
                payload.len()
            )));
        }
        let last_stream_id =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFF_FFFF;
        let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let debug_data = if payload.len() > 8 {
            payload.slice(8..)
        } else {
            Bytes::new()
        };
        Ok(H2Frame::GoAway(GoAwayFrame {
            last_stream_id,
            error_code,
            debug_data,
        }))
    }

    fn decode_window_update(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if payload.len() != 4 {
            return Err(CodecError::InvalidFormat(format!(
                "WINDOW_UPDATE must be 4 bytes, got {}",
                payload.len()
            )));
        }
        let increment =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFF_FFFF;
        // RFC 7540 §6.9: increment=0 is an error, but we pass it through
        // so engine can send the appropriate RST_STREAM vs GOAWAY.
        Ok(H2Frame::WindowUpdate(WindowUpdateFrame {
            stream_id: header.stream_id,
            increment,
        }))
    }

    fn decode_continuation(header: &H2FrameHeader, payload: Bytes) -> Result<H2Frame, CodecError> {
        if header.stream_id == 0 {
            return Err(CodecError::InvalidFormat(
                "CONTINUATION frame with stream ID 0".into(),
            ));
        }
        Ok(H2Frame::Continuation(ContinuationFrame {
            stream_id: header.stream_id,
            header_block: payload,
            end_headers: header.flags.is_end_headers(),
        }))
    }

    // ── Encode ───────────────────────────────────────────────────────────

    pub fn encode(&self, frame: &H2Frame, buf: &mut BytesMut) {
        match frame {
            H2Frame::Data(f) => Self::encode_data(f, buf),
            H2Frame::Headers(f) => Self::encode_headers(f, buf),
            H2Frame::Priority(f) => Self::encode_priority(f, buf),
            H2Frame::RstStream(f) => Self::encode_rst_stream(f, buf),
            H2Frame::Settings(f) => Self::encode_settings(f, buf),
            H2Frame::PushPromise(f) => Self::encode_push_promise(f, buf),
            H2Frame::Ping(f) => Self::encode_ping(f, buf),
            H2Frame::GoAway(f) => Self::encode_goaway(f, buf),
            H2Frame::WindowUpdate(f) => Self::encode_window_update(f, buf),
            H2Frame::Continuation(f) => Self::encode_continuation(f, buf),
            H2Frame::Unknown(f) => {
                let header = H2FrameHeader {
                    length: f.payload.len() as u32,
                    frame_type: H2FrameType::from_u8(f.frame_type).unwrap_or(H2FrameType::Data),
                    flags: H2FrameFlags::new(f.flags),
                    stream_id: f.stream_id,
                };
                buf.extend_from_slice(&header.encode());
                buf.extend_from_slice(&f.payload);
            }
        }
    }

    fn encode_data(frame: &DataFrame, buf: &mut BytesMut) {
        let mut flags = H2FrameFlags::NONE;
        if frame.end_stream {
            flags.set(H2FrameFlags::END_STREAM);
        }
        let (payload_len, padding) = if let Some(pad_len) = frame.padding {
            flags.set(H2FrameFlags::PADDED);
            (1 + frame.data.len() + pad_len as usize, Some(pad_len))
        } else {
            (frame.data.len(), None)
        };
        let header = H2FrameHeader::new(
            H2FrameType::Data,
            flags,
            frame.stream_id,
            payload_len as u32,
        );
        buf.extend_from_slice(&header.encode());
        if let Some(pad_len) = padding {
            buf.extend_from_slice(&[pad_len]);
        }
        buf.extend_from_slice(&frame.data);
        if let Some(pad_len) = padding {
            buf.resize(buf.len() + pad_len as usize, 0);
        }
    }

    fn encode_headers(frame: &HeadersFrame, buf: &mut BytesMut) {
        let mut flags = H2FrameFlags::NONE;
        if frame.end_stream {
            flags.set(H2FrameFlags::END_STREAM);
        }
        if frame.end_headers {
            flags.set(H2FrameFlags::END_HEADERS);
        }
        if frame.priority.is_some() {
            flags.set(H2FrameFlags::PRIORITY);
        }

        let priority_len = if frame.priority.is_some() { 5 } else { 0 };
        let (payload_len, padding) = if let Some(pad_len) = frame.padding {
            flags.set(H2FrameFlags::PADDED);
            (
                1 + priority_len + frame.header_block.len() + pad_len as usize,
                Some(pad_len),
            )
        } else {
            (priority_len + frame.header_block.len(), None)
        };

        let header = H2FrameHeader::new(
            H2FrameType::Headers,
            flags,
            frame.stream_id,
            payload_len as u32,
        );
        buf.extend_from_slice(&header.encode());

        if let Some(pad_len) = padding {
            buf.extend_from_slice(&[pad_len]);
        }
        if let Some(ref priority) = frame.priority {
            let mut dep = priority.stream_dependency;
            if priority.exclusive {
                dep |= 0x8000_0000;
            }
            buf.extend_from_slice(&dep.to_be_bytes());
            buf.extend_from_slice(&[priority.weight]);
        }
        buf.extend_from_slice(&frame.header_block);
        if let Some(pad_len) = padding {
            buf.resize(buf.len() + pad_len as usize, 0);
        }
    }

    fn encode_priority(frame: &PriorityFrame, buf: &mut BytesMut) {
        let header = H2FrameHeader::new(
            H2FrameType::Priority,
            H2FrameFlags::NONE,
            frame.stream_id,
            5,
        );
        buf.extend_from_slice(&header.encode());
        let mut dep = frame.priority.stream_dependency;
        if frame.priority.exclusive {
            dep |= 0x8000_0000;
        }
        buf.extend_from_slice(&dep.to_be_bytes());
        buf.extend_from_slice(&[frame.priority.weight]);
    }

    fn encode_rst_stream(frame: &RstStreamFrame, buf: &mut BytesMut) {
        let header = H2FrameHeader::new(
            H2FrameType::RstStream,
            H2FrameFlags::NONE,
            frame.stream_id,
            4,
        );
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&frame.error_code.to_be_bytes());
    }

    fn encode_settings(frame: &SettingsFrame, buf: &mut BytesMut) {
        let flags = if frame.ack {
            H2FrameFlags::new(H2FrameFlags::ACK)
        } else {
            H2FrameFlags::NONE
        };
        let payload_len = if frame.ack {
            0
        } else {
            frame.settings.len() * 6
        };
        let header = H2FrameHeader::new(H2FrameType::Settings, flags, 0, payload_len as u32);
        buf.extend_from_slice(&header.encode());
        if !frame.ack {
            for s in &frame.settings {
                buf.extend_from_slice(&s.id.to_be_bytes());
                buf.extend_from_slice(&s.value.to_be_bytes());
            }
        }
    }

    fn encode_ping(frame: &PingFrame, buf: &mut BytesMut) {
        let flags = if frame.ack {
            H2FrameFlags::new(H2FrameFlags::ACK)
        } else {
            H2FrameFlags::NONE
        };
        let header = H2FrameHeader::new(H2FrameType::Ping, flags, 0, 8);
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&frame.data);
    }

    fn encode_goaway(frame: &GoAwayFrame, buf: &mut BytesMut) {
        let payload_len = 8 + frame.debug_data.len();
        let header = H2FrameHeader::new(
            H2FrameType::GoAway,
            H2FrameFlags::NONE,
            0,
            payload_len as u32,
        );
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&frame.last_stream_id.to_be_bytes());
        buf.extend_from_slice(&frame.error_code.to_be_bytes());
        buf.extend_from_slice(&frame.debug_data);
    }

    fn encode_window_update(frame: &WindowUpdateFrame, buf: &mut BytesMut) {
        let header = H2FrameHeader::new(
            H2FrameType::WindowUpdate,
            H2FrameFlags::NONE,
            frame.stream_id,
            4,
        );
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&frame.increment.to_be_bytes());
    }

    fn encode_continuation(frame: &ContinuationFrame, buf: &mut BytesMut) {
        let mut flags = H2FrameFlags::NONE;
        if frame.end_headers {
            flags.set(H2FrameFlags::END_HEADERS);
        }
        let header = H2FrameHeader::new(
            H2FrameType::Continuation,
            flags,
            frame.stream_id,
            frame.header_block.len() as u32,
        );
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&frame.header_block);
    }

    fn encode_push_promise(frame: &PushPromiseFrame, buf: &mut BytesMut) {
        let mut flags = H2FrameFlags::NONE;
        if frame.end_headers {
            flags.set(H2FrameFlags::END_HEADERS);
        }
        let (payload_len, padding) = if let Some(pad_len) = frame.padding {
            flags.set(H2FrameFlags::PADDED);
            (
                1 + 4 + frame.header_block.len() + pad_len as usize,
                Some(pad_len),
            )
        } else {
            (4 + frame.header_block.len(), None)
        };
        let header = H2FrameHeader::new(
            H2FrameType::PushPromise,
            flags,
            frame.stream_id,
            payload_len as u32,
        );
        buf.extend_from_slice(&header.encode());
        if let Some(pad_len) = padding {
            buf.extend_from_slice(&[pad_len]);
        }
        buf.extend_from_slice(&frame.promised_stream_id.to_be_bytes());
        buf.extend_from_slice(&frame.header_block);
        if let Some(pad_len) = padding {
            buf.resize(buf.len() + pad_len as usize, 0);
        }
    }
}

impl Default for H2Codec {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_settings_frame() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // header
                0x00, 0x01, 0x00, 0x00, 0x20, 0x00, // HEADER_TABLE_SIZE = 8192
                0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS = 100
            ][..],
        );
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Settings(frame)) => {
                assert!(!frame.ack);
                assert_eq!(frame.settings.len(), 2);
                assert_eq!(frame.settings[0].id, 0x01);
                assert_eq!(frame.settings[0].value, 8192);
                assert_eq!(frame.settings[1].id, 0x03);
                assert_eq!(frame.settings[1].value, 100);
            }
            other => panic!("expected Settings, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_settings_ack() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00][..]);
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Settings(frame)) => {
                assert!(frame.ack);
                assert!(frame.settings.is_empty());
            }
            other => panic!("expected Settings ACK, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_data_frame() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // header
                b'H', b'e', b'l', b'l', b'o',
            ][..],
        );
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Data(frame)) => {
                assert_eq!(frame.stream_id, 1);
                assert!(frame.end_stream);
                assert_eq!(frame.data.as_ref(), b"Hello");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_headers_frame() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x0a, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x86, 0x84, 0x41, 0x8a,
                0x08, 0x9d, 0x5c, 0x0b, 0x81,
            ][..],
        );
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Headers(frame)) => {
                assert_eq!(frame.stream_id, 1);
                assert!(frame.end_stream);
                assert!(frame.end_headers);
                assert_eq!(frame.header_block.len(), 10);
            }
            other => panic!("expected Headers, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_ping_frame() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08,
            ][..],
        );
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Ping(frame)) => {
                assert!(!frame.ack);
                assert_eq!(frame.data, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            other => panic!("expected Ping, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_window_update_frame() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(
            &[
                0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
            ][..],
        );
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::WindowUpdate(frame)) => {
                assert_eq!(frame.stream_id, 1);
                assert_eq!(frame.increment, 4096);
            }
            other => panic!("expected WindowUpdate, got {other:?}"),
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let codec = H2Codec::new();
        let mut buf = BytesMut::new();

        let settings = H2Frame::Settings(SettingsFrame {
            ack: false,
            settings: vec![
                SettingsParameter {
                    id: 0x01,
                    value: 4096,
                },
                SettingsParameter {
                    id: 0x03,
                    value: 256,
                },
            ],
        });
        codec.encode(&settings, &mut buf);

        let mut codec2 = H2Codec::new();
        match codec2.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Settings(frame)) => {
                assert_eq!(frame.settings.len(), 2);
                assert_eq!(frame.settings[0].id, 0x01);
                assert_eq!(frame.settings[0].value, 4096);
            }
            other => panic!("expected Settings, got {other:?}"),
        }
    }

    #[test]
    fn test_need_more_data() {
        let mut codec = H2Codec::new();
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x05, 0x00, 0x00][..]);
        match codec.decode(&mut buf) {
            DecodeResult::NeedMoreData { min_bytes } => {
                assert_eq!(min_bytes, 4);
            }
            other => panic!("expected NeedMoreData, got {other:?}"),
        }
    }

    #[test]
    fn test_headers_with_priority_roundtrip() {
        let codec = H2Codec::new();
        let mut buf = BytesMut::new();

        let frame = H2Frame::Headers(HeadersFrame {
            stream_id: 1,
            header_block: Bytes::from_static(&[0x82, 0x86]),
            end_stream: true,
            end_headers: true,
            priority: Some(PrioritySpec {
                exclusive: true,
                stream_dependency: 0,
                weight: 0,
            }),
            padding: None,
        });
        codec.encode(&frame, &mut buf);

        // 9-byte frame header + 5-byte priority + 2-byte header_block = 16 bytes
        assert_eq!(buf.len(), 16);
        // frame header: length=7 (00 00 07), type=HEADERS(01), flags=0x25(END_STREAM|END_HEADERS|PRIORITY)
        assert_eq!(&buf[0..5], &[0x00, 0x00, 0x07, 0x01, 0x25]);
        // stream_id=1
        assert_eq!(&buf[5..9], &[0x00, 0x00, 0x00, 0x01]);
        // priority: exclusive=1|dep=0 → 0x80000000, weight=0
        assert_eq!(&buf[9..13], &[0x80, 0x00, 0x00, 0x00]); // exclusive + dep
        assert_eq!(buf[13], 0x00, "wire weight byte must be 0x00");

        let mut codec2 = H2Codec::new();
        match codec2.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Headers(f)) => {
                assert_eq!(f.stream_id, 1);
                assert!(f.end_stream);
                assert!(f.end_headers);
                let p = f.priority.unwrap();
                assert!(p.exclusive);
                assert_eq!(p.stream_dependency, 0);
                assert_eq!(p.weight, 0);
                assert_eq!(f.header_block.as_ref(), &[0x82, 0x86]);
            }
            other => panic!("expected Headers with priority, got {other:?}"),
        }
    }

    #[test]
    fn test_priority_frame_roundtrip() {
        let codec = H2Codec::new();
        let mut buf = BytesMut::new();

        let frame = H2Frame::Priority(PriorityFrame {
            stream_id: 3,
            priority: PrioritySpec {
                exclusive: false,
                stream_dependency: 0,
                weight: 201,
            },
        });
        codec.encode(&frame, &mut buf);

        let mut codec2 = H2Codec::new();
        match codec2.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Priority(f)) => {
                assert_eq!(f.stream_id, 3);
                assert!(!f.priority.exclusive);
                assert_eq!(f.priority.stream_dependency, 0);
                assert_eq!(f.priority.weight, 201);
            }
            other => panic!("expected Priority, got {other:?}"),
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────

    const F_PADDED: u8 = 0x08;
    const F_PRIORITY: u8 = 0x20;
    const F_ACK: u8 = 0x01;

    /// Build a raw frame whose declared length matches `payload`.
    fn raw(ftype: H2FrameType, flags: u8, stream_id: u32, payload: &[u8]) -> BytesMut {
        let header = H2FrameHeader::new(
            ftype,
            H2FrameFlags::new(flags),
            stream_id,
            payload.len() as u32,
        );
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(payload);
        buf
    }

    /// True if `buf` decodes to a `DecodeResult::Error`.
    fn is_decode_error(mut buf: BytesMut) -> bool {
        let mut codec = H2Codec::new();
        matches!(codec.decode(&mut buf), DecodeResult::Error(_))
    }

    /// Encode a frame and decode it back through a fresh codec.
    fn roundtrip(frame: &H2Frame) -> H2Frame {
        let codec = H2Codec::new();
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf);
        let mut codec2 = H2Codec::new();
        match codec2.decode(&mut buf) {
            DecodeResult::Frame(f) => f,
            other => panic!("roundtrip failed: {other:?}"),
        }
    }

    // ── encode/decode roundtrips for the frame types not covered above ──────

    #[test]
    fn data_frame_roundtrips_with_and_without_padding() {
        match roundtrip(&H2Frame::Data(DataFrame {
            stream_id: 1,
            data: Bytes::from_static(b"hi"),
            end_stream: false,
            padding: None,
        })) {
            H2Frame::Data(f) => {
                assert_eq!(f.data.as_ref(), b"hi");
                assert!(!f.end_stream);
                assert!(f.padding.is_none());
            }
            o => panic!("{o:?}"),
        }
        match roundtrip(&H2Frame::Data(DataFrame {
            stream_id: 3,
            data: Bytes::from_static(b"pad"),
            end_stream: true,
            padding: Some(4),
        })) {
            H2Frame::Data(f) => {
                assert_eq!(f.data.as_ref(), b"pad");
                assert!(f.end_stream);
                assert_eq!(f.padding, Some(4));
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn rst_stream_roundtrips() {
        match roundtrip(&H2Frame::RstStream(RstStreamFrame {
            stream_id: 5,
            error_code: 8,
        })) {
            H2Frame::RstStream(f) => {
                assert_eq!(f.stream_id, 5);
                assert_eq!(f.error_code, 8);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn goaway_roundtrips_with_optional_debug_data() {
        match roundtrip(&H2Frame::GoAway(GoAwayFrame {
            last_stream_id: 7,
            error_code: 1,
            debug_data: Bytes::new(),
        })) {
            H2Frame::GoAway(f) => {
                assert_eq!(f.last_stream_id, 7);
                assert_eq!(f.error_code, 1);
                assert!(f.debug_data.is_empty());
            }
            o => panic!("{o:?}"),
        }
        match roundtrip(&H2Frame::GoAway(GoAwayFrame {
            last_stream_id: 9,
            error_code: 2,
            debug_data: Bytes::from_static(b"bye"),
        })) {
            H2Frame::GoAway(f) => assert_eq!(f.debug_data.as_ref(), b"bye"),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn ping_ack_roundtrips() {
        match roundtrip(&H2Frame::Ping(PingFrame {
            ack: true,
            data: [9, 8, 7, 6, 5, 4, 3, 2],
        })) {
            H2Frame::Ping(f) => {
                assert!(f.ack);
                assert_eq!(f.data, [9, 8, 7, 6, 5, 4, 3, 2]);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn window_update_roundtrips() {
        match roundtrip(&H2Frame::WindowUpdate(WindowUpdateFrame {
            stream_id: 0,
            increment: 65_535,
        })) {
            H2Frame::WindowUpdate(f) => assert_eq!(f.increment, 65_535),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn continuation_roundtrips() {
        match roundtrip(&H2Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::from_static(&[0x82]),
            end_headers: true,
        })) {
            H2Frame::Continuation(f) => {
                assert_eq!(f.stream_id, 1);
                assert!(f.end_headers);
                assert_eq!(f.header_block.as_ref(), &[0x82]);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn push_promise_roundtrips_with_and_without_padding() {
        match roundtrip(&H2Frame::PushPromise(PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 2,
            header_block: Bytes::from_static(&[0x82]),
            end_headers: true,
            padding: None,
        })) {
            H2Frame::PushPromise(f) => {
                assert_eq!(f.promised_stream_id, 2);
                assert!(f.end_headers);
                assert_eq!(f.header_block.as_ref(), &[0x82]);
            }
            o => panic!("{o:?}"),
        }
        match roundtrip(&H2Frame::PushPromise(PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 4,
            header_block: Bytes::from_static(&[0x86]),
            end_headers: false,
            padding: Some(3),
        })) {
            H2Frame::PushPromise(f) => {
                assert_eq!(f.promised_stream_id, 4);
                assert_eq!(f.padding, Some(3));
                assert_eq!(f.header_block.as_ref(), &[0x86]);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn headers_roundtrips_with_padding() {
        match roundtrip(&H2Frame::Headers(HeadersFrame {
            stream_id: 1,
            header_block: Bytes::from_static(&[0x82, 0x86]),
            end_stream: false,
            end_headers: true,
            priority: None,
            padding: Some(2),
        })) {
            H2Frame::Headers(f) => {
                assert_eq!(f.header_block.as_ref(), &[0x82, 0x86]);
                assert_eq!(f.padding, Some(2));
                assert!(f.end_headers);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn settings_ack_roundtrips() {
        match roundtrip(&H2Frame::Settings(SettingsFrame {
            ack: true,
            settings: vec![],
        })) {
            H2Frame::Settings(f) => {
                assert!(f.ack);
                assert!(f.settings.is_empty());
            }
            o => panic!("{o:?}"),
        }
    }

    // ── unknown frame handling (RFC 7540 §4.1) ──────────────────────────────

    #[test]
    fn unknown_frame_type_is_skipped_and_reported() {
        let mut buf = BytesMut::new();
        // length=2, type=0x1F (unknown), flags=0, stream_id=7
        buf.extend_from_slice(&[0x00, 0x00, 0x02, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x07]);
        buf.extend_from_slice(&[0xAA, 0xBB]);
        let mut codec = H2Codec::new();
        match codec.decode(&mut buf) {
            DecodeResult::Frame(H2Frame::Unknown(f)) => {
                assert_eq!(f.frame_type, 0x1F);
                assert_eq!(f.stream_id, 7);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        assert!(buf.is_empty(), "unknown frame must be fully drained");
    }

    #[test]
    fn unknown_frame_needs_full_payload_before_skipping() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x05, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x07]);
        buf.extend_from_slice(&[0xAA]); // only 1 of 5 payload bytes present
        let mut codec = H2Codec::new();
        match codec.decode(&mut buf) {
            DecodeResult::NeedMoreData { min_bytes } => assert_eq!(min_bytes, 4),
            other => panic!("expected NeedMoreData, got {other:?}"),
        }
    }

    #[test]
    fn unknown_frame_encodes_its_payload() {
        let codec = H2Codec::new();
        let mut buf = BytesMut::new();
        codec.encode(
            &H2Frame::Unknown(UnknownFrame {
                frame_type: 0x1F,
                stream_id: 1,
                flags: 0,
                payload: Bytes::from_static(&[1, 2, 3]),
            }),
            &mut buf,
        );
        assert_eq!(buf.len(), 12, "9-byte header + 3-byte payload");
        assert_eq!(&buf[9..], &[1, 2, 3]);
    }

    // ── limits & clamping ───────────────────────────────────────────────────

    #[test]
    fn frame_larger_than_max_is_rejected() {
        let header = H2FrameHeader::new(
            H2FrameType::Data,
            H2FrameFlags::NONE,
            1,
            DEFAULT_MAX_FRAME_SIZE + 1,
        );
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&header.encode());
        let mut codec = H2Codec::new();
        match codec.decode(&mut buf) {
            DecodeResult::Error(CodecError::TooLarge { size, max }) => {
                assert_eq!(size, (DEFAULT_MAX_FRAME_SIZE + 1) as usize);
                assert_eq!(max, DEFAULT_MAX_FRAME_SIZE as usize);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn set_max_frame_size_clamps_to_protocol_bounds() {
        let mut codec = H2Codec::new();
        assert_eq!(codec.max_frame_size(), DEFAULT_MAX_FRAME_SIZE);

        codec.set_max_frame_size(100); // below the floor
        assert_eq!(codec.max_frame_size(), DEFAULT_MAX_FRAME_SIZE);

        codec.set_max_frame_size(u32::MAX); // above the ceiling
        assert_eq!(codec.max_frame_size(), MAX_FRAME_SIZE_LIMIT);

        codec.set_max_frame_size(32_768); // in range
        assert_eq!(codec.max_frame_size(), 32_768);
    }

    // ── decode error paths ──────────────────────────────────────────────────

    #[test]
    fn stream_id_validation_is_enforced_per_frame_type() {
        assert!(
            is_decode_error(raw(H2FrameType::Data, 0, 0, b"x")),
            "DATA stream 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Headers, 0, 0, &[])),
            "HEADERS stream 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Priority, 0, 0, &[0; 5])),
            "PRIORITY stream 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::RstStream, 0, 0, &[0; 4])),
            "RST stream 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::PushPromise, 0, 0, &[0; 4])),
            "PUSH_PROMISE stream 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Continuation, 0, 0, &[])),
            "CONTINUATION stream 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Settings, 0, 1, &[])),
            "SETTINGS stream != 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Ping, 0, 1, &[0; 8])),
            "PING stream != 0"
        );
        assert!(
            is_decode_error(raw(H2FrameType::GoAway, 0, 1, &[0; 8])),
            "GOAWAY stream != 0"
        );
    }

    #[test]
    fn fixed_length_frames_reject_wrong_sizes() {
        assert!(
            is_decode_error(raw(H2FrameType::Priority, 0, 1, &[0; 4])),
            "PRIORITY len"
        );
        assert!(
            is_decode_error(raw(H2FrameType::RstStream, 0, 1, &[0; 3])),
            "RST len"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Ping, 0, 0, &[0; 4])),
            "PING len"
        );
        assert!(
            is_decode_error(raw(H2FrameType::WindowUpdate, 0, 1, &[0; 3])),
            "WINDOW_UPDATE len"
        );
        assert!(
            is_decode_error(raw(H2FrameType::GoAway, 0, 0, &[0; 4])),
            "GOAWAY len"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Settings, 0, 0, &[0; 5])),
            "SETTINGS not x6"
        );
    }

    #[test]
    fn settings_ack_must_have_empty_payload() {
        assert!(
            is_decode_error(raw(H2FrameType::Settings, F_ACK, 0, &[0; 6])),
            "SETTINGS ACK non-empty"
        );
    }

    #[test]
    fn padding_and_priority_edge_cases_are_rejected() {
        assert!(
            is_decode_error(raw(H2FrameType::Data, F_PADDED, 1, &[])),
            "DATA padded empty"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Data, F_PADDED, 1, &[5, b'a', b'b'])),
            "DATA pad >= len"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Headers, F_PADDED, 1, &[])),
            "HEADERS padded empty"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Headers, F_PADDED, 1, &[10, 0x82])),
            "HEADERS invalid padding"
        );
        assert!(
            is_decode_error(raw(H2FrameType::Headers, F_PRIORITY, 1, &[0, 0, 0])),
            "HEADERS missing priority data"
        );
        assert!(
            is_decode_error(raw(H2FrameType::PushPromise, F_PADDED, 1, &[])),
            "PUSH_PROMISE padded empty"
        );
        assert!(
            is_decode_error(raw(H2FrameType::PushPromise, 0, 1, &[0, 0])),
            "PUSH_PROMISE missing promised id"
        );
    }

    #[test]
    fn end_stream_flag_on_an_unpadded_data_frame_roundtrips() {
        match roundtrip(&H2Frame::Data(DataFrame {
            stream_id: 9,
            data: Bytes::from_static(b"z"),
            end_stream: true,
            padding: None,
        })) {
            H2Frame::Data(f) => {
                assert!(f.end_stream);
                assert_eq!(f.stream_id, 9);
                assert_eq!(f.data.as_ref(), b"z");
            }
            o => panic!("{o:?}"),
        }
    }

    // ── misc ────────────────────────────────────────────────────────────────

    #[test]
    fn codec_error_displays_useful_messages() {
        assert!(CodecError::InvalidFormat("oops".into())
            .to_string()
            .contains("oops"));
        let s = CodecError::TooLarge { size: 100, max: 50 }.to_string();
        assert!(s.contains("100") && s.contains("50"));
    }

    #[test]
    fn default_codec_uses_default_max_frame_size() {
        assert_eq!(H2Codec::default().max_frame_size(), DEFAULT_MAX_FRAME_SIZE);
    }
}
