//! QUIC transport parameters TLS extension support.
//!
//! The extension payload uses QUIC varint framing rather than TLS-specific
//! sub-structures.  This module keeps the encoding generic so higher layers can
//! preserve exact parameter ordering and opaque values where needed.

use crate::error::{Result, TlsError};

/// QUIC Transport Parameters extension type (RFC 9000 Section 18).
pub const QUIC_TRANSPORT_PARAMS_TYPE: u16 = 0x0039;

/// Ordered QUIC transport parameter list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicTransportParams {
    pub parameters: Vec<QuicTransportParam>,
}

impl QuicTransportParams {
    pub fn new(parameters: Vec<QuicTransportParam>) -> Self {
        Self { parameters }
    }

    pub fn get(&self, id: u64) -> Option<&[u8]> {
        self.parameters
            .iter()
            .find(|param| param.id == id)
            .map(|param| param.value.as_slice())
    }
}

/// Single QUIC transport parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTransportParam {
    pub id: u64,
    pub value: Vec<u8>,
}

impl QuicTransportParam {
    pub fn new(id: u64, value: Vec<u8>) -> Self {
        Self { id, value }
    }
}

/// Common transport parameter IDs from RFC 9000 Section 18.2.
pub mod param_id {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
}

/// Encode transport parameters as TLS extension payload bytes.
pub fn encode_transport_params(params: &QuicTransportParams) -> Vec<u8> {
    let mut out = Vec::new();
    for param in &params.parameters {
        encode_varint(param.id, &mut out);
        encode_varint(param.value.len() as u64, &mut out);
        out.extend_from_slice(&param.value);
    }
    out
}

/// Decode a QUIC transport parameter extension payload.
pub fn decode_transport_params(data: &[u8]) -> Result<QuicTransportParams> {
    let mut pos = 0usize;
    let mut parameters = Vec::new();

    while pos < data.len() {
        let id = decode_varint(data, &mut pos)?;
        let value_len = decode_varint(data, &mut pos)? as usize;
        if pos + value_len > data.len() {
            return Err(TlsError::UnexpectedMessage(
                "QUIC transport parameter exceeds payload length".to_string(),
            ));
        }
        parameters.push(QuicTransportParam::new(
            id,
            data[pos..pos + value_len].to_vec(),
        ));
        pos += value_len;
    }

    Ok(QuicTransportParams { parameters })
}

/// Encode a QUIC variable-length integer.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16383 => {
            let encoded = 0x4000 | value as u16;
            out.extend_from_slice(&encoded.to_be_bytes());
        }
        16384..=1073741823 => {
            let encoded = 0x8000_0000 | value as u32;
            out.extend_from_slice(&encoded.to_be_bytes());
        }
        1073741824..=4611686018427387903 => {
            let encoded = 0xC000_0000_0000_0000 | value;
            out.extend_from_slice(&encoded.to_be_bytes());
        }
        _ => panic!("QUIC varint value out of range"),
    }
}

/// Decode a QUIC variable-length integer and advance `pos`.
pub fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos >= data.len() {
        return Err(TlsError::UnexpectedMessage(
            "truncated QUIC varint".to_string(),
        ));
    }

    let first = data[*pos];
    let (len, mut value) = match first >> 6 {
        0 => (1usize, (first & 0x3f) as u64),
        1 => (2usize, (first & 0x3f) as u64),
        2 => (4usize, (first & 0x3f) as u64),
        _ => (8usize, (first & 0x3f) as u64),
    };

    if *pos + len > data.len() {
        return Err(TlsError::UnexpectedMessage(
            "truncated QUIC varint".to_string(),
        ));
    }

    for &byte in &data[*pos + 1..*pos + len] {
        value = (value << 8) | byte as u64;
    }
    *pos += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_boundaries() {
        let values = [
            0u64,
            63,
            64,
            15293,
            16383,
            16384,
            494878333,
            1073741823,
            1073741824,
            151288809941952652,
        ];

        for value in values {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded);
            let mut pos = 0;
            let decoded = decode_varint(&encoded, &mut pos).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(pos, encoded.len());
        }
    }

    #[test]
    fn transport_params_roundtrip_preserves_order_and_values() {
        let params = QuicTransportParams::new(vec![
            QuicTransportParam::new(
                param_id::INITIAL_SOURCE_CONNECTION_ID,
                vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
            ),
            QuicTransportParam::new(param_id::MAX_IDLE_TIMEOUT, vec![0x40, 0x7d]),
            QuicTransportParam::new(param_id::INITIAL_MAX_DATA, vec![0x80, 0x00, 0x10, 0x00]),
        ]);

        let encoded = encode_transport_params(&params);
        let decoded = decode_transport_params(&encoded).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn decode_transport_params_rejects_truncated_value() {
        let data = [0x01, 0x02, 0xaa];
        let err = decode_transport_params(&data).unwrap_err();
        assert!(err.to_string().contains("exceeds payload length"));
    }
}
