//! `lkh3` — HTTP/3 and QUIC **fingerprint** profiles plus a thin client.
//!
//! This crate owns the wire-format knobs that make an HTTP/3 / QUIC client look
//! like a specific browser build:
//!
//! - [`QuicProfile`] / [`QuicTransportParams`] — QUIC transport parameters, their
//!   wire order (with optional per-connection shuffling), GREASE, and
//!   Initial-packet packetization ([`InitialFrameLayoutProfile`]).
//! - [`H3Profile`] — HTTP/3 `SETTINGS` order, QPACK limits, pseudo-header order
//!   ([`PseudoHeaderId`]), control-stream GREASE, and RFC 9218 `PRIORITY_UPDATE`
//!   frames.
//! - Browser presets: [`chrome_quic`], [`chrome_146_quic`], [`chrome_150_quic`],
//!   [`chrome_151_quic`], [`chrome_h3`], [`chrome_146_h3`],
//!   [`chrome_150_h3`], [`chrome_151_h3`], [`firefox_h3`].
//!
//! The transport itself is the patched `h3` + `h3-quinn` stack: [`connect_h3`]
//! wraps a live [`quinn`] connection into an [`H3Connection`], and [`H3Sender`]
//! multiplexes requests over it. Profiles are validated ([`QuicProfile::validate`])
//! before they reach the backend.
//!
//! Higher layers (`lkquic`, `lkrequest`) drive this crate; the QUIC-native TLS
//! 1.3 handshake bytes are produced by `lktls` via `lktls-quic`, so the QUIC
//! fingerprint stays consistent with the TCP-TLS one.

mod connection;
mod profile;
mod sender;
pub mod synthesis;

pub use connection::{
    connect_h3, connect_h3_0rtt, H3Connection, H3Error, H3RecvStream, H3ZeroRttConnection,
};
pub use h3_quinn::quinn;
pub use profile::{
    chrome_146_h3, chrome_146_quic, chrome_150_h3, chrome_150_quic, chrome_151_h3, chrome_151_quic,
    chrome_h3, chrome_quic, encode_alps_h3_settings, firefox_h3, H3Profile, InitialFrameElement,
    InitialFrameLayoutProfile, InitialPacketLayoutProfile, PseudoHeaderId,
    QuicPacketizationProfile, QuicProfile, QuicTransportParams, SETTINGS_H3_DATAGRAM,
    SETTINGS_MAX_FIELD_SECTION_SIZE, SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
};
pub use sender::H3Sender;
pub use synthesis::{validate as validate_quic_profile, InvalidQuicSpec, QuicConstraints};
