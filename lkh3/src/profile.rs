use serde::{Deserialize, Serialize};

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9114 §7.2.4.1).
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §7.2.4.1).
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §4.2).
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// `SETTINGS_H3_DATAGRAM` (RFC 9297 §2.1.1).
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// Pseudo-header identifier used by HTTP/3 HEADERS encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PseudoHeaderId {
    Method,
    Authority,
    Scheme,
    Path,
    Protocol,
}

impl PseudoHeaderId {
    /// Returns the wire-level pseudo-header name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Method => ":method",
            Self::Authority => ":authority",
            Self::Scheme => ":scheme",
            Self::Path => ":path",
            Self::Protocol => ":protocol",
        }
    }

    pub(crate) fn token(self) -> char {
        match self {
            Self::Method => 'm',
            Self::Authority => 'a',
            Self::Scheme => 's',
            Self::Path => 'p',
            Self::Protocol => 'o',
        }
    }
}

/// HTTP/3 fingerprint profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3Profile {
    /// Ordered SETTINGS entries as `(id, value)`.
    pub settings: Vec<(u64, u64)>,
    /// Whether GREASE settings should be sent.
    pub grease_settings: bool,
    /// Pseudo-header serialization order.
    pub pseudo_header_order: Vec<PseudoHeaderId>,
    /// QPACK dynamic table size.
    pub qpack_max_table_capacity: u64,
    /// Maximum blocked streams for QPACK.
    pub qpack_blocked_streams: u64,
    /// Optional `SETTINGS_MAX_FIELD_SECTION_SIZE`.
    pub max_field_section_size: Option<u64>,
    /// RFC 9218 PRIORITY_UPDATE frames to send on the control stream after
    /// SETTINGS.  Each entry is `(element_id, field_value)` where
    /// `element_id` is the predicted request stream ID (0, 4, 8, …) and
    /// `field_value` is the serialized priority (e.g., `"u=1, i"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priority_updates: Vec<(u64, String)>,
    /// Whether to emit a single GREASE frame (RFC 9114 §7.2.8 reserved frame
    /// type) on the control stream after SETTINGS. This is separate from
    /// `grease_settings` (the reserved *setting*): Chrome additionally sends a
    /// reserved *frame*. Per-profile so browsers that don't do this (or aren't
    /// modelled yet) simply leave it `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub send_control_grease_frame: bool,
}

/// QUIC transport parameters that influence fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicTransportParams {
    pub max_idle_timeout: u64,
    /// `None` means the parameter is not sent (uses RFC default 65527).
    /// Chrome does not send this parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_udp_payload_size: Option<u64>,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub active_connection_id_limit: u64,
    /// QUIC DATAGRAM transport parameter (id 0x20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_datagram_frame_size: Option<u64>,
    /// Whether to send Quinn's ACK Frequency `min_ack_delay` transport parameter.
    #[serde(default = "default_true")]
    pub send_min_ack_delay: bool,
    /// Whether to send Quinn's default reserved transport parameter (0xb6).
    #[serde(default = "default_true")]
    pub send_reserved_transport_parameter: bool,
    /// Raw extra QUIC transport parameters encoded as `(id, value_hex)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_transport_parameters: Vec<(u64, String)>,
    /// Preferred wire order for active QUIC transport parameters.
    ///
    /// IDs present here are emitted first if active; active parameters not
    /// listed here are appended by the backend in its default order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport_parameter_order: Vec<u64>,
    pub grease_transport_params: bool,
    /// Whether to randomize the transport-parameter wire ORDER per connection.
    ///
    /// Chrome/BoringSSL shuffles the order of its QUIC transport parameters on
    /// every connection (verified by capture: 3 connections → 3 orders). When
    /// `true`, the backend applies a fresh permutation of
    /// `transport_parameter_order` per connection instead of emitting it
    /// verbatim. Profiles that don't model this leave it `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub shuffle_transport_parameters: bool,
}

/// Local packetization knobs that affect the UDP datagram shape outside the
/// TLS transport-parameter extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicPacketizationProfile {
    /// Initial UDP payload size used by the QUIC sender before MTU discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_mtu: Option<u16>,
    /// Minimum UDP payload size used when padding client Initial datagrams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_datagram_size: Option<u16>,
    /// Disable path MTU discovery when matching a fixed capture more closely.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_mtu_discovery: bool,
    /// Whether UDP segmentation offload may be used by Quinn.
    #[serde(default = "default_true")]
    pub enable_segmentation_offload: bool,
    /// Whether outgoing UDP datagrams should be ECN-marked as ECT(0).
    #[serde(default = "default_true")]
    pub enable_ecn: bool,
    /// Optional profile for the frame layout inside client Initial packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_frame_layout: Option<InitialFrameLayoutProfile>,
}

impl Default for QuicPacketizationProfile {
    fn default() -> Self {
        Self {
            initial_mtu: None,
            initial_datagram_size: None,
            disable_mtu_discovery: false,
            enable_segmentation_offload: true,
            enable_ecn: true,
            initial_frame_layout: None,
        }
    }
}

/// Frame-level layout strategy for client Initial packets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitialFrameLayoutProfile {
    /// Target UDP payload / QUIC packet size for Initial packets.
    pub target_udp_payload_size: u16,
    /// Ordered packet templates applied to the first Initial packets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packets: Vec<InitialPacketLayoutProfile>,
}

impl InitialFrameLayoutProfile {
    /// Chrome 146-style Initial layout captured from Windows Chrome traffic.
    ///
    /// The first two Initial packets split the ClientHello CRYPTO data across
    /// non-monotonic CRYPTO offsets and interleave PING/PADDING frames. Later
    /// Initial packets still use regular Quinn frame selection but are padded
    /// to `target_udp_payload_size` by `initial_datagram_size`.
    pub fn chrome_146() -> Self {
        Self {
            target_udp_payload_size: 1250,
            packets: vec![
                InitialPacketLayoutProfile {
                    packet_number: 0,
                    frames: vec![
                        InitialFrameElement::crypto(1099, 16),
                        InitialFrameElement::padding(21),
                        InitialFrameElement::crypto(0, 73),
                        InitialFrameElement::Ping,
                        InitialFrameElement::crypto(1115, 33),
                        InitialFrameElement::Ping,
                        InitialFrameElement::Ping,
                        InitialFrameElement::padding(120),
                        InitialFrameElement::crypto(1151, 1),
                        InitialFrameElement::crypto(1152, 875),
                        InitialFrameElement::Ping,
                        InitialFrameElement::padding(6),
                        InitialFrameElement::Ping,
                        InitialFrameElement::padding(8),
                        InitialFrameElement::crypto(2027, 21),
                        InitialFrameElement::Ping,
                        InitialFrameElement::crypto(1148, 3),
                        InitialFrameElement::Ping,
                        InitialFrameElement::padding(2),
                    ],
                },
                InitialPacketLayoutProfile {
                    packet_number: 1,
                    frames: vec![
                        InitialFrameElement::padding(88),
                        InitialFrameElement::crypto(1080, 19),
                        InitialFrameElement::padding(2),
                        InitialFrameElement::crypto(378, 258),
                        InitialFrameElement::padding(1),
                        InitialFrameElement::crypto(143, 64),
                        InitialFrameElement::Ping,
                        InitialFrameElement::crypto(1020, 60),
                        InitialFrameElement::crypto(73, 70),
                        InitialFrameElement::crypto(636, 134),
                        InitialFrameElement::Ping,
                        InitialFrameElement::padding(18),
                        InitialFrameElement::crypto(985, 14),
                        InitialFrameElement::padding(30),
                        InitialFrameElement::crypto(999, 21),
                        InitialFrameElement::crypto(207, 171),
                        InitialFrameElement::padding(1),
                        InitialFrameElement::crypto(770, 215),
                    ],
                },
            ],
        }
    }
}

/// Template for one client Initial packet number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitialPacketLayoutProfile {
    /// Zero-based packet number to which this template applies.
    pub packet_number: u64,
    /// Ordered frame elements to encode before packet protection.
    pub frames: Vec<InitialFrameElement>,
}

/// A frame element in a client Initial packet layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InitialFrameElement {
    Crypto { offset: u64, length: usize },
    Padding { length: usize },
    Ping,
}

impl InitialFrameElement {
    pub fn crypto(offset: u64, length: usize) -> Self {
        Self::Crypto { offset, length }
    }

    pub fn padding(length: usize) -> Self {
        Self::Padding { length }
    }
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Full QUIC + HTTP/3 fingerprint profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicProfile {
    pub transport_params: QuicTransportParams,
    pub h3: H3Profile,
    pub connection_id_length: usize,
    /// Client Initial destination CID length. This is distinct from
    /// `connection_id_length`, which controls the source CID we ask the peer to
    /// use for packets back to us.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_destination_connection_id_length: Option<usize>,
    #[serde(default)]
    pub packetization: QuicPacketizationProfile,
}

impl H3Profile {
    /// Returns the setting value if the profile contains the setting ID.
    pub fn setting_value(&self, id: u64) -> Option<u64> {
        self.settings
            .iter()
            .find_map(|(setting_id, value)| (*setting_id == id).then_some(*value))
    }

    /// Returns the pseudo-header order in the compact perk-like token form.
    pub fn pseudo_header_order_token(&self) -> String {
        self.pseudo_header_order
            .iter()
            .map(|id| id.token())
            .collect()
    }

    /// Returns the effective SETTINGS list for the wire, using the individual
    /// fields (`qpack_max_table_capacity`, `qpack_blocked_streams`,
    /// `max_field_section_size`) as the source of truth.
    ///
    /// The ordering and any extra entries (e.g. `SETTINGS_H3_DATAGRAM`) from
    /// `self.settings` are preserved; known setting values are overwritten by
    /// the individual fields.
    pub fn effective_settings(&self) -> Vec<(u64, u64)> {
        let mut result: Vec<(u64, u64)> = self
            .settings
            .iter()
            .map(|&(id, value)| {
                let effective_value = match id {
                    SETTINGS_QPACK_MAX_TABLE_CAPACITY => self.qpack_max_table_capacity,
                    SETTINGS_QPACK_BLOCKED_STREAMS => self.qpack_blocked_streams,
                    SETTINGS_MAX_FIELD_SECTION_SIZE => self.max_field_section_size.unwrap_or(value),
                    _ => value,
                };
                (id, effective_value)
            })
            .collect();

        if self.qpack_max_table_capacity > 0
            && !result
                .iter()
                .any(|(id, _)| *id == SETTINGS_QPACK_MAX_TABLE_CAPACITY)
        {
            result.push((
                SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                self.qpack_max_table_capacity,
            ));
        }
        if !result
            .iter()
            .any(|(id, _)| *id == SETTINGS_QPACK_BLOCKED_STREAMS)
        {
            result.push((SETTINGS_QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams));
        }
        if let Some(mfss) = self.max_field_section_size {
            if !result
                .iter()
                .any(|(id, _)| *id == SETTINGS_MAX_FIELD_SECTION_SIZE)
            {
                result.push((SETTINGS_MAX_FIELD_SECTION_SIZE, mfss));
            }
        }

        result
    }

    /// Synchronize the `settings` vec to match the individual fields.
    ///
    /// Call this after modifying individual fields (e.g. `qpack_max_table_capacity`)
    /// to keep the `settings` vec consistent without rebuilding the entire profile.
    pub fn sync_settings(&mut self) {
        self.settings = self.effective_settings();
    }

    /// Encode HTTP/3 SETTINGS as an ALPS `application_settings` payload.
    ///
    /// The payload contains only the SETTINGS parameter block, matching the
    /// HTTP/3 SETTINGS frame payload and excluding the frame type/length.
    pub fn encode_alps_h3_settings(&self) -> Vec<u8> {
        let settings = self.effective_settings();
        let mut out = Vec::with_capacity(settings.len() * 4);
        for (id, value) in settings {
            encode_quic_varint(id, &mut out);
            encode_quic_varint(value, &mut out);
        }
        out
    }

    /// Validates that the profile is internally consistent before backend use.
    pub fn validate(&self) -> Result<(), String> {
        if self.pseudo_header_order.is_empty() {
            return Err("pseudo_header_order must not be empty".into());
        }

        let mut seen = Vec::with_capacity(self.pseudo_header_order.len());
        for pseudo in &self.pseudo_header_order {
            if seen.contains(pseudo) {
                return Err(format!(
                    "pseudo_header_order contains duplicate {}",
                    pseudo.as_str()
                ));
            }
            seen.push(*pseudo);
        }

        Ok(())
    }
}

pub fn encode_alps_h3_settings(profile: &H3Profile) -> Vec<u8> {
    profile.encode_alps_h3_settings()
}

fn encode_quic_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => panic!("HTTP/3 SETTINGS varint value out of range"),
    }
}

impl H3Profile {
    /// Disable dynamic QPACK (set table capacity and blocked streams to 0).
    ///
    /// This is a conservative setting for broad interoperability with public
    /// servers that may not fully support dynamic QPACK.
    pub fn with_static_qpack(mut self) -> Self {
        self.qpack_max_table_capacity = 0;
        self.qpack_blocked_streams = 0;
        self.sync_settings();
        self
    }
}

impl QuicProfile {
    /// Disable dynamic QPACK on the inner H3 profile.
    ///
    /// Shorthand for `profile.h3 = profile.h3.with_static_qpack()`.
    pub fn with_static_qpack(mut self) -> Self {
        self.h3 = self.h3.with_static_qpack();
        self
    }

    /// Validates the QUIC transport parameters and nested HTTP/3 profile.
    pub fn validate(&self) -> Result<(), String> {
        self.h3.validate()?;

        if self.connection_id_length > 20 {
            return Err("connection_id_length must be in the range 0..=20".into());
        }
        if let Some(len) = self.initial_destination_connection_id_length {
            if len > 20 {
                return Err(
                    "initial_destination_connection_id_length must be in the range 0..=20".into(),
                );
            }
        }

        if let Some(mups) = self.transport_params.max_udp_payload_size {
            if mups < 1200 {
                return Err("max_udp_payload_size must be at least 1200 bytes when set".into());
            }
            if mups > 65_527 {
                return Err("max_udp_payload_size must be at most 65527 bytes when set".into());
            }
        }

        if self.transport_params.active_connection_id_limit < 2 {
            return Err("active_connection_id_limit must be at least 2".into());
        }

        if let Some(value) = self.transport_params.max_datagram_frame_size {
            if value >= (1_u64 << 62) {
                return Err("max_datagram_frame_size must fit QUIC varint".into());
            }
        }

        for (id, value_hex) in &self.transport_params.extra_transport_parameters {
            if *id >= (1_u64 << 62) {
                return Err("extra transport parameter id must fit QUIC varint".into());
            }
            if is_locally_encoded_transport_parameter(*id) {
                return Err(format!(
                    "extra transport parameter {id:#x} duplicates a managed parameter"
                ));
            }
            if value_hex.len() % 2 != 0 || !value_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "extra transport parameter {id:#x} value must be even-length hex"
                ));
            }
        }

        let mut order_seen =
            Vec::with_capacity(self.transport_params.transport_parameter_order.len());
        for id in &self.transport_params.transport_parameter_order {
            if *id >= (1_u64 << 62) {
                return Err("transport parameter order id must fit QUIC varint".into());
            }
            if order_seen.contains(id) {
                return Err(format!(
                    "transport parameter order contains duplicate {id:#x}"
                ));
            }
            order_seen.push(*id);
        }

        if let Some(initial_mtu) = self.packetization.initial_mtu {
            if initial_mtu < 1200 {
                return Err("packetization initial_mtu must be at least 1200 bytes".into());
            }
        }
        if let Some(initial_datagram_size) = self.packetization.initial_datagram_size {
            if initial_datagram_size < 1200 {
                return Err(
                    "packetization initial_datagram_size must be at least 1200 bytes".into(),
                );
            }
        }
        if let Some(layout) = &self.packetization.initial_frame_layout {
            if layout.target_udp_payload_size < 1200 {
                return Err(
                    "initial_frame_layout target_udp_payload_size must be at least 1200 bytes"
                        .into(),
                );
            }
            if let Some(initial_datagram_size) = self.packetization.initial_datagram_size {
                if layout.target_udp_payload_size > initial_datagram_size {
                    return Err(
                        "initial_frame_layout target_udp_payload_size must not exceed \
                         packetization initial_datagram_size"
                            .into(),
                    );
                }
            }
            let mut seen_packets = Vec::with_capacity(layout.packets.len());
            for packet in &layout.packets {
                if seen_packets.contains(&packet.packet_number) {
                    return Err(format!(
                        "initial_frame_layout contains duplicate packet number {}",
                        packet.packet_number
                    ));
                }
                seen_packets.push(packet.packet_number);
                if packet.frames.is_empty() {
                    return Err(format!(
                        "initial_frame_layout packet {} must contain at least one frame",
                        packet.packet_number
                    ));
                }
                for frame in &packet.frames {
                    match *frame {
                        InitialFrameElement::Crypto { length, .. }
                        | InitialFrameElement::Padding { length } => {
                            if length == 0 {
                                return Err(
                                    "initial_frame_layout frame lengths must be non-zero".into()
                                );
                            }
                        }
                        InitialFrameElement::Ping => {}
                    }
                }
            }
        }

        Ok(())
    }
}

fn is_locally_encoded_transport_parameter(id: u64) -> bool {
    matches!(
        id,
        0x00 | 0x01
            | 0x02
            | 0x03
            | 0x04
            | 0x05
            | 0x06
            | 0x07
            | 0x08
            | 0x09
            | 0x0a
            | 0x0b
            | 0x0c
            | 0x0d
            | 0x0e
            | 0x0f
            | 0x10
            | 0x20
            | 0xb6
            | 0x2ab2
            | 0xff04de1a
    )
}

pub fn chrome_h3() -> H3Profile {
    H3Profile {
        settings: vec![
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 65_536),
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 262_144),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 100),
            (SETTINGS_H3_DATAGRAM, 1),
        ],
        grease_settings: true,
        pseudo_header_order: vec![
            PseudoHeaderId::Method,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Scheme,
            PseudoHeaderId::Path,
        ],
        qpack_max_table_capacity: 65_536,
        qpack_blocked_streams: 100,
        max_field_section_size: Some(262_144),
        priority_updates: vec![],
        // Chrome sends a reserved GREASE frame on the control stream after
        // SETTINGS (observed as the second `GREASE` token in browserleaks'
        // h3_text, before the PRIORITY_UPDATE).
        send_control_grease_frame: true,
    }
}

pub fn chrome_quic() -> QuicProfile {
    QuicProfile {
        transport_params: QuicTransportParams {
            max_idle_timeout: 30_000,
            max_udp_payload_size: None, // Chrome does not send this parameter
            initial_max_data: 15_728_640,
            initial_max_stream_data_bidi_local: 6_291_456,
            initial_max_stream_data_bidi_remote: 6_291_456,
            initial_max_stream_data_uni: 6_291_456,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            active_connection_id_limit: 2, // RFC default, Chrome uses this
            max_datagram_frame_size: None,
            send_min_ack_delay: true,
            send_reserved_transport_parameter: true,
            extra_transport_parameters: vec![],
            transport_parameter_order: vec![],
            grease_transport_params: false,
            // Chrome shuffles TP order per connection (no-op here until this
            // generic profile carries an explicit order list).
            shuffle_transport_parameters: true,
        },
        h3: chrome_h3(),
        connection_id_length: 0, // Chrome: SetBytesForConnectionIdToSend(0)
        initial_destination_connection_id_length: None,
        packetization: QuicPacketizationProfile::default(),
    }
}

/// Chrome 146 HTTP/3 fingerprint profile.
///
/// Captured from Chrome 146.0.0.0 on Windows. H3 SETTINGS are identical to
/// the generic `chrome_h3()` preset. Additionally sends a PRIORITY_UPDATE
/// frame (RFC 9218) on the control stream for the first request stream
/// with `u=1, i` (urgency=1, incremental=true), matching Chrome's observed
/// behavior.
pub fn chrome_146_h3() -> H3Profile {
    let mut profile = chrome_h3();
    profile.priority_updates = vec![(0, "u=1, i".into())];
    profile
}

/// Chrome 146 QUIC + HTTP/3 fingerprint profile.
///
/// Captured from a real Chrome 146.0.0.0 browser on Windows 11 via pcap.
/// Key differences from the generic `chrome_quic()`:
///
/// - `max_udp_payload_size` = 1472 (sent on wire; generic preset omits it)
/// - `initial_max_streams_uni` = 103 (not 100)
/// - `max_datagram_frame_size` = 65 536 (QUIC DATAGRAM)
/// - raw reserved transport parameter `0x17af394a4ef8da0a`
/// - pcap-observed transport parameter wire order
/// - packetization starts at 1250-byte UDP payloads in the observed capture
///
/// Google-proprietary transport parameter `google_initial_rtt` is captured as
/// raw bytes. Its value is path-sensitive and should become dynamic once the
/// profile has an RTT estimator hook.
pub fn chrome_146_quic() -> QuicProfile {
    QuicProfile {
        transport_params: QuicTransportParams {
            max_idle_timeout: 30_000,
            max_udp_payload_size: Some(1472),
            initial_max_data: 15_728_640,
            initial_max_stream_data_bidi_local: 6_291_456,
            initial_max_stream_data_bidi_remote: 6_291_456,
            initial_max_stream_data_uni: 6_291_456,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 103,
            active_connection_id_limit: 2,
            max_datagram_frame_size: Some(65_536),
            send_min_ack_delay: false,
            send_reserved_transport_parameter: false,
            extra_transport_parameters: vec![
                (
                    0x11,
                    "000000019a9aca7a00000001".to_string(), // version_information
                ),
                (0x17af394a4ef8da0a, String::new()), // Chrome-style reserved GREASE TP
                (0x3127, "8009df94".to_string()),    // google_initial_rtt = 647060 us
            ],
            transport_parameter_order: vec![
                0x03,
                0x11,
                0x09,
                0x08,
                0x20,
                0x01,
                0x06,
                0x0f,
                0x04,
                0x17af394a4ef8da0a,
                0x3127,
                0x07,
                0x05,
            ],
            // Chrome 146 pcap uses a reserved TP (above), not Quinn's 0x2ab2
            // fixed-bit grease extension.
            grease_transport_params: false,
            // Chrome shuffles the TP wire order per connection (capture-verified
            // against Chrome 148: 3 connections produced 3 distinct orders).
            shuffle_transport_parameters: true,
        },
        h3: chrome_146_h3(),
        connection_id_length: 0,
        initial_destination_connection_id_length: Some(8),
        packetization: QuicPacketizationProfile {
            initial_mtu: Some(1250),
            initial_datagram_size: Some(1250),
            disable_mtu_discovery: false,
            enable_segmentation_offload: false,
            enable_ecn: false,
            initial_frame_layout: Some(InitialFrameLayoutProfile::chrome_146()),
        },
    }
}

/// Chrome 150 HTTP/3 fingerprint profile.
///
/// Captured from Chrome 150.0.7871.47 on Windows while navigating to Outlook.
/// The H3 SETTINGS match the Chrome family baseline. The first request stream
/// receives a navigation PRIORITY_UPDATE of `u=0, i`. This value is
/// request-context-sensitive and must be recaptured when targeting a different
/// Chrome milestone or resource type.
pub fn chrome_150_h3() -> H3Profile {
    let mut profile = chrome_h3();
    profile.priority_updates = vec![(0, "u=0, i".into())];
    profile
}

/// Chrome 150 QUIC + HTTP/3 fingerprint profile.
///
/// Stable fields are taken from the Chrome 150 Outlook captures: 8-byte Initial
/// DCID, QPACK capacity 65 536, 100 blocked streams, 103 unidirectional streams,
/// 65 536-byte DATAGRAM support, `version_information`, and
/// `google_connection_options=ORIG`. The reserved transport parameter is a
/// one-byte placeholder whose id and value are randomized per connection.
pub fn chrome_150_quic() -> QuicProfile {
    QuicProfile {
        transport_params: QuicTransportParams {
            max_idle_timeout: 30_000,
            max_udp_payload_size: Some(1472),
            initial_max_data: 15_728_640,
            initial_max_stream_data_bidi_local: 6_291_456,
            initial_max_stream_data_bidi_remote: 6_291_456,
            initial_max_stream_data_uni: 6_291_456,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 103,
            active_connection_id_limit: 2,
            max_datagram_frame_size: Some(65_536),
            send_min_ack_delay: false,
            send_reserved_transport_parameter: false,
            extra_transport_parameters: vec![
                (
                    0x11,
                    "000000019a9aca7a00000001".to_string(), // version_information
                ),
                (0x17af394a4ef8da0a, "00".to_string()), // one-byte GREASE placeholder
                (0x3128, "4f524947".to_string()),       // google_connection_options = ORIG
                (0x3127, "8009df94".to_string()),       // path-sensitive google_initial_rtt
            ],
            transport_parameter_order: vec![
                0x05,
                0x0f,
                0x04,
                0x20,
                0x06,
                0x09,
                0x3128,
                0x17af394a4ef8da0a,
                0x3127,
                0x01,
                0x03,
                0x07,
                0x08,
                0x11,
            ],
            grease_transport_params: false,
            shuffle_transport_parameters: true,
        },
        h3: chrome_150_h3(),
        connection_id_length: 0,
        initial_destination_connection_id_length: Some(8),
        packetization: QuicPacketizationProfile {
            initial_mtu: Some(1250),
            initial_datagram_size: Some(1250),
            disable_mtu_discovery: false,
            enable_segmentation_offload: false,
            enable_ecn: false,
            // The Chrome 150 report did not establish a stable CRYPTO/PADDING
            // fragmentation layout, so do not reuse Chrome 146's exact layout.
            initial_frame_layout: None,
        },
    }
}

/// Chrome 151 HTTP/3 fingerprint profile.
///
/// Captured from Chrome 151.0.7922.72 across Cloudflare and other public H3
/// origins. SETTINGS and navigation PRIORITY_UPDATE match Chrome 150.
pub fn chrome_151_h3() -> H3Profile {
    chrome_150_h3()
}

/// Chrome 151 QUIC + HTTP/3 fingerprint profile.
///
/// Public-site captures confirm the Chrome 150 transport/H3 stable fields: an
/// 8-byte Initial DCID, 1250-byte Initial datagram, 1472-byte UDP payload limit,
/// QPACK capacity 65 536, 100 blocked streams, 103 unidirectional streams, and
/// 65 536-byte DATAGRAM support. Path-, GREASE-, and RTT-dependent values remain
/// intentionally modelled by the existing Chrome transport profile.
pub fn chrome_151_quic() -> QuicProfile {
    let mut profile = chrome_150_quic();
    profile.h3 = chrome_151_h3();
    profile
}

pub fn firefox_h3() -> H3Profile {
    H3Profile {
        settings: vec![
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 65_536),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 20),
        ],
        grease_settings: false,
        pseudo_header_order: vec![
            PseudoHeaderId::Method,
            PseudoHeaderId::Path,
            PseudoHeaderId::Authority,
            PseudoHeaderId::Scheme,
        ],
        qpack_max_table_capacity: 65_536,
        qpack_blocked_streams: 20,
        max_field_section_size: None,
        priority_updates: vec![],
        // Firefox does not emit a control-stream GREASE frame.
        send_control_grease_frame: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_h3_preset_matches_expected_shape() {
        let profile = chrome_h3();
        assert_eq!(
            profile.settings[0],
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 65_536)
        );
        assert!(profile.grease_settings);
        assert_eq!(profile.pseudo_header_order[0], PseudoHeaderId::Method);
        assert_eq!(profile.max_field_section_size, Some(262_144));
        assert_eq!(profile.pseudo_header_order_token(), "masp");
        profile.validate().unwrap();
    }

    #[test]
    fn chrome_quic_roundtrips_through_json() {
        let profile = chrome_quic();
        let json = serde_json::to_string(&profile).unwrap();
        let decoded: QuicProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, profile);
        decoded.validate().unwrap();
    }

    #[test]
    fn firefox_h3_uses_firefox_header_order() {
        let profile = firefox_h3();
        assert_eq!(
            profile.pseudo_header_order,
            vec![
                PseudoHeaderId::Method,
                PseudoHeaderId::Path,
                PseudoHeaderId::Authority,
                PseudoHeaderId::Scheme,
            ]
        );
        assert!(!profile.grease_settings);
        profile.validate().unwrap();
    }

    #[test]
    fn chrome_146_quic_validates_and_roundtrips() {
        let profile = chrome_146_quic();
        profile.validate().unwrap();

        assert_eq!(profile.transport_params.max_idle_timeout, 30_000);
        assert_eq!(profile.transport_params.max_udp_payload_size, Some(1472));
        assert_eq!(profile.transport_params.initial_max_streams_uni, 103);
        assert_eq!(
            profile.transport_params.max_datagram_frame_size,
            Some(65_536)
        );
        assert!(!profile.transport_params.send_min_ack_delay);
        assert!(!profile.transport_params.send_reserved_transport_parameter);
        assert_eq!(
            profile.transport_params.extra_transport_parameters,
            vec![
                (0x11, "000000019a9aca7a00000001".to_string()),
                (0x17af394a4ef8da0a, String::new()),
                (0x3127, "8009df94".to_string())
            ]
        );
        assert_eq!(
            profile.transport_params.transport_parameter_order,
            vec![
                0x03,
                0x11,
                0x09,
                0x08,
                0x20,
                0x01,
                0x06,
                0x0f,
                0x04,
                0x17af394a4ef8da0a,
                0x3127,
                0x07,
                0x05,
            ]
        );
        assert!(!profile.transport_params.grease_transport_params);
        assert_eq!(profile.packetization.initial_mtu, Some(1250));
        assert_eq!(profile.packetization.initial_datagram_size, Some(1250));
        assert_eq!(profile.initial_destination_connection_id_length, Some(8));
        assert!(!profile.packetization.disable_mtu_discovery);
        assert!(!profile.packetization.enable_segmentation_offload);
        assert!(!profile.packetization.enable_ecn);
        let initial_layout = profile
            .packetization
            .initial_frame_layout
            .as_ref()
            .expect("chrome_146 should include observed Initial frame layout");
        assert_eq!(initial_layout.target_udp_payload_size, 1250);
        assert_eq!(initial_layout.packets.len(), 2);
        assert_eq!(initial_layout.packets[0].packet_number, 0);
        assert_eq!(initial_layout.packets[1].packet_number, 1);
        assert_eq!(
            initial_layout.packets[0].frames[0],
            InitialFrameElement::crypto(1099, 16)
        );
        assert!(initial_layout.packets[0]
            .frames
            .contains(&InitialFrameElement::padding(120)));
        assert!(initial_layout.packets[1]
            .frames
            .contains(&InitialFrameElement::padding(88)));

        assert_eq!(profile.h3.qpack_max_table_capacity, 65_536);
        assert_eq!(profile.h3.qpack_blocked_streams, 100);
        assert_eq!(profile.h3.max_field_section_size, Some(262_144));
        assert!(profile.h3.grease_settings);
        assert_eq!(profile.h3.pseudo_header_order_token(), "masp");

        let json = serde_json::to_string(&profile).unwrap();
        let decoded: QuicProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn chrome_150_quic_matches_captured_stable_fields() {
        let profile = chrome_150_quic();
        profile.validate().unwrap();

        assert_eq!(profile.transport_params.max_idle_timeout, 30_000);
        assert_eq!(profile.transport_params.max_udp_payload_size, Some(1472));
        assert_eq!(profile.transport_params.initial_max_streams_uni, 103);
        assert_eq!(
            profile.transport_params.max_datagram_frame_size,
            Some(65_536)
        );
        assert!(!profile.transport_params.send_min_ack_delay);
        assert_eq!(profile.initial_destination_connection_id_length, Some(8));
        assert_eq!(profile.packetization.initial_mtu, Some(1250));
        assert_eq!(profile.packetization.initial_datagram_size, Some(1250));
        assert!(profile.packetization.initial_frame_layout.is_none());
        assert_eq!(profile.h3.qpack_max_table_capacity, 65_536);
        assert_eq!(profile.h3.qpack_blocked_streams, 100);
        assert_eq!(profile.h3.priority_updates, vec![(0, "u=0, i".into())]);
        assert_eq!(
            profile.transport_params.extra_transport_parameters,
            vec![
                (0x11, "000000019a9aca7a00000001".to_string()),
                (0x17af394a4ef8da0a, "00".to_string()),
                (0x3128, "4f524947".to_string()),
                (0x3127, "8009df94".to_string()),
            ]
        );

        let json = serde_json::to_string(&profile).unwrap();
        let decoded: QuicProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn chrome_151_matches_public_h3_capture_stable_fields() {
        let profile = chrome_151_quic();

        assert_eq!(profile.transport_params.max_idle_timeout, 30_000);
        assert_eq!(profile.transport_params.max_udp_payload_size, Some(1472));
        assert_eq!(profile.transport_params.initial_max_data, 15_728_640);
        assert_eq!(profile.transport_params.initial_max_streams_bidi, 100);
        assert_eq!(profile.transport_params.initial_max_streams_uni, 103);
        assert_eq!(
            profile.transport_params.max_datagram_frame_size,
            Some(65_536)
        );
        assert_eq!(profile.initial_destination_connection_id_length, Some(8));
        assert_eq!(profile.packetization.initial_datagram_size, Some(1250));
        assert_eq!(profile.h3.settings, chrome_150_h3().settings);
        assert_eq!(profile.h3.priority_updates, vec![(0, "u=0, i".into())]);
    }

    #[test]
    fn chrome_150_is_independent_from_chrome_146() {
        let v146 = chrome_146_quic();
        let v150 = chrome_150_quic();

        assert_ne!(v146.h3.priority_updates, v150.h3.priority_updates);
        assert_ne!(
            v146.transport_params.extra_transport_parameters,
            v150.transport_params.extra_transport_parameters
        );
        assert!(v146.packetization.initial_frame_layout.is_some());
        assert!(v150.packetization.initial_frame_layout.is_none());
    }

    #[test]
    fn chrome_146_differs_from_generic_chrome() {
        let generic = chrome_quic();
        let v146 = chrome_146_quic();

        assert_eq!(
            generic.transport_params.max_idle_timeout,
            v146.transport_params.max_idle_timeout
        );
        assert_ne!(
            generic.transport_params.max_udp_payload_size,
            v146.transport_params.max_udp_payload_size
        );
        assert_ne!(
            generic.transport_params.initial_max_streams_uni,
            v146.transport_params.initial_max_streams_uni
        );
        assert_ne!(
            generic.transport_params.max_datagram_frame_size,
            v146.transport_params.max_datagram_frame_size
        );
        assert_eq!(
            generic.transport_params.grease_transport_params,
            v146.transport_params.grease_transport_params
        );
        assert_ne!(
            generic.transport_params.send_reserved_transport_parameter,
            v146.transport_params.send_reserved_transport_parameter
        );
        assert_ne!(
            generic.transport_params.transport_parameter_order,
            v146.transport_params.transport_parameter_order
        );
        assert_ne!(
            generic.transport_params.send_min_ack_delay,
            v146.transport_params.send_min_ack_delay
        );
        assert_ne!(
            generic.transport_params.extra_transport_parameters,
            v146.transport_params.extra_transport_parameters
        );
        assert_ne!(
            generic.initial_destination_connection_id_length,
            v146.initial_destination_connection_id_length
        );
        assert_ne!(
            generic.packetization.initial_mtu,
            v146.packetization.initial_mtu
        );
        assert_ne!(
            generic.packetization.initial_datagram_size,
            v146.packetization.initial_datagram_size
        );
        assert_ne!(
            generic.packetization.initial_frame_layout,
            v146.packetization.initial_frame_layout
        );

        // H3 SETTINGS remain identical; only priority_updates differs
        assert_eq!(generic.h3.settings, v146.h3.settings);
        assert_eq!(generic.h3.grease_settings, v146.h3.grease_settings);
        assert!(generic.h3.priority_updates.is_empty());
        assert_eq!(v146.h3.priority_updates, vec![(0, "u=1, i".to_string())]);
    }

    #[test]
    fn invalid_h3_profile_rejects_duplicate_pseudo_headers() {
        let mut profile = chrome_h3();
        profile.pseudo_header_order.push(PseudoHeaderId::Method);

        let error = profile.validate().unwrap_err();
        assert!(error.contains("duplicate"));
    }

    #[test]
    fn effective_settings_uses_individual_fields_as_source_of_truth() {
        let mut profile = chrome_h3();
        profile.qpack_blocked_streams = 99;

        let effective = profile.effective_settings();
        let blocked = effective
            .iter()
            .find(|(id, _)| *id == SETTINGS_QPACK_BLOCKED_STREAMS)
            .unwrap();
        assert_eq!(blocked.1, 99);
    }

    #[test]
    fn encode_h3_settings_for_alps_payload() {
        let profile = chrome_h3();

        assert_eq!(
            profile.encode_alps_h3_settings(),
            vec![
                0x01, 0x80, 0x01, 0x00, 0x00, 0x06, 0x80, 0x04, 0x00, 0x00, 0x07, 0x40, 0x64, 0x33,
                0x01,
            ]
        );
    }

    #[test]
    fn with_static_qpack_disables_dynamic_qpack() {
        let profile = chrome_h3().with_static_qpack();
        assert_eq!(profile.qpack_max_table_capacity, 0);
        assert_eq!(profile.qpack_blocked_streams, 0);

        let effective = profile.effective_settings();
        let table_cap = effective
            .iter()
            .find(|(id, _)| *id == SETTINGS_QPACK_MAX_TABLE_CAPACITY)
            .unwrap();
        let blocked = effective
            .iter()
            .find(|(id, _)| *id == SETTINGS_QPACK_BLOCKED_STREAMS)
            .unwrap();
        assert_eq!(table_cap.1, 0);
        assert_eq!(blocked.1, 0);
    }

    #[test]
    fn invalid_quic_profile_rejects_transport_constraints() {
        let mut profile = chrome_quic();
        profile.transport_params.max_udp_payload_size = Some(1199);

        let error = profile.validate().unwrap_err();
        assert!(error.contains("at least 1200"));

        profile.transport_params.max_udp_payload_size = Some(65_528);
        let error = profile.validate().unwrap_err();
        assert!(error.contains("at most 65527"));

        profile.transport_params.max_udp_payload_size = None;
        profile.transport_params.max_datagram_frame_size = Some(1_u64 << 62);
        let error = profile.validate().unwrap_err();
        assert!(error.contains("QUIC varint"));

        profile.transport_params.max_datagram_frame_size = None;
        profile.initial_destination_connection_id_length = Some(21);
        let error = profile.validate().unwrap_err();
        assert!(error.contains("initial_destination_connection_id_length"));

        profile.initial_destination_connection_id_length = None;
        profile.packetization.initial_mtu = Some(1199);
        let error = profile.validate().unwrap_err();
        assert!(error.contains("initial_mtu"));

        profile.packetization.initial_mtu = None;
        profile.packetization.initial_datagram_size = Some(1199);
        let error = profile.validate().unwrap_err();
        assert!(error.contains("initial_datagram_size"));

        profile.packetization.initial_datagram_size = None;
        profile.packetization.initial_frame_layout = Some(InitialFrameLayoutProfile {
            target_udp_payload_size: 1199,
            packets: vec![],
        });
        let error = profile.validate().unwrap_err();
        assert!(error.contains("target_udp_payload_size"));

        profile.packetization.initial_frame_layout = Some(InitialFrameLayoutProfile {
            target_udp_payload_size: 1250,
            packets: vec![InitialPacketLayoutProfile {
                packet_number: 0,
                frames: vec![],
            }],
        });
        let error = profile.validate().unwrap_err();
        assert!(error.contains("at least one frame"));

        profile.packetization.initial_frame_layout = Some(InitialFrameLayoutProfile {
            target_udp_payload_size: 1250,
            packets: vec![
                InitialPacketLayoutProfile {
                    packet_number: 0,
                    frames: vec![InitialFrameElement::padding(1)],
                },
                InitialPacketLayoutProfile {
                    packet_number: 0,
                    frames: vec![InitialFrameElement::Ping],
                },
            ],
        });
        let error = profile.validate().unwrap_err();
        assert!(error.contains("duplicate packet number"));

        profile.packetization.initial_frame_layout = Some(InitialFrameLayoutProfile {
            target_udp_payload_size: 1250,
            packets: vec![InitialPacketLayoutProfile {
                packet_number: 0,
                frames: vec![InitialFrameElement::padding(0)],
            }],
        });
        let error = profile.validate().unwrap_err();
        assert!(error.contains("non-zero"));

        profile.packetization.initial_frame_layout = None;
        profile.transport_params.extra_transport_parameters = vec![(0x01, "00".into())];
        let error = profile.validate().unwrap_err();
        assert!(error.contains("duplicates"));

        profile.transport_params.extra_transport_parameters = vec![(0x3127, "abc".into())];
        let error = profile.validate().unwrap_err();
        assert!(error.contains("even-length hex"));

        profile.transport_params.extra_transport_parameters = vec![(0x3127, "zz".into())];
        let error = profile.validate().unwrap_err();
        assert!(error.contains("value must be even-length hex"));

        profile.transport_params.extra_transport_parameters = vec![];
        profile.transport_params.transport_parameter_order = vec![0x03, 0x03];
        let error = profile.validate().unwrap_err();
        assert!(error.contains("order contains duplicate"));
    }

    #[test]
    fn pseudo_header_id_as_str_and_token_cover_all_variants() {
        for (id, name, token) in [
            (PseudoHeaderId::Method, ":method", 'm'),
            (PseudoHeaderId::Authority, ":authority", 'a'),
            (PseudoHeaderId::Scheme, ":scheme", 's'),
            (PseudoHeaderId::Path, ":path", 'p'),
            (PseudoHeaderId::Protocol, ":protocol", 'o'),
        ] {
            assert_eq!(id.as_str(), name);
            assert_eq!(id.token(), token);
        }
    }

    #[test]
    fn setting_value_finds_present_and_missing_ids() {
        let profile = chrome_h3();
        assert_eq!(
            profile.setting_value(SETTINGS_MAX_FIELD_SECTION_SIZE),
            Some(262_144)
        );
        assert_eq!(profile.setting_value(0x99), None); // not carried by this profile
    }

    #[test]
    fn encode_alps_free_function_matches_method() {
        let profile = chrome_h3();
        assert_eq!(
            encode_alps_h3_settings(&profile),
            profile.encode_alps_h3_settings()
        );
    }

    #[test]
    fn quic_varint_encodes_all_four_size_classes() {
        let mut out = Vec::new();
        encode_quic_varint(0x3f, &mut out); // 1-byte boundary
        assert_eq!(out, vec![0x3f]);

        out.clear();
        encode_quic_varint(0x3fff, &mut out); // 2-byte boundary
        assert_eq!(out, vec![0x7f, 0xff]);

        out.clear();
        encode_quic_varint(0x3fff_ffff, &mut out); // 4-byte boundary
        assert_eq!(out, vec![0xbf, 0xff, 0xff, 0xff]);

        out.clear();
        encode_quic_varint(0x3fff_ffff_ffff_ffff, &mut out); // 8-byte boundary
        assert_eq!(out, vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }
}
