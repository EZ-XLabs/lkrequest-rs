//! A-layer fingerprint regression gate (Tier-0, offline, no browser/network).
//!
//! For each Chrome preset this emits the **actual** wire bytes via `lktls`
//! (ClientHello) / `lkh2` (H2 connection preface), parses them, canonicalizes,
//! and compares against a committed golden. Any diff fails the build — catching
//! changes that alter the on-wire fingerprint, including serializer bugs
//! (the "A2" path: gate the real serialized bytes, not just the preset config).
//!
//! Regenerate goldens after an *intentional* fingerprint change:
//! ```text
//! UPDATE_FINGERPRINTS=1 cargo test -p lkrequest --test fingerprint_regression
//! ```

use std::fs;
use std::path::PathBuf;

use bytes::BytesMut;
use fpverify::{canonicalize_tls, diff_values, CanonicalTlsFingerprint, TlsShapeSpec};
use lkprofile::{h2_fingerprint_from_frames_no_preface, parse_client_hello};
use lktls::handshake::client_hello::ClientHelloBuilder;
use lktls::profile::types::TlsProfile;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fingerprints")
}

/// Compare `current` against the committed golden `<basename>.json`, or
/// (re)write it when `UPDATE_FINGERPRINTS` is set.
fn gate_value(basename: &str, current: serde_json::Value) {
    let dir = golden_dir();
    let path = dir.join(format!("{basename}.json"));

    if std::env::var_os("UPDATE_FINGERPRINTS").is_some() {
        fs::create_dir_all(&dir).expect("create golden dir");
        let json = serde_json::to_string_pretty(&current).expect("serialize golden");
        fs::write(&path, format!("{json}\n")).expect("write golden");
        return;
    }

    let golden_str = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing golden {path:?}; regenerate with UPDATE_FINGERPRINTS=1")
    });
    let golden: serde_json::Value = serde_json::from_str(&golden_str).expect("deserialize golden");

    let diffs = diff_values(&golden, &current);
    assert!(
        diffs.is_empty(),
        "fingerprint regression for `{basename}` \
         (if intended, regenerate with UPDATE_FINGERPRINTS=1):\n{}",
        diffs
            .iter()
            .map(|d| format!("  {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ── TLS ──────────────────────────────────────────────────────────────────────

/// Derive the TLS shape from the preset's randomization config.
fn tls_shape(profile: &TlsProfile) -> TlsShapeSpec {
    let shuffled = profile
        .randomization
        .as_ref()
        .map(|r| r.shuffle_extensions)
        .unwrap_or(false);
    if shuffled {
        // lktls pins only `pre_shared_key` (its `NON_SHUFFLEABLE_EXTENSIONS`).
        TlsShapeSpec::shuffled(vec![0x0029])
    } else {
        TlsShapeSpec::fixed_order()
    }
}

fn check_tls(browser: &str, profile: TlsProfile) {
    let out = ClientHelloBuilder::new(&profile, "example.com")
        .build()
        .expect("ClientHello build should succeed");
    let parsed = parse_client_hello(&out.message).expect("emitted ClientHello should parse");
    let canonical = CanonicalTlsFingerprint::from_parsed(&parsed);
    // Store/compare the shape-canonicalized form so goldens are deterministic
    // (per-connection GREASE + shuffle folded away).
    let comparable = canonicalize_tls(&canonical, &tls_shape(&profile));
    let value = serde_json::to_value(&comparable).expect("serialize canonical TLS");
    gate_value(&format!("{browser}_tls_fresh"), value);
}

// ── HTTP/2 ─────────────────────────────────────────────────────────────────

/// Emit the H2 connection preface (SETTINGS + WINDOW_UPDATE + PRIORITY) for the
/// profile, parse it back, and combine with the HEADERS-frame dimensions
/// (pseudo-header order, HEADERS priority) taken from the profile.
///
/// SETTINGS / WINDOW_UPDATE / PRIORITY are gated at the **wire level** (A2);
/// pseudo-header order + HEADERS priority are HEADERS-frame properties not
/// present in the preface, so they are gated from the profile config for now
/// (a follow-up can emit a HEADERS frame to gate them on the wire too).
fn h2_fingerprint_value(profile: &lkh2::profile::H2Profile) -> serde_json::Value {
    let (engine, preface) = lkh2::engine::H2Engine::client(profile);
    let mut buf = BytesMut::new();
    engine.encode_frames(&preface, &mut buf);
    let parsed =
        h2_fingerprint_from_frames_no_preface(&buf).expect("emitted H2 preface should parse");

    serde_json::json!({
        "settings": parsed.profile.settings,
        "window_update": parsed.profile.window_update,
        "priority_frames": parsed.profile.priority_frames,
        "pseudo_header_order": profile.pseudo_header_order,
        "headers_priority": profile.headers_priority,
    })
}

fn check_h2(browser: &str, profile: lkh2::profile::H2Profile) {
    gate_value(&format!("{browser}_h2"), h2_fingerprint_value(&profile));
}

// ── QUIC / HTTP-3 (feature-gated) ──────────────────────────────────────────
//
// Config-level for now: the fingerprint is derived from the `lkh3::QuicProfile`
// via `lkprofile::collect_quic_fingerprint` (mirrors profile_collector's
// `quic_fingerprint_from_profile`). This gates transport-parameter order/values,
// the transport hash, H3 SETTINGS, pseudo-header order, and packetization
// against changes to the preset. A future refinement can emit a real QUIC
// Initial + H3 control stream to gate the bytes at the wire level (A2).

#[cfg(feature = "quic-h3")]
fn quic_packetization(
    p: &lkh3::QuicPacketizationProfile,
) -> lkprofile::QuicPacketizationFingerprint {
    lkprofile::QuicPacketizationFingerprint {
        initial_mtu: p.initial_mtu,
        initial_datagram_size: p.initial_datagram_size,
        disable_mtu_discovery: p.disable_mtu_discovery,
        enable_segmentation_offload: p.enable_segmentation_offload,
        enable_ecn: p.enable_ecn,
        initial_frame_layout: p.initial_frame_layout.as_ref().map(|layout| {
            layout
                .packets
                .iter()
                .map(|packet| {
                    let frames = packet
                        .frames
                        .iter()
                        .map(|frame| match frame {
                            lkh3::InitialFrameElement::Crypto { offset, length } => {
                                format!("crypto@{offset}+{length}")
                            }
                            lkh3::InitialFrameElement::Padding { length } => {
                                format!("padding+{length}")
                            }
                            lkh3::InitialFrameElement::Ping => "ping".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("pn{}[{frames}]", packet.packet_number)
                })
                .collect::<Vec<_>>()
                .join("|")
        }),
    }
}

#[cfg(feature = "quic-h3")]
fn quic_fingerprint_value(profile: &lkh3::QuicProfile) -> serde_json::Value {
    let tp = &profile.transport_params;
    let mut transport_parameters = vec![
        ("max_idle_timeout".to_string(), tp.max_idle_timeout),
        ("initial_max_data".to_string(), tp.initial_max_data),
        (
            "initial_max_stream_data_bidi_local".to_string(),
            tp.initial_max_stream_data_bidi_local,
        ),
        (
            "initial_max_stream_data_bidi_remote".to_string(),
            tp.initial_max_stream_data_bidi_remote,
        ),
        (
            "initial_max_stream_data_uni".to_string(),
            tp.initial_max_stream_data_uni,
        ),
        (
            "initial_max_streams_bidi".to_string(),
            tp.initial_max_streams_bidi,
        ),
        (
            "initial_max_streams_uni".to_string(),
            tp.initial_max_streams_uni,
        ),
        (
            "active_connection_id_limit".to_string(),
            tp.active_connection_id_limit,
        ),
    ];
    if let Some(v) = tp.max_udp_payload_size {
        transport_parameters.push(("max_udp_payload_size".into(), v));
    }
    if let Some(v) = tp.max_datagram_frame_size {
        transport_parameters.push(("max_datagram_frame_size".into(), v));
    }

    let pseudo_header_order = profile
        .h3
        .pseudo_header_order
        .iter()
        .map(|id| match id {
            lkh3::PseudoHeaderId::Method => ":method",
            lkh3::PseudoHeaderId::Authority => ":authority",
            lkh3::PseudoHeaderId::Scheme => ":scheme",
            lkh3::PseudoHeaderId::Path => ":path",
            lkh3::PseudoHeaderId::Protocol => ":protocol",
        })
        .map(str::to_string)
        .collect::<Vec<_>>();

    let input = lkprofile::QuicFingerprintInput {
        transport_parameters,
        h3: lkprofile::H3FingerprintInput {
            settings: profile.h3.effective_settings(),
            pseudo_header_order,
            pseudo_header_order_token: profile.h3.pseudo_header_order_token(),
            grease_settings: profile.h3.grease_settings,
        },
        connection_id_length: profile.connection_id_length,
        initial_destination_connection_id_length: profile.initial_destination_connection_id_length,
        grease_transport_params: tp.grease_transport_params,
        send_min_ack_delay: tp.send_min_ack_delay,
        send_reserved_transport_parameter: tp.send_reserved_transport_parameter,
        extra_transport_parameters: tp.extra_transport_parameters.clone(),
        transport_parameter_order: tp.transport_parameter_order.clone(),
        packetization: quic_packetization(&profile.packetization),
    };
    let fp = lkprofile::collect_quic_fingerprint(&input);
    let mut value = serde_json::to_value(&fp).expect("serialize QUIC fingerprint");

    // Gate the H3 control-stream frame shape too: the default RFC 9218
    // PRIORITY_UPDATE frames and whether a reserved control-stream GREASE frame
    // is emitted. `collect_quic_fingerprint` does not carry these, so fold them
    // in from the profile — a regression that empties `priority_updates` or
    // flips `send_control_grease_frame` then fails offline (the wire-level test
    // in `quic_local_e2e.rs` is the on-wire counterpart).
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "priority_updates".into(),
            serde_json::json!(profile.h3.priority_updates),
        );
        obj.insert(
            "send_control_grease_frame".into(),
            serde_json::json!(profile.h3.send_control_grease_frame),
        );
    }
    value
}

#[cfg(feature = "quic-h3")]
fn check_quic(basename: &str, profile: lkh3::QuicProfile) {
    gate_value(basename, quic_fingerprint_value(&profile));
}

// ── QUIC/H3 0-RTT (resumed) ClientHello fingerprint ──────────────────────────
//
// Emits the resumed/0-RTT TLS ClientHello (with a session ticket seeded) and
// checks the resumption-specific structure: `early_data` (0x002a) present and
// `pre_shared_key` (0x0029) pinned LAST (RFC 8446 §4.2.11), with the rest of the
// fingerprint identical to the fresh ClientHello. Also locks it as a golden.
// (The PSK extension payload carries a wall-clock-dependent obfuscated ticket
// age + binder, so the canonical only fingerprints its presence/position.)

#[cfg(feature = "quic-h3")]
fn synthetic_h3_ticket() -> lktls::session_store::SessionTicketData {
    lktls::session_store::SessionTicketData {
        ticket: vec![1, 2, 3, 4],
        resumption_psk: vec![0xAB; 32],
        tls_version: lktls::session_store::TicketTlsVersion::Tls13,
        cipher_suite: 0x1301,
        lifetime_secs: 3600,
        age_add: 0,
        received_at: std::time::Instant::now(),
        alpn: None, // None bypasses the ALPN-compatibility check in the resumption path
        hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
        aead_algorithm: lktls::crypto::aead::AeadAlgorithm::Aes128Gcm,
        master_secret: Vec::new(),
        max_early_data_size: 16_384, // > 0 → early_data extension is added
        peer_transport_parameters: Some(vec![0x01, 0x00]),
    }
}

#[cfg(feature = "quic-h3")]
fn emit_quic_client_hello(
    store: std::sync::Arc<dyn lktls::session_store::SessionStore>,
) -> CanonicalTlsFingerprint {
    let mut profile = lktls::profile::presets::chrome_146_quic();
    profile.session_resumption.tls13_psk = true;
    let config = lktls_quic::LktlsQuicClientConfig::new(profile)
        .session_store(store)
        .port(443);
    let bytes = config
        .emit_initial_client_hello("localhost", Vec::new())
        .expect("emit QUIC ClientHello");
    let parsed = parse_client_hello(&bytes).expect("parse QUIC ClientHello");
    CanonicalTlsFingerprint::from_parsed(&parsed)
}

#[cfg(feature = "quic-h3")]
#[test]
fn chrome_146_quic_tls_resumed() {
    use lktls::session_store::{InMemorySessionStore, SessionStore};
    use std::sync::Arc;

    let fresh = emit_quic_client_hello(Arc::new(InMemorySessionStore::new()));

    let store = Arc::new(InMemorySessionStore::new());
    store.store("localhost:443", synthetic_h3_ticket());
    let resumed = emit_quic_client_hello(store);

    let types = |fp: &CanonicalTlsFingerprint| -> Vec<u16> {
        fp.extensions.iter().map(|e| e.extension_type).collect()
    };
    let fresh_types = types(&fresh);
    let resumed_types = types(&resumed);

    // Fresh must NOT carry the resumption extensions.
    assert!(
        !fresh_types.contains(&0x0029) && !fresh_types.contains(&0x002a),
        "fresh ClientHello must not carry PSK/early_data; got {fresh_types:#06x?}"
    );
    // Resumed must carry early_data (0x002a) ...
    assert!(
        resumed_types.contains(&0x002a),
        "resumed ClientHello must carry early_data (0x002a); got {resumed_types:#06x?}"
    );
    // ... and pre_shared_key (0x0029) MUST be the last extension (RFC 8446 §4.2.11).
    assert_eq!(
        resumed_types.last(),
        Some(&0x0029),
        "pre_shared_key (0x0029) must be the last extension; got {resumed_types:#06x?}"
    );
    // Resumption is purely additive: the base extension set equals the fresh set
    // (compared as a set — the profile shuffles extension order per connection).
    let mut base: Vec<u16> = resumed_types
        .iter()
        .copied()
        .filter(|t| *t != 0x0029 && *t != 0x002a)
        .collect();
    let mut fresh_set = fresh_types.clone();
    base.sort_unstable();
    fresh_set.sort_unstable();
    assert_eq!(
        base, fresh_set,
        "resumed base extensions must equal the fresh set (resumption is additive)"
    );

    // Lock the resumed-mode fingerprint as a golden.
    let shape = tls_shape(&lktls::profile::presets::chrome_146_quic());
    let comparable = canonicalize_tls(&resumed, &shape);
    gate_value(
        "chrome_146_quic_tls_resumed",
        serde_json::to_value(&comparable).expect("serialize resumed canonical"),
    );
}

// ── Test registry ────────────────────────────────────────────────────────────

macro_rules! tls_gate {
    ($($name:ident => $preset:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                check_tls(stringify!($name), $preset);
            }
        )+
    };
}

macro_rules! h2_gate {
    ($($name:ident => $browser:literal => $preset:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                check_h2($browser, $preset);
            }
        )+
    };
}

#[cfg(feature = "quic-h3")]
macro_rules! quic_gate {
    ($($name:ident => $basename:literal => $preset:expr),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                check_quic($basename, $preset);
            }
        )+
    };
}

tls_gate! {
    chrome_131 => lktls::profile::presets::chrome_131(),
    chrome_144 => lktls::profile::presets::chrome_144(),
    chrome_145 => lktls::profile::presets::chrome_145(),
    chrome_146 => lktls::profile::presets::chrome_146(),
    chrome_147 => lktls::profile::presets::chrome_147(),
    chrome_148 => lktls::profile::presets::chrome_148(),
}

h2_gate! {
    chrome_131_h2 => "chrome_131" => lkh2::profile::chrome_131_h2(),
    chrome_144_h2 => "chrome_144" => lkh2::profile::chrome_144_h2(),
    chrome_145_h2 => "chrome_145" => lkh2::profile::chrome_145_h2(),
    chrome_146_h2 => "chrome_146" => lkh2::profile::chrome_146_h2(),
    chrome_147_h2 => "chrome_147" => lkh2::profile::chrome_147_h2(),
    chrome_148_h2 => "chrome_148" => lkh2::profile::chrome_148_h2(),
}

#[cfg(feature = "quic-h3")]
quic_gate! {
    chrome_146_quic => "chrome_146_quic" => lkh3::chrome_146_quic(),
    chrome_generic_quic => "chrome_generic_quic" => lkh3::chrome_quic(),
}
