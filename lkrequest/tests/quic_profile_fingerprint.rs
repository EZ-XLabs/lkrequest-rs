use lkprofile::{
    collect_quic_fingerprint, compare_collected_fingerprints, CollectedFingerprint,
    H3FingerprintInput, QuicFingerprintInput, QuicPacketizationFingerprint,
};

fn quic_input(profile: &lkh3::QuicProfile) -> QuicFingerprintInput {
    let mut transport_parameters = vec![(
        "max_idle_timeout".into(),
        profile.transport_params.max_idle_timeout,
    )];
    if let Some(max_udp_payload_size) = profile.transport_params.max_udp_payload_size {
        transport_parameters.push(("max_udp_payload_size".into(), max_udp_payload_size));
    }
    transport_parameters.extend([
        (
            "initial_max_data".into(),
            profile.transport_params.initial_max_data,
        ),
        (
            "initial_max_stream_data_bidi_local".into(),
            profile.transport_params.initial_max_stream_data_bidi_local,
        ),
        (
            "initial_max_stream_data_bidi_remote".into(),
            profile.transport_params.initial_max_stream_data_bidi_remote,
        ),
        (
            "initial_max_stream_data_uni".into(),
            profile.transport_params.initial_max_stream_data_uni,
        ),
        (
            "initial_max_streams_bidi".into(),
            profile.transport_params.initial_max_streams_bidi,
        ),
        (
            "initial_max_streams_uni".into(),
            profile.transport_params.initial_max_streams_uni,
        ),
        (
            "active_connection_id_limit".into(),
            profile.transport_params.active_connection_id_limit,
        ),
    ]);

    QuicFingerprintInput {
        transport_parameters,
        h3: H3FingerprintInput {
            settings: profile.h3.settings.clone(),
            pseudo_header_order: profile
                .h3
                .pseudo_header_order
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            pseudo_header_order_token: profile.h3.pseudo_header_order_token(),
            grease_settings: profile.h3.grease_settings,
        },
        connection_id_length: profile.connection_id_length,
        initial_destination_connection_id_length: profile.initial_destination_connection_id_length,
        grease_transport_params: profile.transport_params.grease_transport_params,
        send_min_ack_delay: profile.transport_params.send_min_ack_delay,
        send_reserved_transport_parameter: profile
            .transport_params
            .send_reserved_transport_parameter,
        extra_transport_parameters: profile.transport_params.extra_transport_parameters.clone(),
        transport_parameter_order: profile.transport_params.transport_parameter_order.clone(),
        packetization: QuicPacketizationFingerprint {
            initial_mtu: profile.packetization.initial_mtu,
            initial_datagram_size: profile.packetization.initial_datagram_size,
            disable_mtu_discovery: profile.packetization.disable_mtu_discovery,
            enable_segmentation_offload: profile.packetization.enable_segmentation_offload,
            enable_ecn: profile.packetization.enable_ecn,
            initial_frame_layout: profile
                .packetization
                .initial_frame_layout
                .as_ref()
                .map(initial_frame_layout_fingerprint),
        },
    }
}

fn initial_frame_layout_fingerprint(layout: &lkh3::InitialFrameLayoutProfile) -> String {
    let packets = layout
        .packets
        .iter()
        .map(|packet| {
            let frames = packet
                .frames
                .iter()
                .map(|frame| match *frame {
                    lkh3::InitialFrameElement::Crypto { offset, length } => {
                        format!("crypto@{offset}+{length}")
                    }
                    lkh3::InitialFrameElement::Padding { length } => {
                        format!("pad+{length}")
                    }
                    lkh3::InitialFrameElement::Ping => "ping".to_string(),
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("pn={}:{}", packet.packet_number, frames)
        })
        .collect::<Vec<_>>()
        .join("|");
    format!("target={};{}", layout.target_udp_payload_size, packets)
}

#[test]
fn explicit_quic_profile_matches_chrome_reference() {
    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .build();

    let expected = CollectedFingerprint::default()
        .with_quic(collect_quic_fingerprint(&quic_input(&lkh3::chrome_quic())));
    let configured =
        CollectedFingerprint::default().with_quic(collect_quic_fingerprint(&quic_input(
            client
                .quic_profile()
                .expect("client with explicit quic_profile should have QUIC profile"),
        )));
    let comparison = compare_collected_fingerprints(&expected, &configured);

    assert!(
        comparison.is_match(),
        "explicit QUIC profile drifted from chrome reference: {comparison:?}"
    );
}

#[test]
fn default_client_has_no_quic_profile() {
    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .build();

    assert!(
        client.quic_profile().is_none(),
        "default client should not have a QUIC profile unless explicitly set"
    );
}

#[test]
fn comparison_detects_quic_profile_drift() {
    let mut modified = lkh3::chrome_quic();
    modified.connection_id_length = 12;
    modified.initial_destination_connection_id_length = Some(8);
    modified.h3.grease_settings = false;
    modified.packetization.initial_mtu = Some(1250);
    modified.packetization.initial_datagram_size = Some(1250);
    modified.packetization.initial_frame_layout = Some(lkh3::InitialFrameLayoutProfile {
        target_udp_payload_size: 1250,
        packets: vec![lkh3::InitialPacketLayoutProfile {
            packet_number: 0,
            frames: vec![
                lkh3::InitialFrameElement::crypto(0, 16),
                lkh3::InitialFrameElement::Ping,
            ],
        }],
    });
    modified.transport_params.send_min_ack_delay = false;
    modified.transport_params.send_reserved_transport_parameter = false;
    modified.transport_params.extra_transport_parameters = vec![(0x3127, "8009df94".to_string())];
    modified.transport_params.transport_parameter_order = vec![0x03, 0x3127];

    let left = CollectedFingerprint::default()
        .with_quic(collect_quic_fingerprint(&quic_input(&lkh3::chrome_quic())));
    let right =
        CollectedFingerprint::default().with_quic(collect_quic_fingerprint(&quic_input(&modified)));
    let comparison = compare_collected_fingerprints(&left, &right);

    assert!(!comparison.is_match());
    assert!(comparison
        .fields
        .iter()
        .any(|field| field.field == "quic.connection_id_length"));
    assert!(comparison
        .fields
        .iter()
        .any(|field| field.field == "quic.packetization_hash"));
    assert!(comparison
        .fields
        .iter()
        .any(|field| field.field == "quic.extra_transport_parameters"));
    assert!(comparison
        .fields
        .iter()
        .any(|field| field.field == "quic.transport_parameter_order"));
}
