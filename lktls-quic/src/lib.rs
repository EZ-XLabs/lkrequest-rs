//! `lktls-quic` — bridge between `lktls`'s byte-exact TLS engine and `quinn`.
//!
//! QUIC carries TLS 1.3 inside its own transport, so a QUIC client must send the
//! *same* browser-exact `ClientHello` and run the same TLS 1.3 key schedule that
//! `lktls` produces for TCP TLS — otherwise the QUIC handshake fingerprint
//! diverges from the TCP one. This crate implements `quinn-proto`'s crypto
//! traits (`Session`, `PacketKey`, `HeaderKey`, `KeyPair`, …) on top of `lktls`,
//! so `quinn` drives an `lktls` [`TlsProfile`] instead of its default rustls
//! backend.
//!
//! The entry point is `LktlsQuicClientConfig`: given a `TlsProfile` (and an
//! optional [`SessionStore`] for TLS
//! resumption / 0-RTT), it produces the QUIC client crypto configuration
//! `quinn` needs. It also exposes `emit_initial_client_hello` so offline
//! fingerprint-regression tests can gate the QUIC `ClientHello` bytes without a
//! network.

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::Arc;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aws_lc_rs::digest;
use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::hkdf::{hkdf_expand_label, hkdf_extract};
use lktls::crypto::quic::{
    derive_initial_keys, derive_packet_keys, PacketKeys as LktlsPacketKeys, Side as LktlsSide,
};
use lktls::error::TlsError;
use lktls::extensions::quic_transport_params::encode_transport_params;
use lktls::handshake::driver::{
    HandshakeConfig, PostHandshakeState, QuicHandshakeConfig, QuicHandshakeDriver,
    QuicHandshakeOutput, QuicTrafficSecrets, SessionTicketContext,
};
use lktls::profile::types::TlsProfile;
use lktls::session_store::{SessionStore, SessionTicketData, TicketTlsVersion};
use lktls::verify::policy::VerificationPolicy;
use quinn::ClientConfig as QuinnClientConfig;
use quinn_proto::crypto::{
    self, ClientConfig as ProtoClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey,
    KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};

/// Minimal handshake metadata exposed through `quinn::Connection::handshake_data()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeData {
    pub protocol: Option<Vec<u8>>,
    pub cipher_suite: Option<u16>,
}

/// Builder-style client crypto configuration backed by `lktls`.
#[derive(Clone)]
pub struct LktlsQuicClientConfig {
    handshake: HandshakeConfig,
    port: u16,
}

impl LktlsQuicClientConfig {
    pub fn new(profile: TlsProfile) -> Self {
        Self {
            handshake: HandshakeConfig {
                profile,
                hostname: String::new(),
                port: 443,
                verification_policy: VerificationPolicy::default(),
                alps_payload: None,
                session_store: None,
                ech_config_list: None,
                custom_ca_anchors: None,
                keylog_callback: None,
            },
            port: 443,
        }
    }

    pub fn profile(&self) -> &TlsProfile {
        &self.handshake.profile
    }

    pub fn alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        self.handshake.profile.alpn_protocols = protocols;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self.handshake.port = port;
        self
    }

    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        self.handshake.verification_policy = policy;
        self
    }

    pub fn alps_payload(mut self, payload: Vec<u8>) -> Self {
        self.handshake.alps_payload = Some(payload);
        self
    }

    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.handshake.session_store = Some(store);
        self
    }

    pub fn custom_ca_anchors(
        mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) -> Self {
        self.handshake.custom_ca_anchors = Some(anchors);
        self
    }

    pub fn ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.handshake.ech_config_list = Some(config_list);
        self
    }

    pub fn keylog(mut self, callback: lktls::KeyLogCallback) -> Self {
        self.handshake.keylog_callback = Some(callback);
        self
    }

    pub fn into_quinn(self) -> QuinnClientConfig {
        QuinnClientConfig::new(Arc::new(self))
    }

    /// Emit the initial QUIC ClientHello bytes for `server_name`.
    ///
    /// When the configured session store holds a TLS 1.3 ticket for
    /// `server_name:port` (and the profile enables PSK resumption), the returned
    /// ClientHello is a resumed/0-RTT one — it carries the `pre_shared_key`
    /// extension as the last extension and, when the ticket permits early data,
    /// the `early_data` extension. `transport_params` is the encoded QUIC
    /// transport-parameters payload to embed (it does not affect the TLS
    /// extension structure, so tests may pass an arbitrary/empty value).
    ///
    /// Primarily a diagnostic / fingerprint-inspection entry point that bypasses
    /// quinn's `TransportParameters`; the regular path is via
    /// [`quinn_proto::crypto::ClientConfig::start_session`].
    pub fn emit_initial_client_hello(
        &self,
        server_name: &str,
        transport_params: Vec<u8>,
    ) -> Result<Vec<u8>, TlsError> {
        let mut handshake = self.handshake.clone();
        handshake.hostname = server_name.to_string();
        handshake.port = self.port;
        let quic_config = handshake.into_quic(transport_params);
        let mut driver = QuicHandshakeDriver::new(quic_config);
        driver.start()
    }
}

impl ProtoClientConfig for LktlsQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        ensure_supported_version(version)?;

        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);

        let mut handshake = self.handshake.clone();
        handshake.hostname = server_name.to_string();
        handshake.port = self.port;
        let host_key = format!("{}:{}", server_name, self.port);
        let resumed_ticket = handshake
            .session_store
            .as_ref()
            .and_then(|store| store.take(&host_key));
        if let Some(ticket) = resumed_ticket.clone() {
            handshake.session_store = Some(Arc::new(SeededSessionStore::new(
                ticket,
                self.handshake.session_store.clone(),
            )));
        }
        let quic_config: QuicHandshakeConfig = handshake.into_quic(transport_parameters);

        let mut driver = QuicHandshakeDriver::new(quic_config);
        let initial_output = driver
            .start()
            .map_err(|e| map_tls_start_error(server_name, e))?;

        let zero_rtt = resumed_ticket
            .as_ref()
            .filter(|ticket| {
                ticket.tls_version == TicketTlsVersion::Tls13
                    && ticket.max_early_data_size > 0
                    && ticket.peer_transport_parameters.is_some()
            })
            .and_then(|ticket| derive_early_crypto(ticket, &initial_output).ok());

        tracing::debug!(
            server_name = %server_name,
            version = format_args!("{version:#x}"),
            resumed = resumed_ticket.is_some(),
            zero_rtt = zero_rtt.is_some(),
            transport_params_len = initial_output.len(),
            "quic.tls_session_started"
        );

        let mut pending_output = VecDeque::new();
        pending_output.push_back(initial_output);

        Ok(Box::new(LktlsQuicSession {
            side: Side::Client,
            driver,
            pending_output,
            pending_keys: VecDeque::new(),
            handshake_data: None,
            peer_transport_parameters: resumed_ticket
                .as_ref()
                .and_then(|ticket| ticket.peer_transport_parameters.clone()),
            post_handshake: None,
            session_ticket_ctx: None,
            post_handshake_buf: Vec::new(),
            established: false,
            zero_rtt,
        }))
    }
}

struct LktlsQuicSession {
    side: Side,
    driver: QuicHandshakeDriver,
    pending_output: VecDeque<Vec<u8>>,
    pending_keys: VecDeque<Keys>,
    handshake_data: Option<HandshakeData>,
    peer_transport_parameters: Option<Vec<u8>>,
    post_handshake: Option<PostHandshakeState>,
    session_ticket_ctx: Option<SessionTicketContext>,
    /// Buffers post-handshake CRYPTO bytes that did not yet form a complete
    /// handshake message. quinn delivers CRYPTO stream data in arbitrarily
    /// split chunks, so a NewSessionTicket can straddle two `read_handshake`
    /// calls; without this accumulator the trailing fragment would be dropped
    /// and the ticket lost (no resumption / 0-RTT).
    post_handshake_buf: Vec<u8>,
    established: bool,
    zero_rtt: Option<ZeroRttState>,
}

impl Session for LktlsQuicSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        let side = match side {
            Side::Client => LktlsSide::Client,
            Side::Server => LktlsSide::Server,
        };
        let keys =
            derive_initial_keys(dst_cid, side).expect("initial key derivation should not fail");
        keys_from_derived(keys)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.handshake_data
            .as_ref()
            .cloned()
            .map(|data| Box::new(data) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.zero_rtt.as_ref().map(|zero_rtt| {
            (
                Box::new(LktlsHeaderProtectionKey::new(
                    &zero_rtt.keys.hp_key,
                    zero_rtt.aead_algorithm,
                )) as Box<dyn HeaderKey>,
                Box::new(packet_key_from_derived(
                    zero_rtt.keys.clone(),
                    zero_rtt.aead_algorithm,
                )) as Box<dyn PacketKey>,
            )
        })
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.zero_rtt.as_ref().map(|zero_rtt| zero_rtt.accepted)
    }

    fn is_handshaking(&self) -> bool {
        !self.established
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if self.established {
            // Borrows `session_ticket_ctx` and `post_handshake_buf` as disjoint
            // fields of `self`, so the immutable ctx borrow coexists with the
            // mutable buffer borrows.
            if let Some(ctx) = self.session_ticket_ctx.as_ref() {
                self.post_handshake_buf.extend_from_slice(buf);
                let consumed = process_post_handshake_messages(&self.post_handshake_buf, ctx);
                // Retain any trailing partial message for the next call.
                self.post_handshake_buf.drain(..consumed);
                // Bound the accumulator. A legitimate NewSessionTicket is small
                // (its fields are u16-bounded). A large *unconsumed* remainder
                // means the peer declared a 24-bit message length it never
                // completes; drop it rather than let a misbehaving server grow
                // this buffer without bound.
                const MAX_POST_HANDSHAKE_BUF: usize = 256 * 1024;
                if self.post_handshake_buf.len() > MAX_POST_HANDSHAKE_BUF {
                    tracing::warn!(
                        buffered = self.post_handshake_buf.len(),
                        "quic.post_handshake_buffer_overflow_discarded"
                    );
                    self.post_handshake_buf.clear();
                }
            }
            return Ok(false);
        }

        tracing::trace!(bytes = buf.len(), "quic.tls_handshake_input");
        self.driver.feed(buf);

        loop {
            match self.driver.progress().map_err(map_tls_error)? {
                QuicHandshakeOutput::SendData(data) => {
                    tracing::trace!(bytes = data.len(), "quic.tls_send_data");
                    self.pending_output.push_back(data);
                }
                QuicHandshakeOutput::NeedData => return Ok(false),
                QuicHandshakeOutput::HandshakeSecretsReady { to_send, secrets } => {
                    if !to_send.is_empty() {
                        tracing::trace!(bytes = to_send.len(), "quic.tls_send_handshake_flight");
                        self.pending_output.push_back(to_send);
                    }
                    tracing::debug!(
                        aead = ?secrets.aead_algorithm,
                        hkdf = ?secrets.hkdf_algorithm,
                        "quic.tls_handshake_secrets_ready"
                    );
                    self.pending_keys
                        .push_back(keys_from_secrets(&secrets, self.side));
                    return Ok(false);
                }
                QuicHandshakeOutput::Done { to_send, result } => {
                    if !to_send.is_empty() {
                        tracing::trace!(bytes = to_send.len(), "quic.tls_send_finished_flight");
                        self.pending_output.push_back(to_send);
                    }
                    self.pending_keys
                        .push_back(keys_from_secrets(&result.app_secrets, self.side));
                    self.handshake_data = Some(HandshakeData {
                        protocol: result.negotiated_alpn.clone().map(|s| s.into_bytes()),
                        cipher_suite: result.negotiated_cipher_suite,
                    });
                    self.peer_transport_parameters = result
                        .peer_transport_params
                        .as_ref()
                        .map(encode_transport_params);
                    self.post_handshake = result.post_handshake;
                    self.session_ticket_ctx = result.session_ticket_ctx;
                    if let Some(ref mut zero_rtt) = self.zero_rtt {
                        zero_rtt.accepted = result.early_data_accepted;
                    }
                    tracing::debug!(
                        alpn = ?self.handshake_data.as_ref().and_then(|data| data.protocol.as_ref()),
                        cipher_suite = ?self.handshake_data.as_ref().and_then(|data| data.cipher_suite),
                        early_data_accepted = result.early_data_accepted,
                        peer_transport_params = self.peer_transport_parameters.is_some(),
                        "quic.tls_handshake_complete"
                    );
                    self.established = true;
                    return Ok(true);
                }
            }
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let Some(bytes) = self.peer_transport_parameters.as_ref() else {
            return Ok(None);
        };

        let mut cursor = io::Cursor::new(bytes.as_slice());
        TransportParameters::read(self.side, &mut cursor)
            .map(Some)
            .map_err(Into::into)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        while let Some(chunk) = self.pending_output.pop_front() {
            buf.extend_from_slice(&chunk);
        }
        self.pending_keys.pop_front()
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let post = self.post_handshake.as_mut()?;
        let hkdf = post.hkdf_algorithm;
        let aead = post.aead_algorithm;

        // QUIC redefines the key-update label as "quic ku" (RFC 9001 §6.1).
        // This is distinct from the TLS-1.3-over-TCP KeyUpdate label
        // ("traffic upd", RFC 8446 §7.2) used on the TCP path; using the TCP
        // label here would derive keys the peer cannot decrypt.
        let next_local_secret = hkdf_expand_label(
            hkdf,
            &post.client_app_secret,
            "quic ku",
            &[],
            hkdf.hash_len(),
        )
        .ok()?;
        let next_remote_secret = hkdf_expand_label(
            hkdf,
            &post.server_app_secret,
            "quic ku",
            &[],
            hkdf.hash_len(),
        )
        .ok()?;

        let local = packet_key_from_derived(
            derive_packet_keys(&next_local_secret, hkdf, aead).ok()?,
            aead,
        );
        let remote = packet_key_from_derived(
            derive_packet_keys(&next_remote_secret, hkdf, aead).ok()?,
            aead,
        );

        post.client_app_secret = next_local_secret;
        post.server_app_secret = next_remote_secret;

        Some(KeyPair {
            local: Box::new(local),
            remote: Box::new(remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        // RFC 9001 §5.8: verify the Retry Integrity Tag (the trailing 16 bytes
        // of the Retry packet) with AEAD_AES_128_GCM over the Retry pseudo-
        // packet, using QUIC v1's fixed key/nonce. Chrome speaks QUIC v1, so
        // only the v1 constants are needed.
        const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
            0xc8, 0x4e,
        ];
        const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
        ];

        let Some(tag_start) = payload.len().checked_sub(16) else {
            return false;
        };

        // Retry pseudo-packet = ODCID length || ODCID || Retry header || Retry
        // body. The last 16 bytes of the body are the integrity tag; everything
        // before it is the AEAD associated data.
        let mut pseudo_packet =
            Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + payload.len());
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let Ok(unbound) = aws_lc_rs::aead::UnboundKey::new(
            &aws_lc_rs::aead::AES_128_GCM,
            &RETRY_INTEGRITY_KEY_V1,
        ) else {
            return false;
        };
        let key = aws_lc_rs::aead::LessSafeKey::new(unbound);
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aws_lc_rs::aead::Aad::from(aad), tag)
            .is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // RFC 8446 §7.5 TLS-Exporter:
        //   secret0 = Derive-Secret(exporter_master_secret, label, "")
        //           = HKDF-Expand-Label(ems, label, Hash(""), Hash.length)
        //   output  = HKDF-Expand-Label(secret0, "exporter", Hash(context), len)
        // Only valid once the handshake has produced the exporter master secret.
        let post = self
            .post_handshake
            .as_ref()
            .ok_or(ExportKeyingMaterialError)?;
        let hkdf = post.hkdf_algorithm;
        // TLS exporter labels are ASCII; lktls' HKDF-Expand-Label takes a &str.
        let label = std::str::from_utf8(label).map_err(|_| ExportKeyingMaterialError)?;
        // HKDF-Expand-Label prefixes "tls13 " and encodes the label length in a
        // single byte (RFC 8446 opaque label<7..255>). Reject labels that would
        // overflow that byte rather than silently derive wrong key material.
        if "tls13 ".len() + label.len() > 255 {
            return Err(ExportKeyingMaterialError);
        }

        let empty_hash = hash_for_hkdf(hkdf, &[]);
        let secret0 = hkdf_expand_label(
            hkdf,
            &post.exporter_master_secret,
            label,
            &empty_hash,
            hkdf.hash_len(),
        )
        .map_err(|_| ExportKeyingMaterialError)?;

        let context_hash = hash_for_hkdf(hkdf, context);
        let derived = hkdf_expand_label(hkdf, &secret0, "exporter", &context_hash, output.len())
            .map_err(|_| ExportKeyingMaterialError)?;
        output.copy_from_slice(&derived);
        Ok(())
    }
}

struct LktlsPacketKey {
    aead: Aead,
    algorithm: AeadAlgorithm,
}

impl crypto::PacketKey for LktlsPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let payload_len = buf.len().saturating_sub(header_len + self.tag_len());
        let aad = &buf[..header_len];
        let plaintext = buf[header_len..header_len + payload_len].to_vec();
        let ciphertext = self
            .aead
            .encrypt(packet, aad, &plaintext)
            .expect("packet encryption must succeed");
        buf[header_len..header_len + ciphertext.len()].copy_from_slice(&ciphertext);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plaintext = self
            .aead
            .decrypt(packet, header, payload.as_ref())
            .map_err(|_| CryptoError)?;
        payload.clear();
        payload.extend_from_slice(&plaintext);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        match self.algorithm {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 1u64 << 23,
            AeadAlgorithm::Chacha20Poly1305 => 1u64 << 62,
        }
    }

    fn integrity_limit(&self) -> u64 {
        match self.algorithm {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 1u64 << 52,
            AeadAlgorithm::Chacha20Poly1305 => 1u64 << 36,
        }
    }
}

enum HpCipher {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
    ChaCha20([u8; 32]),
}

struct LktlsHeaderProtectionKey {
    cipher: HpCipher,
}

impl LktlsHeaderProtectionKey {
    fn new(key: &[u8], algorithm: AeadAlgorithm) -> Self {
        let cipher = match algorithm {
            AeadAlgorithm::Aes128Gcm => {
                HpCipher::Aes128(Box::new(aes::Aes128::new(GenericArray::from_slice(key))))
            }
            AeadAlgorithm::Aes256Gcm => {
                HpCipher::Aes256(Box::new(aes::Aes256::new(GenericArray::from_slice(key))))
            }
            AeadAlgorithm::Chacha20Poly1305 => {
                let mut hp_key = [0u8; 32];
                hp_key.copy_from_slice(key);
                HpCipher::ChaCha20(hp_key)
            }
        };
        Self { cipher }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        match &self.cipher {
            HpCipher::Aes128(cipher) => {
                let mut block = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                [block[0], block[1], block[2], block[3], block[4]]
            }
            HpCipher::Aes256(cipher) => {
                let mut block = GenericArray::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                [block[0], block[1], block[2], block[3], block[4]]
            }
            HpCipher::ChaCha20(key) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce = GenericArray::from_slice(&sample[4..16]);
                let key = GenericArray::from_slice(key);
                let mut cipher = ChaCha20::new(key, nonce);
                cipher.seek(u64::from(counter) * 64);
                let mut mask = [0u8; 5];
                cipher.apply_keystream(&mut mask);
                mask
            }
        }
    }
}

impl crypto::HeaderKey for LktlsHeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mask = self.mask(sample);
        let bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        packet[0] ^= mask[0] & bits;
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        for idx in 0..pn_len {
            packet[pn_offset + idx] ^= mask[idx + 1];
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mask = self.mask(sample);
        let bits = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        let pn_len = ((packet[0] & 0x03) + 1) as usize;
        packet[0] ^= mask[0] & bits;
        for idx in 0..pn_len {
            packet[pn_offset + idx] ^= mask[idx + 1];
        }
    }

    fn sample_size(&self) -> usize {
        16
    }
}

fn keys_from_derived(keys: lktls::crypto::quic::QuicKeys) -> Keys {
    let local_header = Box::new(LktlsHeaderProtectionKey::new(
        &keys.local.hp_key,
        keys.aead_algorithm,
    ));
    let remote_header = Box::new(LktlsHeaderProtectionKey::new(
        &keys.remote.hp_key,
        keys.aead_algorithm,
    ));
    let local_packet = Box::new(packet_key_from_derived(keys.local, keys.aead_algorithm));
    let remote_packet = Box::new(packet_key_from_derived(keys.remote, keys.aead_algorithm));

    Keys {
        header: KeyPair {
            local: local_header,
            remote: remote_header,
        },
        packet: KeyPair {
            local: local_packet,
            remote: remote_packet,
        },
    }
}

fn keys_from_secrets(secrets: &QuicTrafficSecrets, side: Side) -> Keys {
    let client = derive_packet_keys(
        &secrets.client_secret,
        secrets.hkdf_algorithm,
        secrets.aead_algorithm,
    )
    .expect("client packet key derivation must succeed");
    let server = derive_packet_keys(
        &secrets.server_secret,
        secrets.hkdf_algorithm,
        secrets.aead_algorithm,
    )
    .expect("server packet key derivation must succeed");

    let client_header = Box::new(LktlsHeaderProtectionKey::new(
        &client.hp_key,
        secrets.aead_algorithm,
    ));
    let server_header = Box::new(LktlsHeaderProtectionKey::new(
        &server.hp_key,
        secrets.aead_algorithm,
    ));
    let client_packet = Box::new(packet_key_from_derived(client, secrets.aead_algorithm));
    let server_packet = Box::new(packet_key_from_derived(server, secrets.aead_algorithm));

    match side {
        Side::Client => Keys {
            header: KeyPair {
                local: client_header,
                remote: server_header,
            },
            packet: KeyPair {
                local: client_packet,
                remote: server_packet,
            },
        },
        Side::Server => Keys {
            header: KeyPair {
                local: server_header,
                remote: client_header,
            },
            packet: KeyPair {
                local: server_packet,
                remote: client_packet,
            },
        },
    }
}

fn packet_key_from_derived(keys: LktlsPacketKeys, algorithm: AeadAlgorithm) -> LktlsPacketKey {
    LktlsPacketKey {
        aead: Aead::new(algorithm, &keys.key, &keys.iv)
            .expect("derived packet keys must have valid sizes"),
        algorithm,
    }
}

fn ensure_supported_version(version: u32) -> Result<(), ConnectError> {
    match version {
        1 => Ok(()), // QUIC v1 (RFC 9000) — the only version Chrome supports
        _ => Err(ConnectError::UnsupportedVersion),
    }
}

fn map_tls_start_error(server_name: &str, error: TlsError) -> ConnectError {
    match error {
        TlsError::InvalidProfile(message) => {
            ConnectError::InvalidServerName(format!("{server_name}: invalid profile: {message}"))
        }
        TlsError::HandshakeFailure(message) => {
            ConnectError::InvalidServerName(format!("{server_name}: {message}"))
        }
        _ => ConnectError::InvalidServerName(server_name.to_string()),
    }
}

fn map_tls_error(error: TlsError) -> TransportError {
    if let Some(alert) = error.as_alert() {
        return TransportError {
            code: TransportErrorCode::crypto(alert.description.as_byte()),
            frame: None,
            reason: error.to_string(),
        };
    }

    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: format!("lktls-quic error: {error}"),
    }
}

impl fmt::Debug for LktlsQuicClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LktlsQuicClientConfig")
            .field("port", &self.port)
            .field("profile", &"[ elided ]")
            .finish()
    }
}

#[derive(Clone)]
struct ZeroRttState {
    keys: LktlsPacketKeys,
    aead_algorithm: AeadAlgorithm,
    accepted: bool,
}

#[derive(Debug)]
struct SeededSessionStore {
    seeded: std::sync::Mutex<Option<SessionTicketData>>,
    downstream: Option<Arc<dyn SessionStore>>,
}

impl SeededSessionStore {
    fn new(ticket: SessionTicketData, downstream: Option<Arc<dyn SessionStore>>) -> Self {
        Self {
            seeded: std::sync::Mutex::new(Some(ticket)),
            downstream,
        }
    }
}

impl SessionStore for SeededSessionStore {
    fn store(&self, host: &str, ticket: SessionTicketData) {
        if let Some(ref downstream) = self.downstream {
            tracing::debug!(host = %host, "quic.tls_ticket_store_forward");
            downstream.store(host, ticket);
        }
    }

    fn take(&self, host: &str) -> Option<SessionTicketData> {
        if let Some(ticket) = self.seeded.lock().unwrap_or_else(|e| e.into_inner()).take() {
            tracing::debug!(host = %host, "quic.tls_ticket_take_seeded");
            return Some(ticket);
        }
        tracing::trace!(host = %host, "quic.tls_ticket_take_downstream");
        self.downstream
            .as_ref()
            .and_then(|downstream| downstream.take(host))
    }
}

fn derive_early_crypto(
    ticket: &SessionTicketData,
    client_hello: &[u8],
) -> Result<ZeroRttState, TlsError> {
    let zero_salt = vec![0u8; ticket.hkdf_algorithm.hash_len()];
    let early_secret = hkdf_extract(ticket.hkdf_algorithm, &zero_salt, &ticket.resumption_psk)?;
    let transcript_hash = hash_for_hkdf(ticket.hkdf_algorithm, client_hello);
    let early_traffic_secret = early_secret.derive_secret("c e traffic", &transcript_hash)?;
    let keys = derive_packet_keys(
        &early_traffic_secret,
        ticket.hkdf_algorithm,
        ticket.aead_algorithm,
    )?;
    tracing::debug!(
        ticket_age_add = ticket.age_add,
        max_early_data = ticket.max_early_data_size,
        client_hello_len = client_hello.len(),
        "quic.tls_zero_rtt_derived"
    );
    Ok(ZeroRttState {
        keys,
        aead_algorithm: ticket.aead_algorithm,
        accepted: false,
    })
}

/// Processes every complete TLS handshake message contained in `payload`,
/// returning the number of leading bytes fully consumed. Any trailing bytes
/// that form only a partial message are left for the caller to retain and
/// re-submit once more data arrives.
fn process_post_handshake_messages(payload: &[u8], ctx: &SessionTicketContext) -> usize {
    let mut pos = 0usize;
    while pos + 4 <= payload.len() {
        let len = ((payload[pos + 1] as usize) << 16)
            | ((payload[pos + 2] as usize) << 8)
            | (payload[pos + 3] as usize);
        let end = pos + 4 + len;
        if end > payload.len() {
            break;
        }
        if payload[pos] == 0x04 {
            tracing::debug!(ticket_len = len, "quic.tls_new_session_ticket");
            ctx.process_new_session_ticket(&payload[pos..end]);
        }
        pos = end;
    }
    pos
}

fn hash_for_hkdf(algorithm: lktls::crypto::hkdf::HkdfAlgorithm, data: &[u8]) -> Vec<u8> {
    let digest_alg = match algorithm {
        lktls::crypto::hkdf::HkdfAlgorithm::Sha256 => &digest::SHA256,
        lktls::crypto::hkdf::HkdfAlgorithm::Sha384 => &digest::SHA384,
    };
    digest::digest(digest_alg, data).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Once};

    use h3::server;
    use http::{Request, Response, StatusCode};
    use lkh3::connect_h3;
    use lktls::profile::presets;
    use quinn::crypto::rustls::QuicServerConfig;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    fn ensure_rustls_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn trust_anchor_from_der(
        cert: &CertificateDer<'static>,
    ) -> rustls_pki_types::TrustAnchor<'static> {
        lktls::verify::certchain::parse_trust_anchor_from_der(cert.as_ref()).unwrap()
    }

    #[tokio::test]
    async fn lktls_quic_handshake_with_rustls_server_and_h3_request() {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));

        let server = Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let mut h3_conn =
                    server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                if let Some(resolver) = h3_conn.accept().await.unwrap() {
                    let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    stream.send_response(response).await.unwrap();
                    stream.finish().await.unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        });

        let anchor = trust_anchor_from_der(&cert_der);
        let client_crypto = LktlsQuicClientConfig::new({
            let mut profile = presets::chrome_144();
            profile.alpn_protocols = vec!["h3".to_string()];
            profile
        })
        .custom_ca_anchors(Arc::new(vec![anchor]))
        .port(server_addr.port());
        let mut endpoint =
            Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        endpoint.set_default_client_config(client_crypto.into_quinn());

        let quic_conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = connect_h3(quic_conn, &lkh3::chrome_h3()).await.unwrap();
        let mut sender = connection.clone_sender();

        let request = Request::builder()
            .uri("https://localhost/test")
            .body(None)
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        server_task.await.unwrap();
        endpoint.wait_idle().await;
        server.wait_idle().await;
    }

    #[tokio::test]
    async fn lktls_quic_enables_zero_rtt_after_ticket_is_stored() {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        server_tls.max_early_data_size = u32::MAX;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));

        let server = Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                for _ in 0..2 {
                    let incoming = server.accept().await.unwrap();
                    let conn = incoming.await.unwrap();
                    let mut h3_conn =
                        server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                            .await
                            .unwrap();

                    if let Some(resolver) = h3_conn.accept().await.unwrap() {
                        let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        stream.send_response(response).await.unwrap();
                        stream.finish().await.unwrap();
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        });

        let anchor = trust_anchor_from_der(&cert_der);
        let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
        let client_crypto = LktlsQuicClientConfig::new({
            let mut profile = presets::chrome_144();
            profile.alpn_protocols = vec!["h3".to_string()];
            profile
        })
        .custom_ca_anchors(Arc::new(vec![anchor]))
        .session_store(store.clone())
        .port(server_addr.port());

        let mut endpoint =
            Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        endpoint.set_default_client_config(client_crypto.clone().into_quinn());

        let quic_conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = connect_h3(quic_conn, &lkh3::chrome_h3()).await.unwrap();
        let mut sender = connection.clone_sender();

        let request = Request::builder()
            .uri("https://localhost/zerortt")
            .body(None)
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let connecting = endpoint.connect(server_addr, "localhost").unwrap();
        let (connection, accepted) = connecting
            .into_0rtt()
            .expect("expected session ticket to make 0-RTT available");
        let stream = connection.open_uni().await.expect("0-rtt stream open");
        drop(stream);
        let _ = accepted.await;

        server_task.abort();
        endpoint.wait_idle().await;
        server.wait_idle().await;
    }

    #[test]
    fn derive_early_crypto_from_ticket_and_client_hello() {
        let ticket = SessionTicketData {
            ticket: vec![1, 2, 3],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 0,
            received_at: std::time::Instant::now(),
            alpn: Some("h3".into()),
            hkdf_algorithm: lktls::crypto::hkdf::HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 16_384,
            peer_transport_parameters: Some(vec![0x01, 0x00]),
        };

        let state = derive_early_crypto(&ticket, b"client hello bytes").unwrap();
        assert_eq!(state.aead_algorithm, AeadAlgorithm::Aes128Gcm);
        assert_eq!(state.keys.key.len(), 16);
        assert_eq!(state.keys.iv.len(), 12);
        assert_eq!(state.keys.hp_key.len(), 16);
        assert!(!state.accepted);
    }
}
