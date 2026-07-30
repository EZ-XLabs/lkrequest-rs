//! TLS 1.3 handshake state machine.
//!
//! Drives the full TLS 1.3 handshake flow:
//!
//! ```text
//! Client                                Server
//! ------                                ------
//! ClientHello          -------->
//!                                       ServerHello
//!                                       EncryptedExtensions
//!                                       Certificate*
//!                                       CertificateVerify*
//!                      <--------        Finished
//! Finished             -------->
//! [Application Data]   <------->        [Application Data]
//! ```
//!
//! Also supports HelloRetryRequest (HRR):
//!
//! ```text
//! ClientHello          -------->
//!                      <--------        HelloRetryRequest
//! ClientHello2         -------->
//!                                       ServerHello
//!                                       ... (continues as above)
//! ```

use aws_lc_rs::digest;
use aws_lc_rs::hmac;

use std::sync::Arc;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hkdf::{hkdf_expand_label, hkdf_extract, HkdfAlgorithm, HkdfPrk};
use crate::crypto::kx::{self, EphemeralKeyPair, KxGroup};
use crate::error::{AlertDescription, Result, TlsError};
use crate::extensions::pre_shared_key::{self, PskIdentity};
use crate::extensions::quic_transport_params::{decode_transport_params, QuicTransportParams};
use crate::handshake::client_hello::{ClientHelloBuilder, EchRetryState};
use crate::handshake::handshake_type;
use crate::handshake::server_hello::{self, ServerHello};
use crate::profile::types::{ext_type, ExtensionSource, ExtensionSpec, TlsProfile, TlsVersion};
use crate::session_store::SessionTicketData;
use crate::verify::policy::VerificationPolicy;

use crate::crypto::to_hex;

// ---------------------------------------------------------------------------
// Transcript Hash
// ---------------------------------------------------------------------------

/// Running transcript hash for the TLS 1.3 handshake.
///
/// Accumulates all handshake messages and provides the current hash value
/// at any point (used for key derivation at multiple stages).
#[derive(Clone)]
struct TranscriptHash {
    context: digest::Context,
    algorithm: HkdfAlgorithm,
}

impl TranscriptHash {
    fn new(algorithm: HkdfAlgorithm) -> Self {
        Self {
            context: digest::Context::new(Self::ring_algorithm(algorithm)),
            algorithm,
        }
    }

    /// Feed handshake message bytes into the transcript.
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Get the current hash value without consuming the context.
    fn current_hash(&self) -> Vec<u8> {
        self.context.clone().finish().as_ref().to_vec()
    }

    /// Replace the transcript with a synthetic `message_hash` message for HRR.
    ///
    /// Per RFC 8446 Section 4.4.1: when HelloRetryRequest is received, the
    /// transcript is replaced with:
    ///   Hash(message_hash || HRR || ...)
    /// where message_hash = [0xFE, 0, 0, Hash.length, Hash(CH1)]
    fn replace_with_message_hash(&mut self) {
        let hash = self.current_hash();
        let hash_len = hash.len();

        // Build the synthetic message_hash handshake message
        let mut msg = Vec::with_capacity(4 + hash_len);
        msg.push(handshake_type::MESSAGE_HASH);
        msg.push(0);
        msg.push(0);
        msg.push(hash_len as u8);
        msg.extend_from_slice(&hash);

        // Reset the context and feed the synthetic message
        self.context = digest::Context::new(Self::ring_algorithm(self.algorithm));
        self.context.update(&msg);
    }

    fn ring_algorithm(algo: HkdfAlgorithm) -> &'static digest::Algorithm {
        match algo {
            HkdfAlgorithm::Sha256 => &digest::SHA256,
            HkdfAlgorithm::Sha384 => &digest::SHA384,
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Represents the current state of a TLS 1.3 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13State {
    /// Initial state — ready to build ClientHello.
    Start,
    /// ClientHello sent, waiting for ServerHello.
    WaitServerHello,
    /// ServerHello received, waiting for EncryptedExtensions.
    WaitEncryptedExtensions,
    /// Waiting for server Certificate (may be skipped with PSK).
    WaitCertificate,
    /// Waiting for CertificateVerify.
    WaitCertificateVerify,
    /// Waiting for server Finished.
    WaitFinished,
    /// Handshake complete, ready for application data.
    Connected,
}

/// Action the caller should take after processing a handshake message.
#[derive(Debug)]
pub enum HandshakeAction {
    /// Install handshake traffic keys for encrypting/decrypting.
    /// After this, subsequent records from the server are encrypted.
    InstallHandshakeKeys(HandshakeKeys),

    /// Continue reading — more messages expected.
    ContinueReading,

    /// The handshake is complete. The caller should:
    /// 1. Send `client_finished` encrypted with the handshake write key.
    /// 2. Install the application traffic keys.
    Complete(HandshakeComplete),

    /// HelloRetryRequest received. Send this new ClientHello (plaintext).
    RetryClientHello(Vec<u8>),
}

/// Handshake traffic keys (installed after ServerHello).
#[derive(Debug)]
pub struct HandshakeKeys {
    /// HKDF algorithm for this cipher suite.
    pub hkdf_algorithm: HkdfAlgorithm,
    /// AEAD algorithm for this cipher suite.
    pub aead_algorithm: AeadAlgorithm,
    /// Server handshake traffic secret.
    pub server_secret: Vec<u8>,
    /// Client handshake traffic secret.
    pub client_secret: Vec<u8>,
    /// Server handshake write key (for decrypting server messages).
    pub server_key: Vec<u8>,
    /// Server handshake write IV.
    pub server_iv: Vec<u8>,
    /// Client handshake write key (for encrypting client Finished).
    pub client_key: Vec<u8>,
    /// Client handshake write IV.
    pub client_iv: Vec<u8>,
}

/// Data returned when the handshake completes.
#[derive(Debug)]
pub struct HandshakeComplete {
    /// Optional Client EncryptedExtensions message (ALPS).
    /// Must be sent *before* `client_finished`, encrypted with handshake keys.
    /// `None` if ALPS was not negotiated.
    pub client_encrypted_extensions: Option<Vec<u8>>,
    /// Client Finished handshake message bytes (to be sent encrypted
    /// with the handshake write key, NOT the application key).
    pub client_finished: Vec<u8>,
    /// Application traffic keys for post-handshake communication.
    pub traffic_secrets: TrafficSecrets,
    /// The ALPN protocol negotiated by the server (from EncryptedExtensions).
    /// `None` if the server didn't include ALPN in EncryptedExtensions.
    pub negotiated_alpn: Option<String>,
    /// The resumption master secret (for deriving PSK from NewSessionTickets).
    /// This is needed by the connector to compute `resumption_psk` for tickets
    /// received as post-handshake messages.
    pub resumption_master_secret: Vec<u8>,
    /// The cipher suite negotiated by the server.
    /// Used when storing session tickets for PSK resumption.
    pub negotiated_cipher_suite: u16,
    /// The server's certificate chain (DER, leaf first), as received in the
    /// Certificate message. Empty on a resumed (PSK) handshake that sends none.
    pub server_certificates: Vec<Vec<u8>>,

    /// ECH retry configs received from the server in EncryptedExtensions.
    ///
    /// If the server supports ECH and the client's ECH attempt failed (or was
    /// GREASE), the server may provide updated ECHConfigList data here.  The
    /// caller should store this for subsequent connections to enable real ECH.
    ///
    /// `None` if the server did not include `encrypted_client_hello` in EE.
    pub ech_retry_configs: Option<Vec<u8>>,

    /// Whether the server accepted real ECH.
    ///
    /// `true` if the client offered real ECH and the server's accept
    /// confirmation matched.  `false` if ECH was not offered, was rejected,
    /// or only GREASE was sent.
    pub ech_accepted: bool,

    /// Server QUIC transport parameters from EncryptedExtensions.
    pub peer_quic_transport_params: Option<QuicTransportParams>,
    /// Whether the server accepted early data (0-RTT).
    pub early_data_accepted: bool,
}

/// Traffic encryption keys derived at the end of the handshake.
#[derive(Debug)]
pub struct TrafficSecrets {
    /// AEAD algorithm.
    pub aead_algorithm: AeadAlgorithm,
    /// HKDF algorithm (for KeyUpdate derivation).
    pub hkdf_algorithm: crate::crypto::hkdf::HkdfAlgorithm,
    /// Client application traffic key.
    pub client_key: Vec<u8>,
    /// Client application traffic IV.
    pub client_iv: Vec<u8>,
    /// Server application traffic key.
    pub server_key: Vec<u8>,
    /// Server application traffic IV.
    pub server_iv: Vec<u8>,
    /// Server application traffic secret (needed for KeyUpdate derivation).
    pub server_app_secret: Vec<u8>,
    /// Client application traffic secret (needed for KeyUpdate write-side rotation).
    pub client_app_secret: Vec<u8>,
    /// Exporter master secret (RFC 8446 §7.5), backing `export_keying_material`.
    pub exporter_master_secret: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Cipher suite info
// ---------------------------------------------------------------------------

/// Map a TLS 1.3 cipher suite to its component algorithms.
fn cipher_suite_info(suite: u16) -> Result<(HkdfAlgorithm, AeadAlgorithm)> {
    match suite {
        0x1301 => Ok((HkdfAlgorithm::Sha256, AeadAlgorithm::Aes128Gcm)),
        0x1302 => Ok((HkdfAlgorithm::Sha384, AeadAlgorithm::Aes256Gcm)),
        0x1303 => Ok((HkdfAlgorithm::Sha256, AeadAlgorithm::Chacha20Poly1305)),
        _ => Err(TlsError::HandshakeFailure(format!(
            "unsupported cipher suite: 0x{suite:04x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tls13Handshake
// ---------------------------------------------------------------------------

/// Manages the TLS 1.3 handshake process.
pub struct Tls13Handshake {
    /// Current state.
    state: Tls13State,
    /// The profile driving this handshake.
    profile: TlsProfile,
    /// Target server hostname (for SNI and cert verification).
    hostname: String,

    // --- Transcript ---
    /// Transcript hash context (initialized after we know the cipher suite).
    transcript: Option<TranscriptHash>,
    /// Buffered ClientHello bytes (before cipher suite is known).
    buffered_client_hello: Option<Vec<u8>>,

    // --- Key exchange ---
    /// Ephemeral key pairs generated for key_share.
    key_pairs: Vec<EphemeralKeyPair>,

    // --- Saved for HRR ---
    /// Client random from the first ClientHello.
    client_random: Option<[u8; 32]>,
    /// Session ID from the first ClientHello.
    session_id: Option<Vec<u8>>,
    /// Whether we have already processed an HRR.
    hrr_received: bool,
    /// GREASE values from the first ClientHello, reused in CH2 after HRR.
    grease_values: Option<crate::extensions::grease::GreaseValues>,
    /// Exact extension permutation selected for CH1.
    extension_order: Option<Vec<ExtensionSpec>>,
    /// Complete fake ECH extension from CH1, reused byte-for-byte in CH2.
    ech_grease_extension: Option<Vec<u8>>,

    // --- Negotiated parameters ---
    /// Selected cipher suite.
    cipher_suite: Option<u16>,
    /// HKDF algorithm (from cipher suite).
    hkdf_algorithm: Option<HkdfAlgorithm>,
    /// AEAD algorithm (from cipher suite).
    aead_algorithm: Option<AeadAlgorithm>,

    // --- Key schedule ---
    /// Handshake secret (for deriving traffic secrets + master secret).
    handshake_secret: Option<HkdfPrk>,
    /// Client handshake traffic secret.
    client_hs_traffic_secret: Option<Vec<u8>>,
    /// Server handshake traffic secret.
    server_hs_traffic_secret: Option<Vec<u8>>,

    // --- Server certificates ---
    /// Server certificate chain (DER-encoded, leaf first).
    server_certificates: Vec<Vec<u8>>,

    // --- ALPS ---
    /// Optional ALPS payload (pre-encoded H2 SETTINGS bytes from upper layer).
    alps_payload: Option<Vec<u8>>,
    /// Server ALPS data received in EncryptedExtensions (opaque blob).
    server_alps_data: Option<Vec<u8>>,
    /// The ALPS extension code point negotiated by the server (0x4469 or 0x44CD).
    alps_code_point: Option<u16>,

    // --- Negotiated ALPN ---
    /// The ALPN protocol selected by the server (extracted from EncryptedExtensions).
    negotiated_alpn: Option<String>,

    // --- ECH ---
    /// Runtime ECHConfigList provided by the caller (raw DER bytes).
    /// When set, overrides the profile's `ech` mode for this handshake.
    ech_config_list: Option<Vec<u8>>,

    /// ECH retry configs received from the server in EncryptedExtensions.
    /// If present, the server supports ECH and provides updated configs
    /// that the client should use for subsequent connections.
    ech_retry_configs: Option<Vec<u8>>,

    /// QUIC transport parameters extension payload for ClientHello.
    quic_transport_parameters: Option<Vec<u8>>,

    /// Server QUIC transport parameters from EncryptedExtensions.
    peer_quic_transport_params: Option<QuicTransportParams>,

    /// Whether this handshake is operating in QUIC-TLS mode.
    quic_mode: bool,

    /// Whether the server accepted early data in EncryptedExtensions.
    early_data_accepted: bool,

    /// Whether real ECH was offered in the ClientHello.
    ech_offered: bool,

    /// Whether the server accepted our real ECH offer.
    ech_accepted: bool,

    /// The raw inner ClientHello bytes (with Handshake header) for
    /// transcript switching when ECH is accepted.
    ech_inner_hello: Option<Vec<u8>>,

    /// Real-ECH HPKE state retained for CH2 after HRR.
    ech_retry_state: Option<EchRetryState>,

    /// ECH acceptance signalled by HRR, when an HRR was received.
    ech_hrr_accepted: Option<bool>,

    /// Raw HRR message bytes, preserved for ECH+HRR transcript reconstruction.
    hrr_raw_bytes: Option<Vec<u8>>,

    /// Raw CH2 (second ClientHello) bytes built from the inner hello,
    /// preserved for ECH+HRR transcript reconstruction.
    hrr_inner_ch2: Option<Vec<u8>>,

    // --- Certificate verification policy ---
    /// Certificate and signature verification policy.
    verification_policy: VerificationPolicy,
    /// Custom CA trust anchors (merged with Mozilla root store).
    custom_ca_anchors: Option<Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>>,

    // --- PSK / Session Resumption ---
    /// Session ticket data for PSK resumption (set before `build_client_hello`).
    psk_ticket: Option<SessionTicketData>,
    /// TLS 1.2 session ticket data for the session_ticket extension.
    /// Set when the session store has a TLS 1.2 ticket; the data goes
    /// into the session_ticket extension (0x0023) instead of pre_shared_key.
    tls12_session_ticket_data: Option<Vec<u8>>,
    /// Whether the server accepted our PSK offer.
    psk_accepted: bool,
    /// The Early Secret derived from the PSK (cached to avoid recomputation).
    early_secret_from_psk: Option<HkdfPrk>,

    /// Optional key log callback (SSLKEYLOGFILE). When set, secrets are
    /// emitted at derivation time with zero extra storage.
    keylog_callback: Option<crate::KeyLogCallback>,
}

impl Tls13Handshake {
    /// Create a new TLS 1.3 handshake with the given profile and hostname.
    pub fn new(profile: TlsProfile, hostname: impl Into<String>) -> Self {
        Self {
            state: Tls13State::Start,
            profile,
            hostname: hostname.into(),
            transcript: None,
            buffered_client_hello: None,
            key_pairs: Vec::new(),
            client_random: None,
            session_id: None,
            hrr_received: false,
            grease_values: None,
            extension_order: None,
            ech_grease_extension: None,
            cipher_suite: None,
            hkdf_algorithm: None,
            aead_algorithm: None,
            handshake_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
            server_certificates: Vec::new(),
            alps_payload: None,
            server_alps_data: None,
            alps_code_point: None,
            negotiated_alpn: None,
            ech_config_list: None,
            ech_retry_configs: None,
            quic_transport_parameters: None,
            peer_quic_transport_params: None,
            quic_mode: false,
            early_data_accepted: false,
            ech_offered: false,
            ech_accepted: false,
            ech_inner_hello: None,
            ech_retry_state: None,
            ech_hrr_accepted: None,
            hrr_raw_bytes: None,
            hrr_inner_ch2: None,
            verification_policy: VerificationPolicy::default(),
            custom_ca_anchors: None,
            psk_ticket: None,
            tls12_session_ticket_data: None,
            psk_accepted: false,
            early_secret_from_psk: None,
            keylog_callback: None,
        }
    }

    /// Returns the current handshake state.
    pub fn state(&self) -> Tls13State {
        self.state
    }

    /// Returns whether this handshake has processed a HelloRetryRequest.
    pub(crate) fn has_received_hrr(&self) -> bool {
        self.hrr_received
    }

    /// Set optional ALPS payload (pre-encoded H2 SETTINGS bytes).
    ///
    /// This must be called before `build_client_hello()`.
    pub fn set_alps_payload(&mut self, payload: Vec<u8>) {
        self.alps_payload = Some(payload);
    }

    /// Set the certificate verification policy.
    pub fn set_verification_policy(&mut self, policy: VerificationPolicy) {
        self.verification_policy = policy;
    }

    /// Set custom CA trust anchors (merged with Mozilla root store).
    pub fn set_custom_ca_anchors(
        &mut self,
        anchors: Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>,
    ) {
        self.custom_ca_anchors = Some(anchors);
    }

    /// Set an ECHConfigList for real ECH (raw DER bytes).
    ///
    /// Must be called before `build_client_hello()`.  When set, the
    /// ClientHello builder constructs an encrypted inner ClientHello
    /// (with real SNI) and embeds it in the outer ClientHello's ECH
    /// extension via HPKE encryption.
    ///
    /// The config can come from:
    /// - DNS HTTPS resource records (`ech` SvcParam)
    /// - A previous connection's `ech_retry_configs`
    /// - Manual configuration by the user
    pub fn set_ech_config(&mut self, config_list: Vec<u8>) {
        self.ech_config_list = Some(config_list);
    }

    /// Enable QUIC-TLS mode.
    pub fn enable_quic_mode(&mut self) {
        self.quic_mode = true;
    }

    /// Set the encoded QUIC transport parameters extension payload.
    pub fn set_quic_transport_parameters(&mut self, payload: Vec<u8>) {
        self.quic_transport_parameters = Some(payload);
    }

    /// Set a session ticket for PSK resumption.
    ///
    /// Must be called before `build_client_hello()`. If set, the ClientHello
    /// will include a `pre_shared_key` extension offering this ticket.
    pub fn set_psk_ticket(&mut self, ticket: SessionTicketData) {
        self.psk_ticket = Some(ticket);
    }

    /// Set TLS 1.2 session ticket data for the ClientHello's `session_ticket`
    /// extension (0x0023).
    ///
    /// This is used when the session store contains a TLS 1.2 ticket. The
    /// ticket data is placed in the `session_ticket` extension (not in
    /// `pre_shared_key`), matching Chrome/BoringSSL behavior.
    pub fn set_tls12_session_ticket(&mut self, ticket_data: Vec<u8>) {
        self.tls12_session_ticket_data = Some(ticket_data);
    }

    /// Set a key log callback for SSLKEYLOGFILE output.
    ///
    /// When set, handshake and application traffic secrets are emitted at
    /// derivation time without storing any extra data.
    pub fn set_keylog_callback(&mut self, cb: Arc<dyn Fn(&str) + Send + Sync>) {
        self.keylog_callback = Some(cb);
    }

    // =======================================================================
    // Build Client EncryptedExtensions (ALPS)
    // =======================================================================

    /// Build the Client EncryptedExtensions handshake message for ALPS.
    ///
    /// This message is sent after receiving the server Finished and before
    /// the client Finished, per draft-vvv-tls-alps. It carries the client's
    /// application settings to the server. Note that real Chrome sends an EMPTY
    /// client-settings payload here (`Some(vec![])`), so `ext_data_len` is
    /// commonly 0; a non-empty payload is also supported for other clients.
    ///
    /// Returns `None` if ALPS was not negotiated by the server or no payload was
    /// configured (`alps_payload == None`).
    fn build_client_encrypted_extensions(&self) -> Option<Vec<u8>> {
        // Only send Client EE if the server negotiated ALPS
        let code_point = self.alps_code_point?;
        let alps_payload = self.alps_payload.as_ref()?;

        // Build the inner extensions block:
        //   extension_type(2) + extension_data_length(2) + extension_data(N)
        let ext_data_len = alps_payload.len();
        let extensions_len = 2 + 2 + ext_data_len; // type + data_len + data

        // Build the EncryptedExtensions body:
        //   extensions_length(2) + extensions
        let body_len = 2 + extensions_len;

        // Full handshake message:
        //   HandshakeType(1) = 0x08 + Length(3) + body
        let total_len = 4 + body_len;
        let mut msg = Vec::with_capacity(total_len);

        // Handshake header
        msg.push(handshake_type::ENCRYPTED_EXTENSIONS);
        let body_len_u32 = body_len as u32;
        msg.push((body_len_u32 >> 16) as u8);
        msg.push((body_len_u32 >> 8) as u8);
        msg.push(body_len_u32 as u8);

        // Extensions length
        msg.push((extensions_len >> 8) as u8);
        msg.push(extensions_len as u8);

        // Extension: application_settings
        msg.push((code_point >> 8) as u8);
        msg.push(code_point as u8);
        msg.push((ext_data_len >> 8) as u8);
        msg.push(ext_data_len as u8);
        msg.extend_from_slice(alps_payload);

        tracing::debug!(
            "Built Client EncryptedExtensions (ALPS, code_point=0x{code_point:04x}, \
             payload_len={ext_data_len}, total_len={total_len})"
        );

        Some(msg)
    }

    // =======================================================================
    // Build ClientHello
    // =======================================================================

    /// Build the initial ClientHello handshake message.
    ///
    /// Returns the complete handshake message bytes (type + length + body).
    /// The caller should wrap these in a TLS record and send to the server.
    ///
    /// After calling this, the state transitions to `WaitServerHello`.
    ///
    /// If a PSK ticket was set via [`Self::set_psk_ticket`], the ClientHello will
    /// include a `pre_shared_key` extension as the last extension, with a
    /// computed binder over the truncated transcript.
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        if self.state != Tls13State::Start {
            return Err(TlsError::HandshakeFailure(
                "build_client_hello called in wrong state".to_string(),
            ));
        }

        // ALPS advertisement in the ClientHello is DECOUPLED from the client's
        // settings payload. Real Chrome advertises `application_settings: h2` in
        // the ClientHello while sending an EMPTY client-settings payload in its
        // Client EncryptedExtensions (verified against a real Chrome capture). So:
        //   None        => no ALPS (e.g. the H1-only request path)
        //   Some(bytes) => advertise ALPS; `bytes` (possibly empty) becomes the
        //                  Client EncryptedExtensions payload.
        let mut profile_for_ch = self.profile.clone();
        if self.alps_payload.is_none() {
            profile_for_ch.alps_protocols = None;
        }
        if self.quic_mode {
            profile_for_ch.tls_min_version = TlsVersion::Tls13;
            profile_for_ch.tls_max_version = TlsVersion::Tls13;
            profile_for_ch.session_id_length = 0;

            let has_quic_tp = profile_for_ch
                .extensions
                .iter()
                .any(|ext| ext.extension_type == ext_type::QUIC_TRANSPORT_PARAMETERS);
            if !has_quic_tp {
                let insert_at = profile_for_ch
                    .extensions
                    .iter()
                    .position(|ext| {
                        matches!(
                            ext.extension_type,
                            ext_type::PADDING | ext_type::PRE_SHARED_KEY
                        )
                    })
                    .unwrap_or(profile_for_ch.extensions.len());
                profile_for_ch.extensions.insert(
                    insert_at,
                    ExtensionSpec {
                        extension_type: ext_type::QUIC_TRANSPORT_PARAMETERS,
                        source: ExtensionSource::Auto,
                    },
                );
            }
        }
        let mut ch_builder = ClientHelloBuilder::new(&profile_for_ch, &self.hostname);
        if let Some(ref ech_config) = self.ech_config_list {
            ch_builder = ch_builder.with_ech_config(ech_config.clone());
        }
        if let Some(ref ticket_data) = self.tls12_session_ticket_data {
            ch_builder = ch_builder.with_session_ticket_data(ticket_data.clone());
        }
        if let Some(ref params) = self.quic_transport_parameters {
            ch_builder = ch_builder.with_quic_transport_parameters(params.clone());
        }
        if self
            .psk_ticket
            .as_ref()
            .is_some_and(|ticket| ticket.max_early_data_size > 0)
        {
            ch_builder = ch_builder.with_early_data();
        }
        if self.ech_config_list.is_some() {
            if let Some(ticket) = self.psk_ticket.as_ref() {
                ch_builder = ch_builder.with_psk_offer(
                    ticket.ticket.clone(),
                    ticket.obfuscated_ticket_age(),
                    ticket.resumption_psk.clone(),
                    ticket.hkdf_algorithm,
                    Vec::new(),
                );
            }
        }
        // Pre-calculate PSK extension length so padding accounts for it.
        let psk_extra_len = if let Some(ref ticket) = self.psk_ticket {
            crate::extensions::pre_shared_key::psk_extension_length(
                ticket.ticket.len(),
                ticket.hkdf_algorithm.hash_len(),
            )
        } else {
            0
        };
        let output = ch_builder.build_with_psk_hint(psk_extra_len)?;

        // Extract random (offset 6..38) and session_id from the built message
        let msg = &output.message;
        let mut random = [0u8; 32];
        random.copy_from_slice(&msg[6..38]);
        let sid_len = msg[38] as usize;
        let session_id = msg[39..39 + sid_len].to_vec();

        if self.quic_mode && sid_len != 0 {
            return Err(TlsError::HandshakeFailure(
                "QUIC ClientHello must use an empty legacy_session_id".to_string(),
            ));
        }

        self.client_random = Some(random);
        self.session_id = Some(session_id);
        self.key_pairs = output.key_shares;
        self.grease_values = Some(output.grease_values);
        self.extension_order = Some(output.shuffled_extensions);
        self.ech_grease_extension = output.ech_grease_extension;

        // Store ECH state from the build output.
        if output.ech_offered {
            self.ech_offered = true;
            self.ech_inner_hello = output.inner_hello;
            self.ech_retry_state = output.ech_retry_state;
            tracing::debug!("ECH: real ECH offered in ClientHello");
        }

        // If we have a PSK ticket, append the pre_shared_key extension
        let psk_ticket_clone = self.psk_ticket.clone();
        let final_msg = if let Some(ref ticket) = psk_ticket_clone {
            if output.ech_offered {
                self.early_secret_from_psk = Some(pre_shared_key::compute_early_secret(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                )?);
                output.message
            } else {
                self.append_psk_extension(output.message, ticket, None)?
            }
        } else {
            output.message
        };

        self.buffered_client_hello = Some(final_msg.clone());

        self.state = Tls13State::WaitServerHello;
        Ok(final_msg)
    }

    /// Append the `pre_shared_key` extension to a ClientHello message and compute
    /// the PSK binder.
    ///
    /// The `pre_shared_key` extension MUST be the last extension in the ClientHello
    /// (RFC 8446 Section 4.2.11). The binder is computed over a truncated transcript
    /// that includes the ClientHello up to (but not including) the binders list.
    fn append_psk_extension(
        &mut self,
        mut ch_msg: Vec<u8>,
        ticket: &SessionTicketData,
        transcript_prefix: Option<&TranscriptHash>,
    ) -> Result<Vec<u8>> {
        let hkdf_algo = ticket.hkdf_algorithm;
        let binder_len = hkdf_algo.hash_len();

        // Build the PSK extension with placeholder binder
        let identities = vec![PskIdentity {
            identity: ticket.ticket.clone(),
            obfuscated_ticket_age: ticket.obfuscated_ticket_age(),
        }];
        let (psk_ext_bytes, binder_value_offset_in_ext) =
            pre_shared_key::encode_psk_extension(&identities, binder_len);

        // We need to update the ClientHello's extensions length and body length
        // to include the PSK extension.
        //
        // ClientHello layout:
        //   [0]    = handshake type (0x01)
        //   [1..4] = body length (3 bytes)
        //   [4..6] = protocol version
        //   [6..38] = random
        //   [38]   = session_id_length
        //   ... cipher suites, compression, extensions ...
        //
        // The extensions length field is at (end_of_message - extensions_data_len - 2).
        // We need to find it and update it.

        // Current total message length
        let old_msg_len = ch_msg.len();

        // The extensions_data is the last part of the body. The extensions_length
        // field is 2 bytes right before the extensions data.
        // body_len = msg_len - 4 (handshake header)
        // We can find extensions_length at the end:
        // Since we're appending to the extensions, just update the two length fields.

        // Append PSK extension bytes to the message
        ch_msg.extend_from_slice(&psk_ext_bytes);
        let new_msg_len = ch_msg.len();
        let added_len = new_msg_len - old_msg_len;

        // Update body length (bytes 1..4, big-endian 24-bit)
        let new_body_len = new_msg_len - 4;
        ch_msg[1] = ((new_body_len >> 16) & 0xFF) as u8;
        ch_msg[2] = ((new_body_len >> 8) & 0xFF) as u8;
        ch_msg[3] = (new_body_len & 0xFF) as u8;

        // Update extensions length field.
        // The extensions_length is a 2-byte field right before the extensions data.
        // We need to find it by walking the ClientHello structure.
        let sid_len = ch_msg[38] as usize;
        let cs_start = 39 + sid_len;
        let cs_len = u16::from_be_bytes([ch_msg[cs_start], ch_msg[cs_start + 1]]) as usize;
        let comp_start = cs_start + 2 + cs_len;
        let comp_len = ch_msg[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;

        let old_ext_len =
            u16::from_be_bytes([ch_msg[ext_len_pos], ch_msg[ext_len_pos + 1]]) as usize;
        let new_ext_len = old_ext_len + added_len;
        ch_msg[ext_len_pos] = ((new_ext_len >> 8) & 0xFF) as u8;
        ch_msg[ext_len_pos + 1] = (new_ext_len & 0xFF) as u8;

        // Now compute the binder.
        // The truncated ClientHello is everything up to (not including) the binders list.
        // binders_size = 2 (binders list len) + 1 (binder len byte) + binder_len
        let binders_sz = pre_shared_key::binders_size(1, binder_len);
        let truncated_ch_len = new_msg_len - binders_sz;
        let truncated_ch = &ch_msg[..truncated_ch_len];

        // For CH2 after HRR, the binder covers the existing
        // message_hash(CH1) + HRR prefix followed by Truncate(CH2).
        let transcript_hash = if let Some(prefix) = transcript_prefix {
            let mut transcript = prefix.clone();
            transcript.update(truncated_ch);
            transcript.current_hash()
        } else {
            use aws_lc_rs::digest;
            let algo = match hkdf_algo {
                HkdfAlgorithm::Sha256 => &digest::SHA256,
                HkdfAlgorithm::Sha384 => &digest::SHA384,
            };
            digest::digest(algo, truncated_ch).as_ref().to_vec()
        };

        // Compute the PSK binder
        let binder = pre_shared_key::compute_psk_binder(
            hkdf_algo,
            &ticket.resumption_psk,
            &transcript_hash,
        )?;

        // Cache the early secret so we can use it in the key schedule
        // if the server accepts our PSK.
        self.early_secret_from_psk = Some(pre_shared_key::compute_early_secret(
            hkdf_algo,
            &ticket.resumption_psk,
        )?);

        // Overwrite the placeholder binder with the real value.
        // The binder is located at: (start of psk extension in ch_msg) + binder_value_offset_in_ext
        let psk_ext_start_in_msg = old_msg_len;
        let binder_abs_offset = psk_ext_start_in_msg + binder_value_offset_in_ext;
        ch_msg[binder_abs_offset..binder_abs_offset + binder_len].copy_from_slice(&binder);

        tracing::debug!(
            binder_len = binder_len,
            ticket_len = ticket.ticket.len(),
            "tls13.psk_extension_appended",
        );

        Ok(ch_msg)
    }

    fn ech_hrr_psk_transcript_prefix(
        hkdf_algorithm: HkdfAlgorithm,
        inner_client_hello: &[u8],
        hello_retry_request: &[u8],
    ) -> Vec<u8> {
        let algorithm = match hkdf_algorithm {
            HkdfAlgorithm::Sha256 => &digest::SHA256,
            HkdfAlgorithm::Sha384 => &digest::SHA384,
        };
        let client_hello_hash = digest::digest(algorithm, inner_client_hello);
        let mut prefix =
            Vec::with_capacity(4 + client_hello_hash.as_ref().len() + hello_retry_request.len());
        prefix.push(handshake_type::MESSAGE_HASH);
        prefix.extend_from_slice(&[0, 0, client_hello_hash.as_ref().len() as u8]);
        prefix.extend_from_slice(client_hello_hash.as_ref());
        prefix.extend_from_slice(hello_retry_request);
        prefix
    }

    // =======================================================================
    // Process handshake records
    // =======================================================================

    /// Process a handshake record payload that may contain one or more
    /// handshake messages.
    ///
    /// Returns the action from the last significant message processed.
    pub fn process_handshake_record(&mut self, data: &[u8]) -> Result<HandshakeAction> {
        let mut pos = 0;
        let mut last_action = HandshakeAction::ContinueReading;

        while pos + 4 <= data.len() {
            let msg_type = data[pos];
            let length = ((data[pos + 1] as usize) << 16)
                | ((data[pos + 2] as usize) << 8)
                | (data[pos + 3] as usize);
            let msg_end = pos + 4 + length;

            if msg_end > data.len() {
                return Err(TlsError::UnexpectedMessage(
                    "truncated handshake message in record".to_string(),
                ));
            }

            let full_msg = &data[pos..msg_end];
            let payload = &data[pos + 4..msg_end];

            last_action = self.process_single_message(msg_type, full_msg, payload)?;
            pos = msg_end;
        }

        Ok(last_action)
    }

    /// Process a single handshake message.
    ///
    /// `full_msg` includes the 4-byte handshake header (for transcript hashing).
    /// `payload` is just the message body (after the header).
    fn process_single_message(
        &mut self,
        msg_type: u8,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        match (self.state, msg_type) {
            (Tls13State::WaitServerHello, handshake_type::SERVER_HELLO) => {
                self.process_server_hello(full_msg, payload)
            }
            (Tls13State::WaitEncryptedExtensions, handshake_type::ENCRYPTED_EXTENSIONS) => {
                self.process_encrypted_extensions(full_msg, payload)
            }
            (Tls13State::WaitCertificate, handshake_type::CERTIFICATE_REQUEST) => {
                // Server requests client authentication (RFC 8446 §4.3.2).
                // We don't support client certificates, but must include the
                // message in the transcript and continue waiting for Certificate.
                if let Some(ref mut transcript) = self.transcript {
                    transcript.update(full_msg);
                }
                tracing::debug!(
                    "tls13.certificate_request_received — client certs not supported, skipping"
                );
                Ok(HandshakeAction::ContinueReading)
            }
            (Tls13State::WaitCertificate, handshake_type::CERTIFICATE) => {
                self.process_certificate(full_msg, payload)
            }
            (Tls13State::WaitCertificate, handshake_type::COMPRESSED_CERTIFICATE) => {
                self.process_compressed_certificate(full_msg, payload)
            }
            (Tls13State::WaitCertificateVerify, handshake_type::CERTIFICATE_VERIFY) => {
                self.process_certificate_verify(full_msg, payload)
            }
            (Tls13State::WaitFinished, handshake_type::FINISHED) => {
                self.process_finished(full_msg, payload)
            }
            _ => Err(TlsError::UnexpectedMessage(format!(
                "unexpected message type 0x{msg_type:02x} in state {:?}",
                self.state
            ))),
        }
    }

    // =======================================================================
    // ServerHello processing
    // =======================================================================

    fn process_server_hello(&mut self, full_msg: &[u8], payload: &[u8]) -> Result<HandshakeAction> {
        let sh = server_hello::parse_server_hello(payload)?;

        if !sh.is_tls13() {
            return Err(TlsError::HandshakeFailure(
                "server did not negotiate TLS 1.3".to_string(),
            ));
        }

        // RFC 8446 §4.1.3: compression_method MUST be 0
        if sh.compression_method != 0 {
            return Err(TlsError::HandshakeFailure(format!(
                "ServerHello compression_method must be 0, got {}",
                sh.compression_method,
            )));
        }

        // RFC 8446 §4.1.3: legacy_session_id_echo MUST match
        if let Some(ref our_session_id) = self.session_id {
            if sh.session_id != *our_session_id {
                return Err(TlsError::HandshakeFailure(
                    "ServerHello session_id does not match ClientHello".to_string(),
                ));
            }
        }

        // Determine cipher suite and algorithms
        let (hkdf_algo, aead_algo) = cipher_suite_info(sh.cipher_suite)?;

        // RFC 8446 §4.2.1: server MUST select a cipher suite from the client's list
        if !self.profile.cipher_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::HandshakeFailure(format!(
                "server selected cipher suite 0x{:04x} not offered by client",
                sh.cipher_suite,
            )));
        }

        // RFC 8446 §4.1.4: after HRR, cipher suite MUST be retained
        if self.hrr_received {
            if let Some(prev_suite) = self.cipher_suite {
                if prev_suite != sh.cipher_suite {
                    return Err(TlsError::HandshakeFailure(format!(
                        "ServerHello cipher suite 0x{:04x} differs from HRR 0x{:04x}",
                        sh.cipher_suite, prev_suite,
                    )));
                }
            }
        }

        self.cipher_suite = Some(sh.cipher_suite);
        self.hkdf_algorithm = Some(hkdf_algo);
        self.aead_algorithm = Some(aead_algo);

        if sh.is_hello_retry_request {
            return self.process_hello_retry_request(full_msg, &sh, hkdf_algo);
        }

        // Check if server accepted our PSK
        if let Some(selected_identity) = sh.extensions.selected_psk_identity {
            if self.psk_ticket.is_some() && selected_identity == 0 {
                // RFC 8446 §4.2.11: PSK cipher suite hash MUST be compatible
                if let Some(ref ticket) = self.psk_ticket {
                    if ticket.hkdf_algorithm != hkdf_algo {
                        return Err(TlsError::HandshakeFailure(format!(
                            "server selected PSK but cipher suite hash {:?} does not match \
                             ticket hash {:?}",
                            hkdf_algo, ticket.hkdf_algorithm,
                        )));
                    }
                }
                self.psk_accepted = true;
                tracing::debug!(
                    cipher_suite = format_args!("0x{:04x}", sh.cipher_suite),
                    "tls13.psk_accepted — session resumption",
                );
            } else {
                return Err(TlsError::HandshakeFailure(format!(
                    "server selected PSK identity {} but we only offered 1",
                    selected_identity,
                )));
            }
        }

        // Normal ServerHello — update transcript and derive keys.

        if self.hrr_received {
            // After HRR: the transcript already contains message_hash(CH1) + HRR + CH2.
            // Just add the real ServerHello to the existing transcript.
            tracing::debug!(
                "Processing ServerHello after HRR (cipher_suite=0x{:04x})",
                sh.cipher_suite
            );
            if let Some(ref mut transcript) = self.transcript {
                transcript.update(full_msg);
            }
        } else {
            // First ServerHello (no HRR): initialize transcript with CH + SH.
            let mut transcript = TranscriptHash::new(hkdf_algo);
            if let Some(ref ch_bytes) = self.buffered_client_hello {
                transcript.update(ch_bytes);
            }
            transcript.update(full_msg);
            self.transcript = Some(transcript);
            self.buffered_client_hello = None;
        }

        // Perform ECDH key exchange
        let shared_secret = self.compute_shared_secret(&sh)?;

        // --- ECH acceptance detection (RFC 9849 Section 7.2) ---
        //
        // If real ECH was offered, check if the server accepted it by
        // verifying that ServerHello.random[24..32] matches the ECH
        // accept_confirmation computed with the inner CH transcript.
        if self.ech_offered {
            if let Some(ref inner_hello) = self.ech_inner_hello {
                let accepted =
                    self.check_ech_acceptance(hkdf_algo, inner_hello, full_msg, &sh.random)?;

                if let Some(hrr_accepted) = self.ech_hrr_accepted {
                    if accepted != hrr_accepted {
                        return Err(TlsError::HandshakeFailure(
                            "server changed ECH acceptance across HelloRetryRequest".to_string(),
                        ));
                    }
                }

                if accepted {
                    self.ech_accepted = true;
                    tracing::info!("ECH: server accepted — switching to inner CH transcript");

                    if self.hrr_received {
                        // HRR + ECH accepted: rebuild the transcript using inner CH.
                        // Transcript = message_hash(inner_CH1) + HRR + inner_CH2 + SH
                        let mut transcript = TranscriptHash::new(hkdf_algo);
                        transcript.update(inner_hello);
                        transcript.replace_with_message_hash();

                        if let Some(ref hrr_bytes) = self.hrr_raw_bytes {
                            transcript.update(hrr_bytes);
                        }
                        if let Some(ref ch2_bytes) = self.hrr_inner_ch2 {
                            transcript.update(ch2_bytes);
                        }
                        transcript.update(full_msg);
                        self.transcript = Some(transcript);
                        self.buffered_client_hello = None;
                    } else {
                        let mut transcript = TranscriptHash::new(hkdf_algo);
                        transcript.update(inner_hello);
                        transcript.update(full_msg);
                        self.transcript = Some(transcript);
                        self.buffered_client_hello = None;
                    }
                } else {
                    tracing::debug!("ECH: server did not accept — continuing with outer CH");
                }
            }
        }

        // If ECH was not accepted (or not offered), transcript is already set
        // from the outer CH above.

        // Derive handshake keys via TLS 1.3 key schedule
        // If PSK was accepted, use the cached Early Secret from the PSK
        let hs_keys = self.derive_handshake_keys(hkdf_algo, aead_algo, &shared_secret)?;

        self.state = Tls13State::WaitEncryptedExtensions;
        Ok(HandshakeAction::InstallHandshakeKeys(hs_keys))
    }

    // =======================================================================
    // HelloRetryRequest processing
    // =======================================================================

    fn process_hello_retry_request(
        &mut self,
        full_msg: &[u8],
        sh: &ServerHello,
        hkdf_algo: HkdfAlgorithm,
    ) -> Result<HandshakeAction> {
        if self.hrr_received {
            return Err(TlsError::local_alert(
                AlertDescription::UnexpectedMessage,
                "received second HelloRetryRequest",
            ));
        }

        if sh.legacy_version != 0x0303 {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                format!(
                    "HRR legacy_version must be 0x0303, got 0x{:04x}",
                    sh.legacy_version
                ),
            ));
        }
        if sh.extensions.supported_version != Some(0x0304) {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "HRR must contain supported_versions selecting TLS 1.3",
            ));
        }

        if self.ech_offered {
            let accepted = if let Some(expected) = sh.extensions.ech_confirmation {
                let inner_hello = self.ech_inner_hello.as_deref().ok_or_else(|| {
                    TlsError::local_alert(
                        AlertDescription::InternalError,
                        "real ECH was offered without a saved inner ClientHello",
                    )
                })?;
                if !self.check_ech_hrr_acceptance(hkdf_algo, inner_hello, full_msg, &expected)? {
                    return Err(TlsError::local_alert(
                        AlertDescription::IllegalParameter,
                        "ECH HRR accept confirmation mismatch",
                    ));
                }
                true
            } else {
                false
            };
            self.ech_hrr_accepted = Some(accepted);
        } else if sh.extensions.ech_confirmation.is_some() {
            return Err(TlsError::local_alert(
                AlertDescription::UnsupportedExtension,
                "server sent ECH HRR confirmation without a real ECH offer",
            ));
        }

        self.hrr_received = true;
        self.hrr_raw_bytes = Some(full_msg.to_vec());
        tracing::debug!(
            "HRR received: selected_group={:?}, cookie={}",
            sh.extensions.selected_group,
            sh.extensions.cookie.is_some()
        );

        // Initialize transcript with buffered CH1, then replace with message_hash
        let mut transcript = TranscriptHash::new(hkdf_algo);
        if let Some(ref ch_bytes) = self.buffered_client_hello {
            transcript.update(ch_bytes);
        }
        // Replace CH1 hash with synthetic message_hash (RFC 8446 Section 4.4.1)
        transcript.replace_with_message_hash();
        // Add the HRR message to transcript
        transcript.update(full_msg);
        self.transcript = Some(transcript);

        let replace_key_share = if let Some(required_group) = sh.extensions.selected_group {
            if !self.profile.supported_groups.contains(&required_group) {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "HRR requested group not offered in supported_groups: 0x{required_group:04x}"
                    ),
                ));
            }
            if self
                .key_pairs
                .iter()
                .any(|key_pair| key_pair.group.code_point() == required_group)
            {
                return Err(TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!(
                        "HRR requested group already present in CH1 key_share: 0x{required_group:04x}"
                    ),
                ));
            }

            let kx_group = KxGroup::from_code_point(required_group).ok_or_else(|| {
                TlsError::local_alert(
                    AlertDescription::IllegalParameter,
                    format!("HRR requested unsupported group: 0x{required_group:04x}"),
                )
            })?;
            self.key_pairs = vec![kx::generate_key_pair(kx_group)?];
            true
        } else {
            false
        };

        if !replace_key_share && sh.extensions.cookie.is_none() {
            return Err(TlsError::local_alert(
                AlertDescription::IllegalParameter,
                "HRR would not change the second ClientHello",
            ));
        }

        // Build CH2: use the original random and session_id, with new key_share
        // and optional cookie from HRR.
        let ch2 = self.build_client_hello_retry(&sh.extensions.cookie, replace_key_share)?;

        // Feed CH2 into transcript
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&ch2);
        }
        self.buffered_client_hello = None;

        self.state = Tls13State::WaitServerHello;
        Ok(HandshakeAction::RetryClientHello(ch2))
    }

    /// Build the second ClientHello (CH2) after HRR.
    ///
    /// Preserves the original random and session_id, but replaces key_share
    /// with the newly generated key pair and adds cookie if provided.
    fn build_client_hello_retry(
        &mut self,
        cookie: &Option<Vec<u8>>,
        replace_key_share: bool,
    ) -> Result<Vec<u8>> {
        let random = self.client_random.ok_or_else(|| {
            TlsError::HandshakeFailure("missing client_random for HRR".to_string())
        })?;
        let session_id = self
            .session_id
            .clone()
            .ok_or_else(|| TlsError::HandshakeFailure("missing session_id for HRR".to_string()))?;

        let mut profile_for_ch = self.profile.clone();
        // Same ALPS gate as the initial ClientHello: only `None` suppresses ALPS;
        // `Some(empty)` still advertises it (Chrome sends empty client settings).
        if self.alps_payload.is_none() {
            profile_for_ch.alps_protocols = None;
        }
        if self.quic_mode {
            profile_for_ch.tls_min_version = TlsVersion::Tls13;
            profile_for_ch.tls_max_version = TlsVersion::Tls13;
            profile_for_ch.session_id_length = 0;
            let has_quic_tp = profile_for_ch
                .extensions
                .iter()
                .any(|ext| ext.extension_type == ext_type::QUIC_TRANSPORT_PARAMETERS);
            if !has_quic_tp {
                let insert_at = profile_for_ch
                    .extensions
                    .iter()
                    .position(|ext| {
                        matches!(
                            ext.extension_type,
                            ext_type::PADDING | ext_type::PRE_SHARED_KEY
                        )
                    })
                    .unwrap_or(profile_for_ch.extensions.len());
                profile_for_ch.extensions.insert(
                    insert_at,
                    ExtensionSpec {
                        extension_type: ext_type::QUIC_TRANSPORT_PARAMETERS,
                        source: ExtensionSource::Auto,
                    },
                );
            }
        }
        let mut builder = ClientHelloBuilder::new(&profile_for_ch, &self.hostname)
            .with_random(random)
            .with_session_id(session_id);

        if let Some(ref grease) = self.grease_values {
            builder = builder.with_grease_values(grease.clone());
        }
        if let Some(ref extension_order) = self.extension_order {
            builder = builder.with_extension_order(extension_order.clone());
        }
        if let Some(ref ech_grease_extension) = self.ech_grease_extension {
            builder = builder.with_ech_grease_extension(ech_grease_extension.clone());
        }
        if let Some(ref ech_config) = self.ech_config_list {
            builder = builder.with_ech_config(ech_config.clone());
        }
        if let Some(ref ticket_data) = self.tls12_session_ticket_data {
            builder = builder.with_session_ticket_data(ticket_data.clone());
        }
        if let Some(ref params) = self.quic_transport_parameters {
            builder = builder.with_quic_transport_parameters(params.clone());
        }
        if let Some(ref cookie_data) = cookie {
            builder = builder.with_cookie(cookie_data.clone());
        }
        if self.ech_retry_state.is_some() {
            if let Some(ticket) = self.psk_ticket.as_ref() {
                let inner_client_hello = self.ech_inner_hello.as_deref().ok_or_else(|| {
                    TlsError::HandshakeFailure(
                        "missing ClientHelloInner1 for ECH PSK HRR".to_string(),
                    )
                })?;
                let hello_retry_request = self.hrr_raw_bytes.as_deref().ok_or_else(|| {
                    TlsError::HandshakeFailure(
                        "missing HelloRetryRequest for ECH PSK binder".to_string(),
                    )
                })?;
                let transcript_prefix = Self::ech_hrr_psk_transcript_prefix(
                    ticket.hkdf_algorithm,
                    inner_client_hello,
                    hello_retry_request,
                );
                builder = builder.with_psk_offer(
                    ticket.ticket.clone(),
                    ticket.obfuscated_ticket_age(),
                    ticket.resumption_psk.clone(),
                    ticket.hkdf_algorithm,
                    transcript_prefix,
                );
            }
        }

        let output = if replace_key_share {
            builder.build_retry_with_key_pairs(&self.key_pairs, self.ech_retry_state.as_mut())?
        } else {
            builder
                .build_cookie_retry_with_key_pairs(&self.key_pairs, self.ech_retry_state.as_mut())?
        };

        let ech_offered = output.ech_offered;
        if ech_offered {
            self.hrr_inner_ch2 = output.inner_hello;
        }

        let mut final_message = output.message;
        if let Some(ticket) = self.psk_ticket.clone() {
            if ech_offered {
                self.early_secret_from_psk = Some(pre_shared_key::compute_early_secret(
                    ticket.hkdf_algorithm,
                    &ticket.resumption_psk,
                )?);
            } else {
                let transcript_prefix = self.transcript.clone();
                final_message =
                    self.append_psk_extension(final_message, &ticket, transcript_prefix.as_ref())?;
            }
        }

        Ok(final_message)
    }

    // =======================================================================
    // EncryptedExtensions processing
    // =======================================================================

    fn process_encrypted_extensions(
        &mut self,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        // Update transcript
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse EncryptedExtensions
        // Format: extensions_length (2 bytes) + extensions
        if payload.len() < 2 {
            return Err(TlsError::UnexpectedMessage(
                "EncryptedExtensions too short".to_string(),
            ));
        }

        let ext_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if 2 + ext_len > payload.len() {
            return Err(TlsError::UnexpectedMessage(
                "EncryptedExtensions length mismatch".to_string(),
            ));
        }

        // Parse individual extensions
        let mut pos = 2;
        let ext_end = 2 + ext_len;
        let mut saw_quic_transport_params = false;
        while pos + 4 <= ext_end {
            let extension_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_data_len > ext_end {
                break;
            }

            let ext_data = &payload[pos..pos + ext_data_len];

            match extension_type {
                // ALPN (0x0010): extract the server's selected protocol
                0x0010
                    // Format: protocol_name_list_length(2) + protocol_name_length(1) + name
                    if ext_data.len() >= 4 => {
                        let name_len = ext_data[2] as usize;
                        if 3 + name_len <= ext_data.len() {
                            let proto =
                                String::from_utf8_lossy(&ext_data[3..3 + name_len]).to_string();
                            tracing::debug!("Server negotiated ALPN: {proto}");
                            self.negotiated_alpn = Some(proto);
                        }
                    }
                // ALPS: application_settings (old code point 0x4469, new 0x44CD)
                0x4469 | 0x44CD => {
                    tracing::debug!(
                        "Server negotiated ALPS (ext=0x{extension_type:04x}), payload_len={}",
                        ext_data.len()
                    );
                    self.server_alps_data = Some(ext_data.to_vec());
                    self.alps_code_point = Some(extension_type);
                }
                // ECH retry_configs (0xFE0D): server provides updated ECHConfigList
                0xFE0D => {
                    tracing::debug!("Server sent ECH retry_configs (len={})", ext_data.len());
                    self.ech_retry_configs = Some(ext_data.to_vec());
                }
                0x002a => {
                    self.early_data_accepted = true;
                    tracing::debug!("Server accepted TLS early_data");
                }
                ext_type::QUIC_TRANSPORT_PARAMETERS => {
                    let params = decode_transport_params(ext_data)?;
                    tracing::debug!(
                        count = params.parameters.len(),
                        "Server sent QUIC transport parameters"
                    );
                    self.peer_quic_transport_params = Some(params);
                    saw_quic_transport_params = true;
                }
                // Other extensions — acknowledged but not processed.
                _ => {}
            }

            pos += ext_data_len;
        }

        if self.quic_mode && !saw_quic_transport_params {
            return Err(TlsError::HandshakeFailure(
                "server did not provide QUIC transport parameters".to_string(),
            ));
        }

        // When PSK is accepted, the server skips Certificate/CertificateVerify
        // and goes directly to Finished (RFC 8446 Section 2.2).
        if self.psk_accepted {
            self.state = Tls13State::WaitFinished;
            tracing::debug!("tls13.psk_resumption — skipping certificate");
        } else {
            self.state = Tls13State::WaitCertificate;
        }
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // Certificate processing
    // =======================================================================

    fn process_certificate(&mut self, full_msg: &[u8], payload: &[u8]) -> Result<HandshakeAction> {
        // Update transcript
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse TLS 1.3 Certificate message
        // Format:
        //   certificate_request_context<0..255>
        //   certificate_list<0..2^24-1>
        //     CertificateEntry:
        //       cert_data<1..2^24-1>
        //       extensions<0..2^16-1>
        self.server_certificates = parse_certificate_message(payload)?;

        if self.server_certificates.is_empty() {
            return Err(TlsError::CertificateError(
                "server sent empty certificate chain".to_string(),
            ));
        }

        self.state = Tls13State::WaitCertificateVerify;
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // CompressedCertificate processing (RFC 8879)
    // =======================================================================

    fn process_compressed_certificate(
        &mut self,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        // Update transcript with the CompressedCertificate message
        // (transcript uses the compressed form, not the decompressed one)
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // Parse CompressedCertificate:
        //   algorithm (2 bytes)
        //   uncompressed_length (3 bytes)
        //   compressed_certificate_message<1..2^24-1>
        if payload.len() < 5 {
            return Err(TlsError::UnexpectedMessage(
                "CompressedCertificate too short".to_string(),
            ));
        }

        let algorithm = u16::from_be_bytes([payload[0], payload[1]]);
        let uncompressed_length =
            ((payload[2] as usize) << 16) | ((payload[3] as usize) << 8) | (payload[4] as usize);

        if payload.len() < 8 {
            return Err(TlsError::UnexpectedMessage(
                "CompressedCertificate truncated".to_string(),
            ));
        }
        let compressed_len =
            ((payload[5] as usize) << 16) | ((payload[6] as usize) << 8) | (payload[7] as usize);

        if 8 + compressed_len > payload.len() {
            return Err(TlsError::UnexpectedMessage(
                "CompressedCertificate data extends past message".to_string(),
            ));
        }
        let compressed_data = &payload[8..8 + compressed_len];

        // Decompress
        let decompressed = decompress_certificate(algorithm, compressed_data, uncompressed_length)?;

        // Parse the decompressed Certificate message
        self.server_certificates = parse_certificate_message(&decompressed)?;

        if self.server_certificates.is_empty() {
            return Err(TlsError::CertificateError(
                "server sent empty certificate chain".to_string(),
            ));
        }

        self.state = Tls13State::WaitCertificateVerify;
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // CertificateVerify processing
    // =======================================================================

    fn process_certificate_verify(
        &mut self,
        full_msg: &[u8],
        payload: &[u8],
    ) -> Result<HandshakeAction> {
        // Get transcript hash BEFORE adding CertificateVerify to transcript
        // (CertificateVerify signs Hash(CH..Cert), not including itself)
        let transcript_hash = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("missing transcript".to_string()))?
            .current_hash();

        // Update transcript with CertificateVerify
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        if self.verification_policy.is_insecure() {
            self.state = Tls13State::WaitFinished;
            return Ok(HandshakeAction::ContinueReading);
        }

        // Parse CertificateVerify: signature_scheme (2) + signature<0..2^16-1>
        if payload.len() < 4 {
            return Err(TlsError::UnexpectedMessage(
                "CertificateVerify too short".to_string(),
            ));
        }
        let sig_scheme = u16::from_be_bytes([payload[0], payload[1]]);
        let sig_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if 4 + sig_len > payload.len() {
            return Err(TlsError::UnexpectedMessage(
                "CertificateVerify signature length mismatch".to_string(),
            ));
        }
        let signature = &payload[4..4 + sig_len];

        // Verify the signature against the leaf certificate's public key
        let leaf_cert = &self.server_certificates[0];
        self.verification_policy.verify_certificate_verify(
            sig_scheme,
            leaf_cert,
            &transcript_hash,
            signature,
        )?;

        // Verify the certificate chain
        self.verification_policy.verify_certificate_chain(
            &self.server_certificates,
            &self.hostname,
            std::time::SystemTime::now(),
            self.custom_ca_anchors.as_deref().map(|v| v.as_slice()),
        )?;

        self.state = Tls13State::WaitFinished;
        Ok(HandshakeAction::ContinueReading)
    }

    // =======================================================================
    // Finished processing
    // =======================================================================

    fn process_finished(&mut self, full_msg: &[u8], payload: &[u8]) -> Result<HandshakeAction> {
        let hkdf_algo = self.hkdf_algorithm.unwrap();
        let aead_algo = self.aead_algorithm.unwrap();

        // --- Verify server Finished ---
        // verify_data = HMAC(finished_key, Transcript-Hash(CH..CV))
        let transcript_hash_before_sf = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("missing transcript".to_string()))?
            .current_hash();

        let server_hs_secret = self.server_hs_traffic_secret.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("missing server_hs_traffic_secret".to_string())
        })?;

        let expected_verify_data =
            compute_finished_verify_data(hkdf_algo, server_hs_secret, &transcript_hash_before_sf)?;

        if payload != expected_verify_data.as_slice() {
            return Err(TlsError::HandshakeFailure(
                "server Finished verify_data mismatch".to_string(),
            ));
        }

        // Update transcript with server Finished
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(full_msg);
        }

        // --- Derive Master Secret ---
        let handshake_secret = self
            .handshake_secret
            .take()
            .ok_or_else(|| TlsError::HandshakeFailure("missing handshake_secret".to_string()))?;

        // Master Secret = Derive-Next(Handshake Secret, 0)
        let zero_ikm = vec![0u8; hkdf_algo.hash_len()];
        let master_secret = handshake_secret.derive_next(&zero_ikm)?;

        // --- Derive application traffic secrets ---
        // Transcript-Hash(CH..SF) — includes server Finished
        let transcript_hash_ch_sf = self.transcript.as_ref().unwrap().current_hash();

        let client_app_secret =
            master_secret.derive_secret("c ap traffic", &transcript_hash_ch_sf)?;
        let server_app_secret =
            master_secret.derive_secret("s ap traffic", &transcript_hash_ch_sf)?;
        // Exporter master secret (RFC 8446 §7.5): Derive-Secret(master, "exp
        // master", CH..server Finished). Computed here while both the master
        // secret and the CH..SF transcript hash are in hand; emits nothing on
        // the wire, so it has no fingerprint impact.
        let exporter_master_secret =
            master_secret.derive_secret("exp master", &transcript_hash_ch_sf)?;

        // Emit application traffic secrets via keylog callback
        if let Some(ref cb) = self.keylog_callback {
            if let Some(cr) = self.client_random {
                let cr_hex = to_hex(&cr);
                cb(&format!(
                    "CLIENT_TRAFFIC_SECRET_0 {cr_hex} {}",
                    to_hex(&client_app_secret)
                ));
                cb(&format!(
                    "SERVER_TRAFFIC_SECRET_0 {cr_hex} {}",
                    to_hex(&server_app_secret)
                ));
            }
        }

        // Derive application traffic keys
        let client_key = hkdf_expand_label(
            hkdf_algo,
            &client_app_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let client_iv = hkdf_expand_label(
            hkdf_algo,
            &client_app_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;
        let server_key = hkdf_expand_label(
            hkdf_algo,
            &server_app_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let server_iv = hkdf_expand_label(
            hkdf_algo,
            &server_app_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;

        // --- Build Client EncryptedExtensions (ALPS) ---
        // If the server negotiated ALPS, we must send a Client EE message
        // *before* the client Finished, and include it in the transcript.
        let client_ee = self.build_client_encrypted_extensions();

        // If ALPS was negotiated, update transcript: CH..SF..CEE
        if let Some(ref cee_msg) = client_ee {
            if let Some(ref mut transcript) = self.transcript {
                transcript.update(cee_msg);
            }
        }

        // --- Compute client Finished ---
        let client_hs_secret = self.client_hs_traffic_secret.as_ref().ok_or_else(|| {
            TlsError::HandshakeFailure("missing client_hs_traffic_secret".to_string())
        })?;

        // Transcript for client Finished = CH..SF[..CEE]
        // (includes Client EE if ALPS was negotiated)
        let transcript_for_cf = self.transcript.as_ref().unwrap().current_hash();
        let client_verify_data =
            compute_finished_verify_data(hkdf_algo, client_hs_secret, &transcript_for_cf)?;

        // Build client Finished handshake message
        let mut client_finished = Vec::with_capacity(4 + client_verify_data.len());
        client_finished.push(handshake_type::FINISHED);
        let len = client_verify_data.len() as u32;
        client_finished.push((len >> 16) as u8);
        client_finished.push((len >> 8) as u8);
        client_finished.push(len as u8);
        client_finished.extend_from_slice(&client_verify_data);

        // --- Derive Resumption Master Secret ---
        // Update transcript with client Finished for RMS computation
        if let Some(ref mut transcript) = self.transcript {
            transcript.update(&client_finished);
        }
        let transcript_hash_ch_cf = self.transcript.as_ref().unwrap().current_hash();
        let resumption_master_secret =
            master_secret.derive_secret("res master", &transcript_hash_ch_cf)?;

        self.state = Tls13State::Connected;
        Ok(HandshakeAction::Complete(HandshakeComplete {
            client_encrypted_extensions: client_ee,
            client_finished,
            traffic_secrets: TrafficSecrets {
                aead_algorithm: aead_algo,
                hkdf_algorithm: hkdf_algo,
                client_key,
                client_iv,
                server_key,
                server_iv,
                server_app_secret: server_app_secret.to_vec(),
                client_app_secret: client_app_secret.to_vec(),
                exporter_master_secret,
            },
            negotiated_alpn: self.negotiated_alpn.clone(),
            resumption_master_secret,
            negotiated_cipher_suite: self.cipher_suite.unwrap_or(0x1301),
            server_certificates: self.server_certificates.clone(),
            ech_retry_configs: self.ech_retry_configs.clone(),
            ech_accepted: self.ech_accepted,
            peer_quic_transport_params: self.peer_quic_transport_params.clone(),
            early_data_accepted: self.early_data_accepted,
        }))
    }

    // =======================================================================
    // ECH acceptance detection
    // =======================================================================

    /// Check if the server accepted ECH by computing the accept_confirmation
    /// and comparing with ServerHello.random[24..32].
    ///
    /// Per RFC 9849 Section 7.2:
    ///
    /// ```text
    /// accept_confirmation = HKDF-Expand-Label(
    ///     HKDF-Extract(0, ClientHelloInner.random),
    ///     "ech accept confirmation",
    ///     Transcript-Hash(ClientHelloInner...ServerHello'),
    ///     8)
    /// ```
    ///
    /// where ServerHello' is ServerHello with random[24..32] zeroed before
    /// hashing. The secret is `HKDF-Extract(salt=0, IKM=ClientHelloInner.random)`
    /// — it is NOT the handshake secret and is independent of the ECDH/PSK
    /// secrets. The output is exactly 8 bytes (length 8 is encoded into the
    /// HKDF label, so this is not `derive_secret()[..8]`).
    fn check_ech_acceptance(
        &self,
        hkdf_algo: HkdfAlgorithm,
        inner_hello: &[u8],
        server_hello_msg: &[u8],
        server_random: &[u8; 32],
    ) -> Result<bool> {
        let hash_len = hkdf_algo.hash_len();

        // Build the RFC 9849 trial transcript. With HRR this is
        // message_hash(InnerCH1) + HRR + InnerCH2 + modified ServerHello.
        let mut modified_sh = server_hello_msg.to_vec();
        // ServerHello body starts at offset 4 (handshake header).
        // In the body: version(2) + random(32).
        // random starts at body offset 2, which is msg offset 6.
        // We need to zero bytes [24..32] of the random, i.e. msg[6+24..6+32] = msg[30..38].
        if modified_sh.len() >= 38 {
            modified_sh[30..38].fill(0);
        }

        let mut trial_transcript = TranscriptHash::new(hkdf_algo);
        trial_transcript.update(inner_hello);
        if self.hrr_received {
            trial_transcript.replace_with_message_hash();
            let hrr = self.hrr_raw_bytes.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailure("missing HRR transcript bytes for ECH".to_string())
            })?;
            let inner_ch2 = self.hrr_inner_ch2.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailure("missing inner CH2 transcript bytes for ECH".to_string())
            })?;
            trial_transcript.update(hrr);
            trial_transcript.update(inner_ch2);
        }
        trial_transcript.update(&modified_sh);
        let transcript_hash = trial_transcript.current_hash();

        // Per RFC 9849 §7.2, the confirmation secret is
        //   HKDF-Extract(salt=0, IKM=ClientHelloInner.random)
        // — NOT the handshake secret, and independent of the ECDH shared secret
        // and any PSK. ClientHelloInner.random is bytes [6..38] of the inner
        // handshake message (type(1) + length(3) + legacy_version(2) + random(32)).
        if inner_hello.len() < 38 {
            return Ok(false);
        }
        let inner_random = &inner_hello[6..38];
        let zero_salt = vec![0u8; hash_len];
        let ech_secret = hkdf_extract(hkdf_algo, &zero_salt, inner_random)?;

        // Output is exactly 8 bytes via HKDF-Expand-Label (length 8 encoded in
        // the label), not derive_secret()[..8].
        let accept_conf =
            ech_secret.expand_label("ech accept confirmation", &transcript_hash, 8)?;

        // Compare first 8 bytes with ServerHello.random[24..32].
        let expected = &server_random[24..32];
        let computed = &accept_conf[..8];

        if expected == computed {
            tracing::debug!("ECH accept confirmation matched");
            Ok(true)
        } else {
            tracing::debug!(
                "ECH accept confirmation mismatch: expected {:02x?}, computed {:02x?}",
                expected,
                computed,
            );
            Ok(false)
        }
    }

    fn check_ech_hrr_acceptance(
        &self,
        hkdf_algo: HkdfAlgorithm,
        inner_hello: &[u8],
        hrr_msg: &[u8],
        expected: &[u8; 8],
    ) -> Result<bool> {
        if inner_hello.len() < 38 {
            return Ok(false);
        }

        let mut modified_hrr = hrr_msg.to_vec();
        Self::zero_hrr_ech_confirmation(&mut modified_hrr)?;
        let mut transcript = TranscriptHash::new(hkdf_algo);
        transcript.update(inner_hello);
        transcript.update(&modified_hrr);

        let zero_salt = vec![0u8; hkdf_algo.hash_len()];
        let ech_secret = hkdf_extract(hkdf_algo, &zero_salt, &inner_hello[6..38])?;
        let confirmation = ech_secret.expand_label(
            "hrr ech accept confirmation",
            &transcript.current_hash(),
            8,
        )?;
        Ok(expected.as_slice() == confirmation.as_slice())
    }

    fn zero_hrr_ech_confirmation(hrr_msg: &mut [u8]) -> Result<()> {
        if hrr_msg.len() < 4 + 2 + 32 + 1 + 2 + 1 + 2 {
            return Err(TlsError::HandshakeFailure(
                "HRR too short for ECH confirmation".to_string(),
            ));
        }

        let mut pos = 4 + 2 + 32;
        let sid_len = hrr_msg[pos] as usize;
        pos += 1 + sid_len;
        if pos + 5 > hrr_msg.len() {
            return Err(TlsError::HandshakeFailure(
                "malformed HRR before extensions".to_string(),
            ));
        }
        pos += 2 + 1;
        let ext_len = u16::from_be_bytes([hrr_msg[pos], hrr_msg[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos
            .checked_add(ext_len)
            .filter(|end| *end <= hrr_msg.len())
            .ok_or_else(|| {
                TlsError::HandshakeFailure("malformed HRR extensions length".to_string())
            })?;

        while pos + 4 <= ext_end {
            let extension_type = u16::from_be_bytes([hrr_msg[pos], hrr_msg[pos + 1]]);
            let extension_len = u16::from_be_bytes([hrr_msg[pos + 2], hrr_msg[pos + 3]]) as usize;
            pos += 4;
            if pos + extension_len > ext_end {
                break;
            }
            if extension_type == ext_type::ENCRYPTED_CLIENT_HELLO && extension_len == 8 {
                hrr_msg[pos..pos + 8].fill(0);
                return Ok(());
            }
            pos += extension_len;
        }

        Err(TlsError::HandshakeFailure(
            "HRR ECH confirmation extension not found".to_string(),
        ))
    }

    // =======================================================================
    // Key derivation helpers
    // =======================================================================

    /// Compute ECDH shared secret from our key pair and the server's public key.
    fn compute_shared_secret(&mut self, sh: &ServerHello) -> Result<Vec<u8>> {
        let (server_group, server_public_key) =
            sh.extensions.key_share.as_ref().ok_or_else(|| {
                TlsError::HandshakeFailure("ServerHello missing key_share extension".to_string())
            })?;
        tracing::debug!(
            "Server selected key_share group=0x{:04x}, server_pub_len={}",
            server_group,
            server_public_key.len()
        );

        // Find our key pair matching the server's group
        let kp_idx = self
            .key_pairs
            .iter()
            .position(|kp| kp.group.code_point() == *server_group)
            .ok_or_else(|| {
                TlsError::HandshakeFailure(format!(
                    "server selected group 0x{server_group:04x} but we don't have a key for it"
                ))
            })?;

        // Take ownership of the key pair (consumed by ECDH)
        let kp = self.key_pairs.swap_remove(kp_idx);
        kx::compute_shared_secret(kp, server_public_key)
    }

    /// Derive handshake traffic keys from the shared secret.
    ///
    /// Follows TLS 1.3 key schedule (RFC 8446 Section 7.1):
    /// 1. Early Secret = HKDF-Extract(0, PSK) — PSK=0 for non-PSK, or the resumption PSK
    /// 2. Handshake Secret = Derive-Next(Early Secret, shared_secret)
    /// 3. client/server_handshake_traffic_secret = Derive-Secret(HS, label, CH..SH)
    /// 4. Derive key + IV from each traffic secret
    fn derive_handshake_keys(
        &mut self,
        hkdf_algo: HkdfAlgorithm,
        aead_algo: AeadAlgorithm,
        shared_secret: &[u8],
    ) -> Result<HandshakeKeys> {
        let hash_len = hkdf_algo.hash_len();

        // Step 1: Early Secret
        // If PSK was accepted and we cached the early secret, use it.
        // Otherwise, compute with zero IKM (non-PSK mode).
        let early_secret = if self.psk_accepted {
            if let Some(es) = self.early_secret_from_psk.take() {
                tracing::debug!("tls13.using_psk_early_secret");
                es
            } else {
                // Fallback: shouldn't happen, but compute from PSK if available
                let zero_salt = vec![0u8; hash_len];
                let zero_ikm = vec![0u8; hash_len];
                hkdf_extract(hkdf_algo, &zero_salt, &zero_ikm)?
            }
        } else {
            let zero_salt = vec![0u8; hash_len];
            let zero_ikm = vec![0u8; hash_len];
            hkdf_extract(hkdf_algo, &zero_salt, &zero_ikm)?
        };

        // Step 2: Handshake Secret = Derive-Next(Early Secret, shared_secret)
        let handshake_secret = early_secret.derive_next(shared_secret)?;

        // Step 3: Derive handshake traffic secrets
        let transcript_hash = self
            .transcript
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailure("missing transcript".to_string()))?
            .current_hash();

        let client_hs_secret = handshake_secret.derive_secret("c hs traffic", &transcript_hash)?;
        let server_hs_secret = handshake_secret.derive_secret("s hs traffic", &transcript_hash)?;

        // Step 4: Derive key + IV
        let client_key = hkdf_expand_label(
            hkdf_algo,
            &client_hs_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let client_iv = hkdf_expand_label(
            hkdf_algo,
            &client_hs_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;
        let server_key = hkdf_expand_label(
            hkdf_algo,
            &server_hs_secret,
            "key",
            &[],
            aead_algo.key_len(),
        )?;
        let server_iv = hkdf_expand_label(
            hkdf_algo,
            &server_hs_secret,
            "iv",
            &[],
            aead_algo.nonce_len(),
        )?;

        // Emit handshake traffic secrets via keylog callback (zero-cost when None)
        if let Some(ref cb) = self.keylog_callback {
            if let Some(cr) = self.client_random {
                let cr_hex = to_hex(&cr);
                cb(&format!(
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET {cr_hex} {}",
                    to_hex(&client_hs_secret)
                ));
                cb(&format!(
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET {cr_hex} {}",
                    to_hex(&server_hs_secret)
                ));
            }
        }

        // Save for later use
        self.handshake_secret = Some(handshake_secret);
        self.client_hs_traffic_secret = Some(client_hs_secret);
        self.server_hs_traffic_secret = Some(server_hs_secret);

        Ok(HandshakeKeys {
            hkdf_algorithm: hkdf_algo,
            aead_algorithm: aead_algo,
            server_secret: self.server_hs_traffic_secret.clone().unwrap_or_default(),
            client_secret: self.client_hs_traffic_secret.clone().unwrap_or_default(),
            server_key,
            server_iv,
            client_key,
            client_iv,
        })
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Compute the `verify_data` for a TLS 1.3 Finished message.
///
/// ```text
/// finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
/// verify_data  = HMAC-Hash(finished_key, transcript_hash)
/// ```
fn compute_finished_verify_data(
    hkdf_algo: HkdfAlgorithm,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let hash_len = hkdf_algo.hash_len();
    let finished_key = hkdf_expand_label(hkdf_algo, base_key, "finished", &[], hash_len)?;

    let hmac_algo = match hkdf_algo {
        HkdfAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HkdfAlgorithm::Sha384 => hmac::HMAC_SHA384,
    };

    let key = hmac::Key::new(hmac_algo, &finished_key);
    let tag = hmac::sign(&key, transcript_hash);
    Ok(tag.as_ref().to_vec())
}

/// Decompress a compressed certificate using the specified algorithm.
///
/// Supported algorithms (RFC 8879):
/// - 1: zlib
/// - 2: brotli
///
/// Maximum allowed decompressed certificate size (256 KB).
/// Real-world certificate chains rarely exceed 20 KB; 256 KB is generous.
const MAX_DECOMPRESSED_CERT_LEN: usize = 256 * 1024;

fn decompress_certificate(
    algorithm: u16,
    compressed: &[u8],
    max_uncompressed_len: usize,
) -> Result<Vec<u8>> {
    if max_uncompressed_len > MAX_DECOMPRESSED_CERT_LEN {
        return Err(TlsError::HandshakeFailure(format!(
            "decompressed certificate too large: {} bytes (max {})",
            max_uncompressed_len, MAX_DECOMPRESSED_CERT_LEN,
        )));
    }

    match algorithm {
        1 => {
            use flate2::read::ZlibDecoder;
            let mut decompressed = Vec::with_capacity(max_uncompressed_len);
            let mut reader = ZlibDecoder::new(compressed);
            std::io::Read::read_to_end(&mut reader, &mut decompressed).map_err(|e| {
                TlsError::HandshakeFailure(format!("zlib decompression failed: {e}"))
            })?;
            if decompressed.len() != max_uncompressed_len {
                return Err(TlsError::HandshakeFailure(format!(
                    "decompressed certificate size mismatch: expected {}, got {}",
                    max_uncompressed_len,
                    decompressed.len()
                )));
            }
            Ok(decompressed)
        }
        2 => {
            let mut decompressed = Vec::with_capacity(max_uncompressed_len);
            let mut reader = brotli::Decompressor::new(compressed, 4096);
            std::io::Read::read_to_end(&mut reader, &mut decompressed).map_err(|e| {
                TlsError::HandshakeFailure(format!("brotli decompression failed: {e}"))
            })?;
            if decompressed.len() != max_uncompressed_len {
                return Err(TlsError::HandshakeFailure(format!(
                    "decompressed certificate size mismatch: expected {}, got {}",
                    max_uncompressed_len,
                    decompressed.len()
                )));
            }
            Ok(decompressed)
        }
        _ => Err(TlsError::HandshakeFailure(format!(
            "unsupported certificate compression algorithm: {algorithm}"
        ))),
    }
}

/// Parse a TLS 1.3 Certificate handshake message.
///
/// Returns a list of DER-encoded certificates (leaf first).
fn parse_certificate_message(payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut pos = 0;

    // certificate_request_context<0..255>
    // RFC 8446 §4.4.2: for server auth this field SHALL be zero length
    if pos >= payload.len() {
        return Err(TlsError::UnexpectedMessage(
            "Certificate message too short".to_string(),
        ));
    }
    let ctx_len = payload[pos] as usize;
    if ctx_len != 0 {
        return Err(TlsError::HandshakeFailure(format!(
            "server Certificate has non-empty request_context (len={})",
            ctx_len,
        )));
    }
    pos += 1 + ctx_len;

    // certificate_list<0..2^24-1>
    if pos + 3 > payload.len() {
        return Err(TlsError::UnexpectedMessage(
            "Certificate message truncated at list length".to_string(),
        ));
    }
    let list_len = ((payload[pos] as usize) << 16)
        | ((payload[pos + 1] as usize) << 8)
        | (payload[pos + 2] as usize);
    pos += 3;

    let list_end = pos + list_len;
    if list_end > payload.len() {
        return Err(TlsError::UnexpectedMessage(
            "Certificate list length exceeds message".to_string(),
        ));
    }

    let mut certs = Vec::new();
    while pos + 3 <= list_end {
        // cert_data<1..2^24-1>
        let cert_len = ((payload[pos] as usize) << 16)
            | ((payload[pos + 1] as usize) << 8)
            | (payload[pos + 2] as usize);
        pos += 3;

        if pos + cert_len > list_end {
            return Err(TlsError::UnexpectedMessage(
                "Certificate entry exceeds list".to_string(),
            ));
        }
        certs.push(payload[pos..pos + cert_len].to_vec());
        pos += cert_len;

        // extensions<0..2^16-1> (per-certificate extensions)
        if pos + 2 > list_end {
            break;
        }
        let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2 + ext_len;
    }

    Ok(certs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_hrr(session_id: &[u8], cipher_suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&server_hello::HRR_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = vec![handshake_type::SERVER_HELLO];
        let body_len = body.len() as u32;
        message.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    fn client_hello_extension(message: &[u8], target: u16) -> Option<Vec<u8>> {
        let body = message.get(4..)?;
        let sid_len = *body.get(34)? as usize;
        let mut pos = 35 + sid_len;
        let cipher_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
        pos += 2 + cipher_len;
        let compression_len = *body.get(pos)? as usize;
        pos += 1 + compression_len;
        let extensions_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
        pos += 2;
        let extensions_end = pos.checked_add(extensions_len)?;
        while pos + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4;
            let extension_end = pos.checked_add(extension_len)?;
            if extension_end > extensions_end {
                return None;
            }
            if extension_type == target {
                return Some(body[pos..extension_end].to_vec());
            }
            pos = extension_end;
        }
        None
    }

    fn client_hello_extension_types(message: &[u8]) -> Vec<u16> {
        let Some(body) = message.get(4..) else {
            return Vec::new();
        };
        let Some(&sid_len) = body.get(34) else {
            return Vec::new();
        };
        let mut pos = 35 + sid_len as usize;
        let Some(cipher_len_bytes) = body.get(pos..pos + 2) else {
            return Vec::new();
        };
        let cipher_len = u16::from_be_bytes([cipher_len_bytes[0], cipher_len_bytes[1]]) as usize;
        pos += 2 + cipher_len;
        let Some(&compression_len) = body.get(pos) else {
            return Vec::new();
        };
        pos += 1 + compression_len as usize;
        let Some(extensions_len_bytes) = body.get(pos..pos + 2) else {
            return Vec::new();
        };
        let extensions_len =
            u16::from_be_bytes([extensions_len_bytes[0], extensions_len_bytes[1]]) as usize;
        pos += 2;
        let extensions_end = pos.saturating_add(extensions_len).min(body.len());
        let mut types = Vec::new();
        while pos + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4;
            let extension_end = pos.saturating_add(extension_len);
            if extension_end > extensions_end {
                return Vec::new();
            }
            types.push(extension_type);
            pos = extension_end;
        }
        types
    }

    fn psk_binder(extension_data: &[u8]) -> Vec<u8> {
        let identities_len = u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
        let binders_len_pos = 2 + identities_len;
        let binder_len_pos = binders_len_pos + 2;
        let binder_len = extension_data[binder_len_pos] as usize;
        extension_data[binder_len_pos + 1..binder_len_pos + 1 + binder_len].to_vec()
    }

    fn build_test_ech_config_list() -> Vec<u8> {
        use hpke::kem::X25519HkdfSha256;
        use hpke::{Kem, Serializable};
        use rand_core::TryRngCore;

        let (_secret_key, public_key) =
            X25519HkdfSha256::gen_keypair(&mut rand_core::OsRng.unwrap_err());
        let public_key = public_key.to_bytes();
        let mut contents = Vec::new();
        contents.push(42);
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.push(32);
        let public_name = b"public.example.com";
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name);
        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut config = Vec::new();
        config.extend_from_slice(&0xFE0Du16.to_be_bytes());
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);

        let mut list = Vec::new();
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);
        list
    }

    #[test]
    fn test_cipher_suite_info() {
        let (hkdf, aead) = cipher_suite_info(0x1301).unwrap();
        assert_eq!(hkdf, HkdfAlgorithm::Sha256);
        assert_eq!(aead, AeadAlgorithm::Aes128Gcm);

        let (hkdf, aead) = cipher_suite_info(0x1302).unwrap();
        assert_eq!(hkdf, HkdfAlgorithm::Sha384);
        assert_eq!(aead, AeadAlgorithm::Aes256Gcm);

        let (hkdf, aead) = cipher_suite_info(0x1303).unwrap();
        assert_eq!(hkdf, HkdfAlgorithm::Sha256);
        assert_eq!(aead, AeadAlgorithm::Chacha20Poly1305);

        assert!(cipher_suite_info(0xFFFF).is_err());
    }

    #[test]
    fn test_transcript_hash_basic() {
        let mut th = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th.update(b"hello");
        let h1 = th.current_hash();
        assert_eq!(h1.len(), 32);

        // Updating should change the hash
        th.update(b"world");
        let h2 = th.current_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_transcript_hash_message_hash_replacement() {
        let mut th = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th.update(b"ClientHello1 data");
        let hash_before = th.current_hash();

        th.replace_with_message_hash();

        // After replacement, the hash should be different
        let hash_after = th.current_hash();
        assert_ne!(hash_before, hash_after);
        assert_eq!(hash_after.len(), 32);
    }

    #[test]
    fn test_zero_hrr_ech_confirmation() {
        let confirmation = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&server_hello::HRR_RANDOM);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&12u16.to_be_bytes());
        body.extend_from_slice(&ext_type::ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&confirmation);

        let mut hrr = vec![handshake_type::SERVER_HELLO, 0, 0, body.len() as u8];
        hrr.extend_from_slice(&body);
        Tls13Handshake::zero_hrr_ech_confirmation(&mut hrr).unwrap();
        assert!(hrr.ends_with(&[0u8; 8]));
    }

    #[test]
    fn test_cookie_only_hrr_preserves_key_share() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        let ch1 = handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();

        let cookie = b"retry-cookie";
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&ext_type::COOKIE.to_be_bytes());
        extensions.extend_from_slice(&((2 + cookie.len()) as u16).to_be_bytes());
        extensions.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        extensions.extend_from_slice(cookie);

        let hrr = build_hrr(&session_id, cipher_suite, &extensions);
        let action = handshake.process_handshake_record(&hrr).unwrap();
        let HandshakeAction::RetryClientHello(ch2) = action else {
            panic!("expected retry ClientHello");
        };

        assert_eq!(
            client_hello_extension(&ch2, ext_type::KEY_SHARE),
            client_hello_extension(&ch1, ext_type::KEY_SHARE),
        );
        assert_eq!(
            client_hello_extension(&ch2, ext_type::COOKIE),
            Some([&(cookie.len() as u16).to_be_bytes()[..], cookie].concat()),
        );
    }

    #[test]
    fn test_hrr_rejects_group_already_offered_in_key_share() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let already_offered = profile.key_share_curves[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();

        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
        extensions.extend_from_slice(&already_offered.to_be_bytes());
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);

        let error = handshake.process_handshake_record(&hrr).unwrap_err();
        assert!(error
            .to_string()
            .contains("already present in CH1 key_share"));
    }

    #[test]
    fn test_hrr_rejects_no_requested_change() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.build_client_hello().unwrap();
        let session_id = handshake.session_id.clone().unwrap();
        let extensions = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);

        let error = handshake.process_handshake_record(&hrr).unwrap_err();
        assert!(error
            .to_string()
            .contains("would not change the second ClientHello"));
    }

    #[test]
    fn test_quic_hrr_preserves_transport_parameters_and_empty_session_id() {
        let mut profile = crate::profile::presets::chrome_150();
        profile.alpn_protocols = vec!["h3".to_string()];
        let cipher_suite = profile.cipher_suites[0];
        let mut handshake = Tls13Handshake::new(profile, "example.com");
        handshake.enable_quic_mode();
        handshake.set_quic_transport_parameters(vec![0x01, 0x02, 0x03, 0x04]);
        let ch1 = handshake.build_client_hello().unwrap();
        assert_eq!(ch1[38], 0, "QUIC CH1 legacy_session_id must be empty");

        let session_id = handshake.session_id.clone().unwrap();
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x18]);
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);

        let action = handshake.process_handshake_record(&hrr).unwrap();
        let HandshakeAction::RetryClientHello(ch2) = action else {
            panic!("expected retry ClientHello");
        };
        assert_eq!(ch2[38], 0, "QUIC CH2 legacy_session_id must remain empty");
        assert_eq!(
            client_hello_extension(&ch2, ext_type::QUIC_TRANSPORT_PARAMETERS),
            client_hello_extension(&ch1, ext_type::QUIC_TRANSPORT_PARAMETERS),
        );
    }

    #[test]
    fn test_ech_psk_hrr_binders_cover_inner_client_hellos() {
        use crate::session_store::TicketTlsVersion;
        use std::time::Instant;

        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = 0x1301;
        let resumption_psk = vec![0xA5; 32];
        let ticket = SessionTicketData {
            ticket: b"ech-psk-hrr-ticket".to_vec(),
            resumption_psk: resumption_psk.clone(),
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite,
            lifetime_secs: 3600,
            age_add: 0x1020_3040,
            received_at: Instant::now(),
            alpn: Some("h2".to_string()),
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
        };
        let mut handshake = Tls13Handshake::new(profile, "secret.example.com");
        handshake.set_ech_config(build_test_ech_config_list());
        handshake.set_psk_ticket(ticket);

        let ch1_outer = handshake.build_client_hello().unwrap();
        let ch1_inner = handshake.ech_inner_hello.clone().expect("ECH inner CH1");
        assert!(client_hello_extension(&ch1_outer, ext_type::PRE_SHARED_KEY).is_none());
        assert_eq!(
            client_hello_extension_types(&ch1_inner).last(),
            Some(&ext_type::PRE_SHARED_KEY),
        );
        let ch1_psk = client_hello_extension(&ch1_inner, ext_type::PRE_SHARED_KEY).unwrap();
        let ch1_binder = psk_binder(&ch1_psk);
        let ch1_truncated_len =
            ch1_inner.len() - pre_shared_key::binders_size(1, HkdfAlgorithm::Sha256.hash_len());
        let ch1_hash = digest::digest(&digest::SHA256, &ch1_inner[..ch1_truncated_len]);
        let expected_ch1_binder = pre_shared_key::compute_psk_binder(
            HkdfAlgorithm::Sha256,
            &resumption_psk,
            ch1_hash.as_ref(),
        )
        .unwrap();
        assert_eq!(ch1_binder, expected_ch1_binder);

        let session_id = handshake.session_id.clone().unwrap();
        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x18]);
        let hrr = build_hrr(&session_id, cipher_suite, &extensions);
        let action = handshake.process_handshake_record(&hrr).unwrap();
        let HandshakeAction::RetryClientHello(ch2_outer) = action else {
            panic!("expected retry ClientHello");
        };
        let ch2_inner = handshake.hrr_inner_ch2.clone().expect("ECH inner CH2");

        assert!(client_hello_extension(&ch2_outer, ext_type::PRE_SHARED_KEY).is_none());
        assert!(client_hello_extension(&ch2_outer, ext_type::EARLY_DATA).is_none());
        assert!(client_hello_extension(&ch2_inner, ext_type::EARLY_DATA).is_none());
        assert_eq!(
            client_hello_extension_types(&ch2_inner).last(),
            Some(&ext_type::PRE_SHARED_KEY),
        );
        let ch2_psk = client_hello_extension(&ch2_inner, ext_type::PRE_SHARED_KEY).unwrap();
        let ch2_binder = psk_binder(&ch2_psk);
        let ch2_truncated_len =
            ch2_inner.len() - pre_shared_key::binders_size(1, HkdfAlgorithm::Sha256.hash_len());
        let prefix =
            Tls13Handshake::ech_hrr_psk_transcript_prefix(HkdfAlgorithm::Sha256, &ch1_inner, &hrr);
        let mut transcript = digest::Context::new(&digest::SHA256);
        transcript.update(&prefix);
        transcript.update(&ch2_inner[..ch2_truncated_len]);
        let expected_ch2_binder = pre_shared_key::compute_psk_binder(
            HkdfAlgorithm::Sha256,
            &resumption_psk,
            transcript.finish().as_ref(),
        )
        .unwrap();
        assert_eq!(ch2_binder, expected_ch2_binder);
    }

    #[test]
    fn test_compute_finished_verify_data() {
        let secret = [0x42u8; 32];
        let transcript_hash = [0xAA; 32];
        let vd =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &transcript_hash).unwrap();
        assert_eq!(vd.len(), 32);

        // Same inputs should give same output
        let vd2 =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &transcript_hash).unwrap();
        assert_eq!(vd, vd2);
    }

    #[test]
    fn test_parse_certificate_message() {
        // Build a minimal Certificate message
        let cert1 = vec![0x30, 0x82, 0x01, 0x00]; // fake DER cert
        let cert2 = vec![0x30, 0x82, 0x02, 0x00]; // fake intermediate

        let mut payload = Vec::new();
        // certificate_request_context length = 0
        payload.push(0);
        // certificate_list (we'll fill length after)
        let list_start = payload.len();
        payload.extend_from_slice(&[0, 0, 0]); // placeholder

        // cert1 entry
        let cert1_len = cert1.len() as u32;
        payload.push((cert1_len >> 16) as u8);
        payload.push((cert1_len >> 8) as u8);
        payload.push(cert1_len as u8);
        payload.extend_from_slice(&cert1);
        payload.extend_from_slice(&[0, 0]); // empty extensions

        // cert2 entry
        let cert2_len = cert2.len() as u32;
        payload.push((cert2_len >> 16) as u8);
        payload.push((cert2_len >> 8) as u8);
        payload.push(cert2_len as u8);
        payload.extend_from_slice(&cert2);
        payload.extend_from_slice(&[0, 0]); // empty extensions

        // Fill in list length
        let list_len = payload.len() - list_start - 3;
        payload[list_start] = (list_len >> 16) as u8;
        payload[list_start + 1] = (list_len >> 8) as u8;
        payload[list_start + 2] = list_len as u8;

        let certs = parse_certificate_message(&payload).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], cert1);
        assert_eq!(certs[1], cert2);
    }

    // ====================================================================
    // to_hex — debug formatting
    // ====================================================================

    #[test]
    fn hex_encoding_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn hex_encoding_known_bytes() {
        assert_eq!(to_hex(&[0x00, 0xFF, 0x42]), "00ff42");
    }

    // ====================================================================
    // Tls13Handshake — initial state and configuration
    // ====================================================================

    #[test]
    fn new_handshake_starts_at_start_state() {
        let profile = crate::profile::presets::chrome_144();
        let hs = Tls13Handshake::new(profile, "example.com");
        assert_eq!(hs.state(), Tls13State::Start);
    }

    #[test]
    fn configure_for_alps_h2() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        hs.set_alps_payload(vec![0x00, 0x03, 0x00, 0x64]);
        assert!(hs.alps_payload.is_some());
    }

    /// Real Chrome sends a Client EncryptedExtensions carrying `application_settings`
    /// with an EMPTY payload (verified from a real Chrome 149 capture). Lock that
    /// exact wire encoding for `Some(vec![])`, and the non-empty case for contrast.
    #[test]
    fn client_ee_alps_empty_payload_yields_empty_settings() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        // Server negotiated ALPS with the new code point.
        hs.alps_code_point = Some(0x44CD);

        // Empty client settings (Chrome): EE with a 0-length application_settings.
        hs.alps_payload = Some(Vec::new());
        assert_eq!(
            hs.build_client_encrypted_extensions(),
            // type=0x08, len=0x000006, ext_len=0x0004, ext=0x44CD, data_len=0x0000
            Some(vec![
                0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x44, 0xCD, 0x00, 0x00
            ]),
            "Some(empty) ⇒ Client EE application_settings with 0-length payload"
        );

        // Non-empty client settings are still supported (2-byte payload here).
        hs.alps_payload = Some(vec![0xAA, 0xBB]);
        assert_eq!(
            hs.build_client_encrypted_extensions(),
            Some(vec![
                0x08, 0x00, 0x00, 0x08, 0x00, 0x06, 0x44, 0xCD, 0x00, 0x02, 0xAA, 0xBB
            ]),
            "Some(non-empty) ⇒ payload carried in the Client EE"
        );

        // No payload ⇒ no Client EE at all.
        hs.alps_payload = None;
        assert_eq!(hs.build_client_encrypted_extensions(), None);
    }

    #[test]
    fn configure_insecure_verification() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        hs.set_verification_policy(VerificationPolicy::Insecure);
        assert_eq!(hs.verification_policy, VerificationPolicy::Insecure);
    }

    #[test]
    fn configure_ech_for_privacy() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        let ech_data = vec![0xFE, 0x0D, 0x00, 0x42];
        hs.set_ech_config(ech_data.clone());
        assert_eq!(hs.ech_config_list, Some(ech_data));
    }

    #[test]
    fn configure_custom_ca_anchors() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        hs.set_custom_ca_anchors(Arc::new(vec![]));
        assert!(hs.custom_ca_anchors.is_some());
    }

    #[test]
    fn configure_keylog_callback() {
        let profile = crate::profile::presets::chrome_144();
        let mut hs = Tls13Handshake::new(profile, "example.com");
        let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let captured = lines.clone();
        hs.set_keylog_callback(Arc::new(move |line: &str| {
            captured.lock().unwrap().push(line.to_string());
        }));
        assert!(hs.keylog_callback.is_some());
    }

    // ====================================================================
    // decompress_certificate — brotli compressed certificates (RFC 8879)
    // ====================================================================

    #[test]
    fn brotli_decompress_round_trip() {
        let original = b"This is a test certificate DER payload for brotli compression.";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
            std::io::Write::write_all(&mut writer, original).unwrap();
        }

        let decompressed = decompress_certificate(2, &compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn brotli_decompress_size_mismatch_fails() {
        let original = b"small data";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
            std::io::Write::write_all(&mut writer, original).unwrap();
        }

        // Claim a different uncompressed size
        let result = decompress_certificate(2, &compressed, 9999);
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_compression_algorithm_fails() {
        let result = decompress_certificate(99, &[0x00], 1);
        assert!(result.is_err());
    }

    #[test]
    fn corrupt_brotli_data_fails() {
        let result = decompress_certificate(2, &[0xFF, 0xFF, 0xFF], 10);
        assert!(result.is_err());
    }

    // ====================================================================
    // parse_certificate_message — edge cases
    // ====================================================================

    #[test]
    fn empty_certificate_message_fails() {
        let result = parse_certificate_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn single_cert_chain() {
        let cert = vec![0x30, 0x82, 0x03, 0xAA]; // fake DER

        let mut payload = Vec::new();
        payload.push(0); // empty context
        let list_start = payload.len();
        payload.extend_from_slice(&[0, 0, 0]); // placeholder

        let cert_len = cert.len() as u32;
        payload.push((cert_len >> 16) as u8);
        payload.push((cert_len >> 8) as u8);
        payload.push(cert_len as u8);
        payload.extend_from_slice(&cert);
        payload.extend_from_slice(&[0, 0]); // empty extensions

        let list_len = payload.len() - list_start - 3;
        payload[list_start] = (list_len >> 16) as u8;
        payload[list_start + 1] = (list_len >> 8) as u8;
        payload[list_start + 2] = list_len as u8;

        let certs = parse_certificate_message(&payload).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);
    }

    // ====================================================================
    // TranscriptHash — SHA-384 variant
    // ====================================================================

    #[test]
    fn transcript_hash_sha384() {
        let mut th = TranscriptHash::new(HkdfAlgorithm::Sha384);
        th.update(b"data");
        let hash = th.current_hash();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn transcript_hash_deterministic() {
        let mut th1 = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th1.update(b"same data");
        let mut th2 = TranscriptHash::new(HkdfAlgorithm::Sha256);
        th2.update(b"same data");
        assert_eq!(th1.current_hash(), th2.current_hash());
    }

    // ====================================================================
    // compute_finished_verify_data — different hash sizes
    // ====================================================================

    #[test]
    fn finished_verify_data_sha384_produces_48_bytes() {
        let secret = [0x11u8; 48];
        let hash = [0x22u8; 48];
        let vd = compute_finished_verify_data(HkdfAlgorithm::Sha384, &secret, &hash).unwrap();
        assert_eq!(vd.len(), 48);
    }

    #[test]
    fn finished_verify_data_changes_with_different_transcript() {
        let secret = [0x42u8; 32];
        let vd1 =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &[0xAA; 32]).unwrap();
        let vd2 =
            compute_finished_verify_data(HkdfAlgorithm::Sha256, &secret, &[0xBB; 32]).unwrap();
        assert_ne!(vd1, vd2);
    }
}
