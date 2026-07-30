//! High-level Sans-I/O handshake driver.
//!
//! [`HandshakeDriver`] orchestrates the full TLS handshake (1.3 or 1.2)
//! without any I/O dependency.  The caller feeds raw bytes from the
//! transport and receives byte buffers to send back.
//!
//! This eliminates the 500+ line async state machine that was previously
//! inlined in the I/O adapter layer.

use std::sync::Arc;

use crate::crypto::aead::{Aead, AeadAlgorithm};
use crate::crypto::hkdf::HkdfAlgorithm;
use crate::crypto::to_hex;
use crate::error::{Result, TlsError};
use crate::extensions::quic_transport_params::QuicTransportParams;
use crate::handshake::content_type;
use crate::handshake::server_hello::{check_downgrade_sentinel, detect_version_from_server_hello};
use crate::handshake::tls12::{Tls12Handshake, Tls12HandshakeAction, Tls12State, Tls12TrafficKeys};
use crate::handshake::tls13::{
    HandshakeAction, HandshakeComplete, HandshakeKeys, Tls13Handshake, TrafficSecrets,
};
use crate::profile::types::TlsProfile;
use crate::record::reader::RecordReader;
use crate::record::writer::RecordWriter;
use crate::session_store::{SessionStore, TicketTlsVersion};
use crate::verify::policy::VerificationPolicy;
use crate::{ClientHelloCallback, KeyLogCallback};

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// Output produced by [`HandshakeDriver::progress`].
pub enum HandshakeOutput {
    /// Send these bytes to the remote peer, then call `progress()` again.
    SendData(Vec<u8>),
    /// Need more data from the transport. Call `feed()` then `progress()`.
    NeedData,
    /// Handshake complete. Contains final bytes to send (may be empty)
    /// and the handshake result.
    Done {
        /// Final bytes to send to the peer (client Finished, etc.).
        /// May be empty if everything was already sent.
        to_send: Vec<u8>,
        /// The completed handshake result (boxed to reduce enum size).
        result: Box<HandshakeResult>,
    },
}

/// Result of a completed TLS handshake.
pub struct HandshakeResult {
    /// Record reader with application traffic keys installed.
    pub reader: RecordReader,
    /// Record writer with application traffic keys installed.
    pub writer: RecordWriter,
    /// Negotiated ALPN protocol (if any).
    pub negotiated_alpn: Option<String>,
    /// Negotiated cipher suite (if available).
    pub negotiated_cipher_suite: Option<u16>,
    /// Negotiated TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3).
    pub negotiated_version: Option<u16>,
    /// Server certificate chain (DER, leaf first); empty on resumption.
    pub peer_certificates: Vec<Vec<u8>>,
    /// Post-handshake state for processing KeyUpdate messages (TLS 1.3 only).
    pub post_handshake: Option<PostHandshakeState>,
    /// Session ticket context for processing NewSessionTicket messages.
    pub session_ticket_ctx: Option<SessionTicketContext>,
}

/// Output produced by [`QuicHandshakeDriver::progress`].
pub enum QuicHandshakeOutput {
    /// Raw handshake bytes to send in QUIC CRYPTO frames.
    SendData(Vec<u8>),
    /// Need more decrypted CRYPTO stream bytes.
    NeedData,
    /// Handshake traffic secrets are ready after ServerHello.
    HandshakeSecretsReady {
        to_send: Vec<u8>,
        secrets: QuicTrafficSecrets,
    },
    /// Handshake complete.
    Done {
        to_send: Vec<u8>,
        result: Box<QuicHandshakeResult>,
    },
}

/// QUIC-specific handshake result.
pub struct QuicHandshakeResult {
    pub negotiated_alpn: Option<String>,
    pub negotiated_cipher_suite: Option<u16>,
    pub handshake_secrets: QuicTrafficSecrets,
    pub app_secrets: QuicTrafficSecrets,
    pub post_handshake: Option<PostHandshakeState>,
    pub session_ticket_ctx: Option<SessionTicketContext>,
    pub peer_transport_params: Option<QuicTransportParams>,
    pub early_data_accepted: bool,
}

/// QUIC traffic secrets with the metadata needed for packet key derivation.
#[derive(Debug, Clone)]
pub struct QuicTrafficSecrets {
    pub client_secret: Vec<u8>,
    pub server_secret: Vec<u8>,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
}

/// State needed to process TLS 1.3 KeyUpdate messages after the handshake.
pub struct PostHandshakeState {
    pub server_app_secret: Vec<u8>,
    pub client_app_secret: Vec<u8>,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
    /// Exporter master secret (RFC 8446 §7.5), backing `export_keying_material`.
    pub exporter_master_secret: Vec<u8>,
}

/// Context needed to process NewSessionTicket messages after the handshake.
pub struct SessionTicketContext {
    pub resumption_master_secret: Vec<u8>,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
    pub cipher_suite: u16,
    pub alpn: Option<String>,
    pub peer_transport_parameters: Option<Vec<u8>>,
    pub store: Arc<dyn SessionStore>,
    pub host_key: String,
}

impl SessionTicketContext {
    /// Parse and store a post-handshake NewSessionTicket message.
    pub fn process_new_session_ticket(&self, payload: &[u8]) {
        match crate::session_store::parse_tls13_new_session_ticket(
            payload,
            &self.resumption_master_secret,
            self.hkdf_algorithm,
            self.aead_algorithm,
            self.cipher_suite,
            self.alpn.clone(),
        ) {
            Ok(mut ticket_data) => {
                ticket_data.peer_transport_parameters = self.peer_transport_parameters.clone();
                self.store.store(&self.host_key, ticket_data);
                tracing::debug!(host = %self.host_key, "tls.session_ticket_stored");
            }
            Err(e) => {
                tracing::warn!(error = %e, "tls.session_ticket_parse_failed");
            }
        }
    }
}

impl PostHandshakeState {
    /// Process a TLS 1.3 KeyUpdate message and return the new AEAD
    /// to install on the record reader.
    pub fn process_key_update(&mut self) -> Result<Aead> {
        use crate::crypto::hkdf::hkdf_expand_label;

        let hash_len = self.hkdf_algorithm.hash_len();
        let new_secret = hkdf_expand_label(
            self.hkdf_algorithm,
            &self.server_app_secret,
            "traffic upd",
            &[],
            hash_len,
        )?;

        let new_key = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "key",
            &[],
            self.aead_algorithm.key_len(),
        )?;

        let new_iv = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "iv",
            &[],
            self.aead_algorithm.nonce_len(),
        )?;

        let new_aead = Aead::new(self.aead_algorithm, &new_key, &new_iv)?;
        self.server_app_secret = new_secret;

        tracing::debug!("tls.key_update_processed");
        Ok(new_aead)
    }

    /// Build a KeyUpdate response message and derive a new client (write-side)
    /// AEAD.  Called when the server sends KeyUpdate with `update_requested`.
    ///
    /// Returns `(key_update_message, new_write_aead)`:
    /// - `key_update_message`: the handshake message bytes (type 0x18 + body)
    ///   that the caller must send encrypted with the **current** write key.
    /// - `new_write_aead`: the new AEAD to install on the record writer
    ///   **after** the message has been encrypted.
    pub fn build_key_update_response(&mut self) -> Result<(Vec<u8>, Aead)> {
        use crate::crypto::hkdf::hkdf_expand_label;

        let hash_len = self.hkdf_algorithm.hash_len();
        let new_secret = hkdf_expand_label(
            self.hkdf_algorithm,
            &self.client_app_secret,
            "traffic upd",
            &[],
            hash_len,
        )?;

        let new_key = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "key",
            &[],
            self.aead_algorithm.key_len(),
        )?;

        let new_iv = hkdf_expand_label(
            self.hkdf_algorithm,
            &new_secret,
            "iv",
            &[],
            self.aead_algorithm.nonce_len(),
        )?;

        let new_aead = Aead::new(self.aead_algorithm, &new_key, &new_iv)?;
        self.client_app_secret = new_secret;

        // Build KeyUpdate handshake message:
        //   msg_type = 0x18, length = 1, update_not_requested = 0x00
        let msg = vec![0x18, 0x00, 0x00, 0x01, 0x00];

        tracing::debug!("tls.key_update_response_built");
        Ok((msg, new_aead))
    }
}

// ---------------------------------------------------------------------------
// HandshakeConfig
// ---------------------------------------------------------------------------

/// Configuration for the handshake driver.
#[derive(Clone)]
pub struct HandshakeConfig {
    pub profile: TlsProfile,
    pub hostname: String,
    pub port: u16,
    pub verification_policy: VerificationPolicy,
    pub alps_payload: Option<Vec<u8>>,
    pub session_store: Option<Arc<dyn SessionStore>>,
    pub ech_config_list: Option<Vec<u8>>,
    pub custom_ca_anchors: Option<Arc<Vec<rustls_pki_types::TrustAnchor<'static>>>>,
    pub keylog_callback: Option<KeyLogCallback>,
    /// Observes the raw ClientHello bytes about to be sent (see
    /// [`ClientHelloCallback`]). Does not affect the handshake.
    pub client_hello_callback: Option<ClientHelloCallback>,
}

/// QUIC handshake configuration wrapper.
#[derive(Clone)]
pub struct QuicHandshakeConfig {
    pub tls: HandshakeConfig,
    pub transport_parameters: Vec<u8>,
}

impl HandshakeConfig {
    pub fn into_quic(self, transport_parameters: Vec<u8>) -> QuicHandshakeConfig {
        QuicHandshakeConfig {
            tls: self,
            transport_parameters,
        }
    }
}

// ---------------------------------------------------------------------------
// DriverState
// ---------------------------------------------------------------------------

enum DriverState {
    Start,
    WaitServerHello {
        handshake: Tls13Handshake,
        ch_msg: Vec<u8>,
    },
    Tls13Encrypted {
        handshake: Tls13Handshake,
    },
    Tls12ServerFlight {
        handshake: Tls12Handshake,
        client_random: [u8; 32],
    },
    Tls12WaitServerFinished {
        handshake: Tls12Handshake,
        client_random: [u8; 32],
        traffic_keys: Tls12TrafficKeys,
        server_ccs_received: bool,
    },
    Complete,
}

enum QuicDriverState {
    Start,
    WaitServerHello { handshake: Tls13Handshake },
    Tls13Encrypted { handshake: Tls13Handshake },
    Complete,
}

// ---------------------------------------------------------------------------
// HandshakeDriver
// ---------------------------------------------------------------------------

/// Sans-I/O TLS handshake driver.
///
/// Orchestrates the full TLS 1.3 or 1.2 handshake. Usage:
///
/// 1. Call [`start()`](Self::start) → send the returned bytes.
/// 2. Read from transport → [`feed()`](Self::feed).
/// 3. Call [`progress()`](Self::progress) in a loop:
///    - `SendData(bytes)` → send bytes, then call `progress()` again.
///    - `NeedData` → read more, `feed()`, then `progress()`.
///    - `Done { to_send, result }` → send `to_send`, use `result`.
pub struct HandshakeDriver {
    config: HandshakeConfig,
    state: DriverState,
    reader: RecordReader,
    writer: RecordWriter,
    /// Reassembly buffer for the TLS 1.3 encrypted handshake flight.
    ///
    /// A handshake message MAY be fragmented across several records (RFC 8446
    /// §5.1: "Handshake messages MAY be … fragmented across several records"),
    /// and server Certificate flights routinely are. Decrypted handshake bytes
    /// are appended here and only *complete* messages are handed to the state
    /// machine, with any partial trailer carried to the next record — the same
    /// buffering the QUIC CRYPTO path already does, and what BoringSSL does with
    /// its handshake buffer (`ssl3_read_handshake_bytes`).
    hs_buffer: Vec<u8>,
    /// Original session ticket taken from the store during `start()`.
    /// Preserved so that if the server negotiates TLS 1.2 instead of 1.3,
    /// the ticket can be used for TLS 1.2 session resumption.
    original_ticket: Option<crate::session_store::SessionTicketData>,
    /// Fatal alert record generated for a local protocol error.
    ///
    /// The Sans-I/O API returns the original error to the caller, so the alert
    /// is retained separately for the transport adapter to send best-effort.
    pending_alert: Option<Vec<u8>>,
}

impl HandshakeDriver {
    pub fn new(config: HandshakeConfig) -> Self {
        Self {
            config,
            state: DriverState::Start,
            reader: RecordReader::new(),
            writer: RecordWriter::new(),
            hs_buffer: Vec::new(),
            original_ticket: None,
            pending_alert: None,
        }
    }

    /// Build and return the initial ClientHello record bytes.
    pub fn start(&mut self) -> Result<Vec<u8>> {
        let host_key = format!("{}:{}", self.config.hostname, self.config.port);

        let mut hs = Tls13Handshake::new(self.config.profile.clone(), &self.config.hostname);
        hs.set_verification_policy(self.config.verification_policy);
        if let Some(ref a) = self.config.custom_ca_anchors {
            hs.set_custom_ca_anchors(Arc::clone(a));
        }
        if let Some(ref p) = self.config.alps_payload {
            hs.set_alps_payload(p.clone());
        }
        if let Some(ref e) = self.config.ech_config_list {
            hs.set_ech_config(e.clone());
        }
        if let Some(ref cb) = self.config.keylog_callback {
            hs.set_keylog_callback(Arc::clone(cb));
        }
        let resumption_cfg = &self.config.profile.session_resumption;
        if resumption_cfg.any_enabled() {
            if let Some(ref store) = self.config.session_store {
                if let Some(ticket) = store.take(&host_key) {
                    tracing::debug!(
                        host = %self.config.hostname,
                        ticket_len = ticket.ticket.len(),
                        tls_version = ?ticket.tls_version,
                        "tls.attempting_session_resumption",
                    );
                    match ticket.tls_version {
                        TicketTlsVersion::Tls13 if resumption_cfg.tls13_psk => {
                            let alpn_compatible =
                                match (&ticket.alpn, &self.config.profile.alpn_protocols) {
                                    (None, _) => true,
                                    (Some(alpn), protos) if protos.iter().any(|p| p == alpn) => {
                                        true
                                    }
                                    _ => false,
                                };
                            if alpn_compatible {
                                self.original_ticket = Some(ticket.clone());
                                hs.set_psk_ticket(ticket);
                            } else {
                                tracing::debug!(
                                    host = %self.config.hostname,
                                    ticket_alpn = ?ticket.alpn,
                                    "tls.psk_ticket_alpn_mismatch — skipping resumption",
                                );
                            }
                        }
                        TicketTlsVersion::Tls12 if resumption_cfg.tls12_session_ticket => {
                            let alpn_compatible =
                                match (&ticket.alpn, &self.config.profile.alpn_protocols) {
                                    (None, _) => true,
                                    (Some(alpn), protos) if protos.iter().any(|p| p == alpn) => {
                                        true
                                    }
                                    _ => false,
                                };
                            if alpn_compatible {
                                self.original_ticket = Some(ticket.clone());
                                hs.set_tls12_session_ticket(ticket.ticket.clone());
                            } else {
                                tracing::debug!(
                                    host = %self.config.hostname,
                                    ticket_alpn = ?ticket.alpn,
                                    "tls12.session_ticket_alpn_mismatch — skipping resumption",
                                );
                            }
                        }
                        _ => {
                            tracing::debug!(
                                host = %self.config.hostname,
                                tls_version = ?ticket.tls_version,
                                "tls.session_resumption_disabled_for_version",
                            );
                        }
                    }
                }
            }
        }

        let ch_msg = hs.build_client_hello()?;
        // Observe the exact ClientHello handshake message (0x01-prefixed, before
        // TLS-record framing) the moment it is produced. Honoured here so the hook
        // works for direct lktls users too, not just lkrequest's connector.
        if let Some(ref cb) = self.config.client_hello_callback {
            cb(&ch_msg);
        }
        let ch_record = self.writer.write_record(content_type::HANDSHAKE, &ch_msg)?;
        tracing::debug!("tls.client_hello_sent");

        self.state = DriverState::WaitServerHello {
            handshake: hs,
            ch_msg,
        };
        Ok(ch_record)
    }

    /// Feed raw bytes received from the transport.
    pub fn feed(&mut self, data: &[u8]) {
        self.reader.feed(data);
    }

    /// Drive the handshake forward. Call in a loop after each `feed()`.
    pub fn progress(&mut self) -> Result<HandshakeOutput> {
        match self.progress_inner() {
            Ok(output) => Ok(output),
            Err(error) => {
                if let TlsError::LocalAlert { alert, .. } = &error {
                    match self.writer.write_record(
                        content_type::ALERT,
                        &[alert.level.as_byte(), alert.description.as_byte()],
                    ) {
                        Ok(record) => self.pending_alert = Some(record),
                        Err(record_error) => tracing::warn!(
                            error = %record_error,
                            "tls.local_alert_record_failed"
                        ),
                    }
                }
                Err(error)
            }
        }
    }

    /// Take a locally generated fatal alert record after [`Self::progress`]
    /// returns [`TlsError::LocalAlert`].
    pub fn take_pending_alert(&mut self) -> Option<Vec<u8>> {
        self.pending_alert.take()
    }

    fn progress_inner(&mut self) -> Result<HandshakeOutput> {
        // TLS 1.2 WaitServerFinished has special record-level handling
        if matches!(self.state, DriverState::Tls12WaitServerFinished { .. }) {
            return self.progress_tls12_wait_finished();
        }

        loop {
            let record = match self.reader.next_record()? {
                Some(r) => r,
                None => return Ok(HandshakeOutput::NeedData),
            };

            if record.content_type == content_type::CHANGE_CIPHER_SPEC {
                if let DriverState::Tls12ServerFlight { ref handshake, .. } = self.state {
                    if handshake.state() == Tls12State::WaitCertificateOrAbbreviated {
                        return self.handle_tls12_abbreviated_ccs();
                    }
                }
                continue;
            }

            if record.content_type == content_type::ALERT {
                let level = record.payload.first().copied().unwrap_or(0);
                let desc = record.payload.get(1).copied().unwrap_or(0);
                return Err(TlsError::Alert(crate::error::TlsAlert::from_bytes(
                    level, desc,
                )));
            }

            if record.content_type != content_type::HANDSHAKE {
                return Err(TlsError::UnexpectedMessage(format!(
                    "expected handshake, got content_type=0x{:02x}",
                    record.content_type
                )));
            }

            let state = std::mem::replace(&mut self.state, DriverState::Complete);
            match state {
                DriverState::WaitServerHello { handshake, ch_msg } => {
                    let version = detect_version_from_server_hello(&record.payload)?;
                    tracing::debug!(
                        version = format_args!("0x{:04x}", version),
                        "tls.version_negotiated"
                    );

                    if version == 0x0304 {
                        return self.begin_tls13(handshake, &record.payload);
                    } else if version == 0x0303 {
                        match self.begin_tls12(ch_msg, &record.payload)? {
                            HandshakeOutput::NeedData => continue,
                            other => return Ok(other),
                        }
                    } else {
                        return Err(TlsError::HandshakeFailure(format!(
                            "unsupported TLS version: 0x{version:04x}"
                        )));
                    }
                }
                DriverState::Tls13Encrypted { mut handshake } => {
                    // A handshake message may span several records (RFC 8446
                    // §5.1); large Certificate flights (e.g. Facebook) routinely
                    // do. Accumulate decrypted handshake bytes and process only
                    // complete messages, carrying any partial trailer to the
                    // next record. Multiple coalesced messages in one record are
                    // handled the same way.
                    self.hs_buffer.extend_from_slice(&record.payload);
                    let Some(messages) = take_complete_handshake_messages(&mut self.hs_buffer)?
                    else {
                        // No complete message yet — wait for the next record.
                        self.state = DriverState::Tls13Encrypted { handshake };
                        continue;
                    };
                    match handshake.process_handshake_record(&messages)? {
                        HandshakeAction::ContinueReading => {
                            self.state = DriverState::Tls13Encrypted { handshake };
                            continue;
                        }
                        HandshakeAction::Complete(c) => return self.finish_tls13(c),
                        _ => {
                            return Err(TlsError::HandshakeFailure(
                                "unexpected action during encrypted handshake".into(),
                            ));
                        }
                    }
                }
                DriverState::Tls12ServerFlight {
                    mut handshake,
                    client_random,
                } => {
                    // TLS 1.2 handshake messages (esp. a large Certificate) can
                    // also span several records (RFC 8446 §5.1 applies to 1.2's
                    // record layer too) — buffer and process only complete
                    // messages, mirroring the TLS 1.3 path above.
                    self.hs_buffer.extend_from_slice(&record.payload);
                    let Some(messages) = take_complete_handshake_messages(&mut self.hs_buffer)?
                    else {
                        self.state = DriverState::Tls12ServerFlight {
                            handshake,
                            client_random,
                        };
                        continue;
                    };
                    let action = handshake.process_handshake_record(&messages)?;
                    match action {
                        Tls12HandshakeAction::ContinueReading => {
                            self.state = DriverState::Tls12ServerFlight {
                                handshake,
                                client_random,
                            };
                            continue;
                        }
                        Tls12HandshakeAction::SendClientFlight(flight) => {
                            return self.finish_tls12_full(handshake, client_random, flight);
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailure(
                                "unexpected TLS 1.2 action during server flight".into(),
                            ));
                        }
                    }
                }
                DriverState::Start => {
                    return Err(TlsError::HandshakeFailure("start() not called".into()));
                }
                DriverState::Complete => {
                    return Err(TlsError::HandshakeFailure(
                        "handshake already complete".into(),
                    ));
                }
                DriverState::Tls12WaitServerFinished { .. } => unreachable!(),
            }
        }
    }

    // -----------------------------------------------------------------------
    // TLS 1.3
    // -----------------------------------------------------------------------

    fn begin_tls13(
        &mut self,
        mut handshake: Tls13Handshake,
        server_hello: &[u8],
    ) -> Result<HandshakeOutput> {
        let action = handshake.process_handshake_record(server_hello)?;
        match action {
            HandshakeAction::InstallHandshakeKeys(keys) => {
                let ccs = if handshake.has_received_hrr() {
                    Vec::new()
                } else {
                    self.writer
                        .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?
                };
                self.reader.set_keys(Aead::new(
                    keys.aead_algorithm,
                    &keys.server_key,
                    &keys.server_iv,
                )?);
                self.writer.set_keys(Aead::new(
                    keys.aead_algorithm,
                    &keys.client_key,
                    &keys.client_iv,
                )?);
                self.state = DriverState::Tls13Encrypted { handshake };
                Ok(HandshakeOutput::SendData(ccs))
            }
            HandshakeAction::RetryClientHello(ch2) => {
                let ccs = self
                    .writer
                    .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?;
                let mut rw = RecordWriter::new();
                rw.mark_post_initial();
                let ch2_record = rw.write_record(content_type::HANDSHAKE, &ch2)?;

                let mut buf = ccs;
                buf.extend_from_slice(&ch2_record);

                self.state = DriverState::WaitServerHello {
                    handshake,
                    ch_msg: ch2,
                };
                Ok(HandshakeOutput::SendData(buf))
            }
            _ => Err(TlsError::HandshakeFailure(
                "unexpected action after ServerHello".into(),
            )),
        }
    }

    fn finish_tls13(&mut self, complete: HandshakeComplete) -> Result<HandshakeOutput> {
        let mut send_buf = Vec::new();

        if let Some(ref cee) = complete.client_encrypted_extensions {
            send_buf.extend_from_slice(&self.writer.write_record(content_type::HANDSHAKE, cee)?);
        }
        send_buf.extend_from_slice(
            &self
                .writer
                .write_record(content_type::HANDSHAKE, &complete.client_finished)?,
        );

        let ts = &complete.traffic_secrets;
        self.reader
            .set_keys(Aead::new(ts.aead_algorithm, &ts.server_key, &ts.server_iv)?);
        self.writer
            .set_keys(Aead::new(ts.aead_algorithm, &ts.client_key, &ts.client_iv)?);

        if complete.ech_accepted {
            tracing::info!(host = %self.config.hostname, "tls.ech_accepted");
        }
        if let Some(ref rc) = complete.ech_retry_configs {
            tracing::info!(host = %self.config.hostname, len = rc.len(), "tls.ech_retry_configs_received");
        }
        tracing::debug!(
            version = "TLS1.3",
            alpn = ?complete.negotiated_alpn,
            aead = ?ts.aead_algorithm,
            ech_accepted = complete.ech_accepted,
            "tls.handshake_complete",
        );

        let host_key = format!("{}:{}", self.config.hostname, self.config.port);
        let st_ctx = if self.config.profile.session_resumption.store_tickets {
            self.config
                .session_store
                .as_ref()
                .map(|store| SessionTicketContext {
                    resumption_master_secret: complete.resumption_master_secret.clone(),
                    hkdf_algorithm: ts.hkdf_algorithm,
                    aead_algorithm: ts.aead_algorithm,
                    cipher_suite: complete.negotiated_cipher_suite,
                    alpn: complete.negotiated_alpn.clone(),
                    peer_transport_parameters: None,
                    store: Arc::clone(store),
                    host_key,
                })
        } else {
            None
        };

        self.state = DriverState::Complete;
        Ok(HandshakeOutput::Done {
            to_send: send_buf,
            result: Box::new(HandshakeResult {
                reader: std::mem::take(&mut self.reader),
                writer: std::mem::take(&mut self.writer),
                negotiated_alpn: complete.negotiated_alpn,
                negotiated_cipher_suite: Some(complete.negotiated_cipher_suite),
                negotiated_version: Some(0x0304),
                peer_certificates: complete.server_certificates,
                post_handshake: Some(PostHandshakeState {
                    server_app_secret: ts.server_app_secret.clone(),
                    client_app_secret: ts.client_app_secret.clone(),
                    hkdf_algorithm: ts.hkdf_algorithm,
                    aead_algorithm: ts.aead_algorithm,
                    exporter_master_secret: ts.exporter_master_secret.clone(),
                }),
                session_ticket_ctx: st_ctx,
            }),
        })
    }

    // -----------------------------------------------------------------------
    // TLS 1.2
    // -----------------------------------------------------------------------

    fn begin_tls12(&mut self, ch_msg: Vec<u8>, server_hello: &[u8]) -> Result<HandshakeOutput> {
        // RFC 8446 §4.1.3: only TLS 1.3-capable clients MUST check the
        // ServerHello.random downgrade sentinel. A client that explicitly
        // capped its `tls_max_version` at TLS 1.2 (e.g. Java SSLEngine,
        // Charles MITM) didn't advertise 1.3 in the first place, so the
        // server's sentinel is informational only and aborting on it would
        // wrongly reject every TLS 1.3-capable origin.
        if self.config.profile.tls_max_version.as_u16() >= 0x0304 {
            check_downgrade_sentinel(server_hello)?;
        }

        let client_random: [u8; 32] = ch_msg[4 + 2..4 + 2 + 32]
            .try_into()
            .map_err(|_| TlsError::HandshakeFailure("ClientHello too short".into()))?;

        let mut tls12 = Tls12Handshake::new(
            client_random,
            &self.config.hostname,
            self.config.verification_policy,
        );
        if let Some(ref a) = self.config.custom_ca_anchors {
            tls12.set_custom_ca_anchors(Arc::clone(a));
        }

        if let Some(ticket) = self.original_ticket.take() {
            if ticket.tls_version == TicketTlsVersion::Tls12 && !ticket.master_secret.is_empty() {
                tracing::debug!(host = %self.config.hostname, "tls12.attempting_session_ticket_resumption");
                tls12.set_session_ticket_master_secret(ticket.master_secret.clone());
            }
        }

        tls12.feed_client_hello(&ch_msg);
        // The first server record may coalesce ServerHello with (part of) the
        // Certificate flight, and a handshake message may be fragmented across
        // records (RFC 8446 §5.1). Process the complete messages here and carry
        // any partial trailer into `hs_buffer` for the Tls12ServerFlight state.
        let mut initial = server_hello.to_vec();
        let action = match take_complete_handshake_messages(&mut initial)? {
            Some(msgs) => tls12.process_handshake_record(&msgs)?,
            None => Tls12HandshakeAction::ContinueReading,
        };
        self.hs_buffer = initial;
        match action {
            Tls12HandshakeAction::ContinueReading => {
                self.state = DriverState::Tls12ServerFlight {
                    handshake: tls12,
                    client_random,
                };
                Ok(HandshakeOutput::NeedData)
            }
            Tls12HandshakeAction::SendClientFlight(flight) => {
                self.finish_tls12_full(tls12, client_random, flight)
            }
            _ => {
                self.state = DriverState::Tls12ServerFlight {
                    handshake: tls12,
                    client_random,
                };
                Ok(HandshakeOutput::NeedData)
            }
        }
    }

    fn handle_tls12_abbreviated_ccs(&mut self) -> Result<HandshakeOutput> {
        let state = std::mem::replace(&mut self.state, DriverState::Complete);
        let (mut handshake, client_random) = match state {
            DriverState::Tls12ServerFlight {
                handshake,
                client_random,
            } => (handshake, client_random),
            _ => {
                return Err(TlsError::HandshakeFailure(
                    "unexpected state for abbreviated CCS".into(),
                ))
            }
        };

        let tk = handshake.accept_abbreviated_ccs()?;
        tk.install_on_reader(&mut self.reader)?;

        // Try to read server Finished from buffered data
        loop {
            match self.reader.next_record()? {
                Some(rec) if rec.content_type == content_type::CHANGE_CIPHER_SPEC => continue,
                Some(rec) if rec.content_type == content_type::HANDSHAKE => {
                    return self.complete_tls12_abbreviated(handshake, client_random, &rec.payload);
                }
                Some(rec) => {
                    return Err(TlsError::UnexpectedMessage(format!(
                        "expected server Finished, got 0x{:02x}",
                        rec.content_type
                    )));
                }
                None => {
                    // Need more data — transition to a waiting state.
                    // Re-use Tls12WaitServerFinished with a flag.
                    self.state = DriverState::Tls12WaitServerFinished {
                        handshake,
                        client_random,
                        traffic_keys: tk,
                        server_ccs_received: true,
                    };
                    return Ok(HandshakeOutput::NeedData);
                }
            }
        }
    }

    fn complete_tls12_abbreviated(
        &mut self,
        mut handshake: Tls12Handshake,
        client_random: [u8; 32],
        finished_payload: &[u8],
    ) -> Result<HandshakeOutput> {
        let abbr_flight = handshake.process_abbreviated_server_finished(finished_payload)?;

        let ccs = self
            .writer
            .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?;
        abbr_flight
            .traffic_keys
            .install_on_writer(&mut self.writer)?;
        let fin = self
            .writer
            .write_record(content_type::HANDSHAKE, &abbr_flight.client_finished)?;

        let mut send_buf = Vec::with_capacity(ccs.len() + fin.len());
        send_buf.extend_from_slice(&ccs);
        send_buf.extend_from_slice(&fin);

        self.emit_tls12_keylog(&handshake, &client_random);

        let alpn = handshake.negotiated_alpn().map(|s| s.to_string());
        tracing::debug!(
            version = "TLS1.2", cipher = ?abbr_flight.traffic_keys.cipher_suite,
            alpn = ?alpn, abbreviated = true, "tls.handshake_complete",
        );

        self.state = DriverState::Complete;
        Ok(HandshakeOutput::Done {
            to_send: send_buf,
            result: Box::new(HandshakeResult {
                reader: std::mem::take(&mut self.reader),
                writer: std::mem::take(&mut self.writer),
                negotiated_alpn: alpn,
                negotiated_cipher_suite: Some(abbr_flight.traffic_keys.cipher_suite.code_point()),
                negotiated_version: Some(0x0303),
                peer_certificates: handshake.server_certificates().to_vec(),
                post_handshake: None,
                session_ticket_ctx: None,
            }),
        })
    }

    fn finish_tls12_full(
        &mut self,
        handshake: Tls12Handshake,
        client_random: [u8; 32],
        flight: crate::handshake::tls12::Tls12ClientFlight,
    ) -> Result<HandshakeOutput> {
        let cke = self
            .writer
            .write_record(content_type::HANDSHAKE, &flight.client_key_exchange)?;
        let ccs = self
            .writer
            .write_record(content_type::CHANGE_CIPHER_SPEC, &[0x01])?;
        flight.traffic_keys.install_on_writer(&mut self.writer)?;
        let fin = self
            .writer
            .write_record(content_type::HANDSHAKE, &flight.client_finished)?;

        let mut send_buf = Vec::with_capacity(cke.len() + ccs.len() + fin.len());
        send_buf.extend_from_slice(&cke);
        send_buf.extend_from_slice(&ccs);
        send_buf.extend_from_slice(&fin);

        self.state = DriverState::Tls12WaitServerFinished {
            handshake,
            client_random,
            traffic_keys: flight.traffic_keys,
            server_ccs_received: false,
        };

        Ok(HandshakeOutput::SendData(send_buf))
    }

    fn progress_tls12_wait_finished(&mut self) -> Result<HandshakeOutput> {
        loop {
            let record = match self.reader.next_record()? {
                Some(r) => r,
                None => return Ok(HandshakeOutput::NeedData),
            };

            if record.content_type == content_type::ALERT {
                let level = record.payload.first().copied().unwrap_or(0);
                let desc = record.payload.get(1).copied().unwrap_or(0);
                return Err(TlsError::Alert(crate::error::TlsAlert::from_bytes(
                    level, desc,
                )));
            }

            let server_ccs_received = match &self.state {
                DriverState::Tls12WaitServerFinished {
                    server_ccs_received,
                    ..
                } => *server_ccs_received,
                _ => return Err(TlsError::HandshakeFailure("unexpected state".into())),
            };

            if record.content_type == content_type::CHANGE_CIPHER_SPEC {
                if !server_ccs_received {
                    // Install read keys: need to take ownership of traffic_keys temporarily
                    // to call install_on_reader (which borrows &mut self.reader).
                    let state = std::mem::replace(&mut self.state, DriverState::Complete);
                    if let DriverState::Tls12WaitServerFinished {
                        handshake,
                        client_random,
                        traffic_keys,
                        ..
                    } = state
                    {
                        traffic_keys.install_on_reader(&mut self.reader)?;
                        self.state = DriverState::Tls12WaitServerFinished {
                            handshake,
                            client_random,
                            traffic_keys,
                            server_ccs_received: true,
                        };
                    }
                }
                continue;
            }

            if record.content_type == content_type::HANDSHAKE {
                let msg_type = record.payload.first().copied().unwrap_or(0);

                if !server_ccs_received {
                    // Pre-CCS handshake message (e.g. NewSessionTicket)
                    self.try_store_tls12_session_ticket(msg_type, &record.payload);

                    if let DriverState::Tls12WaitServerFinished {
                        ref mut handshake, ..
                    } = self.state
                    {
                        handshake.feed_handshake_message(&record.payload);
                    }
                    continue;
                }

                // Post-CCS: this should be server Finished
                let state = std::mem::replace(&mut self.state, DriverState::Complete);
                if let DriverState::Tls12WaitServerFinished {
                    mut handshake,
                    client_random,
                    traffic_keys,
                    ..
                } = state
                {
                    handshake.notify_server_ccs_received();
                    handshake.process_server_finished(&record.payload)?;

                    self.emit_tls12_keylog(&handshake, &client_random);

                    let alpn = handshake.negotiated_alpn().map(|s| s.to_string());
                    tracing::debug!(
                        version = "TLS1.2", cipher = ?traffic_keys.cipher_suite,
                        alpn = ?alpn, "tls.handshake_complete",
                    );

                    self.state = DriverState::Complete;
                    return Ok(HandshakeOutput::Done {
                        to_send: Vec::new(),
                        result: Box::new(HandshakeResult {
                            reader: std::mem::take(&mut self.reader),
                            writer: std::mem::take(&mut self.writer),
                            negotiated_alpn: alpn,
                            negotiated_cipher_suite: Some(traffic_keys.cipher_suite.code_point()),
                            negotiated_version: Some(0x0303),
                            peer_certificates: handshake.server_certificates().to_vec(),
                            post_handshake: None,
                            session_ticket_ctx: None,
                        }),
                    });
                }
            }
        }
    }

    /// Try to parse and store a TLS 1.2 NewSessionTicket from a pre-CCS handshake message.
    fn try_store_tls12_session_ticket(&self, msg_type: u8, payload: &[u8]) {
        if msg_type != 0x04 {
            return;
        }
        if !self.config.profile.session_resumption.store_tickets {
            return;
        }
        let DriverState::Tls12WaitServerFinished { ref handshake, .. } = self.state else {
            return;
        };
        let Some(ref store) = self.config.session_store else {
            return;
        };
        let Some(ms) = handshake.master_secret() else {
            return;
        };
        let host_key = format!("{}:{}", self.config.hostname, self.config.port);
        match crate::session_store::parse_tls12_new_session_ticket(
            payload,
            ms,
            handshake.negotiated_alpn().map(|s| s.to_string()),
            handshake.negotiated_cipher_suite(),
        ) {
            Ok(td) => {
                store.store(&host_key, td);
                tracing::debug!(host = %host_key, "tls12.session_ticket_stored");
            }
            Err(e) => {
                tracing::warn!(error = %e, "tls12.session_ticket_parse_failed");
            }
        }
    }

    fn emit_tls12_keylog(&self, handshake: &Tls12Handshake, client_random: &[u8; 32]) {
        if let Some(ref cb) = self.config.keylog_callback {
            if let Some(ms) = handshake.master_secret() {
                cb(&format!(
                    "CLIENT_RANDOM {} {}",
                    to_hex(client_random),
                    to_hex(ms)
                ));
            }
        }
    }
}

/// Sans-I/O QUIC-TLS handshake driver.
pub struct QuicHandshakeDriver {
    config: QuicHandshakeConfig,
    state: QuicDriverState,
    input: Vec<u8>,
    handshake_secrets: Option<QuicTrafficSecrets>,
}

impl QuicHandshakeDriver {
    pub fn new(config: QuicHandshakeConfig) -> Self {
        Self {
            config,
            state: QuicDriverState::Start,
            input: Vec::new(),
            handshake_secrets: None,
        }
    }

    pub fn start(&mut self) -> Result<Vec<u8>> {
        let host_key = format!("{}:{}", self.config.tls.hostname, self.config.tls.port);

        let mut hs =
            Tls13Handshake::new(self.config.tls.profile.clone(), &self.config.tls.hostname);
        hs.enable_quic_mode();
        hs.set_quic_transport_parameters(self.config.transport_parameters.clone());
        if let Some(ref p) = self.config.tls.alps_payload {
            hs.set_alps_payload(p.clone());
        }
        hs.set_verification_policy(self.config.tls.verification_policy);
        if let Some(ref anchors) = self.config.tls.custom_ca_anchors {
            hs.set_custom_ca_anchors(Arc::clone(anchors));
        }
        if let Some(ref ech) = self.config.tls.ech_config_list {
            hs.set_ech_config(ech.clone());
        }
        if let Some(ref cb) = self.config.tls.keylog_callback {
            hs.set_keylog_callback(Arc::clone(cb));
        }

        let resumption_cfg = &self.config.tls.profile.session_resumption;
        if resumption_cfg.tls13_psk {
            if let Some(ref store) = self.config.tls.session_store {
                if let Some(ticket) = store.take(&host_key) {
                    if ticket.tls_version == TicketTlsVersion::Tls13 {
                        let alpn_compatible =
                            match (&ticket.alpn, &self.config.tls.profile.alpn_protocols) {
                                (None, _) => true,
                                (Some(alpn), protos) if protos.iter().any(|p| p == alpn) => true,
                                _ => false,
                            };
                        if alpn_compatible {
                            hs.set_psk_ticket(ticket);
                        }
                    }
                }
            }
        }

        let ch = hs.build_client_hello()?;
        // Same ClientHello observation hook as the TCP driver. QUIC has no TLS
        // record layer, so this is the bare handshake message (CRYPTO-frame
        // payload) — matching what the TCP driver emits to the callback.
        if let Some(ref cb) = self.config.tls.client_hello_callback {
            cb(&ch);
        }
        self.state = QuicDriverState::WaitServerHello { handshake: hs };
        Ok(ch)
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    pub fn progress(&mut self) -> Result<QuicHandshakeOutput> {
        loop {
            let state = std::mem::replace(&mut self.state, QuicDriverState::Complete);
            match state {
                QuicDriverState::Start => {
                    return Err(TlsError::HandshakeFailure("start() not called".into()));
                }
                QuicDriverState::Complete => {
                    return Err(TlsError::HandshakeFailure(
                        "handshake already complete".into(),
                    ));
                }
                QuicDriverState::WaitServerHello { handshake } => {
                    let Some(server_hello) = take_next_handshake_message(&mut self.input)? else {
                        self.state = QuicDriverState::WaitServerHello { handshake };
                        return Ok(QuicHandshakeOutput::NeedData);
                    };

                    let version = detect_version_from_server_hello(&server_hello)?;
                    if version != 0x0304 {
                        return Err(TlsError::HandshakeFailure(format!(
                            "QUIC requires TLS 1.3, got 0x{version:04x}"
                        )));
                    }
                    return self.begin_quic_tls13(handshake, &server_hello);
                }
                QuicDriverState::Tls13Encrypted { mut handshake } => {
                    let Some(messages) = take_complete_handshake_messages(&mut self.input)? else {
                        self.state = QuicDriverState::Tls13Encrypted { handshake };
                        return Ok(QuicHandshakeOutput::NeedData);
                    };

                    match handshake.process_handshake_record(&messages)? {
                        HandshakeAction::ContinueReading => {
                            self.state = QuicDriverState::Tls13Encrypted { handshake };
                            continue;
                        }
                        HandshakeAction::Complete(complete) => {
                            return self.finish_quic_tls13(complete);
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailure(
                                "unexpected action during QUIC encrypted handshake".into(),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn begin_quic_tls13(
        &mut self,
        mut handshake: Tls13Handshake,
        server_hello: &[u8],
    ) -> Result<QuicHandshakeOutput> {
        match handshake.process_handshake_record(server_hello)? {
            HandshakeAction::InstallHandshakeKeys(keys) => {
                let secrets = quic_secrets_from_handshake_keys(&keys);
                self.handshake_secrets = Some(secrets.clone());
                self.state = QuicDriverState::Tls13Encrypted { handshake };
                Ok(QuicHandshakeOutput::HandshakeSecretsReady {
                    to_send: Vec::new(),
                    secrets,
                })
            }
            HandshakeAction::RetryClientHello(ch2) => {
                self.state = QuicDriverState::WaitServerHello { handshake };
                Ok(QuicHandshakeOutput::SendData(ch2))
            }
            _ => Err(TlsError::HandshakeFailure(
                "unexpected action after QUIC ServerHello".into(),
            )),
        }
    }

    fn finish_quic_tls13(&mut self, complete: HandshakeComplete) -> Result<QuicHandshakeOutput> {
        let mut to_send = Vec::new();
        if let Some(ref cee) = complete.client_encrypted_extensions {
            to_send.extend_from_slice(cee);
        }
        to_send.extend_from_slice(&complete.client_finished);

        let host_key = format!("{}:{}", self.config.tls.hostname, self.config.tls.port);
        let session_ticket_ctx = if self.config.tls.profile.session_resumption.store_tickets {
            self.config
                .tls
                .session_store
                .as_ref()
                .map(|store| SessionTicketContext {
                    resumption_master_secret: complete.resumption_master_secret.clone(),
                    hkdf_algorithm: complete.traffic_secrets.hkdf_algorithm,
                    aead_algorithm: complete.traffic_secrets.aead_algorithm,
                    cipher_suite: complete.negotiated_cipher_suite,
                    alpn: complete.negotiated_alpn.clone(),
                    peer_transport_parameters: complete
                        .peer_quic_transport_params
                        .as_ref()
                        .map(crate::extensions::quic_transport_params::encode_transport_params),
                    store: Arc::clone(store),
                    host_key,
                })
        } else {
            None
        };

        let app_secrets = quic_secrets_from_traffic_secrets(&complete.traffic_secrets);
        let handshake_secrets = self.handshake_secrets.clone().ok_or_else(|| {
            TlsError::HandshakeFailure("missing QUIC handshake traffic secrets".to_string())
        })?;

        self.state = QuicDriverState::Complete;
        Ok(QuicHandshakeOutput::Done {
            to_send,
            result: Box::new(QuicHandshakeResult {
                negotiated_alpn: complete.negotiated_alpn,
                negotiated_cipher_suite: Some(complete.negotiated_cipher_suite),
                handshake_secrets,
                app_secrets: app_secrets.clone(),
                post_handshake: Some(PostHandshakeState {
                    server_app_secret: app_secrets.server_secret.clone(),
                    client_app_secret: app_secrets.client_secret.clone(),
                    hkdf_algorithm: app_secrets.hkdf_algorithm,
                    aead_algorithm: app_secrets.aead_algorithm,
                    exporter_master_secret: complete.traffic_secrets.exporter_master_secret.clone(),
                }),
                session_ticket_ctx,
                peer_transport_params: complete.peer_quic_transport_params,
                early_data_accepted: complete.early_data_accepted,
            }),
        })
    }
}

fn quic_secrets_from_handshake_keys(keys: &HandshakeKeys) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        client_secret: keys.client_secret.clone(),
        server_secret: keys.server_secret.clone(),
        hkdf_algorithm: keys.hkdf_algorithm,
        aead_algorithm: keys.aead_algorithm,
    }
}

fn quic_secrets_from_traffic_secrets(secrets: &TrafficSecrets) -> QuicTrafficSecrets {
    QuicTrafficSecrets {
        client_secret: secrets.client_app_secret.clone(),
        server_secret: secrets.server_app_secret.clone(),
        hkdf_algorithm: secrets.hkdf_algorithm,
        aead_algorithm: secrets.aead_algorithm,
    }
}

fn take_complete_handshake_messages(input: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    let mut pos = 0usize;
    while pos < input.len() {
        if input.len() - pos < 4 {
            break;
        }

        let length = ((input[pos + 1] as usize) << 16)
            | ((input[pos + 2] as usize) << 8)
            | (input[pos + 3] as usize);
        let Some(msg_end) = pos.checked_add(4 + length) else {
            return Err(TlsError::UnexpectedMessage(
                "handshake message length overflow".to_string(),
            ));
        };
        if msg_end > input.len() {
            break;
        }
        pos = msg_end;
    }

    if pos == 0 {
        return Ok(None);
    }

    Ok(Some(input.drain(..pos).collect()))
}

fn take_next_handshake_message(input: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    if input.len() < 4 {
        return Ok(None);
    }

    let length = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | (input[3] as usize);
    let Some(end) = 4usize.checked_add(length) else {
        return Err(TlsError::UnexpectedMessage(
            "handshake message length overflow".to_string(),
        ));
    };
    if end > input.len() {
        return Ok(None);
    }

    Ok(Some(input.drain(..end).collect()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::AeadAlgorithm;
    use crate::crypto::hkdf::HkdfAlgorithm;
    use crate::extensions::quic_transport_params::{
        encode_transport_params, param_id, QuicTransportParam, QuicTransportParams,
    };
    use crate::session_store::{InMemorySessionStore, SessionTicketData, TicketTlsVersion};
    use std::sync::Arc;
    use std::time::Instant;

    // -----------------------------------------------------------------------
    // Handshake-message reassembly across records (RFC 8446 §5.1)
    //
    // A handshake message MAY be fragmented across several TLS records, and
    // several messages MAY be coalesced into one. The TLS 1.2 and 1.3 driver
    // paths both feed decrypted record payloads through
    // `take_complete_handshake_messages`, which drains only *complete* messages
    // and retains any partial trailer for the next record. These tests lock in
    // that behaviour — the exact scenario that made Facebook (a fragmented
    // Certificate flight) fail with "truncated handshake message in record".
    // -----------------------------------------------------------------------

    /// Build a handshake message: 1-byte type + 3-byte length + `len` body bytes.
    fn hs_msg(msg_type: u8, fill: u8, len: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(4 + len);
        m.push(msg_type);
        m.push((len >> 16) as u8);
        m.push((len >> 8) as u8);
        m.push(len as u8);
        m.resize(4 + len, fill);
        m
    }

    fn hrr_message(session_id: &[u8], cipher_suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&crate::handshake::server_hello::HRR_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = vec![crate::handshake::handshake_type::SERVER_HELLO];
        let body_len = body.len();
        message.extend_from_slice(&[
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn local_hrr_error_queues_plaintext_fatal_alert() {
        let profile = crate::profile::presets::chrome_150();
        let cipher_suite = profile.cipher_suites[0];
        let already_offered = profile.key_share_curves[0];
        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.profile = profile;
        config.hostname = "example.com".to_string();
        config.verification_policy = VerificationPolicy::Insecure;
        let mut driver = HandshakeDriver::new(config);

        let client_hello_record = driver.start().unwrap();
        let client_hello = &client_hello_record[5..];
        let session_id_len = client_hello[38] as usize;
        let session_id = &client_hello[39..39 + session_id_len];

        let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
        extensions.extend_from_slice(&already_offered.to_be_bytes());
        let hrr = hrr_message(session_id, cipher_suite, &extensions);
        let mut record = vec![content_type::HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(hrr.len() as u16).to_be_bytes());
        record.extend_from_slice(&hrr);
        driver.feed(&record);

        let error = match driver.progress() {
            Err(error) => error,
            Ok(_) => panic!("invalid HRR must fail"),
        };
        assert!(matches!(
            error,
            TlsError::LocalAlert {
                alert: crate::error::TlsAlert {
                    description: crate::error::AlertDescription::IllegalParameter,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            driver.take_pending_alert().as_deref(),
            Some(&[content_type::ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f][..])
        );
        assert!(driver.take_pending_alert().is_none());
    }

    #[test]
    fn reassembly_single_complete_message() {
        let msg = hs_msg(0x0b, 0xAA, 10);
        let mut buf = msg.clone();
        let out = take_complete_handshake_messages(&mut buf).unwrap();
        assert_eq!(out.as_deref(), Some(msg.as_slice()));
        assert!(buf.is_empty(), "buffer fully drained");
    }

    #[test]
    fn reassembly_coalesced_messages_drain_together() {
        let a = hs_msg(0x08, 0x01, 3);
        let b = hs_msg(0x0b, 0x02, 5);
        let mut buf = [a.clone(), b.clone()].concat();
        let out = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out, [a, b].concat());
        assert!(buf.is_empty());
    }

    #[test]
    fn reassembly_message_fragmented_across_records() {
        // The core regression: one message split across two records. The first
        // record carries only part of it → nothing surfaced yet; the remainder
        // in the next record completes it. (Previously errored "truncated".)
        let msg = hs_msg(0x0b, 0xCD, 20);
        let (head, tail) = msg.split_at(11);

        let mut buf = head.to_vec();
        assert!(
            take_complete_handshake_messages(&mut buf)
                .unwrap()
                .is_none(),
            "a partial message must not be surfaced"
        );
        assert_eq!(buf, head, "partial bytes retained for the next record");

        buf.extend_from_slice(tail);
        let out = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out, msg, "reassembled the full message");
        assert!(buf.is_empty());
    }

    #[test]
    fn reassembly_partial_trailer_retained() {
        // A record with a complete message followed by the start of another:
        // the complete one drains, the partial trailer stays for next time.
        let done = hs_msg(0x0e, 0x00, 0); // ServerHelloDone (empty body)
        let next = hs_msg(0x0b, 0xEE, 30);
        let mut buf = [done.clone(), next[..6].to_vec()].concat();

        let out = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out, done, "only the complete message drains");
        assert_eq!(buf, next[..6], "partial trailer retained");

        buf.extend_from_slice(&next[6..]);
        let out2 = take_complete_handshake_messages(&mut buf).unwrap().unwrap();
        assert_eq!(out2, next);
    }

    #[test]
    fn reassembly_oversized_length_is_incomplete_not_panic() {
        // A header claiming a huge body with no data behind it is treated as
        // incomplete (wait for more), never a panic or a bogus drain.
        let mut buf = vec![0x0b, 0xff, 0xff, 0xff];
        assert!(take_complete_handshake_messages(&mut buf)
            .unwrap()
            .is_none());
        assert_eq!(buf, vec![0x0b, 0xff, 0xff, 0xff], "left intact");
    }

    fn make_tls13_ticket() -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x01, 0x02, 0x03],
            resumption_psk: vec![0xAA; 32],
            tls_version: TicketTlsVersion::Tls13,
            cipher_suite: 0x1301,
            lifetime_secs: 3600,
            age_add: 12345,
            received_at: Instant::now(),
            alpn: Some("h2".to_string()),
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: Vec::new(),
            max_early_data_size: 0,
            peer_transport_parameters: None,
        }
    }

    fn make_quic_early_data_ticket() -> SessionTicketData {
        SessionTicketData {
            alpn: Some("h3".to_string()),
            max_early_data_size: 16_384,
            peer_transport_parameters: Some(vec![0x0f, 0x00]),
            ..make_tls13_ticket()
        }
    }

    fn make_tls12_ticket() -> SessionTicketData {
        SessionTicketData {
            ticket: vec![0x10, 0x20, 0x30, 0x40],
            resumption_psk: Vec::new(),
            tls_version: TicketTlsVersion::Tls12,
            cipher_suite: 0xC02F,
            lifetime_secs: 3600,
            age_add: 0,
            received_at: Instant::now(),
            alpn: Some("http/1.1".to_string()),
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            master_secret: vec![0xBB; 48],
            max_early_data_size: 0,
            peer_transport_parameters: None,
        }
    }

    fn make_config_with_store(store: Arc<InMemorySessionStore>) -> HandshakeConfig {
        let profile = crate::profile::presets::chrome_144();
        HandshakeConfig {
            profile,
            hostname: "example.com".to_string(),
            port: 443,
            verification_policy: VerificationPolicy::default(),
            alps_payload: None,
            session_store: Some(store as Arc<dyn SessionStore>),
            ech_config_list: None,
            custom_ca_anchors: None,
            keylog_callback: None,
            client_hello_callback: None,
        }
    }

    /// Helper: scan ClientHello extensions and return (session_ticket_data_len, has_pre_shared_key).
    fn scan_ch_extensions(ch_record: &[u8]) -> (usize, bool) {
        let ch_msg = &ch_record[5..]; // skip record header
        let sid_len = ch_msg[38] as usize;
        let cs_start = 39 + sid_len;
        let cs_len = u16::from_be_bytes([ch_msg[cs_start], ch_msg[cs_start + 1]]) as usize;
        let comp_start = cs_start + 2 + cs_len;
        let comp_len = ch_msg[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;
        let ext_total_len =
            u16::from_be_bytes([ch_msg[ext_len_pos], ch_msg[ext_len_pos + 1]]) as usize;
        let ext_start = ext_len_pos + 2;
        let ext_end = ext_start + ext_total_len;

        let mut pos = ext_start;
        let mut session_ticket_len = 0usize;
        let mut found_psk = false;
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([ch_msg[pos], ch_msg[pos + 1]]);
            let ext_len = u16::from_be_bytes([ch_msg[pos + 2], ch_msg[pos + 3]]) as usize;
            if ext_type == 0x0023 {
                session_ticket_len = ext_len;
            }
            if ext_type == 0x0029 {
                found_psk = true;
            }
            pos += 4 + ext_len;
        }
        (session_ticket_len, found_psk)
    }

    fn parse_raw_client_hello_extensions(ch_msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let body = &ch_msg[4..];
        let sid_len = body[34] as usize;
        let cs_start = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[cs_start], body[cs_start + 1]]) as usize;
        let comp_start = cs_start + 2 + cs_len;
        let comp_len = body[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;
        let ext_total_len = u16::from_be_bytes([body[ext_len_pos], body[ext_len_pos + 1]]) as usize;
        let ext_start = ext_len_pos + 2;
        let ext_end = ext_start + ext_total_len;

        let mut extensions = Vec::new();
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            let data_start = pos + 4;
            let data_end = data_start + ext_len;
            extensions.push((ext_type, body[data_start..data_end].to_vec()));
            pos = data_end;
        }

        extensions
    }

    #[test]
    fn tls13_ticket_uses_psk_not_session_ticket() {
        let store = Arc::new(InMemorySessionStore::new());
        store.store("example.com:443", make_tls13_ticket());

        let mut driver = HandshakeDriver::new(make_config_with_store(store));
        let ch = driver.start().unwrap();
        let (st_len, has_psk) = scan_ch_extensions(&ch);

        assert_eq!(st_len, 0, "session_ticket must be empty for TLS 1.3 PSK");
        assert!(has_psk, "pre_shared_key must be present for TLS 1.3 ticket");
    }

    #[test]
    fn client_hello_callback_fires_from_driver_with_handshake_message() {
        use std::sync::Mutex;
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);

        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.client_hello_callback = Some(Arc::new(move |bytes: &[u8]| {
            sink.lock().unwrap().extend_from_slice(bytes);
        }));

        let mut driver = HandshakeDriver::new(config);
        let ch_record = driver.start().unwrap();

        let observed = captured.lock().unwrap().clone();
        // The driver itself fires the hook (it was previously dead at the lktls
        // layer — only lkrequest's connector invoked it).
        assert!(
            !observed.is_empty(),
            "client_hello_callback must fire from the driver"
        );
        // It receives the ClientHello *handshake message* (0x01), not the
        // record-framed wire bytes (0x16) that `start()` returns.
        assert_eq!(
            observed[0], 0x01,
            "callback must get the handshake message (0x01), not the record"
        );
        assert_eq!(ch_record[0], 0x16, "start() returns the TLS record (0x16)");
        // No data loss: the observed handshake message is exactly the record
        // payload (the TLS record header is 5 bytes).
        assert_eq!(
            &observed[..],
            &ch_record[5..],
            "callback bytes must equal the record payload"
        );
    }

    #[test]
    fn tls12_ticket_uses_session_ticket_not_psk() {
        let store = Arc::new(InMemorySessionStore::new());
        store.store("example.com:443", make_tls12_ticket());

        let mut driver = HandshakeDriver::new(make_config_with_store(store));
        let ch = driver.start().unwrap();
        let (st_len, has_psk) = scan_ch_extensions(&ch);

        assert!(
            st_len > 0,
            "session_ticket must carry data for TLS 1.2 ticket"
        );
        assert!(
            !has_psk,
            "pre_shared_key must NOT be present for TLS 1.2 ticket"
        );
    }

    #[test]
    fn alpn_mismatch_skips_tls13_ticket() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut ticket = make_tls13_ticket();
        ticket.alpn = Some("h2".to_string());
        store.store("example.com:443", ticket);

        let mut config = make_config_with_store(store);
        config.profile.alpn_protocols = vec!["http/1.1".to_string()];

        let mut driver = HandshakeDriver::new(config);
        let ch = driver.start().unwrap();
        let (_, has_psk) = scan_ch_extensions(&ch);

        assert!(
            !has_psk,
            "pre_shared_key must NOT be present on ALPN mismatch"
        );
        assert!(driver.original_ticket.is_none());
    }

    #[test]
    fn alpn_mismatch_skips_tls12_ticket() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut ticket = make_tls12_ticket();
        ticket.alpn = Some("h2".to_string());
        store.store("example.com:443", ticket);

        let mut config = make_config_with_store(store);
        config.profile.alpn_protocols = vec!["http/1.1".to_string()];

        let mut driver = HandshakeDriver::new(config);
        let ch = driver.start().unwrap();
        let (st_len, _) = scan_ch_extensions(&ch);

        assert_eq!(st_len, 0, "session_ticket must be empty on ALPN mismatch");
        assert!(driver.original_ticket.is_none());
    }

    #[test]
    fn no_ticket_no_psk() {
        let store = Arc::new(InMemorySessionStore::new());
        let mut driver = HandshakeDriver::new(make_config_with_store(store));
        let ch = driver.start().unwrap();
        let (st_len, has_psk) = scan_ch_extensions(&ch);

        assert_eq!(st_len, 0);
        assert!(!has_psk);
    }

    #[test]
    fn quic_driver_start_returns_raw_client_hello_with_empty_session_id_and_transport_params() {
        let transport_parameters = encode_transport_params(&QuicTransportParams::new(vec![
            QuicTransportParam::new(
                param_id::INITIAL_SOURCE_CONNECTION_ID,
                vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
            ),
            QuicTransportParam::new(param_id::INITIAL_MAX_DATA, vec![0x40, 0x64]),
        ]));

        let mut driver = QuicHandshakeDriver::new(
            make_config_with_store(Arc::new(InMemorySessionStore::new()))
                .into_quic(transport_parameters.clone()),
        );
        let ch = driver.start().unwrap();

        assert_eq!(ch[0], 0x01, "must return raw ClientHello handshake bytes");
        let body_len = ((ch[1] as usize) << 16) | ((ch[2] as usize) << 8) | (ch[3] as usize);
        assert_eq!(body_len, ch.len() - 4);

        let body = &ch[4..];
        assert_eq!(
            body[34], 0,
            "QUIC ClientHello must use empty legacy_session_id"
        );

        let extensions = parse_raw_client_hello_extensions(&ch);
        let quic_tp = extensions
            .into_iter()
            .find(|(extension_type, _)| *extension_type == 0x0039)
            .map(|(_, data)| data);

        assert_eq!(quic_tp, Some(transport_parameters));
    }

    #[test]
    fn quic_chrome_profile_inserts_early_data_before_supported_versions_when_ticket_allows_0rtt() {
        let transport_parameters =
            encode_transport_params(&QuicTransportParams::new(vec![QuicTransportParam::new(
                param_id::INITIAL_SOURCE_CONNECTION_ID,
                Vec::new(),
            )]));
        let store = Arc::new(InMemorySessionStore::new());
        store.store("example.com:443", make_quic_early_data_ticket());
        let mut config = make_config_with_store(store);
        config.profile = crate::profile::presets::chrome_146_quic();
        config.alps_payload = Some(vec![0x01, 0x40, 0x00]);

        let mut driver = QuicHandshakeDriver::new(config.into_quic(transport_parameters));
        let ch = driver.start().unwrap();
        let extension_types = parse_raw_client_hello_extensions(&ch)
            .into_iter()
            .map(|(extension_type, _)| extension_type)
            .collect::<Vec<_>>();
        let is_grease = |value: &u16| {
            let hi = (value >> 8) as u8;
            let lo = (value & 0xff) as u8;
            hi == lo && (hi & 0x0f) == 0x0a
        };
        let real_extension_types = extension_types
            .iter()
            .copied()
            .filter(|extension_type| !is_grease(extension_type))
            .collect::<Vec<_>>();

        assert_eq!(
            real_extension_types,
            vec![45, 10, 51, 65037, 16, 0, 27, 13, 42, 43, 57, 17613, 41]
        );
    }

    #[test]
    fn quic_driver_advertises_alps_when_payload_is_configured() {
        let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
        config.profile.alpn_protocols = vec!["h3".to_string()];
        config.profile.alps_protocols = Some(vec!["h3".to_string()]);
        config.alps_payload = Some(vec![0x01, 0x40, 0x00]);

        let mut driver = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
        let ch = driver.start().unwrap();

        let alps = parse_raw_client_hello_extensions(&ch)
            .into_iter()
            .find(|(extension_type, _)| *extension_type == 0x44cd)
            .map(|(_, data)| data);

        assert_eq!(alps, Some(vec![0x00, 0x03, 0x02, b'h', b'3']));
    }

    /// ALPS advertisement in the ClientHello is DECOUPLED from the client's
    /// settings payload. The ClientHello ALPS extension always carries the
    /// profile's protocol list (`h2`); the settings payload rides separately in
    /// the Client EncryptedExtensions. Real Chrome advertises ALPS `h2` with an
    /// EMPTY settings payload, so `Some(vec![])` MUST still advertise ALPS.
    ///   None    => no ALPS (H1-only request path)
    ///   Some(_) => advertise ALPS `h2` (payload content is irrelevant *here*)
    #[test]
    fn alps_advertisement_is_decoupled_from_settings_payload() {
        // chrome_144: alps_protocols = Some(["h2"]) and lists 0x44cd.
        let ch_alps = |payload: Option<Vec<u8>>| -> Option<Vec<u8>> {
            let mut config = make_config_with_store(Arc::new(InMemorySessionStore::new()));
            config.alps_payload = payload;
            let mut driver = HandshakeDriver::new(config);
            let ch = driver.start().unwrap();
            // TCP .start() returns a TLS record; skip the 5-byte record header to
            // get the handshake message that parse_raw_client_hello_extensions wants.
            parse_raw_client_hello_extensions(&ch[5..])
                .into_iter()
                .find(|(t, _)| *t == 0x44cd)
                .map(|(_, d)| d)
        };
        // The ClientHello ALPS extension body is always the h2 protocol list,
        // never the settings payload.
        let h2_protocol_list = vec![0x00, 0x03, 0x02, b'h', b'2'];

        assert_eq!(ch_alps(None), None, "None ⇒ no ALPS (H1-only)");
        assert_eq!(
            ch_alps(Some(vec![])),
            Some(h2_protocol_list.clone()),
            "Some(empty) ⇒ ALPS advertises h2 (Chrome: advertise + empty settings)"
        );
        assert_eq!(
            ch_alps(Some(vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x64])),
            Some(h2_protocol_list),
            "Some(non-empty settings) ⇒ ClientHello ALPS still shows the h2 \
             protocol list, not the settings payload (payload rides in Client EE)"
        );
    }

    #[test]
    fn key_update_response_message_format() {
        let mut state = PostHandshakeState {
            server_app_secret: vec![0x42; 32],
            client_app_secret: vec![0x55; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x33; 32],
        };

        let (msg, _aead) = state.build_key_update_response().unwrap();

        assert_eq!(msg, vec![0x18, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn key_update_response_rotates_client_secret() {
        let mut state = PostHandshakeState {
            server_app_secret: vec![0x42; 32],
            client_app_secret: vec![0x55; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x33; 32],
        };

        let before = state.client_app_secret.clone();
        let _ = state.build_key_update_response().unwrap();
        assert_ne!(before, state.client_app_secret);

        let mid = state.client_app_secret.clone();
        let _ = state.build_key_update_response().unwrap();
        assert_ne!(mid, state.client_app_secret);
    }

    #[test]
    fn key_update_read_rotates_server_secret() {
        let mut state = PostHandshakeState {
            server_app_secret: vec![0x42; 32],
            client_app_secret: vec![0x55; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            exporter_master_secret: vec![0x33; 32],
        };

        let before = state.server_app_secret.clone();
        let _ = state.process_key_update().unwrap();
        assert_ne!(before, state.server_app_secret);
    }
}
