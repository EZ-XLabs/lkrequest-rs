//! ClientHello byte-level builder.
//!
//! This is the core of the fingerprint engine.  Given a [`TlsProfile`] and a
//! target hostname, it produces the exact ClientHello bytes that match the
//! desired client fingerprint.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::crypto::kx::{self, EphemeralKeyPair, KxGroup};
use crate::error::{Result, TlsError};
use crate::extensions::alpn::Alpn;
use crate::extensions::alps::Alps;
use crate::extensions::compress_certificate::CompressCertificate;
use crate::extensions::delegated_credentials::DelegatedCredentials;
use crate::extensions::ec_point_formats::EcPointFormats;
use crate::extensions::ech::{EchGreaseExtension, EchInnerExtension, EchOuterExtensionsExtension};
use crate::extensions::encrypt_then_mac::EncryptThenMac;
use crate::extensions::extended_master_secret::ExtendedMasterSecret;
use crate::extensions::generic::GenericExtension;
use crate::extensions::grease::{self, GreaseExtension};
use crate::extensions::key_share::{KeyShare, KeyShareEntry};
use crate::extensions::padding::Padding;
use crate::extensions::psk_key_exchange_modes::{self, PskKeyExchangeModes};
use crate::extensions::record_size_limit::RecordSizeLimit;
use crate::extensions::renegotiation_info::RenegotiationInfo;
use crate::extensions::sct::SignedCertificateTimestamp;
use crate::extensions::session_ticket::SessionTicket;
use crate::extensions::signature_algorithms::SignatureAlgorithms;
use crate::extensions::sni::Sni;
use crate::extensions::status_request::StatusRequest;
use crate::extensions::supported_groups::SupportedGroups;
use crate::extensions::supported_versions::SupportedVersions;
use crate::extensions::Extension;
use crate::profile::types::TlsProfile;
use crate::profile::types::{
    ext_type, EchMode, ExtensionSource, ExtensionSpec, PaddingStrategy, RandomizationConfig,
    TlsClientHelloStyle,
};

use super::handshake_type;

/// Builder that produces a complete ClientHello message as raw bytes.
///
/// # Usage
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use lktls::profile::presets;
/// use lktls::handshake::client_hello::ClientHelloBuilder;
///
/// let profile = presets::chrome_131();
/// let builder = ClientHelloBuilder::new(&profile, "example.com");
/// let output = builder.build()?;
/// // output.message contains the complete Handshake message bytes
/// // output.key_shares contains ephemeral keys for the TLS handshake
/// # Ok(())
/// # }
/// ```
pub struct ClientHelloBuilder<'a> {
    /// The fingerprint profile that drives the output.
    pub(crate) profile: &'a TlsProfile,
    /// Target server hostname (used for SNI and other extensions).
    pub(crate) hostname: String,
    /// Random bytes (32 bytes). Generated fresh if not provided.
    pub(crate) random: Option<[u8; 32]>,
    /// Session ID bytes. Generated based on profile's `session_id_length`.
    pub(crate) session_id: Option<Vec<u8>>,
    /// Cookie from HelloRetryRequest (added as an extension in CH2).
    pub(crate) cookie: Option<Vec<u8>>,
    /// TLS 1.2 session ticket data for resumption (sent in session_ticket extension).
    /// If set, the session_ticket extension carries this data instead of being empty.
    pub(crate) session_ticket_data: Option<Vec<u8>>,
    /// Runtime ECHConfigList override (raw DER bytes).
    /// When set, overrides the profile's `ech` field for this ClientHello.
    pub(crate) ech_config_list: Option<Vec<u8>>,
    /// QUIC transport parameters extension payload (type 0x0039).
    pub(crate) quic_transport_parameters: Option<Vec<u8>>,
    /// Whether to advertise TLS 1.3 early_data (0-RTT) in ClientHello.
    pub(crate) early_data: bool,
    /// Pre-existing GREASE values to reuse (e.g. from CH1 during HRR).
    /// When set, these values are used instead of generating fresh ones.
    pub(crate) grease_values: Option<grease::GreaseValues>,
    /// Whether this is a HRR retry (CH2). Affects key_share GREASE behavior.
    pub(crate) is_retry: bool,
    /// RNG used for the extension-order shuffle (when
    /// `randomization.shuffle_extensions` is enabled). `None` uses a fresh OS
    /// RNG each build (non-reproducible, the historical behavior); inject a
    /// seeded RNG via [`with_rng`](Self::with_rng) for reproducible output.
    ///
    /// `RefCell` because the shuffle happens inside `build(&self)`; the builder
    /// is used within a single connection setup, never shared across threads.
    pub(crate) shuffle_rng: std::cell::RefCell<Option<Box<dyn rand_core::RngCore + Send>>>,
}

impl<'a> ClientHelloBuilder<'a> {
    /// Create a new builder for the given profile and target hostname.
    pub fn new(profile: &'a TlsProfile, hostname: impl Into<String>) -> Self {
        Self {
            profile,
            hostname: hostname.into(),
            random: None,
            session_id: None,
            cookie: None,
            session_ticket_data: None,
            ech_config_list: None,
            quic_transport_parameters: None,
            early_data: false,
            grease_values: None,
            is_retry: false,
            shuffle_rng: std::cell::RefCell::new(None),
        }
    }

    /// Inject the RNG used for the extension-order shuffle.
    ///
    /// The engine is generic over [`rand_core::RngCore`], so any RNG works —
    /// pass a seeded one (e.g. `rand_chacha::ChaCha20Rng::from_seed(..)`) for a
    /// reproducible permutation, or a mock in tests. Without this, each build
    /// uses a fresh OS RNG (non-reproducible). `lktls` deliberately bundles no
    /// concrete RNG: the caller chooses.
    pub fn with_rng<R: rand_core::RngCore + Send + 'static>(self, rng: R) -> Self {
        *self.shuffle_rng.borrow_mut() = Some(Box::new(rng));
        self
    }

    /// Returns `true` if `self.hostname` is an IP address literal (v4 or v6).
    ///
    /// Per RFC 6066 Section 3, literal IP addresses MUST NOT be sent in the
    /// SNI extension. When this returns `true`, the SNI extension is omitted
    /// from the ClientHello.
    fn hostname_is_ip(&self) -> bool {
        self.hostname.parse::<std::net::IpAddr>().is_ok()
    }

    /// Override the 32-byte random value (useful for deterministic testing).
    pub fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = Some(random);
        self
    }

    /// Override the session ID (useful for session resumption).
    pub fn with_session_id(mut self, session_id: Vec<u8>) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set a cookie from HelloRetryRequest (will be added as cookie extension in CH2).
    pub fn with_cookie(mut self, cookie: Vec<u8>) -> Self {
        self.cookie = Some(cookie);
        self
    }

    /// Set TLS 1.2 session ticket data for resumption.
    ///
    /// When set, the `session_ticket` extension will carry this data instead
    /// of being empty. The server may accept this for abbreviated handshake.
    pub fn with_session_ticket_data(mut self, data: Vec<u8>) -> Self {
        self.session_ticket_data = Some(data);
        self
    }

    /// Set a runtime ECHConfigList override (raw DER bytes).
    ///
    /// When set, the builder performs real ECH encryption: it constructs
    /// both an inner ClientHello (with the real hostname) and an outer
    /// ClientHello (with the ECHConfig's `public_name` as SNI), encrypts
    /// the inner via HPKE, and embeds it in the outer's ECH extension.
    ///
    /// The ECHConfigList can come from DNS HTTPS records, a previous
    /// server's `ech_retry_configs`, or manual configuration.
    pub fn with_ech_config(mut self, config_list: Vec<u8>) -> Self {
        self.ech_config_list = Some(config_list);
        self
    }

    /// Set the QUIC transport parameters extension payload.
    pub fn with_quic_transport_parameters(mut self, payload: Vec<u8>) -> Self {
        self.quic_transport_parameters = Some(payload);
        self
    }

    /// Advertise TLS 1.3 early_data (0-RTT).
    pub fn with_early_data(mut self) -> Self {
        self.early_data = true;
        self
    }

    /// Reuse GREASE values from a previous ClientHello (for HRR retries).
    ///
    /// RFC 8446 Section 4.1.2 requires that the updated ClientHello after
    /// HelloRetryRequest is identical to the original except for specific
    /// allowed changes. GREASE values must remain the same.
    pub fn with_grease_values(mut self, grease: grease::GreaseValues) -> Self {
        self.grease_values = Some(grease);
        self
    }

    /// Build the ClientHello using pre-existing key pairs (for HRR).
    ///
    /// Instead of generating new key pairs, uses the provided ones.
    /// Marks the build as a retry, which skips GREASE in key_share
    /// (matching BoringSSL/Chrome behavior after HelloRetryRequest).
    pub fn build_with_key_pairs(
        mut self,
        key_pairs: &[EphemeralKeyPair],
    ) -> Result<ClientHelloOutput> {
        self.is_retry = true;
        self.build_internal(Some(key_pairs), 0)
    }

    /// Build the complete ClientHello handshake message bytes.
    ///
    /// The returned bytes include the Handshake header (type + 3-byte length)
    /// but **not** the TLS Record header — the caller wraps this in a
    /// TLS record.
    ///
    /// When `ech_config_list` is set, this performs real ECH encryption:
    /// builds both an inner CH (real SNI) and outer CH (public_name SNI),
    /// encrypts the inner via HPKE, and embeds the result in the outer.
    pub fn build(&self) -> Result<ClientHelloOutput> {
        self.build_with_psk_hint(0)
    }

    /// Build the ClientHello, accounting for an additional `psk_extra_len`
    /// bytes that will be appended after `build()` returns (the PSK extension).
    ///
    /// The padding calculation uses `body_len + psk_extra_len` so that the
    /// final ClientHello (after PSK is appended) matches the target size.
    pub fn build_with_psk_hint(&self, psk_extra_len: usize) -> Result<ClientHelloOutput> {
        if let Some(ref ech_config_raw) = self.ech_config_list {
            self.build_with_real_ech(ech_config_raw.clone(), psk_extra_len)
        } else {
            self.build_internal(None, psk_extra_len)
        }
    }

    fn build_internal(
        &self,
        existing_key_pairs: Option<&[EphemeralKeyPair]>,
        psk_extra_len: usize,
    ) -> Result<ClientHelloOutput> {
        self.validate_profile()?;

        // Use provided GREASE values (for HRR retries) or generate fresh ones.
        // Per RFC 8446 §4.1.2, CH2 after HRR must reuse CH1's GREASE values.
        let grease = self.grease_values.clone().unwrap_or_default();

        // --- Step 1: Random (32 bytes) ---
        let random = match self.random {
            Some(r) => r,
            None => generate_random_bytes(),
        };

        // --- Step 2: Session ID ---
        let session_id = match &self.session_id {
            Some(id) => id.clone(),
            None => generate_session_id(self.profile.session_id_length),
        };

        // --- Step 3: Cipher Suites ---
        let cipher_suites = self.encode_cipher_suites(grease.get(grease::GreaseIndex::Cipher));

        // --- Step 4: Compression Methods ---
        let compression_methods = &self.profile.compression_methods;

        // --- Step 5: Generate or reuse ephemeral key pairs for key_share ---
        let key_pairs = if let Some(_existing) = existing_key_pairs {
            // For HRR: the caller provides pre-generated key pairs.
            // We won't return them in the output since the caller already has them.
            Vec::new() // placeholder — we use `existing_key_pairs` for encoding
        } else {
            self.generate_key_pairs()?
        };
        let key_pairs_for_encoding: &[EphemeralKeyPair] = existing_key_pairs.unwrap_or(&key_pairs);

        // --- Step 6: Extensions (first pass, without padding) ---
        // Compute the (possibly shuffled) extension order once.  This order
        // is stored in the output so the ECH inner CH can reuse it.
        let extension_order = self.compute_extension_order();
        let (ext_data_no_padding, padding_insert_pos) = self.encode_extensions_without_padding(
            key_pairs_for_encoding,
            &grease,
            &extension_order,
        )?;

        // --- Step 7: Calculate body length without padding ---
        // Body = version(2) + random(32) + session_id_len(1) + session_id
        //      + cipher_suites_len(2) + cipher_suites
        //      + comp_methods_len(1) + comp_methods
        //      + extensions_len(2) + extensions_data
        let fixed_len = 2
            + 32
            + 1
            + session_id.len()
            + 2
            + cipher_suites.len()
            + 1
            + compression_methods.len()
            + 2;
        let body_len_no_padding = fixed_len + ext_data_no_padding.len();

        // --- Step 8: Calculate padding ---
        let padding_data_len = self.calculate_padding(body_len_no_padding + psk_extra_len);

        // --- Step 9: Build final extensions buffer (with padding if needed) ---
        let ext_data = match padding_data_len {
            Some(pad_len) => {
                let insert_pos = padding_insert_pos.unwrap_or(ext_data_no_padding.len());
                let mut buf = Vec::with_capacity(ext_data_no_padding.len() + 4 + pad_len);
                buf.extend_from_slice(&ext_data_no_padding[..insert_pos]);
                Padding {
                    padding_len: pad_len as u16,
                }
                .encode(&mut buf);
                buf.extend_from_slice(&ext_data_no_padding[insert_pos..]);
                buf
            }
            None => ext_data_no_padding,
        };

        // --- Step 10: Assemble the complete handshake message ---
        let body_len = fixed_len + ext_data.len();
        let mut msg = Vec::with_capacity(4 + body_len);

        // Handshake header: type (1 byte) + length (3 bytes)
        msg.push(handshake_type::CLIENT_HELLO);
        let body_len_u32 = body_len as u32;
        msg.extend_from_slice(&body_len_u32.to_be_bytes()[1..4]);

        // ClientHello body
        // ProtocolVersion: always 0x0303 (TLS 1.2) on the wire, even for TLS 1.3
        msg.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        msg.extend_from_slice(&random);
        // Session ID
        msg.push(session_id.len() as u8);
        msg.extend_from_slice(&session_id);
        // Cipher Suites
        msg.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        msg.extend_from_slice(&cipher_suites);
        // Compression Methods
        msg.push(compression_methods.len() as u8);
        msg.extend_from_slice(compression_methods);
        // Extensions
        msg.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        msg.extend_from_slice(&ext_data);

        Ok(ClientHelloOutput {
            message: msg,
            key_shares: key_pairs,
            inner_hello: None,
            ech_offered: false,
            grease_values: grease,
            shuffled_extensions: extension_order,
        })
    }

    fn validate_profile(&self) -> Result<()> {
        let chromium_boringssl = matches!(
            self.profile.tls_client_hello_style,
            TlsClientHelloStyle::ChromiumBoringssl
        );

        if chromium_boringssl
            && self.profile.grease.key_share
            && !self.profile.grease.supported_groups
        {
            return Err(TlsError::InvalidProfile(
                "chromium_boringssl requires grease.supported_groups when grease.key_share is enabled"
                    .to_string(),
            ));
        }

        if chromium_boringssl && self.profile.grease.signature_algorithms {
            return Err(TlsError::InvalidProfile(
                "chromium_boringssl does not support grease.signature_algorithms".to_string(),
            ));
        }

        self.validate_no_duplicate_grease_sources(chromium_boringssl)?;

        Ok(())
    }

    fn validate_no_duplicate_grease_sources(&self, chromium_boringssl: bool) -> Result<()> {
        if self.profile.grease.cipher_suite {
            Self::reject_explicit_grease_values(
                "cipher_suites",
                "grease.cipher_suite",
                &self.profile.cipher_suites,
            )?;
        }

        if self.profile.grease.supported_groups {
            Self::reject_explicit_grease_values(
                "supported_groups",
                "grease.supported_groups",
                &self.profile.supported_groups,
            )?;
        }

        if self.profile.grease.signature_algorithms {
            Self::reject_explicit_grease_values(
                "signature_algorithms",
                "grease.signature_algorithms",
                &self.profile.signature_algorithms,
            )?;
        }

        if let Some(value) = self
            .profile
            .key_share_curves
            .iter()
            .copied()
            .find(|value| is_grease_value(*value))
        {
            return Err(TlsError::InvalidProfile(format!(
                "key_share_curves contains explicit GREASE value 0x{value:04x}; use grease.key_share=true instead"
            )));
        }

        if self.profile.grease.extensions {
            for spec in &self.profile.extensions {
                if is_grease_value(spec.extension_type)
                    && !matches!(spec.source, ExtensionSource::Grease)
                {
                    return Err(TlsError::InvalidProfile(format!(
                        "extensions contains fixed GREASE extension type 0x{:04x}; use source.type=grease instead",
                        spec.extension_type
                    )));
                }
            }

            if !chromium_boringssl {
                let grease_extension_count = self
                    .profile
                    .extensions
                    .iter()
                    .filter(|spec| matches!(spec.source, ExtensionSource::Grease))
                    .count();
                if grease_extension_count > 2 {
                    return Err(TlsError::InvalidProfile(format!(
                        "extensions contains {grease_extension_count} GREASE placeholders; at most two are supported"
                    )));
                }
            }
        }

        Ok(())
    }

    fn reject_explicit_grease_values(field: &str, grease_flag: &str, values: &[u16]) -> Result<()> {
        if let Some(value) = values.iter().copied().find(|value| is_grease_value(*value)) {
            return Err(TlsError::InvalidProfile(format!(
                "{field} contains explicit GREASE value 0x{value:04x}; remove it and use {grease_flag}=true instead"
            )));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Real ECH Build
    // -----------------------------------------------------------------------

    /// Build a ClientHello with real ECH encryption.
    ///
    /// This constructs both an inner and outer ClientHello:
    ///
    /// 1. Parse the ECHConfigList and select a suitable config.
    /// 2. Build the inner CH (real hostname, `inner` ECH ext, empty session_id).
    /// 3. Encode as `EncodedClientHelloInner` with padding.
    /// 4. Build the outer CH (public_name as SNI, placeholder ECH payload).
    /// 5. HPKE-encrypt the inner CH with the outer CH as AAD.
    /// 6. Replace the placeholder with the real ciphertext.
    fn build_with_real_ech(
        &self,
        ech_config_raw: Vec<u8>,
        psk_extra_len: usize,
    ) -> Result<ClientHelloOutput> {
        use crate::ech::config;
        use crate::ech::inner;

        // --- Step 1: Parse ECHConfigList and select config ---
        let configs = config::parse_ech_config_list(&ech_config_raw)?;
        if configs.is_empty() {
            return Err(TlsError::HandshakeFailure(
                "ECHConfigList contains no usable configs".to_string(),
            ));
        }

        // Prefer AEAD that matches the profile's GREASE config for fingerprint consistency (F4).
        let preferred_aead = self.profile.ech.as_ref().and_then(|m| match m {
            EchMode::Grease(g) => Some(g.aead_id),
            _ => None,
        });

        let (selected_config, selected_cs) = config::select_ech_config(&configs, preferred_aead)
            .ok_or_else(|| {
                TlsError::HandshakeFailure(
                    "no compatible ECHConfig found (need X25519 + SHA256 + supported AEAD)"
                        .to_string(),
                )
            })?;

        tracing::debug!(
            config_id = selected_config.config_id,
            public_name = %selected_config.public_name,
            aead_id = selected_cs.aead_id,
            "ECH: selected config for real ECH"
        );

        // --- Step 2: Build the standard outer CH (no ECH, just GREASE placeholder) ---
        // We build an outer-like CH first to get the key_pairs and overall structure.
        let mut outer_output = self.build_internal(None, psk_extra_len)?;

        // --- Step 3: Build inner CH body (real SNI, inner ECH ext, empty session_id) ---
        let inner_ch_body =
            self.build_inner_ch_body(selected_config, &selected_cs, &outer_output)?;

        // --- Step 4: Encode as EncodedClientHelloInner with padding ---
        let padding_len = inner::compute_ech_padding(
            inner_ch_body.len(),
            &self.hostname,
            selected_config.maximum_name_length,
            selected_cs.aead_id,
        );
        let encoded_inner = inner::encode_client_hello_inner(&inner_ch_body, padding_len);

        // --- Step 5: Build the outer CH with real ECH extension ---
        // Re-build the outer with public_name as SNI and the real ECH extension.
        let outer_with_ech = self.rebuild_outer_with_ech(
            &outer_output.message,
            selected_config,
            &selected_cs,
            &encoded_inner,
        )?;

        // Build the inner CH with handshake header for transcript purposes.
        let inner_hello = self.build_inner_hello_message(&inner_ch_body, &outer_output.message);

        outer_output.message = outer_with_ech;
        outer_output.inner_hello = Some(inner_hello);
        outer_output.ech_offered = true;

        Ok(outer_output)
    }

    /// Build the inner ClientHello body (without Handshake header).
    ///
    /// This is the `EncodedClientHelloInner.client_hello` portion:
    /// - Same cipher suites, compression, extensions as the outer
    /// - Real hostname in SNI
    /// - `inner` ECH extension (type=0x01, empty)
    /// - Empty `legacy_session_id`
    /// - Extensions listed in `ech_outer_extensions` replaced by the 0xFD00 reference
    fn build_inner_ch_body(
        &self,
        _ech_config: &crate::ech::config::EchConfig,
        _cipher_suite: &crate::ech::config::HpkeSymmetricCipherSuite,
        outer_output: &ClientHelloOutput,
    ) -> Result<Vec<u8>> {
        // Reuse outer GREASE values (BoringSSL shares a single GREASE seed
        // per connection for both inner and outer ClientHello).
        let grease = outer_output.grease_values.clone();

        // Random (32 bytes) — MUST be different from outer (spec Section 6.1)
        let random = generate_random_bytes();

        // Session ID — MUST be empty in EncodedClientHelloInner
        let session_id: Vec<u8> = Vec::new();

        // Cipher suites — same as outer
        let cipher_suites = self.encode_cipher_suites(grease.get(grease::GreaseIndex::Cipher));

        // Compression methods — same as outer
        let compression_methods = &self.profile.compression_methods;

        // Extensions for inner CH — build manually
        let inner_extensions = self.encode_inner_extensions(&grease, outer_output)?;

        // Assemble the body (without Handshake header)
        let body_len = 2
            + 32
            + 1
            + session_id.len()
            + 2
            + cipher_suites.len()
            + 1
            + compression_methods.len()
            + 2
            + inner_extensions.len();

        let mut body = Vec::with_capacity(body_len);

        // ProtocolVersion: 0x0303
        body.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        body.extend_from_slice(&random);
        // Session ID (empty for inner)
        body.push(0);
        // Cipher Suites
        body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        body.extend_from_slice(&cipher_suites);
        // Compression Methods
        body.push(compression_methods.len() as u8);
        body.extend_from_slice(compression_methods);
        // Extensions
        body.extend_from_slice(&(inner_extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&inner_extensions);

        Ok(body)
    }

    /// Encode extensions for the inner ClientHello.
    ///
    /// Uses the same shuffled extension order as the outer ClientHello
    /// (matching BoringSSL's shared permutation), but:
    /// - SNI uses real hostname
    /// - ECH extension is type=inner (empty)
    /// - Extensions in `ech_outer_extensions` are replaced by 0xFD00 reference
    /// - GREASE extensions are compressed via 0xFD00 (referencing outer GREASE)
    /// - TLS 1.2-only extensions (EMS, session_ticket, ec_point_formats) are
    ///   skipped entirely, matching BoringSSL behavior
    fn encode_inner_extensions(
        &self,
        grease: &grease::GreaseValues,
        outer_output: &ClientHelloOutput,
    ) -> Result<Vec<u8>> {
        let compress_ext_types = self
            .profile
            .ech_outer_extensions
            .as_deref()
            .unwrap_or(&[51]); // default: compress key_share only

        // TLS 1.2-only extensions that BoringSSL skips when
        // `type == ssl_client_hello_inner` (unnecessary in TLS 1.3).
        const INNER_SKIP_EXTENSIONS: &[u16] = &[
            ext_type::EXTENDED_MASTER_SECRET, // 23
            ext_type::SESSION_TICKET,         // 35
            ext_type::EC_POINT_FORMATS,       // 11
        ];

        let outer_grease_types = Self::extract_grease_extension_types(&outer_output.message);
        let mut outer_grease_idx = 0usize;

        let key_pairs_for_encoding: Vec<EphemeralKeyPair> = Vec::new();

        let mut buf = Vec::with_capacity(512);
        let mut compressed_types: Vec<u16> = Vec::new();
        // Track the byte offset of the first compressed extension so we can
        // insert ech_outer_extensions (0xFD00) at the correct position.
        let mut first_compressed_pos: Option<usize> = None;
        let chromium_boringssl = matches!(
            self.profile.tls_client_hello_style,
            TlsClientHelloStyle::ChromiumBoringssl
        );

        if chromium_boringssl && self.profile.grease.extensions {
            let first_grease = outer_grease_types
                .first()
                .copied()
                .unwrap_or_else(|| grease.get(grease::GreaseIndex::Extension1));
            compressed_types.push(first_grease);
            first_compressed_pos = Some(0);
            outer_grease_idx = 1;
        }

        // Use the outer's shuffled extension order so inner and outer share
        // the same permutation (BoringSSL behavior).
        for ext_spec in &outer_output.shuffled_extensions {
            let ext_type_code = ext_spec.extension_type;

            // Skip TLS 1.2-only extensions in inner CH
            if INNER_SKIP_EXTENSIONS.contains(&ext_type_code) {
                continue;
            }

            // Check if this extension should be compressed via ech_outer_extensions
            if compress_ext_types.contains(&ext_type_code)
                && ext_type_code != ext_type::ENCRYPTED_CLIENT_HELLO
            {
                compressed_types.push(ext_type_code);
                if first_compressed_pos.is_none() {
                    first_compressed_pos = Some(buf.len());
                }
                continue; // skip — will be referenced via 0xFD00
            }

            match &ext_spec.source {
                ExtensionSource::Auto => {
                    if ext_type_code == ext_type::ENCRYPTED_CLIENT_HELLO {
                        // Inner ECH extension: type=inner (empty payload)
                        EchInnerExtension.encode(&mut buf);
                    } else if ext_type_code == ext_type::SNI {
                        // Use real hostname for inner CH (not public_name).
                        // RFC 6066 §3: skip SNI for IP address literals and empty hostnames.
                        if !self.hostname_is_ip() && !self.hostname.is_empty() {
                            Sni {
                                hostname: self.hostname.clone(),
                            }
                            .encode(&mut buf);
                        }
                    } else {
                        // All other auto extensions: encode normally
                        self.encode_auto_extension(
                            ext_type_code,
                            &key_pairs_for_encoding,
                            grease,
                            &mut buf,
                        )?;
                    }
                }
                ExtensionSource::Grease => {
                    // Compress GREASE via ech_outer_extensions, referencing
                    // the outer CH's GREASE extension types (BoringSSL behavior).
                    if let Some(&outer_gt) = outer_grease_types.get(outer_grease_idx) {
                        compressed_types.push(outer_gt);
                        if first_compressed_pos.is_none() {
                            first_compressed_pos = Some(buf.len());
                        }
                        outer_grease_idx += 1;
                    } else {
                        // Fallback: encode GREASE normally if outer types unavailable
                        let (ext_grease, payload_len) = match outer_grease_idx {
                            0 => (grease.get(grease::GreaseIndex::Extension1), 0),
                            _ => (grease.get(grease::GreaseIndex::Extension2), 1),
                        };
                        outer_grease_idx += 1;
                        GreaseExtension::with_value_and_len(ext_grease, payload_len)
                            .encode(&mut buf);
                    }
                }
                ExtensionSource::RawBytes { data } => {
                    let payload = decode_hex(data)?;
                    GenericExtension::new(ext_spec.extension_type, payload).encode(&mut buf);
                }
            }
        }

        if chromium_boringssl && self.profile.grease.extensions {
            let second_grease = outer_grease_types
                .get(1)
                .copied()
                .unwrap_or_else(|| grease.get(grease::GreaseIndex::Extension2));
            compressed_types.push(second_grease);
            if first_compressed_pos.is_none() {
                first_compressed_pos = Some(buf.len());
            }
        }

        // Insert ech_outer_extensions (0xFD00) at the position of the first
        // compressed extension.  Per draft-ietf-tls-esni-24 Section 5.1, the
        // server replaces 0xFD00 in-place with the referenced extensions, so
        // the position must match the original profile order.
        if !compressed_types.is_empty() {
            let insert_pos = first_compressed_pos.unwrap_or(buf.len());
            let mut oext_buf = Vec::new();
            let oext = EchOuterExtensionsExtension {
                extension_types: compressed_types,
            };
            oext.encode(&mut oext_buf);
            // Splice the 0xFD00 extension into the correct position.
            let tail = buf.split_off(insert_pos);
            buf.extend_from_slice(&oext_buf);
            buf.extend_from_slice(&tail);
        }

        Ok(buf)
    }

    /// Extract GREASE extension type codes from an outer ClientHello message.
    ///
    /// Parses the handshake message bytes to find extensions whose type matches
    /// the GREASE pattern (`0x?A?A`).  Returns them in wire order.
    fn extract_grease_extension_types(outer_message: &[u8]) -> Vec<u16> {
        let mut result = Vec::new();
        // Skip Handshake header (4 bytes) to get the ClientHello body.
        if outer_message.len() < 4 {
            return result;
        }
        let body = &outer_message[4..];

        // version(2) + random(32) = 34 bytes
        if body.len() < 35 {
            return result;
        }
        let mut pos = 34;

        // session_id
        let sid_len = body[pos] as usize;
        pos += 1 + sid_len;
        if pos + 2 > body.len() {
            return result;
        }

        // cipher_suites
        let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2 + cs_len;
        if pos + 1 > body.len() {
            return result;
        }

        // compression_methods
        let comp_len = body[pos] as usize;
        pos += 1 + comp_len;
        if pos + 2 > body.len() {
            return result;
        }

        // extensions
        let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total_len;

        while pos + 4 <= ext_end && pos + 4 <= body.len() {
            let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4 + ext_len;

            if is_grease_value(ext_type) {
                result.push(ext_type);
            }
        }

        result
    }

    /// Rebuild the outer CH with a real ECH extension.
    ///
    /// Takes the original outer CH, replaces the SNI with public_name,
    /// and replaces the ECH GREASE extension with a real encrypted payload.
    fn rebuild_outer_with_ech(
        &self,
        original_outer: &[u8],
        ech_config: &crate::ech::config::EchConfig,
        cipher_suite: &crate::ech::config::HpkeSymmetricCipherSuite,
        encoded_inner: &[u8],
    ) -> Result<Vec<u8>> {
        use crate::ech::hpke as ech_hpke;

        // Per draft-ietf-tls-esni-24 Section 5.2, the correct flow is:
        //
        // 1. HPKE SetupBaseS → obtain `enc` + sender context
        // 2. Build the outer CH with real `enc` + zeroed `payload`
        // 3. Compute AAD from that outer CH (skip handshake header)
        // 4. sender_ctx.Seal(encoded_inner, AAD) → ciphertext
        // 5. Replace the zeroed payload with real ciphertext

        let ciphertext_len = encoded_inner.len() + ech_hpke::AEAD_TAG_LEN;

        // --- Phase 1: HPKE SetupBaseS to get enc ---
        let setup = ech_hpke::ech_hpke_setup(ech_config, cipher_suite)?;
        let enc = &setup.enc;

        // Build real ECH extension bytes with real enc + zeroed payload.
        let mut ech_ext_payload = Vec::new();
        ech_ext_payload.push(0x00); // type = outer
        ech_ext_payload.extend_from_slice(&cipher_suite.kdf_id.to_be_bytes());
        ech_ext_payload.extend_from_slice(&cipher_suite.aead_id.to_be_bytes());
        ech_ext_payload.push(ech_config.config_id);
        // enc: real HPKE encapsulated key (32 bytes for X25519)
        ech_ext_payload.extend_from_slice(&(enc.len() as u16).to_be_bytes());
        ech_ext_payload.extend_from_slice(enc);
        // payload: zeroed placeholder (will be replaced after seal)
        ech_ext_payload.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());
        ech_ext_payload.resize(ech_ext_payload.len() + ciphertext_len, 0);

        // --- Phase 2: Rebuild outer CH with real enc + zeroed payload ---
        let mut new_outer =
            self.rebuild_outer_message(original_outer, &ech_config.public_name, &ech_ext_payload)?;

        // Find the ECH extension offsets in the rebuilt message.
        let ech_search = find_ech_extension_in_message(&new_outer)?;

        // --- Phase 3: Build AAD ---
        // AAD = ClientHelloOuter body (without 4-byte handshake header),
        // with real `enc` already in place and `payload` still zeroed.
        let aad = &new_outer[4..];

        // --- Phase 4: HPKE Seal with correct AAD ---
        let ciphertext = setup.sender_ctx.seal(encoded_inner, aad)?;

        // --- Phase 5: Replace zeroed payload with real ciphertext ---
        let payload_abs_offset = ech_search.payload_offset;
        new_outer[payload_abs_offset..payload_abs_offset + ciphertext_len]
            .copy_from_slice(&ciphertext);

        Ok(new_outer)
    }

    /// Rebuild the outer CH message with a new SNI and ECH extension payload.
    ///
    /// Scans the extensions in the original message and rebuilds it,
    /// replacing SNI with public_name and ECH extension with the provided payload.
    fn rebuild_outer_message(
        &self,
        original: &[u8],
        public_name: &str,
        ech_payload: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse the original message to extract its structure.
        // original[0] = handshake type, [1..4] = length, [4..] = body
        if original.len() < 4 {
            return Err(TlsError::HandshakeFailure("outer CH too short".to_string()));
        }

        let body = &original[4..];
        // body: version(2) + random(32) + session_id_len(1) + session_id(N) + ...
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;

        // cipher_suites_len(2) + cipher_suites
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;

        // compression_methods_len(1) + compression_methods
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;

        // extensions_len(2) + extensions
        let _ext_len = u16::from_be_bytes([body[after_cm], body[after_cm + 1]]) as usize;
        let ext_start = after_cm + 2;

        // Rebuild extensions
        let mut new_ext_data = Vec::with_capacity(body.len() - ext_start + 64);
        let mut ext_pos = ext_start;
        while ext_pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[ext_pos], body[ext_pos + 1]]);
            let elen = u16::from_be_bytes([body[ext_pos + 2], body[ext_pos + 3]]) as usize;
            let ext_end = ext_pos + 4 + elen;
            if ext_end > body.len() {
                break;
            }

            if etype == ext_type::SNI {
                // Replace with public_name
                Sni {
                    hostname: public_name.to_string(),
                }
                .encode(&mut new_ext_data);
            } else if etype == ext_type::ENCRYPTED_CLIENT_HELLO {
                // Replace with provided ECH extension
                new_ext_data.extend_from_slice(&ext_type::ENCRYPTED_CLIENT_HELLO.to_be_bytes());
                new_ext_data.extend_from_slice(&(ech_payload.len() as u16).to_be_bytes());
                new_ext_data.extend_from_slice(ech_payload);
            } else {
                // Copy as-is
                new_ext_data.extend_from_slice(&body[ext_pos..ext_end]);
            }

            ext_pos = ext_end;
        }

        // Reassemble the full message
        let _new_body_len = ext_start + new_ext_data.len();
        // Actually: body up to ext_start stays the same, then new extensions
        let pre_ext = &body[..after_cm];

        let full_body_len = pre_ext.len() + 2 + new_ext_data.len();
        let mut msg = Vec::with_capacity(4 + full_body_len);

        // Handshake header
        msg.push(handshake_type::CLIENT_HELLO);
        let body_len_u32 = full_body_len as u32;
        msg.extend_from_slice(&body_len_u32.to_be_bytes()[1..4]);

        // Body up to extensions length
        msg.extend_from_slice(pre_ext);
        // Extensions length
        msg.extend_from_slice(&(new_ext_data.len() as u16).to_be_bytes());
        // Extensions
        msg.extend_from_slice(&new_ext_data);

        Ok(msg)
    }

    /// Build the inner CH as a complete handshake message (with header) for transcript.
    fn build_inner_hello_message(&self, inner_ch_body: &[u8], outer_message: &[u8]) -> Vec<u8> {
        // The inner hello for transcript purposes needs the session_id from the outer CH
        // (per spec, EncodedClientHelloInner has empty session_id, but when decoded
        // the server copies it from outer).
        //
        // For the client's transcript, we use the inner CH body AS-IS but wrapped
        // in a handshake header, with the outer's session_id spliced in.

        // Extract session_id from outer message
        let outer_body = &outer_message[4..];
        let sid_len = outer_body[34] as usize;
        let session_id = &outer_body[35..35 + sid_len];

        // Build inner CH with session_id from outer
        let mut inner_with_sid = Vec::with_capacity(inner_ch_body.len() + sid_len);
        // version(2) + random(32) = first 34 bytes
        inner_with_sid.extend_from_slice(&inner_ch_body[..34]);
        // Replace empty session_id with outer's
        inner_with_sid.push(sid_len as u8);
        inner_with_sid.extend_from_slice(session_id);
        // Rest of the body (skip the original empty session_id: 1 byte of length 0)
        inner_with_sid.extend_from_slice(&inner_ch_body[35..]);

        // Add handshake header
        let body_len = inner_with_sid.len() as u32;
        let mut msg = Vec::with_capacity(4 + inner_with_sid.len());
        msg.push(handshake_type::CLIENT_HELLO);
        msg.extend_from_slice(&body_len.to_be_bytes()[1..4]);
        msg.extend_from_slice(&inner_with_sid);

        msg
    }

    // -----------------------------------------------------------------------
    // Helper: Cipher Suites
    // -----------------------------------------------------------------------

    /// Encode the cipher suites list, optionally prepending a GREASE value.
    fn encode_cipher_suites(&self, grease_value: u16) -> Vec<u8> {
        let grease_extra = if self.profile.grease.cipher_suite {
            1
        } else {
            0
        };
        let count = grease_extra + self.profile.cipher_suites.len();
        let mut buf = Vec::with_capacity(count * 2);

        if self.profile.grease.cipher_suite {
            buf.extend_from_slice(&grease_value.to_be_bytes());
        }
        for &suite in &self.profile.cipher_suites {
            buf.extend_from_slice(&suite.to_be_bytes());
        }
        buf
    }

    // -----------------------------------------------------------------------
    // Helper: Key Pairs
    // -----------------------------------------------------------------------

    /// Generate ephemeral key pairs for all curves listed in `key_share_curves`.
    fn generate_key_pairs(&self) -> Result<Vec<EphemeralKeyPair>> {
        self.profile
            .key_share_curves
            .iter()
            .filter_map(|&curve_code| {
                KxGroup::from_code_point(curve_code).map(kx::generate_key_pair)
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Helper: Extensions
    // -----------------------------------------------------------------------

    /// Encode all extensions in profile order, **except** the padding extension.
    ///
    /// Returns `(encoded_bytes, padding_position)` where `padding_position` is
    /// the byte offset in the buffer where the padding extension should be
    /// inserted (if applicable).
    ///
    /// If the profile has `randomization.shuffle_extensions` enabled, a
    /// Fisher-Yates permutation is applied. ClientHello styles may first remove
    /// style-owned entries such as Chromium/BoringSSL ordinary GREASE bookends.
    /// Compute the (possibly shuffled) extension order for this ClientHello.
    ///
    /// Separated from encoding so the same permutation can be shared with the
    /// ECH inner ClientHello (BoringSSL shares a single permutation per
    /// connection for both inner and outer).
    fn compute_extension_order(&self) -> Vec<crate::profile::types::ExtensionSpec> {
        let extensions = if matches!(
            self.profile.tls_client_hello_style,
            TlsClientHelloStyle::ChromiumBoringssl
        ) {
            self.profile
                .extensions
                .iter()
                .filter(|spec| !matches!(spec.source, ExtensionSource::Grease))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            self.profile.extensions.clone()
        };

        if self
            .profile
            .randomization
            .as_ref()
            .is_some_and(|r| r.shuffle_extensions)
        {
            // Use the injected RNG if the caller supplied one (reproducible when
            // it is seeded); otherwise a fresh OS RNG (the historical behavior).
            let mut slot = self.shuffle_rng.borrow_mut();
            match slot.as_deref_mut() {
                Some(rng) => shuffle_extensions(&extensions, rng),
                None => shuffle_extensions(&extensions, &mut OsRng),
            }
        } else {
            extensions
        }
    }

    fn encode_extensions_without_padding(
        &self,
        key_pairs: &[EphemeralKeyPair],
        grease: &grease::GreaseValues,
        extensions: &[crate::profile::types::ExtensionSpec],
    ) -> Result<(Vec<u8>, Option<usize>)> {
        let mut buf = Vec::with_capacity(512);
        let mut padding_pos: Option<usize> = None;
        let chromium_boringssl = matches!(
            self.profile.tls_client_hello_style,
            TlsClientHelloStyle::ChromiumBoringssl
        );

        if chromium_boringssl && self.profile.grease.extensions {
            GreaseExtension::with_value_and_len(grease.get(grease::GreaseIndex::Extension1), 0)
                .encode(&mut buf);
        }

        // Track which GREASE extension we're on (Extension1 vs Extension2)
        let mut grease_ext_idx = 0u8;
        let mut pending_psk_extensions: Vec<&ExtensionSpec> = Vec::new();

        for spec in extensions {
            if spec.extension_type == ext_type::PADDING {
                if !chromium_boringssl {
                    padding_pos = Some(buf.len());
                }
                continue;
            }

            if chromium_boringssl && spec.extension_type == ext_type::PRE_SHARED_KEY {
                pending_psk_extensions.push(spec);
                continue;
            }

            self.encode_extension_spec(
                spec,
                key_pairs,
                grease,
                chromium_boringssl,
                &mut grease_ext_idx,
                &mut buf,
            )?;
        }

        // If a cookie was provided (from HRR), append it as an extension.
        if let Some(ref cookie_data) = self.cookie {
            // cookie extension: type (2) + length (2) + cookie_length (2) + cookie
            let cookie_ext_len = 2 + cookie_data.len();
            buf.extend_from_slice(&ext_type::COOKIE.to_be_bytes());
            buf.extend_from_slice(&(cookie_ext_len as u16).to_be_bytes());
            buf.extend_from_slice(&(cookie_data.len() as u16).to_be_bytes());
            buf.extend_from_slice(cookie_data);
        }

        if chromium_boringssl && self.profile.grease.extensions {
            GreaseExtension::with_value_and_len(grease.get(grease::GreaseIndex::Extension2), 1)
                .encode(&mut buf);
        }

        if chromium_boringssl {
            padding_pos = Some(buf.len());
        }

        for spec in pending_psk_extensions {
            self.encode_extension_spec(
                spec,
                key_pairs,
                grease,
                chromium_boringssl,
                &mut grease_ext_idx,
                &mut buf,
            )?;
        }

        Ok((buf, padding_pos))
    }

    fn encode_extension_spec(
        &self,
        spec: &ExtensionSpec,
        key_pairs: &[EphemeralKeyPair],
        grease: &grease::GreaseValues,
        chromium_boringssl: bool,
        grease_ext_idx: &mut u8,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        match &spec.source {
            ExtensionSource::Auto => {
                self.encode_auto_extension(spec.extension_type, key_pairs, grease, buf)?;
            }
            ExtensionSource::RawBytes { data } => {
                let payload = decode_hex(data)?;
                GenericExtension::new(spec.extension_type, payload).encode(buf);
            }
            ExtensionSource::Grease => {
                if self.profile.grease.extensions && !chromium_boringssl {
                    let (ext_grease, payload_len) = match grease_ext_idx {
                        0 => (grease.get(grease::GreaseIndex::Extension1), 0),
                        _ => (grease.get(grease::GreaseIndex::Extension2), 1),
                    };
                    *grease_ext_idx += 1;
                    GreaseExtension::with_value_and_len(ext_grease, payload_len).encode(buf);
                }
            }
        }
        Ok(())
    }

    /// Encode a single "auto" extension based on its type code.
    ///
    /// Auto extensions derive their payload from the profile configuration
    /// and runtime context (hostname, generated keys, etc.).
    fn encode_auto_extension(
        &self,
        etype: u16,
        key_pairs: &[EphemeralKeyPair],
        grease: &grease::GreaseValues,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        match etype {
            // --- SNI (Server Name Indication) ---
            // RFC 6066 §3: literal IP addresses MUST NOT appear in SNI,
            // and the HostName MUST NOT be empty.
            ext_type::SNI => {
                if !self.hostname_is_ip() && !self.hostname.is_empty() {
                    Sni {
                        hostname: self.hostname.clone(),
                    }
                    .encode(buf);
                }
            }

            // --- Extended Master Secret (empty payload) ---
            ext_type::EXTENDED_MASTER_SECRET => {
                ExtendedMasterSecret.encode(buf);
            }

            // --- Renegotiation Info ---
            ext_type::RENEGOTIATION_INFO => {
                RenegotiationInfo::initial().encode(buf);
            }

            // --- Supported Groups ---
            // Optionally prepend a GREASE value
            ext_type::SUPPORTED_GROUPS => {
                let mut groups = Vec::with_capacity(self.profile.supported_groups.len() + 1);
                if self.profile.grease.supported_groups {
                    groups.push(grease.get(grease::GreaseIndex::Group));
                }
                groups.extend_from_slice(&self.profile.supported_groups);
                SupportedGroups { groups }.encode(buf);
            }

            // --- EC Point Formats ---
            ext_type::EC_POINT_FORMATS => {
                EcPointFormats {
                    formats: self.profile.ec_point_formats.clone(),
                }
                .encode(buf);
            }

            // --- Session Ticket (empty in initial CH, or with data for resumption) ---
            ext_type::SESSION_TICKET => {
                if let Some(ref ticket_data) = self.session_ticket_data {
                    SessionTicket {
                        data: ticket_data.clone(),
                    }
                    .encode(buf);
                } else {
                    SessionTicket::empty().encode(buf);
                }
            }

            // --- ALPN ---
            ext_type::ALPN => {
                if !self.profile.alpn_protocols.is_empty() {
                    Alpn {
                        protocols: self.profile.alpn_protocols.clone(),
                    }
                    .encode(buf);
                }
            }

            // --- Status Request (OCSP Stapling) ---
            ext_type::STATUS_REQUEST => {
                StatusRequest.encode(buf);
            }

            // --- Signature Algorithms ---
            // Optionally prepend a GREASE value
            ext_type::SIGNATURE_ALGORITHMS => {
                let mut algos = Vec::with_capacity(self.profile.signature_algorithms.len() + 1);
                if self.profile.grease.signature_algorithms {
                    algos.push(grease.get(grease::GreaseIndex::Cipher));
                }
                algos.extend_from_slice(&self.profile.signature_algorithms);
                SignatureAlgorithms { algorithms: algos }.encode(buf);
            }

            // --- Signed Certificate Timestamp (empty) ---
            ext_type::SIGNED_CERTIFICATE_TIMESTAMP => {
                SignedCertificateTimestamp.encode(buf);
            }

            // --- Key Share ---
            ext_type::KEY_SHARE => {
                let mut entries: Vec<KeyShareEntry> = Vec::new();

                // Optionally prepend a GREASE key_share entry.
                // After HRR (is_retry), Chrome/BoringSSL omits the GREASE
                // key_share entry and only sends the server-requested group.
                if self.profile.grease.key_share && !self.is_retry {
                    entries.push(KeyShareEntry {
                        group: grease.get(grease::GreaseIndex::Group),
                        key_data: vec![0x00], // 1-byte dummy
                    });
                }

                for kp in key_pairs {
                    entries.push(KeyShareEntry {
                        group: kp.group.code_point(),
                        key_data: kp.public_key.clone(),
                    });
                }
                KeyShare { entries }.encode(buf);
            }

            // --- PSK Key Exchange Modes ---
            ext_type::PSK_KEY_EXCHANGE_MODES => {
                PskKeyExchangeModes {
                    modes: vec![psk_key_exchange_modes::mode::PSK_DHE_KE],
                }
                .encode(buf);
            }

            // --- Supported Versions ---
            // List all versions from max to min, optionally with GREASE prefix
            ext_type::SUPPORTED_VERSIONS => {
                let max_v = self.profile.tls_max_version.as_u16();
                let min_v = self.profile.tls_min_version.as_u16();

                let mut versions = Vec::with_capacity((max_v - min_v + 1) as usize + 1);
                if self.profile.grease.supported_versions {
                    versions.push(grease.get(grease::GreaseIndex::Version));
                }
                // Add versions from max to min (descending)
                for v in (min_v..=max_v).rev() {
                    versions.push(v);
                }
                SupportedVersions { versions }.encode(buf);
            }

            // --- Compress Certificate ---
            ext_type::COMPRESS_CERTIFICATE => {
                if let Some(ref algos) = self.profile.compress_cert_algorithms {
                    CompressCertificate {
                        algorithms: algos.clone(),
                    }
                    .encode(buf);
                }
            }

            // --- Application Settings (ALPS) — both old (0x4469) and new (0x44CD) code points ---
            ext_type::APPLICATION_SETTINGS | ext_type::APPLICATION_SETTINGS_NEW => {
                if let Some(ref protos) = self.profile.alps_protocols {
                    Alps {
                        extension_type: etype, // Use the actual type from the profile
                        protocols: protos.clone(),
                    }
                    .encode(buf);
                }
            }

            // --- Delegated Credentials ---
            ext_type::DELEGATED_CREDENTIALS => {
                if let Some(ref dc) = self.profile.delegated_credentials {
                    DelegatedCredentials {
                        signature_algorithms: dc.signature_algorithms.clone(),
                    }
                    .encode(buf);
                }
            }

            // --- Record Size Limit ---
            ext_type::RECORD_SIZE_LIMIT => {
                if let Some(limit) = self.profile.record_size_limit {
                    RecordSizeLimit { limit }.encode(buf);
                }
            }

            // --- Encrypted Client Hello (ECH) ---
            ext_type::ENCRYPTED_CLIENT_HELLO => {
                if let Some(ref ech_mode) = self.profile.ech {
                    match ech_mode {
                        EchMode::Grease(config) => {
                            // ECH GREASE: generate random-looking ECH outer extension.
                            // config_id comes from per-connection GREASE seed, matching
                            // BoringSSL's hs->grease_seed[ssl_grease_ech_config_id].
                            let config_id = grease.raw_seed(grease::GreaseIndex::EchConfigId);
                            EchGreaseExtension::new(config, &self.hostname, config_id).encode(buf);
                        }
                        EchMode::Disabled => {}
                        EchMode::Real { .. } => {
                            // Real ECH is handled by build_with_real_ech() when
                            // ech_config_list is provided at runtime.  When the profile
                            // says Real but no runtime config was injected, we skip
                            // the extension (the outer CH won't have ECH).
                            tracing::debug!("ECH profile mode is Real but no runtime config — skipping ECH extension");
                        }
                    }
                }
            }

            // --- QUIC transport parameters ---
            ext_type::QUIC_TRANSPORT_PARAMETERS => {
                let payload = self.quic_transport_parameters.as_ref().ok_or_else(|| {
                    TlsError::InvalidProfile(
                        "QUIC transport parameters extension requested without payload".to_string(),
                    )
                })?;
                GenericExtension::new(etype, payload.clone()).encode(buf);
            }

            // --- Early Data (empty payload) ---
            ext_type::EARLY_DATA => {
                if self.early_data {
                    GenericExtension::empty(etype).encode(buf);
                }
            }

            // --- Encrypt-Then-MAC (empty) ---
            ext_type::ENCRYPT_THEN_MAC => {
                EncryptThenMac.encode(buf);
            }

            // --- Padding is handled separately ---
            ext_type::PADDING => {
                // Should not reach here; padding is skipped in the main loop.
            }

            // --- Unknown / fallback: emit as empty extension ---
            _ => {
                tracing::warn!(
                    ext_type = etype,
                    "unknown auto extension type, emitting as empty"
                );
                GenericExtension::empty(etype).encode(buf);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helper: Padding
    // -----------------------------------------------------------------------

    /// Calculate how many zero bytes the padding extension should contain.
    ///
    /// Returns `Some(n)` if padding is needed (n zero bytes), or `None`
    /// if no padding extension should be emitted.
    ///
    /// `body_len_no_padding` is the ClientHello body length (everything after
    /// the 4-byte handshake header) without the padding extension.
    fn calculate_padding(&self, body_len_no_padding: usize) -> Option<usize> {
        match &self.profile.padding {
            PaddingStrategy::None => None,

            PaddingStrategy::BlockAlign {
                min_length,
                block_size,
            } => {
                let min = *min_length as usize;
                let block = *block_size as usize;
                if body_len_no_padding > min && body_len_no_padding < block {
                    // Total bytes the padding extension must add = block - current
                    let padding_ext_total = block - body_len_no_padding;
                    // Subtract the 4-byte extension header (type + length)
                    let padding_data = padding_ext_total.saturating_sub(4);
                    Some(padding_data)
                } else {
                    None
                }
            }

            PaddingStrategy::FixedTarget { target_length } => {
                let target = *target_length as usize;
                if body_len_no_padding < target {
                    let padding_ext_total = target - body_len_no_padding;
                    let padding_data = padding_ext_total.saturating_sub(4);
                    Some(padding_data)
                } else {
                    None
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Output of the ClientHello builder.
/// Location of the ECH extension fields within a ClientHello message.
struct EchExtensionOffsets {
    /// Absolute offset of the `enc` field data within the message.
    #[allow(dead_code)]
    enc_offset: usize,
    /// Absolute offset of the `payload` field data within the message.
    payload_offset: usize,
}

/// Find the ECH extension (0xFE0D) in a ClientHello message and return
/// the byte offsets of the `enc` and `payload` data fields.
fn find_ech_extension_in_message(msg: &[u8]) -> Result<EchExtensionOffsets> {
    // Skip handshake header (4 bytes)
    let body = &msg[4..];

    // Skip: version(2) + random(32) + session_id_len(1) + session_id(N)
    let sid_len = body[34] as usize;
    let after_sid = 35 + sid_len;

    // Skip: cipher_suites_len(2) + cipher_suites + comp_methods_len(1) + comp_methods
    let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
    let after_cs = after_sid + 2 + cs_len;
    let cm_len = body[after_cs] as usize;
    let after_cm = after_cs + 1 + cm_len;

    // Extensions start
    let ext_start = after_cm + 2;
    let mut pos = ext_start;

    while pos + 4 <= body.len() {
        let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let data_start = pos + 4;

        if etype == ext_type::ENCRYPTED_CLIENT_HELLO {
            // ECH outer payload structure:
            // type(1) + kdf_id(2) + aead_id(2) + config_id(1) + enc_len(2) + enc(N) + payload_len(2) + payload(M)
            let inner = &body[data_start..data_start + elen];
            if inner.len() < 10 {
                return Err(TlsError::HandshakeFailure(
                    "ECH extension too short".to_string(),
                ));
            }
            let enc_len = u16::from_be_bytes([inner[6], inner[7]]) as usize;
            let enc_data_offset = 4 + data_start + 8; // 4 = handshake header
            let payload_len_offset = 8 + enc_len;
            let payload_data_offset = 4 + data_start + payload_len_offset + 2;

            return Ok(EchExtensionOffsets {
                enc_offset: enc_data_offset,
                payload_offset: payload_data_offset,
            });
        }

        pos = data_start + elen;
    }

    Err(TlsError::HandshakeFailure(
        "ECH extension not found in outer ClientHello".to_string(),
    ))
}

/// Output of the ClientHello builder.
pub struct ClientHelloOutput {
    /// The complete ClientHello handshake message bytes
    /// (Handshake header + ClientHello body).
    ///
    /// When real ECH is active, this is the **outer** ClientHello
    /// (with `public_name` as SNI and encrypted inner CH in the ECH payload).
    pub message: Vec<u8>,

    /// Ephemeral key pairs generated for the key_share extension.
    /// These must be kept for use in the TLS key exchange after ServerHello.
    pub key_shares: Vec<EphemeralKeyPair>,

    /// The raw inner ClientHello bytes (with Handshake header), if real ECH
    /// was used.  Needed for transcript switching when the server accepts ECH.
    ///
    /// `None` when ECH is not active or only GREASE is used.
    pub inner_hello: Option<Vec<u8>>,

    /// Whether real ECH encryption was performed for this ClientHello.
    pub ech_offered: bool,

    /// GREASE values used in this ClientHello, preserved for HRR retries.
    pub grease_values: grease::GreaseValues,

    /// The (possibly shuffled) extension order used in this ClientHello.
    /// Stored so the inner ECH ClientHello can reuse the same permutation
    /// (matching BoringSSL's `ssl_setup_extension_permutation`).
    pub(crate) shuffled_extensions: Vec<crate::profile::types::ExtensionSpec>,
}

impl std::fmt::Debug for ClientHelloOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHelloOutput")
            .field("message_len", &self.message.len())
            .field("key_shares", &self.key_shares.len())
            .field("ech_offered", &self.ech_offered)
            .field("has_inner_hello", &self.inner_hello.is_some())
            .field("shuffled_extensions", &self.shuffled_extensions.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Generate 32 cryptographically random bytes for the ClientHello.random field.
fn generate_random_bytes() -> [u8; 32] {
    let rng = SystemRandom::new();
    let mut random = [0u8; 32];
    rng.fill(&mut random).expect("system RNG failed");
    random
}

/// Generate a random session ID of the specified length.
fn generate_session_id(length: u8) -> Vec<u8> {
    let len = length as usize;
    if len == 0 {
        return Vec::new();
    }
    let rng = SystemRandom::new();
    let mut id = vec![0u8; len];
    rng.fill(&mut id).expect("system RNG failed");
    id
}

/// Decode a hex string (with optional spaces and colons) into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let hex: String = hex
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !hex.len().is_multiple_of(2) {
        return Err(TlsError::InvalidProfile(
            "hex string has odd length".to_string(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| TlsError::InvalidProfile(format!("invalid hex at position {}", i)))
        })
        .collect()
}

fn is_grease_value(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Minimal [`rand_core::RngCore`] over the OS RNG (aws-lc-rs), used as the
/// default shuffle source when the caller injects no RNG. `lktls` bundles no
/// concrete PRNG — reproducible randomness is the caller's choice via
/// [`ClientHelloBuilder::with_rng`].
struct OsRng;

impl rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        // OS RNG failure is catastrophic and not expected; fall back to a
        // deterministic fill so we never panic in the handshake path.
        if SystemRandom::new().fill(dst).is_err() {
            for (i, b) in dst.iter_mut().enumerate() {
                *b = i as u8;
            }
        }
    }
}

/// Uniform index in `[0, n)` via rejection sampling (unbiased; no `rand` dep).
fn below<R: rand_core::RngCore + ?Sized>(rng: &mut R, n: usize) -> usize {
    debug_assert!(n > 0);
    let n = n as u64;
    // Reject the bottom `2^64 mod n` values so the rest is an exact multiple of n.
    let reject_below = n.wrapping_neg() % n;
    loop {
        let v = rng.next_u64();
        if v >= reject_below {
            return (v % n) as usize;
        }
    }
}

/// Fisher-Yates permutation of TLS extensions, matching BoringSSL's
/// `ssl_setup_extension_permutation()`.
///
/// BoringSSL permutes **only the real extensions**. The GREASE extensions are
/// *not* part of the permutation: the leading GREASE stays at the front and the
/// trailing GREASE at the back (their slots are structural). `pre_shared_key`
/// must be the very last extension (RFC 8446 §4.2.11). So GREASE extensions are
/// pinned **in their original slots** (a profile lists the leading GREASE first
/// and the trailing GREASE last), `pre_shared_key` is forced last, and only the
/// remaining (real) extensions are shuffled — and re-inserted into the non-fixed
/// slots so the GREASE bookends never move.
fn shuffle_extensions<R: rand_core::RngCore + ?Sized>(
    extensions: &[crate::profile::types::ExtensionSpec],
    rng: &mut R,
) -> Vec<crate::profile::types::ExtensionSpec> {
    use crate::profile::types::ExtensionSource;

    let is_grease =
        |e: &crate::profile::types::ExtensionSpec| matches!(e.source, ExtensionSource::Grease);
    // `pre_shared_key` is the only type-pinned extension (see NON_SHUFFLEABLE).
    let is_psk = |e: &crate::profile::types::ExtensionSpec| {
        !RandomizationConfig::is_shuffleable(e.extension_type)
    };

    let mut shuffleable: Vec<_> = extensions
        .iter()
        .filter(|e| !is_grease(e) && !is_psk(e))
        .cloned()
        .collect();

    // Unbiased Fisher-Yates over the shuffleable subset. The caller supplies the
    // RNG, so the permutation is reproducible whenever a seeded RNG is passed.
    let n = shuffleable.len();
    for i in (1..n).rev() {
        shuffleable.swap(i, below(rng, i + 1));
    }

    // Reassemble: GREASE keeps its original slot, `pre_shared_key` is forced
    // last, every other slot is filled from the shuffled set in order.
    let mut shuffled = shuffleable.into_iter();
    let mut psk: Vec<_> = Vec::new();
    let mut out: Vec<_> = Vec::with_capacity(extensions.len());
    for e in extensions {
        if is_grease(e) {
            out.push(e.clone());
        } else if is_psk(e) {
            psk.push(e.clone());
        } else if let Some(next) = shuffled.next() {
            out.push(next);
        }
    }
    out.extend(psk);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::presets;

    #[test]
    fn test_build_chrome_131_produces_valid_handshake_message() {
        let profile = presets::chrome_131();
        let builder = ClientHelloBuilder::new(&profile, "example.com");
        let output = builder.build().expect("build should succeed");

        let msg = &output.message;

        // Verify handshake header
        assert_eq!(msg[0], 0x01, "should be ClientHello type");

        // Verify 3-byte length matches actual body length
        let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        assert_eq!(body_len, msg.len() - 4, "handshake length should match");

        // Verify protocol version on wire = TLS 1.2
        assert_eq!(msg[4], 0x03);
        assert_eq!(msg[5], 0x03);

        // Verify random is 32 bytes (offset 6..38)
        // Session ID length at offset 38
        let session_id_len = msg[38] as usize;
        assert_eq!(
            session_id_len, 32,
            "Chrome 131 session ID should be 32 bytes"
        );

        // Verify key shares were generated
        assert!(!output.key_shares.is_empty(), "should have key shares");
        assert_eq!(
            output.key_shares[0].group,
            KxGroup::X25519,
            "Chrome 131 uses X25519"
        );

        // Verify message is reasonably sized (Chrome CH is typically ~500-520 bytes)
        assert!(
            msg.len() >= 400 && msg.len() <= 600,
            "unexpected message size: {} bytes",
            msg.len()
        );
    }

    #[test]
    fn test_build_chrome_144_produces_valid_handshake_message() {
        let profile = presets::chrome_144();
        let builder = ClientHelloBuilder::new(&profile, "example.com");
        let output = builder.build().expect("build should succeed");
        let msg = &output.message;
        assert_eq!(msg[0], 0x01, "ClientHello type");
        let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        assert_eq!(body_len, msg.len() - 4, "handshake length");
        assert!(
            msg.len() >= 400 && msg.len() <= 2048,
            "unexpected Chrome 144 CH size: {}",
            msg.len()
        );
        assert!(!output.key_shares.is_empty(), "key shares");
    }

    #[test]
    fn test_chromium_boringssl_grease_bookends_are_runtime_generated() {
        let profile = presets::chrome_144();
        let output = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect("build should succeed");
        let details = extract_extension_types_and_lengths_from_body(&output.message[4..]);

        let grease_entries: Vec<_> = details
            .iter()
            .filter(|(ext_type, _)| is_grease_value(*ext_type))
            .collect();
        assert_eq!(
            grease_entries.len(),
            2,
            "Chromium/BoringSSL should emit two ordinary GREASE extensions"
        );
        assert!(
            is_grease_value(details.first().expect("first extension").0),
            "first extension should be GREASE"
        );
        assert!(
            is_grease_value(details.last().expect("last extension").0),
            "last extension should be GREASE when no PSK is present"
        );
        assert_eq!(grease_entries[0].1, 0, "first GREASE payload is empty");
        assert_eq!(grease_entries[1].1, 1, "second GREASE payload is one byte");
        assert!(
            output
                .shuffled_extensions
                .iter()
                .all(|e| !matches!(e.source, ExtensionSource::Grease)),
            "ordinary GREASE bookends should not participate in the shuffled extension list"
        );

        let wire_real_extensions: Vec<u16> = details
            .iter()
            .map(|(ext_type, _)| *ext_type)
            .filter(|ext_type| !is_grease_value(*ext_type))
            .collect();
        let shuffled_real_extensions: Vec<u16> = output
            .shuffled_extensions
            .iter()
            .map(|e| e.extension_type)
            .collect();
        assert_eq!(wire_real_extensions, shuffled_real_extensions);
    }

    #[test]
    fn test_chromium_boringssl_rejects_key_share_grease_without_supported_groups_grease() {
        let mut profile = presets::chrome_144();
        profile.grease.supported_groups = false;
        profile.grease.key_share = true;

        let err = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect_err("split group/key_share GREASE should be rejected");
        assert!(
            matches!(
                err,
                TlsError::InvalidProfile(ref msg)
                    if msg.contains("requires grease.supported_groups")
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_chromium_boringssl_rejects_signature_algorithms_grease() {
        let mut profile = presets::chrome_144();
        profile.grease.signature_algorithms = true;

        let err = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect_err("Chromium/BoringSSL should reject sigalg GREASE");
        assert!(
            matches!(
                err,
                TlsError::InvalidProfile(ref msg)
                    if msg.contains("does not support grease.signature_algorithms")
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_rejects_explicit_grease_group_when_runtime_grease_is_enabled() {
        let mut profile = presets::chrome_144();
        profile.supported_groups.insert(0, 0x0a0a);

        let err = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect_err("explicit GREASE group should be rejected");
        assert!(
            matches!(
                err,
                TlsError::InvalidProfile(ref msg)
                    if msg.contains("supported_groups contains explicit GREASE value")
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_rejects_fixed_grease_extension_type_when_runtime_grease_is_enabled() {
        let mut profile = presets::chrome_144();
        profile.extensions.push(ExtensionSpec {
            extension_type: 0x0a0a,
            source: ExtensionSource::RawBytes {
                data: String::new(),
            },
        });

        let err = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect_err("fixed GREASE extension type should be rejected");
        assert!(
            matches!(
                err,
                TlsError::InvalidProfile(ref msg)
                    if msg.contains("extensions contains fixed GREASE extension type")
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_chromium_boringssl_psk_stays_after_second_grease_bookend() {
        let mut profile = presets::chrome_144();
        profile.extensions.push(ExtensionSpec {
            extension_type: ext_type::PRE_SHARED_KEY,
            source: ExtensionSource::RawBytes {
                data: String::new(),
            },
        });

        let output = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect("build should succeed");
        let details = extract_extension_types_and_lengths_from_body(&output.message[4..]);
        assert_eq!(
            details.last().map(|(ext_type, _)| *ext_type),
            Some(ext_type::PRE_SHARED_KEY),
            "pre_shared_key must remain the final extension"
        );
        assert!(
            details
                .get(details.len().saturating_sub(2))
                .is_some_and(|(ext_type, _)| is_grease_value(*ext_type)),
            "second GREASE bookend should be immediately before pre_shared_key"
        );
    }

    #[test]
    fn test_chromium_boringssl_padding_stays_before_psk() {
        let mut profile = presets::chrome_144();
        profile.padding = PaddingStrategy::FixedTarget {
            target_length: 4096,
        };
        profile.extensions.push(ExtensionSpec {
            extension_type: ext_type::PRE_SHARED_KEY,
            source: ExtensionSource::RawBytes {
                data: String::new(),
            },
        });

        let output = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect("build should succeed");
        let details = extract_extension_types_and_lengths_from_body(&output.message[4..]);
        assert_eq!(
            details.last().map(|(ext_type, _)| *ext_type),
            Some(ext_type::PRE_SHARED_KEY),
            "pre_shared_key must remain final even when padding is inserted"
        );
        assert_eq!(
            details
                .get(details.len().saturating_sub(2))
                .map(|(ext_type, _)| *ext_type),
            Some(ext_type::PADDING),
            "Chromium/BoringSSL padding should be inserted before pre_shared_key"
        );
    }

    #[test]
    fn test_build_with_custom_random() {
        let profile = presets::chrome_131();
        let random = [0x42u8; 32];
        let builder = ClientHelloBuilder::new(&profile, "example.com").with_random(random);
        let output = builder.build().expect("build should succeed");

        // Verify the custom random bytes appear at offset 6..38
        assert_eq!(&output.message[6..38], &random);
    }

    #[test]
    fn test_build_with_custom_session_id() {
        let profile = presets::chrome_131();
        let session_id = vec![0xAA; 16];
        let builder =
            ClientHelloBuilder::new(&profile, "example.com").with_session_id(session_id.clone());
        let output = builder.build().expect("build should succeed");

        // Session ID length at offset 38
        assert_eq!(output.message[38] as usize, 16);
        assert_eq!(&output.message[39..55], &session_id[..]);
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("0a0b0c").unwrap(), vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(decode_hex("0a 0b 0c").unwrap(), vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(decode_hex("0a:0b:0c").unwrap(), vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        assert!(decode_hex("0a0").is_err()); // odd length
    }

    #[test]
    fn test_build_chrome_144_contains_ech_grease() {
        let profile = presets::chrome_144();
        let builder = ClientHelloBuilder::new(&profile, "example.com");
        let output = builder.build().expect("build should succeed");

        let msg = &output.message;

        // Search for ECH extension type (0xFE0D) in the extensions section.
        // The extensions start after: handshake_header(4) + version(2) + random(32)
        //   + session_id_len(1) + session_id(32) + cipher_suites_len(2) + cipher_suites
        //   + comp_methods_len(1) + comp_methods(1) + extensions_len(2)
        // We scan for the 0xFE 0x0D byte pair.
        let mut found_ech = false;
        for i in 0..msg.len().saturating_sub(1) {
            if msg[i] == 0xFE && msg[i + 1] == 0x0D {
                found_ech = true;
                // After the 4-byte extension header, the first byte should be 0x00 (outer)
                if i + 4 < msg.len() {
                    assert_eq!(msg[i + 4], 0x00, "ECH type should be outer (0x00)");
                }
                break;
            }
        }
        assert!(
            found_ech,
            "Chrome 144 ClientHello should contain ECH extension (0xFE0D)"
        );
    }

    #[test]
    fn test_build_firefox_147_contains_ech_grease() {
        let profile = presets::firefox_147();
        let builder = ClientHelloBuilder::new(&profile, "example.com");
        let output = builder.build().expect("build should succeed");

        let msg = &output.message;

        let mut found_ech = false;
        for i in 0..msg.len().saturating_sub(1) {
            if msg[i] == 0xFE && msg[i + 1] == 0x0D {
                found_ech = true;
                // After 4-byte ext header: type=0x00, kdf=0x0001, aead=0x0003 (ChaCha20)
                if i + 8 < msg.len() {
                    assert_eq!(msg[i + 4], 0x00, "ECH type should be outer");
                    let aead_id = u16::from_be_bytes([msg[i + 7], msg[i + 8]]);
                    assert_eq!(aead_id, 0x0003, "Firefox should use ChaCha20Poly1305");
                }
                break;
            }
        }
        assert!(
            found_ech,
            "Firefox 147 ClientHello should contain ECH extension (0xFE0D)"
        );
    }

    #[test]
    fn test_ech_grease_produces_different_bytes_per_build() {
        let profile = presets::chrome_144();

        let output1 = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect("build 1");
        let output2 = ClientHelloBuilder::new(&profile, "example.com")
            .build()
            .expect("build 2");

        // Isolate the ECH GREASE extension (0xFE0D) instead of comparing whole
        // messages (which differ from random / session_id / key_share anyway):
        // its enc/payload fields must be re-randomized on each build.
        let ech1 = extract_extension_body(&output1.message, 0xFE0D)
            .expect("build 1 should carry the ECH GREASE extension");
        let ech2 = extract_extension_body(&output2.message, 0xFE0D)
            .expect("build 2 should carry the ECH GREASE extension");
        assert_ne!(
            ech1, ech2,
            "ECH GREASE extension (enc/payload) must be randomized per build"
        );
    }

    #[test]
    fn test_grease_value_format() {
        // Verify GREASE values follow the 0x?a?a pattern
        for _ in 0..100 {
            let v = grease::random_grease_value();
            let hi = (v >> 8) as u8;
            let lo = (v & 0xff) as u8;
            assert_eq!(hi, lo, "GREASE hi and lo bytes should match: 0x{:04x}", v);
            assert_eq!(
                hi & 0x0f,
                0x0a,
                "GREASE low nibble should be 0xa: 0x{:04x}",
                v
            );
        }
    }

    // -----------------------------------------------------------------------
    // Real ECH tests
    // -----------------------------------------------------------------------

    /// Helper: build a test ECHConfigList with a real X25519 key pair.
    fn build_test_ech_config_list_with_keypair(aead_id: u16) -> Vec<u8> {
        use ::hpke::kem::X25519HkdfSha256;
        use ::hpke::{Kem, Serializable};
        use rand_core::TryRngCore;

        let (_sk, pk) = X25519HkdfSha256::gen_keypair(&mut rand_core::OsRng.unwrap_err());
        let pk_bytes = pk.to_bytes();

        let mut contents = Vec::new();
        contents.push(42); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem_id = X25519
        contents.extend_from_slice(&(pk_bytes.len() as u16).to_be_bytes());
        contents.extend_from_slice(&pk_bytes);
        // cipher suite
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
        contents.extend_from_slice(&aead_id.to_be_bytes());
        contents.push(32); // max_name_length
        let pn = b"public.example.com";
        contents.push(pn.len() as u8);
        contents.extend_from_slice(pn);
        contents.extend_from_slice(&0u16.to_be_bytes()); // no extensions

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
    fn test_build_with_real_ech_chrome144() {
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001); // AES-128-GCM

        let builder = ClientHelloBuilder::new(&profile, "secret.example.com")
            .with_ech_config(ech_config_list);
        let output = builder.build().expect("ECH build should succeed");

        // Should have real ECH
        assert!(output.ech_offered, "should have ECH offered");
        assert!(output.inner_hello.is_some(), "should have inner hello");

        // Outer CH should be valid
        let msg = &output.message;
        assert_eq!(msg[0], 0x01, "should be ClientHello type");
        let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        assert_eq!(body_len, msg.len() - 4, "handshake length should match");

        // Outer CH SNI should be the public_name, not the real hostname.
        // Search for "public.example.com" in the message.
        let msg_str = String::from_utf8_lossy(msg);
        assert!(
            msg_str.contains("public.example.com"),
            "outer CH should have public_name as SNI"
        );
        assert!(
            !msg_str.contains("secret.example.com"),
            "outer CH should NOT have real hostname in SNI"
        );

        // Check inner hello has the real hostname.
        let inner = output.inner_hello.as_ref().unwrap();
        let inner_str = String::from_utf8_lossy(inner);
        assert!(
            inner_str.contains("secret.example.com"),
            "inner CH should have real hostname"
        );

        // The outer CH should contain the ECH extension (0xFE0D).
        let has_ech = find_extension_in_message(msg, 0xFE0D);
        assert!(has_ech, "outer CH should contain ECH extension");
    }

    #[test]
    fn test_build_with_real_ech_firefox147() {
        let profile = presets::firefox_147();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0003); // ChaCha20Poly1305

        let builder = ClientHelloBuilder::new(&profile, "hidden.example.org")
            .with_ech_config(ech_config_list);
        let output = builder.build().expect("ECH build should succeed");

        assert!(output.ech_offered);
        assert!(output.inner_hello.is_some());

        // Outer should have public_name
        let msg_str = String::from_utf8_lossy(&output.message);
        assert!(msg_str.contains("public.example.com"));
        assert!(!msg_str.contains("hidden.example.org"));
    }

    #[test]
    fn test_real_ech_produces_different_ciphertext_each_call() {
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001);

        let out1 = ClientHelloBuilder::new(&profile, "example.com")
            .with_ech_config(ech_config_list.clone())
            .build()
            .unwrap();
        let out2 = ClientHelloBuilder::new(&profile, "example.com")
            .with_ech_config(ech_config_list)
            .build()
            .unwrap();

        // Isolate the ECH extension (0xFE0D) so we actually check the
        // ciphertext / ephemeral-key fields differ, not the surrounding random.
        let ech1 = extract_extension_body(&out1.message, 0xFE0D)
            .expect("build 1 should carry the ECH extension");
        let ech2 = extract_extension_body(&out2.message, 0xFE0D)
            .expect("build 2 should carry the ECH extension");
        assert_ne!(
            ech1, ech2,
            "ECH extension (enc + ciphertext) must differ per call"
        );
    }

    /// Helper to check if an extension type exists in a ClientHello message.
    fn find_extension_in_message(msg: &[u8], target_type: u16) -> bool {
        let body = &msg[4..];
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_start = after_cm + 2;

        let mut pos = ext_start;
        while pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            if etype == target_type {
                return true;
            }
            pos += 4 + elen;
        }
        false
    }

    /// Return the body bytes of the first extension of `target_type`, if present.
    fn extract_extension_body(msg: &[u8], target_type: u16) -> Option<Vec<u8>> {
        let body = &msg[4..];
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_start = after_cm + 2;

        let mut pos = ext_start;
        while pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            if etype == target_type {
                return Some(body[pos + 4..pos + 4 + elen].to_vec());
            }
            pos += 4 + elen;
        }
        None
    }

    /// Extract the ordered list of extension types from a ClientHello body.
    /// `body` starts at the ClientHello body (after handshake header).
    fn extract_extension_types_from_body(body: &[u8]) -> Vec<u16> {
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_start = after_cm + 2;

        let mut types = Vec::new();
        let mut pos = ext_start;
        while pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            types.push(etype);
            pos += 4 + elen;
        }
        types
    }

    fn extract_extension_types_and_lengths_from_body(body: &[u8]) -> Vec<(u16, usize)> {
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_start = after_cm + 2;

        let mut details = Vec::new();
        let mut pos = ext_start;
        while pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            details.push((etype, elen));
            pos += 4 + elen;
        }
        details
    }

    fn extract_extension_payload_from_body(body: &[u8], target: u16) -> Option<Vec<u8>> {
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_total_len = u16::from_be_bytes([body[after_cm], body[after_cm + 1]]) as usize;
        let ext_start = after_cm + 2;
        let ext_end = ext_start + ext_total_len;

        let mut pos = ext_start;
        while pos + 4 <= body.len() && pos + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            let payload_start = pos + 4;
            let payload_end = payload_start + elen;
            if payload_end > body.len() || payload_end > ext_end {
                return None;
            }
            if etype == target {
                return Some(body[payload_start..payload_end].to_vec());
            }
            pos = payload_end;
        }

        None
    }

    fn extract_ech_outer_extension_types_from_body(body: &[u8]) -> Vec<u16> {
        let payload = extract_extension_payload_from_body(body, 0xFD00)
            .expect("ech_outer_extensions should be present");
        assert!(!payload.is_empty(), "ech_outer_extensions payload");
        let list_len = payload[0] as usize;
        assert_eq!(
            list_len % 2,
            0,
            "ech_outer_extensions list length should contain u16 entries"
        );
        assert!(
            payload.len() > list_len,
            "ech_outer_extensions payload shorter than advertised"
        );

        let mut types = Vec::new();
        for chunk in payload[1..1 + list_len].chunks_exact(2) {
            types.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        types
    }

    // -----------------------------------------------------------------------
    // ech_outer_extensions position tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_inner_ch_ech_outer_extensions_position() {
        // Build a real ECH ClientHello and inspect the inner CH's extension order.
        // The 0xFD00 extension should appear where the first compressed extension
        // was in the original profile order, NOT at the end.
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001);

        let builder =
            ClientHelloBuilder::new(&profile, "test.example.com").with_ech_config(ech_config_list);
        let output = builder.build().expect("build should succeed");
        assert!(output.inner_hello.is_some());

        let inner = output.inner_hello.unwrap();
        // inner is a full handshake message (header + body)
        let inner_body = &inner[4..];
        let inner_ext_types = extract_extension_types_from_body(inner_body);

        // 0xFD00 (ech_outer_extensions) must be present in the inner CH
        assert!(
            inner_ext_types.contains(&0xFD00),
            "inner CH must contain ech_outer_extensions (0xFD00), got: {:04X?}",
            inner_ext_types
        );

        // 0xFD00 must NOT be the last extension — the inner ECH extension (0xFE0D)
        // comes after it in the profile, so 0xFD00 can't be last.
        let fd00_pos = inner_ext_types.iter().position(|&t| t == 0xFD00).unwrap();
        assert!(
            fd00_pos < inner_ext_types.len() - 1,
            "0xFD00 should not be the last extension (pos={}, total={})",
            fd00_pos,
            inner_ext_types.len()
        );

        // The inner ECH extension (type=inner, 0xFE0D) must be present
        assert!(
            inner_ext_types.contains(&0xFE0D),
            "inner CH must contain ECH inner extension (0xFE0D)"
        );
    }

    #[test]
    fn test_chromium_real_ech_inner_references_outer_grease_extensions() {
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001);

        let output = ClientHelloBuilder::new(&profile, "grease.example.com")
            .with_ech_config(ech_config_list)
            .build()
            .expect("ECH build should succeed");

        let outer_grease_types: Vec<u16> = extract_extension_types_from_body(&output.message[4..])
            .into_iter()
            .filter(|ext_type| is_grease_value(*ext_type))
            .collect();
        assert_eq!(
            outer_grease_types.len(),
            2,
            "outer Chromium CH should have two ordinary GREASE extensions"
        );

        let inner = output.inner_hello.as_ref().expect("inner CH");
        let referenced_types = extract_ech_outer_extension_types_from_body(&inner[4..]);
        assert_eq!(
            referenced_types.first().copied(),
            outer_grease_types.first().copied(),
            "first outer GREASE extension should be referenced first"
        );
        assert_eq!(
            referenced_types.last().copied(),
            outer_grease_types.last().copied(),
            "second outer GREASE extension should be referenced last"
        );
        assert!(
            referenced_types.iter().any(|t| !is_grease_value(*t)),
            "real ECH should still reference non-GREASE compressed extensions"
        );
    }

    /// Returns true if a value matches the GREASE pattern (RFC 8701).
    fn is_grease(v: u16) -> bool {
        is_grease_value(v)
    }

    #[test]
    fn test_inner_ch_extension_order_matches_outer_shuffled_order() {
        // Verify that the inner CH uses the outer's shuffled extension
        // permutation (BoringSSL shares a single permutation per connection).
        //
        // Extensions compressed via ech_outer_extensions (0xFD00) appear
        // at a single position in the inner CH, so we verify:
        //   1. The full SET of non-GREASE extension types matches.
        //   2. Non-compressed extensions preserve their relative order
        //      from the shuffled list.
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001);
        let compress_types: std::collections::HashSet<u16> = profile
            .ech_outer_extensions
            .as_deref()
            .unwrap_or(&[51])
            .iter()
            .copied()
            .collect();

        let builder =
            ClientHelloBuilder::new(&profile, "order.example.com").with_ech_config(ech_config_list);
        let output = builder.build().unwrap();
        let inner = output.inner_hello.as_ref().unwrap();
        let inner_body = &inner[4..];
        let inner_ext_types = extract_extension_types_from_body(inner_body);

        // Expand 0xFD00 back into its referenced types.
        let ech_outer_list = profile.ech_outer_extensions.as_deref().unwrap_or(&[51]);
        let mut expanded = Vec::new();
        for &t in &inner_ext_types {
            if t == 0xFD00 {
                expanded.extend_from_slice(ech_outer_list);
            } else {
                expanded.push(t);
            }
        }

        const INNER_SKIP: &[u16] = &[
            ext_type::EXTENDED_MASTER_SECRET,
            ext_type::SESSION_TICKET,
            ext_type::EC_POINT_FORMATS,
        ];

        // Build expected set from the shuffled extension order.
        let expected_set: std::collections::HashSet<u16> = output
            .shuffled_extensions
            .iter()
            .filter(|e| e.extension_type != ext_type::PADDING)
            .filter(|e| !matches!(e.source, ExtensionSource::Grease))
            .filter(|e| !INNER_SKIP.contains(&e.extension_type))
            .map(|e| e.extension_type)
            .collect();

        let expanded_set: std::collections::HashSet<u16> = expanded
            .iter()
            .copied()
            .filter(|&t| !is_grease(t))
            .collect();

        assert_eq!(
            expected_set, expanded_set,
            "inner CH extension types (as set) should match shuffled order"
        );

        // Verify non-compressed extensions preserve relative order from
        // the shuffled list.
        let shuffled_non_compressed: Vec<u16> = output
            .shuffled_extensions
            .iter()
            .filter(|e| !matches!(e.source, ExtensionSource::Grease))
            .filter(|e| !INNER_SKIP.contains(&e.extension_type))
            .filter(|e| !compress_types.contains(&e.extension_type))
            .filter(|e| e.extension_type != ext_type::PADDING)
            .map(|e| e.extension_type)
            .collect();

        let inner_non_compressed: Vec<u16> = expanded
            .iter()
            .copied()
            .filter(|&t| !is_grease(t))
            .filter(|t| !compress_types.contains(t))
            .collect();

        assert_eq!(
            shuffled_non_compressed, inner_non_compressed,
            "non-compressed extensions should preserve shuffled relative order"
        );
    }

    // -----------------------------------------------------------------------
    // AAD correctness: enc must be real in AAD
    // -----------------------------------------------------------------------

    #[test]
    fn test_outer_ch_ech_enc_is_nonzero() {
        // After building a real ECH ClientHello, the outer CH's ECH extension
        // must contain a non-zero enc field (real HPKE encapsulated key).
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001);

        let builder = ClientHelloBuilder::new(&profile, "aad-test.example.com")
            .with_ech_config(ech_config_list);
        let output = builder.build().unwrap();

        // Parse the outer CH to find the ECH extension's enc field
        let msg = &output.message;
        let body = &msg[4..];
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_start = after_cm + 2;

        let mut pos = ext_start;
        let mut found = false;
        while pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            if etype == ext_type::ENCRYPTED_CLIENT_HELLO {
                // ECH payload: type(1) + kdf(2) + aead(2) + config_id(1) + enc_len(2) + enc(N)
                let data = &body[pos + 4..pos + 4 + elen];
                assert!(data.len() >= 8, "ECH ext too short");
                let enc_len = u16::from_be_bytes([data[6], data[7]]) as usize;
                let enc = &data[8..8 + enc_len];

                // enc must NOT be all zeros (that was the old bug)
                let all_zero = enc.iter().all(|&b| b == 0);
                assert!(!all_zero, "ECH enc field must be real HPKE key, not zeros");
                assert_eq!(enc_len, 32, "enc should be 32 bytes (X25519)");
                found = true;
                break;
            }
            pos += 4 + elen;
        }
        assert!(found, "ECH extension must be present in outer CH");
    }

    #[test]
    fn test_outer_ch_ech_payload_is_nonzero() {
        // The payload (ciphertext) must also be non-zero after ECH build.
        let profile = presets::chrome_144();
        let ech_config_list = build_test_ech_config_list_with_keypair(0x0001);

        let output = ClientHelloBuilder::new(&profile, "payload.example.com")
            .with_ech_config(ech_config_list)
            .build()
            .unwrap();

        let msg = &output.message;
        let body = &msg[4..];
        let sid_len = body[34] as usize;
        let after_sid = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_start = after_cm + 2;

        let mut pos = ext_start;
        while pos + 4 <= body.len() {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            if etype == ext_type::ENCRYPTED_CLIENT_HELLO {
                let data = &body[pos + 4..pos + 4 + elen];
                let enc_len = u16::from_be_bytes([data[6], data[7]]) as usize;
                let payload_offset = 8 + enc_len;
                let payload_len =
                    u16::from_be_bytes([data[payload_offset], data[payload_offset + 1]]) as usize;
                let payload = &data[payload_offset + 2..payload_offset + 2 + payload_len];

                let all_zero = payload.iter().all(|&b| b == 0);
                assert!(!all_zero, "ECH payload must be real ciphertext, not zeros");
                return;
            }
            pos += 4 + elen;
        }
        panic!("ECH extension not found");
    }

    /// Helper: scan extensions in a ClientHello message and return all extension type codes.
    fn extract_extension_types(msg: &[u8]) -> Vec<u16> {
        let body = &msg[4..];
        let session_id_len = body[34] as usize;
        let after_sid = 35 + session_id_len;
        let cs_len = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]) as usize;
        let after_cs = after_sid + 2 + cs_len;
        let cm_len = body[after_cs] as usize;
        let after_cm = after_cs + 1 + cm_len;
        let ext_total = u16::from_be_bytes([body[after_cm], body[after_cm + 1]]) as usize;
        let ext_start = after_cm + 2;
        let ext_end = ext_start + ext_total;

        let mut types = Vec::new();
        let mut pos = ext_start;
        while pos + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            types.push(etype);
            pos += 4 + elen;
        }
        types
    }

    #[test]
    fn test_sni_omitted_for_ipv4_address() {
        let profile = presets::chrome_144();
        let builder = ClientHelloBuilder::new(&profile, "127.0.0.1");
        let output = builder.build().expect("build should succeed");

        let ext_types = extract_extension_types(&output.message);
        assert!(
            !ext_types.contains(&ext_type::SNI),
            "SNI extension must NOT be present when hostname is an IPv4 address"
        );
    }

    #[test]
    fn test_sni_omitted_for_ipv6_address() {
        let profile = presets::chrome_144();
        let builder = ClientHelloBuilder::new(&profile, "::1");
        let output = builder.build().expect("build should succeed");

        let ext_types = extract_extension_types(&output.message);
        assert!(
            !ext_types.contains(&ext_type::SNI),
            "SNI extension must NOT be present when hostname is an IPv6 address"
        );
    }

    #[test]
    fn test_sni_omitted_for_full_ipv6_address() {
        let profile = presets::chrome_144();
        let builder = ClientHelloBuilder::new(&profile, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        let output = builder.build().expect("build should succeed");

        let ext_types = extract_extension_types(&output.message);
        assert!(
            !ext_types.contains(&ext_type::SNI),
            "SNI extension must NOT be present when hostname is an IPv6 address"
        );
    }

    #[test]
    fn test_sni_present_for_dns_hostname() {
        let profile = presets::chrome_144();
        let builder = ClientHelloBuilder::new(&profile, "example.com");
        let output = builder.build().expect("build should succeed");

        let ext_types = extract_extension_types(&output.message);
        assert!(
            ext_types.contains(&ext_type::SNI),
            "SNI extension MUST be present for DNS hostnames"
        );
    }

    #[test]
    fn test_hostname_is_ip_detection() {
        let profile = presets::chrome_144();

        let cases_ip = [
            "127.0.0.1",
            "192.168.0.10",
            "10.0.0.10",
            "::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "0.0.0.0",
            "255.255.255.255",
        ];
        for ip in &cases_ip {
            let builder = ClientHelloBuilder::new(&profile, *ip);
            assert!(builder.hostname_is_ip(), "{ip} should be detected as IP");
        }

        let cases_dns = [
            "example.com",
            "localhost",
            "my-server",
            "a.b.c.d.example.com",
            "192.168.0.10.nip.io",
        ];
        for name in &cases_dns {
            let builder = ClientHelloBuilder::new(&profile, *name);
            assert!(
                !builder.hostname_is_ip(),
                "{name} should NOT be detected as IP"
            );
        }
    }

    /// Regression: BoringSSL/Chrome does NOT permute the GREASE extensions — the
    /// leading GREASE is always first and the trailing GREASE always last. This
    /// is invisible to JA3/JA4 and the canonicalized fingerprint gate (they fold
    /// GREASE away), so it is guarded here at the shuffle level directly.
    #[test]
    fn shuffle_pins_grease_bookends_and_psk_last() {
        use crate::profile::types::{ExtensionSource, ExtensionSpec};

        let grease = || ExtensionSpec {
            extension_type: 0xFFFF,
            source: ExtensionSource::Grease,
        };
        let real = |t: u16| ExtensionSpec {
            extension_type: t,
            source: ExtensionSource::Auto,
        };
        let psk = ExtensionSpec {
            extension_type: 0x0029,
            source: ExtensionSource::Auto,
        };

        // Chrome's base layout plus a (resumption) pre_shared_key:
        // [GREASE, reals…, GREASE, PSK].
        let with_psk = vec![
            grease(),
            real(0x0000),
            real(0x002b),
            real(0x000b),
            real(0x0033),
            real(0x000d),
            grease(),
            psk.clone(),
        ];
        // Base layout (no PSK — Chrome's resting state): [GREASE, reals…, GREASE].
        let no_psk = vec![grease(), real(0x0000), real(0x002b), real(0x000b), grease()];

        // Run many times — the shuffle is randomized, so a position bug would
        // only show up probabilistically across iterations. One PRNG drives the
        // whole loop, so each call advances the stream to a different permutation
        // (fixed seed keeps the test deterministic).
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0xA5; 32]);
        for _ in 0..128 {
            let out = shuffle_extensions(&with_psk, &mut rng);
            assert_eq!(out.len(), with_psk.len());
            assert!(
                matches!(out.first().unwrap().source, ExtensionSource::Grease),
                "leading GREASE must remain first"
            );
            assert_eq!(
                out.last().unwrap().extension_type,
                0x0029,
                "pre_shared_key must be the last extension"
            );
            assert!(
                matches!(out[out.len() - 2].source, ExtensionSource::Grease),
                "trailing GREASE must remain just before pre_shared_key"
            );
            let mut reals: Vec<u16> = out
                .iter()
                .filter(|e| {
                    !matches!(e.source, ExtensionSource::Grease) && e.extension_type != 0x0029
                })
                .map(|e| e.extension_type)
                .collect();
            reals.sort_unstable();
            assert_eq!(reals, vec![0x0000, 0x000b, 0x000d, 0x002b, 0x0033]);

            let out = shuffle_extensions(&no_psk, &mut rng);
            assert!(
                matches!(out.first().unwrap().source, ExtensionSource::Grease),
                "leading GREASE must remain first (no-PSK layout)"
            );
            assert!(
                matches!(out.last().unwrap().source, ExtensionSource::Grease),
                "trailing GREASE must remain last (no-PSK layout)"
            );
        }
    }

    #[test]
    fn seeded_shuffle_order_is_reproducible_and_seed_sensitive() {
        // An injected seeded RNG (`with_rng`) controls the extension *order*
        // (not the per-connection GREASE values / key shares / CH-random, which
        // remain independently random). So we assert on the extension order:
        // same seed → identical order; varying seeds → not all identical.
        let profile = presets::chrome_148();
        assert!(
            profile
                .randomization
                .as_ref()
                .is_some_and(|r| r.shuffle_extensions),
            "test assumes chrome_148 shuffles extensions"
        );

        let order_for = |seed: [u8; 32]| -> Vec<u16> {
            use rand_core::SeedableRng;
            ClientHelloBuilder::new(&profile, "example.com")
                .with_rng(rand_chacha::ChaCha20Rng::from_seed(seed))
                .build()
                .expect("build should succeed")
                .shuffled_extensions
                .iter()
                .map(|e| e.extension_type)
                .collect()
        };

        // Reproducible: same seed → identical order, every time.
        let a = order_for([1u8; 32]);
        assert_eq!(
            a,
            order_for([1u8; 32]),
            "same seed must reproduce the order"
        );
        assert_eq!(
            a,
            order_for([1u8; 32]),
            "still reproducible on a third build"
        );

        // Seed-sensitive: across several seeds, not all orders are identical.
        let distinct = (1u8..=8)
            .map(|s| order_for([s; 32]))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            distinct.len() > 1,
            "different seeds should yield different extension orders"
        );
    }
}
