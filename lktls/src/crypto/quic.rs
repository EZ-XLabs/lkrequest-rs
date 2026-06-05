//! QUIC-specific key derivation helpers.
//!
//! This module exposes the key schedule pieces that differ from TLS record
//! protection:
//! - QUIC v1 Initial key derivation from the destination connection ID
//! - Packet protection key/IV/header-protection key derivation from a traffic
//!   secret

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hkdf::{hkdf_expand_label, hkdf_extract, HkdfAlgorithm};
use crate::error::Result;

/// QUIC v1 Initial salt (RFC 9001 Section 5.2).
pub const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Which endpoint perspective should be treated as "local" in [`QuicKeys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// QUIC packet protection material derived from a traffic secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub hp_key: Vec<u8>,
}

/// Local/peer packet protection material for a QUIC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicKeys {
    pub local_secret: Vec<u8>,
    pub remote_secret: Vec<u8>,
    pub local: PacketKeys,
    pub remote: PacketKeys,
    pub hkdf_algorithm: HkdfAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
}

/// Derive QUIC v1 Initial packet protection keys from the destination CID.
pub fn derive_initial_keys(dst_cid: &[u8], side: Side) -> Result<QuicKeys> {
    let hkdf_algorithm = HkdfAlgorithm::Sha256;
    let aead_algorithm = AeadAlgorithm::Aes128Gcm;
    let initial_secret = hkdf_extract(hkdf_algorithm, &QUIC_V1_INITIAL_SALT, dst_cid)?;

    let client_secret = initial_secret.expand_label("client in", &[], hkdf_algorithm.hash_len())?;
    let server_secret = initial_secret.expand_label("server in", &[], hkdf_algorithm.hash_len())?;

    let client = derive_packet_keys(&client_secret, hkdf_algorithm, aead_algorithm)?;
    let server = derive_packet_keys(&server_secret, hkdf_algorithm, aead_algorithm)?;

    let (local_secret, remote_secret, local, remote) = match side {
        Side::Client => (client_secret, server_secret, client, server),
        Side::Server => (server_secret, client_secret, server, client),
    };

    Ok(QuicKeys {
        local_secret,
        remote_secret,
        local,
        remote,
        hkdf_algorithm,
        aead_algorithm,
    })
}

/// Derive QUIC packet protection keys from a traffic secret.
pub fn derive_packet_keys(
    secret: &[u8],
    hkdf_algorithm: HkdfAlgorithm,
    aead_algorithm: AeadAlgorithm,
) -> Result<PacketKeys> {
    Ok(PacketKeys {
        key: hkdf_expand_label(
            hkdf_algorithm,
            secret,
            "quic key",
            &[],
            aead_algorithm.key_len(),
        )?,
        iv: hkdf_expand_label(
            hkdf_algorithm,
            secret,
            "quic iv",
            &[],
            aead_algorithm.nonce_len(),
        )?,
        hp_key: hkdf_expand_label(
            hkdf_algorithm,
            secret,
            "quic hp",
            &[],
            aead_algorithm.key_len(),
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::to_hex;

    const RFC9001_SAMPLE_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have even length");
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
        }
        out
    }

    #[test]
    fn derive_packet_keys_matches_rfc9001_appendix_a_client_vector() {
        let secret = decode_hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        let keys =
            derive_packet_keys(&secret, HkdfAlgorithm::Sha256, AeadAlgorithm::Aes128Gcm).unwrap();

        assert_eq!(to_hex(&keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(to_hex(&keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(to_hex(&keys.hp_key), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn derive_initial_keys_matches_rfc9001_appendix_a_vectors() {
        let client = derive_initial_keys(&RFC9001_SAMPLE_DCID, Side::Client).unwrap();

        assert_eq!(
            to_hex(&client.local_secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        assert_eq!(
            to_hex(&client.remote_secret),
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
        );
        assert_eq!(
            to_hex(&client.local.key),
            "1f369613dd76d5467730efcbe3b1a22d"
        );
        assert_eq!(to_hex(&client.local.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(
            to_hex(&client.local.hp_key),
            "9f50449e04a0e810283a1e9933adedd2"
        );
        assert_eq!(
            to_hex(&client.remote.key),
            "cf3a5331653c364c88f0f379b6067e37"
        );
        assert_eq!(to_hex(&client.remote.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(
            to_hex(&client.remote.hp_key),
            "c206b8d9b9f0f37644430b490eeaa314"
        );
    }

    #[test]
    fn derive_initial_keys_swaps_local_and_remote_by_side() {
        let client = derive_initial_keys(&RFC9001_SAMPLE_DCID, Side::Client).unwrap();
        let server = derive_initial_keys(&RFC9001_SAMPLE_DCID, Side::Server).unwrap();

        assert_eq!(client.local_secret, server.remote_secret);
        assert_eq!(client.remote_secret, server.local_secret);
        assert_eq!(client.local, server.remote);
        assert_eq!(client.remote, server.local);
    }
}
