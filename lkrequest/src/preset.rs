use http::header::HeaderName;
use lktls::profile::types::TlsProfile;

use crate::client::ClientBuilder;
use crate::h2::H2Profile;
use crate::protocol::ProtocolPolicy;
use crate::QuicProfile;

/// High-level browser/client preset bundle for [`ClientBuilder`].
///
/// Unlike the lower-level TLS/H2/H3 preset functions in `lktls`, `lkh2`, and
/// `lkh3`, this type bundles the pieces that `lkrequest` needs to build a full
/// browser-like client template:
///
/// - TLS fingerprint profile
/// - H2 fingerprint profile
/// - Optional QUIC / H3 fingerprint profile
/// - Header order template
/// - Optional cookie order template
#[derive(Debug, Clone)]
pub struct ClientPreset {
    /// TLS ClientHello fingerprint profile.
    pub tls_profile: TlsProfile,
    /// Optional separate TLS profile for QUIC (TLS 1.3 over QUIC). Falls back to
    /// `tls_profile` when `None`.
    pub quic_tls_profile: Option<TlsProfile>,
    /// HTTP/2 fingerprint profile (SETTINGS, window, header/priority behaviour).
    pub h2_profile: H2Profile,
    /// Optional QUIC/H3 transport fingerprint profile. `None` disables HTTP/3 for
    /// this preset.
    pub quic_profile: Option<QuicProfile>,
    /// Default protocol-selection policy (H1/H2/H3 negotiation and fallback).
    pub default_protocol_policy: Option<ProtocolPolicy>,
    /// Request header order template applied over HTTP/1.1 and HTTP/2.
    pub header_order: Vec<HeaderName>,
    /// Optional H3-specific header order. Falls back to `header_order` when `None`.
    pub h3_header_order: Option<Vec<HeaderName>>,
    /// Optional ordering template for cookies serialized into the `cookie` header.
    pub cookie_order: Option<Vec<String>>,
}

impl ClientPreset {
    /// Apply this preset to a [`ClientBuilder`].
    ///
    /// Later builder calls can still override individual dimensions.
    pub fn apply(self, builder: ClientBuilder) -> ClientBuilder {
        let ClientPreset {
            tls_profile,
            quic_tls_profile,
            h2_profile,
            quic_profile,
            default_protocol_policy,
            header_order,
            h3_header_order,
            cookie_order,
        } = self;

        let mut builder = builder.fingerprint(tls_profile).h2_profile(h2_profile);
        if let Some(quic_tls_profile) = quic_tls_profile {
            builder = builder.quic_fingerprint(quic_tls_profile);
        }

        if let Some(quic_profile) = quic_profile {
            builder = builder.quic_profile(quic_profile);
        } else {
            builder = builder.disable_http3();
        }
        if let Some(default_protocol_policy) = default_protocol_policy {
            builder = builder.protocol_policy(default_protocol_policy);
        }
        if !header_order.is_empty() {
            builder = builder.header_order_from_names(header_order);
        }
        if let Some(h3_header_order) = h3_header_order {
            builder = builder.h3_header_order_from_names(h3_header_order);
        }
        if let Some(cookie_order) = cookie_order {
            builder = builder.cookie_order_from_strings(cookie_order);
        }

        builder
    }

    /// Return the header-order template as owned strings.
    pub fn header_order_strings(&self) -> Vec<String> {
        self.header_order
            .iter()
            .map(|header| header.as_str().to_string())
            .collect()
    }
}

fn header_names(order: Vec<String>) -> Vec<HeaderName> {
    order
        .into_iter()
        .map(|name| HeaderName::from_bytes(name.as_bytes()).expect("valid built-in header name"))
        .collect()
}

fn chrome_146_h3_header_order() -> Vec<HeaderName> {
    header_names(vec![
        "content-length".into(),
        "sec-ch-ua-platform".into(),
        "accept-language".into(),
        "accept".into(),
        "sec-ch-ua".into(),
        "content-type".into(),
        "sec-ch-ua-mobile".into(),
        "user-agent".into(),
        "origin".into(),
        "sec-fetch-site".into(),
        "sec-fetch-mode".into(),
        "sec-fetch-dest".into(),
        "sec-fetch-storage-access".into(),
        "referer".into(),
        "accept-encoding".into(),
        "cookie".into(),
        "priority".into(),
    ])
}

#[cfg(feature = "quic-h3")]
fn default_chrome_quic_profile() -> Option<QuicProfile> {
    Some(lkh3::chrome_quic())
}

#[cfg(not(feature = "quic-h3"))]
fn default_chrome_quic_profile() -> Option<QuicProfile> {
    None
}

#[cfg(feature = "quic-h3")]
fn chrome_146_quic_profile() -> Option<QuicProfile> {
    Some(lkh3::chrome_146_quic())
}

#[cfg(not(feature = "quic-h3"))]
fn chrome_146_quic_profile() -> Option<QuicProfile> {
    None
}

#[cfg(feature = "quic-h3")]
fn chrome_150_quic_profile() -> Option<QuicProfile> {
    Some(lkh3::chrome_150_quic())
}

#[cfg(not(feature = "quic-h3"))]
fn chrome_150_quic_profile() -> Option<QuicProfile> {
    None
}

/// Chrome 131 client preset.
///
/// QUIC/H3 currently uses the shared generic Chromium profile.
pub fn chrome_131() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_131(),
        quic_tls_profile: None,
        h2_profile: crate::h2::profile::chrome_131_h2(),
        quic_profile: default_chrome_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Chrome 144 client preset.
///
/// QUIC/H3 shares the captured Chrome 146 transport profile (same Chromium
/// family — identical control-stream frames incl. the default PRIORITY_UPDATE).
pub fn chrome_144() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_144(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_146_quic()),
        h2_profile: crate::h2::profile::chrome_144_h2(),
        quic_profile: chrome_146_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Chrome 145 client preset.
///
/// QUIC/H3 shares the captured Chrome 146 transport profile (same Chromium
/// family — identical control-stream frames incl. the default PRIORITY_UPDATE).
pub fn chrome_145() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_145(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_146_quic()),
        h2_profile: crate::h2::profile::chrome_145_h2(),
        quic_profile: chrome_146_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Chrome 146 client preset.
///
/// Uses the captured Chrome 146 QUIC/H3 transport profile from
/// `lkh3::chrome_146_quic()`.
pub fn chrome_146() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_146(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_146_quic()),
        h2_profile: crate::h2::profile::chrome_146_h2(),
        quic_profile: chrome_146_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: Some(chrome_146_h3_header_order()),
        cookie_order: None,
    }
}

/// Chrome 147 client preset.
///
/// QUIC/H3 shares the captured Chrome 146 transport profile (same Chromium
/// family — identical control-stream frames incl. the default PRIORITY_UPDATE).
pub fn chrome_147() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_147(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_146_quic()),
        h2_profile: crate::h2::profile::chrome_147_h2(),
        quic_profile: chrome_146_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Chrome 148 client preset.
///
/// QUIC/H3 shares the captured Chrome 146 transport profile (same Chromium
/// family — identical control-stream frames incl. the default PRIORITY_UPDATE).
pub fn chrome_148() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_148(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_146_quic()),
        h2_profile: crate::h2::profile::chrome_148_h2(),
        quic_profile: chrome_146_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Chrome 149 client preset.
///
/// Verified byte-identical to Chrome 148 on the wire (captured real Chrome
/// 149.0.7827.54). QUIC/H3 shares the captured Chrome 146 transport profile
/// (same Chromium family).
pub fn chrome_149() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_149(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_146_quic()),
        h2_profile: crate::h2::profile::chrome_149_h2(),
        quic_profile: chrome_146_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Chrome 150 client preset.
///
/// Captured from real Chrome 150.0.7871.47. The TCP and QUIC ClientHello use
/// Chrome 150's ML-DSA signature algorithms. H2 is unchanged. QUIC/H3 uses the
/// dedicated Chrome 150 transport profile captured from the Outlook flow.
pub fn chrome_150() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::chrome_150(),
        quic_tls_profile: Some(lktls::profile::presets::chrome_150_quic()),
        h2_profile: crate::h2::profile::chrome_150_h2(),
        quic_profile: chrome_150_quic_profile(),
        default_protocol_policy: Some(ProtocolPolicy::chrome_standard()),
        header_order: header_names(crate::h2::profile::chrome_full_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Firefox 133 client preset.
///
/// A dedicated QUIC transport capture is not modelled yet, so this preset does
/// not override `ClientBuilder`'s QUIC profile.
pub fn firefox_133() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::firefox_133(),
        quic_tls_profile: None,
        h2_profile: crate::h2::profile::firefox_133_h2(),
        quic_profile: None,
        default_protocol_policy: Some(ProtocolPolicy::crawler_throughput()),
        header_order: header_names(crate::h2::profile::firefox_133_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Firefox 147 client preset.
///
/// A dedicated QUIC transport capture is not modelled yet, so this preset does
/// not override `ClientBuilder`'s QUIC profile.
pub fn firefox_147() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::firefox_147(),
        quic_tls_profile: None,
        h2_profile: crate::h2::profile::firefox_147_h2(),
        quic_profile: None,
        default_protocol_policy: Some(ProtocolPolicy::crawler_throughput()),
        header_order: header_names(crate::h2::profile::firefox_147_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Safari 18 client preset.
///
/// A dedicated QUIC transport capture is not modelled yet, so this preset does
/// not override `ClientBuilder`'s QUIC profile.
pub fn safari_18() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::safari_18(),
        quic_tls_profile: None,
        h2_profile: crate::h2::profile::safari_18_h2(),
        quic_profile: None,
        default_protocol_policy: Some(ProtocolPolicy::crawler_throughput()),
        header_order: header_names(crate::h2::profile::safari_18_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

/// Safari 26.2 client preset.
///
/// A dedicated QUIC transport capture is not modelled yet, so this preset does
/// not override `ClientBuilder`'s QUIC profile.
pub fn safari_26() -> ClientPreset {
    ClientPreset {
        tls_profile: lktls::profile::presets::safari_26(),
        quic_tls_profile: None,
        h2_profile: crate::h2::profile::safari_26_h2(),
        quic_profile: None,
        default_protocol_policy: Some(ProtocolPolicy::crawler_throughput()),
        header_order: header_names(crate::h2::profile::safari_26_header_order()),
        h3_header_order: None,
        cookie_order: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "quic-h3")]
    #[test]
    fn chrome_146_preset_uses_captured_quic_profile() {
        let preset = chrome_146();
        assert_eq!(preset.tls_profile.name, "Chrome 146");
        assert_eq!(
            preset
                .quic_tls_profile
                .as_ref()
                .expect("chrome_146 preset should set QUIC TLS profile")
                .name,
            "Chrome 146 QUIC"
        );
        assert_eq!(
            preset
                .quic_profile
                .as_ref()
                .expect("chrome_146 preset should set QUIC profile"),
            &lkh3::chrome_146_quic()
        );
        assert_eq!(preset.header_order_strings()[0], "content-length");
        assert_eq!(
            preset
                .h3_header_order
                .as_ref()
                .expect("chrome_146 preset should set H3 header order")[0]
                .as_str(),
            "content-length"
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn chrome_150_preset_uses_dedicated_quic_profiles() {
        let preset = chrome_150();
        assert_eq!(preset.tls_profile.name, "Chrome 150");
        assert_eq!(
            preset
                .quic_tls_profile
                .as_ref()
                .expect("chrome_150 preset should set QUIC TLS profile")
                .name,
            "Chrome 150 QUIC"
        );
        assert_eq!(
            preset
                .quic_profile
                .as_ref()
                .expect("chrome_150 preset should set QUIC profile"),
            &lkh3::chrome_150_quic()
        );
        assert_ne!(preset.quic_profile, chrome_146().quic_profile);
    }

    #[test]
    fn firefox_147_preset_leaves_quic_profile_unspecified() {
        let preset = firefox_147();
        assert!(preset.quic_profile.is_none());
        assert_eq!(preset.tls_profile.name, "Firefox 147");
    }

    #[test]
    fn chrome_148_preset_uses_captured_tls_and_h2_profiles() {
        let preset = chrome_148();
        assert_eq!(preset.tls_profile.name, "Chrome 148");
        assert_eq!(preset.h2_profile.window_update, 15_663_105);
        assert_eq!(preset.h2_profile.settings.len(), 4);
        assert_eq!(
            preset
                .h2_profile
                .settings
                .iter()
                .map(|setting| (setting.id.as_u16(), setting.value))
                .collect::<Vec<_>>(),
            vec![(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)]
        );
        assert_eq!(preset.header_order_strings()[0], "content-length");
        assert_eq!(
            preset.default_protocol_policy,
            Some(ProtocolPolicy::chrome_standard())
        );
        assert!(preset.h3_header_order.is_none());
    }

    #[test]
    fn builder_preset_applies_all_supported_layers() {
        let client = crate::Client::builder().preset(chrome_146()).build();
        let header_order: Vec<&str> = client
            .header_order()
            .expect("preset should set header_order")
            .iter()
            .map(|header| header.as_str())
            .collect();
        let h3_header_order: Vec<&str> = client
            .h3_header_order()
            .expect("preset should set h3_header_order")
            .iter()
            .map(|header| header.as_str())
            .collect();

        assert_eq!(client.tls_profile().name, "Chrome 146");
        assert_eq!(
            client
                .quic_tls_profile()
                .expect("chrome_146 preset should set QUIC TLS profile")
                .name,
            "Chrome 146 QUIC"
        );
        assert_eq!(client.h2_profile().window_update, 15_663_105);
        assert_eq!(client.protocol_policy(), &ProtocolPolicy::chrome_standard());
        #[cfg(feature = "quic-h3")]
        assert_eq!(client.quic_profile(), Some(&lkh3::chrome_146_quic()));
        #[cfg(not(feature = "quic-h3"))]
        assert!(client.quic_profile().is_none());
        assert_eq!(header_order[0], "content-length");
        assert_eq!(*header_order.last().expect("header order"), "cookie");
        assert_eq!(h3_header_order[0], "content-length");
        assert_eq!(
            *h3_header_order.last().expect("h3 header order"),
            "priority"
        );
    }

    #[test]
    fn every_browser_preset_constructs_with_a_header_order() {
        for preset in [
            chrome_131(),
            chrome_144(),
            chrome_145(),
            chrome_146(),
            chrome_147(),
            chrome_148(),
            chrome_149(),
            chrome_150(),
            firefox_133(),
            firefox_147(),
            safari_18(),
            safari_26(),
        ] {
            assert!(
                !preset.tls_profile.name.is_empty(),
                "preset must name its TLS profile"
            );
            assert!(
                !preset.header_order.is_empty(),
                "preset must define a header order"
            );
            assert_eq!(
                preset.header_order_strings().len(),
                preset.header_order.len(),
                "header_order_strings must mirror header_order"
            );
        }
    }

    #[test]
    fn apply_threads_optional_dimensions_and_disables_h3_without_a_quic_profile() {
        // A hand-built preset that takes every "optional" branch of `apply`:
        // no QUIC profile (→ disable_http3), no protocol policy, an empty header
        // order (→ skipped), and an explicit cookie order.
        let base = chrome_131();
        let custom = ClientPreset {
            tls_profile: base.tls_profile,
            quic_tls_profile: None,
            h2_profile: base.h2_profile,
            quic_profile: None,
            default_protocol_policy: None,
            header_order: Vec::new(),
            h3_header_order: None,
            cookie_order: Some(vec!["sid".to_string(), "uid".to_string()]),
        };

        let client = custom.apply(crate::Client::builder()).build();
        // No QUIC profile → `apply` took the `disable_http3()` arm.
        assert!(client.quic_profile().is_none());
        // The empty header order was skipped, so none was installed.
        assert!(client.header_order().is_none());
        // The explicit cookie order was threaded through.
        assert_eq!(client.cookie_order().map(<[_]>::len), Some(2));
    }
}
