//! Per-profile fingerprint **shape**: which dimensions are order-sensitive vs
//! shuffled, and which extensions are anchored. See design doc §4.5 / §4.6.
//!
//! This is plain data. The values are supplied by the caller (e.g. derived from
//! a preset's randomization config on the `lkrequest` side) — the client-agnostic
//! core never reads client-specific config itself.

/// Shape of a TLS ClientHello fingerprint for a given profile/mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsShapeSpec {
    /// Whether the client shuffles extension order per connection (Chrome 108+,
    /// BoringSSL `permute_extensions`). When `true`, extension order is compared
    /// as an unordered multiset; when `false`, exact order is required.
    pub extensions_shuffled: bool,
    /// Extension types pinned to the end (e.g. `pre_shared_key` = `0x0029`),
    /// excluded from the shuffle.
    pub pinned_last: Vec<u16>,
}

impl TlsShapeSpec {
    /// A profile that does not shuffle extensions (exact order is gated).
    pub fn fixed_order() -> Self {
        Self {
            extensions_shuffled: false,
            pinned_last: Vec::new(),
        }
    }

    /// A profile that shuffles all extensions except `pinned_last`.
    pub fn shuffled(pinned_last: Vec<u16>) -> Self {
        Self {
            extensions_shuffled: true,
            pinned_last,
        }
    }
}
