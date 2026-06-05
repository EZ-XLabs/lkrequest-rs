use std::ffi::{c_char, CStr};

use crate::panic::catch_value;

pub const LKREQUEST_FFI_ABI_VERSION: u32 = 1;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_status_t {
    LK_OK = 0,
    LK_ERR = -1,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_error_code_t {
    LK_ERR_UNKNOWN = 1,
    LK_ERR_INVALID_ARGUMENT = 2,
    LK_ERR_INTERNAL_PANIC = 3,
    LK_ERR_STREAM_CLOSED = 4,
    LK_ERR_INVALID_HANDLE = 5,
    LK_ERR_BUSY = 6,
    LK_ERR_RESOURCE_LIMIT_EXCEEDED = 7,
    LK_ERR_INVALID_CONFIG = 8,
    LK_ERR_NOT_FOUND = 9,
    LK_ERR_DECOMPRESSION_FAILED = 10,
    LK_ERR_TLS = 11,
    LK_ERR_HTTP = 12,
    LK_ERR_H2 = 13,
    LK_ERR_IO = 14,
    LK_ERR_PROXY = 15,
    LK_ERR_CONNECTION = 16,
    LK_ERR_TIMEOUT = 17,
    LK_ERR_TOO_MANY_REDIRECTS = 18,
    LK_ERR_POOL = 19,
    LK_ERR_URL_PARSE = 20,
    LK_ERR_STATUS = 21,
    LK_ERR_QUIC = 22,
    LK_ERR_H3 = 23,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_phase_t {
    LK_PHASE_NONE = 0,
    LK_PHASE_DNS_RESOLUTION = 1,
    LK_PHASE_TCP_CONNECT = 2,
    LK_PHASE_PROXY_TUNNEL = 3,
    LK_PHASE_TLS_HANDSHAKE = 4,
    LK_PHASE_H2_NEGOTIATION = 5,
    LK_PHASE_H2C_UPGRADE = 6,
    LK_PHASE_HTTP_REQUEST = 7,
    LK_PHASE_QUIC_HANDSHAKE = 8,
    LK_PHASE_H3_NEGOTIATION = 9,
    LK_PHASE_QUIC_FALLBACK = 10,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_http_version_t {
    LK_HTTP_VERSION_UNKNOWN = 0,
    LK_HTTP_VERSION_10 = 10,
    LK_HTTP_VERSION_11 = 11,
    LK_HTTP_VERSION_2 = 20,
    LK_HTTP_VERSION_3 = 30,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_negotiated_http_version_t {
    LK_NEGOTIATED_HTTP_VERSION_10 = 10,
    LK_NEGOTIATED_HTTP_VERSION_11 = 11,
    LK_NEGOTIATED_HTTP_VERSION_2 = 20,
    LK_NEGOTIATED_HTTP_VERSION_3 = 30,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_preferred_http_version_t {
    LK_PREFERRED_HTTP_VERSION_AUTO = 0,
    LK_PREFERRED_HTTP_VERSION_HTTP1_ONLY = 10,
    LK_PREFERRED_HTTP_VERSION_HTTP2_ONLY = 20,
    LK_PREFERRED_HTTP_VERSION_HTTP3_ONLY = 30,
    LK_PREFERRED_HTTP_VERSION_HTTP3_WITH_FALLBACK = 31,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_rotation_strategy_t {
    LK_ROTATION_ROUND_ROBIN = 0,
    LK_ROTATION_RANDOM = 1,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_dns_config_t {
    LK_DNS_SYSTEM = 0,
    LK_DNS_GOOGLE = 1,
    LK_DNS_GOOGLE_HTTPS = 2,
    LK_DNS_CLOUDFLARE = 3,
    LK_DNS_CLOUDFLARE_HTTPS = 4,
    LK_DNS_QUAD9 = 5,
    LK_DNS_QUAD9_HTTPS = 6,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_op_state_t {
    LK_OP_IN_PROGRESS = 0,
    LK_OP_COMPLETED_OK = 1,
    LK_OP_COMPLETED_ERR = 2,
    LK_OP_CANCELLED = 3,
    LK_OP_CONSUMED = 4,
}

/// Fingerprint randomization tier for `lk_client_builder_set_randomize`.
///
/// `OFF` / `EXTENSION_ORDER` are always available. `RECOMBINE` / `FULL` require
/// the `synthetic-fp` feature; without it the setter returns an error.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_randomize_mode_t {
    /// Tier 0 — emit the preset's fingerprint as-is.
    LK_RANDOMIZE_OFF = 0,
    /// Tier 1 — per-connection TLS extension-order permutation (real browser).
    LK_RANDOMIZE_EXTENSION_ORDER = 1,
    /// Tier 3a — synthetic recombination of the selected layers (synthetic-fp).
    LK_RANDOMIZE_RECOMBINE = 2,
    /// Tier 3b — recombine plus out-of-corpus H2/QUIC values (synthetic-fp).
    LK_RANDOMIZE_FULL = 3,
}

/// Fingerprint-layer bits for the `layers` argument of
/// `lk_client_builder_set_randomize` (synthetic modes). OR them together; `0`
/// means "all layers" (the safe default). Ignored for off/extension_order.
pub const LK_FP_LAYER_TLS: u32 = 1;
pub const LK_FP_LAYER_H2: u32 = 2;
pub const LK_FP_LAYER_QUIC: u32 = 4;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_socks5_udp_probe_mode_t {
    LK_SOCKS5_UDP_PROBE_ASSOCIATE_ONLY = 0,
    LK_SOCKS5_UDP_PROBE_DNS_ROUND_TRIP = 1,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_socks5_udp_probe_support_t {
    LK_SOCKS5_UDP_SUPPORT_NOT_SOCKS5 = 0,
    LK_SOCKS5_UDP_SUPPORT_ASSOCIATE_OK = 1,
    LK_SOCKS5_UDP_SUPPORT_RELAY_OK = 2,
    LK_SOCKS5_UDP_SUPPORT_UNSUPPORTED = 3,
    LK_SOCKS5_UDP_SUPPORT_FAILED = 4,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_socks5_udp_probe_phase_t {
    LK_SOCKS5_UDP_PROBE_PHASE_NOT_SOCKS5 = 0,
    LK_SOCKS5_UDP_PROBE_PHASE_UDP_ASSOCIATE = 1,
    LK_SOCKS5_UDP_PROBE_PHASE_UDP_ROUND_TRIP = 2,
}

#[no_mangle]
pub extern "C" fn lk_abi_version() -> u32 {
    LKREQUEST_FFI_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn lk_library_version() -> *const c_char {
    static VERSION: &str = concat!("lkrequest-ffi/", env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn lk_feature_supported(name: *const c_char) -> bool {
    catch_value(false, || unsafe {
        if name.is_null() {
            return false;
        }

        match CStr::from_ptr(name).to_str() {
            Ok("sync") => true,
            Ok("async") => true,
            Ok("streaming") => true,
            Ok("preset-discovery") => true,
            Ok("diagnostics") => true,
            Ok("logging") => true,
            Ok("logging-callback") => true,
            Ok("multipart") => true,
            Ok("proxy-pool") => true,
            Ok("session-pool") => true,
            Ok("dns") => true,
            Ok("dns-custom-resolver") => true,
            Ok("socks5-udp-probe") => true,
            Ok("session-resumption") => true,
            Ok("quic-connect-timeout") => true,
            Ok("quic-profile-json") => cfg!(feature = "quic-h3"),
            Ok("http3") | Ok("quic-h3") | Ok("http3-with-fallback") => {
                cfg!(feature = "quic-h3")
            }
            Ok("debug-registry") => cfg!(feature = "debug-registry"),
            Ok(_) | Err(_) => false,
        }
    })
}
