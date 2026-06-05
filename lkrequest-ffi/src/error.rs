use std::ffi::c_char;
use std::ptr;

use crate::abi::{lk_error_code_t, lk_phase_t, lk_status_t};
use crate::conv::{clear_out_len, clear_out_ptr, set_string_out};
use crate::diagnostics::FfiDiagnostics;
use crate::handles::{box_into_handle, handle_drop, lk_error_t, require_handle, ErrorHandle};
use crate::panic::{catch_status, catch_value};

#[derive(Clone, Debug)]
pub struct FfiError {
    pub code: lk_error_code_t,
    pub phase: lk_phase_t,
    pub message: Vec<u8>,
    pub retryable: bool,
    pub http_status: i32,
    pub diagnostics: Option<Box<FfiDiagnostics>>,
}

impl FfiError {
    pub fn new(code: lk_error_code_t, message: impl Into<String>) -> Self {
        Self {
            code,
            phase: lk_phase_t::LK_PHASE_NONE,
            message: message.into().into_bytes(),
            retryable: false,
            http_status: -1,
            diagnostics: None,
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(lk_error_code_t::LK_ERR_INVALID_ARGUMENT, message)
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(lk_error_code_t::LK_ERR_INVALID_CONFIG, message)
    }

    pub fn busy(message: impl Into<String>) -> Self {
        Self::new(lk_error_code_t::LK_ERR_BUSY, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(lk_error_code_t::LK_ERR_NOT_FOUND, message)
    }

    pub fn resource_limit_exceeded(message: impl Into<String>) -> Self {
        Self::new(lk_error_code_t::LK_ERR_RESOURCE_LIMIT_EXCEEDED, message)
    }

    pub fn internal_panic(message: impl Into<String>) -> Self {
        Self::new(lk_error_code_t::LK_ERR_INTERNAL_PANIC, message)
    }

    pub fn from_lkrequest(err: lkrequest::error::Error) -> Self {
        let retryable = err.is_retryable();
        let phase = map_phase(err.phase());
        let http_status = err.status().map_or(-1, |status| i32::from(status.as_u16()));
        let code = match &err {
            lkrequest::error::Error::Tls(_) => lk_error_code_t::LK_ERR_TLS,
            lkrequest::error::Error::Http(_) => lk_error_code_t::LK_ERR_HTTP,
            lkrequest::error::Error::Body(_) => lk_error_code_t::LK_ERR_DECOMPRESSION_FAILED,
            lkrequest::error::Error::H2(_) => lk_error_code_t::LK_ERR_H2,
            lkrequest::error::Error::ConnectionClosed { .. } => lk_error_code_t::LK_ERR_CONNECTION,
            lkrequest::error::Error::Quic(_) => lk_error_code_t::LK_ERR_QUIC,
            lkrequest::error::Error::QuicTransport(_) => lk_error_code_t::LK_ERR_QUIC,
            // Handshake-class QUIC failures share the generic QUIC error
            // code on the wire — FFI consumers that care about the
            // distinction can read the phase field (which reports
            // QuicHandshake for these).
            lkrequest::error::Error::QuicHandshake(_) => lk_error_code_t::LK_ERR_QUIC,
            lkrequest::error::Error::H3(_) => lk_error_code_t::LK_ERR_H3,
            // Per-request H3 failures reuse the generic H3 error code.
            lkrequest::error::Error::Http3Request(_) => lk_error_code_t::LK_ERR_H3,
            lkrequest::error::Error::Io(_) => lk_error_code_t::LK_ERR_IO,
            lkrequest::error::Error::Proxy(_) => lk_error_code_t::LK_ERR_PROXY,
            lkrequest::error::Error::Connection(_) => lk_error_code_t::LK_ERR_CONNECTION,
            lkrequest::error::Error::Timeout { .. } => lk_error_code_t::LK_ERR_TIMEOUT,
            lkrequest::error::Error::TooManyRedirects(_) => {
                lk_error_code_t::LK_ERR_TOO_MANY_REDIRECTS
            }
            lkrequest::error::Error::Pool(_) => lk_error_code_t::LK_ERR_POOL,
            lkrequest::error::Error::InvalidConfig(_) => lk_error_code_t::LK_ERR_INVALID_CONFIG,
            lkrequest::error::Error::UrlParse(_) => lk_error_code_t::LK_ERR_URL_PARSE,
            lkrequest::error::Error::ResourceLimitExceeded(_) => {
                lk_error_code_t::LK_ERR_RESOURCE_LIMIT_EXCEEDED
            }
            lkrequest::error::Error::Status { .. } => lk_error_code_t::LK_ERR_STATUS,
            // Error is #[non_exhaustive]; any future variant falls through
            // to the generic internal-panic bucket until the FFI layer
            // learns a specific code for it.
            _ => lk_error_code_t::LK_ERR_INTERNAL_PANIC,
        };

        Self {
            code,
            phase,
            message: err.to_string().into_bytes(),
            retryable,
            http_status,
            diagnostics: None,
        }
    }
}

pub fn map_phase(phase: Option<lkrequest::ConnectionPhase>) -> lk_phase_t {
    match phase {
        Some(lkrequest::ConnectionPhase::DnsResolution) => lk_phase_t::LK_PHASE_DNS_RESOLUTION,
        Some(lkrequest::ConnectionPhase::TcpConnect) => lk_phase_t::LK_PHASE_TCP_CONNECT,
        Some(lkrequest::ConnectionPhase::ProxyTunnel) => lk_phase_t::LK_PHASE_PROXY_TUNNEL,
        Some(lkrequest::ConnectionPhase::TlsHandshake) => lk_phase_t::LK_PHASE_TLS_HANDSHAKE,
        Some(lkrequest::ConnectionPhase::H2Negotiation) => lk_phase_t::LK_PHASE_H2_NEGOTIATION,
        Some(lkrequest::ConnectionPhase::H2cUpgrade) => lk_phase_t::LK_PHASE_H2C_UPGRADE,
        Some(lkrequest::ConnectionPhase::QuicHandshake) => lk_phase_t::LK_PHASE_QUIC_HANDSHAKE,
        Some(lkrequest::ConnectionPhase::H3Negotiation) => lk_phase_t::LK_PHASE_H3_NEGOTIATION,
        Some(lkrequest::ConnectionPhase::QuicFallback) => lk_phase_t::LK_PHASE_QUIC_FALLBACK,
        Some(lkrequest::ConnectionPhase::HttpRequest) => lk_phase_t::LK_PHASE_HTTP_REQUEST,
        None => lk_phase_t::LK_PHASE_NONE,
    }
}

pub(crate) unsafe fn clear_error_out(out_err: *mut *mut lk_error_t) {
    if !out_err.is_null() {
        *out_err = ptr::null_mut();
    }
}

pub(crate) unsafe fn write_error_out(out_err: *mut *mut lk_error_t, error: FfiError) {
    if !out_err.is_null() {
        let mut error = error;
        let diagnostics = error
            .diagnostics
            .take()
            .map(|value| *value)
            .unwrap_or_default();
        *out_err = box_into_handle::<ErrorHandle, lk_error_t>(ErrorHandle {
            error,
            diagnostics,
            diagnostics_json: std::sync::OnceLock::new(),
        });
    }
}

pub(crate) fn make_error_handle(error: FfiError, diagnostics: FfiDiagnostics) -> ErrorHandle {
    ErrorHandle {
        error,
        diagnostics,
        diagnostics_json: std::sync::OnceLock::new(),
    }
}

#[no_mangle]
pub extern "C" fn lk_error_code(err: *const lk_error_t) -> lk_error_code_t {
    catch_value(lk_error_code_t::LK_ERR_INVALID_HANDLE, || unsafe {
        require_handle::<ErrorHandle, lk_error_t>(err.cast_mut())
            .map(|handle| handle.error.code)
            .unwrap_or(lk_error_code_t::LK_ERR_INVALID_HANDLE)
    })
}

#[no_mangle]
pub extern "C" fn lk_error_phase(err: *const lk_error_t) -> lk_phase_t {
    catch_value(lk_phase_t::LK_PHASE_NONE, || unsafe {
        require_handle::<ErrorHandle, lk_error_t>(err.cast_mut())
            .map(|handle| handle.error.phase)
            .unwrap_or(lk_phase_t::LK_PHASE_NONE)
    })
}

#[no_mangle]
pub extern "C" fn lk_error_message(
    err: *const lk_error_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);

        let err = require_handle::<ErrorHandle, lk_error_t>(err.cast_mut())?;
        set_string_out(&err.error.message, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_error_is_retryable(err: *const lk_error_t) -> bool {
    catch_value(false, || unsafe {
        require_handle::<ErrorHandle, lk_error_t>(err.cast_mut())
            .map(|handle| handle.error.retryable)
            .unwrap_or(false)
    })
}

#[no_mangle]
pub extern "C" fn lk_error_http_status(err: *const lk_error_t) -> i32 {
    catch_value(-1, || unsafe {
        require_handle::<ErrorHandle, lk_error_t>(err.cast_mut())
            .map(|handle| handle.error.http_status)
            .unwrap_or(-1)
    })
}

#[no_mangle]
pub extern "C" fn lk_error_get_diagnostics_json(
    err: *const lk_error_t,
    out_ptr: *mut *const c_char,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_ptr is null"));
        }
        *out_ptr = ptr::null();

        let err = require_handle::<ErrorHandle, lk_error_t>(err.cast_mut())?;
        let bytes = err
            .diagnostics_json
            .get_or_init(|| err.diagnostics.to_json_bytes());
        *out_ptr = bytes.as_ptr().cast::<c_char>();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_error_free(err: *mut lk_error_t) {
    catch_value((), || unsafe {
        handle_drop::<ErrorHandle, lk_error_t>(err);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_quic_error_maps_to_quic_code_and_phase() {
        let err = lkrequest::error::Error::QuicTransport(Box::new(lkrequest::QuicError {
            phase: lkrequest::QuicPhase::Handshake,
            message: "connect failed".into(),
        }));
        let ffi = FfiError::from_lkrequest(err);

        assert_eq!(ffi.code, lk_error_code_t::LK_ERR_QUIC);
        assert_eq!(ffi.phase, lk_phase_t::LK_PHASE_QUIC_HANDSHAKE);
        assert!(ffi.retryable);
    }

    #[test]
    fn typed_connection_closed_maps_to_connection_code_and_http_phase() {
        let err = lkrequest::error::Error::ConnectionClosed {
            phase: lkrequest::ConnectionPhase::HttpRequest,
            kind: lkrequest::ConnectionClosedKind::Goaway,
            message: "server sent GOAWAY".into(),
        };
        let ffi = FfiError::from_lkrequest(err);

        assert_eq!(ffi.code, lk_error_code_t::LK_ERR_CONNECTION);
        assert_eq!(ffi.phase, lk_phase_t::LK_PHASE_HTTP_REQUEST);
        assert!(ffi.retryable);
    }
}
