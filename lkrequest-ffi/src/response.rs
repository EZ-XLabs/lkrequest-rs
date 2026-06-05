use std::ffi::c_char;
use std::ptr;

use crate::abi::{lk_http_version_t, lk_negotiated_http_version_t, lk_status_t};
use crate::conv::{
    clear_out_len, clear_out_ptr, copy_bytes_to_buffer, read_string_parts, set_bytes_out,
    set_string_out,
};
use crate::diagnostics::FfiDiagnostics;
use crate::error::FfiError;
use crate::handles::{handle_drop, lk_error_t, lk_response_t, require_handle, ResponseHandle};
use crate::panic::{catch_status, catch_value};

fn map_http_version(version: lkrequest::HttpVersion) -> lk_http_version_t {
    match version {
        lkrequest::HttpVersion::Http10 => lk_http_version_t::LK_HTTP_VERSION_10,
        lkrequest::HttpVersion::Http11 => lk_http_version_t::LK_HTTP_VERSION_11,
        lkrequest::HttpVersion::H2 => lk_http_version_t::LK_HTTP_VERSION_2,
        lkrequest::HttpVersion::H3 => lk_http_version_t::LK_HTTP_VERSION_3,
        lkrequest::HttpVersion::Unknown => lk_http_version_t::LK_HTTP_VERSION_UNKNOWN,
    }
}

fn map_negotiated_http_version(
    version: lkrequest::NegotiatedHttpVersion,
) -> lk_negotiated_http_version_t {
    match version {
        lkrequest::NegotiatedHttpVersion::Http10 => {
            lk_negotiated_http_version_t::LK_NEGOTIATED_HTTP_VERSION_10
        }
        lkrequest::NegotiatedHttpVersion::Http11 => {
            lk_negotiated_http_version_t::LK_NEGOTIATED_HTTP_VERSION_11
        }
        lkrequest::NegotiatedHttpVersion::Http2 => {
            lk_negotiated_http_version_t::LK_NEGOTIATED_HTTP_VERSION_2
        }
        lkrequest::NegotiatedHttpVersion::Http3 => {
            lk_negotiated_http_version_t::LK_NEGOTIATED_HTTP_VERSION_3
        }
    }
}

pub(crate) fn make_response_handle(
    response: lkrequest::Response,
    diagnostics: FfiDiagnostics,
) -> ResponseHandle {
    ResponseHandle {
        response,
        diagnostics,
        diagnostics_json: std::sync::OnceLock::new(),
        cookies: std::sync::OnceLock::new(),
    }
}

#[no_mangle]
pub extern "C" fn lk_response_status(response: *const lk_response_t) -> u16 {
    catch_value(0, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .map(|handle| handle.response.status().as_u16())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_version(
    response: *const lk_response_t,
    out_version: *mut lk_http_version_t,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_version.is_null() {
            return Err(FfiError::invalid_argument("out_version is null"));
        }
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        *out_version = map_http_version(response.response.version());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_response_negotiated_version(
    response: *const lk_response_t,
    out_version: *mut lk_negotiated_http_version_t,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_version.is_null() {
            return Err(FfiError::invalid_argument("out_version is null"));
        }
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        *out_version = map_negotiated_http_version(response.response.negotiated_version());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_response_url(
    response: *const lk_response_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        set_string_out(response.response.url().as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_header_count(response: *const lk_response_t) -> usize {
    catch_value(0, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .map(|handle| handle.response.headers().len())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_header_name_at(
    response: *const lk_response_t,
    index: usize,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let (name, _) = response
            .response
            .headers()
            .iter()
            .nth(index)
            .ok_or_else(|| FfiError::not_found(format!("header index {index} out of range")))?;
        set_string_out(name.as_str().as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_header_value_at(
    response: *const lk_response_t,
    index: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let (_, value) = response
            .response
            .headers()
            .iter()
            .nth(index)
            .ok_or_else(|| FfiError::not_found(format!("header index {index} out of range")))?;
        set_bytes_out(value.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_get_header_by_name(
    response: *const lk_response_t,
    name_ptr: *const c_char,
    name_len: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let name = read_string_parts(name_ptr, name_len, "header name")?;
        let value = response
            .response
            .headers()
            .get(name.as_str())
            .ok_or_else(|| FfiError::not_found(format!("header not found: {name}")))?;
        set_bytes_out(value.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_body(
    response: *const lk_response_t,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        set_bytes_out(response.response.bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_text(
    response: *const lk_response_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let text = response.response.text().map_err(FfiError::from_lkrequest)?;
        set_string_out(text.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_copy_body(
    response: *const lk_response_t,
    buf: *mut u8,
    buf_len: usize,
    out_read_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        copy_bytes_to_buffer(response.response.bytes(), buf, buf_len, out_read_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_content_length(response: *const lk_response_t) -> i64 {
    catch_value(-1, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .ok()
            .and_then(|handle| handle.response.content_length())
            .filter(|value| *value <= i64::MAX as u64)
            .map(|value| value as i64)
            .unwrap_or(-1)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_was_redirected(response: *const lk_response_t) -> bool {
    catch_value(false, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .map(|handle| handle.response.was_redirected())
            .unwrap_or(false)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_error_for_status(
    response: *const lk_response_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        response
            .response
            .error_for_status_ref()
            .map(|_| ())
            .map_err(FfiError::from_lkrequest)
    })
}

fn response_cookies(handle: &ResponseHandle) -> &[(String, String)] {
    handle.cookies.get_or_init(|| {
        handle
            .response
            .cookies()
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    })
}

#[no_mangle]
pub extern "C" fn lk_response_cookie_count(response: *const lk_response_t) -> usize {
    catch_value(0, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .map(|handle| response_cookies(handle).len())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_cookie_name_at(
    response: *const lk_response_t,
    index: usize,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let (name, _) = response_cookies(response)
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("cookie index {index} out of range")))?;
        set_string_out(name.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_cookie_value_at(
    response: *const lk_response_t,
    index: usize,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let (_, value) = response_cookies(response)
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("cookie index {index} out of range")))?;
        set_string_out(value.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_cookie_at(
    response: *const lk_response_t,
    index: usize,
    out_name_ptr: *mut *const c_char,
    out_name_len: *mut usize,
    out_value_ptr: *mut *const c_char,
    out_value_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_name_ptr);
        clear_out_len(out_name_len);
        clear_out_ptr(out_value_ptr);
        clear_out_len(out_value_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let (name, value) = response_cookies(response)
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("cookie index {index} out of range")))?;
        set_string_out(name.as_bytes(), out_name_ptr, out_name_len)?;
        set_string_out(value.as_bytes(), out_value_ptr, out_value_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_redirect_count(response: *const lk_response_t) -> usize {
    catch_value(0, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .map(|handle| handle.response.redirect_history().len())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_redirect_url_at(
    response: *const lk_response_t,
    index: usize,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let url = response
            .response
            .redirect_history()
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("redirect index {index} out of range")))?
            .url();
        set_string_out(url.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_redirect_status_at(
    response: *const lk_response_t,
    index: usize,
) -> u16 {
    catch_value(0, || unsafe {
        require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())
            .ok()
            .and_then(|handle| {
                handle
                    .response
                    .redirect_history()
                    .get(index)
                    .map(|record| record.status().as_u16())
            })
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_response_redirect_at(
    response: *const lk_response_t,
    index: usize,
    out_url_ptr: *mut *const c_char,
    out_url_len: *mut usize,
    out_status: *mut u16,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_url_ptr);
        clear_out_len(out_url_len);
        if !out_status.is_null() {
            *out_status = 0;
        }
        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let record = response
            .response
            .redirect_history()
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("redirect index {index} out of range")))?;
        set_string_out(record.url().as_bytes(), out_url_ptr, out_url_len)?;
        if !out_status.is_null() {
            *out_status = record.status().as_u16();
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_response_get_diagnostics_json(
    response: *const lk_response_t,
    out_ptr: *mut *const c_char,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_ptr is null"));
        }
        *out_ptr = ptr::null();

        let response = require_handle::<ResponseHandle, lk_response_t>(response.cast_mut())?;
        let bytes = response
            .diagnostics_json
            .get_or_init(|| response.diagnostics.to_json_bytes());
        *out_ptr = bytes.as_ptr().cast::<c_char>();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_response_free(response: *mut lk_response_t) {
    catch_value((), || unsafe {
        handle_drop::<ResponseHandle, lk_response_t>(response);
    });
}
