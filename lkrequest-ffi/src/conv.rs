use std::ffi::{c_char, CStr};
use std::ptr;
use std::slice;

use crate::error::FfiError;
use crate::types::lk_form_pair_t;

pub unsafe fn read_c_string(ptr: *const c_char, name: &str) -> Result<String, FfiError> {
    if ptr.is_null() {
        return Err(FfiError::invalid_argument(format!("{name} is null")));
    }

    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| FfiError::invalid_argument(format!("{name} is not valid UTF-8")))
}

pub unsafe fn read_string_parts(
    ptr: *const c_char,
    len: usize,
    name: &str,
) -> Result<String, FfiError> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(String::new());
        }
        return Err(FfiError::invalid_argument(format!(
            "{name} is null while len > 0"
        )));
    }

    let bytes = slice::from_raw_parts(ptr.cast::<u8>(), len);
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| FfiError::invalid_argument(format!("{name} is not valid UTF-8")))
}

pub unsafe fn read_bytes(ptr: *const u8, len: usize, name: &str) -> Result<Vec<u8>, FfiError> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(Vec::new());
        }
        return Err(FfiError::invalid_argument(format!(
            "{name} is null while len > 0"
        )));
    }

    Ok(slice::from_raw_parts(ptr, len).to_vec())
}

pub unsafe fn read_form_pairs(
    pairs_ptr: *const lk_form_pair_t,
    pairs_count: usize,
) -> Result<Vec<(String, String)>, FfiError> {
    if pairs_ptr.is_null() {
        if pairs_count == 0 {
            return Ok(Vec::new());
        }
        return Err(FfiError::invalid_argument(
            "pairs_ptr is null while pairs_count > 0",
        ));
    }

    let pairs = slice::from_raw_parts(pairs_ptr, pairs_count);
    let mut out = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let name = read_string_parts(pair.name.ptr, pair.name.len, "form pair name")?;
        let value = read_string_parts(pair.value.ptr, pair.value.len, "form pair value")?;
        out.push((name, value));
    }
    Ok(out)
}

pub unsafe fn require_out_ptr<T>(out: *mut *const T, name: &str) -> Result<(), FfiError> {
    if out.is_null() {
        Err(FfiError::invalid_argument(format!("{name} is null")))
    } else {
        Ok(())
    }
}

pub unsafe fn require_out_len(out: *mut usize, name: &str) -> Result<(), FfiError> {
    if out.is_null() {
        Err(FfiError::invalid_argument(format!("{name} is null")))
    } else {
        Ok(())
    }
}

pub unsafe fn clear_out_ptr<T>(out: *mut *const T) {
    if !out.is_null() {
        *out = ptr::null();
    }
}

pub unsafe fn clear_out_len(out: *mut usize) {
    if !out.is_null() {
        *out = 0;
    }
}

pub unsafe fn set_bytes_out(
    data: &[u8],
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> Result<(), FfiError> {
    require_out_ptr(out_ptr, "out_ptr")?;
    require_out_len(out_len, "out_len")?;

    if data.is_empty() {
        *out_ptr = ptr::null();
        *out_len = 0;
    } else {
        *out_ptr = data.as_ptr();
        *out_len = data.len();
    }
    Ok(())
}

pub unsafe fn set_string_out(
    data: &[u8],
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> Result<(), FfiError> {
    require_out_ptr(out_ptr, "out_ptr")?;
    require_out_len(out_len, "out_len")?;

    if data.is_empty() {
        *out_ptr = ptr::null();
        *out_len = 0;
    } else {
        *out_ptr = data.as_ptr().cast::<c_char>();
        *out_len = data.len();
    }
    Ok(())
}

pub unsafe fn copy_bytes_to_buffer(
    data: &[u8],
    buf: *mut u8,
    buf_len: usize,
    out_read_len: *mut usize,
) -> Result<(), FfiError> {
    require_out_len(out_read_len, "out_read_len")?;
    if buf.is_null() && buf_len > 0 {
        return Err(FfiError::invalid_argument("buf is null while buf_len > 0"));
    }

    let to_copy = data.len().min(buf_len);
    if to_copy > 0 {
        ptr::copy_nonoverlapping(data.as_ptr(), buf, to_copy);
    }
    *out_read_len = to_copy;
    Ok(())
}
