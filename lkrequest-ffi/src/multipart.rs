use std::ffi::c_char;
use std::ptr;

use crate::abi::lk_status_t;
use crate::conv::{read_bytes, read_string_parts};
use crate::handles::{
    box_into_handle, handle_drop, lk_multipart_t, require_handle_mut, MultipartHandle,
};
use crate::panic::{catch_status, catch_value, null_error_out};

#[no_mangle]
pub extern "C" fn lk_multipart_new() -> *mut lk_multipart_t {
    catch_value(ptr::null_mut(), || {
        box_into_handle::<MultipartHandle, lk_multipart_t>(MultipartHandle {
            multipart: lkrequest::multipart::Multipart::new(),
        })
    })
}

#[no_mangle]
pub extern "C" fn lk_multipart_add_text(
    multipart: *mut lk_multipart_t,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let multipart = require_handle_mut::<MultipartHandle, lk_multipart_t>(multipart)?;
        let name = read_string_parts(name_ptr, name_len, "multipart field name")?;
        let value = read_string_parts(value_ptr, value_len, "multipart field value")?;
        let current = std::mem::take(&mut multipart.multipart);
        multipart.multipart = current.text(&name, &value);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_multipart_add_file(
    multipart: *mut lk_multipart_t,
    name_ptr: *const c_char,
    name_len: usize,
    filename_ptr: *const c_char,
    filename_len: usize,
    content_type_ptr: *const c_char,
    content_type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let multipart = require_handle_mut::<MultipartHandle, lk_multipart_t>(multipart)?;
        let name = read_string_parts(name_ptr, name_len, "multipart file field name")?;
        let filename = read_string_parts(filename_ptr, filename_len, "multipart filename")?;
        let content_type =
            read_string_parts(content_type_ptr, content_type_len, "multipart content type")?;
        let data = read_bytes(data_ptr, data_len, "multipart file data")?;
        let part = lkrequest::multipart::Part::new(&name, data)
            .filename(&filename)
            .content_type(&content_type);
        let current = std::mem::take(&mut multipart.multipart);
        multipart.multipart = current.part(part);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_multipart_free(multipart: *mut lk_multipart_t) {
    catch_value((), || unsafe {
        handle_drop::<MultipartHandle, lk_multipart_t>(multipart);
    });
}
