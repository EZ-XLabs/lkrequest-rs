use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::abi::lk_status_t;
use crate::error::{clear_error_out, write_error_out, FfiError};
use crate::handles::lk_error_t;

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic across FFI boundary".to_string()
    }
}

pub fn catch_status<F>(out_err: *mut *mut lk_error_t, f: F) -> lk_status_t
where
    F: FnOnce() -> Result<(), FfiError>,
{
    unsafe {
        clear_error_out(out_err);
    }

    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => lk_status_t::LK_OK,
        Ok(Err(err)) => {
            unsafe {
                write_error_out(out_err, err);
            }
            lk_status_t::LK_ERR
        }
        Err(payload) => {
            unsafe {
                write_error_out(out_err, FfiError::internal_panic(panic_message(payload)));
            }
            lk_status_t::LK_ERR
        }
    }
}

pub fn catch_value<T, F>(default: T, f: F) -> T
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

pub fn null_error_out() -> *mut *mut lk_error_t {
    ptr::null_mut()
}
