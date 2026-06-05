use crate::error::FfiError;

#[cfg(feature = "debug-registry")]
use std::collections::HashMap;
#[cfg(feature = "debug-registry")]
use std::sync::OnceLock;

pub use crate::handles_opaque::*;
pub use crate::handles_state::*;

#[cfg(feature = "debug-registry")]
const HANDLE_MAGIC: u32 = 0x4C4B465F;

#[cfg(feature = "debug-registry")]
static NEXT_HANDLE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(feature = "debug-registry")]
#[repr(C)]
struct DebugHandle<T> {
    magic: u32,
    type_tag: u32,
    gen_id: u64,
    value: T,
}

#[cfg(feature = "debug-registry")]
pub(crate) trait HandleMeta {
    const TYPE_TAG: u32;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for ClientHandle {
    const TYPE_TAG: u32 = 1;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for ClientBuilderHandle {
    const TYPE_TAG: u32 = 2;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::session::SessionBuilderHandle {
    const TYPE_TAG: u32 = 3;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for SessionHandle {
    const TYPE_TAG: u32 = 4;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for RequestHandle {
    const TYPE_TAG: u32 = 5;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for ResponseHandle {
    const TYPE_TAG: u32 = 6;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for StreamingResponseHandle {
    const TYPE_TAG: u32 = 7;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for ErrorHandle {
    const TYPE_TAG: u32 = 8;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for OpHandle {
    const TYPE_TAG: u32 = 9;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::ProxyPoolHandle {
    const TYPE_TAG: u32 = 10;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::ProxyPoolBuilderHandle {
    const TYPE_TAG: u32 = 11;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::ProxyGuardHandle {
    const TYPE_TAG: u32 = 12;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::SessionPoolHandle {
    const TYPE_TAG: u32 = 13;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::SessionPoolBuilderHandle {
    const TYPE_TAG: u32 = 14;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::SessionPoolGuardHandle {
    const TYPE_TAG: u32 = 15;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::MultipartHandle {
    const TYPE_TAG: u32 = 16;
}

#[cfg(feature = "debug-registry")]
impl HandleMeta for crate::Socks5UdpProbeReportHandle {
    const TYPE_TAG: u32 = 17;
}

#[cfg(feature = "debug-registry")]
pub(crate) fn box_into_handle<T: HandleMeta, O>(value: T) -> *mut O {
    let gen_id = NEXT_HANDLE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ptr = Box::into_raw(Box::new(DebugHandle {
        magic: HANDLE_MAGIC,
        type_tag: T::TYPE_TAG,
        gen_id,
        value,
    }))
    .cast::<O>();
    register_handle::<T, O>(ptr, gen_id);
    ptr
}

#[cfg(not(feature = "debug-registry"))]
pub(crate) fn box_into_handle<T, O>(value: T) -> *mut O {
    Box::into_raw(Box::new(value)).cast::<O>()
}

#[cfg(feature = "debug-registry")]
pub(crate) unsafe fn require_handle<'a, T: HandleMeta, O>(ptr: *mut O) -> Result<&'a T, FfiError> {
    if ptr.is_null() {
        Err(FfiError::invalid_argument("handle is null"))
    } else {
        validate_handle::<T, O>(ptr)?;
        Ok(&(*ptr.cast::<DebugHandle<T>>()).value)
    }
}

#[cfg(not(feature = "debug-registry"))]
pub(crate) unsafe fn require_handle<'a, T, O>(ptr: *mut O) -> Result<&'a T, FfiError> {
    if ptr.is_null() {
        Err(FfiError::invalid_argument("handle is null"))
    } else {
        Ok(&*ptr.cast::<T>())
    }
}

#[cfg(feature = "debug-registry")]
pub(crate) unsafe fn require_handle_mut<'a, T: HandleMeta, O>(
    ptr: *mut O,
) -> Result<&'a mut T, FfiError> {
    if ptr.is_null() {
        Err(FfiError::invalid_argument("handle is null"))
    } else {
        validate_handle::<T, O>(ptr)?;
        Ok(&mut (*ptr.cast::<DebugHandle<T>>()).value)
    }
}

#[cfg(not(feature = "debug-registry"))]
pub(crate) unsafe fn require_handle_mut<'a, T, O>(ptr: *mut O) -> Result<&'a mut T, FfiError> {
    if ptr.is_null() {
        Err(FfiError::invalid_argument("handle is null"))
    } else {
        Ok(&mut *ptr.cast::<T>())
    }
}

#[cfg(feature = "debug-registry")]
pub(crate) unsafe fn handle_drop<T: HandleMeta, O>(ptr: *mut O) {
    if !ptr.is_null() {
        if !unregister_handle::<T, O>(ptr) {
            return;
        }
        drop(Box::from_raw(ptr.cast::<DebugHandle<T>>()));
    }
}

#[cfg(not(feature = "debug-registry"))]
pub(crate) unsafe fn handle_drop<T, O>(ptr: *mut O) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr.cast::<T>()));
    }
}

#[cfg(feature = "debug-registry")]
fn registry() -> &'static parking_lot::Mutex<HashMap<u64, (usize, u32)>> {
    static REGISTRY: OnceLock<parking_lot::Mutex<HashMap<u64, (usize, u32)>>> = OnceLock::new();
    REGISTRY.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

#[cfg(feature = "debug-registry")]
fn register_handle<T: HandleMeta, O>(ptr: *mut O, gen_id: u64) {
    registry()
        .lock()
        .insert(gen_id, (ptr as usize, T::TYPE_TAG));
}

#[cfg(feature = "debug-registry")]
fn validate_handle<T: HandleMeta, O>(ptr: *mut O) -> Result<(), FfiError> {
    unsafe {
        let header = &*ptr.cast::<DebugHandle<T>>();
        if header.magic != HANDLE_MAGIC {
            return Err(FfiError::new(
                crate::abi::lk_error_code_t::LK_ERR_INVALID_HANDLE,
                "invalid handle magic",
            ));
        }
        if header.type_tag != T::TYPE_TAG {
            return Err(FfiError::new(
                crate::abi::lk_error_code_t::LK_ERR_INVALID_HANDLE,
                "handle type mismatch",
            ));
        }
        match registry().lock().get(&header.gen_id) {
            Some((addr, type_tag)) if *addr == ptr as usize && *type_tag == header.type_tag => {
                Ok(())
            }
            _ => Err(FfiError::new(
                crate::abi::lk_error_code_t::LK_ERR_INVALID_HANDLE,
                "invalid or stale handle",
            )),
        }
    }
}

#[cfg(feature = "debug-registry")]
fn unregister_handle<T: HandleMeta, O>(ptr: *mut O) -> bool {
    unsafe {
        let header = &*ptr.cast::<DebugHandle<T>>();
        if header.magic != HANDLE_MAGIC {
            return false;
        }
        matches!(
            registry().lock().remove(&header.gen_id),
            Some((addr, _)) if addr == ptr as usize
        )
    }
}
