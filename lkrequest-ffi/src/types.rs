use std::ffi::{c_char, c_void};
use std::ptr;

use crate::abi::{lk_socks5_udp_probe_mode_t, lk_status_t};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct lk_bytes_view_t {
    pub ptr: *const u8,
    pub len: usize,
}

impl Default for lk_bytes_view_t {
    fn default() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct lk_string_view_t {
    pub ptr: *const c_char,
    pub len: usize,
}

impl Default for lk_string_view_t {
    fn default() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct lk_chunk_view_t {
    pub data: *const u8,
    pub len: usize,
    pub is_final: bool,
}

impl Default for lk_chunk_view_t {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
            is_final: false,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct lk_form_pair_t {
    pub name: lk_string_view_t,
    pub value: lk_string_view_t,
}

/// SOCKS5 UDP probe configuration.
///
/// If `dns_server_host_ptr` is non-null, the probe encodes that host as the
/// SOCKS5 UDP target name (ATYP=domain). Otherwise `dns_server_addr_ptr` must
/// be a socket-address string such as `"1.1.1.1:53"`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct lk_socks5_udp_probe_config_t {
    pub mode: lk_socks5_udp_probe_mode_t,
    pub timeout_ms: u64,
    pub dns_server_addr_ptr: *const c_char,
    pub dns_server_addr_len: usize,
    pub dns_server_host_ptr: *const c_char,
    pub dns_server_host_len: usize,
    pub dns_query_ptr: *const c_char,
    pub dns_query_len: usize,
}

/// C-style callback sink for forwarding logs into the host language.
pub type lk_log_callback_t = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        level: i32,
        target: *const c_char,
        message: *const c_char,
    ),
>;

/// C-style proxy provider used by ProxyPool / SessionPool builders.
///
/// # Callback contract
///
/// All callbacks (`next_proxy`, `len`, `is_dynamic`) **must return synchronously
/// and quickly**. They are invoked on the library's internal runtime thread and
/// must not perform blocking I/O, network requests, or wait on locks held by
/// other FFI calls. Data should be pre-loaded in memory (e.g. a list of URLs
/// with an atomic index).
///
/// ## `next_proxy` — borrowed pointer semantics
///
/// The string written to `out_url_ptr` / `out_url_len` is **borrowed**: the
/// library copies the data immediately before the callback returns. The pointer
/// is invalidated the moment `next_proxy` returns; the caller (Rust side) will
/// never dereference it afterwards. This means:
///
/// - **Go (cgo):** you may point into a Go `[]byte` pinned with
///   `runtime.Pinner` (Go 1.21+); unpin after the callback returns.
/// - **Go (purego):** use a pre-allocated C buffer that you overwrite each call.
/// - **C/C++:** a stack or static buffer is fine.
/// - You do **not** need to `malloc` or transfer ownership.
///
/// ## `destroy`
///
/// Called once when the pool or builder that owns this provider is freed.
/// May be `NULL` if no cleanup is needed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct lk_proxy_provider_t {
    pub context: *mut c_void,
    /// Return the next proxy URL. The string pointed to by `out_url_ptr` is
    /// borrowed and must remain valid only until this callback returns.
    /// Return `LK_OK` on success or `LK_ERR` when no more proxies are available.
    pub next_proxy: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            out_url_ptr: *mut *const c_char,
            out_url_len: *mut usize,
        ) -> lk_status_t,
    >,
    /// Return the total number of known proxies. May return 0 for dynamic providers.
    pub len: Option<unsafe extern "C" fn(context: *mut c_void) -> usize>,
    /// Return `true` if this provider generates proxies dynamically. May be NULL (defaults to false).
    pub is_dynamic: Option<unsafe extern "C" fn(context: *mut c_void) -> bool>,
    /// Called when the provider is no longer needed. May be NULL.
    pub destroy: Option<unsafe extern "C" fn(context: *mut c_void)>,
}

/// C-style DNS resolver used by `ClientBuilder`.
///
/// # Callback contract
///
/// Callbacks are invoked on the library runtime thread and must return
/// synchronously. They must not block on network I/O or other FFI calls.
///
/// ## `resolve`
///
/// Returns a borrowed JSON string containing an array of socket-address
/// strings, for example:
///
/// `["127.0.0.1:443", "[2606:4700:4700::1111]:443"]`
///
/// The library copies/parses the JSON immediately. Returning `LK_ERR` is
/// treated as a resolution failure.
///
/// ## `lookup_https`
///
/// Optional. Returns a borrowed JSON value matching `lkrequest::HttpsRecord`,
/// or an empty/null output to indicate "no HTTPS record". Returning `LK_ERR`
/// is treated as a lookup failure.
///
/// ## `destroy`
///
/// Called once when the resolver is dropped by the builder/client. May be
/// `NULL` if no cleanup is needed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct lk_dns_resolver_t {
    pub context: *mut c_void,
    pub resolve: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            host_ptr: *const c_char,
            host_len: usize,
            port: u16,
            out_json_ptr: *mut *const c_char,
            out_json_len: *mut usize,
        ) -> lk_status_t,
    >,
    pub lookup_https: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            host_ptr: *const c_char,
            host_len: usize,
            out_json_ptr: *mut *const c_char,
            out_json_len: *mut usize,
        ) -> lk_status_t,
    >,
    pub destroy: Option<unsafe extern "C" fn(context: *mut c_void)>,
}
