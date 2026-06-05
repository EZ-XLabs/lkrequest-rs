use std::ffi::c_char;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use crate::abi::lk_status_t;
use crate::conv::{clear_out_len, clear_out_ptr, read_string_parts, set_string_out};
use crate::error::FfiError;
use crate::handles::{
    box_into_handle, handle_drop, lk_client_t, lk_error_t, lk_op_t, lk_session_builder_t,
    lk_session_t, require_handle, require_handle_mut, ClientHandle, OpHandle, OpResult,
    SessionBuilderState, SessionHandle, SessionHttpVersionPreference, SessionRetryPolicy,
    SessionShared,
};
use crate::panic::{catch_status, catch_value, null_error_out};
use crate::request::parse_accept_encoding;
use crate::runtime::runtime;

pub struct SessionBuilderHandle {
    pub state: SessionBuilderState,
}

fn validate_proxy(proxy: &str) -> Result<(), FfiError> {
    lkrequest::proxy::ProxyConfig::parse(proxy)
        .map(|_| ())
        .map_err(|err| FfiError::invalid_config(format!("invalid proxy URL: {err}")))
}

fn build_session(state: &SessionBuilderState) -> Arc<SessionShared> {
    let mut builder = state
        .client
        .client
        .session()
        .redirect_policy(state.redirect_policy.clone());
    if let Some(proxy) = &state.proxy {
        builder = builder.proxy(proxy);
    }
    if let Some(ech_config) = &state.ech_config {
        builder = builder.ech_config(ech_config.clone());
    }
    builder = match state.preferred_http_version {
        SessionHttpVersionPreference::Auto => builder,
        SessionHttpVersionPreference::Http1Only => builder.http1_only(),
        SessionHttpVersionPreference::Http2Only => builder.http2_only(),
        SessionHttpVersionPreference::Http3Only => builder.http3_only(),
        SessionHttpVersionPreference::Http3WithFallback => builder.http3_with_fallback(),
    };
    if let Some(encoding) = state.default_accept_encoding {
        builder = builder.default_accept_encoding(encoding);
    }
    if let Some(max_connections) = state.max_connections {
        builder = builder.max_connections(max_connections);
    }
    if let Some(idle_timeout_ms) = state.idle_timeout_ms {
        builder = builder.idle_timeout(std::time::Duration::from_millis(idle_timeout_ms));
    }
    builder = match state.retry_policy {
        SessionRetryPolicy::None => builder,
        SessionRetryPolicy::Fixed {
            max_retries,
            interval_ms,
        } => builder.retry_policy(lkrequest::FixedInterval::new(
            max_retries,
            Duration::from_millis(interval_ms),
        )),
        SessionRetryPolicy::Exponential {
            max_retries,
            base_delay_ms,
            max_delay_ms,
            jitter,
        } => builder.retry_policy(
            lkrequest::ExponentialBackoff::new(
                max_retries,
                Duration::from_millis(base_delay_ms),
                Duration::from_millis(max_delay_ms),
            )
            .with_jitter(jitter),
        ),
    };
    if !state.header_order.is_empty() {
        builder = builder.header_order(state.header_order.iter().map(|s| s.as_str()).collect());
    }
    if !state.h3_header_order.is_empty() {
        builder =
            builder.h3_header_order(state.h3_header_order.iter().map(|s| s.as_str()).collect());
    }
    if !state.cookie_order.is_empty() {
        builder = builder.cookie_order(state.cookie_order.iter().map(|s| s.as_str()).collect());
    }

    Arc::new(SessionShared {
        session: builder.build(),
        client: Arc::clone(&state.client),
    })
}

#[no_mangle]
pub extern "C" fn lk_session_new(
    client: *const lk_client_t,
    out_session: *mut *mut lk_session_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_session.is_null() {
            return Err(FfiError::invalid_argument("out_session is null"));
        }
        *out_session = ptr::null_mut();

        let client = require_handle::<ClientHandle, lk_client_t>(client.cast_mut())?;
        let state = SessionBuilderState::new(Arc::clone(&client.shared));
        let shared = build_session(&state);
        *out_session = box_into_handle::<SessionHandle, lk_session_t>(SessionHandle::new(shared));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_new_with_config(
    client: *const lk_client_t,
    proxy_ptr: *const c_char,
    proxy_len: usize,
    max_redirects: u32,
    out_session: *mut *mut lk_session_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_session.is_null() {
            return Err(FfiError::invalid_argument("out_session is null"));
        }
        *out_session = ptr::null_mut();

        let client = require_handle::<ClientHandle, lk_client_t>(client.cast_mut())?;
        let mut state = SessionBuilderState::new(Arc::clone(&client.shared));
        state.redirect_policy = lkrequest::RedirectPolicy::Follow(max_redirects);
        if !(proxy_ptr.is_null() && proxy_len == 0) {
            let proxy = read_string_parts(proxy_ptr, proxy_len, "proxy")?;
            validate_proxy(&proxy)?;
            state.proxy = Some(proxy);
        }

        let shared = build_session(&state);
        *out_session = box_into_handle::<SessionHandle, lk_session_t>(SessionHandle::new(shared));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_clone(session: *const lk_session_t) -> *mut lk_session_t {
    catch_value(ptr::null_mut(), || unsafe {
        match require_handle::<SessionHandle, lk_session_t>(session.cast_mut()) {
            Ok(session) => box_into_handle::<SessionHandle, lk_session_t>(SessionHandle::new(
                Arc::clone(&session.shared),
            )),
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_session_free(session: *mut lk_session_t) {
    catch_value((), || unsafe {
        handle_drop::<SessionHandle, lk_session_t>(session);
    });
}

#[no_mangle]
pub extern "C" fn lk_session_builder_new(client: *const lk_client_t) -> *mut lk_session_builder_t {
    catch_value(ptr::null_mut(), || unsafe {
        match require_handle::<ClientHandle, lk_client_t>(client.cast_mut()) {
            Ok(client) => box_into_handle::<SessionBuilderHandle, lk_session_builder_t>(
                SessionBuilderHandle {
                    state: SessionBuilderState::new(Arc::clone(&client.shared)),
                },
            ),
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_proxy(
    builder: *mut lk_session_builder_t,
    proxy_ptr: *const c_char,
    proxy_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        let proxy = read_string_parts(proxy_ptr, proxy_len, "proxy")?;
        validate_proxy(&proxy)?;
        builder.state.proxy = Some(proxy);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_max_redirects(
    builder: *mut lk_session_builder_t,
    max_redirects: u32,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.redirect_policy = lkrequest::RedirectPolicy::Follow(max_redirects);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_disable_redirects(
    builder: *mut lk_session_builder_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.redirect_policy = lkrequest::RedirectPolicy::None;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_ech_config(
    builder: *mut lk_session_builder_t,
    data_ptr: *const u8,
    data_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.ech_config = Some(crate::conv::read_bytes(data_ptr, data_len, "ech_config")?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_http1_only(
    builder: *mut lk_session_builder_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.preferred_http_version = SessionHttpVersionPreference::Http1Only;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_http2_only(
    builder: *mut lk_session_builder_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.preferred_http_version = SessionHttpVersionPreference::Http2Only;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_http3_only(
    builder: *mut lk_session_builder_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.preferred_http_version = SessionHttpVersionPreference::Http3Only;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_http3_with_fallback(
    builder: *mut lk_session_builder_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.preferred_http_version = SessionHttpVersionPreference::Http3WithFallback;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_default_accept_encoding(
    builder: *mut lk_session_builder_t,
    encoding_bits: u8,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.default_accept_encoding = Some(parse_accept_encoding(encoding_bits)?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_max_connections(
    builder: *mut lk_session_builder_t,
    max_connections: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.max_connections = Some(max_connections);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_idle_timeout(
    builder: *mut lk_session_builder_t,
    idle_timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.idle_timeout_ms = Some(idle_timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_retry_fixed(
    builder: *mut lk_session_builder_t,
    max_retries: u32,
    interval_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.retry_policy = SessionRetryPolicy::Fixed {
            max_retries,
            interval_ms,
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_set_retry_exponential(
    builder: *mut lk_session_builder_t,
    max_retries: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        builder.state.retry_policy = SessionRetryPolicy::Exponential {
            max_retries,
            base_delay_ms,
            max_delay_ms,
            jitter,
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_add_header_order(
    builder: *mut lk_session_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "header order entry")?;
        builder.state.header_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_add_h3_header_order(
    builder: *mut lk_session_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "h3 header order entry")?;
        builder.state.h3_header_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_add_cookie_order(
    builder: *mut lk_session_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "cookie order entry")?;
        builder.state.cookie_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_build(
    builder: *mut lk_session_builder_t,
    out_session: *mut *mut lk_session_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_session.is_null() {
            return Err(FfiError::invalid_argument("out_session is null"));
        }
        *out_session = ptr::null_mut();

        let builder = require_handle::<SessionBuilderHandle, lk_session_builder_t>(builder)?;
        let shared = build_session(&builder.state);
        *out_session = box_into_handle::<SessionHandle, lk_session_t>(SessionHandle::new(shared));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_builder_free(builder: *mut lk_session_builder_t) {
    catch_value((), || unsafe {
        handle_drop::<SessionBuilderHandle, lk_session_builder_t>(builder);
    });
}

fn clear_cookie_caches(session: &SessionHandle) {
    session.cookie_json_cache.lock().clear();
    session.cookie_value_cache.lock().clear();
}

fn read_optional_string(
    ptr: *const c_char,
    len: usize,
    name: &str,
) -> Result<Option<String>, FfiError> {
    if ptr.is_null() {
        return Ok(None);
    }
    unsafe { read_string_parts(ptr, len, name).map(Some) }
}

#[no_mangle]
pub extern "C" fn lk_session_set_cookie_with_attrs(
    session: *mut lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
    path_ptr: *const c_char,
    path_len: usize,
    domain_ptr: *const c_char,
    domain_len: usize,
    secure: bool,
    http_only: bool,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let session = require_handle_mut::<SessionHandle, lk_session_t>(session)?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let name = read_string_parts(name_ptr, name_len, "cookie name")?;
        let value = read_string_parts(value_ptr, value_len, "cookie value")?;
        let path = read_optional_string(path_ptr, path_len, "cookie path")?;
        let domain = read_optional_string(domain_ptr, domain_len, "cookie domain")?;
        session.shared.session.set_cookie_with_attrs(
            &url,
            &name,
            &value,
            path.as_deref(),
            domain.as_deref(),
            secure,
            http_only,
        );
        clear_cookie_caches(session);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_set_cookie(
    session: *mut lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let session = require_handle_mut::<SessionHandle, lk_session_t>(session)?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let name = read_string_parts(name_ptr, name_len, "cookie name")?;
        let value = read_string_parts(value_ptr, value_len, "cookie value")?;
        session.shared.session.set_cookie(&url, &name, &value);
        clear_cookie_caches(session);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_get_cookie(
    session: *const lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    name_ptr: *const c_char,
    name_len: usize,
    out_value_ptr: *mut *const c_char,
    out_value_len: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        clear_out_ptr(out_value_ptr);
        clear_out_len(out_value_len);
        let session = require_handle::<SessionHandle, lk_session_t>(session.cast_mut())?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let name = read_string_parts(name_ptr, name_len, "cookie name")?;
        let value = session
            .shared
            .session
            .get_cookie(&url, &name)
            .ok_or_else(|| FfiError::not_found(format!("cookie not found: {name}")))?;
        let key = (url, name);
        let mut cache = session.cookie_value_cache.lock();
        cache.insert(key.clone(), value.into_bytes().into_boxed_slice());
        let bytes = cache
            .get(&key)
            .expect("just inserted cookie value cache")
            .as_ref();
        set_string_out(bytes, out_value_ptr, out_value_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_session_get_cookies_json(
    session: *const lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    out_json_ptr: *mut *const c_char,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_json_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_json_ptr is null"));
        }
        *out_json_ptr = ptr::null();

        let session = require_handle::<SessionHandle, lk_session_t>(session.cast_mut())?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let cookies = session.shared.session.get_cookies(&url);
        let mut encoded = serde_json::to_vec(
            &cookies
                .into_iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect::<Vec<_>>(),
        )
        .map_err(|err| FfiError::new(crate::abi::lk_error_code_t::LK_ERR_HTTP, err.to_string()))?;
        encoded.push(0);
        let cache_key = url.clone();
        let ptr = {
            let mut cache = session.cookie_json_cache.lock();
            cache.insert(cache_key.clone(), encoded.into_boxed_slice());
            cache
                .get(&cache_key)
                .expect("just inserted cookie json cache")
                .as_ptr()
        };
        *out_json_ptr = ptr.cast::<c_char>();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_remove_cookie(
    session: *mut lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let session = require_handle_mut::<SessionHandle, lk_session_t>(session)?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let name = read_string_parts(name_ptr, name_len, "cookie name")?;
        session.shared.session.remove_cookie(&url, &name);
        clear_cookie_caches(session);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_clear_cookies(session: *mut lk_session_t) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let session = require_handle_mut::<SessionHandle, lk_session_t>(session)?;
        session.shared.session.clear_cookies();
        clear_cookie_caches(session);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_connection_pool_stats(
    session: *const lk_session_t,
    out_h2: *mut usize,
    out_h1: *mut usize,
    out_total: *mut usize,
    out_max: *mut usize,
    out_at_capacity: *mut bool,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_h2.is_null()
            || out_h1.is_null()
            || out_total.is_null()
            || out_max.is_null()
            || out_at_capacity.is_null()
        {
            return Err(FfiError::invalid_argument(
                "one or more pool stats output pointers are null",
            ));
        }
        let session = require_handle::<SessionHandle, lk_session_t>(session.cast_mut())?;
        let stats = session.shared.session.pool_stats();
        *out_h2 = stats.h2_connections;
        *out_h1 = stats.h1_connections;
        *out_total = stats.total;
        *out_max = stats.max_total;
        *out_at_capacity = stats.at_capacity;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_connection_pool_clear(session: *mut lk_session_t) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let session = require_handle_mut::<SessionHandle, lk_session_t>(session)?;
        session.shared.session.pool_clear();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_preconnect(
    session: *const lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let session = require_handle::<SessionHandle, lk_session_t>(session.cast_mut())?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        runtime()
            .block_on(session.shared.session.preconnect(&url))
            .map_err(FfiError::from_lkrequest)?;
        Ok(())
    })
}

/// Preconnect does not produce a response payload. On completion:
/// - `LK_OP_COMPLETED_OK`: preconnect succeeded; call `lk_op_free` directly.
/// - `LK_OP_COMPLETED_ERR`: use `lk_op_take_error` to retrieve the error.
#[no_mangle]
pub extern "C" fn lk_session_preconnect_async(
    session: *const lk_session_t,
    url_ptr: *const c_char,
    url_len: usize,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();

        let session = require_handle::<SessionHandle, lk_session_t>(session.cast_mut())?;
        if !session.shared.client.try_reserve_outstanding() {
            return Err(FfiError::resource_limit_exceeded(
                "max_outstanding_ops limit reached",
            ));
        }

        let url = match read_string_parts(url_ptr, url_len, "url") {
            Ok(url) => url,
            Err(err) => {
                session.shared.client.release_outstanding();
                return Err(err);
            }
        };

        let op_shared = Arc::new(crate::handles::OpShared::default());
        let op_handle = OpHandle {
            client: Some(Arc::clone(&session.shared.client)),
            shared: Arc::clone(&op_shared),
            counted: true,
            cleanup: None,
        };
        let shared = Arc::clone(&op_shared);
        let session_value = session.shared.session.clone();
        let join = runtime().spawn(async move {
            let result = session_value.preconnect(&url).await;
            let mut state = shared.state.lock();
            if matches!(state.result, OpResult::InProgress) {
                state.result = match result {
                    Ok(()) => OpResult::CompletedOk(None),
                    Err(err) => OpResult::CompletedErr(Some(crate::error::make_error_handle(
                        FfiError::from_lkrequest(err),
                        crate::diagnostics::FfiDiagnostics::default(),
                    ))),
                };
            }
            shared.cv.notify_all();
        });
        op_handle.shared.state.lock().join = Some(join);
        *out_op = box_into_handle(op_handle);
        Ok(())
    })
}
