use std::ffi::c_char;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use crate::abi::{lk_rotation_strategy_t, lk_status_t};
use crate::conv::{clear_out_len, clear_out_ptr, read_string_parts, set_string_out};
use crate::error::FfiError;
use crate::handles::{
    box_into_handle, handle_drop, lk_error_t, lk_op_t, lk_proxy_guard_t, lk_proxy_pool_builder_t,
    lk_proxy_pool_t, proxy_url_bytes, require_handle, require_handle_mut, FfiProxyProvider,
    OpHandle, OpResult, OpSuccess, ProxyGuardHandle, ProxyPoolBuilderHandle, ProxyPoolHandle,
};
use crate::panic::{catch_status, catch_value, null_error_out};
use crate::runtime::runtime;
use crate::types::lk_proxy_provider_t;

fn parse_proxy(url: &str) -> Result<lkrequest::proxy::ProxyConfig, FfiError> {
    lkrequest::proxy::ProxyConfig::parse(url)
        .map_err(|err| FfiError::invalid_config(format!("invalid proxy URL: {err}")))
}

fn map_rotation(strategy: lk_rotation_strategy_t) -> lkrequest::proxy::RotationStrategy {
    match strategy {
        lk_rotation_strategy_t::LK_ROTATION_ROUND_ROBIN => {
            lkrequest::proxy::RotationStrategy::RoundRobin
        }
        lk_rotation_strategy_t::LK_ROTATION_RANDOM => lkrequest::proxy::RotationStrategy::Random,
    }
}

fn make_proxy_guard_handle(guard: lkrequest::ProxyGuard) -> ProxyGuardHandle {
    let url = guard.proxy().map(proxy_url_bytes);
    ProxyGuardHandle { guard, url }
}

fn build_proxy_pool(builder: &mut ProxyPoolBuilderHandle) -> lkrequest::ProxyPool {
    let mut pool_builder = lkrequest::ProxyPool::builder()
        .max_proxies(builder.max_proxies)
        .rotation(builder.state.rotation)
        .bad_proxy_config(builder.state.bad_proxy_config.clone());

    if !builder.state.proxies.is_empty() {
        pool_builder = pool_builder.proxies(builder.state.proxies.clone());
    }
    if let Some(config) = builder.state.health_check.clone() {
        pool_builder = pool_builder.health_check(config);
    }
    if let Some(provider) = builder.state.provider.take() {
        pool_builder = pool_builder.proxy_provider(provider);
    }
    if let Some(capacity) = builder.state.proxy_buffer {
        pool_builder = pool_builder.proxy_buffer(capacity);
    }
    pool_builder.build()
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_new() -> *mut lk_proxy_pool_builder_t {
    catch_value(ptr::null_mut(), || {
        box_into_handle::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(
            ProxyPoolBuilderHandle::default(),
        )
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_add_proxy(
    builder: *mut lk_proxy_pool_builder_t,
    url_ptr: *const c_char,
    url_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        let url = read_string_parts(url_ptr, url_len, "proxy URL")?;
        builder.state.proxies.push(parse_proxy(&url)?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_add_proxies(
    builder: *mut lk_proxy_pool_builder_t,
    url_ptrs: *const *const c_char,
    url_lens: *const usize,
    count: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        if count == 0 {
            return Ok(());
        }
        if url_ptrs.is_null() || url_lens.is_null() {
            return Err(FfiError::invalid_argument(
                "url_ptrs or url_lens is null while count > 0",
            ));
        }
        let ptrs = std::slice::from_raw_parts(url_ptrs, count);
        let lens = std::slice::from_raw_parts(url_lens, count);
        for (i, (ptr, len)) in ptrs.iter().zip(lens.iter()).enumerate() {
            let url = read_string_parts(*ptr, *len, &format!("proxy URL [{i}]"))?;
            builder.state.proxies.push(parse_proxy(&url)?);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_set_max_proxies(
    builder: *mut lk_proxy_pool_builder_t,
    n: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        builder.max_proxies = n;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_set_rotation(
    builder: *mut lk_proxy_pool_builder_t,
    strategy: lk_rotation_strategy_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        builder.state.rotation = map_rotation(strategy);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_set_bad_proxy_config(
    builder: *mut lk_proxy_pool_builder_t,
    failure_threshold: u32,
    window_ms: u64,
    cooldown_ms: u64,
    max_cooldowns: u32,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        builder.state.bad_proxy_config = lkrequest::session_pool::BadProxyConfig {
            failure_threshold,
            window: Duration::from_millis(window_ms),
            cooldown_duration: Duration::from_millis(cooldown_ms),
            max_cooldowns,
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_set_health_check(
    builder: *mut lk_proxy_pool_builder_t,
    host_ptr: *const c_char,
    host_len: usize,
    port: u16,
    interval_ms: u64,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        let host = read_string_parts(host_ptr, host_len, "health check host")?;
        builder.state.health_check = Some(lkrequest::session_pool::HealthCheckConfig {
            target_host: host,
            target_port: port,
            interval: Duration::from_millis(interval_ms),
            timeout: Duration::from_millis(timeout_ms),
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_set_provider(
    builder: *mut lk_proxy_pool_builder_t,
    provider: lk_proxy_provider_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        let provider = FfiProxyProvider { provider };
        provider.validate()?;
        builder.state.provider = Some(provider);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_set_proxy_buffer(
    builder: *mut lk_proxy_pool_builder_t,
    capacity: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        builder.state.proxy_buffer = Some(capacity);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_build(
    builder: *mut lk_proxy_pool_builder_t,
    out_pool: *mut *mut lk_proxy_pool_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_pool.is_null() {
            return Err(FfiError::invalid_argument("out_pool is null"));
        }
        *out_pool = ptr::null_mut();
        let builder =
            require_handle_mut::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder)?;
        let pool = runtime().block_on(async { build_proxy_pool(builder) });
        *out_pool = box_into_handle::<ProxyPoolHandle, lk_proxy_pool_t>(ProxyPoolHandle { pool });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_builder_free(builder: *mut lk_proxy_pool_builder_t) {
    catch_value((), || unsafe {
        handle_drop::<ProxyPoolBuilderHandle, lk_proxy_pool_builder_t>(builder);
    });
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_acquire(
    pool: *const lk_proxy_pool_t,
    out_guard: *mut *mut lk_proxy_guard_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_guard.is_null() {
            return Err(FfiError::invalid_argument("out_guard is null"));
        }
        *out_guard = ptr::null_mut();
        let pool = require_handle::<ProxyPoolHandle, lk_proxy_pool_t>(pool.cast_mut())?;
        let guard = runtime().block_on(pool.pool.acquire());
        *out_guard =
            box_into_handle::<ProxyGuardHandle, lk_proxy_guard_t>(make_proxy_guard_handle(guard));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_acquire_async(
    pool: *const lk_proxy_pool_t,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();
        let pool = require_handle::<ProxyPoolHandle, lk_proxy_pool_t>(pool.cast_mut())?;
        let pool_value = pool.pool.clone();
        let op_shared = Arc::new(crate::handles::OpShared::default());
        let op_handle = OpHandle {
            client: None,
            shared: Arc::clone(&op_shared),
            counted: false,
            cleanup: None,
        };
        let shared = Arc::clone(&op_shared);
        let join = runtime().spawn(async move {
            let guard = pool_value.acquire().await;
            let mut state = shared.state.lock();
            if matches!(state.result, OpResult::InProgress) {
                state.result = OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(
                    make_proxy_guard_handle(guard),
                )));
            }
            shared.cv.notify_all();
        });
        op_handle.shared.state.lock().join = Some(join);
        *out_op = box_into_handle(op_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_acquire_fresh(
    pool: *const lk_proxy_pool_t,
    bad_guard: *const lk_proxy_guard_t,
    out_guard: *mut *mut lk_proxy_guard_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_guard.is_null() {
            return Err(FfiError::invalid_argument("out_guard is null"));
        }
        *out_guard = ptr::null_mut();
        let pool = require_handle::<ProxyPoolHandle, lk_proxy_pool_t>(pool.cast_mut())?;
        let bad_guard = require_handle::<ProxyGuardHandle, lk_proxy_guard_t>(bad_guard.cast_mut())?;
        let pool_value = pool.pool.clone();
        let guard = runtime().block_on(async {
            bad_guard.guard.mark_bad();
            tokio::task::yield_now().await;
            pool_value.acquire().await
        });
        *out_guard =
            box_into_handle::<ProxyGuardHandle, lk_proxy_guard_t>(make_proxy_guard_handle(guard));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_mark_bad(
    pool: *const lk_proxy_pool_t,
    identity_ptr: *const c_char,
    identity_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let pool = require_handle::<ProxyPoolHandle, lk_proxy_pool_t>(pool.cast_mut())?;
        let identity = read_string_parts(identity_ptr, identity_len, "proxy identity")?;
        let pool_value = pool.pool.clone();
        runtime().block_on(async move {
            pool_value.mark_bad_proxy(&identity);
            tokio::task::yield_now().await;
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_max_concurrent(pool: *const lk_proxy_pool_t) -> usize {
    catch_value(0, || unsafe {
        require_handle::<ProxyPoolHandle, lk_proxy_pool_t>(pool.cast_mut())
            .map(|pool| pool.pool.max_concurrent())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_pool_free(pool: *mut lk_proxy_pool_t) {
    catch_value((), || unsafe {
        handle_drop::<ProxyPoolHandle, lk_proxy_pool_t>(pool);
    });
}

#[no_mangle]
pub extern "C" fn lk_proxy_guard_url(
    guard: *const lk_proxy_guard_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let guard = require_handle::<ProxyGuardHandle, lk_proxy_guard_t>(guard.cast_mut())?;
        let url = guard
            .url
            .as_ref()
            .ok_or_else(|| FfiError::not_found("proxy guard does not contain a proxy"))?;
        set_string_out(url, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_guard_mark_bad(guard: *mut lk_proxy_guard_t) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let guard = require_handle_mut::<ProxyGuardHandle, lk_proxy_guard_t>(guard)?;
        runtime().block_on(async {
            guard.guard.mark_bad();
            tokio::task::yield_now().await;
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_proxy_guard_free(guard: *mut lk_proxy_guard_t) {
    catch_value((), || unsafe {
        handle_drop::<ProxyGuardHandle, lk_proxy_guard_t>(guard);
    });
}
