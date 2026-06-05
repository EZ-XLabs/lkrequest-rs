use std::ffi::c_char;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use crate::abi::{lk_rotation_strategy_t, lk_status_t};
use crate::conv::read_string_parts;
use crate::error::FfiError;
use crate::handles::{
    box_into_handle, handle_drop, lk_client_t, lk_error_t, lk_op_t, lk_request_t,
    lk_session_pool_builder_t, lk_session_pool_guard_t, lk_session_pool_t, require_handle,
    require_handle_mut, FfiProxyProvider, OpHandle, OpResult, OpSuccess, RequestHandle,
    RequestLifecycle, RequestOwner, RequestState, SessionPoolBuilderHandle, SessionPoolGuardHandle,
    SessionPoolGuardShared, SessionPoolHandle,
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

fn make_session_pool_guard_handle(
    guard: lkrequest::session_pool::SessionGuard,
    client: Arc<crate::handles::ClientShared>,
) -> SessionPoolGuardHandle {
    SessionPoolGuardHandle {
        shared: Arc::new(SessionPoolGuardShared {
            guard: parking_lot::Mutex::new(Some(guard)),
        }),
        client,
    }
}

fn build_session_pool(
    builder: &mut SessionPoolBuilderHandle,
) -> Result<SessionPoolHandle, FfiError> {
    let client = Arc::clone(
        builder
            .client
            .as_ref()
            .ok_or_else(|| FfiError::invalid_argument("session pool builder client is not set"))?,
    );
    let mut pool_builder = lkrequest::SessionPool::builder()
        .client(&client.client)
        .max_sessions(builder.max_sessions)
        .idle_timeout(Duration::from_millis(builder.idle_timeout_ms))
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

    Ok(SessionPoolHandle {
        pool: pool_builder.build(),
        client,
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_new(
    client: *const lk_client_t,
) -> *mut lk_session_pool_builder_t {
    catch_value(ptr::null_mut(), || unsafe {
        match require_handle::<crate::handles::ClientHandle, lk_client_t>(client.cast_mut()) {
            Ok(client) => {
                let handle = SessionPoolBuilderHandle {
                    client: Some(Arc::clone(&client.shared)),
                    ..Default::default()
                };
                box_into_handle::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(handle)
            }
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_add_proxy(
    builder: *mut lk_session_pool_builder_t,
    url_ptr: *const c_char,
    url_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        let url = read_string_parts(url_ptr, url_len, "proxy URL")?;
        builder.state.proxies.push(parse_proxy(&url)?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_add_proxies(
    builder: *mut lk_session_pool_builder_t,
    url_ptrs: *const *const c_char,
    url_lens: *const usize,
    count: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
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
pub extern "C" fn lk_session_pool_builder_set_max_sessions(
    builder: *mut lk_session_pool_builder_t,
    n: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        builder.max_sessions = n;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_set_idle_timeout(
    builder: *mut lk_session_pool_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        builder.idle_timeout_ms = timeout_ms;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_set_rotation(
    builder: *mut lk_session_pool_builder_t,
    strategy: lk_rotation_strategy_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        builder.state.rotation = map_rotation(strategy);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_set_bad_proxy_config(
    builder: *mut lk_session_pool_builder_t,
    failure_threshold: u32,
    window_ms: u64,
    cooldown_ms: u64,
    max_cooldowns: u32,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
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
pub extern "C" fn lk_session_pool_builder_set_health_check(
    builder: *mut lk_session_pool_builder_t,
    host_ptr: *const c_char,
    host_len: usize,
    port: u16,
    interval_ms: u64,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
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
pub extern "C" fn lk_session_pool_builder_set_provider(
    builder: *mut lk_session_pool_builder_t,
    provider: lk_proxy_provider_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        let provider = FfiProxyProvider { provider };
        provider.validate()?;
        builder.state.provider = Some(provider);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_set_proxy_buffer(
    builder: *mut lk_session_pool_builder_t,
    capacity: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        builder.state.proxy_buffer = Some(capacity);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_build(
    builder: *mut lk_session_pool_builder_t,
    out_pool: *mut *mut lk_session_pool_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_pool.is_null() {
            return Err(FfiError::invalid_argument("out_pool is null"));
        }
        *out_pool = ptr::null_mut();
        let builder =
            require_handle_mut::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder)?;
        let pool = runtime().block_on(async { build_session_pool(builder) })?;
        *out_pool = box_into_handle::<SessionPoolHandle, lk_session_pool_t>(pool);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_builder_free(builder: *mut lk_session_pool_builder_t) {
    catch_value((), || unsafe {
        handle_drop::<SessionPoolBuilderHandle, lk_session_pool_builder_t>(builder);
    });
}

#[no_mangle]
pub extern "C" fn lk_session_pool_acquire(
    pool: *const lk_session_pool_t,
    out_guard: *mut *mut lk_session_pool_guard_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_guard.is_null() {
            return Err(FfiError::invalid_argument("out_guard is null"));
        }
        *out_guard = ptr::null_mut();
        let pool = require_handle::<SessionPoolHandle, lk_session_pool_t>(pool.cast_mut())?;
        let guard = runtime().block_on(pool.pool.acquire());
        *out_guard = box_into_handle::<SessionPoolGuardHandle, lk_session_pool_guard_t>(
            make_session_pool_guard_handle(guard, Arc::clone(&pool.client)),
        );
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_acquire_async(
    pool: *const lk_session_pool_t,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();

        let pool = require_handle::<SessionPoolHandle, lk_session_pool_t>(pool.cast_mut())?;
        if !pool.client.try_reserve_outstanding() {
            return Err(FfiError::resource_limit_exceeded(
                "max_outstanding_ops limit reached",
            ));
        }

        let pool_value = pool.pool.clone();
        let client = Arc::clone(&pool.client);
        let op_shared = Arc::new(crate::handles::OpShared::default());
        let op_handle = OpHandle {
            client: Some(Arc::clone(&client)),
            shared: Arc::clone(&op_shared),
            counted: true,
            cleanup: None,
        };
        let shared = Arc::clone(&op_shared);
        let join = runtime().spawn(async move {
            let guard = pool_value.acquire().await;
            let mut state = shared.state.lock();
            if matches!(state.result, OpResult::InProgress) {
                state.result = OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(
                    make_session_pool_guard_handle(guard, client),
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
pub extern "C" fn lk_session_pool_mark_bad(
    pool: *const lk_session_pool_t,
    guard: *const lk_session_pool_guard_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let pool = require_handle::<SessionPoolHandle, lk_session_pool_t>(pool.cast_mut())?;
        let guard =
            require_handle::<SessionPoolGuardHandle, lk_session_pool_guard_t>(guard.cast_mut())?;
        let lock = guard.shared.guard.lock();
        let guard_ref = lock
            .as_ref()
            .ok_or_else(|| FfiError::invalid_argument("session pool guard has been released"))?;
        let pool_value = pool.pool.clone();
        runtime().block_on(async {
            pool_value.mark_bad(guard_ref);
            tokio::task::yield_now().await;
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_acquire_fresh(
    pool: *const lk_session_pool_t,
    bad_guard: *const lk_session_pool_guard_t,
    out_guard: *mut *mut lk_session_pool_guard_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_guard.is_null() {
            return Err(FfiError::invalid_argument("out_guard is null"));
        }
        *out_guard = ptr::null_mut();
        let pool = require_handle::<SessionPoolHandle, lk_session_pool_t>(pool.cast_mut())?;
        let bad_guard = require_handle::<SessionPoolGuardHandle, lk_session_pool_guard_t>(
            bad_guard.cast_mut(),
        )?;
        let pool_value = pool.pool.clone();
        let guard = {
            let lock = bad_guard.shared.guard.lock();
            let guard_ref = lock.as_ref().ok_or_else(|| {
                FfiError::invalid_argument("session pool guard has been released")
            })?;
            runtime().block_on(async {
                pool_value.mark_bad(guard_ref);
                tokio::task::yield_now().await;
            });
            runtime().block_on(pool.pool.acquire())
        };
        *out_guard = box_into_handle::<SessionPoolGuardHandle, lk_session_pool_guard_t>(
            make_session_pool_guard_handle(guard, Arc::clone(&pool.client)),
        );
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_stats(
    pool: *const lk_session_pool_t,
    out_idle: *mut usize,
    out_max: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_idle.is_null() || out_max.is_null() {
            return Err(FfiError::invalid_argument(
                "session pool stats outputs are null",
            ));
        }
        let pool = require_handle::<SessionPoolHandle, lk_session_pool_t>(pool.cast_mut())?;
        let stats = runtime().block_on(pool.pool.stats());
        *out_idle = stats.idle_sessions;
        *out_max = stats.max_sessions;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_free(pool: *mut lk_session_pool_t) {
    catch_value((), || unsafe {
        handle_drop::<SessionPoolHandle, lk_session_pool_t>(pool);
    });
}

/// The created request holds an internal reference to the guard's session.
/// The guard may be freed independently; the request remains valid.
/// The session is returned to the pool when both the guard and all
/// requests created from it have been freed.
#[no_mangle]
pub extern "C" fn lk_session_pool_guard_request_new(
    guard: *const lk_session_pool_guard_t,
    method_ptr: *const c_char,
    method_len: usize,
    url_ptr: *const c_char,
    url_len: usize,
    out_request: *mut *mut lk_request_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_request.is_null() {
            return Err(FfiError::invalid_argument("out_request is null"));
        }
        *out_request = ptr::null_mut();

        let guard =
            require_handle::<SessionPoolGuardHandle, lk_session_pool_guard_t>(guard.cast_mut())?;
        let method = http::Method::from_bytes(
            read_string_parts(method_ptr, method_len, "method")?.as_bytes(),
        )
        .map_err(|err| FfiError::invalid_argument(format!("invalid HTTP method: {err}")))?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let config = crate::handles::RequestConfig::new(method, url);
        *out_request = box_into_handle::<RequestHandle, lk_request_t>(RequestHandle {
            client: Arc::clone(&guard.client),
            owner: RequestOwner::Pooled(Arc::clone(&guard.shared)),
            state: parking_lot::Mutex::new(RequestState {
                lifecycle: RequestLifecycle::Building,
                config,
            }),
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_session_pool_guard_free(guard: *mut lk_session_pool_guard_t) {
    catch_value((), || unsafe {
        handle_drop::<SessionPoolGuardHandle, lk_session_pool_guard_t>(guard);
    });
}
