use std::ptr;
use std::time::{Duration, Instant};

use crate::abi::{lk_op_state_t, lk_status_t};
use crate::error::FfiError;
use crate::handles::{
    box_into_handle, handle_drop, lk_error_t, lk_op_t, lk_proxy_guard_t, lk_response_t,
    lk_session_pool_guard_t, lk_socks5_udp_probe_report_t, lk_streaming_response_t, require_handle,
    require_handle_mut, OpHandle, OpResult, OpSuccess, ProxyGuardHandle, SessionPoolGuardHandle,
    Socks5UdpProbeReportHandle, StreamingResponseHandle,
};
use crate::panic::{catch_status, catch_value};

fn current_state(result: &OpResult) -> lk_op_state_t {
    match result {
        OpResult::InProgress => lk_op_state_t::LK_OP_IN_PROGRESS,
        OpResult::CompletedOk(_) => lk_op_state_t::LK_OP_COMPLETED_OK,
        OpResult::CompletedErr(_) => lk_op_state_t::LK_OP_COMPLETED_ERR,
        OpResult::Cancelled => lk_op_state_t::LK_OP_CANCELLED,
        OpResult::Consumed => lk_op_state_t::LK_OP_CONSUMED,
    }
}

#[no_mangle]
pub extern "C" fn lk_op_poll(op: *const lk_op_t) -> lk_op_state_t {
    catch_value(lk_op_state_t::LK_OP_CONSUMED, || unsafe {
        require_handle::<OpHandle, lk_op_t>(op.cast_mut())
            .map(|handle| current_state(&handle.shared.state.lock().result))
            .unwrap_or(lk_op_state_t::LK_OP_CONSUMED)
    })
}

#[no_mangle]
pub extern "C" fn lk_op_wait(op: *const lk_op_t, timeout_ms: u64) -> lk_op_state_t {
    catch_value(lk_op_state_t::LK_OP_CONSUMED, || unsafe {
        let op = match require_handle::<OpHandle, lk_op_t>(op.cast_mut()) {
            Ok(op) => op,
            Err(_) => return lk_op_state_t::LK_OP_CONSUMED,
        };

        let mut state = op.shared.state.lock();
        if timeout_ms == 0 {
            while matches!(state.result, OpResult::InProgress) {
                op.shared.cv.wait(&mut state);
            }
            return current_state(&state.result);
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while matches!(state.result, OpResult::InProgress) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            op.shared
                .cv
                .wait_for(&mut state, deadline.saturating_duration_since(now));
        }

        current_state(&state.result)
    })
}

#[no_mangle]
pub extern "C" fn lk_op_cancel(op: *mut lk_op_t) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        if matches!(state.result, OpResult::Consumed) {
            return Err(FfiError::invalid_argument(
                "operation has already been consumed",
            ));
        }

        if matches!(state.result, OpResult::InProgress) {
            if let Some(join) = state.join.take() {
                join.abort();
            }
            state.result = OpResult::Cancelled;
            let cleanup = op.cleanup.take();
            op.shared.cv.notify_all();
            drop(state);
            if let Some(cleanup) = cleanup {
                cleanup();
            }
            return Ok(());
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_response(
    op: *mut lk_op_t,
    out_response: *mut *mut lk_response_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_response.is_null() {
            return Err(FfiError::invalid_argument("out_response is null"));
        }
        *out_response = ptr::null_mut();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        match result {
            OpResult::CompletedOk(Some(OpSuccess::Response(response))) => {
                *out_response = box_into_handle(response);
                Ok(())
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Streaming(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a streaming response; use lk_op_take_streaming_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Chunk(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a chunk result; use lk_op_take_chunk",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a proxy guard; use lk_op_take_proxy_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a session pool guard; use lk_op_take_session_pool_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a SOCKS5 UDP probe report; use lk_op_take_socks5_udp_probe_report",
                ))
            }
            OpResult::CompletedOk(None) => Err(FfiError::invalid_argument(
                "operation completed successfully with no response payload",
            )),
            other @ OpResult::InProgress => {
                state.result = other;
                Err(FfiError::busy("operation is still in progress"))
            }
            other @ OpResult::CompletedErr(_) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with an error; use lk_op_take_error",
                ))
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                Err(FfiError::invalid_argument("operation was cancelled"))
            }
            OpResult::Consumed => Err(FfiError::invalid_argument(
                "operation result has already been consumed",
            )),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_error(op: *mut lk_op_t, out_err: *mut *mut lk_error_t) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_err.is_null() {
            return Err(FfiError::invalid_argument("out_err is null"));
        }
        *out_err = ptr::null_mut();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        match result {
            OpResult::CompletedErr(Some(err)) => {
                *out_err = box_into_handle(err);
                Ok(())
            }
            OpResult::CompletedErr(None) => Err(FfiError::invalid_argument("error already taken")),
            other @ OpResult::InProgress => {
                state.result = other;
                Err(FfiError::busy("operation is still in progress"))
            }
            other @ OpResult::CompletedOk(_) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed successfully; this operation may not have an error payload",
                ))
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                Err(FfiError::invalid_argument("operation was cancelled"))
            }
            OpResult::Consumed => Err(FfiError::invalid_argument(
                "operation result has already been consumed",
            )),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_streaming_response(
    op: *mut lk_op_t,
    out_stream: *mut *mut lk_streaming_response_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_stream.is_null() {
            return Err(FfiError::invalid_argument("out_stream is null"));
        }
        *out_stream = ptr::null_mut();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        match result {
            OpResult::CompletedOk(Some(OpSuccess::Streaming(stream))) => {
                *out_stream =
                    box_into_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream);
                Ok(())
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Response(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a buffered response; use lk_op_take_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Chunk(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a chunk result; use lk_op_take_chunk",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a proxy guard; use lk_op_take_proxy_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a session pool guard; use lk_op_take_session_pool_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a SOCKS5 UDP probe report; use lk_op_take_socks5_udp_probe_report",
                ))
            }
            OpResult::CompletedOk(None) => Err(FfiError::invalid_argument(
                "operation completed successfully with no streaming payload",
            )),
            other @ OpResult::InProgress => {
                state.result = other;
                Err(FfiError::busy("operation is still in progress"))
            }
            other @ OpResult::CompletedErr(_) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with an error; use lk_op_take_error",
                ))
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                Err(FfiError::invalid_argument("operation was cancelled"))
            }
            OpResult::Consumed => Err(FfiError::invalid_argument(
                "operation result has already been consumed",
            )),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_chunk(
    op: *mut lk_op_t,
    out_chunk: *mut crate::types::lk_chunk_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_chunk.is_null() {
            return Err(FfiError::invalid_argument("out_chunk is null"));
        }
        *out_chunk = crate::types::lk_chunk_view_t::default();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        let chunk = match result {
            OpResult::CompletedOk(Some(OpSuccess::Chunk(chunk))) => chunk,
            other @ OpResult::CompletedOk(Some(OpSuccess::Response(_))) => {
                state.result = other;
                return Err(FfiError::invalid_argument(
                    "operation completed with a buffered response; use lk_op_take_response",
                ));
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Streaming(_))) => {
                state.result = other;
                return Err(FfiError::invalid_argument(
                    "operation completed with a streaming response; use lk_op_take_streaming_response",
                ));
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(_))) => {
                state.result = other;
                return Err(FfiError::invalid_argument(
                    "operation completed with a proxy guard; use lk_op_take_proxy_guard",
                ));
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(_))) => {
                state.result = other;
                return Err(FfiError::invalid_argument(
                    "operation completed with a session pool guard; use lk_op_take_session_pool_guard",
                ));
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(_))) => {
                state.result = other;
                return Err(FfiError::invalid_argument(
                    "operation completed with a SOCKS5 UDP probe report; use lk_op_take_socks5_udp_probe_report",
                ));
            }
            OpResult::CompletedOk(None) => {
                return Err(FfiError::invalid_argument(
                    "operation completed successfully with no chunk payload",
                ));
            }
            other @ OpResult::InProgress => {
                state.result = other;
                return Err(FfiError::busy("operation is still in progress"));
            }
            other @ OpResult::CompletedErr(_) => {
                state.result = other;
                return Err(FfiError::invalid_argument(
                    "operation completed with an error; use lk_op_take_error",
                ));
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                return Err(FfiError::invalid_argument("operation was cancelled"));
            }
            OpResult::Consumed => {
                return Err(FfiError::invalid_argument(
                    "operation result has already been consumed",
                ));
            }
        };
        drop(state);

        let mut stream = chunk.stream.state.lock();
        stream.last_chunk = chunk.data;
        stream.last_is_final = chunk.is_final;
        *out_chunk = crate::types::lk_chunk_view_t {
            data: if stream.last_chunk.is_empty() {
                ptr::null()
            } else {
                stream.last_chunk.as_ptr()
            },
            len: stream.last_chunk.len(),
            is_final: stream.last_is_final,
        };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_proxy_guard(
    op: *mut lk_op_t,
    out_guard: *mut *mut lk_proxy_guard_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_guard.is_null() {
            return Err(FfiError::invalid_argument("out_guard is null"));
        }
        *out_guard = ptr::null_mut();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        match result {
            OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(guard))) => {
                *out_guard = box_into_handle::<ProxyGuardHandle, lk_proxy_guard_t>(guard);
                Ok(())
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Response(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a buffered response; use lk_op_take_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Streaming(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a streaming response; use lk_op_take_streaming_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Chunk(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a chunk result; use lk_op_take_chunk",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a session pool guard; use lk_op_take_session_pool_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a SOCKS5 UDP probe report; use lk_op_take_socks5_udp_probe_report",
                ))
            }
            OpResult::CompletedOk(None) => Err(FfiError::invalid_argument(
                "operation completed successfully with no proxy guard payload",
            )),
            other @ OpResult::InProgress => {
                state.result = other;
                Err(FfiError::busy("operation is still in progress"))
            }
            other @ OpResult::CompletedErr(_) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with an error; use lk_op_take_error",
                ))
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                Err(FfiError::invalid_argument("operation was cancelled"))
            }
            OpResult::Consumed => Err(FfiError::invalid_argument(
                "operation result has already been consumed",
            )),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_session_pool_guard(
    op: *mut lk_op_t,
    out_guard: *mut *mut lk_session_pool_guard_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_guard.is_null() {
            return Err(FfiError::invalid_argument("out_guard is null"));
        }
        *out_guard = ptr::null_mut();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        match result {
            OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(guard))) => {
                *out_guard =
                    box_into_handle::<SessionPoolGuardHandle, lk_session_pool_guard_t>(guard);
                Ok(())
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Response(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a buffered response; use lk_op_take_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Streaming(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a streaming response; use lk_op_take_streaming_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Chunk(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a chunk result; use lk_op_take_chunk",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a proxy guard; use lk_op_take_proxy_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a SOCKS5 UDP probe report; use lk_op_take_socks5_udp_probe_report",
                ))
            }
            OpResult::CompletedOk(None) => Err(FfiError::invalid_argument(
                "operation completed successfully with no session pool guard payload",
            )),
            other @ OpResult::InProgress => {
                state.result = other;
                Err(FfiError::busy("operation is still in progress"))
            }
            other @ OpResult::CompletedErr(_) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with an error; use lk_op_take_error",
                ))
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                Err(FfiError::invalid_argument("operation was cancelled"))
            }
            OpResult::Consumed => Err(FfiError::invalid_argument(
                "operation result has already been consumed",
            )),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_op_take_socks5_udp_probe_report(
    op: *mut lk_op_t,
    out_report: *mut *mut lk_socks5_udp_probe_report_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_report.is_null() {
            return Err(FfiError::invalid_argument("out_report is null"));
        }
        *out_report = ptr::null_mut();

        let op = require_handle_mut::<OpHandle, lk_op_t>(op)?;
        let mut state = op.shared.state.lock();
        let result = std::mem::replace(&mut state.result, OpResult::Consumed);
        match result {
            OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(report))) => {
                *out_report = box_into_handle::<
                    Socks5UdpProbeReportHandle,
                    lk_socks5_udp_probe_report_t,
                >(report);
                Ok(())
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Response(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a buffered response; use lk_op_take_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Streaming(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a streaming response; use lk_op_take_streaming_response",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::Chunk(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a chunk result; use lk_op_take_chunk",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::ProxyGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a proxy guard; use lk_op_take_proxy_guard",
                ))
            }
            other @ OpResult::CompletedOk(Some(OpSuccess::SessionPoolGuard(_))) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with a session pool guard; use lk_op_take_session_pool_guard",
                ))
            }
            OpResult::CompletedOk(None) => Err(FfiError::invalid_argument(
                "operation completed successfully with no SOCKS5 UDP probe report",
            )),
            other @ OpResult::InProgress => {
                state.result = other;
                Err(FfiError::busy("operation is still in progress"))
            }
            other @ OpResult::CompletedErr(_) => {
                state.result = other;
                Err(FfiError::invalid_argument(
                    "operation completed with an error; use lk_op_take_error",
                ))
            }
            other @ OpResult::Cancelled => {
                state.result = other;
                Err(FfiError::invalid_argument("operation was cancelled"))
            }
            OpResult::Consumed => Err(FfiError::invalid_argument(
                "operation result has already been consumed",
            )),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_op_free(op: *mut lk_op_t) {
    catch_value((), || unsafe {
        handle_drop::<OpHandle, lk_op_t>(op);
    });
}
