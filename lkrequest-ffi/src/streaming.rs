use std::ptr;
use std::sync::Arc;

use crate::abi::lk_status_t;
use crate::diagnostics::FfiDiagnostics;
use crate::error::{make_error_handle, FfiError};
use crate::handles::{
    box_into_handle, handle_drop, lk_error_t, lk_op_t, lk_request_t, lk_streaming_response_t,
    require_handle, require_handle_mut, OpHandle, OpResult, OpSuccess, StreamChunk,
    StreamLifecycle, StreamingResponseHandle, StreamingShared, StreamingState,
};
use crate::panic::{catch_status, catch_value};
use crate::request::{build_request_builder, take_request_config};
use crate::runtime::runtime;
use crate::types::lk_chunk_view_t;

fn snapshot_headers(headers: &http::HeaderMap) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect()
}

fn make_streaming_handle(
    client: Arc<crate::handles::ClientShared>,
    response: lkrequest::StreamingResponse,
    auto_decompress: bool,
    diagnostics: FfiDiagnostics,
) -> StreamingResponseHandle {
    let status = response.status().as_u16();
    let headers = snapshot_headers(response.headers());
    StreamingResponseHandle {
        client,
        shared: Arc::new(StreamingShared {
            state: parking_lot::Mutex::new(StreamingState {
                lifecycle: StreamLifecycle::Open,
                response: Some(response),
                last_chunk: Vec::new(),
                last_is_final: false,
                last_error: None,
                active_read_op: false,
            }),
        }),
        status,
        headers,
        auto_decompress,
        diagnostics,
        diagnostics_json: std::sync::OnceLock::new(),
    }
}

async fn execute_streaming_request(
    session: lkrequest::Session,
    config: crate::handles::RequestConfig,
) -> Result<lkrequest::StreamingResponse, FfiError> {
    build_request_builder(&session, config)
        .send_streaming()
        .await
        .map_err(map_stream_error)
}

fn map_stream_error(error: lkrequest::error::Error) -> FfiError {
    match &error {
        lkrequest::error::Error::Http(message)
            if message.contains("unsupported stream encoding")
                || message.contains("stream decompression")
                || message.contains("stream decoder")
                || message.contains("decompressed stream") =>
        {
            let mut err = FfiError::new(
                crate::abi::lk_error_code_t::LK_ERR_DECOMPRESSION_FAILED,
                error.to_string(),
            );
            err.retryable = false;
            err
        }
        _ => FfiError::from_lkrequest(error),
    }
}

fn unsupported_stream_encoding(headers: &http::HeaderMap) -> Option<String> {
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())?
        .to_ascii_lowercase();

    if encoding.is_empty()
        || matches!(
            encoding.as_str(),
            "identity" | "gzip" | "x-gzip" | "deflate" | "br" | "zstd"
        )
    {
        None
    } else {
        Some(encoding)
    }
}

async fn read_stream_chunk_inner(
    mut response: lkrequest::StreamingResponse,
    auto_decompress: bool,
) -> (
    lkrequest::StreamingResponse,
    Result<Option<bytes::Bytes>, lkrequest::error::Error>,
) {
    let result = if auto_decompress {
        if let Some(encoding) = unsupported_stream_encoding(response.headers()) {
            Err(lkrequest::error::Error::Http(format!(
                "unsupported stream encoding: {encoding}"
            )))
        } else {
            response.chunk_decoded().await
        }
    } else {
        response.chunk().await
    };
    (response, result)
}

fn current_chunk_view(state: &StreamingState) -> lk_chunk_view_t {
    lk_chunk_view_t {
        data: if state.last_chunk.is_empty() {
            ptr::null()
        } else {
            state.last_chunk.as_ptr()
        },
        len: state.last_chunk.len(),
        is_final: state.last_is_final,
    }
}

#[no_mangle]
pub extern "C" fn lk_request_send_streaming(
    request: *mut lk_request_t,
    out_stream: *mut *mut lk_streaming_response_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_stream.is_null() {
            return Err(FfiError::invalid_argument("out_stream is null"));
        }
        *out_stream = ptr::null_mut();

        let request = require_handle::<crate::handles::RequestHandle, lk_request_t>(request)?;
        let config = take_request_config(request)?;
        let session = crate::request::clone_request_session(&request.owner)?;
        let auto_decompress = config.auto_decompress;
        let (result, diagnostics) =
            runtime().block_on(lkrequest::diagnostics::capture_request_diagnostics(
                execute_streaming_request(session.clone(), config),
            ));
        let diagnostics = FfiDiagnostics::from(diagnostics);
        match result {
            Ok(response) => {
                *out_stream = box_into_handle(make_streaming_handle(
                    Arc::clone(&request.client),
                    response,
                    auto_decompress,
                    diagnostics,
                ));
                Ok(())
            }
            Err(mut err) => {
                err.diagnostics = Some(Box::new(diagnostics));
                Err(err)
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_request_send_streaming_async(
    request: *mut lk_request_t,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();

        let request = require_handle::<crate::handles::RequestHandle, lk_request_t>(request)?;
        crate::request::ensure_request_building(request)?;
        if !request.client.try_reserve_outstanding() {
            return Err(FfiError::resource_limit_exceeded(
                "max_outstanding_ops limit reached",
            ));
        }

        let config = match take_request_config(request) {
            Ok(config) => config,
            Err(err) => {
                request.client.release_outstanding();
                return Err(err);
            }
        };
        let auto_decompress = config.auto_decompress;
        let session = match crate::request::clone_request_session(&request.owner) {
            Ok(session) => session,
            Err(err) => {
                request.client.release_outstanding();
                return Err(err);
            }
        };
        let client = Arc::clone(&request.client);
        let op_shared = Arc::new(crate::handles::OpShared::default());
        let op_handle = OpHandle {
            client: Some(Arc::clone(&client)),
            shared: Arc::clone(&op_shared),
            counted: true,
            cleanup: None,
        };

        let shared = Arc::clone(&op_shared);
        let join = runtime().spawn(async move {
            let (result, diagnostics) = lkrequest::diagnostics::capture_request_diagnostics(
                execute_streaming_request(session, config),
            )
            .await;
            let diagnostics = FfiDiagnostics::from(diagnostics);
            let mut state = shared.state.lock();
            if matches!(state.result, OpResult::InProgress) {
                state.result = match result {
                    Ok(response) => {
                        OpResult::CompletedOk(Some(OpSuccess::Streaming(make_streaming_handle(
                            Arc::clone(&client),
                            response,
                            auto_decompress,
                            diagnostics,
                        ))))
                    }
                    Err(err) => OpResult::CompletedErr(Some(make_error_handle(err, diagnostics))),
                };
            }
            shared.cv.notify_all();
        });
        op_handle.shared.state.lock().join = Some(join);
        *out_op = box_into_handle(op_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_stream_read(
    stream: *mut lk_streaming_response_t,
    out_chunk: *mut lk_chunk_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_chunk.is_null() {
            return Err(FfiError::invalid_argument("out_chunk is null"));
        }
        *out_chunk = lk_chunk_view_t::default();

        let stream = require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream)?;
        let response = {
            let mut state = stream.shared.state.lock();
            match state.lifecycle {
                StreamLifecycle::Closed => {
                    return Err(FfiError::new(
                        crate::abi::lk_error_code_t::LK_ERR_STREAM_CLOSED,
                        "stream is closed",
                    ))
                }
                StreamLifecycle::Failed => {
                    return Err(state.last_error.clone().unwrap_or_else(|| {
                        FfiError::new(
                            crate::abi::lk_error_code_t::LK_ERR_UNKNOWN,
                            "stream previously failed",
                        )
                    }))
                }
                StreamLifecycle::Eof => {
                    state.last_chunk.clear();
                    state.last_is_final = true;
                    *out_chunk = current_chunk_view(&state);
                    return Ok(());
                }
                StreamLifecycle::Open => {
                    if state.active_read_op {
                        return Err(FfiError::busy("stream already has an active read op"));
                    }
                    state.response.take().ok_or_else(|| {
                        FfiError::new(
                            crate::abi::lk_error_code_t::LK_ERR_UNKNOWN,
                            "stream response missing",
                        )
                    })?
                }
            }
        };

        let (response, result) =
            runtime().block_on(read_stream_chunk_inner(response, stream.auto_decompress));
        let mut state = stream.shared.state.lock();
        match result {
            Ok(Some(chunk)) => {
                state.response = Some(response);
                state.last_chunk = chunk.to_vec();
                state.last_is_final = false;
                state.last_error = None;
                *out_chunk = current_chunk_view(&state);
                Ok(())
            }
            Ok(None) => {
                state.lifecycle = StreamLifecycle::Eof;
                state.last_chunk.clear();
                state.last_is_final = true;
                state.last_error = None;
                *out_chunk = current_chunk_view(&state);
                Ok(())
            }
            Err(error) => {
                let ffi_err = map_stream_error(error);
                state.lifecycle = StreamLifecycle::Failed;
                state.last_error = Some(ffi_err.clone());
                Err(ffi_err)
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_stream_copy_chunk(
    stream: *const lk_streaming_response_t,
    buf: *mut u8,
    buf_len: usize,
    out_read_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        let stream =
            require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())?;
        let state = stream.shared.state.lock();
        crate::conv::copy_bytes_to_buffer(&state.last_chunk, buf, buf_len, out_read_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_stream_read_async(
    stream: *mut lk_streaming_response_t,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();

        let stream = require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream)?;
        let maybe_immediate_chunk = {
            let state = stream.shared.state.lock();
            match state.lifecycle {
                StreamLifecycle::Closed => {
                    return Err(FfiError::new(
                        crate::abi::lk_error_code_t::LK_ERR_STREAM_CLOSED,
                        "stream is closed",
                    ))
                }
                StreamLifecycle::Failed => {
                    return Err(state.last_error.clone().unwrap_or_else(|| {
                        FfiError::new(
                            crate::abi::lk_error_code_t::LK_ERR_UNKNOWN,
                            "stream previously failed",
                        )
                    }))
                }
                StreamLifecycle::Eof => Some(StreamChunk {
                    stream: Arc::clone(&stream.shared),
                    data: Vec::new(),
                    is_final: true,
                }),
                StreamLifecycle::Open => {
                    if state.active_read_op {
                        return Err(FfiError::busy("stream already has an active read op"));
                    }
                    None
                }
            }
        };

        if !stream.client.try_reserve_outstanding() {
            return Err(FfiError::resource_limit_exceeded(
                "max_outstanding_ops limit reached",
            ));
        }

        if let Some(chunk) = maybe_immediate_chunk {
            let op_handle = OpHandle {
                client: Some(Arc::clone(&stream.client)),
                shared: Arc::new(crate::handles::OpShared {
                    state: parking_lot::Mutex::new(crate::handles::OpState {
                        result: OpResult::CompletedOk(Some(OpSuccess::Chunk(chunk))),
                        join: None,
                    }),
                    cv: parking_lot::Condvar::new(),
                }),
                counted: true,
                cleanup: None,
            };
            *out_op = box_into_handle(op_handle);
            return Ok(());
        }

        let response = {
            let mut state = stream.shared.state.lock();
            if !matches!(state.lifecycle, StreamLifecycle::Open) {
                stream.client.release_outstanding();
                return Err(FfiError::new(
                    crate::abi::lk_error_code_t::LK_ERR_UNKNOWN,
                    "stream state changed unexpectedly",
                ));
            }
            if state.active_read_op {
                stream.client.release_outstanding();
                return Err(FfiError::busy("stream already has an active read op"));
            }
            state.active_read_op = true;
            match state.response.take() {
                Some(response) => response,
                None => {
                    state.active_read_op = false;
                    stream.client.release_outstanding();
                    return Err(FfiError::new(
                        crate::abi::lk_error_code_t::LK_ERR_UNKNOWN,
                        "stream response missing",
                    ));
                }
            }
        };

        let shared_stream = Arc::clone(&stream.shared);
        let cleanup_stream = Arc::clone(&shared_stream);
        let op_shared = Arc::new(crate::handles::OpShared::default());
        let op_handle = OpHandle {
            client: Some(Arc::clone(&stream.client)),
            shared: Arc::clone(&op_shared),
            counted: true,
            cleanup: Some(Box::new(move || {
                let mut state = cleanup_stream.state.lock();
                state.active_read_op = false;
                state.response = None;
                state.lifecycle = StreamLifecycle::Closed;
                state.last_chunk.clear();
                state.last_is_final = false;
                state.last_error = None;
            })),
        };

        let auto_decompress = stream.auto_decompress;
        let shared = Arc::clone(&op_shared);
        let join = runtime().spawn(async move {
            let (response, result) = read_stream_chunk_inner(response, auto_decompress).await;
            let mut stream_state = shared_stream.state.lock();
            if matches!(stream_state.lifecycle, StreamLifecycle::Closed) {
                stream_state.active_read_op = false;
                drop(stream_state);
                let mut state = shared.state.lock();
                if matches!(state.result, OpResult::InProgress) {
                    state.result = OpResult::CompletedErr(Some(make_error_handle(
                        FfiError::new(
                            crate::abi::lk_error_code_t::LK_ERR_STREAM_CLOSED,
                            "stream is closed",
                        ),
                        FfiDiagnostics::default(),
                    )));
                }
                shared.cv.notify_all();
                return;
            }
            let next_result = match result {
                Ok(Some(chunk)) => {
                    stream_state.active_read_op = false;
                    stream_state.response = Some(response);
                    stream_state.last_error = None;
                    OpResult::CompletedOk(Some(OpSuccess::Chunk(StreamChunk {
                        stream: Arc::clone(&shared_stream),
                        data: chunk.to_vec(),
                        is_final: false,
                    })))
                }
                Ok(None) => {
                    stream_state.active_read_op = false;
                    stream_state.lifecycle = StreamLifecycle::Eof;
                    stream_state.response = None;
                    stream_state.last_chunk.clear();
                    stream_state.last_is_final = true;
                    stream_state.last_error = None;
                    OpResult::CompletedOk(Some(OpSuccess::Chunk(StreamChunk {
                        stream: Arc::clone(&shared_stream),
                        data: Vec::new(),
                        is_final: true,
                    })))
                }
                Err(error) => {
                    let ffi_err = map_stream_error(error);
                    stream_state.active_read_op = false;
                    stream_state.lifecycle = StreamLifecycle::Failed;
                    stream_state.last_error = Some(ffi_err.clone());
                    OpResult::CompletedErr(Some(make_error_handle(
                        ffi_err,
                        FfiDiagnostics::default(),
                    )))
                }
            };
            drop(stream_state);

            let mut state = shared.state.lock();
            if matches!(state.result, OpResult::InProgress) {
                state.result = next_result;
            }
            shared.cv.notify_all();
        });
        op_handle.shared.state.lock().join = Some(join);
        *out_op = box_into_handle(op_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_stream_close(stream: *mut lk_streaming_response_t) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        let stream =
            require_handle_mut::<StreamingResponseHandle, lk_streaming_response_t>(stream)?;
        let mut state = stream.shared.state.lock();
        state.response = None;
        state.active_read_op = false;
        state.lifecycle = StreamLifecycle::Closed;
        state.last_chunk.clear();
        state.last_is_final = false;
        state.last_error = None;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_status(stream: *const lk_streaming_response_t) -> u16 {
    catch_value(0, || unsafe {
        require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())
            .map(|stream| stream.status)
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_header_count(
    stream: *const lk_streaming_response_t,
) -> usize {
    catch_value(0, || unsafe {
        require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())
            .map(|stream| stream.headers.len())
            .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_header_name_at(
    stream: *const lk_streaming_response_t,
    index: usize,
    out_ptr: *mut *const std::ffi::c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        crate::conv::clear_out_ptr(out_ptr);
        crate::conv::clear_out_len(out_len);
        let stream =
            require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())?;
        let (name, _) = stream
            .headers
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("header index {index} out of range")))?;
        crate::conv::set_string_out(name.as_bytes(), out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_header_value_at(
    stream: *const lk_streaming_response_t,
    index: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        crate::conv::clear_out_ptr(out_ptr);
        crate::conv::clear_out_len(out_len);
        let stream =
            require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())?;
        let (_, value) = stream
            .headers
            .get(index)
            .ok_or_else(|| FfiError::not_found(format!("header index {index} out of range")))?;
        crate::conv::set_bytes_out(value, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_get_header_by_name(
    stream: *const lk_streaming_response_t,
    name_ptr: *const std::ffi::c_char,
    name_len: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        crate::conv::clear_out_ptr(out_ptr);
        crate::conv::clear_out_len(out_len);
        let stream =
            require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())?;
        let name = crate::conv::read_string_parts(name_ptr, name_len, "header name")?;
        let (_, value) = stream
            .headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(&name))
            .ok_or_else(|| FfiError::not_found(format!("header not found: {name}")))?;
        crate::conv::set_bytes_out(value, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_get_diagnostics_json(
    stream: *const lk_streaming_response_t,
    out_ptr: *mut *const std::ffi::c_char,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_ptr is null"));
        }
        *out_ptr = ptr::null();
        let stream =
            require_handle::<StreamingResponseHandle, lk_streaming_response_t>(stream.cast_mut())?;
        let bytes = stream
            .diagnostics_json
            .get_or_init(|| stream.diagnostics.to_json_bytes());
        *out_ptr = bytes.as_ptr().cast::<std::ffi::c_char>();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_streaming_response_free(stream: *mut lk_streaming_response_t) {
    catch_value((), || unsafe {
        handle_drop::<StreamingResponseHandle, lk_streaming_response_t>(stream);
    });
}
