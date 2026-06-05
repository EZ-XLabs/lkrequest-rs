use std::ffi::c_char;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use crate::abi::{lk_http_version_t, lk_preferred_http_version_t, lk_status_t};
use crate::conv::{read_bytes, read_form_pairs, read_string_parts};
use crate::diagnostics::FfiDiagnostics;
use crate::error::make_error_handle;
use crate::error::FfiError;
use crate::handles::{
    box_into_handle, handle_drop, lk_error_t, lk_multipart_t, lk_op_t, lk_request_t, lk_response_t,
    lk_session_t, require_handle, require_handle_mut, MultipartHandle, OpHandle, OpResult,
    OpSuccess, RequestBody, RequestConfig, RequestHandle, RequestLifecycle, RequestOwner,
    RequestState, SessionHandle,
};
use crate::panic::{catch_status, catch_value, null_error_out};
use crate::response::make_response_handle;
use crate::runtime::runtime;

fn map_legacy_http_version(version: lk_http_version_t) -> lkrequest::PreferredHttpVersion {
    match version {
        lk_http_version_t::LK_HTTP_VERSION_10 | lk_http_version_t::LK_HTTP_VERSION_11 => {
            lkrequest::PreferredHttpVersion::Http1Only
        }
        lk_http_version_t::LK_HTTP_VERSION_2 => lkrequest::PreferredHttpVersion::Http2Only,
        lk_http_version_t::LK_HTTP_VERSION_3 => lkrequest::PreferredHttpVersion::Http3Only,
        lk_http_version_t::LK_HTTP_VERSION_UNKNOWN => lkrequest::PreferredHttpVersion::Auto,
    }
}

fn map_preferred_http_version(
    version: lk_preferred_http_version_t,
) -> lkrequest::PreferredHttpVersion {
    match version {
        lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_AUTO => {
            lkrequest::PreferredHttpVersion::Auto
        }
        lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_HTTP1_ONLY => {
            lkrequest::PreferredHttpVersion::Http1Only
        }
        lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_HTTP2_ONLY => {
            lkrequest::PreferredHttpVersion::Http2Only
        }
        lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_HTTP3_ONLY => {
            lkrequest::PreferredHttpVersion::Http3Only
        }
        lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_HTTP3_WITH_FALLBACK => {
            lkrequest::PreferredHttpVersion::Http3WithFallback
        }
    }
}

pub(crate) fn take_request_config(handle: &RequestHandle) -> Result<RequestConfig, FfiError> {
    let mut state = handle.state.lock();
    match state.lifecycle {
        RequestLifecycle::Building => {
            state.lifecycle = RequestLifecycle::Consumed;
            Ok(std::mem::replace(
                &mut state.config,
                RequestConfig::new(http::Method::GET, String::new()),
            ))
        }
        RequestLifecycle::Consumed => Err(FfiError::invalid_argument(
            "request has already been consumed",
        )),
    }
}

pub(crate) fn ensure_request_building(handle: &RequestHandle) -> Result<(), FfiError> {
    let state = handle.state.lock();
    match state.lifecycle {
        RequestLifecycle::Building => Ok(()),
        RequestLifecycle::Consumed => Err(FfiError::invalid_argument(
            "request has already been consumed",
        )),
    }
}

pub(crate) fn build_request_builder(
    session: &lkrequest::Session,
    config: RequestConfig,
) -> lkrequest::session::RequestBuilder {
    let RequestConfig {
        method,
        url,
        headers,
        query,
        body,
        timeout_ms,
        auto_decompress,
        cookies,
        cookie_overrides,
        basic_auth,
        bearer_auth,
        accept_encoding_header_present,
        proxy_override,
        version_override,
        accept_encoding_override,
        header_order,
        h3_header_order,
        cookie_order,
    } = config;

    let mut builder = session.request(method, &url);

    for (name, value) in &headers {
        builder = builder.header(name, value);
    }

    if !query.is_empty() {
        let query: Vec<(&str, &str)> = query
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        builder = builder.query(&query);
    }

    for (name, value) in &cookies {
        builder = builder.cookie(name, value);
    }
    for (name, value) in &cookie_overrides {
        builder = builder.cookie_override(name, value);
    }

    if let Some((username, password)) = &basic_auth {
        builder = builder.basic_auth(username, password.as_deref());
    }
    if let Some(token) = &bearer_auth {
        builder = builder.bearer_auth(token);
    }
    if let Some(timeout_ms) = timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout_ms));
    }
    if let Some(proxy) = &proxy_override {
        builder = builder.proxy(proxy);
    }
    if let Some(version) = version_override {
        builder = builder.preferred_http_version(version);
    }
    if let Some(accept_encoding) = accept_encoding_override {
        builder = builder.accept_encoding(accept_encoding);
    }
    if auto_decompress {
        if !accept_encoding_header_present && accept_encoding_override.is_none() {
            builder = builder.accept_encoding(lkrequest::AcceptEncoding::ALL);
        }
    } else {
        builder = builder.no_auto_decompress();
    }

    if !header_order.is_empty() {
        builder = builder.header_order(header_order.iter().map(|s| s.as_str()).collect());
    }
    if !h3_header_order.is_empty() {
        builder = builder.h3_header_order(h3_header_order.iter().map(|s| s.as_str()).collect());
    }
    if !cookie_order.is_empty() {
        builder = builder.cookie_order(cookie_order.iter().map(|s| s.as_str()).collect());
    }

    builder = match body {
        RequestBody::None => builder,
        RequestBody::Bytes(body) => builder.body(body),
        RequestBody::Text(text) => builder.text_body(&text),
        RequestBody::JsonText(json) => builder
            .header("content-type", "application/json")
            .body(json.into_bytes()),
        RequestBody::Form(fields) => builder.form(&fields),
        RequestBody::Multipart(multipart) => builder.multipart(multipart),
    };

    builder
}

pub(crate) fn clone_request_session(owner: &RequestOwner) -> Result<lkrequest::Session, FfiError> {
    match owner {
        RequestOwner::Direct(shared) => Ok(shared.session.clone()),
        RequestOwner::Pooled(shared) => {
            let guard = shared.guard.lock();
            let guard = guard.as_ref().ok_or_else(|| {
                FfiError::invalid_argument("session pool guard has been released")
            })?;
            Ok((**guard).clone())
        }
    }
}

pub(crate) async fn execute_request(
    session: lkrequest::Session,
    config: RequestConfig,
) -> Result<lkrequest::Response, FfiError> {
    build_request_builder(&session, config)
        .send()
        .await
        .map_err(FfiError::from_lkrequest)
}

pub(crate) fn parse_accept_encoding(bits: u8) -> Result<lkrequest::AcceptEncoding, FfiError> {
    lkrequest::AcceptEncoding::from_bits(bits).ok_or_else(|| {
        FfiError::invalid_argument(format!("invalid accept-encoding bits: 0x{bits:02x}"))
    })
}

#[no_mangle]
pub extern "C" fn lk_request_new(
    session: *const lk_session_t,
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

        let session = require_handle::<SessionHandle, lk_session_t>(session.cast_mut())?;
        let method = http::Method::from_bytes(
            read_string_parts(method_ptr, method_len, "method")?.as_bytes(),
        )
        .map_err(|err| FfiError::invalid_argument(format!("invalid HTTP method: {err}")))?;
        let url = read_string_parts(url_ptr, url_len, "url")?;
        let config = RequestConfig::new(method, url);
        *out_request = box_into_handle::<RequestHandle, lk_request_t>(RequestHandle {
            client: Arc::clone(&session.shared.client),
            owner: RequestOwner::Direct(Arc::clone(&session.shared)),
            state: parking_lot::Mutex::new(RequestState {
                lifecycle: RequestLifecycle::Building,
                config,
            }),
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_add_header(
    request: *mut lk_request_t,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let name = read_string_parts(name_ptr, name_len, "header name")?;
        let value = read_string_parts(value_ptr, value_len, "header value")?;
        http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| FfiError::invalid_argument(format!("invalid header name: {err}")))?;
        http::header::HeaderValue::from_str(&value)
            .map_err(|err| FfiError::invalid_argument(format!("invalid header value: {err}")))?;

        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        if name.eq_ignore_ascii_case("accept-encoding") {
            state.config.accept_encoding_header_present = true;
        }
        state.config.headers.push((name, value));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_add_query(
    request: *mut lk_request_t,
    key_ptr: *const c_char,
    key_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let key = read_string_parts(key_ptr, key_len, "query key")?;
        let value = read_string_parts(value_ptr, value_len, "query value")?;

        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.query.push((key, value));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_body_bytes(
    request: *mut lk_request_t,
    data_ptr: *const u8,
    data_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let data = read_bytes(data_ptr, data_len, "body bytes")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.body = RequestBody::Bytes(data);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_text_body(
    request: *mut lk_request_t,
    text_ptr: *const c_char,
    text_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let text = read_string_parts(text_ptr, text_len, "text body")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.body = RequestBody::Text(text);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_json_text(
    request: *mut lk_request_t,
    json_ptr: *const c_char,
    json_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let json = read_string_parts(json_ptr, json_len, "json body")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.body = RequestBody::JsonText(json);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_form(
    request: *mut lk_request_t,
    pairs_ptr: *const crate::types::lk_form_pair_t,
    pairs_count: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let fields = read_form_pairs(pairs_ptr, pairs_count)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.body = RequestBody::Form(fields);
        Ok(())
    })
}

/// Takes ownership of `multipart` on success. The caller must NOT call
/// `lk_multipart_free` after a successful return. On `LK_ERR`, ownership
/// is NOT transferred and the caller retains responsibility for freeing it.
#[no_mangle]
pub extern "C" fn lk_request_set_multipart(
    request: *mut lk_request_t,
    multipart: *mut lk_multipart_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let multipart_value = {
            let multipart_handle =
                require_handle_mut::<MultipartHandle, lk_multipart_t>(multipart)?;
            std::mem::take(&mut multipart_handle.multipart)
        };
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.body = RequestBody::Multipart(multipart_value);
        drop(state);
        handle_drop::<MultipartHandle, lk_multipart_t>(multipart);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_timeout(
    request: *mut lk_request_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_auto_decompress(
    request: *mut lk_request_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.auto_decompress = enabled;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_cookie(
    request: *mut lk_request_t,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let name = read_string_parts(name_ptr, name_len, "cookie name")?;
        let value = read_string_parts(value_ptr, value_len, "cookie value")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.cookies.push((name, value));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_cookie_override(
    request: *mut lk_request_t,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let name = read_string_parts(name_ptr, name_len, "cookie name")?;
        let value = read_string_parts(value_ptr, value_len, "cookie value")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.cookie_overrides.push((name, value));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_basic_auth(
    request: *mut lk_request_t,
    username_ptr: *const c_char,
    username_len: usize,
    password_ptr: *const c_char,
    password_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let username = read_string_parts(username_ptr, username_len, "username")?;
        let password = read_string_parts(password_ptr, password_len, "password")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.basic_auth = Some((username, Some(password)));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_bearer_auth(
    request: *mut lk_request_t,
    token_ptr: *const c_char,
    token_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let token = read_string_parts(token_ptr, token_len, "token")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.bearer_auth = Some(token);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_proxy(
    request: *mut lk_request_t,
    proxy_ptr: *const c_char,
    proxy_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let proxy = read_string_parts(proxy_ptr, proxy_len, "proxy")?;
        lkrequest::proxy::ProxyConfig::parse(&proxy)
            .map_err(|err| FfiError::invalid_config(format!("invalid proxy URL: {err}")))?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.proxy_override = Some(proxy);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_version(
    request: *mut lk_request_t,
    version: lk_http_version_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.version_override = Some(map_legacy_http_version(version));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_preferred_http_version(
    request: *mut lk_request_t,
    version: lk_preferred_http_version_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.version_override = Some(map_preferred_http_version(version));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_set_accept_encoding(
    request: *mut lk_request_t,
    encoding_bits: u8,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.accept_encoding_override = Some(parse_accept_encoding(encoding_bits)?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_add_header_order(
    request: *mut lk_request_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let name = read_string_parts(name_ptr, name_len, "header order entry")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.header_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_add_h3_header_order(
    request: *mut lk_request_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let name = read_string_parts(name_ptr, name_len, "h3 header order entry")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.h3_header_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_add_cookie_order(
    request: *mut lk_request_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let request = require_handle_mut::<RequestHandle, lk_request_t>(request)?;
        let name = read_string_parts(name_ptr, name_len, "cookie order entry")?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.cookie_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_send(
    request: *mut lk_request_t,
    out_response: *mut *mut lk_response_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_response.is_null() {
            return Err(FfiError::invalid_argument("out_response is null"));
        }
        *out_response = ptr::null_mut();

        let request = require_handle::<RequestHandle, lk_request_t>(request)?;
        let config = take_request_config(request)?;
        let session = clone_request_session(&request.owner)?;
        let (result, diagnostics) = runtime().block_on(
            lkrequest::diagnostics::capture_request_diagnostics(execute_request(session, config)),
        );
        let diagnostics = FfiDiagnostics::from(diagnostics);
        match result {
            Ok(response) => {
                *out_response = box_into_handle(make_response_handle(response, diagnostics));
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
pub extern "C" fn lk_request_send_async(
    request: *mut lk_request_t,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();

        let request = require_handle::<RequestHandle, lk_request_t>(request)?;
        ensure_request_building(request)?;
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
        let session = match clone_request_session(&request.owner) {
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
                execute_request(session, config),
            )
            .await;
            let diagnostics = FfiDiagnostics::from(diagnostics);
            let mut state = shared.state.lock();
            if matches!(state.result, OpResult::InProgress) {
                state.result = match result {
                    Ok(response) => OpResult::CompletedOk(Some(OpSuccess::Response(
                        make_response_handle(response, diagnostics),
                    ))),
                    Err(err) => OpResult::CompletedErr(Some(make_error_handle(err, diagnostics))),
                };
            }
            shared.cv.notify_all();
        });
        op_handle.shared.state.lock().join = Some(join);
        *out_op = box_into_handle::<OpHandle, lk_op_t>(op_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_request_free(request: *mut lk_request_t) {
    catch_value((), || unsafe {
        handle_drop::<RequestHandle, lk_request_t>(request);
    });
}
