use std::ffi::{c_char, CStr, CString};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ptr;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use lkrequest_ffi::{
    lk_abi_version, lk_client_builder_add_ca_cert_memory, lk_client_builder_build,
    lk_client_builder_free, lk_client_builder_new, lk_client_builder_set_max_outstanding_ops,
    lk_client_builder_set_preset, lk_client_builder_set_timeout_total, lk_client_clone,
    lk_client_free, lk_client_new_default, lk_client_t, lk_error_code, lk_error_free,
    lk_error_http_status, lk_error_is_retryable, lk_error_message, lk_error_t,
    lk_feature_supported, lk_http_version_t, lk_library_version, lk_negotiated_http_version_t,
    lk_op_cancel, lk_op_free, lk_op_poll, lk_op_state_t, lk_op_t, lk_op_take_error,
    lk_op_take_response, lk_op_wait, lk_preferred_http_version_t, lk_request_add_h3_header_order,
    lk_request_add_header, lk_request_add_query, lk_request_free, lk_request_new, lk_request_send,
    lk_request_send_async, lk_request_set_basic_auth, lk_request_set_bearer_auth,
    lk_request_set_json_text, lk_request_set_preferred_http_version, lk_request_set_timeout,
    lk_request_t, lk_response_body, lk_response_content_length, lk_response_copy_body,
    lk_response_free, lk_response_get_header_by_name, lk_response_header_count,
    lk_response_negotiated_version, lk_response_status, lk_response_t, lk_response_url,
    lk_response_version, lk_session_builder_add_h3_header_order, lk_session_builder_build,
    lk_session_builder_disable_redirects, lk_session_builder_free, lk_session_builder_new,
    lk_session_builder_set_max_redirects, lk_session_clone, lk_session_free, lk_session_new,
    lk_session_t, lk_status_t,
};

struct TestServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("server addr");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => handle_connection(stream),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let request = match read_http_request(&mut stream) {
        Ok(req) => req,
        Err(_) => return,
    };
    let route = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());
    if route == "/redirect" {
        // A 3xx that points elsewhere; used to verify disabled-redirect behavior.
        let resp =
            "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes());
        return;
    }

    let body = match route {
        "/ok" => b"hello ffi".to_vec(),
        "/echo" => request.body.clone(),
        "/slow" => {
            thread::sleep(Duration::from_millis(250));
            b"slow".to_vec()
        }
        "/query" => request.path.as_bytes().to_vec(),
        _ => b"not found".to_vec(),
    };

    let status_line = if request.path == "/missing" {
        "HTTP/1.1 404 Not Found"
    } else {
        "HTTP/1.1 200 OK"
    };

    let auth = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    let response = format!(
        "{status_line}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nX-Method: {}\r\nX-Auth: {}\r\nConnection: close\r\n\r\n",
        body.len(),
        request.method,
        auth
    );
    stream
        .write_all(response.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .expect("write response");
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    let header_end;
    loop {
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request completed",
            ));
        }
        data.extend_from_slice(&buffer[..n]);
        if let Some(idx) = find_header_end(&data) {
            header_end = idx;
            break;
        }
    }

    let header_bytes = &data[..header_end];
    let header_text = str::from_utf8(header_bytes).expect("valid request headers");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().expect("method").to_string();
    let path = request_parts.next().expect("path").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').expect("header colon");
        let name = name.trim().to_string();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().expect("content-length");
        }
        headers.push((name, value));
    }

    let mut body = data[(header_end + 4)..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..n]);
    }
    body.truncate(content_length);

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn cstring(value: &str) -> CString {
    CString::new(value).expect("cstring")
}

unsafe fn view_string(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    let bytes = slice::from_raw_parts(ptr.cast::<u8>(), len);
    str::from_utf8(bytes).expect("utf8 view").to_string()
}

unsafe fn view_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    slice::from_raw_parts(ptr, len).to_vec()
}

unsafe fn error_message_string(err: *const lk_error_t) -> String {
    let mut ptr = ptr::null();
    let mut len = 0usize;
    assert_eq!(
        lk_error_message(err, &mut ptr, &mut len),
        lk_status_t::LK_OK
    );
    view_string(ptr, len)
}

#[test]
fn exports_abi_version_and_header_file_consistently() {
    assert_eq!(lk_abi_version(), 1);
    assert!(unsafe { CStr::from_ptr(lk_library_version()) }
        .to_str()
        .unwrap()
        .contains("lkrequest-ffi/"));
    assert!(lk_feature_supported(cstring("sync").as_ptr()));
    assert!(lk_feature_supported(cstring("async").as_ptr()));
    assert!(lk_feature_supported(cstring("streaming").as_ptr()));

    // The C header is generated by build.rs via cbindgen and is not committed.
    // When cbindgen is unavailable the header is absent, so the symbol-contract
    // checks below are best-effort: skip them rather than fail the test.
    let Ok(header) = std::fs::read_to_string("lkrequest-ffi/include/lkrequest.h")
        .or_else(|_| std::fs::read_to_string("include/lkrequest.h"))
    else {
        eprintln!("skipping FFI header symbol checks: lkrequest.h not generated (cbindgen absent)");
        return;
    };
    assert!(header.contains("lk_request_send_async"));
    assert!(header.contains("lk_op_take_response"));
    assert!(header.contains("lk_client_builder_add_h3_header_order"));
    assert!(header.contains("lk_session_builder_add_h3_header_order"));
    assert!(header.contains("lk_request_add_h3_header_order"));
    assert!(header.contains("lk_dns_resolver_t"));
    assert!(header.contains("lk_client_builder_set_dns_resolver"));
    assert!(header.contains("lk_client_builder_set_quic_profile_json"));
    assert!(header.contains("lk_client_builder_disable_http3"));
    assert!(header.contains("lk_client_builder_set_session_resumption_json"));
    assert!(header.contains("lk_client_builder_set_timeout_quic_connect"));
    assert!(header.contains("lk_session_builder_set_http3_with_fallback"));
}

#[test]
fn sync_requests_round_trip_and_expose_response_getters() {
    let server = TestServer::start();

    unsafe {
        let client_builder = lk_client_builder_new();
        assert!(!client_builder.is_null());
        assert_eq!(
            lk_client_builder_set_preset(client_builder, cstring("chrome_131").as_ptr()),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_client_builder_set_timeout_total(client_builder, 5_000),
            lk_status_t::LK_OK
        );
        let mut client = ptr::null_mut::<lk_client_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_client_builder_build(client_builder, &mut client, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_client_builder_free(client_builder);

        let client_clone = lk_client_clone(client);
        assert!(!client_clone.is_null());

        let session_builder = lk_session_builder_new(client_clone);
        assert!(!session_builder.is_null());
        assert_eq!(
            lk_session_builder_set_max_redirects(session_builder, 5),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_builder_disable_redirects(session_builder),
            lk_status_t::LK_OK
        );
        // Re-enable with max_redirects to continue the rest of the test
        assert_eq!(
            lk_session_builder_set_max_redirects(session_builder, 10),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_session_builder_add_h3_header_order(
                session_builder,
                cstring("priority").as_ptr(),
                "priority".len(),
            ),
            lk_status_t::LK_OK
        );
        let mut session = ptr::null_mut::<lk_session_t>();
        assert_eq!(
            lk_session_builder_build(session_builder, &mut session, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_session_builder_free(session_builder);
        lk_client_free(client_clone);

        let session_clone = lk_session_clone(session);
        assert!(!session_clone.is_null());

        let method = cstring("GET");
        let url = server.url("/query");
        let url_c = cstring(&url);
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session_clone,
                method.as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        assert_eq!(
            lk_request_add_header(
                request,
                cstring("x-extra").as_ptr(),
                7,
                cstring("1").as_ptr(),
                1,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_add_query(request, cstring("a").as_ptr(), 1, cstring("b").as_ptr(), 1,),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_add_h3_header_order(request, cstring("priority").as_ptr(), "priority".len(),),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_basic_auth(
                request,
                cstring("alice").as_ptr(),
                5,
                cstring("secret").as_ptr(),
                6,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_bearer_auth(request, cstring("token").as_ptr(), 5),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_preferred_http_version(
                request,
                lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_HTTP1_ONLY,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(lk_request_set_timeout(request, 3_000), lk_status_t::LK_OK);

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_request_free(request);

        assert_eq!(lk_response_status(response), 200);

        let mut version = lk_http_version_t::LK_HTTP_VERSION_UNKNOWN;
        assert_eq!(
            lk_response_version(response, &mut version),
            lk_status_t::LK_OK
        );
        assert!(matches!(
            version,
            lk_http_version_t::LK_HTTP_VERSION_11 | lk_http_version_t::LK_HTTP_VERSION_UNKNOWN
        ));
        let mut negotiated = lk_negotiated_http_version_t::LK_NEGOTIATED_HTTP_VERSION_11;
        assert_eq!(
            lk_response_negotiated_version(response, &mut negotiated),
            lk_status_t::LK_OK
        );
        assert_eq!(
            negotiated,
            lk_negotiated_http_version_t::LK_NEGOTIATED_HTTP_VERSION_11
        );

        let mut url_ptr = ptr::null();
        let mut url_len = 0usize;
        assert_eq!(
            lk_response_url(response, &mut url_ptr, &mut url_len),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(url_ptr, url_len), format!("{url}?a=b"));

        assert!(lk_response_header_count(response) >= 3);
        let mut header_ptr = ptr::null();
        let mut header_len = 0usize;
        assert_eq!(
            lk_response_get_header_by_name(
                response,
                cstring("x-method").as_ptr(),
                8,
                &mut header_ptr,
                &mut header_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        assert_eq!(view_bytes(header_ptr, header_len), b"GET");

        let mut body_ptr = ptr::null();
        let mut body_len = 0usize;
        assert_eq!(
            lk_response_body(response, &mut body_ptr, &mut body_len),
            lk_status_t::LK_OK
        );
        assert_eq!(view_bytes(body_ptr, body_len), b"/query?a=b");
        assert_eq!(lk_response_content_length(response), 10);

        let mut copied = vec![0u8; 64];
        let mut copied_len = 0usize;
        assert_eq!(
            lk_response_copy_body(response, copied.as_mut_ptr(), copied.len(), &mut copied_len),
            lk_status_t::LK_OK
        );
        copied.truncate(copied_len);
        assert_eq!(copied, b"/query?a=b");

        lk_response_free(response);
        lk_session_free(session_clone);
        lk_session_free(session);
        lk_client_free(client);
    }
}

#[test]
fn sync_errors_surface_url_parse_and_ca_validation_failures() {
    unsafe {
        let builder = lk_client_builder_new();
        assert_eq!(
            lk_client_builder_add_ca_cert_memory(builder, b"bad-cert".as_ptr(), 8),
            lk_status_t::LK_ERR
        );
        lk_client_builder_free(builder);

        let mut client = ptr::null_mut::<lk_client_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_client_new_default(&mut client, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());

        let mut session = ptr::null_mut::<lk_session_t>();
        assert_eq!(
            lk_session_new(client, &mut session, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());

        let method = cstring("GET");
        let url = cstring("not-a-url");
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                method.as_ptr(),
                3,
                url.as_ptr(),
                9,
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(request, &mut response, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(response.is_null());
        assert!(!err.is_null());
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_URL_PARSE
        );
        assert_eq!(lk_error_http_status(err), -1);
        assert!(!lk_error_is_retryable(err));
        assert!(error_message_string(err).contains("invalid URL"));

        lk_error_free(err);
        lk_request_free(request);
        lk_session_free(session);
        lk_client_free(client);
    }
}

#[test]
fn async_operations_report_success_limits_errors_and_cancellation() {
    let server = TestServer::start();

    let builder = lk_client_builder_new();
    assert_eq!(
        lk_client_builder_set_max_outstanding_ops(builder, 1),
        lk_status_t::LK_OK
    );
    let mut client = ptr::null_mut::<lk_client_t>();
    let mut err = ptr::null_mut::<lk_error_t>();
    assert_eq!(
        lk_client_builder_build(builder, &mut client, &mut err),
        lk_status_t::LK_OK
    );
    lk_client_builder_free(builder);

    let mut session = ptr::null_mut::<lk_session_t>();
    assert_eq!(
        lk_session_new(client, &mut session, &mut err),
        lk_status_t::LK_OK
    );

    let slow_url = server.url("/slow");
    let slow_url_c = cstring(&slow_url);
    let mut req1 = ptr::null_mut::<lk_request_t>();
    assert_eq!(
        lk_request_new(
            session,
            cstring("GET").as_ptr(),
            3,
            slow_url_c.as_ptr(),
            slow_url.len(),
            &mut req1,
            &mut err,
        ),
        lk_status_t::LK_OK
    );

    let mut op1 = ptr::null_mut::<lk_op_t>();
    assert_eq!(
        lk_request_send_async(req1, &mut op1, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_request_free(req1);
    assert_eq!(lk_op_poll(op1), lk_op_state_t::LK_OP_IN_PROGRESS);

    let ok_url = server.url("/ok");
    let ok_url_c = cstring(&ok_url);
    let mut req2 = ptr::null_mut::<lk_request_t>();
    assert_eq!(
        lk_request_new(
            session,
            cstring("GET").as_ptr(),
            3,
            ok_url_c.as_ptr(),
            ok_url.len(),
            &mut req2,
            &mut err,
        ),
        lk_status_t::LK_OK
    );

    let mut op2 = ptr::null_mut::<lk_op_t>();
    assert_eq!(
        lk_request_send_async(req2, &mut op2, &mut err),
        lk_status_t::LK_ERR
    );
    assert!(op2.is_null());
    assert_eq!(
        lk_error_code(err),
        lkrequest_ffi::lk_error_code_t::LK_ERR_RESOURCE_LIMIT_EXCEEDED
    );
    lk_error_free(err);
    lk_request_free(req2);

    assert!(matches!(
        lk_op_wait(op1, 10),
        lk_op_state_t::LK_OP_IN_PROGRESS | lk_op_state_t::LK_OP_COMPLETED_OK
    ));
    assert_eq!(lk_op_wait(op1, 0), lk_op_state_t::LK_OP_COMPLETED_OK);

    let mut response = ptr::null_mut::<lk_response_t>();
    assert_eq!(
        lk_op_take_response(op1, &mut response, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    assert_eq!(lk_response_status(response), 200);
    lk_response_free(response);
    lk_op_free(op1);

    let mut req3 = ptr::null_mut::<lk_request_t>();
    assert_eq!(
        lk_request_new(
            session,
            cstring("GET").as_ptr(),
            3,
            ok_url_c.as_ptr(),
            ok_url.len(),
            &mut req3,
            &mut err,
        ),
        lk_status_t::LK_OK
    );
    let mut op3 = ptr::null_mut::<lk_op_t>();
    assert_eq!(
        lk_request_send_async(req3, &mut op3, &mut err),
        lk_status_t::LK_OK
    );
    assert_eq!(lk_op_wait(op3, 0), lk_op_state_t::LK_OP_COMPLETED_OK);
    assert_eq!(
        lk_op_take_response(op3, &mut response, &mut err),
        lk_status_t::LK_OK
    );
    assert_eq!(lk_response_status(response), 200);
    lk_response_free(response);
    lk_op_free(op3);
    lk_request_free(req3);

    let mut req4 = ptr::null_mut::<lk_request_t>();
    assert_eq!(
        lk_request_new(
            session,
            cstring("GET").as_ptr(),
            3,
            slow_url_c.as_ptr(),
            slow_url.len(),
            &mut req4,
            &mut err,
        ),
        lk_status_t::LK_OK
    );
    let mut op4 = ptr::null_mut::<lk_op_t>();
    assert_eq!(
        lk_request_send_async(req4, &mut op4, &mut err),
        lk_status_t::LK_OK
    );
    assert_eq!(lk_op_cancel(op4), lk_status_t::LK_OK);
    assert_eq!(lk_op_wait(op4, 0), lk_op_state_t::LK_OP_CANCELLED);
    lk_op_free(op4);
    lk_request_free(req4);

    let bad_url = cstring("://bad");
    let mut req5 = ptr::null_mut::<lk_request_t>();
    assert_eq!(
        lk_request_new(
            session,
            cstring("POST").as_ptr(),
            4,
            bad_url.as_ptr(),
            6,
            &mut req5,
            &mut err,
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_request_set_json_text(req5, cstring("{\"x\":1}").as_ptr(), 7),
        lk_status_t::LK_OK
    );
    let mut op5 = ptr::null_mut::<lk_op_t>();
    assert_eq!(
        lk_request_send_async(req5, &mut op5, &mut err),
        lk_status_t::LK_OK
    );
    assert_eq!(lk_op_wait(op5, 0), lk_op_state_t::LK_OP_COMPLETED_ERR);
    assert_eq!(lk_op_take_error(op5, &mut err), lk_status_t::LK_OK);
    assert_eq!(
        lk_error_code(err),
        lkrequest_ffi::lk_error_code_t::LK_ERR_URL_PARSE
    );
    lk_error_free(err);
    lk_op_free(op5);
    lk_request_free(req5);

    lk_session_free(session);
    lk_client_free(client);
}

/// Regression: with redirects disabled, a 3xx returned as-is must report
/// `lk_response_was_redirected() == false` and `lk_response_redirect_count() == 0`
/// (nothing was followed) — consistent with the empty per-hop history.
#[test]
fn disabled_redirects_3xx_is_not_marked_redirected() {
    let server = TestServer::start();
    let client_builder = lk_client_builder_new();
    assert_eq!(
        lk_client_builder_set_preset(client_builder, cstring("chrome_131").as_ptr()),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_timeout_total(client_builder, 5_000),
        lk_status_t::LK_OK
    );
    let mut client = ptr::null_mut::<lk_client_t>();
    let mut err = ptr::null_mut::<lk_error_t>();
    assert_eq!(
        lk_client_builder_build(client_builder, &mut client, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_client_builder_free(client_builder);

    let client_clone = lk_client_clone(client);
    let session_builder = lk_session_builder_new(client_clone);
    assert_eq!(
        lk_session_builder_disable_redirects(session_builder),
        lk_status_t::LK_OK
    );
    let mut session = ptr::null_mut::<lk_session_t>();
    assert_eq!(
        lk_session_builder_build(session_builder, &mut session, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_session_builder_free(session_builder);
    lk_client_free(client_clone);

    let method = cstring("GET");
    let url = server.url("/redirect");
    let url_c = cstring(&url);
    let mut request = ptr::null_mut::<lk_request_t>();
    assert_eq!(
        lk_request_new(
            session,
            method.as_ptr(),
            3,
            url_c.as_ptr(),
            url.len(),
            &mut request,
            &mut err,
        ),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    assert_eq!(
        lk_request_set_preferred_http_version(
            request,
            lk_preferred_http_version_t::LK_PREFERRED_HTTP_VERSION_HTTP1_ONLY,
        ),
        lk_status_t::LK_OK
    );
    let mut response = ptr::null_mut::<lk_response_t>();
    assert_eq!(
        lk_request_send(request, &mut response, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_request_free(request);

    // The 3xx is delivered as-is (not followed).
    assert_eq!(lk_response_status(response), 302);
    // The reported bug: these must NOT contradict each other.
    assert!(
        !lkrequest_ffi::lk_response_was_redirected(response),
        "was_redirected must be false when redirects are disabled"
    );
    assert_eq!(
        lkrequest_ffi::lk_response_redirect_count(response),
        0,
        "redirect_count must be 0 when redirects are disabled"
    );

    lk_response_free(response);
    lk_session_free(session);
    lk_client_free(client);
}
