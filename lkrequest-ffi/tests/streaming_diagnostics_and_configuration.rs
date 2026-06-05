use std::ffi::{c_char, CStr, CString};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use lkrequest_ffi::{
    lk_client_builder_add_cookie_order, lk_client_builder_add_default_header,
    lk_client_builder_add_h3_header_order, lk_client_builder_add_header_order,
    lk_client_builder_build, lk_client_builder_free, lk_client_builder_new,
    lk_client_builder_set_ech_config, lk_client_builder_set_fallback_h2_to_h1,
    lk_client_builder_set_fallback_proxy_to_direct, lk_client_builder_set_h2_preset,
    lk_client_builder_set_keylog_file, lk_client_builder_set_max_connections_per_session,
    lk_client_builder_set_max_header_count, lk_client_builder_set_max_header_size,
    lk_client_builder_set_max_headers_total_size, lk_client_builder_set_max_response_body_size,
    lk_client_builder_set_min_transfer_rate, lk_client_builder_set_retry_on_connection_close,
    lk_client_builder_set_tcp_fingerprint_ja4t, lk_error_code, lk_error_free,
    lk_error_get_diagnostics_json, lk_error_message, lk_error_t, lk_feature_supported,
    lk_http_version_t, lk_log_init, lk_op_free, lk_op_poll, lk_op_state_t, lk_op_t,
    lk_op_take_chunk, lk_op_take_error, lk_op_take_streaming_response, lk_op_wait,
    lk_preset_get_detail_json, lk_preset_list_json, lk_request_add_h3_header_order,
    lk_request_add_header, lk_request_free, lk_request_new, lk_request_send, lk_request_send_async,
    lk_request_send_streaming, lk_request_send_streaming_async, lk_request_set_accept_encoding,
    lk_request_set_proxy, lk_request_set_version, lk_request_t, lk_response_free,
    lk_response_get_diagnostics_json, lk_response_get_header_by_name, lk_response_status,
    lk_response_t, lk_session_builder_add_h3_header_order, lk_session_builder_build,
    lk_session_builder_free, lk_session_builder_new,
    lk_session_builder_set_default_accept_encoding, lk_session_builder_set_ech_config,
    lk_session_builder_set_http1_only, lk_session_builder_set_idle_timeout,
    lk_session_builder_set_max_connections, lk_session_builder_set_retry_fixed, lk_session_free,
    lk_session_t, lk_status_t, lk_stream_close, lk_stream_copy_chunk, lk_stream_read,
    lk_stream_read_async, lk_streaming_response_free, lk_streaming_response_header_count,
    lk_streaming_response_header_name_at, lk_streaming_response_status, lk_streaming_response_t,
};

struct TestServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        handle_connection(stream);
                    }
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
            thread.join().expect("join server");
        }
    }
}

struct HttpRequest {
    path: String,
    headers: Vec<(String, String)>,
}

fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    let request = read_http_request(&mut stream).expect("request");
    let route = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());

    match route {
        "/stream" => write_chunked_response(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/plain"), ("X-Stream", "plain")],
            &[b"hello ".as_ref(), b"world".as_ref()],
            40,
        ),
        "/stream-slow" => write_chunked_response(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/plain"), ("X-Stream", "slow")],
            &[b"slow ".as_ref(), b"stream".as_ref()],
            150,
        ),
        "/stream-gzip" => {
            let encoded = gzip_bytes(b"compressed stream");
            let mid = encoded.len() / 2;
            write_chunked_response(
                &mut stream,
                "200 OK",
                &[
                    ("Content-Type", "text/plain"),
                    ("Content-Encoding", "gzip"),
                    ("X-Stream", "gzip"),
                ],
                &[&encoded[..mid], &encoded[mid..]],
                30,
            );
        }
        "/stream-unsupported" => write_chunked_response(
            &mut stream,
            "200 OK",
            &[
                ("Content-Type", "application/octet-stream"),
                ("Content-Encoding", "lz4"),
            ],
            &[b"opaque".as_ref()],
            20,
        ),
        _ => {
            let accept_encoding = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            let default_header = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-default"))
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            let body = b"ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Accept-Encoding: {}\r\nX-Default: {}\r\nConnection: close\r\n\r\n",
                body.len(),
                accept_encoding,
                default_header
            );
            stream
                .write_all(response.as_bytes())
                .and_then(|_| stream.write_all(body))
                .expect("write response");
        }
    }
}

fn write_chunked_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    chunks: &[&[u8]],
    delay_ms: u64,
) {
    let mut response =
        format!("HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n");
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write headers");
    stream.flush().expect("flush headers");

    for chunk in chunks {
        let header = format!("{:X}\r\n", chunk.len());
        if stream.write_all(header.as_bytes()).is_err() {
            return;
        }
        if stream.write_all(chunk).is_err() {
            return;
        }
        if stream.write_all(b"\r\n").is_err() {
            return;
        }
        if stream.flush().is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(delay_ms));
    }

    let _ = stream.write_all(b"0\r\n\r\n");
    let _ = stream.flush();
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
                "closed before request",
            ));
        }
        data.extend_from_slice(&buffer[..n]);
        if let Some(idx) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = idx;
            break;
        }
    }

    let header_text = str::from_utf8(&data[..header_end]).expect("header utf8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().expect("method").to_string();
    let path = parts.next().expect("path").to_string();
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').expect("header");
            (name.trim().to_string(), value.trim().to_string())
        })
        .collect();

    Ok(HttpRequest { path, headers })
}

fn gzip_bytes(input: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn cstring(value: &str) -> CString {
    CString::new(value).expect("cstring")
}

unsafe fn view_string(ptr: *const c_char) -> String {
    CStr::from_ptr(ptr).to_str().expect("utf8").to_string()
}

unsafe fn view_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(ptr, len).to_vec()
    }
}

unsafe fn new_client_and_session() -> (*mut lkrequest_ffi::lk_client_t, *mut lk_session_t) {
    let mut client = ptr::null_mut();
    let mut err = ptr::null_mut::<lk_error_t>();
    let builder = lk_client_builder_new();
    assert_eq!(
        lk_client_builder_add_default_header(
            builder,
            cstring("x-default").as_ptr(),
            "x-default".len(),
            cstring("ffi").as_ptr(),
            3,
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_add_header_order(
            builder,
            cstring("x-default").as_ptr(),
            "x-default".len(),
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_add_h3_header_order(
            builder,
            cstring("priority").as_ptr(),
            "priority".len(),
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_add_cookie_order(
            builder,
            cstring("session_id").as_ptr(),
            "session_id".len(),
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_h2_preset(builder, cstring("firefox_147").as_ptr()),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_ech_config(builder, b"ech".as_ptr(), 3),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_tcp_fingerprint_ja4t(
            builder,
            cstring("64240_2-1-3-1-1-4_1460_8").as_ptr(),
            "64240_2-1-3-1-1-4_1460_8".len(),
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_max_response_body_size(builder, 4096),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_max_header_count(builder, 64),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_max_header_size(builder, 4096),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_max_headers_total_size(builder, 16384),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_min_transfer_rate(builder, 16, 1000),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_max_connections_per_session(builder, 8),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_fallback_h2_to_h1(builder, true),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_fallback_proxy_to_direct(builder, false),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_set_retry_on_connection_close(builder, true),
        lk_status_t::LK_OK
    );
    let keylog_path: PathBuf = std::env::temp_dir().join("lkrequest_ffi_keylog.log");
    let keylog_path_str = keylog_path.to_string_lossy().to_string();
    assert_eq!(
        lk_client_builder_set_keylog_file(
            builder,
            cstring(&keylog_path_str).as_ptr(),
            keylog_path_str.len(),
        ),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_client_builder_build(builder, &mut client, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_client_builder_free(builder);

    let session_builder = lk_session_builder_new(client);
    assert_eq!(
        lk_session_builder_set_http1_only(session_builder),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_session_builder_set_default_accept_encoding(session_builder, 0b0001),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_session_builder_set_ech_config(session_builder, b"session-ech".as_ptr(), 11),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_session_builder_set_max_connections(session_builder, 4),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_session_builder_set_idle_timeout(session_builder, 1_000),
        lk_status_t::LK_OK
    );
    assert_eq!(
        lk_session_builder_set_retry_fixed(session_builder, 2, 25),
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
    let mut session = ptr::null_mut();
    assert_eq!(
        lk_session_builder_build(session_builder, &mut session, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_session_builder_free(session_builder);
    (client, session)
}

#[test]
fn streaming_requests_support_sync_and_async_chunk_reading() {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();

        let url = server.url("/stream");
        let url_c = cstring(&url);
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(request, &mut stream, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request);
        assert_eq!(lk_streaming_response_status(stream), 200);
        assert!(lk_streaming_response_header_count(stream) >= 1);

        let mut header_name_ptr = ptr::null();
        let mut header_name_len = 0usize;
        assert_eq!(
            lk_streaming_response_header_name_at(
                stream,
                0,
                &mut header_name_ptr,
                &mut header_name_len,
            ),
            lk_status_t::LK_OK
        );
        assert!(!view_bytes(header_name_ptr.cast(), header_name_len).is_empty());

        let mut body = Vec::new();
        loop {
            let mut chunk = lkrequest_ffi::lk_chunk_view_t::default();
            assert_eq!(
                lk_stream_read(stream, &mut chunk, &mut err),
                lk_status_t::LK_OK
            );
            let copied = view_bytes(chunk.data, chunk.len);
            if !copied.is_empty() {
                let mut copied_buf = vec![0u8; 64];
                let mut copied_len = 0usize;
                assert_eq!(
                    lk_stream_copy_chunk(
                        stream,
                        copied_buf.as_mut_ptr(),
                        copied_buf.len(),
                        &mut copied_len,
                    ),
                    lk_status_t::LK_OK
                );
                copied_buf.truncate(copied_len);
                assert_eq!(copied_buf, copied);
            }
            body.extend_from_slice(&copied);
            if chunk.is_final {
                break;
            }
        }
        assert_eq!(body, b"hello world");
        assert_eq!(lk_stream_close(stream), lk_status_t::LK_OK);
        let mut chunk = lkrequest_ffi::lk_chunk_view_t::default();
        assert_eq!(
            lk_stream_read(stream, &mut chunk, &mut err),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_STREAM_CLOSED
        );
        lk_error_free(err);
        lk_streaming_response_free(stream);

        let gzip_url = server.url("/stream-gzip");
        let gzip_c = cstring(&gzip_url);
        let mut request2 = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                gzip_c.as_ptr(),
                gzip_url.len(),
                &mut request2,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut op = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_request_send_streaming_async(request2, &mut op, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request2);
        assert_eq!(lk_op_wait(op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);

        let mut stream2 = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_op_take_streaming_response(op, &mut stream2, &mut err),
            lk_status_t::LK_OK
        );
        lk_op_free(op);

        let slow_url = server.url("/stream-slow");
        let slow_c = cstring(&slow_url);
        let mut request3 = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                slow_c.as_ptr(),
                slow_url.len(),
                &mut request3,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut stream3 = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(request3, &mut stream3, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request3);

        let mut read_op = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_stream_read_async(stream3, &mut read_op, &mut err),
            lk_status_t::LK_OK
        );
        let mut read_op_2 = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_stream_read_async(stream3, &mut read_op_2, &mut err),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_BUSY
        );
        lk_error_free(err);
        assert!(read_op_2.is_null());
        lk_op_wait(read_op, 0);
        let mut first_chunk = lkrequest_ffi::lk_chunk_view_t::default();
        assert_eq!(
            lk_op_take_chunk(read_op, &mut first_chunk, &mut err),
            lk_status_t::LK_OK
        );
        lk_op_free(read_op);
        assert!(!view_bytes(first_chunk.data, first_chunk.len).is_empty());
        lk_stream_close(stream3);
        lk_streaming_response_free(stream3);

        let mut decoded = Vec::new();
        loop {
            let mut read_chunk_op = ptr::null_mut::<lk_op_t>();
            assert_eq!(
                lk_stream_read_async(stream2, &mut read_chunk_op, &mut err),
                lk_status_t::LK_OK
            );
            assert!(matches!(
                lk_op_poll(read_chunk_op),
                lk_op_state_t::LK_OP_IN_PROGRESS | lk_op_state_t::LK_OP_COMPLETED_OK
            ));
            assert_eq!(
                lk_op_wait(read_chunk_op, 0),
                lk_op_state_t::LK_OP_COMPLETED_OK
            );
            let mut chunk = lkrequest_ffi::lk_chunk_view_t::default();
            assert_eq!(
                lk_op_take_chunk(read_chunk_op, &mut chunk, &mut err),
                lk_status_t::LK_OK
            );
            decoded.extend_from_slice(&view_bytes(chunk.data, chunk.len));
            let is_final = chunk.is_final;
            lk_op_free(read_chunk_op);
            if is_final {
                break;
            }
        }
        assert_eq!(decoded, b"compressed stream");

        let mut eof_op = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_stream_read_async(stream2, &mut eof_op, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(lk_op_wait(eof_op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);
        let mut eof_chunk = lkrequest_ffi::lk_chunk_view_t::default();
        assert_eq!(
            lk_op_take_chunk(eof_op, &mut eof_chunk, &mut err),
            lk_status_t::LK_OK
        );
        assert!(eof_chunk.is_final);
        assert_eq!(eof_chunk.len, 0);
        lk_op_free(eof_op);
        lk_streaming_response_free(stream2);

        lk_session_free(session);
        lkrequest_ffi::lk_client_free(client);
    }
}

#[test]
fn unsupported_stream_encodings_map_to_decompression_errors() {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();
        let url = server.url("/stream-unsupported");
        let url_c = cstring(&url);
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(request, &mut stream, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request);

        let mut chunk = lkrequest_ffi::lk_chunk_view_t::default();
        assert_eq!(
            lk_stream_read(stream, &mut chunk, &mut err),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_DECOMPRESSION_FAILED
        );
        let msg = {
            let mut ptr = ptr::null();
            let mut len = 0usize;
            assert_eq!(
                lk_error_message(err, &mut ptr, &mut len),
                lk_status_t::LK_OK
            );
            str::from_utf8(slice::from_raw_parts(ptr.cast::<u8>(), len))
                .unwrap()
                .to_string()
        };
        assert!(msg.contains("unsupported"));
        lk_error_free(err);
        lk_streaming_response_free(stream);
        lk_session_free(session);
        lkrequest_ffi::lk_client_free(client);
    }
}

#[test]
fn preset_diagnostics_and_logging_apis_work_together() {
    let server = TestServer::start();

    unsafe {
        assert!(lk_feature_supported(cstring("streaming").as_ptr()));
        assert!(lk_feature_supported(cstring("preset-discovery").as_ptr()));
        assert!(lk_feature_supported(cstring("diagnostics").as_ptr()));
        assert!(lk_feature_supported(cstring("logging").as_ptr()));

        let mut list_ptr = ptr::null();
        assert_eq!(lk_preset_list_json(&mut list_ptr), lk_status_t::LK_OK);
        let preset_list: serde_json::Value = serde_json::from_str(&view_string(list_ptr)).unwrap();
        assert!(preset_list
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "chrome_144"));

        let mut detail_ptr = ptr::null();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_preset_get_detail_json(
                cstring("firefox_147").as_ptr(),
                "firefox_147".len(),
                &mut detail_ptr,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let detail: serde_json::Value = serde_json::from_str(&view_string(detail_ptr)).unwrap();
        assert_eq!(detail["name"], "firefox_147");
        assert!(detail["header_order"].is_array());
        assert!(detail.get("quic_profile").is_some());
        assert!(detail.get("h3_header_order").is_some());

        let log_path: PathBuf = std::env::temp_dir().join("lkrequest_ffi_phase57.log");
        let _ = std::fs::remove_file(&log_path);
        assert_eq!(
            lk_log_init(
                cstring("trace").as_ptr(),
                cstring(log_path.to_str().unwrap()).as_ptr(),
            ),
            lk_status_t::LK_OK
        );

        let (client, session) = new_client_and_session();
        let url = server.url("/ok");
        let url_c = cstring(&url);
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_accept_encoding(request, 0b0001),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_version(request, lk_http_version_t::LK_HTTP_VERSION_11),
            lk_status_t::LK_OK
        );
        let bad_proxy = cstring("not-a-proxy");
        assert_eq!(
            lk_request_set_proxy(request, bad_proxy.as_ptr(), "not-a-proxy".len()),
            lk_status_t::LK_ERR
        );

        let good_proxy = cstring("http://127.0.0.1:8080");
        let mut request2 = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut request2,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_add_header(
                request2,
                cstring("x-test").as_ptr(),
                6,
                cstring("1").as_ptr(),
                1,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_add_h3_header_order(
                request2,
                cstring("priority").as_ptr(),
                "priority".len(),
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_request_set_proxy(request2, good_proxy.as_ptr(), "http://127.0.0.1:8080".len()),
            lk_status_t::LK_OK
        );
        lk_request_free(request2);

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(request, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(request);
        assert_eq!(lk_response_status(response), 200);

        let mut header_ptr = ptr::null();
        let mut header_len = 0usize;
        assert_eq!(
            lk_response_get_header_by_name(
                response,
                cstring("x-accept-encoding").as_ptr(),
                "x-accept-encoding".len(),
                &mut header_ptr,
                &mut header_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(view_bytes(header_ptr, header_len), b"gzip");
        assert_eq!(
            lk_response_get_header_by_name(
                response,
                cstring("x-default").as_ptr(),
                "x-default".len(),
                &mut header_ptr,
                &mut header_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(view_bytes(header_ptr, header_len), b"ffi");

        let mut diag_ptr = ptr::null();
        assert_eq!(
            lk_response_get_diagnostics_json(response, &mut diag_ptr),
            lk_status_t::LK_OK
        );
        let diag: serde_json::Value = serde_json::from_str(&view_string(diag_ptr)).unwrap();
        assert_eq!(diag["schema_version"], 1);
        assert!(diag["dns_ms"].is_number());
        assert!(diag["tcp_ms"].is_number());
        assert!(diag["ttfb_ms"].is_number());
        assert!(diag["total_ms"].is_number());
        assert!(diag["remote_addr"].is_string());
        assert!(diag["protocol"].is_string() || diag["protocol"].is_null());
        lk_response_free(response);

        let mut bad_req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring("://bad").as_ptr(),
                6,
                &mut bad_req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut op = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_request_send_async(bad_req, &mut op, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(bad_req);
        assert_eq!(lk_op_wait(op, 0), lk_op_state_t::LK_OP_COMPLETED_ERR);
        assert_eq!(lk_op_take_error(op, &mut err), lk_status_t::LK_OK);
        let mut err_diag_ptr = ptr::null();
        assert_eq!(
            lk_error_get_diagnostics_json(err, &mut err_diag_ptr),
            lk_status_t::LK_OK
        );
        let err_diag: serde_json::Value = serde_json::from_str(&view_string(err_diag_ptr)).unwrap();
        assert_eq!(err_diag["schema_version"], 1);
        assert!(err_diag["total_ms"].is_number());
        lk_error_free(err);
        lk_op_free(op);

        lk_session_free(session);
        lkrequest_ffi::lk_client_free(client);

        std::thread::sleep(Duration::from_millis(50));
        let metadata = std::fs::metadata(&log_path).expect("log metadata");
        assert!(metadata.len() > 0);
    }
}

#[test]
fn sync_streaming_error_paths_preserve_diagnostics_and_closed_reads_release_capacity() {
    let server = TestServer::start();

    unsafe {
        let builder = lk_client_builder_new();
        assert_eq!(
            lkrequest_ffi::lk_client_builder_set_max_outstanding_ops(builder, 1),
            lk_status_t::LK_OK
        );
        let mut client = ptr::null_mut();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_client_builder_build(builder, &mut client, &mut err),
            lk_status_t::LK_OK
        );
        lk_client_builder_free(builder);

        let mut session = ptr::null_mut::<lk_session_t>();
        assert_eq!(
            lkrequest_ffi::lk_session_new(client, &mut session, &mut err),
            lk_status_t::LK_OK
        );

        let mut bad_req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring("://bad").as_ptr(),
                6,
                &mut bad_req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(bad_req, &mut response, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(response.is_null());
        let mut diag_ptr = ptr::null();
        assert_eq!(
            lk_error_get_diagnostics_json(err, &mut diag_ptr),
            lk_status_t::LK_OK
        );
        let diag: serde_json::Value = serde_json::from_str(&view_string(diag_ptr)).unwrap();
        assert!(diag["total_ms"].is_number());
        lk_error_free(err);
        lk_request_free(bad_req);

        let mut bad_stream_req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring("://bad").as_ptr(),
                6,
                &mut bad_stream_req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut bad_stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(bad_stream_req, &mut bad_stream, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(bad_stream.is_null());
        assert_eq!(
            lk_error_get_diagnostics_json(err, &mut diag_ptr),
            lk_status_t::LK_OK
        );
        let diag2: serde_json::Value = serde_json::from_str(&view_string(diag_ptr)).unwrap();
        assert!(diag2["total_ms"].is_number());
        lk_error_free(err);
        lk_request_free(bad_stream_req);

        let stream_url = server.url("/stream");
        let stream_url_c = cstring(&stream_url);
        let mut stream_req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                stream_url_c.as_ptr(),
                stream_url.len(),
                &mut stream_req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(stream_req, &mut stream, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(stream_req);
        assert_eq!(lk_stream_close(stream), lk_status_t::LK_OK);

        let mut read_op = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_stream_read_async(stream, &mut read_op, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(read_op.is_null());
        lk_error_free(err);

        let ok_url = server.url("/ok");
        let ok_url_c = cstring(&ok_url);
        let mut req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                ok_url_c.as_ptr(),
                ok_url.len(),
                &mut req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut op = ptr::null_mut::<lk_op_t>();
        assert_eq!(
            lk_request_send_async(req, &mut op, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req);
        lk_op_free(op);
        lk_streaming_response_free(stream);
        lk_session_free(session);
        lkrequest_ffi::lk_client_free(client);
    }
}

// ── fingerprint randomization (lk_client_builder_set_randomize) ──────────────

/// off / extension_order are always available and a client builds with them.
#[test]
fn client_builder_randomize_basic_modes_build() {
    use lkrequest_ffi::lk_randomize_mode_t::{LK_RANDOMIZE_EXTENSION_ORDER, LK_RANDOMIZE_OFF};
    use lkrequest_ffi::lk_status_t::LK_OK;
    use std::ptr;
    for mode in [LK_RANDOMIZE_OFF, LK_RANDOMIZE_EXTENSION_ORDER] {
        let builder = lkrequest_ffi::lk_client_builder_new();
        assert_eq!(
            lkrequest_ffi::lk_client_builder_set_randomize(builder, mode, 0),
            LK_OK
        );
        let mut client = ptr::null_mut();
        let mut err = ptr::null_mut::<lkrequest_ffi::lk_error_t>();
        assert_eq!(
            lkrequest_ffi::lk_client_builder_build(builder, &mut client, &mut err),
            LK_OK
        );
        assert!(err.is_null());
        lkrequest_ffi::lk_client_builder_free(builder);
        lkrequest_ffi::lk_client_free(client);
    }
}

/// Without `synthetic-fp`, the synthetic modes are rejected (not LK_OK).
#[cfg(not(feature = "synthetic-fp"))]
#[test]
fn client_builder_randomize_synthetic_rejected_without_feature() {
    use lkrequest_ffi::lk_randomize_mode_t::{LK_RANDOMIZE_FULL, LK_RANDOMIZE_RECOMBINE};
    use lkrequest_ffi::lk_status_t::LK_OK;
    for mode in [LK_RANDOMIZE_RECOMBINE, LK_RANDOMIZE_FULL] {
        let builder = lkrequest_ffi::lk_client_builder_new();
        assert_ne!(
            lkrequest_ffi::lk_client_builder_set_randomize(builder, mode, 0),
            LK_OK,
            "synthetic mode should error without the synthetic-fp feature"
        );
        lkrequest_ffi::lk_client_builder_free(builder);
    }
}

/// With `synthetic-fp`, recombine/full (incl. a layer mask) set and build OK.
#[cfg(feature = "synthetic-fp")]
#[test]
fn client_builder_randomize_synthetic_modes_build() {
    use lkrequest_ffi::lk_randomize_mode_t::{LK_RANDOMIZE_FULL, LK_RANDOMIZE_RECOMBINE};
    use lkrequest_ffi::lk_status_t::LK_OK;
    use lkrequest_ffi::{LK_FP_LAYER_H2, LK_FP_LAYER_TLS};
    use std::ptr;
    let cases = [
        (LK_RANDOMIZE_RECOMBINE, 0u32),
        (LK_RANDOMIZE_FULL, LK_FP_LAYER_TLS | LK_FP_LAYER_H2),
    ];
    for (mode, layers) in cases {
        let builder = lkrequest_ffi::lk_client_builder_new();
        assert_eq!(
            lkrequest_ffi::lk_client_builder_set_randomize(builder, mode, layers),
            LK_OK
        );
        let mut client = ptr::null_mut();
        let mut err = ptr::null_mut::<lkrequest_ffi::lk_error_t>();
        assert_eq!(
            lkrequest_ffi::lk_client_builder_build(builder, &mut client, &mut err),
            LK_OK
        );
        assert!(err.is_null());
        lkrequest_ffi::lk_client_builder_free(builder);
        lkrequest_ffi::lk_client_free(client);
    }
}
