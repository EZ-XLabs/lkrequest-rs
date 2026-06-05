use std::ffi::{c_char, CString};
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
    lk_client_builder_build, lk_client_builder_free, lk_client_builder_new, lk_client_free,
    lk_client_t, lk_error_code, lk_error_free, lk_error_message, lk_error_t, lk_op_free,
    lk_op_state_t, lk_op_take_chunk, lk_op_take_error, lk_op_take_response,
    lk_op_take_streaming_response, lk_op_wait, lk_preset_get_detail_json, lk_request_free,
    lk_request_new, lk_request_send_async, lk_request_send_streaming,
    lk_request_send_streaming_async, lk_request_t, lk_response_free,
    lk_response_get_header_by_name, lk_response_t, lk_session_free, lk_session_new, lk_session_t,
    lk_status_t, lk_stream_close, lk_stream_read_async, lk_streaming_response_free,
    lk_streaming_response_header_count, lk_streaming_response_header_name_at,
    lk_streaming_response_header_value_at, lk_streaming_response_t,
};
#[cfg(feature = "debug-registry")]
use lkrequest_ffi::{lk_request_send, lk_response_body};

struct TestServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("server addr");
        listener.set_nonblocking(true).expect("set nonblocking");

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
            thread.join().expect("join server thread");
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let path = read_request_path(&mut stream).expect("path");
    let route = path.split('?').next().unwrap_or(path.as_str());

    match route {
        "/stream" => {
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Transfer-Encoding: chunked\r\n",
                "X-Stream: edge\r\n",
                "Connection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .expect("write headers");
            stream.write_all(b"3\r\nfoo\r\n").expect("write chunk 1");
            stream.write_all(b"0\r\n\r\n").expect("write final chunk");
        }
        _ => {
            let body = b"ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Name: value\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .and_then(|_| stream.write_all(body))
                .expect("write response");
        }
    }
}

fn read_request_path(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request completed",
            ));
        }
        data.extend_from_slice(&buffer[..n]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let request_line = str::from_utf8(&data)
        .expect("request utf8")
        .lines()
        .next()
        .expect("request line");
    Ok(request_line
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string())
}

fn cstring(value: &str) -> CString {
    CString::new(value).expect("cstring")
}

unsafe fn view_string(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    let bytes = slice::from_raw_parts(ptr.cast::<u8>(), len);
    str::from_utf8(bytes).expect("utf8").to_string()
}

unsafe fn new_client_and_session() -> (*mut lk_client_t, *mut lk_session_t) {
    let builder = lk_client_builder_new();
    let mut client = ptr::null_mut::<lk_client_t>();
    let mut err = ptr::null_mut::<lk_error_t>();
    assert_eq!(
        lk_client_builder_build(builder, &mut client, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    lk_client_builder_free(builder);

    let mut session = ptr::null_mut::<lk_session_t>();
    assert_eq!(
        lk_session_new(client, &mut session, &mut err),
        lk_status_t::LK_OK
    );
    assert!(err.is_null());
    (client, session)
}

#[test]
fn op_results_are_single_consume_and_missing_values_return_not_found() {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();

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
        let mut op = ptr::null_mut();
        assert_eq!(
            lk_request_send_async(req, &mut op, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req);
        assert_eq!(lk_op_wait(op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_op_take_response(op, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        let mut duplicate_response = response;
        assert_eq!(
            lk_op_take_response(op, &mut duplicate_response, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(duplicate_response.is_null());
        assert!(view_string_from_error(err).contains("already been consumed"));
        lk_error_free(err);

        let mut value_ptr = ptr::null();
        let mut value_len = 0usize;
        assert_eq!(
            lk_response_get_header_by_name(
                response,
                cstring("missing").as_ptr(),
                7,
                &mut value_ptr,
                &mut value_len,
                &mut err,
            ),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_NOT_FOUND
        );
        lk_error_free(err);
        lk_response_free(response);
        lk_op_free(op);

        let mut req2 = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring("://bad").as_ptr(),
                6,
                &mut req2,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut op2 = ptr::null_mut();
        assert_eq!(
            lk_request_send_async(req2, &mut op2, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req2);
        assert_eq!(lk_op_wait(op2, 0), lk_op_state_t::LK_OP_COMPLETED_ERR);

        let mut wrong_response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_op_take_response(op2, &mut wrong_response, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(view_string_from_error(err).contains("use lk_op_take_error"));
        lk_error_free(err);

        let mut first_error = ptr::null_mut::<lk_error_t>();
        assert_eq!(lk_op_take_error(op2, &mut first_error), lk_status_t::LK_OK);
        assert_eq!(
            lk_error_code(first_error),
            lkrequest_ffi::lk_error_code_t::LK_ERR_URL_PARSE
        );
        lk_error_free(first_error);

        let mut duplicate_error = first_error;
        assert_eq!(
            lk_op_take_error(op2, &mut duplicate_error),
            lk_status_t::LK_ERR
        );
        assert!(duplicate_error.is_null());
        lk_op_free(op2);

        let mut detail_ptr = ptr::null();
        assert_eq!(
            lk_preset_get_detail_json(cstring("missing").as_ptr(), 7, &mut detail_ptr, &mut err,),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_NOT_FOUND
        );
        lk_error_free(err);

        lk_session_free(session);
        lk_client_free(client);
    }
}

#[test]
fn streaming_header_access_and_close_are_idempotent() {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();
        let url = server.url("/stream");
        let url_c = cstring(&url);
        let mut req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );

        let mut stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_request_send_streaming(req, &mut stream, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req);

        assert!(lk_streaming_response_header_count(stream) >= 1);
        let mut found = false;
        for idx in 0..lk_streaming_response_header_count(stream) {
            let mut name_ptr = ptr::null();
            let mut name_len = 0usize;
            let mut value_ptr = ptr::null();
            let mut value_len = 0usize;
            assert_eq!(
                lk_streaming_response_header_name_at(stream, idx, &mut name_ptr, &mut name_len),
                lk_status_t::LK_OK
            );
            assert_eq!(
                lk_streaming_response_header_value_at(stream, idx, &mut value_ptr, &mut value_len),
                lk_status_t::LK_OK
            );
            let name = view_string(name_ptr, name_len);
            if name.eq_ignore_ascii_case("x-stream") {
                let value = str::from_utf8(slice::from_raw_parts(value_ptr, value_len))
                    .unwrap()
                    .to_string();
                assert_eq!(value, "edge");
                found = true;
            }
        }
        assert!(found);

        assert_eq!(lk_stream_close(stream), lk_status_t::LK_OK);
        assert_eq!(lk_stream_close(stream), lk_status_t::LK_OK);
        lk_streaming_response_free(stream);

        lk_session_free(session);
        lk_client_free(client);
    }
}

#[test]
fn wrong_take_apis_do_not_consume_operation_results() {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();

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
        let mut op = ptr::null_mut();
        assert_eq!(
            lk_request_send_async(req, &mut op, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req);
        assert_eq!(lk_op_wait(op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);

        let mut wrong_stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_op_take_streaming_response(op, &mut wrong_stream, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(wrong_stream.is_null());
        lk_error_free(err);

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_op_take_response(op, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_response_free(response);
        lk_op_free(op);

        let stream_url = server.url("/stream");
        let stream_url_c = cstring(&stream_url);
        let mut req2 = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                stream_url_c.as_ptr(),
                stream_url.len(),
                &mut req2,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let mut stream_op = ptr::null_mut();
        assert_eq!(
            lk_request_send_streaming_async(req2, &mut stream_op, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req2);
        assert_eq!(lk_op_wait(stream_op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);

        let mut wrong_response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_op_take_response(stream_op, &mut wrong_response, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(wrong_response.is_null());
        lk_error_free(err);

        let mut stream = ptr::null_mut::<lk_streaming_response_t>();
        assert_eq!(
            lk_op_take_streaming_response(stream_op, &mut stream, &mut err),
            lk_status_t::LK_OK
        );
        lk_op_free(stream_op);

        let mut read_op = ptr::null_mut();
        assert_eq!(
            lk_stream_read_async(stream, &mut read_op, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(lk_op_wait(read_op, 0), lk_op_state_t::LK_OP_COMPLETED_OK);

        let mut response2 = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_op_take_response(read_op, &mut response2, &mut err),
            lk_status_t::LK_ERR
        );
        assert!(response2.is_null());
        lk_error_free(err);

        let mut chunk = lkrequest_ffi::lk_chunk_view_t::default();
        assert_eq!(
            lk_op_take_chunk(read_op, &mut chunk, &mut err),
            lk_status_t::LK_OK
        );
        lk_op_free(read_op);
        lk_streaming_response_free(stream);

        lk_session_free(session);
        lk_client_free(client);
    }
}

#[cfg(feature = "debug-registry")]
#[test]
fn debug_registry_rejects_stale_response_handles() {
    let server = TestServer::start();

    unsafe {
        let (client, session) = new_client_and_session();
        let mut err = ptr::null_mut::<lk_error_t>();
        let url = server.url("/ok");
        let url_c = cstring(&url);
        let mut req = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                url_c.as_ptr(),
                url.len(),
                &mut req,
                &mut err,
            ),
            lk_status_t::LK_OK
        );

        let mut response = ptr::null_mut::<lk_response_t>();
        assert_eq!(
            lk_request_send(req, &mut response, &mut err),
            lk_status_t::LK_OK
        );
        lk_request_free(req);
        lk_response_free(response);

        let mut body_ptr = ptr::null();
        let mut body_len = 0usize;
        assert_eq!(
            lk_response_body(response, &mut body_ptr, &mut body_len),
            lk_status_t::LK_ERR
        );
        assert_eq!(
            lk_error_code(err),
            lkrequest_ffi::lk_error_code_t::LK_ERR_INVALID_HANDLE
        );
        lk_error_free(err);

        lk_session_free(session);
        lk_client_free(client);
    }
}

unsafe fn view_string_from_error(err: *const lk_error_t) -> String {
    let mut ptr = ptr::null();
    let mut len = 0usize;
    if lk_error_message(err, &mut ptr, &mut len) == lk_status_t::LK_OK {
        view_string(ptr, len)
    } else {
        String::new()
    }
}
