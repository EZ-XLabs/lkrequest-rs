use std::ffi::{c_char, c_void, CString};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ptr;
use std::slice;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use lkrequest_ffi::{
    lk_client_builder_build, lk_client_builder_disable_http3, lk_client_builder_free,
    lk_client_builder_new, lk_client_builder_set_dns_resolver,
    lk_client_builder_set_quic_profile_json, lk_client_builder_set_session_resumption_json,
    lk_client_builder_set_timeout_quic_connect, lk_client_fingerprint_info_json, lk_client_free,
    lk_client_t, lk_dns_resolver_t, lk_error_message, lk_error_t, lk_feature_supported,
    lk_request_free, lk_request_new, lk_request_send, lk_request_t, lk_response_free,
    lk_response_t, lk_response_text, lk_session_builder_build, lk_session_builder_free,
    lk_session_builder_new, lk_session_builder_set_http3_with_fallback, lk_session_free,
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

    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n = stream.read(&mut buffer).expect("read request");
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let body = b"resolver ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .and_then(|_| stream.write_all(body))
        .expect("write response");
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

unsafe fn error_message_string(err: *const lk_error_t) -> String {
    if err.is_null() {
        return "<null error>".to_string();
    }
    let mut ptr = ptr::null();
    let mut len = 0usize;
    assert_eq!(
        lk_error_message(err, &mut ptr, &mut len),
        lk_status_t::LK_OK
    );
    view_string(ptr, len)
}

struct ResolverContext {
    resolve_json: CString,
    https_json: Option<CString>,
    resolve_calls: AtomicUsize,
    https_calls: AtomicUsize,
    destroy_calls: Arc<AtomicUsize>,
}

unsafe extern "C" fn dns_resolve_callback(
    context: *mut c_void,
    host_ptr: *const c_char,
    host_len: usize,
    _port: u16,
    out_json_ptr: *mut *const c_char,
    out_json_len: *mut usize,
) -> lk_status_t {
    let ctx = &*(context.cast::<ResolverContext>());
    let host =
        str::from_utf8(slice::from_raw_parts(host_ptr.cast::<u8>(), host_len)).expect("host utf8");
    if host != "ffi-dns.local" {
        *out_json_ptr = ptr::null();
        *out_json_len = 0;
        return lk_status_t::LK_ERR;
    }

    ctx.resolve_calls.fetch_add(1, Ordering::Relaxed);
    *out_json_ptr = ctx.resolve_json.as_ptr();
    *out_json_len = ctx.resolve_json.as_bytes().len();
    lk_status_t::LK_OK
}

unsafe extern "C" fn dns_lookup_https_callback(
    context: *mut c_void,
    host_ptr: *const c_char,
    host_len: usize,
    out_json_ptr: *mut *const c_char,
    out_json_len: *mut usize,
) -> lk_status_t {
    let ctx = &*(context.cast::<ResolverContext>());
    let host =
        str::from_utf8(slice::from_raw_parts(host_ptr.cast::<u8>(), host_len)).expect("host utf8");
    if host != "ffi-dns.local" {
        *out_json_ptr = ptr::null();
        *out_json_len = 0;
        return lk_status_t::LK_ERR;
    }

    ctx.https_calls.fetch_add(1, Ordering::Relaxed);
    if let Some(json) = &ctx.https_json {
        *out_json_ptr = json.as_ptr();
        *out_json_len = json.as_bytes().len();
    } else {
        *out_json_ptr = ptr::null();
        *out_json_len = 0;
    }
    lk_status_t::LK_OK
}

unsafe extern "C" fn dns_resolver_destroy(context: *mut c_void) {
    let ctx = Box::from_raw(context.cast::<ResolverContext>());
    ctx.destroy_calls.fetch_add(1, Ordering::Relaxed);
}

fn make_dns_resolver(addr: SocketAddr, destroy_calls: Arc<AtomicUsize>) -> lk_dns_resolver_t {
    let resolve_json = serde_json::json!([addr.to_string()]).to_string();
    let https_json = serde_json::json!({
        "alpn": ["h3"],
        "port": addr.port(),
    })
    .to_string();

    let context = Box::new(ResolverContext {
        resolve_json: cstring(&resolve_json),
        https_json: Some(cstring(&https_json)),
        resolve_calls: AtomicUsize::new(0),
        https_calls: AtomicUsize::new(0),
        destroy_calls,
    });

    lk_dns_resolver_t {
        context: Box::into_raw(context).cast(),
        resolve: Some(dns_resolve_callback),
        lookup_https: Some(dns_lookup_https_callback),
        destroy: Some(dns_resolver_destroy),
    }
}

fn sample_quic_profile_json() -> String {
    serde_json::json!({
        "transport_params": {
            "max_idle_timeout": 30000,
            "initial_max_data": 15728640,
            "initial_max_stream_data_bidi_local": 6291456,
            "initial_max_stream_data_bidi_remote": 6291456,
            "initial_max_stream_data_uni": 6291456,
            "initial_max_streams_bidi": 100,
            "initial_max_streams_uni": 100,
            "active_connection_id_limit": 2,
            "send_min_ack_delay": false,
            "send_reserved_transport_parameter": false,
            "extra_transport_parameters": [[17, "000000019a9aca7a00000001"], [1706645775112002058u64, ""], [12583, "8009df94"]],
            "transport_parameter_order": [3, 17, 9, 8, 32, 1, 6, 15, 4, 1706645775112002058u64, 12583, 7, 5],
            "grease_transport_params": false
        },
        "h3": {
            "settings": [[1, 65536], [6, 262144], [7, 100], [51, 1]],
            "grease_settings": true,
            "pseudo_header_order": ["method", "authority", "scheme", "path"],
            "qpack_max_table_capacity": 65536,
            "qpack_blocked_streams": 100,
            "max_field_section_size": 262144,
            "priority_updates": []
        },
        "connection_id_length": 0,
        "initial_destination_connection_id_length": 8,
        "packetization": {
            "initial_mtu": 1250,
            "initial_datagram_size": 1250,
            "disable_mtu_discovery": false,
            "enable_segmentation_offload": false,
            "enable_ecn": false
        }
    })
    .to_string()
}

#[test]
fn dns_resolver_callbacks_and_quic_h3_builder_extensions_work() {
    let server = TestServer::start();
    let destroy_calls = Arc::new(AtomicUsize::new(0));

    unsafe {
        assert!(lk_feature_supported(cstring("dns").as_ptr()));
        assert!(lk_feature_supported(
            cstring("dns-custom-resolver").as_ptr()
        ));
        assert!(lk_feature_supported(cstring("session-resumption").as_ptr()));
        assert!(lk_feature_supported(
            cstring("quic-connect-timeout").as_ptr()
        ));
        assert_eq!(
            lk_feature_supported(cstring("quic-h3").as_ptr()),
            cfg!(feature = "quic-h3")
        );
        assert_eq!(
            lk_feature_supported(cstring("quic-profile-json").as_ptr()),
            cfg!(feature = "quic-h3")
        );
        assert_eq!(
            lk_feature_supported(cstring("http3").as_ptr()),
            cfg!(feature = "quic-h3")
        );
        assert_eq!(
            lk_feature_supported(cstring("http3-with-fallback").as_ptr()),
            cfg!(feature = "quic-h3")
        );

        let builder = lk_client_builder_new();
        let mut err = ptr::null_mut::<lk_error_t>();

        assert_eq!(
            lk_client_builder_set_timeout_quic_connect(builder, 3_210),
            lk_status_t::LK_OK
        );

        let session_resumption_json = serde_json::json!({
            "tls13_psk": false,
            "tls12_session_ticket": true,
            "max_tickets_per_host": 2,
            "store_tickets": true
        })
        .to_string();
        assert_eq!(
            lk_client_builder_set_session_resumption_json(
                builder,
                cstring(&session_resumption_json).as_ptr(),
                session_resumption_json.len(),
            ),
            lk_status_t::LK_OK
        );

        assert_eq!(
            lk_client_builder_set_dns_resolver(
                builder,
                make_dns_resolver(server.addr, Arc::clone(&destroy_calls)),
            ),
            lk_status_t::LK_OK
        );

        let mut client = ptr::null_mut::<lk_client_t>();
        assert_eq!(
            lk_client_builder_build(builder, &mut client, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_client_builder_free(builder);

        let mut fingerprint_ptr = ptr::null();
        let mut fingerprint_len = 0usize;
        assert_eq!(
            lk_client_fingerprint_info_json(
                client,
                &mut fingerprint_ptr,
                &mut fingerprint_len,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        let fingerprint: serde_json::Value =
            serde_json::from_str(&view_string(fingerprint_ptr, fingerprint_len))
                .expect("fingerprint json");
        assert_eq!(fingerprint["tls"]["session_resumption"]["tls13_psk"], false);
        assert_eq!(
            fingerprint["tls"]["session_resumption"]["max_tickets_per_host"],
            2
        );

        let fallback_builder = lk_session_builder_new(client);
        assert_eq!(
            lk_session_builder_set_http3_with_fallback(fallback_builder),
            lk_status_t::LK_OK
        );
        let mut fallback_session = ptr::null_mut::<lk_session_t>();
        assert_eq!(
            lk_session_builder_build(fallback_builder, &mut fallback_session, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());
        lk_session_builder_free(fallback_builder);
        lk_session_free(fallback_session);

        let mut session = ptr::null_mut::<lk_session_t>();
        assert_eq!(
            lkrequest_ffi::lk_session_new(client, &mut session, &mut err),
            lk_status_t::LK_OK
        );
        assert!(err.is_null());

        let url = format!("http://ffi-dns.local:{}/ok", server.addr.port());
        let mut request = ptr::null_mut::<lk_request_t>();
        assert_eq!(
            lk_request_new(
                session,
                cstring("GET").as_ptr(),
                3,
                cstring(&url).as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );

        let mut response = ptr::null_mut::<lk_response_t>();
        let send_status = lk_request_send(request, &mut response, &mut err);
        assert_eq!(
            send_status,
            lk_status_t::LK_OK,
            "request send failed: {}",
            error_message_string(err),
        );
        assert!(err.is_null());
        lk_request_free(request);

        let mut text_ptr = ptr::null();
        let mut text_len = 0usize;
        assert_eq!(
            lk_response_text(response, &mut text_ptr, &mut text_len, &mut err),
            lk_status_t::LK_OK
        );
        assert_eq!(view_string(text_ptr, text_len), "resolver ok");
        lk_response_free(response);

        lk_session_free(session);
        lk_client_free(client);
        assert_eq!(destroy_calls.load(Ordering::Relaxed), 1);

        let quic_json = sample_quic_profile_json();
        let quic_builder = lk_client_builder_new();
        let quic_status = lk_client_builder_set_quic_profile_json(
            quic_builder,
            cstring(&quic_json).as_ptr(),
            quic_json.len(),
        );

        if cfg!(feature = "quic-h3") {
            assert_eq!(quic_status, lk_status_t::LK_OK);

            let mut quic_client = ptr::null_mut::<lk_client_t>();
            assert_eq!(
                lk_client_builder_build(quic_builder, &mut quic_client, &mut err),
                lk_status_t::LK_OK
            );
            assert!(err.is_null());
            lk_client_builder_free(quic_builder);

            assert_eq!(
                lk_client_fingerprint_info_json(
                    quic_client,
                    &mut fingerprint_ptr,
                    &mut fingerprint_len,
                    &mut err,
                ),
                lk_status_t::LK_OK
            );
            let quic_fingerprint: serde_json::Value =
                serde_json::from_str(&view_string(fingerprint_ptr, fingerprint_len))
                    .expect("quic fingerprint json");
            assert_eq!(quic_fingerprint["quic"]["connection_id_length"], 0);
            assert_eq!(
                quic_fingerprint["quic"]["initial_destination_connection_id_length"],
                8
            );
            assert_eq!(
                quic_fingerprint["quic"]["packetization"]["initial_mtu"],
                1250
            );
            assert_eq!(
                quic_fingerprint["quic"]["packetization"]["initial_datagram_size"],
                1250
            );
            assert_eq!(
                quic_fingerprint["quic"]["packetization"]["enable_segmentation_offload"],
                false
            );
            assert_eq!(
                quic_fingerprint["quic"]["packetization"]["enable_ecn"],
                false
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["send_min_ack_delay"],
                false
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["send_reserved_transport_parameter"],
                false
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["extra_transport_parameters"][0][0],
                17
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["extra_transport_parameters"][1][0],
                1706645775112002058u64
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["extra_transport_parameters"][2][1],
                "8009df94"
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["transport_parameter_order"][0],
                3
            );
            assert_eq!(
                quic_fingerprint["quic"]["transport_params"]["transport_parameter_order"][9],
                1706645775112002058u64
            );
            lk_client_free(quic_client);

            let disabled_builder = lk_client_builder_new();
            assert_eq!(
                lk_client_builder_set_quic_profile_json(
                    disabled_builder,
                    cstring(&quic_json).as_ptr(),
                    quic_json.len(),
                ),
                lk_status_t::LK_OK
            );
            assert_eq!(
                lk_client_builder_disable_http3(disabled_builder),
                lk_status_t::LK_OK
            );

            let mut disabled_client = ptr::null_mut::<lk_client_t>();
            assert_eq!(
                lk_client_builder_build(disabled_builder, &mut disabled_client, &mut err),
                lk_status_t::LK_OK
            );
            assert!(err.is_null());
            lk_client_builder_free(disabled_builder);

            assert_eq!(
                lk_client_fingerprint_info_json(
                    disabled_client,
                    &mut fingerprint_ptr,
                    &mut fingerprint_len,
                    &mut err,
                ),
                lk_status_t::LK_OK
            );
            let disabled_fingerprint: serde_json::Value =
                serde_json::from_str(&view_string(fingerprint_ptr, fingerprint_len))
                    .expect("disabled fingerprint json");
            assert!(disabled_fingerprint["quic"].is_null());
            lk_client_free(disabled_client);
        } else {
            assert_eq!(quic_status, lk_status_t::LK_ERR);
            lk_client_builder_free(quic_builder);
        }
    }
}
