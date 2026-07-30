use std::ffi::c_char;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

use crate::abi::{lk_dns_config_t, lk_randomize_mode_t, lk_status_t};
use crate::conv::{read_bytes, read_c_string, read_string_parts};
use crate::error::{clear_error_out, FfiError};
use crate::handles::{
    box_into_handle, handle_drop, lk_client_builder_t, lk_client_t, lk_error_t, require_handle,
    require_handle_mut, ClientBuilderHandle, ClientBuilderState, ClientDnsSource, ClientHandle,
    ClientShared, FfiDnsResolver, PresetKind,
};
use crate::panic::{catch_status, catch_value, null_error_out};

pub(crate) fn parse_preset_name(name: &str) -> Result<PresetKind, FfiError> {
    match name {
        "chrome_131" => Ok(PresetKind::Chrome131),
        "chrome_144" | "default" => Ok(PresetKind::Chrome144),
        "chrome_145" => Ok(PresetKind::Chrome145),
        "chrome_146" => Ok(PresetKind::Chrome146),
        "chrome_147" => Ok(PresetKind::Chrome147),
        "chrome_148" => Ok(PresetKind::Chrome148),
        "chrome_149" => Ok(PresetKind::Chrome149),
        "chrome_150" => Ok(PresetKind::Chrome150),
        "firefox_133" => Ok(PresetKind::Firefox133),
        "firefox_147" => Ok(PresetKind::Firefox147),
        "safari_18" => Ok(PresetKind::Safari18),
        "safari_26" | "safari_26_2" => Ok(PresetKind::Safari26),
        _ => Err(FfiError::invalid_config(format!("unknown preset: {name}"))),
    }
}

pub(crate) fn preset_bundle(preset: PresetKind) -> lkrequest::preset::ClientPreset {
    match preset {
        PresetKind::Chrome131 => lkrequest::preset::chrome_131(),
        PresetKind::Chrome144 => lkrequest::preset::chrome_144(),
        PresetKind::Chrome145 => lkrequest::preset::chrome_145(),
        PresetKind::Chrome146 => lkrequest::preset::chrome_146(),
        PresetKind::Chrome147 => lkrequest::preset::chrome_147(),
        PresetKind::Chrome148 => lkrequest::preset::chrome_148(),
        PresetKind::Chrome149 => lkrequest::preset::chrome_149(),
        PresetKind::Chrome150 => lkrequest::preset::chrome_150(),
        PresetKind::Firefox133 => lkrequest::preset::firefox_133(),
        PresetKind::Firefox147 => lkrequest::preset::firefox_147(),
        PresetKind::Safari18 => lkrequest::preset::safari_18(),
        PresetKind::Safari26 => lkrequest::preset::safari_26(),
    }
}

fn parse_ca_ders(data: &[u8]) -> Result<Vec<Vec<u8>>, FfiError> {
    let mut ders = Vec::new();
    let mut saw_pem = false;

    for cert_result in CertificateDer::pem_slice_iter(data) {
        saw_pem = true;
        let cert = cert_result.map_err(|err| {
            FfiError::invalid_config(format!("failed to parse PEM certificate: {err}"))
        })?;
        let der = cert.as_ref().to_vec();
        lkrequest::lktls::verify::certchain::parse_trust_anchor_from_der(&der).map_err(|err| {
            FfiError::invalid_config(format!("failed to parse certificate trust anchor: {err}"))
        })?;
        ders.push(der);
    }

    if !ders.is_empty() {
        return Ok(ders);
    }

    if saw_pem {
        return Err(FfiError::invalid_config(
            "PEM input did not contain any valid certificate",
        ));
    }

    lkrequest::lktls::verify::certchain::parse_trust_anchor_from_der(data).map_err(|err| {
        FfiError::invalid_config(format!("failed to parse certificate trust anchor: {err}"))
    })?;
    Ok(vec![data.to_vec()])
}

fn add_ca_file_to_state(state: &mut ClientBuilderState, path: &str) -> Result<(), FfiError> {
    let data = fs::read(Path::new(path)).map_err(|err| {
        FfiError::invalid_config(format!("failed to read CA file '{path}': {err}"))
    })?;
    state.ca_der_certs.extend(parse_ca_ders(&data)?);
    Ok(())
}

fn add_ca_memory_to_state(state: &mut ClientBuilderState, data: &[u8]) -> Result<(), FfiError> {
    state.ca_der_certs.extend(parse_ca_ders(data)?);
    Ok(())
}

fn validate_quic_profile_json(json: &str) -> Result<(), FfiError> {
    #[cfg(feature = "quic-h3")]
    {
        let profile: lkrequest::QuicProfile = serde_json::from_str(json)
            .map_err(|err| FfiError::invalid_config(format!("invalid QUIC profile JSON: {err}")))?;
        profile
            .validate()
            .map_err(|err| FfiError::invalid_config(format!("invalid QUIC profile: {err}")))?;
        Ok(())
    }

    #[cfg(not(feature = "quic-h3"))]
    {
        let _ = json;
        Err(FfiError::invalid_config(
            "QUIC/H3 support is not compiled in; enable the `quic-h3` feature",
        ))
    }
}

fn parse_session_resumption_json(
    json: &str,
) -> Result<lkrequest::lktls::profile::types::SessionResumptionConfig, FfiError> {
    serde_json::from_str(json)
        .map_err(|err| FfiError::invalid_config(format!("invalid session resumption JSON: {err}")))
}

/// Map the FFI layer bitmask (TLS=1, H2=2, QUIC=4; 0 = all) to [`lkrequest::Layers`].
#[cfg(feature = "synthetic-fp")]
fn ffi_layers(bits: u32) -> lkrequest::Layers {
    use lkrequest::Layers;
    if bits == 0 {
        return Layers::all();
    }
    let mut l = Layers::empty();
    if bits & 1 != 0 {
        l |= Layers::TLS;
    }
    if bits & 2 != 0 {
        l |= Layers::H2;
    }
    if bits & 4 != 0 {
        l |= Layers::QUIC;
    }
    if l.is_empty() {
        Layers::all()
    } else {
        l
    }
}

fn build_client_from_state(state: &ClientBuilderState) -> Result<Arc<ClientShared>, FfiError> {
    let preset = preset_bundle(state.preset);
    let mut builder = lkrequest::Client::builder()
        .preset(preset)
        .verify(state.verify);

    if let Some(h2_preset) = state.h2_preset {
        let preset = preset_bundle(h2_preset);
        builder = builder
            .h2_profile(preset.h2_profile)
            .header_order_from_names(preset.header_order);
    }

    match state.randomize_mode {
        1 => builder = builder.randomize(lkrequest::Randomize::extension_order()),
        #[cfg(feature = "synthetic-fp")]
        2 => {
            builder = builder.randomize(lkrequest::Randomize::recombine_layers(ffi_layers(
                state.randomize_layers,
            )))
        }
        #[cfg(feature = "synthetic-fp")]
        3 => {
            builder = builder.randomize(lkrequest::Randomize::full_layers(ffi_layers(
                state.randomize_layers,
            )))
        }
        // 0 = off (default); synthetic modes without the feature are rejected at set time.
        _ => {}
    }

    match &state.quic_profile_json {
        Some(Some(json)) => {
            #[cfg(feature = "quic-h3")]
            {
                let profile: lkrequest::QuicProfile =
                    serde_json::from_str(json).map_err(|err| {
                        FfiError::invalid_config(format!("invalid QUIC profile JSON: {err}"))
                    })?;
                profile.validate().map_err(|err| {
                    FfiError::invalid_config(format!("invalid QUIC profile: {err}"))
                })?;
                builder = builder.quic_profile(profile);
            }

            #[cfg(not(feature = "quic-h3"))]
            {
                let _ = json;
                return Err(FfiError::invalid_config(
                    "QUIC/H3 support is not compiled in; enable the `quic-h3` feature",
                ));
            }
        }
        Some(None) => {
            builder = builder.disable_http3();
        }
        None => {}
    }

    if state.use_native_certs {
        builder = builder.use_native_certs();
    }
    if let Some(dns_source) = &state.dns_source {
        builder = match dns_source {
            ClientDnsSource::Config(config) => builder.dns(config.clone()),
            ClientDnsSource::Callback(resolver) => {
                let resolver: Arc<dyn lkrequest::DnsResolver> = resolver.clone();
                builder.dns_resolver(resolver)
            }
        };
    }

    let mut timeouts = lkrequest::TimeoutConfig::default();
    let mut custom_timeouts = false;
    if let Some(timeout_ms) = state.dns_timeout_ms {
        timeouts.dns_timeout = Some(Duration::from_millis(timeout_ms));
        custom_timeouts = true;
    }
    if let Some(timeout_ms) = state.tcp_connect_timeout_ms {
        timeouts.tcp_connect_timeout = Some(Duration::from_millis(timeout_ms));
        custom_timeouts = true;
    }
    if let Some(timeout_ms) = state.tls_handshake_timeout_ms {
        timeouts.tls_handshake_timeout = Some(Duration::from_millis(timeout_ms));
        custom_timeouts = true;
    }
    if let Some(timeout_ms) = state.quic_connect_timeout_ms {
        timeouts.quic_connect_timeout = Some(Duration::from_millis(timeout_ms));
        custom_timeouts = true;
    }
    if let Some(timeout_ms) = state.ttfb_timeout_ms {
        timeouts.ttfb_timeout = Some(Duration::from_millis(timeout_ms));
        custom_timeouts = true;
    }
    if let Some(timeout_ms) = state.total_timeout_ms {
        timeouts.total_timeout = Some(Duration::from_millis(timeout_ms));
        custom_timeouts = true;
    }
    if custom_timeouts {
        builder = builder.timeout_config(timeouts);
    }
    for der in &state.ca_der_certs {
        builder = builder.add_ca_cert_der(der);
    }
    for (name, value) in &state.default_headers {
        HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
            FfiError::invalid_argument(format!("invalid default header name: {err}"))
        })?;
        HeaderValue::from_str(value).map_err(|err| {
            FfiError::invalid_argument(format!("invalid default header value: {err}"))
        })?;
        builder = builder.default_header(name, value);
    }
    if !state.header_order.is_empty() {
        let order: Result<Vec<HeaderName>, FfiError> = state
            .header_order
            .iter()
            .map(|name| {
                HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
                    FfiError::invalid_argument(format!(
                        "invalid header order entry '{name}': {err}"
                    ))
                })
            })
            .collect();
        builder = builder.header_order_from_names(order?);
    }
    if !state.h3_header_order.is_empty() {
        let order: Result<Vec<HeaderName>, FfiError> = state
            .h3_header_order
            .iter()
            .map(|name| {
                HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
                    FfiError::invalid_argument(format!(
                        "invalid h3 header order entry '{name}': {err}"
                    ))
                })
            })
            .collect();
        builder = builder.h3_header_order_from_names(order?);
    }
    if !state.cookie_order.is_empty() {
        builder = builder.cookie_order_from_strings(state.cookie_order.clone());
    }
    if let Some(ech_config) = &state.ech_config {
        builder = builder.ech_config(ech_config.clone());
    }
    if let Some(session_resumption) = &state.session_resumption {
        builder = builder.session_resumption(session_resumption.clone());
    }
    if let Some(ja4t) = &state.tcp_fingerprint_ja4t {
        let fingerprint = lkrequest::TcpFingerprint::from_ja4t(ja4t).map_err(|err| {
            FfiError::invalid_config(format!("invalid JA4T fingerprint '{ja4t}': {err}"))
        })?;
        builder = builder.tcp_fingerprint(fingerprint);
    }
    if let Some(max_body_size) = state.max_response_body_size {
        builder = builder.max_response_body_size(max_body_size);
    }
    if let Some(max_connections) = state.max_connections_per_session {
        builder = builder.max_connections_per_session(max_connections);
    }
    let mut resource_limits = lkrequest::ResourceLimits::default();
    let mut custom_resource_limits = false;
    if let Some(value) = state.max_header_count {
        resource_limits.max_header_count = value;
        custom_resource_limits = true;
    }
    if let Some(value) = state.max_header_size {
        resource_limits.max_header_size = value;
        custom_resource_limits = true;
    }
    if let Some(value) = state.max_headers_total_size {
        resource_limits.max_headers_total_size = value;
        custom_resource_limits = true;
    }
    if let Some(value) = state.min_transfer_rate {
        resource_limits.min_transfer_rate = Some(value);
        resource_limits.transfer_rate_window =
            Duration::from_millis(state.transfer_rate_window_ms.unwrap_or(10_000));
        custom_resource_limits = true;
    }
    if custom_resource_limits {
        builder = builder.resource_limits(resource_limits);
    }
    if let Some(enabled) = state.fallback_h2_to_h1 {
        builder = builder.h2_fallback_h1(enabled);
    }
    if let Some(enabled) = state.fallback_proxy_to_direct {
        builder = builder.proxy_fallback_direct(enabled);
    }
    if let Some(enabled) = state.fallback_retry_on_connection_close {
        builder = builder.retry_on_connection_close(enabled);
    }
    if let Some(path) = &state.keylog_file {
        let callback = lkrequest::keylog_to_file(path).map_err(|err| {
            FfiError::invalid_config(format!("failed to initialize keylog file '{path}': {err}"))
        })?;
        builder = builder.keylog(callback);
    }

    Ok(Arc::new(ClientShared {
        client: builder.build(),
        outstanding_ops: AtomicUsize::new(0),
        max_outstanding_ops: state.max_outstanding_ops,
    }))
}

#[no_mangle]
pub extern "C" fn lk_client_new(
    preset_name: *const c_char,
    out_client: *mut *mut lk_client_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_client.is_null() {
            return Err(FfiError::invalid_argument("out_client is null"));
        }
        *out_client = ptr::null_mut();
        clear_error_out(out_err);

        let preset = parse_preset_name(&read_c_string(preset_name, "preset_name")?)?;
        let state = ClientBuilderState {
            preset,
            ..ClientBuilderState::default()
        };
        let shared = build_client_from_state(&state)?;
        *out_client = box_into_handle::<ClientHandle, lk_client_t>(ClientHandle {
            shared,
            fingerprint_json: std::sync::OnceLock::new(),
        });
        Ok(())
    })
}

fn map_dns_config(config: lk_dns_config_t) -> lkrequest::DnsConfig {
    match config {
        lk_dns_config_t::LK_DNS_SYSTEM => lkrequest::DnsConfig::System,
        lk_dns_config_t::LK_DNS_GOOGLE => lkrequest::DnsConfig::Google,
        lk_dns_config_t::LK_DNS_GOOGLE_HTTPS => lkrequest::DnsConfig::GoogleHttps,
        lk_dns_config_t::LK_DNS_CLOUDFLARE => lkrequest::DnsConfig::Cloudflare,
        lk_dns_config_t::LK_DNS_CLOUDFLARE_HTTPS => lkrequest::DnsConfig::CloudflareHttps,
        lk_dns_config_t::LK_DNS_QUAD9 => lkrequest::DnsConfig::Quad9,
        lk_dns_config_t::LK_DNS_QUAD9_HTTPS => lkrequest::DnsConfig::Quad9Https,
    }
}

#[no_mangle]
pub extern "C" fn lk_client_new_default(
    out_client: *mut *mut lk_client_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_client.is_null() {
            return Err(FfiError::invalid_argument("out_client is null"));
        }
        *out_client = ptr::null_mut();

        let shared = build_client_from_state(&ClientBuilderState::default())?;
        *out_client = box_into_handle::<ClientHandle, lk_client_t>(ClientHandle {
            shared,
            fingerprint_json: std::sync::OnceLock::new(),
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_clone(client: *const lk_client_t) -> *mut lk_client_t {
    catch_value(ptr::null_mut(), || unsafe {
        match require_handle::<ClientHandle, lk_client_t>(client.cast_mut()) {
            Ok(client) => box_into_handle::<ClientHandle, lk_client_t>(ClientHandle {
                shared: Arc::clone(&client.shared),
                fingerprint_json: std::sync::OnceLock::new(),
            }),
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn lk_client_free(client: *mut lk_client_t) {
    catch_value((), || unsafe {
        handle_drop::<ClientHandle, lk_client_t>(client);
    });
}

#[no_mangle]
pub extern "C" fn lk_client_fingerprint_info_json(
    client: *const lk_client_t,
    out_json_ptr: *mut *const c_char,
    out_json_len: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_json_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_json_ptr is null"));
        }
        *out_json_ptr = ptr::null();
        if !out_json_len.is_null() {
            *out_json_len = 0;
        }

        let client = require_handle::<ClientHandle, lk_client_t>(client.cast_mut())?;
        let json_bytes = client.fingerprint_json.get_or_init(|| {
            let c = &client.shared.client;
            let quic_value = c
                .quic_profile()
                .map(|profile| serde_json::to_value(profile).unwrap_or(serde_json::Value::Null))
                .unwrap_or(serde_json::Value::Null);
            let tcp_value = c
                .tcp_fingerprint()
                .map(|fp| serde_json::to_value(fp).unwrap_or(serde_json::Value::Null))
                .unwrap_or(serde_json::Value::Null);
            let value = serde_json::json!({
                "tls": c.tls_profile(),
                "h2": c.h2_profile(),
                "quic": quic_value,
                "tcp": tcp_value,
            });
            let mut bytes = serde_json::to_vec(&value).expect("serialize fingerprint info");
            bytes.push(0);
            bytes
        });

        *out_json_ptr = json_bytes.as_ptr().cast::<c_char>();
        if !out_json_len.is_null() {
            *out_json_len = json_bytes.len() - 1;
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_new() -> *mut lk_client_builder_t {
    catch_value(ptr::null_mut(), || {
        box_into_handle::<ClientBuilderHandle, lk_client_builder_t>(ClientBuilderHandle {
            state: ClientBuilderState::default(),
        })
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_preset(
    builder: *mut lk_client_builder_t,
    preset_name: *const c_char,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.preset = parse_preset_name(&read_c_string(preset_name, "preset_name")?)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_h2_preset(
    builder: *mut lk_client_builder_t,
    preset_name: *const c_char,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.h2_preset = Some(parse_preset_name(&read_c_string(
            preset_name,
            "preset_name",
        )?)?);
        Ok(())
    })
}

/// Set the fingerprint randomization policy.
///
/// `mode` selects the tier; `layers` is a bitmask (`LK_FP_LAYER_TLS|H2|QUIC`,
/// `0` = all layers) applied only to the synthetic modes. `OFF` /
/// `EXTENSION_ORDER` are always available; `RECOMBINE` / `FULL` require the
/// `synthetic-fp` feature and return an error otherwise.
#[no_mangle]
pub extern "C" fn lk_client_builder_set_randomize(
    builder: *mut lk_client_builder_t,
    mode: lk_randomize_mode_t,
    layers: u32,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        // Synthetic modes need the `synthetic-fp` feature; reject them otherwise.
        #[cfg(not(feature = "synthetic-fp"))]
        {
            use lk_randomize_mode_t::{LK_RANDOMIZE_FULL, LK_RANDOMIZE_RECOMBINE};
            if matches!(mode, LK_RANDOMIZE_RECOMBINE | LK_RANDOMIZE_FULL) {
                return Err(FfiError::invalid_config(
                    "synthetic fingerprint randomization is not compiled in; \
                     enable the `synthetic-fp` feature",
                ));
            }
        }
        builder.state.randomize_mode = mode as u8;
        builder.state.randomize_layers = layers;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_timeout_dns(
    builder: *mut lk_client_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.dns_timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_timeout_tcp_connect(
    builder: *mut lk_client_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.tcp_connect_timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_timeout_tls_handshake(
    builder: *mut lk_client_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.tls_handshake_timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_timeout_quic_connect(
    builder: *mut lk_client_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.quic_connect_timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_timeout_ttfb(
    builder: *mut lk_client_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.ttfb_timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_timeout_total(
    builder: *mut lk_client_builder_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.total_timeout_ms = Some(timeout_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_verify(
    builder: *mut lk_client_builder_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.verify = enabled;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_dns(
    builder: *mut lk_client_builder_t,
    dns_config: lk_dns_config_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.dns_source = Some(ClientDnsSource::Config(map_dns_config(dns_config)));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_dns_custom(
    builder: *mut lk_client_builder_t,
    addr_ptr: *const c_char,
    addr_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let addr = read_string_parts(addr_ptr, addr_len, "dns custom address")?;
        let parsed: SocketAddr = addr.parse().map_err(|err| {
            FfiError::invalid_argument(format!("invalid DNS socket address '{addr}': {err}"))
        })?;
        builder.state.dns_source = Some(ClientDnsSource::Config(lkrequest::DnsConfig::Custom(
            parsed,
        )));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_dns_resolver(
    builder: *mut lk_client_builder_t,
    resolver: crate::types::lk_dns_resolver_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let resolver = Arc::new(FfiDnsResolver { resolver });
        resolver.validate()?;
        builder.state.dns_source = Some(ClientDnsSource::Callback(resolver));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_use_native_certs(
    builder: *mut lk_client_builder_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.use_native_certs = enabled;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_max_outstanding_ops(
    builder: *mut lk_client_builder_t,
    max_outstanding_ops: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.max_outstanding_ops = max_outstanding_ops;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_add_ca_cert_file(
    builder: *mut lk_client_builder_t,
    path: *const c_char,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        add_ca_file_to_state(&mut builder.state, &read_c_string(path, "path")?)
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_add_ca_cert_memory(
    builder: *mut lk_client_builder_t,
    data_ptr: *const u8,
    data_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        add_ca_memory_to_state(&mut builder.state, &read_bytes(data_ptr, data_len, "data")?)
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_build(
    builder: *mut lk_client_builder_t,
    out_client: *mut *mut lk_client_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_client.is_null() {
            return Err(FfiError::invalid_argument("out_client is null"));
        }
        *out_client = ptr::null_mut();

        let builder = require_handle::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let shared = build_client_from_state(&builder.state)?;
        *out_client = box_into_handle::<ClientHandle, lk_client_t>(ClientHandle {
            shared,
            fingerprint_json: std::sync::OnceLock::new(),
        });
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_add_default_header(
    builder: *mut lk_client_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "header name")?;
        let value = read_string_parts(value_ptr, value_len, "header value")?;
        builder.state.default_headers.push((name, value));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_add_header_order(
    builder: *mut lk_client_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "header order entry")?;
        builder.state.header_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_add_h3_header_order(
    builder: *mut lk_client_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "h3 header order entry")?;
        builder.state.h3_header_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_add_cookie_order(
    builder: *mut lk_client_builder_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let name = read_string_parts(name_ptr, name_len, "cookie order entry")?;
        builder.state.cookie_order.push(name);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_ech_config(
    builder: *mut lk_client_builder_t,
    data_ptr: *const u8,
    data_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.ech_config = Some(read_bytes(data_ptr, data_len, "ech_config")?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_quic_profile_json(
    builder: *mut lk_client_builder_t,
    json_ptr: *const c_char,
    json_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let json = read_string_parts(json_ptr, json_len, "quic profile json")?;
        validate_quic_profile_json(&json)?;
        builder.state.quic_profile_json = Some(Some(json));
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_disable_http3(
    builder: *mut lk_client_builder_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.quic_profile_json = Some(None);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_session_resumption_json(
    builder: *mut lk_client_builder_t,
    json_ptr: *const c_char,
    json_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        let json = read_string_parts(json_ptr, json_len, "session resumption json")?;
        builder.state.session_resumption = Some(parse_session_resumption_json(&json)?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_tcp_fingerprint_ja4t(
    builder: *mut lk_client_builder_t,
    ja4t_ptr: *const c_char,
    ja4t_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.tcp_fingerprint_ja4t = Some(read_string_parts(ja4t_ptr, ja4t_len, "ja4t")?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_max_response_body_size(
    builder: *mut lk_client_builder_t,
    size: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.max_response_body_size = Some(size);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_max_header_count(
    builder: *mut lk_client_builder_t,
    count: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.max_header_count = Some(count);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_max_header_size(
    builder: *mut lk_client_builder_t,
    size: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.max_header_size = Some(size);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_max_headers_total_size(
    builder: *mut lk_client_builder_t,
    size: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.max_headers_total_size = Some(size);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_min_transfer_rate(
    builder: *mut lk_client_builder_t,
    bytes_per_sec: usize,
    window_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.min_transfer_rate = Some(bytes_per_sec);
        builder.state.transfer_rate_window_ms = Some(window_ms);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_max_connections_per_session(
    builder: *mut lk_client_builder_t,
    max_connections: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.max_connections_per_session = Some(max_connections);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_fallback_h2_to_h1(
    builder: *mut lk_client_builder_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.fallback_h2_to_h1 = Some(enabled);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_fallback_proxy_to_direct(
    builder: *mut lk_client_builder_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.fallback_proxy_to_direct = Some(enabled);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_retry_on_connection_close(
    builder: *mut lk_client_builder_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.fallback_retry_on_connection_close = Some(enabled);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_set_keylog_file(
    builder: *mut lk_client_builder_t,
    path_ptr: *const c_char,
    path_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let builder = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(builder)?;
        builder.state.keylog_file = Some(read_string_parts(path_ptr, path_len, "path")?);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_client_builder_free(builder: *mut lk_client_builder_t) {
    catch_value((), || unsafe {
        handle_drop::<ClientBuilderHandle, lk_client_builder_t>(builder);
    });
}

#[cfg(all(test, feature = "synthetic-fp"))]
mod tests {
    use super::ffi_layers;
    use lkrequest::Layers;

    #[test]
    fn ffi_layers_maps_bits() {
        // 0 means "all layers" (the safe default).
        assert_eq!(ffi_layers(0), Layers::all());
        // Individual bits.
        assert_eq!(ffi_layers(1), Layers::TLS);
        assert_eq!(ffi_layers(2), Layers::H2);
        assert_eq!(ffi_layers(4), Layers::QUIC);
        // Combinations.
        assert_eq!(ffi_layers(1 | 2), Layers::TLS | Layers::H2);
        assert_eq!(ffi_layers(1 | 2 | 4), Layers::all());
        // Only-invalid bits fall back to all; invalid bits alongside valid are ignored.
        assert_eq!(ffi_layers(8), Layers::all());
        assert_eq!(ffi_layers(8 | 1), Layers::TLS);
    }
}
