use std::ffi::c_char;
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use crate::abi::{
    lk_socks5_udp_probe_mode_t, lk_socks5_udp_probe_phase_t, lk_socks5_udp_probe_support_t,
    lk_status_t,
};
use crate::conv::{clear_out_len, clear_out_ptr, read_string_parts, set_string_out};
use crate::error::{make_error_handle, FfiError};
use crate::handles::{
    box_into_handle, handle_drop, lk_client_t, lk_error_t, lk_op_t, lk_socks5_udp_probe_report_t,
    require_handle, ClientHandle, OpHandle, OpResult, OpShared, OpSuccess,
    Socks5UdpProbeReportHandle,
};
use crate::panic::{catch_status, catch_value};
use crate::runtime::runtime;
use crate::types::lk_socks5_udp_probe_config_t;

fn map_mode(mode: lk_socks5_udp_probe_mode_t) -> lkrequest::proxy::Socks5UdpProbeMode {
    match mode {
        lk_socks5_udp_probe_mode_t::LK_SOCKS5_UDP_PROBE_ASSOCIATE_ONLY => {
            lkrequest::proxy::Socks5UdpProbeMode::AssociateOnly
        }
        lk_socks5_udp_probe_mode_t::LK_SOCKS5_UDP_PROBE_DNS_ROUND_TRIP => {
            lkrequest::proxy::Socks5UdpProbeMode::DnsRoundTrip
        }
    }
}

fn map_support(support: lkrequest::proxy::Socks5UdpProbeSupport) -> lk_socks5_udp_probe_support_t {
    match support {
        lkrequest::proxy::Socks5UdpProbeSupport::NotSocks5 => {
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_NOT_SOCKS5
        }
        lkrequest::proxy::Socks5UdpProbeSupport::AssociateOk => {
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_ASSOCIATE_OK
        }
        lkrequest::proxy::Socks5UdpProbeSupport::RelayOk => {
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_RELAY_OK
        }
        lkrequest::proxy::Socks5UdpProbeSupport::Unsupported => {
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_UNSUPPORTED
        }
        lkrequest::proxy::Socks5UdpProbeSupport::Failed => {
            lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_FAILED
        }
    }
}

fn map_phase(phase: lkrequest::proxy::Socks5UdpProbePhase) -> lk_socks5_udp_probe_phase_t {
    match phase {
        lkrequest::proxy::Socks5UdpProbePhase::NotSocks5 => {
            lk_socks5_udp_probe_phase_t::LK_SOCKS5_UDP_PROBE_PHASE_NOT_SOCKS5
        }
        lkrequest::proxy::Socks5UdpProbePhase::UdpAssociate => {
            lk_socks5_udp_probe_phase_t::LK_SOCKS5_UDP_PROBE_PHASE_UDP_ASSOCIATE
        }
        lkrequest::proxy::Socks5UdpProbePhase::UdpRoundTrip => {
            lk_socks5_udp_probe_phase_t::LK_SOCKS5_UDP_PROBE_PHASE_UDP_ROUND_TRIP
        }
    }
}

unsafe fn read_probe_config(
    config: *const lk_socks5_udp_probe_config_t,
) -> Result<lkrequest::proxy::Socks5UdpProbeConfig, FfiError> {
    let cfg = if config.is_null() {
        lk_socks5_udp_probe_config_t {
            mode: lk_socks5_udp_probe_mode_t::LK_SOCKS5_UDP_PROBE_DNS_ROUND_TRIP,
            timeout_ms: 5000,
            dns_server_addr_ptr: ptr::null(),
            dns_server_addr_len: 0,
            dns_server_host_ptr: ptr::null(),
            dns_server_host_len: 0,
            dns_query_ptr: ptr::null(),
            dns_query_len: 0,
        }
    } else {
        *config
    };

    let timeout_ms = if cfg.timeout_ms == 0 {
        5000
    } else {
        cfg.timeout_ms
    };

    let dns_server = read_string_parts(
        cfg.dns_server_addr_ptr,
        cfg.dns_server_addr_len,
        "dns_server_addr",
    )?;
    let server = if dns_server.trim().is_empty() {
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53))
    } else {
        dns_server.parse().map_err(|err| {
            FfiError::invalid_argument(format!(
                "dns_server_addr is not a valid socket address: {err}"
            ))
        })?
    };

    let dns_host = read_string_parts(
        cfg.dns_server_host_ptr,
        cfg.dns_server_host_len,
        "dns_server_host",
    )?;
    let query = read_string_parts(cfg.dns_query_ptr, cfg.dns_query_len, "dns_query")?;
    let query = if query.trim().is_empty() {
        "example.com".to_string()
    } else {
        query
    };

    Ok(lkrequest::proxy::Socks5UdpProbeConfig {
        mode: map_mode(cfg.mode),
        timeout: Duration::from_millis(timeout_ms),
        target: lkrequest::proxy::Socks5UdpProbeTarget::DnsUdp {
            server,
            query,
            server_name: if dns_host.trim().is_empty() {
                None
            } else {
                Some(dns_host)
            },
        },
    })
}

async fn execute_probe(
    client: Option<Arc<crate::handles::ClientShared>>,
    proxy_url: String,
    config: lkrequest::proxy::Socks5UdpProbeConfig,
) -> Result<Socks5UdpProbeReportHandle, FfiError> {
    let proxy = lkrequest::proxy::ProxyConfig::parse(&proxy_url)
        .map_err(|err| FfiError::invalid_config(format!("invalid proxy URL: {err}")))?;

    let report = match client {
        Some(client) => {
            proxy
                .probe_socks5_udp_with_client(config, &client.client)
                .await
        }
        None => proxy.probe_socks5_udp(config).await,
    }
    .map_err(FfiError::from_lkrequest)?;

    Ok(Socks5UdpProbeReportHandle::new(report))
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe(
    client: *const lk_client_t,
    proxy_ptr: *const c_char,
    proxy_len: usize,
    config: *const lk_socks5_udp_probe_config_t,
    out_report: *mut *mut lk_socks5_udp_probe_report_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_report.is_null() {
            return Err(FfiError::invalid_argument("out_report is null"));
        }
        *out_report = ptr::null_mut();

        let client = if client.is_null() {
            None
        } else {
            Some(
                require_handle::<ClientHandle, lk_client_t>(client.cast_mut())?
                    .shared
                    .clone(),
            )
        };
        let proxy = read_string_parts(proxy_ptr, proxy_len, "proxy")?;
        let config = read_probe_config(config)?;
        let report = runtime().block_on(execute_probe(client, proxy, config))?;

        *out_report =
            box_into_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(report);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_async(
    client: *const lk_client_t,
    proxy_ptr: *const c_char,
    proxy_len: usize,
    config: *const lk_socks5_udp_probe_config_t,
    out_op: *mut *mut lk_op_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_op.is_null() {
            return Err(FfiError::invalid_argument("out_op is null"));
        }
        *out_op = ptr::null_mut();

        let client = if client.is_null() {
            None
        } else {
            Some(
                require_handle::<ClientHandle, lk_client_t>(client.cast_mut())?
                    .shared
                    .clone(),
            )
        };
        let proxy = read_string_parts(proxy_ptr, proxy_len, "proxy")?;
        let config = read_probe_config(config)?;

        let op_shared = Arc::new(OpShared::default());
        let op_handle = OpHandle {
            client: None,
            shared: Arc::clone(&op_shared),
            counted: false,
            cleanup: None,
        };

        let shared = Arc::clone(&op_shared);
        let join = runtime().spawn(async move {
            let result = match execute_probe(client, proxy, config).await {
                Ok(report) => OpResult::CompletedOk(Some(OpSuccess::Socks5UdpProbeReport(report))),
                Err(err) => {
                    OpResult::CompletedErr(Some(make_error_handle(err, Default::default())))
                }
            };
            let mut state = shared.state.lock();
            state.result = result;
            shared.cv.notify_all();
        });

        op_handle.shared.state.lock().join = Some(join);
        *out_op = box_into_handle::<OpHandle, lk_op_t>(op_handle);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_support(
    report: *const lk_socks5_udp_probe_report_t,
) -> lk_socks5_udp_probe_support_t {
    catch_value(
        lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_FAILED,
        || unsafe {
            require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
                report.cast_mut(),
            )
            .map(|handle| map_support(handle.report.support))
            .unwrap_or(lk_socks5_udp_probe_support_t::LK_SOCKS5_UDP_SUPPORT_FAILED)
        },
    )
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_phase(
    report: *const lk_socks5_udp_probe_report_t,
) -> lk_socks5_udp_probe_phase_t {
    catch_value(
        lk_socks5_udp_probe_phase_t::LK_SOCKS5_UDP_PROBE_PHASE_NOT_SOCKS5,
        || unsafe {
            require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
                report.cast_mut(),
            )
            .map(|handle| map_phase(handle.report.phase))
            .unwrap_or(lk_socks5_udp_probe_phase_t::LK_SOCKS5_UDP_PROBE_PHASE_NOT_SOCKS5)
        },
    )
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_elapsed_ms(
    report: *const lk_socks5_udp_probe_report_t,
) -> u64 {
    catch_value(0, || unsafe {
        require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
            report.cast_mut(),
        )
        .map(|handle| handle.report.elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_proxy(
    report: *const lk_socks5_udp_probe_report_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let report = require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
            report.cast_mut(),
        )?;
        set_string_out(&report.proxy, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_relay_addr(
    report: *const lk_socks5_udp_probe_report_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let report = require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
            report.cast_mut(),
        )?;
        let Some(relay_addr) = report.relay_addr.as_ref() else {
            return Ok(());
        };
        set_string_out(relay_addr, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_error(
    report: *const lk_socks5_udp_probe_report_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let report = require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
            report.cast_mut(),
        )?;
        let Some(error) = report.error.as_ref() else {
            return Ok(());
        };
        set_string_out(error, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_json(
    report: *const lk_socks5_udp_probe_report_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let report = require_handle::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(
            report.cast_mut(),
        )?;
        let bytes = report.json.get_or_init(|| {
            serde_json::to_vec(&report.report).unwrap_or_else(|err| {
                format!("{{\"error\":\"json serialization failed: {err}\"}}").into_bytes()
            })
        });
        set_string_out(bytes, out_ptr, out_len)
    })
}

#[no_mangle]
pub extern "C" fn lk_socks5_udp_probe_report_free(report: *mut lk_socks5_udp_probe_report_t) {
    catch_value((), || unsafe {
        handle_drop::<Socks5UdpProbeReportHandle, lk_socks5_udp_probe_report_t>(report);
    });
}
