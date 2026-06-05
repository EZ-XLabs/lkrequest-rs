//! Probe whether a list of proxies can carry HTTP/3.
//!
//! Edit `PROXIES` below, then run:
//!
//!   cargo run -p lkrequest --features quic-h3 --example proxy_h3_probe
//!
//! The probe is intentionally two-stage:
//!   1. SOCKS5 UDP capability checks (`UDP ASSOCIATE` and DNS UDP round-trip).
//!   2. A real `http3_only()` GET to an H3-capable target.
//!
//! `udp_relay=yes` means generic SOCKS5 UDP relay traffic worked. `h3=yes`
//! means HTTP/3 worked end-to-end through the proxy.

use std::time::{Duration, Instant};

use lkh3::chrome_quic;
use lkrequest::proxy::{
    ProxyConfig, ProxyScheme, Socks5UdpProbeConfig, Socks5UdpProbeMode, Socks5UdpProbeReport,
    Socks5UdpProbeSupport,
};
use lkrequest::{Client, HttpVersion, TimeoutConfig};
use lktls::profile::presets;

const PROXIES: &[&str] = &[
    // Replace these with your proxy vec.
    // "socks5h://user:pass@host:1080",
    // "socks5://user:pass@host:1080",
    // "http://user:pass@host:8080",
];

const H3_TARGET_URL: &str = "https://cloudflare.com/cdn-cgi/trace";
const UDP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const H3_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct ProbeRow {
    proxy: String,
    udp_associate: String,
    udp_relay: String,
    h3: String,
    detail: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "lkrequest=warn,lkquic=warn,lkh3=warn".into()),
        )
        .init();

    let proxies: Vec<&str> = PROXIES
        .iter()
        .copied()
        .filter(|proxy| !proxy.trim().is_empty())
        .collect();

    if proxies.is_empty() {
        eprintln!("PROXIES is empty. Edit lkrequest/examples/proxy_h3_probe.rs first.");
        return;
    }

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .quic_profile(chrome_quic().with_static_qpack())
        .timeout_config(
            TimeoutConfig::default()
                .with_quic_connect_timeout(QUIC_CONNECT_TIMEOUT)
                .with_total_timeout(H3_REQUEST_TIMEOUT),
        )
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build();

    println!("target: {H3_TARGET_URL}");
    println!(
        "{:<4} {:<46} {:<13} {:<11} {:<9} detail",
        "#", "proxy", "udp_associate", "udp_relay", "h3"
    );
    println!("{}", "-".repeat(110));

    for (idx, proxy_url) in proxies.iter().enumerate() {
        let row = probe_one(&client, proxy_url).await;
        println!(
            "{:<4} {:<46} {:<13} {:<11} {:<9} {}",
            idx + 1,
            truncate(&row.proxy, 46),
            row.udp_associate,
            row.udp_relay,
            row.h3,
            row.detail
        );
    }
}

async fn probe_one(client: &Client, proxy_url: &str) -> ProbeRow {
    let proxy = match ProxyConfig::parse(proxy_url) {
        Ok(proxy) => proxy,
        Err(error) => {
            return ProbeRow {
                proxy: mask_proxy_url(proxy_url),
                udp_associate: "parse-fail".into(),
                udp_relay: "skip".into(),
                h3: "skip".into(),
                detail: short_error(&error.to_string()),
            };
        }
    };

    let proxy_id = proxy.identity();
    if !matches!(&proxy.scheme, ProxyScheme::Socks5 { .. }) {
        return ProbeRow {
            proxy: proxy_id,
            udp_associate: "n/a".into(),
            udp_relay: "n/a".into(),
            h3: "no".into(),
            detail: "HTTP CONNECT proxies cannot carry QUIC/HTTP3 UDP without MASQUE".into(),
        };
    }

    let associate = proxy
        .probe_socks5_udp_with_client(socks5_udp_config(Socks5UdpProbeMode::AssociateOnly), client)
        .await;

    let associate = match associate {
        Ok(report) => report,
        Err(error) => {
            return ProbeRow {
                proxy: proxy_id,
                udp_associate: "fail".into(),
                udp_relay: "skip".into(),
                h3: "skip".into(),
                detail: short_error(&error.to_string()),
            };
        }
    };

    if !associate.associate_supported() {
        return ProbeRow {
            proxy: proxy_id,
            udp_associate: support_label(associate.support).into(),
            udp_relay: "skip".into(),
            h3: "skip".into(),
            detail: report_detail(&associate),
        };
    }

    let relay = proxy
        .probe_socks5_udp_with_client(socks5_udp_config(Socks5UdpProbeMode::DnsRoundTrip), client)
        .await;
    let (udp_relay, relay_detail) = match relay {
        Ok(report) => (
            support_label(report.support).to_string(),
            report_detail(&report),
        ),
        Err(error) => ("fail".into(), short_error(&error.to_string())),
    };

    let h3 = probe_h3(client, proxy_url).await;
    let detail = if h3.detail.is_empty() {
        relay_detail
    } else if relay_detail.is_empty() {
        h3.detail
    } else {
        format!("{relay_detail}; {}", h3.detail)
    };

    ProbeRow {
        proxy: proxy_id,
        udp_associate: support_label(associate.support).into(),
        udp_relay,
        h3: h3.label,
        detail,
    }
}

struct H3ProbeResult {
    label: String,
    detail: String,
}

async fn probe_h3(client: &Client, proxy_url: &str) -> H3ProbeResult {
    let session = client.session().proxy(proxy_url).http3_only().build();
    let started = Instant::now();
    let result = session
        .get(H3_TARGET_URL)
        .timeout(H3_REQUEST_TIMEOUT)
        .send()
        .await;
    let elapsed = started.elapsed();

    match result {
        Ok(resp) => {
            let version = resp.version();
            let status = resp.status();
            let body_len = resp.bytes().len();
            if version == HttpVersion::H3 {
                H3ProbeResult {
                    label: "yes".into(),
                    detail: format!(
                        "h3 status={} body={}B elapsed={:.0}ms",
                        status,
                        body_len,
                        elapsed.as_secs_f64() * 1000.0
                    ),
                }
            } else {
                H3ProbeResult {
                    label: "non-h3".into(),
                    detail: format!(
                        "unexpected version={} status={} elapsed={:.0}ms",
                        version,
                        status,
                        elapsed.as_secs_f64() * 1000.0
                    ),
                }
            }
        }
        Err(error) => H3ProbeResult {
            label: "fail".into(),
            detail: format!(
                "h3 error after {:.0}ms: {}",
                elapsed.as_secs_f64() * 1000.0,
                short_error(&error.to_string())
            ),
        },
    }
}

fn socks5_udp_config(mode: Socks5UdpProbeMode) -> Socks5UdpProbeConfig {
    Socks5UdpProbeConfig {
        mode,
        timeout: UDP_PROBE_TIMEOUT,
        ..Socks5UdpProbeConfig::default()
    }
}

fn support_label(support: Socks5UdpProbeSupport) -> &'static str {
    match support {
        Socks5UdpProbeSupport::NotSocks5 => "not-socks5",
        Socks5UdpProbeSupport::AssociateOk => "yes",
        Socks5UdpProbeSupport::RelayOk => "yes",
        Socks5UdpProbeSupport::Unsupported => "no",
        Socks5UdpProbeSupport::Failed => "fail",
    }
}

fn report_detail(report: &Socks5UdpProbeReport) -> String {
    let mut parts = Vec::new();
    if let Some(relay_addr) = report.relay_addr {
        parts.push(format!("relay={relay_addr}"));
    }
    parts.push(format!(
        "udp_elapsed={:.0}ms",
        report.elapsed.as_secs_f64() * 1000.0
    ));
    if let Some(error) = &report.error {
        parts.push(short_error(error));
    }
    parts.join(" ")
}

fn short_error(error: &str) -> String {
    truncate(error.replace('\n', " ").trim(), 180)
}

fn truncate(value: impl AsRef<str>, max_chars: usize) -> String {
    let value = value.as_ref();
    let mut out = String::new();
    for ch in value.chars().take(max_chars) {
        out.push(ch);
    }
    if out.len() < value.len() {
        out.push_str("...");
    }
    out
}

fn mask_proxy_url(proxy_url: &str) -> String {
    match url::Url::parse(proxy_url) {
        Ok(mut url) => {
            if !url.username().is_empty() {
                let _ = url.set_username("***");
            }
            if url.password().is_some() {
                let _ = url.set_password(Some("***"));
            }
            url.to_string()
        }
        Err(_) => proxy_url.to_string(),
    }
}
