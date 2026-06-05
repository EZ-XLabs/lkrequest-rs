//! Force-HTTP/3 over SOCKS5 UDP probe.
//!
//! Drives an actual HTTP/3 GET through a SOCKS5h proxy with `http3_only()` so
//! that any failure on the SOCKS5 UDP ASSOCIATE / Quinn / H3 path surfaces as
//! a hard error instead of silently falling back to H2.
//!
//! Usage:
//!
//! ```sh
//! cargo run -p lkrequest --features quic-h3 --example h3_socks5_force -- \
//!   socks5h://user:pass@host:port https://cloudflare.com/cdn-cgi/trace
//! ```
//!
//! Notes:
//!  - Target must serve HTTP/3 directly (Cloudflare-fronted hosts work well).
//!  - Setting `RUST_LOG=lkrequest=debug,lkquic=debug,lkh3=debug` is recommended
//!    to inspect the ASSOCIATE / handshake stages.
//!  - On UDP failure you will see one of: `udp_associate ... 0x07/0x01`,
//!    `quic.handshake_timeout`, or `quic.handshake_failed`.

use lkh3::chrome_quic;
use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "lkrequest=debug,lktls_quic=info,lkh3=info,lkquic=debug".into()
            }),
        )
        .init();

    let proxy_url = std::env::args().nth(1).ok_or_else(|| {
        "usage: h3_socks5_force <socks5h://user:pass@host:port> [target_url]".to_string()
    })?;
    let target = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "https://cloudflare.com/cdn-cgi/trace".to_string());

    println!("== HTTP/3 force-mode probe ==");
    println!("proxy : {proxy_url}");
    println!("target: {target}");
    println!();

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .quic_profile(chrome_quic().with_static_qpack())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build();

    // Force H3 — no fallback. Any UDP / QUIC / SOCKS5 error becomes a hard
    // error visible to the caller instead of being silently masked by H2.
    let session = client.session().http3_only().proxy(&proxy_url).build();

    let started = std::time::Instant::now();
    let result = session.get(&target).send().await;
    let elapsed = started.elapsed();

    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            println!("--- FAILED in {:.0} ms ---", elapsed.as_secs_f64() * 1000.0);
            println!("error: {e}");
            println!();
            println!(
                "Likely cause: SOCKS5 UDP ASSOCIATE not supported or QUIC datagrams \
                 not relayed. Check the trace log for the exact stage."
            );
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    };

    let status = resp.status();
    let version = resp.version();
    let version_str = format!("{version}");
    println!(
        "--- SUCCESS in {:.0} ms ---",
        elapsed.as_secs_f64() * 1000.0
    );
    println!("status:  {status}");
    println!("version: {version_str}");
    println!();
    let body = resp.text()?;
    let preview = if body.len() > 500 { &body[..500] } else { body };
    println!("body ({} bytes):\n{preview}", body.len());
    println!();

    if version_str.contains("H3") || version_str.contains("HTTP/3") {
        println!(
            "PROOF: H3 worked end-to-end through SOCKS5 UDP. \
             The proxy's UDP ASSOCIATE + relay are functional."
        );
    } else {
        println!(
            "WARN: returned non-H3 version ({version_str}) despite http3_only(). \
             Check the trace log."
        );
    }

    Ok(())
}
