//! Basic HTTP/3 request example.
//!
//! Sends a GET request over QUIC/HTTP3 to a server that supports it.
//! Uses Chrome-like QUIC/TLS transport parameters, but with a conservative
//! H3/QPACK configuration for broad interoperability with public servers.
//!
//! Run with:
//!   cargo run -p lkrequest --features quic-h3 --example basic_h3

use lkh3::chrome_quic;
use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("lkrequest=debug,lktls_quic=debug,lkh3=debug")
        .init();

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

    // Force HTTP/3 — will fail if the server doesn't support QUIC
    let session = client.session().http3_only().build();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://cloudflare-quic.com/".to_string());

    println!("Sending H3 request to {url} ...");
    let resp = session.get(&url).send().await?;

    println!("Status:   {}", resp.status());
    println!("Version:  {}", resp.version());
    println!("Headers:");
    for (name, value) in resp.headers() {
        println!("  {name}: {}", value.to_str().unwrap_or("<binary>"));
    }

    let body = resp.text()?;
    let preview = if body.len() > 500 { &body[..500] } else { body };
    println!("\nBody ({} bytes):\n{preview}", body.len());

    Ok(())
}
