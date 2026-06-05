//! HTTP/3 auto-discovery via Alt-Svc.
//!
//! Demonstrates the full H3 discovery lifecycle:
//! 1. First request goes over TCP + H2
//! 2. Server responds with `Alt-Svc: h3=":443"` header
//! 3. Second request automatically upgrades to QUIC/H3
//!
//! Run with:
//!   cargo run -p lkrequest --features quic-h3 --example h3_auto_discovery

use lkrequest::Client;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("lkrequest=debug,lktls_quic=info")
        .init();

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build();

    // Auto mode: will discover H3 via Alt-Svc or DNS HTTPS
    let session = client.session().build();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://cloudflare.com/".to_string());

    // First request — should go via TCP+TLS (H2 or H1)
    println!("=== Request 1: expecting H2 (first visit) ===");
    let resp1 = session.get(&url).send().await?;
    println!("Status:  {}", resp1.status());
    println!("Version: {}", resp1.version());
    if let Some(alt_svc) = resp1.headers().get("alt-svc") {
        println!("Alt-Svc: {}", alt_svc.to_str().unwrap_or("<binary>"));
    } else {
        println!("Alt-Svc: (not present)");
    }
    let _ = resp1.text()?;

    // Small delay to let Alt-Svc cache settle
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Second request — should try QUIC/H3 if Alt-Svc was received
    println!("\n=== Request 2: expecting H3 (Alt-Svc discovered) ===");
    let resp2 = session.get(&url).send().await?;
    println!("Status:  {}", resp2.status());
    println!("Version: {}", resp2.version());
    let _ = resp2.text()?;

    // Third request — should reuse pooled H3 connection
    println!("\n=== Request 3: expecting H3 (pooled connection) ===");
    let resp3 = session.get(&url).send().await?;
    println!("Status:  {}", resp3.status());
    println!("Version: {}", resp3.version());
    let _ = resp3.text()?;

    println!(
        "\nDone. Protocol progression: {} → {} → {}",
        resp1.version(),
        resp2.version(),
        resp3.version()
    );

    Ok(())
}
