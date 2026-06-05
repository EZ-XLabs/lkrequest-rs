//! End-to-end HTTP/3: from DNS HTTPS record to H3 response.
//!
//! Demonstrates the complete lifecycle of a modern QUIC/H3 connection
//! as a real browser would perform it:
//!
//! ```text
//! [1] DNS HTTPS RR query  →  discover alpn="h3", ECH config, hints
//! [2] QUIC handshake      →  lktls TLS 1.3 ClientHello (Chrome fingerprint)
//!                             + QUIC transport parameters
//! [3] H3 connection       →  SETTINGS frame (Chrome H3 fingerprint)
//!                             + QPACK setup
//! [4] H3 request          →  pseudo-header order (masp)
//!                             + header/cookie ordering
//! [5] H3 response         →  decompress, read body
//! [6] Alt-Svc caching     →  cache for future requests
//! [7] Session resumption  →  0-RTT on next connection
//! ```
//!
//! Run with:
//!   cargo run -p lkrequest --features quic-h3 --example h3_dns_to_response
//!
//! Or with a custom URL:
//!   cargo run -p lkrequest --features quic-h3 --example h3_dns_to_response -- https://cloudflare.com/

use std::time::Instant;

use lkh3::chrome_quic;
use lkrequest::dns::{DnsResolver, HickoryDns};
use lkrequest::{Client, DnsConfig};
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "lkrequest=info,lktls_quic=info,lkh3=info".into()),
        )
        .init();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://cloudflare.com/cdn-cgi/trace".to_string());
    let host = url::Url::parse(&url)?
        .host_str()
        .unwrap_or("cloudflare.com")
        .to_string();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  End-to-End: DNS HTTPS → QUIC → H3 → Response              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =========================================================================
    // Step 1: DNS HTTPS record query
    // =========================================================================
    println!("━━━ Step 1: DNS HTTPS Record Query ━━━");
    // Use plain UDP DNS for the standalone HTTPS RR probe (avoids DoH
    // certificate issues in some environments). The Client itself can use
    // any resolver — we just want to show the HTTPS record here.
    let dns = HickoryDns::from_config(&DnsConfig::Cloudflare);
    let total_start = Instant::now();

    let dns_start = Instant::now();
    let https_record = dns.lookup_https(&host).await?;
    let dns_elapsed = dns_start.elapsed();

    match &https_record {
        Some(record) => {
            println!("  Host:       {host}");
            println!("  Time:       {dns_elapsed:.1?}");
            println!("  ALPN:       {:?}", record.alpn);
            println!("  H3 support: {}", record.supports_h3());
            println!("  Target:     {:?}", record.target);
            println!("  Port:       {:?}", record.port);
            println!("  IPv4 hints: {:?}", record.ipv4_hints);
            println!("  IPv6 hints: {:?}", record.ipv6_hints);
            if let Some(ech_config_list) = &record.ech_config_list {
                println!("  ECH config: present ({} bytes)", ech_config_list.len());
            } else {
                println!("  ECH config: not present");
            }
        }
        None => {
            println!("  No HTTPS record found for {host}");
            println!("  (Will rely on Alt-Svc discovery instead)");
        }
    }

    // =========================================================================
    // Step 2: Build client with DNS resolver + Chrome profile
    // =========================================================================
    println!("\n━━━ Step 2: Client Configuration ━━━");

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .quic_profile(chrome_quic().with_static_qpack())
        .dns(DnsConfig::Cloudflare)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build();

    println!("  TLS profile:      {}", client.tls_profile().name);
    if let Some(qp) = client.quic_profile() {
        println!("  QUIC CID length:  {}", qp.connection_id_length);
        println!("  Transport params:");
        println!(
            "    idle_timeout:     {} ms",
            qp.transport_params.max_idle_timeout
        );
        println!(
            "    max_data:         {} bytes",
            qp.transport_params.initial_max_data
        );
        println!(
            "    streams_bidi:     {}",
            qp.transport_params.initial_max_streams_bidi
        );
        println!(
            "    active_cid_limit: {}",
            qp.transport_params.active_connection_id_limit
        );
        println!("  H3 settings:      {:?}", qp.h3.settings);
        println!(
            "  H3 pseudo order:  {} ({})",
            qp.h3.pseudo_header_order_token(),
            qp.h3
                .pseudo_header_order
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  H3 GREASE:        {}", qp.h3.grease_settings);
    } else {
        println!("  QUIC profile:     (default)");
    }

    // =========================================================================
    // Step 3: First request — protocol auto-selection
    // =========================================================================
    println!("\n━━━ Step 3: First Request (auto protocol selection) ━━━");

    let session = client.session().build();

    let req_start = Instant::now();
    let resp1 = session.get(&url).send().await?;
    let req_elapsed = req_start.elapsed();

    let version1 = resp1.version().to_string();
    let status1 = resp1.status();
    let alt_svc1 = resp1
        .headers()
        .get("alt-svc")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body1 = resp1.text()?;

    println!("  URL:        {url}");
    println!("  Protocol:   {version1}");
    println!("  Status:     {status1}");
    println!("  Time:       {req_elapsed:.1?}");
    println!("  Body size:  {} bytes", body1.len());
    if let Some(ref alt_svc) = alt_svc1 {
        let preview = if alt_svc.len() > 80 {
            &alt_svc[..80]
        } else {
            alt_svc
        };
        println!("  Alt-Svc:    {preview}");
    }

    if alt_svc1.is_some() && version1.eq_ignore_ascii_case("h2") {
        println!("  Action:     Clearing pooled TCP connections to force QUIC re-dial");
        session.pool_clear();
    }

    // =========================================================================
    // Step 4: Second request — should race/upgrade to H3 after discovery
    // =========================================================================
    println!("\n━━━ Step 4: Second Request (after discovery) ━━━");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let req_start = Instant::now();
    let resp2 = session.get(&url).send().await?;
    let req_elapsed = req_start.elapsed();

    let version2 = resp2.version().to_string();
    println!("  Protocol:   {version2}");
    println!("  Status:     {}", resp2.status());
    println!("  Time:       {req_elapsed:.1?}");
    let _ = resp2.text()?;

    // =========================================================================
    // Step 5: Third request — pooled connection reuse
    // =========================================================================
    println!("\n━━━ Step 5: Third Request (connection reuse) ━━━");

    let req_start = Instant::now();
    let resp3 = session.get(&url).send().await?;
    let req_elapsed = req_start.elapsed();

    let version3 = resp3.version().to_string();
    println!("  Protocol:   {version3}");
    println!("  Status:     {}", resp3.status());
    println!("  Time:       {req_elapsed:.1?} (should be fast — reused connection)");
    let _ = resp3.text()?;

    // =========================================================================
    // Step 6: Fresh connection in same session — ticket / 0-RTT candidate
    // =========================================================================
    println!("\n━━━ Step 6: Fresh Connection In Same Session ━━━");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    session.pool_clear();
    println!("  Action:     Cleared pool to force a new connection with cached session tickets");
    let req_start = Instant::now();
    let resp4 = session.get(&url).send().await?;
    let req_elapsed = req_start.elapsed();

    let version4 = resp4.version().to_string();
    println!("  Protocol:   {version4}");
    println!("  Status:     {}", resp4.status());
    println!("  Time:       {req_elapsed:.1?} (may benefit from session resumption)");
    let _ = resp4.text()?;

    // =========================================================================
    // Summary
    // =========================================================================
    let total_elapsed = total_start.elapsed();
    println!("\n━━━ Summary ━━━");
    println!("  Total time:           {total_elapsed:.1?}");
    println!("  Protocol progression: {version1} → {version2} → {version3} → {version4}");
    println!("  DNS HTTPS available:  {}", https_record.is_some());
    println!(
        "  H3 via DNS:           {}",
        https_record.as_ref().is_some_and(|r| r.supports_h3())
    );
    println!("  H3 via Alt-Svc:       {}", alt_svc1.is_some());

    let reached_h3 = [&version2, &version3, &version4]
        .iter()
        .any(|v| v.contains("h3") || v.contains("H3"));
    if reached_h3 {
        println!("  Result:               Successfully upgraded to HTTP/3");
    } else {
        println!(
            "  Result:               Stayed on HTTP/2 (server may not support H3, or QUIC blocked)"
        );
    }

    // Show response body preview
    let preview = if body1.len() > 300 {
        &body1[..300]
    } else {
        body1
    };
    println!("\n━━━ Response Body Preview ━━━");
    println!("{preview}");

    Ok(())
}
