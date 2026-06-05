//! SessionPool example — high-concurrency with proxy rotation.
//!
//! Demonstrates:
//! - Creating a SessionPool with multiple proxies
//! - Using `acquire()` / automatic release via RAII guards
//! - Concurrent requests with `buffer_unordered`
//! - Bad proxy marking
//!
//! Note: This example uses placeholder proxy addresses. Replace them with
//! real proxies to test actual proxy rotation.
//!
//! Run with:
//!   cargo run -p lkrequest --example session_pool

use std::time::Duration;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::proxy::ProxyConfig;
use lkrequest::Client;
use lkrequest::SessionPool;
use lktls::profile::presets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Example 1: Basic SessionPool usage (no proxies) ---
    println!("=== Example 1: Basic SessionPool (no proxies) ===\n");

    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build();

    // Create a pool with no proxies (direct connections) and max 5 sessions
    let pool = SessionPool::builder()
        .client(&client)
        .proxies(vec![])
        .max_sessions(5)
        .idle_timeout(Duration::from_secs(60))
        .build();

    // Acquire a session — this returns a RAII guard that auto-releases on drop
    {
        let guard = pool.acquire().await;
        println!("Acquired session, sending request...");
        let resp = guard.get("https://httpbin.org/get").send().await?;
        println!("Response status: {}\n", resp.status());
    }
    // guard dropped here → session returned to pool automatically

    // --- Example 2: Concurrent requests ---
    println!("=== Example 2: Concurrent requests ===\n");

    let urls = vec![
        "https://httpbin.org/get?id=1",
        "https://httpbin.org/get?id=2",
        "https://httpbin.org/get?id=3",
        "https://httpbin.org/get?id=4",
        "https://httpbin.org/get?id=5",
    ];

    // Use futures::stream for buffer_unordered pattern
    // (or simply spawn tasks as shown below)
    let pool_clone = pool.clone();
    let mut handles = vec![];

    for url in &urls {
        let pool = pool_clone.clone();
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            let guard = pool.acquire().await;
            let resp = guard.get(&url).send().await;
            match resp {
                Ok(r) => println!("  {} -> {}", url, r.status()),
                Err(e) => println!("  {} -> ERROR: {}", url, e),
            }
        }));
    }

    for handle in handles {
        handle.await?;
    }

    println!("\nAll concurrent requests complete!");

    // --- Example 3: SessionPool with proxies (conceptual) ---
    println!("\n=== Example 3: SessionPool with proxies (conceptual) ===\n");

    // NOTE: These are placeholder proxies. Replace with real ones to test.
    let proxy_configs: Vec<ProxyConfig> = vec![
        // Uncomment and replace with real proxies to test:
        // ProxyConfig::parse("socks5://user:pass@proxy1.example.com:1080")?,
        // ProxyConfig::parse("http://user:pass@proxy2.example.com:8080")?,
    ];

    if proxy_configs.is_empty() {
        println!("No real proxies configured — showing conceptual usage:\n");
        println!(
            r#"  let pool = SessionPool::builder()
      .client(&client)
      .proxies(proxy_configs)       // Vec<ProxyConfig>
      .max_sessions(100)            // Max concurrent sessions
      .idle_timeout(Duration::from_secs(300))
      .rotation(RotationStrategy::RoundRobin)
      .build();

  // Each acquired session gets a different proxy
  let guard = pool.acquire().await;
  match guard.get(url).send().await {{
      Ok(resp) if resp.status() == 403 => {{
          // Mark proxy as bad — enters cooldown
          pool.mark_bad(&guard);
      }}
      Err(e) => {{
          eprintln!("Request failed: {{e}}");
          pool.mark_bad(&guard);
      }}
      Ok(resp) => {{
          println!("Success: {{}}", resp.status());
      }}
  }}"#
        );
    } else {
        let pool = SessionPool::builder()
            .client(&client)
            .proxies(proxy_configs)
            .max_sessions(10)
            .idle_timeout(Duration::from_secs(60))
            .build();

        let guard = pool.acquire().await;
        let resp = guard.get("https://httpbin.org/ip").send().await?;
        println!("IP via proxy: {}", resp.text()?);
    }

    println!("\nDone!");

    Ok(())
}
