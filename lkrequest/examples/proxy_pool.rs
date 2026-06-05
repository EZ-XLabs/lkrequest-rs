//! ProxyPool example — decoupled proxy management with fresh sessions.
//!
//! Shows the core ProxyPool workflow:
//!   1. ProxyPool manages proxy allocation + concurrency
//!   2. Each task acquires a proxy, builds a fresh Session, sends requests
//!   3. Session is discarded after use (clean cookies), proxy permit is released
//!
//! This is the recommended pattern for captcha solving, token generation,
//! or any scenario where cookie/TLS state must not leak between tasks.
//!
//! Run with:
//!   cargo run -p lkrequest --example proxy_pool

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lkrequest::{Client, ProxyGuard, ProxyPool, Session};

/// Build a fresh Session from a ProxyGuard — clean cookies, no stale connections.
fn fresh_session(client: &Client, guard: &ProxyGuard) -> Session {
    match guard.proxy() {
        Some(proxy) => client.session().proxy_config(proxy.clone()).build(),
        None => client.session().build(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .default_header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .default_header("accept-language", "en-US,en;q=0.9")
        .build();

    // ── Build a ProxyPool with dynamic residential proxies ──────────────
    let counter = Arc::new(AtomicU64::new(1));
    let pool = ProxyPool::builder()
        .proxy_fn(move || {
            let id = counter.fetch_add(1, Ordering::Relaxed);
            format!("http://user-sid-{id:06}-sesstime=5:pass@residential-gw.example.com:7777")
        })
        .proxy_buffer(20) // pre-generate 20 configs in background
        .max_proxies(10) // at most 10 concurrent proxy usages
        .build();

    // ── Sequential: different domains, same captcha path ────────────────
    println!("--- Sequential requests (different domains, fixed path) ---\n");

    let captcha_path = "/v3/anchor";
    let domains = [
        "site-a.example.com",
        "site-b.example.com",
        "site-c.example.com",
    ];

    for (i, domain) in domains.iter().enumerate() {
        let guard = pool.acquire().await;
        let session = fresh_session(&client, &guard);

        let url = format!("https://{domain}{captcha_path}");
        match session.get(&url).send().await {
            Ok(resp) => println!("  #{i} [{domain}] -> {}", resp.status()),
            Err(e) => {
                eprintln!("  #{i} [{domain}] -> error: {e}");
                guard.mark_bad();
            }
        }
        // session dropped  → cookies destroyed (clean for next task)
        // guard dropped    → proxy permit released
    }

    // ── Concurrent: 20 tasks, pool limits to 10 at a time ──────────────
    println!("\n--- Concurrent requests (20 tasks, max 10 parallel) ---\n");

    let mut handles = vec![];
    for i in 0..20 {
        let pool = pool.clone();
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let guard = pool.acquire().await; // blocks if 10 permits in use
            let session = fresh_session(&client, &guard);

            match session.get("https://httpbin.org/ip").send().await {
                Ok(resp) => {
                    let body: serde_json::Value = resp.json().unwrap_or_default();
                    println!("  concurrent #{i:02} -> IP: {}", body["origin"]);
                }
                Err(e) => {
                    eprintln!("  concurrent #{i:02} -> error: {e}");
                    guard.mark_bad();
                }
            }
        }));
    }
    for h in handles {
        h.await?;
    }

    // ── Retry with acquire_fresh ────────────────────────────────────────
    println!("\n--- Retry with proxy switching (acquire_fresh) ---\n");

    let mut guard = pool.acquire().await;
    for attempt in 0..3 {
        let session = fresh_session(&client, &guard);
        match session.get("https://httpbin.org/ip").send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().unwrap_or_default();
                println!("  attempt #{attempt} -> OK, IP: {}", body["origin"]);
                break;
            }
            Ok(resp) => {
                eprintln!("  attempt #{attempt} -> bad status: {}", resp.status());
                guard = pool.acquire_fresh(&guard).await;
            }
            Err(e) => {
                eprintln!("  attempt #{attempt} -> error: {e}, switching proxy...");
                guard = pool.acquire_fresh(&guard).await;
            }
        }
    }

    println!("\nDone!");
    Ok(())
}
