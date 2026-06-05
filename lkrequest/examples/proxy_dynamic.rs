//! Dynamic proxy example — residential proxy with per-request session-id.
//!
//! Demonstrates using `FnProxyProvider` + `SessionPool` for dynamic
//! residential proxy services where each request gets a unique exit IP
//! via a different session-id in the proxy username.
//!
//! Run with:
//!   cargo run -p lkrequest --example proxy_dynamic

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lkrequest::{Client, SessionPool};

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

    // Each call generates a unique session-id → unique exit IP.
    // Adjust the URL format to match your residential proxy provider.
    let counter = Arc::new(AtomicU64::new(1));
    let pool = SessionPool::builder()
        .client(&client)
        .proxy_fn(move || {
            let id = counter.fetch_add(1, Ordering::Relaxed);
            format!("http://user-sid-{id:06}-sesstime=5:password@residential-gw.example.com:7777")
        })
        .proxy_buffer(30)
        .max_sessions(50)
        .idle_timeout(Duration::from_secs(60))
        .build();

    // Send multiple requests, each through a different exit IP
    let urls = [
        "https://httpbin.org/ip",
        "https://httpbin.org/ip",
        "https://httpbin.org/ip",
    ];

    for (i, url) in urls.iter().enumerate() {
        let guard = pool.acquire().await;
        match guard.get(url).send().await {
            Ok(resp) => {
                let body: serde_json::Value = resp.json()?;
                println!("request #{i} -> IP: {}", body["origin"]);
            }
            Err(e) => {
                eprintln!("request #{i} -> error: {e}");
            }
        }
    }

    // Concurrent requests — each spawned task gets its own session + proxy
    let mut handles = vec![];
    for i in 0..5 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            let guard = pool.acquire().await;
            match guard.get("https://httpbin.org/ip").send().await {
                Ok(resp) => {
                    let body: serde_json::Value = resp.json().unwrap();
                    println!("concurrent #{i} -> IP: {}", body["origin"]);
                }
                Err(e) => eprintln!("concurrent #{i} -> error: {e}"),
            }
        }));
    }
    for h in handles {
        h.await?;
    }

    println!("\nDone!");
    Ok(())
}
