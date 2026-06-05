//! ProxyPool comprehensive example.
//!
//! Demonstrates all key features of `ProxyPool`:
//!
//! 1. **Decoupled proxy & session** — each task gets a fresh Session (clean
//!    cookies), while proxies are pooled and reused across tasks.
//! 2. **Dynamic proxy provider** — closure-based residential proxy generation
//!    with pre-fill buffer.
//! 3. **Static proxy list** — fixed list with round-robin rotation and
//!    automatic bad-proxy cooldown / permanent removal.
//! 4. **Concurrency control** — `max_proxies` semaphore limits parallel usage.
//! 5. **mark_bad / acquire_fresh** — per-proxy failure tracking with retry.
//! 6. **Health checking** — active TCP probes for static proxy lists.
//! 7. **Custom ProxyProvider** — plug in your own selection logic.
//! 8. **Clone & share** — `ProxyPool` is `Clone` (Arc-based), safe across tasks.
//!
//! Run with:
//!   cargo run -p lkrequest --example proxy_pool_captcha

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lkrequest::proxy::{ProxyConfig, ProxyProvider, ProxyRotator, RotationStrategy};
use lkrequest::{BadProxyConfig, Client, ProxyPool};

// ───────────────────────────────────────────────────────────────────────────
// Helper: build a fresh Session from a ProxyGuard
// ───────────────────────────────────────────────────────────────────────────

fn build_session(client: &Client, guard: &lkrequest::ProxyGuard) -> lkrequest::Session {
    if let Some(proxy) = guard.proxy() {
        client.session().proxy_config(proxy.clone()).build()
    } else {
        client.session().build()
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

    // ═══════════════════════════════════════════════════════════════════════
    // 1. Dynamic proxy provider — residential proxy with per-request session-id
    // ═══════════════════════════════════════════════════════════════════════
    println!("=== 1. Dynamic proxy provider ===\n");

    let counter = Arc::new(AtomicU64::new(1));
    let dynamic_pool = ProxyPool::builder()
        .proxy_fn(move || {
            let id = counter.fetch_add(1, Ordering::Relaxed);
            // Each call produces a unique session-id → unique exit IP
            format!("http://user-sid-{id:06}-sesstime=5:password@residential-gw.example.com:7777")
        })
        .proxy_buffer(20) // pre-generate 20 ProxyConfigs in background
        .max_proxies(10) // at most 10 concurrent proxy usages
        .build();

    // Captcha solving: same path, different domains, each task starts clean.
    let captcha_path = "/v3/anchor";
    let domains = [
        "site-a.example.com",
        "site-b.example.com",
        "site-c.example.com",
    ];

    for (i, domain) in domains.iter().enumerate() {
        let guard = dynamic_pool.acquire().await;
        //   ↑ ProxyGuard holds a semaphore permit (max 10 concurrent)

        // Fresh Session — empty cookie jar, no stale TLS tickets
        let session = build_session(&client, &guard);

        let url = format!("https://{domain}{captcha_path}");
        match session.get(&url).send().await {
            Ok(resp) => println!("  task #{i} [{domain}] -> {}", resp.status()),
            Err(e) => {
                eprintln!("  task #{i} [{domain}] -> error: {e}");
                guard.mark_bad(); // no-op for dynamic providers, but good practice
            }
        }
        // guard dropped → permit released, next acquire() can proceed
        // session dropped → cookies & connections destroyed (clean for next task)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. Concurrency control — spawn many tasks, pool limits parallelism
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n=== 2. Concurrency control (max_proxies=10, 20 tasks) ===\n");

    let mut handles = vec![];
    for i in 0..20 {
        let pool = dynamic_pool.clone(); // Arc clone — cheap
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            // If all 10 permits are in use, this awaits until one is released.
            let guard = pool.acquire().await;
            let session = build_session(&client, &guard);

            let url = format!("https://target-{}.example.com/captcha/solve", i % 5);
            match session.get(&url).send().await {
                Ok(resp) => println!("  concurrent #{i:02} -> {}", resp.status()),
                Err(e) => eprintln!("  concurrent #{i:02} -> error: {e}"),
            }
        }));
    }
    for h in handles {
        h.await?;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. Static proxy list — fixed proxies with bad-proxy detection
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n=== 3. Static proxy list with bad-proxy cooldown ===\n");

    let static_pool = ProxyPool::builder()
        .proxies(vec![
            ProxyConfig::parse("socks5://user:pass@dc-proxy-1.example.com:1080")?,
            ProxyConfig::parse("socks5://user:pass@dc-proxy-2.example.com:1080")?,
            ProxyConfig::parse("http://user:pass@dc-proxy-3.example.com:8080")?,
        ])
        .rotation(RotationStrategy::RoundRobin)
        .max_proxies(20)
        .bad_proxy_config(BadProxyConfig {
            failure_threshold: 2,                       // 2 failures in window → cooldown
            window: Duration::from_secs(30),            // 30s sliding window
            cooldown_duration: Duration::from_secs(60), // 60s cooldown
            max_cooldowns: 3,                           // 3 cooldowns → permanently removed
        })
        .build();

    for i in 0..6 {
        let guard = static_pool.acquire().await;
        let proxy_id = guard
            .proxy()
            .map(|p| p.identity())
            .unwrap_or_else(|| "direct".into());
        let session = build_session(&client, &guard);

        match session.get("https://httpbin.org/ip").send().await {
            Ok(resp) => println!("  request #{i} via [{proxy_id}] -> {}", resp.status()),
            Err(e) => {
                eprintln!("  request #{i} via [{proxy_id}] -> error: {e}");
                // mark_bad feeds the sliding-window counter.
                // After 2 failures within 30s, dc-proxy-X enters 60s cooldown.
                guard.mark_bad();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 4. mark_bad + acquire_fresh — retry with a different proxy
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n=== 4. Retry with acquire_fresh ===\n");

    let guard = static_pool.acquire().await;
    let session = build_session(&client, &guard);

    let max_retries = 3;
    let url = "https://httpbin.org/ip";
    let mut current_guard = guard;

    for attempt in 0..max_retries {
        let sess = if attempt == 0 {
            session.clone()
        } else {
            build_session(&client, &current_guard)
        };

        match sess.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("  attempt #{attempt} -> {} (success)", resp.status());
                break;
            }
            Ok(resp) => {
                eprintln!("  attempt #{attempt} -> {} (bad status)", resp.status());
                // Mark current proxy as bad and get a fresh one
                current_guard = static_pool.acquire_fresh(&current_guard).await;
            }
            Err(e) => {
                eprintln!("  attempt #{attempt} -> error: {e}");
                current_guard = static_pool.acquire_fresh(&current_guard).await;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 5. Custom ProxyProvider — plug your own selection logic
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n=== 5. Custom ProxyProvider (geo-weighted) ===\n");

    // Example: a provider that picks proxies by geographic weight.
    struct GeoWeightedProvider {
        us_proxies: ProxyRotator,
        eu_proxies: ProxyRotator,
        us_weight: u8, // out of 100
    }

    impl ProxyProvider for GeoWeightedProvider {
        fn next_proxy(&self) -> Option<ProxyConfig> {
            use aws_lc_rs::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut buf = [0u8; 1];
            rng.fill(&mut buf).unwrap();
            if buf[0] % 100 < self.us_weight {
                self.us_proxies.next_proxy()
            } else {
                self.eu_proxies.next_proxy()
            }
        }

        fn len(&self) -> usize {
            self.us_proxies.len() + self.eu_proxies.len()
        }

        fn all_proxies(&self) -> Vec<ProxyConfig> {
            let mut all = self.us_proxies.all_proxies();
            all.extend(self.eu_proxies.all_proxies());
            all
        }
    }

    let geo_provider = GeoWeightedProvider {
        us_proxies: ProxyRotator::new(
            vec![
                ProxyConfig::parse("http://user:pass@us-east-1.example.com:8080")?,
                ProxyConfig::parse("http://user:pass@us-west-2.example.com:8080")?,
            ],
            RotationStrategy::RoundRobin,
        ),
        eu_proxies: ProxyRotator::new(
            vec![ProxyConfig::parse(
                "http://user:pass@eu-west-1.example.com:8080",
            )?],
            RotationStrategy::RoundRobin,
        ),
        us_weight: 70, // 70% US, 30% EU
    };

    let geo_pool = ProxyPool::builder()
        .proxy_provider(geo_provider)
        .max_proxies(30)
        .build();

    for i in 0..5 {
        let guard = geo_pool.acquire().await;
        let proxy_id = guard
            .proxy()
            .map(|p| p.identity())
            .unwrap_or_else(|| "direct".into());
        println!("  request #{i} routed to [{proxy_id}]");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 6. Health checking — static proxies with active TCP probes
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n=== 6. Health checking (static proxies, TCP probe) ===\n");

    let _monitored_pool = ProxyPool::builder()
        .proxies(vec![
            ProxyConfig::parse("socks5://user:pass@monitored-1.example.com:1080")?,
            ProxyConfig::parse("socks5://user:pass@monitored-2.example.com:1080")?,
        ])
        .max_proxies(10)
        .health_check(lkrequest::proxy_pool::HealthCheckConfig {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            target_host: "www.google.com".into(),
            target_port: 443,
        })
        .bad_proxy_config(BadProxyConfig {
            failure_threshold: 2,
            window: Duration::from_secs(30),
            cooldown_duration: Duration::from_secs(120),
            max_cooldowns: 5,
        })
        .build();

    println!("  Health-check pool created.");
    println!("  Background task probes proxies every 60s via TCP to google.com:443.");
    println!("  Unhealthy proxies enter cooldown; recovered proxies resume automatically.");

    // ═══════════════════════════════════════════════════════════════════════
    // 7. ProxyPool vs SessionPool — when to use which
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n=== Summary: ProxyPool vs SessionPool ===\n");
    println!("  ProxyPool:");
    println!("    - Each task creates a fresh Session (clean cookies/connections)");
    println!("    - Proxy is the long-lived, pooled resource");
    println!("    - Best for: captcha solving, token generation, one-shot requests");
    println!();
    println!("  SessionPool:");
    println!("    - Sessions are reused (cookies, connections, TLS tickets persist)");
    println!("    - Both proxy and session are pooled together");
    println!("    - Best for: scraping, crawling, long-running virtual users");

    println!("\nDone!");
    Ok(())
}
