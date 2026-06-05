//! Primary-backup proxy with automatic failover via SessionPool.
//!
//! Demonstrates:
//! - `PrimaryBackupProvider`: custom `ProxyProvider` that normally yields
//!   proxies from a "primary" pool and falls back to a "backup" pool
//!   when the primary is exhausted or in cooldown.
//! - `SessionPool` + `mark_bad` / `acquire_fresh` for fully automatic
//!   proxy health tracking, cooldown, and switching.
//!
//! Run with:
//!   cargo run -p lkrequest --example proxy_dyn_fallback

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lkrequest::proxy::{
    FnProxyProvider, ProxyConfig, ProxyProvider, ProxyRotator, RotationStrategy,
};
use lkrequest::{BadProxyConfig, Client, SessionPool};

/// Custom ProxyProvider: primary pool first, fallback to backup on failover.
///
/// The failover flag is toggled externally (or you can let SessionPool's
/// built-in `mark_bad` cooldown handle individual proxies automatically).
pub struct PrimaryBackupProvider {
    primary: Box<dyn ProxyProvider>,
    backup: Box<dyn ProxyProvider>,
    failed_over: AtomicBool,
    failure_count: AtomicU32,
    failover_threshold: u32,
    recovery_interval: Duration,
    last_recovery_attempt: Mutex<Instant>,
}

impl PrimaryBackupProvider {
    pub fn new(
        primary: Box<dyn ProxyProvider>,
        backup: Box<dyn ProxyProvider>,
        failover_threshold: u32,
        recovery_interval: Duration,
    ) -> Self {
        Self {
            primary,
            backup,
            failed_over: AtomicBool::new(false),
            failure_count: AtomicU32::new(0),
            failover_threshold,
            recovery_interval,
            last_recovery_attempt: Mutex::new(Instant::now()),
        }
    }

    pub fn mark_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.failover_threshold && !self.failed_over.load(Ordering::Relaxed) {
            self.failed_over.store(true, Ordering::Relaxed);
            eprintln!("[failover] primary failed {count} times, switching to backup");
        }
    }

    pub fn mark_success(&self) {
        if !self.failed_over.load(Ordering::Relaxed) {
            self.failure_count.store(0, Ordering::Relaxed);
        }
    }

    pub fn try_probe_primary(&self) -> Option<ProxyConfig> {
        if !self.failed_over.load(Ordering::Relaxed) {
            return None;
        }
        let mut last = self.last_recovery_attempt.lock().unwrap();
        if last.elapsed() >= self.recovery_interval {
            *last = Instant::now();
            drop(last);
            eprintln!("[recovery] probing primary...");
            self.primary.next_proxy()
        } else {
            None
        }
    }

    pub fn confirm_recovery(&self) {
        self.failed_over.store(false, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
        eprintln!("[recovery] primary recovered, switching back");
    }
}

impl ProxyProvider for PrimaryBackupProvider {
    fn next_proxy(&self) -> Option<ProxyConfig> {
        if self.failed_over.load(Ordering::Relaxed) {
            self.backup.next_proxy()
        } else {
            self.primary.next_proxy()
        }
    }

    fn len(&self) -> usize {
        self.primary.len() + self.backup.len()
    }

    fn is_dynamic(&self) -> bool {
        self.primary.is_dynamic() || self.backup.is_dynamic()
    }

    fn all_proxies(&self) -> Vec<ProxyConfig> {
        let mut all = self.primary.all_proxies();
        all.extend(self.backup.all_proxies());
        all
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

    // -- Primary: fixed high-quality proxies (round-robin) --
    let primary = Box::new(ProxyRotator::new(
        vec![
            ProxyConfig::parse("socks5://user:pass@primary-1.example.com:1080")?,
            ProxyConfig::parse("socks5://user:pass@primary-2.example.com:1080")?,
        ],
        RotationStrategy::RoundRobin,
    ));

    // -- Backup: dynamic residential proxy pool --
    let counter = Arc::new(AtomicU64::new(1));
    let backup = Box::new(FnProxyProvider::new(move || {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        format!("http://user-sid-{id:06}:pass@backup-gw.example.com:7777")
    }));

    // -- Combine into PrimaryBackupProvider --
    let provider = PrimaryBackupProvider::new(
        primary,
        backup,
        3,                       // 3 consecutive failures → failover
        Duration::from_secs(30), // probe primary every 30s
    );

    // -- Feed it into SessionPool for automatic proxy switching --
    let pool = SessionPool::builder()
        .client(&client)
        .proxy_provider(provider)
        .max_sessions(50)
        .idle_timeout(Duration::from_secs(120))
        .bad_proxy_config(BadProxyConfig {
            failure_threshold: 3,
            window: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(300),
            max_cooldowns: 5,
        })
        .build();

    // -- Send requests with automatic failover & retry --
    let urls = [
        "https://httpbin.org/ip",
        "https://httpbin.org/get?id=1",
        "https://httpbin.org/get?id=2",
    ];

    for url in &urls {
        let mut guard = pool.acquire().await;

        let max_retries = 3;
        for attempt in 0..max_retries {
            match guard.get(url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    println!("[ok] {url} -> {}", resp.status());
                    break;
                }
                Ok(resp) => {
                    eprintln!("[fail] {url} -> {} (attempt {attempt})", resp.status());
                    guard = pool.acquire_fresh(&guard).await;
                }
                Err(e) => {
                    eprintln!("[error] {url} -> {e} (attempt {attempt})");
                    guard = pool.acquire_fresh(&guard).await;
                }
            }
        }
        // guard dropped → session returned to pool
    }

    println!("\nDone!");
    Ok(())
}
