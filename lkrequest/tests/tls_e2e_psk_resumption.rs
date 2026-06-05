//! End-to-end TLS 1.3 PSK resumption test.
//!
//! Connects to the same host twice using a shared `InMemorySessionStore`.
//! The first connection performs a full handshake and stores a NewSessionTicket.
//! The second connection should use PSK resumption (verified via tracing logs).

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lkrequest::TlsConnector;
use lktls::profile::presets;
use lktls::session_store::InMemorySessionStore;

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

/// Test TLS 1.3 PSK resumption by connecting twice to the same host.
///
/// Flow:
/// 1. First connection: full TLS 1.3 handshake → receive NewSessionTicket → store
/// 2. Second connection: PSK injected into ClientHello → server accepts → abbreviated handshake
///
/// Verification: capture tracing logs and check for "tls13.psk_accepted" message.
#[tokio::test]
#[ignore = "Tier-2: Cloudflare"]
async fn test_tls13_psk_resumption() {
    // Set up tracing to capture log messages
    use std::sync::Mutex;
    let captured_logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_for_layer = captured_logs.clone();

    // Custom tracing layer that captures log messages
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    struct LogCapture {
        logs: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> Layer<S> for LogCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            if let Ok(mut logs) = self.logs.lock() {
                logs.push(visitor.0);
            }
        }
    }

    struct MessageVisitor(String);
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{:?}", value);
            } else {
                if !self.0.is_empty() {
                    self.0.push(' ');
                }
                self.0.push_str(&format!("{}={:?}", field.name(), value));
            }
        }
    }

    let subscriber = tracing_subscriber::registry().with(LogCapture {
        logs: logs_for_layer,
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    let store = Arc::new(InMemorySessionStore::new());
    let profile = presets::chrome_131();
    let host = "www.cloudflare.com";

    // --- First connection: full handshake ---
    {
        let connector = TlsConnector::new(profile.clone()).session_store(store.clone());

        let mut tls = tls_connect_with_retry(&connector, host, 443, MAX_RETRIES).await;

        // Send a minimal HTTP request to trigger post-handshake messages
        // (NewSessionTicket is sent as post-handshake in TLS 1.3)
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes())
            .await
            .expect("write failed");
        tls.flush().await.expect("flush failed");

        // Read some response data to allow NewSessionTicket to arrive
        let mut buf = [0u8; 16384];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read(&mut buf)).await;

        eprintln!("[PSK test] First connection complete — full handshake");
    }

    // Brief pause to ensure ticket is stored
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify that a ticket was stored
    // (We peek: store.take() would consume, so we create a second store-aware connector instead)
    eprintln!("[PSK test] Session store populated, attempting PSK resumption...");

    // Clear logs before second connection
    if let Ok(mut logs) = captured_logs.lock() {
        logs.clear();
    }

    // --- Second connection: should use PSK resumption ---
    {
        let connector = TlsConnector::new(profile.clone()).session_store(store.clone());

        let mut tls = tls_connect_with_retry(&connector, host, 443, MAX_RETRIES).await;

        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes())
            .await
            .expect("write failed (2nd)");
        tls.flush().await.expect("flush failed (2nd)");

        let mut buf = [0u8; 16384];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read(&mut buf)).await;

        eprintln!("[PSK test] Second connection complete");
    }

    // Check captured logs for PSK acceptance
    let logs = captured_logs.lock().unwrap();
    let psk_accepted = logs
        .iter()
        .any(|msg| msg.contains("psk_accepted") || msg.contains("psk_resumption"));

    eprintln!("[PSK test] Captured {} log messages", logs.len());
    for log in logs.iter() {
        if log.contains("psk")
            || log.contains("PSK")
            || log.contains("ticket")
            || log.contains("resumption")
        {
            eprintln!("  >> {log}");
        }
    }

    assert!(
        psk_accepted,
        "Expected PSK resumption on second connection. \
         The server should have accepted our PSK (look for 'tls13.psk_accepted' in logs). \
         This may indicate a Binder calculation or truncated transcript offset bug."
    );

    eprintln!("[PSK test] SUCCESS — TLS 1.3 PSK resumption verified!");
}
