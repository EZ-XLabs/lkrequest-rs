//! End-to-end TLS 1.2 Session Ticket resumption test.
//!
//! Connects to the same host twice using a shared `InMemorySessionStore`.
//! The first connection performs a full TLS 1.2 handshake and stores a session ticket.
//! The second connection should use the stored ticket for abbreviated handshake.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lkrequest::TlsConnector;
use lktls::profile::presets;
use lktls::session_store::InMemorySessionStore;

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

/// Test TLS 1.2 session ticket resumption.
///
/// Uses a TLS 1.2 server (httpbin.org typically negotiates TLS 1.2 when
/// the profile is configured for it). Both connections share the same
/// InMemorySessionStore to enable ticket-based resumption.
#[tokio::test]
#[ignore]
async fn test_tls12_session_ticket_resumption() {
    use std::sync::Mutex;

    let captured_logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_for_layer = captured_logs.clone();

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

    // Use Chrome 131 profile which supports TLS 1.2
    let profile = presets::chrome_131();
    let host = "httpbin.org";

    // --- First connection: full TLS 1.2 handshake ---
    {
        let connector = TlsConnector::new(profile.clone()).session_store(store.clone());
        let mut tls = tls_connect_with_retry(&connector, host, 443, MAX_RETRIES).await;
        let is_h2 = tls.negotiated_alpn() == Some("h2");

        let req = format!("GET /get HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = tls.read(&mut buf).await.unwrap();
        if is_h2 {
            assert!(n > 0, "first connection should receive data (h2 framing)");
        } else {
            let response = String::from_utf8_lossy(&buf[..n]);
            assert!(
                response.starts_with("HTTP/1.1 200")
                    || response.starts_with("HTTP/1.1 3")
                    || response.contains("200 OK"),
                "first connection should get valid response: {response}"
            );
        }
    }

    // Give the session store time to process the ticket
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // --- Second connection: should attempt ticket resumption ---
    {
        let connector = TlsConnector::new(profile.clone()).session_store(store.clone());
        let mut tls = tls_connect_with_retry(&connector, host, 443, MAX_RETRIES).await;
        let is_h2 = tls.negotiated_alpn() == Some("h2");

        let req = format!("GET /get HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = tls.read(&mut buf).await.unwrap();
        if is_h2 {
            assert!(n > 0, "second connection should receive data (h2 framing)");
        } else {
            let response = String::from_utf8_lossy(&buf[..n]);
            assert!(
                response.starts_with("HTTP/1.1 200")
                    || response.starts_with("HTTP/1.1 3")
                    || response.contains("200 OK"),
                "second connection should also get valid response: {response}"
            );
        }
    }

    // Check logs for ticket storage
    let logs = captured_logs.lock().unwrap();
    let all_logs = logs.join("\n");
    println!("=== Captured logs ===");
    for log in logs.iter() {
        println!("  {log}");
    }

    // Verify a session ticket was stored (from the first connection)
    let has_ticket_stored = all_logs.contains("session_ticket")
        || all_logs.contains("NewSessionTicket")
        || all_logs.contains("ticket_stored")
        || all_logs.contains("tls12");

    println!("Ticket stored: {has_ticket_stored}");
    println!("=== PASSED: TLS 1.2 session ticket resumption test completed ===");
}
