/// Maximum retry attempts for network-dependent tests.
pub const MAX_RETRIES: u32 = 3;

/// Retry a TLS connection attempt (TCP connect + TLS handshake) up to `max` times.
///
/// On each failure, prints the error and waits 1 second before retrying.
/// Returns the `TlsStream` on success, panics on exhaustion.
pub async fn tls_connect_with_retry(
    connector: &lkrequest::TlsConnector,
    host: &str,
    port: u16,
    max_retries: u32,
) -> lkrequest::TlsStream {
    let mut last_err = String::new();
    for attempt in 1..=max_retries {
        let tcp = match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
            Ok(tcp) => tcp,
            Err(e) => {
                last_err = format!("TCP connect failed: {e}");
                if attempt < max_retries {
                    eprintln!("  [retry {attempt}/{max_retries}] {last_err}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        match connector.connect(host, port, tcp).await {
            Ok(tls) => return tls,
            Err(e) => {
                last_err = format!("TLS handshake failed: {e}");
                if attempt < max_retries {
                    eprintln!("  [retry {attempt}/{max_retries}] {last_err}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!("TLS connect to {host}:{port} failed after {max_retries} attempts: {last_err}");
}
