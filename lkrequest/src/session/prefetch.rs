use std::time::Duration;

use super::Session;

/// Result of a single prefetch attempt.
#[derive(Debug, Clone)]
pub struct PrefetchResult {
    pub url: String,
    pub success: bool,
    pub duration: Duration,
    pub error: Option<String>,
}

impl Session {
    /// Pre-warm connections for the given URLs by sending HEAD requests.
    ///
    /// Establishes TCP + TLS + ALPN for each target host concurrently.
    /// The resulting connections are stored in the session's connection pool
    /// and will be reused by subsequent requests to the same hosts.
    ///
    /// Returns a `PrefetchResult` for each URL indicating success/failure
    /// and the time taken to establish the connection.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_144()).build();
    /// # let session = client.session().build();
    /// let results = session.prefetch(&[
    ///     "https://api.example.com",
    ///     "https://cdn.example.com",
    /// ]).await;
    ///
    /// for r in &results {
    ///     println!("{}: {} ({:.0}ms)", r.url, r.success, r.duration.as_millis());
    /// }
    ///
    /// // Subsequent requests reuse pre-warmed connections
    /// let resp = session.get("https://api.example.com/data").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn prefetch(&self, urls: &[&str]) -> Vec<PrefetchResult> {
        let mut handles = Vec::with_capacity(urls.len());

        for url in urls {
            let session = self.clone();
            let url_owned = url.to_string();
            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                let result = session.head(&url_owned).send().await;
                let duration = start.elapsed();
                PrefetchResult {
                    url: url_owned,
                    success: result.is_ok(),
                    duration,
                    error: result.err().map(|e| e.to_string()),
                }
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(PrefetchResult {
                    url: String::new(),
                    success: false,
                    duration: Duration::ZERO,
                    error: Some(format!("task join error: {e}")),
                }),
            }
        }

        results
    }
}
