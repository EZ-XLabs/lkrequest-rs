use std::fmt;
use std::net::SocketAddr;

use crate::error::{Error, Result};

/// Configuration for a proxy (optionally a multi-hop **proxychain**).
///
/// `scheme`/`auth` describe the **final** hop — the proxy that connects to the
/// target. `chain` holds the upstream hops traversed *before* it (client→…);
/// an empty `chain` is an ordinary single proxy. The full path is
/// `chain[0] → chain[1] → … → self → target`, each hop CONNECT-tunneled over
/// the previous hop's stream. Build chains with
/// [`parse_chain`](ProxyConfig::parse_chain) or [`through`](ProxyConfig::through).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// The proxy protocol and address.
    pub scheme: ProxyScheme,
    /// Optional authentication credentials.
    pub auth: Option<ProxyAuth>,
    /// Upstream hops to traverse before reaching this proxy (proxychain).
    ///
    /// Ordered client→…; empty means a direct connection to this proxy. Each
    /// entry is itself a single hop (its own `chain` is ignored).
    pub chain: Vec<ProxyConfig>,
}

/// Proxy protocol type.
#[derive(Debug, Clone)]
pub enum ProxyScheme {
    /// HTTP CONNECT proxy.
    Http {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port.
        port: u16,
    },
    /// SOCKS5 proxy (remote DNS — the proxy resolves the hostname).
    Socks5 {
        /// Proxy hostname or IP address.
        host: String,
        /// Proxy port.
        port: u16,
        /// If `true`, the proxy resolves the target hostname (socks5h).
        /// If `false`, local DNS resolution is done first (socks5).
        remote_dns: bool,
    },
}

/// Proxy authentication credentials.
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    /// Proxy username.
    pub username: String,
    /// Proxy password.
    pub password: String,
}

impl ProxyConfig {
    /// Parse a proxy URL string.
    ///
    /// Supported formats:
    /// - `http://host:port`
    /// - `http://user:pass@host:port`
    /// - `https://host:port`
    /// - `socks5://host:port`
    /// - `socks5://user:pass@host:port`
    pub fn parse(url: &str) -> Result<Self> {
        let parsed = url::Url::parse(url)
            .map_err(|e| Error::InvalidConfig(format!("invalid proxy URL '{url}': {e}")))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| Error::InvalidConfig(format!("proxy URL missing host: '{url}'")))?
            .to_string();

        let auth = if !parsed.username().is_empty() {
            Some(ProxyAuth {
                username: percent_decode(parsed.username()),
                password: percent_decode(parsed.password().unwrap_or("")),
            })
        } else {
            None
        };

        match parsed.scheme() {
            "http" | "https" => {
                let port = parsed.port().unwrap_or(if parsed.scheme() == "https" {
                    443
                } else {
                    8080
                });
                Ok(ProxyConfig {
                    scheme: ProxyScheme::Http { host, port },
                    auth,
                    chain: Vec::new(),
                })
            }
            "socks5" | "socks5h" => {
                let port = parsed.port().unwrap_or(1080);
                let remote_dns = parsed.scheme() == "socks5h";
                Ok(ProxyConfig {
                    scheme: ProxyScheme::Socks5 {
                        host,
                        port,
                        remote_dns,
                    },
                    auth,
                    chain: Vec::new(),
                })
            }
            other => Err(Error::InvalidConfig(format!(
                "unsupported proxy scheme '{other}' (expected http, https, socks5)"
            ))),
        }
    }

    /// Build a **proxychain** from an ordered list of proxy URLs (client→target).
    ///
    /// The last URL is the final hop (connects to the target); earlier URLs are
    /// traversed first. Equivalent to parsing each URL and chaining them.
    ///
    /// ```
    /// use lkrequest::proxy::ProxyConfig;
    /// let chain = ProxyConfig::parse_chain([
    ///     "socks5://hop1:1080",
    ///     "socks5h://hop2:1080",
    /// ]).unwrap();
    /// assert_eq!(chain.hop_count(), 2);
    /// ```
    pub fn parse_chain<I, S>(urls: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut configs: Vec<ProxyConfig> = urls
            .into_iter()
            .map(|u| ProxyConfig::parse(u.as_ref()))
            .collect::<Result<_>>()?;
        let mut last = configs.pop().ok_or_else(|| {
            Error::InvalidConfig("proxy chain must contain at least one proxy".to_string())
        })?;
        // Flatten: ignore any nested chains on the parsed hops (parse() never
        // sets one) and treat the leading configs as the upstream hops.
        last.chain = configs;
        Ok(last)
    }

    /// Prepend `hops` as upstream proxies traversed before this one.
    ///
    /// Resulting path: `hops[0] → … → hops[n-1] → self → target`.
    pub fn through(mut self, hops: Vec<ProxyConfig>) -> Self {
        self.chain = hops;
        self
    }

    /// Number of proxy hops in the path (1 = single proxy, no chain).
    pub fn hop_count(&self) -> usize {
        self.chain.len() + 1
    }

    /// Returns the host and port of this proxy.
    pub fn host_port(&self) -> (&str, u16) {
        match &self.scheme {
            ProxyScheme::Http { host, port } => (host, *port),
            ProxyScheme::Socks5 { host, port, .. } => (host, *port),
        }
    }

    /// Returns a synthetic socket address for use as a connection pool key.
    ///
    /// For IP-based proxies this is the real address; for hostname proxies
    /// a placeholder `0.0.0.0:port` is returned (the actual DNS resolution
    /// happens at connect time).
    pub fn addr(&self) -> SocketAddr {
        let (host, port) = self.host_port();
        format!("{}:{}", host, port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)))
    }

    /// Returns a unique identity string for this proxy configuration.
    ///
    /// Unlike [`addr()`](Self::addr) which only considers `host:port`, this
    /// includes the authentication username when present.  This correctly
    /// distinguishes residential-proxy sessions that share the same gateway
    /// address but use different session-ids in the username.
    ///
    /// Used as the key for cooldown / failure tracking in `SessionPool`.
    ///
    /// For a proxychain the identities of all hops are folded in (joined with
    /// `>`), so distinct chains track cooldown/failures independently.
    pub fn identity(&self) -> String {
        let (host, port) = self.host_port();
        let base = if let Some(ref auth) = self.auth {
            format!("{}@{}:{}", auth.username, host, port)
        } else {
            format!("{}:{}", host, port)
        };
        if self.chain.is_empty() {
            return base;
        }
        // Each hop has an empty chain, so `hop.identity()` is the base case.
        let mut s = String::new();
        for hop in &self.chain {
            s.push_str(&hop.identity());
            s.push('>');
        }
        s.push_str(&base);
        s
    }

    /// Perform a health check by attempting a TCP connection through this proxy.
    ///
    /// Returns the connection latency on success, or an error if the probe fails.
    pub async fn health_check(
        &self,
        target_host: &str,
        target_port: u16,
        timeout: std::time::Duration,
        resolver: &dyn crate::dns::DnsResolver,
    ) -> Result<std::time::Duration> {
        let start = std::time::Instant::now();
        tokio::time::timeout(
            timeout,
            self.connect(target_host, target_port, None, resolver),
        )
        .await
        .map_err(|_| {
            Error::timeout(
                format!(
                    "health check timed out after {:?} for proxy {}",
                    timeout, self
                ),
                Some(crate::error::ConnectionPhase::ProxyTunnel),
                Some(timeout),
            )
        })??;
        Ok(start.elapsed())
    }
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render upstream hops first (each has an empty chain, so this does not
        // recurse further): "hop1 -> hop2 -> finalhop".
        for hop in &self.chain {
            write!(f, "{hop} -> ")?;
        }
        match &self.scheme {
            ProxyScheme::Http { host, port } => write!(f, "http://{}:{}", host, port),
            ProxyScheme::Socks5 {
                host,
                port,
                remote_dns,
            } => {
                let scheme = if *remote_dns { "socks5h" } else { "socks5" };
                write!(f, "{}://{}:{}", scheme, host, port)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn percent_decode(s: &str) -> String {
    // Re-use the percent-encoding crate bundled with url
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| s.to_string())
}

/// Parse HTTP status code from a status line like "HTTP/1.1 200 Connection Established".
pub(super) fn parse_http_status(line: &str) -> Option<u16> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ProxyConfig::parse -------------------------------------------------

    #[test]
    fn parse_http_proxy() {
        let p = ProxyConfig::parse("http://proxy.example.com:8080").unwrap();
        match &p.scheme {
            ProxyScheme::Http { host, port } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(*port, 8080);
            }
            _ => panic!("expected Http"),
        }
        assert!(p.auth.is_none());
    }

    #[test]
    fn parse_http_proxy_default_port() {
        let p = ProxyConfig::parse("http://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Http { port, .. } => assert_eq!(*port, 8080),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn parse_https_proxy_default_port() {
        let p = ProxyConfig::parse("https://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Http { port, .. } => assert_eq!(*port, 443),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn parse_http_proxy_with_auth() {
        let p = ProxyConfig::parse("http://user:pass@proxy.example.com:3128").unwrap();
        let auth = p.auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn parse_http_proxy_percent_encoded_auth() {
        let p = ProxyConfig::parse("http://us%40er:p%23ss@proxy.example.com:3128").unwrap();
        let auth = p.auth.as_ref().unwrap();
        assert_eq!(auth.username, "us@er");
        assert_eq!(auth.password, "p#ss");
    }

    #[test]
    fn parse_socks5_proxy() {
        let p = ProxyConfig::parse("socks5://proxy.example.com:1080").unwrap();
        match &p.scheme {
            ProxyScheme::Socks5 {
                host,
                port,
                remote_dns,
            } => {
                assert_eq!(host, "proxy.example.com");
                assert_eq!(*port, 1080);
                assert!(!remote_dns);
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn parse_socks5h_proxy() {
        let p = ProxyConfig::parse("socks5h://proxy.example.com:1080").unwrap();
        match &p.scheme {
            ProxyScheme::Socks5 { remote_dns, .. } => {
                assert!(*remote_dns);
            }
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn parse_socks5_default_port() {
        let p = ProxyConfig::parse("socks5://proxy.example.com").unwrap();
        match &p.scheme {
            ProxyScheme::Socks5 { port, .. } => assert_eq!(*port, 1080),
            _ => panic!("expected Socks5"),
        }
    }

    #[test]
    fn parse_socks5_with_auth() {
        let p = ProxyConfig::parse("socks5://user:pass@proxy.example.com:1080").unwrap();
        assert!(p.auth.is_some());
    }

    #[test]
    fn parse_invalid_scheme() {
        let result = ProxyConfig::parse("ftp://proxy.example.com:21");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_url() {
        let result = ProxyConfig::parse("not a url");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_string() {
        let result = ProxyConfig::parse("");
        assert!(result.is_err());
    }

    // -- Proxychain ---------------------------------------------------------

    #[test]
    fn parse_chain_orders_hops_client_to_target() {
        let chain = ProxyConfig::parse_chain([
            "socks5://hop1:1080",
            "socks5h://hop2:1081",
            "http://hop3:8080",
        ])
        .unwrap();
        // Final hop (connects to the target) is the last URL.
        assert_eq!(chain.host_port(), ("hop3", 8080));
        assert_eq!(chain.hop_count(), 3);
        // Upstream hops are preserved in client→target order.
        assert_eq!(chain.chain.len(), 2);
        assert_eq!(chain.chain[0].host_port(), ("hop1", 1080));
        assert_eq!(chain.chain[1].host_port(), ("hop2", 1081));
    }

    #[test]
    fn parse_chain_single_url_is_a_plain_proxy() {
        let p = ProxyConfig::parse_chain(["http://only:8080"]).unwrap();
        assert_eq!(p.hop_count(), 1);
        assert!(p.chain.is_empty());
    }

    #[test]
    fn parse_chain_empty_is_error() {
        assert!(ProxyConfig::parse_chain(Vec::<String>::new()).is_err());
    }

    #[test]
    fn through_prepends_upstream_hops() {
        let hop = ProxyConfig::parse("socks5://hop:1080").unwrap();
        let p = ProxyConfig::parse("http://final:8080")
            .unwrap()
            .through(vec![hop]);
        assert_eq!(p.hop_count(), 2);
        assert_eq!(p.chain[0].host_port(), ("hop", 1080));
    }

    #[test]
    fn identity_folds_chain_hops_for_distinct_cooldown_keys() {
        let single = ProxyConfig::parse("http://final:8080").unwrap();
        let chain = ProxyConfig::parse_chain(["socks5://hop:1080", "http://final:8080"]).unwrap();
        assert_ne!(single.identity(), chain.identity());
        assert!(chain.identity().contains("hop:1080"));
        assert!(chain.identity().contains("final:8080"));
    }

    #[test]
    fn display_renders_chain_with_arrows() {
        let chain = ProxyConfig::parse_chain(["socks5://hop:1080", "http://final:8080"]).unwrap();
        assert_eq!(chain.to_string(), "socks5://hop:1080 -> http://final:8080");
    }
}
