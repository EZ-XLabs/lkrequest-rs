use std::time::Duration;

use http::HeaderMap;
use http_body_util::Full;
use tracing::Instrument;
use url::Url;

use crate::client::Client;
use crate::connection_pool::{AcquiredConnection, ConnectionKey, ConnectionPermit, Scheme};
use crate::error::{ConnectionPhase, Error, Result};
use crate::proxy::ProxyConfig;
use crate::response::{HttpVersion, RedirectRecord, Response};

use super::pipeline;
use super::request::RequestBuilder;
use super::PreferredHttpVersion;

/// Shared context for a single HTTP request, passed through connection
/// establishment and protocol-specific send paths.
pub(crate) struct RequestContext<'a> {
    pub method: &'a http::Method,
    pub host: &'a str,
    pub port: u16,
    pub scheme: Scheme,
    pub path: &'a str,
    pub conn_key: &'a ConnectionKey,
    pub extra_headers: &'a HeaderMap,
    pub parsed_url: &'a Url,
    #[cfg(feature = "quic-h3")]
    /// Per-request QUIC 0-RTT / TLS early data gate. See
    /// [`super::Idempotency`] and [`super::can_send_early_data`].
    pub idempotency: super::Idempotency,
}

impl RequestBuilder {
    /// Inner send logic that handles redirect following.
    ///
    /// Heap-allocated future to avoid stack overflow (see `establish_and_send`).
    pub(crate) fn send_with_redirects(
        mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send>> {
        Box::pin(async move {
            let max_redirects = self
                .session
                .inner
                .redirect_policy
                .max_redirects()
                .unwrap_or(0);
            let follow_redirects = !matches!(
                self.session.inner.redirect_policy,
                super::RedirectPolicy::None
            );

            // One absolute deadline for the *entire* request, shared across
            // every redirect hop (connect + all hops + body read). This gives a
            // true total timeout instead of resetting it per hop, which would
            // make the real worst case (N+1)x the configured value.
            let deadline = tokio::time::Instant::now() + self.effective_total_timeout();

            // Apply query parameters to the URL
            let mut current_url = if self.query_params.is_empty() {
                self.url.clone()
            } else {
                let mut parsed = Url::parse(&self.url)
                    .map_err(|e| Error::UrlParse(format!("{}: {e}", self.url)))?;
                {
                    let mut pairs = parsed.query_pairs_mut();
                    for (key, value) in &self.query_params {
                        pairs.append_pair(key, value);
                    }
                }
                parsed.to_string()
            };

            let mut current_method = self.method.clone();
            let mut current_headers = self.headers.clone();
            let mut current_body = self.body.clone();
            let mut redirects_remaining = max_redirects;
            let mut redirect_history: Vec<RedirectRecord> = Vec::new();

            loop {
                // HSTS pre-upgrade (RFC 6797 §8.3): rewrite http->https before
                // connecting, for any host the policy treats as HTTPS-only.
                // Applies uniformly to the initial URL and every redirect target.
                if let Some(upgraded) = hsts_upgrade(&current_url, &*self.session.inner.hsts_policy)
                {
                    current_url = upgraded;
                }

                // Opt-in https_only: refuse a non-HTTPS request once HSTS has
                // had its chance to upgrade. Default off keeps behavior
                // Chrome-faithful (downgrades are followed).
                if self.session.inner.https_only {
                    if let Ok(parsed) = Url::parse(&current_url) {
                        if parsed.scheme() != "https" {
                            return Err(Error::Http(format!(
                                "https_only: refusing non-HTTPS request to {current_url}"
                            )));
                        }
                    }
                }

                let resp = self
                    .send_single_request(
                        &current_url,
                        &current_method,
                        &current_headers,
                        current_body.clone(),
                        deadline,
                    )
                    .await?;

                // Learn dynamic HSTS from a Strict-Transport-Security response,
                // if the policy is stateful (no-op for NoHsts/StaticHsts).
                if let Some(sts) = resp
                    .headers()
                    .get(http::header::STRICT_TRANSPORT_SECURITY)
                    .and_then(|v| v.to_str().ok())
                {
                    if let Some(host) = Url::parse(&current_url)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_string))
                    {
                        self.session.inner.hsts_policy.record_sts(&host, sts);
                    }
                }

                // Check for redirect status codes
                let status = resp.status();
                let is_redirect = status.is_redirection();

                if !is_redirect || !follow_redirects || redirects_remaining == 0 {
                    if is_redirect && follow_redirects && redirects_remaining == 0 {
                        tracing::warn!(
                            status = status.as_u16(),
                            limit = max_redirects,
                            "http.too_many_redirects",
                        );
                        return Err(Error::TooManyRedirects(max_redirects));
                    }
                    tracing::info!(
                        status = status.as_u16(),
                        body_bytes = resp.bytes().len(),
                        "http.response",
                    );
                    let mut resp = resp;
                    resp.set_url(current_url);
                    resp.set_redirect_history(redirect_history);
                    return Ok(resp);
                }

                // Extract the Location header
                let location = resp
                    .headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        Error::Http("redirect response missing Location header".into())
                    })?;

                // Resolve relative URLs against the current URL
                let base_url = Url::parse(&current_url)
                    .map_err(|e| Error::UrlParse(format!("{}: {e}", current_url)))?;
                let redirect_url = base_url.join(location).map_err(|e| {
                    Error::UrlParse(format!("invalid redirect URL '{location}': {e}"))
                })?;

                // Origin = scheme + host + port (Fetch "same origin"). Note the
                // redirect target's https_only / HSTS handling happens at the
                // top of the next loop iteration, after it becomes current_url.
                let is_cross_origin = redirect_is_cross_origin(&base_url, &redirect_url);

                tracing::debug!(
                    status = status.as_u16(),
                    from = %current_url,
                    to = %redirect_url,
                    remaining = redirects_remaining,
                    cross_origin = is_cross_origin,
                    "http.redirect",
                );

                let redirect_to_str = redirect_url.to_string();

                // Record this hop in the redirect history
                redirect_history.push(RedirectRecord::new(
                    current_url.clone(),
                    status,
                    resp.headers().clone(),
                    redirect_to_str.clone(),
                ));

                // Update method and body based on status code
                match status.as_u16() {
                    301..=303 => {
                        // 301/302 (historically POST->GET) and 303 See Other:
                        // follow with GET, drop the body and all request-body
                        // headers (Fetch "request-body-header name" set). 303 was
                        // previously not followed at all.
                        current_method = http::Method::GET;
                        current_body = None;
                        current_headers.remove(http::header::CONTENT_TYPE);
                        current_headers.remove(http::header::CONTENT_LENGTH);
                        current_headers.remove(http::header::CONTENT_ENCODING);
                        current_headers.remove(http::header::CONTENT_LANGUAGE);
                        current_headers.remove(http::header::CONTENT_LOCATION);
                    }
                    307 | 308 => {
                        // 307/308: Preserve method and body
                    }
                    _ => {
                        // Other 3xx codes (300/304/305/306): return as-is
                        let mut resp = resp;
                        resp.set_redirect_history(redirect_history);
                        return Ok(resp);
                    }
                }

                // Strip sensitive headers on cross-origin redirect.
                //
                // Per browser behavior (Fetch spec):
                // - Authorization: never forwarded cross-origin
                // - Cookie: handled below — always removed so merge_headers_common
                //   rebuilds from the latest jar (supports cookie_order + H2 multi-cookie)
                // - Host: rebuilt by merge_headers_common for the new target
                if is_cross_origin {
                    current_headers.remove(http::header::AUTHORIZATION);
                    current_headers.remove(http::header::HOST);
                    // Prevent request-level cookies from leaking to third-party domains
                    self.extra_cookies.clear();
                    self.cookie_overrides.clear();
                }

                // Chrome (and reqwest) drop the Referer when downgrading the
                // scheme from https to http, so the secure URL isn't leaked over
                // cleartext. Independent of cross-origin (same-host downgrade
                // still strips it).
                if base_url.scheme() == "https" && redirect_url.scheme() == "http" {
                    current_headers.remove(http::header::REFERER);
                }

                // Always remove Cookie so merge_headers_common can rebuild from
                // the latest jar, explicit request pairs, and `.cookie()` data.
                // This ensures Set-Cookie responses from intermediate hops are
                // reflected, cookie_order is applied, and the correct H1/H2
                // format is used.
                current_headers.remove(http::header::COOKIE);

                current_url = redirect_to_str;
                redirects_remaining -= 1;
            }
        })
    }

    /// Send a single HTTP request without redirect following, bounded by an
    /// absolute `deadline`.
    ///
    /// The deadline is computed once and shared across the whole redirect chain
    /// by [`Self::send_with_redirects`], so the total timeout covers connect +
    /// every hop + body read — not each hop independently. This matches the
    /// "total timeout" semantics of reqwest, Go's `http.Client.Timeout`, and
    /// curl's `--max-time`.
    pub(crate) async fn send_single_request(
        &self,
        url: &str,
        method: &http::Method,
        extra_headers: &HeaderMap,
        body: Option<bytes::Bytes>,
        deadline: tokio::time::Instant,
    ) -> Result<Response> {
        tokio::time::timeout_at(
            deadline,
            self.send_single_request_inner(url, method, extra_headers, body),
        )
        .await
        .map_err(|_| {
            let total_timeout = self.effective_total_timeout();
            Error::timeout(
                format!("request timed out (total deadline of {total_timeout:?} exceeded)"),
                None,
                Some(total_timeout),
            )
        })?
    }

    /// Inner implementation of a single request (no timeout wrapper).
    ///
    /// 1. Parse URL
    /// 2. Build connection key
    /// 3. Try to acquire a pooled connection (H2 or H1.1)
    /// 4. If no pooled connection, establish TLS and select protocol via ALPN
    /// 5. Send request via the appropriate protocol
    /// 6. Handle cookies
    /// 7. Read response body
    ///
    /// Heap-allocated future to avoid stack overflow (see `establish_and_send`).
    pub(crate) fn send_single_request_inner<'a>(
        &'a self,
        url: &'a str,
        method: &'a http::Method,
        extra_headers: &'a HeaderMap,
        body: Option<bytes::Bytes>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            let effective_proxy = self.effective_proxy();
            let effective_policy = self.effective_protocol_policy();
            effective_policy.validate()?;
            let http_version_pref = self.effective_http_version(&effective_policy);
            let target = pipeline::parse_request_target(url, effective_proxy)?;

            let pooled =
                pipeline::try_acquire_pooled(&self.session, &target.conn_key, http_version_pref);

            let ctx = RequestContext {
                method,
                host: &target.host,
                port: target.port,
                scheme: target.scheme,
                path: &target.path,
                conn_key: &target.conn_key,
                extra_headers,
                parsed_url: &target.parsed_url,
                #[cfg(feature = "quic-h3")]
                idempotency: self.idempotency,
            };

            match pooled {
                #[cfg(feature = "quic-h3")]
                Some(AcquiredConnection::H3(mut cached_sender)) => {
                    tracing::debug!(host = %target.host, port = target.port, protocol = "h3", pooled = true, "connection.acquired");
                    let result = self
                        .send_h3_request(&mut cached_sender, &ctx, body.clone())
                        .await;

                    match result {
                        Err(ref e)
                            if e.is_connection_closed()
                                && self
                                    .session
                                    .inner
                                    .client
                                    .fallback()
                                    .retry_on_connection_close =>
                        {
                            tracing::debug!(
                                host = %target.host,
                                error = %e,
                                "connection.pooled_h3_closed_retrying",
                            );
                            {
                                let mut pool = self.session.inner.pool.lock();
                                pool.remove(&target.conn_key);
                            }
                            self.establish_and_send(&ctx, body).await
                        }
                        other => other,
                    }
                }
                Some(AcquiredConnection::H2(cached_sender)) => match cached_sender.ready().await {
                    Ok(sender) => {
                        tracing::debug!(host = %target.host, port = target.port, protocol = "h2", pooled = true, "connection.acquired");
                        let result = self.send_h2_request(sender, &ctx, body.clone()).await;

                        match result {
                            Err(ref e)
                                if e.is_connection_closed()
                                    && self
                                        .session
                                        .inner
                                        .client
                                        .fallback()
                                        .retry_on_connection_close =>
                            {
                                tracing::debug!(
                                    host = %target.host,
                                    error = %e,
                                    "connection.pooled_h2_closed_retrying",
                                );
                                {
                                    let mut pool = self.session.inner.pool.lock();
                                    pool.remove(&target.conn_key);
                                }
                                self.establish_and_send(&ctx, body).await
                            }
                            other => other,
                        }
                    }
                    Err(e) => {
                        tracing::debug!(host = %target.host, error = %e, "connection.stale_evicted");
                        {
                            let mut pool = self.session.inner.pool.lock();
                            pool.remove(&target.conn_key);
                        }
                        self.establish_and_send(&ctx, body).await
                    }
                },
                Some(AcquiredConnection::H1 {
                    mut sender,
                    conn_task,
                    permit,
                }) => match sender.ready().await {
                    Ok(()) => {
                        tracing::debug!(host = %target.host, port = target.port, protocol = "h1.1", pooled = true, "connection.acquired");
                        let result = self
                            .send_h1_request(sender, conn_task, permit, &ctx, body.clone())
                            .await;

                        match result {
                            Err(ref e)
                                if e.is_connection_closed()
                                    && self
                                        .session
                                        .inner
                                        .client
                                        .fallback()
                                        .retry_on_connection_close =>
                            {
                                tracing::debug!(
                                    host = %target.host,
                                    error = %e,
                                    "connection.pooled_h1_closed_retrying",
                                );
                                self.establish_and_send(&ctx, body).await
                            }
                            other => other,
                        }
                    }
                    Err(e) => {
                        tracing::debug!(host = %target.host, error = %e, "connection.h1_stale_evicted");
                        conn_task.abort();
                        drop(permit);
                        self.establish_and_send(&ctx, body).await
                    }
                },
                None => {
                    tracing::debug!(host = %target.host, port = target.port, pooled = false, "connection.new");
                    self.establish_and_send(&ctx, body).await
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // Connection establishment
    // -----------------------------------------------------------------------

    /// Establish a new connection, detect ALPN, and send the request.
    ///
    /// This is the fallback path when no pooled connection is available.
    ///
    /// Returns a `Pin<Box<..>>` future so that the (very large) async state
    /// machine lives on the heap instead of being inlined into the caller's
    /// future.  This prevents stack overflow in debug builds on platforms
    /// with small default stacks (e.g. Windows 1 MB main thread).
    pub(crate) fn establish_and_send<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<bytes::Bytes>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        let host = ctx.host;
        let port = ctx.port;
        let scheme = ctx.scheme;

        let effective_proxy = self.effective_proxy().cloned();
        let via_proxy = effective_proxy.is_some();
        let span = tracing::debug_span!(
            "http.connect",
            host = %host,
            port = port,
            via_proxy = via_proxy,
            phase = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        );

        Box::pin(
            async move {
                let connect_start = std::time::Instant::now();

                let effective_policy = self.effective_protocol_policy();
                effective_policy.validate()?;
                let http_version_pref = self.effective_http_version(&effective_policy);
                if http_version_pref == PreferredHttpVersion::Http3Only
                    && self.session.inner.client.quic_profile().is_none()
                {
                    return Err(Error::InvalidConfig(
                        "HTTP/3 requested but client has no QUIC/H3 profile".into(),
                    ));
                }
                pipeline::log_protocol_policy(
                    &ctx.conn_key.route,
                    host,
                    port,
                    &effective_policy,
                    http_version_pref,
                );
                let quic_discovery = pipeline::discover_quic_support(
                    &self.session,
                    scheme,
                    host,
                    port,
                    effective_proxy.as_ref(),
                    &effective_policy,
                    http_version_pref,
                )
                .await;
                pipeline::log_quic_discovery(&quic_discovery);
                let decision = pipeline::decide_protocol(
                    http_version_pref,
                    &effective_policy,
                    &quic_discovery,
                );
                pipeline::log_protocol_decision(&quic_discovery, &effective_policy, decision);
                match decision {
                    pipeline::ProtocolDecision::Tcp => {
                        let result = self
                            .establish_and_send_tcp(
                                ctx,
                                body,
                                effective_proxy.clone(),
                                &effective_policy,
                                http_version_pref,
                                connect_start,
                            )
                            .await;
                        let schedule_probe = result.is_ok()
                            && pipeline::should_background_probe(
                                &effective_policy,
                                &quic_discovery,
                            );
                        pipeline::log_background_probe_decision(
                            &ctx.conn_key.route,
                            ctx.host,
                            ctx.port,
                            &effective_policy,
                            &quic_discovery,
                            schedule_probe,
                        );
                        if schedule_probe {
                            self.session.spawn_background_quic_probe(
                                ctx.host.to_string(),
                                ctx.port,
                                ctx.conn_key.clone(),
                                quic_discovery.clone(),
                                effective_proxy.clone(),
                            );
                        }
                        result
                    }
                    #[cfg(feature = "quic-h3")]
                    pipeline::ProtocolDecision::Race => {
                        self.establish_and_send_race(
                            ctx,
                            body,
                            &quic_discovery,
                            effective_proxy.as_ref(),
                            effective_proxy.clone(),
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await
                    }
                    #[cfg(not(feature = "quic-h3"))]
                    pipeline::ProtocolDecision::Race => {
                        self.establish_and_send_tcp(
                            ctx,
                            body,
                            effective_proxy,
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await
                    }
                    #[cfg(feature = "quic-h3")]
                    pipeline::ProtocolDecision::Quic => {
                        self.establish_and_send_quic(
                            ctx,
                            body,
                            &quic_discovery,
                            effective_proxy.as_ref(),
                            effective_proxy.clone(),
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await
                    }
                    #[cfg(not(feature = "quic-h3"))]
                    pipeline::ProtocolDecision::Quic => Err(Error::InvalidConfig(
                        "QUIC/H3 support is not compiled in; enable the `quic-h3` feature".into(),
                    )),
                }
            }
            .instrument(span),
        )
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_race<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<bytes::Bytes>,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a crate::protocol::ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            let race_cfg = pipeline::protocol_policy_chrome_like_config(
                protocol_policy,
                self.session.chrome_like_protocol_config(),
            );
            let mut quic_future = self.establish_and_send_quic(
                ctx,
                body.clone(),
                discovery,
                proxy,
                effective_proxy_owned.clone(),
                protocol_policy,
                http_version_pref,
                connect_start,
            );

            if !race_cfg.tcp_main_job_delay.is_zero() {
                let mut tcp_delay = std::pin::pin!(tokio::time::sleep(race_cfg.tcp_main_job_delay));
                tokio::select! {
                    biased;

                    quic_result = &mut quic_future => match quic_result {
                        Ok(resp) => {
                            if race_cfg.keep_tcp_probe_after_quic_win {
                                self.session.spawn_background_tcp_probe(
                                    ctx.host.to_string(),
                                    ctx.port,
                                    ctx.scheme,
                                    ctx.conn_key.clone(),
                                    effective_proxy_owned.clone(),
                                    http_version_pref,
                                );
                            }
                            return Ok(resp);
                        }
                        Err(quic_error) => {
                            tracing::warn!(
                                host = %ctx.host,
                                error = %quic_error,
                                fallback = "quic_to_tcp",
                                "http.protocol_race_quic_failed_before_tcp_release",
                            );
                            return match self.establish_and_send_tcp(
                                ctx,
                                body,
                                effective_proxy_owned,
                                protocol_policy,
                                http_version_pref,
                                connect_start,
                            )
                            .await {
                                Ok(resp) => Ok(resp),
                                Err(tcp_error) => Err(pipeline::protocol_race_error(tcp_error, quic_error)),
                            };
                        }
                    },
                    _ = &mut tcp_delay => {}
                }
            }

            let mut tcp_future = self.establish_and_send_tcp(
                ctx,
                body.clone(),
                effective_proxy_owned.clone(),
                protocol_policy,
                http_version_pref,
                connect_start,
            );

            tokio::select! {
                biased;

                quic_result = &mut quic_future => match quic_result {
                    Ok(resp) => {
                        if race_cfg.keep_tcp_probe_after_quic_win {
                            self.session.spawn_background_tcp_probe(
                                ctx.host.to_string(),
                                ctx.port,
                                ctx.scheme,
                                ctx.conn_key.clone(),
                                effective_proxy_owned.clone(),
                                http_version_pref,
                            );
                        }
                        Ok(resp)
                    }
                    Err(quic_error) => {
                        tracing::warn!(
                            host = %ctx.host,
                            error = %quic_error,
                            fallback = "quic_to_tcp",
                            "http.protocol_race_quic_failed_waiting_for_tcp",
                        );
                        match tcp_future.await {
                            Ok(resp) => Ok(resp),
                            Err(tcp_error) if pipeline::is_connection_limit_error(&tcp_error) => {
                                self.establish_and_send_tcp(
                                    ctx,
                                    body,
                                    effective_proxy_owned,
                                    protocol_policy,
                                    http_version_pref,
                                    connect_start,
                                )
                                .await
                                .map_err(|retry_error| {
                                    pipeline::protocol_race_error(retry_error, quic_error)
                                })
                            }
                            Err(tcp_error) => {
                                Err(pipeline::protocol_race_error(tcp_error, quic_error))
                            }
                        }
                    }
                },
                tcp_result = &mut tcp_future => match tcp_result {
                    Ok(resp) => {
                        if race_cfg.keep_quic_probe_after_tcp_win {
                            self.session.spawn_background_quic_probe(
                                ctx.host.to_string(),
                                ctx.port,
                                ctx.conn_key.clone(),
                                discovery.clone(),
                                effective_proxy_owned.clone(),
                            );
                        }
                        Ok(resp)
                    }
                    Err(tcp_error) => {
                        tracing::warn!(
                            host = %ctx.host,
                            error = %tcp_error,
                            fallback = "tcp_to_quic",
                            "http.protocol_race_tcp_failed_waiting_for_quic",
                        );
                        match quic_future.await {
                            Ok(resp) => Ok(resp),
                            Err(quic_error) if pipeline::is_connection_limit_error(&tcp_error) => {
                                self.establish_and_send_tcp(
                                    ctx,
                                    body,
                                    effective_proxy_owned,
                                    protocol_policy,
                                    http_version_pref,
                                    connect_start,
                                )
                                .await
                                .map_err(|retry_error| {
                                    pipeline::protocol_race_error(retry_error, quic_error)
                                })
                            }
                            Err(quic_error) => {
                                Err(pipeline::protocol_race_error(tcp_error, quic_error))
                            }
                        }
                    }
                },
            }
        })
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_quic<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<bytes::Bytes>,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a crate::protocol::ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            // Concurrent-handshake dedup: when two requests race to reach the
            // same origin and neither has a pooled H3 connection yet, we want
            // exactly one of them to drive the handshake. The loser waits on
            // a per-key `Notify`, then retries the pool lookup. If the winner
            // succeeded, the loser sees the pooled sender and skips the
            // second handshake; if the winner failed, the loser attempts its
            // own handshake (necessary so a transient failure doesn't strand
            // every concurrent request).
            let maybe_wait = {
                let mut in_flight = self.session.inner.quic_in_flight.lock();
                match in_flight.get(ctx.conn_key) {
                    Some(existing) => Some(existing.clone()),
                    None => {
                        let notify = std::sync::Arc::new(tokio::sync::Notify::new());
                        in_flight.insert(ctx.conn_key.clone(), notify.clone());
                        None
                    }
                }
            };

            if let Some(wait) = maybe_wait {
                tracing::debug!(
                    host = %ctx.host,
                    port = ctx.port,
                    "quic.handshake_coalesce_wait",
                );
                wait.notified().await;

                // Retry the pool lookup. If the winning task pooled a sender
                // we can piggyback on it. If the pool is still empty (the
                // winner failed) we fall through and run our own handshake.
                let pooled = {
                    let mut pool = self.session.inner.pool.lock();
                    pool.try_acquire_h3(ctx.conn_key)
                };
                if let Some(mut sender) = pooled {
                    tracing::debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        protocol = "h3",
                        pooled = true,
                        "connection.acquired_after_coalesce",
                    );
                    return self.send_h3_request(&mut sender, ctx, body).await;
                }
            }

            // On every return path below, make sure we drop the in-flight
            // marker and wake waiters. Wrap the handshake in a scope guard so
            // panics don't leave a dead Notify stuck in the map.
            struct InFlightGuard<'s> {
                session: &'s super::Session,
                key: &'s crate::connection_pool::ConnectionKey,
            }
            impl Drop for InFlightGuard<'_> {
                fn drop(&mut self) {
                    let removed = {
                        let mut map = self.session.inner.quic_in_flight.lock();
                        map.remove(self.key)
                    };
                    if let Some(notify) = removed {
                        notify.notify_waiters();
                    }
                }
            }
            let _in_flight_guard = InFlightGuard {
                session: &self.session,
                key: ctx.conn_key,
            };
            let permit = self.session.reserve_connection()?;

            let early_data_allowed = super::can_send_early_data(ctx.method, ctx.idempotency);
            tracing::trace!(
                method = %ctx.method,
                idempotency = ?ctx.idempotency,
                early_data_allowed,
                proxy = proxy.is_some(),
                "h3.early_data_gate",
            );

            let h3_conn = match self
                .session
                .establish_h3_connection_with_0rtt(
                    ctx.host,
                    ctx.port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy,
                    early_data_allowed,
                )
                .await
            {
                Ok(super::H3ConnectOutcome::Handshake(h3_conn)) => h3_conn,
                Ok(super::H3ConnectOutcome::ZeroRtt(zero_rtt)) => {
                    let zero_rtt_result =
                        self.send_h3_0rtt_request(zero_rtt, ctx, body.clone()).await;
                    let (h3_conn, response, replay_connection_ready) = match zero_rtt_result {
                        Ok((h3_conn, response)) => (h3_conn, response, false),
                        Err(error) => {
                            if error.is_connection_closed()
                                && self
                                    .session
                                    .inner
                                    .client
                                    .fallback()
                                    .retry_on_connection_close
                            {
                                tracing::debug!(
                                    error = %error,
                                    "h3.early_data_failed_retrying_fresh"
                                );
                                let replay_h3_conn = self
                                    .session
                                    .establish_h3_connection(
                                        ctx.host,
                                        ctx.port,
                                        discovery.advertised_host.as_deref(),
                                        discovery.advertised_port,
                                        proxy,
                                    )
                                    .await?;
                                (replay_h3_conn, None, true)
                            } else {
                                return Err(error);
                            }
                        }
                    };

                    self.session
                        .broken_quic_tracker()
                        .mark_working_for_route(&discovery.route, &discovery.origin);
                    self.session
                        .broken_quic_tracker()
                        .mark_route_working(&discovery.route);
                    self.session
                        .alt_svc_cache()
                        .mark_h3_validated_for_route(&discovery.route, &discovery.origin);

                    if let Some(response) = response {
                        let (sender, driver) = h3_conn.into_parts();
                        {
                            let mut pool = self.session.inner.pool.lock();
                            pool.insert_h3_reserved(ctx.conn_key.clone(), sender, driver, permit);
                        }
                        tracing::debug!(
                            route = %ctx.conn_key.route,
                            path = "new_h3_0rtt",
                            protocol = "h3",
                            duration_ms = connect_start.elapsed().as_millis() as u64,
                            "connection.established",
                        );
                        return Ok(response);
                    }

                    let replay_h3_conn = if replay_connection_ready {
                        h3_conn
                    } else {
                        drop(h3_conn);
                        self.session
                            .establish_h3_connection(
                                ctx.host,
                                ctx.port,
                                discovery.advertised_host.as_deref(),
                                discovery.advertised_port,
                                proxy,
                            )
                            .await?
                    };
                    tracing::debug!(
                        route = %ctx.conn_key.route,
                        protocol = "h3",
                        "h3.early_data_replay_connection_ready",
                    );
                    replay_h3_conn
                }
                Err(error) => {
                    // Only mark the origin as broken-QUIC when the failure is
                    // a genuine handshake-class error. Post-handshake errors
                    // (e.g. HTTP-layer parsing) can't reach this branch — the
                    // `establish_h3_connection` call only returns errors
                    // before the QUIC handshake completes — but we still
                    // classify explicitly so that future code paths that
                    // share the same `Err` type don't silently cause
                    // spurious fallback.
                    let is_handshake_class = error.is_quic_handshake_failure();
                    if is_handshake_class {
                        self.session
                            .broken_quic_tracker()
                            .mark_broken_for_route(&discovery.route, &discovery.origin);
                        self.session
                            .alt_svc_cache()
                            .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    } else {
                        tracing::debug!(
                            host = %ctx.host,
                            error = %error,
                            "quic.non_handshake_error_no_broken_mark",
                        );
                    }

                    let fallback_allowed =
                        is_handshake_class && pipeline::fallback_permitted(protocol_policy, &error);
                    if fallback_allowed {
                        tracing::warn!(
                            route = %discovery.route,
                            host = %ctx.host,
                            port = ctx.port,
                            fallback_policy = ?protocol_policy.fallback,
                            error = %error,
                            "quic.handshake_failed_fallback_tcp",
                        );
                        return self
                            .establish_and_send_tcp(
                                ctx,
                                body,
                                effective_proxy_owned,
                                protocol_policy,
                                http_version_pref,
                                connect_start,
                            )
                            .await;
                    }
                    if is_handshake_class {
                        tracing::warn!(
                            route = %discovery.route,
                            host = %ctx.host,
                            port = ctx.port,
                            fallback_policy = ?protocol_policy.fallback,
                            error = %error,
                            "quic.handshake_failed_no_fallback",
                        );
                    }
                    return Err(error);
                }
            };

            self.session
                .broken_quic_tracker()
                .mark_working_for_route(&discovery.route, &discovery.origin);
            self.session
                .broken_quic_tracker()
                .mark_route_working(&discovery.route);
            self.session
                .alt_svc_cache()
                .mark_h3_validated_for_route(&discovery.route, &discovery.origin);
            let (sender, driver) = h3_conn.into_parts();
            let mut send_sender = sender.clone();
            {
                let mut pool = self.session.inner.pool.lock();
                pool.insert_h3_reserved(ctx.conn_key.clone(), sender, driver, permit);
            }

            tracing::debug!(
                route = %ctx.conn_key.route,
                path = "new_h3",
                protocol = "h3",
                duration_ms = connect_start.elapsed().as_millis() as u64,
                "connection.established",
            );

            self.send_h3_request(&mut send_sender, ctx, body).await
        })
    }

    fn establish_and_send_tcp<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<bytes::Bytes>,
        effective_proxy: Option<ProxyConfig>,
        _protocol_policy: &'a crate::protocol::ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        let host = ctx.host;
        let port = ctx.port;
        let scheme = ctx.scheme;
        let conn_key = ctx.conn_key;

        Box::pin(async move {
            let permit = self.session.reserve_connection()?;
            let client = &self.session.inner.client;
            let mut connect_config =
                pipeline::build_connect_config(client, http_version_pref, scheme);
            if client.fallback().proxy_to_direct && effective_proxy.is_some() {
                connect_config = connect_config
                    .with_proxy_fallback(connect_start, self.effective_total_timeout());
            }

            let conn = self
                .session
                .establish_connection(host, port, effective_proxy.as_ref(), &connect_config)
                .await?;

            if scheme == Scheme::Http {
                let tcp = conn
                    .into_tcp_stream()?
                    .into_plain_tcp()
                    .ok_or_else(|| Error::Http("expected plain TCP for HTTP scheme".into()))?;
                return self
                    .send_cleartext(tcp, permit, ctx, body, connect_start)
                    .await;
            }

            let negotiated_alpn = conn.negotiated_alpn();
            tracing::debug!(alpn = ?negotiated_alpn, "tls.alpn_negotiated");

            let use_h2 = pipeline::should_use_h2(negotiated_alpn, http_version_pref)?;

            if use_h2 {
                let h2_result: Result<Response> = async {
                    let first_req = self.build_h2_request_for_preface(ctx, body.as_ref())?;
                    let (first_resp, _pool_sender) = pipeline::establish_h2_with_first_request(
                        conn.into_tcp_stream()?,
                        client,
                        &self.session,
                        conn_key,
                        first_req,
                        permit,
                    )
                    .await?;

                    tracing::debug!(
                        protocol = "h2",
                        duration_ms = connect_start.elapsed().as_millis() as u64,
                        first_request_piggybacked = true,
                        "connection.established",
                    );

                    self.receive_h2_first_response(first_resp, ctx, body.clone())
                        .await
                }
                .await;

                match h2_result {
                    Ok(resp) => Ok(resp),
                    Err(e)
                        if client.fallback().h2_to_h1
                            && (matches!(e, Error::H2(_)) || e.is_connection_closed()) =>
                    {
                        tracing::warn!(
                            error = %e,
                            fallback = "h2_to_h1",
                            "http.h2_failed_falling_back_to_h1",
                        );

                        let fallback_permit = self.session.reserve_connection()?;
                        let h1_config = pipeline::build_h1_only_connect_config(client, scheme);
                        let conn2 = self
                            .session
                            .establish_connection(host, port, effective_proxy.as_ref(), &h1_config)
                            .await?;

                        let (sender, conn_task) =
                            pipeline::handshake_h1(conn2.into_tcp_stream()?).await?;

                        tracing::debug!(
                            route = %ctx.conn_key.route,
                            path = "fallback_h1",
                            protocol = "h1.1",
                            fallback = true,
                            "connection.established_via_fallback",
                        );

                        self.send_h1_request(sender, conn_task, fallback_permit, ctx, body)
                            .await
                    }
                    Err(e) => Err(e),
                }
            } else {
                if negotiated_alpn != Some("http/1.1")
                    && negotiated_alpn.is_some()
                    && http_version_pref != PreferredHttpVersion::Http1Only
                {
                    tracing::warn!(
                        alpn = ?negotiated_alpn,
                        "tls.unexpected_alpn_falling_back_to_h1",
                    );
                }

                let (sender, conn_task) = pipeline::handshake_h1(conn.into_tcp_stream()?).await?;

                tracing::debug!(
                    route = %ctx.conn_key.route,
                    path = "new_h1",
                    protocol = "h1.1",
                    duration_ms = connect_start.elapsed().as_millis() as u64,
                    "connection.established",
                );

                self.send_h1_request(sender, conn_task, permit, ctx, body)
                    .await
            }
        })
    }

    // -----------------------------------------------------------------------
    // HTTP/2 request sending
    // -----------------------------------------------------------------------

    /// Send a request via HTTP/2.
    pub(crate) async fn send_h2_request(
        &self,
        sender: lkh2::H2ReadySender,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response> {
        let method = ctx.method;
        let host = ctx.host;
        let port = ctx.port;
        let scheme = ctx.scheme;
        let path = ctx.path;
        let extra_headers = ctx.extra_headers;
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        let uri = pipeline::build_h2_uri(scheme, host, port, path);

        let has_body = body.is_some();
        let end_stream = !has_body;

        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(&uri)
            .body(())
            .map_err(|e| Error::Http(format!("failed to build HTTP request: {e}")))?;

        // Resolve effective request priority from: explicit .priority() > parsed
        // priority header > profile default.
        let h2_profile = client.h2_profile();
        let priority_config = &h2_profile.priority_config;

        let effective_priority = pipeline::resolve_request_priority(
            self.priority,
            extra_headers,
            client.default_headers(),
        );

        let rp = priority_config.effective_priority(effective_priority);

        // Inject RequestPriority into extensions for the H2 engine.
        request.extensions_mut().insert(rp);

        // Auto-inject `priority` HTTP header if not already present.
        if priority_config.auto_priority_header && !extra_headers.contains_key("priority") {
            if let Ok(hv) = http::HeaderValue::from_str(&rp.to_header_value()) {
                request.headers_mut().insert("priority", hv);
            }
        }

        let header_order = pipeline::effective_header_order(
            self.header_order.as_deref(),
            self.session.inner.header_order.as_deref(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        pipeline::auto_insert_content_length(request.headers_mut(), body.as_ref());

        self.merge_headers(
            request.headers_mut(),
            client,
            extra_headers,
            parsed_url,
            false,
            HeaderMergeOrdering {
                header_order,
                cookie_order,
            },
        );

        tracing::debug!(
            method = %method,
            uri = %uri,
            protocol = "h2",
            has_body = has_body,
            "http.request_sent",
        );

        let ttfb_started = std::time::Instant::now();
        let (resp_future, mut send_stream) =
            sender.send_request(request, end_stream).map_err(|e| {
                Error::h2_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("failed to send H2 request: {e}"),
                )
            })?;

        if let Some(body_data) = body {
            send_stream.send_data(body_data, true).map_err(|e| {
                Error::h2_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("failed to send request body: {e}"),
                )
            })?;
        }

        let resp = resp_future.await_response().await.map_err(|e| {
            Error::h2_or_connection_closed(
                ConnectionPhase::HttpRequest,
                format!("failed to receive H2 response: {e}"),
            )
        })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h2");

        let (parts, mut body_recv) = resp.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = self.session.inner.client.resource_limits();

        tracing::debug!(
            status = status.as_u16(),
            protocol = "h2",
            "http.response_headers"
        );

        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            host,
            port,
        );

        let capacity_hint = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|cl| cl.min(limits.max_response_body_size))
            .unwrap_or(0);
        let mut body_data = bytes::BytesMut::with_capacity(capacity_hint);
        let body_start = std::time::Instant::now();
        while let Some(chunk) = body_recv.data().await {
            let chunk = chunk.map_err(|e| {
                Error::h2_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("error reading response body: {e}"),
                )
            })?;
            let len = chunk.len();
            body_data.extend_from_slice(&chunk);

            limits.check_body_size(body_data.len())?;

            if let Some(min_rate) = limits.min_transfer_rate {
                let elapsed = body_start.elapsed();
                if elapsed > limits.transfer_rate_window {
                    let rate = body_data.len() as f64 / elapsed.as_secs_f64();
                    if rate < min_rate as f64 {
                        return Err(Error::timeout(
                            format!(
                                "transfer rate too slow: {:.0} bytes/s < {} bytes/s",
                                rate, min_rate
                            ),
                            None,
                            None,
                        ));
                    }
                }
            }

            let _ = body_recv.flow_control().release_capacity(len);
        }

        self.make_response(status, resp_headers, body_data.freeze(), HttpVersion::H2)
    }

    /// Send a request via HTTP/3.
    #[cfg(feature = "quic-h3")]
    fn build_h3_request(
        &self,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
    ) -> Result<http::Request<Option<bytes::Bytes>>> {
        let client = &self.session.inner.client;
        let uri = pipeline::build_h2_uri(ctx.scheme, ctx.host, ctx.port, ctx.path);
        let mut request = http::Request::builder()
            .method(ctx.method.clone())
            .uri(&uri)
            .body(body.clone())
            .map_err(|e| Error::Http3Request(format!("failed to build HTTP/3 request: {e}")))?;

        let effective_priority = pipeline::resolve_request_priority(
            self.priority,
            ctx.extra_headers,
            client.default_headers(),
        );
        let rp = effective_priority.unwrap_or_else(lkh2::RequestPriority::fetch);

        if !ctx.extra_headers.contains_key("priority")
            && !client.default_headers().contains_key("priority")
        {
            if let Ok(hv) = http::HeaderValue::from_str(&rp.to_header_value()) {
                request.headers_mut().insert("priority", hv);
            }
        }

        let header_order = pipeline::effective_h3_header_order(
            self.h3_header_order.as_deref(),
            self.header_order.as_deref(),
            self.session.h3_header_order(),
            self.session.header_order(),
            client.h3_header_order(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        pipeline::auto_insert_content_length(request.headers_mut(), body.as_ref());
        pipeline::merge_headers(
            request.headers_mut(),
            client,
            ctx.extra_headers,
            ctx.parsed_url,
            false,
            &self.session,
            &self.extra_cookies,
            &self.cookie_overrides,
            header_order,
            cookie_order,
        );

        Ok(request)
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) async fn send_h3_request(
        &self,
        sender: &mut lkh3::H3Sender,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response> {
        let method = ctx.method;

        let request = self.build_h3_request(ctx, body)?;

        let early_data_allowed = super::can_send_early_data(method, ctx.idempotency);
        tracing::trace!(
            method = %method,
            idempotency = ?ctx.idempotency,
            early_data_allowed,
            "h3.early_data_gate",
        );

        let ttfb_started = std::time::Instant::now();
        let response = sender.send_request(request).await.map_err(|e| {
            Error::http3_or_connection_closed(ConnectionPhase::HttpRequest, e.to_string())
        })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h3");

        self.receive_h3_response(response, ctx).await
    }

    #[cfg(feature = "quic-h3")]
    async fn receive_h3_response(
        &self,
        response: http::Response<lkh3::H3RecvStream>,
        ctx: &RequestContext<'_>,
    ) -> Result<Response> {
        let host = ctx.host;
        let port = ctx.port;
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        let (parts, mut body_recv) = response.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = client.resource_limits();

        limits.check_response_headers(&resp_headers)?;
        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            host,
            port,
        );

        let mut body_data = bytes::BytesMut::new();
        while let Some(chunk) = body_recv.data().await {
            let chunk = chunk.map_err(|e| {
                Error::http3_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("error reading response body: {e}"),
                )
            })?;
            body_data.extend_from_slice(&chunk);
            limits.check_body_size(body_data.len())?;
        }

        self.make_response(status, resp_headers, body_data.freeze(), HttpVersion::H3)
    }

    #[cfg(feature = "quic-h3")]
    async fn send_h3_0rtt_request(
        &self,
        zero_rtt: lkh3::H3ZeroRttConnection,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
    ) -> Result<(lkh3::H3Connection, Option<Response>)> {
        let early_request = self.build_h3_request(ctx, body.clone())?;
        let mut early_sender = zero_rtt.sender();
        let accepted_fut = zero_rtt.accepted();
        let send_fut = early_sender.send_request(early_request);
        tokio::pin!(accepted_fut);
        tokio::pin!(send_fut);

        let mut send_result: Option<
            std::result::Result<http::Response<lkh3::H3RecvStream>, lkh3::H3Error>,
        > = None;
        let (h3_conn, accepted) = loop {
            tokio::select! {
                accepted = &mut accepted_fut => break accepted,
                result = &mut send_fut, if send_result.is_none() => {
                    send_result = Some(result);
                }
            }
        };

        tracing::debug!(
            method = %ctx.method,
            idempotency = ?ctx.idempotency,
            accepted,
            send_error = ?send_result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(ToString::to_string),
            "h3.early_data_result"
        );

        if accepted {
            let response = match send_result {
                Some(result) => result,
                None => (&mut send_fut).await,
            }
            .map_err(|e| {
                Error::http3_or_connection_closed(ConnectionPhase::HttpRequest, e.to_string())
            })?;
            crate::diagnostics::record_protocol("h3");
            let response = self.receive_h3_response(response, ctx).await?;
            Ok((h3_conn, Some(response)))
        } else {
            tracing::debug!(
                method = %ctx.method,
                "h3.early_data_rejected_replay_required"
            );
            Ok((h3_conn, None))
        }
    }

    // -----------------------------------------------------------------------
    // HTTP/2 first-request (back-to-back with preface)
    // -----------------------------------------------------------------------

    /// Build an `http::Request<Option<Bytes>>` suitable for piggybacking on the
    /// H2 connection preface as a `FirstRequest`.
    ///
    /// This constructs the same request that `send_h2_request` would, but
    /// returns it as a value instead of sending it through a sender.
    fn build_h2_request_for_preface(
        &self,
        ctx: &RequestContext<'_>,
        body: Option<&bytes::Bytes>,
    ) -> Result<http::Request<Option<bytes::Bytes>>> {
        let client = &self.session.inner.client;
        let uri = pipeline::build_h2_uri(ctx.scheme, ctx.host, ctx.port, ctx.path);

        let mut headers = http::HeaderMap::new();

        pipeline::auto_insert_content_length(&mut headers, body);

        let priority_config = &client.h2_profile().priority_config;
        let effective_priority = if let Some(p) = self.priority {
            Some(p)
        } else if let Some(hv) = ctx
            .extra_headers
            .get("priority")
            .and_then(|v| v.to_str().ok())
        {
            lkh2::RequestPriority::from_header_value(hv)
        } else {
            None
        };
        let rp = priority_config.effective_priority(effective_priority);

        if priority_config.auto_priority_header && !ctx.extra_headers.contains_key("priority") {
            if let Ok(hv) = http::HeaderValue::from_str(&rp.to_header_value()) {
                headers.insert("priority", hv);
            }
        }

        let header_order = pipeline::effective_header_order(
            self.header_order.as_deref(),
            self.session.inner.header_order.as_deref(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        self.merge_headers(
            &mut headers,
            client,
            ctx.extra_headers,
            ctx.parsed_url,
            false,
            HeaderMergeOrdering {
                header_order,
                cookie_order,
            },
        );

        let builder = http::Request::builder()
            .method(ctx.method.clone())
            .uri(&uri);

        let req = builder
            .body(body.cloned())
            .map_err(|e| Error::Http(format!("failed to build first H2 request: {e}")))?;

        // Copy merged headers into the request
        let (mut parts, body_val) = req.into_parts();
        parts.headers = headers;
        let mut req = http::Request::from_parts(parts, body_val);
        req.extensions_mut().insert(rp);
        Ok(req)
    }

    /// Receive the response for a first request that was piggybacked on the
    /// H2 connection preface via `establish_h2_with_first_request`.
    async fn receive_h2_first_response(
        &self,
        first_resp: lkh2::driver::FirstRequestResponse,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response> {
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        // If there was a body, it was already included in the first request.
        // For requests with bodies, the body was sent inline as part of the
        // HEADERS+DATA frames in the first request.
        // (The h2-native driver handles DATA frame emission for first requests
        // that have a body.)
        let _ = body;

        let ttfb_started = std::time::Instant::now();

        let resp = crate::h2::await_first_response(first_resp)
            .await
            .map_err(|e| Error::H2(format!("first request response failed: {e}")))?;

        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h2");

        let (parts, mut body_recv) = resp.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = client.resource_limits();

        tracing::debug!(
            status = status.as_u16(),
            protocol = "h2",
            first_request = true,
            "http.response_headers"
        );

        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            ctx.host,
            ctx.port,
        );

        let capacity_hint = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|cl| cl.min(limits.max_response_body_size))
            .unwrap_or(0);
        let mut body_data = bytes::BytesMut::with_capacity(capacity_hint);
        let body_start = std::time::Instant::now();
        while let Some(chunk) = body_recv.data().await {
            let chunk =
                chunk.map_err(|e| Error::H2(format!("error reading response body: {e}")))?;
            let len = chunk.len();
            body_data.extend_from_slice(&chunk);

            limits.check_body_size(body_data.len())?;

            if let Some(min_rate) = limits.min_transfer_rate {
                let elapsed = body_start.elapsed();
                if elapsed > limits.transfer_rate_window {
                    let rate = body_data.len() as f64 / elapsed.as_secs_f64();
                    if rate < min_rate as f64 {
                        return Err(Error::timeout(
                            format!(
                                "transfer rate too slow: {:.0} bytes/s < {} bytes/s",
                                rate, min_rate
                            ),
                            None,
                            None,
                        ));
                    }
                }
            }

            let _ = body_recv.flow_control().release_capacity(len);
        }

        self.make_response(status, resp_headers, body_data.freeze(), HttpVersion::H2)
    }

    // -----------------------------------------------------------------------
    // HTTP/1.1 request sending
    // -----------------------------------------------------------------------

    /// Send a request via HTTP/1.1.
    ///
    /// After a successful request, the sender is returned to the connection pool
    /// for keep-alive reuse.
    pub(crate) async fn send_h1_request(
        &self,
        mut sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: std::sync::Arc<tokio::task::JoinHandle<()>>,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response> {
        let method = ctx.method;
        let host = ctx.host;
        let path = ctx.path;
        let conn_key = ctx.conn_key;
        let extra_headers = ctx.extra_headers;
        let parsed_url = ctx.parsed_url;
        use http_body_util::BodyExt;

        let client = &self.session.inner.client;

        // Build URI — just the path for HTTP/1.1 (Host header carries the authority)
        let uri: http::Uri = path
            .parse()
            .map_err(|e| Error::Http(format!("invalid request path '{}': {e}", path)))?;

        // Build request with Full<Bytes> body
        let body_bytes = body.unwrap_or_default();
        let has_body = !body_bytes.is_empty();
        let full_body = Full::new(body_bytes);

        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(uri)
            .body(full_body)
            .map_err(|e| Error::Http(format!("failed to build HTTP/1.1 request: {e}")))?;

        let header_order = pipeline::effective_header_order(
            self.header_order.as_deref(),
            self.session.inner.header_order.as_deref(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        pipeline::auto_insert_content_length(request.headers_mut(), self.body.as_ref());

        self.merge_headers(
            request.headers_mut(),
            client,
            extra_headers,
            parsed_url,
            true,
            HeaderMergeOrdering {
                header_order,
                cookie_order,
            },
        );

        tracing::debug!(
            method = %method,
            host = %host,
            path = %path,
            protocol = "h1.1",
            has_body = has_body,
            "http.request_sent",
        );

        // Send the request via H1.1
        let ttfb_started = std::time::Instant::now();
        let resp = sender.send_request(request).await.map_err(|e| {
            Error::http_or_connection_closed(
                ConnectionPhase::HttpRequest,
                format!("HTTP/1.1 request failed: {e}"),
            )
        })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("http/1.1");

        // Decompose response to avoid cloning headers
        let (parts, mut body) = resp.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = self.session.inner.client.resource_limits();

        tracing::debug!(
            status = status.as_u16(),
            protocol = "h1.1",
            "http.response_headers"
        );

        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            host,
            ctx.port,
        );

        // Read response body incrementally (matching H2 path behavior)
        let capacity_hint = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|cl| cl.min(limits.max_response_body_size))
            .unwrap_or(0);
        let mut body_data = bytes::BytesMut::with_capacity(capacity_hint);
        let body_start = std::time::Instant::now();

        while let Some(frame_result) = body.frame().await {
            let frame = frame_result.map_err(|e| {
                Error::http_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("error reading HTTP/1.1 response body: {e}"),
                )
            })?;
            if let Some(chunk) = frame.data_ref() {
                body_data.extend_from_slice(chunk);

                limits.check_body_size(body_data.len())?;

                if let Some(min_rate) = limits.min_transfer_rate {
                    let elapsed = body_start.elapsed();
                    if elapsed > limits.transfer_rate_window {
                        let rate = body_data.len() as f64 / elapsed.as_secs_f64();
                        if rate < min_rate as f64 {
                            return Err(Error::timeout(
                                format!(
                                    "transfer rate too slow: {:.0} bytes/s < {} bytes/s",
                                    rate, min_rate
                                ),
                                None,
                                None,
                            ));
                        }
                    }
                }
            }
        }
        let body_data = body_data.freeze();

        // Return the sender to the pool for keep-alive reuse.
        // Check if the connection is still usable (not Connection: close).
        let connection_close = resp_headers
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);

        if !connection_close {
            let mut pool = self.session.inner.pool.lock();
            pool.return_h1_reserved(conn_key.clone(), sender, conn_task, permit);
            tracing::trace!(host = %host, "h1.connection_returned_to_pool");
        } else {
            tracing::trace!(host = %host, "h1.connection_close_not_pooled");
        }

        self.make_response(status, resp_headers, body_data, HttpVersion::Http11)
    }

    // -----------------------------------------------------------------------
    // Cleartext HTTP (h2c upgrade / prior knowledge / plain H1.1)
    // -----------------------------------------------------------------------

    /// Send a request over a cleartext (non-TLS) TCP connection.
    ///
    /// Protocol selection depends on [`PreferredHttpVersion`]:
    /// - `Http1Only`           → plain HTTP/1.1
    /// - `Http2Only`           → h2c with prior knowledge (RFC 7540 §3.4)
    /// - `Auto`                → plain HTTP/1.1
    /// - `Http3WithFallback`   → plain HTTP/1.1 (H3 fundamentally needs
    ///   QUIC + TLS, so cleartext HTTP **is** the fallback the user explicitly
    ///   asked for)
    /// - `Http3Only`           → hard error (user demanded H3 but supplied
    ///   an `http://` URL — config conflict)
    ///
    /// Note: real Chrome / Firefox / Safari never send `Upgrade: h2c` over
    /// `http://` — h2c upgrade was deprecated by all major browsers years
    /// before HTTP/2 became dominant, and HTTP/2 in practice is gated on
    /// TLS + ALPN. To keep the wire format byte-identical to the target
    /// browser (the project's core invariant), the `Auto` and
    /// `Http3WithFallback` policies on cleartext stay on plain HTTP/1.1.
    /// Callers that genuinely need h2c can opt in via `Http2Only` for
    /// prior-knowledge h2c, or by invoking `Self::send_h2c_upgrade`
    /// explicitly.
    async fn send_cleartext(
        &self,
        tcp: tokio::net::TcpStream,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        let policy = self.effective_protocol_policy();
        policy.validate()?;
        let http_version_pref = self.effective_http_version(&policy);

        match http_version_pref {
            PreferredHttpVersion::Http1Only
            | PreferredHttpVersion::Auto
            | PreferredHttpVersion::Http3WithFallback => {
                tracing::debug!(
                    protocol = "h1.1",
                    cleartext = true,
                    requested = ?http_version_pref,
                    "connection.h1_cleartext"
                );
                self.send_h1_cleartext(tcp, permit, ctx, body, connect_start)
                    .await
            }
            PreferredHttpVersion::Http2Only => {
                tracing::debug!(
                    protocol = "h2c",
                    mode = "prior_knowledge",
                    "connection.h2c_prior_knowledge",
                );
                self.send_h2c_prior_knowledge(tcp, permit, ctx, body, connect_start)
                    .await
            }
            PreferredHttpVersion::Http3Only => Err(Error::InvalidConfig(
                "HTTP/3 requires HTTPS and QUIC, but the request URL is cleartext `http://`".into(),
            )),
        }
    }

    /// Send a plain HTTP/1.1 request over a cleartext TCP connection.
    async fn send_h1_cleartext(
        &self,
        tcp: tokio::net::TcpStream,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        let stream = crate::connect::TransportStream::plain(tcp);
        let (sender, conn_task) = pipeline::handshake_h1(stream).await?;

        tracing::debug!(
            protocol = "h1.1",
            cleartext = true,
            duration_ms = connect_start.elapsed().as_millis() as u64,
            "connection.established",
        );

        self.send_h1_request(sender, conn_task, permit, ctx, body)
            .await
    }

    /// h2c with prior knowledge (RFC 7540 §3.4): send the HTTP/2 connection
    /// preface directly over TCP, then send the request as HTTP/2.
    async fn send_h2c_prior_knowledge(
        &self,
        tcp: tokio::net::TcpStream,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        let client = &self.session.inner.client;

        let stream = crate::connect::TransportStream::plain(tcp);
        let sender =
            pipeline::establish_h2_and_pool(stream, client, &self.session, ctx.conn_key, permit)
                .await
                .map_err(|e| {
                    Error::connection(
                        crate::error::ConnectionPhase::H2Negotiation,
                        format!("h2c prior knowledge handshake failed: {e}"),
                        None,
                    )
                })?;

        tracing::debug!(
            protocol = "h2c",
            mode = "prior_knowledge",
            duration_ms = connect_start.elapsed().as_millis() as u64,
            "connection.established",
        );

        self.send_h2_request(sender, ctx, body).await
    }

    /// h2c upgrade (RFC 7540 §3.2): send an HTTP/1.1 request with `Upgrade: h2c`
    /// and `HTTP2-Settings` headers. If the server accepts (101), switch to HTTP/2
    /// and resend the request; otherwise return the HTTP/1.1 response.
    ///
    /// Currently unused — the default `Auto` cleartext path stays on plain
    /// H1.1 to match real browser wire format (no major browser sends
    /// `Upgrade: h2c` over `http://`). Retained for a future explicit
    /// opt-in API (e.g. `HttpIntent::CleartextH2cUpgrade`) and as a
    /// reference implementation; removing it now would lose the carefully
    /// audited header-injection / pool-insertion logic.
    #[allow(dead_code)]
    async fn send_h2c_upgrade(
        &self,
        tcp: tokio::net::TcpStream,
        ctx: &RequestContext<'_>,
        body: Option<bytes::Bytes>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        use http::header::{CONNECTION, UPGRADE};
        use http_body_util::BodyExt;
        use hyper_util::rt::TokioIo;

        let permit = self.session.reserve_connection()?;
        let method = ctx.method;
        let host = ctx.host;
        let path = ctx.path;
        let conn_key = ctx.conn_key;
        let extra_headers = ctx.extra_headers;
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        let h2_settings_payload =
            crate::h2::profile::encode_h2_settings_base64url(client.h2_profile());

        let uri: http::Uri = path
            .parse()
            .map_err(|e| Error::Http(format!("invalid request path '{}': {e}", path)))?;

        let body_bytes = body.clone().unwrap_or_default();
        let full_body = Full::new(body_bytes);

        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(uri)
            .body(full_body)
            .map_err(|e| Error::Http(format!("failed to build h2c upgrade request: {e}")))?;

        let header_order = pipeline::effective_header_order(
            self.header_order.as_deref(),
            self.session.inner.header_order.as_deref(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        pipeline::auto_insert_content_length(request.headers_mut(), body.as_ref());

        self.merge_headers(
            request.headers_mut(),
            client,
            extra_headers,
            parsed_url,
            true,
            HeaderMergeOrdering {
                header_order,
                cookie_order,
            },
        );

        request
            .headers_mut()
            .insert(UPGRADE, "h2c".parse().unwrap());
        request
            .headers_mut()
            .insert(CONNECTION, "Upgrade, HTTP2-Settings".parse().unwrap());
        request.headers_mut().insert(
            http::header::HeaderName::from_static("http2-settings"),
            http::header::HeaderValue::from_str(&h2_settings_payload)
                .map_err(|e| Error::Http(format!("invalid HTTP2-Settings value: {e}")))?,
        );

        tracing::debug!(
            method = %method,
            host = %host,
            path = %path,
            protocol = "h1.1",
            h2c_upgrade = true,
            "http.h2c_upgrade_request_sent",
        );

        let io = TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .title_case_headers(true)
            .preserve_header_case(true)
            .handshake(io)
            .await
            .map_err(|e| Error::Http(format!("H1 handshake for h2c upgrade failed: {e}")))?;

        let conn_task = tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!(error = %e, "h2c.upgrade_connection_closed");
            }
        });
        let conn_task = std::sync::Arc::new(conn_task);

        let resp = sender
            .send_request(request)
            .await
            .map_err(|e| Error::Http(format!("h2c upgrade request failed: {e}")))?;

        if resp.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            tracing::debug!("h2c.upgrade_accepted");

            let upgraded = hyper::upgrade::on(resp).await.map_err(|e| {
                Error::connection(
                    crate::error::ConnectionPhase::H2cUpgrade,
                    format!("h2c upgrade extraction failed: {e}"),
                    None,
                )
            })?;

            let upgraded_io = TokioIo::new(upgraded);

            let h2_conn = crate::h2::connect_h2_with_config(
                upgraded_io,
                client.h2_profile(),
                None,
                client.max_pending_h2_requests(),
            )
            .await
            .map_err(|e| {
                Error::connection(
                    crate::error::ConnectionPhase::H2cUpgrade,
                    format!("h2c post-upgrade H2 handshake failed: {e}"),
                    None,
                )
            })?;
            let h2_sender = h2_conn.clone_sender();

            {
                let mut pool = self.session.inner.pool.lock();
                pool.insert_h2_reserved(
                    conn_key.clone(),
                    h2_conn.clone_sender(),
                    h2_conn.into_task(),
                    permit,
                );
            }

            tracing::debug!(
                protocol = "h2c",
                mode = "upgrade",
                duration_ms = connect_start.elapsed().as_millis() as u64,
                "connection.established",
            );

            let h2_sender = h2_sender
                .ready()
                .await
                .map_err(|e| Error::H2(format!("h2c connection not ready: {e}")))?;

            self.send_h2_request(h2_sender, ctx, body).await
        } else {
            // Server did not accept the upgrade — return the HTTP/1.1 response
            tracing::debug!(
                status = resp.status().as_u16(),
                "h2c.upgrade_rejected_using_h1",
            );

            let (parts, resp_body) = resp.into_parts();
            let status = parts.status;
            let resp_headers = parts.headers;
            let limits = self.session.inner.client.resource_limits();

            limits.check_response_headers(&resp_headers)?;
            pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
            pipeline::store_alt_svc(
                &self.session,
                &resp_headers,
                self.effective_proxy(),
                ctx.scheme,
                host,
                ctx.port,
            );

            let body_collected = resp_body
                .collect()
                .await
                .map_err(|e| Error::Http(format!("error reading h2c fallback response: {e}")))?;
            let body_data = body_collected.to_bytes();
            limits.check_body_size(body_data.len())?;

            // Return the H1.1 sender to the pool for keep-alive reuse,
            // unless the server indicated Connection: close.
            let connection_close = resp_headers
                .get(http::header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("close"))
                .unwrap_or(false);

            if !connection_close {
                let mut pool = self.session.inner.pool.lock();
                pool.return_h1_reserved(conn_key.clone(), sender, conn_task, permit);
                tracing::trace!(host = %host, "h2c.rejected_h1_returned_to_pool");
            }

            self.make_response(status, resp_headers, body_data, HttpVersion::Http11)
        }
    }

    // -----------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------

    /// Merge default headers + request headers + cookies into the request headers.
    pub(crate) fn merge_headers(
        &self,
        headers: &mut HeaderMap,
        client: &Client,
        extra_headers: &HeaderMap,
        parsed_url: &Url,
        is_h1: bool,
        ordering: HeaderMergeOrdering<'_>,
    ) {
        merge_headers_common(
            headers,
            client,
            extra_headers,
            parsed_url,
            is_h1,
            &self.session.inner.cookie_jar,
            &self.extra_cookies,
            &self.cookie_overrides,
            ordering.header_order,
            ordering.cookie_order,
        );
    }

    /// Build a Response, applying decompression unless `no_decompress` is set.
    pub(crate) fn make_response(
        &self,
        status: http::StatusCode,
        headers: HeaderMap,
        body: bytes::Bytes,
        http_version: HttpVersion,
    ) -> Result<Response> {
        let mut resp = if self.no_decompress {
            Response::from_parts(status, headers, body)
        } else {
            Response::new(status, headers, body)?
        };
        resp.set_http_version(http_version);
        Ok(resp)
    }

    pub(crate) fn effective_proxy(&self) -> Option<&ProxyConfig> {
        pipeline::effective_proxy(self.proxy_override.as_ref(), &self.session)
    }

    pub(crate) fn effective_protocol_policy(&self) -> crate::protocol::ProtocolPolicy {
        pipeline::effective_protocol_policy(self.protocol_policy_override.as_ref(), &self.session)
    }

    pub(crate) fn effective_http_version(
        &self,
        protocol_policy: &crate::protocol::ProtocolPolicy,
    ) -> PreferredHttpVersion {
        pipeline::effective_http_version(self.version_override, protocol_policy, &self.session)
    }

    /// Resolve the effective total timeout for this request.
    pub(crate) fn effective_total_timeout(&self) -> Duration {
        self.timeout.unwrap_or_else(|| {
            self.session
                .inner
                .client
                .timeouts()
                .total_timeout_or(Duration::from_secs(60))
        })
    }
}

// ---------------------------------------------------------------------------
// Shared header merge logic
// ---------------------------------------------------------------------------

/// Parse `name=value` pairs from one `Cookie` header value (`;`-separated, RFC 6265-style).
fn parse_cookie_header_value(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((n, v)) = part.split_once('=') {
            out.push((n.trim().to_string(), v.trim().to_string()));
        } else {
            out.push((part.to_string(), String::new()));
        }
    }
    out
}

/// Remove all `Cookie` headers and return the parsed pairs in field order.
fn drain_cookie_pairs_from_headers(headers: &mut HeaderMap) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for val in headers.get_all(http::header::COOKIE) {
        if let Ok(s) = val.to_str() {
            pairs.extend(parse_cookie_header_value(s));
        }
    }
    headers.remove(http::header::COOKIE);
    pairs
}

/// Header name order and optional cookie name order for [`RequestBuilder::merge_headers`].
pub(crate) struct HeaderMergeOrdering<'a> {
    pub header_order: &'a [http::header::HeaderName],
    pub cookie_order: Option<&'a [Box<str>]>,
}

/// Merge default headers, request headers, and cookies into the target
/// `HeaderMap`.
///
/// This is the single implementation shared by `RequestBuilder::merge_headers`
/// and `merge_headers_for_streaming`.
///
/// `is_h1` controls whether the Host header is preserved (H1.1 needs it,
/// H2 uses `:authority` instead).
///
/// # Cookie merging
///
/// Whether two URLs differ in **origin** (scheme, host, or port).
///
/// This is the Fetch "same origin" comparison and is the trigger for stripping
/// the `Authorization` header on a cross-origin redirect (Fetch §4.4 / Chrome
/// M112+). Note that a scheme-only change (e.g. an `https`→`http` downgrade on
/// the same host) counts as cross-origin, because the default port differs and,
/// explicitly here, the scheme differs.
pub(crate) fn redirect_is_cross_origin(from: &Url, to: &Url) -> bool {
    from.scheme() != to.scheme()
        || from.host_str() != to.host_str()
        || from.port_or_known_default() != to.port_or_known_default()
}

/// Apply an HSTS scheme upgrade to `url` if `policy` marks its host HTTPS-only.
///
/// Returns the rewritten `https://` URL (with an explicit `:80` bumped to
/// `:443`, per RFC 6797 §8.3), or `None` if no upgrade applies. Called before
/// connecting, for both the initial URL and every redirect target.
fn hsts_upgrade(url: &str, policy: &dyn crate::hsts::HstsPolicy) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    let host = parsed.host_str()?.to_string();
    if !policy.should_upgrade(&host) {
        return None;
    }
    parsed.set_scheme("https").ok()?;
    if parsed.port() == Some(80) {
        parsed.set_port(Some(443)).ok()?;
    }
    Some(parsed.to_string())
}

/// Any `Cookie` set on the request (defaults or per-request headers) is taken
/// as **explicit** pairs. They are sent **first**, and override the session
/// jar for matching cookie names. Pairs from [`RequestBuilder::cookie`](crate::session::RequestBuilder::cookie)
/// are appended after jar-derived pairs (duplicates allowed, matching that API).
///
/// Fully synchronous — cookie reads use lock-free `ArcSwap::load()`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_headers_common(
    headers: &mut HeaderMap,
    client: &Client,
    extra_headers: &HeaderMap,
    parsed_url: &Url,
    is_h1: bool,
    cookie_jar: &arc_swap::ArcSwap<crate::session::CookieStore>,
    extra_cookies: &[(String, String)],
    cookie_overrides: &[String],
    header_order: &[http::header::HeaderName],
    cookie_order: Option<&[Box<str>]>,
) {
    use std::collections::HashSet;

    for (name, value) in client.default_headers() {
        if !extra_headers.contains_key(name) {
            headers.insert(name.clone(), value.clone());
        }
    }

    for (name, value) in extra_headers {
        headers.insert(name.clone(), value.clone());
    }

    if !is_h1 {
        headers.remove(http::header::HOST);
    }

    let manual_pairs = drain_cookie_pairs_from_headers(headers);

    let jar = cookie_jar.load();
    let matches = jar.matches(parsed_url);
    let mut cookie_list: Vec<(String, String)> = matches
        .iter()
        .map(|c| (c.name().to_string(), c.value().to_string()))
        .collect();

    if !cookie_overrides.is_empty() {
        cookie_list.retain(|(n, _)| !cookie_overrides.iter().any(|o| o == n));
    }

    let manual_names: HashSet<&str> = manual_pairs.iter().map(|(n, _)| n.as_str()).collect();
    cookie_list.retain(|(n, _)| !manual_names.contains(n.as_str()));

    for (name, value) in extra_cookies {
        cookie_list.push((name.clone(), value.clone()));
    }

    let mut merged: Vec<(String, String)> =
        Vec::with_capacity(manual_pairs.len() + cookie_list.len());
    merged.extend(manual_pairs);
    merged.extend(cookie_list);

    if let Some(order) = cookie_order {
        reorder_cookies(&mut merged, order);
    }

    if !merged.is_empty() {
        tracing::trace!(url = %parsed_url, "http.cookies_sent");

        // Split cookies into separate headers only when:
        // 1. The request is HTTP/2, AND
        // 2. The user has explicitly configured header ordering
        //    (via fingerprint preset or manual header_order)
        //
        // Without explicit ordering, use a single combined Cookie
        // header for maximum server compatibility.
        let split_h2_cookies = !is_h1 && !header_order.is_empty();

        if split_h2_cookies {
            for (n, v) in &merged {
                let pair = format!("{n}={v}");
                if let Ok(hv) = http::header::HeaderValue::from_str(&pair) {
                    headers.append(http::header::COOKIE, hv);
                }
            }
        } else {
            let val: String =
                merged
                    .iter()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, (n, v))| {
                        if i > 0 {
                            acc.push_str("; ");
                        }
                        acc.push_str(n);
                        acc.push('=');
                        acc.push_str(v);
                        acc
                    });
            if let Ok(hv) = http::header::HeaderValue::from_str(&val) {
                headers.insert(http::header::COOKIE, hv);
            }
        }
    }

    // Auto-insert Host for HTTP/1.1 if not already present.
    // Must happen before reorder_headers so that header_order can control Host position.
    if is_h1 && !headers.contains_key(http::header::HOST) {
        if let Some(host_value) = super::pipeline::build_host_value_from_url(parsed_url) {
            if let Ok(hv) = http::header::HeaderValue::from_str(&host_value) {
                headers.insert(http::header::HOST, hv);
            }
        }
    }

    if !header_order.is_empty() {
        reorder_headers(headers, header_order);
    }
}

// ---------------------------------------------------------------------------
// Header ordering
// ---------------------------------------------------------------------------

/// Reorder headers according to a template.
///
/// Headers matching entries in `order` are placed first, in the template's
/// order.  Remaining headers that are not in the template are appended
/// after the ordered ones, preserving their relative order from the
/// original `HeaderMap`.
///
/// Reorder a list of `(name, value)` cookie pairs according to a template.
///
/// Reorder a list of cookie pairs in-place according to a template.
///
/// Cookies whose names appear in `order` are placed first (in the template's
/// order). Remaining cookies are appended in their original order.
///
/// Generic over the string type (`String`, `Cow<str>`, etc.) to support
/// both owned and borrowed cookie data without extra allocations.
pub(crate) fn reorder_cookies<S: AsRef<str>, O: AsRef<str>>(
    cookies: &mut Vec<(S, S)>,
    order: &[O],
) {
    let mut result = Vec::with_capacity(cookies.len());

    for name in order {
        if let Some(pos) = cookies
            .iter()
            .position(|(n, _)| n.as_ref() == name.as_ref())
        {
            result.push(cookies.remove(pos));
        }
    }

    result.append(cookies);
    *cookies = result;
}

/// Reorder headers in-place according to a template.
///
/// Headers matching entries in `order` are placed first, in the template's
/// order. Remaining headers are appended after, preserving their relative
/// order. Multi-value headers (e.g. multiple `Cookie` entries in HTTP/2)
/// are fully preserved — all values for a given name are moved together.
pub(crate) fn reorder_headers(headers: &mut HeaderMap, order: &[http::header::HeaderName]) {
    // Snapshot all entries in their current iteration order BEFORE any
    // mutation.  `HeaderMap::remove()` uses backward-shift deletion which
    // can scramble the relative positions of remaining entries, so we must
    // drain first to capture the true insertion order.
    let mut all: Vec<(http::header::HeaderName, http::header::HeaderValue)> =
        Vec::with_capacity(headers.len());
    let mut last_name: Option<http::header::HeaderName> = None;
    for (opt_name, value) in headers.drain() {
        let name = match opt_name {
            Some(n) => {
                last_name = Some(n.clone());
                n
            }
            None => match &last_name {
                Some(n) => n.clone(),
                None => {
                    tracing::warn!("reorder_headers: skipping orphan header value (no field name)");
                    continue;
                }
            },
        };
        all.push((name, value));
    }

    let mut result = HeaderMap::with_capacity(all.len());

    // Phase 1: pull headers matching the template, in template order.
    for template_name in order {
        let mut i = 0;
        while i < all.len() {
            if all[i].0 == *template_name {
                let (name, value) = all.remove(i);
                result.append(name, value);
            } else {
                i += 1;
            }
        }
    }

    // Phase 2: append remaining headers in their original relative order.
    for (name, value) in all {
        result.append(name, value);
    }

    *headers = result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_cross_origin_trigger_includes_scheme() {
        let u = |s: &str| Url::parse(s).unwrap();

        // Same origin → not cross-origin.
        assert!(!redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("https://a.com/y")
        ));
        // Different host → cross-origin.
        assert!(redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("https://b.com/y")
        ));
        // Different (default) port via scheme downgrade → cross-origin.
        assert!(redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("http://a.com/y")
        ));
        // Same host+port but scheme differs (explicit equal ports) → still
        // cross-origin, because the scheme is part of the origin. This is the
        // case the old host+port-only predicate missed.
        assert!(redirect_is_cross_origin(
            &u("https://a.com:8443/x"),
            &u("http://a.com:8443/y")
        ));
        // Different explicit port → cross-origin.
        assert!(redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("https://a.com:8443/y")
        ));
    }

    #[test]
    fn test_reorder_headers_basic() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("user-agent", "test/1.0".parse().unwrap());
        headers.insert("cookie", "a=b".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].as_str(), "user-agent");
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "cookie");
    }

    #[test]
    fn test_reorder_headers_extra_headers_appended() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "value".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("user-agent", "test/1.0".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].as_str(), "user-agent");
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "x-custom");
    }

    #[test]
    fn test_reorder_headers_missing_template_entries() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].as_str(), "accept");
    }

    #[test]
    fn test_reorder_headers_empty_template() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("user-agent", "test/1.0".parse().unwrap());

        let order: Vec<http::header::HeaderName> = vec![];

        reorder_headers(&mut headers, &order);

        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("accept"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn test_reorder_headers_preserves_values() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json".parse().unwrap());
        headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
        ];

        reorder_headers(&mut headers, &order);

        assert_eq!(headers.get("user-agent").unwrap(), "Mozilla/5.0");
        assert_eq!(headers.get("accept").unwrap(), "application/json");
    }

    // -------------------------------------------------------------------
    // Cookie order tests
    // -------------------------------------------------------------------

    #[test]
    fn test_reorder_cookies_basic() {
        let mut cookies: Vec<(String, String)> = vec![
            ("c".into(), "3".into()),
            ("a".into(), "1".into()),
            ("b".into(), "2".into()),
        ];
        let order: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0].0, "a");
        assert_eq!(cookies[1].0, "b");
        assert_eq!(cookies[2].0, "c");
    }

    #[test]
    fn test_reorder_cookies_extra_appended() {
        let mut cookies: Vec<(String, String)> = vec![
            ("z".into(), "9".into()),
            ("a".into(), "1".into()),
            ("x".into(), "8".into()),
        ];
        let order: Vec<String> = vec!["a".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0].0, "a");
        assert_eq!(cookies[1].0, "z");
        assert_eq!(cookies[2].0, "x");
    }

    #[test]
    fn test_reorder_cookies_empty_template() {
        let mut cookies: Vec<(String, String)> =
            vec![("b".into(), "2".into()), ("a".into(), "1".into())];
        let order: Vec<&str> = vec![];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0].0, "b");
        assert_eq!(cookies[1].0, "a");
    }

    #[test]
    fn test_reorder_cookies_preserves_values() {
        let mut cookies: Vec<(String, String)> = vec![
            ("session".into(), "abc123".into()),
            ("csrf".into(), "token456".into()),
        ];
        let order: Vec<String> = vec!["csrf".into(), "session".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0], ("csrf".into(), "token456".into()));
        assert_eq!(cookies[1], ("session".into(), "abc123".into()));
    }

    #[test]
    fn test_reorder_cookies_missing_template_entries_skipped() {
        let mut cookies: Vec<(String, String)> = vec![("a".into(), "1".into())];
        let order: Vec<String> = vec!["x".into(), "a".into(), "y".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "a");
    }

    // -------------------------------------------------------------------
    // Multi-value header reorder tests
    // -------------------------------------------------------------------

    #[test]
    fn test_reorder_preserves_multi_value_header() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        headers.append("cookie", "a=1".parse().unwrap());
        headers.append("cookie", "b=2".parse().unwrap());
        headers.append("cookie", "c=3".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "cookie");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values, vec!["a=1", "b=2", "c=3"]);
    }

    #[test]
    fn test_reorder_multi_value_in_template() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "test/1.0".parse().unwrap());
        headers.append("cookie", "x=1".parse().unwrap());
        headers.append("cookie", "y=2".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("cookie"),
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "cookie");
        assert_eq!(keys[1].as_str(), "user-agent");
        assert_eq!(keys[2].as_str(), "accept");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values, vec!["x=1", "y=2"]);
    }

    #[test]
    fn test_reorder_mixed_single_and_multi_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "val".parse().unwrap());
        headers.append("cookie", "a=1".parse().unwrap());
        headers.append("cookie", "b=2".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());
        headers.append("x-multi", "v1".parse().unwrap());
        headers.append("x-multi", "v2".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "cookie");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values, vec!["a=1", "b=2"]);

        let multi_values: Vec<&str> = headers
            .get_all("x-multi")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(multi_values, vec!["v1", "v2"]);

        assert_eq!(headers.get("x-custom").unwrap(), "val");
    }

    // -------------------------------------------------------------------
    // Host auto-insert in merge_headers_common tests
    // -------------------------------------------------------------------

    fn make_test_client_with_order(order: Vec<&str>) -> Client {
        Client::builder().header_order(order).build()
    }

    #[test]
    fn test_host_auto_insert_respects_header_order() {
        let client = make_test_client_with_order(vec!["host", "accept", "user-agent"]);
        let mut headers = HeaderMap::new();
        let extra = HeaderMap::new();
        let url = url::Url::parse("https://example.com/path").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieStore::new());

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "host");
        assert_eq!(headers.get("host").unwrap(), "example.com");
    }

    #[test]
    fn test_host_auto_insert_not_in_template() {
        let client = make_test_client_with_order(vec!["accept", "user-agent"]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        let url = url::Url::parse("https://example.com/path").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieStore::new());

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        let host_pos = keys.iter().position(|k| k.as_str() == "host").unwrap();
        assert!(host_pos > 0, "Host should be after template items");
    }

    #[test]
    fn test_host_not_overwritten_if_user_set() {
        let client = make_test_client_with_order(vec!["host", "accept"]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("host", "custom-host.example.com".parse().unwrap());
        let url = url::Url::parse("https://example.com/path").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieStore::new());

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        assert_eq!(headers.get("host").unwrap(), "custom-host.example.com");
    }

    #[test]
    fn test_host_value_format() {
        let client = make_test_client_with_order(vec!["host"]);
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieStore::new());
        let ho = client.header_order().unwrap_or(&[]);
        let co = client.cookie_order();

        // HTTPS port 443: omit port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com");

        // HTTPS non-standard port: include port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com:8443/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com:8443");

        // HTTP port 80: omit port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("http://example.com/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com");

        // HTTP non-standard port: include port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("http://example.com:8080/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com:8080");
    }

    #[test]
    fn test_host_not_inserted_for_h2() {
        let client = make_test_client_with_order(vec!["host", "accept"]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieStore::new());

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        assert!(
            !headers.contains_key("host"),
            "Host should not be present for H2"
        );
    }

    // -------------------------------------------------------------------
    // Cookie path tests (unified path + H1/H2 branching)
    // -------------------------------------------------------------------

    fn make_jar_with_cookies(
        url_str: &str,
        cookies: &[(&str, &str)],
    ) -> arc_swap::ArcSwap<crate::session::CookieStore> {
        let url = url::Url::parse(url_str).unwrap();
        let mut jar = crate::session::CookieStore::new();
        for (name, value) in cookies {
            let raw = cookie_store::RawCookie::build((*name, *value))
                .domain(url.host_str().unwrap())
                .path("/")
                .build();
            let _ = jar.insert_raw(&raw, &url);
        }
        arc_swap::ArcSwap::from_pointee(jar)
    }

    #[test]
    fn test_merge_explicit_cookie_with_jar_and_extra() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("cookie", "sid=manual".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("from_jar", "yes")]);

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[("from_extra".to_string(), "1".to_string())],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(cookie_val.contains("sid=manual"), "explicit: {cookie_val}");
        assert!(cookie_val.contains("from_jar=yes"), "jar: {cookie_val}");
        assert!(cookie_val.contains("from_extra=1"), "extra: {cookie_val}");
        let sid = cookie_val.find("sid=manual").unwrap();
        let j = cookie_val.find("from_jar=yes").unwrap();
        let e = cookie_val.find("from_extra=1").unwrap();
        assert!(
            sid < j && j < e,
            "expected explicit → jar → .cookie order: {cookie_val}"
        );
    }

    #[test]
    fn test_explicit_cookie_overrides_same_name_in_jar() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("cookie", "dup=from_header".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("dup", "from_jar")]);

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(
            cookie_val.contains("dup=from_header"),
            "header should win: {cookie_val}"
        );
        assert!(
            !cookie_val.contains("from_jar"),
            "jar value should be overridden: {cookie_val}"
        );
    }

    #[test]
    fn test_parse_cookie_header_value_splits_pairs() {
        let p = parse_cookie_header_value("a=1; b=two; c=");
        assert_eq!(
            p,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "two".to_string()),
                ("c".to_string(), "".to_string()),
            ]
        );
    }

    #[test]
    fn test_cookie_no_order_no_extra_unchanged() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("a", "1"), ("b", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(cookie_val.contains("a=1"));
        assert!(cookie_val.contains("b=2"));
    }

    #[test]
    fn test_cookie_with_order_applied() {
        let client = Client::builder().cookie_order(vec!["b", "a"]).build();
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("a", "1"), ("b", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        let b_pos = cookie_val.find("b=2").unwrap();
        let a_pos = cookie_val.find("a=1").unwrap();
        assert!(b_pos < a_pos, "b should come before a, got: {cookie_val}");
    }

    #[test]
    fn test_h2_multiple_cookie_headers() {
        let client = make_test_client_with_order(vec!["cookie"]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            3,
            "H2 should have 3 separate Cookie headers"
        );
        for val in &cookie_values {
            assert!(
                !val.contains("; "),
                "Each H2 Cookie header should be a single pair: {val}"
            );
        }
    }

    #[test]
    fn test_h1_single_cookie_header() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "H1 should have 1 combined Cookie header"
        );
        assert!(
            cookie_values[0].contains("; "),
            "H1 Cookie should have semicolon separators"
        );
    }

    #[test]
    fn test_h2_cookie_order_before_split() {
        let client = Client::builder()
            .header_order(vec!["cookie"])
            .cookie_order(vec!["c", "a", "b"])
            .build();
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values.len(), 3);
        assert_eq!(cookie_values[0], "c=3");
        assert_eq!(cookie_values[1], "a=1");
        assert_eq!(cookie_values[2], "b=2");
    }

    #[test]
    fn test_h2_cookie_survives_reorder_headers() {
        let client = Client::builder()
            .header_order(vec!["accept", "cookie", "user-agent"])
            .build();
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("x", "1"), ("y", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "cookie");
        assert_eq!(keys[2].as_str(), "user-agent");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            2,
            "Both H2 Cookie values should survive reorder"
        );
    }

    #[test]
    fn test_h2_no_header_order_uses_single_cookie() {
        let client = Client::builder().build();
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("a", "1"), ("b", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            &[],
            None,
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "H2 without header_order should use single Cookie header for compatibility"
        );
        assert!(
            cookie_values[0].contains("; "),
            "Single Cookie header should use semicolons"
        );
    }

    // -------------------------------------------------------------------
    // Header/cookie ordering override hierarchy tests
    // -------------------------------------------------------------------

    #[test]
    fn test_session_header_order_overrides_client() {
        let client = Client::builder()
            .header_order(vec!["user-agent", "accept"])
            .build();
        let session = client
            .session()
            .header_order(vec!["accept", "user-agent"])
            .build();

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &[],
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &session.inner.cookie_jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "user-agent");
    }

    #[test]
    fn test_request_header_order_overrides_session_and_client() {
        let client = Client::builder()
            .header_order(vec!["user-agent", "accept"])
            .build();
        let session = client
            .session()
            .header_order(vec!["accept", "user-agent"])
            .build();

        let request_order = vec![
            http::header::HeaderName::from_static("cookie"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("user-agent"),
        ];

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            Some(&request_order),
            session.header_order(),
            client.header_order(),
            &[],
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        let jar = make_jar_with_cookies("https://example.com/", &[("sid", "abc")]);
        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(
            keys[0].as_str(),
            "cookie",
            "cookie should be first per request order"
        );
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "user-agent");
    }

    #[test]
    fn test_no_explicit_order_uses_insertion_order() {
        let client = Client::builder().build();
        let session = client.session().build();

        let insertion_order = vec![
            http::header::HeaderName::from_static("x-custom"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("user-agent"),
        ];

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        extra.insert("x-custom", "value".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &insertion_order,
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &session.inner.cookie_jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(
            keys[0].as_str(),
            "x-custom",
            "insertion order should be respected"
        );
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "user-agent");
    }

    #[test]
    fn test_no_fingerprint_no_implicit_header_order() {
        let client = Client::builder().build();
        assert!(
            client.header_order().is_none(),
            "No implicit header_order without fingerprint"
        );
    }

    #[test]
    fn test_header_insertion_order_dedup() {
        let client = Client::builder().build();
        let session = client.session().build();

        let rb = session
            .get("https://example.com")
            .header("accept", "text/html")
            .header("user-agent", "test/1.0")
            .header("accept", "application/json");

        assert_eq!(rb.header_insertion_order.len(), 2);
        assert_eq!(rb.header_insertion_order[0].as_str(), "accept");
        assert_eq!(rb.header_insertion_order[1].as_str(), "user-agent");
    }

    #[test]
    fn test_session_cookie_order_overrides_client() {
        let client = Client::builder().cookie_order(vec!["a", "b", "c"]).build();
        let session = client.session().cookie_order(vec!["c", "b", "a"]).build();

        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &[],
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        let c_pos = cookie_val.find("c=3").unwrap();
        let b_pos = cookie_val.find("b=2").unwrap();
        let a_pos = cookie_val.find("a=1").unwrap();
        assert!(
            c_pos < b_pos,
            "c should come before b per session cookie_order"
        );
        assert!(
            b_pos < a_pos,
            "b should come before a per session cookie_order"
        );
    }

    #[test]
    fn test_user_sets_headers_no_config_order_preserved() {
        let client = Client::builder().build();
        let session = client.session().build();

        let insertion_order = vec![
            http::header::HeaderName::from_static("x-first"),
            http::header::HeaderName::from_static("x-second"),
            http::header::HeaderName::from_static("x-third"),
        ];

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("x-first", "1".parse().unwrap());
        extra.insert("x-second", "2".parse().unwrap());
        extra.insert("x-third", "3".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &insertion_order,
        );

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &session.inner.cookie_jar,
            &[],
            &[],
            header_order,
            None,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "x-first");
        assert_eq!(keys[1].as_str(), "x-second");
        assert_eq!(keys[2].as_str(), "x-third");
    }

    #[test]
    fn test_request_protocol_policy_override_wins_over_session_policy() {
        let client = Client::builder()
            .protocol_policy(crate::protocol::ProtocolPolicy::crawler_throughput())
            .build();
        let session = client
            .session()
            .protocol_policy(crate::protocol::ProtocolPolicy::chrome_conservative())
            .build();
        let rb = session
            .get("https://example.com")
            .protocol_policy(crate::protocol::ProtocolPolicy::h3_strict());

        assert_eq!(
            rb.effective_protocol_policy(),
            crate::protocol::ProtocolPolicy::h3_strict()
        );
    }
}
