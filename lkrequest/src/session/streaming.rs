use std::sync::Arc;

use http::HeaderMap;
use http_body_util::Full;

use crate::connection_pool::PooledConnection;
use crate::error::{ConnectionPhase, Error, Result};
use crate::protocol::ProtocolPolicy;
use crate::proxy::ProxyConfig;
use crate::response::{BodyStream, StreamingResponse};

use super::pipeline;
use super::{PreferredHttpVersion, Session};

/// Internal builder used by [`super::RequestBuilder::send_streaming`].
///
/// Mirrors the relevant fields of `RequestBuilder` but produces a
/// [`StreamingResponse`] instead of a buffered [`crate::response::Response`].
pub(crate) struct StreamRequestBuilder {
    pub(crate) session: Session,
    pub(crate) method: http::Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<bytes::Bytes>,
    pub(crate) extra_cookies: Vec<(String, String)>,
    pub(crate) cookie_overrides: Vec<String>,
    pub(crate) proxy_override: Option<ProxyConfig>,
    pub(crate) version_override: Option<PreferredHttpVersion>,
    pub(crate) protocol_policy_override: Option<ProtocolPolicy>,
    pub(crate) no_decompress: bool,
    pub(crate) header_order: Option<Vec<http::header::HeaderName>>,
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub(crate) h3_header_order: Option<Vec<http::header::HeaderName>>,
    pub(crate) cookie_order: Option<Vec<Box<str>>>,
    pub(crate) header_insertion_order: Vec<http::header::HeaderName>,
    /// Explicit RFC 9218 priority carried over from the originating
    /// `RequestBuilder::priority()` (if set). Currently consumed only by the
    /// HTTP/3 streaming path (the H2 streaming path does not yet apply it).
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub(crate) priority: Option<lkh2::RequestPriority>,
}

impl StreamRequestBuilder {
    /// Core streaming request implementation (no redirect following).
    ///
    /// Heap-allocated future to avoid stack overflow (see `establish_and_send`).
    pub(crate) fn send_streaming_inner(
        self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send>>
    {
        Box::pin(async move {
            let effective_proxy = self.effective_proxy();
            let protocol_policy = self.effective_protocol_policy();
            protocol_policy.validate()?;
            let http_version_pref = self.effective_http_version(&protocol_policy);
            let target = pipeline::parse_request_target(&self.url, effective_proxy)?;

            let pooled =
                pipeline::try_acquire_pooled(&self.session, &target.conn_key, http_version_pref);

            match pooled {
                #[cfg(feature = "quic-h3")]
                Some(PooledConnection::H3(mut cached_sender)) => {
                    let result = self.send_h3_streaming(&mut cached_sender, &target).await;

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
                            self.establish_and_send_streaming(&target).await
                        }
                        other => other,
                    }
                }
                Some(PooledConnection::H2(cached_sender)) => match cached_sender.ready().await {
                    Ok(sender) => {
                        let result = self.send_h2_streaming(sender, &target).await;

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
                                self.establish_and_send_streaming(&target).await
                            }
                            other => other,
                        }
                    }
                    Err(_) => {
                        {
                            let mut pool = self.session.inner.pool.lock();
                            pool.remove(&target.conn_key);
                        }
                        self.establish_and_send_streaming(&target).await
                    }
                },
                Some(PooledConnection::H1 { sender, conn_task }) => {
                    self.send_h1_streaming(sender, conn_task, &target).await
                }
                None => self.establish_and_send_streaming(&target).await,
            }
        })
    }

    /// Send a streaming request via HTTP/2 using an existing sender.
    async fn send_h2_streaming(
        &self,
        sender: lkh2::H2ReadySender,
        target: &pipeline::ParsedTarget,
    ) -> Result<StreamingResponse> {
        let client = &self.session.inner.client;
        let uri = pipeline::build_h2_uri(target.scheme, &target.host, target.port, &target.path);

        let has_body = self.body.is_some();
        let end_stream = !has_body;

        let mut request = http::Request::builder()
            .method(self.method.clone())
            .uri(&uri)
            .body(())
            .map_err(|e| Error::Http(format!("failed to build HTTP request: {e}")))?;

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

        pipeline::merge_headers(
            request.headers_mut(),
            client,
            &self.headers,
            &target.parsed_url,
            false,
            &self.session,
            &self.extra_cookies,
            &self.cookie_overrides,
            header_order,
            cookie_order,
        );

        let (resp_future, mut send_stream) =
            sender.send_request(request, end_stream).map_err(|e| {
                Error::h2_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("failed to send H2 request: {e}"),
                )
            })?;

        if let Some(ref body_data) = self.body {
            send_stream
                .send_data(body_data.clone(), true)
                .map_err(|e| {
                    Error::h2_or_connection_closed(
                        ConnectionPhase::HttpRequest,
                        format!("failed to send request body: {e}"),
                    )
                })?;
        }

        let ttfb_started = std::time::Instant::now();
        let resp = resp_future.await_response().await.map_err(|e| {
            Error::h2_or_connection_closed(
                ConnectionPhase::HttpRequest,
                format!("failed to receive H2 response: {e}"),
            )
        })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h2");

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let limits = client.resource_limits();
        limits.check_response_headers(&resp_headers)?;
        let body_stream = BodyStream::H2(resp.into_body());

        pipeline::store_cookies(&self.session, &resp_headers, &target.parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            target.scheme,
            &target.host,
            target.port,
        );

        Ok(StreamingResponse::new(status, resp_headers, body_stream)
            .with_max_body_size(limits.max_response_body_size)
            .with_no_decompress(self.no_decompress))
    }

    #[cfg(feature = "quic-h3")]
    async fn send_h3_streaming(
        &self,
        sender: &mut lkh3::H3Sender,
        target: &pipeline::ParsedTarget,
    ) -> Result<StreamingResponse> {
        let client = &self.session.inner.client;
        let uri = pipeline::build_h2_uri(target.scheme, &target.host, target.port, &target.path);

        let mut request = http::Request::builder()
            .method(self.method.clone())
            .uri(&uri)
            .body(self.body.clone())
            .map_err(|e| Error::Http3Request(format!("failed to build HTTP/3 request: {e}")))?;

        let effective_priority = pipeline::resolve_request_priority(
            self.priority,
            &self.headers,
            client.default_headers(),
        );
        let rp = effective_priority.unwrap_or_else(lkh2::RequestPriority::fetch);

        if !self.headers.contains_key("priority")
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

        pipeline::auto_insert_content_length(request.headers_mut(), self.body.as_ref());
        pipeline::merge_headers(
            request.headers_mut(),
            client,
            &self.headers,
            &target.parsed_url,
            false,
            &self.session,
            &self.extra_cookies,
            &self.cookie_overrides,
            header_order,
            cookie_order,
        );

        let ttfb_started = std::time::Instant::now();
        let response = sender.send_request(request).await.map_err(|e| {
            Error::http3_or_connection_closed(ConnectionPhase::HttpRequest, e.to_string())
        })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h3");

        let (parts, body) = response.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = client.resource_limits();
        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, &target.parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            target.scheme,
            &target.host,
            target.port,
        );

        Ok(
            StreamingResponse::new(status, resp_headers, BodyStream::H3(Box::new(body)))
                .with_max_body_size(limits.max_response_body_size)
                .with_no_decompress(self.no_decompress),
        )
    }

    /// Establish a new connection and send a streaming request.
    ///
    /// Heap-allocated future to avoid stack overflow.
    fn establish_and_send_streaming<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
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
            let effective_proxy = self.effective_proxy().cloned();
            pipeline::log_protocol_policy(
                &target.conn_key.route,
                &target.host,
                target.port,
                &effective_policy,
                http_version_pref,
            );
            let quic_discovery = pipeline::discover_quic_support(
                &self.session,
                target.scheme,
                &target.host,
                target.port,
                effective_proxy.as_ref(),
                &effective_policy,
                http_version_pref,
            )
            .await;
            pipeline::log_quic_discovery(&quic_discovery);
            let decision =
                pipeline::decide_protocol(http_version_pref, &effective_policy, &quic_discovery);
            pipeline::log_protocol_decision(&quic_discovery, &effective_policy, decision);
            match decision {
                pipeline::ProtocolDecision::Tcp => {
                    let result = self
                        .establish_and_send_streaming_tcp(
                            target,
                            effective_proxy.clone(),
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await;
                    let schedule_probe = result.is_ok()
                        && pipeline::should_background_probe(&effective_policy, &quic_discovery);
                    pipeline::log_background_probe_decision(
                        &target.conn_key.route,
                        &target.host,
                        target.port,
                        &effective_policy,
                        &quic_discovery,
                        schedule_probe,
                    );
                    if schedule_probe {
                        self.session.spawn_background_quic_probe(
                            target.host.clone(),
                            target.port,
                            target.conn_key.clone(),
                            quic_discovery.clone(),
                            effective_proxy.clone(),
                        );
                    }
                    result
                }
                #[cfg(feature = "quic-h3")]
                pipeline::ProtocolDecision::Race => {
                    self.establish_and_send_streaming_race(
                        target,
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
                    self.establish_and_send_streaming_tcp(
                        target,
                        effective_proxy,
                        &effective_policy,
                        http_version_pref,
                        connect_start,
                    )
                    .await
                }
                #[cfg(feature = "quic-h3")]
                pipeline::ProtocolDecision::Quic => {
                    self.establish_and_send_streaming_quic(
                        target,
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
        })
    }

    fn effective_proxy(&self) -> Option<&ProxyConfig> {
        pipeline::effective_proxy(self.proxy_override.as_ref(), &self.session)
    }

    fn effective_protocol_policy(&self) -> ProtocolPolicy {
        pipeline::effective_protocol_policy(self.protocol_policy_override.as_ref(), &self.session)
    }

    fn effective_http_version(&self, protocol_policy: &ProtocolPolicy) -> PreferredHttpVersion {
        pipeline::effective_http_version(self.version_override, protocol_policy, &self.session)
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_streaming_race<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            let race_cfg = pipeline::protocol_policy_chrome_like_config(
                protocol_policy,
                self.session.chrome_like_protocol_config(),
            );
            let mut quic_future = self.establish_and_send_streaming_quic(
                target,
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
                                    target.host.clone(),
                                    target.port,
                                    target.scheme,
                                    target.conn_key.clone(),
                                    effective_proxy_owned.clone(),
                                    http_version_pref,
                                );
                            }
                            return Ok(resp);
                        }
                        Err(quic_error) => {
                            tracing::warn!(
                                host = %target.host,
                                error = %quic_error,
                                fallback = "quic_to_tcp",
                                "streaming.protocol_race_quic_failed_before_tcp_release",
                            );
                            return match self.establish_and_send_streaming_tcp(
                                target,
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

            let mut tcp_future = self.establish_and_send_streaming_tcp(
                target,
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
                                target.host.clone(),
                                target.port,
                                target.scheme,
                                target.conn_key.clone(),
                                effective_proxy_owned.clone(),
                                http_version_pref,
                            );
                        }
                        Ok(resp)
                    }
                    Err(quic_error) => {
                        tracing::warn!(
                            host = %target.host,
                            error = %quic_error,
                            fallback = "quic_to_tcp",
                            "streaming.protocol_race_quic_failed_waiting_for_tcp",
                        );
                        match tcp_future.await {
                            Ok(resp) => Ok(resp),
                            Err(tcp_error) => Err(pipeline::protocol_race_error(tcp_error, quic_error)),
                        }
                    }
                },
                tcp_result = &mut tcp_future => match tcp_result {
                    Ok(resp) => {
                        if race_cfg.keep_quic_probe_after_tcp_win {
                            self.session.spawn_background_quic_probe(
                                target.host.clone(),
                                target.port,
                                target.conn_key.clone(),
                                discovery.clone(),
                                effective_proxy_owned.clone(),
                            );
                        }
                        Ok(resp)
                    }
                    Err(tcp_error) => {
                        tracing::warn!(
                            host = %target.host,
                            error = %tcp_error,
                            fallback = "tcp_to_quic",
                            "streaming.protocol_race_tcp_failed_waiting_for_quic",
                        );
                        match quic_future.await {
                            Ok(resp) => Ok(resp),
                            Err(quic_error) => Err(pipeline::protocol_race_error(tcp_error, quic_error)),
                        }
                    }
                },
            }
        })
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_streaming_quic<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            let h3_conn = match self
                .session
                .establish_h3_connection(
                    &target.host,
                    target.port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy,
                )
                .await
            {
                Ok(h3_conn) => h3_conn,
                Err(error) => {
                    self.session
                        .broken_quic_tracker()
                        .mark_broken_for_route(&discovery.route, &discovery.origin);
                    self.session
                        .alt_svc_cache()
                        .clear_h3_validation_for_route(&discovery.route, &discovery.origin);

                    let fallback_allowed = pipeline::fallback_permitted(protocol_policy, &error);
                    if fallback_allowed {
                        tracing::warn!(
                            route = %discovery.route,
                            host = %target.host,
                            port = target.port,
                            fallback_policy = ?protocol_policy.fallback,
                            error = %error,
                            "quic.handshake_failed_fallback_tcp",
                        );
                        return self
                            .establish_and_send_streaming_tcp(
                                target,
                                effective_proxy_owned,
                                protocol_policy,
                                http_version_pref,
                                connect_start,
                            )
                            .await;
                    }
                    tracing::warn!(
                        route = %discovery.route,
                        host = %target.host,
                        port = target.port,
                        fallback_policy = ?protocol_policy.fallback,
                        error = %error,
                        "quic.handshake_failed_no_fallback",
                    );
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
            let driver = std::sync::Arc::new(driver);
            let mut send_sender = sender.clone();
            {
                let mut pool = self.session.inner.pool.lock();
                pool.insert_h3(target.conn_key.clone(), sender, driver);
            }

            tracing::debug!(
                route = %target.conn_key.route,
                path = "new_h3",
                protocol = "h3",
                duration_ms = connect_start.elapsed().as_millis() as u64,
                "connection.established",
            );

            self.send_h3_streaming(&mut send_sender, target).await
        })
    }

    fn establish_and_send_streaming_tcp<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        effective_proxy: Option<ProxyConfig>,
        _protocol_policy: &'a ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            let client = &self.session.inner.client;
            let connect_config =
                pipeline::build_connect_config(client, http_version_pref, target.scheme);
            let conn = self
                .session
                .establish_connection(
                    &target.host,
                    target.port,
                    effective_proxy.as_ref(),
                    &connect_config,
                )
                .await?;

            let use_h2 = pipeline::should_use_h2(conn.negotiated_alpn(), http_version_pref)?;

            if use_h2 {
                let h2_result: Result<StreamingResponse> = async {
                    let sender = pipeline::establish_h2_and_pool(
                        conn.into_tcp_stream()?,
                        client,
                        &self.session,
                        &target.conn_key,
                    )
                    .await?;

                    tracing::debug!(
                        route = %target.conn_key.route,
                        path = "new_h2",
                        protocol = "h2",
                        duration_ms = connect_start.elapsed().as_millis() as u64,
                        "connection.established",
                    );

                    self.send_h2_streaming(sender, target).await
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
                            "streaming.h2_failed_falling_back_to_h1",
                        );

                        let h1_config =
                            pipeline::build_h1_only_connect_config(client, target.scheme);
                        let conn2 = self
                            .session
                            .establish_connection(
                                &target.host,
                                target.port,
                                effective_proxy.as_ref(),
                                &h1_config,
                            )
                            .await?;

                        let (sender, conn_task) =
                            pipeline::handshake_h1(conn2.into_tcp_stream()?).await?;

                        tracing::debug!(
                            route = %target.conn_key.route,
                            path = "fallback_h1",
                            protocol = "h1.1",
                            fallback = true,
                            "connection.established_via_fallback",
                        );

                        self.send_h1_streaming(sender, conn_task, target).await
                    }
                    Err(e) => Err(e),
                }
            } else {
                let negotiated_alpn = conn.negotiated_alpn();
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
                    route = %target.conn_key.route,
                    path = "new_h1",
                    protocol = "h1.1",
                    duration_ms = connect_start.elapsed().as_millis() as u64,
                    "connection.established",
                );

                self.send_h1_streaming(sender, conn_task, target).await
            }
        })
    }

    async fn send_h1_streaming(
        &self,
        mut sender: hyper::client::conn::http1::SendRequest<Full<bytes::Bytes>>,
        conn_task: Arc<tokio::task::JoinHandle<()>>,
        target: &pipeline::ParsedTarget,
    ) -> Result<StreamingResponse> {
        let client = &self.session.inner.client;
        let request = self.build_h1_request_obj(target)?;
        let ttfb_started = std::time::Instant::now();
        let resp = sender.send_request(request).await.map_err(|e| {
            Error::http_or_connection_closed(
                ConnectionPhase::HttpRequest,
                format!("HTTP/1.1 request failed: {e}"),
            )
        })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("http/1.1");

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let limits = client.resource_limits();
        limits.check_response_headers(&resp_headers)?;
        let mut incoming = resp.into_body();

        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            use http_body_util::BodyExt;

            let _conn_task = conn_task;
            while let Some(frame) = incoming.frame().await {
                match frame {
                    Ok(f) => {
                        if let Some(data) = f.data_ref() {
                            if tx.send(Ok(data.clone())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(format!("error reading H1 body stream: {e}")))
                            .await;
                        break;
                    }
                }
            }
        });

        let body_stream = BodyStream::H1(rx);
        pipeline::store_cookies(&self.session, &resp_headers, &target.parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            target.scheme,
            &target.host,
            target.port,
        );

        Ok(StreamingResponse::new(status, resp_headers, body_stream)
            .with_max_body_size(limits.max_response_body_size)
            .with_no_decompress(self.no_decompress))
    }

    fn build_h1_request_obj(
        &self,
        target: &pipeline::ParsedTarget,
    ) -> Result<http::Request<Full<bytes::Bytes>>> {
        let client = &self.session.inner.client;

        let uri: http::Uri = target
            .path
            .parse()
            .map_err(|e| Error::Http(format!("invalid request path '{}': {e}", target.path)))?;

        let body_bytes = self.body.clone().unwrap_or_default();
        let full_body = Full::new(body_bytes);

        let mut request = http::Request::builder()
            .method(self.method.clone())
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

        pipeline::merge_headers(
            request.headers_mut(),
            client,
            &self.headers,
            &target.parsed_url,
            true,
            &self.session,
            &self.extra_cookies,
            &self.cookie_overrides,
            header_order,
            cookie_order,
        );

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use url::Url;

    fn test_session() -> Session {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .default_header("user-agent", "TestBot/1.0")
            .build();
        client.session().build()
    }

    // ====================================================================
    // store_cookies (pipeline) — server Set-Cookie handling
    // ====================================================================

    #[test]
    fn stores_single_set_cookie_header() {
        let session = test_session();
        let url = Url::parse("https://shop.example.com/cart").unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::SET_COOKIE,
            "cart_id=abc123; Path=/".parse().unwrap(),
        );

        pipeline::store_cookies(&session, &headers, &url);

        assert_eq!(
            session.get_cookie("https://shop.example.com/cart", "cart_id"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn stores_multiple_set_cookie_headers() {
        let session = test_session();
        let url = Url::parse("https://example.com/login").unwrap();

        let mut headers = HeaderMap::new();
        headers.append(
            http::header::SET_COOKIE,
            "session=xyz; Path=/; HttpOnly".parse().unwrap(),
        );
        headers.append(
            http::header::SET_COOKIE,
            "theme=dark; Path=/".parse().unwrap(),
        );

        pipeline::store_cookies(&session, &headers, &url);

        assert_eq!(
            session.get_cookie("https://example.com/", "session"),
            Some("xyz".to_string())
        );
        assert_eq!(
            session.get_cookie("https://example.com/", "theme"),
            Some("dark".to_string())
        );
    }

    #[test]
    fn no_set_cookie_headers_is_noop() {
        let session = test_session();
        let url = Url::parse("https://example.com").unwrap();
        let headers = HeaderMap::new();

        pipeline::store_cookies(&session, &headers, &url);
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    // ====================================================================
    // merge_headers (pipeline) — header assembly for requests
    // ====================================================================

    #[test]
    fn default_headers_applied() {
        let session = test_session();
        let url = Url::parse("https://example.com/api").unwrap();
        let client = session.client();

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            false,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        assert!(target.contains_key("user-agent"));
    }

    #[test]
    fn request_headers_override_defaults() {
        let session = test_session();
        let url = Url::parse("https://example.com").unwrap();
        let client = session.client();

        let mut extra = HeaderMap::new();
        extra.insert("user-agent", "CustomBot/2.0".parse().unwrap());

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &extra,
            &url,
            false,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        assert_eq!(target.get("user-agent").unwrap(), "CustomBot/2.0");
    }

    #[test]
    fn cookies_from_jar_merged_into_request() {
        let session = test_session();
        session.set_cookie("https://example.com", "sid", "abc");
        let url = Url::parse("https://example.com/page").unwrap();
        let client = session.client();

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            true,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        let cookie_hdr = target.get(http::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_hdr.contains("sid=abc"));
    }

    #[test]
    fn extra_cookies_appended() {
        let session = test_session();
        let url = Url::parse("https://example.com").unwrap();
        let client = session.client();

        let extra_cookies = vec![("tracking".to_string(), "xyz".to_string())];

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            true,
            &session,
            &extra_cookies,
            &[],
            &[],
            None,
        );

        let cookie_hdr = target.get(http::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_hdr.contains("tracking=xyz"));
    }

    #[test]
    fn cookie_overrides_remove_jar_cookies() {
        let session = test_session();
        session.set_cookie("https://example.com", "token", "old_val");
        let url = Url::parse("https://example.com").unwrap();
        let client = session.client();

        let extra_cookies = vec![("token".to_string(), "new_val".to_string())];
        let overrides = vec!["token".to_string()];

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            true,
            &session,
            &extra_cookies,
            &overrides,
            &[],
            None,
        );

        let cookie_hdr = target.get(http::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_hdr.contains("new_val"));
        assert!(!cookie_hdr.contains("old_val"));
    }

    #[test]
    fn h2_skips_host_header_from_defaults() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .default_header("host", "should-be-skipped.com")
            .default_header("accept", "text/html")
            .build();
        let session = client.session().build();
        let url = Url::parse("https://example.com").unwrap();

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        assert!(!target.contains_key("host"));
        assert!(target.contains_key("accept"));
    }
}
