//! gRPC Inspector agent implementation.

use crate::client_ip::{default_forwarding_headers, resolve_client_ip, TrustedProxies};
use crate::config::{Config, FailAction, RateLimitKeyType};
use crate::grpc::{is_grpc_content_type, parse_message_size, GrpcPath, GrpcStatus};
use crate::matchers::CompiledConfig;
use crate::rate_limiter::{RateLimitKey, RateLimitResult, RateLimiter};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthStatus,
    MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestHeadersEvent, ResponseHeadersEvent,
};

/// gRPC Inspector agent.
pub struct GrpcInspectorAgent {
    config: Arc<Config>,
    compiled: Arc<CompiledConfig>,
    rate_limiter: Arc<RateLimiter>,
    /// Proxies whose forwarding headers are believed
    trusted_proxies: TrustedProxies,
    /// Forwarding headers read behind a trusted proxy
    forwarding_headers: Vec<String>,
    /// Counters for metrics
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    requests_allowed: AtomicU64,
}

impl GrpcInspectorAgent {
    /// Create a new gRPC Inspector agent.
    pub fn new(config: Config) -> Self {
        let compiled = CompiledConfig::new(
            &config.authorization,
            &config.size_limits,
            &config.metadata,
            &config.rate_limiting,
            &config.reflection,
        );

        info!(
            authorization = config.authorization.enabled,
            size_limits = config.size_limits.enabled,
            metadata = config.metadata.enabled,
            rate_limiting = config.rate_limiting.enabled,
            reflection = config.reflection.enabled,
            "gRPC Inspector agent initialized"
        );

        // Config::validate rejects bad entries; if it was skipped, believe no
        // forwarding headers rather than fail.
        let trusted_proxies = TrustedProxies::parse(&config.settings.trusted_proxies)
            .unwrap_or_else(|e| {
                warn!(error = %e, "Ignoring settings.trusted_proxies");
                TrustedProxies::default()
            });

        Self {
            config: Arc::new(config),
            compiled: Arc::new(compiled),
            rate_limiter: Arc::new(RateLimiter::new()),
            trusted_proxies,
            forwarding_headers: default_forwarding_headers(),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
        }
    }

    /// Flatten multi-value headers to single values.
    fn flatten_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.first().cloned().unwrap_or_default()))
            .collect()
    }

    /// Client IP: the connection address from the event metadata, or behind
    /// a trusted proxy the right-most untrusted forwarding hop. `None` when
    /// there is no usable address.
    fn client_ip(&self, event: &RequestHeadersEvent) -> Option<IpAddr> {
        resolve_client_ip(
            &event.metadata.client_ip,
            &event.headers,
            &self.forwarding_headers,
            &self.trusted_proxies,
        )
    }

    /// Block with gRPC status.
    fn block_grpc(&self, status: GrpcStatus, message: &str, tag: &str) -> AgentResponse {
        self.requests_blocked.fetch_add(1, Ordering::Relaxed);

        if self.config.settings.log_blocked {
            warn!(
                grpc_status = status.name(),
                message = message,
                tag = tag,
                "gRPC request blocked"
            );
        }

        let audit = AuditMetadata {
            tags: vec![tag.to_string()],
            reason_codes: vec![message.to_string()],
            ..Default::default()
        };

        AgentResponse::block(status.http_status(), None)
            .add_response_header(HeaderOp::Set {
                name: "grpc-status".to_string(),
                value: status.as_str().to_string(),
            })
            .add_response_header(HeaderOp::Set {
                name: "grpc-message".to_string(),
                value: message.to_string(),
            })
            .add_response_header(HeaderOp::Set {
                name: "content-type".to_string(),
                value: "application/grpc".to_string(),
            })
            .with_audit(audit)
    }

    /// Check authorization rules.
    fn check_authorization(
        &self,
        path: &GrpcPath,
        headers: &HashMap<String, String>,
    ) -> Option<AgentResponse> {
        if !self.compiled.authorization.enabled {
            return None;
        }

        if let Some(rule) = self.compiled.authorization.find_matching_rule(path) {
            // Check metadata requirements
            for req in &rule.metadata_requirements {
                if !req.satisfied_by(headers) {
                    return Some(self.block_grpc(
                        GrpcStatus::Unauthenticated,
                        &format!("Missing required metadata: {}", req.name),
                        "grpc-inspector:missing-metadata",
                    ));
                }
            }

            // Check role requirements
            if let Some(role_config) = &rule.role_config {
                let user_roles: Vec<&str> = headers
                    .get(&role_config.roles_header.to_lowercase())
                    .map(|v| v.split(',').map(|s| s.trim()).collect())
                    .unwrap_or_default();

                let has_required_role = role_config
                    .required_roles
                    .iter()
                    .any(|r| user_roles.contains(&r.as_str()));

                if !has_required_role {
                    return Some(self.block_grpc(
                        GrpcStatus::PermissionDenied,
                        "Insufficient roles",
                        "grpc-inspector:insufficient-roles",
                    ));
                }
            }

            // Apply rule action
            match rule.action {
                crate::config::Action::Allow => {
                    debug!(service = %path.full_service, method = %path.method, "Authorization allowed");
                    None
                }
                crate::config::Action::Deny => Some(self.block_grpc(
                    GrpcStatus::PermissionDenied,
                    "Method not allowed",
                    "grpc-inspector:method-denied",
                )),
            }
        } else {
            // No rule matched, apply default
            match self.compiled.authorization.default_action {
                crate::config::Action::Allow => None,
                crate::config::Action::Deny => Some(self.block_grpc(
                    GrpcStatus::PermissionDenied,
                    "No matching authorization rule",
                    "grpc-inspector:no-rule-match",
                )),
            }
        }
    }

    /// Check reflection control.
    fn check_reflection(
        &self,
        path: &GrpcPath,
        headers: &HashMap<String, String>,
        client_ip: Option<IpAddr>,
    ) -> Option<AgentResponse> {
        if !self.compiled.reflection.enabled || !path.is_reflection() {
            return None;
        }

        // If reflection is allowed globally, allow
        if self.compiled.reflection.allow {
            debug!("Reflection allowed globally");
            return None;
        }

        // Check if client IP is in allowlist (no usable IP matches nothing)
        let client_ip = client_ip.map(|ip| ip.to_string());
        if self
            .compiled
            .reflection
            .is_client_allowed(client_ip.as_deref())
        {
            debug!(client_ip = ?client_ip, "Reflection allowed for client IP");
            return None;
        }

        // Check if metadata allows reflection
        if let Some(meta) = &self.compiled.reflection.allowed_metadata {
            if meta.matches(headers) {
                debug!("Reflection allowed via metadata");
                return None;
            }
        }

        // Block reflection
        Some(self.block_grpc(
            GrpcStatus::PermissionDenied,
            "Reflection API is disabled",
            "grpc-inspector:reflection-blocked",
        ))
    }

    /// Check metadata requirements.
    fn check_metadata(
        &self,
        path: &GrpcPath,
        headers: &HashMap<String, String>,
    ) -> Option<AgentResponse> {
        if !self.compiled.metadata.enabled {
            return None;
        }

        // Check required headers
        for req in &self.compiled.metadata.required {
            if req.applies_to(path) && !headers.contains_key(&req.name) {
                return Some(self.block_grpc(
                    GrpcStatus::InvalidArgument,
                    &format!("Missing required header: {}", req.name),
                    "grpc-inspector:missing-required-header",
                ));
            }
        }

        // Check forbidden headers
        for forb in &self.compiled.metadata.forbidden {
            if forb.applies_to(path) {
                for header_name in headers.keys() {
                    if forb.matches_header(header_name) {
                        return Some(self.block_grpc(
                            GrpcStatus::InvalidArgument,
                            &format!("Forbidden header present: {}", header_name),
                            "grpc-inspector:forbidden-header",
                        ));
                    }
                }
            }
        }

        // Check header validations
        for val in &self.compiled.metadata.validation {
            if let Some(value) = headers.get(&val.name) {
                if let Some(error) = val.validate(value) {
                    return Some(self.block_grpc(
                        GrpcStatus::InvalidArgument,
                        &error,
                        "grpc-inspector:header-validation-failed",
                    ));
                }
            }
        }

        None
    }

    /// Check rate limits.
    async fn check_rate_limit(
        &self,
        path: &GrpcPath,
        headers: &HashMap<String, String>,
        client_ip: Option<IpAddr>,
    ) -> Option<AgentResponse> {
        if !self.compiled.rate_limiting.enabled {
            return None;
        }

        // Find rate limit config for this method
        let (limit, window_seconds, burst, key_type, key_metadata_name) =
            if let Some(method_limit) = self.compiled.rate_limiting.find_limit(path) {
                (
                    method_limit.limit,
                    method_limit.window_seconds,
                    method_limit.burst,
                    method_limit
                        .key_type
                        .unwrap_or(self.compiled.rate_limiting.default_key_type),
                    method_limit.key_metadata_name.as_ref().or(self
                        .compiled
                        .rate_limiting
                        .default_key_metadata_name
                        .as_ref()),
                )
            } else {
                (
                    self.compiled.rate_limiting.default_limit,
                    self.compiled.rate_limiting.default_window_seconds,
                    0,
                    self.compiled.rate_limiting.default_key_type,
                    self.compiled
                        .rate_limiting
                        .default_key_metadata_name
                        .as_ref(),
                )
            };

        // Build rate limit key. Requests without a usable client IP share
        // one bucket, so they are limited together, never exempted.
        let ip_key = client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let client_key = match key_type {
            RateLimitKeyType::ClientIp => ip_key,
            RateLimitKeyType::Metadata => {
                let header_name = key_metadata_name
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                headers
                    .get(&header_name)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
            }
            RateLimitKeyType::Composite => {
                format!("{}:{}", path.full_path, ip_key)
            }
        };

        let key = RateLimitKey::new(&path.full_service, &path.method, &client_key);

        match self
            .rate_limiter
            .check(key, limit, window_seconds, burst)
            .await
        {
            RateLimitResult::Allowed { remaining } => {
                debug!(
                    service = %path.full_service,
                    method = %path.method,
                    remaining = remaining,
                    "Rate limit check passed"
                );
                None
            }
            RateLimitResult::Exceeded { retry_after_secs } => {
                let response = self
                    .block_grpc(
                        GrpcStatus::ResourceExhausted,
                        "Rate limit exceeded",
                        "grpc-inspector:rate-limited",
                    )
                    .add_response_header(HeaderOp::Set {
                        name: "retry-after".to_string(),
                        value: retry_after_secs.to_string(),
                    });
                Some(response)
            }
        }
    }

    /// Check request size limits.
    /// Note: Currently unused - v2 protocol doesn't pass body in request headers event.
    /// Retained for future streaming body support.
    #[allow(dead_code)]
    fn check_request_size(&self, path: &GrpcPath, body: Option<&[u8]>) -> Option<AgentResponse> {
        if !self.compiled.size_limits.enabled {
            return None;
        }

        let max_size = self.compiled.size_limits.get_max_request_bytes(path);
        if max_size == 0 {
            return None; // Unlimited
        }

        // Try to parse message size from gRPC frame header
        if let Some(body) = body {
            if let Some(msg_size) = parse_message_size(body) {
                if msg_size as u64 > max_size {
                    return Some(self.block_grpc(
                        GrpcStatus::ResourceExhausted,
                        &format!(
                            "Request message size {} exceeds limit {}",
                            msg_size, max_size
                        ),
                        "grpc-inspector:request-too-large",
                    ));
                }
            }
        }

        None
    }

    /// Check response size limits.
    /// Note: Currently unused - v2 protocol doesn't pass body in response headers event.
    /// Retained for future streaming body support.
    #[allow(dead_code)]
    fn check_response_size(&self, path: &GrpcPath, body: Option<&[u8]>) -> Option<AgentResponse> {
        if !self.compiled.size_limits.enabled {
            return None;
        }

        let max_size = self.compiled.size_limits.get_max_response_bytes(path);
        if max_size == 0 {
            return None; // Unlimited
        }

        // Try to parse message size from gRPC frame header
        if let Some(body) = body {
            if let Some(msg_size) = parse_message_size(body) {
                if msg_size as u64 > max_size {
                    warn!(
                        service = %path.full_service,
                        method = %path.method,
                        size = msg_size,
                        limit = max_size,
                        "Response message size exceeds limit"
                    );
                    return Some(self.block_grpc(
                        GrpcStatus::ResourceExhausted,
                        &format!(
                            "Response message size {} exceeds limit {}",
                            msg_size, max_size
                        ),
                        "grpc-inspector:response-too-large",
                    ));
                }
            }
        }

        None
    }

    /// Allow with optional debug headers.
    fn allow_with_debug(&self, path: &GrpcPath) -> AgentResponse {
        self.requests_allowed.fetch_add(1, Ordering::Relaxed);

        if self.config.settings.log_allowed {
            debug!(
                service = %path.full_service,
                method = %path.method,
                "gRPC request allowed"
            );
        }

        let audit = AuditMetadata {
            tags: vec!["grpc-inspector:allowed".to_string()],
            ..Default::default()
        };

        let mut response = AgentResponse::default_allow().with_audit(audit);

        if self.config.settings.debug_headers {
            response = response
                .add_request_header(HeaderOp::Set {
                    name: "x-grpc-inspector-service".to_string(),
                    value: path.full_service.clone(),
                })
                .add_request_header(HeaderOp::Set {
                    name: "x-grpc-inspector-method".to_string(),
                    value: path.method.clone(),
                });
        }

        response
    }

    /// Handle non-gRPC requests based on fail action.
    fn handle_non_grpc(&self) -> AgentResponse {
        match self.config.settings.fail_action {
            FailAction::Block => AgentResponse::default_allow(), // Pass through non-gRPC
            FailAction::Allow => AgentResponse::default_allow(),
        }
    }
}

#[async_trait]
impl AgentHandlerV2 for GrpcInspectorAgent {
    /// Get agent capabilities for v2 protocol negotiation.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "grpc-inspector",
            "gRPC Inspector Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::ResponseHeaders)
        .with_features(AgentFeatures {
            streaming_body: false,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
        .with_limits(AgentLimits {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_concurrency: 100,
            preferred_chunk_size: 64 * 1024,
            max_memory: None,
            max_processing_time_ms: Some(5000),
        })
    }

    /// Handle request headers event.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Get content-type header
        let headers = Self::flatten_headers(&event.headers);
        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Check if this is a gRPC request
        if !is_grpc_content_type(content_type) {
            return self.handle_non_grpc();
        }

        // Parse gRPC path
        let path = match GrpcPath::parse(&event.uri) {
            Some(p) => p,
            None => {
                return self.block_grpc(
                    GrpcStatus::InvalidArgument,
                    "Invalid gRPC path format",
                    "grpc-inspector:invalid-path",
                );
            }
        };

        // Skip health checks by default (they should always pass)
        if path.is_health_check() {
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            let audit = AuditMetadata {
                tags: vec!["grpc-inspector:health-check".to_string()],
                ..Default::default()
            };
            return AgentResponse::default_allow().with_audit(audit);
        }

        let client_ip = self.client_ip(&event);

        // Check reflection control (early exit)
        if let Some(response) = self.check_reflection(&path, &headers, client_ip) {
            return response;
        }

        // Check authorization
        if let Some(response) = self.check_authorization(&path, &headers) {
            return response;
        }

        // Check metadata
        if let Some(response) = self.check_metadata(&path, &headers) {
            return response;
        }

        // Check rate limits
        if let Some(response) = self.check_rate_limit(&path, &headers, client_ip).await {
            return response;
        }

        // All checks passed
        self.allow_with_debug(&path)
    }

    /// Handle response headers event.
    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        // Only check response size if size limits are enabled
        // Note: Response size checking is limited without body access in v2
        // For now, just allow all responses
        AgentResponse::default_allow()
    }

    /// Get current health status.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("grpc-inspector")
    }

    /// Get current metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::CounterMetric;

        let mut report = MetricsReport::new("grpc-inspector", 10_000);
        report.counters.push(CounterMetric::new(
            "grpc_inspector_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "grpc_inspector_requests_blocked",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "grpc_inspector_requests_allowed",
            self.requests_allowed.load(Ordering::Relaxed),
        ));

        Some(report)
    }

    /// Handle configuration update from proxy.
    async fn on_configure(&self, _config: serde_json::Value, version: Option<String>) -> bool {
        info!(
            config_version = ?version,
            "Received configuration update"
        );
        // For now, we don't support dynamic config updates
        // Return true to acknowledge receipt
        true
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Clean up resources if needed
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            reason = ?reason,
            duration_ms = duration_ms,
            "Received drain request"
        );
        // Stop accepting new requests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_auth() -> Config {
        let yaml = r#"
authorization:
  enabled: true
  default_action: deny
  rules:
    - service: "test.PublicService"
      methods: ["*"]
      action: allow
    - service: "test.AdminService"
      methods: ["*"]
      action: deny
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn test_flatten_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/grpc".to_string()],
        );
        headers.insert(
            "X-Request-Id".to_string(),
            vec!["123".to_string(), "456".to_string()],
        );

        let flat = GrpcInspectorAgent::flatten_headers(&headers);
        assert_eq!(
            flat.get("content-type"),
            Some(&"application/grpc".to_string())
        );
        assert_eq!(flat.get("x-request-id"), Some(&"123".to_string())); // First value only
    }

    fn grpc_event(client_ip: &str, uri: &str, headers: &[(&str, &str)]) -> RequestHeadersEvent {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert(
            "content-type".to_string(),
            vec!["application/grpc".to_string()],
        );
        for (k, v) in headers {
            map.entry(k.to_string()).or_default().push(v.to_string());
        }
        RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test".to_string(),
                request_id: "test".to_string(),
                client_ip: client_ip.to_string(),
                client_port: 40000,
                server_name: None,
                protocol: "HTTP/2".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2026-10-22T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "POST".to_string(),
            uri: uri.to_string(),
            headers: map,
        }
    }

    fn reflection_agent(trusted: &str) -> GrpcInspectorAgent {
        let yaml = format!(
            "settings:\n  trusted_proxies: [{}]\nreflection:\n  enabled: true\n  allow: false\n  allowed_clients:\n    - \"127.0.0.1\"\n",
            trusted
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        GrpcInspectorAgent::new(config)
    }

    const REFLECTION: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";

    async fn blocked(agent: &GrpcInspectorAgent, event: RequestHeadersEvent) -> bool {
        let response = agent.on_request_headers(event).await;
        matches!(
            response.decision,
            zentinel_agent_protocol::Decision::Block { .. }
        )
    }

    #[tokio::test]
    async fn test_spoofed_forwarding_headers_ignored() {
        let agent = reflection_agent("");
        // A remote client claiming to be localhost does not get reflection.
        for header in ["x-forwarded-for", "x-real-ip"] {
            let event = grpc_event("203.0.113.9", REFLECTION, &[(header, "127.0.0.1")]);
            assert!(blocked(&agent, event).await, "{} was believed", header);
        }
        // The real localhost connection does.
        let event = grpc_event(
            "127.0.0.1",
            REFLECTION,
            &[("x-forwarded-for", "203.0.113.9")],
        );
        assert!(!blocked(&agent, event).await);
    }

    #[tokio::test]
    async fn test_trusted_proxy_uses_right_most_untrusted_hop() {
        let agent = reflection_agent("\"10.0.0.0/8\"");
        // Behind the trusted proxy 10.0.0.1, the hop it saw is the client.
        let event = grpc_event(
            "10.0.0.1",
            REFLECTION,
            &[("x-forwarded-for", "203.0.113.9, 127.0.0.1")],
        );
        assert!(!blocked(&agent, event).await);
        // A spoofed left-most "127.0.0.1" does not count.
        let event = grpc_event(
            "10.0.0.1",
            REFLECTION,
            &[("x-forwarded-for", "127.0.0.1, 203.0.113.9")],
        );
        assert!(blocked(&agent, event).await);
    }

    #[tokio::test]
    async fn test_no_usable_ip_not_allowed() {
        let agent = reflection_agent("\"0.0.0.0/0\"");
        let event = grpc_event("", REFLECTION, &[("x-forwarded-for", "127.0.0.1")]);
        assert!(blocked(&agent, event).await);
    }

    #[tokio::test]
    async fn test_rate_limit_key_ignores_spoofed_xff() {
        let yaml = r#"
rate_limiting:
  enabled: true
  per_method:
    - service: "test.LimitedService"
      method: "Call"
      limit: 2
      window_seconds: 60
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let agent = GrpcInspectorAgent::new(config);
        // Rotating X-Forwarded-For does not buy a fresh bucket.
        for (i, expect_block) in [false, false, true].iter().enumerate() {
            let xff = format!("198.51.100.{}", i);
            let event = grpc_event(
                "203.0.113.9",
                "/test.LimitedService/Call",
                &[("x-forwarded-for", xff.as_str())],
            );
            assert_eq!(blocked(&agent, event).await, *expect_block, "request {}", i);
        }
    }

    #[tokio::test]
    async fn test_authorization_check() {
        let config = config_with_auth();
        let agent = GrpcInspectorAgent::new(config);

        let headers = HashMap::new();

        // Public service should be allowed
        let path = GrpcPath::parse("/test.PublicService/GetStatus").unwrap();
        let decision = agent.check_authorization(&path, &headers);
        assert!(decision.is_none());

        // Admin service should be denied
        let path = GrpcPath::parse("/test.AdminService/DeleteAll").unwrap();
        let decision = agent.check_authorization(&path, &headers);
        assert!(decision.is_some());

        // Unknown service should be denied (default_action: deny)
        let path = GrpcPath::parse("/test.UnknownService/Method").unwrap();
        let decision = agent.check_authorization(&path, &headers);
        assert!(decision.is_some());
    }

    #[tokio::test]
    async fn test_rate_limit_check() {
        let yaml = r#"
rate_limiting:
  enabled: true
  per_method:
    - service: "test.LimitedService"
      method: "Call"
      limit: 2
      window_seconds: 60
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let agent = GrpcInspectorAgent::new(config);

        let headers = HashMap::new();
        let ip = Some("1.2.3.4".parse().unwrap());

        let path = GrpcPath::parse("/test.LimitedService/Call").unwrap();

        // First two requests should be allowed
        assert!(agent.check_rate_limit(&path, &headers, ip).await.is_none());
        assert!(agent.check_rate_limit(&path, &headers, ip).await.is_none());

        // Third request should be denied
        assert!(agent.check_rate_limit(&path, &headers, ip).await.is_some());
    }

    #[tokio::test]
    async fn test_reflection_check() {
        let yaml = r#"
reflection:
  enabled: true
  allow: false
  allowed_clients:
    - "127.0.0.1"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let agent = GrpcInspectorAgent::new(config);

        let path =
            GrpcPath::parse("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo").unwrap();

        let headers = HashMap::new();

        // Unknown client should be blocked
        let ip = Some("1.2.3.4".parse().unwrap());
        assert!(agent.check_reflection(&path, &headers, ip).is_some());

        // No usable client IP should be blocked
        assert!(agent.check_reflection(&path, &headers, None).is_some());

        // Localhost should be allowed
        let ip = Some("127.0.0.1".parse().unwrap());
        assert!(agent.check_reflection(&path, &headers, ip).is_none());
    }

    #[tokio::test]
    async fn test_size_limit_check() {
        let yaml = r#"
size_limits:
  enabled: true
  default_max_request_bytes: 100
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let agent = GrpcInspectorAgent::new(config);

        let path = GrpcPath::parse("/test.Service/Method").unwrap();

        // Small message should pass
        let body = vec![0x00, 0x00, 0x00, 0x00, 0x0A]; // 10 bytes
        assert!(agent.check_request_size(&path, Some(&body)).is_none());

        // Large message should fail
        let body = vec![0x00, 0x00, 0x00, 0x00, 0x80]; // 128 bytes
        assert!(agent.check_request_size(&path, Some(&body)).is_some());
    }

    #[tokio::test]
    async fn test_response_size_limit_check() {
        let yaml = r#"
size_limits:
  enabled: true
  default_max_response_bytes: 100
  per_method:
    - service: "test.FileService"
      method: "Download"
      max_response_bytes: 1000
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let agent = GrpcInspectorAgent::new(config);

        let path = GrpcPath::parse("/test.Service/Method").unwrap();

        // Small message should pass
        let body = vec![0x00, 0x00, 0x00, 0x00, 0x0A]; // 10 bytes
        assert!(agent.check_response_size(&path, Some(&body)).is_none());

        // Large message should fail
        let body = vec![0x00, 0x00, 0x00, 0x00, 0x80]; // 128 bytes
        assert!(agent.check_response_size(&path, Some(&body)).is_some());

        // FileService.Download has higher limit
        let file_path = GrpcPath::parse("/test.FileService/Download").unwrap();
        let body = vec![0x00, 0x00, 0x00, 0x00, 0x80]; // 128 bytes
        assert!(agent.check_response_size(&file_path, Some(&body)).is_none());
    }
}
