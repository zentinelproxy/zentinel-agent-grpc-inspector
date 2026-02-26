//! Compiled matchers for efficient runtime matching.

use crate::config::{
    Action, AuthorizationConfig, AuthorizationRule, ForbiddenHeader, HeaderValidation,
    MetadataConfig, MetadataRequirement, MethodRateLimit, RateLimitKeyType, RateLimitingConfig,
    ReflectionConfig, RequiredHeader, RequirementType, SizeLimitsConfig,
};
use crate::grpc::GrpcPath;
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;

/// Compiled configuration for efficient runtime matching.
pub struct CompiledConfig {
    pub authorization: CompiledAuthorization,
    pub size_limits: CompiledSizeLimits,
    pub metadata: CompiledMetadata,
    pub rate_limiting: CompiledRateLimiting,
    pub reflection: CompiledReflection,
}

impl CompiledConfig {
    pub fn new(
        auth: &AuthorizationConfig,
        size: &SizeLimitsConfig,
        meta: &MetadataConfig,
        rate: &RateLimitingConfig,
        refl: &ReflectionConfig,
    ) -> Self {
        Self {
            authorization: CompiledAuthorization::new(auth),
            size_limits: CompiledSizeLimits::new(size),
            metadata: CompiledMetadata::new(meta),
            rate_limiting: CompiledRateLimiting::new(rate),
            reflection: CompiledReflection::new(refl),
        }
    }
}

// ============================================================================
// Authorization Matchers
// ============================================================================

pub struct CompiledAuthorization {
    pub enabled: bool,
    pub default_action: Action,
    pub rules: Vec<CompiledAuthRule>,
}

impl CompiledAuthorization {
    fn new(config: &AuthorizationConfig) -> Self {
        Self {
            enabled: config.enabled,
            default_action: config.default_action,
            rules: config.rules.iter().map(CompiledAuthRule::new).collect(),
        }
    }

    /// Find the first matching rule for a gRPC path.
    pub fn find_matching_rule(&self, path: &GrpcPath) -> Option<&CompiledAuthRule> {
        self.rules.iter().find(|rule| rule.matches(path))
    }
}

pub struct CompiledAuthRule {
    service_matcher: ServiceMatcher,
    method_matchers: Vec<MethodMatcher>,
    pub action: Action,
    pub metadata_requirements: Vec<CompiledMetadataRequirement>,
    pub role_config: Option<RoleConfig>,
}

impl CompiledAuthRule {
    fn new(rule: &AuthorizationRule) -> Self {
        let service_matcher = if let Some(service) = &rule.service {
            ServiceMatcher::Exact(service.clone())
        } else if let Some(pattern) = &rule.service_pattern {
            ServiceMatcher::Regex(Regex::new(pattern).unwrap())
        } else {
            ServiceMatcher::Any
        };

        let method_matchers: Vec<_> = rule.methods.iter().map(|m| MethodMatcher::new(m)).collect();

        let role_config = rule.require_roles.as_ref().map(|roles| RoleConfig {
            required_roles: roles.clone(),
            roles_header: rule.roles_header.clone().unwrap_or_default(),
        });

        Self {
            service_matcher,
            method_matchers,
            action: rule.action,
            metadata_requirements: rule
                .require_metadata
                .iter()
                .map(CompiledMetadataRequirement::new)
                .collect(),
            role_config,
        }
    }

    fn matches(&self, path: &GrpcPath) -> bool {
        // Check service
        if !self.service_matcher.matches(&path.full_service) {
            return false;
        }

        // Check method - if any matcher matches, the rule applies
        if self.method_matchers.is_empty() {
            return false;
        }

        self.method_matchers.iter().any(|m| m.matches(&path.method))
    }
}

pub struct RoleConfig {
    pub required_roles: Vec<String>,
    pub roles_header: String,
}

enum ServiceMatcher {
    Any,
    Exact(String),
    Regex(Regex),
}

impl ServiceMatcher {
    fn matches(&self, service: &str) -> bool {
        match self {
            ServiceMatcher::Any => true,
            ServiceMatcher::Exact(s) => s == service,
            ServiceMatcher::Regex(r) => r.is_match(service),
        }
    }
}

pub enum MethodMatcher {
    All,
    Exact(String),
    Glob(glob::Pattern),
}

impl MethodMatcher {
    fn new(pattern: &str) -> Self {
        if pattern == "*" {
            MethodMatcher::All
        } else if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            MethodMatcher::Glob(glob::Pattern::new(pattern).unwrap())
        } else {
            MethodMatcher::Exact(pattern.to_string())
        }
    }

    fn matches(&self, method: &str) -> bool {
        match self {
            MethodMatcher::All => true,
            MethodMatcher::Exact(s) => s == method,
            MethodMatcher::Glob(p) => p.matches(method),
        }
    }
}

pub struct CompiledMetadataRequirement {
    pub name: String,
    pub check: MetadataCheck,
}

impl CompiledMetadataRequirement {
    fn new(req: &MetadataRequirement) -> Self {
        let check = match req.requirement_type {
            RequirementType::Present => MetadataCheck::Present,
            RequirementType::Absent => MetadataCheck::Absent,
            RequirementType::Exact => MetadataCheck::Exact(req.value.clone().unwrap_or_default()),
            RequirementType::Pattern => {
                MetadataCheck::Pattern(Regex::new(req.pattern.as_deref().unwrap_or("")).unwrap())
            }
        };
        Self {
            name: req.name.clone(),
            check,
        }
    }

    /// Check if the requirement is satisfied by the given headers.
    pub fn satisfied_by(&self, headers: &HashMap<String, String>) -> bool {
        let value = headers.get(&self.name.to_lowercase());
        self.check.satisfied_by(value)
    }
}

pub enum MetadataCheck {
    Present,
    Absent,
    Exact(String),
    Pattern(Regex),
}

impl MetadataCheck {
    fn satisfied_by(&self, value: Option<&String>) -> bool {
        match self {
            MetadataCheck::Present => value.is_some(),
            MetadataCheck::Absent => value.is_none(),
            MetadataCheck::Exact(expected) => value.is_some_and(|v| v == expected),
            MetadataCheck::Pattern(regex) => value.is_some_and(|v| regex.is_match(v)),
        }
    }
}

// ============================================================================
// Size Limit Matchers
// ============================================================================

pub struct CompiledSizeLimits {
    pub enabled: bool,
    pub default_max_request_bytes: u64,
    pub default_max_response_bytes: u64,
    method_limits: HashMap<String, MethodSizeLimitCompiled>,
}

struct MethodSizeLimitCompiled {
    max_request_bytes: Option<u64>,
    max_response_bytes: Option<u64>,
}

impl CompiledSizeLimits {
    fn new(config: &SizeLimitsConfig) -> Self {
        let mut method_limits = HashMap::new();
        for limit in &config.per_method {
            let key = format!("{}/{}", limit.service, limit.method);
            method_limits.insert(
                key,
                MethodSizeLimitCompiled {
                    max_request_bytes: limit.max_request_bytes,
                    max_response_bytes: limit.max_response_bytes,
                },
            );
        }
        Self {
            enabled: config.enabled,
            default_max_request_bytes: config.default_max_request_bytes,
            default_max_response_bytes: config.default_max_response_bytes,
            method_limits,
        }
    }

    /// Get the max request size for a method.
    pub fn get_max_request_bytes(&self, path: &GrpcPath) -> u64 {
        self.method_limits
            .get(&path.full_path)
            .and_then(|l| l.max_request_bytes)
            .unwrap_or(self.default_max_request_bytes)
    }

    /// Get the max response size for a method.
    pub fn get_max_response_bytes(&self, path: &GrpcPath) -> u64 {
        self.method_limits
            .get(&path.full_path)
            .and_then(|l| l.max_response_bytes)
            .unwrap_or(self.default_max_response_bytes)
    }
}

// ============================================================================
// Metadata Matchers
// ============================================================================

pub struct CompiledMetadata {
    pub enabled: bool,
    pub required: Vec<CompiledRequiredHeader>,
    pub forbidden: Vec<CompiledForbiddenHeader>,
    pub validation: Vec<CompiledHeaderValidation>,
}

impl CompiledMetadata {
    fn new(config: &MetadataConfig) -> Self {
        Self {
            enabled: config.enabled,
            required: config
                .required
                .iter()
                .map(CompiledRequiredHeader::new)
                .collect(),
            forbidden: config
                .forbidden
                .iter()
                .map(CompiledForbiddenHeader::new)
                .collect(),
            validation: config
                .validation
                .iter()
                .map(CompiledHeaderValidation::new)
                .collect(),
        }
    }
}

pub struct CompiledRequiredHeader {
    pub name: String,
    pub apply_to: Vec<MethodMatcher>,
}

impl CompiledRequiredHeader {
    fn new(header: &RequiredHeader) -> Self {
        let apply_to = if header.apply_to.is_empty() {
            vec![MethodMatcher::All]
        } else {
            header
                .apply_to
                .iter()
                .map(|p| MethodMatcher::new(p))
                .collect()
        };
        Self {
            name: header.name.to_lowercase(),
            apply_to,
        }
    }

    pub fn applies_to(&self, path: &GrpcPath) -> bool {
        let full_method = format!("{}/{}", path.full_service, path.method);
        self.apply_to.iter().any(|m| m.matches(&full_method))
    }
}

pub struct CompiledForbiddenHeader {
    pub name_matcher: HeaderNameMatcher,
    pub apply_to: Vec<MethodMatcher>,
}

impl CompiledForbiddenHeader {
    fn new(header: &ForbiddenHeader) -> Self {
        let name_matcher = if let Some(name) = &header.name {
            HeaderNameMatcher::Exact(name.to_lowercase())
        } else if let Some(pattern) = &header.name_pattern {
            HeaderNameMatcher::Pattern(Regex::new(pattern).unwrap())
        } else {
            HeaderNameMatcher::None
        };

        let apply_to = if header.apply_to.is_empty() {
            vec![MethodMatcher::All]
        } else {
            header
                .apply_to
                .iter()
                .map(|p| MethodMatcher::new(p))
                .collect()
        };

        Self {
            name_matcher,
            apply_to,
        }
    }

    pub fn applies_to(&self, path: &GrpcPath) -> bool {
        let full_method = format!("{}/{}", path.full_service, path.method);
        self.apply_to.iter().any(|m| m.matches(&full_method))
    }

    pub fn matches_header(&self, header_name: &str) -> bool {
        self.name_matcher.matches(header_name)
    }
}

pub enum HeaderNameMatcher {
    None,
    Exact(String),
    Pattern(Regex),
}

impl HeaderNameMatcher {
    fn matches(&self, name: &str) -> bool {
        match self {
            HeaderNameMatcher::None => false,
            HeaderNameMatcher::Exact(n) => n == &name.to_lowercase(),
            HeaderNameMatcher::Pattern(r) => r.is_match(name),
        }
    }
}

pub struct CompiledHeaderValidation {
    pub name: String,
    pub pattern: Option<Regex>,
    pub allowed_values: Vec<String>,
    pub max_value: Option<String>,
}

impl CompiledHeaderValidation {
    fn new(val: &HeaderValidation) -> Self {
        Self {
            name: val.name.to_lowercase(),
            pattern: val.pattern.as_ref().map(|p| Regex::new(p).unwrap()),
            allowed_values: val.allowed_values.clone(),
            max_value: val.max_value.clone(),
        }
    }

    /// Validate a header value. Returns None if valid, or an error message if invalid.
    pub fn validate(&self, value: &str) -> Option<String> {
        if let Some(pattern) = &self.pattern {
            if !pattern.is_match(value) {
                return Some(format!(
                    "Header '{}' value '{}' does not match pattern",
                    self.name, value
                ));
            }
        }

        if !self.allowed_values.is_empty() && !self.allowed_values.contains(&value.to_string()) {
            return Some(format!(
                "Header '{}' value '{}' not in allowed values",
                self.name, value
            ));
        }

        None
    }
}

// ============================================================================
// Rate Limiting Matchers
// ============================================================================

pub struct CompiledRateLimiting {
    pub enabled: bool,
    pub default_limit: u32,
    pub default_window_seconds: u32,
    pub default_key_type: RateLimitKeyType,
    pub default_key_metadata_name: Option<String>,
    pub method_limits: Vec<CompiledMethodRateLimit>,
}

impl CompiledRateLimiting {
    fn new(config: &RateLimitingConfig) -> Self {
        Self {
            enabled: config.enabled,
            default_limit: config.default_limit,
            default_window_seconds: config.default_window_seconds,
            default_key_type: config.key_type,
            default_key_metadata_name: config.key_metadata_name.clone(),
            method_limits: config
                .per_method
                .iter()
                .map(CompiledMethodRateLimit::new)
                .collect(),
        }
    }

    /// Find a rate limit configuration for a method.
    pub fn find_limit(&self, path: &GrpcPath) -> Option<&CompiledMethodRateLimit> {
        self.method_limits.iter().find(|l| l.matches(path))
    }
}

pub struct CompiledMethodRateLimit {
    service: String,
    method_matchers: Vec<MethodMatcher>,
    pub limit: u32,
    pub window_seconds: u32,
    pub burst: u32,
    pub key_type: Option<RateLimitKeyType>,
    pub key_metadata_name: Option<String>,
}

impl CompiledMethodRateLimit {
    fn new(config: &MethodRateLimit) -> Self {
        let methods = if let Some(method) = &config.method {
            vec![method.clone()]
        } else {
            config.methods.clone()
        };

        Self {
            service: config.service.clone(),
            method_matchers: methods.iter().map(|m| MethodMatcher::new(m)).collect(),
            limit: config.limit,
            window_seconds: config.window_seconds,
            burst: config.burst,
            key_type: config.key_type,
            key_metadata_name: config.key_metadata_name.clone(),
        }
    }

    fn matches(&self, path: &GrpcPath) -> bool {
        if path.full_service != self.service {
            return false;
        }
        self.method_matchers.iter().any(|m| m.matches(&path.method))
    }
}

// ============================================================================
// Reflection Matchers
// ============================================================================

pub struct CompiledReflection {
    pub enabled: bool,
    pub allow: bool,
    allowed_ips: Vec<IpAddr>,
    allowed_cidrs: Vec<IpNet>,
    pub allowed_metadata: Option<CompiledReflectionMetadata>,
}

impl CompiledReflection {
    fn new(config: &ReflectionConfig) -> Self {
        let mut allowed_ips = Vec::new();
        let mut allowed_cidrs = Vec::new();

        for client in &config.allowed_clients {
            if client.contains('/') {
                if let Ok(cidr) = client.parse::<IpNet>() {
                    allowed_cidrs.push(cidr);
                }
            } else if let Ok(ip) = client.parse::<IpAddr>() {
                allowed_ips.push(ip);
            }
        }

        let allowed_metadata =
            config
                .allowed_metadata
                .as_ref()
                .map(|m| CompiledReflectionMetadata {
                    name: m.name.to_lowercase(),
                    values: m.values.clone(),
                });

        Self {
            enabled: config.enabled,
            allow: config.allow,
            allowed_ips,
            allowed_cidrs,
            allowed_metadata,
        }
    }

    /// Check if a client IP is allowed to access reflection.
    pub fn is_client_allowed(&self, client_ip: Option<&str>) -> bool {
        if self.allowed_ips.is_empty() && self.allowed_cidrs.is_empty() {
            return false;
        }

        let Some(ip_str) = client_ip else {
            return false;
        };

        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            return false;
        };

        // Check exact IP matches
        if self.allowed_ips.contains(&ip) {
            return true;
        }

        // Check CIDR matches
        self.allowed_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
}

pub struct CompiledReflectionMetadata {
    pub name: String,
    pub values: Vec<String>,
}

impl CompiledReflectionMetadata {
    pub fn matches(&self, headers: &HashMap<String, String>) -> bool {
        headers
            .get(&self.name)
            .is_some_and(|v| self.values.contains(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn test_method_matcher_all() {
        let matcher = MethodMatcher::new("*");
        assert!(matcher.matches("GetUser"));
        assert!(matcher.matches("CreateUser"));
        assert!(matcher.matches("DeleteUser"));
    }

    #[test]
    fn test_method_matcher_exact() {
        let matcher = MethodMatcher::new("GetUser");
        assert!(matcher.matches("GetUser"));
        assert!(!matcher.matches("CreateUser"));
    }

    #[test]
    fn test_method_matcher_glob() {
        let matcher = MethodMatcher::new("Delete*");
        assert!(matcher.matches("DeleteUser"));
        assert!(matcher.matches("DeleteAll"));
        assert!(!matcher.matches("GetUser"));

        let matcher = MethodMatcher::new("*User");
        assert!(matcher.matches("GetUser"));
        assert!(matcher.matches("DeleteUser"));
        assert!(!matcher.matches("GetUsers"));
    }

    #[test]
    fn test_service_matcher() {
        let exact = ServiceMatcher::Exact("myapp.UserService".to_string());
        assert!(exact.matches("myapp.UserService"));
        assert!(!exact.matches("myapp.AdminService"));

        let regex = ServiceMatcher::Regex(Regex::new(r"^myapp\.internal\..*").unwrap());
        assert!(regex.matches("myapp.internal.SecretService"));
        assert!(!regex.matches("myapp.UserService"));
    }

    #[test]
    fn test_metadata_check() {
        let mut headers = HashMap::new();
        headers.insert("x-request-id".to_string(), "123".to_string());

        let present = MetadataCheck::Present;
        assert!(present.satisfied_by(Some(&"123".to_string())));
        assert!(!present.satisfied_by(None));

        let absent = MetadataCheck::Absent;
        assert!(absent.satisfied_by(None));
        assert!(!absent.satisfied_by(Some(&"123".to_string())));

        let exact = MetadataCheck::Exact("123".to_string());
        assert!(exact.satisfied_by(Some(&"123".to_string())));
        assert!(!exact.satisfied_by(Some(&"456".to_string())));
    }

    #[test]
    fn test_reflection_ip_matching() {
        let config = ReflectionConfig {
            enabled: true,
            allow: false,
            allowed_clients: vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()],
            allowed_metadata: None,
        };
        let compiled = CompiledReflection::new(&config);

        assert!(compiled.is_client_allowed(Some("127.0.0.1")));
        assert!(compiled.is_client_allowed(Some("10.1.2.3")));
        assert!(!compiled.is_client_allowed(Some("192.168.1.1")));
        assert!(!compiled.is_client_allowed(None));
    }

    #[test]
    fn test_size_limits() {
        let config = SizeLimitsConfig {
            enabled: true,
            default_max_request_bytes: 1000,
            default_max_response_bytes: 2000,
            per_method: vec![MethodSizeLimit {
                service: "myapp.FileService".to_string(),
                method: "Upload".to_string(),
                max_request_bytes: Some(100000),
                max_response_bytes: Some(1000),
            }],
        };
        let compiled = CompiledSizeLimits::new(&config);

        let upload_path = GrpcPath::parse("/myapp.FileService/Upload").unwrap();
        assert_eq!(compiled.get_max_request_bytes(&upload_path), 100000);
        assert_eq!(compiled.get_max_response_bytes(&upload_path), 1000);

        let other_path = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
        assert_eq!(compiled.get_max_request_bytes(&other_path), 1000);
        assert_eq!(compiled.get_max_response_bytes(&other_path), 2000);
    }
}
