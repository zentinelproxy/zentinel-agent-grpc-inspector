//! Configuration for the gRPC Inspector agent.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration for the gRPC Inspector agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Global settings
    #[serde(default)]
    pub settings: Settings,

    /// Method-level authorization
    #[serde(default)]
    pub authorization: AuthorizationConfig,

    /// Message size limits
    #[serde(default)]
    pub size_limits: SizeLimitsConfig,

    /// Metadata inspection
    #[serde(default)]
    pub metadata: MetadataConfig,

    /// Rate limiting per method
    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,

    /// Reflection API control
    #[serde(default)]
    pub reflection: ReflectionConfig,
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.authorization.validate()?;
        self.size_limits.validate()?;
        self.metadata.validate()?;
        self.rate_limiting.validate()?;
        self.reflection.validate()?;
        Ok(())
    }
}

/// Global settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Action when checks fail: block or allow (detect-only mode)
    #[serde(default = "default_fail_action")]
    pub fail_action: FailAction,

    /// Add X-Grpc-Inspector-* debug headers to responses
    #[serde(default)]
    pub debug_headers: bool,

    /// Log blocked requests
    #[serde(default = "default_true")]
    pub log_blocked: bool,

    /// Log allowed requests (verbose)
    #[serde(default)]
    pub log_allowed: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            fail_action: default_fail_action(),
            debug_headers: false,
            log_blocked: true,
            log_allowed: false,
        }
    }
}

fn default_fail_action() -> FailAction {
    FailAction::Block
}

fn default_true() -> bool {
    true
}

/// Action to take when a check fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailAction {
    /// Block the request
    Block,
    /// Allow the request (detect-only mode)
    Allow,
}

/// Authorization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConfig {
    /// Enable authorization checks
    #[serde(default)]
    pub enabled: bool,

    /// Default action for methods not matching any rule
    #[serde(default = "default_action_allow")]
    pub default_action: Action,

    /// Authorization rules (evaluated in order)
    #[serde(default)]
    pub rules: Vec<AuthorizationRule>,
}

impl Default for AuthorizationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: Action::Allow,
            rules: Vec::new(),
        }
    }
}

impl AuthorizationConfig {
    fn validate(&self) -> anyhow::Result<()> {
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate()
                .map_err(|e| anyhow::anyhow!("Authorization rule {}: {}", i, e))?;
        }
        Ok(())
    }
}

fn default_action_allow() -> Action {
    Action::Allow
}

/// Action for authorization rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// A single authorization rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRule {
    /// Exact service name to match (e.g., "myapp.UserService")
    #[serde(default)]
    pub service: Option<String>,

    /// Regex pattern for service name
    #[serde(default)]
    pub service_pattern: Option<String>,

    /// Methods to match (supports glob patterns like "Delete*")
    #[serde(default)]
    pub methods: Vec<String>,

    /// Action to take when rule matches
    pub action: Action,

    /// Required metadata for this rule
    #[serde(default)]
    pub require_metadata: Vec<MetadataRequirement>,

    /// Required roles (extracted from roles_header)
    #[serde(default)]
    pub require_roles: Option<Vec<String>>,

    /// Header containing comma-separated roles
    #[serde(default)]
    pub roles_header: Option<String>,
}

impl AuthorizationRule {
    fn validate(&self) -> anyhow::Result<()> {
        if self.service.is_none() && self.service_pattern.is_none() {
            anyhow::bail!("Either 'service' or 'service_pattern' must be specified");
        }
        if self.service.is_some() && self.service_pattern.is_some() {
            anyhow::bail!("Cannot specify both 'service' and 'service_pattern'");
        }
        if let Some(pattern) = &self.service_pattern {
            regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("Invalid service_pattern regex: {}", e))?;
        }
        if self.methods.is_empty() {
            anyhow::bail!("At least one method must be specified (use '*' for all)");
        }
        for req in &self.require_metadata {
            req.validate()?;
        }
        if self.require_roles.is_some() && self.roles_header.is_none() {
            anyhow::bail!("'roles_header' must be specified when 'require_roles' is set");
        }
        Ok(())
    }
}

/// Metadata requirement for authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataRequirement {
    /// Header name
    pub name: String,

    /// Requirement type
    #[serde(rename = "type", default = "default_requirement_type")]
    pub requirement_type: RequirementType,

    /// Expected value (for exact match)
    #[serde(default)]
    pub value: Option<String>,

    /// Regex pattern (for pattern match)
    #[serde(default)]
    pub pattern: Option<String>,
}

impl MetadataRequirement {
    fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("Metadata requirement name cannot be empty");
        }
        match self.requirement_type {
            RequirementType::Exact => {
                if self.value.is_none() {
                    anyhow::bail!("'value' must be specified for 'exact' requirement type");
                }
            }
            RequirementType::Pattern => {
                if let Some(pattern) = &self.pattern {
                    regex::Regex::new(pattern)
                        .map_err(|e| anyhow::anyhow!("Invalid pattern regex: {}", e))?;
                } else {
                    anyhow::bail!("'pattern' must be specified for 'pattern' requirement type");
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn default_requirement_type() -> RequirementType {
    RequirementType::Present
}

/// Type of metadata requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequirementType {
    /// Header must be present
    Present,
    /// Header must be absent
    Absent,
    /// Header must match exact value
    Exact,
    /// Header must match regex pattern
    Pattern,
}

/// Size limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SizeLimitsConfig {
    /// Enable size limit checks
    #[serde(default)]
    pub enabled: bool,

    /// Default max request size in bytes (0 = unlimited)
    #[serde(default = "default_max_size")]
    pub default_max_request_bytes: u64,

    /// Default max response size in bytes (0 = unlimited)
    #[serde(default = "default_max_size")]
    pub default_max_response_bytes: u64,

    /// Per-method size limits
    #[serde(default)]
    pub per_method: Vec<MethodSizeLimit>,
}

impl Default for SizeLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_max_request_bytes: default_max_size(),
            default_max_response_bytes: default_max_size(),
            per_method: Vec::new(),
        }
    }
}

impl SizeLimitsConfig {
    fn validate(&self) -> anyhow::Result<()> {
        for (i, limit) in self.per_method.iter().enumerate() {
            limit
                .validate()
                .map_err(|e| anyhow::anyhow!("Size limit {}: {}", i, e))?;
        }
        Ok(())
    }
}

fn default_max_size() -> u64 {
    4 * 1024 * 1024 // 4MB
}

/// Per-method size limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodSizeLimit {
    /// Service name
    pub service: String,

    /// Method name
    pub method: String,

    /// Max request size in bytes (0 = unlimited)
    #[serde(default)]
    pub max_request_bytes: Option<u64>,

    /// Max response size in bytes (0 = unlimited)
    #[serde(default)]
    pub max_response_bytes: Option<u64>,
}

impl MethodSizeLimit {
    fn validate(&self) -> anyhow::Result<()> {
        if self.service.is_empty() {
            anyhow::bail!("Service name cannot be empty");
        }
        if self.method.is_empty() {
            anyhow::bail!("Method name cannot be empty");
        }
        Ok(())
    }
}

/// Metadata inspection configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    /// Enable metadata inspection
    #[serde(default)]
    pub enabled: bool,

    /// Required headers
    #[serde(default)]
    pub required: Vec<RequiredHeader>,

    /// Forbidden headers
    #[serde(default)]
    pub forbidden: Vec<ForbiddenHeader>,

    /// Header validation rules
    #[serde(default)]
    pub validation: Vec<HeaderValidation>,
}

impl MetadataConfig {
    fn validate(&self) -> anyhow::Result<()> {
        for (i, req) in self.required.iter().enumerate() {
            req.validate()
                .map_err(|e| anyhow::anyhow!("Required header {}: {}", i, e))?;
        }
        for (i, forb) in self.forbidden.iter().enumerate() {
            forb.validate()
                .map_err(|e| anyhow::anyhow!("Forbidden header {}: {}", i, e))?;
        }
        for (i, val) in self.validation.iter().enumerate() {
            val.validate()
                .map_err(|e| anyhow::anyhow!("Header validation {}: {}", i, e))?;
        }
        Ok(())
    }
}

/// Required header configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredHeader {
    /// Header name
    pub name: String,

    /// Methods to apply to (glob patterns, empty = all)
    #[serde(default)]
    pub apply_to: Vec<String>,
}

impl RequiredHeader {
    fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("Header name cannot be empty");
        }
        Ok(())
    }
}

/// Forbidden header configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenHeader {
    /// Exact header name
    #[serde(default)]
    pub name: Option<String>,

    /// Header name pattern (regex)
    #[serde(default)]
    pub name_pattern: Option<String>,

    /// Methods to apply to (glob patterns, empty = all)
    #[serde(default)]
    pub apply_to: Vec<String>,
}

impl ForbiddenHeader {
    fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_none() && self.name_pattern.is_none() {
            anyhow::bail!("Either 'name' or 'name_pattern' must be specified");
        }
        if let Some(pattern) = &self.name_pattern {
            regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("Invalid name_pattern regex: {}", e))?;
        }
        Ok(())
    }
}

/// Header validation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderValidation {
    /// Header name
    pub name: String,

    /// Regex pattern the value must match
    #[serde(default)]
    pub pattern: Option<String>,

    /// Allowed values
    #[serde(default)]
    pub allowed_values: Vec<String>,

    /// Max value (for timeout headers)
    #[serde(default)]
    pub max_value: Option<String>,
}

impl HeaderValidation {
    fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("Header name cannot be empty");
        }
        if let Some(pattern) = &self.pattern {
            regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("Invalid pattern regex: {}", e))?;
        }
        Ok(())
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    #[serde(default)]
    pub enabled: bool,

    /// Default rate limit (requests per window)
    #[serde(default = "default_rate_limit")]
    pub default_limit: u32,

    /// Default window size in seconds
    #[serde(default = "default_window")]
    pub default_window_seconds: u32,

    /// Key type for rate limiting
    #[serde(default)]
    pub key_type: RateLimitKeyType,

    /// Metadata header name for key extraction
    #[serde(default)]
    pub key_metadata_name: Option<String>,

    /// Per-method rate limits
    #[serde(default)]
    pub per_method: Vec<MethodRateLimit>,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_limit: default_rate_limit(),
            default_window_seconds: default_window(),
            key_type: RateLimitKeyType::ClientIp,
            key_metadata_name: None,
            per_method: Vec::new(),
        }
    }
}

impl RateLimitingConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.key_type == RateLimitKeyType::Metadata && self.key_metadata_name.is_none() {
            anyhow::bail!("'key_metadata_name' must be set when key_type is 'metadata'");
        }
        for (i, limit) in self.per_method.iter().enumerate() {
            limit
                .validate()
                .map_err(|e| anyhow::anyhow!("Rate limit {}: {}", i, e))?;
        }
        Ok(())
    }
}

fn default_rate_limit() -> u32 {
    1000
}

fn default_window() -> u32 {
    60
}

/// Rate limit key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyType {
    /// Use client IP address
    #[default]
    ClientIp,
    /// Use a metadata header value
    Metadata,
    /// Composite key (service/method/client)
    Composite,
}

/// Per-method rate limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodRateLimit {
    /// Service name
    pub service: String,

    /// Method name (or "*" for all methods)
    #[serde(default)]
    pub method: Option<String>,

    /// Methods list (alternative to single method)
    #[serde(default)]
    pub methods: Vec<String>,

    /// Rate limit (requests per window)
    pub limit: u32,

    /// Window size in seconds
    #[serde(default = "default_window")]
    pub window_seconds: u32,

    /// Burst allowance
    #[serde(default)]
    pub burst: u32,

    /// Override key type for this method
    #[serde(default)]
    pub key_type: Option<RateLimitKeyType>,

    /// Override key metadata name for this method
    #[serde(default)]
    pub key_metadata_name: Option<String>,
}

impl MethodRateLimit {
    fn validate(&self) -> anyhow::Result<()> {
        if self.service.is_empty() {
            anyhow::bail!("Service name cannot be empty");
        }
        if self.method.is_none() && self.methods.is_empty() {
            anyhow::bail!("Either 'method' or 'methods' must be specified");
        }
        if self.limit == 0 {
            anyhow::bail!("Rate limit must be greater than 0");
        }
        if self.window_seconds == 0 {
            anyhow::bail!("Window seconds must be greater than 0");
        }
        Ok(())
    }
}

/// Reflection API control configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectionConfig {
    /// Enable reflection control
    #[serde(default)]
    pub enabled: bool,

    /// Allow reflection API (false = block)
    #[serde(default)]
    pub allow: bool,

    /// Allowed client IPs/CIDRs
    #[serde(default)]
    pub allowed_clients: Vec<String>,

    /// Allowed metadata for reflection access
    #[serde(default)]
    pub allowed_metadata: Option<ReflectionMetadata>,
}

impl ReflectionConfig {
    fn validate(&self) -> anyhow::Result<()> {
        for (i, client) in self.allowed_clients.iter().enumerate() {
            // Try to parse as IP or CIDR
            if client.contains('/') {
                client.parse::<ipnet::IpNet>().map_err(|e| {
                    anyhow::anyhow!("Invalid CIDR at allowed_clients[{}]: {}", i, e)
                })?;
            } else {
                client
                    .parse::<std::net::IpAddr>()
                    .map_err(|e| anyhow::anyhow!("Invalid IP at allowed_clients[{}]: {}", i, e))?;
            }
        }
        Ok(())
    }
}

/// Metadata-based reflection access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectionMetadata {
    /// Header name
    pub name: String,

    /// Allowed values
    pub values: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.settings.fail_action, FailAction::Block);
        assert!(!config.authorization.enabled);
        assert!(!config.size_limits.enabled);
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
settings:
  fail_action: block
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.settings.fail_action, FailAction::Block);
    }

    #[test]
    fn test_parse_authorization_config() {
        let yaml = r#"
authorization:
  enabled: true
  default_action: deny
  rules:
    - service: "myapp.UserService"
      methods: ["GetUser", "ListUsers"]
      action: allow
    - service_pattern: "^myapp\\.internal\\."
      methods: ["*"]
      action: deny
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert!(config.authorization.enabled);
        assert_eq!(config.authorization.default_action, Action::Deny);
        assert_eq!(config.authorization.rules.len(), 2);
    }

    #[test]
    fn test_parse_size_limits() {
        let yaml = r#"
size_limits:
  enabled: true
  default_max_request_bytes: 1048576
  per_method:
    - service: "myapp.FileService"
      method: "Upload"
      max_request_bytes: 104857600
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert!(config.size_limits.enabled);
        assert_eq!(config.size_limits.default_max_request_bytes, 1048576);
    }

    #[test]
    fn test_parse_rate_limiting() {
        let yaml = r#"
rate_limiting:
  enabled: true
  default_limit: 100
  per_method:
    - service: "myapp.AuthService"
      method: "Login"
      limit: 10
      window_seconds: 60
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert!(config.rate_limiting.enabled);
        assert_eq!(config.rate_limiting.default_limit, 100);
    }

    #[test]
    fn test_parse_reflection_config() {
        let yaml = r#"
reflection:
  enabled: true
  allow: false
  allowed_clients:
    - "127.0.0.1"
    - "10.0.0.0/8"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert!(config.reflection.enabled);
        assert!(!config.reflection.allow);
    }

    #[test]
    fn test_validation_fails_for_invalid_regex() {
        let yaml = r#"
authorization:
  enabled: true
  rules:
    - service_pattern: "[invalid"
      methods: ["*"]
      action: deny
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_for_missing_service() {
        let yaml = r#"
authorization:
  enabled: true
  rules:
    - methods: ["GetUser"]
      action: allow
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }
}
