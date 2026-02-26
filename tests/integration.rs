//! Integration tests for the Zentinel gRPC Inspector Agent.
//!
//! These tests verify the complete functionality of the gRPC inspector,
//! including configuration parsing, path matching, authorization rules,
//! size limits, metadata inspection, rate limiting, and reflection control.

use std::collections::HashMap;
use zentinel_agent_grpc_inspector::config::{
    Action, AuthorizationConfig, AuthorizationRule, FailAction, MetadataConfig,
    MetadataRequirement, MethodRateLimit, MethodSizeLimit, RateLimitKeyType, RateLimitingConfig,
    ReflectionConfig, ReflectionMetadata, RequirementType, Settings, SizeLimitsConfig,
};
use zentinel_agent_grpc_inspector::grpc::{
    is_grpc_content_type, is_grpc_web_content_type, parse_message_size, GrpcPath, GrpcStatus,
};
use zentinel_agent_grpc_inspector::matchers::CompiledConfig;
use zentinel_agent_grpc_inspector::{Config, GrpcInspectorAgent};

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_default_config_is_valid() {
    let config = Config::default();
    assert!(config.validate().is_ok());

    assert_eq!(config.settings.fail_action, FailAction::Block);
    assert!(!config.authorization.enabled);
    assert!(!config.size_limits.enabled);
    assert!(!config.metadata.enabled);
    assert!(!config.rate_limiting.enabled);
    assert!(!config.reflection.enabled);
}

#[test]
fn test_full_config_from_yaml() {
    let yaml = r#"
settings:
  fail_action: block
  debug_headers: true
  log_blocked: true
  log_allowed: false

authorization:
  enabled: true
  default_action: deny
  rules:
    - service: "myapp.UserService"
      methods: ["GetUser", "ListUsers"]
      action: allow
    - service: "myapp.AdminService"
      methods: ["*"]
      action: deny
      require_roles:
        - admin
      roles_header: x-user-roles

size_limits:
  enabled: true
  default_max_request_bytes: 4194304
  default_max_response_bytes: 4194304
  per_method:
    - service: "myapp.FileService"
      method: "Upload"
      max_request_bytes: 104857600
    - service: "myapp.FileService"
      method: "Download"
      max_response_bytes: 104857600

metadata:
  enabled: true
  required:
    - name: "x-request-id"
    - name: "x-api-key"
      apply_to: ["myapp.AdminService/*"]
  forbidden:
    - name: "x-internal-token"
  validation:
    - name: "grpc-timeout"
      pattern: "^\\d+[smh]$"

rate_limiting:
  enabled: true
  default_limit: 1000
  default_window_seconds: 60
  key_type: client_ip
  per_method:
    - service: "myapp.AuthService"
      method: "Login"
      limit: 10
      window_seconds: 60
      burst: 5

reflection:
  enabled: true
  allow: false
  allowed_clients:
    - "127.0.0.1"
    - "10.0.0.0/8"
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());

    // Settings
    assert_eq!(config.settings.fail_action, FailAction::Block);
    assert!(config.settings.debug_headers);

    // Authorization
    assert!(config.authorization.enabled);
    assert_eq!(config.authorization.default_action, Action::Deny);
    assert_eq!(config.authorization.rules.len(), 2);

    // Size limits
    assert!(config.size_limits.enabled);
    assert_eq!(config.size_limits.default_max_request_bytes, 4194304);
    assert_eq!(config.size_limits.per_method.len(), 2);

    // Metadata
    assert!(config.metadata.enabled);
    assert_eq!(config.metadata.required.len(), 2);
    assert_eq!(config.metadata.forbidden.len(), 1);
    assert_eq!(config.metadata.validation.len(), 1);

    // Rate limiting
    assert!(config.rate_limiting.enabled);
    assert_eq!(config.rate_limiting.default_limit, 1000);
    assert_eq!(config.rate_limiting.per_method.len(), 1);

    // Reflection
    assert!(config.reflection.enabled);
    assert!(!config.reflection.allow);
    assert_eq!(config.reflection.allowed_clients.len(), 2);
}

#[test]
fn test_config_validation_invalid_regex() {
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
fn test_config_validation_missing_service() {
    let yaml = r#"
authorization:
  enabled: true
  rules:
    - methods: ["GetUser"]
      action: allow
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Either 'service' or 'service_pattern'"));
}

#[test]
fn test_config_validation_invalid_cidr() {
    let yaml = r#"
reflection:
  enabled: true
  allowed_clients:
    - "not-an-ip"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validation_rate_limit_metadata_key() {
    let yaml = r#"
rate_limiting:
  enabled: true
  key_type: metadata
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("key_metadata_name"));
}

// =============================================================================
// gRPC Path Parsing Tests
// =============================================================================

#[test]
fn test_grpc_path_parsing_simple() {
    let path = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    assert_eq!(path.package, "myapp");
    assert_eq!(path.service, "UserService");
    assert_eq!(path.method, "GetUser");
    assert_eq!(path.full_service, "myapp.UserService");
    assert_eq!(path.full_path, "myapp.UserService/GetUser");
}

#[test]
fn test_grpc_path_parsing_nested_package() {
    let path = GrpcPath::parse("/com.example.api.v1.UserService/CreateUser").unwrap();
    assert_eq!(path.package, "com.example.api.v1");
    assert_eq!(path.service, "UserService");
    assert_eq!(path.method, "CreateUser");
    assert_eq!(path.full_service, "com.example.api.v1.UserService");
}

#[test]
fn test_grpc_path_reflection_detection() {
    let v1 = GrpcPath::parse("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo").unwrap();
    assert!(v1.is_reflection());
    assert!(!v1.is_health_check());

    let v1alpha =
        GrpcPath::parse("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo").unwrap();
    assert!(v1alpha.is_reflection());
}

#[test]
fn test_grpc_path_health_check_detection() {
    let health = GrpcPath::parse("/grpc.health.v1.Health/Check").unwrap();
    assert!(health.is_health_check());
    assert!(!health.is_reflection());
}

#[test]
fn test_grpc_path_invalid_formats() {
    assert!(GrpcPath::parse("no-leading-slash").is_none());
    assert!(GrpcPath::parse("/invalid").is_none());
    assert!(GrpcPath::parse("/no.method/").is_none());
    assert!(GrpcPath::parse("//Method").is_none());
    assert!(GrpcPath::parse("/").is_none());
}

// =============================================================================
// Content Type Detection Tests
// =============================================================================

#[test]
fn test_grpc_content_type_detection() {
    assert!(is_grpc_content_type("application/grpc"));
    assert!(is_grpc_content_type("application/grpc+proto"));
    assert!(is_grpc_content_type("application/grpc+json"));
    assert!(is_grpc_content_type("Application/GRPC")); // case insensitive

    assert!(!is_grpc_content_type("application/json"));
    assert!(!is_grpc_content_type("text/plain"));
    // Note: application/grpc-web starts with "application/grpc" so it matches
    // Use is_grpc_web_content_type() for specific grpc-web detection
    assert!(is_grpc_content_type("application/grpc-web")); // starts_with match
}

#[test]
fn test_grpc_web_content_type_detection() {
    assert!(is_grpc_web_content_type("application/grpc-web"));
    assert!(is_grpc_web_content_type("application/grpc-web+proto"));
    assert!(is_grpc_web_content_type("application/grpc-web-text"));

    assert!(!is_grpc_web_content_type("application/grpc"));
    assert!(!is_grpc_web_content_type("application/json"));
}

// =============================================================================
// Message Size Parsing Tests
// =============================================================================

#[test]
fn test_parse_message_size() {
    // Frame: [0x00 (uncompressed)][0x00 0x00 0x00 0x0A (10 bytes)]
    let frame = vec![0x00, 0x00, 0x00, 0x00, 0x0A];
    assert_eq!(parse_message_size(&frame), Some(10));

    // Larger message: 1024 bytes = 0x00000400
    let frame = vec![0x00, 0x00, 0x00, 0x04, 0x00];
    assert_eq!(parse_message_size(&frame), Some(1024));

    // Compressed frame (same parsing, compression flag ignored)
    let frame = vec![0x01, 0x00, 0x00, 0x01, 0x00];
    assert_eq!(parse_message_size(&frame), Some(256));

    // Large message: 1MB = 0x00100000
    let frame = vec![0x00, 0x00, 0x10, 0x00, 0x00];
    assert_eq!(parse_message_size(&frame), Some(1048576));
}

#[test]
fn test_parse_message_size_too_short() {
    assert!(parse_message_size(&[]).is_none());
    assert!(parse_message_size(&[0x00]).is_none());
    assert!(parse_message_size(&[0x00, 0x00]).is_none());
    assert!(parse_message_size(&[0x00, 0x00, 0x00]).is_none());
    assert!(parse_message_size(&[0x00, 0x00, 0x00, 0x00]).is_none());
}

// =============================================================================
// gRPC Status Code Tests
// =============================================================================

#[test]
fn test_grpc_status_codes() {
    assert_eq!(GrpcStatus::Ok.as_str(), "0");
    assert_eq!(GrpcStatus::InvalidArgument.as_str(), "3");
    assert_eq!(GrpcStatus::PermissionDenied.as_str(), "7");
    assert_eq!(GrpcStatus::ResourceExhausted.as_str(), "8");
    assert_eq!(GrpcStatus::Unauthenticated.as_str(), "16");
}

#[test]
fn test_grpc_status_names() {
    assert_eq!(GrpcStatus::Ok.name(), "OK");
    assert_eq!(GrpcStatus::PermissionDenied.name(), "PERMISSION_DENIED");
    assert_eq!(GrpcStatus::ResourceExhausted.name(), "RESOURCE_EXHAUSTED");
    assert_eq!(GrpcStatus::Unauthenticated.name(), "UNAUTHENTICATED");
}

#[test]
fn test_grpc_status_http_mapping() {
    assert_eq!(GrpcStatus::Ok.http_status(), 200);
    assert_eq!(GrpcStatus::InvalidArgument.http_status(), 400);
    assert_eq!(GrpcStatus::Unauthenticated.http_status(), 401);
    assert_eq!(GrpcStatus::PermissionDenied.http_status(), 403);
    assert_eq!(GrpcStatus::NotFound.http_status(), 404);
    assert_eq!(GrpcStatus::ResourceExhausted.http_status(), 429);
    assert_eq!(GrpcStatus::Internal.http_status(), 500);
    assert_eq!(GrpcStatus::Unimplemented.http_status(), 501);
    assert_eq!(GrpcStatus::Unavailable.http_status(), 503);
    assert_eq!(GrpcStatus::DeadlineExceeded.http_status(), 504);
}

// =============================================================================
// Method Matcher Tests (via authorization rules)
// =============================================================================

#[test]
fn test_method_matching_via_authorization_wildcard() {
    // Test wildcard method matching through authorization rules
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Deny,
        rules: vec![AuthorizationRule {
            service: Some("myapp.UserService".to_string()),
            service_pattern: None,
            methods: vec!["*".to_string()], // Wildcard
            action: Action::Allow,
            require_metadata: vec![],
            require_roles: None,
            roles_header: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    // Any method should match
    let path1 = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path1).is_some());

    let path2 = GrpcPath::parse("/myapp.UserService/CreateUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path2).is_some());

    let path3 = GrpcPath::parse("/myapp.UserService/DeleteUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path3).is_some());
}

#[test]
fn test_method_matching_via_authorization_exact() {
    // Test exact method matching through authorization rules
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Deny,
        rules: vec![AuthorizationRule {
            service: Some("myapp.UserService".to_string()),
            service_pattern: None,
            methods: vec!["GetUser".to_string()], // Exact
            action: Action::Allow,
            require_metadata: vec![],
            require_roles: None,
            roles_header: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    // Only GetUser should match
    let path1 = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path1).is_some());

    let path2 = GrpcPath::parse("/myapp.UserService/CreateUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path2).is_none());
}

#[test]
fn test_method_matching_via_authorization_glob() {
    // Test glob method matching through authorization rules
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Deny,
        rules: vec![AuthorizationRule {
            service: Some("myapp.UserService".to_string()),
            service_pattern: None,
            methods: vec!["Delete*".to_string()], // Glob pattern
            action: Action::Deny,
            require_metadata: vec![],
            require_roles: None,
            roles_header: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    // Delete* should match DeleteUser, DeleteAll, etc.
    let path1 = GrpcPath::parse("/myapp.UserService/DeleteUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path1).is_some());

    let path2 = GrpcPath::parse("/myapp.UserService/DeleteAll").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path2).is_some());

    // Should not match non-Delete methods
    let path3 = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    assert!(compiled.authorization.find_matching_rule(&path3).is_none());
}

// =============================================================================
// Metadata Requirement Tests (via authorization rules)
// =============================================================================

#[test]
fn test_metadata_requirement_present_via_config() {
    // Test metadata present requirement through compiled config
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Deny,
        rules: vec![AuthorizationRule {
            service: Some("myapp.UserService".to_string()),
            service_pattern: None,
            methods: vec!["*".to_string()],
            action: Action::Allow,
            require_metadata: vec![MetadataRequirement {
                name: "x-request-id".to_string(),
                requirement_type: RequirementType::Present,
                value: None,
                pattern: None,
            }],
            require_roles: None,
            roles_header: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    let path = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    let rule = compiled.authorization.find_matching_rule(&path).unwrap();

    // Check the metadata requirements are compiled
    assert_eq!(rule.metadata_requirements.len(), 1);
    assert_eq!(rule.metadata_requirements[0].name, "x-request-id");

    // Verify satisfied_by works through the public API
    let mut headers = HashMap::new();
    headers.insert("x-request-id".to_string(), "abc123".to_string());
    assert!(rule.metadata_requirements[0].satisfied_by(&headers));

    let empty_headers = HashMap::new();
    assert!(!rule.metadata_requirements[0].satisfied_by(&empty_headers));
}

#[test]
fn test_metadata_requirement_exact_via_config() {
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Deny,
        rules: vec![AuthorizationRule {
            service: Some("myapp.UserService".to_string()),
            service_pattern: None,
            methods: vec!["*".to_string()],
            action: Action::Allow,
            require_metadata: vec![MetadataRequirement {
                name: "x-api-version".to_string(),
                requirement_type: RequirementType::Exact,
                value: Some("v2".to_string()),
                pattern: None,
            }],
            require_roles: None,
            roles_header: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    let path = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    let rule = compiled.authorization.find_matching_rule(&path).unwrap();

    // Correct value
    let mut headers = HashMap::new();
    headers.insert("x-api-version".to_string(), "v2".to_string());
    assert!(rule.metadata_requirements[0].satisfied_by(&headers));

    // Wrong value
    headers.insert("x-api-version".to_string(), "v1".to_string());
    assert!(!rule.metadata_requirements[0].satisfied_by(&headers));
}

// =============================================================================
// Compiled Config Tests
// =============================================================================

#[test]
fn test_compiled_authorization_rule_matching() {
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Deny,
        rules: vec![
            AuthorizationRule {
                service: Some("myapp.UserService".to_string()),
                service_pattern: None,
                methods: vec!["GetUser".to_string(), "ListUsers".to_string()],
                action: Action::Allow,
                require_metadata: vec![],
                require_roles: None,
                roles_header: None,
            },
            AuthorizationRule {
                service: Some("myapp.AdminService".to_string()),
                service_pattern: None,
                methods: vec!["*".to_string()],
                action: Action::Deny,
                require_metadata: vec![],
                require_roles: None,
                roles_header: None,
            },
        ],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    // Should match first rule
    let path1 = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    let rule1 = compiled.authorization.find_matching_rule(&path1);
    assert!(rule1.is_some());
    assert_eq!(rule1.unwrap().action, Action::Allow);

    // Should match first rule
    let path2 = GrpcPath::parse("/myapp.UserService/ListUsers").unwrap();
    let rule2 = compiled.authorization.find_matching_rule(&path2);
    assert!(rule2.is_some());
    assert_eq!(rule2.unwrap().action, Action::Allow);

    // Should not match first rule (CreateUser not in list)
    let path3 = GrpcPath::parse("/myapp.UserService/CreateUser").unwrap();
    let rule3 = compiled.authorization.find_matching_rule(&path3);
    assert!(rule3.is_none());

    // Should match second rule (wildcard)
    let path4 = GrpcPath::parse("/myapp.AdminService/DeleteUser").unwrap();
    let rule4 = compiled.authorization.find_matching_rule(&path4);
    assert!(rule4.is_some());
    assert_eq!(rule4.unwrap().action, Action::Deny);
}

#[test]
fn test_compiled_authorization_regex_service() {
    let config = AuthorizationConfig {
        enabled: true,
        default_action: Action::Allow,
        rules: vec![AuthorizationRule {
            service: None,
            service_pattern: Some(r"^myapp\.internal\..*".to_string()),
            methods: vec!["*".to_string()],
            action: Action::Deny,
            require_metadata: vec![],
            require_roles: None,
            roles_header: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &config,
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    // Should match internal services
    let path1 = GrpcPath::parse("/myapp.internal.SecretService/GetSecret").unwrap();
    let rule1 = compiled.authorization.find_matching_rule(&path1);
    assert!(rule1.is_some());
    assert_eq!(rule1.unwrap().action, Action::Deny);

    // Should not match non-internal services
    let path2 = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    let rule2 = compiled.authorization.find_matching_rule(&path2);
    assert!(rule2.is_none());
}

#[test]
fn test_compiled_size_limits() {
    let config = SizeLimitsConfig {
        enabled: true,
        default_max_request_bytes: 4_000_000,
        default_max_response_bytes: 8_000_000,
        per_method: vec![
            MethodSizeLimit {
                service: "myapp.FileService".to_string(),
                method: "Upload".to_string(),
                max_request_bytes: Some(100_000_000),
                max_response_bytes: None,
            },
            MethodSizeLimit {
                service: "myapp.FileService".to_string(),
                method: "Download".to_string(),
                max_request_bytes: None,
                max_response_bytes: Some(500_000_000),
            },
        ],
    };

    let compiled = CompiledConfig::new(
        &AuthorizationConfig::default(),
        &config,
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &ReflectionConfig::default(),
    );

    // Upload: custom request limit, default response limit
    let upload = GrpcPath::parse("/myapp.FileService/Upload").unwrap();
    assert_eq!(
        compiled.size_limits.get_max_request_bytes(&upload),
        100_000_000
    );
    assert_eq!(
        compiled.size_limits.get_max_response_bytes(&upload),
        8_000_000
    );

    // Download: default request limit, custom response limit
    let download = GrpcPath::parse("/myapp.FileService/Download").unwrap();
    assert_eq!(
        compiled.size_limits.get_max_request_bytes(&download),
        4_000_000
    );
    assert_eq!(
        compiled.size_limits.get_max_response_bytes(&download),
        500_000_000
    );

    // Other method: default limits
    let other = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    assert_eq!(
        compiled.size_limits.get_max_request_bytes(&other),
        4_000_000
    );
    assert_eq!(
        compiled.size_limits.get_max_response_bytes(&other),
        8_000_000
    );
}

#[test]
fn test_compiled_rate_limiting() {
    let config = RateLimitingConfig {
        enabled: true,
        default_limit: 1000,
        default_window_seconds: 60,
        key_type: RateLimitKeyType::ClientIp,
        key_metadata_name: None,
        per_method: vec![MethodRateLimit {
            service: "myapp.AuthService".to_string(),
            method: Some("Login".to_string()),
            methods: vec![],
            limit: 10,
            window_seconds: 60,
            burst: 5,
            key_type: None,
            key_metadata_name: None,
        }],
    };

    let compiled = CompiledConfig::new(
        &AuthorizationConfig::default(),
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &config,
        &ReflectionConfig::default(),
    );

    // Login method should have specific rate limit
    let login = GrpcPath::parse("/myapp.AuthService/Login").unwrap();
    let limit = compiled.rate_limiting.find_limit(&login);
    assert!(limit.is_some());
    let limit = limit.unwrap();
    assert_eq!(limit.limit, 10);
    assert_eq!(limit.window_seconds, 60);
    assert_eq!(limit.burst, 5);

    // Other method should not have specific limit
    let other = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
    assert!(compiled.rate_limiting.find_limit(&other).is_none());
}

#[test]
fn test_compiled_reflection_ip_access() {
    let config = ReflectionConfig {
        enabled: true,
        allow: false,
        allowed_clients: vec![
            "127.0.0.1".to_string(),
            "10.0.0.0/8".to_string(),
            "192.168.1.0/24".to_string(),
        ],
        allowed_metadata: None,
    };

    let compiled = CompiledConfig::new(
        &AuthorizationConfig::default(),
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &config,
    );

    // Exact IP match
    assert!(compiled.reflection.is_client_allowed(Some("127.0.0.1")));

    // CIDR match - 10.x.x.x
    assert!(compiled.reflection.is_client_allowed(Some("10.0.0.1")));
    assert!(compiled
        .reflection
        .is_client_allowed(Some("10.255.255.255")));

    // CIDR match - 192.168.1.x
    assert!(compiled.reflection.is_client_allowed(Some("192.168.1.1")));
    assert!(compiled.reflection.is_client_allowed(Some("192.168.1.254")));

    // Not allowed
    assert!(!compiled.reflection.is_client_allowed(Some("192.168.2.1")));
    assert!(!compiled.reflection.is_client_allowed(Some("8.8.8.8")));
    assert!(!compiled.reflection.is_client_allowed(None));
}

// =============================================================================
// Compiled Metadata Requirement Tests (Covered via authorization rule tests above)
// =============================================================================

// =============================================================================
// Agent Creation Tests
// =============================================================================

#[tokio::test]
async fn test_agent_creation_with_default_config() {
    let config = Config::default();
    let _agent = GrpcInspectorAgent::new(config);
}

#[tokio::test]
async fn test_agent_creation_with_full_config() {
    let config = Config {
        settings: Settings {
            fail_action: FailAction::Block,
            debug_headers: true,
            log_blocked: true,
            log_allowed: false,
        },
        authorization: AuthorizationConfig {
            enabled: true,
            default_action: Action::Deny,
            rules: vec![AuthorizationRule {
                service: Some("myapp.UserService".to_string()),
                service_pattern: None,
                methods: vec!["*".to_string()],
                action: Action::Allow,
                require_metadata: vec![],
                require_roles: None,
                roles_header: None,
            }],
        },
        size_limits: SizeLimitsConfig {
            enabled: true,
            default_max_request_bytes: 4_000_000,
            default_max_response_bytes: 4_000_000,
            per_method: vec![],
        },
        metadata: MetadataConfig::default(),
        rate_limiting: RateLimitingConfig::default(),
        reflection: ReflectionConfig::default(),
    };

    let _agent = GrpcInspectorAgent::new(config);
}

// =============================================================================
// Role-Based Access Tests
// =============================================================================

#[test]
fn test_authorization_with_roles() {
    let yaml = r#"
authorization:
  enabled: true
  default_action: deny
  rules:
    - service: "myapp.AdminService"
      methods: ["*"]
      action: allow
      require_roles:
        - admin
        - superuser
      roles_header: x-user-roles
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());

    let rule = &config.authorization.rules[0];
    assert_eq!(
        rule.require_roles,
        Some(vec!["admin".to_string(), "superuser".to_string()])
    );
    assert_eq!(rule.roles_header, Some("x-user-roles".to_string()));
}

// =============================================================================
// Header Validation Tests
// =============================================================================

#[test]
fn test_header_validation_config() {
    let yaml = r#"
metadata:
  enabled: true
  validation:
    - name: "grpc-timeout"
      pattern: "^\\d+[smh]$"
    - name: "x-api-key"
      allowed_values:
        - "key1"
        - "key2"
        - "key3"
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());

    assert_eq!(config.metadata.validation.len(), 2);
    assert!(config.metadata.validation[0].pattern.is_some());
    assert_eq!(config.metadata.validation[1].allowed_values.len(), 3);
}

// =============================================================================
// Reflection Metadata Access Tests
// =============================================================================

#[test]
fn test_reflection_metadata_access() {
    let config = ReflectionConfig {
        enabled: true,
        allow: false,
        allowed_clients: vec![],
        allowed_metadata: Some(ReflectionMetadata {
            name: "x-debug-token".to_string(),
            values: vec!["secret-debug-123".to_string(), "admin-token".to_string()],
        }),
    };

    let compiled = CompiledConfig::new(
        &AuthorizationConfig::default(),
        &SizeLimitsConfig::default(),
        &MetadataConfig::default(),
        &RateLimitingConfig::default(),
        &config,
    );

    let metadata = compiled.reflection.allowed_metadata.as_ref().unwrap();

    let mut headers = HashMap::new();
    headers.insert("x-debug-token".to_string(), "secret-debug-123".to_string());
    assert!(metadata.matches(&headers));

    headers.insert("x-debug-token".to_string(), "wrong-token".to_string());
    assert!(!metadata.matches(&headers));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_empty_config_uses_defaults() {
    let yaml = "";
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());

    // All defaults
    assert_eq!(config.settings.fail_action, FailAction::Block);
    assert!(!config.authorization.enabled);
    assert_eq!(
        config.size_limits.default_max_request_bytes,
        4 * 1024 * 1024
    );
}

#[test]
fn test_fail_action_allow_mode() {
    let yaml = r#"
settings:
  fail_action: allow
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.settings.fail_action, FailAction::Allow);
}

#[test]
fn test_rate_limit_composite_key() {
    let yaml = r#"
rate_limiting:
  enabled: true
  key_type: composite
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());
    assert_eq!(config.rate_limiting.key_type, RateLimitKeyType::Composite);
}

#[test]
fn test_forbidden_header_pattern() {
    let yaml = r#"
metadata:
  enabled: true
  forbidden:
    - name_pattern: "^x-internal-.*"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());
    assert!(config.metadata.forbidden[0].name_pattern.is_some());
}

#[test]
fn test_required_header_with_scope() {
    let yaml = r#"
metadata:
  enabled: true
  required:
    - name: "x-admin-token"
      apply_to:
        - "myapp.AdminService/*"
        - "myapp.internal.*/*"
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());
    assert_eq!(config.metadata.required[0].apply_to.len(), 2);
}
