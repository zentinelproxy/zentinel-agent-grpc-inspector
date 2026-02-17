# gRPC Inspector Agent for Zentinel

A security agent for [Zentinel](https://zentinelproxy.io) that provides comprehensive security controls for gRPC services.

## Features

- **Method-level Authorization** - Allow/deny based on service and method with glob patterns and regex support
- **Reflection API Control** - Block or allow gRPC reflection by client IP or metadata
- **Metadata Inspection** - Required/forbidden headers with validation rules
- **Message Size Limits** - Per-method max request/response size limits
- **Rate Limiting** - Token bucket rate limiting per service/method/client

## Installation

```bash
cargo install zentinel-agent-grpc-inspector
```

Or build from source:

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-grpc-inspector.git
cd zentinel-agent-grpc-inspector
cargo build --release
```

## Usage

```bash
# Run with default config file (grpc-inspector.yaml)
zentinel-agent-grpc-inspector

# Specify config file
zentinel-agent-grpc-inspector -c /path/to/config.yaml

# Specify socket path
zentinel-agent-grpc-inspector -s /tmp/grpc-inspector.sock

# Print example configuration
zentinel-agent-grpc-inspector --print-config

# Validate configuration
zentinel-agent-grpc-inspector --validate
```

## Configuration

### Basic Structure

```yaml
settings:
  fail_action: block        # block or allow (detect-only mode)
  debug_headers: false      # Add X-Grpc-Inspector-* debug headers
  log_blocked: true         # Log blocked requests
  log_allowed: false        # Log allowed requests (verbose)
```

### Authorization

Control which services and methods are accessible:

```yaml
authorization:
  enabled: true
  default_action: allow     # Default for unmatched methods
  rules:
    # Allow all methods in PublicService
    - service: "myapp.PublicService"
      methods: ["*"]
      action: allow

    # Deny all Delete* methods in AdminService
    - service: "myapp.AdminService"
      methods: ["Delete*", "Destroy*"]
      action: deny

    # Block all internal services using regex
    - service_pattern: "^myapp\\.internal\\."
      methods: ["*"]
      action: deny

    # Require specific metadata for sensitive operations
    - service: "myapp.PaymentService"
      methods: ["ProcessPayment", "Refund"]
      action: allow
      require_metadata:
        - name: "x-idempotency-key"
          type: present
      require_roles: ["payment_processor"]
      roles_header: "x-user-roles"
```

### Size Limits

Prevent oversized requests:

```yaml
size_limits:
  enabled: true
  default_max_request_bytes: 4194304     # 4MB
  default_max_response_bytes: 4194304    # 4MB
  per_method:
    - service: "myapp.FileService"
      method: "Upload"
      max_request_bytes: 104857600       # 100MB for uploads
      max_response_bytes: 1048576        # 1MB response
```

### Metadata Inspection

Enforce header requirements:

```yaml
metadata:
  enabled: true
  required:
    - name: "x-request-id"               # Require for all methods
    - name: "x-tenant-id"
      apply_to: ["myapp.TenantService/*"]
  forbidden:
    - name: "x-internal-only"            # Block if present
    - name_pattern: "^x-debug-"          # Block debug headers
      apply_to: ["myapp.ProductionService/*"]
  validation:
    - name: "content-type"
      allowed_values:
        - "application/grpc"
        - "application/grpc+proto"
```

### Rate Limiting

Token bucket rate limiting:

```yaml
rate_limiting:
  enabled: true
  default_limit: 1000                    # Requests per window
  default_window_seconds: 60
  key_type: client_ip                    # client_ip, metadata, or composite
  per_method:
    - service: "myapp.AuthService"
      method: "Login"
      limit: 10
      window_seconds: 60
      burst: 2
    - service: "myapp.SearchService"
      methods: ["*"]
      limit: 100
      window_seconds: 60
      key_type: metadata
      key_metadata_name: "x-user-id"
```

### Reflection Control

Control gRPC reflection API access:

```yaml
reflection:
  enabled: true
  allow: false                           # Block by default
  allowed_clients:
    - "127.0.0.1"                        # Allow localhost
    - "10.0.0.0/8"                       # Allow internal network
  allowed_metadata:
    name: "x-reflection-key"
    values: ["dev-key-12345"]
```

## gRPC Status Codes

When blocking requests, the agent returns appropriate gRPC status codes:

| Scenario | gRPC Status | Code |
|----------|-------------|------|
| Method denied | PERMISSION_DENIED | 7 |
| Missing metadata | UNAUTHENTICATED | 16 |
| Insufficient roles | PERMISSION_DENIED | 7 |
| Rate limited | RESOURCE_EXHAUSTED | 8 |
| Request too large | RESOURCE_EXHAUSTED | 8 |
| Invalid request | INVALID_ARGUMENT | 3 |

## Zentinel Configuration

Add the agent to your Zentinel proxy configuration:

```yaml
agents:
  - name: grpc-inspector
    socket: /tmp/zentinel-grpc-inspector.sock
    on_request: true
    on_response: false
```

## Testing

Run the test suite:

```bash
cargo test
```

## License

MIT License - see [LICENSE](LICENSE) for details.
