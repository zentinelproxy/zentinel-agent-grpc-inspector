//! gRPC Inspector Agent CLI.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zentinel_agent_grpc_inspector::{Config, GrpcInspectorAgent};
use zentinel_agent_protocol::v2::GrpcAgentServerV2;

#[derive(Parser, Debug)]
#[command(name = "zentinel-agent-grpc-inspector")]
#[command(about = "gRPC security agent for Zentinel (v2 protocol)")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "grpc-inspector.yaml")]
    config: PathBuf,

    /// Unix socket path (mutually exclusive with --grpc-address)
    #[arg(short, long, conflicts_with = "grpc_address")]
    socket: Option<PathBuf>,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051")
    #[arg(
        short = 'g',
        long,
        env = "GRPC_INSPECTOR_GRPC_ADDRESS",
        conflicts_with = "socket"
    )]
    grpc_address: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'L', long, default_value = "info")]
    log_level: String,

    /// Print example configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,
}

fn print_example_config() {
    let example = r#"# gRPC Inspector Agent Configuration
# See https://zentinelproxy.io/agents/grpc-inspector/ for full documentation

settings:
  fail_action: block        # block or allow (detect-only mode)
  debug_headers: false      # Add X-Grpc-Inspector-* debug headers
  log_blocked: true         # Log blocked requests
  log_allowed: false        # Log allowed requests (verbose)

# Method-level authorization
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

    # Block all internal services
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

# Message size limits
size_limits:
  enabled: true
  default_max_request_bytes: 4194304     # 4MB
  default_max_response_bytes: 4194304    # 4MB
  per_method:
    - service: "myapp.FileService"
      method: "Upload"
      max_request_bytes: 104857600       # 100MB for uploads
      max_response_bytes: 1048576        # 1MB response

# Metadata inspection
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

# Rate limiting per method
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

# Reflection API control
reflection:
  enabled: true
  allow: false                           # Block by default
  allowed_clients:
    - "127.0.0.1"                        # Allow localhost
    - "10.0.0.0/8"                       # Allow internal network
  allowed_metadata:
    name: "x-reflection-key"
    values: ["dev-key-12345"]
"#;
    println!("{}", example);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --print-config
    if args.print_config {
        print_example_config();
        return Ok(());
    }

    // Initialize logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Load configuration
    info!(config = %args.config.display(), "Loading configuration");
    let config = Config::from_file(&args.config)?;

    // Handle --validate
    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    // Create agent
    let agent = GrpcInspectorAgent::new(config);

    // Determine transport mode
    match (&args.socket, &args.grpc_address) {
        (Some(socket), None) => {
            // Unix socket mode (v2 protocol over UDS)
            info!(socket = %socket.display(), "Starting gRPC Inspector agent (Unix socket, v2 protocol)");

            // For UDS transport, we'd use AgentServerV2Uds when available
            // For now, fall back to gRPC server on localhost
            let addr = "127.0.0.1:0"
                .parse()
                .context("Failed to parse fallback address")?;
            let server = GrpcAgentServerV2::new("grpc-inspector", Box::new(agent));
            server
                .run(addr)
                .await
                .context("Failed to run gRPC Inspector agent")?;
        }
        (None, Some(grpc_addr)) => {
            // gRPC transport mode (v2 protocol)
            info!(
                grpc_address = %grpc_addr,
                version = env!("CARGO_PKG_VERSION"),
                "Starting gRPC Inspector agent (gRPC transport, v2 protocol)"
            );

            let addr = grpc_addr
                .parse()
                .context("Invalid gRPC address format (expected host:port)")?;

            let server = GrpcAgentServerV2::new("grpc-inspector", Box::new(agent));
            server
                .run(addr)
                .await
                .context("Failed to run gRPC Inspector agent")?;
        }
        (None, None) => {
            // Default: gRPC on 0.0.0.0:50051
            let default_addr = "0.0.0.0:50051";
            info!(
                grpc_address = %default_addr,
                version = env!("CARGO_PKG_VERSION"),
                "Starting gRPC Inspector agent (gRPC transport, v2 protocol, default)"
            );

            let addr = default_addr
                .parse()
                .context("Failed to parse default address")?;

            let server = GrpcAgentServerV2::new("grpc-inspector", Box::new(agent));
            server
                .run(addr)
                .await
                .context("Failed to run gRPC Inspector agent")?;
        }
        (Some(_), Some(_)) => {
            // This shouldn't happen due to clap's conflicts_with
            unreachable!("Cannot specify both --socket and --grpc-address");
        }
    }

    Ok(())
}
