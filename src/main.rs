//! gRPC Inspector Agent CLI.

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zentinel_agent_grpc_inspector::{Config, GrpcInspectorAgent};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};

#[derive(Parser, Debug)]
#[command(name = "zentinel-grpc-inspector-agent")]
#[command(about = "gRPC security agent for Zentinel (v2 protocol)")]
#[command(version)]
struct Args {
    /// Path to configuration file. Without it, `grpc-inspector.yaml` in the
    /// working directory is read if it exists, otherwise the agent starts
    /// with the defaults (every check off: every request is allowed).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Unix socket to serve agent protocol v2 on (the default transport;
    /// mutually exclusive with --grpc-address)
    #[arg(short, long, conflicts_with = "grpc_address")]
    socket: Option<PathBuf>,

    /// gRPC address to serve agent protocol v2 on instead of the Unix socket
    /// (e.g., "127.0.0.1:50051")
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

/// Config file read when `--config` is not given, if it exists.
const DEFAULT_CONFIG: &str = "grpc-inspector.yaml";

/// Unix socket used when neither `--socket` nor `--grpc-address` is given.
const DEFAULT_SOCKET: &str = "/tmp/zentinel-grpc-inspector.sock";

/// An explicit `--config` must exist; the implicit default file is optional.
fn load_config(path: Option<&Path>) -> Result<Config> {
    match path {
        Some(path) => {
            info!(config = %path.display(), "Loading configuration");
            Config::from_file(path)
                .with_context(|| format!("failed to load config {}", path.display()))
        }
        None if Path::new(DEFAULT_CONFIG).exists() => {
            info!(config = DEFAULT_CONFIG, "Loading configuration");
            Config::from_file(Path::new(DEFAULT_CONFIG))
                .with_context(|| format!("failed to load config {DEFAULT_CONFIG}"))
        }
        None => {
            info!("No configuration file, using defaults");
            let config = Config::default();
            config.validate()?;
            Ok(config)
        }
    }
}

#[derive(Debug, PartialEq)]
enum Transport {
    Uds(PathBuf),
    Grpc(SocketAddr),
}

/// `--grpc-address` (or `GRPC_INSPECTOR_GRPC_ADDRESS`) selects gRPC;
/// otherwise the agent serves the Unix socket.
fn transport(args: &Args) -> Result<Transport> {
    match (&args.socket, &args.grpc_address) {
        (_, Some(addr)) => Ok(Transport::Grpc(
            addr.parse()
                .context("Invalid gRPC address format (expected host:port)")?,
        )),
        (Some(socket), None) => Ok(Transport::Uds(socket.clone())),
        (None, None) => Ok(Transport::Uds(PathBuf::from(DEFAULT_SOCKET))),
    }
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
    let config = load_config(args.config.as_deref())?;

    // Handle --validate
    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    // Create agent
    let agent = GrpcInspectorAgent::new(config);

    match transport(&args)? {
        Transport::Uds(socket) => {
            info!(
                socket = %socket.display(),
                version = env!("CARGO_PKG_VERSION"),
                "Starting gRPC Inspector agent (Unix socket, v2 protocol)"
            );
            let server = UdsAgentServerV2::new("grpc-inspector", socket, Box::new(agent));
            server
                .run()
                .await
                .context("Failed to run gRPC Inspector agent")?;
        }
        Transport::Grpc(addr) => {
            info!(
                grpc_address = %addr,
                version = env!("CARGO_PKG_VERSION"),
                "Starting gRPC Inspector agent (gRPC transport, v2 protocol)"
            );
            let server = GrpcAgentServerV2::new("grpc-inspector", Box::new(agent));
            server
                .run(addr)
                .await
                .context("Failed to run gRPC Inspector agent")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn args(argv: &[&str]) -> Args {
        Args::try_parse_from(
            std::iter::once("zentinel-grpc-inspector-agent").chain(argv.iter().copied()),
        )
        .unwrap()
    }

    /// The release pipeline and `zentinel bundle install` expect exactly
    /// `<binary> <version>`.
    #[test]
    fn version_is_binary_name_and_package_version() {
        assert_eq!(
            Args::command().render_version(),
            format!("{} {}\n", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn socket_selects_the_unix_socket() {
        assert_eq!(
            transport(&args(&["--socket", "/tmp/x.sock"])).unwrap(),
            Transport::Uds(PathBuf::from("/tmp/x.sock"))
        );
    }

    #[test]
    fn default_transport_is_the_unix_socket() {
        if std::env::var_os("GRPC_INSPECTOR_GRPC_ADDRESS").is_some() {
            return;
        }
        assert_eq!(
            transport(&args(&[])).unwrap(),
            Transport::Uds(PathBuf::from(DEFAULT_SOCKET))
        );
    }

    #[test]
    fn grpc_address_selects_grpc() {
        assert_eq!(
            transport(&args(&["--grpc-address", "127.0.0.1:50051"])).unwrap(),
            Transport::Grpc("127.0.0.1:50051".parse().unwrap())
        );
    }

    #[test]
    fn starts_without_a_config_file() {
        assert!(load_config(None).is_ok());
    }

    #[test]
    fn explicit_missing_config_is_an_error() {
        assert!(load_config(Some(Path::new("/nonexistent/grpc-inspector.yaml"))).is_err());
    }

    /// The Unix socket used to be a gRPC server on a random TCP port: nothing
    /// ever listened on the socket path.
    #[tokio::test]
    async fn unix_socket_is_actually_served() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let server = UdsAgentServerV2::new(
            "grpc-inspector",
            socket.clone(),
            Box::new(GrpcInspectorAgent::new(Config::default())),
        );
        let task = tokio::spawn(async move { server.run().await });
        for _ in 0..50 {
            if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                task.abort();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("nothing listens on {}", socket.display());
    }
}
