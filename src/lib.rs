//! gRPC Inspector Agent for Zentinel.
//!
//! Provides security controls for gRPC services including:
//! - Method-level authorization
//! - Message size limits
//! - Metadata inspection
//! - Rate limiting per method
//! - Reflection API control

pub mod agent;
pub mod config;
pub mod grpc;
pub mod matchers;
pub mod rate_limiter;

pub use agent::GrpcInspectorAgent;
pub use config::Config;
