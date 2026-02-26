//! gRPC protocol utilities.

/// Parsed gRPC path from :path header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcPath {
    /// Full package name (e.g., "com.example.api.v1")
    pub package: String,
    /// Service name without package (e.g., "UserService")
    pub service: String,
    /// Method name (e.g., "GetUser")
    pub method: String,
    /// Full service name including package (e.g., "com.example.api.v1.UserService")
    pub full_service: String,
    /// Full path as service/method (e.g., "com.example.api.v1.UserService/GetUser")
    pub full_path: String,
}

impl GrpcPath {
    /// Parse a gRPC path from the :path HTTP/2 header.
    ///
    /// Expected format: `/:package.Service/MethodName`
    ///
    /// Examples:
    /// - `/myapp.UserService/GetUser`
    /// - `/com.example.api.v1.UserService/CreateUser`
    pub fn parse(path: &str) -> Option<Self> {
        // Remove leading slash
        let path = path.strip_prefix('/')?;

        // Split into service and method parts
        let (service_part, method) = path.rsplit_once('/')?;

        if service_part.is_empty() || method.is_empty() {
            return None;
        }

        // Split service into package and service name
        let (package, service) = service_part.rsplit_once('.')?;

        Some(Self {
            package: package.to_string(),
            service: service.to_string(),
            method: method.to_string(),
            full_service: service_part.to_string(),
            full_path: path.to_string(),
        })
    }

    /// Check if this is a reflection service request.
    pub fn is_reflection(&self) -> bool {
        self.full_service == "grpc.reflection.v1.ServerReflection"
            || self.full_service == "grpc.reflection.v1alpha.ServerReflection"
    }

    /// Check if this is a health check request.
    pub fn is_health_check(&self) -> bool {
        self.full_service == "grpc.health.v1.Health"
    }
}

/// Check if the content-type indicates a gRPC request.
pub fn is_grpc_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("application/grpc")
}

/// Check if the content-type indicates gRPC-Web.
pub fn is_grpc_web_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("application/grpc-web")
}

/// Parse the message size from a gRPC frame header.
///
/// gRPC frame format:
/// - Byte 0: Compression flag (0x00 = uncompressed, 0x01 = compressed)
/// - Bytes 1-4: Message length as big-endian u32
/// - Remaining: Message payload
///
/// Returns None if the body is too short to contain a valid frame header.
pub fn parse_message_size(body: &[u8]) -> Option<u32> {
    if body.len() < 5 {
        return None;
    }
    // Skip compression flag (byte 0), read 4-byte big-endian length
    Some(u32::from_be_bytes([body[1], body[2], body[3], body[4]]))
}

/// Check if the gRPC frame is compressed.
pub fn is_compressed(body: &[u8]) -> Option<bool> {
    if body.is_empty() {
        return None;
    }
    Some(body[0] != 0)
}

/// gRPC status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Get the status code as a string for the grpc-status header.
    pub fn as_str(&self) -> &'static str {
        match self {
            GrpcStatus::Ok => "0",
            GrpcStatus::Cancelled => "1",
            GrpcStatus::Unknown => "2",
            GrpcStatus::InvalidArgument => "3",
            GrpcStatus::DeadlineExceeded => "4",
            GrpcStatus::NotFound => "5",
            GrpcStatus::AlreadyExists => "6",
            GrpcStatus::PermissionDenied => "7",
            GrpcStatus::ResourceExhausted => "8",
            GrpcStatus::FailedPrecondition => "9",
            GrpcStatus::Aborted => "10",
            GrpcStatus::OutOfRange => "11",
            GrpcStatus::Unimplemented => "12",
            GrpcStatus::Internal => "13",
            GrpcStatus::Unavailable => "14",
            GrpcStatus::DataLoss => "15",
            GrpcStatus::Unauthenticated => "16",
        }
    }

    /// Get the name of the status code.
    pub fn name(&self) -> &'static str {
        match self {
            GrpcStatus::Ok => "OK",
            GrpcStatus::Cancelled => "CANCELLED",
            GrpcStatus::Unknown => "UNKNOWN",
            GrpcStatus::InvalidArgument => "INVALID_ARGUMENT",
            GrpcStatus::DeadlineExceeded => "DEADLINE_EXCEEDED",
            GrpcStatus::NotFound => "NOT_FOUND",
            GrpcStatus::AlreadyExists => "ALREADY_EXISTS",
            GrpcStatus::PermissionDenied => "PERMISSION_DENIED",
            GrpcStatus::ResourceExhausted => "RESOURCE_EXHAUSTED",
            GrpcStatus::FailedPrecondition => "FAILED_PRECONDITION",
            GrpcStatus::Aborted => "ABORTED",
            GrpcStatus::OutOfRange => "OUT_OF_RANGE",
            GrpcStatus::Unimplemented => "UNIMPLEMENTED",
            GrpcStatus::Internal => "INTERNAL",
            GrpcStatus::Unavailable => "UNAVAILABLE",
            GrpcStatus::DataLoss => "DATA_LOSS",
            GrpcStatus::Unauthenticated => "UNAUTHENTICATED",
        }
    }

    /// Get the appropriate HTTP status code for this gRPC status.
    pub fn http_status(&self) -> u16 {
        match self {
            GrpcStatus::Ok => 200,
            GrpcStatus::Cancelled => 499,
            GrpcStatus::Unknown => 500,
            GrpcStatus::InvalidArgument => 400,
            GrpcStatus::DeadlineExceeded => 504,
            GrpcStatus::NotFound => 404,
            GrpcStatus::AlreadyExists => 409,
            GrpcStatus::PermissionDenied => 403,
            GrpcStatus::ResourceExhausted => 429,
            GrpcStatus::FailedPrecondition => 400,
            GrpcStatus::Aborted => 409,
            GrpcStatus::OutOfRange => 400,
            GrpcStatus::Unimplemented => 501,
            GrpcStatus::Internal => 500,
            GrpcStatus::Unavailable => 503,
            GrpcStatus::DataLoss => 500,
            GrpcStatus::Unauthenticated => 401,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_path() {
        let path = GrpcPath::parse("/myapp.UserService/GetUser").unwrap();
        assert_eq!(path.package, "myapp");
        assert_eq!(path.service, "UserService");
        assert_eq!(path.method, "GetUser");
        assert_eq!(path.full_service, "myapp.UserService");
        assert_eq!(path.full_path, "myapp.UserService/GetUser");
    }

    #[test]
    fn test_parse_nested_package() {
        let path = GrpcPath::parse("/com.example.api.v1.UserService/CreateUser").unwrap();
        assert_eq!(path.package, "com.example.api.v1");
        assert_eq!(path.service, "UserService");
        assert_eq!(path.method, "CreateUser");
        assert_eq!(path.full_service, "com.example.api.v1.UserService");
    }

    #[test]
    fn test_parse_reflection_service() {
        let path =
            GrpcPath::parse("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo").unwrap();
        assert!(path.is_reflection());
        assert!(!path.is_health_check());
    }

    #[test]
    fn test_parse_health_service() {
        let path = GrpcPath::parse("/grpc.health.v1.Health/Check").unwrap();
        assert!(path.is_health_check());
        assert!(!path.is_reflection());
    }

    #[test]
    fn test_parse_invalid_paths() {
        assert!(GrpcPath::parse("no-leading-slash").is_none());
        assert!(GrpcPath::parse("/invalid").is_none());
        assert!(GrpcPath::parse("/no.method/").is_none());
        assert!(GrpcPath::parse("//Method").is_none());
    }

    #[test]
    fn test_content_type_detection() {
        assert!(is_grpc_content_type("application/grpc"));
        assert!(is_grpc_content_type("application/grpc+proto"));
        assert!(is_grpc_content_type("application/grpc+json"));
        assert!(is_grpc_content_type("Application/GRPC")); // case insensitive

        assert!(!is_grpc_content_type("application/json"));
        assert!(!is_grpc_content_type("text/plain"));
    }

    #[test]
    fn test_grpc_web_detection() {
        assert!(is_grpc_web_content_type("application/grpc-web"));
        assert!(is_grpc_web_content_type("application/grpc-web+proto"));
        assert!(!is_grpc_web_content_type("application/grpc"));
    }

    #[test]
    fn test_parse_message_size() {
        // Frame: [0x00 (uncompressed)][0x00 0x00 0x00 0x0A (10 bytes)]
        let frame = vec![0x00, 0x00, 0x00, 0x00, 0x0A];
        assert_eq!(parse_message_size(&frame), Some(10));

        // Larger message: 1024 bytes = 0x00000400
        let frame = vec![0x00, 0x00, 0x00, 0x04, 0x00];
        assert_eq!(parse_message_size(&frame), Some(1024));

        // Compressed frame
        let frame = vec![0x01, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(parse_message_size(&frame), Some(256));
    }

    #[test]
    fn test_parse_message_size_too_short() {
        assert!(parse_message_size(&[]).is_none());
        assert!(parse_message_size(&[0x00, 0x00]).is_none());
        assert!(parse_message_size(&[0x00, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_is_compressed() {
        assert_eq!(is_compressed(&[0x00, 0x00, 0x00, 0x00, 0x01]), Some(false));
        assert_eq!(is_compressed(&[0x01, 0x00, 0x00, 0x00, 0x01]), Some(true));
        assert!(is_compressed(&[]).is_none());
    }

    #[test]
    fn test_grpc_status_codes() {
        assert_eq!(GrpcStatus::Ok.as_str(), "0");
        assert_eq!(GrpcStatus::PermissionDenied.as_str(), "7");
        assert_eq!(GrpcStatus::ResourceExhausted.as_str(), "8");
        assert_eq!(GrpcStatus::Unauthenticated.as_str(), "16");

        assert_eq!(GrpcStatus::PermissionDenied.http_status(), 403);
        assert_eq!(GrpcStatus::ResourceExhausted.http_status(), 429);
    }
}
