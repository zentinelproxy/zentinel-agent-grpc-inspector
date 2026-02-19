# syntax=docker/dockerfile:1.4

# Zentinel gRPC Inspector Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-grpc-inspector-agent /zentinel-grpc-inspector-agent

LABEL org.opencontainers.image.title="Zentinel gRPC Inspector Agent" \
      org.opencontainers.image.description="Zentinel gRPC Inspector Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-grpc-inspector"

ENV RUST_LOG=info,zentinel_agent_grpc_inspector=debug \
    SOCKET_PATH=/var/run/zentinel/grpc-inspector.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-grpc-inspector-agent"]
