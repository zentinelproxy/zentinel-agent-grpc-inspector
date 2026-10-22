#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# Requests carry `content-type: application/grpc` and a /package.Service/Method
# path; the agent only looks at headers, so HTTP/1.1 to the proxy is enough.
#   1. no config file: the agent starts with its defaults and allows;
#   2. with a config denying myapp.AdminService/Delete* and
#      ^myapp\.internal\., forbidding the x-internal-only metadata and the
#      reflection API (over the Unix socket and over gRPC): an allowed method
#      and a non-gRPC request are forwarded (200); a denied method, an
#      internal service and a reflection call get 403 (PERMISSION_DENIED),
#      forbidden metadata and a malformed gRPC path 400 (INVALID_ARGUMENT),
#      none of them reaching the upstream.
# Each run also checks that with the agent stopped the request is refused.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

# The first run changes directory, so make the paths absolute.
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
AGENT_BIN=$(abs "$AGENT_BIN"); ZENTINEL_BIN=$(abs "$ZENTINEL_BIN"); AGENT_SMOKE=$(abs "$AGENT_SMOKE")

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cat > "$dir/grpc-inspector.yaml" <<'YAML'
authorization:
  enabled: true
  default_action: allow
  rules:
    - service: "myapp.AdminService"
      methods: ["Delete*"]
      action: deny
    - service_pattern: "^myapp\\.internal\\."
      methods: ["*"]
      action: deny
metadata:
  enabled: true
  forbidden:
    - name: "x-internal-only"
reflection:
  enabled: true
  allow: false
YAML

smoke() {
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name grpc-inspector "$@"
}

GRPC='"Content-Type": "application/grpc", "TE": "trailers"'

echo "=== grpc-inspector agent, no config file: defaults allow"
(cd "$dir" && mkdir -p empty && cd empty && smoke \
    --clean "{\"name\": \"gRPC call\", \"method\": \"POST\", \"path\": \"/myapp.AdminService/DeleteUser\", \"headers\": {$GRPC}, \"body\": \"\"}")

for transport in uds grpc; do
    echo "=== grpc-inspector agent over $transport: method authorization"
    smoke --transport "$transport" --agent-arg=--config="$dir/grpc-inspector.yaml" \
        --clean "{\"name\": \"allowed method\", \"method\": \"POST\", \"path\": \"/myapp.AdminService/GetUser\", \"headers\": {$GRPC}, \"body\": \"\"}" \
        --case "{\"name\": \"denied method\", \"method\": \"POST\", \"path\": \"/myapp.AdminService/DeleteUser\", \"headers\": {$GRPC}, \"body\": \"\", \"expect\": 403}" \
        --case "{\"name\": \"internal service\", \"method\": \"POST\", \"path\": \"/myapp.internal.Billing/Charge\", \"headers\": {$GRPC}, \"body\": \"\", \"expect\": 403}" \
        --case "{\"name\": \"forbidden metadata\", \"method\": \"POST\", \"path\": \"/myapp.AdminService/GetUser\", \"headers\": {$GRPC, \"x-internal-only\": \"1\"}, \"body\": \"\", \"expect\": 400}" \
        --case "{\"name\": \"reflection API\", \"method\": \"POST\", \"path\": \"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo\", \"headers\": {$GRPC}, \"body\": \"\", \"expect\": 403}" \
        --case "{\"name\": \"malformed gRPC path\", \"method\": \"POST\", \"path\": \"/not-a-grpc-path\", \"headers\": {$GRPC}, \"body\": \"\", \"expect\": 400}" \
        --case '{"name": "non-gRPC request passes through", "path": "/index.html", "expect": 200}'
done
