<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">gRPC inspector agent</h3>

<p align="center">Method authorization, metadata rules, rate limits and reflection control for gRPC calls, decided at the request-headers stage.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-grpc-inspector/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-grpc-inspector/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/grpc-inspector/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For teams that put gRPC services behind Zentinel and want per-method policy without touching the services. The agent parses `/package.Service/Method` from the request path of every request whose `content-type` starts with `application/grpc`, runs reflection, authorization, metadata and rate-limit checks in that order, and stops at the first one that fails, answering with a gRPC status. Non-gRPC requests and `grpc.health.v1.Health` calls pass unchecked. If the agent is unreachable, the `failure-mode` of the Zentinel filter decides.

## Quick start

```bash
zentinel bundle install grpc-inspector

cat > grpc-inspector.yaml <<'EOF'
reflection:
  enabled: true      # block the reflection API for everyone
EOF

zentinel-grpc-inspector-agent -c grpc-inspector.yaml -g 127.0.0.1:50051
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "grpc-backend" {
        target "127.0.0.1:50052"
    }
}

agents {
    agent "grpc-inspector" type="custom" {
        grpc "http://127.0.0.1:50051"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "grpc-inspector" {
        type "agent"
        agent "grpc-inspector"
        failure-mode "closed"
    }
}

routes {
    route "grpc" {
        matches { path-prefix "/" }
        upstream "grpc-backend"
        filters "grpc-inspector"
    }
}
```

A reflection call such as `curl -i -H 'content-type: application/grpc' http://localhost:8080/grpc.reflection.v1.ServerReflection/ServerReflectionInfo` is now refused with HTTP 403 and `grpc-status: 7`, before it reaches the upstream.

## Install

### Bundle (recommended)

```bash
zentinel bundle install grpc-inspector
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-grpc-inspector-agent`.

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-grpc-inspector/releases).

### From source

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-grpc-inspector   # needs protoc
```

Installs the `zentinel-grpc-inspector-agent` binary.

## Configuration

The agent reads a YAML file (`-c`, default `grpc-inspector.yaml`; it must exist, and unknown keys are rejected). It acknowledges configuration sent over the protocol (`on_configure`) without applying it, and Zentinel 0.6.50 does not forward an `agent { config { ... } }` block anyway, so set everything in the file. `--print-config` prints a full example.

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `grpc-inspector.yaml` | Path to the YAML configuration file. |
| `-g`, `--grpc-address` | `0.0.0.0:50051` | Address the agent's gRPC server listens on. Env `GRPC_INSPECTOR_GRPC_ADDRESS`. The default listens on all interfaces; pass `127.0.0.1:50051` unless the proxy is remote. |
| `-L`, `--log-level` | `info` | Log level; `RUST_LOG` takes precedence. |
| `--print-config` | | Print an example configuration and exit. |
| `--validate` | | Load and validate the configuration, then exit. |

The agent listens on gRPC only. `-s/--socket` is accepted but does not open a Unix socket: it starts the gRPC server on a random localhost port instead, so do not use it.

Configuration file keys:

| Option | Default | Meaning |
|---|---|---|
| `settings.debug_headers` | `false` | On allowed calls, add `x-grpc-inspector-service` and `x-grpc-inspector-method`. |
| `settings.log_blocked` | `true` | Log blocked calls. |
| `settings.log_allowed` | `false` | Log allowed calls. |
| `settings.fail_action` | `block` | Parsed but has no effect; there is no detect-only mode. |
| `settings.trusted_proxies` | empty | IPs or CIDRs of proxies whose `X-Forwarded-For` / `X-Real-IP` are believed. Only needed with Zentinel older than 0.6.48; newer versions resolve the client behind the listener's `trusted-proxies` themselves. |
| `authorization.enabled` | `false` | Turn on method authorization. |
| `authorization.default_action` | `allow` | `allow` or `deny` when no rule matches. |
| `authorization.rules[].service` | | Exact full service name, e.g. `myapp.AdminService`. |
| `authorization.rules[].service_pattern` | | Regex on the full service name (use instead of `service`). |
| `authorization.rules[].methods` | | Method names; `*` for all, globs such as `Delete*`. A rule with no methods never matches. |
| `authorization.rules[].action` | required | `allow` or `deny`. The first matching rule wins. |
| `authorization.rules[].require_metadata` | | List of `{ name, type, value, pattern }`; `type` is `present` (default), `absent`, `exact` or `pattern`. |
| `authorization.rules[].require_roles` | | The comma-separated `roles_header` must contain at least one of these. |
| `authorization.rules[].roles_header` | | Header carrying the caller's roles. |
| `metadata.enabled` | `false` | Turn on metadata checks. |
| `metadata.required` | | List of `{ name, apply_to }`; the header must be present. `apply_to` takes `Service/*`-style paths. |
| `metadata.forbidden` | | List of `{ name or name_pattern, apply_to }`; the header must be absent. |
| `metadata.validation` | | List of `{ name, pattern, allowed_values }`, checked only when the header is present. (`max_value` is parsed but not used.) |
| `rate_limiting.enabled` | `false` | Turn on rate limiting. |
| `rate_limiting.default_limit` | `1000` | Calls per window for methods without a `per_method` entry. |
| `rate_limiting.default_window_seconds` | `60` | Window length. |
| `rate_limiting.key_type` | `client_ip` | `client_ip`, `metadata` (value of `key_metadata_name`) or `composite` (path plus client IP). |
| `rate_limiting.key_metadata_name` | | Header used when `key_type` is `metadata`. |
| `rate_limiting.per_method` | | List of `{ service, method or methods, limit, window_seconds, burst, key_type, key_metadata_name }`. |
| `reflection.enabled` | `false` | Turn on reflection control (`grpc.reflection.v1` and `v1alpha`). |
| `reflection.allow` | `false` | Allow reflection for everyone. |
| `reflection.allowed_clients` | | IPs or CIDRs that may use reflection. |
| `reflection.allowed_metadata` | | `{ name, values }`: a request with one of these header values may use reflection. |
| `size_limits.*` | | Parsed and validated, **not enforced**: the agent never receives message bodies. |

Full reference: <https://registry.zentinelproxy.io/grpc-inspector/>

## How it works

- **Blocking.** A refused call gets an HTTP status plus `grpc-status`, `grpc-message` and `content-type: application/grpc` headers:

  | Check | gRPC status | HTTP status |
  |---|---|---|
  | Reflection disabled, method denied, no matching rule under `default_action: deny`, missing role | `PERMISSION_DENIED` (7) | 403 |
  | Missing `require_metadata` on an authorization rule | `UNAUTHENTICATED` (16) | 401 |
  | Missing required, forbidden or invalid metadata; malformed gRPC path | `INVALID_ARGUMENT` (3) | 400 |
  | Rate limit exceeded (also sets `retry-after`) | `RESOURCE_EXHAUSTED` (8) | 429 |

- **Client IP** for rate limits and `reflection.allowed_clients` is the connection address Zentinel reports in the request metadata; forwarding headers the client sends are ignored. Only when that address is in `settings.trusted_proxies` are `X-Forwarded-For` (right to left, first hop that is not a trusted proxy) and then `X-Real-IP` read. A request without a usable address matches no `allowed_clients` entry and shares the rate-limit key `unknown` with every other such request.
- **Rate limits** are token buckets held in memory per service, method and key: `limit` tokens refilled over `window_seconds`, starting with `limit + burst` tokens. Buckets idle for five minutes are dropped. They are not shared between agent instances.
- **Metrics** are reported over the agent protocol: total, blocked and allowed counters.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Needs stable Rust (CI uses `dtolnay/rust-toolchain@stable`) and `protoc` (CI installs `protobuf-compiler`).

## Related

- [Registry page](https://registry.zentinelproxy.io/grpc-inspector/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [GraphQL security agent](https://github.com/zentinelproxy/zentinel-agent-graphql-security), the same idea for GraphQL APIs
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
