<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# FerroGate

> Developed by the commercial cloud service company represented by
> [Token4AI Cloud](https://token4ai.cloud). Created by jamesduan
> ([X](https://x.com/JamesDuanL)) on 2026-06-11.

**Language:** English | [简体中文](README.zh-CN.md)

FerroGate is an open-source Rust API gateway and AI gateway built on
Cloudflare Pingora. It gives teams a self-hostable control point for LLM
traffic: routing, virtual API keys, provider adapters, exact-match response
cache, MCP tool execution, policy checks, token usage accounting,
observability, admin APIs, cluster operations, and automatic HTTPS.

The project is developed as the open-source gateway foundation behind
[Token4AI Cloud](https://token4ai.cloud).

## What FerroGate Provides

- **Pingora gateway runtime** for HTTP reverse proxying, route matching,
  upstream pools, path/header rewrites, request IDs, tracing IDs, streaming
  responses, graceful shutdown, and listener-level graceful upgrade.
- **OpenAI-compatible AI API** with `GET /v1/models`,
  `POST /v1/chat/completions`, and `POST /v1/responses`, including
  non-streaming and streaming SSE forwarding. See
  [Agent Framework Compatibility](docs/agent-framework-compatibility.md) for
  AutoGen, CrewAI, LangChain, LlamaIndex, Phidata, Control Flow, and custom SDK
  wiring.
- **Provider adapters** for OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, and Grok/xAI.
- **Model registry and fallback routing** with logical model names, provider
  model mapping, priority fallback, weighted fallback, lowest-cost,
  lowest-latency, balanced routing, tenant visibility, and provider allow/deny
  controls.
- **Exact-match AI response cache** for non-streaming requests with global,
  model, and API-key enablement controls. Cache keys include tenant context,
  route, logical model, provider route/model, and normalized request body.
- **MCP gateway support** through `ferrogate-mcp`, with streamable HTTP, SSE,
  and stdio server sessions, startup `initialize` plus `tools/list`, namespaced
  `serverName-toolName` tools, deny-by-default execution allowlists, policy
  targets, admin visibility, health checks, reconnects, and
  `POST /v1/mcp/tool/execute`.
- **Agentic Lite extension surface** with built-in request hooks, tool
  providers, event sinks, `GET /v1/tools`, `POST /v1/tools/execute`, admin tool
  session views, and audit events.
- **Caddy-style config file compatibility** through `Ferrogate/Caddyfile`
  parsing for familiar reverse-proxy routes, matchers, TLS, logging, and
  gateway settings, alongside structured TOML configuration.
- **Virtual API keys and policy checks** with hashed keys, tenant context,
  scopes, disabled/expired keys, model/provider allowlists and denylists,
  minimal deny-rule policy evaluation, request rate limits, and token budgets.
  Full RBAC is served by the optional `ferrogate-auth` REST service rather than
  embedded in the gateway request path.
- **Token usage metering events** using provider-reported usage when
  available, gateway estimates when needed, and a request reservation /
  settlement flow inspired by production AI gateways.
- **Observability** with structured request logs, token metering events,
  configurable in-memory retention, usage aggregates, provider health, cache
  metrics, MCP tool metrics, Prometheus metrics, request/trace ID propagation,
  and OTLP/HTTP metrics/logs/traces export.
- **Admin API and dashboard** for gateway status, providers, models, API keys,
  tenants, policies, request logs, metering events, usage aggregates, audit
  events, gateway config profiles, provider health, extensions, tools, MCP
  servers, config validation, process-local reload, and node drain/readiness.
- **Cluster operations** for multi-node deployments with node identity, shared
  file control-plane state, Redis-backed request and token counters, status,
  readiness, and drain semantics.
- **Automatic HTTPS** with manual TLS, ACME HTTP-01, ACME DNS-01 through a
  built-in Cloudflare provider, renewal scheduling, and graceful-upgrade
  handoff when listener-level TLS reload is required. ACME provider credentials
  are read from the configuration file, not environment variables or Python
  scripts.
- **Supply-chain and security gates** with formatting, clippy, locked metadata,
  high-confidence secret scanning, cargo-deny, cargo-audit, and GitHub Actions.

## Current Status

The open-source gateway implementation now covers the core API gateway, AI
gateway, governance, tool execution, observability, TLS, and cluster operations
needed for a self-hosted first production slice.

Validated end-to-end:

- HTTP reverse proxy runtime on Pingora.
- OpenAI-compatible Chat Completions and Responses API paths.
- Agent framework compatibility for OpenAI-compatible clients using FerroGate
  `base_url`, virtual API keys, logical models, request logs, metering events,
  and Prometheus model/provider metrics.
- Reusable request-time gateway config profiles through `x-ferrogate-config`,
  with cache-policy overrides, API-key allowlists, Admin API visibility, and
  request-log profile evidence.
- Provider adapters and priority, weighted, cost, latency, and balanced routing.
- Virtual API key auth, policy checks, rate limits, and token budget handling.
- Exact-match response cache for non-streaming AI requests.
- Agentic Lite tools and MCP gateway execution through auth, policy, billing,
  audit, and metrics.
- Request logs, token metering events, usage aggregates, provider health, cache
  metrics, MCP tool metrics, Prometheus, and OTLP export.
- Admin API, API key and policy CRUD, static dashboard, config validation,
  process-local reload, status, readiness, and drain.
- Manual TLS, ACME HTTP-01, ACME DNS-01, renewal scheduling, and listener-level
  graceful upgrade handoff.
- Cluster identity, shared file state, Redis counters, readiness, and drain
  runbooks.
- Real Let's Encrypt staging and production issuance for both HTTP-01 and
  Cloudflare DNS-01 during live validation.

Still intentionally scoped as next-stage production work:

- Durable database-backed storage implementations for API keys, tenants, policy,
  billing, request logs, audit logs, and multi-node control-plane state. Current
  runtime state is primarily config, shared file state, Redis counters, and
  in-memory repository driven.
- Full Admin API write control plane beyond the current API key, policy,
  config-validation, reload, and drain resources.
- Semantic/vector cache matching. The implemented cache is exact-match only.
- Expanded DNS provider set beyond the built-in Cloudflare provider and the
  generic external hook boundary.

## Repository Layout

```text
crates/
  ferrogate-cli             CLI, Pingora runtime wiring, gateway handlers
  ferrogate-config          Caddyfile/TOML config model and parser
  ferrogate-providers       AI provider adapters and model registry
  ferrogate-auth            Standalone tenant and RBAC REST API service
  ferrogate-policy          Policy decision models and engine
  ferrogate-storage         Repository traits and in-memory storage
  ferrogate-billing         Token usage metering models and local event retention
  ferrogate-observability   Metrics, spans, exporter contracts
  ferrogate-runtime         Reload and runtime lifecycle state machine
  ferrogate-mcp             MCP host/client manager and tool execution bridge
config/                     Example TOML configuration
Ferrogate/Caddyfile          Default Caddyfile-style development config
scripts/security-check.sh    Local security and supply-chain gate
```

## Quick Start

Prerequisites:

- Rust toolchain compatible with the workspace `rust-version`.
- `cmake`, `g++`, `make`, and `pkg-config` for Pingora's native compression
  dependency chain.

Run the default development gateway:

```bash
cargo run -- run --config Ferrogate/Caddyfile
```

Validate configuration:

```bash
cargo run -- validate --config Ferrogate/Caddyfile
cargo run -- validate --config config/ferrogate.example.toml
```

Probe the gateway:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/proxy/httpbin/get
curl -H 'Authorization: Bearer dev-secret' http://127.0.0.1:8080/v1/models
```

Send an OpenAI-compatible chat request:

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}'
```

Send an OpenAI-compatible Responses API request:

```bash
curl -X POST http://127.0.0.1:8080/v1/responses \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","input":"hello"}'
```

Open the admin dashboard:

```text
http://127.0.0.1:8080/admin
```

## Configuration

FerroGate loads `Ferrogate/Caddyfile` by default. TOML is also supported for
structured self-hosting and tests.

```bash
ferrogate run --config Ferrogate/Caddyfile
ferrogate run --config /etc/ferrogate/ferrogate.toml
```

### Caddyfile Example

```caddyfile
:8080 {
    log

    respond /healthz "ok" 200

    ai_gateway {
        provider openai {
            kind openai-compatible
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }

        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat streaming
            input_price_per_1m 0.15
            output_price_per_1m 0.60
        }

        api_key key_dev {
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions admin.read
            allowed_models fast-chat
            allowed_providers openai
            request_limit_per_minute 60
            monthly_token_budget 1000000
        }
    }

    route /v1/* {
        reverse_proxy https://api.openai.com {
            header_up Authorization "Bearer {env.OPENAI_API_KEY}"
        }
    }
}
```

### TOML Example

```toml
listen = "0.0.0.0:8080"

[admin]
listen = "127.0.0.1:2019"

[telemetry]
access_log = "error"
access_log_sample_rate = 100
access_log_error_rate_limit_per_sec = 100

[metering]
export_enabled = false
export_endpoint = "https://api.token4ai.cloud/v1/metering/events"
# export_token_env = "FERROGATE_METERING_TOKEN"

[storage]
request_log_retention_records = 10000
audit_event_retention_records = 10000
billing_event_retention_records = 10000
admin_list_default_limit = 100
admin_list_max_limit = 1000

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 300
max_records = 1000

[reliability]
provider_circuit_breaker_failure_threshold = 3
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 10
provider_dispatch_max_retries = 1
provider_response_body_max_bytes = 16777216
graceful_shutdown_grace_period_secs = 3
graceful_shutdown_timeout_secs = 15

[[providers]]
name = "openai"
kind = "openai-compatible"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = "0.15"
output_price_per_1m = "0.60"
cache_enabled = true

[[api_keys]]
id = "dev"
key = "dev-secret"
scopes = ["models.read", "tools.read", "tools.execute", "chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
allowed_providers = ["openai"]
request_limit_per_minute = 60
monthly_token_budget = 1000000
cache_enabled = true

[[mcp_servers]]
name = "github"
transport = "streamable_http"
url = "http://127.0.0.1:9000/mcp"
auth_type = "headers"
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
tool_include = ["search"]
timeout_ms = 3000

[[mcp_servers.headers]]
name = "Authorization"
value_env = "GITHUB_MCP_TOKEN"

[[policies]]
name = "deny dev MCP search"
effect = "deny"
enabled = false
api_key_ids = ["dev"]
models = ["mcp_tool:github-search"]
providers = ["mcp:github"]
message = "MCP search is blocked for this key"
```

The first cache mode is `exact_match`. FerroGate only caches non-streaming AI
responses when the tenant context, route, logical model, provider route/model,
and normalized JSON request body are identical. Semantic/vector cache matching
is intentionally not part of this first version.

Reusable gateway config profiles can be selected per request with
`x-ferrogate-config`. The first profile slice supports cache policy overrides
inside the operator's global cache policy; it cannot enable caching when
`[cache].enabled = false`, but it can disable caching for selected workflows.

```toml
[[gateway_configs]]
id = "no-cache-agent"
name = "No-cache agent workflow"
revision = 1
cache_enabled = false
api_key_ids = ["dev"]
```

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -H 'x-ferrogate-config: no-cache-agent' \
  -d '{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}'
```

Profile ID and revision are recorded in request logs as
`gateway_config_id` and `gateway_config_revision`. Operators can inspect
configured profiles with `GET /admin/v1/gateway-configs` and manage them with
the Admin API `POST`, `PUT`/`PATCH`, and `DELETE` profile endpoints.

`[[mcp_servers]]` makes FerroGate an MCP host/client. Each server is connected
as a long-lived session at startup or reload, initialized with `initialize` plus
`tools/list`, and health checked in the background. Tool names are exposed as
`serverName-toolName`, so the example server exposes `github-search`. Execution
is deny-by-default: every server must declare `tools_to_execute`, and
`POST /v1/mcp/tool/execute` still runs through gateway auth, policy, billing,
and observability. Policy targets use `models = ["mcp_tool:github-search"]` and
`providers = ["mcp:github"]`.

For production, prefer `key_hash` generated by `ferrogate hash-key` over plain
development keys.

```bash
ferrogate hash-key --secret 'your-client-secret'
```

For multi-node cluster mode, set `cluster.counter_backend = "redis"` with
`cluster.redis_url` to enforce API-key request limits and token-budget
reservation/settlement across gateway replicas. Redis counters are fail-closed:
if the counter backend is unavailable, guarded AI requests return a governance
backend error instead of falling back to per-process counters.

For the full Kubernetes-first, not Kubernetes-only cluster deployment contract,
including readiness, drain, shared state, Redis counters, checked-in manifests,
the optional Helm chart, and non-Kubernetes paths, see
[Cluster Deployment](docs/cluster-deployment.md).

### OpenRouter Provider

OpenRouter is available as a first-class provider kind while using the same
OpenAI-compatible chat completions and Responses API dispatch path.

```toml
[[providers]]
name = "openrouter"
kind = "openrouter"
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"
openrouter_http_referer = "https://example.com"
openrouter_x_title = "Example FerroGate"

[[models]]
name = "router-chat"
provider = "openrouter"
provider_model = "openai/gpt-4o-mini"
capabilities = ["chat", "streaming"]
```

The optional `openrouter_http_referer` and `openrouter_x_title` settings are
sent upstream as `HTTP-Referer` and `X-Title` headers. They are not client API
keys and do not replace `api_key_env`.

Caddyfile-style provider configuration supports the same fields:

```caddyfile
ai_gateway {
    provider openrouter {
        kind openrouter
        base_url https://openrouter.ai/api/v1
        api_key {env.OPENROUTER_API_KEY}
        openrouter_http_referer https://example.com
        openrouter_x_title Example FerroGate
    }

    model router-chat -> openrouter:openai/gpt-4o-mini {
        capabilities chat streaming
    }
}
```

## Automatic HTTPS

FerroGate supports manual TLS certificates, startup-time ACME issuance, and
background ACME renewal scheduling.

### Manual TLS

```toml
[tls]
enabled = true
cert_path = "/etc/ferrogate/certs/fullchain.pem"
key_path = "/etc/ferrogate/certs/privkey.pem"
http2 = true
```

### ACME HTTP-01

HTTP-01 requires public inbound access to port 80 for the challenge and port
443 for HTTPS service.

```toml
listen = "0.0.0.0:443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "http-01"
http_challenge_listen = "0.0.0.0:80"
storage_dir = "/var/lib/ferrogate/acme-http"
renewal_window_secs = 2592000
renewal_check_interval_secs = 43200
renewal_retry_interval_secs = 1800
auto_graceful_reload = true
```

### ACME DNS-01 With Built-In Cloudflare

DNS-01 does not require public port 80 and is required for wildcard
certificates. Cloudflare credentials are configured in the FerroGate config
file.

```toml
listen = "0.0.0.0:443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "dns-01"
storage_dir = "/var/lib/ferrogate/acme-dns"
dns_provider = "cloudflare"
dns_config = { api_token = "cf-token", zone_name = "example.com" }
dns_propagation_delay_secs = 30
renewal_window_secs = 2592000
renewal_check_interval_secs = 43200
renewal_retry_interval_secs = 1800
auto_graceful_reload = true
```

Caddyfile-style DNS-01:

```caddyfile
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        storage /var/lib/ferrogate/acme-dns
        renewal_window_secs 2592000
        renewal_check_interval_secs 43200
        renewal_retry_interval_secs 1800
        auto_graceful_reload true
        dns cloudflare {
            api_token cf-token
            zone_name example.com
        }
    }
}
```

FerroGate also keeps a provider-neutral external hook boundary for DNS
providers that are not built in. Hooks receive a 0600 JSON payload file path and
are invoked as:

```text
<hook> <set|cleanup> <payload-json-path>
```

When ACME is enabled, FerroGate starts a background renewal loop after the
startup certificate has been issued or loaded from cache. Renewal starts when
the leaf certificate enters `renewal_window_secs` before expiry, failed renewal
attempts are logged and retried after `renewal_retry_interval_secs`, and current
certificate expiry plus the last renewal result are exposed on
`GET /admin/v1/status`.

With the Rustls listener used by the current Pingora runtime, renewed certificate
files require listener-level reload before new TLS handshakes use them. If
`auto_graceful_reload = true` and `reliability.graceful_upgrade_pid_file` plus
`reliability.graceful_upgrade_sock` are configured, FerroGate triggers the
existing graceful-upgrade reload path after a successful renewal. Otherwise,
admin status reports `reload_required: true` and `reload_mode:
"listener-level-required"` so operators can run `ferrogate reload --graceful-upgrade`.

## Reloading

Validate-only reload report:

```bash
ferrogate reload --config Ferrogate/Caddyfile
```

Process-local reload through a running Admin API:

```bash
ferrogate reload \
  --config Ferrogate/Caddyfile \
  --admin-url http://127.0.0.1:8080 \
  --admin-token "$FERROGATE_ADMIN_TOKEN"
```

Listener-level reload through Pingora graceful upgrade:

```bash
ferrogate reload --config Ferrogate/Caddyfile --graceful-upgrade
```

Process-local reload is used only when the listen socket and TLS listener
fingerprint do not change. Listener/TLS changes require graceful upgrade.

## Admin API

The checked-in OpenAPI 3.1 document for the Admin API lives at
[`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json).

Common endpoints:

```text
GET  /v1/models
GET  /v1/tools
POST /v1/tools/execute
POST /v1/mcp/tool/execute
POST /v1/chat/completions
POST /v1/responses
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/extensions
GET  /admin/v1/tools
GET  /admin/v1/mcp-servers
GET  /admin/v1/tool-sessions/{session_id}
GET  /admin/v1/models
GET  /admin/v1/gateway-configs
GET  /admin/v1/gateway-configs/{id}
POST /admin/v1/gateway-configs
PUT  /admin/v1/gateway-configs/{id}
DELETE /admin/v1/gateway-configs/{id}
GET  /admin/v1/api-keys
GET  /admin/v1/api-keys/{id}
POST /admin/v1/api-keys
PUT  /admin/v1/api-keys/{id}
DELETE /admin/v1/api-keys/{id}
GET  /admin/v1/tenants
GET  /admin/v1/policies
GET  /admin/v1/policies/{name}
POST /admin/v1/policies
PUT  /admin/v1/policies/{name}
DELETE /admin/v1/policies/{name}
GET  /admin/v1/request-logs
GET  /admin/v1/metering-events
GET  /admin/v1/billing-events  # compatibility alias
GET  /admin/v1/usage-aggregates
GET  /admin/v1/audit-events
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /admin/v1/drain
POST /admin/v1/drain
DELETE /admin/v1/drain
GET  /metrics
GET  /admin
```

Read endpoints require `admin.read` when API keys are configured. Tool listing
requires `tools.read`, explicit tool execution requires `tools.execute`, chat
completions require `chat.completions`, Responses API requests require
`responses.create`, and config validation and reload require `admin.write`.

## Tenant and RBAC Service

FerroGate does not make the gateway process the source of truth for RBAC. The
gateway resolves API keys into tenant context and gateway scopes, then can call
an external authorization service for tenant/RBAC decisions. The bundled
`ferrogate-auth` binary is that standalone service boundary and can also be
started through the main CLI:

```bash
ferrogate-auth serve --listen 127.0.0.1:8090 --data auth-data.yaml
ferrogate auth serve --listen 127.0.0.1:8090 --data auth-data.yaml
```

The service exposes JSON REST endpoints:

```text
GET  /healthz
GET  /v1/healthz
GET  /v1/tenants
POST /v1/auth/resolve-api-key
POST /v1/auth/authorize
```

`POST /v1/auth/resolve-api-key` returns tenant context, subject identity, and
gateway scopes. `POST /v1/auth/authorize` accepts tenant context, subject,
action, and resource, then returns an allow/deny decision. This keeps third-party
RBAC implementations pluggable without forcing their role and permission model
into the gateway.

## Docker

Stable releases use date-based tags such as `v2026.06.07`.

Pull the published GitHub Packages image and run it with a mounted config:

```bash
docker pull ghcr.io/lianluo-esign/ferrogate:v2026.06.07

docker run --rm \
  -p 8080:8080 \
  -v "$PWD/config/ferrogate.example.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.06.07
```

Build a local image when developing Docker changes:

```bash
docker build -t ferrogate .
```

For two or more Docker, VM, ECS/Fargate, Nomad, or Kubernetes replicas, follow
the cluster deployment runbook instead of relying on Docker alone for gateway
state consistency. Docker runs the process; FerroGate cluster mode owns shared
state revisioning, readiness, drain, and distributed counters.

Kubernetes examples are checked in under `deploy/kubernetes/`, and an optional
Helm chart is available under `charts/ferrogate/`:

```bash
scripts/check-kubernetes-examples.sh
helm template ferrogate charts/ferrogate
```

For automatic HTTPS, publish the relevant ports and mount ACME storage:

```bash
docker run --rm \
  -p 80:80 \
  -p 443:443 \
  -v /etc/ferrogate/ferrogate.toml:/etc/ferrogate/ferrogate.toml:ro \
  -v /var/lib/ferrogate/acme:/var/lib/ferrogate/acme \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.06.07
```

## Quality And Security

Run the local gate before committing:

```bash
./scripts/security-check.sh
```

Strict mode requires cargo-deny and cargo-audit:

```bash
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

Install the supply-chain tools:

```bash
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.1 --locked
```

The security gate runs:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo metadata --locked`
- high-confidence secret scanning
- `cargo deny check licenses bans sources`
- `cargo audit`

Known residual audit warnings are documented in `.cargo/audit.toml` and the
development plan. They currently come from Pingora transitive dependencies and
are monitored separately from direct FerroGate code.

## Documentation

- Project roadmap: [`docs/roadmap.md`](docs/roadmap.md)
- Cluster deployment guide: [`docs/cluster-deployment.md`](docs/cluster-deployment.md)
- Admin API OpenAPI:
  [`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json)
- Performance testing guide:
  [`docs/performance-testing.md`](docs/performance-testing.md)
- Example TOML configuration:
  [`config/ferrogate.example.toml`](config/ferrogate.example.toml)
- Default Caddyfile-style configuration:
  [`Ferrogate/Caddyfile`](Ferrogate/Caddyfile)

Internal development planning notes are maintained outside this product
repository.

## Contributing

FerroGate is built for human maintainers and AI coding agents working together.
The best contributions are small, issue-linked slices that can be reviewed,
tested, and explained from the operator's point of view.

Good first contribution areas:

- Provider adapters, model registry coverage, routing strategies, fallback, and
  streaming correctness.
- Policy, virtual API keys, rate limits, token budgets, metering, audit, and
  request-log evidence.
- MCP gateway behavior, Agentic Lite tools, OpenAI-compatible client
  compatibility, and examples for agent frameworks.
- Admin API, dashboard visibility, OpenAPI schema coverage, config validation,
  reload behavior, and cluster operations.
- Documentation that makes an implemented runtime path usable in production.

Development workflow:

1. Start from a GitHub issue. If the change does not clearly map to an issue,
   open or identify one before writing code.
2. Define the end-to-end proof before editing: operator input, gateway runtime
   path, failure behavior, admin/log/metric evidence, and focused regression
   tests.
3. Read the existing code path first. Keep behavior in the owning crate:
   `ferrogate-cli` for runtime and handlers, `ferrogate-config` for config
   parsing, `ferrogate-providers` for provider quirks, `ferrogate-policy` for
   policy decisions, `ferrogate-storage` for repository contracts,
   `ferrogate-billing` for usage records, and `ferrogate-observability` for
   metrics and spans.
4. Keep the patch narrow. Prefer deletion, reuse, and typed validation over new
   abstractions. Do not add dependencies unless they remove real complexity or
   are required by the issue.
5. For AI-agent-authored work, leave enough context for humans to review:
   mention the issue, the files touched, the runtime path exercised, commands
   run, and any known gaps. Do not submit broad, unverified rewrites.

Verification expectations:

- Documentation-only changes should at least pass `git diff --check`.
- Rust changes should run focused tests for the touched path, then the relevant
  workspace gate:

  ```bash
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace
  ```

- Config, OpenAPI, deployment, security, streaming, billing, or runtime reload
  changes need the matching schema, E2E, or security check. The local security
  gate is:

  ```bash
  ./scripts/security-check.sh
  ```

Pull request checklist:

- Link the GitHub issue and state whether the PR closes it or implements one
  bounded slice of a larger epic.
- Describe the operator-visible behavior, not just the internal refactor.
- Include exact verification commands and results.
- Update README, OpenAPI, deployment docs, examples, or runbooks when behavior,
  configuration, operations, or architecture changes.
- Do not commit provider secrets, ACME tokens, private keys, generated
  certificates, or local runtime state.

For autonomous issue selection and AI-agent execution, follow
[`docs/dynamic-workflow.md`](docs/dynamic-workflow.md). That workflow is the
project contract for choosing the next issue, closing a narrow E2E slice,
recording evidence, and updating GitHub without turning broad roadmap items into
unreviewable rewrites.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
