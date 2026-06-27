<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# FerroGate

**Language:** English | [简体中文](README.zh-CN.md)

FerroGate is an open-source Rust API gateway and AI gateway built on
Cloudflare Pingora. It gives teams a self-hostable control point for AI traffic:
OpenAI-compatible APIs, provider routing, virtual API keys, policy checks,
token accounting, MCP/tool execution, opt-in agent runs, WASM sandboxed agent
execution, observability, Admin APIs, cluster operations, and automatic HTTPS.

The project is developed as the open-source gateway foundation behind
[Token4AI Cloud](https://token4ai.cloud).

For the longer capability inventory and current implementation status, read the
[Product Overview](docs/product-overview.md).

## Highlights

- **OpenAI-compatible gateway:** `GET /v1/models`,
  `POST /v1/chat/completions`, and `POST /v1/responses`, including streaming
  SSE forwarding.
- **Provider orchestration:** OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, and Grok/xAI with logical models and fallback
  routing.
- **Governance:** virtual API keys, scopes, tenant context, allow/deny rules,
  request rate limits, token budgets, and exact-match response caching.
- **Agent and tool traffic:** MCP host/client support, native `POST /v1/mcp`
  JSON-RPC ingress, explicit `POST /v1/agent-runs`, governed tool execution,
  plugin registration, opt-in WASM sandbox execution, and audit events.
- **Operator visibility:** request logs, usage and metering events, provider
  health, cache/tool metrics, agent run timelines, structured agent-run OTLP
  spans, Prometheus, OTLP export, Admin API, and dashboard.
- **Production operations:** durable control-plane storage options, analytics
  warehouse delivery, reload/drain readiness, cluster counters, Docker,
  Kubernetes manifests, Helm chart, and ACME HTTPS.

## Quick Start

Prerequisites:

- Rust toolchain compatible with the workspace `rust-version`.
- `cmake`, `g++`, `make`, and `pkg-config` for Pingora's native dependency
  chain.

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

Send a Responses API request:

```bash
curl -X POST http://127.0.0.1:8080/v1/responses \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","input":"hello"}'
```

Open the local dashboard:

```text
http://127.0.0.1:8080/admin
```

## Agentic Gateway

FerroGate supports explicit agent traffic without turning every AI request into
an agent loop. Normal Chat Completions and Responses calls keep their existing
behavior; agent execution is opt-in through agent runtime, upstream, workflow,
skill, prompt, and plugin control-plane surfaces.

Implemented agentic gateway surfaces include:

- Agent discovery through `/.well-known/agent.json` and visible skill packages
  through `GET /v1/skills` and `GET /v1/skills/{id}`.
- Governed A2A-style agent upstreams with tenant/API-key visibility,
  `agents.read`/`agents.invoke` scopes, request forwarding, and streaming
  forwarding for `message:stream` paths.
- Explicit `POST /v1/agent-runs` execution with max-turn and timeout limits.
- Default, external-process, and configured Wasmtime-backed agent providers.
- Deny-by-default WASM execution with fuel and timeout bounds, no ambient
  WASI/network/filesystem access, and an optional host ABI for
  `ferrogate.log`, `ferrogate.state_get`, `ferrogate.state_set`, and
  `ferrogate.tool_dispatch`.
- Workflow graph policies with model/tool nodes, edge conditions, model-call
  and tool-call budgets, token budgets, iteration limits, counters, and runtime
  timelines.
- Skill packages that can bundle visible capabilities and materialize owned
  plugins, tools, MCP servers, prompt templates, and workflows.
- Versioned prompt templates with audited `POST /v1/prompts/{id}/render`
  output for Chat Completions or Responses request bodies.
- Plugin registration and plugin-owned tool exposure with permissions, approval
  policy, secret redaction, lifecycle status, and Admin API inspection.
- Tool calls from agent runs and WASM host ABI dispatch go through the same
  gateway governance path as ordinary tool execution: auth, scopes, policy,
  approvals, billing, and audit evidence.
- Durable `agent_run` and `agent_run_event` records, plus
  `GET /admin/v1/agent-runs` and `GET /admin/v1/agent-runs/{run_id}` timelines
  for request, billing, audit, tool, and run-event evidence.
- Agent run timelines export as structured OTLP traces with
  `ferrogate.agent.run`, provider-step, billing-write, audit/tool, and WASM
  host-ABI spans, while preserving W3C trace context for external correlation.

## Configuration

FerroGate loads `Ferrogate/Caddyfile` by default. Structured TOML and YAML
configuration are also supported.

```bash
ferrogate run --config Ferrogate/Caddyfile
ferrogate run --config config/ferrogate.example.toml
```

Minimal Caddyfile-style AI gateway shape:

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
        }

        api_key key_dev {
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions responses.create admin.read
            allowed_models fast-chat
            allowed_providers openai
        }
    }
}
```

Use these as the main configuration references:

- Default development config: [`Ferrogate/Caddyfile`](Ferrogate/Caddyfile)
- Full TOML example: [`config/ferrogate.example.toml`](config/ferrogate.example.toml)
- Durable storage: [`docs/durable-storage.md`](docs/durable-storage.md)
- Analytics warehouse: [`docs/analytics-warehouse.md`](docs/analytics-warehouse.md)
- Cluster deployment: [`docs/cluster-deployment.md`](docs/cluster-deployment.md)

For production client secrets, prefer hashed API keys:

```bash
ferrogate hash-key --secret 'your-client-secret'
```

## Core Modules

```text
crates/
  ferrogate-cli             CLI, Pingora runtime wiring, gateway handlers
  ferrogate-config          Caddyfile/TOML/YAML config model and parser
  ferrogate-providers       AI provider adapters and model registry
  ferrogate-auth            Standalone tenant and RBAC REST API service
  ferrogate-policy          Policy decision models and engine
  ferrogate-storage         Repository traits and control-plane storage boundary
  ferrogate-billing         Token usage metering models and local event retention
  ferrogate-observability   Metrics, spans, exporter contracts
  ferrogate-runtime         Reload, lifecycle, bounded agent harness, WASM sandbox
  ferrogate-mcp             MCP host/client manager and tool execution bridge
```

## Docker And Deployment

Run a published image with a mounted config:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/config/ferrogate.example.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:<tag>
```

Build locally when changing image contents:

```bash
docker build -t ferrogate .
```

Kubernetes examples and the optional Helm chart are checked in under
[`deploy/kubernetes/`](deploy/kubernetes/) and [`charts/ferrogate/`](charts/ferrogate/).
Validate them with:

```bash
scripts/check-kubernetes-examples.sh
helm template ferrogate charts/ferrogate
```

## Admin API

The checked-in OpenAPI 3.1 document lives at
[`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json).

Common runtime and admin surfaces:

```text
GET  /v1/models
POST /v1/chat/completions
POST /v1/responses
POST /v1/agent-runs
GET  /.well-known/agent.json
GET  /v1/skills
GET  /v1/skills/{id}
POST /v1/prompts/{id}/render
GET  /v1/tools
POST /v1/tools/execute
POST /v1/mcp
POST /v1/mcp/tool/execute
GET  /admin/v1/agent-runs
GET  /admin/v1/agent-runs/{run_id}
GET  /admin/v1/agent-upstreams
GET  /admin/v1/agent-upstreams/{id}
GET  /admin/v1/agent-workflows
GET  /admin/v1/agent-workflows/{id}
GET  /admin/v1/skill-packages
GET  /admin/v1/skill-packages/{id}
GET  /admin/v1/prompt-templates
GET  /admin/v1/prompt-templates/{id}
GET  /admin/v1/plugins
GET  /admin/v1/plugins/{plugin_id}
GET  /admin/v1/plugins/{plugin_id}/tools
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/request-logs
GET  /admin/v1/metering-events
GET  /admin/v1/usage-aggregates
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /metrics
GET  /admin
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

For narrower local checks:

```bash
cargo fmt --all -- --check
cargo metadata --locked --format-version=1
python3 scripts/check-openapi.py
git diff --check
```

## Documentation

- Product overview and status: [`docs/product-overview.md`](docs/product-overview.md)
- Agent framework compatibility: [`docs/agent-framework-compatibility.md`](docs/agent-framework-compatibility.md)
- Durable storage: [`docs/durable-storage.md`](docs/durable-storage.md)
- Analytics warehouse: [`docs/analytics-warehouse.md`](docs/analytics-warehouse.md)
- Cluster deployment: [`docs/cluster-deployment.md`](docs/cluster-deployment.md)
- Auth service contract: [`docs/auth-service-contract.md`](docs/auth-service-contract.md)
- Performance testing: [`docs/performance-testing.md`](docs/performance-testing.md)
- Roadmap: [`docs/roadmap.md`](docs/roadmap.md)

## Contributing

FerroGate is built for human maintainers and AI coding agents working together.
The best contributions are small, issue-linked slices that can be reviewed,
tested, and explained from the operator's point of view.

Good contribution areas:

- Provider adapters, model registry coverage, routing strategies, fallback, and
  streaming correctness.
- Policy, virtual API keys, rate limits, token budgets, metering, audit, and
  request-log evidence.
- MCP gateway behavior, Agentic Lite tools, OpenAI-compatible client
  compatibility, and examples for agent frameworks.
- Admin API, dashboard visibility, OpenAPI schema coverage, config validation,
  reload behavior, and cluster operations.
- Documentation that makes an implemented runtime path usable in production.

Workflow:

1. Start from a GitHub issue.
2. Define the end-to-end proof before editing: operator input, runtime path,
   failure behavior, admin/log/metric evidence, and focused regression tests.
3. Keep behavior in the owning crate; avoid cross-cutting rewrites.
4. Keep patches narrow, typed, reversible, and dependency-light.
5. Include exact verification commands and known gaps in the PR.

For autonomous issue selection and AI-agent execution, follow
[`docs/dynamic-workflow.md`](docs/dynamic-workflow.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
