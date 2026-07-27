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
OpenAI-compatible and Anthropic-native APIs, multi-vendor provider routing,
virtual API keys, policy checks, token accounting settled against a standalone
billing service, MCP/tool execution, opt-in agent runs and schedules, isolated
`agent-worker` execution (managed or self-hosted over verified mTLS), a hosted
asset closed loop for agent-consumable artifacts and static sites,
observability, Admin APIs, cluster operations, and automatic HTTPS.

The project is developed as the open-source gateway foundation behind
[Token4AI Cloud](https://token4ai.cloud).

For the longer capability inventory and current implementation status, read the
[Product Overview](docs/product-overview.md).

## Where the project is going

Three directions are actively shaping the codebase. They are stated here
because they change what a contributor should build *toward*, not just what
exists today.

**1. Cloudflare-native as a first-class deployment target.** Beyond using
Pingora as the proxy core, FerroGate is growing a real Cloudflare runtime: a
shared [`ferrogate-cloudflare`](crates/ferrogate-cloudflare) client, D1 as a
control-plane backend, R2 for asset storage, Secrets Store (`cf://`) for
credential resolution, and Workers under [`workers/`](workers) — including an
agent-gateway that runs agent workloads in Containers. Self-hosting on your own
infrastructure remains fully supported; Cloudflare becomes an alternative
substrate rather than a replacement. See
[`docs/cloudflare-integration.md`](docs/cloudflare-integration.md) and
[`docs/cloudflare-deploy-topology.md`](docs/cloudflare-deploy-topology.md).

**2. Every privileged action is attributable.** The gateway is meant to be
auditable end to end, not only authenticated. That means a canonical action
identity and fingerprint shared between the runtime and the CLI, a decision
receipt on every mutating CLI verb (actor, target fingerprint, policy decision,
dry-run flag, rollback pointer, audit id — and an explicit `null` with a stated
reason where the control plane does not yet return one), and client-side
attribution on every API call. Fields that cannot be determined are rendered
absent with a reason rather than guessed: **a wrong value in an audit trail is
worse than a missing one.**

**3. Explicit tenancy over implicit defaults.** Platform-root authority is
becoming something an operator writes down rather than something an omitted
field grants, and tenant scoping is enforced at one chokepoint per seam rather
than per handler. Work in this direction treats a silently-permissive default
as a defect in its own right.

## Highlights

- **Multi-protocol inference gateway:** `GET /v1/models`,
  `POST /v1/chat/completions`, `POST /v1/responses`, Anthropic-native
  `POST /v1/messages`, `POST /v1/embeddings`, and
  `POST /v1/images/generations`, including streaming SSE forwarding.
- **Provider orchestration:** OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, and Grok/xAI with logical models, fallback
  routing, and canary plus shadow/mirror traffic splitting for model
  rollouts. Ships a ready-to-run [token4ai.cloud](https://token4ai.cloud)
  example (`config/ferrogate.token4ai.example.toml`) serving gpt-5.5 through
  the same OpenAI-compatible adapter.
- **Governance:** virtual API keys, scopes, tenant context, allow/deny rules,
  request rate limits, token budgets with local tokenizer pre-request
  estimation, wallet reserve/hold for exact-amount spends, and exact-match
  plus opt-in semantic (vector-similarity) response caching.
- **Asset hosting closed loop:** publish, govern, and agent-consume artifacts
  through `/v1/assets/*` — versioned assets with channels/semver and
  platform variants, signature and malware-scan supply-chain gates, MCP
  `resources/*` ingress plus a built-in `fetch_asset` tool for agent
  consumption, static-site serve mode at `GET /sites/{tenant}/{site}/{path}`
  with ETag/Range/304 caching, a presigned large-file path against a private
  S3-compatible bucket (Supabase Storage), egress metering/audit,
  retention/GC lifecycle policies, and a `ferrogate assets` push/pull CLI.
- **Service decomposition:** `ferrogate auth serve` and `ferrogate billing
  serve` run tenant/RBAC and token-usage settlement as independent REST
  services from the same binary, each with an optional durable Supabase
  backend — a durable, dead-letter-tracked outbox delivers settled usage from
  the gateway to the billing service without blocking the request hot path.
- **Agent and tool traffic:** MCP host/client support, native `POST /v1/mcp`
  JSON-RPC ingress on the MCP 2026-07-28 spec, explicit `POST /v1/agent-runs`,
  cron/interval agent schedules with an admin CRUD API, governed A2A ingress
  with policy/guardrails/billing on message bodies, governed tool execution,
  plugin registration, an isolated `agent-worker` process for
  Firecracker-backed execution — self-hosted workers connect over verified
  mTLS with control-plane cert issuance and CRL revocation — and audit
  events.
- **Governed CLI:** `ferrogate ctl` covers the Admin API resource families
  under an OpenAPI-to-CLI parity gate, and every *mutating* verb returns a
  decision receipt rather than a bare response body — actor, target
  fingerprint (byte-identical to the runtime's `CanonicalCapabilityTarget`
  contract), policy decision, `--dry-run` state, rollback pointer and audit id.
  The receipt shape is enforced by the command registry at compile time, and a
  dry run provably issues no state-changing request.
- **Operator visibility:** request logs, usage and metering events, provider
  health, cache/tool metrics, agent run timelines, structured agent-run OTLP
  spans, Prometheus, OTLP export, Admin API, and dashboard. Where a signal
  cannot be read, the surface reports *unknown* rather than a confident
  negative — a presence-store outage does not render as "not running".
- **Production operations:** durable control-plane storage options, a
  retention engine with per-tenant TTL/purge for request logs and audit
  events, analytics warehouse delivery, reload/drain readiness, cluster
  counters, Docker, Kubernetes manifests, Helm chart, and ACME HTTPS.

## Quick Start

Prerequisites:

- Rust toolchain compatible with the workspace `rust-version`.
- `cmake`, `g++`, `make`, and `pkg-config` for Pingora's native dependency
  chain.

`ferrogate` is one binary whose subcommand selects which service process
runs. `run` (below) starts the AI gateway itself; the standalone `auth serve`
and `billing serve` services are covered under
[Service Decomposition](#service-decomposition).

Run the default development gateway:

```bash
cargo run -- run --config Ferrogate/Caddyfile
```

`Ferrogate/Caddyfile` ships with one model (`fast-chat` → OpenAI's
`gpt-4o-mini`) and one development API key (`dev-secret`, real request
auth — a wrong key is rejected). Set `OPENAI_API_KEY` first if you want an
actual completion; without it, requests still route correctly and fail with
a clean 401 from OpenAI.

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

Run the billing service alongside the gateway to see settled usage land in a
durable ledger — each is its own process, started with its own subcommand
(full explanation, including the fail-closed pricing rule, under
[Service Decomposition](#service-decomposition)):

```bash
FERROGATE_BILLING_LISTEN=127.0.0.1:8092 cargo run -- billing serve &
TOKEN4AI_API_KEY=sk-... cargo run -- gateway --config config/ferrogate.token4ai.example.toml

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'authorization: Bearer client-secret' -H 'content-type: application/json' \
  -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}'

curl -s http://127.0.0.1:8092/v1/billing/ledger
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
- Managed agent runtime contract that defaults to an external `agent-worker`
  process owning Firecracker microVM lifecycle. The gateway records policy,
  quota, template selection, capability-envelope, and evidence state; it does
  not run the microVM in the request handler.
- Explicit external-process provider support for local tests and harness
  adapters. Production managed execution should go through `agent-worker` and
  Firecracker microVM isolation.
- A standalone `agent-worker` process boundary that owns Firecracker microVM
  lifecycle, framework-handler adapters (Codex, Claude Code, Hermes), and
  gateway-authorized governed execution of CLI, tool, MCP tool, skill, memory,
  secret, network-egress, browser, REST, and filesystem actions. A shared
  `--worker-type cloud|self-hosted` flag selects the trust/enforcement policy
  on one binary; self-hosted workers run covered command families in
  report-only mode, connect to the gateway's production ingress over verified
  mTLS (single explicit issuing CA, control-plane certificate issuance,
  rotation, and CRL revocation), and poll dispatched runs through
  `/v1/self-hosted-workers/*`. See
  [`docs/security/self-hosted-mtls-transport.md`](docs/security/self-hosted-mtls-transport.md).
- Time-based agent schedules: cron/interval triggers fire `agent_run` targets
  into the same dispatch lease queue self-hosted workers poll, managed
  through `/admin/v1/agent-schedules` CRUD, `run-now`, and per-schedule fire
  history.
- Workflow graph policies with model/tool nodes, edge conditions, model-call
  and tool-call budgets, token budgets, iteration limits, counters, and runtime
  timelines.
- Skill packages that can bundle visible capabilities and materialize owned
  plugins, tools, MCP servers, prompt templates, and workflows.
- Versioned prompt templates with audited `POST /v1/prompts/{id}/render`
  output for Chat Completions or Responses request bodies.
- Plugin registration and plugin-owned tool exposure with permissions, approval
  policy, secret redaction, lifecycle status, and Admin API inspection.
- Tool calls from agent runs go through the same gateway governance path as
  ordinary tool execution: auth, scopes, policy, approvals, billing, and audit
  evidence.
- Durable `agent_run` and `agent_run_event` records, plus
  `GET /admin/v1/agent-runs` and `GET /admin/v1/agent-runs/{run_id}` timelines
  for request, billing, audit, tool, and run-event evidence.
- Agent run timelines export as structured OTLP traces with
  `ferrogate.agent.run`, provider-step, billing-write, audit/tool, and runtime
  lifecycle spans, while preserving W3C trace context for external correlation.

## Configuration

FerroGate loads `Ferrogate/Caddyfile` by default today. Structured TOML and
YAML configuration are also supported — the loader dispatches on the file
extension.

> **Direction:** a purpose-built **YAML** schema is becoming the primary
> configuration format, and the Caddyfile dialect is being retired. The system
> has outgrown what that dialect expresses well — optional nested records,
> tri-state flags where `null` is meaningful, and unset-versus-explicit-zero
> distinctions all need a bespoke line in the Caddyfile mapping layer. New
> configuration surfaces should be designed against the YAML schema. The
> Caddyfile examples below still work and will keep working through a stated
> deprecation window.

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

## Service Decomposition

`ferrogate` is one binary with subcommands that select which service process
runs, rather than separate binaries per service:

- `ferrogate run` (alias `gateway`) — the Pingora AI gateway.
- `ferrogate auth serve` — the tenant/RBAC REST API, optionally backed by
  Supabase for durable virtual API keys. See
  [`docs/auth-service-contract.md`](docs/auth-service-contract.md).
- `ferrogate billing serve` — the token-usage pricing and ledger REST API,
  in-memory by default or durable via `--supabase-dsn`.
- `ferrogate control-api serve` — the standalone **FerroGate Control Plane
  API** service: a dedicated, fail-closed authenticated listener that proxies
  the path-compatible `/admin/v1/*` (+ `/v1/assets/*`) surface to the gateway,
  so control-plane traffic never rides the AI data-plane listener. Configured
  under `[control_api]`. `ferrogate admin-api serve` and the `[admin_api]`
  section remain a deprecated compatibility alias for the migration window.
  See [`docs/admin-api-service.md`](docs/admin-api-service.md).
- `ferrogate storage migrate-to-supabase` — one-shot migration of legacy
  Postgres control-plane state into Supabase.

Point the gateway at a running billing service with a `[billing_service]`
config section (`enabled`, `endpoint`, `timeout_millis`, optional
`token`/`token_env`). When enabled, config validation fails closed unless every
model (and fallback route) carries `input_price_per_1m`/`output_price_per_1m`,
so monthly budget enforcement can never silently diverge from the billing
service's own ledger. The gateway then reports each settled usage event to the
billing service fire-and-forget — the billing round trip never blocks the
request hot path — and a durable, dead-letter-tracked outbox re-delivers on
failure.

Try the full loop with the token4ai.cloud (gpt-5.5) example:

```bash
FERROGATE_BILLING_LISTEN=127.0.0.1:8092 cargo run -- billing serve
TOKEN4AI_API_KEY=sk-... cargo run -- gateway --config config/ferrogate.token4ai.example.toml

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'authorization: Bearer client-secret' -H 'content-type: application/json' \
  -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}'

curl -s http://127.0.0.1:8092/v1/billing/ledger
```

Note that `GET /v1/billing/ledger` belongs to the standalone billing service's
own port (`8092` above), not to the gateway's `/admin` or `/v1` surface.

The admin console (`admin-console/`) is a standalone deployable: a
static React SPA, not a `ferrogate` subcommand. It calls `ferrogate auth
serve`'s `/v1/admin/*` endpoints for login/registration and, for everything
else, the dedicated `ferrogate control-api serve` FerroGate Control Plane API
service (issue #359, formerly `admin-api serve` from #315) when
`ADMIN_API_BASE_URL` is set — falling back to the gateway's own
`/admin/v1/*` surface (`GATEWAY_ADMIN_BASE_URL`) for backward
compatibility. Both calls are cross-origin, so configure CORS for whatever
origin the console is served from (the auth service's
`--cors-allowed-origin` / `FERROGATE_AUTH_CORS_ALLOWED_ORIGIN`, plus
`control_api.cors_allowed_origin` — or the deprecated `admin_api.cors_allowed_origin` —
and the gateway's `admin.cors_allowed_origin` config fields). See
[`admin-console/README.md`](admin-console/README.md) to run it locally.

## Core Modules

```text
crates/
  agent-worker              Standalone process for isolated agent execution:
                             Firecracker microVMs, framework-handler adapters,
                             governed CLI/tool/MCP/browser/REST/filesystem actions
  ferrogate-admin           Scaffolding for a future dedicated admin-API service;
                             not yet wired into any binary
  ferrogate-auth            Standalone tenant and RBAC REST API service
  ferrogate-billing         Standalone billing service: rate cards, ledger
                             charging, durable outbox delivery
  ferrogate-cli             CLI, Pingora runtime wiring, gateway/auth/billing/
                             storage subcommands, gateway handlers
  ferrogate-config          Caddyfile/TOML/YAML config model and parser
  ferrogate-core            Shared domain primitives (tenant/request context,
                             tool definitions, error types) used across crates
  ferrogate-mcp             MCP host/client manager and tool execution bridge
  ferrogate-observability   Metrics, spans, exporter contracts
  ferrogate-policy          Policy decision models and engine
  ferrogate-providers       AI provider adapters and model registry
  ferrogate-routing         Scaffolding for a future shared route-matching
                             boundary; not yet consumed by the runtime
  ferrogate-runtime         Reload, lifecycle, bounded harness, managed worker
                             isolation
  ferrogate-storage         Repository traits and control-plane storage
                             boundary (in-memory, Postgres, Supabase)
tools/
  ferrogate-test            End-to-end test harness driving admin/auth/gateway/
                             billing/storage scenarios locally and via Docker

admin-console/               Standalone admin console frontend (Vite + React +
                             TypeScript + Tailwind + shadcn/ui), covering the
                             full Admin API surface; not a `ferrogate` subcommand
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

These manifests currently deploy the gateway process only (`ferrogate run`) as
a single container. The standalone billing and auth services (`ferrogate
billing serve` / `ferrogate auth serve`, see
[Service Decomposition](#service-decomposition)) ship in the same image but
are not yet templated as sibling deployments — run them as their own
workloads pointed at the gateway's `[billing_service]` config and auth
contract until that lands.

### Admin console

The admin console frontend ships as its own image, built from
`admin-console/Dockerfile` (a static SPA served by nginx — not part of the
main `ferrogate` image):

```bash
docker build -t ferrogate-admin-console admin-console/
docker run --rm -p 8081:8080 \
  -e AUTH_BASE_URL=https://auth.ferrogate.example.com \
  -e GATEWAY_ADMIN_BASE_URL=https://ferrogate.example.com \
  ferrogate-admin-console
```

`AUTH_BASE_URL`/`GATEWAY_ADMIN_BASE_URL` are rendered into `env-config.js` by
the image's nginx entrypoint at container start (see
[`admin-console/README.md`](admin-console/README.md)), so the same image
works across environments without a rebuild — unlike the Vite
`VITE_AUTH_BASE_URL`/`VITE_GATEWAY_ADMIN_BASE_URL` build-time env vars used
for local `npm run dev`.

It has its own Kubernetes manifest
([`deploy/kubernetes/admin-console.yaml`](deploy/kubernetes/admin-console.yaml))
and an optional, disabled-by-default Helm component (`adminConsole.enabled:
true` in [`charts/ferrogate/values.yaml`](charts/ferrogate/values.yaml)) —
both covered by the same `scripts/check-kubernetes-examples.sh` / `helm
template` validation above.

## Admin API

The checked-in OpenAPI 3.1 document lives at
[`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json).

This is a representative subset — the OpenAPI document is authoritative for
the full surface, which also covers virtual API keys, quota policies,
self-hosted worker registration, MCP server/plugin CRUD, tenant/project/
workspace management, and more.

```text
GET  /healthz
GET  /readyz
GET  /v1/models
POST /v1/chat/completions
POST /v1/responses
POST /v1/messages
POST /v1/embeddings
POST /v1/images/generations
POST /v1/agent-runs
GET  /.well-known/agent.json
GET  /v1/skills
GET  /v1/skills/{id}
POST /v1/prompts/{id}/render
GET  /v1/tools
POST /v1/tools/execute
POST /v1/mcp
POST /v1/mcp/tool/execute
POST /v1/functions/execute
GET  /v1/assets
GET/PUT/DELETE /v1/assets/{asset_type}/{name}/{version}
POST /v1/assets/presign/upload/{asset_type}/{name}/{version}
POST /v1/assets/presign/commit/{asset_type}/{name}/{version}
GET  /v1/assets/presign/download/{asset_type}/{name}/{version}
GET  /sites/{tenant}/{site}/{path}
POST /v1/self-hosted-workers/heartbeat
POST /v1/self-hosted-workers/runs/poll
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
GET  /admin/v1/virtual-keys
GET  /admin/v1/quota-policies
GET/POST /admin/v1/agent-schedules
POST /admin/v1/agent-schedules/{id}/run-now
GET  /admin/v1/agent-schedules/{id}/fires
GET  /admin/v1/self-hosted-workers
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/request-logs
GET  /admin/v1/audit-events
GET  /admin/v1/metering-events
GET  /admin/v1/billing-events
GET  /admin/v1/usage-aggregates
GET  /admin/v1/usage-reports
GET  /admin/v1/billing-outbox-dead-letters
GET/POST /admin/v1/drain
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /metrics
GET  /admin
```

The standalone billing service (`ferrogate billing serve`) exposes its own
`GET /v1/billing/ledger` and `POST /v1/billing/charge` on its own listen
address — these are billing-service routes, not gateway routes.

## Quality And Security

Run the local gate before committing:

```bash
./scripts/security-check.sh
```

Strict mode requires cargo-deny and cargo-audit, and is what CI enforces on
every change (see [`.github/workflows/rust-quality.yml`](.github/workflows/rust-quality.yml)):

```bash
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

See [`SECURITY.md`](SECURITY.md) for the vulnerability-disclosure process and
[`docs/security-controls.md`](docs/security-controls.md) for a control-family
mapping of shipped security capabilities.

For narrower local checks:

```bash
cargo fmt --all -- --check
cargo metadata --locked --format-version=1
python3 scripts/check-openapi.py
git diff --check
```

## Documentation

- Product overview and status: [`docs/product-overview.md`](docs/product-overview.md)
- Cloudflare integration: [`docs/cloudflare-integration.md`](docs/cloudflare-integration.md)
- Cloudflare deploy topology: [`docs/cloudflare-deploy-topology.md`](docs/cloudflare-deploy-topology.md)
- Autonomous development loop: [`docs/autonomous-dev-loop.md`](docs/autonomous-dev-loop.md)
- Agentic gateway architecture: [`docs/agentic-gateway-architecture.md`](docs/agentic-gateway-architecture.md)
- Agent framework compatibility: [`docs/agent-framework-compatibility.md`](docs/agent-framework-compatibility.md)
- Agent worker protocol: [`docs/agent-worker-protocol.md`](docs/agent-worker-protocol.md)
- Durable storage: [`docs/durable-storage.md`](docs/durable-storage.md)
- Analytics warehouse: [`docs/analytics-warehouse.md`](docs/analytics-warehouse.md)
- Cluster deployment: [`docs/cluster-deployment.md`](docs/cluster-deployment.md)
- Auth service contract: [`docs/auth-service-contract.md`](docs/auth-service-contract.md)
- Cloudflare integration reference (AI Gateway, MCP, R2/Workers/Pages, managed agents, Secrets Store, D1): [`docs/cloudflare-integration.md`](docs/cloudflare-integration.md)
- Hosting a FerroGate-defined MCP server on Cloudflare (McpAgent Worker, deploy flow, OAuth/KV): [`docs/cloudflare-mcp-hosting.md`](docs/cloudflare-mcp-hosting.md)
- Performance testing: [`docs/performance-testing.md`](docs/performance-testing.md)
- Security controls: [`docs/security-controls.md`](docs/security-controls.md)
- Guardrail investigation view (who/why/target/action/cost for a blocked request): [`docs/guardrails/investigation-view.md`](docs/guardrails/investigation-view.md)
- Supply-chain verification (SBOM, cosign signing, provenance): [`docs/security/supply-chain.md`](docs/security/supply-chain.md)
- Agent sandbox security model: [`docs/security/agent-sandbox-model.md`](docs/security/agent-sandbox-model.md)
- Self-hosted worker mTLS transport: [`docs/security/self-hosted-mtls-transport.md`](docs/security/self-hosted-mtls-transport.md)
- Private asset-bucket migration runbook: [`docs/assets/private-bucket-migration.md`](docs/assets/private-bucket-migration.md)
- SOC 2 audit scoping: [`docs/soc2-audit-scoping.md`](docs/soc2-audit-scoping.md)
- Roadmap: [`docs/roadmap.md`](docs/roadmap.md)

## Contributing

FerroGate is built for human maintainers and AI coding agents working together.
The best contributions are small, issue-linked slices that can be reviewed,
tested, and explained from the operator's point of view.

Day-to-day development runs as **three cooperating agent roles** — one that
generates code, one that reviews it, and one that tests it end to end — moving
issues across a GitHub Project board and bouncing anything that fails back with
findings. The contract is in
[`docs/autonomous-dev-loop.md`](docs/autonomous-dev-loop.md). Two conventions
from it are worth knowing even for a one-off human patch:

- **Say what you did not verify.** Commits carry `Tested:` and `Not-tested:`
  trailers, and a handoff that reads as verified when it is not costs a whole
  review round.
- **Assert the behaviour, not the call.** A test that proves a guard was
  *invoked* while the guard itself could be inverted with the suite still green
  is the single most common defect this project has had to reject. If you add a
  guard, name the mutation that would break it.

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
