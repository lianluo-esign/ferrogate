---
title: FerroGate architecture and functional modules
tags:
  - architecture
  - modules
  - pingora
  - api-gateway
---

# FerroGate architecture and functional modules

FerroGate is an AI gateway implemented in Rust. The long-term product direction is to provide a mature API gateway experience for AI traffic while using Cloudflare's [Pingora](https://github.com/cloudflare/pingora) as the high-performance proxy foundation.

## Product positioning

FerroGate should feel like **a complete API gateway for AI APIs**:

- simple configuration first
- safe defaults
- automatic operational ergonomics where possible
- extensible modules
- production-grade proxying
- clear observability
- a developer experience that is easy to reason about

FerroGate should reproduce the important capabilities expected from production API gateways, then specialize them for LLM providers, OpenAI-compatible APIs, tokens, usage accounting, and AI governance.

## Why Pingora

Pingora is a Rust framework for building fast, reliable, and programmable networked systems. It provides a strong foundation for FerroGate because it already supports:

- async Rust proxy infrastructure
- HTTP/1 and HTTP/2 end-to-end proxying
- TLS support through multiple backends
- graceful reload
- customizable load balancing and failover
- gRPC and WebSocket proxying
- integration points for observability

FerroGate should use Pingora for the lower-level proxy runtime and focus FerroGate-specific code on AI routing, provider normalization, policy, observability, and configuration experience.

## High-level architecture

```mermaid
flowchart TB
  Client[Client SDK / App] --> Listener[Pingora listener and TLS]
  Listener --> RequestPipeline[FerroGate request pipeline]

  RequestPipeline --> Auth[Auth and key resolution]
  RequestPipeline --> Policy[Policy engine]
  RequestPipeline --> Router[AI provider router]
  RequestPipeline --> Transform[Request/response transform]
  RequestPipeline --> Usage[Usage and token accounting]
  RequestPipeline --> Observability[Logs / Metrics / Traces]

  Router --> LB[Pingora load balancing and failover]
  LB --> OpenAI[OpenAI]
  LB --> Anthropic[Anthropic]
  LB --> Gemini[Google Gemini]
  LB --> Azure[Azure OpenAI]
  LB --> Compatible[OpenAI-compatible upstreams]

  Config[Ferrogate/Caddyfile / typed config] --> RequestPipeline
  Admin[Admin API / control plane] --> Config
```

## Runtime layers

### 1. Network and proxy runtime

Responsible for accepting traffic, TLS, connection handling, upstream proxying, retries, timeouts, load balancing, and graceful reload.

Initial implementation direction:

- use `pingora-core` for service lifecycle
- use `pingora-proxy` for HTTP proxy behavior
- use `pingora-load-balancing` for upstream pools and failover
- use Pingora's graceful reload model for config reloads

### 2. FerroGate request pipeline

This is the AI-specific gateway pipeline that runs around the proxy path.

Typical stages:

1. receive inbound request
2. identify tenant, project, and API key
3. parse OpenAI-compatible route
4. apply policy and quota checks
5. select provider/model/upstream
6. normalize request for the selected provider
7. proxy through Pingora
8. normalize response back to the client contract
9. record usage, latency, tokens, and errors

### 3. Configuration and control plane

FerroGate should support a simple file-first workflow while leaving room for a future dynamic control plane.

Near-term config:

- `Ferrogate/Caddyfile` as the default startup path
- explicit TOML config for internal tests and transitional workflows
- provider definitions
- routes and model aliases
- upstream pools
- timeout/retry/load balancing options
- auth keys and env var references
- Caddyfile `ai_gateway` provider/model/API key subset mapped into the same typed runtime config used by TOML

Reload lifecycle contract:

1. `ferrogate reload --config <path>` first loads and validates the candidate config.
2. Validation produces a deterministic snapshot id from the normalized typed config.
3. CLI reload defaults to `mode=validate-only` and reports `swap=false`; when `--admin-url` and `--admin-token` are provided it posts the candidate config to the running Admin API reload endpoint and reports the committed/rejected runtime outcome. For listener/TLS changes, `--graceful-upgrade` starts a new `ferrogate run --upgrade` process and signals the active pid with `SIGQUIT`.
4. Invalid candidates fail before any runtime swap path and must not emit a success report.
5. The running admin API exposes `POST /admin/v1/config/validate` and `POST /admin/v1/config/reload` for TOML/Caddyfile candidates or `source=file` reloads from the current `ferrogate run --config` path; validation returns a reload plan with `reload_mode`, `listener_reload_required`, and `reload_reason`. Process-local config swap is allowed when `listen` and TLS listener settings are unchanged. It replaces request handling state for new requests and preserves in-memory logs, audit events, billing events, usage aggregates, and request id state. The CLI Admin API mode is a thin shell client over the same endpoint.
6. The runtime reload state machine uses prepare/commit/reject semantics: prepare creates a candidate snapshot without publishing it, commit replaces the active snapshot, and reject returns the unchanged active snapshot with the failure reason.
7. Listener address and TLS changes are classified by a listener runtime fingerprint and use the Pingora listener-level graceful-upgrade path; the process-local swap path rejects those candidates before publishing them. FerroGate passes configured Pingora `pid_file`, `upgrade_sock`, and upgrade socket retry count into `ServerConf`, and the CLI orchestrates SIGQUIT graceful upgrade plus FD transfer.
8. `/admin/status` exposes the active snapshot id. Failed reload tests must compare this value before and after an invalid candidate to prove the active config was not changed.

Future config direction:

- gateway-style readable config syntax
- hot reload
- admin API
- optional Token4AI Cloud managed config sync

### 4. Provider abstraction

Provider implementations isolate vendor-specific behavior.

Each provider adapter should own:

- endpoint mapping
- auth header injection
- model name translation
- request body transformation
- response body transformation
- streaming behavior
- error mapping
- usage extraction

P3 当前的 OpenAI-compatible adapter MVP 已经把 endpoint mapping、auth header planning、model name translation、stream flag preservation 和 chat completion request body transformation 固化在 `ferrogate-providers` crate 中。Gateway 只调用 adapter 生成 provider request plan，再通过 gateway dispatch 边界执行 HTTP upstream 调用，并已支持透传 provider 的 `text/event-stream` SSE response body。HTTPS dispatch、response transformation、真正增量式 streaming、error mapping 和 usage extraction 继续作为后续 P3 切片推进。

### 5. Policy and governance

Policy is applied before and after provider routing.

Policy examples:

- API key authentication
- tenant/project isolation
- model allow/deny lists
- rate limits
- token budgets
- request size limits
- prompt/content guard hooks
- audit logging hooks

Provider reliability:

- `reliability.provider_circuit_breaker_failure_threshold` enables provider-level circuit breaking.
- `reliability.provider_circuit_breaker_cooldown_secs` controls how long an unhealthy provider is skipped before a trial request can be attempted again.
- `reliability.provider_dispatch_timeout_secs` controls provider connect/read/write timeout for AI dispatch.
- `reliability.provider_dispatch_max_retries` controls retry attempts for retryable provider status responses or dispatch errors before falling back to another route.
- `reliability.graceful_shutdown_grace_period_secs` and `reliability.graceful_shutdown_timeout_secs` are passed to Pingora `ServerConf` so supervisor stop windows can be aligned with graceful termination.
- Circuit state is kept outside the provider adapter and is evaluated before dispatch, so fallback routing can avoid known-unhealthy providers without changing adapter behavior.
- `/admin/v1/provider-health` performs admin-triggered TCP reachability checks for provider `base_url` endpoints and combines the result with circuit state for the Dashboard Health view.

Listener TLS:

- `[tls]` enables a Pingora TLS listener with `cert_path`, `key_path`, and optional `http2`.
- Caddyfile `tls cert.pem key.pem` maps into the same typed config.
- TLS certificate and private key paths are resolved relative to the loaded config file and validated with Pingora/rustls before runtime startup.
- This is manual certificate loading; automatic certificate issuance/renewal remains a separate later module.

API key governance:

- `api_keys[].request_limit_per_minute` is enforced with a per-key in-memory 60 second window after authentication and scope checks pass.
- `api_keys[].monthly_token_budget` is enforced with a request-time token reservation before provider dispatch, then settled against provider usage when available.
- If provider usage is missing, including current streaming responses, FerroGate records a gateway estimate and marks the billing event with `usage_source = gateway_estimate`.
- Rejected rate or budget requests are returned before provider dispatch and are recorded through the existing structured request log path.

### 6. Observability and usage accounting

FerroGate must make AI traffic observable by default.

Core telemetry:

- request ID
- tenant/project/key identity
- selected provider/model/upstream
- request latency
- upstream latency
- status code and provider error code
- prompt/completion/total tokens when available
- retry/failover events
- policy decision events

Runtime export path:

- Prometheus metrics are rendered from the in-memory gateway snapshot and served at `/metrics`.
- When `telemetry.otlp_endpoint` is configured, `ferrogate run` starts a background OTLP/HTTP sender.
- The sender periodically posts metrics, newly appended structured request logs, and `ferrogate.gateway.request` spans to `/v1/metrics`, `/v1/logs`, and `/v1/traces`.
- The sender runs outside the Pingora request path and does not export prompt/response bodies, even when body recording is enabled for local request logs.

## Functional module map

| Module | Responsibility | Initial priority |
| --- | --- | --- |
| CLI | `run`, `validate`, `reload`, and `check` compatibility alias | P0 |
| Config loader | Parse and validate gateway configuration | P0 |
| Pingora runtime | Listener, proxy lifecycle, graceful reload | P0 |
| Route matcher | Match OpenAI-compatible paths and future route rules | P0 |
| Provider router | Select provider/model/upstream | P0 |
| Provider adapters | OpenAI-compatible first, then OpenAI/Anthropic/Gemini/Azure | P1 |
| Auth module | Gateway API key validation and upstream secret resolution | P1 |
| Policy engine | Quotas, limits, allow/deny rules, hooks | P1 |
| Usage accounting | Token and request metrics | P1 |
| Observability | tracing, metrics, structured logs | P1 |
| Admin API | config reload, status, provider health | P2 |
| Built-in module system | 内建 Provider、Policy、Observability、Dashboard 模块边界 | P2 |
| Static docs/wiki | Product and architecture documentation | P0 |

## General API gateway capabilities translated to FerroGate

| General gateway concept | FerroGate equivalent |
| --- | --- |
| Reverse proxy | AI provider proxy and model router |
| Readable config syntax | `Ferrogate/Caddyfile` plus typed internal config |
| Automatic HTTPS | Manual TLS listener is available; certificate automation remains a later module |
| Built-in modules | Provider adapters, policy modules, observability sinks |
| Admin API | Gateway runtime control plane |
| Hot reload | Pingora-backed graceful config reload |
| Site blocks/routes | Tenant/project/model route blocks |

## Suggested crate/module structure

```text
src/
  main.rs
  cli.rs
  config/
    mod.rs
    schema.rs
    validate.rs
  runtime/
    mod.rs
    pingora_service.rs
    reload.rs
  proxy/
    mod.rs
    pipeline.rs
    request_context.rs
  routing/
    mod.rs
    matcher.rs
    provider_router.rs
    upstream_pool.rs
  providers/
    mod.rs
    openai_compatible.rs
    openai.rs
    anthropic.rs
    gemini.rs
    azure_openai.rs
  policy/
    mod.rs
    auth.rs
    limits.rs
    decisions.rs
  usage/
    mod.rs
    tokens.rs
    accounting.rs
  observability/
    mod.rs
    tracing.rs
    metrics.rs
  admin/
    mod.rs
    api.rs
```

## MVP implementation sequence

1. Keep existing Axum health/config prototype as a temporary bootstrap.
2. Add Pingora dependencies and introduce a minimal Pingora HTTP proxy service.
3. Implement `GET /healthz` outside or beside the proxy path.
4. Implement OpenAI-compatible `/v1/models` from config.
5. Implement OpenAI-compatible chat completions proxy to one upstream.
6. Add provider router and upstream pool.
7. Add structured tracing and request IDs.
8. Add auth and basic policy checks.
9. Add streaming support and provider error normalization.
10. Add graceful reload from config.

## Key design principles

- Use Pingora for networking and proxy mechanics.
- Keep FerroGate's AI semantics independent from Pingora internals.
- Prefer explicit typed interfaces for providers and policies.
- Keep the first config format simple and stable.
- Design for hot reload and operational introspection from the beginning.
- Do not build an external plugin system as an early goal. Keep core gateway capabilities built in and maintain clear internal module boundaries.
