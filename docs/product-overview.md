# FerroGate Product Overview

This page keeps the longer product description out of the README landing page.
It should describe shipped or explicitly tracked capabilities only; roadmap
work belongs in [`roadmap.md`](roadmap.md).

## What FerroGate Provides

- **Pingora gateway runtime** for HTTP reverse proxying, route matching,
  upstream pools, path/header rewrites, request IDs, tracing IDs, streaming
  responses, graceful shutdown, and listener-level graceful upgrade.
- **OpenAI-compatible AI API** with `GET /v1/models`,
  `POST /v1/chat/completions`, and `POST /v1/responses`, including
  non-streaming and streaming SSE forwarding.
- **Provider adapters** for OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, and Grok/xAI.
- **Model registry and fallback routing** with logical model names, provider
  model mapping, priority fallback, weighted fallback, lowest-cost,
  lowest-latency, balanced routing, tenant visibility, and provider allow/deny
  controls.
- **Exact-match AI response cache** for non-streaming requests with global,
  model, and API-key enablement controls.
- **MCP gateway support** through `ferrogate-mcp`, including streamable HTTP,
  SSE, stdio sessions, `initialize`, `tools/list`, namespaced tools,
  deny-by-default execution allowlists, health checks, reconnects, and governed
  tool execution.
- **Native MCP JSON-RPC ingress** at `POST /v1/mcp` for `initialize`, `ping`,
  `tools/list`, and `tools/call`.
- **Agentic Lite plugin surface** for governed capability bundles, tool
  providers, event sinks, permission declarations, tool sessions, admin views,
  and audit events.
- **Agent runtime and skill package surface** for agent discovery, governed
  agent upstreams, bounded runs, workflow counters/timelines, and skill-owned
  plugins, tools, MCP servers, prompt templates, and workflows.
- **Caddy-style config compatibility** through `Ferrogate/Caddyfile`, alongside
  structured TOML and YAML configuration.
- **Virtual API keys and policy checks** with hashed keys, tenant context,
  scopes, disabled/expired keys, model/provider allowlists and denylists,
  deny-rule evaluation, request rate limits, and token budgets.
- **Token usage metering events** using provider-reported usage when available
  and gateway estimates when needed.
- **Observability** with structured request logs, token metering events,
  configurable retention, usage aggregates, provider health, cache metrics, MCP
  tool metrics, agent-run OTLP spans, Prometheus metrics, request/trace ID
  propagation, and OTLP/HTTP export.
- **Admin API and dashboard** for status, providers, model catalog discovery,
  configured models, API keys, tenants, policies, request logs, agent run
  timelines, metering events, aggregates, audit events, gateway config
  profiles, provider health, plugins/extensions, tools, MCP servers, config
  validation, reload, readiness, and drain.
- **Durable control-plane storage** with Supabase-compatible PostgreSQL as the
  production target, plus memory, PostgreSQL, PostgreSQL TLS, MySQL, and MySQL
  TLS compatibility providers. Legacy Turso/libSQL configs are migration
  inputs, not new production provider choices.
- **Analytics delivery boundary** through either Vector-to-ClickHouse pipeline
  mode or direct ClickHouse warehouse mode.
- **Cluster operations** for multi-node deployments with node identity, shared
  file control-plane state, Redis-backed request and token counters, status,
  readiness, and drain semantics.
- **Automatic HTTPS** with manual TLS, ACME HTTP-01, ACME DNS-01 through a
  built-in Cloudflare provider, renewal scheduling, and graceful-upgrade
  handoff when listener-level TLS reload is required.
- **Supply-chain and security gates** with formatting, clippy, locked metadata,
  high-confidence secret scanning, cargo-deny, cargo-audit, and GitHub Actions.

## Current Status

The open-source gateway implementation covers the core API gateway, AI gateway,
governance, tool execution, observability, TLS, durable storage, analytics, and
cluster operations needed for a self-hosted first production slice.

Validated end to end:

- HTTP reverse proxy runtime on Pingora.
- OpenAI-compatible Chat Completions and Responses API paths.
- Canonical Responses request mapping for text, image, tool definitions, tool
  choice, and tool-call input shapes across provider paths.
- Agent framework compatibility for OpenAI-compatible clients using FerroGate
  `base_url`, virtual API keys, logical models, request logs, metering events,
  and Prometheus model/provider metrics.
- Provider adapters and priority, weighted, cost, latency, and balanced routing.
- Virtual API key auth, policy checks, rate limits, and token budget handling.
- Exact-match response cache for non-streaming AI requests.
- Agentic Lite tools and MCP gateway execution through auth, policy, billing,
  audit, and metrics.
- Native MCP JSON-RPC ingress at `POST /v1/mcp`.
- Agent discovery, A2A-style agent upstream invocation and streaming, bounded
  agent runs, workflow graph execution, workflow budgets, tool-call limits,
  immutable approval/audit evidence, and agent run timelines.
- Agent run timelines exported as reconstructable OTLP trace trees with agent
  root, provider-step, billing-write, audit/tool, and runtime lifecycle spans.
- Plugin registration, plugin-owned tool exposure, skill package compatibility
  metadata, and skill-owned resource materialization.
- Request logs, token metering events, usage aggregates, provider health, cache
  metrics, MCP tool metrics, Prometheus, W3C-correlated agent-run OTLP export,
  and ClickHouse analytics.
- Admin API, API key and policy CRUD, static dashboard, config validation,
  reload, status, readiness, and drain.
- Durable control-plane restart behavior for Supabase-compatible PostgreSQL TLS
  as the default production target, with PostgreSQL, PostgreSQL TLS, MySQL, and
  MySQL TLS retained as compatibility and local test providers. Legacy
  Turso/libSQL data remains a migration source.
- Manual TLS, ACME HTTP-01, ACME DNS-01, renewal scheduling, and listener-level
  graceful upgrade handoff.
- Cluster identity, shared file state, Redis counters, readiness, and drain
  runbooks.

Still intentionally scoped as next-stage production work:

- Production hardening beyond the implemented Supabase control-plane path;
  generic PostgreSQL and MySQL remain compatibility providers until their
  operator boundaries are separately hardened, while Turso/libSQL is retired
  from the production provider surface.
- Full hosted Admin API control plane beyond the current implemented resources.
- Semantic/vector cache matching. The implemented cache is exact-match only.
- Expanded DNS provider set beyond the built-in Cloudflare provider and the
  generic external hook boundary.

## Provider Notes

OpenRouter is available as a first-class provider kind while using the same
OpenAI-compatible Chat Completions and Responses API dispatch path. The optional
`openrouter_http_referer` and `openrouter_x_title` settings are sent upstream as
`HTTP-Referer` and `X-Title` headers.

Commercial and open-source upstreams that expose compatible
`/v1/chat/completions` or `/v1/responses` surfaces use the shared
`openai-compatible` path. Use a dedicated provider kind only when the upstream
needs its own auth or endpoint shape.

## Operational Notes

- For third-party usage billing, set `export_provider = "openmeter"` and point
  `export_endpoint` at an OpenMeter-compatible CloudEvents ingestion endpoint.
- Reusable gateway config profiles can be selected per request with
  `x-ferrogate-config`; profile evidence is recorded in request logs.
- MCP tool execution, agent operations, and external API calls are
  deny-by-default and must run through gateway auth, policy, billing, audit,
  and observability. Direct agent/tool bypass paths are outside the supported
  security boundary.
- Multi-node rate limits and token-budget reservation/settlement should use
  `cluster.counter_backend = "redis"`. Redis counters are fail-closed.
- Process-local reload is used only when the listen socket and TLS listener
  fingerprint do not change. Listener/TLS changes require graceful upgrade.

## Related Documentation

- README landing page: [`../README.md`](../README.md)
- Agent framework compatibility: [`agent-framework-compatibility.md`](agent-framework-compatibility.md)
- Durable storage: [`durable-storage.md`](durable-storage.md)
- Analytics warehouse: [`analytics-warehouse.md`](analytics-warehouse.md)
- Cluster deployment: [`cluster-deployment.md`](cluster-deployment.md)
- Auth service contract: [`auth-service-contract.md`](auth-service-contract.md)
- Admin API OpenAPI: [`openapi/admin-api.openapi.json`](openapi/admin-api.openapi.json)
