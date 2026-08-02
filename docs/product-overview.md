# FerroGate Product Overview

This page keeps the longer product description out of the README landing page.
It should describe shipped or explicitly tracked capabilities only; roadmap
work belongs in [`roadmap.md`](roadmap.md).

## What FerroGate Provides

- **Pingora gateway runtime** for HTTP reverse proxying, route matching,
  upstream pools, path/header rewrites, request IDs, tracing IDs, streaming
  responses, graceful shutdown, and listener-level graceful upgrade.
- **Multi-protocol inference API** with `GET /v1/models`,
  `POST /v1/chat/completions`, `POST /v1/responses`, Anthropic-native
  `POST /v1/messages`, `POST /v1/embeddings` (served through OpenAI-compatible
  and non-OpenAI adapter families), and `POST /v1/images/generations`,
  including non-streaming and streaming SSE forwarding.
- **Provider adapters** for OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, and Grok/xAI.
- **Model registry and fallback routing** with logical model names, provider
  model mapping, priority fallback, weighted fallback, lowest-cost,
  lowest-latency, balanced routing, canary rollout splits, shadow/mirror
  traffic duplication, tenant visibility, and provider allow/deny controls.
- **AI response caching** with exact-match caching for non-streaming requests
  plus an opt-in semantic (vector-similarity) cache behind the same cache
  seam, with global, model, and API-key enablement controls.
- **MCP gateway support** through `ferrogate-mcp`, including streamable HTTP,
  SSE, stdio, `tools/list`, namespaced tools, deny-by-default execution
  allowlists, health checks, reconnects, and governed tool execution.
  Streamable HTTP and stdio probe the final 2026-07-28 revision first, use
  stateless per-request metadata when supported, and fall back on non-modern
  errors or bounded stdio silence to initialize-based 2025-11-25/2025-06-18
  peers. Modern health checks use `server/discover`; `ping` is legacy-only. An
  upstream that answers with an MRTR interim result (`resultType:
  "input_required"`, SEP-2322) is refused rather than having that envelope
  passed off as tool output — FerroGate implements no client half of MRTR.
- **Native MCP JSON-RPC ingress** at `POST /v1/mcp` for legacy `initialize` / `ping`,
  `tools/list`, `tools/call`, and `resources/list`/`resources/read` over the
  hosted-asset registry. It also implements stateless `server/discover` and
  per-request validation for the FINAL MCP 2026-07-28 revision. Every modern
  result carries `resultType` and `io.modelcontextprotocol/serverInfo`;
  cacheable results carry a short `ttlMs` and authorization-private
  `cacheScope`; `server/discover` advertises an EMPTY `extensions` map and all
  three spoken revisions. Body-schema failures use `-32602`; Streamable-HTTP
  header failures use `-32020`; an unsupported revision is refused `-32022`
  with the supported list in `error.data`. NOT implemented, and refused rather
  than half-served: `subscriptions/listen`, the `io.modelcontextprotocol/tasks`
  and MCP Apps extensions, `prompts/*`, `resources/templates/list`, and the
  client half of MRTR. Conformance is checked against the PUBLISHED SCHEMA, not
  a transcription of it: the official `2026-07-28` JSON Schema is vendored at
  `apps/mcp/spec/2026-07-28/` with its upstream commit, git blob sha and SHA-256
  recorded beside it, and real `server/discover` / `tools/list` / `tools/call` /
  `resources/read` responses plus the `-32020`/`-32022` refusals are validated
  against it. A hand-edited copy is caught offline by the recorded digest;
  upstream movement by `bun apps/mcp/spec/refresh.mjs --check`. Execution
  evidence against an external official SDK remains separate from the command's
  implementation and must not be inferred from compilation.
- **Hosted asset closed loop** at `/v1/assets/*`: versioned publish/pull/
  delete with tenant quota accounting, artifact-registry semantics (channels
  such as latest/stable/canary, semver resolution, platform/arch variants,
  yank), supply-chain trust gates (malware scanning, signature verification,
  cross-tenant publish approval), presigned large-file S3 upload/download
  against a private Supabase Storage (S3-compatible) bucket, egress
  metering/billing with download-side audit and bandwidth quotas, unified
  ETag/Range/304 HTTP caching on pulls, version retention policies with
  unreferenced-blob GC, static-site serve mode at
  `GET|HEAD /sites/{site}/{path}` (issue #737: `index.html` resolution with a
  308 to one canonical URL per document, the site's own `404.html`, optional SPA
  fallback, per-site and per-channel anonymous opt-in, per-response
  `cache-control`), verified custom domains for those sites (issue #738: a
  DNS-TXT ownership challenge binds a hostname to one tenant's site, and a
  request on that hostname is served through the same path as `/sites/*` — an
  unverified, expired or revoked hostname is refused rather than routed), and
  agent consumption through MCP `resources/*` plus the built-in `fetch_asset`
  tool.
- **Agentic Lite plugin surface** for governed capability bundles, tool
  providers, event sinks, permission declarations, tool sessions, admin views,
  and audit events.
- **Agent runtime and skill package surface** for agent discovery, governed
  agent upstreams, bounded runs, workflow counters/timelines, and skill-owned
  plugins, tools, MCP servers, prompt templates, and workflows.
- **A2A ingress deep governance** applying policy, guardrails, and billing to
  agent-to-agent message bodies, and **workflow-graph-level execution
  budgets** (model-call, tool-call, and token budgets with iteration limits)
  for multi-step agent runs.
- **Agent schedules** with cron/interval triggers that fire `agent_run`
  targets into the dispatch lease queue, plus an
  `/admin/v1/agent-schedules` CRUD API with `run-now` and per-schedule fire
  history.
- **Self-hosted worker transport** over verified mutual TLS: a single
  explicitly configured issuing CA, control-plane certificate issuance and
  rotation, CRL revocation, fail-closed trust-anchor handling, and
  report-only governed execution for covered command families on the shared
  `agent-worker` binary (`--worker-type self-hosted`).
- **Caddy-style config compatibility** through `Ferrogate/Caddyfile`, alongside
  structured TOML and YAML configuration.
- **Virtual API keys and policy checks** with hashed keys, tenant context,
  scopes, disabled/expired keys, model/provider allowlists and denylists,
  deny-rule evaluation, request rate limits, and token budgets.
- **Token usage metering events** using provider-reported usage when available
  and gateway estimates when needed, with a local BPE tokenizer for
  pre-request estimation and budget prechecks.
- **Billing primitives** including a prepaid-wallet reserve/hold mechanic for
  exact-amount, irreversible spend decisions under concurrency.
- **Per-tenant SSO persistence** with SAML alongside OIDC in the standalone
  auth service.
- **Observability** with structured request logs, token metering events,
  a retention engine applied to request logs and audit events (per-tenant
  TTL and audited purge, disabled and dry-run by default), usage aggregates,
  provider health, cache metrics,
  MCP tool metrics, agent-run OTLP spans, Prometheus metrics, request/trace
  ID propagation, and OTLP/HTTP export.
- **Admin API and dashboard** for status, providers, model catalog discovery,
  configured models, API keys, tenants, policies, request logs, agent run
  timelines, metering events, aggregates, audit events, gateway config
  profiles, provider health, plugins/extensions, tools, MCP servers, config
  validation, reload, readiness, and drain.
- **Durable control-plane storage** with Supabase-compatible PostgreSQL as the
  production target, plus memory, PostgreSQL, and PostgreSQL TLS compatibility
  providers. Legacy Turso/libSQL configs are migration inputs, not new
  production provider choices; MySQL is retired outright with no remaining
  migration tooling.
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
governance, tool execution, asset hosting, agent scheduling, observability,
TLS, durable storage, analytics, and cluster operations needed for a
self-hosted first production slice.

Validated end to end:

- HTTP reverse proxy runtime on Pingora.
- OpenAI-compatible Chat Completions and Responses API paths, the
  Anthropic-native `/v1/messages` ingress, `/v1/embeddings` across
  OpenAI-compatible and non-OpenAI adapter families, and the governed
  `/v1/images/generations` ingress with per-image metering.
- Canonical Responses request mapping for text, image, tool definitions, tool
  choice, and tool-call input shapes across provider paths.
- Agent framework compatibility for OpenAI-compatible clients using FerroGate
  `base_url`, virtual API keys, logical models, request logs, metering events,
  and Prometheus model/provider metrics.
- Provider adapters and priority, weighted, cost, latency, and balanced
  routing, plus canary rollout splits and shadow/mirror traffic duplication.
- Virtual API key auth, policy checks, rate limits, and token budget handling
  with local-tokenizer pre-request estimation.
- Exact-match and semantic (vector-similarity) response caches for
  non-streaming AI requests.
- Agentic Lite tools and MCP gateway execution through auth, policy, billing,
  audit, and metrics.
- Native legacy MCP JSON-RPC ingress at `POST /v1/mcp`, including
  `resources/list`/`resources/read` over hosted assets. The final MCP
  2026-07-28 ingress and outbound-client slices have focused regression
  coverage over the surface FerroGate serves, with response shapes validated
  against the vendored official schema and both eras' version negotiation
  driven end to end; external official-SDK compatibility, and the
  extensions/notification surfaces listed above, remain open.
- The hosted-asset closed loop: authenticated publish/pull/delete on
  `/v1/assets/*`, channels/semver/variant resolution, signature and
  malware-scan gates, presigned large-file upload/commit/download against a
  private bucket (mock S3-compatible endpoint; live Supabase Storage bucket
  verification remains open), egress metering with download quotas and
  audit, 304/Range pull caching, retention/GC sweeps, static-site serving
  under `/sites/*`, and agent consumption via MCP resources and
  `fetch_asset`.
- Agent discovery, A2A-style agent upstream invocation and streaming, deep
  A2A message-body governance (policy, guardrails, billing), bounded agent
  runs, workflow graph execution, workflow-graph-level budgets, tool-call
  limits, immutable approval/audit evidence, and agent run timelines.
- Cron/interval agent schedules firing into the dispatch lease queue, with
  admin CRUD, run-now, and fire-history endpoints.
- Self-hosted worker registration, verified-mTLS ingress with control-plane
  certificate issuance and CRL revocation, run polling/acknowledgement, and
  report-only governed execution for covered command families.
- Wallet reserve/hold settlement and per-tenant SSO (OIDC and SAML)
  persistence in the auth service.
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
  as the default production target, with PostgreSQL and PostgreSQL TLS
  retained as compatibility and local test providers. Legacy Turso/libSQL data
  remains a migration source; MySQL is retired outright.
- Manual TLS, ACME HTTP-01, ACME DNS-01, renewal scheduling, and listener-level
  graceful upgrade handoff.
- Cluster identity, shared file state, Redis counters, readiness, and drain
  runbooks.

Still intentionally scoped as next-stage production work:

- Production hardening beyond the implemented Supabase control-plane path;
  generic PostgreSQL remains a compatibility provider until its operator
  boundary is separately hardened, while Turso/libSQL and MySQL are retired
  from the production provider surface.
- Full hosted Admin API control plane beyond the current implemented resources.
- Audio endpoints (`/v1/audio/speech`, `/v1/audio/transcriptions`) — the
  multimodal surface currently ships images only; audio needs multipart
  request and binary response handling in the body path.
- Real Firecracker guest execution in `agent-worker` (blocked on
  KVM-capable infrastructure); per-VM rootfs isolation and the boot-validation
  harness are in place.
- Live Supabase Storage bucket verification for the asset object-storage
  path, which is currently proven against a mock S3-compatible endpoint.
- Static-site custom domains (binding a hosted site to a hostname via
  ACME).
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
