<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Roadmap
description: FerroGate development milestones and implementation progress.
permalink: /roadmap/
---

# FerroGate Roadmap

Last reviewed: 2026-07-20.

This roadmap describes where FerroGate is going and how current GitHub issues
map to that direction. It is a planning document, not a release promise. The
source of truth for work status is still the issue tracker, pull requests,
commits, and local `ferrogate-test` evidence.

## How We Plan

FerroGate uses a GitHub-native planning model:

- **Shipped** means the feature is implemented, documented where needed, and
  has local or CI verification evidence.
- **Now** means active or highest-value near-term work. These issues should be
  small enough to land in reviewable slices.
- **Next** means designed or likely, but blocked behind Now work or still
  needing tighter acceptance criteria.
- **Later** means useful but intentionally deferred.

The issue tracker is organized as a two-level epic hierarchy: six product
pillars ([#266](https://github.com/lianluo-esign/ferrogate/issues/266)–[#271](https://github.com/lianluo-esign/ferrogate/issues/271))
that describe outcome-level direction, and per-module epics
([#285](https://github.com/lianluo-esign/ferrogate/issues/285)–[#300](https://github.com/lianluo-esign/ferrogate/issues/300))
that own the concrete work inside each crate or deliverable. Individual work
items are filed as child issues of those epics. Broad epics stay open until
their acceptance criteria are actually complete. When a slice lands, the
related issue should get a progress comment with the commit, verification
commands, and remaining work.

## Product Direction

FerroGate is evolving into an agent-native AI gateway: a production traffic
control point for model access, policy, routing, cost, tool execution,
observability, durable control-plane state, and operator evidence.

The system should stay understandable under incident pressure. Every major
runtime decision should leave enough evidence to answer:

- which tenant/API key made the request;
- which model/provider/tool was selected;
- which policy, approval, guardrail, or budget decision applied;
- how much usage was recorded;
- where to inspect the timeline afterward.

## Shipped Foundations

These areas are implemented in the current open-source gateway:

- Pingora gateway runtime, reverse proxying, route matching, upstream pools,
  request IDs, trace IDs, streaming responses, graceful shutdown, and graceful
  listener upgrade.
- OpenAI-compatible `GET /v1/models`, `POST /v1/chat/completions`, and
  `POST /v1/responses`, Anthropic-native `POST /v1/messages`,
  `POST /v1/embeddings` through OpenAI-compatible and non-OpenAI adapter
  families, and the governed `POST /v1/images/generations` ingress.
- Provider adapters for OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, Grok/xAI, and DeepSeek.
- Logical model registry, fallback routing, weighted routing, lowest-cost
  routing, lowest-latency routing, balanced routing, canary rollout splits,
  shadow/mirror traffic duplication, tenant visibility, and provider
  allow/deny controls.
- Virtual API keys, scopes, tenant context, model/provider allowlists and
  denylists, request rate limits, token budget reservation/settlement with
  local-tokenizer pre-request estimation, and a wallet reserve/hold
  primitive for exact-amount irreversible spends.
- Exact-match AI response cache for non-streaming requests, plus a semantic
  (vector-similarity) cache behind the same cache seam.
- Prompt/response guardrails, request logs, token metering events, usage
  aggregates, provider health, Prometheus metrics, OTLP export, and ClickHouse
  analytics delivery through Vector pipeline mode or direct warehouse mode.
- Dual-era MCP host/client adapters with stateless 2026-07-28 candidate
  discovery/per-request metadata and strict legacy fallback, plus native
  `/v1/mcp` support for 2025-11-25 and 2025-06-18 and JSON-RPC ingress including
  `resources/list`/`resources/read` and the first pinned MCP 2026-07-28
  candidate ingress slice: stateless `server/discover`, per-request metadata,
  required routing headers, and typed transport errors (`-32602` for malformed
  body metadata, `-32020` for header validation). The outbound negotiation
  slice has focused in-repo peer coverage, and the locked opt-in
  `mcp-candidate-client-official` command now supplies the official Tier-1 SDK
  opponent with two-instance stateless request routing. Recording a passing
  external run and final-spec conformance remain
  roadmap work. Existing MCP
  execution also includes dispatch isolation, timeout handling, approval gates,
  immutable approval fingerprints, Codex compatibility, and Claude Code
  compatibility.
- The hosted-asset closed loop: versioned `/v1/assets/*` publish/pull/delete,
  artifact-registry channels/semver/variants/yank, signature and malware-scan
  supply-chain gates, presigned large-file S3 path with a private bucket,
  egress metering with download quotas and audit, 304/Range pull caching,
  retention policies and unreferenced-blob GC, static-site serve mode under
  `/sites/{site}/{path}` — private by default, anonymous per site and per
  channel — verified custom domains routed to the same serve path through a
  DNS-TXT ownership proof, and agent consumption via MCP resources and the
  `fetch_asset` tool.
- Time-based agent schedules (cron/interval) firing `agent_run` targets into
  the dispatch lease queue, with an `/admin/v1/agent-schedules` CRUD API,
  run-now, and fire history.
- Self-hosted worker transport over verified mTLS: explicit issuing CA,
  control-plane certificate issuance and rotation, CRL revocation, and
  report-only governed execution for covered command families.
- A2A ingress deep governance (policy, guardrails, billing on message
  bodies) and workflow-graph-level execution budgets for multi-step agent
  runs.
- Per-tenant SSO persistence with SAML alongside OIDC in the auth service,
  and retention-engine TTL/purge adoption for request logs and audit
  events.
- Agent-sandbox capability boundary (`isolation.rs` + `capability_boundary.rs`
  + `function_egress.rs`): ten `CapabilityAction` classes, fail-closed
  denial proven against a CVE-2025-53967-shaped escalation attempt with a
  red-team regression test and an inspectable audit trail. See
  [`docs/security/agent-sandbox-model.md`](security/agent-sandbox-model.md).
- Agentic Lite plugin surface with built-in plugin registrations, request
  hooks, tool providers, event sinks, admin plugin/tool views, tool sessions,
  and audit events.
- Reusable gateway config profiles through `x-ferrogate-config`.
- Agent run evidence through `x-ferrogate-agent-run-id`, request logs, billing
  events, audit events, and Admin API run timelines.
- Admin API, OpenAPI document, config validation, process-local reload, status,
  readiness, drain, API-key CRUD, policy CRUD, gateway-config CRUD, prompt
  template CRUD/render, tool approvals, request-log exports, and dashboard
  visibility.
- Durable storage provider abstraction plus Supabase-first control-plane
  storage wiring for configured control-plane resources, with PostgreSQL as a
  compatibility path and Turso/libSQL and MySQL retired from the production
  provider surface.
- Managed agent runtime primitives in `ferrogate-runtime`: the default contract
  is an external `agent-worker` process that owns Firecracker microVM lifecycle,
  while the gateway owns policy, quota, template selection, capability
  envelopes, and evidence. Local test harnesses may use an external mock
  provider, but production managed execution should use Firecracker microVMs.
- Automatic HTTPS with manual TLS, ACME HTTP-01, ACME DNS-01 through
  Cloudflare, certificate renewal, and graceful-upgrade handoff.
- Docker, Kubernetes, Helm examples, cluster identity, shared file state, Redis
  counters, and deployment runbooks.

## Now

Near-term work is organized under the six product pillars. Each pillar epic
lists its own child issues and acceptance criteria:

| Pillar | Goal | Tracking |
| --- | --- | --- |
| LLM routing & provider surface | Deepen the multi-protocol inference surface (Chat Completions, Responses, Messages, embeddings, images), provider adapters, and rollout routing. | [#266](https://github.com/lianluo-esign/ferrogate/issues/266) |
| MCP & agent governance | Keep MCP ingress/host support current with the spec and deepen agent-run, A2A, workflow, and schedule governance. | [#267](https://github.com/lianluo-esign/ferrogate/issues/267) |
| Cost management & billing | Wallets, plans, metering dimensions, settlement paths, and billing-service integration. | [#268](https://github.com/lianluo-esign/ferrogate/issues/268) |
| Guardrails, identity & compliance | Guardrail adapters and promotion loops, SSO/RBAC, retention, and audit evidence. | [#269](https://github.com/lianluo-esign/ferrogate/issues/269) |
| Static-asset & tool hosting closed loop v2 | Extend the shipped `/v1/assets/*` + `/sites/*` loop (custom domains, live-bucket verification, richer registry semantics). | [#270](https://github.com/lianluo-esign/ferrogate/issues/270) |
| Platform, durable storage & operations | Durable control plane, cluster operations, deployment shapes, and operational hardening. | [#271](https://github.com/lianluo-esign/ferrogate/issues/271) |

## Next

Module epics own the concrete slices inside each crate or deliverable and
feed the pillars above:

| Module | Scope | Tracking |
| --- | --- | --- |
| Gateway core | Pingora data plane and request pipeline. | [#285](https://github.com/lianluo-esign/ferrogate/issues/285) |
| MCP | `ferrogate-mcp` host/client and MCP ingress. | [#286](https://github.com/lianluo-esign/ferrogate/issues/286) |
| Agent worker | `agent-worker` process, self-hosted and managed workers. | [#287](https://github.com/lianluo-esign/ferrogate/issues/287) |
| Runtime | `ferrogate-runtime` isolation, sandbox, and function egress. | [#288](https://github.com/lianluo-esign/ferrogate/issues/288) |
| Auth | `ferrogate-auth-service`, RBAC, SSO, and tenant entitlements. | [#289](https://github.com/lianluo-esign/ferrogate/issues/289) |
| Security | Security hardening and vulnerability remediation. | [#290](https://github.com/lianluo-esign/ferrogate/issues/290) |
| Secrets | `ferrogate-secrets` and credential backends. | [#291](https://github.com/lianluo-esign/ferrogate/issues/291) |
| Storage | `ferrogate-storage` durable control plane. | [#292](https://github.com/lianluo-esign/ferrogate/issues/292) |
| Test | `ferrogate-test` harness, CI gates, and compliance suites. | [#293](https://github.com/lianluo-esign/ferrogate/issues/293) |
| Observability | Metrics, tracing, and analytics. | [#294](https://github.com/lianluo-esign/ferrogate/issues/294) |
| Admin console | Admin console UI and Admin API surface. | [#295](https://github.com/lianluo-esign/ferrogate/issues/295) |
| Release | Release engineering and supply-chain integrity. | [#296](https://github.com/lianluo-esign/ferrogate/issues/296) |
| Deploy | Deployment, TLS/ACME, and cluster operations. | [#297](https://github.com/lianluo-esign/ferrogate/issues/297) |
| Config | Configuration model and Caddyfile compatibility. | [#298](https://github.com/lianluo-esign/ferrogate/issues/298) |
| Docs | Documentation, wiki, and repo housekeeping. | [#299](https://github.com/lianluo-esign/ferrogate/issues/299) |
| Commercialization | Secure Agent Gateway wedge, pilots, and GTM. | [#300](https://github.com/lianluo-esign/ferrogate/issues/300) |

## Later

| Theme | Goal | Tracking |
| --- | --- | --- |
| Firecracker real guest execution | Run real workloads inside Firecracker microVMs in `agent-worker`; blocked on KVM-capable infrastructure. Per-VM rootfs isolation and the boot-validation harness are already in place. | [#280](https://github.com/lianluo-esign/ferrogate/issues/280) |
| Static-site custom-domain CERTIFICATES | [#738](https://github.com/lianluo-esign/ferrogate/issues/738) shipped the serve path, the Cloudflare for SaaS custom-hostname client (`packages/cloudflare/src/custom-hostnames.ts`) and `certificate_status` on `GET /admin/v1/site-domains/{hostname}` (`docs/assets/custom-domains.md` §6). What is still open is AUTOMATIC provisioning: `ensureCustomHostname` exists and nothing calls it, because creating a billable Cloudflare resource from a tenant-triggered admin write needs its own rate-limiting, unbind-cleanup and no-entitlement answers. TLS termination and SNI remain deploy-time and unprovable offline. | [#265](https://github.com/lianluo-esign/ferrogate/issues/265) |
| Audio endpoints | `/v1/audio/speech` and `/v1/audio/transcriptions`; needs multipart request and binary response handling in the body path (images shipped first). | Backlog, child of [#266](https://github.com/lianluo-esign/ferrogate/issues/266) |
| Hosted control plane | Expand hosted Admin API and dashboard workflows after the self-hosted durable control-plane contract is stable. | Backlog |
| DNS provider expansion | Add DNS providers beyond the current Cloudflare ACME DNS-01 implementation and external hook boundary. | Backlog |

## Storage And Analytics Boundary

FerroGate intentionally separates control-plane storage from analytics storage.

Use durable control-plane storage for point lookups and CRUD:

- API keys, policies, tenants, gateway configs;
- prompt templates and rendered prompt metadata;
- plugin registrations and permission declarations;
- MCP server registrations and execution allowlists;
- tool approvals and human approval evidence;
- agent run records and lifecycle events.

Use analytics delivery for high-write observability data:

- massive request logs;
- traces and spans;
- usage metrics aggregation;
- billing and metering analytics;
- dashboard chart statistics.

The current direction is Supabase-first for commercial durable control-plane
tables and operator evidence. Turso/libSQL is retired from the production
provider surface (closed [#94](https://github.com/lianluo-esign/ferrogate/issues/94))
and remains only as legacy migration input; MySQL is retired outright
(closed [#192](https://github.com/lianluo-esign/ferrogate/issues/192)), with
no remaining migration tooling. Generic PostgreSQL is a compatibility path
tracked under the storage module epic
([#292](https://github.com/lianluo-esign/ferrogate/issues/292)). Analytics can
flow through Vector to ClickHouse or directly to ClickHouse when operators
want fewer moving parts.

## Non-Goals

- FerroGate is not trying to replace every agent framework runtime.
- The gateway hot path should not hide blocking DB writes, opaque scheduler
  state, or provider-specific logic in core abstractions.
- Prompt, tool, and model payloads must not be persisted by default outside the
  existing body logging and redaction policy.
- Broad roadmap issues should not close from partial slices.

## How To Contribute

Good roadmap contributions usually do one of these:

- close a narrow issue slice with tests and `ferrogate-test` evidence;
- tighten acceptance criteria on an open roadmap issue;
- add compatibility evidence for a real client, provider, database, or
  deployment shape;
- split an oversized issue into smaller verifiable work;
- update docs only after the implementation is actually shipped.

For issue-driven development, use
[`docs/dynamic-workflow.md`](dynamic-workflow.md) and record the local
verification commands in the issue comment before treating the work as done.
