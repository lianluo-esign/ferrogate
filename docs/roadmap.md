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

Last reviewed: 2026-06-20.

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

Broad epics stay open until their acceptance criteria are actually complete.
When a slice lands, the related issue should get a progress comment with the
commit, verification commands, and remaining work.

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
  `POST /v1/responses`.
- Provider adapters for OpenAI-compatible APIs, OpenAI, Azure OpenAI,
  OpenRouter, Anthropic, Gemini, Grok/xAI, and DeepSeek.
- Logical model registry, fallback routing, weighted routing, lowest-cost
  routing, lowest-latency routing, balanced routing, tenant visibility, and
  provider allow/deny controls.
- Virtual API keys, scopes, tenant context, model/provider allowlists and
  denylists, request rate limits, and token budget reservation/settlement.
- Exact-match AI response cache for non-streaming requests.
- Prompt/response guardrails, request logs, token metering events, usage
  aggregates, provider health, Prometheus metrics, OTLP export, and ClickHouse
  analytics delivery through Vector pipeline mode or direct warehouse mode.
- MCP host/client support, native `/v1/mcp` JSON-RPC ingress, tool execution,
  dispatch isolation, timeout handling, approval gates, immutable approval
  fingerprints, Codex compatibility, and Claude Code compatibility.
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
- Durable storage provider abstraction and Turso/libSQL control-plane storage
  wiring for configured control-plane resources.
- Automatic HTTPS with manual TLS, ACME HTTP-01, ACME DNS-01 through
  Cloudflare, certificate renewal, and graceful-upgrade handoff.
- Docker, Kubernetes, Helm examples, cluster identity, shared file state, Redis
  counters, and deployment runbooks.

## Now

| Theme | Goal | Tracking |
| --- | --- | --- |
| Plugin system | Finish the plugin model as a reusable capability bundle layer above raw tools: registration, permissions, admin visibility, tool exposure, event sinks, and durable control-plane wiring. | [#71](https://github.com/lianluo-esign/ferrogate/issues/71) |
| Agent run evidence | Move from retained evidence aggregation to durable `agent_run` and `agent_run_event` records, lifecycle events, checkpoint/resume evidence, cancellation events, and tenant/API-key filters. | [#49](https://github.com/lianluo-esign/ferrogate/issues/49) |
| Durable control plane | Close the full durable control-plane boundary for API keys, policies, gateway configs, prompt templates, plugin registrations, MCP servers, tool approvals, and agent run records. | [#12](https://github.com/lianluo-esign/ferrogate/issues/12), [#66](https://github.com/lianluo-esign/ferrogate/issues/66), [#67](https://github.com/lianluo-esign/ferrogate/issues/67) |
| Prompt workflows | Complete versioned prompt template management and render APIs as first-class agent workflow inputs. | [#44](https://github.com/lianluo-esign/ferrogate/issues/44) |

## Next

| Theme | Goal | Tracking |
| --- | --- | --- |
| Database providers | Add PostgreSQL and MySQL providers behind the same storage contract used by Turso/libSQL. | [#69](https://github.com/lianluo-esign/ferrogate/issues/69), [#68](https://github.com/lianluo-esign/ferrogate/issues/68) |
| External service boundaries | Keep tenant RBAC and billing integrations behind explicit service/provider boundaries instead of moving that complexity into the gateway hot path. | [#54](https://github.com/lianluo-esign/ferrogate/issues/54) |
| Agent graph governance | Add workflow graph policy and execution budgets so multi-step agent runs can be governed at graph/run level, not only per request. | [#50](https://github.com/lianluo-esign/ferrogate/issues/50) |
| Agent protocol ingress | Add A2A and broader agent protocol ingress governance while reusing auth, policy, approvals, billing, and observability surfaces. | [#48](https://github.com/lianluo-esign/ferrogate/issues/48) |
| Canonical AI request model | Extend the internal AI request model for tools and multimodal inputs without leaking provider-specific request shapes into gateway core. | [#9](https://github.com/lianluo-esign/ferrogate/issues/9) |
| Responses streaming | Normalize Responses API streaming events so client compatibility is predictable across providers. | [#10](https://github.com/lianluo-esign/ferrogate/issues/10) |

## Later

| Theme | Goal | Tracking |
| --- | --- | --- |
| Sandboxed runtime | Evaluate an opt-in WASM sandboxed agent runtime only after gateway evidence, storage, and policy boundaries are solid. The gateway must not become an opaque scheduler by accident. | [#59](https://github.com/lianluo-esign/ferrogate/issues/59) |
| Semantic caching | Add semantic/vector cache matching after exact-match caching, billing evidence, and redaction policy remain reliable. | Backlog |
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

The current direction is Turso/libSQL first for the commercial cloud-friendly
control plane, then PostgreSQL and MySQL. Analytics can flow through Vector to
ClickHouse or directly to ClickHouse when operators want fewer moving parts.

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
