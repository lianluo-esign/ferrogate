<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Agentic Gateway Architecture & Roadmap
description: How FerroGate evolves from a proxy-only LLM gateway into a modular, plugin-based agentic gateway (MCP host, tool calling, agent runtime, skills), modeled on Bifrost's plugin architecture and benchmarked against Portkey.
status: proposal
last_reviewed: 2026-06-01
---

# Agentic Gateway Architecture & Roadmap

> **Status: proposal / design.** This document is research-backed (primary
> sources cited inline and in the appendix) and describes a target architecture
> and phased roadmap. It does not yet reflect shipped code. The current shipped
> capabilities are described in [README](../README.md) and [roadmap](./roadmap.md).

## 1. Purpose & scope

FerroGate today is a **proxy-only LLM gateway**: an OpenAI-compatible Rust/Pingora
control point for LLM traffic (routing, virtual keys, provider adapters, policy,
billing, observability, ACME). Across 2025–2026 the "AI gateway" category split
into two adjacent tiers:

1. **LLM gateway** — proxy / routing / keys / budgets / observability. *(FerroGate today.)*
2. **Agentic gateway** — layers MCP traffic governance, server-side tool-call
   orchestration, and optionally an in-process agent loop / runtime on top.

Every major competitor invested in tier 2 during 2025 (Portkey, Bifrost, LiteLLM,
Cloudflare, Kong, Envoy, Solo/agentgateway, Docker, AWS Bedrock AgentCore). To
"stay in sync with the community" FerroGate must add: a **modular plugin system**,
a **canonical tool-calling model**, an **MCP host/client**, an **agent runtime /
loop**, and **skills**. This document specifies how, modeled on **Bifrost's**
modular plugin architecture and benchmarked against **Portkey's** feature set.

The split between the FerroGate OSS gateway and the **[Token4AI Cloud](https://token4ai.cloud)**
hosted control plane mirrors Portkey's OSS-gateway-vs-hosted-platform model and
guides what belongs in the OSS repo vs. the commercial control plane (§5.9).

---

## 2. The agentic-gateway landscape (2025–2026)

### 2.1 Capability tiers

An "agentic gateway" is defined by capabilities layered on top of LLM proxying:

| # | Capability | What it means |
|---|-----------|----------------|
| a | **MCP host / aggregator** | Front many backend MCP servers behind one gateway endpoint |
| b | **MCP client / server** | Call out to external MCP servers; optionally expose own tools as an MCP server |
| c | **Tool-call orchestration** | Translate MCP tools ↔ OpenAI/Anthropic tool schemas, namespace, filter, multiplex |
| d | **Agent loop** | Multi-step reason→act→observe with server-side auto tool execution |
| e | **Hosted agent runtime** | Session isolation, long-running execution, microVMs |
| f | **Memory / state** | Persistent conversation/agent memory |
| g | **Guardrails in the loop** | Policy/safety checks evaluated *before* tool execution |
| h | **Skills / plugins** | Reusable, packaged capability extensions |

MCP (Model Context Protocol, Anthropic Nov-2024) became the de-facto standard:
adopted by OpenAI (Agents SDK, Responses API) and Google in 2025, with an official
[registry](https://registry.modelcontextprotocol.io/) launched 2025-09-08. **MCP
host/aggregation is now table stakes.** Security is the primary buying driver
(e.g. CVE-2025-53967 RCE in Figma's MCP server; cross-tool privilege escalation).

### 2.2 Competitor matrix

| Product | Lang | MCP host | MCP client/server | Tool orchestration | Agent loop (server-side) | Skills / sandbox |
|---|---|---|---|---|---|---|
| **FerroGate** (today) | Rust/Pingora | ✗ | ✗ | passthrough only | ✗ | ✗ |
| **Bifrost** (maximhq) | Go | ✓ | ✓ / ✓ | ✓ (prefix `client-tool`) | ✓ "Agent Mode" (`MaxAgentDepth=10`) | "Code Mode" (Python-in-Starlark sandbox) |
| **Portkey** (OSS+hosted) | TS/Hono | ✓ (hosted MCP Gateway) | ✓ / ✓ | ✓ | ✗ (proxy/governance only) | ✗ (guardrail plugins) |
| **LiteLLM** | Python | ✓ | ✓ / ✓ | ✓ | ✓ (`require_approval:"never"`) | ✗ |
| **Cloudflare AI Gateway** | — | ✓ (MCP Portals) | proxy | ✓ | ✗ | originated "Code Mode" |
| **Kong AI Gateway** 3.14+ | — | ✓ | proxy | ✓ + A2A | ✗ (governance) | ✗ |
| **Envoy AI Gateway** | — | ✓ (`MCPRoute` CRD) | proxy | ✓ (`toolSelector`) | ✗ | ✗ |
| **Solo/agentgateway** | Rust | ✓ | proxy | ✓ + A2A | ✗ | ✗ |
| **AWS Bedrock AgentCore** | — | ✓ (Gateway) | ✓ | ✓ (semantic tool search) | ✓ Runtime | ✓ microVM Runtime + Memory |

**Read:** most players ship (a)–(d) + guardrails; only LiteLLM and Bifrost run the
loop in-process; only AWS provides a full hosted runtime + memory. **Cross-cutting
patterns:** "Code Mode" (model writes code to call tools, cutting tokens 50–99% —
Cloudflare, Bifrost) and **Anthropic Agent Skills** (filesystem folders of
`SKILL.md` + scripts, progressive disclosure) — both need a code-execution sandbox.

### 2.3 Where FerroGate should aim

Proxy-only is now the *lower* tier. The highest-leverage, most on-brand next step
is to **become an MCP gateway/host**, reusing FerroGate's existing routing, auth,
policy, billing, and observability — now extended to tool calls. An in-process
agent loop is a credible second bet; a sandboxed runtime/skills layer is the
heaviest, separable tier. Rust/Pingora gives FerroGate a credible performance and
security story vs. Go (Bifrost) and Python (LiteLLM).

---

## 3. Bifrost as the architectural model

Bifrost (Apache-2.0, ~75% Go) is the cleanest open reference for a **modular,
plugin-based** gateway. Its discipline is worth copying.

### 3.1 Module split

```
core/        engine (bifrost.go) + schemas/ (unified types & interfaces) + providers/ (24 adapters) + mcp/ + network/ + keyselectors/
transports/  bifrost-http server (binary / Docker / NPX); /openai, /anthropic, /genai surfaces
framework/   pluggable persistence: configstore / logstore / vectorstore
plugins/     governance, logging, semanticcache, telemetry, otel, mocker, jsonparser, maxim, prompts, compat
ui/          web console (TypeScript)
```

Key lessons: **one big `schemas` package** (every adapter depends on a single
canonical request/response + `Provider`/`Account` interface); **per-provider
channel queues + object pools** for near-zero overhead (~11 µs @ 5k RPS); an
`Account` interface (`GetConfiguredProviders` / `GetKeysForProvider(ctx)` /
`GetConfigForProvider`) as the **context-aware** seam between config storage and
the engine — this is what enables virtual keys and per-tenant key sets.

### 3.2 Plugin system (verified against source)

Bifrost has **no single `Plugin` interface**. It composes a tiny base with typed
capability interfaces (`core/schemas/plugin.go`):

```go
type BasePlugin interface { GetName() string; Cleanup() error }

type LLMPlugin interface {
    BasePlugin
    PreLLMHook(ctx *BifrostContext, req *BifrostRequest)
        (*BifrostRequest, *LLMPluginShortCircuit, error)
    PostLLMHook(ctx *BifrostContext, resp *BifrostResponse, bifrostErr *BifrostError)
        (*BifrostResponse, *BifrostError, error)
}
// + HTTPTransportPlugin (PreHook/PostHook/StreamChunkHook at the HTTP edge)
// + MCPPlugin / MCPConnectionPlugin  (PreMCPHook/PostMCPHook + connect hooks)
// + ObservabilityPlugin (Inject)     // detected via type assertion, no marker method
// + ConfigMarshallerPlugin
```

Verified behaviors to replicate:

- **Execution order:** `HTTPTransportPreHook` (registration order) → `PreLLMHook`
  (registration order) → provider → `PostLLMHook` (**reverse** order) →
  `HTTPTransportPostHook` (reverse). `StreamChunkHook` replaces PostHook per-chunk
  for streaming.
- **Symmetry guarantee:** for every PreHook that ran, the matching PostHook runs
  in reverse — even on short-circuit (only the executed plugins' PostHooks run).
- **Short-circuit:** `PreLLMHook` returns a non-nil `*LLMPluginShortCircuit
  {Response | Stream | Error}` to skip the provider call (e.g. governance denies
  with 402 budget / 429 rate-limit / 403 blocked; semantic cache returns a hit).
- **Errors never reach the caller** — logged as warnings; `PostLLMHook` can
  *recover* (clear error, supply response) or *invalidate* (clear response, supply
  error); fallback is gated by `BifrostError.AllowFallbacks` (nil = true).
- **Config:** per-plugin `{ enabled, name, path, version, config, placement, order }`
  where `placement ∈ {pre_builtin, builtin, post_builtin(default)}` and `order`
  positions within a placement group.
- **Loading:** native `.so` via `-buildmode=plugin` (free-function exports; only
  `GetName`/`Cleanup` required, every hook optional) — **operationally brittle**
  (must match Bifrost's exact Go version, currently `1.26.3`, no cross-compile).
  Bifrost added a **WASM** alternative (`plugin_wasm.go`) — the better model.
- First-party plugins register names like `governance`, `logging`,
  `semantic_cache` (underscore), `telemetry`, `otel`, `bifrost-mocker`,
  `streaming-json-parser`, `maxim`, `prompts`, `compat`.

### 3.3 MCP in Bifrost

Bifrost is **both MCP client/host and MCP server**. `core/mcp` exposes
`AddMCPClient` / `RemoveMCPClient` / `GetAvailableMCPTools` / `ExecuteChatMCPTool`
/ `RegisterMCPTool`, etc. Four transports (`http` Streamable HTTP, `stdio`, `sse`,
`inprocess`) via the `mark3labs/mcp-go` library. Tools are namespaced
`clientName-toolName`; per-client config carries `ToolsToExecute` /
`ToolsToAutoExecute` allowlists (**deny-by-default**, `["*"]`=all, *both* lists
required to auto-execute), `AuthType ∈ {none, headers, oauth, per_user_oauth,
per_user_headers}`, and TLS/timeout/sync settings. Global:
`ToolExecutionTimeout=30s`, `MaxAgentDepth=10`, `DisableAutoToolInject`.
**Execution is explicit-by-default** (`POST /v1/mcp/tool/execute`); "Agent Mode"
opts into the autonomous loop bounded by `MaxAgentDepth`. Connections have
exponential backoff (5 retries, 1s→30s) + 10s health pings + auto-reconnect;
credentials sit behind an `MCPCredentialStore` interface for per-user auth.

---

## 4. Portkey as the feature reference

Portkey ships as an **OSS TypeScript/Hono gateway** (`Portkey-AI/gateway`) +
a **hosted control plane**. Notable features (verified):

- **Composable Gateway Config Object**: `strategy.mode ∈ {single, loadbalance,
  fallback, conditional}` with `targets[]` that can **recursively** nest strategies
  (a fallback target can itself be a load balancer). Keys: `retry {attempts,
  on_status_codes, use_retry_after_headers}` (max 5, exp backoff), `request_timeout`,
  `cache {mode: simple|semantic, max_age}`, `input_guardrails`/`output_guardrails`.
- **Guardrails via a `HooksManager`** hook framework: sync/async **before/after**
  request hooks, `HookType ∈ {GUARDRAIL, MUTATOR}`, deny→HTTP 446 / soft-fail→246.
  **21 partner plugin folders** under `plugins/` (Aporia, Pangea, Patronus, Azure,
  Bedrock, Mistral, …) each with a `manifest.json`, plus a `default` plugin with
  built-in checks (`regexMatch`, `jsonSchema`, `pii`, `contains`, `webhook`,
  `modelWhitelist`, …).
- **Conditional routing** on request metadata (`$eq/$ne/$in/$regex/$and/$or` over
  `metadata.*` / `params.*` / `url.pathname`).
- **Hosted-only**: semantic caching, Model Catalog (virtual keys → org-level
  credential store, `model="@provider-slug/model"`), org→workspace RBAC
  management + metadata schemas, analytics dashboard (21+ metrics), Prompt
  Engineering Studio, MCP Gateway. FerroGate integrates with RBAC over service
  APIs instead of making the gateway own the RBAC source of truth.

### 4.1 Feature parity matrix

| Feature | FerroGate (today) | Portkey OSS | Bifrost | Target for FerroGate |
|---|---|---|---|---|
| Unified OpenAI API | ✓ (chat, responses) | ✓ | ✓ | keep |
| Providers | 6 adapters | 45+ | 24+ | grow registry |
| Priority + weighted fallback | ✓ | ✓ | ✓ | keep |
| **Composable/nested routing** | ✗ (flat registry) | ✓ | partial | **add** (§5) |
| **Conditional/metadata routing** | ✗ | ✓ | — | **add** |
| Retries / timeouts | ✓ (`reliability`) | ✓ | ✓ | align naming + backoff |
| Circuit breaker | ✓ (explicit) | ✗ in OSS | enterprise | keep (ahead) |
| Caching | ✗ | simple (+semantic hosted) | semantic_cache plugin | **add simple**, defer semantic |
| **Guardrail/plugin hooks** | minimal deny-rules | ✓ HooksManager + 21 plugins | ✓ typed plugins | **add** (§5.2) — biggest gap |
| Virtual keys + budgets/limits | ✓ | hosted Model Catalog | ✓ governance plugin | keep; evolve to catalog (hosted) |
| Observability (Prom/OTLP) | ✓ | ✓ + dashboard (hosted) | ✓ plugins | keep; dashboard → hosted |
| **MCP host/client** | ✗ | ✓ (hosted) | ✓ | **add** (§5.4) |
| **Tool calling (server-side)** | passthrough | ✓ | ✓ | **add** (§5.3) |
| **Agent loop** | ✗ | ✗ | ✓ | **add, opt-in** (§5.5) |
| **Skills / Code Mode** | ✗ | ✗ | Code Mode | stretch (§5.6) |
| Prompt management | ✗ | hosted | prompts plugin | hosted (Token4AI Cloud) |

---

## 5. Proposed architecture for FerroGate

### 5.0 Current state & the one hard constraint

Request flow today (`crates/ferrogate-cli/src/gateway/`): `serve` (`mod.rs`) →
Pingora `ProxyHttp::request_filter` (`proxy.rs`) → `handle_request_filter`
(`handlers.rs`) → auth (`auth.rs`) → route match (`state.rs`) → model resolve +
policy → `dispatch_provider_request` (`dispatch.rs`) → response/stream.

**Critical constraint:** `dispatch.rs` uses **synchronous blocking I/O** (raw
`std::net::TcpStream` + rustls, `Connection: close`, blocking reads) called
directly inside the async handler, with **no connection pooling**. A single
request tolerates this; an **agent loop making N sequential model calls would
N×-multiply the blocking-in-async cost and connection churn**, starving Pingora
worker threads. **An async, pooled dispatch path is a prerequisite for the agent
loop** (§5.8) — this is the single most important enabling refactor.

Also note: `providers/canonical.rs` (`CanonicalContent ∈ {Text, TextBlocks}`)
**does not model tools** today — tool *definitions* pass through transparently in
the raw body, but the gateway never parses or executes `tool_calls`.

### 5.1 Crate map

The intentional skeleton crates kept in the last cleanup now get real homes,
plus new crates. (See [[workspace-skeleton-is-intentional]] reasoning.)

```
NEW   ferrogate-plugins     Plugin trait + registry + pipeline (the modular core)
NEW   ferrogate-mcp         MCP host/client (rmcp): sessions, tool registry, transports
NEW   ferrogate-guardrails  Built-in guardrail/mutator hooks (PII, regex, json-schema, webhook)
NEW   ferrogate-skills      Skill loader (SKILL.md progressive disclosure) — stretch
ACT.  ferrogate-runtime     Agent runtime / agent loop (today: only reload state)
ACT.  ferrogate-routing     Composable/conditional routing strategies (today: skeleton)
ACT.  ferrogate-auth        Standalone tenant/RBAC REST service boundary
GROW  ferrogate-providers   Canonical tool-calling model; async pooled dispatch
GROW  ferrogate-core        Canonical tool types (ToolDef, ToolCall, ToolResult)
GROW  ferrogate-billing     Per-tool-call + per-agent-turn cost accounting
GROW  ferrogate-config      plugins / mcp_servers / agents / skills config sections
```

### 5.2 Plugin system (the modular core)

Mirror Bifrost's *small base + typed capability traits*, idiomatic in async Rust.
Prefer **enums over nilable tuples** for short-circuit:

```rust
// ferrogate-plugins
#[async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    async fn cleanup(&self) -> Result<(), PluginError> { Ok(()) }
}

pub enum PreHook {
    Continue,                       // proceed; request mutated in place via &mut
    ShortCircuit(ShortCircuit),     // skip upstream entirely
}
pub enum ShortCircuit {
    Response(GatewayResponse),
    Stream(ResponseStream),
    Deny { status: http::StatusCode, code: String, message: String }, // e.g. 402/429/403
}

#[async_trait]
pub trait LlmPlugin: Plugin {
    async fn pre_request(&self, cx: &PluginCtx, req: &mut GatewayRequest)
        -> Result<PreHook, PluginError> { Ok(PreHook::Continue) }
    /// post-hooks run in REVERSE order; may recover or invalidate.
    async fn post_response(&self, cx: &PluginCtx, out: &mut HookResult)
        -> Result<(), PluginError> { Ok(()) }
}

// Optional capability traits, feature-detected at registration (Bifrost-style):
#[async_trait] pub trait HttpEdgePlugin: Plugin { /* pre / post / stream_chunk */ }
#[async_trait] pub trait McpPlugin: Plugin     { /* pre_mcp / post_mcp / connect hooks */ }
pub trait ObservabilityPlugin: Plugin          { fn inject(&self, span: &Span); }
```

**Pipeline** (in `ferrogate-plugins`, invoked from `handle_request_filter` /
`response_filter`): run `pre_request` in registration order, track the executed
count, run matching `post_response` in reverse — always, including on
short-circuit. Carry a `FallbackPolicy` on errors (`Option<bool>`, default allow).

**Placement/order config** (Bifrost-proven): `{ enabled, name, config, placement:
pre_builtin|builtin|post_builtin, order }`. Built-ins (auth, policy, rate-limit,
billing, circuit-breaker) become the `builtin` group; user plugins interleave via
placement. This **generalizes today's hard-coded governance** into one ordered,
observable pipeline — the single largest architectural win.

**Loading strategy** (avoid Go's `.so` ABI pain):
1. **In-tree trait objects via Cargo features** — first-class, safe, recommended default.
2. **WASM plugins** (`wasmtime`/`extism` + serializable edge types) — the
   third-party/untrusted extensibility story (Bifrost itself pivoted here).
3. **External webhook plugins** (HTTP) — partner integrations, à la Portkey's
   `webhook` guardrail; language-agnostic.

### 5.3 Canonical tool-calling model

Extend `ferrogate-core` + `providers/canonical.rs` to model tools, and add adapter
methods so each provider translates the canonical form to its dialect:

```rust
// ferrogate-core
pub struct ToolDef   { pub name: String, pub description: String, pub input_schema: serde_json::Value } // JSON Schema
pub struct ToolCall  { pub id: String, pub name: String, pub arguments: serde_json::Value }
pub struct ToolResult{ pub tool_call_id: String, pub content: serde_json::Value, pub is_error: bool }

// ferrogate-providers: extend ProviderAdapter
trait ProviderAdapter {
    /* existing: prepare_chat_completions / prepare_responses / extract_usage ... */
    fn inject_tools(&self, body: &mut serde_json::Value, tools: &[ToolDef]);     // OpenAI `tools` vs Anthropic `tools`
    fn extract_tool_calls(&self, body: &serde_json::Value) -> Vec<ToolCall>;     // finish_reason=="tool_calls" / stop_reason=="tool_use"
    fn append_tool_results(&self, msgs: &mut serde_json::Value, results: &[ToolResult]); // role:"tool" / tool_result blocks
}
```

Default behavior stays **passthrough** (transparent proxy). Server-side
interception is engaged only when an MCP/agent route or flag is active.

### 5.4 MCP host/client

Add the official Rust SDK **`rmcp` (1.7.0)** with features `client`,
`transport-streamable-http-client-reqwest`, `transport-child-process`,
`transport-io`, `macros` (and `server` + `transport-streamable-http-server` +
`tower` to expose FerroGate's own tools as an MCP server later).

```rust
// ferrogate-mcp — long-lived state in AppState, NOT per-request
pub struct McpManager { /* server_name -> McpSession (persistent rmcp client) */ }
impl McpManager {
    pub async fn connect_all(cfg: &[McpServerConfig]) -> Self;   // initialize handshake + tools/list
    pub fn available_tools(&self, allow: &ToolFilter) -> Vec<ToolDef>; // namespaced "server-tool"
    pub async fn execute(&self, name: &str, args: serde_json::Value) -> Result<ToolResult, McpError>;
    // refresh on notifications/tools/list_changed; health pings; backoff reconnect
}
```

Design rules (Bifrost/Envoy/LiteLLM-proven):
- **Transports:** Streamable HTTP + SSE first (network), stdio/subprocess for local.
- **Tool namespacing:** `serverName-toolName`; **deny-by-default** allowlists
  (`tools_to_execute`, `tools_to_auto_execute`); `toolSelector`-style include/regex.
- **Auth:** `none | headers | oauth | per_user_oauth | per_user_headers`;
  **credential injection** so secrets never leave the gateway — reuse `ferrogate-auth`.
- **Explicit-by-default execution:** `POST /v1/mcp/tool/execute`; opt-in auto-exec.
- **Resilience:** exp backoff (5 retries, 1s→30s), 10s health checks, auto-reconnect.
- **Endpoints:** `/mcp` and `/mcp/{server}` (LiteLLM-style) when FerroGate is the MCP server.
- **Governance/billing:** route every tool call through `ferrogate-policy` +
  `ferrogate-billing` (emit user/server/tool/latency/cost events).

### 5.5 Agent runtime / agent loop

Build the loop in the (currently stub) `ferrogate-runtime` crate, **opt-in per
route/flag**, behind an explicit approval policy:

```
loop:
  resp = call_model(messages, tools)            // async pooled dispatch (§5.8)
  calls = adapter.extract_tool_calls(resp)
  if calls.is_empty(): return resp              // final answer
  enforce policy + budget per call (ferrogate-policy / ferrogate-billing)
  results = join_all(calls.map(execute via McpManager / local skills))
  adapter.append_tool_results(messages, results)
  if ++turn > max_turns: return MaxTurnsExceeded // hard guard (cf. rig multi_turn / OpenAI max_turns)
```

Reference loops: OpenAI Agents SDK (`max_turns`/`MaxTurnsExceeded`), Rust `rig`
(`PromptRequest::multi_turn(n)`/`MaxDepthError`, with `.rmcp_tools()` to pull MCP
tools). Stream intermediate steps via the existing SSE path. **Apply auth, policy,
billing reservation/settlement, and circuit-breaker on *every* turn**, and account
for multiplied token usage across turns.

### 5.6 Skills + Code Mode (stretch)

**Anthropic Agent Skills** = filesystem dirs with a `SKILL.md` (YAML frontmatter
`name`≤64, `description`≤1024) using 3-level progressive disclosure (L1 metadata
always loaded → L2 body when triggered → L3 bundled scripts/refs executed on
demand). **Code Mode** = model writes code that calls tools in a sandbox (50–99%
token reduction). Both **require a code-execution sandbox** FerroGate does not have
— the heaviest, highest-risk tier. Scope as a separate product surface gated by
explicit trust/config; do not let it block MCP-host work. A single sandboxed-exec
capability could unlock both.

### 5.7 Config additions

New TOML/Caddyfile sections (validate cross-references in `config/validate.rs`):

```toml
[[plugins]]      # name, enabled, placement, order, config (per-plugin)
[[mcp_servers]]  # name, transport, url|command/args, auth_type, tools_to_execute, tools_to_auto_execute, tls
[[agents]]       # name, model, instructions, tools (mcp/local), max_turns, token_budget, enabled
[agent_loop]     # max_turns, token_budget_per_loop, tool_timeout_secs, auto_approve
[skills]         # dirs, sandbox config (stretch)
```

### 5.8 The async-dispatch refactor (prerequisite, do first)

Replace the blocking `TcpStream`+rustls path in `gateway/dispatch.rs` with **async
Tokio I/O + a pooled HTTP client** (`reqwest` is already pulled in transitively by
`instant-acme`/`rmcp`), or — as a stopgap — wrap calls in `spawn_blocking`. Expose
per-upstream pool knobs (max conns/host, idle timeout, HTTP/1.1 vs h2). This bounds
tail latency, lets the agent loop reuse connections, and brings FerroGate's upstream
handling in line with Bifrost's hand-tuned pooling (Pingora gives this largely for
free vs. Bifrost's manual `fasthttp` tuning).

### 5.9 OSS (FerroGate) vs hosted (Token4AI Cloud) split

Mirror Portkey's line. **OSS FerroGate**: routing, plugin pipeline, guardrail hooks,
simple caching, virtual keys, MCP host/client, tool calling, opt-in agent loop,
Prometheus/OTLP emission, and the standalone `ferrogate-auth` service boundary
for tenant/RBAC decisions. **Token4AI Cloud (hosted control plane)**: analytics
dashboard, Prompt Engineering Studio, org→workspace RBAC management + budgets
governance UI, Model Catalog, MCP registry/discovery UI, semantic caching, and
(if pursued) the hosted agent runtime + memory + sandbox.

---

## 6. Phased roadmap

Dependencies flow top→down; each phase ships independently.

| Phase | Deliverable | Depends on | Notes |
|---|---|---|---|
| **P0 — Enable** | Async pooled dispatch (§5.8) + canonical tool-calling model (§5.3) | — | Prerequisite for loop; low user-visible risk, internal refactor |
| **P1 — Plugin core** | `ferrogate-plugins` trait + ordered pipeline; migrate auth/policy/rate-limit/billing/circuit-breaker into it (§5.2) | P0 (partial) | The "modular plugin" foundation the project asked for; behavior-preserving migration |
| **P2 — Guardrails** | `ferrogate-guardrails` built-ins (regex, json-schema, PII, webhook) + simple cache plugin | P1 | Closes the biggest Portkey gap; webhook plugin = partner extensibility |
| **P3 — MCP host** | `ferrogate-mcp` (rmcp): sessions, tool registry, transports, allowlists, auth, `POST /v1/mcp/tool/execute` (§5.4) | P0, P1 | Highest-leverage agentic step; reuses auth/policy/billing |
| **P4 — Agent loop** | `ferrogate-runtime` opt-in reason-act-observe loop with approval gate + max-turns (§5.5) | P0, P3 | Per-turn policy/billing; SSE intermediate steps |
| **P5 — Extensibility** | WASM plugin host; FerroGate-as-MCP-server (`/mcp`); MCP registry client | P1, P3 | Community/ecosystem reach |
| **P6 — Stretch** | Skills loader + Code Mode sandbox (§5.6) | P4 | Separate product surface; heaviest security review |

Cross-cutting throughout: extend `ferrogate-billing` to count tool calls + agent
turns; extend OTLP/Prometheus to emit tool-call spans; keep everything off the hot
path when disabled.

---

## 7. Risks & open decisions

- **Blocking-in-async (P0)** is the top technical risk; the loop is not viable
  until dispatch is async + pooled. *Decision:* full `reqwest` migration vs.
  incremental `spawn_blocking` stopgap.
- **Plugin loading model:** in-tree (safe) vs. WASM (flexible, more infra) vs.
  webhook (language-agnostic, network cost). *Recommendation:* in-tree first, WASM next.
- **Tool execution trust:** explicit-by-default like Bifrost; auto-exec strictly
  opt-in and policy-gated (security is the category's #1 driver).
- **Skills/Code Mode sandbox** is a large new attack surface and arguably beyond a
  Pingora proxy's remit — treat as a distinct product, possibly hosted-only.
- **Scope creep vs. A2A:** Kong/agentgateway add agent-to-agent governance; defer
  until customer demand — it rides the same control plane later.
- **OSS vs hosted line:** keep dashboards, prompt studio, governance UI, semantic
  cache, and any hosted runtime in Token4AI Cloud; keep protocol/runtime primitives OSS.

---

## 8. Sources (primary, verified)

- **Bifrost:** `github.com/maximhq/bifrost` — `core/schemas/plugin.go`,
  `plugin_native.go`, `core/schemas/mcp.go`, `core/mcp/`, `framework/plugins/soloader.go`,
  `plugins/`; `docs.getbifrost.ai` (MCP overview, Code Mode, writing-go-plugin).
- **Portkey:** `github.com/Portkey-AI/gateway` — `src/middlewares/hooks/index.ts`,
  `src/handlers/`, `plugins/`; `portkey.ai/docs` (config-object, guardrails,
  conditional-routing, virtual-keys/Model Catalog, administration, remote-mcp).
- **MCP:** `modelcontextprotocol.io` (architecture, transports 2025-03-26),
  `registry.modelcontextprotocol.io`; spec revisions 2025-06-18 / 2025-11-25.
- **Rust:** `rmcp` 1.7.0 (`github.com/modelcontextprotocol/rust-sdk`, docs.rs),
  `rig-core` (docs.rs / book.rig.rs).
- **Landscape:** Cloudflare AI Gateway (dynamic-routing, MCP Portals, Code Mode),
  Kong AI Gateway 3.14 (MCP + Agent/A2A), Envoy AI Gateway (`MCPRoute`),
  agentgateway.dev, Docker MCP Gateway, AWS Bedrock AgentCore, LiteLLM MCP,
  Anthropic Agent Skills (`anthropic.com/engineering`, `platform.claude.com`).
- **FerroGate:** this repo — `crates/ferrogate-cli/src/gateway/`, `crates/ferrogate-providers/`,
  `crates/ferrogate-cli/src/{auth,state,config}.rs`, `Cargo.toml`.

*Full per-claim research with confidence levels and the adversarial verification
pass is preserved in the session workflow transcript.*
