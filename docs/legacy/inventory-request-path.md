# Legacy inventory — request-path cluster

Authoritative porting spec for the FerroGate **request-path** crates being
rewritten 1:1 into TypeScript on Cloudflare Workers (Bun + Hono + Zod + full CF
product suite). Source of truth is the Rust tree in this worktree
(`/home/dev/ferrogate-ts`). One section per crate:

- [`ferrogate-gateway`](#1-ferrogate-gateway) — the Pingora data plane + Admin/Control API + `AppState`
- [`ferrogate-routing`](#2-ferrogate-routing) — route match + canary/shadow rollout
- [`ferrogate-providers`](#3-ferrogate-providers) — LLM provider adapters
- [`ferrogate-runtime`](#4-ferrogate-runtime) — agent-execution runtime boundary (CF Workers/Containers/DOs, self-hosted workers)

> Scale note: `ferrogate-gateway` is ~136k lines / 200+ files and holds a third
> of the workspace. It is one crate but really three subsystems (Pingora proxy,
> ~50-resource Admin API, `AppState` control plane). Treat the three as separate
> Worker/DO surfaces when porting.

---

## Cross-crate architecture (read first)

**Data-plane shape.** `FerroGateway { state: SharedAppState }` implements
Pingora's `ProxyHttp` trait (`server/proxy.rs`). Every request enters
`request_filter` → `handle_request_filter` (`server/handlers.rs`). That single
function is the whole ingress middleware chain, in order:

1. assign `request_id` (`AppState.next_request_id`, an `AtomicU64`);
2. `ClientActionTimeModule` downstream-module check (signed action-time tokens on CLI requests);
3. W3C trace-context extraction (`ingress_trace_context`, validates `traceparent`);
4. `/control/v1/*` → `/admin/v1/*` alias canonicalization (`ferrogate_admin::control_plane::canonicalize_alias_path`);
5. network access: IP allowlist + unauthenticated per-IP rate limit (`AppState.check_network_access` → `NetworkAccessDecision::{Allowed,IpDenied,RateLimited}`);
6. CORS preflight for `OPTIONS /admin/*`;
7. CSRF / confused-deputy defense for state-changing `/admin/*` (Sec-Fetch-Site / Origin);
8. `run_pre_request_hooks`;
9. fixed API-contract match (`api_contract::operation`) → 405 if path documented but method not;
10. health (`/healthz`) / readiness (`/readyz`) short-circuits;
11. **route-group dispatch** (`try_route_groups`) — `matchit` radix tree resolves one `RouteGroup`, whose `try_*_routes` handler either writes a response (`Ok(true)`) or declines (`Ok(false)`);
12. fall-through: custom-domain static-site serve → dynamic host/path proxy route match (`match_runtime_route`) → build target URI → hand to Pingora upstream hooks.

Routes served **internally** (all LLM APIs + the entire Admin API + assets +
sites + agent runs) write their own response and return `true`. Only **dynamic
proxy routes** (operator-configured `[[routes]]` → `[[upstreams]]`) return
`false` and flow through `upstream_peer` / `upstream_request_filter` /
`response_filter` / `logging`.

**Upstream request rewriting** (`proxy.rs::apply_upstream_request_filter`): sets
target URI, `Host`, injects `x-ferrogate-request-id`, `x-ferrogate-trace-id`,
`traceparent`, `tracestate`, `x-forwarded-host`, plus per-route request headers.
`response_filter` injects `server: FerroGate`, `x-ferrogate-runtime: pingora`,
`x-request-id`, `x-trace-id`, per-route response headers.

**The authoritative route table** is a committed JSON contract:
`docs/openapi/runtime-api-contract.json` (version 1) — 251 operations across the
route-groups. It declares per-operation `path`, `method`, `visibility`
(`public`/`admin`/`internal`), `auth.kind` (`anonymous`/`bearer`/`method_dependent`/`internal`),
`auth.scope`, `auth.scope_discriminator`, and `rbac_action`. **Port this file
verbatim** and drive Hono routing + a shared auth middleware from it (it is
already loaded through `matchit` at runtime and cross-checked against the
OpenAPI doc). The full table is reproduced in §1.

**State.** `SharedAppState = Arc<RwLock<AppState>>` — an immutable snapshot
swapped atomically on config reload. `AppState` bundles ~40 `Arc`-wrapped
subsystems (providers, upstreams, model registry, provider adapters, circuit
breakers, counters, caches, repositories, MCP manager, guardrail policies,
approval registry, rate limiters). Background sweeper threads (billing outbox,
agent schedules, asset lifecycle, x402 TTL/reconciler, ACME renewal, MCP
health) are `std::thread::spawn` loops that re-read `state.current()` each tick.

**Persistence** (external, in sibling `ferrogate-storage`): Supabase / Postgres
(`RuntimeStorageRepositories`) for all durable control-plane data; Redis
(optional) for cross-node cluster counters; in-memory `Mutex<HashMap>` for
single-node counters/caches. **Egress**: `reqwest` HTTPS client (shared,
redirect-disabled, rustls-ring) for provider dispatch, payments, MCP, function
egress, guardrail detectors.

---

## 1. `ferrogate-gateway`

### 1.1 Purpose
The Pingora data plane, the ~50-resource Admin/Control API handler surface, and
the `AppState` control plane both run over. The blob that was `ferrogate-cli`.

### 1.2 Public API surface (crate is mostly `pub(crate)`; only ~22 bare `pub`)
- `server::serve(config, source_path, upgrade) -> Result<()>` — boots Pingora, spawns all background sweepers, binds TLS/TCP listener, `run_forever()`.
- `server::assets::INLINE_ASSET_MAX_BYTES`.
- `state::runtime_storage_repositories(config)` — build durable repositories.
- `lifecycle::{ensure_auth_posture_is_declared, execute_graceful_upgrade_reload, + 2 report/reload entry points}` — config validate/reload/graceful-upgrade; also `ferrogate check` posture gate.
- `service_storage::{build_supabase_repositories, resolve_secret, SupabaseConnection}` — inline-or-`$ENV` secret resolver shared by gateway/billing/auth services.
- `auth::{hash_api_key_secret, authenticate_admin_gate, build_auth_service_target, AuthError, AuthServiceTarget, AuthServiceClientError}` — for the standalone control-api service.
- Everything else (`state::AppState`, `responses::*`, all `server::*` handlers, `auth::AuthContext`/`CallerScope`) is `pub(crate)`.

### 1.3 HTTP routes / handlers / middleware — the full contract
Middleware chain: see cross-crate architecture above. Dispatch is
`RouteGroup` (radix `matchit`) → `try_<group>_routes` → `handle_<resource>`.
Groups + their `handle_*` methods live in `server/route_groups.rs`; the module
per resource is named for the resource (`server/chat.rs`, `server/assets.rs`, …).

**LLM / data-plane API (`public`, `bearer` unless noted):**

| Method | Path | Scope | Handler / module |
|---|---|---|---|
| GET | `/v1/models` | `models.read` | `chat.rs` (via inference group) |
| POST | `/v1/chat/completions` | `chat.completions` | `chat.rs::handle_chat_completions` |
| POST | `/v1/responses` | `responses.create` | `chat.rs::handle_responses` (OpenAI Responses) |
| POST | `/v1/messages` | `messages.create` | `messages.rs::handle_messages` (Anthropic-native) |
| POST | `/v1/embeddings` | `embeddings.create` | `embeddings.rs::handle_embeddings` |
| POST | `/v1/images/generations` | `images.generate` | `images.rs::handle_images` |
| GET/POST | `/v1/tools`, `/v1/tools/execute` | `tools.read` / `tools.execute` | `state_tools.rs` + handlers |
| POST | `/v1/mcp` | *method_dependent* | `mcp_rpc.rs::handle_request` (MCP JSON-RPC) |
| GET/POST/DELETE | `/v1/mcp/identity/{server}[/authorize]`, `/v1/mcp/identity/callback` | `tools.read`/`tools.execute` / anonymous | `mcp_identity.rs` (OAuth callback) |
| POST | `/v1/mcp/tool/execute` | `mcp.execute` | `mcp_rpc.rs` |
| POST | `/v1/functions/execute` | `functions.execute` | `function_egress.rs` broker |
| POST | `/v1/agent-runs` | `agents.invoke` | `agent_runs.rs` (synchronous run) |
| POST | `/v1/agent-jobs`, GET `/v1/agent-jobs/{run_id}[/events\|/result]`, POST `…/cancel` | `agent.runs.create`/`agent.runs.read` | `agent_jobs.rs` (async job protocol; `/events` is SSE) |
| POST | `/v1/agents/{name}`, `…/message:send`, `…/message:stream` | `agents.invoke` | `a2a.rs` (A2A protocol; `:stream` is SSE) |
| GET | `/.well-known/agent.json` | `agents.read` | `a2a.rs` agent-card discovery |
| GET/PUT/DELETE/POST | `/v1/assets`, `/v1/assets/{asset_type}/{name}/{version}[/visibility\|/yank]`, `…/channels/{channel}`, `…/manifest` | `assets.read`/`assets.write` | `assets.rs`, `asset_bucket.rs` |
| GET/POST | `/v1/assets/presign/{upload\|download\|commit\|abort}/…`, `/v1/assets/storage/summary`, `/v1/assets/withheld` | `assets.read`/`assets.write` | `asset_presign.rs` (large-file multipart) |
| GET | `/v1/skills`, `/v1/skills/{id}` | `skills.read` | skill packages |
| POST | `/v1/prompts/{id}/render` | `prompts.render` | prompt templates |
| POST | `/v1/self-hosted-workers/{heartbeat\|events\|artifacts\|checkpoints\|runs/poll\|runs/ack}` | `internal` (`internal` auth) | `self_hosted` transport |
| GET | `/sites/{*rest}` | (site visibility) | `sites.rs` static-site serve |
| GET | `/healthz`, `/readyz` | anonymous | health/readiness |
| GET | `/metrics` | `admin.read` (internal) | Prometheus metrics |

**Admin/Control API** (`/admin/v1/*`, alias `/control/v1/*`; all `bearer`,
scope `admin.read` on GET / `admin.write` on mutations, `visibility: admin`).
~200 operations across these resources — dashboard/status/overview/observability;
request-logs/audit-events/guardrail-evaluations/investigations; config
validate/reload/drain; providers/provider-health/provider-models; managed-workers/
framework-adapters/observed-agent-activity; agent-cost-burn; agent-upstreams;
plugins/extensions; tools/tool-approvals/tool-sessions; mcp-servers; models;
gateway-configs; agent-workflows; agent-schedules (`…/fires`, `…/run-now`);
api-keys; policies; guardrail-policies (`…/activate`, `…/dry-run`, `…/revisions`,
`…/rollback` — carry explicit `rbac_action` like `guardrails.policy.activate`);
tenant-accounts/projects/workspaces/tenants (`…/plan`, `…/resolved-defaults`);
virtual-keys (`…/enable`, `…/disable`, `…/revoke`, `…/rotate`); quota-policies
(`{scope_type}/{scope_id}`); plans; wallets (`…/adjust`, `…/charge`, `…/ledger`)
+ payment-methods; billing-events/metering-events/usage-reports/usage-aggregates/
metering-export-status/billing-outbox-dead-letters(`…/replay`); rbac
permissions/roles/tenant-roles; site-domains (`…/verify`); skill-packages;
prompt-templates; self-hosted-workers (`…/heartbeat`,`…/events`,`…/artifacts`,
`…/checkpoints`,`…/rotate`) + self-hosted-worker-records + self-hosted-runs;
x402-spend-policies (`…/effective`, `…/evaluate`); payment-attempts.

> **Port strategy:** generate the Hono router from `runtime-api-contract.json`.
> One shared bearer-auth middleware reads `auth.kind`/`auth.scope`/`rbac_action`
> per matched operation. `method_dependent` (`POST /v1/mcp`) uses
> `auth.scope_discriminator` (a body-field → scope map). List endpoints share a
> pagination contract (`AdminPagination`, `AdminPage<T>`, `AdminList<T>`).

### 1.4 Request/response data shapes (→ Zod schemas)
`responses.rs` (2734 lines) is the entire HTTP response vocabulary — ~180
`pub(crate)` structs, all `Serialize`. Port each to a Zod schema. Highlights:
- **Error envelope** (every error path): `{ "error": { message, type: "ferrogate_error", code, request_id } }` via `write_json_error` / `write_json_error_and_close`.
- **Health/readiness**: `HealthResponse`, `ReadinessResponse`.
- **Admin generic**: `AdminList<T>`, `AdminPage<T>`, `AdminPagination`, `AdminDeleteResponse`, `AdminTenantRef`, per-resource `Admin*` + `Admin*Mutation` + `Admin*MutationResponse` (api-keys, plans, wallets, payment-methods, tenant-accounts, projects, workspaces, virtual-keys, quota-policies, plugins, prompt-templates, gateway-configs, agent-workflows, skill-packages, agent-upstreams, providers, permissions, roles, tenant-roles, mcp-servers, policies).
- **Self-hosted worker transport DTOs**: `AdminSelfHostedWorker*`, `SelfHostedWorker*TransportRequest`, registration/rotate/heartbeat/artifact/checkpoint/run-lease/run-ack request+response pairs.
- **Assets**: `AssetSummary`, `WithheldAssetSummary`, `AssetStorageSummary`, `AssetManifest`/`AssetManifestVersion`/`AssetManifestVariant`, `AssetChannelSummary`, `AssetVisibilityPromotionRequest/Response`, `AssetPresignedUploadConstraints`, `AssetMutationResponse`, `AssetCacheHeaders` + `ConditionalOutcome` (ETag/Range/304/206 logic in `evaluate_conditional_request`).
- **LLM**: `OpenAiModelList` / `OpenAiModel` (`/v1/models`). Chat/messages/embeddings/images request bodies are largely passed through as `serde_json::Value` and translated by the provider adapters, not strongly typed here (`ChatCompletionRequest` in `chat.rs` is a thin extractor of `model`/`stream`).
- Config ops: `AdminConfigValidateRequest/Response`, `AdminConfigReloadResponse`, `AdminDrainRequest/Response`.

`auth.rs::AuthContext` (the resolved caller identity threaded through every
handler): `api_key_id`, `scopes: Set`, `allowed/denied_models`,
`allowed/denied_providers`, `region_allowlist`, `monthly_token_budget`,
`request_limit_per_minute`, `organization_id` (tenant), `platform_operator`,
`team_id`/`project_id`/`workspace_id`/`user_id`, `log_bodies`, `rbac_subject`,
`effective_quota` (`ferrogate_policy::EffectiveQuota`). `CallerScope` =
`PlatformOperator | Tenant(&str)`; `UNSCOPED_TENANT_ID` sentinel matches no row
(fail-closed tenant isolation). `tenant_filter() -> Option<&str>` (None = root)
is the ONE place a query gets its tenant narrowing.

### 1.5 Streaming behavior (SSE) — critical for the port
The proxy is **not** WebSocket; LLM streaming is Server-Sent Events. Mechanism
(`responses.rs`): an **async pump** pulls provider body chunks
(`StreamingBodySource::next_chunk`, backed by `reqwest::Response::chunk`) into an
in-memory feed (`StreamingBodyUpstream`/`StreamingBodyFeedReader`,
`streaming_body_channel`), then runs them through a **synchronous `Read`-based
transform tower** and writes to the client via
`write_streaming_response` (chunked, `Content-Type: text/event-stream`). Dropping
the upstream aborts the provider connection (client-disconnect propagation).

Transform normalizers:
- `messages_stream.rs` — OpenAI chat SSE ⇄ Anthropic Messages SSE.
  - `chat_sse_to_completion(sse) -> Value` (aggregate SSE → single completion),
  - `message_to_anthropic_sse(message) -> Vec<u8>` (Messages object → Anthropic event stream: `message_start`, `content_block_start/delta/stop`, `message_delta`, `message_stop`),
  - `MessagesStreamNormalizer<R>` — incremental `Read` adapter translating an OpenAI stream into Anthropic events with tool-call accumulation (`ToolCallAccumulator`, `OpenBlock`),
  - `error_sse(code, message)`.
- `responses_stream.rs` — OpenAI Responses-shaped SSE.
  - `ResponsesStreamProviderKind` discriminator, `ResponsesStreamNormalizer<R>` (renders `response.*` event sequence with `ProviderUsageState` + `FunctionCallState`).
- **Usage capture during streaming** (`chat.rs`): `StreamingUsageCapturingReader`, `StreamingUsageCapture`, `extract_last_provider_stream_usage`, `read_provider_streaming_body` — token usage is scraped from the final SSE `usage` frame for metering/billing.

Async job events (`/v1/agent-jobs/{id}/events`) and A2A `message:stream` are
also SSE.

> **CF port:** Workers stream natively via `ReadableStream`/`TransformStream`.
> Reimplement the normalizers as `TransformStream`s over the provider
> `fetch().body`. The Rust sync-`Read`-over-async-feed shim exists only because
> Pingora's transform tower is synchronous; on Workers you don't need it —
> compose `TransformStream`s directly. Preserve the exact SSE event grammar
> (Anthropic `message_start`/`content_block_delta`/… and OpenAI `response.*`).

### 1.6 External services & I/O
- **Provider dispatch** (`server/dispatch.rs`): shared `reqwest` client
  (`provider_http_client`, `OnceLock`, `Policy::none()` no-redirect, no
  gzip/brotli/zstd/deflate, rustls-ring). `dispatch_provider_request` (bounded
  body read, chunk-capped), `dispatch_provider_streaming_request`,
  `dispatch_provider_catalog_request`. Transport-failure classification
  (`connect`/`timeout`/`redirect`/`body`/`decode`/`request`).
- **Durable storage**: Supabase/Postgres via `RuntimeStorageRepositories`
  (`service_storage.rs`, sibling `ferrogate-storage`) — api-keys, tenants,
  wallets, assets metadata, agent runs, audit/request logs, guardrail evidence,
  x402 payment attempts, quota policies, RBAC, etc.
- **Redis** (optional, `redis` crate): cross-node cluster counters
  (`ClusterCounterBackend::Redis`) for RPM/TPM/token/wallet windows.
- **Object storage**: asset bucket (`asset_bucket.rs`) — S3-compatible /
  bucket-backed blobs with presigned multipart upload/download.
- **Billing service** (`billing_client.rs`): HTTP client to standalone billing.
- **Auth service** (`auth.rs`): HTTP client to standalone identity service
  (external SSO/SAML/SCIM); `authenticate_external`, `authorize_external_rbac`.
- **MCP servers** (`ferrogate-mcp`): outbound MCP tool calls, health checks.
- **ACME** (`acme.rs`, `instant-acme`): TLS cert issuance/renewal.
- **Clamd/HTTP malware scanner** (`asset_scan.rs`): async TCP to clamd.
- **Workers AI Llama Guard** guardrail detector (HTTP).

### 1.7 Concurrency / state (→ Durable Objects)
- `SharedAppState = Arc<RwLock<AppState>>` — atomically-swapped snapshot; config
  reload builds a new `AppState` and swaps it. **~40 `Arc` subsystems** inside
  (see `state.rs:1466`): `providers`, `upstreams`, `runtime_routes`,
  `model_registry`, `provider_adapters` (`ProviderAdapterRegistry`),
  `provider_circuits` (circuit breakers), `provider_routing_metrics`,
  `cluster_counters` (`ClusterCounterBackend`), `metering_events`,
  `asset_egress_month_counters`, `evidence_writer` (bounded background writer),
  `response_cache` + `semantic_cache`, `mcp_manager` + dispatch semaphores,
  `approvals`, `guardrail_policies` + `guardrail_policy_fingerprint`,
  `shadow_budget` (`ferrogate_routing::ShadowBudgetLedger`), `request_ids`
  (`AtomicU64`), `drain` (`AtomicBool`), rate limiters, `resolved_provider_secrets`.
- **Counters** (`ClusterCounterBackend`): `Local` (`Mutex<HashMap>` sliding
  windows for RPM/TPM/token-reservation/wallet-reservation) or `Redis`.
  → **DO** (atomic per-tenant/per-key counters) or Rate Limiting API.
- **Caches**: `AiResponseCache` (exact-match, `Mutex`, TTL, tenant+policy
  scoped) and `SemanticResponseCache` (feature-hashed local embeddings, cosine
  threshold, `semantic_cache.rs`). → KV (exact) / Vectorize (semantic).
- **Background threads** (spawned in `server::serve`, each a `thread::spawn`
  loop re-reading `state.current()` with a `Drop`-based stop flag): OTLP +
  analytics senders, ACME renewal, MCP health (10s), external-action authorizer
  (Unix socket), billing-outbox sweeper (1s), agent-schedule sweeper,
  asset-lifecycle sweeper, x402 TTL sweeper, x402 settlement reconciler.
  → **CF Cron Triggers** / **Queues** / DO alarms.
- **`ferrogate_sync_bridge::block_on_sync_bridge`**: bridges async storage calls
  onto the synchronous Pingora worker / plain `std::thread` sweepers. Disappears
  on Workers (everything is already async).

### 1.8 Proposed CF/TS mapping
| Concern | CF product | TS lib |
|---|---|---|
| HTTP ingress + all routing | **Workers** + **Hono** | router generated from `runtime-api-contract.json` |
| Ingress middleware (trace, IP allowlist, CSRF, CORS, auth) | Hono middleware | Zod for header/body validation |
| Response/request DTOs | — | **Zod** schemas (port `responses.rs`) |
| LLM streaming SSE + normalizers | Workers streaming | `TransformStream` (reimplement `messages_stream`/`responses_stream`) |
| Provider dispatch | **AI Gateway** (already modeled by `cloudflare_ai_gateway`), else `fetch` | — |
| Durable control-plane data (Supabase/Postgres) | **D1** (or keep Hyperdrive→Postgres) | Drizzle/Kysely |
| Rate-limit / token / wallet counters | **Durable Objects** (atomic) or **Rate Limiting API** | — |
| Exact response cache | **KV** / **Cache API** | — |
| Semantic cache | **Vectorize** + Workers AI embeddings | — |
| Asset blobs + presigned multipart | **R2** (native presign) | — |
| `AppState` snapshot / config | KV or DO module-global + reload via KV write | — |
| Background sweepers | **Cron Triggers** + **Queues** (+ DO alarms) | — |
| Metering/billing outbox | **Queues** | — |
| Guardrail Llama-Guard | **Workers AI** | — |
| ACME/TLS | **CF-managed TLS** (drop `acme.rs` entirely) | — |
| Metrics/OTLP | **Workers Analytics Engine** / Tail Workers | — |

**No clean CF equivalent / flags:** (1) Pingora graceful-upgrade / PID-file /
`upgrade_sock` reload — Workers deploys are immutable, drop this. (2) Unix-socket
external-action authorizer — replace with Service Binding. (3) The
`RwLock<AppState>` hot-reload model — Workers have no long-lived mutable global;
config must come from KV/DO per-request or via a config DO. (4) `block_on_sync_bridge`
sync/async bridge — delete. (5) Local `Mutex<HashMap>` counters are per-isolate
and non-atomic across isolates → **must** move to DO/Rate-Limiting on Workers.

---

## 2. `ferrogate-routing`

### 2.1 Purpose
Pure, deterministic route-match and canary/shadow rollout selection primitives
shared by the request path. Tiny (2 files, ~230 lines). Zero I/O.

### 2.2 Public API surface (`lib.rs` + `rollout.rs`)
- `struct RouteMatch { route_name: String, upstream_name: String }`.
- `trait RouteMatcher { fn match_route(&self, host: Option<&str>, path: &str) -> Option<RouteMatch>; }` — the abstract dynamic-route matcher (implemented over `AppState`'s runtime routes).
- `fn rollout_bucket(salt, sticky_key) -> u8` — deterministic 0..=99 bucket (FNV-1a64 of `salt\0sticky_key`).
- `fn canary_selected(sticky_key, percent) -> bool` — sticky per-key canary (salt `"canary"`); 0 never, ≥100 always, monotonic in percent.
- `fn shadow_sampled(sticky_key, sample_percent) -> bool` — independent salt (`"shadow"`) so canary/shadow sample decorrelated subsets.
- `struct ShadowBudgetLedger { used: Mutex<HashMap<String,u64>> }` — process-lifetime shadow-mirror cap keyed by logical model: `try_consume(key, limit) -> bool` (0 = uncapped, poison-safe), `consumed(key) -> u64`.

### 2.3–2.7 Routes / shapes / streaming / I/O / state
None — pure functions. The only state is `ShadowBudgetLedger`'s in-memory
`Mutex<HashMap>` (a process-wide counter).

### 2.8 CF/TS mapping
- Port all functions 1:1 to a pure TS module (FNV-1a64 in BigInt/`Uint8Array`).
  `canary_selected`/`shadow_sampled`/`rollout_bucket` are deterministic and must
  produce **byte-identical** bucketing (they gate traffic; tests assert exact
  distributions) — keep the exact FNV constants (`0xcbf29ce484222325`,
  `0x100000001b3`) and the `salt\0key` framing.
- `ShadowBudgetLedger` (process-wide cap) → **Durable Object** counter (or KV
  with the same caveat as gateway counters — not atomic across isolates).
- `RouteMatcher` → a Hono/`matchit`-equivalent over the runtime route table.

---

## 3. `ferrogate-providers`

### 3.1 Purpose
The AI-provider adapter boundary: translate FerroGate's canonical
chat/responses/embeddings/images/catalog "plans" into each provider's upstream
wire request, and normalize responses/errors/usage back. Pure + synchronous (no
network — dispatch is the gateway's job). Depends only on `ferrogate-core`,
`serde`, `hmac`, `sha2`.

### 3.2 Public API surface
**Core trait** (`types.rs`): `ProviderAdapter: Send + Sync` —
- `kind()`, `prepare_chat_completions`, `prepare_responses`, `prepare_embeddings`, `prepare_images`, `prepare_model_catalog` (each `ProviderConfig + Plan -> Result<ProviderHttpRequest, AdapterError>`, defaults fail-closed with `UnsupportedProviderKind`/`UnsupportedCapability`);
- `translate_embeddings_response(body, model) -> Option<Value>` (Some = normalize to OpenAI shape; None = passthrough);
- `parse_model_catalog(body) -> Vec<ProviderCatalogModel>`;
- `normalize_error_response(status, content_type, body, request_id) -> ProviderErrorResponse`;
- `extract_usage(body) -> Option<ProviderUsage>`;
- tool plumbing: `inject_tools`, `extract_tool_calls`, `append_tool_results`;
- `is_retryable_status(status) -> bool` (default 429 + 5xx).

**Registry** (`registry.rs`): `ProviderAdapterRegistry` holds one instance of
each of the 8 adapters; `adapter_for(kind) -> &dyn ProviderAdapter` resolves via
`canonical_provider_adapter_family`. Wraps every trait method and, after
preparation, applies **Cloudflare AI Gateway routing** (`CloudflareRouting`) —
rewrites the prepared request onto the tenant's CF AI Gateway surface
(chat/messages/responses/embeddings) while preserving BYOK auth.

**Adapters** (`AnthropicAdapter`, `OpenAiCompatibleAdapter`, `AzureOpenAiAdapter`,
`BedrockAdapter`, `GeminiAdapter`, `GrokAdapter`, `OpenRouterAdapter`,
`VertexAiAdapter`). Families + aliases (`SUPPORTED_PROVIDER_ADAPTER_FAMILIES`):
- `openai-compatible` ← openai, deepseek, newapi, sub2api, cliproxyapi, vllm, llama.cpp, tgi, ollama, …
- `anthropic`; `gemini`; `grok`←xai; `openrouter`; `azure-openai`←azure; `bedrock`←aws-bedrock; `vertex`←vertex-ai.
- `canonical_provider_adapter_family(kind)`, `is_openai_compatible_provider_kind`, `provider_compatibility_kind`.

**Model registry** (`models.rs`): `ModelRegistry` (logical→physical),
`ModelRegistryEntry { name, primary: ModelRoute, fallbacks, capabilities,
context_window, prices, routing_strategy, enabled }`, `ModelRoute { provider,
provider_model, input/output_price_per_1m, priority, weight, capabilities:
Vec<ModelCapability>, context_window, region }`, `ResolvedModelRoute`,
`RoutingStrategy { Priority, LowestCost, LowestLatency, Balanced }`,
`ModelCapability { Chat, Streaming, Vision, Images, Embeddings, Tools,
StructuredOutput }`, `ModelRegistryError`. `resolve(logical) ->
ResolvedModelRoute` (sorts fallbacks by priority→weight→provider→model).

**SigV4** (`sigv4.rs`, for Bedrock): `sign`, `presign_query[_bound]`,
`sign_with_content_hash_header[_and_query]`, `sign_streamed_with_content_hash_header`,
`canonical_query_string`; types `AwsCredentials`, `SigningRequest`,
`StreamedSigningRequest`, `SignedHeaders`, `PresignRequest`, `BoundPresignedUpload`,
`PresignBoundPayload`.

**Anthropic ⇄ OpenAI translation** (`anthropic_messages.rs`, `pub`):
`to_chat_completions(anthropic_body) -> Value`,
`chat_completion_to_message(chat, fallback_model) -> Value`,
`is_anthropic_message`, `finish_reason_to_stop_reason`, `parse_arguments` —
the `/v1/messages` ingress reuses the OpenAI chat path by translating in/out.

### 3.3 Data shapes (→ Zod)
`ProviderConfig` (name, kind, base_url, api_key, openrouter_http_referer/x_title,
`aws_credentials: AwsProviderCredentials`, `gcp_credentials:
GcpProviderCredentials`, `cloudflare_ai_gateway: CloudflareAiGatewayRouting`);
`ChatCompletionPlan`/`ResponsesPlan`/`EmbeddingsPlan`/`ImagesPlan` (logical_model,
provider_model, stream?, `body: Value`); `ProviderHttpRequest` (provider,
endpoint, `body: Value`, stream, `headers: Vec<ProviderHeader>`);
`ProviderCatalogRequest`; `ProviderErrorResponse { status, body }`;
`ProviderUsage { prompt/completion/total_tokens }`; `ProviderCatalogModel`;
`SecretValue` (redacted-Debug wrapper); `AdapterError { UnsupportedProviderKind,
InvalidRequest, UnsupportedCapability }`. Request/response `body` is opaque JSON
— provider wire schemas live inside each adapter (e.g. Gemini `contents/parts`,
Anthropic `messages`, Azure deployment-in-URL).

### 3.4–3.7 Streaming / I/O / state
No I/O, no streaming, no long-lived state — all methods pure and synchronous.
(Streaming is transformed in the gateway crate; adapters only shape the initial
request + normalize non-stream usage/errors.) `GcpProviderCredentials` is
deliberately a pre-minted OAuth token (no in-crate token minting — would need a
blocking network round trip).

### 3.8 CF/TS mapping
- Port the whole crate to a pure TS module — one file per adapter implementing a
  `ProviderAdapter` interface, a `ProviderAdapterRegistry`, `ModelRegistry`, and
  the family-alias table. **Zod** for `ProviderConfig`/`*Plan`/`ProviderHttpRequest`.
- SigV4: use Web Crypto (`crypto.subtle` HMAC-SHA256) — port `sigv4.rs` carefully
  (Bedrock signing must be byte-exact; there is a streaming-content-hash variant).
- **CF AI Gateway** is a first-class target: `CloudflareAiGatewayRouting`/`Surface`
  already model routing every family through AI Gateway — prefer wiring provider
  dispatch through AI Gateway bindings (caching/rate-limit/observability free).
- Anthropic⇄OpenAI translation → pure TS; it backs the `/v1/messages` surface.
- No CF blockers.

---

## 4. `ferrogate-runtime`

### 4.1 Purpose
The agent-execution runtime boundary: the contracts + control clients FerroGate
uses to run agents on **Cloudflare Workers/Containers/Durable Objects**, on
**self-hosted customer workers**, or on local **managed workers** — plus the
governance model (action identity, capability boundary, isolation, egress,
function-token minting) that gates what those agents may do. Large (~35 files).
Depends on `ferrogate-cloudflare` (HTTP transport seam), `ferrogate-storage`,
`rustls`/`rcgen` (mTLS), `tokio`.

### 4.2 Public API surface (grouped; all `pub`, re-exported from `lib.rs`)
**Agent harness** (`agent.rs`): `AgentHarness` + `AgentHarnessConfig`,
`trait AgentProvider`, `ExternalAgentProvider(Config)`, `AgentRunInput`,
`AgentContext`, `AgentStep`, `AgentRunOutcome`/`AgentRunStatus`,
`AgentRunEvent`/`AgentRunEventKind`/`trait AgentRunEventSink`,
`AgentToolDispatchRequest` + `trait GovernedAgentToolDispatcher`,
`AgentCancellation`, `AgentRuntimeError`/`Result`.

**Action identity / governance vocabulary** (`action_identity.rs`) — the shared
tuple every governance layer emits so budgets/approvals/audit compose:
`ActionIdentity`, `ActingPrincipal`, `ActionContext`, `ActionDecision`,
`DecisionReason`, `ActionReceipt`, `AuditOutcome`, `GuardrailVerdict`/`Outcome`/
`Enforcement`/`TriggeredAction`, `OutputDisposition`, `decision_codes`,
`is_canonical_action_fingerprint`, `*_from_action_decision` converters,
`ACTION_FINGERPRINT_CONTRACT`.

**Capability boundary** (`capability_boundary.rs`): `trait CapabilityAuthorizer`
+ `SimpleCapabilityAuthorizer`, `CapabilityAction`, `CapabilityPolicy`,
`CapabilityTargetGrant`, `ManagedCapabilityRequest`,
`CapabilityAuthorization{Decision,Outcome,Evidence}`, `CapabilityBoundaryError`.
**Target canonicalization** (`target_capability.rs`): `canonical_{cli,filesystem,
mcp,network_host,network_url,secret}_target`, `CanonicalCapabilityTarget`,
`BoundCapabilityTarget`, `TargetOperation`, `McpRisk`, `opaque_reference_fingerprint`.

**Cloudflare control surfaces** (each because CF exposes **no public REST API**
for individual agent DO/container lifecycle — all go through a deployed
"agent-gateway" fronting Worker over authenticated routes):
- `cloudflare_worker.rs`: `trait CloudflareControlSurface` (sync, matches managed-worker scheduler seam), `CloudflareAgentControlClient<S>`, `CloudflareRun{Status,Props,StartRequest,Handle,ExecRequest,ExecOutcome}`, `Mock*`.
- `cloudflare_gateway_control.rs`: `WorkerGatewayControlSurface<T>` (maps each lifecycle verb → one HTTP call to the Worker's `/control/*` routes), `trait GatewayControlTransport`, `BlockingHttpControlTransport`.
- `cloudflare_gateway_deploy.rs`: `GatewayWorkerDeployer` — uploads the agent-gateway Worker via `multipart/form-data PUT /accounts/{id}/workers/scripts/{name}` (`GatewayWorkerSpec`, `GATEWAY_MULTIPART_BOUNDARY`, DO binding/class constants).
- `cloudflare_agent_memory.rs`: `AgentMemoryClient` over the Worker's `/memory/*` routes (CF agents keep memory in ONE DO per instance: synced JSON state, SQL, chat history, semantic search). `AgentInstanceIdentity`, `AgentStateSnapshot`, `AgentChatHistory/Message`, `AgentSemanticMatch(es)`, `AgentSqlOutcome`.
- `cloudflare_agent_schedule.rs`: `AgentScheduleClient` over `/schedule/*` (CF `this.schedule()` DO-alarm rows; no external enqueue). `AgentScheduleKind` (delay/at/cron), `AgentScheduleWhen`, `AgentScheduleTaskSpec`, records/list/cancel.
- `cloudflare_container.rs` + `cloudflare_container_egress.rs`: `ContainerControlClient<T>` (prepare/start/exec/stop/logs/artifacts/cleanup via Worker routes — CF Containers/Sandbox), `ContainerInstanceTier`, `ContainerEgressPosture`/`GovernedEgressAllowlist`/`PROVIDER_EGRESS_DENYLIST` (enforced egress + tether-bypass detection), `cloudflare_container_tether_audit.rs` (`TetherAuditor`, reconciliation).
- `cloudflare_agent_cost.rs`: per-agent cost/burn governance — `AgentCostGovernor`, `AgentBudgetPolicy`, `trait AgentBurnLedger` (`InMemory` + `StorageAgentBurnLedger` over `ferrogate-storage`), `CfRuntimeCostModel`/`Pricing` (DO requests, duration GB-s, SQLite rows, container vCPU/mem/disk/egress USD constants), `evaluate`, `should_dispatch`, `BudgetDecision`, `KillMode`.
- `cloudflare_worker_target.rs`: `CloudflareWorkerTarget` + `prepare_governed_worker_invocation` (governed Worker-function invocation broker).

**Self-hosted workers** (`self_hosted_worker.rs`, `self_hosted_mtls.rs`):
customer-owned hosts. `SelfHostedWorkerRegistry`, `SelfHostedWorker{Registration,
Identity,Heartbeat}`, run dispatch/poll/lease/ack (`SelfHostedRun*`), telemetry
ingest, transport posture/policy/channel, plus a full **mTLS** stack:
`SelfHostedMtlsCertIssuer` (mints SPIFFE-4-tuple leaf certs via `rcgen`),
`SelfHostedMtlsServer`/`Connection` (rustls-ring client-cert verification),
`SelfHostedTransportToken(Issuer/Store)`, revocation list.

**Managed workers** (`managed_worker.rs`): local-process agent workers —
`ManagedWorkerScheduler`(`Config`) generic over `trait AgentWorkerControlClient`,
`AgentWorkerHttpManagementClient` / (unix) `AgentWorkerUnixManagementClient`,
run-lifecycle state machine, AEAD-encrypted management frames
(`AgentWorkerManagement*`, chacha20poly1305), tenant/workspace concurrency limits,
worker templates.

**Framework adapters** (`framework_adapter.rs`): `trait FrameworkAdapter`,
`SupportedFramework` (Claude Code / Codex / Hermes / native), `Native`/`Process`
adapters, normalized session/run/resume/stream/artifact requests +
`NormalizedFrameworkEvent` timeline.

**Isolation** (`isolation.rs`): `trait IsolationBackendLifecycle`,
`IsolationBackendKind` (Firecracker/…), policy (`IsolationPolicy`,
`Network/Filesystem/ResourceLimits`), prepare/start/exec/stop/snapshot outcomes,
`select_isolation_backend`.

**Function egress** (`function_egress.rs`, `function_token.rs`,
`supabase_edge_function.rs`, `egress_dispatch_stage.rs`): `FunctionEgressAllowlist`
(deny-by-default per-tenant `{project_base_url, function_slug}` gate),
`FunctionEgressRule`/`Denied`, `FunctionInvocationRequest/Outcome`;
`FunctionTokenMinter` (short-lived scoped **HS256 JWT** per call, `FunctionTokenClaims`,
default/max TTL); `SupabaseEdgeFunctionInvocation` (builds governed
`{project}/functions/v1/{slug}` request with `FunctionCredential`);
`RequestWireStage`/`HoldDisposition` (typed "how far did egress get" for x402).

**Managed external actions** (`managed_external_action.rs`): `authorize_managed_external_action`,
`ManagedExternalAction`(+ `Rest`/`Cli`/`Browser`/`Filesystem`/`Memory`/`Secret`/
`Skill`/`Tool`/`McpTool`/`NetworkEgress` variants), canonical-target mapping,
transport request/response envelopes.

**Reload** (`reload.rs`): `ReloadCoordinator`, `ReloadCandidate`, `ReloadOutcome`,
`RuntimeSnapshot` — the config hot-reload state machine `SharedAppState` drives.

Also re-exports `ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse,
HttpTransport}` (the injectable transport seam every CF call is mockable through).
`enum RuntimeCommand { Run, Validate, Reload }`.

### 4.3 HTTP routes / handlers
This crate defines **no ingress routes**; it is the client/contract side. But it
defines the **outbound** route contracts against the deployed agent-gateway
Worker (`/control/*`, `/memory/*`, `/schedule/*`, container lifecycle) and the
self-hosted-worker transport. The gateway crate's `/v1/self-hosted-workers/*`,
`/v1/agent-runs`, `/v1/agent-jobs/*`, external-action authorizer are the ingress
counterparts.

### 4.4 Data shapes
Extensive — see 4.2. All `serde`-derived; port to Zod. Notable wire contracts:
agent-gateway Worker control/memory/schedule request+response bodies; CF cost
model pricing constants; AEAD management frames; self-hosted mTLS envelopes;
`FunctionTokenClaims` (JWT); `NormalizedFrameworkEvent`.

### 4.5 Streaming behavior
Framework adapters expose stream requests (`FrameworkAdapterStreamRequest`) and
`AgentRunEventSink`; agent runs emit event streams (surfaced by the gateway's
`/v1/agent-jobs/{id}/events` and A2A `message:stream` SSE). CF agent memory
supports semantic-match streaming. No raw socket handling here — events are
modeled as typed records the gateway serializes to SSE.

### 4.6 External services & I/O
- **Cloudflare API**: Workers script upload (multipart PUT), and all
  agent/container/memory/schedule ops via the deployed agent-gateway Worker
  (through `HttpTransport`/`GatewayControlTransport` seams — fully mockable).
- **Self-hosted workers**: HTTP(S) + **mTLS** (rustls-ring) transport; cert
  issuance via `rcgen`.
- **Managed workers**: local process over HTTP or **Unix socket**, AEAD-framed.
- **Supabase edge functions**: `{project}/functions/v1/{slug}` with minted JWT.
- **Storage**: `StorageAgentBurnLedger` reads/writes agent burn via `ferrogate-storage`.

### 4.7 Concurrency / state
- `ManagedWorkerScheduler` — run-lifecycle state machine, tenant/workspace
  concurrency limits (in-memory in the local variant).
- `SelfHostedWorkerRegistry`, `InMemorySelfHostedRunQueue` — in-memory run queue/leases.
- `AgentCostGovernor` + burn ledgers (in-memory or storage-backed).
- `ReloadCoordinator` (`Arc<Mutex<..>>` in `SharedAppState`).
- CF agent state itself lives in **one Durable Object per agent instance**
  (single-writer SQLite) — FerroGate only holds *clients* to it.

### 4.8 CF/TS mapping
| Concern | CF product | Notes |
|---|---|---|
| Agent instance (memory/schedule/state) | **Durable Objects** (Agents SDK) | This is the *native* home — CF agents already ARE DOs. Much of `cloudflare_agent_*` becomes the DO itself, not a client-to-a-fronting-Worker. The Rust "agent-gateway fronting Worker" indirection exists only because Rust can't run inside a DO; on the TS port the fronting Worker + DO are the target, so collapse the client seam into direct DO/binding calls. |
| Container/sandbox agents | **CF Containers / Sandbox** | `ContainerControlClient` → container bindings; port egress posture + tether audit. |
| Scheduling | DO **alarms** + Agents `this.schedule()` | drop the external control client. |
| Agent cost/burn | **DO** counter + `CfRuntimeCostModel` | port pricing constants exactly. |
| Function egress broker | **Workers** + `fetch` | HS256 JWT via Web Crypto; keep deny-by-default allowlist. |
| Function-token minting | Web Crypto HMAC-SHA256 | port `FunctionTokenMinter` / claims. |
| Managed-worker isolation (Firecracker), Unix-socket transport | **No clean CF equivalent** | Firecracker/jailer + Unix sockets don't exist on Workers. Container tier maps to CF Containers; the Firecracker isolation backend and local managed-worker process model are out-of-platform — flag for a product decision (drop, or keep behind a self-hosted control plane). |
| Self-hosted worker mTLS | **No native fit** | rustls mTLS server + `rcgen` cert issuance have no Workers analogue; mTLS termination would need a fronting proxy / Cloudflare Access / mTLS on a Custom Domain. Flag. |
| AEAD management frames | Web Crypto (chacha20poly1305 not in `crypto.subtle`) | needs a WASM/JS AEAD lib — flag. |
| Framework adapters (Claude Code/Codex/Hermes process launch) | Containers only | process-launch adapters can't run in a Worker isolate; only the container/native-in-DO adapters port cleanly. Flag. |

---

## Summary — cluster architecture & the 3 hardest ports

FerroGate's request path is a **Pingora reverse proxy** (`ferrogate-gateway`)
whose single `request_filter` middleware chain (`server/handlers.rs`) does trace
context, IP allowlist + unauth rate-limit, CSRF/CORS, then dispatches through a
`matchit` radix tree (`server/route_groups.rs`) driven by a committed 251-op JSON
contract (`docs/openapi/runtime-api-contract.json`). Requests are either **served
internally** (all `/v1/*` LLM APIs, the ~50-resource `/admin/v1/*` control API,
assets, sites, agent runs) or **proxied upstream** (operator routes). LLM calls
resolve a logical model → physical route via `ferrogate-providers`
(`ModelRegistry` + a per-family `ProviderAdapter` that shapes the upstream wire
request), dispatch over a shared `reqwest` client with circuit-breaking +
priority/weight fallback, and stream back via an async-pump → sync-`Read`
transform tower that normalizes SSE (OpenAI ⇄ Anthropic Messages ⇄ Responses).
`ferrogate-routing` supplies deterministic canary/shadow bucketing.
`ferrogate-runtime` is the agent-execution boundary — governed clients to
Cloudflare agents (DOs), containers, self-hosted mTLS workers, and local managed
workers, plus the shared action-identity / capability / isolation / egress
governance model. All mutable state hangs off one hot-reloadable
`Arc<RwLock<AppState>>` snapshot with ~10 background sweeper threads; durability
is Supabase/Postgres + optional Redis counters + object-store asset blobs.

**Top 3 hardest things to port to Workers:**

1. **The `Arc<RwLock<AppState>>` hot-reload model + in-memory atomic counters.**
   Workers have no long-lived mutable global and no cross-isolate atomicity. The
   whole snapshot-swap config model, the `Local` `Mutex<HashMap>` RPM/TPM/token/
   wallet windows, the response/shadow-budget ledgers, and the `block_on_sync_bridge`
   sync/async bridge must be re-architected onto **Durable Objects** (atomic
   counters, config DO) / KV / Vectorize. Getting rate-limit and wallet-overdraft
   semantics *exactly* right across isolates is the core risk (a `Mutex<HashMap>`
   silently becomes non-atomic and per-isolate on Workers).

2. **Streaming SSE normalization on the transform tower.** The gateway proxies
   and *rewrites* live LLM streams (OpenAI→Anthropic `message_start`/
   `content_block_delta`/…, OpenAI Responses `response.*`), scraping the trailing
   `usage` frame for metering mid-stream, with client-disconnect → provider-abort
   propagation. Reimplementing `messages_stream`/`responses_stream` as
   `TransformStream`s with byte-exact event grammar, incremental tool-call
   accumulation, and correct usage capture is intricate and easy to get subtly wrong.

3. **The agent-execution runtime's out-of-platform pieces.** Firecracker
   isolation, Unix-socket managed-worker transport, self-hosted-worker **mTLS**
   (rustls server + `rcgen` cert issuance), chacha20poly1305 AEAD management
   frames, and process-launch framework adapters (Claude Code/Codex/Hermes) have
   **no clean Workers equivalent**. The CF agent/container/memory/schedule clients
   invert nicely (they become the DO/Container itself, collapsing the fronting-
   Worker indirection), but the self-hosted + local-process execution paths need a
   product decision — drop, or keep behind a separate self-hosted control plane.
</content>
