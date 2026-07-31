# Parity audit — the REQUEST PATH (`providers` / `routing` / `gateway` / `runtime`)

**Date:** 2026-07-31 · **Scope:** `packages/providers`, `packages/routing`,
`apps/gateway` vs `crates/ferrogate-{providers,routing,gateway,runtime}` (READ-ONLY
reference) · **Method:** read-only diff against `docs/legacy/inventory-request-path.md`
and `docs/openapi/runtime-api-contract.json`. No behavior was implemented; the
product of this pass is this table plus 8 `PORT-TODO(...)` markers.

**What counts as a finding here:** behavior present in the Rust request path,
absent from the TS request path, **and carrying no `PORT-TODO` marker anywhere in
the tree**. A gap that is already marked is *not* a finding — it is a tracked
deferral, and this tree has 159 of them. Those are listed separately in §4 so the
count stays honest.

---

## 0. Quantitative baseline (correcting the brief)

The brief cites **providers 9,193 Rust vs 4,297 TS (0.47)**. That ratio is not
comparable: Rust keeps its unit tests inline under `#[cfg(test)]` in the same
files, and `cloudflare_test.rs` is a test file by name. Excluding both:

| Measure | Rust | TS | Ratio |
|---|---:|---:|---:|
| `providers` — **all** lines | 9,193 | 4,297 | 0.47 |
| `providers` — **production** lines (Rust: pre-`#[cfg(test)]`, minus `cloudflare_test.rs`) | **4,877** | **4,297** | **0.88** |
| `providers` — test lines | 4,316 | 1,019 (`packages/providers/test`) | 0.24 |
| `routing` — production lines | 226 | 347 | 1.54 |
| `gateway` — all lines | 144,052 | 27,511 (`apps/gateway/src`) | 0.19 |
| `gateway` — production lines (excl. `*_test*.rs`) | 108,818 | 27,511 | 0.25 |
| `gateway` — test lines | 35,234 | 18,729 (`apps/gateway/test`) | 0.53 |

So `packages/providers` is **not** half-ported — it is ~0.88 of the Rust
production surface and the adapter method matrix is a 1:1 match (§1). The real
deficit is concentrated in the **gateway crate at 0.25**, and this audit finds
that the missing quarter is not evenly spread: it is the *routing/reliability
layer* between "resolve a model" and "call the provider" (§2), plus two
ingress middleware steps (§5).

`packages/routing` at 1.54 is the opposite pathology — it is fully ported, has
28 tests, and **is imported by zero application code** (F7).

---

## 1. Provider adapters — NO FINDINGS

All 8 Rust families exist in `packages/providers/src` and in the gateway's own
registry. The 13-method `ProviderAdapter` trait matrix matches Rust **exactly**,
including which families deliberately decline which capability (a declined
method falls through to `BaseProviderAdapter`, which throws
`AdapterError.unsupportedCapability` — fail-closed, exactly like the Rust
default-method behavior).

| Family | Rust methods overridden | TS methods overridden | Match |
|---|---|---|---|
| `anthropic` | kind, prep chat, prep responses, normalize err, extract usage, inject/extract/append tools | same 8 | ✅ |
| `azure-openai` | kind, prep chat, normalize err, extract usage | same 4 | ✅ |
| `bedrock` | kind, prep chat, prep embeddings, translate embeddings, normalize err, extract usage | same 6 | ✅ |
| `gemini` | kind, prep chat, prep responses, prep embeddings, translate embeddings, normalize err, extract usage | same 7 | ✅ |
| `grok` | kind, prep chat, prep responses, normalize err, extract usage | same 5 | ✅ |
| `openai-compatible` | all 12 (incl. images + model catalog) | same 12 | ✅ |
| `openrouter` | kind, prep chat, prep responses, prep/parse catalog, normalize err, extract usage | same 7 | ✅ |
| `vertex` | kind, prep chat, prep embeddings, translate embeddings, normalize err, extract usage | same 6 | ✅ |

**No family silently falls through.** `defaultAdapterRegistry.adapterFor`
(`apps/gateway/src/inference/adapters.ts:916`) returns `null` for an unknown
kind and the handler renders the Rust `unsupported provider kind <kind>` error;
`canonicalProviderKind` carries the full `SUPPORTED_PROVIDER_ADAPTER_FAMILIES`
alias table (openai/deepseek/vllm/ollama/… → `openai-compatible`, `xai` → `grok`,
`aws-bedrock` → `bedrock`, `vertex-ai` → `vertex`, `azure` → `azure-openai`).

The one adapter-layer gap is **F8** (the `ProviderAdapterRegistry` wrapper, and
with it Cloudflare AI Gateway routing, is never mounted) — a wiring finding, not
an adapter finding.

---

## 2. Findings table

Severity: **H** = a Rust guarantee a deployed tenant would observe missing;
**M** = a Rust feature absent, degraded but safe; **L** = fidelity detail.

| # | Sev | Finding | Rust source | TS state | Marker added |
|---|---|---|---|---|---|
| **F1** | **H** | **IP allowlist + unauthenticated per-IP rate limit are validated but never enforced.** `network_access.{ip_allowlist,trust_forwarded_for,trusted_proxy_hops,unauthenticated_rate_limit_per_minute}` is fully ported into `packages/config` (schema + CIDR/prefix-length validators + 4 tests). Nothing in `apps/gateway` reads it. `resolve_client_ip` has no TS port at all. An operator who configures an allowlist gets a **green config and an open gateway**. | `state.rs:5011 check_network_access`, `handlers.rs:68` (steps 5), `ferrogate-config/config/network_access.rs` | absent; `grep -ri "cf-connecting-ip\|ip_allowlist" apps/gateway/src` → 0 | `apps/gateway/src/index.ts` |
| **F2** | **M** | **W3C trace-context ingress extraction absent.** Rust validates an inbound `traceparent`, adopts its trace-id, and propagates `traceparent`/`tracestate` onward; the TS gateway always sets `x-trace-id` = its own request id, so a caller's distributed trace is broken at the gateway. The *response* headers (`x-request-id`/`x-trace-id`/`x-ferrogate-runtime`) ARE ported. | `server/mod.rs:156 ingress_trace_context`, `handlers.rs:44`, `proxy.rs:146-150` | `grep -ri traceparent apps packages` → **0 hits** | `apps/gateway/src/index.ts` |
| **F3** | **H** | **Provider circuit breaker absent.** `ProviderCircuitBreaker` (failure threshold + cooldown, config `reliability.provider_circuit_breaker_*`), `provider_circuit_allows`, `record_provider_success/failure`, the `provider_circuit_open` 503 and the "skip to next candidate when the circuit is open" branch have no TS counterpart. A wedged provider is retried on every request forever. | `state.rs:5540`, `state_routing.rs:686-719`, `chat.rs:283-314` | `grep -ri circuit apps/gateway/src` → 0 | `apps/gateway/src/inference/ports.ts` |
| **F4** | **H** | **Failover ladder absent** — no fallback routes, no dispatch retries. `ModelResolver.resolve()` returns **one** `PhysicalRoute`; `ModelRegistryEntry.fallbacks` / `priority` / `weight` are not representable in the `GATEWAY_MODELS` var at all. `isRetryableStatus` is implemented in `packages/providers` (both `types.ts` and `registry.ts`) and **called from nowhere in `apps/gateway`**. `provider_dispatch_max_retries` is unported. | `chat.rs:259 'routes:` loop, `ProviderAttemptDecision::{from_retryable_status,from_dispatch_error}` (`chat.rs:3163-3187`) | single dispatch (`handlers.ts:283`) | `apps/gateway/src/inference/ports.ts`, `apps/gateway/src/inference/catalog.ts` |
| **F5** | **H** | **Route-eligibility gate absent (issue #582).** `model_routing.rs` (564 lines) filters candidate routes on declared `ModelCapability`, `context_window` fit (`input_token_upper_bound` + `explicit_output_tokens`), unbounded-media exclusion, and the caller's `region_allowlist` — *before* any strategy reads price or health, specifically so an incompatible route can never reach dispatch. TS carries `capabilities` on `PhysicalRoute` but **never reads it for eligibility**; `contextWindow`, prices and `region_allowlist` are not on the gateway's route type at all. The only `unsupported_capability` in TS is the ADAPTER-family error (`images` on Anthropic), a different check. | `model_routing.rs`, `state_routing.rs:489 candidate_model_routes` | `grep "\.capabilities" apps/gateway/src` → only catalog construction + agent-discovery | `apps/gateway/src/inference/ports.ts` |
| **F6** | **M** | **Routing strategies absent.** `RoutingStrategy::{LowestCost,LowestLatency,Balanced}` and the weighted round-robin within a priority group (`model_route_counter`, `weighted_start_index`, `total_weight`) plus `provider_routing_metrics` latency scoring are unported. `packages/providers/src/models.ts` *declares* the enum and sorts by priority→weight, but the gateway never uses `ModelRegistry`. | `state_routing.rs:517-598` | enum declared, unused by the data plane | `apps/gateway/src/inference/catalog.ts` |
| **F7** | **H** | **`packages/routing` is dead code — the repo's signature defect class.** `canarySelected`, `shadowSampled`, `rolloutBucket` (byte-exact FNV-1a64) and `ShadowBudgetDurableObject` are fully ported and covered by 28 tests. `grep -rn 'from "@ferrogate/routing"' apps/*/src packages/*/src` returns **exactly one hit, and it is inside a docstring**. `@ferrogate/routing` is a declared dependency of `apps/gateway/package.json` and is imported by no application module. `ShadowBudgetDurableObject` is exported from no `worker.ts` and bound in no `wrangler.toml`. Canary rollout and shadow mirroring (`server/shadow.rs`, `state_rollout.rs`) are therefore unreachable in production even though `canaryRouteSchema` is validated by `packages/config`. | `state_rollout.rs:47`, `server/shadow.rs:69,78` | 0 call sites | `packages/routing/src/index.ts` |
| **F8** | **M** | **`ProviderAdapterRegistry` is dead code, and with it Cloudflare AI Gateway routing (issue #406).** `packages/providers/src/registry.ts` wraps every adapter method and applies `applyCloudflareAiGatewayRouting` after preparation. `apps/gateway` never imports it — `inference/adapters.ts` builds its own `defaultAdapterRegistry` from the adapter classes directly, skipping the CF-AIG wrapper. `providerRecordSchema` is `.strict()` and has no `cloudflare_ai_gateway` key, so the routing cannot be configured either. Net: `cloudflare.ts` (153 lines) and the registry wrapper are unreachable on the deployed data plane. | `registry.rs` `CloudflareRouting`, `config/types.rs:1413`, `validate.rs:291` | own registry, no CF-AIG field | `packages/providers/src/registry.ts` |
| **F9** | **M** | **Operator reverse-proxy routes (`[[routes]]` → `[[upstreams]]`) absent.** Step 12 of the Rust ingress chain — the fall-through that makes FerroGate a general gateway, not only an LLM API. `packages/config` validates `routes` + `upstreams`; `packages/routing` exports a `RouteMatcher` **interface with no implementation**; `apps/gateway` has no catch-all and no `upstream_request_filter` equivalent (`x-forwarded-host`, per-route request/response header injection, `build_target_uri`). `ROUTE-MAP.md` §"Dynamic surfaces" explicitly puts this **in scope** ("in Hono use a catch-all resolved against the config snapshot"). | `handlers.rs` step 12, `state_routing.rs:816 match_runtime_route`, `proxy.rs::apply_upstream_request_filter` | absent | `apps/gateway/src/routes/index.ts` |
| **F10** | **M** | **Gateway config profiles absent.** The `x-ferrogate-config` request header selects a `[[gateway_configs]]` profile that overrides cache-enable and routing per request, with a typed `GatewayConfigResolveError::NotFound`. `packages/config` ports `gateway_configs` (schema + validation); `apps/gateway` never reads the header. `grep -ri "x-ferrogate-config" apps packages` → 0. | `chat.rs:115 GATEWAY_CONFIG_HEADER`, `state_routing.rs:262 resolve_gateway_config_profile` | absent | `apps/gateway/src/inference/handlers.ts` |
| **F11** | **M** | **Semantic response cache absent, and the metric for it already ships with no producer.** `packages/observability` emits `ferrogate_ai_cache_requests_total{status="semantic_hit"}` and carries `semanticCacheHitsTotal` through the OTLP exporter — a gauge that can only ever read 0. The exact-match `AiResponseCache` has a *binding-level* note in `apps/gateway/wrangler.toml` ("KV `CACHE` … Rust `response_cache`"), so it is half-tracked; `SemanticResponseCache` (`semantic_cache.rs`, feature-hashed local embeddings + cosine threshold → Vectorize) has **no marker anywhere**, and neither has a marker in the request-path code that would need it. | `state_routing.rs:223-482`, `semantic_cache.rs` | metric exists, cache does not | `apps/gateway/src/inference/handlers.ts` |
| **F12** | **L** | **Pre-request hooks + `ClientActionTimeModule` absent.** Steps 2 and 8 of the Rust ingress chain: signed action-time tokens on CLI requests (rejected with the module's own status/code before anything else runs) and `run_pre_request_hooks`. `grep -ri "action_time\|pre_request_hook" apps packages` → 0. Lower severity because both are opt-in postures, but a CLI that signs action-time tokens today would have them silently ignored. | `handlers.rs:29-41`, `handlers.rs:124`, `client_action_time.rs` | absent | rolled into the `apps/gateway/src/index.ts` marker |

### Findings deliberately NOT raised

- **CORS on the gateway** — already marked at `apps/gateway/src/inference/errors.ts:70`
  with the exact Rust shape (`cors_allowed_origin`, `write_cors_preflight_response`,
  204 preflight) and a pointer to the sibling port. Tracked, not silent.
- **CSRF / confused-deputy** — the Rust check guards `/admin/*`, which
  `apps/gateway` does not serve. It **is** ported, in `apps/control-plane/src/middleware/auth.ts`
  (`adminCrossSiteRejection`, `Sec-Fetch-Site` + `Origin` fallback) with 5 tests.
  Correct placement, no gap.
- **Monthly-budget / wallet-balance admission** — marked in detail at
  `apps/gateway/src/ratelimit/middleware.ts:225`, including the consequence and
  the exact remaining change.
- **Per-key model allow/deny list** — marked at `apps/gateway/src/inference/identity.ts:57`
  and `apps/gateway/src/keys/resolver.ts:136`.
- **`/v1/models` upstream catalog dispatch** — Rust `handle_models`
  (`local.rs:321`) lists the **configured registry** filtered by
  `can_tenant_use_model`, and does *not* dispatch a provider catalog request
  (that is an admin operation). TS matches, including the #515 tenant-visibility
  filter. No gap.
- **Anthropic→OpenAI-chat stream normalization** — TS returns `null`
  (passthrough) for the `openai.chat` dialect. Rust does the same: the only
  normalizers wired in `chat.rs` are `ResponsesStreamNormalizer` and
  `MessagesStreamNormalizer`; there is no Anthropic→chat normalizer in the Rust
  tree either. Parity, not a gap.
- **The 6 tooling operations** (`listTools`, `executeTool`, `executeFunction`,
  `listAgentSkills`, `getAgentSkill`, `renderPromptTemplate`) — explicit 501s,
  each with a `PORT-TODO` naming its blocking upstream, each still routed through
  `contractAuth` so the 401/403/501 ladder is real and pinned by `test/auth.test.ts`.
  Tracked, not silent.

---

## 3. SSE normalization completeness — NO FINDINGS

| Check | Rust | TS | Verdict |
|---|---|---|---|
| Anthropic event vocabulary | `message_start`, `content_block_start`, `content_block_delta`, `content_block_stop`, `message_delta`, `message_stop`, `error` | identical set, `streaming/anthropic.ts` | ✅ |
| Anthropic delta types | `text_delta`, `input_json_delta` | `text_delta`, `input_json_delta` | ✅ (neither emits `thinking_delta`/`signature_delta`) |
| Responses event vocabulary | `response.output_text.delta/.done`, `response.output_item.delta`, `response.function_call_arguments.delta/.done`, `response.completed`, `response.failed` | identical set, `streaming/responses.ts` | ✅ |
| Trailing usage frame | `StreamingUsageCapture` / `extract_last_provider_stream_usage` | `streaming/usage.ts` (419 lines) | ✅ (one marked deferral: `usage.ts:119`, Anthropic's newer usage field) |
| Tool-call accumulation | `ToolCallAccumulator`, `OpenBlock` | `streaming/toolcalls.ts` | ✅ |
| **Mid-event chunk split** | `Read`-over-feed with `WouldBlock` retries (`chat.rs:4240 chunkwise_fed_normalizer_matches_continuous_read`) | `SseFrameParser` buffers a partial line and a partial frame across `push()` calls; `final` flag drains an unterminated trailing frame — the same `drain_frame` semantics | ✅ |
| **Mid-UTF-8-multibyte split** | Rust operates on bytes, decodes per frame | `new TextDecoder("utf-8")` + `decode(chunk, { stream: true })` + a final `decode()` flush, at both call sites (`sse.ts:344`, `sse.ts:467`) | ✅ |
| CR / LF / CRLF terminators | — | explicit; a lone trailing `CR` is held back unless `final` | ✅ |
| Client-disconnect → provider abort | drop upstream aborts `reqwest` | `streaming/abort.ts` (193 lines) + `fetchDispatcher` forwards the inbound `AbortSignal` | ✅ |
| Dialect selection | normalize `openai.responses` unconditionally; `anthropic.messages` only off a non-Anthropic upstream | `defaults.ts:197 defaultStreamNormalizers`, same two rules, with the reason recorded | ✅ |
| `ResponsesStreamProviderKind` discriminator | anthropic / gemini / openai_compatible / other | same 4, same family mapping | ✅ |

Streaming is the strongest-ported subsystem in the request path. One residual
marked deferral each in `streaming/openai.ts:191`, `streaming/responses.ts:352`
and `streaming/usage.ts:119`.

---

## 4. The 31 gateway contract operations

All 31 gateway-owned `operation_id`s are registered on the app the Worker
exports (`GATEWAY_ROUTE_MODULES` in `src/index.ts` → `createGatewayApp`), and
`PENDING_MODULE_OPERATION_IDS` is empty. `test/contract.test.ts` imports that
exact array, so an unmounted module fails the suite — the anti-drift guard the
brief asks about is present and load-bearing.

**Behavioral** equivalence, not just registration:

| Group | Ops | Behavior verdict |
|---|---:|---|
| Shared health | 2 | ✅ (`/readyz` drain input is a marked platform limit, `routes/readiness.ts:17`) |
| Inference | 6 | ⚠️ routed, authenticated, validated, dispatched, metered, streamed — but every request takes **one** provider attempt with **no** circuit breaker, fallback, retry, eligibility gate, strategy, cache or config profile: **F3–F6, F10, F11** |
| Assets | 18 | ✅ substantially complete — R2-backed store, semver channel resolution, ETag / `If-None-Match` / single-byte `Range` / 304 / 416 conditional logic (`assets/service.ts:190-210`), yank/unyank, visibility promotion. Presign family answers `503 asset_bucket_unavailable` unbound, which is the Rust unconfigured posture. Marked deferrals: malware scan (`assets/ports.ts:583`), presign secrets (`assets/sigv4.ts:174`), governed action (`assets/handlers.ts:234`) |
| Tooling | 4 of 7 | ⚠️ explicit, marked, auth-guarded 501s (`listTools`, `executeTool`, `executeFunction`, `listAgentSkills`, `getAgentSkill`, `renderPromptTemplate`) |
| Agent discovery | 1 | ✅ real projection of `[[agent_upstreams]]` with the tenant-visibility rule preserved |

So the honest summary is: **route registration parity is complete and guarded;
behavioral parity is complete for assets and streaming, and is missing its
reliability layer for inference.**

---

## 5. Middleware chain — Rust `request_filter` vs the TS chain

Rust order (`handlers.rs::handle_request_filter`), against
`createGatewayApp` + `GATEWAY_MIDDLEWARE`:

| # | Rust step | TS | Finding |
|---:|---|---|---|
| 1 | assign `request_id` (`AtomicU64`) | ✅ `requestId` middleware, honours inbound `x-request-id` | — |
| 2 | `ClientActionTimeModule` | ❌ | **F12** |
| 3 | W3C trace-context extraction | ❌ | **F2** |
| 4 | `/control/v1` → `/admin/v1` alias | n/a for this Worker; ported in `apps/control-plane/src/middleware/alias.ts` | — |
| 5 | IP allowlist + unauthenticated per-IP rate limit | ❌ | **F1** |
| 6 | CORS preflight for `OPTIONS /admin/*` | n/a here; `apps/control-plane/src/middleware/cors.ts`. Gateway-wide CORS is marked at `inference/errors.ts:70` | — |
| 7 | CSRF / confused-deputy for `/admin/*` mutations | n/a here; ported in `apps/control-plane` | — |
| 8 | `run_pre_request_hooks` | ❌ | **F12** |
| 9 | contract match → 405 if path documented but method not | ✅ contract-driven `GatewayRouter.register` + `contractAuth` | — |
| 10 | `/healthz` / `/readyz` short-circuit | ✅ | — |
| 11 | route-group dispatch | ✅ (contract-driven, anti-drift tested) | — |
| 12 | fall-through: static site → dynamic proxy route | ❌ | **F9** |
| — | *(post-auth)* rate limit / quota | ✅ DO limiter + quota chain | budget/wallet steps marked |
| — | *(post-auth)* guardrails | ✅ | — |
| — | *(post-response)* metering drain | ✅ | — |

Four of the twelve ingress steps are absent from the Worker that serves the data
plane; three of those four (2, 3, 5) run **before authentication** in Rust,
which is precisely why F1 matters: the Rust comment on `check_network_access`
says the gate exists "so a flood or credential-stuffing scan never pays the
virtual-key/storage lookup cost."

---

## 6. Markers added by this pass

Eight `PORT-TODO(...)` markers, each at the seam that would have to change —
not at the file that noticed:

| File | Anchors |
|---|---|
| `apps/gateway/src/index.ts` (`GATEWAY_MIDDLEWARE`) | F1, F2, F12 — the composition root is where the missing pre-auth middleware would mount |
| `apps/gateway/src/inference/ports.ts` (`ModelResolver`) | F3, F4, F5 — the one-route seam is the reason none of them can exist |
| `apps/gateway/src/inference/catalog.ts` (`modelRecordSchema`) | F4, F6 — `fallbacks`/`priority`/`weight`/`context_window`/`prices`/`routing_strategy` are unrepresentable in the config var |
| `apps/gateway/src/inference/handlers.ts` (dispatch site) | F10, F11 |
| `apps/gateway/src/routes/index.ts` (`createGatewayApp`) | F9 |
| `packages/routing/src/index.ts` | F7 |
| `packages/providers/src/registry.ts` | F8 |
| `packages/providers/src/models.ts` | F6 (the strategy enum with no consumer) |

## 7. Notes on method

- **No behavior was implemented and no test was touched**, so there is nothing
  to mutation-test in this change: every edit is a comment. The claims above are
  each backed by a `grep` over the TS tree plus the cited Rust file:line, and the
  two dead-code findings (F7, F8) were confirmed by import-graph search
  (`from "@ferrogate/routing"` → 1 hit, in a docstring;
  `ProviderAdapterRegistry` → 0 importers outside `packages/providers`).
- **F7 and F8 are the defect class named in the porting rules** — modules fully
  implemented and fully tested but never mounted on the app the Worker exports.
  Both are green in every suite today. When either is wired up, the wiring commit
  must add an assertion that fails when it is unmounted, and prove it red by
  mutation, exactly as `test/contract.test.ts` does for the route modules.
