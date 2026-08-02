# Legacy Inventory — POLICY-CORE cluster

Authoritative port spec for the 1:1 Rust → TypeScript (Bun + Hono + Zod + Cloudflare)
rewrite. Covers five crates:

| Crate | Role | LOC (src, incl. tests) |
|---|---|---|
| `ferrogate-core` | Shared domain primitives (identity, tool types, error) | ~260 |
| `ferrogate-config` | Config model + loader + validation + Caddyfile compat + signed snapshots | ~1.1M chars across many files (types.rs 127KB, validate.rs 173KB) |
| `ferrogate-policy` | Pure policy decisions: quota merge, workflow budget, x402 spend | ~120K chars |
| `ferrogate-guardrails` | Typed detector contract + PII/secret/injection/content-mod detectors | ~470K chars |
| `ferrogate-secrets` | Secret-reference resolution (env / Vault / Cloudflare Secrets Store) | ~150K chars |

Dependency direction (low → high): `ferrogate-core` sits at the bottom.
`ferrogate-policy`, `ferrogate-guardrails`, `ferrogate-secrets` build on `core`
(+ storage/payments/cloudflare). `ferrogate-config` sits ON TOP of all of them —
it is the operator-facing config surface that references every other crate's enums.

> Note: x402 / Solana payment code is present in `config` and `policy` but is
> **deprioritized** per the port directive; it is documented at survey depth only.

---

## 1. `ferrogate-core`

### 1.1 Purpose
The shared vocabulary every layer must read identically: request identity,
tenant attribution, canonical tool types, and a boundary error. No dependency on
any layer above; depends only on `serde` + `serde_json`.

File: `crates/ferrogate-core/src/lib.rs` (single file).

### 1.2 Public API surface
- `const SECRET_SHAPED_KEY_FRAGMENTS: &[&str]` — the 10 case-insensitive
  substrings (`secret`, `signer`, `signature`, `private`, `keypair`, `mnemonic`,
  `seed`, `credential`, `password`, `token`) that must never appear in any
  admin/diagnostics response key at any depth. **Port as a shared constant + a
  recursive redaction helper.**
- `enum ApprovalPolicy { Never (default), Always }` — snake_case serde.
- `struct RequestContext` — request identity threaded through runtime/auth/routing/logs.
- `struct TenantContext` — tenant fields resolved from a virtual API key.
- `struct WorkspaceScope { tenant_id, project_id, workspace_id }` + `new()` + `apply_to(&mut TenantContext)`.
- `struct ToolDef { name, description?, input_schema: Value }`.
- `struct ToolCall { id, name, arguments: Value }`.
- `struct ToolResult { tool_call_id, content: Value, is_error }`.
- `type Result<T> = std::result::Result<T, GatewayError>`.
- `struct GatewayError { code, message }` + `new()`.

### 1.3 Core domain models (→ Zod schemas)
```
RequestContext {
  request_id: string
  trace_id?: string
  agent_run_id?: string          // #[serde(default)]
  workflow_id?: string
  workflow_version?: u32
  workflow_node_id?: string
  route?: string
  upstream?: string
  tenant: TenantContext
}
TenantContext {                  // ALL fields optional
  organization_id?: string       // == tenants.id; the tenant/billing boundary.
  team_id?: string
  project_id?: string
  workspace_id?: string          // #[serde(default)] — additive, legacy payloads omit it
  user_id?: string
  api_key_id?: string
}
WorkspaceScope { tenant_id: string, project_id: string, workspace_id: string }
```
**Load-bearing semantics to preserve in TS:**
- `organization_id` IS the tenant id and is used for authorization (tenant-isolation
  checks), not just attribution. `None`/`undefined` means "names no tenant" — only
  legitimate for a platform operator, and (since issue #515) must be *declared*, not inferred.
- `TenantContext.workspace_id` must deserialize from legacy payloads that omit it
  (Zod `.default(undefined)` / `.optional()`).
- `WorkspaceScope.apply_to` maps `tenant_id → organization_id`, fills `project_id`/`workspace_id`.

### 1.4 Business logic
None beyond `WorkspaceScope::apply_to` overlay and `GatewayError::new`. This is a
pure types crate.

### 1.5–1.7 Config / secrets / IO
None.

### 1.8 CF/TS mapping
- Pure TS module: `src/core/types.ts` (Zod schemas + inferred types) and
  `src/core/errors.ts` (`GatewayError`). No CF product. Zod for `TenantContext`,
  `RequestContext`, `ToolDef/Call/Result`. `input_schema`/`arguments`/`content` are
  arbitrary JSON → `z.unknown()` or `z.any()`.
- Clean 1:1 port; no friction.

---

## 2. `ferrogate-policy`

### 2.1 Purpose
Pure, side-effect-free policy DECISION boundaries. Given already-fetched state
(injected via closures/args) it returns Allow/Deny/merged-quota values. It never
does I/O — storage lookups are passed in as `impl Fn`. Three modules: `quota`,
`workflow_budget`, `x402_spend` (deprioritized).

Depends on `ferrogate-core`, `ferrogate-storage` (for `StoredQuotaPolicy`,
`StoredPlan`, `QuotaScopeKind`, `StoredWorkflowRunBudget`, `WorkflowBudgetDimension`),
`ferrogate-payments` (x402).

### 2.2 Public API surface (`lib.rs`)
- `enum PolicyDecision { Allow, Deny { code, message } }`
- `trait PolicyEngine { fn evaluate(&self, req: &RequestContext, model: Option<&str>, provider: Option<&str>) -> PolicyDecision }`
- `struct BasicPolicyEngine { rules: Vec<PolicyRule> }` + `new()` — impl of `PolicyEngine`.
- `struct PolicyRule { subject: PolicySubject, models: Vec<String>, providers: Vec<String>, code, message }` + `deny()`.
- `struct PolicySubject { organization_id?, project_id?, api_key_id? }`.
- Re-exports from `quota`, `workflow_budget`, `x402_spend`.

### 2.3 Core domain models
- `EffectiveQuota` (the merged result — see below).
- `QuotaScopeChain<'a> { tenant_id?, project_id?, workspace_id?, key_id? }` (borrowed strs).
- `QuotaScopeSelector { kind: QuotaScopeKind, id: String }`.
- `WorkflowBudgetCaps { cost_budget_credits?: i64, token_budget?: i64, tool_call_budget?: i64, wall_clock_millis?: u64 }`.
- `WorkflowNodeDispatchPolicy<'a> { node_id, model?, providers: &[String] }`.

### 2.4 Business logic — reimplement precisely

**(a) `BasicPolicyEngine::evaluate`** — first matching rule wins; default Allow.
A `PolicyRule` matches when: `PolicySubject` matches the tenant (each of
`organization_id`/`project_id`/`api_key_id` is either `None` = wildcard or must
equal the tenant's value), AND the model is in `models` (empty = any) AND provider
in `providers` (empty = any). Match ⇒ `Deny{code,message}`.

**(b) `resolve_effective_quota(chain, lookup, plan)` → `EffectiveQuota`** — the
multi-level quota merge (the heart of rate limiting). Algorithm:
1. Build scope list in fixed order `[Tenant, Project, Workspace, Key]`, keeping
   only scopes present in the chain; for each, call `lookup(kind, id) -> Option<StoredQuotaPolicy>`.
2. **Fail closed:** if ANY fetched policy has `enabled == false`, return
   `EffectiveQuota { denied_by: Some(that_scope_kind), ..default }` immediately
   (all other fields left default).
3. Otherwise fold each policy:
   - `model_allowlist`: **intersection** across every scope that defines a
     non-empty allowlist. `None` = unrestricted. A contradictory intersection ⇒
     empty list ⇒ denies every model.
   - `rpm_limit`, `tpm_limit`, `monthly_budget_usd`, `agent_cost_budget_usd`
     (#428), `monthly_egress_bytes_budget` (#262), `download_rpm_limit` (#262):
     each is the **`min` across the chain** ("nearest scope overrides but can
     never exceed an ancestor cap" — provably identical to min because min is
     commutative/associative). Each records a `*_scope` selector for the WINNING
     scope. **Ties go to the most specific scope** (Key > Workspace > Project >
     Tenant): the fold overrides on `<=` given Tenant→Key iteration order.
   - `asset_storage_quota_bytes` + `asset_max_object_bytes` (#259): taken from the
     Tenant-scoped policy only (not a min-merge).
4. If a `plan` (`StoredPlan`, issue #168) is given, it supplies the FLOOR: a field
   takes the plan default ONLY when no policy in the chain set it. Plan-supplied
   limits are keyed on the **Tenant** scope selector. Plan never tightens/loosens
   an explicit value.
- `EffectiveQuota::is_denied()` = `denied_by.is_some()`.
- `EffectiveQuota::allows_model(m)` = allowlist is `None` OR contains `m`.

**(c) `QuotaScopeSelector::counter_key(api_key_id)`** — the rate-limit/budget
counter-window key. **Security-critical:** every scope is namespaced `"{kind}:{id}"`.
For `Key`, it uses `"key:{api_key_id}"` (the actual key id, prefixed). This
prefix prevents a tenant minting a virtual key whose id is `"tenant:<victim>"`
from colliding a per-key window with another tenant's aggregate window
(cross-tenant DoS). Preserve exactly: `key:` / `tenant:` / `project:` / `workspace:` prefixes.

**(d) Workflow budget (`workflow_budget.rs`, #279):**
- `resolve_workflow_budget_envelope(graph, node)` — per-dimension `min` (node may
  tighten but never widen graph ceiling; `None` = unbounded, dominated by any `Some`).
- `WorkflowBudgetCaps::deadline_unix(started_at)` — `wall_clock_millis` rounded UP
  (`div_ceil(1000)`) to whole seconds, saturating-added to start.
- `preflight_workflow_budget(budget: &StoredWorkflowRunBudget, cost, tokens, tool_calls, now) -> Result<(), WorkflowBudgetDenial>` —
  pure fail-closed pre-flight: if run status is `EXHAUSTED` OR
  `budget.dimension_exceeded_by(...)` returns a dimension, deny with a
  dimension-qualified code `workflow_budget_exceeded:{cost|tokens|tool_calls|wall_clock}`.
  Does NOT mutate the ledger (durable `debit_workflow_run_budget` remains authoritative).
- `evaluate_node_dispatch(node, requested_model?, requested_provider?)` — fail-closed
  at dispatch: a node pinned to a model rejects any other model
  (`workflow_node_model_not_allowed`); a node with a non-empty provider allowlist
  rejects any provider outside it (`workflow_node_provider_not_allowed`). `None`
  requested side ⇒ that facet is not gated.

### 2.5 Config loading / 2.6 Secrets / 2.7 IO
None — everything is injected. `lookup` closures replace storage; `StoredPlan`/
`StoredQuotaPolicy` come from the storage crate.

### 2.8 CF/TS mapping
- **Pure TS module** `src/policy/` — no CF product needed for the algorithms.
  The `lookup` closure maps to an async fetch from **D1** (`StoredQuotaPolicy`,
  `StoredPlan`, `StoredWorkflowRunBudget`). Keep the resolve functions pure/sync;
  fetch state first, then call.
- The `counter_key` output is the **key for a Durable Object rate-limit counter**
  (or KV counter). The min-merge selects WHICH DO instance a window is keyed to —
  central to enforcing an aggregate cap across N keys under one tenant/project/workspace.
- Zod schemas for `EffectiveQuota`, `WorkflowBudgetCaps`, `PolicyRule`, `PolicySubject`.
- `StoredWorkflowRunBudget.dimension_exceeded_by` lives in the storage crate — port
  it alongside (it decides the breached dimension for a proposed spend at `now`).

---

## 3. `ferrogate-guardrails`

### 3.1 Purpose
Typed, bounded guardrail DETECTOR contracts and the built-in `custom_http`
runtime, plus native detectors: deterministic (keyword/regex/secret/JSON-schema/
request-constraint), Microsoft Presidio (PII/DLP), ProtectAI LLM-Guard (prompt
injection), and Cloudflare Workers-AI Llama-Guard (content moderation). Owns
detector execution + its safety boundary: async I/O, deadlines, bulkheads
(semaphore), circuit breakers, SSRF-safe DNS, typed results, and constrained
text patches. **Policy composition and gateway wiring live elsewhere** — this
crate only executes one detector at a time and reports a verdict.

Deps: `async-trait`, `ferrogate-cloudflare`, `hmac`, `jsonschema`, `reqwest`,
`regex`, `rustls`, `sha2`, `tokio`. Feature `conformance` exposes the test harness.

Module map: `contract` (types + trait), `envelope` (protocol normalization +
patch application), `deterministic` (in-repo detector), `policy` (revisions +
composition domain), `custom_http` (HTTP detector runtime), `net` (SSRF DNS),
`adapters/{presidio,llm_guard,workers_ai_llama_guard,fixture}`, `conformance`,
`evaluation` (accuracy corpus + shadow/promotion).

### 3.2 Public API surface (`contract.rs`)
- `const MAX_DETECTOR_TIMEOUT = 30s`; `CONTRACT_VERSION = 1` (pub(crate)).
- `enum DetectorStage { Request, Response }` (snake_case).
- `struct DetectorTenant<'a> { organization_id?, team_id?, project_id?, user_id?, api_key_id? }`.
- `struct DetectorInput<'a> { protocol: GuardrailProtocol, stage, tenant, model?, provider?, text: &str, segments: &[ContentSegment] }`.
- `enum DetectorCredentialType { None, BearerToken }`.
- `enum DataResidency { InRepo, ProviderSaas, CustomerVpc }`.
- `struct DetectorDescriptor { id, version, supports_request, supports_response, supports_transform, supported_sources: Vec<ContentSource>, credential, data_residency, max_payload_bytes, declared_failure_modes: Vec<DetectorErrorKind> }`.
- `enum DetectorVerdict { Pass, Fail }`.
- `enum FindingSeverity { Info, Low, Medium, High(default), Critical }`.
- `struct Finding { category, severity, confidence?: f32, byte_start?, byte_end?, segment_id?, fingerprint?, matched_text?, attributes: Map }`.
  - **Evidence rule:** `fingerprint` is a keyed non-reversible HMAC id; `matched_text`
    is kept ONLY in the in-memory decision path and must NEVER be persisted as evidence.
- `struct ContentPatch { segment_id, expected_fingerprint, protocol_location, byte_start, byte_end, replacement }`.
- `struct DetectorResult { verdict, findings, patches, detector_version }` + `first_matched_text()`.
- `enum DetectorErrorKind { Timeout, Unavailable, InvalidResponse, Overloaded, Unauthorized, PayloadTooLarge, CircuitOpen, InvalidConfiguration, InvalidPatch, StalePatch, ProtectedPath, Internal }` + `as_str()`.
- `struct DetectorError { kind, message }` + `safe_message()`, `affects_circuit()`, `retriable()`.
  - `affects_circuit` = Timeout | Unavailable | InvalidResponse | Overloaded.
  - `retriable` = Timeout | Unavailable | Overloaded.
- `struct DetectorHealth { circuit_open, consecutive_failures, in_flight, request_total, success_total, failure_total }`.
- `#[async_trait] trait GuardrailDetector { fn descriptor() -> DetectorDescriptor; fn health() -> DetectorHealth; async fn evaluate(&self, input, deadline: Instant) -> Result<DetectorResult, DetectorError> }`.
- `struct DetectorSecret(String)` — redacting wrapper (`Debug` prints `<redacted>`), `expose()`/`as_bytes()` pub(crate).

### 3.3 Envelope model (`envelope.rs`)
- `enum GuardrailProtocol { ChatCompletions, Responses, Embeddings, Images, ManagedAction, A2a }`
  - Embeddings/Images/ManagedAction/A2a are REQUEST-only or built directly (no
    HTTP response normalization).
- `enum ContentSource { System, Developer, User, Assistant, ToolSchema, ToolArguments, ToolResult, Metadata, TextAttachment, Unknown }` (+ `ALL_CONTENT_SOURCES`, `all_content_sources()`).
- `enum SegmentContentType { Text, Json, TextAttachment }`.
- `struct ContentSegment { segment_id, source, protocol_location, content_type, text, fingerprint }`.
- `struct GuardrailEnvelope { protocol, stage, segments }` + `from_text`, `managed_action`, `flattened_text` (joins with `"\n"`), `total_text_bytes`.
- `fn content_fingerprint(text) -> "sha256:<hex>"`.
- `fn normalize_request(protocol, body: &Value) -> GuardrailEnvelope` — walks the
  provider request JSON into segments. Extractors per protocol (chat: `messages[].content`
  incl. multi-part text/input_file text-attachments, `tool_calls[].function.arguments`,
  `tools[]`, `metadata`; responses: `instructions`/`input`/`output` items incl.
  `function_call`/`function_call_output`; embeddings/images: `input`/`prompt`).
  `source_for_role` maps role → ContentSource.
- `fn normalize_response(protocol, body: &[u8], streaming) -> GuardrailEnvelope` —
  non-streaming JSON or SSE frame accumulation (`accumulate_chat_sse`,
  `accumulate_responses_sse`, keyed by `(source, location)` in a BTreeMap, joined
  in order); falls back to a raw-body Assistant segment.
- **Patch application (security-critical):**
  - `validate_content_patches_for_segments(segments, patches)` — patches must
    reference a known segment, match its `protocol_location`, match its
    `expected_fingerprint` (else `StalePatch`), have a valid non-overlapping
    UTF-8-boundary byte range (`byte_start <= byte_end <= len`, char boundaries).
  - `apply_content_patches_to_document(document, envelope, declared_sources, patches)` —
    only applies to exact text-bearing protocol paths; re-checks fingerprint against
    the LIVE document text (else `StalePatch`); replaces ranges right-to-left.
  - `validate_content_patch_permissions` — patch target's source must be in
    `declared_sources` AND be a mutable text source (System/Developer/User/
    Assistant/ToolResult/TextAttachment) with content_type Text/TextAttachment,
    else `ProtectedPath`. JSON/metadata/tool-schema/tool-args are immutable.
  - `value_at_protocol_path_mut` + `parse_protocol_path` — a mini dotted/indexed
    path parser (`messages[0].content`), rejects `..`/leading-`.`.

### 3.4 Business logic — the detectors

**(a) DeterministicDetector (`deterministic.rs`)** — the in-repo, no-backend,
transform-capable detector. Config: `DeterministicDetectorConfig { id, supported_sources,
keywords, regex, max_input_bytes?, json?: JsonConstraints, request?: RequestConstraints,
secret_patterns: Vec<SecretPattern>, fingerprint_key?: DetectorSecret }`.
- `enum SecretPattern { OpenAiApiKey, GithubToken, AwsAccessKeyId }` — each has a
  fixed regex (v1 favors precision over recall):
  - OpenAI: `\bsk-(?:proj-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{32,})\b`
  - GitHub: `\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b`
  - AWS access key id: `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`
  - category strings: `secret.openai_api_key` / `secret.github_token` / `secret.aws_access_key_id`.
- `JsonConstraints { schema?: Value, required_keys: Vec<String> (RFC6901 pointers),
  forbidden_keys: Vec<String> }` — schema via `jsonschema` crate; failures →
  `json.json_schema` / `json.required_key` / `json.forbidden_key` findings.
- `RequestConstraints { allowed_endpoints: Vec<GuardrailProtocol>, allowed_models,
  forbidden_models, allowed_providers, forbidden_providers, metadata?: JsonConstraints,
  tool_parameters?: JsonConstraints }` — context findings `request.endpoint/model/provider`,
  plus metadata/tool_parameters JSON checks on Metadata/ToolArguments segments.
- **Scan algorithm (`evaluate`):** deadline check (expired ⇒ Timeout). Select
  segments whose source is in `supported_sources`. Optional `max_input_bytes`
  over-limit ⇒ `size.input_bytes` finding.
  - **Coalesced-group scan:** consecutive SAME-source segments concatenated (no
    separator) so a token split across adjacent parts is caught; match offsets
    mapped back to per-segment sub-ranges (`add_group_match`).
  - **Per-segment scan:** re-run keyword/regex/secret over each segment so
    `\b`/`^`-anchored patterns keep their per-segment anchor context (the
    coalesced concat can destroy a word boundary). `add_text_match` dedupes.
  - Keywords → `contains` (High), regex → `regex` (High), secrets → category
    (Critical, conf 0.99). JSON per-segment; request constraints once.
  - Findings on mutable text segments also emit a redaction `ContentPatch`
    (`[REDACTED]`), skipping overlaps (kept non-overlapping via sorted interval
    maps; overlap avoidance is REQUIRED — overlapping patch sets are rejected
    downstream and would collapse into whole-field redaction).
  - **Bounded evidence:** `MAX_FINDINGS_PER_EVALUATION = 10_000`. On overflow,
    stop and emit ONE zero-width `detector.truncated` (Critical) finding with no
    covering patch → forces fail-closed (can't be fully scrubbed).
  - Dedup keyed on `(category, segment_id, byte_start, byte_end)`; O(n log n) via
    HashSet + per-segment BTreeMap interval probes.
  - Fingerprint = `hmac-sha256:<hex>` over the matched value (requires `fingerprint_key`).
  - Verdict Fail iff any findings; `matched_text` always `None` (never persisted).

**(b) CustomHttpDetector (`custom_http.rs`)** — bounded external HTTP detector.
Config: `CustomHttpDetectorConfig { id, endpoint, timeout, max_concurrency,
circuit_failure_threshold, circuit_cooldown, max_retries, max_payload_bytes,
max_response_bytes, allow_private_network, supported_sources, bearer_token? }`.
- On construct: validate config + endpoint (`validate_custom_http_endpoint`:
  http(s) only, host required, no userinfo/password/query/fragment; unless
  `allow_private_network`, rejects `localhost` and disallowed IPs). Build reqwest
  client with no redirects, connect_timeout, custom SSRF DNS resolver.
- `evaluate`: deadline check; **circuit gate** (open + within cooldown or
  half-open probe in flight ⇒ `CircuitOpen`; else allow one half-open probe);
  project supported segments; payload-size check; JSON body
  (`{contract_version, protocol, stage, tenant, model, provider, text, segments}`);
  acquire **semaphore permit** bounded by deadline (timeout ⇒ `Overloaded`);
  retry loop (`retriable && attempt < max_retries`, max_retries capped at 1) with
  per-attempt `timeout.min(remaining)`; `send_once` streams body up to
  `max_response_bytes` (else `PayloadTooLarge`); `parse_detector_response`
  (accepts new `verdict` or legacy `match`+`matched_text`, requires a verdict);
  `validate_detector_result` (patches valid; finding byte ranges within their
  segment/text and on char boundaries). Circuit success/failure bookkeeping.
- Error classification: `classify_reqwest_error` (timeout/connect/other),
  `status_error` (401/403 → Unauthorized, 429 → Overloaded, 5xx → Unavailable,
  else InvalidResponse).

**(c) Native adapters (`adapters/`)** — over a `DetectorTransport` trait
(`post_json(body) -> TransportReply{status, body}`); prod = `HttpJsonTransport`
(same SSRF/bounded-response pattern), tests = `FixtureTransport`. Shared helpers:
`hmac_evidence_fingerprint` (`hmac-sha256:<hex>`), `char_index_to_byte_offset`
(Python code-point → byte offset), `config_digest` (4-byte sha256 prefix appended
to `detector_version`), `AdapterCounters`, `native_adapter_failure_modes` (no
CircuitOpen, no patch kinds).
- **PresidioDetector** — `POST /analyze` (`{text, language, score_threshold,
  entities?}`) → `[{entity_type, start, end, score}]` (code-point indexed).
  Transform-capable (redacts spans ≥ threshold on mutable segments,
  non-overlapping). Findings `pii.presidio.<entity_lowercased>` (High). CustomerVpc.
- **LlmGuardPromptInjectionDetector** — `POST /analyze/prompt` (`{prompt}`) →
  `{is_valid, scanners: {name: score}, sanitized_prompt (ignored)}`. Detect-only
  (`supports_transform: false`). Hit iff `!is_valid || scanners["PromptInjection"]
  >= threshold`. Finding `prompt_injection.llm_guard` (High). CustomerVpc.
- **WorkersAiLlamaGuardDetector** (#422) — Cloudflare Workers-AI Llama-Guard via
  the shared `CloudflareClient` (`POST accounts/{account_id}/ai/run/@cf/meta/llama-guard-*`
  with chat `messages`). Content-moderation (NOT prompt-injection), detect-only,
  ProviderSaas. `interpret_response` handles plain `"safe"`/`"unsafe\nS2,S9"`,
  bool, or structured object; hazard S-codes S1..S14 (`normalize_hazard_code`,
  `hazard_name` table). Optional `categories` allow-list filters which S-codes
  Fail. Findings `content_moderation.llama_guard.<code>`; CF errors mapped to
  detector taxonomy (`classify_cloudflare_error`). **Only constructible when a
  `[cloudflare]` block is configured** = graceful disable.

**(d) SSRF DNS (`net.rs`)** — `GuardrailDnsResolver { allow_private_network }`
implements reqwest `Resolve`; `filter_resolved_detector_addresses` drops
disallowed IPs. `is_disallowed_detector_ip` (pub) covers v4 (private, loopback,
link-local, unspecified, multicast, broadcast, documentation, CGNAT 100.64/10,
192.0.0.0/24, benchmarking 198.18/15, ≥240) and v6 (loopback, unspecified,
multicast, ULA fc00::/7, link-local fe80::/10, site-local fec0::/10, doc 2001:db8::/32,
v4-mapped). **This must be reimplemented — see CF friction below.**

### 3.5 Policy composition domain (`policy.rs`)
Not enforcement (that lives in the gateway), but the immutable revision model +
deterministic composition. Key types (all serde, `deny_unknown_fields`):
- `PolicyMode { Enforce, Shadow }`, `PolicyExecution { Sequential, Parallel }`,
  `PolicyStreamingMode { BufferAndEnforce, ShadowAfterComplete, RejectStreaming }`,
  `PolicyRevisionStatus { Draft, Active, Archived }`.
- `PolicyAggregation { All, Any, Threshold{minimum} }`.
- `PolicyScopeSelector { tenant_ids, organization_ids, project_ids, workspace_ids,
  api_key_ids, service_account_ids, gateway_config_ids, models, providers,
  managed_action?: ManagedActionSelector }` + `matches(ctx)`, `administrative_rank()`
  (0–5, gateway_config highest), `validate()`.
- `ManagedActionClass { Mcp, Tool, Cli, Skill, Filesystem, Browser, Rest, Secret,
  Memory, Network }` + `as_str()`; `ManagedActionSelector { classes, targets }`;
  `ManagedActionContext { class, target? }`; `PolicySelectionContext { ... managed_action? }`.
- `DetectorDefinition` (tagged enum `kind`): `Local {...}`, `CustomHttp {...}`,
  `Presidio {...}`, `LlmGuardPromptInjection {...}`, `WorkersAiLlamaGuard {...}` —
  each with `validate()` (URL/endpoint/limit/threshold/fingerprint rules; timeouts
  ≤ 30s; `max_retries ≤ 1`; Llama-Guard model must start `@cf/meta/llama-guard`;
  category S-codes unique/valid). Defaults via `default_detector_*` fns
  (timeout 2000ms, max_concurrency 16, circuit_failure_threshold 3, cooldown 30000ms,
  max_payload 1 MiB, max_response 256 KiB, presidio language "en", threshold 50%).
- `CheckBinding { id, enabled, stage, sources, detector, fallback_detector? }`
  (fallback must be Local).
- `ActionKind { Allow, Block, Redact, Record, RequireApproval, Quarantine }`;
  `PolicyAction { kind, code?, message? }` (enforcing kinds require code+message).
- `PolicyRevision { policy_id, revision, name, description?, enforced, scope,
  checks, aggregation, execution, mode, streaming, on_pass, on_fail, on_error,
  deadline_ms, created_at_unix, created_by }` + `immutable_id()` (`id@rev`),
  `validate()` (ids/name/created_by/revision≠0; deadline 1..30000; ≥1 enabled
  check; unique check ids/sources; threshold ≤ enabled count; non-empty
  on_pass/fail/error), `selected_check_ids(stage)`.
- `PolicyRevisionView { revision (flattened), status }`.
- Outcome model: `CheckOutcome { Pass, Fail, Error, Disabled }`,
  `AggregateOutcome { Pass, Fail, Error }`, `aggregate_check_outcomes(agg, outcomes)`
  (All: any fail⇒Fail, else any error⇒Error, else Pass; Any: any pass⇒Pass...;
  Threshold: failures≥min⇒Fail, failures+errors≥min⇒Error, else Pass).
- `select_policy_revisions(policies, ctx)` — filter by scope match, sort by
  `(administrative_rank, policy_id, revision)`.

### 3.6 Conformance + evaluation (test/feature-gated)
- `conformance.rs`: `run_detector_conformance` drives 6 behaviours (pass verdict,
  sanitized fail, transform validates, error classified in declared modes, timeout
  on expired deadline, version reported). `MockAdapter` scriptable. `PROBE_SECRET`
  = assembled `AKIA...` (never a real credential).
- `evaluation.rs`: accuracy corpus (`EvaluationCase`, `EvaluationCorpus`,
  `reference_corpus` v2), `run_detector_evaluation` (precision/recall/F1 +
  p50/p95/max latency), shadow scoring (`record_shadow_observations`,
  `score_shadow_observations`), promotion gate (`PromotionThresholds::conservative`,
  `PromotionGate::assess_shadow`/`assess_enforced` → Promote/Hold/Keep/Rollback with hysteresis).

### 3.7 External services & IO
- Outbound HTTPS to custom detector endpoints, self-hosted Presidio, self-hosted
  LLM-Guard (all SSRF-guarded, bounded).
- Cloudflare Workers-AI via shared `CloudflareClient`.
- `jsonschema` for JSON-schema constraints; `regex`; `hmac`+`sha2`.

### 3.8 CF/TS mapping
- Runs inside a **Worker** (`GuardrailDetector` = an async interface). Detector
  execution per request; timeouts via `AbortController`.
- **DeterministicDetector** → pure TS + a JS regex engine. **PII/secret scanning →
  keep the deterministic detector AND/OR use Cloudflare AI Gateway's native
  Guardrails / Llama-Guard.** The `WorkersAiLlamaGuard` adapter maps directly to
  **Workers AI** (`env.AI.run("@cf/meta/llama-guard-*")`) — no external client needed.
- **EICAR-style scanning:** there is no AV/EICAR here; malware scanning is
  referenced in `config` (asset commit path) but out-of-cluster. Secret/PII
  scanning is the deterministic + Presidio path.
- **HMAC fingerprints** → WebCrypto `crypto.subtle.sign('HMAC', ...)`.
- **JSON Schema** → `ajv` (or `@cfworker/json-schema`, workerd-friendly).
- **Circuit breaker / semaphore bulkhead / health counters** → per-detector state
  in a **Durable Object** (shared circuit state across requests), or in-isolate
  state accepting per-isolate scope. `MAX_DETECTOR_TIMEOUT`, retry, bounded
  response reads carry over.
- **SSRF DNS filtering — NO clean CF equivalent (flag).** Workers `fetch` does not
  expose DNS resolution or a custom resolver; you cannot pre-resolve and filter IPs
  before connecting, and outbound `fetch` from a Worker cannot reach RFC1918/loopback
  anyway. Port `is_disallowed_detector_ip` as host/allowlist validation on the
  *config* value (reject `localhost`, private-range literals in the endpoint URL),
  and rely on the Worker egress boundary for the rest. This is a genuine behavioral gap.
- `matched_text`-never-persisted and the redaction-patch validation must survive
  the port verbatim — they are the crate's security invariants.

---

## 4. `ferrogate-secrets`

### 4.1 Purpose
Resolve a `secret_ref` string to its live value across three backends:
`env://NAME`, `vault://<mount>/<path>#<field>` (HashiCorp Vault KV v2), and
`cf://<store>/<name>` (Cloudflare Secrets Store). Deliberately dependency-light:
a hand-rolled blocking rustls HTTP client for Vault; the shared async
`CloudflareClient` for the CF REST manage-plane.

Deps: `ferrogate-cloudflare`, `anyhow`, `http`, `rustls`(+native-certs,pki-types),
`serde`, `serde_json`, `tokio` (only to bridge async CF client to the sync trait).

### 4.2 Public API surface
- `enum SecretRef { Env{name}, Vault{mount, path, field}, CfSecret{store, name} }` + `parse(raw)`.
- `trait SecretResolver { fn resolve(&self, &SecretRef) -> Result<Option<String>> }`
  — `Ok(None)` = "not found/unset", `Err` = genuine failure. Requires `Debug + Send + Sync`.
- `struct EnvSecretResolver` — reads env, empty-string = unset.
- `struct VaultConfig { address, token, ca_cert_path?, timeout }` (hand-written
  `Debug` redacts `token`) + `from_env()` (VAULT_ADDR/VAULT_TOKEN/VAULT_CACERT).
- `struct VaultSecretResolver` — `GET {addr}/v1/{mount}/data/{path}`, reads
  `data.data.<field>`, checks `errors`.
- `struct SecretResolverRegistry { vault?, cloudflare?, cf_bindings: CfSecretBindings }`
  + `new`, `with_vault`, `with_cloudflare`, `with_cf_bindings`, `from_env`, `resolve(raw)`.
- `fn http_get`, `fn http_post` — reusable minimal blocking HTTP(S) client (rustls).
- CF re-exports (see 4.6): `CfSecretsStoreConfig`, `CloudflareSecretResolver`,
  `CF_ACCOUNT_ID_ENV`/`CF_API_TOKEN_ENV`/`CF_API_BASE_URL_ENV`, beta-cap consts;
  `CfSecretBindings`, `cf_binding_env_var`, `cf_binding_name_is_unambiguous`,
  `CF_BINDING_ENV_PREFIX`; `CfSecretsCapacityPolicy`, `CfSecretsCapacityWarning`, cap-env consts.

### 4.3 Core domain models
`SecretRef` (parsed URI) is the model. Parse rules:
- `env://NAME` — name non-empty.
- `vault://<mount>/<path>#<field>` — requires `#field`, `<mount>/<path>`, all non-empty.
- `cf://<store>/<name>` — requires `<store>/<name>`, both non-empty.
- anything else ⇒ error naming the three schemes.

### 4.4 Business logic — resolution precedence
`SecretResolverRegistry::resolve(raw)`:
1. `env://` → always via `EnvSecretResolver`.
2. `vault://` → `VaultSecretResolver` if configured, else error naming VAULT_ADDR/VAULT_TOKEN.
3. `cf://` → **Worker-binding context first** (`CfSecretBindings`, no network),
   then the CF REST backend (`CloudflareSecretResolver`) if configured; else a
   precise error explaining that Secrets Store values are write-only over REST.

### 4.5 Config loading
Env-driven, mirroring Vault's convention (`from_env` on each config type). No file
format of its own — this crate is called BY `ferrogate-config` when a `secret_ref`
field needs resolving. `resolve_env_placeholders` (in the config crate) is the
related `{env.NAME}` string interpolation.

### 4.6 Secrets — the Cloudflare Secrets Store story (central to CF port)
**Key constraint: Secrets Store values are WRITE-ONLY over REST.** No REST endpoint
returns a stored value; the ONLY read path is a **Worker binding at runtime**
(deploy-time binding). This crate encodes that split:
- **`cloudflare.rs` (`CloudflareSecretResolver`)** — the REST MANAGE plane only:
  - `create_secret(store, name, value, comment?)` — writes via `POST
    accounts/{account_id}/secrets_store/stores/{store_id}/secrets` with
    `scopes: ["workers"]`. Enforces capacity guardrails BEFORE any network call.
    Rejects non-canonical names (must match `[a-z0-9-]+`) so they can't collide
    under the lossy env-var mapping.
  - `resolve()` = **existence check only** — walks list-stores → list-secrets;
    absent ⇒ `Ok(None)`; present ⇒ a precise Err pointing at the binding path.
    Never returns a value.
  - `CfSecretsStoreConfig { account_id, api_token_ref, api_base_url? }` — the token
    is held as a **reference** (`env://CLOUDFLARE_API_TOKEN`), never a value;
    materialized per-request by `EnvTokenResolver` at the Authorization header.
  - `block_on_cloudflare` bridges the async CF client to the sync trait via a
    dedicated thread + current-thread runtime (irrelevant in TS — everything async).
  - Beta caps: 1 store, 100 secrets, 1024 bytes/value per account.
- **`cloudflare_bindings.rs` (`CfSecretBindings`)** — the VALUE resolution path
  (decision #423, Option A): a name→value map. Two injection paths:
  1. **Env convention** (always on): `FERROGATE_CF_SECRET_<NAME>` where `<NAME>` is
     the secret name uppercased with every non-alphanumeric → `_`
     (`cf_binding_env_var`). LOSSY, so only accepted for **canonical names**
     (`^[a-z0-9-]+$`, `cf_binding_name_is_unambiguous`); a non-canonical name with
     no exact injected binding ⇒ Err (would risk serving the wrong credential).
  2. **Injected map** (`from_map`/`insert`) — keyed by exact name, lossless, any name.
     Consulted BEFORE the env convention. `Debug` redacts values, prints names+count.
- **`cloudflare_caps.rs` (`CfSecretsCapacityPolicy`)** — fail-fast beta-cap
  guardrails for the write path: `check_value_size` (≤ 1024 B default),
  `check_secret_budget` (hard error creating a NEW secret at/over 100; soft
  `CfSecretsCapacityWarning` at ≥ 90). Env overrides
  `FERROGATE_CF_SECRETS_MAX_SECRETS`/`_WARN_AT`/`_MAX_VALUE_BYTES`.

### 4.7 External services & IO
Vault over rustls HTTPS (blocking, native + optional CA cert); Cloudflare REST via
`CloudflareClient`; process environment.

### 4.8 CF/TS mapping
- **`cf://` value resolution → Cloudflare Secrets Store binding.** In the Worker,
  a `secrets_store_secrets` binding in `wrangler.jsonc` exposes the value at
  runtime (`await env.MY_SECRET.get()`). `CfSecretBindings` becomes reading from
  `env` bindings; the `FERROGATE_CF_SECRET_*` env convention maps to Worker
  vars/bindings. **The deploy-time binding constraint is native to Workers** — a
  binding must be declared at deploy and cannot be read via REST. This crate's
  whole write-only/binding split is exactly the Workers model; the port is
  natural, but note: the mapping name→binding is decided at deploy, so dynamic
  `cf://<name>` references must correspond to declared bindings (or an injected map
  built from `env`). **Flag:** you cannot resolve an arbitrary `cf://` at runtime
  that wasn't bound at deploy — same as the Rust binding-context requirement.
- `env://` → Worker plaintext `vars` / secrets (`wrangler secret put`).
- `vault://` → **NO clean CF equivalent (flag).** A Worker can `fetch` a Vault
  HTTP API, but the hand-rolled blocking rustls TCP client (`http_get`/`http_post`)
  must be replaced with `fetch`; custom CA trust and raw-socket TLS are not
  available in workerd. For most CF deployments, prefer migrating `vault://` refs
  to CF Secrets Store bindings; keep `vault://` only for self-hosted/hybrid via `fetch`.
- The REST manage-plane (`create_secret`, existence check, capacity guards) →
  Cloudflare API via `fetch` with an API token from a Worker secret. Beta caps and
  canonical-name guard port verbatim as TS validation.
- Redaction of secret values in `Debug`/logs → a `toJSON`/logger-redaction discipline in TS.

---

## 5. `ferrogate-config`

### 5.1 Purpose
The operator-facing configuration: the `Config` model an operator writes, the
loader that reads it (TOML/YAML/Caddyfile), the validation that refuses a bad one,
the Caddyfile→Config compatibility bridge, secret-placeholder resolution, R2/asset
endpoint decomposition, pre-auth network-access primitives, upstream/route URI
building, config-snapshot ids, and Ed25519-signed cluster config snapshots.

**This crate sits on top of the whole workspace** — its `Config` fields are typed
as other crates' enums (`RoutingStrategy`, `ContentSource`, `PostgresTlsMode`,
`ModelCapability`, `McpServerConfig`, `CloudflareConfig`, `X402SpendPolicy`, ...),
and several validators pre-flight the very constructors the runtime will call.

Public surface is a curated `pub use` list in `lib.rs` (the private `mod config`
is re-exported name-by-name; that list, not the module tree, is the contract).
Deps: `anyhow`, `base64`, `ed25519-dalek`, `http`, `pingora`, `regex`, `reqwest`,
`serde`+`serde_json`+`serde_yaml`, `sha2`, `tokio`, `toml`, `tracing`, and 10
sibling ferrogate crates.

### 5.2 Public API surface (highlights from `lib.rs` re-exports)
- `parse_caddyfile`, `is_caddyfile_path`, `load_caddyfile`.
- Asset endpoint: `parse_endpoint`, `parse_r2_endpoint`, `endpoint_targets_r2`,
  `EndpointParts`, `R2Endpoint`, `R2_ENDPOINT_SUFFIX`, `R2_REGION`.
- Network access: `resolve_client_ip`, `IpCidr`, `UnauthenticatedIpRateLimiter`.
- Routing: `build_target_uri`, `normalize_host`, `parse_upstream_endpoint`, `UpstreamEndpoint`.
- Signed snapshots: `build_snapshot_crypto`, `SignedSnapshotEnvelope`,
  `SignedSnapshotPayload`, `SnapshotCrypto`, `SnapshotSigner`.
- `config_snapshot_id`, `resolve_env_placeholders`, `x402_hold_ttl_floor_secs`.
- The whole `Config` type + ~120 config structs/enums (see 5.3).
- Caddyfile intermediate types (`types.rs`): `GatewayConfig`, `GatewayProvider`,
  `GatewayModel`, `GatewayApiKey`, `GatewayRoute`, `GatewayUpstream`, `GatewayHeader`,
  `GatewayLog`, `GatewayTlsConfig`, `GatewayTlsAcmeConfig`, `StaticResponse`.
- `CaddyfileDiagnostic` (file:line:col + directive + message + suggestion).
- x402 (deprioritized): `X402SpendPolicy`, `ValidatedX402SpendPolicy`,
  `load_x402_spend_policy_toml`, `X402ScopedSpendPolicy`, scope-resolution fns, etc.

### 5.3 Core domain model — `Config` (→ the big Zod schema)
`Config` (in `config/types.rs`, lines 21–202) is the root. Top-level fields
(all `#[serde(default)]` unless noted):
`listen`, `admin: AdminConfig`, `tls: TlsConfig`, `auth_service`, `billing_service`,
`admin_api`(effective, serialized as `control_api`, `skip_deserializing`),
`control_api`/`admin_api_alias` (raw inputs, `skip_serializing`), `providers:
Vec<Provider>`, `models: Vec<Model>`, `api_keys: Vec<ApiKey>`, `policies:
Vec<PolicyRule>`, `gateway_configs`, `agent_workflows`, `skill_packages`,
`prompt_templates`, `guardrails: Vec<GuardrailRule>`, `plugins`, `extensions`,
`mcp_servers: Vec<McpServerConfig>` (from `ferrogate-mcp`), `agent_upstreams`,
`telemetry`, `billing_alerts`, `observability`, `analytics`, `metering`, `cache`,
`storage: StorageConfig`, `reliability`, `limits: LimitsConfig`, `agent_runtime`,
`cluster`, `upstreams: Vec<Upstream>`, `routes: Vec<RouteRule>`, `network_access`,
`asset_bucket`, `scheduler`, `asset_lifecycle`, `x402_sweeper`, `x402_reconciler`,
`x402_spend_policies`, `asset_egress_price_per_gb?`, `cloudflare:
Option<CloudflareConfig>` (from `ferrogate-cloudflare`), `tenancy: TenancyConfig`,
`auth: AuthConfig`, `api_keys_are_control_plane_documents` (`#[serde(skip)]`).

~120 nested types (from `grep`): `AuthConfig`, `TenancyConfig`, `SchedulerConfig`,
`AssetLifecycleConfig`, `X402SweeperConfig`, `X402ReconcilerConfig`,
`AssetBucketBackend`, `AssetBucketConfig`, `NetworkAccessConfig`, `AdminConfig`,
`AdminApiConfig`, `AuthServiceConfig`, `BillingServiceConfig`, `ClusterConfig`,
`ClusterSnapshotKey`, `AgentRuntimeConfig`/`Provider`/`External`/`ManagedWorker`,
`ManagedWorkerCapability*Config`, `TlsConfig`, `TlsAcmeConfig`, `Provider`,
`ProviderCloudflareAiGatewayConfig`/`Mode`, `Model`, `CanaryRoute`, `ShadowRoute`,
`ModelFallback`, `ApiKey`, `PolicyRule`, `GatewayConfigProfile`, `AgentWorkflow*`,
`PromptTemplate*`, `GuardrailRule`, `GuardrailProviderRuntimeConfig`,
`GuardrailProviderErrorMode`/`Kind`, `GuardrailStage`, `GuardrailEffect`,
`ExtensionKind`/`Config`/`Permissions`, `PluginManifest`/`Compatibility`,
`SkillPackage*`, `TelemetryConfig`, `BillingAlertsConfig`, `ObservabilityConfig`/
`Provider`, `AnalyticsConfig`/`Provider`, `MeteringConfig`/`ExportProvider`/
`ExportSubject`, `CacheConfig`/`CacheMode`, `AccessLogMode`, `StorageConfig`/
`StorageMigrationMode`, `ReliabilityConfig`, `LimitsConfig`, `Upstream`,
`AgentUpstream*`, `RouteRule`, `HeaderMutation`, `HeaderMatcher`.

**Representative structs already extracted (for schema building):**
- `Provider` — `name, kind(default "openai"?), base_url, api_key_env?, secret_ref?
  (env://|vault://|cf://, precedence over api_key_env), openrouter_http_referer?,
  openrouter_x_title?, enabled(true), region?, aws_access_key_id?,
  aws_secret_access_key_env?, aws_session_token_env?, gcp_project_id?,
  gcp_access_token_env?, cloudflare_ai_gateway?`.
- `Model` — `name, provider, provider_model, routing_strategy(default),
  fallbacks[], canary?, shadow?, visible_organization_ids[], visible_project_ids[],
  capabilities[], context_window?, input_price_per_1m?: f64, output_price_per_1m?,
  enabled(true), cache_enabled?`.
- `ApiKey` — `id, name, key_env?, key? (dev only), key_hash?, enabled(true),
  scopes[], allowed_models[], denied_models[], allowed_providers[],
  denied_providers[], region_allowlist[], organization_id?, platform_operator?:
  bool (mutually exclusive with organization_id), team_id?, project_id?,
  workspace_id?, user_id?, monthly_token_budget?, request_limit_per_minute?,
  expires_at_unix?, log_bodies?, cache_enabled?`.
- `GuardrailRule` — `id, name, enabled(true), stage(request), sources(all),
  organization_ids[], project_ids[], api_key_ids[], models[], providers[],
  keywords[], regex[], max_input_bytes?, provider: GuardrailProviderKind(None|
  CustomHttp|Presidio|LlmGuardPromptInjection), provider_endpoint?,
  provider_language?, provider_score_threshold_percent?, provider_entities?,
  provider_fingerprint_secret_ref?, provider_timeout_ms(2000),
  provider_runtime(flattened GuardrailProviderRuntimeConfig), effect(Deny|Redact),
  code, message`. This is the CONFIG mirror that gets translated into the
  guardrails crate's `DetectorDefinition`/`PolicyRevision`.
- `AuthConfig { disabled: bool }` — `false` (default) = auth required.
- `TenancyConfig { implicit_platform_operator: bool(false), require_registered_tenant: bool(false) }`.
- `StorageConfig` — provider + provider_order (libsql/postgres/cloudflare_d1/...),
  libsql/postgres/supabase DSNs + `_env` variants, pool/timeout/tls settings,
  `d1_control_database_id?`, `d1_tenant_databases: BTreeMap`, migration_mode, admin
  list limits.
- `LimitsConfig` — 9 per-route body-size caps (inference 1 MiB, admin 64 KiB,
  admin_small 16 KiB, admin_config 256 KiB, tool 64 KiB, asset_control 64 KiB,
  agent_ingress 128 KiB, worker_transport 1 MiB, guardrail_policy 1 MiB) with
  `DEFAULT_*` consts + accessor methods applying defaults.
- `AssetBucketConfig` — `enabled, backend (S3|WorkersStaticAssets), endpoint?,
  bucket?, region?, access_key_id?, secret_access_key_env?, presign_ttl_secs?,
  presign_max_object_bytes?, max_gateway_buffer_bytes?, max_total_gateway_buffer_bytes?,
  buffer_admission_wait_ms?, cf_account_id?, cf_api_token?(ref), cf_script_name?`;
  `builds_s3_client()` = enabled && backend==S3.

### 5.4 Business logic
- **`Config::validate()`** (`validate.rs`, ~1800 lines, 98 fns) — the load-time gate.
  Delegates to dozens of helpers: postgres identifier/DSN checks, TLS file
  presence, header name/value validity (via `http` types), plugin/skill-package
  manifest + permission validation, prompt-template placeholder checks, managed-worker
  action lists, x402 scoped-policy validation (delegates to the policy crate), asset
  bucket R2 host/region rules, tenancy-posture warnings, api-key tenant-identity
  enforcement (`ensure_api_key_declares_tenant_identity`,
  `api_keys_without_tenant_identity`, `warn_implicit_platform_operators`), etc.
  Also `materialize_skill_package_resources[_with_previous]`, `plugin_registrations`.
- **Network access (`network_access.rs`)** — `IpCidr::parse`/`contains` (v4/v6 CIDR,
  bare IP = /32 or /128, prefix masking); `resolve_client_ip` (uses
  `X-Forwarded-For` from the RIGHT by `trusted_proxy_hops`, only when
  `trust_forwarded_for`; falls back to `X-Real-IP` then peer; fail-closed when the
  chain is shorter than the hop count — anti-spoof); `UnauthenticatedIpRateLimiter`
  (fixed per-minute window per source IP, `MAX_TRACKED_SOURCE_IPS = 100_000` with
  clear-on-overflow to bound memory).
- **Routing (`routing.rs`)** — `parse_upstream_endpoint` (scheme/authority/base_path),
  `RouteRule::rewrite_path` (strip_prefix/add_prefix), `build_target_uri`,
  `normalize_host`, path join helpers.
- **Asset endpoint (`asset_endpoint.rs`)** — `parse_endpoint` → `EndpointParts`
  (scheme, authority lowercased, path_prefix); `parse_r2_endpoint` → `R2Endpoint`
  (account_id + `eu`/`fedramp` jurisdiction) with strict host/scheme/port/path rules;
  `endpoint_targets_r2`. R2 pinned to region `auto`; suffix `r2.cloudflarestorage.com`.
- **Snapshot id (`snapshot.rs`)** — `config_snapshot_id` = FNV-1a-64 hex of the
  serialized JSON config (stable, change-detecting).
- **Env placeholders (`secrets.rs`)** — `resolve_env_placeholders("...{env.NAME}...")`
  interpolates uppercase/digit/`_` env-var names; errors on unterminated/invalid/unset.
- **Signed snapshots (`signed_snapshot.rs`, ~800 lines)** — Ed25519 sign/verify of
  a cluster config snapshot: `SignedSnapshotPayload`, `SignedSnapshotEnvelope`,
  `VerifiedSnapshot`, `sign_snapshot`/`verify_snapshot`, `RejectReason`, `SignError`,
  `SnapshotConfigError`, `parse_signing_key`/`parse_verifying_key`, `SnapshotSigner`,
  `SnapshotVerifier`, `SnapshotCrypto`, `build_snapshot_crypto`, `SignedSnapshotStore`,
  `SnapshotIngestOutcome`, `OfflineStatus`. `SIGNED_SNAPSHOT_SCHEMA_VERSION = 1`.

### 5.5 Config loading — formats, precedence, validation
`Config::load(path)`:
- missing file ⇒ defaults (with a warning).
- filename exactly `Caddyfile` (case-insensitive) ⇒ Caddyfile bridge.
- `.yaml`/`.yml` ⇒ serde_yaml; otherwise ⇒ TOML.
- Every path then runs: `migrate_control_plane_aliases` → `resolve_paths_relative_to`
  (cert/key/ACME paths made relative to the config dir) → `materialize_skill_package_resources`
  → `validate()`.
- Constructors: `from_toml_str`, `from_yaml_str`, `from_caddyfile_str`,
  `from_gateway_config` (Caddyfile intermediate → runtime `Config` mapping).
- **`control_api` vs `admin_api` precedence:** canonical `[control_api]` used
  directly; deprecated `[admin_api]` alias works with a warning; BOTH present ⇒
  hard error; neither ⇒ defaults. Idempotent.
- Secret references (`secret_ref`) and `{env.NAME}` placeholders resolved
  separately (by the secrets crate / `resolve_env_placeholders`), not during parse.

### 5.6 Caddyfile compatibility (`caddyfile/`)
A small compatibility subset: `lexer.rs` (`TokenKind`), `parser.rs` (recursive-descent
`Parser` over tokens → `GatewayConfig`), `parser_support.rs` (helpers:
`adapt_site_address`, `caddy_path_to_prefix`, `env_reference`, `global_suggestion`,
`looks_like_upstream`, `model_ref_arg`). Supported directives include: `reverse_proxy`,
`handle_path`, `header_up`/`header_down`, `respond`, `encode`, `log`, `tls`
(+ ACME: `domains`/`email`/`directory_url`/`challenge`/`dns`/`dns_hook_*`/renewal
knobs), `admin`, `auth` (`auth off`), and the FerroGate `ai_gateway { provider,
model, api_key { ... }, policy, ... }` blocks (`provider`/`base_url`/`api_key_env`/
`openrouter_*`, `model`/`capabilities`/`context_window`, `api_key`/`key`/`key_env`/
`key_hash`/`scopes`/`allowed_models`/`denied_models`/`allowed_providers`/
`denied_providers`/`monthly_token_budget`/`request_limit_per_minute`/
`organization_id`/`platform_operator`). Env references via `env.NAME`, `{env.NAME}`,
`{$NAME}`. Errors are structured `CaddyfileDiagnostic` (file:line:col + suggestion).

### 5.7 External services & IO
Filesystem (config + Caddyfile + TLS files), `reqwest`/`tokio` (validators that
pre-flight subsystem constructors), `pingora` TLS loader (a config that validates
is one the server can bind), Ed25519 (`ed25519-dalek`) for signed snapshots.

### 5.8 CF/TS mapping
- **`Config` → one big Zod schema tree** (`src/config/schema.ts`), inferred TS
  types. `#[serde(default)]` → `.default(...)`, snake_case enums →
  `z.enum([...])`, `deny_unknown_fields` → `.strict()`.
- **Loader → Worker startup / build step.** TOML/YAML parsing is unusual for a
  Worker; config more naturally lives in **wrangler vars / KV / D1 / a bundled JSON
  asset**. Options: (a) parse TOML/YAML at build/deploy time and ship JSON; (b)
  keep a small TOML/YAML parser for a `wrangler`-uploaded config. The
  `control_api`/`admin_api` alias merge, relative-path resolution, and
  `validate()` port as pure TS.
- **`validate()`** — port as a layered Zod refinement + custom checks (the ~98
  helper fns become `superRefine` predicates). This is large but mechanical.
- **Caddyfile parser** — a self-contained recursive-descent parser + lexer; ports
  1:1 to TS. Likely deprioritizable for a CF-native deployment (Caddyfile is a
  legacy migration path), but the intermediate `GatewayConfig` model and diagnostics
  are clean to port.
- **Signed snapshots (Ed25519)** — → WebCrypto (`crypto.subtle` Ed25519 is
  supported in workerd) or `@noble/ed25519`. Snapshot store → **KV or D1**;
  `config_snapshot_id` (FNV-1a) → trivial TS. **Ingest/offline-status** logic ports directly.
- **Network access primitives** — `IpCidr`/`resolve_client_ip` → TS using
  `request.headers` + `cf-connecting-ip`. **On Cloudflare, `CF-Connecting-IP` is
  the trustworthy client IP** (Cloudflare sets it), which largely SUPERSEDES the
  `X-Forwarded-For`-from-the-right anti-spoof logic — flag as a simplification
  opportunity, but keep the CIDR allowlist matcher. `UnauthenticatedIpRateLimiter`
  → a **Durable Object** or **KV/rate-limiting binding** (the in-process HashMap is
  per-isolate and won't share state; use CF's native rate-limiting or a DO counter).
- **Storage config** — `provider = cloudflare_d1` + `d1_control_database_id` /
  `d1_tenant_databases` already anticipates **D1**; libsql/postgres map to external
  DBs via `fetch`/Hyperdrive. This is the natural CF target.
- **Asset endpoint / R2** — `parse_r2_endpoint` + `R2_ENDPOINT_SUFFIX` map to
  **R2** (native binding) or R2's S3 API; `AssetBucketBackend::WorkersStaticAssets`
  maps to **Workers Static Assets**. `endpoint`/SigV4 logic mostly disappears with a
  native R2 binding.
- **`LimitsConfig` body caps** → Hono body-size middleware.
- **Flag (no clean CF equivalent):** the `pingora` TLS-loader pre-flight and the
  blocking TLS/cert-file validation are irrelevant on Cloudflare (CF terminates
  TLS); `TlsConfig`/`TlsAcmeConfig` and ACME challenge handling drop out entirely
  on the CF edge — the whole manual-TLS + ACME surface has no CF analogue and
  should be marked "N/A on Cloudflare" rather than ported.

---

## Appendix: cross-cutting security invariants to preserve verbatim
1. **`matched_text` is never persisted** (guardrails) — only `fingerprint` goes to
   durable evidence; conformance harness asserts the raw value never appears in
   serialized results.
2. **HMAC-keyed, non-reversible fingerprints** (`hmac-sha256:<hex>`) for all secret/PII evidence.
3. **Fail-closed everywhere:** disabled quota policy ⇒ hard deny; exhausted
   workflow budget ⇒ deny every step; truncated findings ⇒ unredactable ⇒ deny;
   detector error ⇒ policy `on_error` decides (never silent pass).
4. **Counter-key namespacing** (`key:`/`tenant:`/`project:`/`workspace:`) prevents
   cross-tenant rate-limit-window collision.
5. **SSRF guard** on all detector egress (private-range denylist) — partially
   subsumed by the Worker egress boundary but must stay as endpoint validation.
6. **Redacted `Debug`** on every secret-bearing type (`VaultConfig.token`,
   `CfSecretsStoreConfig.api_token_ref`, `CfSecretBindings.values`,
   `CfSecretCreate.value`, `DetectorSecret`) — port as logger/`toJSON` redaction.
7. **Tenant identity must be declared, not inferred** (`organization_id`/
   `platform_operator`) — an omitted identity is refused, never promoted to root.
8. **Cloudflare Secrets Store values are write-only over REST**; the only read path
   is a deploy-time Worker binding — this is native to Workers and must gate any
   dynamic `cf://` resolution.
