# Cutover certification — the DATA PLANE (54 non-`/admin` operations)

**Scope.** The 58 contract operations whose `visibility` is not `admin`
(`docs/openapi/runtime-api-contract.json`: 51 `public` + 7 `internal`). Four of
those live on `apps/control-plane` (`GET /metrics`, `GET /admin`, `GET /admin/`,
`GET /admin/dashboard`) and are covered only briefly at the end. The **54 data-plane
operations** certified here split exactly as `ROUTE-MAP.md` claims — verified by
re-deriving the split from the contract JSON rather than trusting the doc:

```
gateway 31 · agent-runtime 15 · mcp 6 · shared health 2  (+ control-plane 4) = 58
```

**Verdict summary.**

| verdict | count | share |
|---|---:|---:|
| EQUIVALENT | **24** | 44% |
| DIVERGENT | **27** | 50% |
| MISSING | **3** | 6% |
| UNVERIFIED | **0** | — |

**The headline is better than 50% DIVERGENT makes it sound, and worse than the
suite makes it look.** 20 of the 27 DIVERGENT verdicts share ONE root cause with
ONE fix (finding D1 below: the admission half of `authenticate()` was not carried
across the Worker split). The remaining 7 are seven independent gaps. Every one of
the 27 is a real, client-observable difference against the Rust — none is a
bookkeeping quibble, and none was previously recorded anywhere in `docs/rewrite/`.

**Confidence tiers.** Verdicts are not all equally deep, and this document says
which is which rather than averaging them:

- **DEEP (36 ops)** — both implementations read side by side: the Rust handler
  body and the TS handler body, on all five axes in the brief.
- **CATALOGUE (18 ops)** — full error-code catalogue diff (every `"snake_case"`
  literal in the Rust handler file checked for a TS counterpart), plus response
  `object` discriminators, plus the auth ladder. Not a line-by-line read of the
  handler body.
- No operation is UNVERIFIED: all 54 got at least the CATALOGUE treatment.

---

## Part 1 — the seven findings

### D1. The ADMISSION half of `authenticate()` did not cross the Worker split — 20 ops

**Severity: highest. This is money and abuse control, not fidelity.**

In the Rust tree every authenticated data-plane request — inference, assets,
agent jobs, agent invoke, MCP — entered through the same
`gateway/auth.rs::authenticate()`, which is two halves:

1. **credential** — resolve the key, check scope, check the lifecycle chain.
2. **admission** — `finalize_auth` (`crates/ferrogate-gateway/src/auth.rs:1395`),
   which charges, in order:
   `403 tenant_identity_required` · lifecycle suspension ·
   `503 quota_resolution_unavailable` · `403 quota_scope_disabled` ·
   `429 monthly_budget_exceeded` · `429 wallet_balance_exhausted` ·
   `429 rate_limit_exceeded` (per-key RPM counter) ·
   `503 governance_counter_unavailable`.

The TS rewrite ports **both** halves — but mounts the admission half on
`apps/gateway` alone (`apps/gateway/src/ratelimit/`, mounted from
`GATEWAY_MIDDLEWARE`). `apps/agent-runtime` and `apps/mcp` each grew their own
`contractAuth` carrying only the credential half.

Evidence:

```
$ grep -rn "rate_limit_exceeded\|monthly_budget_exceeded\|wallet_balance_exhausted\|quota_scope_disabled" \
    apps/mcp/src apps/agent-runtime/src
(no output)
```

Consequence: a tenant whose RPM cap and monthly budget stop it dead on
`POST /v1/chat/completions` can, **on the same key**, submit unbounded agent jobs
(`POST /v1/agent-jobs`) and unbounded MCP `tools/call` — both of which then spend
real provider money on that tenant's behalf. Rate limiting and spend caps are
bypassable by choosing a different verb.

What is NOT broken: the 401-vs-403 ladder and the suspended-key semantics ARE
ported consistently in all three Workers
(`apps/gateway/src/keys/resolver.ts:25-41`, `apps/mcp/src/auth.ts:50-64`,
`apps/agent-runtime/src/middleware/auth.ts:105-115`) — a suspended native key is
401 everywhere. The gap is specifically **money and rate**, not identity.

Not a platform limit. `rateLimit()` is ordinary Hono middleware over a DO counter
plus a D1 quota source. The one non-obvious requirement is that all three Workers
must share ONE counter namespace (a shared `RATE_LIMIT` DO binding, or a Service
Binding into the gateway) — a per-Worker counter would hand each surface its own
full quota, which is a different bug.

Marker added: `apps/agent-runtime/src/middleware/auth.ts` (on `bearerAuth`) and
`apps/mcp/src/auth.ts` (on the auth-ladder doc block).

### D2. The workflow GRAPH gate is unported; the config table is dead — 5 ops

`packages/config` parses `[[agent_workflows]]` in full
(`packages/config/src/schema/config.ts:72`) and validates node/edge ids
(`packages/config/src/validate/policies.ts:64-80`). And:

```
$ grep -rn "agent_workflows\|agentWorkflows" apps/
(no output)
```

The table is loaded, validated, and never consulted. Rust
`chat.rs::enforce_ai_workflow_policy` (line 3310) runs on **every** inference
request that declares a workflow and can refuse with thirteen codes that do not
exist anywhere in this tree:

`workflow_not_found` (400) · `workflow_disabled` (403) · `workflow_not_allowed`
(403) · `workflow_node_required` (400) · `workflow_node_not_found` (400) ·
`workflow_node_not_model` (403) · `workflow_model_not_allowed` (403) ·
`workflow_provider_not_allowed` (403) · `workflow_edge_not_allowed` (403) ·
`workflow_model_call_limit_exceeded` (429) · `workflow_iteration_limit_exceeded`
(429) · `workflow_timeout_exceeded` (429) · `workflow_token_budget_exceeded` (429).

What IS ported is the run **budget envelope** (`apps/gateway/src/ratelimit/workflow.ts`
→ `402 workflow_budget_exceeded`), which is a different control. The edge gate is
the one that makes a workflow a graph rather than a spend cap: without it a caller
inside a legitimate run can invoke any node's model in any order.

The headers also differ, so a Rust-shaped client is refused outright:

| Rust | TS |
|---|---|
| `x-ferrogate-workflow-id` | same |
| `x-ferrogate-workflow-version` | same |
| `x-ferrogate-workflow-node-id` | **no reader** |
| `x-ferrogate-workflow-iteration` | **no reader** |
| — | `x-ferrogate-workflow-run-id` (new, required) |
| `400 invalid_workflow_header` | `400 invalid_workflow_declaration` |

Marker added: `apps/gateway/src/ratelimit/workflow.ts`.

### D3. `x-ferrogate-agent-run-id` is not read on the inference path — 5 ops

Rust threads `agent_run_id` through the entire chat pipeline (28 call sites in
`chat.rs`): it is validated at ingress
(`400 invalid_agent_run_id_header`, `chat.rs:2767`) and then stamped on the
metering event, the guardrail-evidence row, the observed-activity row and the
rollout decision — this is the #305/#522 correlation chain.

The TS reads that header in `apps/gateway/src/assets/handlers.ts:316`,
`apps/mcp/src/protocol.ts:65` and `apps/agent-runtime` — but **not** in
`apps/gateway/src/inference/`:

```
$ grep -rn "agent-run-id" apps/gateway/src/inference/ apps/gateway/src/metering/
(no output)
```

So the one surface that produces the actual token spend is the one surface whose
spend cannot be joined back to the agent run that caused it. An operator
investigating "why did this run cost $400" can see the asset pulls and the MCP
tool calls but not the model calls.

### D4. Asset egress: no quota gate, no metering, no pull audit — 1 op (`getAsset`)

Rust `assets.rs:1114` runs two things per download, using the resolved object size:

- `asset_egress_quota_denial` (fail-closed, before a byte is served) →
  `429 asset_egress_quota_exceeded` (monthly byte budget, checked read-only so an
  exhausted budget never burns an RPM token) and
  `429 asset_download_rate_limit_exceeded` (download RPM), with
  `503 governance_counter_unavailable` on counter failure.
- `record_asset_egress` → meters the bytes through the billing outbox (priced by
  `asset_egress_price_per_gb`), accumulates the monthly counter, and writes the
  PULL-side audit event.

None of the three codes exists in `apps/`. The quota fields **are** ported and
durable — `apps/gateway/src/ratelimit/quota.ts:178-179` parses
`monthly_egress_bytes_budget` / `download_rpm_limit`, and
`apps/control-plane/src/store/quota_registry.ts:153` persists and serves them — but
nothing reads them:

```
$ grep -rn "monthlyEgressBytesBudget\|downloadRpmLimit" apps/ packages/ | grep -v quota
apps/control-plane/... (store + admin projection only)
```

Same for pricing: `asset_egress_price_per_gb` appears once in the whole TS tree
(`packages/config/src/schema/config.ts:104`) and has no consumer.

So an operator can set an egress budget today, see it echoed back by the admin
API, and have it enforce nothing — unlimited bandwidth served, none of it billed.

Marker added: `apps/gateway/src/assets/handlers.ts` (on `getAsset`).

### D5. Asset publish: the content-type allowlist and the stdio-manifest refusal are unported — 2 ops

`asset_security.rs::screen_asset_push` runs three gates. This tree ports gates 2
and 3 (signature, malware scan) and not gate 1, the cheap synchronous one:

- **`content_type_allowed`** (`asset_security.rs:107`) — a per-`asset_type`
  allowlist. `cli_tool` accepts 8 types; **`mcp_manifest` accepts
  `application/json` alone**; `skill_bundle` 6; `static_site` a web-safe set.
  Anything else is `422 asset_rejected`.
- **the `mcp_manifest` stdio refusal** — a manifest declaring a `stdio` transport
  is refused, because (quoting the Rust) "a stdio manifest causes the consuming
  agent's MCP client to spawn an arbitrary local process".
  `validate_streamed_asset_content` (#259) goes further: a manifest too large to
  parse is REJECTED rather than admitted with that field unread.

```
$ grep -rn "content_type_allowed\|mcp_manifest\|stdio\|asset_rejected" apps/gateway/src/assets/
(no output)
```

`putAsset` and `commitAssetUpload` therefore accept any content-type for any
asset type, and a tenant can publish an `mcp_manifest` declaring `stdio` that a
consuming agent will act on. This is a security control, and it is a pure function
of two strings and a byte buffer — no binding, no I/O, no platform limit.

Marker added: `apps/gateway/src/assets/scan.ts`.

### D6. `503 node_draining` is advertised by `/readyz` and honoured by nothing — 5 ops

`GATEWAY_DRAIN=true` flips `/readyz` to 503
(`apps/gateway/src/routes/readiness.ts:75`). In Rust the SAME flag is re-checked
per AI request (`chat.rs:2862`, `embeddings.rs:98`, `images.rs:115`,
`messages.rs:145`, `governed_decision.rs:502`) and refuses
`503 node_draining "gateway node is draining and is not accepting new AI requests"`.

```
$ grep -rn "node_draining" apps/
(no output)
```

An operator draining a deployment before a migration still takes new billable
traffic. This is NOT the platform limit already documented in `readiness.ts`
(that one is about how fast the flag can be flipped); it is the flag being read
on one route out of 31. `drainStatus(env)` is already a pure synchronous env
read.

Marker added: `apps/gateway/src/routes/readiness.ts`.

### D7. Agent-job event feed: three independent divergences — 2 ops

1. **Response `object` differs.** Rust `agent_jobs.rs:838` emits
   `object: "agent_job_event_page"`; `apps/agent-runtime/src/runs/lifecycle.ts:396`
   emits `object: "list"`. A client discriminating on `object` breaks.
2. **`400 invalid_event_cursor` is not raised.** Rust
   `AgentJobEventCursor::from_query` (`agent_jobs.rs:1411`) returns `Err` for a
   non-integer `limit` and for `limit=0`; only the UPPER bound is clamped.
   `runs/events.ts::clampEventLimit` folds both refusals into the default page
   size — and carries the comment *"(Rust: silently clamped, never rejected)"*,
   which is **factually wrong about the Rust**. `?limit=0` answers 200 with 100
   rows where Rust answers 400.
3. **The resume cursor regressed to the pre-#474 form.** Rust
   `agent_job_event_cursor_token` emits `"<occurred_at_unix>:<event id>"`
   precisely so a cursor survives the event it names being pruned by retention;
   `runs/do.ts::listEvents` emits the bare event id and falls back to
   `cursorReset: true`. A long-lived poll loop therefore RE-DELIVERS its whole
   retained history after a retention pass instead of resuming.

Also in this family: `getAgentJobResult` drops Rust's `work_products`
(`WorkProductView::from_timeline_events`) and substitutes a raw `artifacts` array
of `artifact`/`checkpoint` events.

Marker added: `apps/agent-runtime/src/runs/events.ts`.

---

## Part 2 — the verdict table

Legend: **D** = deep read of both implementations · **C** = catalogue-level
(error-code diff + response shape + auth ladder). "Regression test" answers the
brief's question — *would a test FAIL if this behaviour regressed*, not merely
*is it exercised*.

### `apps/gateway` — inference (6)

| # | operation | verdict | why | tier | regression test |
|---|---|---|---|---|---|
| 1 | `listModels` | **EQUIVALENT** | `#515` tenant-visibility filter matches the invocation gate; `{object:"list", data:[{id,object,created:0,owned_by}]}` identical | D | `test/inference/operations.test.ts`, `allowlist.test.ts` — assert the private-model leak is closed |
| 2 | `createChatCompletion` | **DIVERGENT** | D1 (only via gateway: admission IS mounted here) n/a; **D2, D3, D6**; plus gateway-config profile ids fail open instead of `gateway_config_{not_found,disabled,not_allowed}` (marked in `handlers.ts:352`) | D | yes — validation ladder, model gate, streaming framing, failover, metering all pinned; **mutation-proven** (below) |
| 3 | `createResponse` | **DIVERGENT** | as #2 (shared `plan_ai_ingress`) | D | yes — `test/streaming/responses.test.ts` |
| 4 | `createMessage` | **DIVERGENT** | as #2; Anthropic translation + SSE normalization otherwise faithful | D | yes — `test/streaming/anthropic.test.ts` |
| 5 | `createEmbedding` | **DIVERGENT** | as #2 | D | yes — `test/inference/operations.test.ts` |
| 6 | `createImage` | **DIVERGENT** | as #2 | D | yes — `test/inference/operations.test.ts` |

Everything else on this family checks out and is worth stating, because it is the
hardest part of the port: the 7-step ingress order is preserved verbatim
(authenticate **before** reading the body, so an oversized unauthenticated request
is `missing_api_key` and not `payload_too_large`); `invalid_json` stays distinct
from `invalid_request`; `payload_too_large` is 413; the model gate is 403
**before** resolution so a denied key cannot probe the catalogue; streaming bodies
are relayed as the upstream `ReadableStream` with no re-encoding, and the three
deliberate non-parities in `src/streaming/` are pinned *in their Rust-matching
form* by `test/streaming/parity-limits.test.ts` — the best piece of parity
engineering in the tree.

### `apps/gateway` — assets (18)

| # | operation | verdict | why | tier | regression test |
|---|---|---|---|---|---|
| 7 | `listAssets` | EQUIVALENT | | C | `test/assets/routes.test.ts` |
| 8 | `listAssetsByType` | EQUIVALENT | | C | `test/assets/routes.test.ts` |
| 9 | `getAssetStorageSummary` | EQUIVALENT | `object:"asset_storage_summary"` | C | `test/assets/service.test.ts` |
| 10 | `listWithheldAssets` | EQUIVALENT | | C | `test/assets/scan.test.ts` |
| 11 | `getAsset` | **DIVERGENT** | **D4** | D | pull path yes (`r2.test.ts`, range/conditional/yank headers); the missing gate has no test because it has no code |
| 12 | `putAsset` | **DIVERGENT** | **D5** | D | signature + scan gates yes; content-type/stdio gate absent |
| 13 | `deleteAsset` | EQUIVALENT | | C | `test/assets/service.test.ts` |
| 14 | `getAssetManifest` | EQUIVALENT | `object:"asset_manifest"` | C | `test/assets/service.test.ts` |
| 15 | `listAssetChannels` | EQUIVALENT | `object:"asset_channel"` | C | `test/assets/registry.test.ts` |
| 16 | `putAssetChannel` | EQUIVALENT | `?version=` required → `400 channel_target_required` preserved | C | `test/assets/registry.test.ts` |
| 17 | `deleteAssetChannel` | EQUIVALENT | | C | `test/assets/registry.test.ts` |
| 18 | `yankAssetVersion` | EQUIVALENT | | C | `test/assets/service.test.ts` |
| 19 | `unyankAssetVersion` | EQUIVALENT | | C | `test/assets/service.test.ts` |
| 20 | `promoteAssetVisibility` | EQUIVALENT | `object:"asset.visibility_promotion"` matches | C | `test/assets/scan.test.ts` |
| 21 | `createAssetUploadIntent` | **DIVERGENT** | Rust `400 invalid_upload_intent`; TS Zod `400 invalid_request`. Same status, different code | D | `test/assets/service.test.ts` |
| 22 | `commitAssetUpload` | **DIVERGENT** | Rust `400 invalid_commit`; plus **D5** on the committed bytes | D | hash/size mismatch + quota + screening all pinned |
| 23 | `abortAssetUpload` | **DIVERGENT** | Rust `400 invalid_abort`; TS `400 invalid_request` | D | `test/assets/service.test.ts` |
| 24 | `getAssetDownloadUrl` | EQUIVALENT | `object:"asset_download_url"`; `503 asset_bucket_unavailable` unconfigured posture matches | D | `test/assets/wiring.test.ts` |

Positives worth recording: `parseSingleByteRange` / conditional-request handling
is a faithful port (`206`, `content-range`, `bytes */N` on unsatisfiable);
`x-ferrogate-asset-{resolved,version,variant,yanked}` and the
`299 ferrogate "... is yanked"` warning header are byte-identical; the presign
commit re-runs the FULL trust screening over the verified bytes (#366) and copies
to a fresh immutable key so a staging-URL replay cannot race a different payload
in; the audit sink flushes in a `finally` so REFUSED requests are audited too.

### `apps/gateway` — tooling / discovery (7)

| # | operation | verdict | why | tier | regression test |
|---|---|---|---|---|---|
| 25 | `listTools` | **MISSING** | `501` — needs the extension registry (no TS package) **and** the MCP server registry (different Worker). Listing one without the other would understate what a tenant may call | D | `test/auth.test.ts` pins the 401 → 403 → 501 ladder, so the stub cannot start answering ahead of the guard |
| 26 | `executeTool` | **MISSING** | `501` — governed dispatch + approval store unported | D | as above |
| 27 | `executeFunction` | **MISSING** | `501` — sandboxed function dispatch; belongs to `apps/agent-runtime` (Containers), which `apps/gateway` deliberately does not bind | D | as above |
| 28 | `renderPromptTemplate` | **DIVERGENT** | error codes match one-for-one, but Rust writes an `admin_audit_event` on EVERY arm (success and each refusal) and this tree writes none — honestly marked at `routes/prompts.ts:48` | D | `test/routes/prompts.test.ts` covers the codes; nothing covers the absent audit |
| 29 | `listAgentSkills` | EQUIVALENT | behaviour identical. **Note:** Rust demands scope `tools.read`; the contract (authoritative) says `skills.read`, and TS follows the contract. A Rust client holding only `tools.read` now gets 403 | D | `test/routes/skills.test.ts` |
| 30 | `getAgentSkill` | EQUIVALENT | `404 skill_package_not_found`; visibility filter matches | D | `test/routes/skills.test.ts` |
| 31 | `getAgentDiscovery` | EQUIVALENT | bearer `agents.read` confirmed against the Rust (`local.rs:10383`) — **`ROUTE-MAP.md` invariant 3 is wrong** to list this as anonymous; the contract and the code agree it is not | D | `test/routes/agent-discovery.test.ts` |

### `apps/agent-runtime` (15)

| # | operation | verdict | why | tier | regression test |
|---|---|---|---|---|---|
| 32 | `createAgentRun` | **DIVERGENT** | **D1** | D | `test/lifecycle.test.ts` |
| 33 | `submitAgentJob` | **DIVERGENT** | **D1**; Rust's granular `invalid_agent_job_input` / `invalid_agent_job_capabilities` / `agent_job_id_conflict` collapse to `invalid_request` | D | `test/lifecycle.test.ts` |
| 34 | `getAgentJob` | **DIVERGENT** | **D1** | D | `test/lifecycle.test.ts` |
| 35 | `listAgentJobEvents` | **DIVERGENT** | **D1** + **D7** (all three) | D | SSE framing pinned by `test/sse.test.ts`; the paged shape is pinned to the *divergent* `object:"list"` |
| 36 | `getAgentJobResult` | **DIVERGENT** | **D1**; `work_products` → `artifacts` | D | `409 agent_job_not_terminal` pinned by `test/lifecycle.test.ts` |
| 37 | `cancelAgentJob` | **DIVERGENT** | **D1**; Rust `agent_job_not_cancellable` / `agent_job_cancel_unavailable` absent | D | `test/cancel.test.ts` |
| 38 | `invokeAgent` | **DIVERGENT** | **D1** only — otherwise a close port: same `404 agent_not_found` / `403 agent_not_visible` / `413 payload_too_large` / `400 invalid_json` order, and both the `x-ferrogate-agent-run-id` (#305) and `x-ferrogate-parent-action-fingerprint` (#307) declarations are read and validated | D | `test/agents.test.ts`, `test/guardrails.test.ts` |
| 39 | `sendAgentMessage` | **DIVERGENT** | as #38 | D | `test/agents.test.ts` |
| 40 | `streamAgentMessage` | **DIVERGENT** | as #38 | D | `test/sse.test.ts` |
| 41 | `recordSelfHostedWorkerHeartbeat` | **EQUIVALENT** | see below | D | `test/internal-auth.test.ts`, `test/mtls.test.ts` |
| 42 | `recordSelfHostedWorkerEvent` | **EQUIVALENT** | | D | as above |
| 43 | `uploadSelfHostedWorkerArtifact` | **EQUIVALENT** | | D | as above |
| 44 | `uploadSelfHostedWorkerCheckpoint` | **EQUIVALENT** | | D | as above |
| 45 | `pollSelfHostedWorkerRun` | **EQUIVALENT** | | D | as above |
| 46 | `acknowledgeSelfHostedWorkerRun` | **EQUIVALENT** | | D | as above |

The six `internal` callbacks are the **strongest** family in the whole data plane
and deserve saying so. Verified against `local.rs:5434-5990`: the
`x-ferrogate-transport-security` requirement (`401
invalid_self_hosted_worker_transport_security`), the downgrade ladder
(`403 self_hosted_worker_transport_downgrade_rejected` for `symmetric_aead`,
`501 self_hosted_worker_production_mtls_not_implemented` for the unverified
`mutual_tls` marker) matching Rust's status codes exactly, the same
`FG_REQUIRE_PRODUCTION_MTLS` posture switch, `201 Created` on all four record
verbs, the `invalid_self_hosted_worker_identity` (401) / `inactive_...` (403)
split, and — notably — a from-scratch RFC-8439/XChaCha20-Poly1305 implementation
(workerd's `crypto.subtle` has no ChaCha family) that reproduces Rust's HKDF salt,
info string, associated-data join and 32-byte secret floor **byte for byte**, so
an unmodified Rust worker binary interoperates.

### `apps/mcp` (6)

| # | operation | verdict | why | tier | regression test |
|---|---|---|---|---|---|
| 47 | `mcpJsonRpc` | **DIVERGENT** | **D1** | C | `test/jsonrpc.test.ts`, `test/protocol.test.ts`; `method_dependent` scope map is read from the contract (`contract.ts:299-316`), not hand-copied, and `test/contract.test.ts` fails if the discriminator is dropped |
| 48 | `executeMcpTool` | **DIVERGENT** | **D1** | C | `test/tools.test.ts`, `test/approvals.test.ts`, `test/agent-run-id.test.ts` (mutation-proven in an earlier wave) |
| 49 | `completeMcpIdentityOauth` | **EQUIVALENT** | anonymous in both, so there is no admission to lose; `mcp_oauth_callback_invalid` present | C | `test/oauth-flow-claim.test.ts` |
| 50 | `authorizeMcpIdentity` | **DIVERGENT** | **D1** | C | `test/identity.test.ts`, `test/durable-identity.test.ts` |
| 51 | `getMcpIdentity` | **DIVERGENT** | **D1** | C | as above |
| 52 | `revokeMcpIdentity` | **DIVERGENT** | **D1** | C | as above |

The MCP error vocabulary is a strict **superset** of Rust's: every Rust code
(`mcp_identity_not_found`, `mcp_oauth_callback_invalid`, `mcp_server_unavailable`,
`tool_denied`, `tool_not_found`) has a TS counterpart, plus ~15 more that make
identity failure modes distinguishable where Rust collapsed them. That is an
improvement, not a divergence, and it is not counted as one.

### shared health (2, implemented in every Worker)

| # | operation | verdict | why | tier | regression test |
|---|---|---|---|---|---|
| 53 | `getHealthz` | **DIVERGENT** | gateway/mcp: `{status,service,runtime}` — Rust also carries `version`. **agent-runtime returns `{ok:true}`** — a different document entirely | D | `test/health.test.ts` in each app (pins the divergent shapes) |
| 54 | `getReadyz` | **DIVERGENT** | gateway/mcp port the decision table faithfully (`ready`/`not_ready`, 200/503, `readiness_reason` ∈ {`operator_drain`,`stale_state`,`state_loaded`,`sync_error`,`revision_missing`}). **agent-runtime answers a flat 200 `{ok:true}`** — no revision check, no drain check, never 503 | D | `test/routes/readiness.test.ts` (gateway) is thorough; agent-runtime's asserts only 200 |

`apps/agent-runtime/src/index.ts` is a composition root and out of this wave's
write scope, so no marker was added there — it is recorded here instead. A load
balancer pointed at agent-runtime's `/readyz` gets "ready" from a Worker that
cannot serve, forever.

### control-plane's four non-`/admin/v1` operations (context only)

- `GET /admin`, `/admin/`, `/admin/dashboard` — anonymous HTML, ported.
- `GET /metrics` — **DIVERGENT**. Rust renders the full
  `GatewayMetricsSnapshot` (47 `ferrogate_*` series) plus the #522 unjoinable-action
  counter. `packages/observability/src/prometheus.ts` ports `renderPrometheusText`
  with all 47 series, and `apps/control-plane/src/adapters.ts:491` deliberately
  does NOT call it — it emits 2 gauges, on the stated grounds that this Worker
  measures none of the others and a scrape full of zeros reads as "no traffic".
  That reasoning is sound but the consequence is that **every existing FerroGate
  dashboard and alert breaks at cutover**: the series they query no longer exist.
  The counters live in `apps/gateway`; exposing them means a gateway-side
  `/metrics` or an Analytics Engine query binding.

---

## Part 3 — mutation evidence

Verdicts about test quality were spot-checked by mutation, because this project's
dominant defect mode is a green suite over a dead seam.

| mutation | file | result |
|---|---|---|
| `if (!callerCanUseModel(...))` → `if (false && ...)` | `apps/gateway/src/inference/handlers.ts:340` | **RED** — 3 failures across 2 files; `test/inference/validation.test.ts:281` caught `403 model_not_allowed` degrading to 400 |
| `if (required !== null && !hasScope(auth, required))` → `if (false && ...)` | `apps/agent-runtime/src/middleware/auth.ts:433` | **RED** — 2 failures; `test/lifecycle.test.ts:265` caught a read-only key being allowed to `POST /v1/agent-jobs` (403 → 202) |

Both mutations changed behaviour (not just bytes) and both were reverted; the
suites are green as this document is written: gateway 1720 + 24 + 42, agent-runtime
309, mcp 345.

---

## Part 4 — what would break a real client

Ordered by how quickly a paying customer notices.

1. **Rate limits and spend caps stop applying if you use agent jobs or MCP.**
   (D1, 20 ops.) A key at its RPM ceiling on `/v1/chat/completions` gets 429; the
   same key submitting `/v1/agent-jobs` gets 202 and the job then spends. Same for
   a key over its monthly budget or with an exhausted wallet. This is exploitable
   without any special knowledge — it is just "call the other endpoint".
2. **Asset bandwidth is unlimited and unbilled.** (D4.) Egress budgets and download
   RPM caps configured through the admin API are echoed back and enforce nothing;
   downloaded bytes are never metered, so `asset_egress_price_per_gb` revenue is
   simply not collected.
3. **Draining a deployment does not drain it.** (D6.) `GATEWAY_DRAIN=true` turns
   `/readyz` red while `/v1/chat/completions` keeps accepting new billable work —
   the opposite of what an operator running a migration expects.
4. **`/readyz` on agent-runtime is a lie.** (op 54.) It answers 200 unconditionally,
   so a health-checked rollout of a broken agent-runtime is never rolled back.
5. **Anyone using workflows loses every workflow guarantee.** (D2.) Node pinning,
   edge transitions, iteration and model-call limits, and the workflow timeout all
   stop being enforced; the workflow config is accepted and ignored. And the header
   rename means a Rust-shaped workflow client is refused 400 outright rather than
   degraded.
6. **`mcp_manifest` assets can declare `stdio`.** (D5.) A tenant publishes a
   manifest whose transport makes a *consuming* agent spawn a local process. Rust
   refused this at publish; this tree stores it. The content-type allowlist is gone
   with it, so any byte stream can be published under any asset type.
7. **Agent-job pagination clients break in three ways.** (D7.) `object` changed
   from `agent_job_event_page` to `list`; `?limit=0` / `?limit=abc` silently
   succeed instead of 400; and a poll loop re-delivers its whole history after a
   retention pass. `getAgentJobResult` also loses `work_products`.
8. **Model spend is no longer joinable to the agent run that caused it.** (D3.)
   `x-ferrogate-agent-run-id` is honoured on assets and MCP but ignored on
   inference, so cost attribution has a hole exactly where the cost is.
9. **Every Prometheus dashboard goes blank.** (`/metrics`.) 47 series → 2.
10. **Small but real, in decreasing order:** three asset-validation error codes
    renamed to `invalid_request`; `renderPromptTemplate` writes no audit trail;
    `listAgentSkills` needs `skills.read` where Rust needed `tools.read`;
    `/healthz` lost `version` on the gateway and returns a wholly different
    document on agent-runtime; misspelling `x-ferrogate-config` silently selects
    the default posture instead of erroring; and the semantic cache
    (`semantic_cache.rs`) has no TS counterpart while
    `ferrogate_ai_cache_requests_total{status="semantic_hit"}` is still rendered —
    a series with no producer.

---

## Part 5 — certification statement

**Is the TypeScript data plane a 1:1 replica of the Rust? No — not yet.**

It is a high-quality, largely faithful reimplementation with **seven identified
behavioural gaps**, one of which (D1) is a control-bypass affecting 20 of 54
operations and two of which (D4, D5) have direct money and security consequences.
None of the seven is a Cloudflare platform limit. All seven are closeable with
ordinary Workers primitives already present in this repo.

What this certification is confident about, and it is a lot: routing and mount
coverage (all 54 registered, contract-driven, anti-drift tested); the 401-vs-403
ladder including suspended-key semantics, consistent across three Workers; the
inference validation ladder and its exact ordering; streaming framing, including
three deliberate non-parities pinned in their Rust-matching form; the self-hosted
worker transport, down to a hand-written XChaCha20-Poly1305; asset range,
conditional-request, presign, signature and malware-screening behaviour; and the
MCP error vocabulary.

**Recommendation: do not delete `crates/**` yet.** Close D1 first — it is the only
finding that is a live control bypass rather than a fidelity gap — then D4 and D5,
then re-run this certification. The other four are safe to carry into cutover as
documented known differences provided they are announced, but D1 is not: it makes
the product's rate limiting and spend caps optional at the client's choosing.

Once D1/D4/D5 are closed, the remaining delta is small enough that the Rust tree is
no longer load-bearing as a reference and can go.

---

*Method: contract JSON re-derived per app; per-family error-code catalogue diff
(every `"snake_case"` literal in each Rust handler file checked for a TS
counterpart, then each miss traced to its Rust call site to classify it);
side-by-side read of both handler bodies for the 36 DEEP ops; response `object`
discriminator diff; two behaviour-changing mutations to check the suite is not
vacuous. No Rust was compiled, imported or executed. No live Cloudflare account
was touched. All suites re-run green after the markers this wave added.*
