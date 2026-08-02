# CERT 2 — the DATA PLANE, judged on the NEW rule

**Date:** 2026-08-01 · **Wave 19** · **Branch:** `main-ts` · **Scope:** the 58
contract operations whose `visibility` is not `admin`.

**The rule this document is written under is not the rule the previous one was.**
`cutover-parity-dataplane.md` treated the Rust tree as the specification and
graded "DIVERGENT / MISSING" against it. The project owner has since stated that
the **Rust system is itself a half-finished product** and that TypeScript is now
the forward platform. So every gap here is classified:

| class | meaning | blocks cutover |
|---|---|---|
| **EQUIVALENT** | behaviour matches on validation, error code, response shape, auth ladder, framing and side effects | — |
| **CLASS A — REGRESSION** | the behaviour was **complete and working in Rust** and the port dropped or broke it | **yes** |
| **CLASS B — RUST UNFINISHED** | Rust is a stub / `todo!()` / dead code / half-wired; copying it would be wrong | no — product backlog |
| **CLASS C — DELIBERATE** | obsolete on Workers, a genuine platform limit, or a standing product decision | no |
| **UNVERIFIED** | this pass did not settle it; listed, never guessed | — |

**Nothing below is inherited.** Every verdict was re-derived this wave by reading
the Rust handler body and the TypeScript handler body side by side, and every
"was Rust finished?" question was answered by reading the Rust — `todo!()` count,
call sites, whether anything constructs the type — not by reading a doc.

---

## 0. The numbers

| verdict | ops | share |
|---|---:|---:|
| **EQUIVALENT** | **31** | 53% |
| **CLASS A — REGRESSION** | **24** | 41% |
| **CLASS B — Rust unfinished** | **0** | — |
| **CLASS C — deliberate** | **0** | — |
| **UNVERIFIED** | **3** | 5% |
| total | **58** | |

No operation is CLASS B or CLASS C **as a whole**; four CLASS B/C *sub-items*
exist inside CLASS A operations and are named in §4 so a future wave does not
port them by mistake.

**Of the 24 CLASS A operations, 22 are LOW severity** (an error code renamed, a
missing header validation, a field dropped from a health document). **Two are
not:** `createAgentRun` (§2.1) is a different operation from the one the contract
names, and `executeFunction` (§2.2) has been filed as platform-blocked for
eighteen waves on a claim about the Rust that is **factually false**.

**The wave 16–18 security fixes all hold.** Every one was re-proved RED by
mutation this wave, by this pass, on the current tree — §1. That is the good
news and it is substantial: the admission bypass, the unreachable workflow gate,
asset egress, the `mcp_manifest` stdio refusal, `agent-run-id` correlation and
the drain gate are all live and all held by tests that fail when they are broken.

---

## 1. Do the wave 16–18 fixes hold? — measured, not asserted

Protocol, per the project's own standard: apply the mutation, `grep` it back off
disk to prove it landed, require the named test RED, restore, require GREEN.
Every mutation was written as an `if (true/false as boolean)` guard so the
mutated tree still compiles and RED means an assertion failed, not a parse error.
Baselines on the unmutated tree, measured first: **gateway 1884 / 109 files ·
mcp 400 / 24 · agent-runtime 390 / 23**.

| # | claim under test | mutation | result |
|---|---|---|---|
| M1 | the admission ladder is enforced on **`apps/mcp`** | neutralise the `!admitted.ok` branch in `src/http.ts::authenticateRequest` | **6 RED** — `test/admission.test.ts`: RPM ceiling, the TOK-12 `request_limit_per_minute` column, monthly budget, empty wallet, `403 quota_scope_disabled`, and `tools/list` (the READ surface). Restored 400/400 GREEN |
| M2 | …on **`apps/agent-runtime`** | drop the `admissionGrant` set in `src/middleware/auth.ts::bearerAuth` | **6 RED** — `test/admission.test.ts`: per-credential RPM, the READ charge, tenant-scope RPM across keys, `rpm_limit = 0` is a stop, key-scope counting, `quota_scope_disabled`. Restored 390/390 GREEN |
| M3 | …and on **`apps/gateway`** | remove `rateLimit()` from `GATEWAY_MIDDLEWARE` | **16 RED** across `test/keys/credential-limits.test.ts`, `test/ratelimit/{guards,spend}.test.ts`, `test/metering/wiring.test.ts`. Restored 1884/1884 GREEN |
| M4 | the **workflow graph gate is REACHABLE in production** (it was dead behind the budget middleware with 1866 green) | delete the `x-ferrogate-agent-run-id` alias in `src/ratelimit/workflow.ts::workflowDeclarationFrom` | **6 RED** in the `SELF`-driven `test/inference/workflow-mount.test.ts`, including *"a REFERENCE-SHAPED client reaches the gate — the run-id alias"* and the CONTROL case *"a LEGAL step is admitted and dispatched"*. Restored GREEN |
| M5 | **asset egress is budgeted and billed** | `#egressDenial` → `return null` (`src/assets/service.ts`) | **55 RED** in `test/assets/` (control run on the same file set: 354/354 GREEN). Includes the over-budget pull, the over-RPM pull, the range request gated on FULL object size, and the presigned-URL issuance |
| M6 | the **`mcp_manifest` stdio refusal holds** | `#contentGate` → `return null` | **7 RED** in `test/assets/content-gate.test.ts`, including *"refuses regardless of the case"* and *"is NOT disableable through the screener seam"* |
| M7 | **`agent-run-id` reaches the metering record** | force `agentRunId` to `undefined` in `src/metering/middleware.ts` | **5 RED**, incl. `test/metering/agent-run-correlation.test.ts` *"a declared `x-ferrogate-agent-run-id` reaches the settled `event_json`"* (control run: 144/144 GREEN) |
| M8 | **`node_draining` is honoured per request** | unmount `nodeDrainGate()` from `createGatewayApp` | **3 RED** in `test/routes/drain.test.ts`: 503 on all five spend-producing ops, re-read PER REQUEST, same flag `/readyz` uses |

**All eight held. All eight files were restored and the suites re-run green.**

### 1.1 The one leg that is still open, and it is not closed by any of the above

The **RPM window is one counter on `apps/gateway` only.** `apps/gateway/wrangler.toml:788`
binds `RATE_LIMIT` to its own `RateLimiterDurableObject`; `apps/mcp/wrangler.toml:225-231`
and `apps/agent-runtime/wrangler.toml:170-176` carry the cross-script stanza
**commented out**, because workerd cannot resolve a `script_name` binding
offline (`binding "RATE_LIMIT" refers to a service "core:user:ferrogate-gateway",
but no such service is defined`).

So today a credential capped at 60 rpm is charged **60 on the gateway, plus 60×N
across N MCP isolates, plus 60×M across M agent-runtime isolates.** The other
four legs of the ladder — quota scope, monthly USD budget, prepaid-wallet
no-oversell hold, and the counter-KEY derivation — are shared and durable across
all three (proven by `test/admission-consistency.test.ts`, which reads all three
refusal tables as source text and requires identical status, identical message
and one `@ferrogate/policy` `counterKey` site).

This is **CLASS C on the local tree and CLASS A on a deployed one**: uncommenting
two stanzas at deploy time closes it, and nothing mechanical forces that to
happen. It belongs on the pre-deploy checklist, not in the "already fine" column.

### 1.2 What the consistency gate does and does not prove

`apps/gateway/test/admission-consistency.test.ts` is a **source-text** gate, by
necessity: three separately-bundled Workers cannot import each other. It proves
the three *tables* agree. It does **not** prove the three Workers *reach* their
tables on every operation. That second half is covered per-Worker by M1/M2/M3
plus the fact that all five authenticated MCP surfaces go through one
`authenticateRequest` (`grep -rn "authenticateRequest(" apps/mcp/src` → 5 call
sites, no bypass) and all nine bearer agent-runtime operations through one
`bearerAuth`. Recorded so the limit of the evidence is visible.

---

## 2. The two CLASS A findings that are not cosmetic

### 2.1 A1 — `POST /v1/agent-runs` is not the operation the contract names (HIGH)

**This is the largest single finding of this certification, and no previous
document records it.**

Rust `handle_agent_run_create` (`crates/ferrogate-gateway/src/server/agent_runs.rs`,
1,718 lines; harness in `crates/ferrogate-runtime/src/agent.rs`, 1,085 lines;
**`grep -c "todo!\|unimplemented!"` = 0 in both**) is a **synchronous agent run**:

```
AgentRunCreateRequest { input, run_id?, max_turns?, timeout_millis?, tool_calls[] }
  → AgentHarness::run(input, provider, tool_dispatcher, event_sink)
      turn loop → run_started / turn_started / tool_call_requested
                  / tool_call_completed / run_output / run_completed
                  / run_cancelled / run_stopped
  → 200 { object:"agent_run", id, status, turns_executed, output, tool_results, request_id }
```

`apps/agent-runtime/src/runs/lifecycle.ts:319` is:

```ts
runRoutes.post("/v1/agent-runs", (c) =>
  createRun(c, { initialStatus: "running", enqueueDispatch: true }),
);
```

— the **same function `submitAgentJob` calls**, differing only in the initial
status string. It answers `202 { object:"agent_run", run_id, status,
idempotency_key, terminal, isolation, status_url, events_url, result_url,
request_id }` and never executes a turn. `max_turns`, `timeout_millis` and
`tool_calls` have **no reader anywhere in `apps/agent-runtime/src`**.

A client written against the Rust reads `output`, `tool_results` and
`turns_executed` off the response and finds none of the three; the field it does
get, `run_id`, is not the field Rust named (`id`).

Dropped with it, all of them live and complete in the Rust
(`agent_runs.rs:554-660`):

| Rust refusal | status | what it stops | in TS? |
|---|---|---|---|
| `invalid_agent_run_input` | 400 | empty input | `invalid_request` |
| `invalid_agent_run_max_turns` | 400 | out-of-range `max_turns` | **no reader** |
| `invalid_agent_run_timeout` | 400 | out-of-range `timeout_millis` | **no reader** |
| `invalid_agent_tool_call` | 400 | malformed `tool_calls[]` | **no reader** |
| `invalid_agent_runtime_provider` / `invalid_agent_runtime_config` | 400 | provider selection | **absent** |
| `workflow_node_not_tool` | 403 | a non-tool node dispatching tool traffic | **absent** |
| `workflow_tool_not_allowed` | 403 | a node calling a tool it is not pinned to | **absent** |
| `workflow_edge_not_allowed` | 403 | an illegal transition **on the run path** | absent here |
| `workflow_parallelism_limit_exceeded` | 429 | `max_parallelism` over `tool_calls` | **absent** |
| `run_budget_exhausted` | 429 | the workflow run budget, **debited here** | **absent** |
| `agent_run_failed` | 502 | a harness/provider failure | **absent** |

**The tool-side half of the workflow graph is unported.** Wave 17 ported the
MODEL-side gate into `apps/gateway/src/inference/workflow.ts` (verified live in
M4). But:

```
$ grep -rn "workflow" apps/agent-runtime/src/
(no output)
```

The Worker that owns `/v1/agent-runs` — the operation on which Rust enforces node
kind, tool pinning, edge transition and parallelism — reads no workflow at all.

**Not a platform limit.** The harness is a pure turn loop over an injected
`AgentProvider` and tool dispatcher; the budget debit is `D1WorkflowBudgetStore`,
which `apps/gateway` already calls. This is a **scope gap: no wave ever owned
it**, and the contract row `createAgentRun` looked satisfied because a handler
answers on the path.

Marker added: `apps/agent-runtime/src/runs/lifecycle.ts` (on the route).

### 2.2 A2 — `executeFunction`'s 501 rests on a false statement about the Rust

`apps/gateway/src/routes/index.ts` recorded `executeFunction` as *"the only one
with a real deployment constraint attached: the Rust ran user functions in an
out-of-process sandbox. On Workers that is `@cloudflare/sandbox`/containers"* —
i.e. filed as CLASS C, blocked on a paid-plan prerequisite, for eighteen waves.

Read the Rust. `crates/ferrogate-gateway/src/server/local.rs:3219
handle_function_execute` contains **no sandbox and no container**. It is a
**broker**:

- `405 method_not_allowed` on non-POST;
- since #435, a Cloudflare Worker branch (`local.rs:3417
  handle_function_execute_cloudflare` + `function_egress_cloudflare.rs`)
  selected by `FG_FN_TARGET_KIND=cloudflare_worker`;
- otherwise fail-closed: `503 function_egress_disabled` unless a signing secret
  is configured;
- `413 payload_too_large` against `limits().tool_body_max_bytes()`;
- a fail-closed per-tenant allowlist of `{project_base_url, function_slug}`
  targets — `crates/ferrogate-runtime/src/function_egress.rs`, 197 lines,
  **0 `todo!()`**, with `ANY_FUNCTION_SLUG` and typed denials
  (`InvalidTarget`, `InvalidWorkerTarget`, `NoRuleForTenant`, `TargetNotAllowed`);
- a short-lived signed function token (`function_token.rs`, 200 lines, 0
  `todo!()`) and an HTTPS `POST` to a Supabase Edge Function
  (`supabase_edge_function.rs`, 262 lines) or a Cloudflare Worker.

Every primitive it needs exists on Workers **today**: `fetch()`, WebCrypto HMAC,
a config table. There is no Containers dependency and no paid-plan prerequisite.

**Verdict: CLASS A, not CLASS C.** This is exactly the failure mode the project's
own history names — a comment that is factually wrong about the Rust, which
survives because nobody re-reads the Rust (the `?limit=0` case). It was the sole
justification for the only remaining CLASS C on the data plane, and it does not
survive contact with the source.

Marker corrected in place: `apps/gateway/src/routes/index.ts`.

---

## 3. The other CLASS A findings (all LOW severity)

| ID | finding | ops | evidence |
|---|---|---:|---|
| **A3** | **`400 invalid_agent_run_id_header` is not enforced on ordinary inference.** Rust validates the header on EVERY `/v1/chat/completions` and `/v1/responses` ingress (`chat.rs:2767` → `chat.rs:3209 requested_agent_run_id`, unconditional, 0 `todo!()`). TS refuses only when a **workflow is also declared** (`inference/workflow.ts:899`); otherwise `agentRunIdFor` silently drops it (`metering/agent-run.ts:82`) and the request is served 200 with the correlation absent. The client whose correlation id is broken is the one that is never told | 2 | marker added at `metering/agent-run.ts` |
| **A4** | **Gateway-config profile resolution fails open.** Rust `resolve_gateway_config_profile` returns `NotFound` / `Disabled` / `NotAllowed` and REFUSES (`gateway_config_not_found`, `gateway_config_disabled`, `gateway_config_not_allowed`), plus `400 invalid_gateway_config_header` for a malformed value. None of the four exists in TS; a misspelled `x-ferrogate-config` silently selects the default posture | 2 | already marked in `inference/handlers.ts:352-378` |
| **A5** | **`createImage` capability refusal changed status AND code.** Rust `422 image_generation_unsupported` *"model X resolves to provider family Y which does not support image generation"* (`images.rs:574`); TS `400 model_capability_unsupported` (`inference/handlers.ts:483`). Also `502 provider_not_found` → `502 provider_adapter_error`, and `503 wallet_reservation_unavailable` has no TS counterpart | 1 | — |
| **A6** | **The BPE token count is not ported; `chars/4` is used for every model.** Rust embeds `cl100k_base` / `o200k_base` and only falls back to `(chars+3)/4` for models with no bundled vocabulary. The estimate feeds three admission gates (TPM window, monthly token budget, wallet reservation). Honestly documented and **fails closed** — `chars/4` is an upper bound on the BPE count, so the port over-reserves and refuses at or before the point Rust would. Held by `test/inference/estimate.test.ts`, which pins the inequality direction | 5 | `inference/estimate.ts:27-58` |
| **A7** | **Three asset presign error codes collapsed to `invalid_request`**: `invalid_upload_intent` (`asset_presign.rs:421`), `invalid_commit` (:652), `invalid_abort` (:1349). Same status, different code. Plus `503 asset_commit_outcome_unknown` (:1256), the ambiguous-durable-write arm, is absent | 3 | full code-catalogue diff: **only 5 of 51** asset codes are absent, and one of the 5 is `method_not_allowed` (Hono's job) |
| **A8** | **`renderPromptTemplate` writes no audit trail.** Rust records an `admin_audit_event` on EVERY arm, success and each refusal; there is no admin-audit sink in `apps/gateway/src` (the tables live in `apps/control-plane`) | 1 | honestly marked at `routes/prompts.ts:48` |
| **A9** | **`submitAgentJob` / `cancelAgentJob` error-code collapse.** `invalid_agent_job_input` and `invalid_agent_job_capabilities` → `invalid_request`; `409 agent_job_not_cancellable` and `503 agent_job_cancel_unavailable` have no counterpart | 2 | `agent_jobs.rs:558,572,948,966` |
| **A10** | **The six self-hosted-worker callbacks collapse Rust's per-verb error vocabulary.** Rust has `invalid_self_hosted_worker_{heartbeat,event,artifact,checkpoint}` (400) and `self_hosted_worker_{heartbeat,event,artifact,checkpoint}_failed` (500) and `404 self_hosted_worker_not_found`; TS has two generic codes (`invalid_self_hosted_worker_transport`, `invalid_self_hosted_worker_telemetry`) and folds the 404 into `401 invalid_self_hosted_worker_identity`. **The previous certification called this family "EQUIVALENT … the strongest in the whole data plane"** — true of the transport ladder, false of the error catalogue. 18 of 35 Rust codes on this surface have no TS counterpart (several are admin-surface). The 401-for-404 fold is a *tightening* (it does not leak worker existence) and is worth keeping; the per-verb 400/500 codes are a straight loss | 6 | `local.rs:5570,5590,6807,6825,6843,7047` vs `apps/agent-runtime/src/workers/callbacks.ts` |
| **A11** | **`/healthz` still lacks `version` on `apps/mcp`.** Wave 17 recorded this closed. It was closed on `apps/gateway` (`routes/index.ts:209`) and `apps/agent-runtime` (`routes/health.ts:139`) and **not** on `apps/mcp` (`routes/index.ts:144-150` — `{status, service, runtime, protocol}`). Confirmed independently by CUTOVER-READINESS §1.2's own boot proof, which prints the mcp body with no `version` | 1 | — |
| **A12** | **`/readyz` answers three different documents on three Workers for ONE contract operation.** gateway nests `cluster: ClusterStatus` (matches Rust `responses.rs:77-83`); agent-runtime flattens `ready`/`readiness_reason`/`draining`/`accepting_new_requests`/`dependencies` to the top level; mcp emits `{status, service, runtime, protocol, dependencies}` with no readiness reason and no version. Omitting the gossip-topology members is CLASS C and correct; inventing **two** different replacement shapes is not | 1 | — |
| **A13** | **CORS is absent from the entire data plane.** Rust `apply_cors_headers` (`responses.rs:38`) runs on 9 response sites and covers every `write_json_response`-family answer, driven by `config.admin.cors_allowed_origin` (`server/mod.rs:235`); `write_cors_preflight_response` answers `204` with `access-control-allow-{methods,headers}` and `access-control-max-age: 600`. `grep -ri "access-control-allow" apps/gateway/src apps/mcp/src apps/agent-runtime/src` returns only comments. `apps/control-plane/src/middleware/cors.ts` exists, so `/admin/v1/**` is covered and `/v1/**` is not: a browser client of the data plane that worked against Rust does not work here | cross-cutting | already marked at `inference/errors.ts:70` |
| **A14** | **`GET /metrics` is served by two Workers with two different bodies.** The contract has one `/metrics` operation and `ROUTE-MAP.md` assigns it to `apps/control-plane`. Wave 17 correctly added a gateway-side exposition with all 47 `ferrogate_*` series (`apps/gateway/src/routes/metrics.ts`), and `apps/control-plane/src/adapters.ts:496` still emits **2 gauges**. An operator scraping the control-plane host gets the 2-gauge answer and a blank dashboard; nothing in the tree says which host is canonical | 1 | — |

---

## 4. CLASS B and CLASS C sub-items — do NOT port these literally

No operation is wholly B or C. These four sub-items are, and naming them is the
point of the new rule:

1. **CLASS B — the extension-plugin KINDS beyond `ToolProvider`.**
   `crates/ferrogate-gateway/src/extensions.rs` (1,389 lines, 0 `todo!()`,
   constructed at `state.rs:4684` and read by `state_tools.rs`) is real, but its
   `RequestHook` enum has exactly one variant — `Noop` — and `EventSink` exactly
   one, `audit_log`. The pre/post-request hook machinery is scaffolding with a
   no-op behind it. Port the tool catalogue; **design the hook model fresh.**
2. **CLASS C — `409 agent_job_id_conflict`.** Rust needs it because agent runs
   live in one process-global map keyed by id, so two tenants can collide. TS
   addresses runs as `runStateStub(env, tenantId, runId)` — the Durable Object
   name is tenant-namespaced, so a cross-tenant collision is **structurally
   unrepresentable**. Adding the code would be adding an unreachable branch.
3. **CLASS C — the `ClusterStatus` peer-topology members** (`cluster_id`,
   `node_id`, `last_sync_at_unix`). They describe FerroGate's gossip cluster,
   which the Cloudflare edge replaces wholesale.
4. **CLASS C — `x402` / Solana payment legs** on any data-plane response, by
   standing owner directive.

Two markers in the tree are now **STALE and should be de-marked by the owning
wave** (they describe defects that wave 17 fixed, and a reader who trusts them
will re-derive a closed finding):

- `apps/gateway/src/ratelimit/workflow.ts:70` — *"the workflow GRAPH gate is not
  ported"* and its 13-code table. It **is** ported
  (`apps/gateway/src/inference/workflow.ts`, mounted from
  `handlers.ts::admitWorkflowStep`, proven live by M4).
- `apps/gateway/src/inference/handlers.ts:378` item 2 — *"the SEMANTIC cache has
  no TS counterpart … a series with no producer"*. It exists
  (`apps/gateway/src/cache/semantic.ts`, 428 lines, feature-hashed local
  embeddings, per-isolate) and `cache/metrics.ts:71` increments the counter.

---

## 5. The per-operation table

Legend for **regression test**: answers *would a test FAIL if this behaviour
regressed* — not *is it exercised*. **M*n*** = mutation-proven by this wave.

### `apps/gateway` — inference (6)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 1 | `listModels` | **EQUIVALENT** | `{object:"list", data:[{id,object,created:0,owned_by}]}`; the #515 tenant-visibility filter matches the invocation gate | yes — `test/inference/{operations,allowlist}.test.ts` assert the private-model leak stays closed |
| 2 | `createChatCompletion` | **CLASS A** (A3, A4, A6) | ingress order, `invalid_json` vs `invalid_request`, 413, the 403-before-resolution model gate, streaming relay, failover, metering, the drain gate and the workflow graph gate are all faithful | yes — validation ladder pinned; **M3/M4/M7/M8** |
| 3 | `createResponse` | **CLASS A** (A3, A4, A6) | shares `plan_ai_ingress` with #2 | yes — `test/streaming/responses.test.ts`; **M4/M8** |
| 4 | `createMessage` | **CLASS A** (A6) | Anthropic translation + SSE normalization faithful. Note: Rust does **not** thread `agent_run_id` on this surface (`messages.rs` passes `agent_run_id: None` at all 6 sites) — TS stamping it is a superset, not a divergence | yes — `test/streaming/anthropic.test.ts`; **M8** |
| 5 | `createEmbedding` | **CLASS A** (A6) | as #4 | yes — `test/inference/operations.test.ts`; **M8** |
| 6 | `createImage` | **CLASS A** (A5, A6) | capability refusal status+code changed | yes for the ladder; **no test pins the 422** because the 422 does not exist |

The hardest part of the port is right, and that is worth stating: authenticate
**before** reading the body (so an oversized unauthenticated request is
`missing_api_key`, not `payload_too_large`); `invalid_json` distinct from
`invalid_request`; the model gate 403 **before** resolution so a denied key
cannot probe the catalogue; streaming bodies relayed as the upstream
`ReadableStream` with no re-encoding; and the three deliberate stream
non-parities pinned **in their Rust-matching form** by
`test/streaming/parity-limits.test.ts`.

### `apps/gateway` — assets (18)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 7-10 | `listAssets`, `listAssetsByType`, `getAssetStorageSummary`, `listWithheldAssets` | **EQUIVALENT** ×4 | discriminators `asset_storage_summary` etc. match | yes — `test/assets/{routes,service,scan}.test.ts` |
| 11 | `getAsset` | **EQUIVALENT** | **D4 closed and live**: fail-closed monthly byte budget + download RPM ahead of any byte, then metering + the pull-side audit row; a `206` bills its slice, a `304`/`416`/`HEAD` bills nothing | yes — **M5 (55 RED)** |
| 12 | `putAsset` | **EQUIVALENT** | **D5 closed and live**: the per-`asset_type` content-type allowlist and the `mcp_manifest` **stdio** refusal, called directly by `AssetService` ahead of the screener so no operator config and no injected double can disable it | yes — **M6 (7 RED)** |
| 13-20 | `deleteAsset`, `getAssetManifest`, `listAssetChannels`, `putAssetChannel`, `deleteAssetChannel`, `yankAssetVersion`, `unyankAssetVersion`, `promoteAssetVisibility` | **EQUIVALENT** ×8 | `400 channel_target_required`, `asset.visibility_promotion`, the `299 ferrogate` yank warning header, and `x-ferrogate-asset-{resolved,version,variant,yanked}` are byte-identical | yes — `test/assets/{registry,service,scan}.test.ts` |
| 21 | `createAssetUploadIntent` | **CLASS A** (A7) | `invalid_upload_intent` → `invalid_request` | code: no. shape: yes |
| 22 | `commitAssetUpload` | **CLASS A** (A7) | `invalid_commit`; `asset_commit_outcome_unknown` absent. The commit re-runs the FULL trust screening over the verified bytes (#366) and copies to a fresh immutable key, so a staging-URL replay cannot race a different payload in | yes for hash/size/quota/screening; **M5/M6** |
| 23 | `abortAssetUpload` | **CLASS A** (A7) | `invalid_abort` → `invalid_request` | shape only |
| 24 | `getAssetDownloadUrl` | **EQUIVALENT** | `asset_download_url`; `503 asset_bucket_unavailable` unconfigured posture matches; **the egress budget is now charged at ISSUANCE**, which is the right place | yes — **M5** covers the presign leg explicitly |

`parseSingleByteRange` and conditional-request handling are a faithful port
(`206`, `content-range`, `bytes */N` on unsatisfiable), and the audit sink
flushes in a `finally` so REFUSED requests are audited too.

### `apps/gateway` — tooling / discovery (7)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 25 | `listTools` | **CLASS A** | 501. Rust's registry is real (§4 item 1 for the B sub-half): `tools_for(tenant, api_key_id, route)` merges builtin providers, MCP-HTTP-declared tools, and per-tool approval policy + tenant/key/route allowlists | `test/auth.test.ts` pins 401 → 403 → 501, so the stub cannot answer ahead of the guard |
| 26 | `executeTool` | **CLASS A** | 501. Rust dispatches through the approval record + governed chokepoint | as above |
| 27 | `executeFunction` | **CLASS A** — **reclassified from C** | §2.2 | as above |
| 28 | `renderPromptTemplate` | **CLASS A** (A8) | error codes match one-for-one; no audit row | codes yes; the absent audit is covered by nothing |
| 29 | `listAgentSkills` | **EQUIVALENT** | Rust demands scope `tools.read`, the contract says `skills.read`, TS follows the contract. The contract is authoritative | yes — `test/routes/skills.test.ts` |
| 30 | `getAgentSkill` | **EQUIVALENT** | `404 skill_package_not_found`; visibility filter matches | yes |
| 31 | `getAgentDiscovery` | **EQUIVALENT** | bearer `agents.read`, confirmed against `local.rs:10383`. `ROUTE-MAP.md` invariant 3 is **wrong** to list this as anonymous; contract and code agree | yes — `test/routes/agent-discovery.test.ts` |

### `apps/agent-runtime` (15)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 32 | `createAgentRun` | **CLASS A — HIGH** | §2.1 | the suite pins the **divergent** async envelope; nothing would catch the absence of the harness because there is no harness |
| 33 | `submitAgentJob` | **CLASS A** (A9) | admission ladder live | yes — **M2**; `test/lifecycle.test.ts` |
| 34 | `getAgentJob` | **EQUIVALENT** | | yes — **M2** |
| 35 | `listAgentJobEvents` | **EQUIVALENT** | **D7 closed on all three legs**: `object:"agent_job_event_page"` (`lifecycle.ts:401`), `400 invalid_event_cursor` for a non-integer and for `limit=0` (`events.ts:128,132`), and the resume cursor is `<occurred_at_unix>:<id>` so it survives its own event being pruned (`do.ts:318-342`) | yes — `test/event-feed.test.ts`, `test/sse.test.ts` |
| 36 | `getAgentJobResult` | **EQUIVALENT** | `work_products` restored as a real projection (`lifecycle.ts:496,555`), with `attribution_verified` re-derived against the caller's `run_id` | yes — `test/lifecycle.test.ts` pins `409 agent_job_not_terminal` |
| 37 | `cancelAgentJob` | **CLASS A** (A9) | | yes — `test/cancel.test.ts` |
| 38 | `invokeAgent` | **EQUIVALENT** | faithful: `404 agent_not_found` before `403 agent_not_visible` before `413 payload_too_large` before `400 invalid_json`, both #305 and #307 declarations read and validated, and the upstream host checked against the same governed egress allowlist | yes — `test/agents.test.ts`, `test/guardrails.test.ts` |
| 39 | `sendAgentMessage` | **EQUIVALENT** | as #38 | yes |
| 40 | `streamAgentMessage` | **EQUIVALENT** | as #38 | yes — `test/sse.test.ts` |
| 41-46 | the six `internal` self-hosted-worker callbacks | **CLASS A** (A10) ×6 | **The transport half remains the strongest work in the tree** and this verdict does not dispute it: the `x-ferrogate-transport-security` requirement, the downgrade ladder (`403 …transport_downgrade_rejected`, `501 …production_mtls_not_implemented`), the `FG_REQUIRE_PRODUCTION_MTLS` posture switch, `201` on all four record verbs, and a from-scratch XChaCha20-Poly1305 reproducing Rust's HKDF salt, info string and AD join byte for byte. The **error catalogue** is what diverges | yes for the ladder — `test/internal-auth.test.ts`, `test/mtls.test.ts`; **no** for the per-verb codes |

### `apps/mcp` (6)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 47 | `mcpJsonRpc` | **EQUIVALENT** | admission live; the `method_dependent` scope map is read from the contract (`contract.ts:299-316`), not hand-copied | yes — **M1**; `test/{jsonrpc,protocol,contract}.test.ts` |
| 48 | `executeMcpTool` | **EQUIVALENT** | | yes — **M1**; `test/{tools,approvals,agent-run-id}.test.ts` |
| 49 | `completeMcpIdentityOauth` | **EQUIVALENT** | anonymous in both | yes — `test/oauth-flow-claim.test.ts` |
| 50-52 | `authorizeMcpIdentity`, `getMcpIdentity`, `revokeMcpIdentity` | **EQUIVALENT** ×3 | all three route through the one `authenticateRequest`, so admission cannot be bypassed per-route | yes — **M1**; `test/{identity,durable-identity}.test.ts` |

The MCP error vocabulary is a strict **superset** of Rust's — every Rust code has
a counterpart plus ~15 more that make identity failures distinguishable. That is
an improvement and is not counted as a divergence. The only Rust MCP codes with
no TS counterpart (`invalid_mcp_server`, `mcp_server_not_found`,
`mcp_server_reload_rejected`) are `/admin/v1/mcp-servers` CRUD — control-plane
scope.

### shared health (2, in every Worker)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 53 | `getHealthz` | **CLASS A** (A11) | `version` on gateway + agent-runtime, absent on mcp | each app's `test/health.test.ts` pins its own current shape — so it pins the divergence |
| 54 | `getReadyz` | **CLASS A** (A12) | three shapes for one operation | gateway's `test/routes/readiness.test.ts` is thorough; the other two assert their own shapes |

### `apps/control-plane`'s four non-`/admin/v1` operations

| # | operation | verdict | why |
|---|---|---|---|
| 55 | `getMetrics` | **CLASS A** (A14) | dual-host, two bodies |
| 56-58 | `getAdminDashboard`, `getAdminDashboardSlash`, `getAdminDashboardAlias` | **UNVERIFIED** ×3 | anonymous HTML on `apps/control-plane`. **This pass did not read them.** They are outside the three data-plane Workers and belong to `cert2-controlplane.md`. Recorded as UNVERIFIED rather than assumed EQUIVALENT |

---

## 6. Axis-level UNVERIFIED — true of operations that still carry a verdict

Three load-bearing axes were **not** settled this wave. They do not change any
verdict above, and pretending they were checked would be the exact over-claim
the previous certification made when it wrote *"no operation is UNVERIFIED"*.

1. **SSE framing byte-for-byte** against Rust `messages_stream.rs` /
   `responses_stream.rs`. The suites are thorough and the three deliberate
   non-parities are pinned, but **no normalised-frame diff was run** against the
   Rust output. Affects ops 2, 3, 4, 40.
2. **AEAD interoperability with a real Rust self-hosted worker binary.** The TS
   XChaCha20-Poly1305 reproduces the Rust constants by inspection and by its own
   vectors; no Rust binary was run against it (and none can be — no `cargo`).
   Affects ops 41-46.
3. **`sigv4` (Bedrock) and Vertex OAuth signing** against real AWS/GCP canonical
   request vectors. Affects ops 2-6 on those provider families.

---

## 7. What a paying customer notices, ordered

1. **`POST /v1/agent-runs` does not run the agent.** It returns a job envelope
   and no `output`. Any client using the synchronous run API is broken outright.
2. **`POST /v1/functions/execute` answers 501** for a feature the product
   shipped, on a stated reason that is not true.
3. **The tool surface answers 501** — `listTools` / `executeTool`.
4. **RPM is enforced per isolate on MCP and agent-runtime** until the two
   commented `wrangler.toml` stanzas are uncommented at deploy. Four of five
   admission legs are shared and durable; the fifth is not.
5. **Browser clients of `/v1/**` get no CORS headers.**
6. **Prometheus depends on which host you scrape** — 47 series from the gateway,
   2 gauges from the control plane.
7. **Load balancers see three different `/readyz` documents**, and `/healthz` on
   MCP has no `version`.
8. Smaller, real in aggregate: six error codes collapsed to `invalid_request`;
   `422` → `400` on the image capability refusal; a malformed
   `x-ferrogate-agent-run-id` accepted silently on inference; a misspelled
   `x-ferrogate-config` silently selecting the default posture;
   `renderPromptTemplate` writing no audit row; `chars/4` over-reserving tokens
   for known model families.

---

## 8. Certification statement

**Is the TypeScript data plane complete and correct on its own terms?**
**Not yet — but the gap is now small, named, and mostly cheap.**

The security and money controls are in place and *held*: eight mutations this
wave, eight RED, on the current tree. The admission ladder is live on all three
Workers; the workflow graph gate is reachable by a reference-shaped client; asset
egress is budgeted and billed; a `stdio` MCP manifest cannot be published; the
agent run that caused a spend reaches the ledger row; and a drained node stops
taking billable work. Those were the arguments for the last NO-GO and they are
answered.

What replaces them is different in kind and much smaller in blast radius:
**24 CLASS A operations, of which 22 are error codes, header validations and
health-document fields.** Two are real:

- **`createAgentRun` must be built or the contract row must change.** Shipping an
  operation id whose behaviour is another operation's is worse than shipping a
  501, because a client cannot detect it. This is the one finding that should
  block, and the cheapest honest fix may be to *rename the row* and add
  `runAgentSynchronously` later — a product decision, not a porting one.
- **`executeFunction` should be re-planned, not re-deferred.** It is a broker
  with no platform blocker, and the eighteen-wave deferral rested on a false
  reading of the Rust.

**Recommendation.** Close `createAgentRun` (or ratify a contract change), and
re-scope `executeFunction` / `listTools` / `executeTool` as funded TS work rather
than platform-blocked items. The remaining 21 CLASS A items are a
one-wave sweep — they are error-code strings, one header validator, one CORS
middleware, and two health documents.

**On deleting `crates/**`:** the data plane is no longer the reason to keep it.
Everything in §2 and §3 is *transcribed here* with file and line, which is the
only form of the Rust that survives the delete. The one thing this document
cannot transcribe is the thing it found by reading: `agent.rs`'s 1,085-line
harness and `agent_runs.rs`'s 1,718-line handler are the **only specification**
for what `POST /v1/agent-runs` is supposed to do. **Do not delete
`crates/ferrogate-runtime/src/agent.rs`, `crates/ferrogate-gateway/src/server/agent_runs.rs`,
`crates/ferrogate-gateway/src/extensions.rs` or the four
`function_egress`/`function_token`/`supabase_edge_function` modules until those
three surfaces are built or explicitly dropped by the owner.** The rest of the
data-plane Rust is safe to go.

---

*Method: the 58 operations re-derived from `docs/openapi/runtime-api-contract.json`
(not from `ROUTE-MAP.md`); per-family error-code catalogue diffs generated
mechanically from the Rust handler files and checked against the TS trees; the
Rust read directly for every "is this finished?" question (`todo!()` counts, call
sites, constructor sites); side-by-side handler reads for every CLASS A verdict;
eight behaviour-changing mutations applied, `grep`-confirmed on disk, measured,
reverted and re-run green. No Rust was compiled, imported or executed. No live
Cloudflare account was touched. No real upstream LLM was called. No test was
weakened, skipped or deleted. Three `PORT-TODO` markers were added or corrected
(`apps/agent-runtime/src/runs/lifecycle.ts`, `apps/gateway/src/routes/index.ts`,
`apps/gateway/src/metering/agent-run.ts`); `bunx tsc --noEmit` is clean on both
apps and their suites are green (agent-runtime 390/390, gateway
`test/routes` + `test/metering` 301/301).*
