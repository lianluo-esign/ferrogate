# CERT 3 — the DATA PLANE, re-derived from scratch

**Date:** 2026-08-01 · **Wave 23** · **Branch:** `main-ts` · **Scope:** the **58**
contract operations in `docs/openapi/runtime-api-contract.json` whose
`visibility` is not `admin`.

**This document inherits nothing from `cert2-dataplane.md`.** Waves 20, 21 and 22
changed the agent-run contract, the tool-side workflow gate, `/healthz`, the
drain gate, the tenancy-suspension gate and the guardrail binding. Every verdict
below was re-derived this wave against the tree as it stands, and the fixes that
matter were re-proved by mutation on the CURRENT source rather than trusted
because a previous document said they held.

| class | meaning | blocks deleting `crates/**` |
|---|---|---|
| **EQUIVALENT** | behaviour matches on validation, error code, response shape, auth ladder, framing and side effects | — |
| **CLASS A — REGRESSION** | complete, wired and reachable in Rust; dropped or broken in the port | **yes** |
| **CLASS B — RUST UNFINISHED** | stub / `todo!()` / dead code / no production caller | no |
| **CLASS C — DELIBERATE** | obsolete on workerd, a genuine platform limit, or a standing owner decision | no |
| **UNVERIFIED** | this pass did not settle it — listed, never guessed | — |

---

## 0. The numbers

| verdict | ops | share |
|---|---:|---:|
| **EQUIVALENT** | **32** | 55% |
| **CLASS A — REGRESSION** | **22** | 38% |
| **CLASS B — Rust unfinished** | **0** | — |
| **CLASS C — deliberate** | **4** | 7% |
| **UNVERIFIED (whole operation)** | **0** | — |
| total | **58** | |

**Of the 22 CLASS A, none is HIGH.** Three are MEDIUM (`listTools` /
`executeTool` / `executeFunction` answer `501`; CORS is absent from the entire
data plane; `/metrics` is served by two Workers with two different bodies). The
other nineteen are error-code strings, one header validator, one health-document
field and one missing audit row.

**Two accounting rules, stated so the numbers can be checked:**

1. **CORS (§4 A13) is counted ONCE as cross-cutting**, not multiplied across the
   31 operations it touches. Multiplying it would make every op CLASS A and the
   count meaningless. The same rule was used in `cert2-dataplane.md`.
2. **`createAgentRun` moved from CLASS A (HIGH) to CLASS C**, and that is the
   single largest change in the count since the last certification. §2.1 gives
   the full reasoning and the residual that survives the reclassification.

**The wave-16→22 security fixes all hold, on the current tree, measured.**
Nineteen behaviour-changing mutations were applied this wave, each grepped back
off disk to prove it landed, each restored with a SHA equality check. **All
nineteen produced RED. 172 assertions failed across them.** §1 is the table.

**Two things this pass found that no previous document records** — §3. Neither
is a data-plane behaviour defect; both are evidence-integrity defects, which in
this repository is the more dangerous kind.

---

## 1. Do the fixes hold? — nineteen mutations, measured

### 1.0 Baselines, measured first, on the unmutated tree

`bun run test` per app, **including the escalated channels** — `apps/gateway`
and `apps/agent-runtime` each run more than one vitest config, and §3.2 is about
what happens when you forget that.

| app | default channel | escalated channel(s) | total |
|---|---:|---|---:|
| `apps/gateway` | 2019 / 114 files | `test/ratelimit/harness` 24 / 2 · `test/tenancy/harness` 42 / 4 | **2085** |
| `apps/mcp` | 453 / 28 files | — | **453** |
| `apps/agent-runtime` | 446 / 26 files | `test/durable/harness` 95 / 9 | **541** |
| | | | **3079** |

`bunx tsc --noEmit` exits 0 on all three. Independently re-derived this wave:
`bun scripts/seam-proof.mjs` reports **claimed 200 = parsed 200, 198 gated, 0
ungated without a reason.**

### 1.1 The mutation table

Protocol: apply an exact-string edit that still parses, `grep` the marker back
off disk, run the app's suites, restore from a byte copy, assert SHA equality.
Every mutation neutralises a **DECISION**, not a mount — the M22 warning
(neutralising the drain decision left every source-text gate green) is taken
seriously here, and three of these mutations are specifically the shape that
warning describes.

| # | claim under test | mutation | RED |
|---|---|---|---:|
| **M1** | admission (`finalize_auth`) is enforced on **`apps/mcp`** | `src/http.ts` — `if (!admitted.ok)` neutralised | **6** — `test/admission.test.ts`: per-key RPM, the TOK-12 `request_limit_per_minute` column, monthly budget, empty wallet, `403 quota_scope_disabled`, and `tools/list` (the READ surface) |
| **M2** | tenancy suspension is enforced on **`apps/mcp`** | `src/http.ts` — `if (lifecycle !== null)` neutralised | **7** — `test/fleet-tenancy-suspension.test.ts`, incl. *"computes an EMPTY exploit set"*, the ancestor walk, and the fail-closed `503` when the authority is unreadable |
| **M3** | the drain **DECISION** is honoured on **`apps/mcp`** | `src/drain.ts::drainRefusal` — `if (!state.draining) return null` forced | **4** — `test/drain-fleet.test.ts`: both doors shut on one admin write, the REST tool transport, per-request re-read, identical durable document |
| **M4** | admission is enforced on **`apps/agent-runtime`** | `src/admission/admit.ts` — early `return NO_HOLDS` | **15** — `test/admission{,-units}.test.ts`: every 503-not-429 failure arm, Rust's ladder order, wallet-hold release, per-credential and tenant-scope RPM, `rpm_limit = 0` is a stop |
| **M5** | tenancy suspension is enforced on **`apps/agent-runtime`** | `src/ports.ts::tenancyGatedApiKeyPort` — early `return resolution` | **5** in `test/durable/lifecycle.spec.ts` (ESC channel) **plus 6** in `apps/mcp/test/fleet-tenancy-suspension.test.ts`, which names the offender: `expected [ 'agent-runtime' ] to deeply equal []` |
| **M6** | the drain **DECISION** is honoured on **`apps/agent-runtime`** | `src/drain.ts::drainRefusal` | **0 in the default channel · 4** in `test/durable/drain.spec.ts` (ESC) — see §3.2 |
| **M7** | tenancy suspension is enforced on **`apps/gateway`** | `src/middleware/auth.ts` — `if (!lifecycle.admitted)` neutralised | **3** — `test/auth.test.ts` + `test/lifecycle-chain.test.ts` (suspended PROJECT, suspended WORKSPACE) |
| **M8** | admission is enforced on **`apps/gateway`** | `src/index.ts` — `rateLimit(),` removed from `GATEWAY_MIDDLEWARE` | **16** — `test/keys/credential-limits.test.ts`, `test/ratelimit/{guards,spend}.test.ts`, `test/metering/wiring.test.ts` |
| **M9** | the drain **DECISION** is honoured on **`apps/gateway`** | `src/routes/drain.ts::drainRefusal` | **6** — `test/routes/drain.test.ts` (all five spend ops, per-request re-read, same flag `/readyz` uses) **and** `test/fleet-control-matrix.test.ts` §5, whose message is the finding: *"it refuses off the deploy-time `GATEWAY_DRAIN` var, a different variable from the one `POST /admin/v1/drain` writes"* |
| **M10** | the model-side workflow gate is **REACHABLE** by a reference-shaped client | `src/ratelimit/workflow.ts` — the `x-ferrogate-agent-run-id` alias deleted | **6** in `test/inference/workflow-mount.test.ts`, incl. *"a REFERENCE-SHAPED client reaches the gate"* and the CONTROL case *"a LEGAL step is admitted and dispatched"* |
| **M11** | the model-side workflow **DECISION** is live | `src/inference/workflow.ts` — always `{kind:"ungated"}` | **40** across `workflow-graph` (all 13 refusals, the provider pin, the header contract), `workflow-ledger`, `workflow-mount` |
| **M12** | the **TOOL-side** workflow gate (wave 20, new) is live and reachable | `apps/agent-runtime/src/runs/workflow.ts` — always admit | **18** in `test/workflow-tool-gate.test.ts` **+ 3** in `test/durable/workflow-catalog.spec.ts` — incl. `workflow_node_not_tool`, `workflow_tool_not_allowed`, the edge rule, all four counters, the `402` budget debit, cross-tenant, *"a refused step does not create the run"*, and *"the async twin cannot be used to walk around the gate"* |
| **M13** | asset egress is **BUDGETED** | `src/assets/service.ts::#egressDenial` — denial dropped | **4** — over-budget pull, over-RPM pull, a range request gated on FULL object size, and presigned-URL issuance |
| **M14** | asset egress is **BILLED** | `src/assets/service.ts::#recordEgress` — early return | **7** — the meter row, the monthly counter, the PULL-side audit event joined to the agent run, `206` billing its slice, `304` billing zero, presign metering the whole object at issuance |
| **M15** | the **`mcp_manifest` stdio refusal** holds | `src/assets/service.ts::#contentGate` — rejection dropped | **7** — at `putAsset` and at `commitAssetUpload`, case-insensitively, on the audit trail, and *"is NOT disableable through the screener seam"* |
| **M16** | `agent-run-id` reaches the **metering record** | `src/metering/middleware.ts` — `agentRunId` forced `undefined` | **1** — `test/metering/agent-run-correlation.test.ts` *"a declared `x-ferrogate-agent-run-id` reaches the settled `event_json`"* |
| **M17** | `agent-run-id` reaches the **MCP audit + dispatch** | `apps/mcp/src/http.ts` — `context.agentRunId` never set | **8** — `tools/call` upstream context + `tool.execute` row, a DENIED call's row, the REST transport, the four ingress rows (`tool.list`, `resource.list`, `resource.read`, protocol negotiation), and the approval join |
| **M18** | guardrails on `apps/mcp` are bound to the **durable activated revision** (FC-3) | `apps/mcp/src/guardrails.ts` — control-DB read short-circuited | **2** — `test/fleet-guardrail-activation.test.ts`: one activation must shut the MCP door AND be live on the gateway, and must screen the tool RESULT too |
| **M19** | `createAgentRun` answers the **synchronous** contract shape | `apps/agent-runtime/src/runs/lifecycle.ts` — `synchronousShape` forced false | **4** — `test/agent-run-contract.test.ts` (`object`, the echoed plan, the body `run_id`) and `test/contract.test.ts` pass 2 (reachability) |

**All nineteen held. All nineteen files were restored and re-verified by SHA.**
Post-restore the tree is green on every channel: gateway 2019 + 24 + 42, mcp 453,
agent-runtime 446 + 95, with `tsc --noEmit` clean on all three.

### 1.2 Answering the seven questions the certification brief asked, one by one

| question | answer | evidence |
|---|---|---|
| admission enforced consistently on all three Workers | **YES** | M1 (6) · M4 (15) · M8 (16). Plus `apps/gateway/test/admission-consistency.test.ts` (5 assertions) proving the three refusal tables agree as source text, and `test/fleet-control-matrix.test.ts` (24) proving the emitter set is COMPUTED, not listed |
| the workflow graph gate REACHABLE in production | **YES, on both sides** | model side M10 (reachability, 6) + M11 (decision, 40); tool side M12 (21). Both driven through `SELF` against the exported Worker |
| asset egress budgeted **AND** billed | **YES, separately proven** | M13 (budget, 4) and M14 (bill, 7) are two different mutations of two different methods. Neutralising one leaves the other's tests green — which is why both were run |
| the `mcp_manifest` stdio refusal | **YES** | M15 (7), including the "cannot be disabled through the screener seam" arm |
| `agent-run-id` reaching the metering record | **YES, but thinly on the gateway** | M16 turns exactly **one** assertion red. The MCP half is much better held (M17, 8). One assertion is enough to be a gate; it is not enough to be comfortable |
| `503 node_draining` honoured per request on all three | **YES** | M9 (gateway, 6) · M3 (mcp, 4) · M6 (agent-runtime, 4 — ESC channel only, §3.2) |
| a suspended tenant refused everywhere | **YES** | M2 (mcp, 7) · M5 (agent-runtime, 5 + 6) · M7 (gateway, 3). The cross-Worker gate `apps/mcp/test/fleet-tenancy-suspension.test.ts` drives all three real Workers from one isolate and computes the exploit set, so a regression on any one names that Worker |

### 1.3 The one admission leg that is still open, unchanged since wave 19

The **RPM window is one counter on `apps/gateway` only.** `apps/mcp/wrangler.toml:244-294`
and `apps/agent-runtime/wrangler.toml:190-232` still carry the cross-script
`RATE_LIMIT` stanza **commented out**, because workerd cannot resolve a
`script_name` binding offline (committed uncommented, both suites go to 0 tests /
23 collection errors and `wrangler dev --local` never reaches "Ready on").

Four of five admission legs — quota scope, monthly USD budget, prepaid-wallet
no-oversell hold, and the counter-KEY derivation — are shared and durable across
all three Workers. The fifth is not: a credential capped at 60 rpm is charged
60 on the gateway plus 60×N across N MCP isolates plus 60×M across M
agent-runtime isolates.

**This remains CLASS C on the local tree and CLASS A on a deployed one.**
Uncommenting two stanzas at deploy time closes it and **nothing mechanical
forces that to happen.** It is a pre-deploy checklist item, not an "already
fine" item, and it has now survived four waves in that state.

---

## 2. What changed since `cert2-dataplane.md`

### 2.1 `createAgentRun` — CLASS A (HIGH) → **CLASS C**, with a residual

This was the largest finding of the last certification: `POST /v1/agent-runs`
answered the async-job envelope under the synchronous operation's name, and
`max_turns` / `timeout_millis` / `tool_calls` had **no reader anywhere in
`apps/agent-runtime/src`**. Wave 20 closed the portable half. Re-verified this
wave, on the current source:

**Restored, and each held by a biting test** (`test/agent-run-contract.test.ts`,
12 assertions, all driven through `SELF`):

| Rust refusal | status | where it lives now |
|---|---|---|
| `invalid_agent_run_input` | 400 | `createRun`'s `emptyInputCode` |
| `invalid_agent_run_id` | 400 | `bodyRunId` — the BODY half, which previously had no reader at all |
| `invalid_agent_tool_call` | 400 | `parseToolCalls` |
| `invalid_agent_run_max_turns` | 400 | `parseRunPlan`, including the `len + 1` turn rule |
| `invalid_agent_run_timeout` | 400 | `parseRunPlan` |
| `workflow_node_not_tool` · `workflow_tool_not_allowed` · `workflow_edge_not_allowed` | 403 | `src/runs/workflow.ts` — **M12** |
| `workflow_parallelism_limit_exceeded` · `workflow_tool_call_limit_exceeded` · `workflow_iteration_limit_exceeded` · `workflow_timeout_exceeded` | 429 | same — **M12** |
| `workflow_budget_exceeded` | 402 | `AgentRunState.admitWorkflowStep`, the atomic DEBIT inside the run's own Durable Object — **M12** |

The response now carries `id`, `turns_executed`, `output`, `tool_results`, plus
the ACCEPTED `max_turns` / `timeout_millis` echoed back, and the plan rides the
dispatch as `SelfHostedRunDispatch.run_plan` — the reader the three fields never
had. `grep -rn "workflow" apps/agent-runtime/src/` now returns five files where
wave 19 measured zero. The gate is **opt-in by header**, so no existing client
changes behaviour, and `POST /v1/agent-jobs` is gated by the SAME ladder so the
twin cannot be used to walk around it (asserted, and RED under M12).

**Why CLASS C and not CLASS A.** The one thing still absent is the synchronous
turn loop, and the reason is that **the reference's own version of it is
unfinished**. `agent_runs.rs::agent_provider` has exactly two arms, both read
directly:

* **`ManagedWorker`** — `AgentRuntimeProvider::default()`
  (`ferrogate-config/src/config/types.rs:1149`), i.e. what every deployment that
  does not override it gets — returns `Err(("agent_worker_transport_unavailable",
  "managed agent runtime requires the external agent-worker Firecracker microVM
  transport, which is not implemented yet"))`. **A default Rust deployment
  answers 503 to every request on this path.**
* **`External`** — `ExternalAgentProvider::with_input`, which spawns a local
  child process.

So the working backend is process spawn, which workerd does not have, and the
default backend is an explicit "not implemented yet". Copying either would mean
shipping a 503 under a contract operation. Dispatching the run to a leased
self-hosted worker or the Sandbox container is strictly more than Rust's default
answer. That is a **reasoned decision, not a copied stub** — which is exactly
the distinction the owner's revised rule exists to make.

**The residual, and it should not be lost in the reclassification.** The
response is `202` where Rust answers `201` on `Completed`, and it is an
*accepted* envelope, not a *finished* one. A client written against a
`External`-configured Rust deployment still reads `output` and finds it empty.
**The contract row should be ratified or renamed** — the honest options are (a)
accept the async semantics under `createAgentRun`, or (b) rename the row and add
`runAgentSynchronously` later. This is a product decision and it is the only
thing standing between this operation and EQUIVALENT.

### 2.2 `executeFunction` — still CLASS A, still 501, marker still correct

`cert2` §2.2 reclassified this from C to A on the ground that the "out-of-process
sandbox" justification is **factually false about the Rust** — `local.rs:3219
handle_function_execute` is a broker (`fetch` + WebCrypto HMAC + a config table),
with a fail-closed per-tenant allowlist (`function_egress.rs`, 197 lines, 0
`todo!()`), a signed short-lived token (`function_token.rs`, 200 lines) and a
Cloudflare-Worker target arm added in #435. The corrected marker is still in
place at `apps/gateway/src/routes/index.ts` and the operation still answers 501.

**No wave has picked it up.** It remains the clearest "funded TS work, not a
platform limit" item on the data plane.

### 2.3 The rest of the cert2 findings, re-checked one by one

| ID | finding | status this wave |
|---|---|---|
| A3 | `400 invalid_agent_run_id_header` not enforced on ordinary inference | **OPEN.** Still refused only when a workflow is ALSO declared (`inference/workflow.ts:899`); `agentRunIdFor` still drops a malformed id silently and serves 200. Marker present at `metering/agent-run.ts` |
| A4 | gateway-config profile resolution fails open | **OPEN.** `grep -rn "gateway_config_not_found\|gateway_config_disabled\|gateway_config_not_allowed\|invalid_gateway_config_header" apps/gateway/src` → **0 hits.** A misspelled `x-ferrogate-config` still silently selects the default posture |
| A5 | `createImage` capability refusal is `400 model_capability_unsupported`, not Rust's `422 image_generation_unsupported` | **OPEN** (`inference/handlers.ts:487`) |
| A6 | `chars/4` in place of BPE | **OPEN, and correctly filed.** It fails CLOSED (an upper bound on the BPE count, so the port over-reserves), and `test/inference/estimate.ts` pins the inequality direction |
| A7 | three asset presign codes collapsed to `invalid_request`; `503 asset_commit_outcome_unknown` absent | **OPEN.** `grep` for `invalid_upload_intent\|invalid_commit\|invalid_abort\|asset_commit_outcome_unknown` across `apps/gateway/src` → **0 hits** |
| A8 | `renderPromptTemplate` writes no audit trail | **OPEN.** Was prose only; **a `PORT-TODO` marker was added this wave** so `grep -rn PORT-TODO` finds it |
| A9 | `submitAgentJob` / `cancelAgentJob` error-code collapse | **PARTIALLY CLOSED.** The run-plan codes are restored (§2.1) and `lifecycle.ts:102` records the change. Still absent: `invalid_agent_job_input`, `invalid_agent_job_capabilities`, `409 agent_job_not_cancellable`, `503 agent_job_cancel_unavailable` (0 grep hits) |
| A10 | the six self-hosted-worker callbacks collapse Rust's per-verb error vocabulary | **OPEN.** Two generic codes (`invalid_self_hosted_worker_transport`, `invalid_self_hosted_worker_telemetry`) where Rust names the verb in both directions. The transport ladder itself remains the strongest work in the tree and is not disputed. **Marker added this wave** |
| A11 | `/healthz` lacks `version` on `apps/mcp` | **CLOSED, and better than asked.** `apps/telemetry/test/fleet-health-contract.test.ts` derives the fleet from `apps/*/wrangler.toml` and the document by parsing the object literal out of `apps/*/src/**/*.ts`, then asserts all five agree on `[status, service, version, runtime]` **in Rust's declaration order**. A sixth Worker is covered the moment it has a `wrangler.toml` |
| A12 | `/readyz` answers three different documents for one operation | **SUBSTANTIALLY CLOSED.** All five Workers now emit the identity members and a `readiness_reason`, and the per-Worker DETAIL member (`cluster` / `dependencies` / `sink`) is declared deliberate — reasonably, since the detail is the thing each Worker can actually answer. **One residual: `apps/gateway` still omits `version`** — §3.3 |
| A13 | CORS is absent from the entire data plane | **OPEN, and re-verified against the Rust this wave.** `apply_cors_headers` (`responses.rs:38`) is called from **9** sites including the generic `write_json_response` / `write_raw_response` bodies that serve `/v1/**`, driven by `config.admin.cors_allowed_origin` (`server/mod.rs:235`). `grep -ri "access-control-allow" apps/{gateway,mcp,agent-runtime}/src` returns **comments only**. `apps/control-plane/src/middleware/cors.ts` exists, so `/admin/v1/**` is covered and `/v1/**` is not |
| A14 | `GET /metrics` served by two Workers with two bodies | **OPEN.** `apps/gateway/src/routes/metrics.ts` renders the full 47-series exposition; `apps/control-plane/src/adapters.ts:495` renders **two gauges** (`ferrogate_control_plane_up`, `ferrogate_request_log_entries`). `ROUTE-MAP.md:12` assigns the row to `apps/control-plane` — i.e. to the two-gauge host. **Marker added this wave** |

---

## 3. New this wave

### 3.1 Two stray source files whose NAMES contain newlines — an evidence hazard

```
apps/mcp/src/admission/gate.ts\n    code: "quota_scope_disabled",\n    code: "quota_scope_disabled",
apps/agent-runtime/src/admission/admit.ts\n    message: (requestId: string): string =>\n      `API key request rate limit is exhausted for request ${requestId}`,\n    message: (requestId: string): string =>\n      `too many requests ${requestId}`,
```

Both are **27,809 bytes and byte-identical to each other** (sha256
`5861badf…`), and both are an older snapshot of
`apps/agent-runtime/src/middleware/auth.ts`. They were produced by a shell
redirect whose target was an unquoted multi-line variable.

**They are inert for the build.** Neither name ends in `.ts`, so no
`import.meta.glob("**/*.ts")`, no `tsconfig` include and no bundler entry
resolves them. Every fleet gate that scans source (`fleet-control-matrix`,
`fleet-health-contract`, `env-var-drift`) is unaffected, and every suite is green
with them present.

**They are NOT inert for `grep`,** which is this project's primary
evidence-gathering instrument. The first grep this pass ran for
`tenancy_suspended` across `apps/mcp/src` reported a hit at
**`apps/mcp/src/admission/gate.ts:114`** — text that is not in that file, in a
Worker that reaches its suspension gate through an entirely different module.
That is one substitution away from a wrong verdict in a certification document,
and it is the same class as the NUL-byte incident that made `grep -r PORT-TODO`
blind to whole files (repo tasks #92 / #104).

Deleting them is a one-line `find … -delete`; it is outside this document's
owned scope. **The durable fix is a gate**, in the shape
`apps/gateway/test/source-nul-bytes.test.ts` already has: assert that no path
under `apps/*/src` or `packages/*/src` contains a control character.

### 3.2 On `apps/agent-runtime`, the drain and suspension gates are INVISIBLE to `bunx vitest run`

Measured, twice:

* the drain **decision** neutralised (M6) → `bunx vitest run` in
  `apps/agent-runtime` is **446 / 446 GREEN**; the ESC channel
  (`--config test/durable/harness/vitest.config.ts`) is **4 RED**.
* the tenancy-suspension **decision** neutralised (M5) → `bunx vitest run` is
  **446 / 446 GREEN**; the ESC channel is **5 RED**.

Both controls exist, both bite, and both are held **only** by
`test/durable/*.spec.ts`, which runs under the SECOND config in that app's
`package.json` `test` script (`vitest run && vitest run --config …`).

This is not a defect. It is the reason the project's own rule — *run `bun run
test`, not bare `bunx vitest run`* — is load-bearing, and it is a trap set for
the next wave: a reviewer who measures with the ordinary command will conclude
that two live, money-shaped security controls are vacuous and will "fix" a
non-problem, or worse, will delete a gate they believe is dead.

**Recommendation:** the ESC channel should be discoverable from the default one.
The cheapest version is a single assertion in the default channel that reads
`package.json` and requires the durable config to be named in `scripts.test` —
so deleting the second `vitest run` turns the first one red.

A milder instance of the same shape: `apps/mcp/test/drain.test.ts` — the file
whose name says "drain" — stays **green** under M3. It covers the document
parse, the precedence rule and `/readyz`. The behavioural refusal on `tools/call`
is held by `test/drain-fleet.test.ts`. The control is held; the attribution is
misleading.

### 3.3 `apps/gateway`'s `/readyz` omits `version`

`readinessResponse` (`apps/gateway/src/routes/readiness.ts`) answers
`{status, service, runtime, cluster}`. Rust's `ReadinessResponse`
(`responses.rs:77`) carries `version`, and `apps/mcp`, `apps/agent-runtime`,
`apps/control-plane` and `apps/telemetry` all now emit it.

**It is honestly recorded rather than hidden**, and the shape of the recording is
worth copying: `apps/telemetry/test/fleet-health-contract.test.ts` asserts the
exception as an exact COMPUTED set —

```ts
const omitting = WORKER_APPS.filter((app) => !readinessDocumentOf(app).members.includes("version"));
expect(omitting).toEqual(["gateway"]);
```

— so a fourth Worker regressing lands in the list and fails, **and fixing the
gateway also fails**, forcing the exception to be deleted rather than left behind
as folklore. LOW-severity CLASS A. A marker was added at
`routes/readiness.ts` this wave, naming both halves of the edit.

---

## 4. The per-operation table

Legend for **regression test**: answers *would a test FAIL if this behaviour
regressed* — not *is it exercised*. **M*n*** = mutation-proven RED by this wave,
on this tree. **ESC** = held only in an escalated vitest channel.

### `apps/gateway` — inference (6)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 1 | `listModels` | **EQUIVALENT** | `{object:"list", data:[{id,object,created:0,owned_by}]}`; the #515 tenant-visibility filter matches the invocation gate | yes — `test/inference/{operations,allowlist}.test.ts` keep the private-model leak closed |
| 2 | `createChatCompletion` | **CLASS A** (A3, A4, A6) | ingress ORDER is right and that is the hard part: authenticate before reading the body, `invalid_json` distinct from `invalid_request`, 413, the 403-before-resolution model gate, streaming relayed as the upstream `ReadableStream`, failover, metering, drain, and both workflow gates | yes — **M8 · M9 · M10 · M11 · M16** |
| 3 | `createResponse` | **CLASS A** (A3, A4, A6) | shares `plan_ai_ingress` with #2 | yes — `test/streaming/responses.test.ts`; **M9 · M11** |
| 4 | `createMessage` | **CLASS A** (A6) | Anthropic translation + SSE normalisation faithful. Rust does NOT thread `agent_run_id` here (`messages.rs` passes `None` at all 6 sites) — TS stamping it is a superset | yes — `test/streaming/anthropic.test.ts`; **M9 · M11** |
| 5 | `createEmbedding` | **CLASS A** (A6) | as #4 | yes — **M9 · M11** |
| 6 | `createImage` | **CLASS A** (A5, A6) | capability refusal changed status AND code | ladder yes; **no test pins the 422, because the 422 does not exist** |

### `apps/gateway` — assets (18)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 7-10 | `listAssets`, `listAssetsByType`, `getAssetStorageSummary`, `listWithheldAssets` | **EQUIVALENT** ×4 | discriminators match; #366 withholding confined to the dedicated view | yes — `test/assets/{routes,service,scan}.test.ts` |
| 11 | `getAsset` | **EQUIVALENT** | fail-closed monthly byte budget + download RPM ahead of any byte, then the meter, the monthly counter and the pull-side audit row; a `206` bills its slice, a `304`/`416`/`HEAD` bills nothing | yes — **M13 (budget) and M14 (bill), separately** |
| 12 | `putAsset` | **EQUIVALENT** | the per-`asset_type` content-type allowlist and the `mcp_manifest` **stdio** refusal, called by `AssetService` ahead of the screener so no operator config and no injected double can disable them | yes — **M15** |
| 13-20 | `deleteAsset`, `getAssetManifest`, `listAssetChannels`, `putAssetChannel`, `deleteAssetChannel`, `yankAssetVersion`, `unyankAssetVersion`, `promoteAssetVisibility` | **EQUIVALENT** ×8 | `400 channel_target_required`, `asset.visibility_promotion`, the `299 ferrogate` yank warning header and the four `x-ferrogate-asset-*` headers are byte-identical | yes — `test/assets/{registry,service,scan}.test.ts` |
| 21 | `createAssetUploadIntent` | **CLASS A** (A7) | `invalid_upload_intent` → `invalid_request` | code: no. shape: yes |
| 22 | `commitAssetUpload` | **CLASS A** (A7) | `invalid_commit`; `asset_commit_outcome_unknown` absent. The commit re-runs the FULL #366 screening over the verified bytes and copies to a fresh immutable key, so a staging-URL replay cannot race a different payload in | hash/size/quota/screening yes — **M14 · M15** |
| 23 | `abortAssetUpload` | **CLASS A** (A7) | `invalid_abort` → `invalid_request` | shape only |
| 24 | `getAssetDownloadUrl` | **EQUIVALENT** | `asset_download_url`; the unconfigured-R2 `503 asset_bucket_unavailable` posture matches; the egress budget is charged **at issuance**, which is the right place | yes — **M13 · M14** both cover the presign leg explicitly |

### `apps/gateway` — tooling / discovery (7)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 25 | `listTools` | **CLASS A — MEDIUM** | 501. Rust's registry is real: `tools_for(tenant, api_key_id, route)` merges builtin providers, MCP-HTTP-declared tools, and per-tool approval policy + tenant/key/route allowlists | `test/auth.test.ts` pins 401 → 403 → 501, so the stub cannot answer ahead of the guard |
| 26 | `executeTool` | **CLASS A — MEDIUM** | 501. Rust dispatches through the approval record + the governed chokepoint | as above |
| 27 | `executeFunction` | **CLASS A — MEDIUM** | 501 on a false platform claim — §2.2 | as above |
| 28 | `renderPromptTemplate` | **CLASS A** (A8) | error codes match one-for-one; no audit row on any arm | codes yes; **the absent audit is covered by nothing** |
| 29 | `listAgentSkills` | **EQUIVALENT** | Rust demands scope `tools.read`, the contract says `skills.read`, TS follows the contract — the contract is authoritative | yes — `test/routes/skills.test.ts` |
| 30 | `getAgentSkill` | **EQUIVALENT** | `404 skill_package_not_found`; visibility filter matches | yes |
| 31 | `getAgentDiscovery` | **EQUIVALENT** | bearer `agents.read` (`local.rs:10383`); durable agent-upstream withdrawal closed in wave 20 and held on BOTH Workers | yes — `test/routes/agent-discovery.test.ts`, `test/routes/agent-upstream-{,fleet-}withdrawal.test.ts` |

### `apps/agent-runtime` (15)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 32 | `createAgentRun` | **CLASS C** (was A-HIGH) | §2.1 — validation ladder, run-id contract, response field set and the tool-side workflow gate all restored; the synchronous turn loop is Rust's own unfinished half. **Residual: the contract row should be ratified or renamed** | yes — **M19 · M12**; `test/agent-run-contract.test.ts` (12) |
| 33 | `submitAgentJob` | **CLASS A** (A9 residual) | admission live; gated by the same workflow ladder as #32, which Rust does not do — a deliberate tightening, since both URLs reach one create path | yes — **M4 · M12**; `test/lifecycle.test.ts` |
| 34 | `getAgentJob` | **EQUIVALENT** | | yes — **M4** |
| 35 | `listAgentJobEvents` | **EQUIVALENT** | `object:"agent_job_event_page"`, `400 invalid_event_cursor` for a non-integer AND for `limit=0`, and a `<occurred_at_unix>:<id>` resume cursor that survives its own event being pruned | yes — `test/event-feed.test.ts`, `test/sse.test.ts` |
| 36 | `getAgentJobResult` | **EQUIVALENT** | `work_products` is a real projection with `attribution_verified` re-derived against the caller's `run_id` | yes — `test/lifecycle.test.ts` pins `409 agent_job_not_terminal` |
| 37 | `cancelAgentJob` | **CLASS A** (A9) | `409 agent_job_not_cancellable` / `503 agent_job_cancel_unavailable` absent | yes for the behaviour — `test/cancel.test.ts`; no for the codes |
| 38 | `invokeAgent` | **EQUIVALENT** | `404 agent_not_found` before `403 agent_not_visible` before `413 payload_too_large` before `400 invalid_json`; both #305 and #307 declarations read and validated; the upstream host checked against the governed egress allowlist; the durable agent-upstream catalog closed in wave 21 | yes — `test/agents.test.ts`, `test/guardrails.test.ts`, `test/durable/agent-upstream-withdrawal.spec.ts` (ESC) |
| 39 | `sendAgentMessage` | **EQUIVALENT** | as #38 | yes |
| 40 | `streamAgentMessage` | **EQUIVALENT** | as #38 | yes — `test/sse.test.ts` |
| 41-46 | the six `internal` self-hosted-worker callbacks | **CLASS A** (A10) ×6 | The TRANSPORT half remains the strongest work in the tree and this verdict does not dispute it: the `x-ferrogate-transport-security` requirement, the downgrade ladder, the `FG_REQUIRE_PRODUCTION_MTLS` posture switch, `201` on all four record verbs, and a from-scratch XChaCha20-Poly1305 reproducing Rust's HKDF salt, info string and AD join byte for byte. The **error catalogue** is what diverges | ladder yes — `test/internal-auth.test.ts`, `test/mtls.test.ts`, `test/xchacha20poly1305.test.ts`; **no** for the per-verb codes |

### `apps/mcp` (6)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 47 | `mcpJsonRpc` | **EQUIVALENT** | admission + suspension + drain + durable guardrails all live; the `method_dependent` scope map is READ from the contract (`contract.ts:299-316`), not hand-copied | yes — **M1 · M2 · M3 · M17 · M18** |
| 48 | `executeMcpTool` | **EQUIVALENT** | | yes — **M1 · M3 · M17 · M18** |
| 49 | `completeMcpIdentityOauth` | **EQUIVALENT** | anonymous in both | yes — `test/oauth-flow-claim.test.ts` |
| 50-52 | `authorizeMcpIdentity`, `getMcpIdentity`, `revokeMcpIdentity` | **EQUIVALENT** ×3 | all five authenticated MCP surfaces route through ONE `authenticateRequest`, so admission/suspension/drain cannot be bypassed per-route | yes — **M1 · M2**; `test/{identity,durable-identity}.test.ts` |

The MCP error vocabulary is a strict **superset** of Rust's — every Rust code has
a counterpart plus ~15 more that make identity failures distinguishable. That is
an improvement and is not counted as a divergence. The three Rust MCP codes with
no TS counterpart (`invalid_mcp_server`, `mcp_server_not_found`,
`mcp_server_reload_rejected`) are `/admin/v1/mcp-servers` CRUD — control-plane
scope.

### shared health (2, in every Worker)

| # | operation | verdict | why | regression test |
|---|---|---|---|---|
| 53 | `getHealthz` | **EQUIVALENT** | A11 closed. All five Workers declare `[status, service, version, runtime]` in Rust's declaration order | yes — `apps/telemetry/test/fleet-health-contract.test.ts` derives BOTH sides (fleet from `wrangler.toml`, document by parsing the object literal) and asserts the absence separately from the shape |
| 54 | `getReadyz` | **CLASS A — LOW** | §3.3 — identity members and `readiness_reason` unified across five Workers; **`apps/gateway` alone omits `version`** | yes, in both directions — the same gate records the exception as an exact computed set |

### `apps/control-plane`'s four non-`/admin/v1` operations

| # | operation | verdict | why |
|---|---|---|---|
| 55 | `getMetrics` | **CLASS A — MEDIUM** (A14) | two Workers, two bodies, one contract row; `ROUTE-MAP.md` points operators at the two-gauge host |
| 56-58 | `getAdminDashboard`, `getAdminDashboardSlash`, `getAdminDashboardAlias` | **CLASS C** ×3 | **No longer UNVERIFIED — read this wave.** All three are anonymous and answer `raw(c, 200, "text/html; charset=utf-8", ADMIN_DASHBOARD_HTML)`, matching Rust's `write_raw_response(…, "text/html; charset=utf-8", …)` on status, content-type and anonymity. The BODY is a placeholder shell that names the API and deliberately ships **no script tag and no bundle reference** — a shell loading a non-existent bundle would answer 200 with a blank page, which an operator reads as "broken" rather than "not built yet". `PORT-PLAN.md` sequences `admin-console` last by owner directive, so this is a product decision, not a port gap. `apps/control-plane/test/auth.test.ts` pins both halves |

---

## 5. Axis-level UNVERIFIED

Load-bearing axes this pass did **not** settle. They change no verdict above, and
listing them is the alternative to the over-claim of writing "no operation is
UNVERIFIED" and leaving it there.

1. **SSE framing byte-for-byte** against Rust `messages_stream.rs` /
   `responses_stream.rs`. The suites are thorough and the three deliberate
   non-parities are pinned in their Rust-matching form by
   `test/streaming/parity-limits.test.ts`, but **no normalised-frame diff was run
   against real Rust output.** Affects ops 2, 3, 4, 40.
2. **AEAD interoperability with a real Rust self-hosted worker binary.** The TS
   XChaCha20-Poly1305 reproduces Rust's constants by inspection and by its own
   vectors; **no Rust binary was run against it, and none can be** (no `cargo`,
   by hard rule). Affects ops 41-46.
3. **`sigv4` (Bedrock) and Vertex OAuth signing** against real AWS/GCP canonical
   request vectors. Affects ops 2-6 on those provider families.
4. **NEW: this pass did not re-run `wrangler dev --local` boot or the Playwright
   E2E.** The 5/5 boot proof and 22/22 E2E are inherited from wave 22 and are
   *not* re-measured here. They are the two channels that would catch a
   composition-root break, and the tree was being edited concurrently by other
   agents throughout this pass (§6). Anyone acting on this document should re-run
   both before the cutover.

---

## 6. A note on the conditions this was measured under

The worktree was **live** during this certification: other agents were editing
`apps/agent-runtime/src` and `apps/mcp/test` concurrently. One consequence is
recorded because it is instructive rather than because it changed a verdict —
during the M7 run, `apps/gateway/test/fleet-consistency.test.ts` reported
*"agent-runtime no longer mounts the durable guardrail policy"*, a failure with
no relationship to the mutation, caused by another agent's in-flight refactor of
that mount. It was green again minutes later.

Two protections made that survivable and both should be standard: every mutation
was **grepped back off disk** after being applied (so an edit clobbered by a
concurrent write shows up as a failed apply, not as a false vacuity finding), and
every restore was verified by **SHA equality** against the pre-mutation file.
The `apps/mcp` test count also moved from 452 to 453 mid-pass; both numbers are
reported where they were measured rather than reconciled after the fact.

---

## 7. What a paying customer notices, ordered

1. **`POST /v1/functions/execute` answers 501** for a feature the product
   shipped, on a stated reason that is not true about the reference.
2. **The tool surface answers 501** — `listTools` / `executeTool`.
3. **`POST /v1/agent-runs` accepts rather than completes.** It now returns the
   right field set, the right refusals and a real workflow gate, but a client
   that reads `output` off the response gets an empty one. This needs a contract
   ratification, not code.
4. **RPM is enforced per isolate on MCP and agent-runtime** until two commented
   `wrangler.toml` stanzas are uncommented at deploy. Four of five admission legs
   are shared and durable; the fifth is not, and nothing mechanical forces the
   uncommenting.
5. **Browser clients of `/v1/**` get no CORS headers**, where a Rust deployment
   with `admin.cors_allowed_origin` set did.
6. **Prometheus depends on which host you scrape** — 47 series from the gateway,
   2 gauges from the control plane, and `ROUTE-MAP.md` names the latter.
7. **The admin console is a placeholder page** (owner-sequenced, not a defect).
8. Smaller, real in aggregate: six error codes collapsed to `invalid_request`;
   the four job-lifecycle codes and the eight per-verb worker-callback codes
   absent; `422` → `400` on the image capability refusal; a malformed
   `x-ferrogate-agent-run-id` accepted silently on ordinary inference; a
   misspelled `x-ferrogate-config` silently selecting the default posture;
   `renderPromptTemplate` writing no audit row; `chars/4` over-reserving tokens
   for known model families; `/readyz` on the gateway missing `version`.

---

## 8. Certification statement

**Is the TypeScript data plane complete and correct on its own terms?**

**On security and money: yes, and it is now held by tests that fail when it is
broken.** Nineteen mutations, nineteen RED, 172 assertions, on this tree, this
wave. Admission is enforced on all three spending Workers. A suspended tenant is
refused on all three, proven from one isolate that drives all three real Workers
and computes the exploit set. A drained node stops taking billable work on all
three, and the drain DECISION — not merely a reference to it — is what the tests
bite on. Both halves of the workflow graph are live and reachable by a
reference-shaped client. Asset egress is budgeted and billed, proven by two
independent mutations. A `stdio` MCP manifest cannot be published, and cannot be
made publishable through the screener seam. The agent run that caused a spend
reaches the ledger row and every MCP audit row.

**On completeness: not yet, but the gap is smaller than last wave and every item
in it is named with a file and a line.** 22 CLASS A operations, none HIGH, three
MEDIUM. The single largest finding of the previous certification —
`createAgentRun` is not the operation the contract names — has been substantively
answered; what survives it is a contract-ratification decision, not porting work.

**Where the discipline is thinnest, stated plainly:**

* two live security controls on `apps/agent-runtime` are invisible to the
  ordinary test command (§3.2);
* the `agent-run-id` → metering join on the gateway rests on **one** assertion
  (M16);
* two stray files are actively corrupting `grep` output in the two Workers whose
  admission ladders are the most security-relevant code in the tree (§3.1);
* the boot proof and E2E are inherited, not re-measured (§5.4).

**On deleting `crates/**` — the data plane's answer.**

Nothing in §4 requires the Rust to be readable in order to be finished, with
**three exceptions**, and they are the same three the last certification named
minus one:

* **`crates/ferrogate-gateway/src/server/local.rs` (the `handle_function_execute`
  region) and `crates/ferrogate-runtime/src/{function_egress,function_token,supabase_edge_function,function_egress_cloudflare}.rs`** — the ONLY
  specification for `executeFunction`, which is unported and is not
  platform-blocked. **Keep until built or explicitly dropped.**
* **`crates/ferrogate-gateway/src/extensions.rs` and `state_tools.rs`** — the
  only specification for `listTools` / `executeTool`. Note that
  `extensions.rs`'s `RequestHook` enum has exactly one variant (`Noop`) and
  `EventSink` exactly one (`audit_log`): the **tool catalogue** is the part worth
  porting and the **hook model** should be designed fresh. **Keep the catalogue
  half.**
* `crates/ferrogate-runtime/src/agent.rs` and
  `crates/ferrogate-gateway/src/server/agent_runs.rs` — **no longer required by
  the data plane.** Everything portable in them is now in
  `apps/agent-runtime/src/runs/{lifecycle,workflow}.ts`, and what is not portable
  is transcribed in §2.1 with the exact reason (the default provider is a 503,
  the working one spawns a process). They may go **once the owner ratifies or
  renames the `createAgentRun` contract row** — which is the decision that should
  be made *before* the delete, not after.

Everything else in this document is transcribed here with a file and a line,
which is the only form of the Rust that survives the delete.

---

*Method: the 58 operations enumerated mechanically from
`docs/openapi/runtime-api-contract.json` (`visibility != "admin"`), not from
`ROUTE-MAP.md`. Baselines measured on every vitest channel each app declares in
its `package.json` `test` script, before any mutation. Nineteen
behaviour-changing mutations applied, each grepped back off disk, measured,
restored, and the restore verified by SHA equality; suites re-run green
afterwards on all channels. The Rust read directly (read-only) for CORS
(`responses.rs:38` + its 9 call sites), the agent provider arms
(`agent_runs.rs::agent_provider`, `types.rs:1149`) and the readiness struct
(`responses.rs:77`). Seam inventory re-derived with `bun scripts/seam-proof.mjs`
(200 = 200, 198 gated, 0 unproven). No Rust was compiled, imported or executed;
no `cargo` was run. No live Cloudflare account was touched. No real upstream LLM
was called. No test was weakened, skipped or deleted. Four `PORT-TODO` markers
were ADDED for genuine CLASS A gaps that previously had none:
`apps/gateway/src/routes/prompts.ts` (A8),
`apps/gateway/src/routes/metrics.ts` (A14),
`apps/gateway/src/routes/readiness.ts` (§3.3) and
`apps/agent-runtime/src/workers/callbacks.ts` (A10). `bunx tsc --noEmit` exits 0
on `apps/gateway`, `apps/mcp` and `apps/agent-runtime` with those edits in
place.*
