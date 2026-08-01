# CUTOVER READINESS — the decision document

**Date:** 2026-08-01 · **Wave 15** · **Branch:** `main-ts`
**Question:** may we delete `crates/**`, `workers/**` and `Cargo.*`, and merge
`main-ts` → `main`?

---

## 0. The verdict

# **NO-GO.**

Do **not** delete the Rust tree and do **not** merge `main-ts` → `main` on the
strength of this wave's evidence.

This is not a close call and it is not a quality complaint about the TypeScript.
The port is good. It is mounted, it boots, it is heavily and — as of this wave —
**exhaustively** mutation-tested at every composition seam. The reason for NO-GO
is narrower and harder:

> **Three independent certifications, run by three agents against three different
> surfaces, each independently concluded "do not delete `crates/**` yet" — and
> each found first-order defects that no previous wave had recorded.**

The most severe of them is a live control bypass: **the admission half of Rust's
`authenticate()` — rate limit, monthly budget, wallet balance, quota scope — was
silently dropped from `apps/mcp` and `apps/agent-runtime` when the Rust single
process was split into five Workers.** A key that is rate-limited and
budget-exhausted on `POST /v1/chat/completions` is admitted on
`POST /v1/agent-jobs` and on MCP `tools/call`, and both then spend real provider
money. That is not a fidelity gap. It is the product's spend controls being
optional at the client's choosing, and it affects **20 of the 54 data-plane
operations**.

Equally decisive is the shape of the evidence: the marker ledger recorded **+25
new portable markers appearing in ninety minutes**, all written by concurrent
audits, including eight of the most severe findings in the whole ledger. **The
defect-discovery curve has not flattened.** A GO taken today would be taken on
the premise that we know what is missing, and the last two waves have repeatedly
shown that we do not — we know what has been *noticed*.

**What a GO would cost if wrong:** the Rust is the only specification for
sixteen enumerated items, several of them security- and money-relevant. Deleting
the working tree ends practical parity checking (§5), so a defect found after
cutover is re-derived from behaviour, not read off a reference.

**What NO-GO costs:** one more wave. That asymmetry is the entire argument.

### What IS certified by this wave

| Gate | Result |
|---|---|
| `bun install` | clean, 260 installs / 336 packages, no changes |
| `bun run typecheck` | **clean** across all 24 workspaces |
| `bun run test` per package/app | **5679 passed · 0 failed · 0 skipped · 9 todo** across 24 vitest projects (baseline ~5607) |
| **FULL mount-seam pass** | **161/161 inventory rows re-proved by mutation; 150 RED, 13 GREEN, 0 CONFIRM-FAIL, 163/163 restored byte-identical** |
| Real boot, all five Workers | `wrangler dev --local` → "Ready on" + `/healthz` **200** on all five |
| E2E | `playwright test` → **21 passed**, exit 0 |

Every one of those is a *necessary* condition for cutover and every one is met.
None of them is *sufficient*, because all of them measure whether the TypeScript
does what the TypeScript's own tests say it should — not whether that matches the
Rust. The three parity certifications are the only documents that ask the second
question, and all three answer no.

---

## 1. Evidence produced by this wave

### 1.1 The full mount-seam pass

`MOUNT-SEAMS.md` §4 mandates a FULL pass — not the incremental §4(a)/(b) policy —
**before deleting the Rust tree**. This wave is that gate; it is executed and
recorded in `MOUNT-SEAMS.md` §16.

**161 of 161 inventory rows re-proved by mutation.** 163 runs (GW-A1/GW-A1b share
one mutation; three extra `new_sqlite_classes → new_classes` substitution
variants were added). Every file restored and `sha256sum -c`-verified; a
whole-tree check confirmed **827/827** `.ts`/`.toml` files byte-identical to the
pre-pass snapshot.

Two guards were added beyond the §2 protocol, both because of prior burns:

- **Marker uniqueness** — every replacement carries a `/*MUT*/` token and the
  driver refuses any row whose replacement text already exists in the pristine
  file. A CONFIRM that could not fail is not a CONFIRM.
- **Behaviour, not bytes** — recipes that would only have produced a *parse
  error* were rewritten as `if (false as boolean) …` guards so the mutated tree
  still compiles and RED means an assertion failed. The wave-14 lesson (a recipe
  that applies but does nothing) was the reason.

That second guard immediately paid: **five recipes recorded in `MOUNT-SEAMS.md`
were themselves defective** (GW-A3's CONFIRM could never fire; MCP-R3, TEL-A3,
TEL-A5, TEL-A6 orphaned blocks; GW-C7 inserted a middleware that never calls
`next()` and would have broken every request rather than only guardrails). All
five are repaired and recorded in §16.4.

**Result: 150 RED, 13 GREEN.**

| App | rows | RED | GREEN |
|---|---:|---:|---:|
| `apps/gateway` | 55 (54 runs) | 52 | 2 |
| `apps/control-plane` | 28 | 26 | 2 |
| `apps/mcp` | 26 (28 runs) | 25 | 3 |
| `apps/agent-runtime` | 30 (31 runs) | 30 | 1 |
| `apps/telemetry` | 14 | 11 | 3 |
| `apps/cli` | 8 | 6 | 2 |

Nine of the 13 GREEN are documented-and-expected (the four `compatibility_flags`
rows and two `main =` rows are DEPLOY-ONLY; `TEL-T4` has no local effect;
`MCP-P6` is the known weakly-gated row; `CLI-8` is a known NO-GATE).

**Four are newly-found unproven seams:**

| ID | Tier | What is unproven |
|---|---|---|
| **GW-C11** | T3 | `app.get("/version", …)` is asserted by nothing — `grep -rn "/version" apps/gateway/test` → 0 |
| **MCP-R4** | T2 | the `app.onError` 500 envelope code is asserted by nothing — `grep -rn internal_error apps/mcp/test` → 0 |
| **AR-C2** | T2 | `app.notFound(notFoundHandler)` is dead for every path the suite probes: `middleware/auth.ts:574,585` throws the identical `404 not_found` first, so the handler only fires outside `/v1/*` |
| **CLI-7** | T2 | the composition root's `--ca-bundle` transport. `test/transport.test.ts:360,367` builds its OWN transport and never calls `createDefaultRuntime()` — the exact factory-vs-mount confusion that made GW-A1 a fake mount last wave |

Each GREEN was hand-checked to confirm the mutation genuinely changed behaviour
rather than being a semantic no-op (§16.3). **None of the four is money, auth or
tenant isolation**; all are T2/T3. Three of the four sit in the set §15.5
recorded as SKIPPED by wave 14's incremental policy — the cost of that trade,
now measured rather than asserted.

**One genuine improvement to record:** the new `test/env-var-drift.test.ts` gates
in all five Workers **closed six holes §15.3 had recorded as ungated** —
`GW-T17`, `GW-T18`, `GW-TS`, `CP-T5`, `AR-T9` and `TEL-T3` all now go RED. They
remain *drift* gates, not behavioural ones (pinned miniflare bindings still win
over committed values), but a deleted or renamed var is no longer invisible.

### 1.2 Real boot

All five Workers were booted in real workerd via `bunx wrangler dev --local` on
distinct ports, each printed "Ready on", each answered `/healthz` **200**, each
was killed. No live Cloudflare resource was created or mutated; no
`wrangler deploy` was run.

```
gateway        ready /healthz 200 {"status":"ok","service":"ferrogate-gateway","runtime":"workers"}
control-plane  ready /healthz 200 {"status":"ok","service":"ferrogate-control-plane","runtime":"workers"}
mcp            ready /healthz 200 {"status":"ok","service":"ferrogate-mcp","runtime":"workers","protocol":"2026-07-28"}
agent-runtime  ready /healthz 200 {"ok":true}
telemetry      ready /healthz 200 {"status":"ok","service":"ferrogate-telemetry","runtime":"workers"}
```

Note `agent-runtime`'s `{"ok":true}` — a *different document* from the other
four and from the Rust. That is finding op-53/54 in the data-plane certification
and it is visible right here in the boot proof.

### 1.3 E2E

`bunx playwright test --config e2e/playwright.config.ts` → **21 passed**, exit 0,
unchanged from the previous wave. E2E covers `apps/gateway` and `apps/mcp` only;
`control-plane`, `agent-runtime` and `telemetry` are not in it.

---

## 2. Every DIVERGENT / MISSING / IN-MEMORY-ONLY finding, with blast radius

Consolidated from `cutover-parity-dataplane.md`, `cutover-parity-controlplane.md`
and `cutover-parity-libraries.md`. Nothing is summarised away.

### 2.1 Data plane — 27 DIVERGENT, 3 MISSING of 54 operations

| ID | Finding | Ops | Blast radius |
|---|---|---:|---|
| **D1** | **The admission half of `authenticate()` did not cross the Worker split.** `403 tenant_identity_required` · lifecycle suspension · `503 quota_resolution_unavailable` · `403 quota_scope_disabled` · `429 monthly_budget_exceeded` · `429 wallet_balance_exhausted` · `429 rate_limit_exceeded` are mounted on `apps/gateway` only. `grep -rn "rate_limit_exceeded\|monthly_budget_exceeded" apps/mcp/src apps/agent-runtime/src` → nothing | **20** | **CRITICAL — money + abuse.** Rate limits and spend caps bypassable by calling a different verb on the same key. Exploitable with no special knowledge. Not a platform limit; the fix needs all three Workers to share ONE counter namespace, or a per-Worker counter hands each surface a full quota (a different bug) |
| **D2** | **The workflow GRAPH gate is unported.** `[[agent_workflows]]` is parsed and validated by `packages/config` and read by nothing (`grep -rn "agent_workflows\|agentWorkflows" apps/` → nothing). 13 Rust refusal codes absent. Header set also renamed (`…-node-id`/`…-iteration` have no reader; `…-run-id` is new and required) | 5 | **HIGH — policy bypass.** Node pinning, edge transitions, iteration/model-call limits and workflow timeout all stop being enforced while the config is accepted. A Rust-shaped workflow client is refused `400` outright |
| **D3** | `x-ferrogate-agent-run-id` is read on assets and MCP but **not** on the inference path (`grep -rn "agent-run-id" apps/gateway/src/inference/ apps/gateway/src/metering/` → nothing) | 5 | **MEDIUM — evidence.** Model spend cannot be joined to the agent run that caused it. Cost attribution has a hole exactly where the cost is |
| **D4** | **Asset egress: no quota gate, no metering, no pull audit.** `monthly_egress_bytes_budget` / `download_rpm_limit` are parsed, persisted and served by the admin API and read by nothing; `asset_egress_price_per_gb` has no consumer | 1 | **HIGH — money.** Unlimited bandwidth served and none of it billed. An operator can configure an egress budget, see it echoed back, and have it enforce nothing |
| **D5** | **Asset publish gate 1 unported**: the per-`asset_type` content-type allowlist, and the `mcp_manifest` **stdio refusal** | 2 | **HIGH — security.** Any byte stream publishable under any asset type; a tenant can publish an `mcp_manifest` declaring `stdio`, which makes a *consuming* agent spawn an arbitrary local process. Pure function of two strings and a buffer — no platform limit |
| **D6** | `503 node_draining` is advertised by `/readyz` and honoured by nothing (`grep -rn "node_draining" apps/` → nothing). Rust re-checks the flag per AI request on 5 handlers | 5 | **MEDIUM — operational.** Draining a deployment before a migration still takes new billable traffic |
| **D7** | Agent-job event feed, three divergences: `object` is `"list"` not `"agent_job_event_page"`; `?limit=0` / `?limit=abc` answer 200 with 100 rows where Rust answers `400 invalid_event_cursor`; the resume cursor regressed to the bare event id, so a poll loop **re-delivers its whole retained history** after a retention pass. Plus `getAgentJobResult` drops `work_products` | 2 | **MEDIUM — correctness.** Pagination clients break three ways |
| **MISSING** | `listTools`, `executeTool`, `executeFunction` answer **501** | 3 | Contract operations that do not exist. `executeFunction` additionally needs Containers (paid-plan prerequisite) |
| — | `/healthz` lost `version`; **`agent-runtime` `/readyz` answers a flat 200 unconditionally** — no revision check, no drain check, never 503 | 2 | **MEDIUM.** A load balancer gets "ready" from a Worker that cannot serve, forever; a health-checked rollout of a broken agent-runtime is never rolled back |
| — | `GET /metrics` renders 2 gauges where Rust rendered 47 `ferrogate_*` series | 1 | **MEDIUM.** Every existing FerroGate dashboard and alert goes blank at cutover |
| — | Smaller: three asset-validation codes collapsed to `invalid_request`; `renderPromptTemplate` writes no audit trail; `listAgentSkills` needs `skills.read` where Rust needed `tools.read`; a misspelled `x-ferrogate-config` silently selects the DEFAULT posture instead of erroring; `semantic_cache.rs` has no TS counterpart while the `semantic_hit` metric series is still rendered | — | LOW each, real in aggregate |

### 2.2 Control plane — 15 groups / 87 of 197 ops DURABLE-BUT-UNREAD

There are **0 MISSING routes and 0 IN-MEMORY-ONLY groups** here (`resolveStore`
*throws* rather than silently degrading — the silent-data-loss shape was
deliberately removed). The defect is one level deeper: mounted, reached,
authorized, audited, tenant-fenced — and writing to a store nothing reads.

| Group | Ops | The reader looks somewhere else | Blast radius |
|---|---:|---|---|
| `rbac` | 11 | `tenant_role_bindings ⋈ roles`, read by 4 modules across 3 Workers | **HIGH — security.** A granted role authorizes nothing; **`DELETE /admin/v1/tenant-roles/{t}/{r}` answers 200 and revokes nothing** |
| `wallets` | 10 | `wallets.balance_credits` + `wallet_reservations` in the TENANT db (admin writes `balance_cents` in the CONTROL db) | **HIGH — money.** Crediting a wallet does not fund a request |
| `guardrail_policy` | 10 | `guardrail_policy_revisions` / `guardrail_policy_bindings` | **HIGH — safety.** An activated policy is never evaluated |
| `admin_api_key` | 6 | `static_api_keys` — and no secret is minted at all | **HIGH — security.** The group cannot produce a working credential and cannot revoke one; both answer 200 |
| `admin_request_log` | 5 | `request_logs` has no writer at all | MEDIUM — evidence |
| `admin_provider` / `admin_model` | 4 | Rust reads live config + dispatches a catalog per provider | MEDIUM |
| `agent_run` | 3 | the `AgentRunState` Durable Object | MEDIUM — evidence |
| `admin_agent_cost_burn` | 1 | `agent_cost_burn` in the TENANT db | MEDIUM |
| `prompt` / `admin_agent_upstream` | 12 | the `GATEWAY_PROMPT_TEMPLATES` / `GATEWAY_AGENT_UPSTREAMS` **vars** | MEDIUM — admin CRUD needs a redeploy to take effect |
| `skill` / `admin_plugin` / `admin_policy` / `admin_agent_workflow` | 25 | no reader | LOW — the Rust surfaces were also thin config CRUD |

Plus three PARTIAL findings that are not "unread":

- **The tenant WRITE fence is wider than Rust.** `tenantScopeSql` is
  `tenant_id IS NULL OR tenant_id = ?`. For SELECT the widening is deliberate,
  argued and pinned. **It is also on `#update`, `remove` and the `atomic` batch,
  and no test pins the write side** — so a tenant-scoped credential holding
  `admin.write` can PATCH or DELETE any un-attributed platform row: a global
  `role`, a shared `policy`, a `plan` other tenants are billed against. Rust
  makes that unreachable. **HIGH — cross-tenant integrity.**
- **`billing.replay` can never replay a real dead letter.** It requires a
  `billing-outbox-dead-letters` DOCUMENT before it will re-arm; the sweeper
  dead-letters the ROW. A genuine dead letter answers **404**. MEDIUM — money.
- **Three mutation-receipt envelope keys are wrong on the wire**
  (`api_key`/`key`, `mcp_server`/`server`, `tenant_account`/`tenant`), and
  **`apps/cli`'s receipt harvester is blind to the admin envelope** — it searches
  only the top level where Rust searches top level *then* `wrapped_resource`, so
  against a real control-plane response every harvested receipt field collapses
  to its absence code and a guardrail revision mutation emits **no reversal
  command at all**. 339 CLI tests stay green because the fixture uses a bare body
  the control plane never returns. MEDIUM — operator tooling.

### 2.3 Libraries — 12 of 13 packages faithful; four unported slices; one unheld invariant

The library layer is the strongest part of the tree: the six correctness-critical
algorithm families (quota merge + counter-key namespacing, billing settled-cost /
`price_not_found` / bigint credits / idempotency, wallet no-oversell, guardrail
detector families, provider retry/breaker/failover/canary, the 56/56 portable
config validators) are all reproduced, and five of six are held by tests proven
RED by mutation. The counter-key port even **closes a reachable hole the Rust
still has** (`auth.rs:225 tpm_window` falls back to the raw, un-namespaced key id).

What is not there:

| Finding | Blast radius |
|---|---|
| **`ferrogate-cloudflare` is the 21st crate and appears in NO row of `PORT-PLAN.md`.** Four slices have no TS equivalent anywhere: (1) per-tenant R2 bucket provisioning; (2) minting SCOPED temporary R2 S3 credentials; (3) the required token-permission-group list + the `preflight` GET that names WHICH group is missing; (4) the shared retry/backoff honouring Cloudflare's ~1,200 req/5 min API limit plus the typed auth/missing-scope code mapping | **The single strongest argument against deleting the Rust.** These are account-MANAGEMENT operations, so no request path misses them — which is exactly why they would be most painful to re-derive. There are instead **three independent partial Cloudflare v4 clients**, each decoding the `{success,errors,result}` envelope itself |
| **Guardrail evidence-fingerprint KEYING is held by nothing.** Two semantically-real mutations (key → empty bytes; key → the constant `"FIXED"`) both left **407/407 guardrails + 112/112 gateway guardrail tests GREEN**. Every assertion is the SHAPE `/^hmac-sha256:[0-9a-f]{64}$/`, which an *unkeyed* SHA-256 also satisfies | **Security, test-integrity.** An unkeyed digest of a short secret is reversible by dictionary attack. Removing the key is precisely the regression the keying exists to prevent. **Test-only to close; hours of work** |
| **Cloudflare AI Gateway routing (#406) is unreachable in production.** `packages/providers` applies it; `apps/gateway/src/inference/adapters.ts` builds its own registry and never goes through that class. Not even *configurable* — `providerRecordSchema` is `.strict()` with no `cloudflare_ai_gateway` key, so a provider carrying the Rust block is REJECTED | MEDIUM — a live product feature (free caching, rate-limiting, observability) is off for every tenant. The textbook instance of this project's defect class, correctly identified and still open |
| `packages/sync-bridge` — zero importers, inventory target is literally `Deleted` | Recommend deleting the package. No risk |
| `packages/storage` carries credit amounts as `number`, `packages/billing` as `bigint`. Nothing asserts the boundary | LOW — unreachable below ~9.0e15 credits, but the two layers do not share an integer type |

### 2.4 IN-MEMORY-ONLY, as committed

| Worker | As committed | Consequence |
|---|---|---|
| `apps/mcp` | `FG_DEV_IN_MEMORY_PORTS = "1"` (`wrangler.toml:37`) | Auth, approvals, guardrails and secrets ARE durable in every posture. But `resolvePorts` short-circuits at `ports.ts:1723`, so `DurableCredentialStore` and the identity cipher stay in-memory: **OAuth grants die with the isolate** |
| `apps/agent-runtime` | `FG_DEV_IN_MEMORY_PORTS = "1"` (`wrangler.toml:64`); both D1 stanzas commented out | Real `d1ApiKeyPort` / `d1WorkerIdentityPort` exist and win when bound, and `resolveDeps` fails CLOSED when neither is — but **as committed, both are the dev bundle**. `governance` and `upstreams` have no durable leg in any posture |
| `apps/agent-runtime` | `FG_REQUIRE_PRODUCTION_MTLS = "0"` | Committed OFF. Must be `"1"` in production |
| `apps/agent-runtime` | `CONTAINER_SANDBOX` / `[[containers]]` commented out | `@cloudflare/sandbox` is a declared dependency; the binding is commented because Containers need a paid account. `agent-worker`'s only portable isolation backend is declared and unbound |
| `packages/guardrails` | `guardrail_evaluations` / `guardrail_check_evaluations` **do not exist in `sql/d1-ts/`** | Guardrail evidence is in-memory only |

`CLOUD-VERIFICATION.md` §B1 covers the two `FG_DEV_IN_MEMORY_PORTS` flags by
*procedure*. **Nothing mechanical stops a deploy inheriting any of the three.**
Seams `MCP-T9`, `AR-T6` and `AR-T7` prove the values are the committed ones; they
do not prevent them shipping.

---

## 3. The true portable marker residue, and what of it blocks cutover

From `MARKER-LEDGER.md`, which classified all 170 `PORT-TODO(` occurrences.

### 3.1 The count is not the story

| | |
|---|---|
| Repo-wide grep | 170 — **has never been the residue** |
| Canonical (`packages/*/src` + `apps/*/src`) | 130 at 05:40 |
| **P — PORTABLE** | 48 at 05:40 → **65 by 06:17** |
| **L — PLATFORM LIMIT** | 51, each naming a specific falsifiable limitation |
| **D — DEPRIORITIZED** (x402/Solana, by standing directive) | 10 |
| **N — NOT A MARKER** (epitaphs, cross-refs) | 20, de-marked to `PORT_TODO(` |
| **True portable residue** | **~43 distinct work items ≈ 100–145 dev-days** — *a floor, not an estimate* |

**The single most important number in this document is not any of those. It is
`+25 portable markers in ninety minutes`** — all written by concurrent
certification passes, including the eight most consequential findings in the
ledger (§3.1b: D1, D2, D4, D5, D6, D7 above, plus the guardrail-keying gap).
A fifth of the total residue, and the most severe fifth, was discovered by ONE
targeted audit of ONE surface, *while the ledger that was supposed to bound the
residue was being written*.

De-marking, prefixing and classification are genuinely useful and permanent work
— separating the 51 real platform limits from everything else will not have to
be done again. But **marker burndown has not hit diminishing returns**, and any
cutover decision framed as "130 markers, mostly platform limits" would rest on a
false premise.

### 3.2 What of it blocks deleting `crates/**`

Sixteen items. Deleting the Rust destroys the only specification for each.

- **Admission / money / abuse (4):** P39 + P40 (the dropped admission ladder on
  `apps/mcp` and `apps/agent-runtime` = finding D1) · P43 (asset egress quota +
  download RPM = D4) · P41 (workflow graph gate = D2).
- **Security (4):** P42 (asset content-type allowlist + `mcp_manifest` stdio
  refusal = D5) · P13 (self-hosted worker transport AEAD seal unverified) ·
  P21 (cross-tenant publish-approval + malware scan legs) · P6 (eligibility gate
  admits candidates Rust refuses).
- **Behavioural regressions (5):** P1 (CORS entirely absent — Rust ran
  `apply_cors_headers` on 9 response sites) · P2/P3/P4 (three ops answer 501) ·
  P5 (profile-resolution errors silently downgraded) · P8
  (`[[models]].cache_enabled` silently ignored) · P44 (drain honoured on 1 route
  of 31) · P46 (`?limit=0` → 200 instead of 400).
- **Specification-bearing (3):** P7 (Rust embeds the `cl100k_base` / `o200k_base`
  vocabularies — the TS estimates `chars/4`, and it feeds budget admission) ·
  P10 (the Rust extractor defines what a legitimate payload is) · P20
  (Rust `asset_bucket.rs` is the multipart contract).
- **Test-integrity (1):** P45 (guardrail evidence-fingerprint keying — the Rust
  is the only statement of what the key is FOR).

The remaining ~26 items are internal wiring, dead-code removal and duplication
cleanup. **They do not need the Rust and can proceed in parallel with it in the
tree.** Blocking on them would be over-caution; blocking on the sixteen is not.

### 3.3 Items with non-engineering prerequisites

These cannot be scheduled at all until something outside the repo changes:

- **R2 is not enabled on the live Cloudflare account** → P26 (MCP asset reader),
  and the `ferrogate-cloudflare` R2 provisioning slices.
- **Containers / `@cloudflare/sandbox` need a paid plan and a published image** →
  P4 (`executeFunction`), P27 (the `governance` port).
- **Secrets Store bindings resolve at DEPLOY time** and are unexercisable under
  `wrangler dev --local` → P14.

---

## 4. What is still UNVERIFIED — provable only by the live deploy

Every result in this repository, in every wave, comes from
`@cloudflare/vitest-pool-workers` or `wrangler dev --local`. The following are
believed correct and are **not** certified.

### 4.1 Only a real `wrangler deploy` can settle these

1. **The three DEPLOY-ONLY seams** — `GW-T2`, `CP-T2`, `MCP-T2`, `TEL-T5`
   (`compatibility_flags`) and `CP-T1`, `TEL-T1` (`main = "src/worker.ts"`).
   Confirmed GREEN under the full local suite this wave: nothing in the tree
   imports a `node:` builtin on a path the suites reach, and the local pool does
   not run workerd's entrypoint-shape check on `main`.
2. **`[[migrations]]` acceptance.** The local pool builds a DO namespace from the
   BINDING alone and never reads `[[migrations]]`. The gates ported in wave 14
   now assert the stanzas *textually* (all seven `new_sqlite_classes` rows went
   RED, including the `new_classes` substitution variants), but whether
   Cloudflare accepts them is a deploy fact.
3. **Secrets Store bindings** (P14) — deploy-time by construction.
4. **The `FG_DEV_IN_MEMORY_PORTS = "0"` override** required by
   `CLOUD-VERIFICATION.md` §B1. The committed `"1"` is what a naive deploy
   inherits (§2.4).
5. **Per-tenant D1 provisioning and binding**, incl. `GATEWAY_TENANT_DB_ROUTING`
   flipped away from its committed `"off"`. Deploy-time binding is the standing
   open constraint on the whole one-database-per-tenant design.
6. **Queue producer/consumer delivery** on the `BILLING` queue, and the
   `TELEMETRY_COLLECTOR` service binding across two deployed Workers.
7. **Analytics Engine write and read.** The read side is account-scoped REST with
   no offline emulation, which is why `observability()` returns `[]`.
8. **Cron trigger delivery.** `[triggers] crons` is asserted textually and the
   `scheduled` handler is invoked directly; that Cloudflare actually fires it on
   schedule is unproven.
9. **The ~1,200 req / 5 min Cloudflare API rate limit** and the typed
   auth / missing-scope code mapping (`ferrogate-cloudflare` slice 4).

### 4.2 Unverified for reasons a deploy would NOT fix

10. **Per-operation request/response *field* parity for ~60 control-plane
    collections** — bodies validate against a shared `passthrough()` base.
11. **Envelope keys beyond the three found.** Only Rust structs named
    `*MutationResponse` were swept.
12. **Search/filter field sets per collection.** Rust's `matches_search` uses a
    per-handler field list; the TS store applies `search` uniformly.
13. **Streaming SSE framing byte-for-byte** against Rust `messages_stream.rs` /
    `responses_stream.rs` — the suites are thorough but no normalised-frame diff
    was run.
14. **`sigv4` (Bedrock) and Vertex OAuth signing** against real AWS/GCP canonical
    request vectors.
15. **Three storage CAS / state-machine items not mutation-tested**: the
    workflow-budget optimistic CAS, the guardrail-binding generation CAS, and the
    payment-attempt state machine — **which has no dedicated test file at all**.
16. **`crates/ferrogate-auth-service`'s non-contract surface** — `/v1/admin/*`
    console identity, `/v1/auth/*`, `/scim/v2/*`, SAML/SSO: **11,474 LOC, a real
    and large unported cluster**, and the control plane's own `admin_users` /
    `sso_provider_configs` / `sso_pending_flows` tables have no writer. Outside
    every audit's declared scope so far. **This must not be forgotten at
    cutover.**
17. **The 51 `L` platform-limit claims were spot-checked, not exhaustively
    re-derived** (~15 checked, all held). If any single `L` is wrong, it is a `P`.
18. **The eight mid-wave §3.1b findings** are recorded on their author's
    authority; their `grep` evidence is quoted in each marker but was not
    independently re-run in the ledger (two spot-checks did hold).

---

## 5. The irreversibility note

`crates/**` is tagged `legacy-rs` and every byte is recoverable from git. **That
is not the same as the deletion being reversible in the way that matters.**

What the working-tree copy actually provides is a *diffable* reference. Every
certification in this wave was produced by an agent reading a Rust handler body
and a TypeScript handler body side by side, in one workspace, with `grep -rn`
spanning both. That is how D1 was found — not from a marker, not from a failing
test, but because someone read `finalize_auth` next to `contractAuth` and noticed
half of it was missing. The marker ledger states the same conclusion in one line:
*"half the severe defects in this ledger had no marker at all until someone read
the Rust handler next to the TS handler and compared them line by line."*

After deletion, that workflow ends. Recovering a tag into a scratch directory is
mechanically easy and practically almost never done: it is not in the workspace,
agents do not `grep` it, and the reference stops being consulted. Parity checking
degrades from *comparison* to *archaeology* — a defect found post-cutover gets
re-derived from observed behaviour, which is exactly what produced the
`?limit=0` divergence (the TS carries a comment asserting *"Rust: silently
clamped, never rejected"* which is **factually wrong about the Rust**, and which
survived precisely because nobody re-read the Rust).

So the deletion is best understood as **the irreversible step in this project,
even though the bytes are recoverable.** It should be taken once, deliberately,
after the sixteen specification-bearing items of §3.2 are either closed or
transcribed into this repository as ratified divergences — because transcription
is the only thing that survives the delete.

**Corollary, worth doing regardless of the verdict:** the four `ferrogate-cloudflare`
slices (§2.3) and a Rust-generated golden bucket table for `rolloutBucket` are
cheap to extract *now* and impossible to extract later. They should be written
down before any GO is reconsidered, not after.

---

## 6. What would turn this into a GO

Ordered by what unblocks the decision, not by size. Items 1–5 are the cutover
gate; the rest is ordinary work that can proceed alongside.

1. **Close D1** — mount the admission ladder on `apps/mcp` and
   `apps/agent-runtime`, over ONE shared counter namespace. This is the only
   finding that is a live control bypass rather than a fidelity gap.
2. **Close D4 and D5** — asset egress quota + metering; the content-type
   allowlist and the `mcp_manifest` stdio refusal. Money and security, both pure
   functions, neither a platform limit.
3. **Close the control-plane write half for `rbac`, `admin_api_key`,
   `guardrail_policy` and `wallets`** (37 ops) — the four groups where a 200
   response means "nothing happened" on a security or money surface. Plus the
   one-line `tenantScopeSql` write-fence split, with a mutation test.
4. **Close the guardrail evidence-fingerprint keying gap** — test-only, hours:
   assert two detectors with DIFFERENT keys produce DIFFERENT fingerprints for
   the same input, plus the same-key reproducibility control.
5. **Extract the four `ferrogate-cloudflare` slices** into `@ferrogate/cloudflare`
   or into a document that survives the deletion, and add the missing 21st-crate
   row to `PORT-PLAN.md`.
6. **Re-run all three parity certifications** afterwards, and re-run the FULL
   seam pass. Do not inherit either.
7. **Scope `crates/ferrogate-auth-service`'s 11,474 unported lines** (§4.2 item
   16) — decide explicitly whether SSO/SCIM is in or out of the cutover, because
   right now it is neither.
8. Close the four newly-unproven seams (GW-C11, MCP-R4, AR-C2, CLI-7); mutation-
   test the three storage CAS/state-machine items; give
   `payment-attempt.ts` a test file; mount AI Gateway routing (#406); delete
   `packages/sync-bridge`; move `FG_DEV_IN_MEMORY_PORTS` into an `[env.dev]`
   block so a deploy cannot inherit it.

**Then, and only then**, run the single authorised live deploy against the §4.1
list — because half of that list is unprovable any other way, and a deploy is
also the only way to find out what §4.1 does not yet know it is missing.

---

## 7. Scope statement

This wave: **local only.** No `wrangler deploy` was run. No live Cloudflare
resource was created, read or mutated. No real upstream LLM was called. No
`crates/**` or `workers/**` file was modified or deleted; none was read except
for comparison. Every one of the 163 seam mutations was reverted and verified
byte-identical by `sha256sum -c`, and the whole 827-file tree was re-verified
against a pre-pass snapshot. No test was weakened, skipped or deleted.

The cutover itself remains a separate, human-gated decision. This document is
evidence for it, not an execution of it.
