# CUTOVER READINESS — the decision document

**Date:** 2026-08-01 · **Wave 15**, amended by **waves 16, 17 and 18** · **Branch:** `main-ts`
**Question:** may we delete `crates/**`, `workers/**` and `Cargo.*`, and merge
`main-ts` → `main`?

> **Wave-16 amendment (2026-08-01).** Wave 16 fixed defects this document
> found. **§0.1 records exactly which findings are CLOSED and which are not.**
> The verdict below is UNCHANGED and was not re-litigated: closing findings is
> not the same as re-certifying, this document's own §6.6 requires all three
> parity certifications and the full seam pass to be re-run before the verdict
> moves, and the argument for NO-GO was never only the finding list — it was the
> shape of the evidence (sixteen specification-bearing items; a discovery curve
> that had not flattened). Only a fresh certification can change it.
>
> **Wave-17 amendment (2026-08-01).** Wave 17 took the entire remaining §0.1
> "NOT closed" list except the two items that need a live account.
> **§0.2 records what is now CLOSED, with the RED/GREEN the integrate step
> observed itself.** The verdict is again **UNCHANGED and not re-litigated**,
> for the same reason and for one more: wave 17's own integrate step found
> **three first-order defects that the delivering agents' green suites did not
> show** (§0.2's "found during integration" table), one of them a HIGH
> policy-bypass residue that made the wave's own D2 fix unreachable on the
> deployed Worker. That is direct evidence that **the discovery curve still has
> not flattened** — which is the second of the two arguments the NO-GO rests on.
> Only wave 18's fresh certification can move it; §0.2 ends by naming exactly
> what that certification must check.
>
> **Wave-18 amendment (2026-08-01).** Wave 18 did NOT run that certification. It
> ported the enterprise-identity surface that had no TypeScript at all, mounted
> it, fixed the one DEAD production route (`GW-C11`), and — the part that
> matters — ran `MODULE-OWNERSHIP.md`, the first **module-granularity** audit of
> the Rust tree. **§0.3 records what closed and what that audit opened: 37
> MISSING modules (27,644 lines) and 46 UNVERIFIED (23,040 lines).** The verdict
> is **UNCHANGED**, and §0.3.4 explains why the new evidence makes it firmer
> rather than closer to a GO.

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

## 0.1 WAVE 16 — which findings are CLOSED, and which are not

Wave 16 took §6 items 1–4. Everything below was verified by the integrate step
**independently of the delivering agents**: for each fix, the fix was reverted or
neutralised in place, a `grep` confirmed the edit had actually landed (a
concurrent write silently reverting a mutation is a known failure mode here), the
named test was required to go RED, the file was restored and required to go
GREEN again. A fix whose test was never *seen* red is not recorded as closed.

### CLOSED

| Finding | What landed | RED-before / GREEN-after, observed by the integrate step |
|---|---|---|
| **D1 — admission bypass** (the live control bypass; 20 of 54 data-plane ops) | The `finalize_auth` admission ladder — quota-scope chain, monthly USD budget, prepaid-wallet no-oversell hold, RPM window — ported onto `apps/mcp` (`src/admission/`, called from `src/http.ts::authenticateRequest`) and `apps/agent-runtime` (`src/admission/`, called from `src/middleware/auth.ts`). Both import `@ferrogate/policy`'s `QuotaScopeSelector.counterKey` rather than re-deriving it, so the counter key cannot drift between Workers | MCP: neutralising the `ports.admission.admit` call ⇒ **6 RED** in `apps/mcp/test/admission.test.ts`, restored **33/33 GREEN**. agent-runtime: neutralising `deps.admission.admit` ⇒ **6 RED** in `test/admission.test.ts` **and 4 RED** in `test/durable/admission.spec.ts` (real migrated D1), restored **8/8 + 8/8 GREEN**. Gateway leg re-proved on the same run: removing `rateLimit()` from `GATEWAY_MIDDLEWARE` ⇒ **16 RED** in the deployed-app suites |
| **D1 cross-Worker consistency** — the half that three green suites cannot show | `apps/gateway/test/admission-consistency.test.ts` (new, 7 cases): the three Workers' refusal tables must agree on status, on message text, and on every code two of them share; and all three must derive the counter key from the ONE `@ferrogate/policy` site | Proven RED by two mutations: MCP `quota_scope_disabled` 403→429 ⇒ **2 RED**; agent-runtime `rate_limit_exceeded` message reworded ⇒ **1 RED**. Restored **7/7 GREEN** |
| **D4 — asset egress** (money) | `apps/gateway/src/assets/egress.ts`: the fail-closed monthly egress BYTE budget and the download-RPM cap ahead of any byte served, then `recordAssetEgress` metering + the pull-side audit row. Wired through `AssetService`, so a `206` bills its slice and a `304`/`416`/`HEAD` bills nothing | Neutralising `#egressDenial`'s refusal ⇒ **4 RED** in `test/assets/egress.test.ts` (over-budget pull, over-RPM pull, the range request gated on FULL object size, the presigned-URL issuance). Restored **24/24 GREEN** |
| **D5 — asset publish gate 1** (security; the `mcp_manifest` **stdio** refusal) | `apps/gateway/src/assets/content-gate.ts`, called DIRECTLY by `AssetService` on `putAsset` and `commitUpload` ahead of the screener — deliberately not as an `AssetScreener` decorator, so no operator configuration and no injected test double can switch it off | Neutralising `#contentGate`'s rejection ⇒ **7 RED** in `test/assets/content-gate.test.ts`, including "REFUSES a stdio manifest", "refuses regardless of case" and "is NOT disableable through the screener seam". Restored **17/17 GREEN** |
| **Control plane — `rbac` write half** (a granted role authorized nothing; `DELETE` answered 200 and revoked nothing) | `apps/control-plane/src/store/rbac_registry.ts` + the route projections, ordered so a crash mid-write leaves a visible-but-unauthorizing binding rather than an invisible grant, and revokes the GRANT before the document | Neutralising `projectTenantRoleBinding` ⇒ **8 RED** in `test/rbac-write-half.test.ts`, incl. "DELETE stops authorizing on the very next request". Restored **12/12 GREEN** |
| **Control plane — `admin_api_key` write half** (the group could neither mint a working credential nor revoke one; both answered 200) | `apps/control-plane/src/store/static_keys.ts` + mint/revoke projection, with the minted key clamped so it can never exceed the caller that minted it | Neutralising `projectStaticApiKey` ⇒ **13 RED** in `test/api-keys-write-half.test.ts`, incl. "the minted secret authenticates on the very next request" and "the secret stops authenticating on the very next request". Restored **14/14 GREEN** |
| **Control plane — the tenant WRITE fence** (a tenant admin holding `admin.write` could PATCH or DELETE any un-attributed PLATFORM row) | `tenantWriteScopeSql` (D1) and `query.ts::writableBy` (memory) split from the READ predicate: strict `tenant_id = ?`, no `IS NULL` disjunct. Reads keep the disjunct, which `resolved-defaults` depends on | Both implementations mutated back to the read predicate, separately. D1 ⇒ **4 RED** in `test/tenant-write-fence.test.ts` (8/8 restored); memory ⇒ **6 RED** in `test/store-conformance.test.ts` (98/98 restored). The first mutation of `writableBy` left `tenant-write-fence.test.ts` GREEN — that file drives the D1 store — which is why both twins were mutated rather than one |
| **Guardrail evidence-fingerprint keying** (test-only; two real mutations used to leave 407/407 + 112/112 green) | `packages/guardrails/test/fingerprint-keying.test.ts` (32 cases) over all four fingerprint sites, checked against an INDEPENDENT `node:crypto` oracle rather than the package's own `hash.ts` | key → empty bytes at `hmacEvidenceFingerprint` ⇒ **12 RED**; key → a hard-coded constant in `DeterministicDetector#hmacFingerprint` ⇒ **3 RED**. Both restored **32/32 GREEN** |

### NOT closed — carried forward unchanged

| Finding | Why it is still open |
|---|---|
| **D1's shared counter, on the RPM leg only** | The four other legs (quota scope, monthly budget, wallet hold, and the counter-KEY derivation) are shared and durable across all three Workers today. The RPM WINDOW is not: it needs `apps/gateway`'s `RateLimiterDurableObject` bound cross-script into the other two, and **workerd cannot resolve a `script_name` binding offline**. Committed uncommented, `apps/mcp`'s suite collapses to 0 collected tests / 23 errors on a correct tree and `wrangler dev --local` never reaches "Ready on" (measured this wave). The stanza is therefore written out IN FULL but COMMENTED in both `wrangler.toml`s, pinned by both apps' `env-var-drift` gates (status, `script_name`, and the absence of a migration claiming the class), and is a **DEPLOY-ONLY** seam. Until it is uncommented the RPM cap is enforced per isolate — 60 rpm becomes 60·N across N isolates — versus **none** of the five legs enforced before this wave |
| **Control plane — `guardrail_policy` write half** (10 ops) | Deliberately NOT projected, and the reason is now written into `routes/guardrail_policy.ts`: `binding.ts::policySourceFromStore` calls `compilePolicyChecks` EAGERLY at construction with no `try`/`catch`, so projecting today's partially-validated revision documents would take the gateway's whole guardrail source down **at boot**. Closing it requires tightening the ADMISSION (a revision the data plane could never enforce must be a 400, not a 201 followed by silence), which is a behaviour change to two create operations and moves existing accepted cases with it |
| **Control plane — `wallets` write half** (10 ops) | Untouched. Admin writes `balance_cents` in the CONTROL db; the reader is `wallets.balance_credits` + `wallet_reservations` in the TENANT db. Crediting a wallet still does not fund a request |
| **D2, D3, D6, D7**, the three MISSING ops, `/metrics`, `/healthz` `version`, agent-runtime `/readyz` | Untouched by this wave |
| **`ferrogate-cloudflare` — the 21st crate** (§6 item 5) | Untouched. Still the single strongest argument against deleting the Rust: four slices with no TS equivalent anywhere and no `PORT-PLAN.md` row |
| **The other §2.2 DURABLE-BUT-UNREAD groups**, §2.3's AI-Gateway routing (#406), `sync-bridge`, the credits `number`/`bigint` boundary, §2.4's IN-MEMORY-ONLY postures | Untouched |
| **§4.1 — everything only a real deploy can settle** | Unchanged, and now one row longer: the cross-script `RATE_LIMIT` binding above |
| **§6 items 6, 7, 8** — re-run all three parity certifications and the full seam pass; scope `ferrogate-auth-service`'s 11,474 unported lines; the four newly-unproven seams | Untouched. **Item 6 is what gates the verdict**, and it has not been done |

**Net effect on the verdict: none, by design.** Wave 16 closed the four §6 items
that were nominated as closable, and did not touch the two arguments the NO-GO
actually rests on — the sixteen specification-bearing items, and a
defect-discovery curve that had not flattened. Wave 16 is itself weak evidence
about the curve: it was a *fix* wave, not an *audit* wave, so it was not looking.

---

## 0.2 WAVE 17 — which findings are CLOSED, and what wave 18 must still check

Wave 17 took the whole remaining §0.1 "NOT closed" list except the two rows that
require a live Cloudflare account. Six agents delivered; the integrate step
verified **every** fix independently, by the §0.1 protocol: neutralise the fix in
place, `grep` the mutation back OFF DISK to prove it landed, require the named
test RED, restore, `sha256sum`-verify the restore, require GREEN. **A fix whose
test was never *seen* red is not recorded as closed.** Nothing below is taken on
a delivering agent's word.

### CLOSED — verified by the integrate step's own mutations

| Finding | What landed | RED-before / GREEN-after, observed by the integrate step |
|---|---|---|
| **`wallets` write half** (MONEY — "crediting a wallet still does not fund a request") | `apps/control-plane/src/store/wallet_projection.ts`: the admin movement now projects into the TENANT database's `wallets.balance_credits` through `@ferrogate/storage`'s `D1WalletStore.settleWalletBalance` — **the same class `apps/gateway/src/ratelimit/wallet.ts` calls** — inside one `batch()` claimed by a `wallet_settlements` row. Cents→credits is `bigint` end to end. CREDIT writes the ledger claim first, DEBIT writes the enforced row first | **END-TO-END, asserted as the effect and not the status code:** seed an EXHAUSTED wallet, run the gateway's own `reserveWalletCredits` ⇒ `insufficient`; `POST /admin/v1/wallets/{t}/adjust {amount_cents:500}` ⇒ 200; run the SAME decision ⇒ **`reserved`**, balance exactly `5_000_000` credits. Neutralising the tenant leg ⇒ **10 RED** in `test/wallet-funding.test.ts`; restored **15/15 GREEN**. **Double-submit:** the same `reference` twice ⇒ both 200, balance moves **once**, ONE ledger entry; making `walletLedgerEntryId` non-deterministic ⇒ **3 RED**. Cross-tenant control included: crediting `tenant_a` leaves `tenant_b` at 0 and still `insufficient`. Two-implementation trap CHECKED: `MemoryWalletStore` exists in `@ferrogate/storage` but **no app constructs it** — all four (`gateway`, `mcp`, `agent-runtime`, `control-plane`) build `D1WalletStore`, so there is no green twin |
| **D2 — the workflow GRAPH gate** (HIGH; policy bypass. `[[agent_workflows]]` was parsed by `packages/config` and read by nothing) | `packages/policy/src/workflow-graph.ts` (all thirteen Rust refusals) + `apps/gateway/src/inference/workflow.ts` (Rust header names, the `control_plane_resources` catalog, a durable step ledger), enforced from `handlers.ts::admitWorkflowStep` ahead of dispatch | Neutralising the gate mount ⇒ **19 RED** across `test/inference/workflow-graph.test.ts` + `workflow-ledger.test.ts`. Replacing the composition root's env-resolved catalog with an empty one ⇒ **RED** (see the trap row below for what that mutation showed BEFORE the new gate). Restored GREEN |
| **`guardrail_policy` write half** (10 ops; previously refused on purpose because projecting a bad row took the gateway's guardrail source down at BOOT) | Admission tightened first — `packages/guardrails/src/admission.ts::admitPolicyRevision`, a revision the data plane could never compile is now a **400**, not a 201 followed by silence — then projection into `guardrail_policy_revisions` / `guardrail_policy_bindings` (`apps/control-plane/src/store/guardrail_registry.ts`), plus per-policy boot resilience on the read side so a pre-existing bad row fails **that one policy CLOSED** instead of the Worker | Neutralising `admitPolicyRevision` ⇒ **7 RED** in `test/guardrail-write-half.test.ts`; neutralising `projectGuardrailRevision` ⇒ **7 RED** in the same file (activate/rollback/archive all move the binding row). Read side: unmounting `D1GuardrailPolicyStore.fromEnv` from `guardrailDepsFromEnv` ⇒ **3 RED** in `test/guardrails/d1.test.ts`. Restored **1875/1875 GREEN**. Two-implementation trap CHECKED: `InMemoryGuardrailPolicyStore` is the var half and `loadGuardrailPolicyStore` layers the durable half onto it — the D1 leg has its own gate, so mutating one does NOT leave the other silently green |
| **`ferrogate-cloudflare` — the 21st crate** (§6 item 5; "the single strongest argument against deleting the Rust") | `packages/cloudflare` — S1–S5: account-scoped client with the retry schedule, D1 management, R2 buckets, bucket-scoped R2 token minting, scopes/envelope/errors. 146 tests | Narrowing `RETRYABLE_STATUSES` to `[429]` ⇒ **5 RED** across `test/retry.test.ts` + `test/client.test.ts`. **Wired, not merely written:** `packages/storage/src/tenant-rest.ts` now routes the D1 REST transport through `executeWithRetry`; forcing `isRetryableOutcome` to `false` ⇒ **5 RED** in `packages/storage/test/d1/rest-retry.test.ts`. `r2-token.ts` (S2) stays deliberately UNMOUNTED and says so — it needs the bucket-per-tenant decision and R2 enabled on the account |
| **D3** — the agent run that caused the spend never reached the metering row | `apps/gateway/src/metering/agent-run.ts`, threaded through `middleware.ts` (read off the request) and `event.ts` (`agent_run_id`, absent-stays-absent) | Dropping the header read ⇒ **1 RED** in `test/metering/agent-run-correlation.test.ts` ("a declared `x-ferrogate-agent-run-id` reaches the settled `event_json`"). Restored **13/13 GREEN** |
| **D6** — no per-request drain gate | `apps/gateway/src/routes/drain.ts`, mounted `app.use("*", options.nodeDrain ?? nodeDrainGate())` | Unmounting it ⇒ **3 RED** in `test/routes/drain.test.ts` (503 `node_draining` on all five spend-producing ops; re-read PER REQUEST; the same flag `/readyz` uses) |
| **D7** — agent-job event-feed divergences | `apps/agent-runtime/src/runs/events.ts` — discriminator, `400 invalid_event_cursor`, the resume cursor surviving its own event, the `/result` `work_products` projection | Making a non-integer `?limit` fall back instead of refusing ⇒ **2 RED** in `test/event-feed.test.ts` |
| **Contract gaps — `/metrics`, `/healthz` `version`, agent-runtime `/readyz`** | `apps/gateway/src/routes/metrics.ts` (`getMetrics`, Prometheus exposition over this isolate's counters) and `apps/agent-runtime/src/routes/health.ts` (the shared health document + the Rust readiness decision table) | Unregistering `getMetrics` ⇒ **5 RED** (`test/routes/metrics.test.ts` **and** `test/contract.test.ts`'s "mounts ALL 31 gateway-owned operations"). `/healthz` `version`: caught by `e2e/tests/gateway.spec.ts` over real HTTP. agent-runtime `/readyz`: see the "wired during integration" row below |
| **Remaining DURABLE-BUT-UNREAD control-plane groups + the 3 MISSING ops** | `admin_agent_cost_burn`, `admin_agent_upstream`, `admin_agent_workflow`, `admin_request_log` now read the durable rows | Dropping the tenant fence from the cost-burn query ⇒ **10 RED** in `test/agent-cost-burn-read.test.ts` (incl. "never shows one tenant another tenant's burn"). Dropping the audit-trail fence ⇒ **3 RED** in `test/audit-events-read.test.ts` |
| **`sync-bridge` deleted** | `packages/sync-bridge/**` removed; the root `workspaces` glob picks the removal up with no manifest edit | Verified by the integrate step: `grep -rn "sync-bridge"` over `apps/`, `packages/`, `e2e/` and every `package.json`/`tsconfig.json` returns **nothing** (only historical prose in `docs/`); `bun.lock` contains **0** references; `bun run typecheck` clean; full suite green |

### FOUND DURING INTEGRATION — defects the delivering agents' green suites did not show

These are the reason this wave is *not* evidence that the discovery curve has
flattened. All three were found by the integrate step's own mutations, and all
three are fixed and gated here.

| Defect | How it hid | Fix + observed RED |
|---|---|---|
| **The D2 gate was UNREACHABLE on the deployed Worker** (HIGH — the wave's own headline security fix did nothing in production for reference-shaped clients) | `src/ratelimit/workflow.ts::workflowDeclarationFrom` (wave 16's budget envelope) required `x-ferrogate-workflow-run-id` among three headers that must appear together. The graph gate uses Rust's `x-ferrogate-agent-run-id`. A reference-shaped client therefore met the RATE-LIMIT middleware first and got `400 invalid_workflow_declaration` before the gate ran. Invisible because **every** workflow test built its own router (`fixtures.ts::harness` → `createInferenceRouter`) and none ran the middleware chain. `src/inference/workflow.ts` documented the residue and wrote out the fix, but as "not this module's to fix" | The recipe applied verbatim (the run-id alias, with its load-bearing `workflowId === ""` guard so a bare correlation id on assets/MCP traffic stays `absent`), plus a NEW SELF-driven gate `apps/gateway/test/inference/workflow-mount.test.ts` (9 cases). **Measured: all nine answered `400 invalid_workflow_declaration` before the alias.** Removing the alias again ⇒ **6 RED**; replacing the composition root's catalog with an empty one ⇒ **7 RED** (was **1** of 1866 before this file existed, i.e. no HTTP-level proof at all). `test/ratelimit/guards.test.ts` green either way, as the residue note predicted |
| **Three DO binding NAMES had no gate** (GW-T8/T10/T12) | `test/wrangler-bindings.test.ts` asserted `class_name` three ways and `name` **zero** ways — and `name` is the half `src/` reads (`env.RATE_LIMIT`, `env.PROVIDER_CIRCUIT`, `env.SHADOW_BUDGET`). The cited escalation gate `test/ratelimit/durable-object.spec.ts` runs under `test/ratelimit/harness/vitest.config.ts`, which points at **`harness/wrangler.toml` — a different file**. Each read degrades SILENTLY when unbound: the RPM limiter falls back per isolate (the quieter form of the wave-16 admission bypass), the provider circuit becomes a per-isolate `Map`, the shadow budget stops being a cross-isolate cap | New `it("binds each namespace under the NAME src/ reads it by")`. Renaming any of the three ⇒ **1 RED** each |
| **`compatibility_flags`, `main`, and MCP's DO migrations had no gate in 4 of 5 Workers** (GW-T2, CP-T1/T2, AR-T2, MCP-T1/T2/T6/T7, TEL-T1/T5) | MOUNT-SEAMS recorded GW-T2's *Expected RED* as "whole suite". Measured: commenting `compatibility_flags` out left **every** suite in every app GREEN — `@cloudflare/vitest-pool-workers` supplies its own runtime flags. Same for `main` and for `new_sqlite_classes` in `apps/mcp` (already known NO-GATE, now closed) | Drift assertions added to `apps/gateway/test/wrangler-bindings.test.ts`, `apps/agent-runtime/test/wrangler-bindings.test.ts`, and the `env-var-drift.test.ts` of control-plane, mcp and telemetry. Each mutation ⇒ **1 RED** |
| **MCP-P6 — the identity CIPHER seam had no gate** (security) | `resolvePorts`'s durable branch sets `cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY)`. Deleting that line left all 359 mcp tests GREEN — every assertion in the block was about `ports.credentials`. Without it the durable credential store seals OAuth grants under `webCryptoIdentityCipher()`'s **ephemeral per-isolate key**: every stored grant becomes undecryptable on the next isolate recycle, and the operator's configured key sits unread | New case in `test/durable-identity.test.ts`: seal with a cipher built from the fixture key, open with the one `resolvePorts` chose. Deleting the line ⇒ **1 RED** |

### NOT closed — carried forward

| Finding | Why it is still open |
|---|---|
| **D1's shared counter, on the RPM leg only** | Unchanged from §0.1. Needs a cross-script `script_name` binding, which **workerd cannot resolve offline**; committed uncommented, `apps/mcp` collapses to 0 collected tests and `wrangler dev --local` never reaches "Ready on". Still DEPLOY-ONLY, still pinned commented by both apps' `env-var-drift` gates |
| **§4.1 — everything only a real deploy can settle** | Unchanged. `packages/cloudflare` narrows the *code* gap but every one of its five slices talks to the Cloudflare API and **none has been run against the live account**; the tests are transport-level fakes by construction. `r2-token.ts` additionally needs R2 enabled, which it is not |
| **§2.3's AI-Gateway routing (#406), the credits `number`/`bigint` boundary at the remaining call sites, §2.4's IN-MEMORY-ONLY postures** | Untouched by this wave |
| **`ferrogate-auth-service`'s 11,474 unported lines** (§6 item 7) | Untouched. Not scoped, not ported, not certified |
| **§6 item 6 — re-run all three parity certifications and the full seam pass** | **Untouched, and it is what gates the verdict.** See below |

### What wave 18's certification must check — explicitly

The verdict cannot move until §6.6 is satisfied. Concretely, wave 18 must:

1. **Re-run all three parity certifications** (`cutover-parity-dataplane.md`,
   `cutover-parity-controlplane.md`, `cutover-parity-libraries.md`) against the
   CURRENT tree, by fresh agents. Waves 16 and 17 were *fix* waves, not *audit*
   waves — neither was looking for new defects, and wave 17 still tripped over
   four. The specific new surface that has never been parity-certified at all:
   `packages/policy/src/workflow-graph.ts`, `packages/guardrails/src/admission.ts`,
   `packages/cloudflare/**` (all 21 modules), `packages/storage/src/credits.ts`,
   `apps/control-plane/src/store/{wallet_projection,guardrail_registry}.ts`,
   `apps/gateway/src/{inference/workflow,metering/agent-run,routes/drain,routes/metrics,routes/service}.ts`,
   and `apps/agent-runtime/src/routes/health.ts`.
2. **Re-run the FULL mount-seam pass** — all rows, not the §4(a)/(b) incremental
   policy. Wave 17 ran the incremental policy (touched files + every T1) and that
   is what found the ten ungated config rows above; a full pass is mandatory
   before the Rust tree is deleted, per `MOUNT-SEAMS.md` §4 exception 2.
   **The inventory itself must be re-derived mechanically first**: wave 17 added
   rows (AR-C10) and corrected the *Expected RED* of ten others, so a pass run
   off the old table would re-assert corrections that are now wrong.
3. **Re-audit the two escalation-config apps for the harness trap.** The
   `test/ratelimit/harness/` finding above is a class, not an instance: any
   `*.spec.ts` project pointed at its own `wrangler.toml` or its own
   `worker.ts` proves nothing about the deployed config. `apps/gateway`'s
   tenancy harness and `apps/agent-runtime`'s durable harness have not been
   checked for it.
4. **Decide the two deferred sub-questions the code now names**: whether the
   budget envelope's `x-ferrogate-workflow-version` may be optional (Rust's is
   `Option<u32>`; ours is part of a primary key), and whether R2 goes
   bucket-per-tenant (which is what unmounts-or-mounts `r2-token.ts`).
5. **Answer the question no local wave can**: run the §4.1 live-deploy list.
   `packages/cloudflare` existing does not make it verified.

**Net effect on the verdict: none, by design.** Wave 17 closed nine of the ten
remaining findings and found four more while doing it. The second of those two
numbers is the one that matters.

---

## 0.3 WAVE 18 — what this wave CLOSED, and the much larger thing it OPENED

> **The verdict in §0 is UNCHANGED and was not re-litigated.** Per §6.6 only a
> fresh three-way certification plus a full seam pass can move it, and wave 18
> produced neither: it produced a *port*, an *integration*, and — decisively —
> a **new control that had never been run before**, whose first result is the
> largest single piece of bad news in this document's history.

### 0.3.1 CLOSED by wave 18

| # | What was closed | Evidence the integrate step observed ITSELF |
|---|---|---|
| C1 | **Enterprise identity existed nowhere in TypeScript.** SAML 2.0 (`packages/sso`), OIDC RP + SCIM 2.0 (`packages/identity`) and the admin-console session surface (`apps/control-plane/src/session/`) are now implemented AND MOUNTED on the deployed control-plane Worker | `apps/control-plane/test/identity-mount.test.ts` — 23 `SELF`-driven cases. Mount seams `CP-S1`/`CP-S2`/`CP-S3` mutated: **18 / 10 / 12 RED**, restored GREEN. Confirmed again on a real `wrangler dev --local` boot: `POST /v1/admin/login` → `503 admin_console_unconfigured`, `GET /scim/v2/Users` → `401`, `GET /v1/admin/auth/saml/acs` → `422 missing_relay_state` — three surfaces answering, none `404` |
| C2 | **`GW-C11` — the gateway's `/version` was DEAD IN PRODUCTION**, registered after the `app.all("*")` fall-through, for seventeen waves. It was the only one of the five Workers not serving `/version` | Moved inside `createGatewayApp`, above the fall-through. Re-proven by deletion: **2 RED**. Confirmed on a real boot: `GET /version` → `200 {"api":"v1"}` (it was `404 not_found`) |
| C3 | **Eight mount lines that had never been a row in any wave's table**, plus three T1 rows whose only cited gate was a harness that builds its own Worker | `docs/rewrite/MOUNT-SEAMS.md` was re-derived mechanically from the composition roots rather than patched. Five new T1 rows (`CP-S1`…`CP-S5`) were added by the integrate step for its own mounts |
| C4 | **The SSO replay defence had no durable proof.** `packages/{sso,identity}` prove single-use `take` against an in-memory map; the D1 twin was unproven | `apps/control-plane/test/sso-store-contract.test.ts` runs the package's OWN exported `samlPendingFlowStoreContract` against the D1 implementation. Mutating the `DELETE … RETURNING` to a `SELECT` is **5 RED** across that file and the mount suite |

### 0.3.2 Found DURING integration — the curve still has not flattened

Wave 17's amendment rested on this same observation, and wave 18 reproduces it.
Every item below was green in the delivering agent's own suite.

1. **The D1 pending-flow store diverged from the package's own exported contract
   in two ways**, and one of them is replay-adjacent: the first implementation
   filtered expiry in SQL (`… AND expires_at_unix > ?`), so **presenting an
   expired state did not BURN it** — the row survived for a second attempt under
   a different clock. Caught only because the contract is exported from `src/`
   and could be run against the durable twin; **no test in `packages/sso` or
   `packages/identity` could have seen it.** Fixed to `DELETE … WHERE state = ?
   RETURNING *` with the expiry decided in TypeScript on a row that no longer
   exists either way.
2. **`test/console-session.test.ts` is a FACTORY test**, not a mount test: it
   builds its own `Hono` app and calls `app.request(...)`. Measured — it stays
   **fully green with the console-session surface unmounted from the deployed
   Worker**. That is `MOUNT-SEAMS.md` §4's rule firing for the twelfth time.
3. **`ADMIN_CONSOLE_JWT_SECRET` was read by `src/` and named nowhere in the
   deploy config.** The env-var drift gate caught it the moment the surface was
   mounted; it is now a documented `wrangler secret` and a new **B7** blocker in
   `CLOUD-VERIFICATION.md`, alongside **B8** (per-tenant IdP secret references)
   and **B9** (the control migrations are now two files).

### 0.3.3 OPENED by wave 18 — `MODULE-OWNERSHIP.md`, and why it is the headline

`docs/rewrite/MODULE-OWNERSHIP.md` is the first control this project has ever run
at **module** granularity. `PORT-PLAN.md` maps CRATES, and
`docs/openapi/runtime-api-contract.json` enumerates OPERATIONS — and
`crates/ferrogate-auth-service/src/server.rs` serves **34 routes, none of which is
in that contract**. Two independent controls therefore had the *same* blind spot,
which is why an entire enterprise-identity crate could be missing for seventeen
waves with every audit green.

Its verdict, over **363 product modules / 275,295 lines** of Rust:

| Class | Modules | Lines |
|---|---:|---:|
| PORTED | 245 | 197,756 |
| OBSOLETE-ON-CF | 24 | 19,677 |
| DELIBERATELY-DROPPED | 11 | 7,178 |
| **MISSING** | **37** | **27,644** |
| **UNVERIFIED** | **46** | **23,040** |

**Do not net wave 18's work off that 37.** The audit ran while the identity
packages were being written and states its own rule: *"a row does not become
PORTED because a package directory appeared."* Wave 18 has now delivered
implementations **and mutation-proven mounts** for the 8-module / 5,345-line
enterprise-identity group, so a wave-19 **behaviour-level re-derivation** may
reclassify those eight. It has not happened yet. What is certain today is the
other number:

> **29 MISSING modules / ~22,300 lines that no wave has touched, plus 46
> UNVERIFIED modules / 23,040 lines that this pass explicitly declines to call
> PORTED.**

The unfunded MISSING work is not cosmetic. It includes the 4-module,
11,371-line **external-action capability boundary** (TypeScript models it as
`requiredCapabilities: string[]`, which cannot express a per-variant decision),
the 11-module **coding-agent five-phase contract** including its credential
broker, **evidence redaction** (`recorded_evidence.rs` — evidence rows can carry
unredacted upstream bytes), **tether-bypass detection**, **agent memory**, the
**brokered edge-function egress** family, and the **budget-alert webhook** that
never fires. Several are security- or money-relevant and **none of them was in
any wave's task list**.

### 0.3.4 What this means for the verdict

It strengthens **NO-GO** rather than weakening it, and for a new reason: until
wave 18 the argument was *"the discovery curve has not flattened."* It is now
*"we have measured the residue for the first time, and it is 37 modules we
cannot see the bottom of plus 46 we have not looked at."* §5's irreversibility
note applies with full force — deleting `crates/**` deletes the only
specification for every one of them.

**Wave 19 cannot certify on this evidence.** The minimum before a GO is
re-litigated:

1. re-derive the 8 enterprise-identity rows at BEHAVIOUR level and reclassify
   them honestly (they are the only rows wave 18 could have moved);
2. take the **46 UNVERIFIED** rows to a decision — each is a claim that this
   pass did not prove presence, not a claim of absence, and shipping on them is
   shipping on "probably";
3. fund or explicitly drop, with a recorded decision, the **29 untouched
   MISSING** modules — starting with `recorded_evidence.rs`,
   `cloudflare_container_tether_audit.rs` and the external-action boundary,
   which are the security-relevant ones;
4. everything §0.2 already listed, which is unchanged.

**Net effect on the verdict: none, by design — but the gap to a plausible GO got
measurably larger, because for the first time it was measured.**

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
| **D1** | **CLOSED (wave 16) except the shared RPM counter — see §0.1.** **The admission half of `authenticate()` did not cross the Worker split.** `403 tenant_identity_required` · lifecycle suspension · `503 quota_resolution_unavailable` · `403 quota_scope_disabled` · `429 monthly_budget_exceeded` · `429 wallet_balance_exhausted` · `429 rate_limit_exceeded` are mounted on `apps/gateway` only. `grep -rn "rate_limit_exceeded\|monthly_budget_exceeded" apps/mcp/src apps/agent-runtime/src` → nothing | **20** | **CRITICAL — money + abuse.** Rate limits and spend caps bypassable by calling a different verb on the same key. Exploitable with no special knowledge. Not a platform limit; the fix needs all three Workers to share ONE counter namespace, or a per-Worker counter hands each surface a full quota (a different bug) |
| **D2** | **The workflow GRAPH gate is unported.** `[[agent_workflows]]` is parsed and validated by `packages/config` and read by nothing (`grep -rn "agent_workflows\|agentWorkflows" apps/` → nothing). 13 Rust refusal codes absent. Header set also renamed (`…-node-id`/`…-iteration` have no reader; `…-run-id` is new and required) | 5 | **HIGH — policy bypass.** Node pinning, edge transitions, iteration/model-call limits and workflow timeout all stop being enforced while the config is accepted. A Rust-shaped workflow client is refused `400` outright |
| **D3** | `x-ferrogate-agent-run-id` is read on assets and MCP but **not** on the inference path (`grep -rn "agent-run-id" apps/gateway/src/inference/ apps/gateway/src/metering/` → nothing) | 5 | **MEDIUM — evidence.** Model spend cannot be joined to the agent run that caused it. Cost attribution has a hole exactly where the cost is |
| **D4** | **CLOSED (wave 16) — see §0.1.** **Asset egress: no quota gate, no metering, no pull audit.** `monthly_egress_bytes_budget` / `download_rpm_limit` are parsed, persisted and served by the admin API and read by nothing; `asset_egress_price_per_gb` has no consumer | 1 | **HIGH — money.** Unlimited bandwidth served and none of it billed. An operator can configure an egress budget, see it echoed back, and have it enforce nothing |
| **D5** | **CLOSED (wave 16) — see §0.1.** **Asset publish gate 1 unported**: the per-`asset_type` content-type allowlist, and the `mcp_manifest` **stdio refusal** | 2 | **HIGH — security.** Any byte stream publishable under any asset type; a tenant can publish an `mcp_manifest` declaring `stdio`, which makes a *consuming* agent spawn an arbitrary local process. Pure function of two strings and a buffer — no platform limit |
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
| `rbac` **— CLOSED (wave 16)** | 11 | `tenant_role_bindings ⋈ roles`, read by 4 modules across 3 Workers | **HIGH — security.** A granted role authorizes nothing; **`DELETE /admin/v1/tenant-roles/{t}/{r}` answers 200 and revokes nothing** |
| `wallets` | 10 | `wallets.balance_credits` + `wallet_reservations` in the TENANT db (admin writes `balance_cents` in the CONTROL db) | **HIGH — money.** Crediting a wallet does not fund a request |
| `guardrail_policy` **— STILL OPEN; blocker documented in place, §0.1** | 10 | `guardrail_policy_revisions` / `guardrail_policy_bindings` | **HIGH — safety.** An activated policy is never evaluated |
| `admin_api_key` **— CLOSED (wave 16)** | 6 | `static_api_keys` — and no secret is minted at all | **HIGH — security.** The group cannot produce a working credential and cannot revoke one; both answer 200 |
| `admin_request_log` | 5 | `request_logs` has no writer at all | MEDIUM — evidence |
| `admin_provider` / `admin_model` | 4 | Rust reads live config + dispatches a catalog per provider | MEDIUM |
| `agent_run` | 3 | the `AgentRunState` Durable Object | MEDIUM — evidence |
| `admin_agent_cost_burn` | 1 | `agent_cost_burn` in the TENANT db | MEDIUM |
| `prompt` / `admin_agent_upstream` | 12 | the `GATEWAY_PROMPT_TEMPLATES` / `GATEWAY_AGENT_UPSTREAMS` **vars** | MEDIUM — admin CRUD needs a redeploy to take effect |
| `skill` / `admin_plugin` / `admin_policy` / `admin_agent_workflow` | 25 | no reader | LOW — the Rust surfaces were also thin config CRUD |

Plus three PARTIAL findings that are not "unread":

- **CLOSED (wave 16) — see §0.1.** ~~The tenant WRITE fence is wider than Rust.~~ The write fence is now `tenant_id = ?` in both the D1 and the memory store, split from the read predicate and mutation-pinned in both. The original finding, for the record: `tenantScopeSql` is
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
| **CLOSED (wave 16) — see §0.1.** **Guardrail evidence-fingerprint KEYING is held by nothing.** Two semantically-real mutations (key → empty bytes; key → the constant `"FIXED"`) both left **407/407 guardrails + 112/112 gateway guardrail tests GREEN**. Every assertion is the SHAPE `/^hmac-sha256:[0-9a-f]{64}$/`, which an *unkeyed* SHA-256 also satisfies | **Security, test-integrity.** An unkeyed digest of a short secret is reversible by dictionary attack. Removing the key is precisely the regression the keying exists to prevent. **Test-only to close; hours of work** |
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

> **Wave-16 status line.** Items 1–4 are **DONE except one leg of item 1 and two
> of the four groups in item 3**; see §0.1 for exactly what was closed, and for
> the RED-before/GREEN-after each closure was verified with. **Item 6 is what
> gates the verdict and has not been started.** Items marked DONE below are kept
> in place rather than deleted, because the list is also the record of what the
> cutover gate WAS.

1. ~~**Close D1**~~ — **DONE except the shared RPM counter (wave 16).** The
   ladder is mounted on `apps/mcp` and `apps/agent-runtime`, and the quota
   chain, monthly budget, wallet hold and the counter-KEY derivation are one
   shared, durable answer across all three Workers. The RPM WINDOW is not yet
   one counter: it needs `apps/gateway`'s `RateLimiterDurableObject` bound
   cross-script, which **workerd cannot resolve offline**, so the stanza is
   committed COMMENTED in both `wrangler.toml`s and is DEPLOY-ONLY. Per-isolate
   RPM until then. This was the only finding that is a live control bypass
   rather than a fidelity gap, and the bypass itself is closed.
2. ~~**Close D4 and D5**~~ — **DONE (wave 16).** Asset egress quota + metering
   (`src/assets/egress.ts`); the content-type allowlist and the `mcp_manifest`
   stdio refusal (`src/assets/content-gate.ts`, enforced ahead of the screener
   and not through it).
3. **Close the control-plane write half for `rbac`, `admin_api_key`,
   `guardrail_policy` and `wallets`** (37 ops) — the four groups where a 200
   response means "nothing happened" on a security or money surface. Plus the
   one-line `tenantScopeSql` write-fence split, with a mutation test.
   **PARTLY DONE (wave 16): `rbac` (11) and `admin_api_key` (6) are closed and
   mutation-pinned, and the write fence is split in BOTH stores. `wallets` (10)
   is untouched. `guardrail_policy` (10) is deliberately still open — projecting
   today's partially-validated revisions would take the gateway's guardrail
   source down at boot, because `policySourceFromStore` compiles checks eagerly
   with no `try`/`catch`; closing it means tightening the create-revision
   ADMISSION first. The reason is written into `routes/guardrail_policy.ts` so
   it is not rediscovered.**
4. ~~**Close the guardrail evidence-fingerprint keying gap**~~ — **DONE
   (wave 16).** `packages/guardrails/test/fingerprint-keying.test.ts`, 32 cases
   over all four fingerprint sites, checked against an independent `node:crypto`
   oracle. No source change was needed; the code was always correct, only unheld.
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

**Wave 16 (the amendment in §0.1): local only, on the same terms.** No
`wrangler deploy`, no live Cloudflare resource, no real upstream LLM call, and no
`crates/**` or `workers/**` file created, modified or deleted. Every fix
verification in §0.1 was a mutation that was reverted and re-verified GREEN, and
every mutation was `grep`-confirmed to have landed before its RED was believed.
No test was weakened, skipped or deleted; the two `env-var-drift` exception lists
that changed were made STRICTER (a name moved from "not even mentioned in
`wrangler.toml`" to "mentioned but undeclared", and three new assertions were
added pinning the `RATE_LIMIT` stanza's commented state, its `script_name`, and
the absence of a migration claiming a class the script does not export).
