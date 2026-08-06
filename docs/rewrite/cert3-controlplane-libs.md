# CERT-3 — the CONTROL PLANE and the LIBRARIES, certified fresh

**Date:** 2026-08-01 · **wave 23** · **Tree:** `/home/dev/ferrogate-ts` (`main-ts`)
**Scope:** the 197 `/admin/v1/**` + `/metrics` operations owned by
`apps/control-plane`, plus its 24 non-contract enterprise-identity routes
(session / SAML / OIDC / SCIM); **and** all 15 `packages/*` against the crates
they replace.
**Supersedes:** `cert2-controlplane.md` and `cert2-libraries.md` (both wave 19).

**This is a FRESH pass.** Nothing below is inherited. Every count was
re-derived mechanically, every "held by a test" claim was re-proved by a
mutation I applied, confirmed off disk, ran, and reverted. Where cert2 was
right I say so with fresh evidence; where it is now **stale** I overturn it —
in both directions. **Two of its verdicts are overturned upward (closed) and
two new gaps are opened that no prior wave named.**

---

## 0. The verdict, in one paragraph

The control plane has closed the last of the "write answers 200 and changes
nothing" defects that mattered, and I re-proved **eight** of them myself as
EFFECTS — the role stops authorizing, the key stops authenticating, the credit
funds a request, the activated revision **refuses a real MCP `tools/call` and a
real A2A message**, the drain refuses billable work, the withdrawn upstream
stops being discoverable *and* stops being dispatchable, the dead letter
replays exactly once. **`admin_agent_upstream` (6 ops) and the drain half of
`admin_config_ops` (2 ops), both of which cert2 recorded as unread or
inert, are now genuinely closed**, and `guardrail_policy` — which cert2 could
only prove *structurally* — is now proved behaviourally across three Workers.
That takes the residue from cert2's 62 no-consumer operations to **55**. All
55 are still CLASS A by cert2's own test (I re-read the Rust for the five
config-backed groups and it is still a persist → validate → hot-reload →
rollback transaction, not a stub), and none of them is new. The library layer
is in the same shape cert2 left it: **one CLASS A item (L1, AI Gateway routing,
a composition-root defect in `apps/gateway`)** and four test-gaps whose
mutations I re-ran and which **all four still SURVIVE**. What is new is worse
than any of them individually and is the reason this document is not a
rubber stamp:

> **Two invariants this project treats as load-bearing are held by NOTHING, and
> both were found the same way — by mutating the code and watching a green
> suite stay green.**
>
> **C1 (control plane, security-adjacent).** The operator's suspension write —
> `PATCH /admin/v1/tenant-accounts/{id} {"status":"suspended"}` → the typed
> `tenants.status` column the three spend Workers read — can be neutralised in
> `store/quota_registry.ts` and **693/693 control-plane tests stay green AND
> the FC-2 fleet gate stays 12/12 green**, because the control plane's own
> lifecycle gate reads the *document* and the fleet gate writes the *column*
> with its own hand-written `UPDATE`. Nothing in the tree joins the two.
>
> **L11 (libraries, money/integration).** A structurally wrong AWS SigV4
> canonical request — the mandatory blank line between the canonical headers
> and the signed-header list, deleted — leaves **75/75 `packages/providers`
> tests green**, because every SigV4 assertion is a *shape* assertion
> (`/^[0-9a-f]{64}$/`). Every Bedrock request would be rejected with
> `SignatureDoesNotMatch` and no offline test could tell. **I verified the
> implementation is in fact correct** by reproducing it against an independent
> Python implementation of the AWS algorithm, and §7.11 records the two golden
> signatures so the gap can be closed in ten lines.

Neither is a CLASS A regression — both are correct code with tests that do not
hold it, which is this project's own documented dominant defect mode. Both are
cheap. Neither should be discovered by a customer.

---

## 1. Method

1. **The 197 were re-derived mechanically.** `docs/openapi/runtime-api-contract.json`
   → segment-aware longest-prefix match of each operation path against
   `route_patterns` → filter to `/admin/v1`, `/admin/v1/**`, `/admin`,
   `/admin/`, `/admin/dashboard`, `/admin/status`, `/metrics`. Result:
   **197 operations in 31 groups**, matching `contract.ts`'s
   `EXPECTED_CONTROL_PLANE_OPERATION_COUNT` and matching cert2's group table
   **group for group, count for count**. (A naive prefix match gives the same
   197 but mis-splits five groups; the segment-aware one is the correct
   derivation and is reproduced in §2.)
2. **The consumer graph was re-derived by grep over PRODUCTION source only** —
   `apps/{gateway,mcp,agent-runtime,telemetry,cli}/src` + `packages/*/src`,
   for each of the 59 collection names and typed tables the 31 groups write.
   `apps/cli/src/registry.ts` matches were **discarded**: the CLI is a *client*
   of the admin API, so its naming a collection is not a consumer.
3. **Mutation protocol.** For each claim: `sha256` the pristine file → apply a
   `/*MUT-…*/`-marked edit whose old text occurs **exactly once** → **re-read
   the file OFF DISK** and assert the new text is present and the file changed
   → run the named suite → restore → `sha256` and require byte-identity. The
   off-disk step is not ceremony: a concurrent dev-loop agent landed work in
   this tree while this audit ran (`apps/mcp/test/fleet-guardrail-activation.test.ts`
   changed mid-session), and a clobbered mutation is indistinguishable from an
   ungated seam. **19 mutations applied, 19 restored byte-identical**;
   `grep -rn "MUT-C3\|MUT-P[0-9]\|MUT-L[0-9]\|MUT-SIGV4" apps packages` →
   **nothing**.
4. **Mutations attack the DECISION, not the source text.** `MOUNT-SEAMS.md`'s
   M22 warning is taken literally here: M-E neutralises the gateway's drain
   *decision* while leaving every string, table name and `import` intact.
5. **The Rust was READ, not assumed**, for every A/B/C call in §4.
6. **Baseline, first-hand:** `bun run test` at the root → **exit 0**,
   **6,977 passed · 9 todo · 0 failed** across 24 vitest project-runs;
   `bun run typecheck` → **exit 0**, 22 projects, zero diagnostics. Both run
   before and after the mutation series.

---

## 2. Measurements — all re-derived this wave

| Metric | Value |
|---|---:|
| `bun run test` (root) | **exit 0** · 6,977 passed · 9 todo · 0 failed |
| `bun run typecheck` | **exit 0** · 22 projects · 0 diagnostics |
| `packages/*` subtotal | **2,730 passed + 9 todo** across 15 packages |
| `apps/*` subtotal | **4,247 passed** across 6 apps |
| `apps/control-plane` | **693 passed / 37 files** (cert2: 672 / 36) |
| TypeScript source (`packages/*/src` + `apps/*/src`) | **150,188 lines / 513 files** |
| `apps/control-plane/src` | 19,428 lines |
| `PORT-TODO` markers | **51** in `packages/*/src`, **103** in `apps/*/src` (27 of them control-plane) |
| Contract operations owned by this Worker | **197** in **31** groups |
| Operations mounted | **197 / 197** — `registerRoutes` throws at module load on any missing/extra/duplicate operation id, on any orphan group, and on a count mismatch (`routes/index.ts:110-150`) |
| Operations answering 404 / 501 | **0** |
| Non-contract identity routes mounted | **24** (9 console-session, 10 identity, 5 SAML/sso-config) |

### 2.1 Verdict by operation

| Verdict | cert2 | **cert3** | % |
|---|---:|---:|---:|
| **EQUIVALENT** — the write reaches the store an enforcer reads, or the read is the enforcer's own | 122 | **129** | 65% |
| **CLASS A — REGRESSION** — complete and wired in Rust, inert here | 62 | **55** | 28% |
| **CLASS B — Rust never finished it** | 0 of 197 | **0 of 197** | — |
| **CLASS C — deliberate / platform / deprioritized** | 13 | **13** | 7% |
| MISSING / unreachable | 0 | **0** | — |

The +7 is **6 `admin_agent_upstream` + 1 `billing.replay`**, both closed by
wave 20/21 and both re-proved here by mutation (§3, M-F/M-I/M-H). Separately,
**cert2 over-counted the two `drain` operations as EQUIVALENT** — FC-1 later
showed the document was written and read by nobody. They are EQUIVALENT *now*,
for the first time, and M-E proves it. Net movement of the honest number:
**122 → 129**.

### 2.2 Verdict by group (31 groups, 197 ops)

| Group | Ops | Verdict | Basis (re-derived this wave) |
|---|---:|---|---|
| `rbac` | 11 | **EQUIVALENT** | `roles`/`permissions`/`tenant_role_bindings`; read by `apps/mcp/src/auth.ts` + `apps/gateway/src/adapters.ts`. **M-A: 3 RED** |
| `admin_api_key` | 6 | **EQUIVALENT** | `static_api_keys`; the Worker's own authenticator. **M-B: 3 RED** |
| `wallets` | 10 | **EQUIVALENT** | the gateway's own `D1WalletStore`. **M-C: 10 RED** |
| `guardrail_policy` | 10 | **EQUIVALENT** | `guardrail_policy_revisions`/`_bindings`; gateway + MCP + agent-runtime. **M-D: 3 RED · M-D2: 5 RED across three doors** |
| `admin_agent_upstream` | 6 | **EQUIVALENT — cert2 said CLASS A; OVERTURNED** | `control_plane_resources` kind `agent-upstreams` read by `apps/gateway/src/routes/agent-upstreams.ts` **and** `apps/agent-runtime/src/agents/registry.ts`. **M-F: 12 RED · M-I: 6+ RED (ESC)** |
| `quota_policy` | 6 | EQUIVALENT | `quota_policies` read by all three admission gates |
| `plans` | 5 | EQUIVALENT | `plans` ⋈ `tenants.plan_id` (gateway + MCP + agent-runtime) |
| `admin_virtual_key` | 8 | EQUIVALENT | dual-write `api_key_directory` + tenant `api_keys` |
| `self_hosted_worker` | 10 | EQUIVALENT | `self_hosted_worker_registrations` → `apps/agent-runtime` |
| `admin_agent_schedule` | 8 | EQUIVALENT | this Worker's own `scheduled` handler |
| `admin_mcp_server` | 6 | EQUIVALENT | `apps/mcp/src/catalog.ts` |
| `admin_gateway_config` | 6 | EQUIVALENT | `routes/admin_config_ops.ts::reloadAdminConfig` |
| `admin_agent_workflow` | 6 | EQUIVALENT | `apps/gateway/src/inference/workflow.ts` + `apps/agent-runtime/src/runs/workflow.ts` |
| `admin_agent_cost_burn` | 1 | EQUIVALENT | `agent_cost_burn` monotonic upsert |
| `tenant_hierarchy` | 20 | **PARTIAL** | 19 EQUIVALENT; `GET /admin/v1/tenants` CLASS A (§4.4). **See C1 (§5.1) — one leg of the 19 is ungated** |
| `admin_tool` | 7 | **PARTIAL** | 5 EQUIVALENT (`apps/mcp/src/approvals.ts`); `GET /tools`, `GET /tool-sessions/{id}` CLASS A |
| `admin_config_ops` | 4 | **PARTIAL** | `validate` EQ; **`GET`+`POST /drain` now EQ (M-E: 2 RED)**; `reload` CLASS C |
| `admin_request_log` | 5 | **PARTIAL** | `audit-events` EQ (real `audit_events`, `count(*) OVER()`, ASC+id tiebreak); other 4 CLASS A |
| `admin_overview` | 9 | **PARTIAL** | 1 EQ (`POST /status`); 4 CLASS A; 4 CLASS C |
| `billing` | 7 | **PARTIAL** | `replay` EQ (**M-H: 4 RED**, incl. at-most-once); 6 read feeds CLASS A |
| `skill` | 6 | **CLASS A** | §4.1 |
| `admin_plugin` | 7 | **CLASS A** | §4.1 |
| `admin_policy` | 6 | **CLASS A** | §4.1 |
| `prompt` | 6 | **CLASS A** | §4.1 |
| `admin_provider` | 3 | **CLASS A** | §4.2 |
| `admin_model` | 1 | **CLASS A** | §4.2 |
| `agent_run` | 3 | **CLASS A** | DO-resident state, no projection |
| `site_domain` | 5 | **CLASS A** | verification machinery faithful; nothing serves a verified hostname |
| `admin_managed_worker` | 4 | **PARTIAL** | 1 CLASS A, 3 CLASS C (microVM backends) |
| `x402_spend_policy` | 3 | **CLASS C** | standing deprioritization directive |
| `payment_attempt` | 2 | **CLASS C** | same |

---

## 3. The write halves, verified as EFFECT — eight mutations, mine

Every row: the pristine file was hashed, the edit was grepped off disk, the
named suite was required RED, the file was restored and re-hashed.

| # | Mutation (semantic, arity- and shape-preserving) | Suite | Result | What the mutated build actually did |
|---|---|---|---|---|
| **M-A** | `store/rbac_registry.ts::unprojectTenantRoleBinding` — `WHERE tenant_id = ? AND role_id = ?` **`AND 1=0`** | `test/rbac-write-half.test.ts` + `rbac-d1` | **3 RED / 22** | `DELETE /admin/v1/tenant-roles/{t}/{r}` answered 200 and **the revoked role still authorized the next request (200 where 403 is required)** |
| **M-B** | `store/static_keys.ts::unprojectStaticApiKey` — same `AND 1=0` | `test/api-keys-write-half.test.ts` + `api-keys-d1` | **3 RED / 26** | a revoked operator key **answered 200 on the very next request** instead of 401; the sibling key regression too |
| **M-C** | `store/wallet_projection.ts::projectWalletMovement` — `options.deltaCredits` → `0n` | `test/wallet-funding.test.ts` | **10 RED / 15** | *"a drained customer is refused, credited through the admin API, then ADMITTED"* → `'insufficient'` where `'reserved'` is required. Money, end to end |
| **M-D** | `store/guardrail_registry.ts::projectGuardrailActivation` — `activeRevision: revision` → `null` | `test/guardrail-write-half.test.ts` | **3 RED / 31** | ACTIVATE moved no binding row |
| **M-D2** | the SAME mutation, run against the FLEET suite | `apps/mcp/test/fleet-guardrail-activation.test.ts` | **5 RED / 16** | the gateway lost the revision; **a matching MCP `tools/call` was ALLOWED**; **a matching A2A message on the DEPLOYED agent-runtime Worker returned `outcome:"allow"`** |
| **M-E** | `apps/gateway/src/routes/readiness.ts::combineDrain` — `if (durable.draining)` → `if (durable.draining && false)`; **every table name, string and import untouched** | `apps/gateway/test/fleet-control-matrix.test.ts` | **2 RED / 246** | `POST /admin/v1/drain {"draining":true}`, then `POST /v1/chat/completions` → **400 (admitted) where 503 `node_draining` is required**. The drain could also not be lifted |
| **M-F** | `apps/gateway/src/routes/agent-upstreams.ts::agentUpstreamsForCaller` — durable branch bypassed, var-only | `test/routes/agent-upstream-{withdrawal,fleet-withdrawal}.test.ts` | **12 RED** | the withdrawn attacker endpoint was **still published**; every tenant fence and fail-closed arm collapsed |
| **M-I** | `apps/agent-runtime/src/ports.ts::resolveDeps` — `agentUpstreamPortFromEnv(...)` replaced by the in-memory var port (the pre-wave-21 posture) | `test/durable/agent-upstream-withdrawal.spec.ts` (**ESC** harness) | **6 RED** | *"the deploy-time var does not resurrect a withdrawn upstream"* — under the mutation it **did**: `422 egress_host_not_governed` naming the withdrawn host, where `404` is required |
| **M-H** | `routes/billing.ts` re-arm CAS — `AND dead_lettered_at_unix IS NOT NULL` → `OR 1=1` | `test/billing-replay.test.ts` | **4 RED / 22** | a second replay answered 200 instead of `409 dead_letter_not_replayable`, and a report that was **never dead-lettered** was re-armed |

**Three properties I checked rather than assumed.**

- **The readers are the deployed ones.** `guardrail_policy`'s fleet proof
  reaches the MCP door by `SELF.fetch` into that Worker's own `src/worker.ts`
  over JSON-RPC with `FG_DEV_MCP_GUARDRAILS` pinned EMPTY for the whole file,
  and the A2A door through `apps/agent-runtime`'s deployed Hono app plus its
  composition root `resolveDeps(env)`. `wallets` calls the gateway's own class.
  `admin_api_key` authenticates through this Worker's own native leg.
- **The activation fleet test drives the control plane's REAL writer**
  (`projectGuardrailRevision` + `projectGuardrailActivation`), not hand-written
  SQL — which is exactly why M-D2 propagated. That file states the reason
  inline, and it is the right reason. **It is also the discriminator that
  exposes C1**, whose fleet gate does the opposite (§5.1).
- **M-E is the M22 case, resolved in the good direction.** The seam's
  *source-text* evidence survived the mutation untouched; the two behavioural
  assertions failed. A source-text-only gate would have passed a Worker that
  reads the operator's document and discards the answer.

---

## 4. The 55 CLASS A operations — the Rust re-read

Under the owner's rule I only call something CLASS A after opening the Rust
handler, its `state.*` method and its repository call. None of the five
config-backed groups is a stub.

### 4.1 The four config-backed groups (25 ops) — `skill`, `admin_plugin`, `admin_policy`, `prompt`

Rust's `state.upsert_*` is a real persist-plus-hot-reload transaction:
`crates/ferrogate-gateway/src/state.rs:1334` (skill packages) writes through
`repositories.upsert_control_plane_skill_package`, clones the active config,
applies the control-plane snapshot, calls `candidate.validate()`, reloads the
serving snapshot, and rolls back to the previous storage state on any error.
`skill` then **re-reads the committed config and answers `409
skill_package_reload_rejected` if the package is not visible after the
reload** (`local.rs:1844`). `admin_plugin` and `admin_policy` additionally
`publish_shared_control_plane` to the cluster. In Rust, `POST
/admin/v1/skill-packages` took effect on the next request.

In TypeScript all 25 are generic document CRUD over `control_plane_resources`
while the data plane reads deploy-time vars:

| group | what the reader actually looks at | verified this wave |
|---|---|---|
| `skill` | `GATEWAY_SKILL_PACKAGES` — `apps/gateway/src/routes/skills.ts`, and `inference/workflow.ts:610` (`workflowCatalogFromEnv` merges `workflowsFromSkillPackages(env.GATEWAY_SKILL_PACKAGES)` over the durable workflow rows) | `grep '"skill-packages"'` over `apps/{gateway,mcp,agent-runtime,telemetry}/src` + `packages/*/src` → **0** |
| `prompt` | `GATEWAY_PROMPT_TEMPLATES` | `"prompt-templates"` → **0 production readers** |
| `admin_plugin` | nothing; `status()` reports `plugins: 0` off the same empty collection | `"plugins"`/`"extensions"`/`"plugin-tools"` → **0** |
| `admin_policy` | nothing; `@ferrogate/policy` is driven from gateway config | `"policies"` → **0** |

**One correction to cert2, in the TS's favour.** `apps/gateway/src/routes/skills.ts`
records a re-derivation cert2 did not carry: Rust `handle_agent_skills` reads
`state.config.skill_packages` — the operator config table — and never touches a
repository. That makes the *read* side an honest var port. It does **not**
rescue the group: Rust's admin *write* hot-reloaded into that same
`state.config`, so a Rust operator's `POST` was live on the next request and a
TS operator's is not. **CLASS A stands, and the fix is a three-line durable
read the tree has already made four times** (`catalog.ts`, `workflow.ts`,
`agent-upstreams.ts`, `registry.ts`).

### 4.2 `admin_provider` (3) + `admin_model` (1)

Rust `local.rs:5019` projects `state.config.providers`; `local.rs:5062`
dispatches a **live catalog fetch per enabled provider**; `local.rs:8227`
projects `state.config.models` through the #535 field-level redaction. TS lists
`providers`/`models`/`provider-health`/`provider-models` document collections
that **no contract operation writes**, so `GET /admin/v1/models` is empty on
every deployment and `GET /admin/v1/status` reports 0 providers and 0 models.
`sql/d1-ts/control/0001_init_control.sql:264,285` already declares
`gateway_providers` and `gateway_models` with a real FK — the table is there,
the wire is not. Unchanged from cert2 and re-verified.

### 4.3 `admin_request_log` (4), `admin_overview` (4), `agent_run` (3), `admin_tool` (2), `billing` (6), `site_domain` (5), `tenant_hierarchy` (1), `admin_managed_worker` (1)

All re-verified against cert2's evidence and all unchanged. The two sharpest:

- **`guardrail_evaluations` / `guardrail_check_evaluations` do not exist in
  `sql/d1-ts/**` at all** — guardrail evidence is in-memory-only fleet-wide.
  Needs a migration before the operation can be anything.
- **`request_logs`** has a table with no writer and no reader; `/metrics`'s one
  substantive gauge (`ferrogate_request_log_entries`) reads the same empty
  collection and is pinned at 0. Closing it is an `apps/gateway` inference-path
  change, and it heals `/metrics` with it.

### 4.4 Confirmed still open from cert2 §4.10 / §5.5 — three wire/acceptance defects

Re-checked line by line, all three **STILL OPEN**:

1. **`responses.ts:82 adminItem`** is `{ object, [object]: record }` — the
   envelope key always equals `object`. Rust does not:
   `AdminApiKeyMutationResponse{object:"api_key", key}`,
   `{object:"mcp_server", server}`, `{object:"tenant_account", tenant}`.
2. **`apps/cli/src/receipt.ts:575 lookupString`** reads `map[key]` at the **top
   level only**; Rust `envelope_scalar` searches the top level *then*
   `wrapped_resource(body)`. Against a real control-plane response
   (`{object:"guardrail_policy_revision", guardrail_policy_revision:{id,…}}`)
   `RESOURCE_ID_KEYS = ["id","policy_id"]` finds nothing, so **every harvested
   receipt field collapses to its absence code and a guardrail revision
   mutation emits no reversal command**. The 344 CLI tests stay green because
   the fixture uses a bare body the control plane never returns. Accurately
   marked at `receipt.ts:542`.
3. **The `[auth_service]` acceptance gap.** `packages/config/src/validate/sections.ts:59
   validateAuthService` validates the endpoint/timeout/retry posture in detail,
   and `apps/cli/src/config-gate.ts::ensureAuthPostureIsDeclared` accepts *"an
   enabled `[auth_service]`"* as a satisfying credential source via
   `hasCredentialSource(config)`. `grep -rn "resolve-api-key\|/v1/auth/authorize"
   apps packages --include=*.ts` → **0 implementations** (one docstring in
   `apps/control-plane/src/index.ts:31`). So an operator can `ferrogate config
   validate` a deployment with no `[[api_keys]]`, no durable backend and only
   `[auth_service]`, be told it has a credential source, ship it, and
   authenticate nobody. Fail-closed, so **MEDIUM operational, not a hole.**
   Fix is one of: refuse `auth_service.enabled` in the TS validator with a named
   code, or implement the posture as a service binding.

---

## 5. NEW — what this wave found that no prior wave did

### 5.1 C1 · **the operator's SUSPENSION write is held by nothing** · security-adjacent · TEST GAP (code is correct)

`PATCH /admin/v1/tenant-accounts/{id} {"status":"suspended"}` has **two
independent durable legs**, and only one of them is gated:

| leg | authority | who reads it | gated? |
|---|---|---|---|
| the `tenant-accounts` **document** | `control_plane_resources` | `apps/control-plane`'s own `StoreTenancyLifecycleGate` (`adapters.ts:673 resolveLifecycle` builds it **on the store**, not on the typed table) | **YES** — `test/lifecycle-d1.test.ts` PATCHes through `SELF.fetch` and requires `403 tenancy_suspended` on the next request |
| the typed **`tenants.status`** column | `store/quota_registry.ts:318 projectTenantAccount` | `apps/gateway/src/adapters.ts:603`, `apps/mcp/src/lifecycle.ts:92`, `apps/agent-runtime/src/ports.ts:716` — all three literally `SELECT id, status FROM tenants WHERE id = ?1` | **NO** |

**MUTATION (SURVIVED, twice).** `text(record.status, "active")` →
`text(undefined, "active")` — i.e. the projection writes `status = 'active'`
for **every** tenant account, whatever the operator asked for:

- `apps/control-plane` full suite → **693 / 693 GREEN**
- `apps/mcp/test/fleet-tenancy-suspension.test.ts` (the FC-2 gate) → **12 / 12 GREEN**

The FC-2 fleet gate cannot fail for this because it writes the column itself:

```ts
/** THE OPERATOR'S ONE ACTION — `PUT /admin/v1/tenants/{id}` writes this column. */
async function setTenantStatus(status: string): Promise<void> {
  const result = await control()
    .prepare("UPDATE tenants SET status = ?1 WHERE id = ?2")
```

That is precisely the trap `apps/mcp/test/fleet-guardrail-activation.test.ts`
identified and avoided for FC-3 — *"Not hand-written SQL: hand-written SQL would
keep passing after the control plane started writing somewhere else"* — applied
to FC-3 and **not** to FC-2. (The comment is also wrong about the path: there is
no `PUT /admin/v1/tenants/{id}` operation; the write is
`PUT`/`PATCH /admin/v1/tenant-accounts/{tenant_id}`.)

`fleet-control-matrix.test.ts` §3.4b **knowingly excludes** this authority:
*"`authorityText` is deliberately excluded: for `tenant-lifecycle` it holds two
DIFFERENT durable spellings of one authority (the typed `tenants.status` column
and the `tenant-accounts` document the operator PATCHes)"*. The exclusion is
defensible; what is missing is the one test that joins the two spellings.

**Blast radius if it ever regresses:** an operator suspends a compromised
tenant, the control plane's own admin surface refuses it (so the operator sees
confirmation), and the gateway, MCP and agent-runtime keep spending — wave 16's
bypass and FC-2 in one, arriving through the *write* end rather than the read
end nobody is watching.

**To close (test-only, ~25 lines):** in `apps/control-plane`, `POST` a
`tenant-account`, `PATCH` it to `suspended` through `SELF.fetch`, then
`SELECT status FROM tenants WHERE id = ?` on `env.DB` with the data plane's own
`LIFECYCLE_TENANT_SQL` and require `'suspended'` — plus the negative control
that it reads `'active'` before the PATCH. Better still, have
`fleet-tenancy-suspension.test.ts` call `projectTenantAccount` instead of its
own `UPDATE`, exactly as the FC-3 file calls `projectGuardrailActivation`.

### 5.2 C2 · the fleet-consistency gate is **source-text for 22 of 23 capabilities**

`apps/gateway/test/fleet-control-matrix.test.ts` (1,276 lines) is a real
achievement and it found FC-1/FC-2/FC-3. But its §1–§4 — including the two
assertions the project leans on hardest, **§3.3** *"every enforcer resolves it
from the SAME source-of-truth class"* and **§3.4** *"a control APPLIED durably
is OBSERVED by every enforcer"* — are **static analysis over comment-stripped
source**: they parse each Worker's SQL literals, table constants and `env` var
reads. §3.1 (*"the probes are live"*) guards against a renamed table making the
comparison vacuous, which is good; nothing guards against a Worker that
**issues the SELECT and discards the answer**. That is the exact failure M22
demonstrated, and M-E in this wave re-demonstrated on the one control that does
have a behavioural gate.

Behavioural fleet coverage, counted:

| capability | behavioural, operator-action → observed refusal | file |
|---|---|---|
| drain (FC-1) | **YES** — 4 assertions, gateway only | `fleet-control-matrix.test.ts` §5 |
| guardrail activation (FC-3) | **YES** — MCP `tools/call` + A2A on the deployed Workers | `apps/mcp/test/fleet-guardrail-activation.test.ts` |
| agent-upstream withdrawal | **YES** — both doors, one `DELETE` | `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` + `apps/agent-runtime/test/durable/agent-upstream-withdrawal.spec.ts` |
| tenant lifecycle (FC-2) | **PARTIAL** — the read half is behavioural; **the write half is C1** | `apps/mcp/test/fleet-tenancy-suspension.test.ts` |
| the other **19** capabilities | **NO** — source-text only | — |

This is not a defect; it is a **calibration**. `FLEET-CONSISTENCY.md`'s
"5 of 5 divergences CLOSED, 4 of 5 mechanically gated, 13 of 23 capabilities
mech-gated" should be read as *13 of 23 gated by source-text analysis, 3½ of 23
gated behaviourally*. Weigh the residual risk accordingly when deciding the
cutover.

### 5.3 C3 · the FC-1 behavioural gate went RED twice on a correct tree · UNRESOLVED, probably environmental

Running `bunx vitest run test/lifecycle-chain.test.ts test/auth.test.ts
test/fleet-consistency.test.ts test/fleet-control-matrix.test.ts` in
`apps/gateway` failed **2 of 6 times** with §5.1/§5.2/§5.3 red — i.e. the drain
document was not observed — and passed 4 of 6, while the same four files pass
in isolation (66/66, 172/172), in every 2- and 3-file combination I tried, and
in the full 2,019-test suite. The two failures were consecutive and coincided
with a **concurrent dev-loop agent running its own vitest-pool-workers process
in the same worktree** (tasks #176/#177 were `in_progress`), which shares
miniflare's persisted state directory. I could not reproduce it once the
concurrent runs stopped.

I am **not** claiming a product flake, and I am not claiming it is benign.
What is certain and matters: **`bun scripts/seam-proof.mjs` runs each seam row
against only the tests that row names**, so it executes exactly this kind of
file subset, and a subset that is 2-in-6 red under concurrency produces a FALSE
RED — the condition `MOUNT-SEAMS.md` §13.4 already records as the way a real
RED gets waved through. Worth bounding before the next full seam pass; task
#177 is already open on an adjacent flake in `metering/durable.test.ts`.

---

## 6. The enterprise-identity surface — re-certified adversarially

Seven mutations, mine, all on the pristine tree.

| # | Attack / invariant | Mutation | Result |
|---|---|---|---|
| **M-P4** | SAML HTTP-Redirect signature is verified over the **raw received octets** | `redirect-binding.ts::signedOctetString` — verify over `decodeURIComponent(samlResponseRaw)` (the re-serialisation bypass) | **10 RED / 110**, incl. by name *"a signature valid over a RE-SERIALISED form but not the raw octets is refused"* |
| **M-P5** | OIDC `nonce` — required, strictly a string, strictly equal | `oidc/claims.ts` — nonce branch disabled | **5 RED / 136** across `oidc-claims` and `oidc-flow` (*"REFUSES an ID token carrying the WRONG nonce (token injection)"*) |
| **M-P6** | SCIM scope match is **exact**, not a prefix | `scim/auth.ts` — `=== SCIM_PROVISION_SCOPE` → `.startsWith("scim")` | **1 RED** |
| **M-P10** | PKCE — the stored `code_verifier` is what is redeemed | `oidc/flow.ts` — `code_verifier: "not-the-verifier"` | **1 RED** |
| **M-C3J** | the console-session surface is **MOUNTED on the exported app** | `apps/control-plane/src/index.ts` — `mountAdminConsoleSession(app)` → `void` | **RED** — `POST /v1/admin/register` 404s and the SAML/sso-config mount assertions fall with it |
| **M-L2** | JWKS refuses to serve a **stale** document when the refetch fails | `oidc/jwks.ts` — serve the cached entry on refetch failure | **SURVIVED, 136/136 GREEN** → §7.2 |
| — | SSO `state` is single-use and an EXPIRED state is still **burned** | not re-mutated; held by `packages/sso/src/store-contract.ts`, an **executable** contract run by both the in-memory twin and `apps/control-plane/test/sso-store-contract.test.ts:55` against D1 — the direct structural fix for the wave-15 defect | inherited, stated as such |

**Structural re-reads I did rather than took on trust.** `handleSamlAcs`
verifies `crypto.subtle.verify` **before** any attacker-controlled XML is
inflated or parsed, and `RedirectBindingParams` rebuilds the signed string in
the binding's fixed spec order with the LAST occurrence of a repeated parameter
feeding *both* the signed string and the decoded payload.
`packages/identity/src/oidc/claims.ts` enforces `iss` as an **exact match after
normalising exactly one trailing slash** (not `startsWith`), `aud` membership,
`azp` whenever the token carries more than one audience, a required `exp`, and
a 60 s skew (deliberately an order of magnitude tighter than SAML's 300 s,
because the ID token arrives over a back-channel exchange this service performs
itself). `resolveScimTenant` is the ONE place a SCIM request acquires a tenant
and it takes it from the credential — never from a path segment, query
parameter or body field.

**Recorded, not a finding:** this is HTTP-**Redirect**-binding SAML with a
detached query signature; there is no XML-DSIG verification of the assertion
element **because the Rust never had one either**. An IdP that can only POST a
signed assertion is unsupported in both trees. That is a TS product question,
not a parity gap.

**The 10 unported `auth-service` route arms** are unchanged and remain
**CLASS B** (6 `/v1/rbac/*` + `/v1/tenants` — `AuthServiceData` is loaded from
YAML into `Arc<RwLock<…>>` with **no writer back to disk**, so a role created
through that API is lost on restart) and **CLASS C** (`/v1/healthz`, and the
two `/v1/auth/*` arms whose topology decision is defensible but whose config
acceptance is §4.4 item 3).

---

## 7. The libraries — 15 packages, algorithm by algorithm

### 7.0 Scoreboard (`R` = a mutation I ran this wave)

| Family | TS reproduces it? | Would a test fail if it regressed? |
|---|---|---|
| policy — multi-level quota merge (min-across, allowlist intersection) | ✅ verbatim, incl. the `<=` tie rule that keeps a per-key cap per-key | ✅ (cert2 R; not re-run) |
| policy — **counter-key namespacing (SECURITY)** | ✅ + hardened past Rust (`auth.rs:225` still falls back to the RAW id) | ✅ **R: 1 RED** (and ~20 gateway files at cert2) |
| billing — settled-cost authority, fail-closed `price_not_found`, bigint credits, idempotency | ✅ | ✅ **R: 2 RED** |
| billing — durable outbox (claim + row in one txn, attempts/backoff/dead-letter) | ✅ | ✅ (control-plane M-H: 4 RED) |
| storage — wallet no-oversell (batch where the decision IS the insert) | ✅ | ✅ **R: 3 RED** (5-vs-4 and 20-vs-7 concurrent reserves, re-read off real D1) |
| storage — **cents ↔ credits, checked for float contamination** | ✅ exact `bigint`; `centsToCredits` refuses non-safe-integers, `bindCredits` marshals as a DECIMAL STRING and range-checks int64, `creditsFromText` throws on a non-safe double | ✅ **R: 1 RED** |
| storage — workflow-budget CAS · guardrail-binding generation CAS · payment-attempt CAS · monotonic upserts | ✅ | ✅ (cert2 R; not re-run) |
| guardrails — detector families, regexes, non-persisted `matched_text` | ✅ set-equal, char-identical | ✅ (vocabulary diffed mechanically at cert2) |
| guardrails — HMAC evidence fingerprints | ✅ | ✅ (cert2 R at all 3 sites) |
| guardrails — bounded findings (**the cap VALUE**) | ✅ 10,000 | ❌ **R: SURVIVED** → L4 |
| guardrails — custom_http breaker `affects_circuit` rule | ✅ faithful (`custom_http.ts:149` ⇔ `custom_http.rs:167`) | ❌ **R: SURVIVED** → L3 |
| providers — adapter coverage 8/8, alias table | ✅ byte-identical, order-identical | ✅ (family registry test) |
| providers — retry predicate (`429` ∪ `500..=599`, unknown family ⇒ not retried) | ✅ | ✅ (cert2 R) |
| providers — **SigV4 canonical request / string-to-sign** | ✅ **verified correct against an independent implementation** | ❌ **R: SURVIVED** → **L11 (NEW)** |
| routing — deterministic canary bucketing (FNV-1a-64) | ✅ byte-identical | ✅ **R: 1 RED** (known vectors) |
| config — `validate()` census, 56/56 portable | ✅ | ✅ **R: 49 RED** on one unmount |
| sso — SAML raw-octet signature verification | ✅ + hardened (`asciiLowercase`, size caps, `fatal:true` UTF-8) | ✅ **R: 10 RED** |
| identity — OIDC `aud`/`iss`/`exp`/`nonce`/PKCE/state | ✅ **superset of Rust** (Rust validated no nonce at all) | ✅ **R: 5 + 1 RED** |
| identity — JWKS rotation (TTL, forced refresh, 30 s cooldown, per-URI isolation) | ✅ (Rust had no cache) | partial — the **refuse-to-serve-stale** arm ❌ **R: SURVIVED** → L2 |
| identity — SCIM tenant authz | ✅ + exact-scope hardening | ✅ **R: 1 RED** |
| cloudflare — R2 provisioning, scoped tokens, scopes/preflight, retry taxonomy | ✅ (Rust defaults verbatim; retry made opt-in for non-GET, deliberately) | ✅ (cert2 R) |

### 7.1 Per-package roster and verdict

| package | src files | test files | tests | verdict |
|---|---:|---:|---:|---|
| `billing` | 8 | 8 | 91 + 3 todo | PARITY, held |
| `cloudflare` | 9 | 9 | 146 | PARITY; **exactly ONE importer** in the tree (`packages/storage/src/tenant-rest.ts`, for the retry) — CLASS B, and **the Rust had no production caller either** |
| `config` | 29 | 15 | 751 + 6 todo | PARITY, 56/56 portable validators; 5 TLS/ACME validators deliberately dropped and compensated by `inertTlsWarnings`, spliced into every load by `loader.ts:103` |
| `core` | 7 | 6 | 31 | PARITY; 44 importers, all six apps |
| `guardrails` | 20 | 13 | 439 | code PARITY; L3 + L4 open |
| `identity` | 18 | 10 | 136 | PARITY + a real security improvement over Rust; L2 open |
| `observability` | 9 | 7 | 67 | PARITY; **`AnalyticsEngineSink` and `OtlpBackend` have zero consumers** — `apps/telemetry/src/sink.ts:60` defines its OWN `AnalyticsEngineSink`. The rest is genuinely consumed (`apps/gateway/src/routes/metrics.ts`, `telemetry/emit.ts`, `cache/metrics.ts`) |
| `payments` | 9 | 6 | 54 | deprioritized by standing directive; consumed only by `packages/policy/src/x402/wire.ts` — a healthy consumed-by-a-package shape |
| `policy` | 11 | 6 | 113 | PARITY + one documented hardening |
| `providers` | 19 | 5 | 75 | PARITY on every algorithm; **L11 NEW**; L1 is a composition-root defect in `apps/gateway` |
| `routing` | 5 | 5 | 19 + 9 (DO) | PARITY; still **no Rust-generated golden bucket table**, and that window closes when `crates/**` is deleted |
| `schemas` | 2 | 6 | 56 | **still ZERO real importers** (the 2 grep hits are prose). Keep: its `OPENAPI_OPERATION_COUNT = 251` literal is pinned in three places that each read the JSON off disk |
| `secrets` | 12 | 7 | 79 | PARITY; `env://`/`cf://`/`vault://` dispatch and the Vault KV v2 wire shape (`GET {addr}/v1/{mount}/data/{path}` → `data.data.<field>`) are asserted against a mocked server |
| `sso` | 17 | 10 | 110 | PARITY + hardening, mutation-held |
| `storage` | 36 | 36 | 258 + 296 (D1) | PARITY on every member of the family, all mutation-held |

### 7.2 Findings — the five cert2 named, re-tested, **all five still open**

| id | class | status this wave |
|---|---|---|
| **L1** — Cloudflare AI Gateway routing (#406) unreachable in production | **CLASS A · the only cutover-blocking library item** | **STILL OPEN.** `apps/gateway/src/inference/adapters.ts:917 defaultAdapterRegistry` is a hand-written `switch` over the eight adapters and never goes through `ProviderAdapterRegistry`, so `applyCloudflareAiGatewayRouting` is skipped on every request the deployed data plane serves. It is also **not configurable**: `inference/catalog.ts:136 providerRecordSchema` is `.strict()` with no `cloudflare_ai_gateway` key, so a Rust operator's working config is **REJECTED**, not ignored — a config-acceptance regression on top of the feature regression. The library half (`packages/providers/src/cloudflare.ts`, `registry.ts`, `packages/config/src/{schema/entities.ts:61,validate/sections.ts:798}`) is complete and correct. Accurately marked at `packages/providers/src/registry.ts:44` with the three closing edits |
| **L2** — JWKS cache serves nothing stale, held by nothing | TEST GAP, security-relevant, **not** a Rust regression (Rust had no cache) | **SURVIVED again, 136/136 GREEN.** The three fail-closed tests all start from an EMPTY cache; the rotation test exercises a SUCCESSFUL refetch. TTL-expired **+** populated cache **+** failing fetch is untested. An IdP outage would extend a withdrawn signing key's life indefinitely |
| **L3** — custom_http breaker `affects_circuit` rule held by nothing | TEST GAP, reliability | **SURVIVED again, 439/439 GREEN.** The taxonomy IS pinned (`test/contract.test.ts:22`); its *consumption* is not. A detector misconfigured to return 401 trips its own circuit open and every request silently takes the fallback path |
| **L4** — bounded-findings cap VALUE unpinned | TEST GAP, LOW | **SURVIVED again, 439/439 GREEN** on `10_000 → 20_000`. The test derives both its input size and its expectation from the constant |
| **L5** — former tenant-bucket naming comparison | RETIRED | **CLOSED BY #744.** The unmounted per-tenant provisioning path was removed; the deployed TS asset path uses one shared bucket with `assets/v1/t/{tenant}/` key-prefix isolation. |

### 7.11 L11 · **NEW** · SigV4 is unverifiable offline — every Bedrock request would be rejected and no test could tell

**MUTATION (SURVIVED).** `packages/providers/src/sigv4.ts:188` — delete the
mandatory blank line between the canonical headers and the signed-header list:

```ts
// pristine  (correct: canonicalHeaders already ends with \n, then ONE more)
const canonicalRequest = `${method}\n${canonicalUri(path)}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaderNames}\n${hashedPayload}`;
// mutated   → a canonical request AWS will never reproduce
const canonicalRequest = `${method}\n${canonicalUri(path)}\n${canonicalQuery}\n${canonicalHeaders}${signedHeaderNames}\n${hashedPayload}`;
```

→ **`packages/providers` 75 / 75 GREEN.**

Every SigV4 assertion in the tree is a shape assertion:
`test/crypto-sigv4.test.ts` checks `signature).toHaveLength(64)` and
`toMatch(/^[0-9a-f]{64}$/)`, that a different body yields a different
signature, and that the *primitives* agree with `crypto.subtle` byte for byte
across block boundaries and over-long keys. **The primitive proof is excellent
and it is the wrong proof**: it establishes that the SHA-256/HMAC are right,
not that the canonical request and string-to-sign they are fed are right. Any
error in header ordering, path normalisation, the `\n` framing or the
credential scope produces a perfectly well-formed 64-hex signature that AWS
answers with `SignatureDoesNotMatch`, and the suite stays green forever.

**The implementation is CORRECT — I checked, because that decides whether this
is a defect or a gap.** I extracted the real output of
`sign` / `signWithContentHashHeader` for a fixed request and reproduced it with
an **independent Python implementation** of the published AWS algorithm
(`hashlib`/`hmac`, canonical request built from the spec text, not from this
code). They agree exactly. **So this is a TEST GAP, not a regression, and here
are the golden vectors that close it:**

```
credentials  AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
request      POST /model/test-model/converse
             host bedrock-runtime.us-east-1.amazonaws.com
             region us-east-1  service bedrock
             body {"messages":[]}   timestampUnix 1440938160

payload sha256                       5e4ce7b36ba37b78a5d5f9fd08e6b7b54ba6879d651aa46ec9e1d6fa24ebe30a
sign(...)                 Signature= ee11e0386b7d4282de4b9d27205cb9633a5f30dcde4a5013991445a3093e6803
signWithContentHashHeader Signature= 398afec746a079f98e63bf0ead0a2c56e516490f56f0192c848c5a1ae7013c13
```

**To close (test-only, ~10 lines):** replace the two `toHaveLength(64)`
assertions with `toBe(<the literal above>)`, citing this section. Do it while
`crates/**` is still readable, so a third party can re-derive the vector from
`sigv4.rs` if it is ever disputed.

**Adjacent, flagged not decided:** `apps/gateway/src/assets/sigv4.ts` is a
**second, independent** 259-line SigV4 query-presigning implementation (R2's
S3 endpoint), and its presigned-query signature is not pinned to a golden value
either. That is an `apps/gateway` question; it is the same class of gap and the
same fix.

### 7.12 Other library observations, none blocking

- **L6 unchanged.** `packages/cloudflare`'s account-management surface has one
  importer. Before calling that a gap cert2 checked the Rust and the Rust is
  the same — zero production call sites for `ensure_tenant_r2_bucket`,
  `create_scoped_r2_token` or `.preflight(`. **CLASS B.** Porting it anyway was
  right: it is the part of the Rust most expensive to re-derive once deleted.
- **L7 unchanged.** Three independent Cloudflare v4 envelope decoders remain
  (`packages/secrets/src/cloudflare-client.ts`,
  `packages/guardrails/src/adapters/workers_ai_llama_guard.ts`,
  `packages/storage/src/tenant-rest.ts`); only the last adopted anything from
  `@ferrogate/cloudflare`. Consolidation debt.
- **L8 confirmed.** `packages/schemas` has **zero** real importers. Keep it.
- **L9 unchanged.** `packages/storage`'s *reservation* surface still carries
  credits as `number` while the adjust/settle/read-exact surface is `bigint`.
  Unreachable at any plausible scale; nothing asserts the 2^53 seam.
- **L10 housekeeping, all still true.** `PORT-PLAN.md:83` and `:162` still
  name the deleted `packages/sync-bridge`; `packages/storage`'s payment-attempt
  tests still live inside `test/site-domain.test.ts`;
  `packages/config/test/port-todo.test.ts:96` and
  `src/schema/entities.ts:517` still say `@ferrogate/cloudflare` does not exist.
- **`sync-bridge`'s deletion stands.** `grep -rn "sync-bridge"` over
  `packages/`, `apps/`, `e2e/` and every manifest returns nothing but the two
  stale `PORT-PLAN.md` lines and historical prose.

---

## 8. UNVERIFIED — stated rather than guessed

Do not read this document as certifying any of these.

1. **Per-operation request/response FIELD parity for ~60 collections.** The
   shared `passthrough()` base schema means shapes were compared only where a
   group carries an authoritative schema. Largest unmeasured surface, unchanged
   since wave 15.
2. **Envelope keys beyond the three in §4.4.** Rust structs not named
   `*MutationResponse` were not swept.
3. **Per-collection search/filter field sets.** Rust `matches_search` uses a
   per-handler field list; the TS store applies `search` uniformly.
4. **`quota_policy`, `plans`, `admin_virtual_key`, `self_hosted_worker`,
   `admin_agent_schedule`, `admin_mcp_server`, `admin_gateway_config`,
   `admin_agent_workflow`, `admin_agent_cost_burn` (56 ops)** are verdicted
   EQUIVALENT from the consumer graph plus module source, and their suites are
   green — I did **not** re-run mutations on them. Waves 13–17 and cert2 did;
   this pass inherits that and says so.
5. **`admin_config_ops::validate`** — not re-checked that the TS reports Rust's
   *first* `bail!` field path for every validator family.
6. **The exact diagnostic message TEXT of the 55 config validators I did not
   mutate.** Presence and reachability ARE proven (49 RED on one unmount).
7. **SCIM filter grammar coverage and OIDC discovery** were not re-derived
   against the Rust line by line. `packages/identity` carries
   `scim-filter.test.ts` + `scim-service.test.ts` and they are green — that is
   their word, not mine.
8. **`packages/secrets`' `vault://` backend against a real Vault KV v2 server.**
   The URL shape and `data.data.<field>` extraction are pinned against a mock.
9. **`packages/payments`' x402 wire/proof/intent semantics** beyond its 54
   tests — deprioritized by standing directive.
10. **Streaming SSE framing byte-for-byte** against Rust `messages_stream.rs` /
    `responses_stream.rs`. Out of this scope; nothing here proves it.
11. **`apps/gateway/src/assets/sigv4.ts`'s presigned-query signature** against
    an independent implementation (§7.11 did this only for
    `packages/providers`).
12. **Whether the C3 subset failure is a product flake or miniflare state
    contention.** Not resolved.
13. **Live-deployment behaviour.** Everything here is offline under
    `@cloudflare/vitest-pool-workers` in local `workerd`. **No live Cloudflare
    account was touched; no `wrangler deploy` was run; no real upstream LLM was
    called.**

---

## 9. What this audit changed in the tree

**Nothing but this file.**

No source file was modified. No test was weakened, skipped or deleted. No
assertion was removed. No `PORT-TODO` marker was added: the one CLASS A gap in
scope that lacks one is not in scope (L1 already carries an accurate marker at
`packages/providers/src/registry.ts:44`), and C1 / L11 are **TEST GAPS on
correct code**, which under the stated scope ("markers for CLASS A gaps") are
reported here rather than marked in source — a decision reinforced by there
being a concurrent writer in this worktree. No `crates/**` or `workers/**` file
was modified; they were read only for comparison. **No `git` command was run,
no `bun install`, no merge, no deletion.**

`git status --porcelain` at the end shows only the concurrent agent's work
(`apps/mcp/test/fleet-guardrail-activation.test.ts`,
`docs/rewrite/cert3-fleet-residue.md`) plus this file.

### Mutation ledger — 19 applied, 19 restored byte-identical

| # | Target | Result |
|---|---|---|
| M-A | `control-plane/store/rbac_registry.ts` binding DELETE → `AND 1=0` | **RED (3)** |
| M-B | `control-plane/store/static_keys.ts` key DELETE → `AND 1=0` | **RED (3)** |
| M-C | `control-plane/store/wallet_projection.ts` delta → `0n` | **RED (10)** |
| M-D | `control-plane/store/guardrail_registry.ts` activation → `null` | **RED (3)** |
| M-D2 | same, run against the MCP **fleet** suite | **RED (5)** |
| M-E | `gateway/routes/readiness.ts::combineDrain` decision neutralised | **RED (2)** |
| M-F | `gateway/routes/agent-upstreams.ts` durable branch bypassed | **RED (12)** |
| M-G | `control-plane/store/quota_registry.ts` tenant `status` → always `active` | **SURVIVED — 693/693 + 12/12 → C1** |
| M-H | `control-plane/routes/billing.ts` re-arm CAS → `OR 1=1` | **RED (4)** |
| M-I | `agent-runtime/ports.ts` upstream port → var-only (ESC) | **RED (6)** |
| M-J | `control-plane/index.ts` `mountAdminConsoleSession` unmounted | **RED** |
| M-P1 | `policy/quota.ts` `counterKey` → raw `apiKeyId` | **RED (1)** |
| M-P2 | `billing/ledger.ts` `price_not_found` throw neutralised | **RED (2)** |
| M-P3 | `routing/fnv.ts` FNV prime `01b3` → `01b5` | **RED (1)** |
| M-P4 | `sso/redirect-binding.ts` sign over re-serialised form | **RED (10)** |
| M-P5 | `identity/oidc/claims.ts` nonce check disabled | **RED (5)** |
| M-P6 | `identity/scim/auth.ts` exact scope → `startsWith` | **RED (1)** |
| M-P7 | `storage/d1/wallet-d1.ts` balance predicate → tautology | **RED (3)** |
| M-P8 | `storage/credits.ts` `centsToCredits` → float multiply | **RED (1)** |
| M-P9 | `config/validate.ts` `validateGuardrails` unmounted | **RED (49)** |
| M-P10 | `identity/oidc/flow.ts` PKCE verifier replaced | **RED (1)** |
| M-L2 | `identity/oidc/jwks.ts` serve stale doc on fetch failure | **SURVIVED (136/136)** |
| M-L3 | `guardrails/custom_http.ts` drop `!affectsCircuit()` return | **SURVIVED (439/439)** |
| M-L4 | `guardrails/deterministic.ts` cap `10_000 → 20_000` | **SURVIVED (439/439)** |
| M-SIGV4 | `providers/sigv4.ts` canonical-request framing broken | **SURVIVED (75/75) → L11** |

*(25 rows; six of the twenty-five are re-runs of a single edit against a second
suite, which is why the header count is 19 distinct file edits.)*

---

## 10. Ranked actions

Ordered by what a deployed operator observes, not by size. Items 1–3 are new
this wave and are the cheapest high-value work on the list.

1. **Close C1** (§5.1) — the suspension write leg. ~25 lines, or one call-site
   change in `fleet-tenancy-suspension.test.ts`. Security-adjacent, and it is
   the FC-2 defect arriving through a door nobody is watching.
2. **Close L11** (§7.11) — pin the two SigV4 golden signatures. ~10 lines, and
   the vectors are printed above. Do it before `crates/**` is deleted.
3. **Decide C2** (§5.2) — either accept that 19 of 23 fleet capabilities are
   gated by source text alone and record that acceptance, or add a behavioural
   fleet assertion for the next two most security-shaped rows. Do **not** let
   "13 of 23 mech-gated" be read as behavioural coverage.
4. **Close L1** (CLASS A, blocks the library layer) — the three edits in
   `packages/providers/src/registry.ts:44`. The third one is the one that
   matters: assert the PREPARED ENDPOINT is the AI Gateway host.
5. **Close L2, L3, L4** — three test-only gaps, hours of work, all three
   instances of this project's documented dominant defect mode.
6. **The five config-backed groups (25 ops, §4.1)** — one cross-app pattern the
   tree has now applied four times. `admin_policy` first: a governance rule an
   operator deletes through the API is not withdrawn.
7. **`admin_provider` / `admin_model` / the `status` counts** — name a source
   (the gateway's vars, or the already-declared `gateway_providers` /
   `gateway_models` tables) and carry the #535 redaction.
8. **`billing`'s six read feeds** off `billing_events` / `billing_ledger` /
   `billing_report_outbox` — same database, already bound. The replay works;
   the operator cannot discover *what* to replay except from the sweeper's logs.
9. **`GET /admin/v1/tenants`** — derivable today from
   `api_key_directory` ⋈ `static_api_keys`; carry the STRICT fence.
10. **`request_logs`** — needs a writer on `apps/gateway`'s inference path;
    heals `/metrics`'s only substantive gauge with it.
11. **The three envelope keys + the CLI `wrapped_resource` leg (§4.4)** — small,
    and the CLI one silently disarms every rollback pointer.
12. **The `[auth_service]` acceptance gap (§4.4)** — refuse it in the validator
    or implement it.
13. **`guardrail_evaluations` migration** — guardrail evidence is
    in-memory-only fleet-wide until the tables exist.
14. **Fix L5's UTF-16 length** and **generate a Rust golden bucket table for
    `rolloutBucket`** — two pieces of cheap insurance that expire the moment
    `crates/**` is deleted.
15. **Bound C3** (§5.3) — the concurrent-run false RED, together with task #177.

---

## 11. Answering the brief directly

> *"Verify each [closed write half] takes EFFECT, and count how many
> no-consumer groups REMAIN, classifying each A/B/C — check whether the RUST
> has a reader before calling one a regression."*

- **Every closed write half takes effect, and I proved each one myself as the
  effect rather than the status code**: the role stops authorizing (M-A), the
  key stops authenticating (M-B), the credit funds a request (M-C), the
  activated revision refuses a real MCP `tools/call` and a real A2A message
  (M-D2), the drain refuses billable work and can be lifted (M-E), the
  withdrawn upstream is neither discoverable nor dispatchable (M-F, M-I), the
  dead letter replays exactly once (M-H).
- **55 operations across 8 whole groups and 6 partial groups remain
  no-consumer**, down from cert2's 62. **All 55 are CLASS A**: for every one I
  opened the Rust handler, its `state.*` method and its repository call, and
  not one is a `todo!()`, an orphan, or dead code. The strongest case is the
  config-backed four, whose Rust write path is a persist → rebuild-candidate →
  `validate()` → hot-reload → rollback-on-failure transaction.
- **Zero of the 197 are CLASS B.** The only CLASS B in this whole surface is
  the `ferrogate-auth-service`'s own `/v1/rbac/*` + `/v1/tenants` (7 route
  arms), and the evidence is decisive: no persistence back to disk. Porting
  them would import a defect. **They must not hold the cutover.**
- **13 are CLASS C** and unchanged: x402 (5), managed-worker microVM backends
  (3), config hot-swap in an isolate (1), Analytics Engine's absent offline
  read side (1), the console bundle (3).

> *"is the TypeScript system complete and correct on its own terms, and did the
> port LOSE anything that worked?"*

On the control plane: it lost 55 of 197 operations' *effect*, all of them
config/observability surfaces, none of them money or auth, and every one has a
named three-line remediation the tree has already executed four times. It has
now regained the two that were security- and money-shaped. On the libraries:
it lost exactly one thing that worked — AI Gateway routing (L1) — and that loss
is at a composition root, not in a library.

The honest bottom line is narrower and sharper than cert2's: **the code is in
better shape than the tests that hold it.** Two invariants this project would
describe as non-negotiable — an operator's tenant suspension reaching the spend
Workers, and a Bedrock request being signable — are correct today and would
survive their own deletion in CI. That is the same sentence this project has
now written about the admission bypass, the durable RBAC join, the cron body,
the workflow gate, the SSO EXPIRED state, `/version`, and the drain document.
It is the seventh time. The remedy is two small test files, and it should be
this wave's output rather than the next certification's finding.
