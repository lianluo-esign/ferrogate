# CERT-2 — the CONTROL PLANE, certified under the NEW rule

**Date:** 2026-08-01 · **wave 19**, the first certification run under the owner's
ruling that *"the Rust system is itself a half-finished product"* and that
TypeScript is the FORWARD platform.
**Scope:** the 197 `/admin/v1/**` + `/metrics` operations owned by
`apps/control-plane` (18,640 LOC `src`, 36 test files, **672 tests**), **plus**
the 24 non-contract enterprise-identity routes mounted in wave 18
(`apps/control-plane/src/session/`, `packages/identity`, `packages/sso`).
**Reference (READ-ONLY):** `crates/ferrogate-gateway/src/{state,state_*,auth}.rs`
and `src/server/{local,virtual_keys,wallets,plans,quota_policies,guardrail_policies,site_domains,sites,agent_schedules,rbac}.rs`;
`crates/ferrogate-auth-service/src/{server,sso,saml,scim,rbac,admin_console}.rs`.

**This is a FRESH pass.** Nothing is inherited from
`cutover-parity-controlplane.md` (wave 15). Every verdict below was re-derived,
and two of wave 15's and one of wave 17's are **overturned** — in both
directions.

---

## 0. The verdict, in one paragraph

The control plane is **not a parity risk any more, and it is not certified
either**. The systemic wave-15 defect — *"87 of 197 operations are RBAC-gated
CRUD with no consumer"* — has been genuinely closed for the four groups that
mattered (`rbac`, `admin_api_key`, `wallets`, `guardrail_policy`, 37 ops), and I
re-proved all four **by mutation, myself**, asserting the EFFECT and not the
status code. The enterprise-identity surface mounted three days ago survives
adversarial attack on all four legs the brief named, also mutation-proved. What
remains is **62 operations (31%) that still write or read a store nothing
consumes**, and under the new rule that number splits sharply:

> **CLASS A — 62 ops.** These are REGRESSIONS. I read the Rust for every one, and
> in every case the Rust handler is fully implemented, non-stub, wired to a live
> reader, and — for the nine write-bearing groups — persists through
> `repositories.upsert_control_plane_*` **and hot-reloads the running config**
> with a validate/commit/rollback ladder. There is no `todo!()`, no orphan, no
> dead code. Copying it is the RIGHT call.
>
> **CLASS B — 7 routes.** The `ferrogate-auth-service` `/v1/rbac/*` + `/v1/tenants`
> surface. `AuthServiceData` is loaded from a YAML file into
> `Arc<RwLock<…>>` and **there is no writer back to disk** (`rbac.rs:255
> upsert_role` mutates the guard and returns; `grep "fn save\|serde_yaml::to_"
> crates/ferrogate-auth-service/src` → nothing). A role created through
> `POST /v1/rbac/roles` is lost on the next restart. Rust never finished it.
> Do NOT port it; design it on TS terms.
>
> **CLASS C — 13 ops.** Deprioritized (x402, 5), a real workerd limit (managed
> workers' microVM backends, 3), a real isolate limit (config hot-swap, 1), a
> real platform limit (Analytics Engine has no offline read side, 1), and a
> recorded product-sequencing decision (the console bundle, 3).

**One wave-17 "CLOSED" claim does not hold.** `CUTOVER-READINESS.md` §0.2 lists
`admin_agent_upstream` among the groups that "now read the durable rows". They do
not: `grep -n "CONTROL_DB\|control_plane_resources"
apps/gateway/src/routes/agent-discovery.ts` → **0 hits**; the file still reads
`GATEWAY_AGENT_UPSTREAMS` only (`agent-discovery.ts:22`). Six operations are
still inert and the group's own marker says so. That is the second time a
fix-wave's summary and its code have disagreed, and it is the reason this pass
re-derived rather than inherited.

---

## 1. Method, so every number here can be re-run

1. **The 197 were re-derived mechanically**, not copied. `docs/openapi/runtime-api-contract.json`
   → longest-prefix match of each operation's path against `route_patterns` →
   filter by `path === "/admin/v1" || startsWith("/admin/v1/") ||
   {"/admin","/admin/","/admin/dashboard","/admin/status","/metrics"}`. Result:
   **197 operations in 31 groups**, matching `contract.ts`'s
   `EXPECTED_CONTROL_PLANE_OPERATION_COUNT` exactly, group for group.
2. **Consumer graph by grep over production code only**, `apps/*/src` +
   `packages/*/src`, test fixtures excluded — a fixture INSERT is what hides this
   defect class.
3. **The Rust was READ, not assumed.** For every CLASS A/B call I opened the
   handler AND its state method AND its repository call. Verdicts without that
   chain are marked UNVERIFIED in §6 rather than guessed.
4. **Nine mutations run by me**, each: `sha256sum` the pristine file → apply a
   `/*MUT-…*/`-marked edit → `grep` the marker **off disk** to prove it landed →
   run the named suite → restore → `sha256sum` verify byte-identical. All nine
   restored clean; `git status --porcelain` was empty before and after (the only
   working-tree changes are the five markers §7 records).
5. **Baseline:** `bun run test` in `apps/control-plane` → **36 files / 672 tests
   passed** before the pass and again after the markers landed;
   `bunx tsc --noEmit` clean.

---

## 2. Quantitative summary

| Check | Result |
|---|---|
| Operations the contract assigns to this Worker | **197** (192 `/admin/v1/**` + `/admin`, `/admin/`, `/admin/dashboard`, `/admin/status`, `/metrics`) |
| Operations MOUNTED on the exported app | **197 / 197** — `MOUNTED_ROUTES` is the value `registerRoutes(app)` returned for the app below `export default` (`src/index.ts:120`) |
| Operations answering 404 / 501 / unimplemented | **0** |
| Contract groups owned | **31** |
| Non-contract identity routes mounted (wave 18) | **24** = 9 console-session + 10 identity (SCIM + OIDC + scim-token) + 5 SAML/sso-config |
| Rust `auth-service` route arms | **34** — so **10 unported**, all CLASS B or CLASS C (§5.5) |
| Tests | **672** (was 487 at wave 15) |

### 2.1 Verdict by operation

| Verdict | Ops | % |
|---|---:|---:|
| **EQUIVALENT** — the write reaches the store the enforcer reads, or the read is the enforcer's own | **122** | 62% |
| **CLASS A — REGRESSION** — complete in Rust, dropped in the port | **62** | 31% |
| **CLASS B — Rust never finished it** | **0** of the 197 (7 of the 34 auth-service routes) | — |
| **CLASS C — deliberate / platform / deprioritized** | **13** | 7% |
| MISSING (route absent or unreachable) | **0** | — |
| IN-MEMORY-ONLY | **0** — `resolveStore` (`src/adapters.ts:559`) *throws* rather than degrading silently | — |

Wave 15 said **87** ops were unread. It is **62**, and the 25-op improvement is
real and mutation-proved. But wave 15 also rated four of the remaining groups
`L` ("the Rust surfaces were also thin config CRUD"). **That rating was wrong**,
and §4.1 shows the Rust that disproves it. The severity of the residue went UP
even as its size went down.

### 2.2 Verdict by group

| Group | Ops | Verdict | One-line basis |
|---|---:|---|---|
| `rbac` | 11 | **EQUIVALENT** | `store/rbac_registry.ts` → `roles` / `permissions` / `tenant_role_bindings`; the same join all four fleet authorizers issue. **Mutation M5: 3 RED** |
| `admin_api_key` | 6 | **EQUIVALENT** | `store/static_keys.ts` → `static_api_keys`. **Mutation M7: 3 RED**, incl. a revoked key answering 200 |
| `wallets` | 10 | **EQUIVALENT** | `store/wallet_projection.ts` → the gateway's own `D1WalletStore.settleWalletBalance`. **Mutation M6: 10 RED** |
| `guardrail_policy` | 10 | **EQUIVALENT** | `store/guardrail_registry.ts` → `guardrail_policy_revisions` / `_bindings`, SQL a verbatim twin of `apps/gateway/src/guardrails/d1.ts` (diffed, §3.4). **Mutation M8: 3 RED** |
| `quota_policy` | 6 | EQUIVALENT | `projectQuotaPolicy` → `quota_policies`, read by `apps/gateway/src/ratelimit/quota.ts`, `apps/mcp/src/admission/quota.ts`, `apps/agent-runtime/src/admission/quota.ts` |
| `plans` | 5 | EQUIVALENT | `projectPlan` → `plans`, read via `JOIN plans p ON t.plan_id = p.id` |
| `admin_virtual_key` | 8 | EQUIVALENT | dual-writes `api_key_directory` (control) + `api_keys` (tenant), direction-aware ordering |
| `self_hosted_worker` | 10 | EQUIVALENT | `projectWorkerRegistration` → `self_hosted_worker_registrations`, read by `apps/agent-runtime/src/durable/adapters.ts` |
| `admin_agent_schedule` | 8 | EQUIVALENT | consumer is this Worker's own `scheduled` handler |
| `admin_mcp_server` | 6 | EQUIVALENT | `apps/mcp/src/catalog.ts:65` reads the same `mcp-servers` documents |
| `admin_gateway_config` | 6 | EQUIVALENT | consumer is `routes/admin_config_ops.ts::reloadAdminConfig` |
| `admin_agent_workflow` | 6 | EQUIVALENT | `apps/gateway/src/inference/workflow.ts:354` reads kind `agent-workflows` |
| `admin_agent_cost_burn` | 1 | EQUIVALENT | `packages/storage/src/d1/monotonic.ts` `agent_cost_burn` |
| `tenant_hierarchy` | 20 | **PARTIAL** | 19 EQUIVALENT; `GET /admin/v1/tenants` **CLASS A** (§4.4) |
| `admin_tool` | 7 | **PARTIAL** | 5 EQUIVALENT (`apps/mcp/src/approvals.ts:78`); `GET /tools`, `GET /tool-sessions/{id}` **CLASS A** (§4.3) |
| `admin_config_ops` | 4 | **PARTIAL** | 3 EQUIVALENT; `reload` **CLASS C** (a Worker isolate cannot hot-swap; `applied:false` is the honest answer) |
| `admin_request_log` | 5 | **PARTIAL** | `audit-events` EQUIVALENT (real `audit_events` query, `count(*) OVER()`, ASC+id tiebreak); other 4 **CLASS A** (§4.5) |
| `admin_overview` | 9 | **PARTIAL** | 1 EQUIVALENT (`POST /status` = worker registration); 4 **CLASS A** (§4.6); 4 **CLASS C** |
| `skill` | 6 | **CLASS A** | §4.1 |
| `admin_plugin` | 7 | **CLASS A** | §4.1 |
| `admin_policy` | 6 | **CLASS A** | §4.1 |
| `prompt` | 6 | **CLASS A** | §4.1 |
| `admin_agent_upstream` | 6 | **CLASS A** | §4.1 — and wave 17 recorded it CLOSED |
| `admin_provider` | 3 | **CLASS A** | §4.2 |
| `admin_model` | 1 | **CLASS A** | §4.2 |
| `agent_run` | 3 | **CLASS A** | §4.7 |
| `billing` | 7 | **CLASS A** | §4.8, incl. the `replay` 404 |
| `site_domain` | 5 | **CLASS A** | §4.9 |
| `admin_managed_worker` | 4 | **PARTIAL** | 1 CLASS A (the fixed descriptor), 3 CLASS C |
| `x402_spend_policy` | 3 | **CLASS C** | standing deprioritization directive |
| `payment_attempt` | 2 | **CLASS C** | same |

---

## 3. The four write halves — verified as EFFECT, by my own mutations

The brief asked for the effect, not the status code. Every one of the four suites
below provisions **only through the admin API** and asserts on a *second,
independent* observation. I neutralised each projection in place and required the
named test RED.

| # | Mutation (file, `/*MUT-…*/`-marked, grepped off disk) | Result | What the mutated build actually did |
|---|---|---|---|
| **M5** | `store/rbac_registry.ts::unprojectTenantRoleBinding` — the `DELETE` guarded to `if (false as boolean)` | **3 RED** in `test/rbac-write-half.test.ts` | `DELETE /admin/v1/tenant-roles/{t}/{r}` answered 200 and the binding row survived — the exact wave-15 finding, reproduced on demand |
| **M6** | `store/wallet_projection.ts::projectWalletMovement` — `deltaCredits` forced to `0n` | **10 RED** in `test/wallet-funding.test.ts` | balance stayed `0n` where the suite requires `5_000_000n`; the drained customer stayed refused after a successful `200` credit |
| **M7** | `store/static_keys.ts::unprojectStaticApiKey` — the `DELETE` guarded off | **3 RED** in `test/api-keys-write-half.test.ts` | a revoked operator key answered **200** on the very next request instead of 401 |
| **M8** | `store/guardrail_registry.ts::projectGuardrailActivation` — returns the current generation without committing | **3 RED** in `test/guardrail-write-half.test.ts` | `active_revision` came back `undefined`; ACTIVATE moved nothing the data plane enforces from |
| **M9** | `store/d1.ts::tenantWriteScopeSql` — reverted to the READ predicate (`IS NULL OR = ?`) | **4 RED** in `test/tenant-write-fence.test.ts` | a tenant-scoped `admin.write` caller **mutated an un-attributed PLATFORM row** (200 where the fence requires a 404 indistinguishable from absent) |

Three further properties I checked rather than took on trust:

- **The reader is the real one, not a twin.** `rbac`'s guarded probe runs
  `apps/control-plane/src/adapters.ts:326`, whose SQL is semantically identical
  to `apps/gateway/src/adapters.ts:827` (`RBAC_TENANT_ROLE_GRANTS_SQL`) and
  `apps/mcp/src/auth.ts:107`. `wallets` calls **the gateway's own class**
  (`D1WalletStore.settleWalletBalance` / `reserveWalletCredits`). `admin_api_key`
  authenticates through the deployed Worker's own native leg.
- **No green twin.** `MemoryWalletStore` exists in `@ferrogate/storage` but no app
  constructs it — all four Workers build `D1WalletStore`, so there is no
  in-memory implementation that could stay green while the durable one broke.
- **The guardrail SQL twins do not drift.** I extracted every
  `GUARDRAIL_*_SQL` from both `apps/gateway/src/guardrails/d1.ts` and
  `apps/control-plane/src/store/guardrail_registry.ts` and compared the resolved
  statements: **all four shared constants are byte-identical** once the
  `${TABLE}` template placeholders resolve. The gateway additionally exports
  three list statements the control plane does not need.

**Residual weakness, stated:** `wallets` is proved *end to end through the
gateway's own decision function*; `guardrail_policy` is proved *structurally* —
`test/guardrail-write-half.test.ts` reads the rows back with the gateway's
`SELECT`s and re-runs `validatePolicyRevision` (the first statement of the
gateway's `putRevision`), and `apps/gateway/test/guardrails/control-plane-projection.test.ts`
proves rows of that shape compile and block a request, but no single test drives
`POST /admin/v1/guardrail-policies` → a refused inference call. That is a
one-fixture gap, not a defect, and it is the strongest remaining asymmetry among
the four.

---

## 4. CLASS A — the 62, with the Rust evidence that makes each a regression

The wave-15 pass rated `skill` / `admin_plugin` / `admin_policy` /
`admin_agent_workflow` **`L` — "the corresponding Rust surfaces were also
config-document CRUD with a thin runtime"**. I read them. That is false for all
four, and this section is the evidence.

### 4.1 The five config-backed groups (31 ops) — `skill`, `admin_plugin`, `admin_policy`, `prompt`, `admin_agent_upstream`

**What the Rust does.** Each of these has a `state.upsert_*` that is a real
persist-plus-hot-reload transaction, not a stub:

```rust
// crates/ferrogate-gateway/src/state.rs:1334  (skill packages; the others are identical in shape)
pub(crate) fn upsert_skill_package(&self, package: SkillPackage) -> anyhow::Result<RuntimeReloadResult> {
    let active = self.current();
    let result = (|| {
        active.repositories.upsert_control_plane_skill_package(package.id.clone(), serde_json::to_string(&package)?)?;
        let mut candidate = (*active.config).clone();
        active.apply_control_plane_snapshot_to_config(&mut candidate)?;
        candidate.validate()?;
        Ok(self.reload_process_local(candidate))
    })();
    if result.is_err() { let _ = active.sync_control_plane_storage_from_config(&active.config); }
    result
}
```

| group | Rust READ | Rust WRITE | persisted by |
|---|---|---|---|
| `skill` | `local.rs:1696` — `state.config.skill_packages` through `scope.visible_skill_package` (#535 re-sweep: `api_key_ids` is a cross-tenant selector) | `local.rs:1844` → `state.rs:1334`; **re-reads the committed config and answers `409 skill_package_reload_rejected` if the package is not visible after reload** | `upsert_control_plane_skill_package` (`ferrogate-storage/src/lib.rs:14160`) |
| `admin_plugin` | `local.rs:7470` — `state.extension_statuses()` / `state.plugin_tools(id)` (`state_tools.rs:13,17,24`, the live registry) | `state.rs:674`, + `publish_shared_control_plane` for the cluster | `…_plugin_registration` (14188) |
| `admin_policy` | `local.rs:8865` — `state.config.policies` through `scope.visible_policy`; **absent and out-of-scope are the same answer**, so the names are not recoverable one probe at a time | `state.rs:1223`, + `publish_shared_control_plane` | `…_policy` (14108) |
| `prompt` | `local.rs:2182` — `state.config.prompt_templates` | `local.rs:2278` → `state.rs:1404` | `…_prompt_template` (14176) |
| `admin_agent_upstream` | `local.rs` agent-upstream family + `agent_upstream_visible_to_auth` | `state.rs:774`, with `upsert_or_replace_agent_upstream` merged into the candidate | `…_agent_upstream` (14222) |

None is `todo!()`. None is orphaned. All five are reachable from a mounted route,
committed to storage, validated as a whole-config candidate, hot-reloaded into
the serving snapshot, and rolled back on failure. **In Rust, `POST
/admin/v1/skill-packages` took effect on the next request.**

**What TypeScript does.** All 31 operations are generic document CRUD over
`control_plane_resources`, and the data plane reads deploy-time Worker vars:

| group | the reader actually looks at |
|---|---|
| `skill` | `GATEWAY_SKILL_PACKAGES` — `apps/gateway/src/routes/skills.ts`, and `inference/workflow.ts:611` (a package OWNS workflows, so this gates what the graph gate will execute) |
| `prompt` | `GATEWAY_PROMPT_TEMPLATES` — `apps/gateway/src/routes/prompts.ts:331` |
| `admin_agent_upstream` | `GATEWAY_AGENT_UPSTREAMS` — `apps/gateway/src/routes/agent-discovery.ts:22`. **`grep -n "CONTROL_DB\|control_plane_resources" apps/gateway/src/routes/agent-discovery.ts` → 0** |
| `admin_plugin` | nothing. `status()` reports `plugins: 0` off the same empty collection |
| `admin_policy` | nothing. `@ferrogate/policy` is driven from gateway config, never these rows |

**Blast radius.** The operator is told `201`/`200` and nothing takes effect until
someone edits `wrangler.toml` and redeploys. For `agent-upstreams` that includes
`DELETE`: **removing a compromised upstream through the admin API does not
withdraw it.** For `admin_policy` the same applies to a governance rule.

**The fix is not an open design question.** It has been decided twice, the same
way: `apps/mcp/src/catalog.ts` and `apps/gateway/src/inference/workflow.ts:565`
both read `control_plane_resources` directly with the var as fallback. Each of
the five is the same three-line change in the consuming Worker.

### 4.2 `admin_provider` (3) + `admin_model` (1) — CLASS A

`local.rs:5019 handle_admin_providers` projects `state.config.providers` into
`AdminProvider{name,kind,compatibility,base_url,has_api_key,enabled}` with
`matches_search` over `&[&provider.name, &provider.kind]`.
`local.rs:5062 handle_admin_provider_models` goes further and **dispatches a live
catalog fetch per enabled provider**, with a `status:"disabled"` arm for the
disabled ones. `local.rs:8227 handle_admin_models` projects `state.config.models`
through `config_catalog_scope(...).visible_model(...)` — the #535 field-level
redaction of `visible_organization_ids` / `visible_project_ids`.

TypeScript lists `providers` / `models` document collections that **no contract
operation writes** — there is no `upsert_control_plane_provider` in the Rust
either, because in Rust these were config projections. So `GET
/admin/v1/models` and `GET /admin/v1/providers` are empty on every deployment,
and `GET /admin/v1/status` tells an operator the gateway has **0 providers and 0
models**.

Note the control schema already declares `gateway_providers` and `gateway_models`
(`sql/d1-ts/control/0001_init_control.sql:264,285`, with a real FK between them)
and **neither has a writer or a reader in `apps/*/src`** — the table is there,
the wire is not. Closing this needs one source decision (the gateway's
`GATEWAY_PROVIDERS`/`GATEWAY_MODELS` vars, or those two tables), and must carry
the #535 redaction, which the store's `passthrough()` does not perform.

### 4.3 `admin_tool` — 5 EQUIVALENT, 2 CLASS A

The approvals half is genuinely wired: `apps/mcp/src/approvals.ts:78` reads the
same `tool-approvals` documents the three decisions write. `GET /admin/v1/tools`
is not: Rust answers from `state.all_tools()` (`state_tools.rs:71`, the live tool
registry), TS lists an unwritten collection. `GET /tool-sessions/{id}` needs an
`apps/mcp` writer first — MCP session state lives in a Durable Object, which is
addressable but not queryable across instances, exactly like `agent_run` (§4.7).

### 4.4 `tenant_hierarchy` — 19 EQUIVALENT, `GET /admin/v1/tenants` CLASS A

Rust `local.rs:9288` answers a DERIVED view: `state.tenant_refs()`
(`state_tools.rs:28`) projects every configured api key carrying an
`organization_id`/`team_id`/`project_id`/`user_id` into an `AdminTenantRef`,
then `filter_by_tenant_scope` fences it with **strict** equality. It is the
"which tenancies exist, and through which credential" answer an operator uses to
find an unattributed key. TS pages a `tenants` DOCUMENT collection that no
operation writes (tenant *accounts* are the separate `tenant-accounts`
collection, and the typed `tenants` TABLE is written by `projectTenantAccount`,
not by the document store). Empty on every deployment. Closable here with no new
binding, from `api_key_directory` ⋈ `static_api_keys`.

### 4.5 `admin_request_log` — 1 EQUIVALENT, 4 CLASS A

`audit-events` is closed and correct (real `audit_events` query, `count(*)
OVER()` so `total` cannot disagree with the page under a concurrent write,
`ORDER BY occurred_at_unix ASC, id ASC`, and `AdminList::paginated`
*unconditionally* — Rust does not fork on "was there a query string" for this
one). The other four:

- `request-logs` / `request-log-exports`: Rust `local.rs:4330` pages
  `state.request_logs_page(...)` with a real #185 tenant filter, and `:4358`
  renders a JSONL export. The TS control schema has a `request_logs` table with
  **no writer and no reader**; the gateway meters to `billing_events`/`billing_ledger`
  and never persists a request log. **This cannot be closed from this app** — the
  writer is on `apps/gateway`'s inference path. `StoreRuntimeStatus.metrics()`
  publishes `ferrogate_request_log_entries` off the same empty collection, so the
  Prometheus gauge is pinned at 0 and heals with it.
- `guardrail-evaluations` / `investigations`: one step worse —
  `guardrail_evaluations` / `guardrail_check_evaluations` **do not exist in
  `sql/d1-ts/` at all**, so guardrail evidence is in-memory-only fleet-wide.
  Needs a migration first.

### 4.6 `admin_overview` — 1 EQUIVALENT, 4 CLASS A, 4 CLASS C

CLASS A: `GET /admin/v1/status`, `GET /admin/status`, `GET /admin/v1/overview`
count `providers`/`models`/`api-keys`/`prompt-templates`/`plugins`/`tools` from
document collections with no writer — **every count is 0 on a working
deployment** — where Rust `local.rs:385` reports live config lengths plus
`enabled_*` splits, `storage`, `analytics`, `cluster`, `observability` and `acme`
sub-documents. `GET /metrics` is the fourth: correctly bearer-guarded, correct
`text/plain; version=0.0.4` exposition, but its one substantive gauge reads the
empty `request-logs` collection.

CLASS C: the three anonymous dashboard routes (the console bundle is a recorded
sequencing decision; the shell deliberately ships **no script tag**, so an
operator sees "not built yet" rather than a blank page), and
`GET /admin/v1/observability`, which returns `[]` because Analytics Engine's read
side is an authenticated account-scoped REST call with no offline emulation —
fabricating series would be worse.

### 4.7 `agent_run` (3) — CLASS A

Rust `local.rs:4395 handle_admin_agent_runs` pages `state.agent_runs_page(...)`
(`state_agent_runtime.rs:329`). TS pages `agent-runs` / `agent-run-events` /
`self-hosted-runs` documents that nothing writes; the runs are real but live in
`apps/agent-runtime`'s `AgentRunState` Durable Object keyed `${tenant}:${run}`.
The control schema declares `agent_runs` and `agent_run_events` and neither has a
writer. A DO is addressable but not queryable across instances, so closing this
is a projection `apps/agent-runtime` must write.

### 4.8 `billing` (7) — CLASS A, and one operation is worse than inert

Rust `local.rs:9317` pages `state.metering_events_page(...)`
(`state_billing_metering.rs:351`, with the #185 tenant filter). All six TS read
feeds page document collections that the metering path never writes; the data
plane writes `billing_events` / `billing_ledger` / `billing_report_outbox` **in
the same control database this Worker already binds**.

The sharp edge is `POST /admin/v1/billing-outbox-dead-letters/{id}/replay`: it
requires a `billing-outbox-dead-letters` DOCUMENT before it will re-arm, and the
sweeper dead-letters the **row**. So a real dead letter answers **404 and can
never be replayed**, while the `rearmOutboxRow` half — which is genuinely sharp
(a `sqlite_master` structural probe distinguishes "not provisioned" from
"unreadable", `AND dead_lettered_at_unix IS NOT NULL` is a true CAS, `RETURNING`
makes the answer real) — is reachable only from a hand-seeded document.

### 4.9 `site_domain` (5) — CLASS A

The #488/#576 challenge machinery is a faithful port and is well tested (rate
limit reserved BEFORE the resolver is touched, challenge minted not assumed,
`unavailable` never folded into `verified`, default resolver unbound so an
unconfigured deployment cannot verify, and `test/site-domain-cas.test.ts` races
two callers). But **nothing serves a verified hostname**: `grep -rn
"site_domains" apps/*/src packages/*/src` returns only `apps/control-plane`,
where Rust `server/sites.rs` (1,226 lines) + `site_domains.rs` (1,370) route an
inbound request by verified custom hostname to the tenant's published static
site. Separately, `packages/storage/src/d1/site-domain-d1.ts::D1SiteDomainVerificationStore`
— the only writer of `site_domain_verifications` — is imported by no application
module, so the durable store is dead code and this group keeps verification state
as documents.

Two separable slices: mounting the durable store is local to this app; hostname
routing is an `apps/gateway` change (and is the one place a CLASS C argument has
force — Cloudflare Custom Hostnames may own part of it).

### 4.10 Two wire-shape regressions that survive from wave 15

- **Three mutation-receipt envelope keys.** `responses.ts::adminItem` assumes
  "envelope key equals `object`". Rust does not:
  `AdminApiKeyMutationResponse{object:"api_key", key}` (`responses.rs:1096`),
  `AdminMcpServerMutationResponse{object:"mcp_server", server}` (`:1900`),
  `{object:"tenant_account", tenant}` (`virtual_keys.rs`). Confirmed still open.
- **`apps/cli/src/receipt.ts::lookupString` searches only the top level**, where
  Rust `envelope_scalar` searches the top level *then* `wrapped_resource(body)`.
  Confirmed still open (`receipt.ts:575`). Against a real control-plane response
  every harvested receipt field collapses to its absence code and a guardrail
  revision mutation emits **no reversal command**. The CLI's 339 tests stay green
  because the fixture uses a bare body the control plane never returns.

---

## 5. The enterprise-identity surface, certified adversarially

Mounted three days ago; 24 routes; security-critical. I ran the four attacks the
brief named **through the deployed Worker** (`SELF.fetch`, real D1), and then
mutated the defence to prove each assertion is load-bearing.

| # | Attack | Result on the pristine tree | Mutation | Result |
|---|---|---|---|---|
| **M1** | OIDC ID token minted for **another audience** | `401`, `"ID token validation failed"`, no `access_token` | `packages/identity/src/oidc/claims.ts:89` — the `aud_mismatch` refusal guarded off | **1 RED**, and the mutated build answered **`200` with a session** — a full cross-client token-replay admission |
| **M2** | **Tampered** SAML assertion, and an assertion signed by **another key** | `401 saml_signature_verification_failed` on both | `packages/sso/src/flow.ts:152` — `verifyRedirectSignature` guarded off | **2 RED**, mutated build answered **`200`** — a full SAML auth bypass |
| **M3** | **Expired** SSO `state` presented, then re-presented under an earlier clock | second presentation is `null` — the row was BURNED | `apps/control-plane/src/identity/adapters.ts:429` — `DELETE … RETURNING *` → `SELECT … ` | **5 RED** across `test/sso-store-contract.test.ts` (the package's own exported contract, run against the D1 twin) and `test/identity-mount.test.ts` |
| **M4** | Tenant A's SCIM token reads, then **deprovisions**, tenant B's user by id | `404` on both, indistinguishable from a nonexistent id; B's membership intact | `packages/identity/src/scim/service.ts::membershipRoleInTenant` — falls back to a global user lookup | **2 RED**, mutated build answered **`204` and deleted another tenant's user** |

### 5.1 Why the SAML port is sound, at the level below the test

`handleSamlAcs` (`packages/sso/src/flow.ts:110`) is a line-for-line port of
`crates/ferrogate-auth-service/src/sso.rs:899 handle_saml_acs`, in the same
order: parse redirect-binding params → require `RelayState` → **`flows.take(state,
now)` (single-use; this is the only replay defence, and the code says so)** →
require a SAML flow and a SAML config → require the IdP certificate → **verify
the signature over the exact received octets BEFORE any attacker-controlled XML
is inflated or parsed** → then validate the assertion. There is no branch that
reaches an authenticated state without `crypto.subtle.verify` having returned
`true`.

`RedirectBindingParams` preserves the raw percent-encoded octets and rebuilds the
signed string in the binding's fixed spec order (`SAMLResponse`, `RelayState`,
`SigAlg`) — never via `URLSearchParams`, whose re-serialisation is a textbook
signature bypass. A repeated parameter takes the **last** occurrence for *both*
the signed string and the decoded payload, so an attacker cannot append a second
`SAMLResponse` and have the signature checked against one while the assertion is
parsed from the other. The assertion validator then rejects on non-`Success`
status, `InResponseTo` mismatch, issuer mismatch, audience mismatch, `NotBefore`,
`NotOnOrAfter`, and "no usable email" — every one a hard rejection, and
`asciiLowercase` is ASCII-only on purpose so Turkish `İ` / Kelvin `K` cannot
collapse two IdP users onto one account here but not in Rust.

**Recorded, not a finding:** this is HTTP-**Redirect**-binding SAML with a
detached query signature, matching the Rust exactly. There is no XML-DSIG
verification of the assertion element, because the Rust never had one either.
An IdP that can only POST a signed assertion (HTTP-POST binding) is unsupported
in both trees. That is a **product** question for TS, not a parity gap.

### 5.2 SCIM

`resolveScimTenant` (`packages/identity/src/scim/auth.ts`) is the ONE place a
SCIM request acquires a tenant, and it takes it from the credential — never from
a path segment, a query parameter or a body field. The scope check is **exact
string equality** on `scim.provision` (not `startsWith`, not case-insensitive),
deliberately distinct from `admin.write` so the far more numerous `admin.write`
holders are not silently also directory administrators. Lifecycle is re-checked
per request through `requireUsableTenancy`. Mounted behaviour confirmed:
anonymous → `401` (not `404`), valid key without the scope → `403` (not `200`).

### 5.3 OIDC

`packages/identity/src/oidc/claims.ts` enforces `iss` (trailing-slash-normalised),
`aud` **membership**, and — the subtle one — **`azp` MUST be present and MUST be
this client whenever the token carries more than one audience**, which is what
stops a co-audience application's token being replayed here. `exp` is required,
not optional. M1 proves the `aud` leg is what refuses.

### 5.4 The console session

`test/console-session.test.ts` is a FACTORY test (wave 18 measured it green with
the surface unmounted); the MOUNT is held separately by
`test/identity-mount.test.ts` §1, whose forged-JWT case runs through `SELF`.
Between them the surface pins: no plaintext password stored, identical `401` for
wrong password and unknown email, `alg:none` and algorithm-confusion refused,
tampered payload with a kept signature refused, refresh tokens stored hashed and
single-use with rotation, `#514` suspended-tenancy `403` mid-TTL, `#517`
tier-scoped gateway key minted and revoked on demotion/removal, no cookies (it is
a bearer API), and `503 admin_console_unconfigured` when no signing secret is
bound.

### 5.5 The 10 unported `auth-service` routes — CLASS B and CLASS C, **not** blockers

`crates/ferrogate-auth-service/src/server.rs` serves 34 route arms; 24 are
mounted. The 10 that are not:

| routes | class | evidence |
|---|---|---|
| `GET /v1/rbac/roles`, `POST /v1/rbac/roles`, `DELETE /v1/rbac/roles/{id}`, and the three `/v1/rbac/bindings` twins (6) | **CLASS B** | They mutate `AuthServiceData`, loaded from YAML into `Arc<RwLock<…>>` at boot. `rbac.rs:255 upsert_role` mutates the write guard and returns; there is **no writer back to disk** anywhere in the crate (`grep "fn save\|fs::write\|serde_yaml::to_"` → nothing but tests). **A role created through this API is lost on restart.** Rust never finished it. It is also a *second*, parallel RBAC model — the enforcing one is `tenant_role_bindings ⋈ roles`, which `/admin/v1/roles` already owns and which §3/M5 proves works |
| `GET /v1/tenants` (1) | **CLASS B** | A read of the same non-persistent in-memory `AuthServiceData` |
| `GET /v1/healthz` (1) | **CLASS C** | `/healthz` is mounted on all five Workers; this is the auth-service's own alias for a service that no longer exists as a separate process |
| `POST /v1/auth/resolve-api-key`, `POST /v1/auth/authorize` (2) | **CLASS C at the topology level, with one CLASS A residue** — see below | |

**The residue is real and is a new finding.** The Rust gateway has a genuinely
wired external-auth posture: `auth.rs:643 authenticate_external` POSTs to
`/v1/auth/resolve-api-key` and `auth.rs:614` POSTs to `/v1/auth/authorize` when
`[auth_service] enabled = true`. On Workers that becomes a service binding or a
direct D1 read, and the port chose the latter — a defensible CLASS C decision.
**But the TypeScript still ACCEPTS the config that selects it:**

- `packages/config/src/schema/config.ts:63` parses `auth_service`, and
  `validate/sections.ts:59-94` validates its endpoint, timeout, retries and TLS
  posture in detail;
- `apps/cli/src/config-gate.ts:71` counts `[auth_service] enabled = true` as a
  **satisfying credential source**, so a config with no `[[api_keys]]`, no
  durable backend and only `[auth_service]` **passes `ferrogate config
  validate`** — and the same loader backs `POST /admin/v1/config/validate`;
- `grep -rn "resolve-api-key\|/v1/auth/authorize" apps packages --include=*.ts`
  → **0 implementations**.

So an operator can validate, be told the deployment has a credential source, ship
it, and authenticate nobody. Same shape as finding D2 (config parsed, nothing
reads it). **Severity: MEDIUM, operational, not a security hole** — the failure is
fail-closed. Fix is one of: refuse `auth_service.enabled` in the TS validator
with a named code, or implement the posture as a service binding. **Marked in §7.**

---

## 6. UNVERIFIED — stated rather than guessed

The brief asked for two operations per group at full depth. I did not reach that
bar uniformly and will not claim it. What was NOT verified to the depth of §3–§5:

1. **Per-operation request/response FIELD parity for ~60 collections.** The
   shared `passthrough()` base schema means field shapes were compared only where
   a group carries an authoritative schema (`guardrail_policy` →
   `@ferrogate/guardrails`, `admin_config_ops` → `@ferrogate/config`,
   `tenant_hierarchy` → `@ferrogate/storage`, `admin_agent_upstream` →
   `@ferrogate/config`'s enums). Unchanged from wave 15 and still the largest
   unmeasured surface.
2. **Envelope keys beyond the three in §4.10.** Rust structs not named
   `*MutationResponse` were not swept.
3. **Search / filter field sets per collection.** `parseListQuery` matches
   `AdminPagination` exactly, but Rust's `matches_search` uses a per-handler field
   list (`&[&provider.name, &provider.kind]`) while the TS store applies `search`
   uniformly. Not checked collection by collection.
4. **`quota_policy`, `plans`, `admin_virtual_key`, `self_hosted_worker`,
   `admin_agent_schedule`, `admin_mcp_server`, `admin_gateway_config`,
   `admin_agent_workflow`, `admin_agent_cost_burn` (56 ops)** were verdicted
   EQUIVALENT from the **consumer graph plus module source**, and their suites are
   green — but I did **not** re-run mutations on them this pass. Waves 13–17 did;
   this pass inherits that and says so.
5. **`admin_config_ops` `validate`** — I did not re-check that the TS reports
   Rust's *first* `bail!` field path for every validator family.
6. **The 5 SAML / 10 identity / 9 session routes' full protocol surface.** I
   certified the four adversarial legs named in the brief plus the mount. I did
   not re-derive SCIM filter grammar coverage, OIDC discovery/JWKS rotation, or
   PKCE against the Rust line by line — `packages/identity` and `packages/sso`
   carry 10 test files of their own and they are green, but that is their word.
7. **Live-deployment behaviour.** Everything here is offline under
   `@cloudflare/vitest-pool-workers`. No live Cloudflare account was touched, no
   `wrangler deploy` was run.
8. **Whether the (unbuilt) admin console would read the 62 CLASS A collections
   through this API.** It is a different question from data-plane enforcement,
   and for the write-bearing groups it does not help: the Rust versions
   *enforced*.

---

## 7. Markers added by this pass (5, all class `P`)

Comment-only. `bunx tsc --noEmit` clean and `bun run test` **36 files / 672
tests passed** after they landed.

| File | Anchor | Covers |
|---|---|---|
| `apps/control-plane/src/routes/admin_plugin.ts` | `pluginSchema` | §4.1 — CLASS A, with the `state.rs:674` hot-reload chain that disproves the wave-15 `L` rating |
| `apps/control-plane/src/routes/admin_policy.ts` | `adminPolicySchema` | §4.1 — CLASS A, incl. the #535 scope redaction and the "absent == out-of-scope" rule to carry |
| `apps/control-plane/src/routes/skill.ts` | `skillPackageSchema` | §4.1 — CLASS A, incl. the second-order effect on `workflow.ts` |
| `apps/control-plane/src/routes/admin_tool.ts` | `TOOL_APPROVAL_SPEC` | §4.3 — approvals EQUIVALENT, `tools` + `tool-sessions` CLASS A |
| `apps/control-plane/src/routes/tenant_hierarchy.ts` | `readOnlyCollection("tenants", …)` | §4.4 — the one non-equivalent op in a 20-op group, with the closable derivation |

**One marker this pass could NOT place, because the file is outside the owned
scope:** the `[auth_service]` acceptance gap of §5.5 belongs on
`packages/config/src/validate/sections.ts:59` (`validateAuthService`) and
`apps/cli/src/config-gate.ts:71`. It is recorded here and nowhere else.

---

## 8. What would have to be true to certify this Worker

Ordered by what a deployed operator observes, not by size.

1. **The five config-backed groups (31 ops, §4.1)** — one cross-app pattern
   applied five times, already proven twice. `admin_agent_upstream` first: its
   `DELETE` not withdrawing a compromised upstream is the only security-shaped
   item left in the CLASS A set.
2. **`billing.replay` addressing the ROW (§4.8)** — a real dead letter currently
   404s and can never be replayed. Money.
3. **`admin_provider` / `admin_model` / the `status` counts (§4.2, §4.6)** — name
   a source (the gateway's vars, or the already-declared `gateway_providers` /
   `gateway_models` tables) and carry the #535 redaction.
4. **`billing`'s six read feeds** off `billing_events` / `billing_ledger` /
   `billing_report_outbox` — same database, already bound.
5. **`GET /admin/v1/tenants` (§4.4)** — derivable today from
   `api_key_directory` ⋈ `static_api_keys`; carry the STRICT fence.
6. **`request_logs` (§4.5)** — needs a writer on `apps/gateway`'s inference path;
   heals `/metrics`'s only substantive gauge with it.
7. **`agent_run` + `tool-sessions` (§4.7, §4.3)** — DO → summary-row projections;
   `apps/agent-runtime` and `apps/mcp` own the write side.
8. **`site_domain` (§4.9)** — two slices: mount `D1SiteDomainVerificationStore`
   here; decide hostname routing on `apps/gateway` (CF Custom Hostnames may own
   part of it, in which case that half is CLASS C).
9. **The three envelope keys + the CLI `wrapped_resource` leg (§4.10)** — small,
   and the CLI one silently disarms every rollback pointer.
10. **The `[auth_service]` acceptance gap (§5.5)** — refuse it in the validator or
    implement it. Today `config validate` blesses a posture nothing serves.
11. **`guardrail_evaluations` migration (§4.5)** — guardrail evidence is
    in-memory-only fleet-wide until it exists.

Items 1–5, 9 and 10 are local to `apps/control-plane`, `apps/cli` and
`packages/config`. Items 6–8 and 11 need a cross-app agreement or a migration.

**Not on this list, deliberately:** the `ferrogate-auth-service` `/v1/rbac/*` and
`/v1/tenants` routes. They are CLASS B (§5.5) — a YAML-loaded, never-persisted,
parallel RBAC model that Rust abandoned. Porting them would import a defect.
They belong on the TS product backlog, designed on their own merits, and they
must not hold the cutover.

---

## 9. Answering the brief's question directly

> *"87 of 197 operations were RBAC-gated CRUD with no consumer. Verify each of
> the four closed groups actually takes effect, and determine how many
> no-consumer groups remain and whether each is CLASS A or CLASS B."*

- **All four closed groups take effect**, proved by my own mutations, asserted as
  the effect: the role stops authorizing (M5), the key stops authenticating (M7),
  the credit funds a request (M6), the activated revision moves the row the data
  plane enforces from (M8). Plus the tenant WRITE fence (M9).
- **62 operations across 9 whole groups and 6 partial groups remain
  no-consumer.** That is down from 87.
- **All 62 are CLASS A.** I read the Rust handler, its `state.*` method and its
  repository call for every one. Not a single one is a stub, a `todo!()`, dead
  code, or an orphan. The five config-backed groups are the strongest case: their
  Rust write path is a persist → rebuild-candidate → `validate()` → hot-reload →
  rollback-on-failure transaction, and one of them (`skill`) even re-reads the
  committed config and answers `409` if the write did not take.
- **The only CLASS B in this whole surface is the `auth-service`'s own
  `/v1/rbac/*` + `/v1/tenants` (7 routes)**, and the evidence is decisive: no
  persistence back to disk.

The honest bottom line is that this Worker is **closer than any previous wave
recorded and further than any previous wave admitted**: the volume of unread
operations fell by 29%, and the severity of what is left rose, because four
groups previously dismissed as "the Rust was thin too" turn out to be complete,
hot-reloading features the port replaced with deploy-time vars.
