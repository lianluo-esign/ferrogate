# Cutover parity certification — the CONTROL PLANE (197 `/admin/v1/**` operations + `/metrics`)

**Date:** 2026-08-01 · wave 15, the "verdicts, not volume" wave.
**Scope:** `apps/control-plane` (13,102 LOC src, 26 test files, 487 tests green)
against `crates/ferrogate-{admin,auth-service,control-plane-client}` and the
`/admin/v1` handlers those crates' surface actually lives in —
`crates/ferrogate-gateway/src/server/{local,rbac,wallets,plans,quota_policies,guardrail_policies,virtual_keys,site_domains,agent_schedules,route_groups}.rs`
(24,784 LOC) — plus `docs/legacy/inventory-edge-control.md`. All READ-ONLY.

**Method.** Group-by-group. For each of the 31 contract groups this Worker owns:
read the TS module, read the Rust handler it ports, and then ask the one question
the previous fourteen waves did not — *does the write reach the thing that reads
it?* Every claim below is backed by a named `file:line` on both sides, or by a
`grep` over `apps/<app>/src` + `packages/<pkg>/src` (production code only; test
fixtures excluded, because a fixture INSERT is exactly what hides this defect).
No behaviour was implemented. The product of this pass is this document plus
**17 new `PORT-TODO(P: …)` markers**.

---

## 0. The verdict

**The control plane is NOT at 1:1 parity, and `crates/**` must not be deleted
on the strength of this Worker.**

The failure is not where fourteen waves of marker burndown were looking. It is
not missing routes, missing auth, missing validation or missing durability —
all four of those are in excellent shape and several are *better* than the Rust.
It is one systemic seam, repeated across 15 of the 31 groups:

> **The admin surface writes durable documents that nothing reads.**

`apps/control-plane` persists ~60 admin collections into the control database's
generic `control_plane_resources` document table. Seven families additionally
*project* into the typed rows the rest of the fleet actually queries (plans,
tenants, projects, workspaces, quota policies, virtual keys, self-hosted worker
registrations) — that work landed in waves 13–14 and is genuinely done. The
other fifteen families do not project, and their readers are elsewhere:

| the admin group writes | the enforcing reader queries | result |
|---|---|---|
| `roles` / `tenant-roles` documents | `tenant_role_bindings ⋈ roles` (4 modules, 3 Workers) | a granted role authorizes nothing |
| `guardrail-policy-revisions` documents | `guardrail_policy_revisions` + `guardrail_policy_bindings` | an activated policy is never evaluated |
| `wallets.balance_cents` (control DB) | `wallets.balance_credits` (TENANT DB) | crediting a wallet does not fund a request |
| `api-keys` documents | `static_api_keys` | a created operator key authenticates nothing |
| `metering-events` documents | `billing_events` / `billing_ledger` | the billing feeds are empty |
| `agent-runs` documents | `AgentRunState` Durable Object | the run evidence feed is empty |
| `agent-upstreams` / `prompt-templates` documents | `GATEWAY_AGENT_UPSTREAMS` / `GATEWAY_PROMPT_TEMPLATES` **vars** | admin CRUD needs a redeploy to take effect |

This is the project's signature defect class, at a scale none of the ten prior
instances reached: **87 of 197 operations (44%)** are a complete, audited,
tenant-fenced, RBAC-gated CRUD surface over storage that has no consumer. Every
one of the 487 tests is green, because every test drives the admin API and reads
back through the *same* document store.

**Two of these are security-relevant, not merely inert:**
`DELETE /admin/v1/tenant-roles/{t}/{r}` does not revoke a grant, and
`POST /admin/v1/api-keys` + `DELETE` do not create or revoke a credential —
so the two operations an operator would reach for during an incident are no-ops
that answer `200`.

**What IS at parity** (and it is a lot): the contract-driven mount of all 197
operations with a real anti-drift gate; the entire auth ladder including the
401-vs-403 invariants; the `/control/v1` alias; CSRF; tenant fencing on reads;
the D1 store's revision-guarded concurrency and atomic batch; the audit trail;
the `AdminList`/`AdminDelete` envelopes and pagination fork; and seven fully
wired groups.

---

## 1. Quantitative summary

### 1.1 Coverage of the contract

| Check | Result |
|---|---|
| Operations the contract assigns to this Worker | **197** (192 `/admin/v1/**` + `/admin`, `/admin/`, `/admin/dashboard`, `/admin/status`, `/metrics`) |
| Operations MOUNTED on the app the Worker exports | **197 / 197** |
| Operations answering `404` / unimplemented / `501` | **0** |
| Contract groups owned | **31** |
| Anti-drift gate present and load-bearing | **yes** — `MOUNTED_ROUTES` is the value `registerRoutes(app)` returned for the exported `app` (`src/index.ts:87`), and `test/wiring.test.ts` inspects THAT array, not a test-built app. Three further fail-closed checks throw at module load (`src/routes/index.ts:1-19`): unknown group, unhandled operation, registered-vs-contract set difference. |

So the "code exists but is not mounted" variant of the defect class is **not**
present here. The variant that is present is one level deeper: mounted, reached,
authorized, and writing to the wrong store.

### 1.2 Group verdicts

| Verdict | Groups | Ops |
|---|---:|---:|
| **EQUIVALENT** — writes reach the enforcing store, behaviour matches Rust to the depth checked | **7** | **49** |
| **PARTIAL** — some operations equivalent, named others not | **9** | **61** |
| **DURABLE-BUT-UNREAD** — every write persists, no consumer exists anywhere in the fleet | **15** | **87** |
| **MISSING** (route absent / unreachable) | **0** | **0** |
| **IN-MEMORY-ONLY** | **0** | **0** |

There is no in-memory residue: `resolveStore` (`src/adapters.ts:559`) *throws*
when no `DB` is bound and `CONTROL_PLANE_STORE` was not explicitly set to
`"memory"` — the silent-data-loss shape was deliberately removed. "Not durable"
is not one of this Worker's problems.

---

## 2. Group-by-group verdicts

`ops` = operations in this Worker's slice of the group. `consumer` = the module
that reads what the group writes, in production code.

### 2.1 EQUIVALENT (7 groups, 49 ops)

| Group | Ops | Consumer of the write | Notes |
|---|---:|---|---|
| `quota_policy` | 6 | `apps/gateway` `d1QuotaPolicySource` ← `quota_policies` | `projectQuotaPolicy` on all four mutating legs (each is an override, so the spec hook cannot cover them and each calls it explicitly); `deleteQuotaPolicyRow` on DELETE. `authorizeScopedResource` reproduces Rust `auth::authorize_scoped_resource` including the fail-closed "resolution failure denies". |
| `plans` | 5 | same, via `JOIN plans p ON t.plan_id = p.id` | `project: projectPlan` on the spec, so POST/PUT/PATCH all run it. No DELETE, by contract — 405, correct. |
| `admin_virtual_key` | 8 | `D1NativeApiKeyAuthenticator`, `apps/mcp/src/auth.ts` | Mints, hashes, returns plaintext once; dual-writes `api_key_directory` (control) + `api_keys` (tenant DB) with the direction-aware ordering (`loosen` = tenant row first, `tighten` = directory first). `test/virtual-key-credential.test.ts` proves the minted secret authenticates on the next request and that revoke → 401. |
| `self_hosted_worker` | 10 | `apps/agent-runtime` `d1WorkerIdentityPort` ← `self_hosted_worker_registrations` | `projectWorkerRegistration`; the transport secret is not derived from anything the admin surface publishes; `POST /admin/v1/status` delegates to the SAME handler so the two entry points cannot diverge. |
| `admin_agent_schedule` | 8 | this Worker's own `scheduled` handler (`[triggers] crons = ["* * * * *"]`) | Self-consistent by design and argued at `src/schedule/model.ts:14-35`; `test/worker-entry.test.ts` fires a due schedule through the real entrypoint. |
| `admin_mcp_server` | 6 | `apps/mcp/src/catalog.ts` reads `control_plane_resources` kind `mcp-servers` directly | The one group where the document IS the cross-app contract. This is the template the other 15 should follow. |
| `admin_gateway_config` | 6 | `routes/admin_config_ops.ts::reloadAdminConfig` | Storing and activating are two operations, as in Rust. |

### 2.2 PARTIAL (9 groups, 61 ops)

| Group | Ops | What is equivalent | What is not |
|---|---:|---|---|
| `tenant_hierarchy` | 20 | 19 ops. Projections into `tenants` (control) and `projects`/`workspaces` (tenant DB); `assignTenantPlan` re-projects explicitly because it is an override; `deleteProject`/`deleteWorkspace` go through `@ferrogate/storage`'s reference-guarded delete FIRST so a refusal leaves both rows intact; `getTenantResolvedDefaults` calls the SAME `resolveEffectiveQuota` the data plane calls. | `GET /admin/v1/tenants` pages a `tenants` DOCUMENT collection nothing writes (tenant *accounts* are a different collection). Rust `handle_admin_tenants` (`local.rs:9288`) projects `state.tenant_refs()` through `filter_by_tenant_scope`. Answers an empty list on every deployment. |
| `admin_tool` | 7 | The 3 approval decisions + the approvals collection — `apps/mcp/src/approvals.ts` reads `control_plane_resources` kind `tool-approvals`. | `tools`, `tool-sessions`, `tool-session-events` are read-only document collections with no writer. |
| `admin_config_ops` | 4 | `validate` runs the real `@ferrogate/config` loader + `validateConfigAsync` and reports the loader's own first `field …:` (Rust `bail!`s the first, so exactly one error is correct); `reload` refuses a candidate that would not load with `409 config_reload_rejected` before recording activation; `drain` is durable. | `reload` cannot swap a live isolate — `applied: false`, `propagation: "on_next_isolate_config_read"`. Marked as a platform limit, and the honesty is right: `applied: true` would be a lie an operator acts on during an incident. |
| `admin_overview` | 9 | The auth ladder on all 9; `/metrics` correctly bearer-guarded (`visibility: internal`, `auth.kind: bearer`); Prometheus content type `text/plain; version=0.0.4`; the three anonymous dashboard paths; `snapshot` reports the real promoted `configSnapshotId`. | `status()` counts `providers`/`models`/`api-keys`/`prompt-templates`/`plugins`/`tools` from document collections that have no writer — every count is **0** on a working deployment. `metrics()` publishes `ferrogate_request_log_entries` off the same empty `request-logs` collection, so the gauge is pinned at 0. `observability()` returns `[]` (marked platform limit: Analytics Engine has no offline read side). The dashboard is a placeholder, marked, and deliberately ships no script tag. |
| `billing` | 7 | `rearmOutboxRow` is real, correct and sharp: a `sqlite_master` structural probe distinguishes "not provisioned" from "unreadable", the `AND dead_lettered_at_unix IS NOT NULL` is a genuine CAS, `RETURNING` makes the answer real, re-arm precedes the document mark, and `emitted: false` is honest. | All 6 read feeds page document collections; the data plane writes `billing_events` / `billing_ledger` / `billing_report_outbox`. **And that breaks `replay`:** it requires a `billing-outbox-dead-letters` DOCUMENT before it will re-arm, and the sweeper dead-letters the ROW — so a real dead letter answers **404 and can never be replayed**, while the correct half is reachable only from a hand-seeded document. |
| `site_domain` | 5 | The #488/#576 challenge machinery is a faithful port: rate limit reserved BEFORE the resolver is touched, challenge minted not assumed, `unavailable` never folded into `verified`, default resolver unbound so an unconfigured deployment cannot verify. `test/site-domain-cas.test.ts` races two callers. | Nothing serves a verified hostname (`grep -ri "site.domain" apps/gateway/src` → 0; Rust `server/sites.rs` routes by verified custom hostname). `packages/storage`'s `D1SiteDomainVerificationStore` — the only writer of `site_domain_verifications` — is imported by no application module. |
| `admin_managed_worker` | 4 | Auth + tenant fence. | All four answer an empty list. Rust `handle_admin_managed_workers` (`local.rs:5187`) answers a NON-empty fixed contract descriptor (process boundary, 8 lifecycle actions, ranked isolation backends) — answerable here today with no new binding. The three storage feeds have no writer, consistent with the workerd microVM platform limit. |
| `x402_spend_policy` | 3 | Routed, guarded. | Deprioritized by standing user directive; marked `PORT-TODO(D: x402)`. Not counted against parity. |
| `payment_attempt` | 2 | Routed, guarded. | Read-only document collection, x402 family. Same directive. |

### 2.3 DURABLE-BUT-UNREAD (15 groups, 87 ops)

Every operation persists correctly, is tenant-fenced, is audited, and is RBAC-
gated. No production module anywhere in `apps/<app>/src` or `packages/<pkg>/src`
reads what it wrote.

| Group | Ops | Where the real reader looks instead | Severity |
|---|---:|---|---|
| `rbac` | 11 | `tenant_role_bindings ⋈ roles` — `src/adapters.ts:325`, `apps/gateway/src/adapters.ts:827`, `apps/gateway/src/assets/entitlements.ts:68`, `apps/mcp/src/auth.ts:90` | **H, security** |
| `wallets` | 10 | `wallets.balance_credits` + `wallet_reservations` in the TENANT DB (`apps/gateway/src/ratelimit/quota.ts:624`) | **H, money** |
| `guardrail_policy` | 10 | `guardrail_policy_revisions` / `guardrail_policy_bindings` (`apps/gateway/src/guardrails/d1.ts:93,109,119`) | **H, safety** |
| `admin_api_key` | 6 | `static_api_keys` (`src/store/api_keys.ts:79`) — and no secret is minted at all | **H, security** |
| `admin_request_log` | 5 | `audit_events` IS written (`src/store/d1.ts:911`) but read only by the gateway's asset audit tail; `request_logs` has no writer at all | **M, evidence** |
| `admin_provider` | 3 | Rust reads `state.config.providers` and DISPATCHES a live catalog per provider (`local.rs:5019,5062,7445`) | **M** |
| `admin_model` | 1 | Rust reads `state.config.models` with the #535 field redaction (`local.rs:8227`) | **M** |
| `agent_run` | 3 | `AgentRunState` Durable Object, keyed `tenant:run` (`apps/agent-runtime/src/runs/do.ts`) | **M, evidence** |
| `admin_agent_cost_burn` | 1 | `agent_cost_burn` in the TENANT DB (`packages/storage/src/d1/monotonic.ts:148`) | **M** |
| `prompt` | 6 | `GATEWAY_PROMPT_TEMPLATES` var (`apps/gateway/src/routes/prompts.ts:71`) | **M** |
| `admin_agent_upstream` | 6 | `GATEWAY_AGENT_UPSTREAMS` var (`apps/gateway/src/routes/agent-discovery.ts:21`) | **M** |
| `skill` | 6 | no reader | **L** |
| `admin_plugin` | 7 | no reader | **L** |
| `admin_policy` | 6 | no reader | **L** |
| `admin_agent_workflow` | 6 | no reader | **L** |

The last four are `L` because the corresponding Rust surfaces were also
config-document CRUD with a thin runtime; the first eleven are not.

---

## 3. Full-depth spot-checks

Two per group was the brief. Below are the checks whose result was not simply
"matches" — the rest are folded into §2. Each is stated so it can be re-run.

### 3.1 The auth ladder — EQUIVALENT, and well pinned

`src/middleware/auth.ts` is ONE table-driven middleware for all 197, exactly as
`ROUTE-MAP.md` invariant 1 requires. Verified line-by-line against
`crates/ferrogate-gateway/src/auth.rs::authenticate_with_admission`
(`auth.rs:1180-1328`):

| Invariant | Rust | TS | Test |
|---|---|---|---|
| suspended NATIVE key → **401** `invalid_api_key`, indistinguishable from unknown | `authenticate_durable` returns `None` for `!enabled`/revoked/expired, falls through to the final `401` | `key_suspended` and `unknown` collapse onto the same throw (`auth.ts:83-85`) | 4 cases incl. "suspension is byte-identical to a typo" |
| STATIC config key disabled → **403** `api_key_disabled` | `auth.rs:1255` | `auth.ts:86-89` | 1 |
| insufficient scope → **403** `scope_denied`, never 401 | `auth.rs:1243`, `auth.rs:1313` | `auth.ts:220` | 2 |
| empty scope set on a durable key ⇒ data-plane only, never admin | `authenticate_durable` keeps the empty set | `hasScope` | 2 |
| empty scope set on a STATIC key ⇒ wildcard (operator intent) | `auth.rs:1284` | `adapters.ts` | 1 |
| tenancy suspended → **403** `tenancy_suspended`, distinct from a key 401 | `finalize_auth` lifecycle chain | `auth.ts:236-244` | 3 |
| lifecycle store unavailable → **503**, never implicit allow | `LifecycleGateError::Unavailable` | handled BEFORE the truthiness check, deliberately | 1 |
| RBAC unavailable → **503**, never implicit allow | same | `auth.ts:248` | 1 |
| `GET /metrics` internal-but-bearer | `handle_metrics` → `authenticate(…, "admin.read", …)` | driven from the contract table, no carve-out | 3 (unauthenticated → refused; wrong scope → refused; authorized → exposition) |
| documented path + undocumented method → **405** with `Allow`, decided BEFORE auth | `api_contract::path_is_documented` | `auth.ts:157-169` | 1 |
| CSRF `Sec-Fetch-Site` authoritative, `Origin` fallback | `handlers.rs::admin_cross_site_rejection` | `auth.ts:112-129` | 5 |

**One deliberate omission, stated:** Rust has an `[auth] disabled = true` escape
(`auth.rs:1194`) that grants wildcard platform root. It has no TS counterpart.
That is a *hardening*, not a regression — but it is a behaviour difference, and
a deployment migrating a config that used it will find the gateway closed.

### 3.2 `/control/v1` → `/admin/v1` alias — EQUIVALENT

`withAliasCanonicalization` wraps `app.fetch` (`src/middleware/alias.ts:59`), not
a Hono `use()`, because Hono resolves the whole chain in one `router.match()` and
a middleware is already too late to change route selection. Whole-segment
semantics match `control_plane_test.rs` exactly: `/control/v1` and `/control/v1/x`
fold; `/control/v1x`, `/control/v1x/y`, `/control`, `/controlled/v1` do not; an
already-canonical path is not double-rewritten. Never a redirect. 8 tests,
including "reaches the same handler".

### 3.3 Cross-tenant isolation — PARTIAL, with an unpinned write-side hole

Reads are strong: one helper (`tenantScopeSql`, `src/store/d1.ts`) appends the
fence to every SELECT, UPDATE and DELETE, so there is no "resolve by bare id"
path to forget it on — structurally better than the Rust, whose #185/#186 defects
were exactly that. Another tenant's row is a `404`, indistinguishable from
absent. `quota_policy` and `rbac` additionally check path-parameter tenants with
`403 tenant_scope_denied` (Rust `authorize_tenant_scope`), correctly a 403 and
not a 404 because the caller named the tenant explicitly.

**The gap.** The predicate is
`tenant_id IS NULL OR tenant_id = ?`, whereas Rust `filter_by_tenant_scope`
(`auth.rs:428`) is strict equality. For READS the widening is deliberate,
argued and pinned ("shows an un-attributed platform row to every tenant",
`test/store-conformance.test.ts:135`). But the same predicate is on `#update`,
`remove` and the `atomic` batch, and **no test pins the write side**. A
tenant-scoped credential holding `admin.write` — a tenant administrator, an
intended configuration — can therefore PATCH or DELETE any un-attributed
platform row: a global `role`, a shared `policy`, a `plan` other tenants are
billed against. Rust makes that unreachable.

Marked at `src/store/d1.ts` (`tenantScopeSql`). The fix is to split the
predicate: keep the `IS NULL` disjunct for SELECT, drop it for UPDATE/DELETE.

### 3.4 Persistence actually reaching D1 — see §2; the store itself is EQUIVALENT+

`D1ControlPlaneStore` was checked independently of whether anything reads it:

- **Concurrency.** D1 has no interactive transactions, so `replace`/`merge` are
  read → compute → `UPDATE … WHERE revision = ?` with a bounded 3-attempt retry.
  A racing writer moves the revision, the guarded UPDATE matches zero rows, and
  the operation retries against the new state. No lost update.
- **Atomicity.** `atomic()` is a real D1 `batch()` with per-mutation guards; the
  wallet ledger entry and the balance movement are one unit, and `applied === null`
  means neither happened.
- **Conflict identity.** `INSERT … ON CONFLICT DO NOTHING RETURNING` gives a real
  409 rather than a silent overwrite; the conflict is on `(resource_kind,
  resource_id)` and deliberately ignores tenancy, so a tenant cannot probe another
  tenant's id space by observing 201-vs-409… **and cannot squat it either** —
  worth noting as an intentional trade.
- **Audit.** Every applied mutation appends an `audit_events` row stamped with the
  request id threaded from `src/index.ts:68`.

### 3.5 Response shape and error identity — PARTIAL

`AdminList` / `AdminDeleteResponse` / pagination are exact, including the two
details most likely to be missed: the un-paginated envelope genuinely *omits*
`total`/`offset`/`limit` (Rust `skip_serializing_if`), and the fork is on "was
there a query string at all", not on which keys it had. Status codes match
(`POST` collection → 201, `PUT`/`PATCH` with a path id → 200, `DELETE` → 200 with
`{object,id,deleted:true}`), and `prompt-templates` archive correctly returns
`deleted: false`.

**Three mutation-receipt envelopes are wrong on the wire.** The port assumes
"envelope key equals `object`", which is true for most Rust structs but not all:

| resource | Rust | this port |
|---|---|---|
| `/admin/v1/api-keys` | `{ object: "api_key", key }` (`responses.rs:1096`) | `{ object: "api_key", api_key }` |
| `/admin/v1/mcp-servers` | `{ object: "mcp_server", server }` (`responses.rs:1900`, `local.rs:698`) | `{ object: "mcp_server", mcp_server }` |
| `/admin/v1/tenant-accounts` | `{ object: "tenant_account", tenant }` (`virtual_keys.rs:320`) | `{ object: "tenant_account", tenant_account }` |

Marked at `src/responses.ts::adminItem`.

### 3.6 Body validation — PARTIAL, honestly marked

~60 collections validate against a shared `passthrough()` base rather than the
per-resource Rust mutation struct. The existing marker at `routes/resource.ts:175`
is correct that this is blocked on `@ferrogate/schemas`, not on the platform, and
that `passthrough()` is the safe approximation (`strict()` against a guessed shape
would reject fields Rust accepts). Body-size 413 is enforced before parse at the
Rust limit (1 MiB). The collections that DO have an authoritative schema use it
(`guardrail_policy` → `@ferrogate/guardrails`, `admin_config_ops` →
`@ferrogate/config`, `tenant_hierarchy` → `@ferrogate/storage`'s
`LIFECYCLE_STATUS_ALL`). Left as-is; not re-marked.

---

## 4. Cross-boundary finding: the CLI mutation receipt is blind to the admin envelope

Not in `apps/control-plane`, but it is the control plane's contract and the brief
names it, so it is certified here.

`apps/cli/src/receipt.ts::lookupString` searches **only the top level** of the
response body. Rust `envelope_scalar`
(`crates/ferrogate-control-plane-client/src/receipt.rs:2238`) searches the top
level **and then `wrapped_resource(body)`** — the single nested object beside
`object` — because that is where the contract puts the changed document:
`{ object: "project", project: { id, revision, … } }`.

Against a real control-plane response, every harvested receipt field therefore
collapses to its absence code:

- `target.resource_id` → `response_names_no_resource_id`
- `target.object_version` → `response_carries_no_object_version`
- `audit_id`, `approval_id` → their contract-absence codes
- the rollback pointer → `response_carries_no_revision`, so a guardrail revision
  mutation emits **no reversal command at all**

The Rust doc comment on `attested_resource_id` names this exact regression as a
bug it had already fixed: *"`ctl projects create` used to leave this null … even
though the response had already arrived carrying `proj_1` … the operator had to
parse the nested raw body — the bare-body reading this receipt exists to remove."*
The port reintroduced it.

**Why 339 CLI tests stay green:** `apps/cli/test/ctl.test.ts:118` scripts the fake
server with a BARE body (`{ id: "p9", name: "new" }`) — a shape the control plane
never returns. No test asserts on `resource_id` at all (`grep -rn resource_id
apps/cli/test` → 0 hits). This is the unrepresentative-fixture variant of the
vacuous-assertion class.

Marked at `apps/cli/src/receipt.ts::lookupString`, including the warning not to
restore a deep walk — Rust deleted that on purpose (`receipt.rs:2225`) because it
attested a nested rule's `version` as the changed object's.

---

## 5. What would have to be true to certify this Worker

Ordered by what a deployed tenant or operator would observe, not by size.

1. **`rbac` write half** (11 ops, security). Project `roles.permission_keys_json`
   and `tenant_role_bindings` on bind/unbind. Until then `DELETE
   /admin/v1/tenant-roles/{t}/{r}` answers 200 and revokes nothing.
2. **`admin_api_key` mint + project** (6 ops, security). Mint like
   `admin_virtual_key` does; project into `static_api_keys`. Until then the group
   cannot produce a working credential and cannot revoke one.
3. **`guardrail_policy` projection** (10 ops, safety). Revisions +
   `guardrail_policy_bindings.active_revision` under the existing generation CAS.
4. **`wallets` dual write** (10 ops, money), with the credits↔cents conversion
   taken from `apps/gateway/src/metering/credits.ts` rather than re-derived.
5. **`billing` feeds off the typed tables** (7 ops) — and specifically make
   `replay` address the outbox ROW, so a real dead letter stops 404-ing.
6. **The tenant write fence** (§3.3) — one-line predicate split plus a mutation
   test.
7. **The CLI receipt's `wrapped_resource` leg** (§4) plus fixtures that use the
   real envelope.
8. **The three envelope keys** (§3.5).
9. **`admin_provider` / `admin_model` / `admin_overview` counts** — name a source
   (the gateway's vars, or the unwritten `gateway_providers` / `gateway_models`
   tables) and project it. Today `GET /admin/v1/status` tells an operator the
   deployment has 0 providers and 0 models.
10. **`agent_run`, `admin_agent_cost_burn`, `admin_request_log`** — evidence
    projections; `agent_run` needs `apps/agent-runtime` to write the summary row,
    because a Durable Object is addressable but not queryable across instances.
11. **`prompt` / `admin_agent_upstream` / `skill` / `admin_plugin` /
    `admin_policy` / `admin_agent_workflow`** — one cross-app decision, not six:
    either the gateway grows a control-DB read (the `admin_mcp_server` shape,
    already proven), or these project into gateway-bound typed tables.

Items 1–8 are local to `apps/control-plane` + `apps/cli`. Items 9–11 need a
cross-app agreement about where the gateway's configuration lives, and that is
the single largest open question this audit surfaced.

---

## 6. Markers added by this pass (17, all class `P` — portable)

Each is placed at the seam that would have to change, not at the file that
noticed. All are comment-only; `bun run typecheck` and `bun run test` are green
in both touched workspaces (control-plane 487/487, cli 339/339).

| File | Anchor | Covers |
|---|---|---|
| `apps/control-plane/src/routes/rbac.ts` | `rbacRoutes` | §2.3 rbac |
| `apps/control-plane/src/routes/wallets.ts` | `WALLETS`/`LEDGER` | §2.3 wallets |
| `apps/control-plane/src/routes/guardrail_policy.ts` | `guardrailPolicyRoutes` | §2.3 guardrail_policy |
| `apps/control-plane/src/routes/admin_api_key.ts` | `adminApiKeyRoutes` | §2.3 admin_api_key (both halves) |
| `apps/control-plane/src/routes/billing.ts` | `billingRoutes` | §2.2 billing, incl. the `replay` 404 |
| `apps/control-plane/src/routes/admin_request_log.ts` | `adminRequestLogRoutes` | §2.3 evidence feeds |
| `apps/control-plane/src/routes/admin_provider.ts` | `adminProviderRoutes` | §2.3 provider views |
| `apps/control-plane/src/routes/admin_model.ts` | `adminModelRoutes` | §2.3 model listing + the #535 redaction |
| `apps/control-plane/src/routes/agent_run.ts` | `agentRunRoutes` | §2.3 run evidence |
| `apps/control-plane/src/routes/admin_agent_cost_burn.ts` | `adminAgentCostBurnRoutes` | §2.3 cost burn |
| `apps/control-plane/src/routes/admin_agent_upstream.ts` | `adminAgentUpstreamRoutes` | §2.3 the config-var split (the canonical statement) |
| `apps/control-plane/src/routes/prompt.ts` | `PROMPT_TEMPLATES` | §2.3, pointer to the above |
| `apps/control-plane/src/routes/admin_managed_worker.ts` | `adminManagedWorkerRoutes` | §2.2 the missing fixed descriptor |
| `apps/control-plane/src/routes/site_domain.ts` | `SITE_DOMAINS` | §2.2 site domains |
| `apps/control-plane/src/store/d1.ts` | `tenantScopeSql` | §3.3 the write-side fence |
| `apps/control-plane/src/responses.ts` | `adminItem` | §3.5 the three envelope keys |
| `apps/cli/src/receipt.ts` | `lookupString` | §4 the receipt harvesting gap |

---

## 7. UNVERIFIED — stated rather than guessed

These were NOT checked to the depth of §3 and must not be read as certified:

1. **Per-operation request/response *field* parity.** The `passthrough()` base
   schema means field-level shapes were compared only where a group carries an
   authoritative schema. Roughly 60 collections' bodies are unverified against
   their Rust mutation structs.
2. **Envelope keys beyond the three in §3.5.** The Rust `Admin*MutationResponse`
   structs were enumerated and cross-checked against the TS `object:` names in
   bulk; three mismatches surfaced. Resources whose Rust struct is not named
   `*MutationResponse` were not swept.
3. **Search / filter semantics.** `parseListQuery` matches Rust `AdminPagination`
   exactly, but Rust's `matches_search` operates on a per-handler field list
   (`&[&provider.name, &provider.kind]`); the TS store applies `search` uniformly.
   Whether the searched field sets agree per collection is unchecked.
4. **The 6 `admin_agent_workflow` and 6 `skill` operations** were verdicted from
   their consumer graph (none) and their module source, not from a Rust handler
   diff.
5. **`apps/auth-service`'s non-contract surface** — `/v1/admin/*` console
   identity, `/v1/auth/*`, `/scim/v2/*`, SAML/SSO (`crates/ferrogate-auth-service`,
   11,474 LOC). `src/index.ts` states these are not among the 197 and are not
   built. **They are a real, large, unported cluster**, and the control-plane's
   own `admin_users` / `admin_user_tenant_memberships` /
   `admin_user_refresh_tokens` / `sso_provider_configs` / `sso_pending_flows`
   tables have no writer. Out of this audit's scope; must not be forgotten at
   cutover.
6. **Live-deployment behaviour.** Everything here was verified offline under
   `@cloudflare/vitest-pool-workers`. No live Cloudflare account was touched.
7. **Whether the 15 DURABLE-BUT-UNREAD groups' documents are read by the unbuilt
   admin console.** They are not read by any Worker; a future console would read
   them through this API, which is a different question from data-plane
   enforcement. For the eleven `H`/`M` rows the distinction does not help — the
   Rust versions of those surfaces enforced.
