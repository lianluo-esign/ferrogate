# Tenant-private vs platform-shared: the authoritative table classification

Status: proposed, 2026-08-04. Issue #831.
Companion to `docs/design/per-tenant-durable-object-storage-2026-08.md`, which decided
*that* tenant storage becomes one SQLite-backed Durable Object per tenant. This document
decides *what goes in it*.

Scope: all **81** tables that exist in the two D1 roles today — **59** control, **22**
tenant. Verified by enumeration, not by trusting the migration headers:

```
$ cd sql/d1-ts && grep -ciE '^\s*CREATE TABLE' control/*.sql tenant/*.sql
control/0001_init_control.sql:44   control/0003_tenant_provider_credentials.sql:1
control/0004_guardrail_evaluations.sql:2   control/0004_semantic_cache_policies.sql:1
control/0005_siem_export_cursors.sql:1     control/0008_delegation_chain.sql:1
control/0009_online_eval.sql:2             control/0010_spend_anomaly.sql:3
control/0011_experiment_outcomes.sql:1                          → 56
tenant/0001_init_tenant.sql:20             tenant/0004_asset_bundle_files.sql:1
tenant/0005_responses_conversations.sql:1                       → 22
```

`storage_schema_migrations` is byte-identical DDL in both roles and is therefore counted
once per role — two of the 81, not one.

### Correction: the migrations directory is not the schema

A first draft of this document scoped itself to `sql/d1-ts/` and called the result complete.
It was not, and the failure is instructive enough to leave in rather than quietly fix: **three
control tables are created at runtime from TypeScript and never appear in a migration file
at all.** The enumeration above was `grep CREATE TABLE sql/d1-ts/`, which cannot see them —
exactly the grep artifact Part 3 warns its *own* collection list might be, without the
caution having been applied here. The second sweep that found them:

```
$ grep -rn "CREATE TABLE" --include="*.ts" apps packages | grep -v /test/
apps/control-plane/src/store/d1.ts:13     (a docblock, not DDL)
apps/gateway/src/metering/d1.ts:102,117,133   billing_ledger / _report_outbox / _events
apps/mcp/src/durable.ts:59,85,93          mcp_oauth_credentials / _identity_generations / mcp_servers
```

- `apps/mcp/src/durable.ts:58-109` — `MCP_IDENTITY_SCHEMA`, applied by
  `ensureMcpIdentitySchema()` (`:140-142`) from **eight** production call sites
  (`:428, 441, 458, 470, 496, 531, 558, 788`). These are **new tables**, classified below as
  C57–C59. They land in the control D1: `apps/mcp/wrangler.toml:212` binds
  `DB = ferrogate-control` and `apps/mcp/src/ports.ts:2071` says so outright — "`env.DB`
  already IS the control database".
- `apps/gateway/src/metering/d1.ts:102-133` — a **second DDL source for tables that also
  exist in `sql/d1-ts/control/0001_init_control.sql`** (C23/C24/C25). No new tables, but two
  places to change, and Step 8 must move both or the gateway will re-create the control-D1
  shape it just stopped writing to.

The rule this corrects: **the schema is what the running Worker creates, not what the
migrations directory contains.** Any future table census runs both greps.

---

## The three labels, and the bar

| label | meaning | where the row physically lives |
|---|---|---|
| **tenant-private** | the row belongs to exactly one tenant and nothing outside that tenant needs to read it without naming it | the tenant's Durable Object, only |
| **platform-shared** | the row must be readable before any tenant is known, or spans tenants by nature, or *is* the registry | control D1, only |
| **derived** | authoritative copy lives in the tenant's object; a narrowed projection is **pushed** to control D1 for a fleet view | both, one direction of truth |

**The bar for platform-shared is high and the burden of proof sits on that label.** A table
earns it only by satisfying one of exactly four tests:

1. **Chicken-and-egg.** It is read *before* a tenant id exists to address an object with.
   `env.TENANT_DATA.idFromName(tenantId)` needs `tenantId`; anything on the path that
   produces `tenantId` cannot itself live behind it. (`api_key_directory`, `site_domains`,
   `sso_pending_flows`, `static_api_keys`.)
2. **Cross-tenant by nature.** The row is *about* a relation between tenants or between a
   tenant and something that outlives it. (`admin_users` — one human, many tenants;
   `admin_user_tenant_memberships` — the edge itself; `plans`/`roles`/`permissions` — a
   vocabulary the governed party may not author.)
3. **It is the registry.** The thing that says which tenants exist at all.
4. **A global uniqueness invariant.** The table's key is unique *across* tenants and something
   depends on the collision. Per-tenant objects structurally cannot enforce this: two objects
   cannot both refuse a key neither can see. (`site_domains` — one hostname, one tenant;
   `siem_export_cursors` — `(sink_id, stream)`, where the collision is the mis-configuration
   detector.)

Test 4 was implicit in the first draft — it was the *actual* reason `site_domains` survived,
stated there as "a stronger reason than the chicken-and-egg one" — and leaving it unnamed is
what let C49 be classified against a key it does not have. Naming it makes the next such table
answerable by the same question instead of by inspection.

**"Moving it is work" is not a reason. "It is currently read fleet-wide" is not a reason** —
that is a description of a pull implementation, and the design doc's cost item 3 already
committed to converting those pulls to pushes. A table that is read fleet-wide *only because
the reader was written as a `SELECT … GROUP BY tenant`* is **derived**, not platform-shared.

### The one new argument the DO topology adds, in both directions

**For platform-shared:** a Durable Object namespace has no existence check. `idFromName(x)`
resolves for *every* string `x` — there is no "no such object". Today a bogus tenant id is
refused by `EnvBindingTenantDatabaseRouter` because `tenant_databases` has no row
(`packages/storage/src/tenant-router.ts:493-497`, kind `not_found`). Under DO addressing that
refusal has no source unless a registry outside the objects supplies it. So `tenants` and
`tenant_databases` do not merely survive the migration — they become **more** load-bearing,
because they are the only thing standing between a caller-declared tenant id and unbounded
object materialisation. (A caller *can* declare its own id: `apps/control-plane/src/routes/resource.ts:333`
and `apps/control-plane/src/session/routes.ts:349`.)

**Against platform-shared:** a control-D1 table that a tenant's own admin authors and that
nothing else reads by any key but the tenant's is tenant data sitting in the wrong database.
Two of the design doc's headline wins — hard residency via `jurisdiction("eu")` and per-tenant
PITR — apply only to bytes inside the object. Every row left on control D1 is a row outside
the residency guarantee. That cost is what makes the bar high.

### The governance constraint that is NOT a classification

Several tenant-private tables hold *ceilings imposed on the tenant*: `quota_policies`,
`spend_throttles`. `apps/control-plane/test/quota-self-escalation.test.ts:11` states the rule —
**"a ceiling its subject can lift is not a ceiling"** — and `apps/control-plane/src/routes/rbac.ts:196`
states the same for grants: *"a grant the governed party can write is not a grant"*.

Today that is enforced by *database separation*: the tenant data plane has no handle on
control D1. Moving these rows into the tenant's own object removes that separation, so the
enforcement must be re-expressed as **a privileged RPC method on `TenantDataObject` that the
tenant-facing code path does not call**, plus a class-level split between operator-writable and
tenant-writable tables. This is an implementation constraint on the move, **not** a reason to
label the table platform-shared — it fails all four tests above. Recording it here so the
slice that moves `quota_policies` cannot claim it was unforeseen.

---

## Refutation log — platform-shared claims I tried to break

Every platform-shared label below was written as a claim and attacked. Six survived cleanly,
five survived contingently, three did not survive.

### Did not survive → reclassified

| claim | how it broke |
|---|---|
| `api_key_directory` is platform-shared | It *is* read before the tenant is known — but it is not authoritative. `apps/control-plane/src/store/api_keys.ts:315` says outright that it **"duplicates four lifecycle columns across two databases"**; the authoritative row is the tenant's own `api_keys`. A duplicate whose master lives elsewhere is the textbook **derived**. Reclassified. |
| `quota_policies` is platform-shared | Fails all four tests: read only after the tenant is known (`apps/gateway/src/ratelimit/quota.ts:601` binds a scope id), one row per scope, not the registry, and `UNIQUE (scope_type, scope_id)` is not a cross-tenant invariant. The only fleet read is `apps/control-plane/src/finops/pass.ts:414` — a `SELECT … WHERE scope_type = 'tenant'` pull that the design doc already committed to replacing with a push. **derived.** |
| `spend_throttles` is platform-shared | Same failure. `PRIMARY KEY (scope_type, scope_id)`, read on the admission hot path for one tenant. The only argument for keeping it out was the self-escalation risk — which is the governance constraint above, not a classification. **tenant-private.** |

### Broke in the other direction — a tenant-private claim that did not hold

| claim | how it broke |
|---|---|
| `siem_export_cursors` (C49) is tenant-private | The claim rested on a stated key of `PRIMARY KEY (sink_id, stream, tenant)`. **That is false.** The DDL is `PRIMARY KEY (sink_id, stream)` (`sql/d1-ts/control/0005_siem_export_cursors.sql:58`); `tenant` is a *column*, and its own comment (`:44-47`) says why — it is "COPIED here rather than only living in configuration… what makes a mis-edited config visible after the fact". So the key is **globally unique across tenants**, which is the same structure that keeps C19 `site_domains` platform-shared, and it earns the same label. Two things the tenant-private reading destroyed: (1) two sinks sharing a `sink_id` across tenants stop colliding and silently get separate cursors — deleting the exact detector the `tenant` column exists to be; (2) the reader is tenant-anonymous — `readSiemCursor` is `WHERE sink_id = ? AND stream = ?` with no tenant predicate (`apps/control-plane/src/siem/cursor.ts:75-86`), so "no cross-tenant reader" was false on its face. **platform-shared.** |

The move is coherent because a sink *is* fenced to one tenant (that is what the `tenant`
column records), so the pump can still address one object for the rows while the bookmark
stays on control D1 under a globally unique key. What the pump may not do is keep reading the
cursor without naming the tenant it then delivers for; see the Step 2 note.

### Survived contingently — stated so the door stays visible

| claim | the attack it survives only barely |
|---|---|
| `admin_user_refresh_tokens` | Looked up by `token_hash` alone (`apps/control-plane/src/session/store.ts:290`) and the secret is opaque (`generateRefreshTokenSecret()`, `session/routes.ts:233`) — so today the tenant is genuinely unknown at lookup. **But the row carries `tenant_id` and the session is pinned to one tenant.** Minting the token as `<tenantId>.<secret>` makes the lookup tenant-addressable and flips this to tenant-private. Kept platform-shared *for the current token format*, and the format change is the cheapest way to bring console sessions inside the residency boundary. |
| `sso_pending_flows` | The IdP callback carries only `state` (`identity/adapters.ts:429`, `DELETE … WHERE state = ? RETURNING *`). But `state` is minted by us, and SSO *initiation* already knows the tenant — `GET /v1/admin/auth/saml/authorize?tenant_id=…` (`identity/routes.ts:126-130`). Same prefix trick applies. Kept platform-shared for the current state format; note the residency counter-argument, since the row carries a nonce tied to a named human. |
| `site_domain_verifications` | Not itself hostname-keyed (PK is `(tenant_id, hostname)`, deliberately, so several tenants may hold a challenge for one hostname — `apps/gateway/src/sites/domains.ts:288-293`). It stays only because `SITE_DOMAIN_ROUTE_SQL` **`LEFT JOIN`s it in the hostname routing read** and treats a NULL state as a refusal. Splitting the join across a DO boundary turns one fail-closed query into two, and the second one failing is indistinguishable from "unverified". Could legitimately become derived; kept platform-shared because the fail-closed join is load-bearing. |
| `self_hosted_worker_registrations` | `SELECT registration_json FROM self_hosted_worker_registrations WHERE id = ?` (`apps/agent-runtime/src/durable/adapters.ts:301`) — a self-hosted worker presents `worker_id` + a transport secret and the tenant is learned from the row. Genuine chicken-and-egg. It is the same *shape* as `api_key_directory` and could be split the same way, but unlike the directory it is authoritative (the secret lives only here — `store/worker_registry.ts:46`). |
| `spend_anomaly_runs` | One row per detector window for the whole fleet (`sql/d1-ts/control/0010_spend_anomaly.sql:103`), and it is the pass's own idempotence claim (`INSERT OR IGNORE` window claim, `finops/pass.ts:193`). Survives *only for as long as the detector remains a fleet pass*. If detection moves into each object's alarm, this table has no subject and should be deleted rather than migrated. |

### Survived cleanly

`tenants`, `tenant_databases`, `static_api_keys`, `plans`/`roles`/`permissions`,
`admin_users` + `admin_user_tenant_memberships`, `site_domains` (global hostname uniqueness
cannot be enforced from inside per-tenant objects — test 4, which is a stronger reason than
the chicken-and-egg one), `guardrail_policy_revisions`/`_bindings` (a revision with an absent
`scope` matches **every** tenant — `apps/control-plane/src/routes/guardrail_policy.ts:232-253`
— and the gateway loads the whole catalog unfenced at `apps/gateway/src/guardrails/d1.ts:107`;
a policy the governed tenant cannot see or edit cannot live in that tenant's object).

---

## Part 1 — the 22 tenant tables

These are already per-tenant by construction. The classification question here is not *whether*
they move but whether anything outside the tenant reads them, which decides tenant-private vs
derived.

**The grep behind every "no cross-tenant reader" claim below.** A cross-tenant reader of a
tenant table can only be a fan-out, because the table is already inside a routed handle. There
are exactly two fan-out sources in the tree:

```
$ grep -rn "provisionedTenants\|fleetTenantIds" --include="*.ts" apps packages | grep -v /test/
packages/storage/src/tenant-router.ts:113,532,608,774   (the interface + 3 impls)
packages/storage/src/tenant-rest.ts:473
apps/control-plane/src/store/tenancy.ts:281
apps/control-plane/src/store/asset_fleet.ts:330  fleetTenantIds  → capped at 50 (FLEET_FANOUT_MAX_TENANTS, :84)
apps/control-plane/src/routes/admin_asset.ts:376  the only fleetTenantIds caller
apps/control-plane/src/routes/admin_agent_cost_burn.ts:127  provisionedTenantIds (its own copy)
```

So the *complete* set of cross-tenant readers of tenant tables is
`admin_asset.ts:376 → asset_fleet.ts:283-302` (assets) and `admin_agent_cost_burn.ts:101,127`
(burn). Everything else named "tenant-private" below has no cross-tenant reader, by that
enumeration rather than by per-table assertion.

**This enumeration is valid for the 22 tenant tables and for nothing else.** Its premise is
that a tenant table already sits behind a routed handle, so the only way to read two tenants'
rows is a fan-out. That premise does not hold for a *control* table labelled tenant-private:
those rows share one database today, so a plain `SELECT` with no tenant predicate is already a
cross-tenant read and needs no fan-out to be one. That class was missing from the first draft
and is swept separately in Part 2.

| # | table | label | reason (one line) |
|---|---|---|---|
| T1 | `storage_schema_migrations` | tenant-private | the object's own migration ledger; the DO applier writes it under `blockConcurrencyWhile` and nothing outside reads it |
| T2 | `projects` | tenant-private | `UNIQUE (tenant_id, slug)` — uniqueness is already per-tenant, so the object *is* the constraint domain; no cross-tenant reader |
| T3 | `workspaces` | tenant-private | same, `UNIQUE (project_id, slug)` inside one tenant; no cross-tenant reader |
| T4 | `api_keys` | tenant-private | the authoritative credential row incl. `key_hash`; its hash→tenant index is the separate derived `api_key_directory` (C5), so the secret half never needs a cross-tenant read |
| T5 | `wallets` | tenant-private | money, one row per tenant (`tenant_id … UNIQUE`); the only outside reader is the control-plane's own routed projection (`store/wallet_projection.ts:11`), which is a routed read, not a fan-out |
| T6 | `wallet_reservations` | tenant-private | the no-oversell hold; `transactionSync` is exactly what it has been missing (`wallet-d1.ts:317` `requireAtomicBatch`) |
| T7 | `wallet_settlements` | tenant-private | the tenant's own ledger tail; must commit in the same transaction as T5/T6 |
| T8 | `payment_methods` | tenant-private | `UNIQUE (tenant_id, provider, provider_payment_method_id)` — checked: no handler looks a method up by `provider_payment_method_id` alone, so no provider webhook needs a tenant-anonymous read |
| T9 | `tenant_contexts` | tenant-private | the org/project/key tuple a usage row is attributed to; written only by `usage-d1.ts:180` inside the routed batch |
| T10 | `usage_aggregate_rollups` | **derived** | authoritative accumulator per tenant, but platform billing needs the fleet sum; project `(tenant, period, cost_usd, tokens)` upward |
| T11 | `usage_monthly_rollups` | **derived** | read on the admission hot path for one tenant (`quota.ts:804`) *and* is the input to fleet spend views; the `CHECK (scope_type IN …)` must survive verbatim into the object |
| T12 | `usage_metadata_rollups` | **derived** | same; note `usage-d1.ts:354` reads it by `metadata_key` with **no** `organization_id` — harmless once the object is the fence, but it is why this table must never sit in a shared database |
| T13 | `stored_assets` | tenant-private | **has a cross-tenant reader**: `apps/control-plane/src/store/asset_fleet.ts:283-302` (`readFleetAssets`), reached from `apps/control-plane/src/routes/admin_asset.ts:376`. It is already an explicit, capped, admin-only fan-out (`FLEET_FANOUT_MAX_TENANTS = 50`, `asset_fleet.ts:84`) and stays one over DO stubs |
| T14 | `asset_channels` | tenant-private | same fan-out, same file; channel resolution is per-tenant by `UNIQUE (tenant_id, asset_type, name, channel)` |
| T15 | `retention_policies` | tenant-private | the tenant's own sweep policy; no cross-tenant reader |
| T16 | `workflow_run_budgets` | tenant-private | per-run money, three `requireAtomicBatch` sites (`workflow-budget-d1.ts:160,220,276`); no cross-tenant reader |
| T17 | `agent_schedules` | tenant-private | **the fleet reader is the tick, not a query**: `apps/control-plane/src/schedule/engine.ts:556` lists the schedule *document* collection under `TICK_SCOPE = {kind:"platform_operator"}` (`:129`), unpaginated, every tick. The partial index `idx_agent_schedules_due` exists to serve exactly that scan. Under DO this becomes each object's own `alarm()` — the single largest behavioural change in this classification |
| T18 | `agent_schedule_fires` | tenant-private | `UNIQUE (schedule_id, scheduled_fire_at_unix)` is the at-most-once gate; must move with T17 and in the same transaction as the fire it claims |
| T19 | `observed_agent_presence` | **derived** | composite PK `(tenant_id, api_key_id)` is tenant-private, but the `observed-agent-activity` admin collection (`routes/admin_managed_worker.ts:38`) is a fleet view; project last-seen upward |
| T20 | `agent_cost_burn` | tenant-private | **has a cross-tenant reader**: `apps/control-plane/src/routes/admin_agent_cost_burn.ts:101` inside the fan-out at `:127`, whose own docblock (`:119-125`) already says it "must never appear on a request path" |
| T21 | `asset_bundle_files` | tenant-private | composite PK `(asset_id, path)` under T13; no independent reader |
| T22 | `responses_conversations` | tenant-private | composite PK leads `(tenant_id, project_id, …)` **precisely because** that prefix is the cross-tenant fence for caller-supplied `previous_response_id`; inside one object the fence becomes structural. The sweep `DELETE … WHERE expires_at_unix <= ?` (`conversation-store.ts:448`) becomes a per-object alarm |

Tenant totals: **18 tenant-private, 4 derived, 0 platform-shared.** No tenant table earns
platform-shared, which is the expected result — a table that is already inside a per-tenant
database has by construction never been read before its tenant was known.

---

## Part 2 — the 59 control tables

C1–C56 are the `sql/d1-ts/control/` migrations; C57–C59 are the three the migrations directory
does not contain (see the correction at the top).

| # | table | label | reason (one line) |
|---|---|---|---|
| C1 | `storage_schema_migrations` | platform-shared | the control database's own ledger; same DDL as T1, different database, different subject |
| C2 | `control_plane_resources` | **must split** | one table multiplexing tenant documents, platform documents and singletons under `(resource_kind, resource_id)` — see Part 3; it is the only row in this table whose label is per-kind |
| C3 | `tenants` | platform-shared | **the registry**, and more load-bearing under DO than under D1: `idFromName` resolves every string, so this is the only thing that can answer "does this tenant exist?" before an object is materialised (`LIFECYCLE_TENANT_SQL`, `apps/gateway/src/adapters.ts:638`) |
| C4 | `tenant_databases` | platform-shared | the storage registry; loses `binding_name`/`database_uuid` and gains `location_hint`/`jurisdiction`, which the design doc's cost #1 requires be *recorded* rather than accidental |
| C5 | `api_key_directory` | **derived** | read before the tenant is known, so a copy must be here — but `store/api_keys.ts:315` says it "duplicates four lifecycle columns across two databases with no transaction spanning them" and the master is T4. The existing ordering rule is already the derived-projection discipline and must survive verbatim: **create** writes the tenant row then the directory, **revoke** writes the directory then the tenant row (`:316-318`), so a crash in either direction fails closed |
| C6 | `static_api_keys` | platform-shared | keyed by `key_hash` with no tenant in the signature, and `tenant_id` is NULLable precisely because platform-operator grants belong to no tenant |
| C7 | `gateway_providers` | platform-shared | platform provider catalog — **and it is dead**: zero readers and zero writers in non-test source (`store/d1.ts:1160` says so itself). Delete rather than migrate |
| C8 | `gateway_models` | platform-shared | same; `tenant_id` NULLable for a tenant catalog overlay that nothing writes. Delete rather than migrate |
| C9 | `quota_policies` | **derived** | reclassified — see the refutation log; authoritative in the object, `scope_type='tenant'` budget columns projected up for `finops/pass.ts:414`, with operator-only writes as a privileged RPC |
| C10 | `plans` | platform-shared | billing catalog joined by tenant id (`… FROM plans p JOIN tenants t ON t.plan_id = p.id`, 4 apps); a plan the tenant could author is not a plan |
| C11 | `permissions` | platform-shared | the RBAC vocabulary; `routes/rbac.ts:196` refuses tenant authorship in so many words |
| C12 | `roles` | platform-shared | operator-authored role catalog — confirmed: `tenant-roles` is the *binding* collection (`routes/rbac.ts:76`), not tenant-authored roles; there is no `INSERT INTO roles` outside operator paths |
| C13 | `tenant_role_bindings` | tenant-private | one tenant's grants; the catch is `RBAC_TENANT_ROLE_GRANTS_SQL` (`apps/gateway/src/adapters.ts:869`) **joins `roles`**, so moving the bindings requires `roles.permission_keys_json` be projected *into* each object — a reverse projection, and the only one in this document |
| C14 | `admin_users` | platform-shared | one human, many tenants — the schema comment (`session/store.ts:25-26`) says this is deliberate; looked up by `email` before any tenant is known |
| C15 | `admin_user_tenant_memberships` | platform-shared | it *is* the user→tenant edge; "which tenants am I in?" is a cross-tenant question with no tenant to address |
| C16 | `admin_user_refresh_tokens` | platform-shared | contingent — see the refutation log; flips to tenant-private the day the token is minted with a tenant prefix |
| C17 | `sso_provider_configs` | tenant-private | PK is `tenant_id`, read only as `WHERE tenant_id = ?` (`identity/adapters.ts:321`), and SSO initiation already carries `tenant_id` (`identity/routes.ts:129`) |
| C18 | `sso_pending_flows` | platform-shared | contingent — the IdP callback carries only `state` (`identity/adapters.ts:429`) |
| C19 | `site_domains` | platform-shared | hostname→tenant *and* a **global** uniqueness invariant (one hostname, one tenant) that per-tenant objects structurally cannot enforce |
| C20 | `site_domain_verifications` | platform-shared | co-located because `SITE_DOMAIN_ROUTE_SQL`'s `LEFT JOIN` is the fail-closed refusal for an unproven binding (`sites/domains.ts:305-308`) |
| C21 | `budget_alert_notifications` | tenant-private | `(scope_type, scope_id, period_month)` dedupe of alerts already sent to one tenant; read only with a bound scope (`budget-alerts-d1.ts:141`) |
| C22 | `control_plane_replay_floors` | tenant-private | `PRIMARY KEY (tenant_id, deployment_id)`; the `max()` upsert (`monotonic.ts:218`) becomes a real transaction instead of an upsert-with-`RETURNING` trick |
| C23 | `billing_ledger` | **derived** | `organization_id` **is** the tenant id (`apps/gateway/src/metering/event.ts:170-175`); authoritative in the object because it settles against T5–T7, projected up for the fleet ledger (`metering/d1.ts:171-174` reads it unfiltered) |
| C24 | `billing_report_outbox` | tenant-private | the outbox must be in the same database as the event it enqueues — `0001_init_control.sql:617-620` says the atomicity is real *only because both rows are here*; it moves with C25 or the guarantee is lost. **Two facts the first draft missed, both of which the move must handle:** the DDL (`:622-630`) has **no tenant reference at all** — `id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix, updated_at_unix, event_json` — the tenant is parsed back out of the payload (`routes/billing.ts:174`, "plus the tenant its event names"), so the move must add a real `tenant` column or the row cannot name the object it belongs in; and it has a genuine tenant-anonymous fleet reader, `BILLING_OUTBOX_LIST_DUE_SQL` (`metering/d1.ts:187-196`) — see the sweep below |
| C25 | `billing_events` | **derived** | authoritative with C23/C24 in one `transactionSync`; projected up because `finops/source.ts:100-116`, `admin_experiment.ts:171-174` and `admin_cost_record.ts:172,403` all join it fleet-wide. **Same missing-column defect as C24**: the DDL (`0001_init_control.sql:642-648`) is `billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json` — no tenant, only the payload. This is the identical hazard already caught for C37 and C47, and the lens was simply not turned on the billing pair; `getBillingEvent(billingEventId)` (`billing-d1.ts:212-220`) is the tenant-anonymous read it produces |
| C26 | `guardrail_policy_revisions` | platform-shared | a revision with an absent `scope` matches **every** tenant (`routes/guardrail_policy.ts:232-253`) and the gateway loads all of them unfenced (`guardrails/d1.ts:107`) |
| C27 | `guardrail_policy_bindings` | platform-shared | same, `guardrails/d1.ts:115` |
| C28 | `agent_runs` | tenant-private | `tenant` column; the caveat is the investigation leg (`admin_request_log.ts:868-905`) pinned **only** by `request_id IN (…)` — see the fragility note below |
| C29 | `agent_run_events` | tenant-private | same table family, same caveat |
| C30 | `request_logs` | **derived** | highest-volume table in the fleet and the tenant anchor for C25, C56 and the FinOps pass; authoritative in the object, a narrow `(tenant, request_id, cost, bucket)` projection pushed up. The design doc's cost #2 names this table as the one to keep a splitting seam open for |
| C31 | `audit_events` | **derived** | `auditChainKey(tenant) = tenant ?? ""` (`packages/storage/src/audit-chain.ts:132-134`) — the hash chain is **already per tenant**, so the object is its natural home and `transactionSync` upgrades the optimistic `UNIQUE (chain_key, seq)` retry loop (`0003_audit_chain.sql:28-38`) into a real serialization. `row_hash` travels with the row, so the projection is self-verifying **for chained rows only** — and that qualifier is load-bearing, see the correction below. The `""` platform chain stays on control D1 |
| C32 | `managed_worker_templates` | tenant-private | `id` + `template_json`; the DDL header (`:757-761`) calls the tenant "a composite storage key", which is a description of the current admin read, not of the data |
| C33 | `agent_worker_instances` | tenant-private | an instance belongs to exactly one tenant's workspace; fleet admin view becomes a fan-out or a projection |
| C34 | `managed_worker_sessions` | tenant-private | a session belongs to an instance (C33) |
| C35 | `managed_worker_lifecycle_events` | tenant-private | child of C34 by `session_id` |
| C36 | `managed_worker_isolation_selections` | tenant-private | keyed `session_id`, moves with C34 |
| C37 | `managed_worker_isolation_policies` | tenant-private | `PRIMARY KEY (session_id)` — no tenant column at all, so it is reachable *only* through C34 and must move with it or orphan |
| C38 | `managed_worker_isolation_evidence` | **derived** | isolation evidence is a compliance artifact; authoritative next to the session, projected up because the audit reader has no tenant in its signature (`ORDER BY occurred_at_unix, id`) |
| C39 | `self_hosted_worker_registrations` | platform-shared | `WHERE id = ?` with the transport secret inside `registration_json` (`agent-runtime/src/durable/adapters.ts:301`, `store/worker_registry.ts:46`) — worker_id→tenant is a chicken-and-egg read |
| C40 | `self_hosted_worker_heartbeats` | tenant-private | keyed `worker_id`; the tenant is known once C39 has resolved |
| C41 | `self_hosted_worker_telemetry_events` | tenant-private | same, and high volume — a natural candidate for the same split seam as C30 |
| C42 | `self_hosted_worker_artifacts` | tenant-private | same |
| C43 | `self_hosted_worker_checkpoints` | tenant-private | same |
| C44 | `self_hosted_run_dispatches` | tenant-private | a dispatch is one tenant's run assigned to one of its own workers |
| C45 | `tenant_provider_credentials` | tenant-private | the cleanest move in the schema: `PRIMARY KEY (tenant_id, alias)`, envelope-encrypted BYOK, **no cross-tenant reader anywhere**. Moving it is a security win (residency + blast radius), not just a topology change |
| C46 | `guardrail_evaluations` | **derived** | has `tenant`, but the platform-operator investigation surface reads it with the `WHERE` omitted entirely (`admin_request_log.ts:684-691`) and SIEM exports it fleet-wide |
| C47 | `guardrail_check_evaluations` | tenant-private | has **only** `evaluation_id` — no tenant reachable without its parent, so it moves with C46 or orphans; `guardrailChecksFor` (`admin_request_log.ts:655-666`) inherits C46's fence today |
| C48 | `semantic_cache_policies` | tenant-private | `PRIMARY KEY (scope_type, scope_id)`, read with both bound (`cache/governance.ts:160`) |
| C49 | `siem_export_cursors` | platform-shared | reclassified — see the refutation log. The key is `PRIMARY KEY (sink_id, stream)` (`0005_siem_export_cursors.sql:58`), **globally unique across tenants**, and that collision is the mis-edited-config detector the `tenant` column was added to serve (`:44-47`). Same structure as C19, same label. The bookmark stays on control D1; the rows it bookmarks move, which is a coupling the pump must handle explicitly rather than a reason to move the cursor |
| C50 | `delegation_revocations` | tenant-private | `PRIMARY KEY (tenant, subject)`, checked inside an already-authenticated request; a revocation that could be read cross-tenant would be a leak, not a feature |
| C51 | `online_eval_scores` | **derived** | tenant-scoped rows, but the regression sweep is `GROUP BY tenant, criterion_id, …` across the fleet (`apps/gateway/src/evals/d1.ts:168`) |
| C52 | `online_eval_regressions` | **derived** | the output of that fleet sweep, per tenant + `claim_key` |
| C53 | `spend_anomaly_episodes` | **derived** | only `scope_type='tenant'` is ever written (`0010_spend_anomaly.sql:82`); one episode is about one tenant, so the object owns it and the fleet dashboard reads the projection |
| C54 | `spend_anomaly_runs` | platform-shared | contingent — one row per detector window for the **whole fleet** (`0010:103`) and the pass's own `INSERT OR IGNORE` idempotence claim (`finops/pass.ts:193`); has no subject if detection ever moves into per-object alarms |
| C55 | `spend_throttles` | tenant-private | reclassified — see the refutation log; the write must be a privileged operator RPC on the object, never a tenant-reachable path |
| C56 | `experiment_shadow_legs` | **derived** | `tenant` + `request_id`; the experiment cost view joins `billing_events` fleet-wide before fencing (`admin_experiment.ts:171-174`) |
| C57 | `mcp_oauth_credentials` | tenant-private | **the single most residency-sensitive table in the tree, and the first draft did not list it at all.** Per-end-user OAuth access *and refresh* tokens, envelope-encrypted, `UNIQUE (tenant_id, workspace_id, user_id, server_name)` (`apps/mcp/src/durable.ts:59-84`). Read tenant-scoped, no tenant-anonymous reader. Its own schema comment (`:53-56`) says the physical per-tenant separation "is a control-plane deployment decision, not this Worker's" — i.e. the table was written expecting this classification to place it |
| C58 | `mcp_identity_generations` | tenant-private | `PRIMARY KEY (tenant_id, workspace_id, user_id, server_name)` (`durable.ts:85-92`) — the revocation generation counter for exactly the C57 tuple; moves with C57 or a revoked credential's generation is stranded |
| C59 | `mcp_servers` | tenant-private | `PRIMARY KEY (tenant_id, name)` (`durable.ts:93-108`), read `WHERE tenant_id = ?` by `loadServerCatalog` (`:788-794`); the tenant's own authored MCP server catalog including per-server auth material |

Control totals (counting C2 as its own category): **26 tenant-private, 20 platform-shared,
12 derived, 1 must-split.**

### The sweep the first draft skipped: tenant-anonymous reads of control tables

Part 1's fan-out enumeration does not transfer here (see the note there). A control table
labelled tenant-private or derived needs its own check: **is there a `SELECT` that reaches its
rows without naming a tenant?** The sweep, and what it found:

```
$ for t in <every control table labelled tenant-private or derived>; do
    grep -rn "FROM $t\b" --include="*.ts" apps packages | grep -v /test/; done
```

| table | tenant-anonymous read | what the move must do |
|---|---|---|
| C24 `billing_report_outbox` | `BILLING_OUTBOX_LIST_DUE_SQL` (`gateway/src/metering/d1.ts:187-196`) — `WHERE dead_lettered_at_unix IS NULL AND next_attempt_unix <= ?`, globally ordered, globally limited, no tenant predicate. Also `SELECT_OUTBOX_COLUMNS` (`storage/src/d1/billing-d1.ts:117-119`) | This is the outbox **pump** — the thing that actually delivers billing reports — so "convert the pull to a push" is not a hand-wave here, it is the whole redesign: each object drains its own outbox from its own `alarm()` and there is no fleet due-scan left. The dead-letter admin listing becomes the `billing-outbox-dead-letters` projection (Part 3a ‡) |
| C25 `billing_events` | `getBillingEvent(billingEventId)` (`billing-d1.ts:212-220`) by PK alone; `admin_request_log.ts:897` by `request_id IN (…)` | The PK read must take a tenant argument (the caller always has one — it just was not asked for) and the `request_id` leg is covered by the fragility note below |
| C49 `siem_export_cursors` | `readSiemCursor` (`siem/cursor.ts:75-86`) | Reclassified to platform-shared for exactly this reason |
| C21 `budget_alert_notifications` | `budgetAlertAlreadyNotified(id)` (`budget-alerts-d1.ts:117-119`) | Survives: the id is `{scope_type}:{scope_id}:{period}:{threshold}` (`storage/src/ids.ts:71-77`), so a `tenant`-scoped id contains the tenant. For `project`/`workspace` scopes it does not, and the caller's already-held scope is the only fence — worth an explicit predicate when the row moves, not a reclassification |

Everything else checked is fenced by a key that carries the tenant: C13
(`gateway/src/adapters.ts:869`, `WHERE tenant_role_bindings.tenant_id = ?1`), C22
(`monotonic.ts:244-246`, `tenant_id` + `deployment_id`), C45
(`provider-credential-d1.ts:118-119, 258-261`, `tenant_id` in both), C48
(`cache/governance.ts:160`, `scope_type` + `scope_id` both bound). C57–C59 are fenced by
`tenant_id` in every read.

### Fleet totals

| label | tables |
|---|---|
| tenant-private | 44 (18 tenant + 26 control) |
| derived | 16 (4 tenant + 12 control) |
| platform-shared | 20 (all control) |
| must split | 1 (`control_plane_resources`) |
| **total** | **81** |

Of the 20 platform-shared, two (`gateway_providers`, `gateway_models`) are dead tables that
should be dropped rather than migrated, and three (`admin_user_refresh_tokens`,
`sso_pending_flows`, `spend_anomaly_runs`) survive only contingently. The **durable
platform-shared core is 15 tables**:

`storage_schema_migrations` · `tenants` · `tenant_databases` · `static_api_keys` · `plans` ·
`permissions` · `roles` · `admin_users` · `admin_user_tenant_memberships` ·
`site_domains` + `site_domain_verifications` · `guardrail_policy_revisions` +
`guardrail_policy_bindings` · `self_hosted_worker_registrations` · `siem_export_cursors`

That is the honest size of the shared control plane: **15 of 81 tables, none of which contain
a tenant's own content** — they contain the tenant's *name*, its *plan*, the *grants imposed on
it*, the three hash→tenant indexes (credential, hostname, worker id) that exist only to
answer "which object?", and one export bookmark whose key is global on purpose.

### Correction: `audit_events` has a second writer, and it is not chained

The first draft justified C31's **derived** label with "`row_hash` travels with the row, so the
projection is self-verifying". That is true of the chained writer and **false for a whole
second one**, which the draft never mentioned. `sql/d1-ts/control/0003_audit_chain.sql:11-21`
states it plainly — the four chain columns are nullable partly because "`audit_events` has a
SECOND writer — the gateway's asset audit sink (`apps/gateway/src/assets/d1.ts`) — which is
not chained yet". Confirmed at `apps/gateway/src/assets/d1.ts:673-675`:

```
INSERT INTO audit_events (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json)
VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING
```

Six columns, no `chain_key`/`seq`/`prev_hash`/`row_hash`. For every row this sink writes,
`row_hash` is NULL, the projection carries nothing to verify with, and the verifier downgrades
to `inconclusive` (`0003_audit_chain.sql:18-21`). So the correct statement is narrower: **the
projection is self-verifying for chained rows and merely a copy for the asset sink's rows**,
and the migration either chains the second writer or accepts that a slice of the fleet audit
view is unverifiable by construction. The label stays **derived** — the chain key is still
`tenant`, which is still the object — but the reason it is *safe* now has an explicit hole in
it, and that hole should be closed in the same slice rather than discovered later.

Worse, and unremarked anywhere in the first draft: `D1AssetAuditSink.flush()`
(`apps/gateway/src/assets/d1.ts:735-757`) commits **one `batch()` mixing rows from multiple
tenants**. That is not incidental — the class docblock (`:706-714`) says the sink "is built
once per `env` and shared by every concurrent request in the isolate", and `event.tenantId` is
bound per row. Under the DO topology **a single batch cannot address more than one object**,
so this must become N transactions in N objects, which falsifies the docblock guarantee at
`:702-704` that "either all of a request's audit rows land or none do". The per-*request*
guarantee is recoverable (one request has one tenant); the per-*flush* batch is not. Step 2
owns this.

### The single most fragile query in the tree

`apps/control-plane/src/routes/admin_request_log.ts:868-905` — the investigation joins
`audit_events`, `agent_runs`, `agent_run_events` and `billing_events` pinned **only** by
`request_id IN (…)`. It is safe today because the ids came from two already-fenced tables at
`:824-847`. Under this classification those four legs live in the tenant object while the ids
that cleared them are gathered elsewhere, so the inherited fence evaporates. **Any slice that
touches C25, C28, C29 or C31 must re-establish an explicit tenant predicate on this query
first**, not after. `apps/mcp/src/approvals.ts:263-273` has the same shape (isolation rests on
`approvalFingerprint` being computed over the tenant, `:68` — a hash-collision argument rather
than a SQL predicate) and should be fixed in the same pass.

---

## Part 3 — `control_plane_resources` must split

One table, `PRIMARY KEY (resource_kind, resource_id)`, holding three unrelated populations.
The discriminator is not a column: `tenantScopeSql` (`apps/control-plane/src/store/d1.ts:190-199`)
fences on `json_extract(document_json, '$.tenant_id')`, and for a `platform_operator` scope it
returns **an empty predicate** — every platform-operator read is a full cross-tenant scan by
construction.

There is **no central registry of collection kinds** in the tree — I looked
(`grep -rn "ALL_COLLECTIONS\|COLLECTION_SPECS\|collectionRegistry" apps/control-plane/src` →
nothing). The list below is the union of `segment:` literals, `readOnlyCollection(` arguments
and `*_COLLECTION` constants. Treat it as complete-as-of-HEAD, not as guaranteed exhaustive;
the split slice should add the missing registry so this list stops being a grep artifact.

### 3a. Tenant-discriminated kinds → **tenant-private** (move into the object)

The document carries `$.tenant_id`; `tenantScopeSql`'s equality branch is the whole fence, and
inside an object the fence becomes structural.

`tenant-accounts`* · `projects` · `workspaces` · `virtual-keys` · `api-keys` ·
`quota-policies`§ · `agent-upstreams` · `agent-workflows` · `agent-schedules` ·
`agent-schedule-fires` · `agent-runs` · `agent-run-events` · `mcp-servers` ·
`tool-approvals` · `tool-sessions` · `tool-session-events` · `plugins` · `plugin-tools` ·
`skill-packages` · `prompt-templates` · `prompt-template-labels` · `policies` ·
`x402-spend-policies` · `wallets` · `wallet-ledger` · `payment-methods` ·
`payment-attempts` · `site-domains`† · `site-domain-verifications`† ·
`semantic-cache-policies` · `asset-reviews` · `asset-deletions` · `tenant-roles` ·
`self-hosted-workers` · `self-hosted-runs` · `self-hosted-run-events` ·
`self-hosted-run-dispatches` · `self-hosted-worker-artifacts` ·
`self-hosted-worker-checkpoints` · `self-hosted-worker-events` · `experiments` ·
`investigations` · `workflow-run-steps` · `metering-events`‡ ·
`billing-outbox-dead-letters`‡ · `usage-reports`‡ · `cost-record-exports`‡ ·
`request-log-exports`‡

\* `tenant-accounts` is the **document** for a tenant; its typed projection is C3 `tenants`,
which stays. The document moves, the registry row does not.
† these two documents move even though their typed tables (C19/C20) stay platform-shared —
the document is the tenant's authored intent, the table is the router's index.
‡ these are **derived**, not tenant-private: they are the document faces of C23/C25/C30.
§ `quota-policies` is tenant-private but **does not move in the Step 3 batch with the rest of
3a** — it moves in Step 4 with C9, the typed row it is the master of. See the ordering
correction in Part 4.

### 3b. Platform-global kinds → **platform-shared** (stay on control D1)

No `$.tenant_id` **at the key `tenantScopeSql` extracts**. That precision matters and the first
draft lost it — see the guardrail correction below. These are why `tenantScopeSql` has an
`IS NULL` disjunct — a tenant *reads* platform rows. **That disjunct is the reason the split
cannot be clean:** a tenant object will still need a control-D1 read for the platform half of
any collection it consumes.

`plans` · `permissions` · `roles` · `providers` · `provider-models` · `provider-health` ·
`models` · `gateway-configs` · `framework-adapters` · `extensions` · `runtime-state`
(singleton ids `drain`, `active-config`) · `d1_tenant_database` (Rust-era singleton registry
document, `packages/storage/src/tenant-router.ts:168`) · `guardrail-policies` ·
`guardrail-policy-revisions`

**Correction — `guardrail-policies` / `guardrail-policy-revisions` do name tenants.** The
first draft said these kinds have "no `$.tenant_id` at all", and that is wrong as written: the
scope selector parsed at `apps/control-plane/src/routes/guardrail_policy.ts:240-251` carries
`tenant_ids`, `organization_ids`, `project_ids`, `workspace_ids`, `api_key_ids` and more. They
name tenants — just not through the single `$.tenant_id` key `tenantScopeSql` reads, which is
why the fence does not fire on them. The **platform-shared label still holds**, on the
unscoped-revision argument alone: a revision with an absent `scope` is
`PolicyScopeSelector::default()` and matches **every** selection context (`:232-239`), so a
policy the governed tenant can neither see nor edit cannot live in that tenant's object. Only
the "no tenant identifiers" phrasing was false, and it is corrected here before someone builds
a projection on it.

### 3c. Read-only projections of a typed table → follow their table

Registered as collections but with no document writer; they list empty and exist so the admin
API has a uniform surface. Each takes the label of the typed table it fronts.

| kind | fronts | label |
|---|---|---|
| `tenants` | C3 | platform-shared |
| `request-logs` | C30 | derived |
| `audit-events` | C31 | derived |
| `guardrail-evaluations` | C46 | derived |
| `cost-records` | C25 | derived |
| `usage-aggregates` | T10 | derived |
| `agent-cost-burn` | T20 | tenant-private (via the capped fan-out) |
| `managed-workers` | C33 | tenant-private |
| `managed-worker-sessions` | C34 | tenant-private |
| `self-hosted-worker-records` | C39 | platform-shared |
| `spend-anomalies` | C53 | derived |
| `metering-export-status` | C24 | tenant-private |
| `observed-agent-activity` | T19 | derived |
| `tools` | plugin registry | tenant-private |

### The split verdict

`control_plane_resources` **cannot move as a unit and cannot stay as a unit.** It becomes two
tables with the same DDL:

- `control_plane_resources` on control D1 — 3b only, and `tenantScopeSql` collapses to
  "platform documents are visible to everyone", losing its tenant branch entirely.
- `tenant_resources` inside each object — 3a, with **no scope predicate at all**, because the
  object is the scope.

**Correction — `tenantWriteScopeSql` does not go away with the tenant branch.** The first
draft justified deleting it with "it exists solely to stop a document write crossing tenants,
and a predicate that can be forgotten is worse than a boundary that cannot be." Its actual
docblock (`apps/control-plane/src/store/d1.ts:202-218`) says something different and stronger:
it exists so the `IS NULL` disjunct cannot survive into an `UPDATE`/`DELETE`, because with it
a tenant-scoped caller holding `admin.write` — an ordinary tenant administrator — "could edit
or delete any platform row: a global `role`, a shared `policy`, a `plan` other tenants are
billed against."

That is a tenant→**platform** write, not a tenant→tenant one, and **the object boundary does
not subsume it**: 3b deliberately leaves the un-attributed platform documents on control D1,
and this very section concedes a tenant object "will still need a control-D1 read for the
platform half of any collection it consumes." A read path into control D1 that a tenant can
reach is a write path someone will wire next. So:

- the object's `tenant_resources` needs no predicate — correct, the object is the scope;
- **`tenantWriteScopeSql` stays on the control-D1 half**, unchanged, guarding the population
  it was actually written for. Only `tenantScopeSql`'s *tenant* branch is deleted.
- its in-memory twin `writableBy` (`store/query.ts:74-77`, `record.tenant_id ===
  scope.tenantId`) stays for the same reason. `quota-self-escalation.test.ts:40-49` calls it
  load-bearing in so many words, and `tenant-write-fence.test.ts` pins it.

Two reads must survive the split and neither is fenced today:

- `apps/control-plane/src/adapters.ts:431-448` — `#activeSnapshot`/`#count` with
  `{kind:"platform_operator"}` and `limit: MAX_SAFE_INTEGER`; `GET /admin/v1/status` counters
  become a projection read, not a scan.
- `apps/control-plane/src/store/lifecycle.ts:263,273,282` — `GATE_SCOPE` reads the
  workspace/project/tenant-account by bare id across tenants on **every admission**. That is
  deliberate (docblock `:29`) and it is the one place the split forces a real decision: either
  the gate reads the object (a hop on the request path) or the lifecycle status is projected
  into control D1 alongside C3.

---

## Part 4 — sequenced migration plan

Ordered by risk, lowest first. The ordering principle: **a step is low risk when it is
append-only and reversible by deleting the copy that was written second.** A step is high risk
when a torn write loses money or admits a request that should have been refused.

Every step assumes the object and its schema already exist. Step 0 is not optional.

### Step 0 — the object, its schema, and the registry hardening

Move: nothing. Build: `TenantDataObject`, the migration applier, the `D1Database` facade,
the `durable_object` routing mode, and — **before any data moves** — the existence gate.

Because `idFromName` resolves every string, C3/C4 must be checked *before* an object is
addressed. Without this, step 1 is a hostile-input object-creation primitive.

> **Transactional coupling: none, and that is the point.** Nothing dual-writes yet. The whole
> step is verifiable by `packages/storage/test/d1/router.test.ts`-shaped isolation proofs
> against DO stubs plus a `9_000_000_000_000_000_000`-credit round trip through
> `balanceCreditsExact()` proving `bindCredits()`/`creditsFromText()` still refuse a lossy
> decode.

### Step 1 — high-volume append-only evidence (lowest risk)

Tables: **C30 `request_logs`**, **C29 `agent_run_events`**, **C41
`self_hosted_worker_telemetry_events`**, **C35 `managed_worker_lifecycle_events`**.

Why first: append-only, never updated, never the input to an admission decision. A row written
to both places is a duplicate, not a conflict. Rollback is "stop writing to the object".

> **Transactional coupling: none required.** These are fire-and-forget writes today
> (`requestlog/queue.ts:124` already batches them off the request path). Dual-write with the
> control D1 write as the source of truth; cut over the read when the projection is proven.
> The `WHERE tenant = ?` fence at `requestlog/retention.ts:192` — which is an **empty string**
> when no tenant is named — becomes a per-object alarm and stops being fleet-wide.

### Step 2 — the rest of the evidence plane, and the investigation fence

Tables: **C28 `agent_runs`**, **C31 `audit_events`**, **C46 `guardrail_evaluations`** +
**C47 `guardrail_check_evaluations`**, **C38 `managed_worker_isolation_evidence`**,
**C51/C52 online-eval**, **C56 `experiment_shadow_legs`**. C49 `siem_export_cursors` is
**no longer in this step** — it is platform-shared and does not move at all.

Prerequisite, hard: the tenant predicate on `admin_request_log.ts:868-905` and
`:655-666`. Do it in this step's first commit.

> **Transactional coupling: three real couplings.**
> (a) C46↔C47 must move in one step — the child has only `evaluation_id`.
> (b) C31's chain-head read and append must be in **one `transactionSync`**. Today it is an
> optimistic read-then-insert retried against `UNIQUE (chain_key, seq)`
> (`store/d1.ts:1042-1084`); inside the object it becomes a genuine serialization and the retry
> loop should be **deleted, not kept** — a retry loop around a real transaction hides a
> deadlock as a latency spike.
> (c) **C31's second writer must be split per tenant before C31 moves.**
> `D1AssetAuditSink.flush()` (`assets/d1.ts:735-757`) commits one `batch()` carrying rows from
> every concurrent request in the isolate, i.e. from several tenants. A batch cannot address
> two objects. Partition `#pending` by `event.tenantId` and commit one transaction per tenant,
> and **update the docblock at `:702-704`** — "either all of a request's audit rows land or
> none do" survives (a request has one tenant), the implicit flush-wide version does not. This
> is a code change that must land *before* the table moves, not with it.
>
> **Ordering correction.** The first draft's note (c) read: "C49 must land in the same commit
> as C30/C31 or the exporter resumes from a cursor that points into a database it no longer
> reads." That note was inconsistent with its own plan — **C30 `request_logs` is in Step 1**,
> not Step 2, and `request_logs` is one of exactly two SIEM streams
> (`apps/control-plane/src/siem/config.ts:44-46`). So the plan created precisely the
> split-brain the note forbade, one step wide. Reclassifying C49 as platform-shared dissolves
> the contradiction rather than papering over it: the cursor never moves, so there is no commit
> it must land in. What replaces the note is a **reader** obligation — `readSiemCursor`
> (`siem/cursor.ts:75-86`) is tenant-anonymous today, and once the rows live in objects the
> pump must resolve the sink's `tenant` column to an object *before* it reads. A cursor read
> that still does not name a tenant is now a bug that delivers nothing rather than a bug that
> delivers the wrong rows, but it is still a bug. Fix it in Step 1, alongside C30.

### Step 3 — tenant configuration and secrets

Tables: **C45 `tenant_provider_credentials`** (first — it is the cleanest and the security win
is immediate), **C57–C59 the MCP identity tables** (second, and for the same reason — see
below), **C17 `sso_provider_configs`**, **C13 `tenant_role_bindings`**, **C48
`semantic_cache_policies`**, **C50 `delegation_revocations`**, **C22
`control_plane_replay_floors`**, **C21 `budget_alert_notifications`**, **C32–C37, C40, C42–C44**
(the worker plane), and the 3a half of **C2 `control_plane_resources`** — **minus
`quota-policies`, which moves in Step 4** (see that step).

> **Transactional coupling: one reverse projection and one ordering rule.**
> C13 needs `roles.permission_keys_json` pushed *down* into each object — the only downward
> projection in this document — and the object's copy must be refreshed on every role edit or a
> revoked permission stays granted. That makes it fail-**open** if done lazily, so the role
> edit must fan out synchronously or the object must read control D1 for the join until it
> does. C32–C37 move as one unit (C37 has no tenant column and is reachable only via C34).

> **C57–C59 bring a migration-shape decision the rest of this plan does not have.** They are
> the only tables in the fleet whose schema is applied *at runtime from application code*
> rather than from `sql/d1-ts/`, and two of that mechanism's properties do not survive the
> move:
> 1. `ensureMcpIdentitySchema` guards on a **per-isolate `WeakSet<D1Database>`**
>    (`apps/mcp/src/durable.ts:129,141`), which is a cache, not a ledger. Inside the object the
>    guard becomes T1 `storage_schema_migrations` consulted in the constructor under
>    `ctx.blockConcurrencyWhile` — a real ledger, and the reason no request can observe a
>    half-migrated database.
> 2. `MCP_IDENTITY_ADDED_COLUMNS` (`:126`) is an unconditional `ALTER TABLE` whose
>    `duplicate column name` error **is the success case** (`:113-124`), run deliberately
>    *outside* the schema batch because that expected failure would roll the batch back. Under
>    a versioned applier that pattern has no reason to exist and must not be carried over: the
>    `ALTER` becomes a numbered migration that runs once, and an error from it becomes an error
>    again. Keeping "the exception is the happy path" inside `blockConcurrencyWhile` would mean
>    a genuinely failed migration is indistinguishable from a completed one, on a constructor
>    path that cannot be retried by the caller.
>
> The prize justifies the sequencing: C57 holds per-end-user OAuth **refresh** tokens. It is
> the most residency-sensitive table in the tree and it is currently outside the residency
> boundary this whole document exists to draw.

### Step 4 — quotas and throttles, with the governance seam

Tables: **C9 `quota_policies`**, **C55 `spend_throttles`**, **C53 `spend_anomaly_episodes`**,
and — moved here from Step 3 — the **`quota-policies` document kind** (the 3a half of C2 that
C9 is projected from).

This is where the classification stops being mechanical. These rows are ceilings imposed on
the tenant, and today the enforcement is database separation. The step is not done when the
rows move; it is done when `TenantDataObject` has a split write surface — operator-only RPCs
for these three tables, tenant-reachable RPCs for everything else — and a test proves the
tenant-facing path cannot reach them. `quota-self-escalation.test.ts` is the shape to copy and
must be re-pointed at the object, not deleted.

> **Ordering correction: the governance seam cannot open one step late.** The first draft put
> the `quota-policies` **document** in the Step 3 batch and the typed row C9 here in Step 4 —
> and the document is the master. `projectQuotaPolicy`
> (`apps/control-plane/src/store/quota_registry.ts:419-441`) projects it into "the typed
> `quota_policies` row the gateway's admission gate reads on every authenticated request", so
> whoever can write the document sets the ceiling. Landing it in `tenant_resources` — which
> Part 3 specifies as having **no scope predicate at all** — a full step before the
> operator-only write surface exists opens a self-escalation window on the ceiling: exactly
> the defect `apps/control-plane/test/quota-self-escalation.test.ts` was written to pin
> (`:9-12`, "a ceiling its subject can lift is not a ceiling"). Master and projection move in
> the same step as the seam that guards them, or not at all.

> **Transactional coupling: read-side atomicity gets stronger, write-side gets a new fence.**
> The admission read (`ratelimit/quota.ts:601` + the plan join + the wallet balance) becomes one
> local synchronous read instead of a control-D1 round trip plus a routed one — which also
> removes the window in which a throttle was written between the two. The projection **up** for
> `finops/pass.ts:414` is eventually consistent and must be, because a fleet pass that blocked
> on every object would take the whole fleet's latency.

### Step 5 — schedules, and the tick becomes an alarm

Tables: **T17 `agent_schedules`**, **T18 `agent_schedule_fires`**.

The largest behavioural change: `schedule/engine.ts:556` lists every tenant's schedules
unpaginated on every tick. That becomes each object's own `alarm()`.

> **Transactional coupling: the at-most-once gate becomes real, and one `requireAtomicBatch`
> site the first draft missed.** Today the fire claim is `INSERT … ON CONFLICT DO NOTHING
> RETURNING fire_id` against `UNIQUE (schedule_id, scheduled_fire_at_unix)`
> (`agent-schedule-d1.ts:82`) with `advanceSchedule` reading `meta.changes` at `:342`. Inside
> one `transactionSync` the claim and the advance commit together, so the "fired but not
> advanced" and "advanced but not fired" windows both close. **Do not keep the
> `INSERT OR IGNORE` and the transaction** — one of them is now redundant and keeping both
> hides which one is load-bearing.
>
> The third site in this step is `deleteSchedule` (`agent-schedule-d1.ts:416`,
> `delete_agent_schedule`) — a two-statement batch that deletes the fire ledger and then the
> schedule. Its docblock (`:405-414`) says why the cascade is mandatory rather than hygiene:
> D1 has no cross-table FK, so "a surviving fire ledger would make a schedule re-created with
> the same id believe its early slots had already fired — and the at-most-once gate would then
> suppress every one of them, silently, forever." That is the same invariant as the claim
> above, approached from the delete side, and it is the site whose torn write is silent.
> Note it also reads `results[1]` positionally, so constraint 2 of Step 8 (batch result arity)
> applies here too.

### Step 6 — assets

Tables: **T13 `stored_assets`**, **T14 `asset_channels`**, **T21 `asset_bundle_files`**,
**T15 `retention_policies`**.

> **Transactional coupling: three `requireAtomicBatch` sites become real transactions.**
> `create_asset_within_quota` (`assets-d1.ts:241`), `move_asset_channel_if_resolvable` (`:508`)
> and `set_asset_version_yank` (`:563`). The `pending_scan → visible|quarantined` promotion CAS
> at `:418` reads `meta.changes` — and `SqlStorageCursor` exposes only `rowsRead`/`rowsWritten`,
> **neither of which is SQLite's `changes()`**. The facade must synthesize `meta.changes` with
> a `SELECT changes()` inside the same transaction; faking it as `rowsWritten` publishes an
> unscanned artifact. This step is the natural place to prove that, because the failure is
> loud. The R2 bytes do not move — `stored_assets` never carried them (`assets-d1.ts:139-140`).

### Step 7 — usage rollups

Tables: **T9 `tenant_contexts`**, **T10/T11/T12 the three `usage_*_rollups`**, **T19
`observed_agent_presence`**, **T20 `agent_cost_burn`**.

> **Transactional coupling: `persist_usage_aggregate` (`usage-d1.ts:152`) is a single
> `requireAtomicBatch` over `2 + scopes.length + metadataPairs.length` statements** — an
> unbounded batch that becomes one `transactionSync`. This is the step where the DO's row-write
> billing bites (design doc cost #6), so batch inside the transaction rather than looping RPCs.
> The upward projection for platform billing starts here and must be idempotent by
> `(tenant, period)`, because an alarm that retries after a partial push must not double-count.

### Step 8 — billing and the wallet, together, LAST

Tables: **T5 `wallets`**, **T6 `wallet_reservations`**, **T7 `wallet_settlements`**, **T8
`payment_methods`**, **T16 `workflow_run_budgets`**, **C23 `billing_ledger`**, **C24
`billing_report_outbox`**, **C25 `billing_events`**.

**Why last, and why one step.** These eight tables are one consistency domain. A settlement
debits `wallets`, closes a `wallet_reservations` hold, appends `wallet_settlements`, writes a
`billing_ledger` entry, appends a `billing_events` row and enqueues a `billing_report_outbox`
row. Today that is *two* databases and the atomicity claim is only half true — the control
comment at `0001_init_control.sql:617-620` says the event/outbox pair is atomic **"because both
rows are here"**, which is precisely an admission that the wallet half is not in the same
commit. Moving the wallet tables without the billing tables (or vice versa) does not preserve
that; it makes the gap wider and puts a network hop in the middle of it.

> **Transactional coupling: total. This is the step the whole design exists for.**
> Five `requireAtomicBatch` sites collapse into one synchronous transaction: `reserve`
> (`wallet-d1.ts:317`), `settle_reservation` (`:448`), `release` (`:557`), `sweep_expired`
> (`:601`), `settle_balance` (`:665`), plus the three `workflow_run_budgets` sites.
> Three constraints the step must not relax:
> 1. **`RETURNING` is the CAS**, not `meta.changes` — `wallet-d1.ts:347` is the no-oversell
>    guard and an empty result set means *not admitted*. It must stay empty-means-refused.
> 2. **`batch()` returns exactly one result per statement, in order.** `wallet-d1.ts:377-381`
>    and `billing-d1.ts:182-189` assert this by hand, the latter noting a short response would
>    make "every settled call look like a replay and never be billed".
> 3. **Credits are int64 and JS decodes 53 bits.** `bindCredits()` sends a decimal string and
>    `creditsFromText()` **throws** on a lossy decode (`packages/storage/src/credits.ts:122-155`).
>    The facade must not "helpfully" coerce; the loud throw is the feature.
> 4. **The outbox pump is a fleet-wide scan and there is no DO shape for it.** The first draft
>    listed none of this. `BILLING_OUTBOX_LIST_DUE_SQL` (`gateway/src/metering/d1.ts:187-196`)
>    joins `billing_report_outbox` to `billing_ledger` `WHERE dead_lettered_at_unix IS NULL AND
>    next_attempt_unix <= ?`, `ORDER BY next_attempt_unix, id`, `LIMIT ?` — **no tenant
>    predicate, globally ordered, globally limited.** This is not a dashboard; it is the thing
>    that actually delivers billing reports, so "convert the pull to a push" is the redesign,
>    not a footnote: each object drains its own outbox from its own `alarm()`, the global
>    ordering becomes per-tenant ordering (acceptable — the `id` tiebreak was never a
>    cross-tenant fairness guarantee), and the global `LIMIT` becomes a per-object one. The
>    fleet dead-letter listing becomes the `billing-outbox-dead-letters` projection.
> 5. **C24 and C25 have no tenant column.** The tenant is inside `event_json`
>    (`routes/billing.ts:174`). Add a real `tenant` column in the same migration that moves
>    them — an object cannot be addressed by a value that has to be JSON-parsed out of a blob,
>    and a backfill that parses it once is cheaper and more auditable than every reader doing
>    so forever. The second DDL source at `gateway/src/metering/d1.ts:102-133` must change in
>    the same commit.
>
> Rollback for this step is not "stop writing to the object" — once a reservation lives there,
> the ledger of record has moved. Cut over behind a per-tenant flag, one tenant at a time, with
> the balance reconciled before and after.

### Step 9 — retire the shared halves

Drop **C7 `gateway_providers`** and **C8 `gateway_models`** (dead: zero readers, zero writers —
`store/d1.ts:1160` already says so). Re-evaluate **C54 `spend_anomaly_runs`** (no subject if
detection moved into alarms in step 4) and **C16/C18** (both flip to tenant-private with a
token/state format change, which is a smaller diff than the migration would be). Split
`control_plane_resources` per Part 3 and delete `tenantScopeSql`'s tenant branch.

---

## Execution sub-issues (ordered)

The issue was written against a 78-table census. The live schema is now **81 tables**:
56 tables from `sql/d1-ts/control/`, 3 MCP identity tables created by application code, and
22 tables from `sql/d1-ts/tenant/`. The three runtime-created tables are included as C57-C59
above; the issue title keeps the original 78-table wording for history.

The classification is deliberately separate from the moves. These are the nine PR-sized
scopes attached to #831. Their order preserves the risk order in Part 4, while some scopes
group or split Part 4 steps: #859 includes the investigation-linked `agent_runs`, #852 carries
the worker telemetry and usage projections, and #861-#863/#856 divide the control-plane, MCP,
configuration, worker, and schedule work. The Part 4 step sections remain authoritative for
each table's transactional coupling and reader prerequisite:

| step | scope | sub-issue |
|---|---|---|
| 1 | `request_logs`, `agent_runs`, `agent_run_events` | [#859](https://github.com/lianluo-esign/ferrogate/issues/859) |
| 2 | guardrail evidence and policy state | [#860](https://github.com/lianluo-esign/ferrogate/issues/860) |
| 3 | split `control_plane_resources` by document kind | [#861](https://github.com/lianluo-esign/ferrogate/issues/861) |
| 4 | MCP registrations, credentials, and identity generations | [#862](https://github.com/lianluo-esign/ferrogate/issues/862) |
| 5 | tenant configuration, secrets, and policy records | [#863](https://github.com/lianluo-esign/ferrogate/issues/863) |
| 6 | managed/self-hosted workers and schedules | [#856](https://github.com/lianluo-esign/ferrogate/issues/856) |
| 7 | assets and retention state | [#851](https://github.com/lianluo-esign/ferrogate/issues/851) |
| 8 | usage, evaluation, audit, and derived rollups | [#852](https://github.com/lianluo-esign/ferrogate/issues/852) |
| 9 | billing and wallet state as one consistency domain | [#858](https://github.com/lianluo-esign/ferrogate/issues/858) |

The sub-issues are attached to #831 in this order. A later move cannot start until its named
cross-tenant reader and transactional coupling are covered by the earlier slice or by #825.

## What this document does not decide

- **Where the projection lands.** Alarm→control-D1 write vs alarm→Queue→consumer is a
  throughput question the projection slice owns. Every "derived" row above states *that* a
  projection exists and what it must key on, not how it is transported.
- **The residency default.** `jurisdiction("eu")` is per-namespace-handle and must be chosen
  at first `get()`; which tenants get which jurisdiction is a product decision.
- **Whether `request_logs` eventually leaves the object again.** Design doc cost #2 keeps that
  seam open deliberately; step 1 puts it in the object because that is where the tenant fence
  is, not because it should live there forever.
