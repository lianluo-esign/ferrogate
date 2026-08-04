# `@ferrogate/storage`

The persistence boundary for the FerroGate control plane and its per-tenant
financial / usage / asset state. Clean-room TypeScript re-implementation of the
Rust crate `ferrogate-storage`.

The package has two halves:

| half | where | tested by |
|---|---|---|
| **pure algorithms** + their in-memory reference backends (`Memory*Store`) | `src/*.ts` | `vitest.config.ts` — plain vitest, 87 tests |
| **durable D1 backends** + the tenant router | `src/d1/*.ts`, `src/tenant-router.ts` | `vitest.d1.config.ts` — `@cloudflare/vitest-pool-workers`, real `workerd` + real D1 SQLite, 96 tests |

`bun run test` runs both. The in-memory stores are **not** superseded by the D1
ones: they remain the executable specification of every invariant, and the D1
suite asserts the same observable outcomes, so a divergence between the two
backends is a test failure (`test/d1/workflow-budget-d1.test.ts`, "parity with
the in-memory reference backend").

---

## 1. Databases: one CONTROL + one per TENANT

The user directive for this rewrite is **one D1 database per tenant plus an
account-global control database**. Migrations live in `sql/d1-ts/`:

```
sql/d1-ts/
  control/0001_init_control.sql   # applied ONCE, to the account-global database
  tenant/0001_init_tenant.sql     # applied ONCE PER TENANT, to that tenant's database
```

This is a genuine split, not a convention. The Rust-era `sql/d1/001_init_d1.sql`
provisioned **one** file into **both** roles — every table existed in every
database, and only the backend remembered which role owned a family. A routing
bug therefore wrote a control row into a tenant database (or vice versa) and
nothing complained, because the table was there. Here a control-only table does
not exist in a tenant database, so a mis-routed write fails loudly with
`no such table`. `test/d1/schema.test.ts` asserts the split table-by-table in
both directions.

### The split rule

A family lives in **CONTROL** when any of these hold:

| rule | why | examples |
|---|---|---|
| **(a)** account-global configuration shared across tenants | there is no tenant to route it to | `plans`, `permissions`, `roles` |
| **(b)** read on a path that has **no tenant id yet** | the lookup is what *produces* the tenant id, so it cannot be tenant-routed | `api_key_directory`, `static_api_keys`, `site_domains`, `quota_policies`, `sso_pending_flows` |
| **(c)** rows span tenants by nature | one human belongs to several tenants, so the edge fits in no single tenant database | `tenants`, `tenant_databases`, `admin_user_tenant_memberships` |
| **(d)** whole-table, time-ordered, `count(*)`-paginated cross-tenant analytics | the `tenant` column is a **composite storage key**, not a routing key; sharding would turn every list into a lossy fan-out merge-sort plus fetch-all-then-slice pagination | `request_logs`, `audit_events`, `agent_runs`, `billing_*`, `guardrail_*`, managed/self-hosted worker stores |

Everything else is **TENANT**-scoped.

### The table map

**CONTROL** — `sql/d1-ts/control/0001_init_control.sql`

```
tenants  tenant_databases  control_plane_resources  control_plane_replay_floors
plans  quota_policies  permissions  roles  tenant_role_bindings
admin_users  admin_user_tenant_memberships  admin_user_refresh_tokens
sso_provider_configs  sso_pending_flows
site_domains  site_domain_verifications  budget_alert_notifications
api_key_directory  static_api_keys
billing_ledger  billing_report_outbox  billing_events
guardrail_policy_revisions  guardrail_policy_bindings
agent_runs  agent_run_events  request_logs  audit_events
managed_worker_*  agent_worker_instances  self_hosted_worker_*  self_hosted_run_dispatches
```

**TENANT** — `sql/d1-ts/tenant/*.sql`, one routed tenant database or Durable Object

```
projects  workspaces  api_keys
wallets  wallet_reservations  wallet_settlements  payment_methods
tenant_contexts  usage_aggregate_rollups  usage_monthly_rollups  usage_metadata_rollups
stored_assets  asset_channels  retention_policies
workflow_run_budgets
agent_schedules  agent_schedule_fires
observed_agent_presence  agent_cost_burn
tenant_database_identity  provider_channels  catalog_models
catalog_model_offerings  catalog_revisions
```

### Divergences from the Rust D1 file, stated so they are auditable

Column names are **parity** — a rename is a silent break, because the Rust
reader would still compile, the row would still write, and the value would
simply stop arriving. `test/d1/schema.test.ts` pins the column lists of the
load-bearing tables. Four deliberate divergences:

1. **`api_keys` gains a control-database lookup index.** The Rust backend put
   `api_keys` only in the tenant database and resolved a bearer credential by
   **fanning out** across every provisioned tenant database. That is defensible
   on an admin path and indefensible on the inference hot path — authenticating
   one `/v1/chat/completions` would cost N round trips for N tenants, and the
   fan-out is itself a cross-tenant read. So the full `api_keys` row (scopes,
   allowlists, budgets — all tenant data) stays physically isolated, and the
   control database gains `api_key_directory` holding only hash → tenant plus
   the two fail-closed lifecycle columns. This is the minimum answer to the
   chicken-and-egg in the router: something must resolve credential → tenant,
   and that something cannot itself be tenant-routed.

   **The cost is a dual write.** Four columns exist twice, in different
   databases, so there is no transaction spanning them. The ordering rule is
   fail-closed: **create** writes the tenant row first then the directory;
   **revoke** writes the directory first then the tenant row. A crash between
   the two legs, in either direction, leaves a key that cannot authenticate.

2. **`stored_assets.content` is dropped.** The Rust column held ≤10 MiB of
   base64 inline body because the D1 HTTP proxy bound every parameter as TEXT.
   Running inside a Worker with R2 available, inventory §1.7 is explicit that
   inline BYTEA moves to R2, so only `content_hash` / `size_bytes` /
   `storage_uri` remain — which is everything the quota-admission guard reads.
   That ordering is now implemented: `commitAssetWithBlob`
   (`src/d1/assets-r2.ts`) writes the R2 object **before** the row and
   compensates (deletes) on a failed or refused insert, because **no
   transaction spans R2 and D1**. A crash between the two leaves an orphan
   object that no read path can name; `R2AssetBlobStore.deleteOrphans` reclaims
   it.

3. **The model/provider registry is tenant-owned catalog data.**
   `provider_channels` stores endpoint and secret-reference metadata,
   `catalog_models` stores the logical client-facing SKU, and
   `catalog_model_offerings` stores one upstream leg and its price. A model can
   therefore have several channels and prices without duplicating the logical
   model. The new schema's role/binding uniques and real foreign keys carry the
   loader invariants; **credentials are never stored** — `api_key_var` names a
   secret binding. The gateway still uses `GATEWAY_PROVIDERS` /
   `GATEWAY_MODELS` until #812 makes this graph the runtime source.

4. **`tenant_databases` is a new control table.** Rust kept the tenant→database
   registry only as a `control_plane_resources` JSON document, because it reached
   D1 over HTTP by uuid. In-Worker a handle is a *binding name*, so the registry
   must carry that too, and the hot path wants a point lookup. The document key
   is still named (`TENANT_DATABASE_REGISTRY_KIND`) so a Rust-era control
   database can be read and migrated.

Two `CHECK` constraints are kept against the "enumeration CHECKs are dropped"
convention, because both are **join keys / privilege tiers** rather than
descriptions: `admin_user_tenant_memberships.role` (#517) and
`usage_monthly_rollups.scope_type`. A typo'd scope silently creates a parallel
rollup that no budget check reads, and the spend becomes invisible.

---

## 2. Runtime routing: `TenantDatabaseRouter`

### The constraint

Cloudflare resolves bindings at **deploy** time. A `[[d1_databases]]` stanza
becomes a property on `env`, and **there is no runtime API to open D1 database
`<uuid>`**. This is the biggest architectural open question in the port
(inventory §1.7), and it is why the Rust tree needed a `d1-proxy` Worker
(#450): the D1 **REST** query API *can* address a database by uuid at runtime,
but it **cannot run an atomic `batch()`** — the multi-statement primitive every
money-path guard here is built on.

> **Corrected.** This paragraph used to add "and cannot return `RETURNING`
> rows". That is **wrong**: the `/query` response is
> `{ result: [{ results, … }] }`, one entry per statement, and `results` is
> exactly where a `RETURNING` clause's rows land — `D1RestDatabase` reads it and
> `test/d1/rest-transport.test.ts` drives a guarded `UPDATE … RETURNING` through
> it. The error mattered in the expensive direction: an engineer who believes a
> single-statement CAS cannot report whether its guard held will replace it with
> a SELECT-then-UPDATE, and that read-then-write *is* the oversell.

### The resolution

Bindings are *declared* at deploy time but **selected at runtime by name**:
`env` is an ordinary object, so `env[bindingName]` is a runtime lookup over a
deploy-time-declared set. The router therefore needs no bind-by-uuid API — it
needs a **registry** mapping tenantId → binding name, which is the control
database's `tenant_databases` table.

`EnvBindingTenantDatabaseRouter` implements exactly that, and yields a **native**
`D1Database` per tenant: real `batch()`, real `RETURNING`, and the whole
`d1-proxy` HTTP hop disappears.

### The four strategies, honestly compared

Encoded as `D1_BINDING_STRATEGIES` in `src/tenant-router.ts` and asserted by
`test/d1/router.test.ts` and `test/platform-limits.test.ts`, so this table
cannot silently rot.

| strategy | atomic `batch()` | `RETURNING` | deploy per tenant? | tenant ceiling | extra hop |
|---|---|---|---|---|---|
| **`native_binding`** — one `[[d1_databases]]` stanza per tenant; `env[name]` selects it | yes | yes | **yes** | low hundreds | no |
| **`proxy_service`** — a proxy Worker holds the bindings behind a `[[services]]` binding (the `d1-proxy` shape, minus the public HTTP hop) | yes | yes | yes, but only the proxy redeploys | low hundreds per proxy; shard beyond | yes |
| **`rest`** — D1 HTTP query API, runtime uuid | **no** | yes | **no** | unbounded | yes |
| **`durable_object`** — one SQLite-backed DO per tenant, `env.TENANT_DATA.idFromName(tenantId)` | **yes** | yes | **no** | unbounded; 10 GB per object | yes (one stub hop per `batch()`) |

**The cell that used to be empty.** For three strategies, "atomic `batch()`" and
"no deploy per tenant" were mutually exclusive, and `test/platform-limits.test.ts`
pinned that as an empty set. `durable_object` (#822/#823,
`docs/design/per-tenant-durable-object-storage-2026-08.md`) fills it — not by
finding a transaction envelope in the D1 HTTP API (that question is still open
and still `false`), but by leaving D1 for the tenant plane. A Durable Object is
created by being addressed, so onboarding is not a deploy, and
`ctx.storage.transactionSync()` is a real SQLite transaction, so `batch()` is one
commit. `src/tenant-do.ts` is a `D1Database`-shaped facade over
`src/tenant-data-object.ts`, which is what lets the tenant-plane modules
under `src/d1/` run over it **unmodified** — `test/d1/**` executes twice, once
per backend (`vitest.d1.config.ts` and `vitest.d1do.config.ts`), and that is the
acceptance test rather than a facade-shaped suite that would agree with the
facade by construction.

**The honest tradeoff among the D1 three.** `native_binding` is what to deploy
today, and its price is that onboarding a tenant requires a `wrangler deploy` and
the tenant count is capped by the Worker's binding budget. `rest` is the only D1
strategy with no deploy-time coupling — and it is **unusable for the money
paths**. There is no
envelope over the query API that makes N statements one commit, so the wallet
reserve's 3-statement guard would become three independent round trips with a
race window between the guard and the insert. That is not a slower reserve, it
is an **oversell**. Two postures ship, both fail-closed:

- `D1RestTenantDatabaseRouter` (`src/tenant-router.ts`) **throws** on
  `forTenant`. This is the "REST is not an option for this deployment" posture,
  and the right default for anything touching money.
- `NonAtomicD1RestTenantDatabaseRouter` (`src/tenant-rest.ts`) hands back a
  handle with `supportsAtomicBatch: false`, so `requireAtomicBatch` — which
  every guarded write in `src/d1/` calls first — turns the no-oversell reserve
  into an **error** rather than a non-atomic read-then-write. Reads and
  single-statement guarded writes go through.

A stub that "worked" for reads and silently lost atomicity on writes would be
the more dangerous artifact than either.

`PORT-TODO(inventory-data-billing §1.7 "per-tenant D1 binding at runtime")`: the
unresolved half was the path past a few hundred tenants. **(i) landed** —
`NonAtomicD1RestTenantDatabaseRouter` is REST restricted to what it can serve
safely, mounted in `apps/gateway/src/tenancy/resolver.ts`. **The path itself is
now `durable_object`**, which needs neither (ii) sharding across proxy Workers
nor (iii) a D1 API offering a runtime-addressed transaction: it obtains runtime
addressing and a real transaction from the same primitive. (iii) remains
genuinely open *for D1* — see the OPEN QUESTION on the `rest` entry in
`src/tenant-router.ts`, which is deliberately *not* asserted because it cannot be
verified locally and guessing wrong is an oversell.

The WIRING landed in #819 and this paragraph used to deny it. For the record,
because a stale claim is worse than none: `DurableObjectTenantDatabaseRouter` is
constructed on the `durable_object` branch of
`apps/gateway/src/tenancy/resolver.ts`, that branch is the committed DEFAULT
(`GATEWAY_TENANT_DB_ROUTING = "durable_object"` in `apps/gateway/wrangler.toml`),
and `test/mount-inventory.test.ts` accordingly carries the symbol in `MOUNTED`.
`DurableObjectD1Database` is the one that stays in `DEAD`, and deliberately: no
app names it, because the router constructs it — a transitive mount, which is a
weaker claim than a direct one.

What IS still open is that the two Workers do not agree about where a tenant's
rows live. `apps/gateway` routes on the DO; `apps/control-plane` resolves its
tenant-data paths through `EnvBindingTenantDatabaseRouter` unless the roster row
says `durable_object` (see `resolveTenantDatabases` there). Every call site that
predates the roster still depends on that dispatch being right.

### Fail-closed is the invariant

Every unresolvable tenant is an **error**, never a fallback. There is
deliberately no "default database" parameter. A router that quietly returned the
control database on a miss would write one tenant's money into the
account-global ledger. The refusals, each covered by a test:

| situation | outcome |
|---|---|
| tenant not in `tenant_databases` | `StorageError` `not_found` |
| registered but `binding_name IS NULL` (provisioned, not yet redeployed) | `runtime` — refuses, does **not** fall back |
| `binding_name` names a binding this Worker does not have | `runtime` |
| `binding_name` names a non-D1 binding (a var, a KV namespace) | `runtime` |
| empty tenant id | `runtime` |

`SharedDatabaseTenantRouter` routes every tenant to one database and provides
**no physical isolation**. It is a separate named class rather than a flag so it
cannot be reached by a config typo, and so a code search finds every deployment
that accepted the tradeoff. Legitimate uses: `wrangler dev --local`, and a
genuinely single-tenant self-hosted deployment.

---

## 3. Atomicity: the concurrency proofs

All three are tested against **real D1 in `workerd`**, never a fake — a fake's
`batch()` is atomic because the fake says so, which is precisely the
green-but-vacuous test this repo keeps being bitten by.

### Wallet reserve — no oversell (`D1WalletStore`, §1.5.1/§1.5.2)

Postgres used `SELECT ... FOR UPDATE`. **D1/SQLite has no row lock**, so the
decision cannot be made in the application and then written — another isolate
commits in the gap. The fix is to stop deciding in the application: the guard
becomes part of the *writing statement*.

One `batch()`, three statements:

| # | statement | why it is in the batch |
|---|---|---|
| S0 | idempotency probe by hold id | a replay must return the first outcome; probing outside the batch would race a concurrent first insert |
| S1 | `INSERT ... SELECT ... WHERE ? <= balance - SUM(live holds) ON CONFLICT DO NOTHING RETURNING id` | guard and write are one statement, so no window exists between deciding and writing; empty `RETURNING` = not admitted |
| S2 | balance + outstanding read | splits `no_wallet` from `insufficient`, from the same snapshot |

`settle` captures the hold as one batch (debit → settlement row → `active →
settled` flip), every statement guarded on the hold still being `active`.
`release` is a single guarded `UPDATE ... RETURNING` CAS.

### Workflow-budget debit — optimistic CAS (`D1WorkflowBudgetStore`, §1.5.3)

This one cannot be a single conditional statement: the decision is a
multi-dimensional precedence rule (wall-clock → cost → tokens → tool-calls)
whose outcome is *which* dimension broke, and a breach must flip the run to
`exhausted` **without applying spend**. Encoding that in SQL would duplicate the
rule in two languages and the copies would drift. So the decision stays in TS,
shared verbatim with the in-memory store, and the write is guarded:

```sql
UPDATE workflow_run_budgets SET spent_x = spent_x + ?, ...
WHERE id = ? AND status = 'active'
  AND spent_credits = ? AND spent_tokens = ? AND spent_tool_calls = ?
  AND cost_budget_credits IS ? AND token_budget IS ? AND ...
RETURNING ...
```

Empty `RETURNING` = somebody committed in between → re-read and re-decide,
bounded by `WORKFLOW_BUDGET_CAS_MAX_ATTEMPTS` (16). Two details are load-bearing:

* **The caps are in the guard, not just the counters.** A debit that decided
  `exceeded` against a cap of 100 must not write that verdict if a concurrent
  top-up raised the cap to 500 — the step would be refused against a budget that
  now affords it.
* **`IS`, not `=`.** A NULL cap means unbounded, and `NULL = NULL` is NULL, so
  `=` would make every unbounded-dimension CAS miss forever.

### Monotonic upserts (`TenantMonotonicUpserts` / `ControlMonotonicUpserts`, §1.5.6)

Presence touches, replay floors and cost-burn ticks arrive **out of order**
(queue retries, lagging deployments). A plain `DO UPDATE SET x = excluded.x` is
last-write-wins, so a delayed write moves the row backwards — the agent
disappears from the presence window, the replay floor drops and a superseded
snapshot is accepted again. The merge must be a lattice join:

* high-water columns → `max(existing, incoming)`
* low-water columns → `min(existing, incoming)`
* counters → `existing + incoming` (**not** `max`: two distinct requests in the
  same second must both count)

SQLite has no `GREATEST`/`LEAST`; the two-argument `max`/`min` are scalar
functions and are the port.

### Reference-guarded deletes (`D1ReferenceGuardedDeletes`, §1.5.7)

`deleteProjectIfUnreferenced` / `deleteWorkspaceIfUnreferenced` must refuse
while a workspace or a virtual API key still points at the row, and report how
many of each are in the way. Counting first and deleting second is a
**time-of-check/time-of-use race**: a workspace created between the two
statements is orphaned by a delete authorized against a stale count, and its
api-keys keep authenticating against a project that no longer exists. Postgres
closed the window with `SELECT ... FOR UPDATE` on the parent; D1 has no row
lock, so the port removes the window instead of locking it — the guard is a
`NOT EXISTS` subquery **inside the DELETE**, evaluated by SQLite against
committed state at execution time:

```sql
DELETE FROM projects WHERE id = ?
  AND NOT EXISTS (SELECT 1 FROM workspaces WHERE project_id = ?)
  AND NOT EXISTS (SELECT 1 FROM api_keys   WHERE project_id = ?)
```

`meta.changes > 0` means the guard held. A refusal is then *labelled* — never
decided — by a second, read-only count query that separates `not_found` from
`referenced {workspaces, virtualKeys}`. All three tables are in the tenant
database, so every subquery is local and the atomicity is genuine.

### Mutation-test record

Each guard was broken on purpose, the suite confirmed RED, then restored and
confirmed GREEN.

| mutation | result |
|---|---|
| neutralize the no-oversell arithmetic in S1 (`? <= 999999999`) | **RED** — 3 tests, incl. 5 concurrent reserves admitting 5 instead of 4 |
| replace the in-statement guard with a naive TS read-then-write (arithmetic identical, atomicity gone) | **RED** — 20 parallel reserves against a balance affording 7 admitted **all 20** |
| drop the `spent_*` counters from the debit CAS guard | **RED** — 10 concurrent debits against a cap of 4 applied all 10 |
| drop the `workspaces` `NOT EXISTS` clause from the project delete | **RED** — 3 tests, incl. the late-reference race |
| reshape the project delete into check-then-delete (same SQL semantics, guard moved out of the statement) | **RED** — exactly 1 test: the late-reference race, which every other test misses |
| restore each | **GREEN** — 104 pure + 152 D1 |

The second one is the decisive observation: `Promise.all` over the store's
methods genuinely interleaves at the D1 level in `workerd`, so the concurrency
tests detect loss of **atomicity**, not merely loss of the arithmetic.

---

## 4. Wiring (for the composition root — not done in this package)

`packages/storage` exports **no Worker, no `fetch` handler and no Durable Object
class**, so there is nothing for a `src/worker.ts` to re-export and no
entry-module named-export hazard. It is a library; the composition root mounts
it.

```toml
# apps/gateway/wrangler.toml (or apps/control-plane)
[[d1_databases]]
binding = "CONTROL_DB"
database_name = "ferrogate-control"
database_id = "<deploy-time>"

[[d1_databases]]
binding = "TENANT_DB_ACME"          # == tenant_databases.binding_name
database_name = "ferrogate-tenant-acme"
database_id = "<deploy-time>"
```

```ts
import {
  D1UsageLedger,
  D1WalletStore,
  D1WorkflowBudgetStore,
  EnvBindingTenantDatabaseRouter,
} from "@ferrogate/storage";

const router = new EnvBindingTenantDatabaseRouter(env, env.CONTROL_DB);

// Hot path: resolve the tenant from the credential first (control
// `api_key_directory`), THEN make exactly one routed call. Never fan out here.
const handle = await router.forTenant(caller.tenantId);

// UsageSink (apps/gateway/src/inference/ports.ts:285) → D1:
const ledger = new D1UsageLedger(handle);
await ledger.persistUsageAggregate({ /* … */ });

const wallet = new D1WalletStore(handle);
const budgets = new D1WorkflowBudgetStore(handle);
```

Applying migrations:

```sh
wrangler d1 migrations apply ferrogate-control      # sql/d1-ts/control
wrangler d1 migrations apply ferrogate-tenant-acme  # sql/d1-ts/tenant
```

(`wrangler.toml` needs `migrations_dir` pointed at the matching directory, or
pass `--local` plus an explicit path; the D1 suite loads both sets through
`readD1Migrations` in `vitest.d1.config.ts`.)

### Deferred, with markers in the code

* `PORT-TODO(inventory-data-billing §4 "x402")` — `payment_attempts` is not
  created; x402/Solana is deprioritized by standing directive, and the Rust D1
  file never defined it either. Consequence:
  `D1WalletStore.sweepExpiredWalletReservations` sweeps **unconditionally**,
  lacking the Postgres `NOT EXISTS (payment_attempts …)` guard that protects a
  hold owned by an in-flight payment (#396/#352). Callers must keep enforcing
  hold protection at the application layer until the table lands.
* `PORT-TODO(inventory-data-billing §1.5.8)` — **PLATFORM LIMIT, partially
  closed.** The claim itself is now ported: `D1BillingEventLedger`
  (`src/d1/billing-d1.ts`) claims `billing_events.billing_event_id` and enqueues
  the `billing_report_outbox` row in ONE atomic `controlDb.batch()`, which is
  the whole of Rust's `append_billing_event_with_outbox_enqueue` — both tables
  are in the control database, so the atomicity is real. What CANNOT be closed:
  `D1UsageLedger`'s rollup batch is on a TENANT database, and **D1 has no
  transaction spanning two databases** (no cross-database `BEGIN`, no two-phase
  commit), so the claim and the accumulate cannot be one commit. The
  approximation is claim-then-accumulate, whose residual window UNDER-counts
  rather than double-bills. The caller owns the ordering: run the claim first,
  accumulate only on `recorded: true`.
* `PORT-TODO(inventory-request-path §1.6)` — the tenant model catalog schema
  exists but the gateway still reads `GATEWAY_PROVIDERS` / `GATEWAY_MODELS` vars;
  swapping in a tenant-DB-backed `ModelResolver` is #812.
* `PORT-TODO(inventory-data-billing §1.7)` — `request_logs` / `audit_events` /
  `billing_events` are append-heavy and time-ordered, the exact shape Analytics
  Engine is for. Ported as D1 tables so the admin read surface stays queryable;
  the sink swap is an `apps/telemetry` slice.
