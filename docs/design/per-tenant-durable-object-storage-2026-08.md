# Per-tenant storage on Durable Objects

Status: accepted, 2026-08-04. Supersedes the "one D1 database per tenant" topology
described in `docs/cloudflare-d1-backend.md`, `docs/cloudflare-integration.md:340`,
`packages/storage/README.md:24` and `README.md:95`.

## The problem with the current design

FerroGate's tenant data plane is specified as **one D1 database per tenant**. The
implementation exists (`packages/storage/src/tenant-router.ts`) and is deliberately
inert: `GATEWAY_TENANT_DB_ROUTING = "off"`, zero `TENANT_DB_*` stanzas, and
`tenantDatabaseOf(c)` has no production call sites. The reason it never turned on is
stated in the module's own docblock and in `D1_BINDING_STRATEGIES`
(`tenant-router.ts:623`):

> Cloudflare bindings are declared at **deploy** time. There is no runtime
> `env.openD1("<uuid>")`.

That forces a three-way choice, none of which is a multi-tenant SaaS answer:

| strategy | atomic `batch()` | onboarding cost | tenant ceiling |
|---|---|---|---|
| `native_binding` | yes | a `wrangler deploy` per tenant | low hundreds |
| `proxy_service` | yes | a deploy of the proxy per tenant | low hundreds per proxy |
| `rest` | **no** | none | unbounded, but non-atomic |

The hard platform numbers (verified against Cloudflare docs, 2026-08-04):

- **~5,000 D1 bindings per Worker script.** That is the real wall, and it is a
  *script metadata* limit, not something a support ticket removes cheaply.
- 50,000 D1 databases per account (Workers Paid), raisable on request.
- 10 GB per D1 database, 1 TB per account.

So `native_binding` and `proxy_service` cap the product at a few hundred tenants and
make signup a deploy. `rest` scales, but `TenantDatabaseHandle.supportsAtomicBatch`
goes `false`, and `requireAtomicBatch()` — 17 call sites across `wallet-d1.ts`,
`workflow-budget-d1.ts`, `assets-d1.ts`, `agent-schedule-d1.ts`, `usage-d1.ts` —
refuses to run. Those are the money paths. **Under `rest`, wallet reserve does not
work at all.** Choosing `rest` was choosing to scale by giving up the ledger.

## The resolution: one Durable Object per tenant

A SQLite-backed Durable Object carries its own embedded SQLite database. One DO class
(`TenantDataObject`), one binding, and `idFromName(tenantId)` addresses a tenant's
database **at runtime with no deploy and no provisioning API call**.

Verified limits:

| property | value |
|---|---|
| objects per namespace | **unlimited** ("as many separate Durable Objects as you want") |
| DO classes per account | 500 (Paid) / 100 (Free) — we need **one** |
| SQLite storage per object | **10 GB** (same ceiling as a D1 database) |
| account storage | unlimited (Paid) |
| requests per object | ~1,000/s soft cap, single-threaded |
| memory per object | 128 MB |
| CPU per request | 30 s default, configurable to 5 min via `limits.cpu_ms` |
| SQL limits | identical to D1: 100 cols/table, 2 MB row, 100 KB statement, 100 bound params |
| PITR | 30 days, per object |

So the user's premise is right, and the scaling story is strictly better than D1's:
unlimited objects vs a ~5,000-binding ceiling, at the same 10 GB per tenant.

### It is a correctness fix, not only a scaling fix

This is the part that matters more than the tenant count. `ctx.storage.sql.exec()` is
**synchronous**, and `ctx.storage.transactionSync(cb)` runs a callback in a real
SQLite transaction that rolls back on throw. That means a per-tenant DO gives back
exactly what the `rest` strategy takes away:

- real multi-statement atomicity → `supportsAtomicBatch: true`
- real `RETURNING`
- no D1 subrequest budget (D1 caps 1,000 queries per Worker invocation; DO SQL is not
  a subrequest at all)
- in-object caching across requests — api keys, gateway config and the model catalog
  can live in DO memory instead of being re-read per request

A tenant's wallet reserve becomes a single synchronous transaction inside the tenant's
own object. That is a stronger isolation and correctness story than any D1 topology
we have available.

### Secondary wins

- **No provisioning step.** #820's "create DB2 via the D1 REST API, then apply
  migrations with a runner that does not exist yet" collapses to: the object
  materialises on first `get()`, and its constructor applies
  `sql/d1-ts/tenant/*.sql` idempotently under `blockConcurrencyWhile`. Schema
  migration becomes lazy and per tenant instead of a fleet-wide batch job.
- **Locally verifiable.** The `rest` path explicitly cannot be exercised by workerd —
  see #820's own note. DOs can: `cloudflare:test` ships `runInDurableObject`,
  `listDurableObjectIds`, `runDurableObjectAlarm` and per-file isolated storage, and
  this repo already runs eight SQLite-backed DO classes under that harness.
- **Data residency for free.** `env.TENANT_DATA.jurisdiction("eu").idFromName(t)`
  pins a tenant's data to the EU (`us` and `fedramp` also supported). That is a hard
  constraint, not a hint, and it is what `docs/security` residency claims need.
- **Per-tenant PITR.** 30 days of bookmarks per tenant, restorable without touching
  any other tenant.

### The proven-in-repo argument

This is not a new platform bet. `apps/gateway`, `apps/mcp`, `apps/agent-runtime` and
`packages/routing` already ship **eight** SQLite-backed DO classes —
`RateLimiterDurableObject`, `ProviderCircuitDurableObject`, `ShadowBudgetDurableObject`,
`FerroGateMcpSession`, `FerroGateMcpUnifiedSession`, `McpOauthFlowClaim`,
`AgentRunState`, `WorkerPlane`. The wrangler config, the cross-Worker
re-export discipline (`apps/gateway/wrangler.toml:1275`), and the test harness are all
already load-bearing here.

## What it costs — the honest list

1. **One region per tenant.** A DO is homed near its first `get()` and
   **cannot be moved afterwards** (relocation is "planned"). D1 has read replication;
   DO does not. A tenant with globally spread traffic pays cross-ocean RTT on every
   storage op. Mitigation: pass `locationHint` derived from the registration request's
   `cf.continent` on first resolution, and record it on the tenant row so the choice
   is auditable rather than accidental. Objects created from a migration backfill must
   carry the hint explicitly, or every tenant lands wherever the backfill job ran.
2. **~1,000 req/s and one thread per tenant.** A single very large tenant can saturate
   its own object. D1 is also single-threaded per database, so this is not a
   regression — but the DO puts *all* of a tenant's storage behind one lock. The seam
   to keep open is splitting high-volume append-only tables (usage rollups, request
   logs) out of the tenant object into a sharded child namespace or Analytics Engine.
3. **No cross-tenant SQL.** There is no `SELECT ... FROM all_tenants`. Platform
   billing, fleet dashboards and the `usage_*_rollups` aggregate views must be fed by
   push (alarm-driven flush from each DO into the control D1 or a Queue), not pull.
   This is real work and it is the largest new surface in the migration.
4. **No `wrangler d1 execute` for support.** Operator access to a tenant's data needs
   a purpose-built, audited admin RPC on the object. Treat that as a feature, not a
   gap — an audited seam beats an unaudited console.
5. **Storage backend is immutable.** `new_sqlite_classes` / `storage = "sqlite"` can
   never be changed on a live namespace (`storage_type_mismatch`); converting requires
   a `deleted` tombstone and total data loss. Get it right in the first deploy.
6. **Billing shape changes.** DO storage bills rows read ($0.001/M after 25 B/mo),
   rows written ($1.00/M after 50 M/mo), storage ($0.20/GB-mo after 5 GB), plus
   requests and duration. Idle, hibernation-eligible objects cost nothing for
   duration, so a long tail of dormant tenants is cheap — but a hot write path is
   billed per row, which rewards batching inside `transactionSync`.

## Design

```
                       env.TENANT_DATA.idFromName(tenantId)
  request ─ resolver ─────────────────────────────────────► TenantDataObject
             │                                                 ctx.storage.sql
             │  control D1 (shared, unchanged):                 ├─ 0001_init_tenant
             └─ tenants, tenant_databases, plans, platform      ├─ …0007
                catalog template, cross-tenant rollups          └─ tenant_database_identity
```

- **Control plane stays on D1.** Account/tenant registry, plans, the catalog template
  and cross-tenant aggregates are genuinely shared and genuinely need cross-row
  queries. Nothing about this proposal moves them.
- **`TenantDatabaseHandle` keeps its shape.** The 14 modules under
  `packages/storage/src/d1/` are written against the `D1Database` interface. The DO
  gets a D1-compatible facade — `prepare().bind().first()/all()/run()` and `batch()`
  forwarded over RPC into `transactionSync` — so those modules port **unchanged** and
  `supportsAtomicBatch` becomes `true` again. This keeps the migration a storage-layer
  change rather than a rewrite of every call site.
- **`durable_object` becomes a fourth `TenantDatabaseSource`** and then the default.
  `native_binding` stays for single-tenant/self-hosted deploys; `rest` and
  `proxy_service` are retired.

## Verdict

Feasible, and it is the right topology. It removes the ~5,000-tenant ceiling, removes
the deploy-per-tenant onboarding step, restores atomic transactions to the money
paths, makes the whole thing testable on workerd locally, and buys hard data
residency — on a platform primitive this repo already runs in production in eight
places. The costs are real (single region per tenant, no cross-tenant SQL) and are
tracked as named slices in milestone M9 rather than waved away.
