<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-08-07
  description: Token4AI Cloud, FerroGate AI Gateway, Zero-D1 decision: retire
  every [[d1_databases]] binding by moving the control database onto a singleton
  SQLite-backed Durable Object (ControlDataObject), extending epic #821.
-->

# Zero-D1: the control database moves onto a Durable Object (extends #821)

> **Decision, 2026-08-07 (owner directive).** FerroGate stops using D1
> entirely. Tenant-private data already lives in one SQLite-backed Durable
> Object per tenant (`TenantDataObject`, #822/#819, default since
> `GATEWAY_TENANT_DB_ROUTING = "durable_object"`). This document decides how
> the **remaining** D1 surface — the CONTROL database — moves to a Durable
> Object as well, and sequences the slices. End state: **zero
> `[[d1_databases]]` stanzas in every `wrangler.toml`.**
>
> This supersedes §"What stays on D1 — deliberately" of
> [`per-tenant-durable-object-storage-2026-08.md`](per-tenant-durable-object-storage-2026-08.md)
> and the corresponding section of #821. Everything else in that design
> (per-tenant objects, the facade, the fail-closed router) is unchanged and is
> the foundation this builds on.

## 1. What is still on D1 today (complete inventory)

Nine bindings across four Workers (telemetry binds none):

| Worker | binding | role today |
|---|---|---|
| gateway | `DB` | legacy shared tenant-compatible surface; wallet path only under `GATEWAY_TENANT_DB_ROUTING = "off"` |
| gateway | `BILLING_DB` | CONTROL billing compatibility: unscoped (`__control__`) settlement, legacy billing rows, derived projections |
| gateway | `CONTROL_DB` | the control database: `api_key_directory`, `tenants`, `tenant_databases`, plans, quotas, RBAC, guardrail policy revisions, site domains, budget alerts (`src/tenancy/ports.ts:55`) |
| control-plane | `DB` | the admin store — every admin collection persists through `src/store/d1.ts` |
| control-plane | `LEGACY_TENANT_DB` | pre-DO tenant compatibility reads |
| mcp | `DB`, `BILLING_DB` | control reads + billing compatibility |
| agent-runtime | `DB`, `CONTROL_DB` | control reads |

All of it is **one logical database** — the CONTROL database
(`sql/d1-ts/control/`, 26 migrations) — reached through per-Worker bindings.
`sql/d1-ts/tenant/` (22 migrations) already ships inside `TenantDataObject`.

## 2. The design: one `ControlDataObject`, one instance, same facade trick

**A new SQLite-backed Durable Object class, `ControlDataObject`, with exactly
one instance, addressed `idFromName("control")`.** It is the control database.

The whole point of the shape is that it repeats what #822 already proved,
rather than inventing anything:

1. **Same class discipline as `TenantDataObject`**
   (`packages/storage/src/tenant-data-object.ts`): `ctx.storage.sql` API,
   `transactionSync()` as the only transaction boundary, cursors drained in
   the same synchronous stretch, `blockConcurrencyWhile` for lazy schema
   migration, RPC-only (no `fetch()` surface), `storage = "sqlite"` from the
   first deploy (immutable thereafter).
2. **Same schema-inlining pipeline**: `scripts/generate-tenant-schema-sql.mjs`
   is parameterized (or duplicated) to also inline `sql/d1-ts/control/*` into
   `packages/storage/src/control-schema-sql.ts` with a byte-verbatim test,
   exactly like `tenant-schema-sql.ts`.
3. **Same D1-shaped facade**: `DurableObjectD1Database`
   (`packages/storage/src/tenant-do.ts`) already forwards a whole `batch()`
   into the object's `transactionSync()` in one RPC round trip. A
   `ControlDataStub` satisfies the same structural interface, so **none of the
   ~87 store/route files that hold a `D1Database` are rewritten** — only the
   handful of binding-resolution seams change what they return:
   - gateway: `meteringDatabaseFrom`/`meteringProjectionDatabaseFrom`
     (`src/metering/runtime.ts`), guardrail/config/keys control readers,
     `tenancy` `control()`;
   - control-plane: the single `D1ControlPlaneStore` construction seam
     (`src/store/d1.ts`);
   - mcp / agent-runtime: their `DB`/`BILLING_DB`/`CONTROL_DB` accessors.
4. **Same cross-script binding precedent**: the class is exported from
   `ferrogate-gateway`'s entry module; the other Workers bind it with
   `script_name = "ferrogate-gateway"` (precedent: `apps/mcp/wrangler.toml`
   binding gateway-owned DO classes). Binding name: `CONTROL_DATA`.

**Address check, mirrored from the tenant object:** every RPC carries the
caller's believed address (`"control"`); the object refuses anything else.
The tenant-id tripwire columns in control tables keep their current meaning.

### Why a singleton is correct here (and what it cannot do)

The control database answers "which tenant?" — it cannot be tenant-routed
(the chicken-and-egg rule in `src/tenancy/ports.ts:51-62`). It also backs
`provisionedTenants()` enumeration, which a DO **namespace** cannot provide but
a registry **table inside one object** can — same as the control D1 table
today. Capacity is unchanged: one D1 database is 10 GB; one SQLite DO is
10 GB. And #831 is already moving the bulky tenant-private rows
(request logs, agent runs, guardrail evidence, MCP registrations) *out* of
control storage into tenant objects, so the control set shrinks over time.

## 3. The one real risk: the auth hot path

Every authenticated request resolves its credential through the CONTROL
`api_key_directory` point lookup (`src/keys/`). Today that is a D1 read with
global read replication. After the move it is an RPC to a **single-threaded
object homed in one region**: ~1,000 req/s soft cap, plus cross-region RTT
for every isolate not co-located with the object.

This is the load-bearing constraint of the whole migration, and it is
addressed head-on, not waved away:

1. **The key TTL cache flips from opt-in to DEFAULT-ON** with a short TTL
   (`src/keys/cache.ts`, `ApiKeyResolverOptions.cacheTtlSeconds`). The cache
   already has the right semantics — positive outcomes cached, `unknown` and
   `unavailable` never cached, suspension propagates within one TTL. With a
   30 s TTL, steady-state directory load is O(distinct keys / 30 s) per
   isolate, not O(requests). The revocation-latency tradeoff (≤ TTL) is
   documented at the flag.
2. **Admission-adjacent control reads batch through the same RPC** where they
   already share a request (quota/plan lookups), so a request costs at most
   one control round trip on cache miss.
3. **If measured load approaches the ceiling**, the escape hatch is a
   read-projection tier (per-colo cache objects or KV projection of the
   directory, written through by the control object). That is a follow-up
   issue (filed with the slices), **not** a blocker: the cache alone puts the
   directory RPC rate two orders of magnitude below request rate.

What is explicitly accepted: control writes (admin operations) serialize
through one object. Admin-API write volume is human-scale; this is fine.

## 4. Migration sequencing (slices)

Strict order; each slice lands green through the normal PR gate:

1. **S1 — `ControlDataObject` + control schema inlining + facade** (this
   branch): the class, `control-schema-sql.ts` generation + verbatim test,
   `ControlDurableObjectD1Database` (thin reuse of the tenant facade), export
   from the gateway entry module, `CONTROL_DATA` bindings in all four
   wranglers (D1 bindings stay, unused-by-default, until S5).
2. **S2 — gateway seams**: `meteringDatabaseFrom` (no-tenant branch),
   `meteringProjectionDatabaseFrom`, keys/store control reader, tenancy
   `control()`, guardrail deps, budget alerts — all resolve `CONTROL_DATA`
   first, `CONTROL_DB`/`BILLING_DB` only as an explicit
   `GATEWAY_CONTROL_STORAGE = "d1_compat"` posture. Key cache default-on
   lands here.
3. **S3 — control-plane store seam**: `D1ControlPlaneStore` constructed over
   the facade; `LEGACY_TENANT_DB` reads retired or routed to tenant objects.
4. **S4 — mcp + agent-runtime seams**: same pattern as S2.
5. **S5 — backfill + cutover + delete D1**: one-shot audited export of the
   live CONTROL D1 into the control object (JSONL pages, same export shape as
   `tenant-data-object.ts`), verify row counts per table, flip the posture
   var default, then **remove all nine `[[d1_databases]]` stanzas and the
   `d1_compat` code path**. `wrangler d1` disappears from deploy docs.
6. **S6 (follow-up, non-blocking) — directory read projection** if measured
   control-object load warrants it (§3.3).

Rollback: until S5's stanza deletion, `GATEWAY_CONTROL_STORAGE = "d1_compat"`
restores the previous topology per Worker; the backfill is re-runnable
(idempotent by primary key) in either direction.

## 5. Test posture

- vitest-pool-workers provisions the `CONTROL_DATA` DO from each
  `wrangler.toml` exactly as it provisions `TENANT_DATA` today; the
  `cloudflare:test` harness needs no new machinery.
- The backend-parity suite (`packages/storage/test/d1/backend-parity.test.ts`)
  gains a control-object leg: every control store module runs against both
  backends until S5 deletes the D1 leg.
- The schema-inlining verbatim test mirrors
  `test/tenant-schema-sql.test.ts` (byte-identical, filename order, count).

## 6. What "zero D1" means at the end

- `grep -rn 'd1_databases' apps/*/wrangler.toml` → no matches.
- `grep -rn 'D1Database' apps/ packages/` matches only the **facade type**
  (the D1-*shaped* interface over DO SQLite) — the name survives as a wire
  shape, not a backend. A follow-up rename
  (`D1LedgerStore` → `SqlLedgerStore` etc.) is filed separately as pure
  refactor, so the money-path diff stays reviewable.
- Registration cost stays zero: a tenant's object exists the moment
  `idFromName(tenantId)` is first addressed; the control object exists the
  moment the first Worker boots. No provisioning API, no per-tenant deploy.
