# `@ferrogate/storage`

The persistence boundary for the FerroGate control plane and tenant-owned
financial, usage, asset, catalog and scheduling state. It is a clean-room
TypeScript implementation of the durable storage contracts used by the Workers
applications.

The package keeps pure in-memory reference stores alongside durable adapters.
The pure stores specify invariants; the durable suites exercise the same
observable behavior on workerd-backed SQLite.

| half | where | durable target |
|---|---|---|
| Pure algorithms and `Memory*Store` reference implementations | `src/*.ts` | in-memory |
| Control-plane stores and tenant routing | `src/d1/*.ts`, `src/tenant-router.ts` | CONTROL D1 and tenant Durable Objects |

`bun run test` runs the package suites. A durable implementation that differs
from its in-memory reference is a defect, not an alternative behavior.

## Current storage topology

FerroGate has two durable planes:

| plane | backing store | responsibility |
|---|---|---|
| **CONTROL** | one shared Cloudflare D1 database | tenants and tenancy metadata, account-wide configuration, credential directories, compatibility records and cross-tenant projections |
| **TENANT** | one SQLite-backed Durable Object addressed by tenant id | tenant-owned wallets, usage, assets, projects, workspaces, API keys, schedules and catalog state |

The tenant router resolves a tenant id to the Durable Object namespace and uses
a D1-shaped SQLite facade. A `batch()` therefore executes as one SQLite
transaction inside the tenant's object. Addressing a new tenant materializes
its storage without an operator provisioning step or a deployment change.

The CONTROL D1 database is deliberately not a tenant fallback. A missing or
invalid tenant route fails closed so tenant-owned rows cannot be written into
shared control data.

### Compatibility modes

`durable_object` is the multi-tenant production topology. The supported router
strategies are:

| strategy | use |
|---|---|
| `durable_object` | Default multi-tenant topology: one SQLite Durable Object per tenant. |
| `native_binding` | Explicit single-tenant or self-hosted compatibility deployment with a predeclared native D1 binding. It is not a SaaS tenant-provisioning mechanism. |
| `shared_development` | Local development and intentionally shared development storage only. |

The retired D1-per-tenant, REST, proxy and lifecycle paths are not supported
tenant data planes. Historical rationale is retained only in the dated rewrite
records under `docs/rewrite/` and `docs/legacy/`.

## Data placement

CONTROL data is data that is account-wide, establishes tenant identity before a
tenant route exists, or is a cross-tenant projection. Tenant data is owned by
one tenant and remains inside that tenant's Durable Object.

Examples of CONTROL data include `tenants`, plans, permissions, roles,
`api_key_directory`, site-domain configuration, compatibility billing records,
and aggregate projections. Examples of TENANT data include projects,
workspaces, API keys, wallets and settlements, usage rollups, assets, workflow
budgets, schedules and tenant model catalog data.

The boundary is intentional: cross-tenant queries use CONTROL projections;
tenant correctness paths use the object's local SQLite transaction. No request
path silently fans out across every tenant.

## Tenant lifecycle and retention

Tenant data is created lazily when its Durable Object is addressed. Deleting a
tenant removes it from the active roster and lifecycle gate; it does not erase
object storage as a side effect. Retention and erasure need a separately
audited administrative operation, because they carry billing and legal
consequences.

## Testing the durable boundary

The D1 and Durable Object suites run against workerd rather than a handwritten
database fake. They cover routing failures, schema behavior, atomic wallet and
workflow transitions, lifecycle gates and durable-object transaction behavior.
Run the focused package suite with:

```bash
bun run --filter '@ferrogate/storage' test
```

For the design decision and its tradeoffs, see
[`docs/design/per-tenant-durable-object-storage-2026-08.md`](../../docs/design/per-tenant-durable-object-storage-2026-08.md).
