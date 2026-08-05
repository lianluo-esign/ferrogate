# Cloudflare D1 Control Database Compatibility

**Current topology as of 2026-08-05:** FerroGate uses one shared Cloudflare D1
database as the **CONTROL** store and one SQLite-backed Durable Object for each
tenant's data. This document describes the CONTROL compatibility boundary. It
does not describe a tenant database provisioning runbook.

## Scope

CONTROL D1 contains data that is account-wide, needed before a tenant can be
routed, or maintained as a cross-tenant projection. Typical examples are the
tenant registry, plans and roles, credential directories, site-domain
configuration, compatibility billing records and aggregate views.

Tenant-owned data is not selected from a pool of D1 databases. The tenant router
addresses `TenantDataObject` by tenant id and executes its SQLite work inside
that object. Wallet, usage, asset, schedule, project, workspace, API-key and
catalog operations therefore have a per-tenant transaction boundary without a
deployment or provisioning action for each tenant.

## Compatibility contract

The storage package keeps D1-shaped interfaces so existing storage modules can
use prepared statements and `batch()` consistently. That interface is an
implementation compatibility layer, not a promise that every tenant has a D1
database.

The CONTROL schema remains useful for three compatibility cases:

1. Account and tenant lifecycle records must be readable before tenant storage
   is addressed.
2. Cross-tenant administration uses explicit CONTROL projections instead of
   fan-out queries across tenant objects.
3. Older control records can be read and migrated without treating historical
   tenant database identifiers as active routing instructions.

A routing failure is fail-closed. CONTROL D1 is never a fallback for a missing
tenant object, and a missing tenant route must not cause tenant data to be
stored in shared control tables.

## Supported deployment modes

| mode | purpose | tenant storage |
|---|---|---|
| `durable_object` | Default multi-tenant production topology | One SQLite Durable Object addressed by tenant id. |
| `native_binding` | Explicit single-tenant or self-hosted compatibility deployment | A predeclared native D1 binding. |
| `shared_development` | Local and intentionally shared development | Shared development storage only. |

`native_binding` is deliberately narrow. It is not a way to create bindings for
new SaaS tenants, and it must be explicitly chosen by a self-hosted or
single-tenant deployment.

## Retired D1 tenant apparatus

The following architecture was retired on 2026-08-05:

- one D1 database for every tenant;
- runtime REST-query routing to a D1 database identifier;
- proxy Workers used to regain tenant transaction semantics; and
- tenant-scoped D1 lifecycle and manual provisioning procedures.

Those mechanisms do not participate in current request handling. Historical
analysis is preserved, with dated annotations, in `docs/rewrite/` and
`docs/legacy/`; it must not be used as an operator runbook.

## Operations and migration

Apply CONTROL D1 migrations with the normal Worker deployment process. Tenant
schema initialization and migration are owned by the tenant Durable Object
lifecycle. Operators should use audited application-level administration for
tenant data rather than a console procedure that targets a tenant-specific D1
database.

For the full rationale, limits and retention decision, see
[`design/per-tenant-durable-object-storage-2026-08.md`](design/per-tenant-durable-object-storage-2026-08.md).
