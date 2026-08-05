# Retire the D1-Per-Tenant Apparatus

**Issue:** #830
**Parent:** #821

## Goal

Make the Durable Object tenant data plane the current Cloudflare architecture.
Remove the obsolete runtime-D1 REST/proxy/lifecycle paths and correct current
documentation without rewriting historical migration records.

## Architecture

Tenant routing has three supported sources: `durable_object` for the product
default, `native_binding` for explicit single-tenant or self-hosted deployments,
and `shared_development` for local development. The old REST and proxy-service
strategies are removed because no deployed path uses them and the Durable Object
provides runtime addressing with transactional storage.

`tenant_databases` remains the control-plane roster and provisioning ledger. Its
`storage_backend`, provisioning, location, and #824 migration fields remain
authoritative for operator state. `binding_name` remains only as the optional
binding selector used by `EnvBindingTenantDatabaseRouter`; the old
`database_uuid` and `database_name` columns are removed by a forward migration,
and no application reader or writer depends on them.

The Rust-era registry-document migration and Cloudflare D1 lifecycle client are
deleted. Existing Durable Object provisioning and the shared legacy source used
by #824 remain intact.

## Documentation and CI

README files and current Cloudflare deployment documentation describe the
control database plus Durable Object tenant storage. The old D1 backend document
is rewritten as a control-database compatibility document. Audit and inventory
documents under `docs/rewrite/` and `docs/legacy/` retain their historical
claims but receive dated annotations and pointers to the current design.

A repository script scans current docs and the relevant source/configuration for
retired topology names. CI runs it so a future reintroduction of the old design
fails before review.

## Failure behavior

- A routing mode outside the supported set is rejected as misconfigured.
- A self-hosted binding tenant without a `binding_name`, or with a missing or
  non-D1 binding, remains fail-closed.
- Durable Object resolution never falls back to the shared database.
- The removed REST credentials are not declared, typed, read, or listed as a
  secret.

## Testing

The storage strategy test asserts the exact three-key set and a mutation check
confirms that adding `rest` makes it fail. Gateway tests assert the reduced
routing modes and the absence of the retired variables. Schema tests assert the
legacy uuid/name columns are absent while `binding_name` remains available for
the self-hosted compatibility path. The issue-required package tests, typecheck,
lint, and the CI topology guard are run before independent audit and merge.
