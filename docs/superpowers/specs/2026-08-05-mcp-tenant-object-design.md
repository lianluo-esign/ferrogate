# MCP Tenant Object Storage Design

**Issue:** #862  
**Parent:** #831

## Goal

Make tenant-owned MCP server registrations and runtime-created MCP identity
credentials/generations authoritative in the tenant's SQLite-backed
`TenantDataObject`. The existing OAuth flow claim object remains responsible
for single-use flow state; no MCP identity/catalog read or write may depend on a
flat control-D1 identity schema.

## Architecture

`sql/d1-ts/tenant/0014_mcp_identity.sql` adds `mcp_servers`,
`mcp_oauth_credentials`, and `mcp_identity_generations` to the tenant schema.
`TenantDataObject` applies that migration under its existing per-file
`storage_schema_migrations` ledger, so MCP code does not run an isolate-local
schema cache or ad-hoc DDL.

MCP creates a tenant-scoped `DurableObjectD1Database` from
`env.TENANT_DATA.idFromName(actor.tenantId)` for each operation. The existing
credential SQL remains transaction-safe and preserves envelope-encrypted token
bytes, issuer/AAD binding, generation-guarded callback commits, and
idempotent revocation. Every SQL predicate retains the authenticated tenant
fence even though the object is physically tenant-owned.

The catalog loader reads `mcp_servers` from the exact tenant object. Admin CRUD
continues to use the control-plane resource document as the operator-facing
projection/source until a later control-plane issue moves that mutation path;
the MCP runtime no longer reads that flat projection as an upstream catalog.
Tests use real workerd Durable Objects to prove migration application,
cross-tenant refusal, catalog isolation, encrypted credential round trips,
generation CAS, and revocation persistence.

## Failure behavior

- Missing `TENANT_DATA` or identity key material keeps the durable credential
  port unbound and readiness fails closed.
- A blank tenant id is refused before `idFromName` is addressed.
- A stub addressed with a different tenant id is refused by the object and is
  never retried through control D1 or another tenant.
- Object migration failure propagates as an unavailable durable identity path;
  no per-isolate schema cache masks it.

## Scope

This change does not move `mcp_oauth_flows`: its atomic single-use claim is
already implemented by `MCP_OAUTH_FLOWS`. It does not merge or close the PR or
issue; those are release workflow actions after review.
