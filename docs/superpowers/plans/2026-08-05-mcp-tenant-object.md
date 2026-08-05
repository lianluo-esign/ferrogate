# MCP Tenant Object Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the tenant-owned MCP catalog and identity grant state into each tenant's `TenantDataObject` while preserving encryption, revocation, tenant fencing, and OAuth generation CAS.

**Architecture:** Add one versioned tenant migration and reuse the existing `DurableObjectD1Database` facade for object-local SQL. Replace the MCP identity D1 schema bootstrap and fixed control-D1 store with a namespace-backed store that derives the exact tenant object from every actor. Keep flow claim state in the existing dedicated OAuth Durable Object.

**Tech Stack:** TypeScript, Cloudflare Durable Objects, `ctx.storage.sql`, SQLite, D1-shaped object facade, Vitest with `@cloudflare/vitest-pool-workers`, Bun.

---

### Task 1: Add the tenant MCP identity schema

**Files:**
- Create: `sql/d1-ts/tenant/0014_mcp_identity.sql`
- Modify: `packages/storage/test/do/tenant-data-object.test.ts`

- [ ] Write real-workerd tests that require the new catalog, credentials, and generation tables and verify the tenant schema reaches the new version.
- [ ] Run the focused storage object test and observe the missing-table/version failure.
- [ ] Add the migration with tenant-qualified primary keys, indexes, encrypted token nonce/ciphertext columns, and generation rows.
- [ ] Re-run the focused storage object test and commit the migration.

### Task 2: Replace the flat D1 identity store

**Files:**
- Modify: `apps/mcp/src/durable.ts`
- Modify: `apps/mcp/src/ports.ts`
- Modify: `apps/mcp/src/upstreams.ts`
- Modify: `apps/mcp/test/durable-identity.test.ts`
- Modify: `apps/mcp/test/durable-upstreams.test.ts`

- [ ] Add failing object-backed store tests for encrypted credential round trips, generation CAS, revocation persistence, and cross-tenant reads.
- [ ] Replace `ensureMcpIdentitySchema` and the `WeakSet` schema cache with namespace-backed `DurableObjectD1Database` handles.
- [ ] Keep the existing guarded SQL semantics, using the authenticated actor tenant for every object and predicate.
- [ ] Route catalog reads to the exact tenant object and remove the control-D1 catalog dependency.
- [ ] Commit the object-backed identity store.

### Task 3: Wire the namespace and request paths

**Files:**
- Modify: `apps/mcp/wrangler.toml`
- Modify: `apps/mcp/src/worker.ts`
- Modify: `apps/mcp/vitest.config.ts`
- Modify: `apps/mcp/test/wrangler-bindings.test.ts`
- Modify: `apps/mcp/test/multiplex-tenant-fence.test.ts`

- [ ] Add the `TENANT_DATA` binding and export `TenantDataObject` from the MCP worker entrypoint.
- [ ] Make durable identity readiness require the object namespace rather than the flat identity D1 schema.
- [ ] Add deployed-path catalog/fence coverage for two tenants in separate objects.
- [ ] Commit the wiring and tests.

### Task 4: Verify and publish

**Files:**
- Modify: `apps/mcp/src/*.ts`, `apps/mcp/test/*.test.ts` only as required by failures.

- [ ] Run MCP focused tests, typecheck, storage typecheck/object tests, Biome, and `git diff --check`.
- [ ] Review the diff for control-D1 identity/catalog references and confirm only auth/platform-control uses remain.
- [ ] Commit any verification fixes, push `feat/issue-862-mcp-tenant-object`, and create/update a PR linking `#862` and `#831`.
