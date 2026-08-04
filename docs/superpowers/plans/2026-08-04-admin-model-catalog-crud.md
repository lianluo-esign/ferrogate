# Admin Model Catalog CRUD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make provider channels, logical models, and model offerings real tenant-owned Durable Object catalog resources with authenticated CRUD, revision invalidation, audit evidence, status counts, and a synchronized API contract.

**Architecture:** Keep generic control-plane document CRUD for unrelated resources, but route catalog operations through a focused tenant catalog service. Resolve the tenant from the authenticated tenant scope or an explicit `tenant_id` for platform operators, obtain the existing `TenantDatabaseRouter` handle, and execute each catalog mutation plus its `catalog_revisions` bump in one `batch()`. Emit the existing control-D1 hash-chain audit event after the tenant transaction commits. Preserve legacy provider/model response fields while adding catalog fields and nested offering endpoints.

**Tech Stack:** TypeScript, Hono, Zod, Cloudflare D1-shaped `TenantDatabaseHandle`, SQLite Durable Object facade, Vitest pool-workers, OpenAPI JSON, generated TypeScript clients, Biome.

---

### Task 1: Add failing end-to-end catalog contract tests

**Files:**
- Create: `apps/control-plane/test/admin-model-catalog.test.ts`
- Modify: `docs/openapi/runtime-api-contract.json`
- Modify: `docs/openapi/admin-api.openapi.json`

- [x] **Step 1: Write the failing tests**

Drive `SELF.fetch` against provisioned Durable Object tenants and cover: one provider plus one model with four priced offerings; every write verb with an `admin.read`-only key returning 403; tenant A unable to read/update/delete tenant B; channel deletion with live offerings returning 409 without mutation; revision and audit changes for committed writes; and `/admin/v1/status` reporting catalog providers.

- [x] **Step 2: Run the new file and confirm the expected red failure**

Run: `bun run --filter '@ferrogate/app-control-plane' test -- admin-model-catalog.test.ts`

Expected: documented-operation/handler failures because the new contract paths and handlers do not exist yet.

### Task 2: Implement the tenant catalog storage service

**Files:**
- Create: `apps/control-plane/src/store/tenant-model-catalog.ts`
- Modify: `apps/control-plane/src/store/d1.ts`

- [x] **Step 1: Add typed Zod inputs and projections**

Validate provider kinds through `canonicalProviderKind`, store the canonical kind, serialize capabilities/nested metadata, and project reads to `has_api_key` without returning `api_key_var`.

- [x] **Step 2: Resolve the tenant database**

Use `callerScope(c.get("auth"))`; tenant credentials always use their own tenant, platform operators require `tenant_id` in query/body. Resolve through `tenantDatabaseFor` and return `503 tenant_database_unavailable` when no tenant database is available.

- [x] **Step 3: Implement atomic mutations**

Build one `D1PreparedStatement[]` per write so the resource mutation and `catalog_revisions` bump execute in the same `batch()`. Guard target tenant ids, preserve `NULL` versus `0`, map invisible rows to 404, and map referenced-channel/unique-role conflicts to 409.

- [x] **Step 4: Implement list/item operations**

Add provider, model, and offering reads/writes with explicit joins and all seven nullable offering prices. Enforce canary/shadow percentage requirements and duplicate upstream bindings at the request boundary while retaining database uniqueness for races.

- [x] **Step 5: Reuse the control-D1 hash-chain audit writer**

Extract the current `D1ControlPlaneStore` audit append into an exported helper accepting catalog action, collection, tenant record, actor scope, request id, clock, and id factory. Call it after each committed catalog batch.

- [x] **Step 6: Re-run the focused tests**

Run: `bun run --filter '@ferrogate/app-control-plane' test -- admin-model-catalog.test.ts`

Expected: storage assertions reach route/contract failures, not SQL or fixture errors.

### Task 3: Mount provider, model, and offering routes

**Files:**
- Modify: `apps/control-plane/src/routes/admin_provider.ts`
- Modify: `apps/control-plane/src/routes/admin_model.ts`
- Modify: `apps/control-plane/src/routes/resource.ts` only for shared helpers if needed

- [x] **Step 1: Register custom tenant-catalog handlers**

Keep provider-health/provider-models read-only; replace only providers/models CRUD and add nested offering list/create plus item get/replace/patch/delete.

- [x] **Step 2: Enforce envelopes and statuses**

Use 201 for collection creates, 200 for reads/replacements/patches, and the standard delete envelope. Return 409 for duplicate names/bindings/role arity or referenced channel deletion, and 404 for invisible cross-tenant ids.

- [x] **Step 3: Run the focused end-to-end tests**

Run: `bun run --filter '@ferrogate/app-control-plane' test -- admin-model-catalog.test.ts`

Expected: all catalog CRUD, RBAC, isolation, reference, revision, and audit assertions pass.

### Task 4: Update contract, OpenAPI, and generated clients

**Files:**
- Modify: `docs/openapi/runtime-api-contract.json`
- Modify: `docs/openapi/admin-api.openapi.json`
- Modify: `apps/control-plane/src/contract.ts`
- Generated: outputs selected by `tools/generated-clients/artifacts.mjs`

- [x] **Step 1: Add 17 operations and route patterns**

Add five provider mutations, five model mutations, and seven nested offering operations. Reads require `admin.read`; writes require `admin.write`; route patterns assign the paths to the existing groups.

- [x] **Step 2: Document catalog request/response schemas**

Add provider/model/offering mutation schemas, keep legacy required provider/model response fields for compatibility, widen response objects for catalog fields, and document `has_api_key` without credential references.

- [x] **Step 3: Regenerate and validate clients**

Run `bun run generate`, then `python3 scripts/check-openapi.py`; expect all generated artifacts and bidirectional/compatibility checks to pass.

### Task 5: Make status count real catalog providers and verify

**Files:**
- Modify: `apps/control-plane/src/adapters.ts`
- Modify: `apps/control-plane/test/runtime-status.test.ts` if needed

- [x] **Step 1: Count tenant provider channels**

Keep legacy generic-row counting as a fallback and sum readable `provider_channels` rows across the control registry; a failed tenant read must not make status unavailable.

- [x] **Step 2: Run targeted verification**

Run:

```bash
bun run --filter '@ferrogate/app-control-plane' test -- admin-model-catalog.test.ts runtime-status.test.ts contract.test.ts wiring.test.ts openapi-drift.test.ts
bun run --filter '@ferrogate/app-control-plane' typecheck
bun run --filter '@ferrogate/app-gateway' test -- inference/tenant-catalog.test.ts
bun run generate && git diff --exit-code
python3 scripts/check-openapi.py
bun run lint
```

- [x] **Step 3: Run the required mutation checks**

Remove the `admin.write` guard from one write operation and confirm the read-only-key test turns red; remove the revision bump and confirm the revision assertion turns red; restore both before committing.

- [ ] **Step 4: Run an independent read-only audit agent**

Require exactly `MERGE: YES` or actionable findings covering isolation, atomic revision bumps, secret redaction, RBAC, audit evidence, contract drift, and tests.

- [ ] **Step 5: Create the PR early, continue development on the PR branch, then merge, close, and clean up**

Create the issue-linked PR after the initial implementation commit. Continue any fixes as additional commits on that PR, merge it only after audit approval and verification, then close the issue, remove the worktree and local/remote branch, fast-forward `main`, and verify a clean worktree.

---

## Self-review

- Spec coverage: CRUD, tenant routing, adapter validation, secret redaction, reference-protected deletes, role/duplicate validation, atomic revision bump, audit evidence, RBAC, isolation, status, OpenAPI/client generation, and mutation checks are assigned above.
- Placeholder scan: all implementation files, tests, commands, and verification gates are named.
- Type consistency: catalog routes use the existing `AdminList`/single-item/delete envelopes and `TenantDatabaseHandle.db` surface.
