# Retire the D1-Per-Tenant Apparatus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the unused runtime-D1 apparatus and make current docs, schemas,
and deployment checks describe Durable Object tenant storage.

**Architecture:** Keep `durable_object`, `native_binding`, and
`shared_development`. Preserve `EnvBindingTenantDatabaseRouter` for explicit
self-hosted compatibility, retaining only `binding_name` as its registry input.
Delete REST/proxy/lifecycle/registry-document code, remove the obsolete registry
uuid/name columns with a forward migration, and add a CI guard for current docs.

**Tech Stack:** TypeScript, Vitest with `@cloudflare/vitest-pool-workers`, D1 SQL
migrations, TOML, Markdown, Bun, GitHub Actions.

---

### Task 1: Establish the PR and the RED guards

**Files:**
- Modify: `packages/storage/test/platform-limits.test.ts`
- Modify: `apps/gateway/test/tenancy/resolver.spec.ts`
- Modify: `apps/gateway/test/wrangler-bindings.test.ts`
- Modify: `apps/gateway/test/env-var-drift.test.ts`
- Create: `scripts/check-current-topology.mjs`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Make the strategy contract exact.** Replace imports and REST
  assertions in `platform-limits.test.ts` with an assertion that
  `Object.keys(D1_BINDING_STRATEGIES).sort()` is exactly
  `['durable_object', 'native_binding', 'shared_development']`, and retain the
  atomicity assertions for the three supported entries.

- [ ] **Step 2: Add the gateway mode and configuration guards.** Assert that
  `TENANT_DATABASE_ROUTING_MODES` contains only
  `durable_object`, `off`, `binding`, `binding_strict`, and
  `shared_development`; assert that the committed TOML has neither retired REST
  variables nor a `rest` routing mode; remove the retired secret from the
  expected secret set.

- [ ] **Step 3: Add the repository topology guard.** Create
  `scripts/check-current-topology.mjs` using `node:fs` and `node:path`. It must:
  scan `packages/*/src`, `apps/*/src`, the committed gateway TOML, and current
  Markdown outside `docs/legacy`, `docs/rewrite`, and
  `docs/superpowers`; fail on the retired symbols
  `NonAtomicD1RestTenantDatabaseRouter`, `D1LifecycleClient`, or
  `migrateTenantDatabaseRegistryDocument`; fail on `rest` as a routing strategy
  or the retired gateway variables; and fail on an unannotated current-doc
  occurrence of `database per tenant` or `per-tenant D1`. Historical files are
  checked separately for an explicit `superseded`/`retired`/`historical`
  annotation.

- [ ] **Step 4: Run the guards before implementation.** Run:

  ```bash
  bun run --filter '@ferrogate/storage' test -- platform-limits.test.ts
  bun run --filter '@ferrogate/app-gateway' test -- test/tenancy/resolver.spec.ts test/wrangler-bindings.test.ts test/env-var-drift.test.ts
  bun scripts/check-current-topology.mjs
  ```

  Expected result: RED because production code, old tests, and current docs
  still expose the retired paths. Record the failure output in the PR notes;
  do not weaken the assertions.

- [ ] **Step 5: Commit the plan and RED guards, push, and create the linked PR.**

  ```bash
  git add docs/superpowers/specs/2026-08-05-retire-d1-apparatus-design.md \
    docs/superpowers/plans/2026-08-05-retire-d1-apparatus.md \
    packages/storage/test/platform-limits.test.ts \
    apps/gateway/test/tenancy/resolver.spec.ts \
    apps/gateway/test/wrangler-bindings.test.ts \
    apps/gateway/test/env-var-drift.test.ts \
    scripts/check-current-topology.mjs .github/workflows/ci.yml
  git commit -m "test: guard retired d1 tenant topology"
  git push -u origin feat/issue-830-retire-d1-apparatus
  gh pr create --base main --head feat/issue-830-retire-d1-apparatus \
    --title "Retire the D1-per-tenant apparatus" \
    --body $'Part of #821. Closes #830.\n\nRetires the unused runtime-D1 apparatus, keeps explicit self-hosted binding compatibility, and updates current documentation and CI guards.'
  ```

### Task 2: Remove storage-side REST, proxy, and registry-document code

**Files:**
- Delete: `packages/storage/src/tenant-rest.ts`
- Delete: `packages/storage/test/d1/rest-transport.test.ts`
- Delete: `packages/storage/test/d1/registry-migration.test.ts`
- Modify: `packages/storage/src/index.ts`
- Modify: `packages/storage/src/tenant-router.ts`
- Modify: `packages/storage/test/platform-limits.test.ts`
- Modify: `packages/storage/test/mount-inventory.test.ts`
- Modify: `packages/storage/test/d1/router.test.ts`
- Modify: `packages/storage/test/d1/harness.ts`
- Modify: `packages/storage/test/d1/schema.test.ts`
- Modify: `packages/storage/test/d1/provisioning.test.ts`

- [ ] **Step 1: Remove obsolete source exports and types.** Delete the REST
  barrel export, remove `proxy_service` and `rest` from `TenantDatabaseSource`,
  delete `D1RestTenantDatabaseRouter`, and delete the registry document parser,
  migration result/options types, constants, and function. Remove every stale
  REST/proxy explanation from the active router headers while keeping the
  deploy-time limitation explanation for native binding.

- [ ] **Step 2: Narrow the strategy table.** Leave only
  `native_binding`, `durable_object`, and `shared_development` in
  `D1_BINDING_STRATEGIES`. Update its doc comment to say that Durable Objects
  replaced runtime D1 addressing and that native bindings are compatibility for
  explicit self-hosted deployments.

- [ ] **Step 3: Keep the self-hosted router but remove dead uuid/name plumbing.**
  Remove `databaseUuid` from `TenantDatabaseHandle` and
  `TenantDatabaseRegistration`, remove `databaseName` from registrations, and
  make registry SELECT/INSERT/UPSERT column lists include only `tenant_id`,
  `binding_name`, `schema_version`, storage/provisioning fields, and #824
  migration fields. `EnvBindingTenantDatabaseRouter` must fail closed on a
  missing `binding_name` without inspecting a database uuid.

- [ ] **Step 4: Update storage tests.** Delete tests that only exercise removed
  REST or registry-document code. Update binding-router fixtures to seed only
  `binding_name`, keep the registered-but-unreachable case, and assert native
  handles contain no removed uuid field. Add a schema assertion that
  `tenant_databases` contains `binding_name` but not `database_uuid` or
  `database_name`.

- [ ] **Step 5: Run the storage RED-to-GREEN loop.** Run:

  ```bash
  bun run --filter '@ferrogate/storage' test -- platform-limits.test.ts test/d1/router.test.ts test/d1/schema.test.ts test/mount-inventory.test.ts
  ```

  Expected result after the implementation is PASS. A failure involving a
  #824 shared source or native binding is a correctness issue and must be
  fixed, not marked as baseline.

### Task 3: Migrate the control registry schema and update all raw fixtures

**Files:**
- Create: `sql/d1-ts/control/0022_retire_legacy_d1_registry_columns.sql`
- Modify: `apps/control-plane/test/*.ts` files that insert `tenant_databases`
- Modify: `apps/mcp/test/*.ts` files that insert `tenant_databases`
- Modify: `apps/gateway/test/tenancy/setup.ts`
- Modify: `packages/storage/test/d1/harness.ts`
- Modify: `apps/control-plane/test/tenant-db.ts`
- Modify: `apps/control-plane/test/tenant-object.ts`
- Modify: `apps/mcp/test/tenant-object.ts`

- [ ] **Step 1: Add the forward migration.** Rebuild `tenant_databases` into a
  new table that preserves `tenant_id`, `storage_backend`,
  `provisioning_status`, `schema_version`, catalog/provisioning fields,
  `binding_name`, timestamps, and all #824 migration fields. Copy every existing
  value except the retired uuid/name fields, drop the old table, rename the new
  table, and recreate the binding/status/migration/retention indexes.

- [ ] **Step 2: Update raw SQL fixtures.** Remove `database_uuid` and
  `database_name` from every `INSERT INTO tenant_databases` and its bind list.
  Keep `binding_name` for native-binding tests and set it to NULL for Durable
  Object registrations. Remove obsolete uuid/name assertions and fixture
  comments; do not remove the provisioned-but-unreachable binding case.

- [ ] **Step 3: Verify migration shape and compatibility.** Run:

  ```bash
  bun run --filter '@ferrogate/storage' test -- test/d1/schema.test.ts test/d1/provisioning.test.ts
  bun run --filter '@ferrogate/app-control-plane' test -- test/tenant-db.test.ts test/tenant-backfill.test.ts
  bun run --filter '@ferrogate/app-mcp' test -- test/d1-auth.test.ts test/admission.test.ts
  ```

  Expected result: the new migration applies, native binding fixtures still
  refuse missing bindings, and Durable Object fixtures still use the control
  registry only for roster/provisioning state.

### Task 4: Delete the Cloudflare D1 lifecycle client and gateway REST wiring

**Files:**
- Delete: `packages/cloudflare/src/d1.ts`
- Delete: `packages/cloudflare/test/d1.test.ts`
- Modify: `packages/cloudflare/src/index.ts`
- Modify: `apps/gateway/src/tenancy/resolver.ts`
- Modify: `apps/gateway/src/tenancy/ports.ts`
- Modify: `apps/gateway/src/tenancy/index.ts`
- Modify: `apps/gateway/src/ports.ts`
- Modify: `apps/gateway/wrangler.toml`
- Modify: `apps/gateway/test/tenancy/resolver.spec.ts`
- Delete: `apps/gateway/test/tenancy/rest.spec.ts`
- Modify: `apps/gateway/test/tenancy/harness/wrangler.toml`
- Modify: `apps/gateway/test/env-var-drift.test.ts`
- Modify: `packages/secrets/src/cloudflare-client.ts`

- [ ] **Step 1: Remove the lifecycle export and tests.** Delete the unused D1
  lifecycle module/test and remove its barrel export. Remove stale lifecycle
  references from the Cloudflare client documentation.

- [ ] **Step 2: Narrow gateway routing.** Remove the REST import and branch from
  `resolver.ts`, remove `rest` from the routing type/list, and remove
  `GATEWAY_TENANT_DB_ACCOUNT_ID` and `GATEWAY_TENANT_DB_API_TOKEN` from all
  environment types and the secret drift table. Keep `binding` and
  `binding_strict` as explicit self-hosted modes and retain the missing-binding
  harness case.

- [ ] **Step 3: Remove the manual provisioning runbook.** Rewrite the active
  tenancy module header and gateway TOML comments to describe the Durable Object
  default and the narrow self-hosted binding compatibility path. Delete the
  `wrangler d1 create` -> migrations -> binding -> deploy -> registry INSERT
  instructions and remove the committed REST account id.

- [ ] **Step 4: Run gateway and Cloudflare focused tests.** Run:

  ```bash
  bun run --filter '@ferrogate/cloudflare' test
  bun run --filter '@ferrogate/app-gateway' test -- test/tenancy/resolver.spec.ts test/tenancy/mount.spec.ts test/tenancy/durable-object.spec.ts test/wrangler-bindings.test.ts test/env-var-drift.test.ts
  ```

  Expected result: no REST mode is accepted, no old credentials are read or
  declared, and both the native-binding refusal and Durable Object unreachable
  cases remain covered.

### Task 5: Correct current docs, annotate historical docs, and wire CI

**Files:**
- Modify: `README.md`
- Modify: `packages/storage/README.md`
- Modify: `docs/cloudflare-integration.md`
- Modify: `docs/cloudflare-d1-backend.md`
- Modify: `docs/cloudflare-deploy-topology.md`
- Modify: `docs/design/per-tenant-durable-object-storage-2026-08.md`
- Modify: `docs/rewrite/cf-crate-assessment.md`
- Modify: `docs/rewrite/parity-audit-storage.md`
- Modify: `docs/legacy/inventory-data-billing.md`
- Modify: `docs/rewrite/MARKER-LEDGER.md`
- Modify: `scripts/check-current-topology.mjs`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Rewrite current docs.** State that CONTROL remains D1 for
  account-global registry/projections while tenant authority is in one named
  SQLite Durable Object per tenant. Describe native binding only as explicit
  self-hosted compatibility. Rewrite `docs/cloudflare-d1-backend.md` as the
  control-database compatibility document rather than leaving the old Rust-era
  proxy runbook in place.

- [ ] **Step 2: Annotate historical docs.** Preserve the original findings in
  `docs/rewrite/` and `docs/legacy/`, but add a dated `2026-08-05` annotation and
  a pointer to the current Durable Object design. Do not silently rewrite audit
  conclusions.

- [ ] **Step 3: Enable the CI guard.** Add a CI step after dependency install:

  ```yaml
  - name: Check current storage topology
    run: bun scripts/check-current-topology.mjs
  ```

  The script must exit non-zero when a retired symbol, REST routing strategy,
  retired gateway credential, or unannotated current-doc claim is reintroduced.

- [ ] **Step 4: Run the guard and a mutation check.** Run:

  ```bash
  bun scripts/check-current-topology.mjs
  git diff --check
  ```

  Make a temporary, uncommitted `rest` entry in
  `D1_BINDING_STRATEGIES`, run the exact strategy test, confirm it is RED, then
  restore the file and rerun the test GREEN. The mutation must not remain in the
  worktree.

### Task 6: Full verification and independent audit

**Files:**
- Modify only files required by failing verification or audit findings.

- [ ] **Step 1: Run issue-required verification.** Run:

  ```bash
  bun run --filter '@ferrogate/storage' test
  bun run --filter '@ferrogate/cloudflare' test
  bun run --filter '@ferrogate/app-gateway' test
  bun run typecheck
  bun run lint
  ```

  Capture known repository-wide baseline failures separately from failures in
  changed files. Run a diff-scoped Biome check for touched TypeScript/JS/MJS/JSON
  files and require it to pass.

- [ ] **Step 2: Push the final implementation.**

  ```bash
  git diff --check
  git status --short
  git add <changed-files>
  git commit -m "feat: retire obsolete d1 tenant apparatus"
  git push
  ```

- [ ] **Step 3: Launch a fresh independent read-only audit agent.** Give it the
  issue body, PR number, changed-file list, verification output, and explicit
  instructions to inspect the PR tip without editing, with special attention to
  cross-tenant isolation, migration compatibility, fail-closed routing, stale
  docs, and test gaps. Treat timeout or partial output as no decision, not PASS.

- [ ] **Step 4: Fix every audit finding, rerun affected tests, push, and obtain
  an explicit `AUDIT PASS`.** Re-run the full verification set after any
  correctness change and request a second audit when the first audit identifies
  a defect.

### Task 7: Admin bypass merge and cleanup

- [ ] **Step 1: Merge only after explicit audit PASS.**

  ```bash
  gh pr merge <PR_NUMBER> --squash --admin
  gh pr view <PR_NUMBER> --json state,mergedAt,mergeCommit
  gh issue view 830 --json state
  ```

- [ ] **Step 2: Clean up the merged branch and worktree.** Verify the remote
  branch is gone, delete the local branch, remove only `/home/dev/wt/pr830`, and
  fast-forward the root `/home/dev/ferrogate` main worktree. Do not touch
  `/home/dev/wt/pr827`.

- [ ] **Step 3: Verify the final state.** Confirm root `main` is clean and
  synced, #830 is closed, the PR is merged, the feature branch and worktree are
  gone, and the existing #827 worktree still points at its original branch and
  commit.
