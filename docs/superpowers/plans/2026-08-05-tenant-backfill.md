# Tenant Backfill to Durable Objects

## Goal

Implement issue #824 for M9: move one tenant at a time from the shared legacy
tenant D1 database into its named `TenantDataObject`, with resumable copying,
table-level verification, an explicit cutover state machine, rollback guards,
and an audit trail for every transition.

The migration deliberately uses a **write freeze**. A tenant is frozen before
the first source scan, remains served by the shared database through
`copying`/`verifying`, and is served by the Durable Object only after `cut`.
The source rows are retained; this slice does not drop them. That makes a
verified rollback possible during the retention window and avoids silently
losing writes made by an object after cutover.

## Design

1. Extend `tenant_databases` with migration state and verification metadata.
   The legal states are `shared -> copying -> verifying -> cut -> done`; all
   state changes are compare-and-set transitions in the control database and
   append a row to control-plane `audit_events`.
2. Add a `LEGACY_TENANT_DB` binding to the control plane. It points at the
   existing shared `ferrogate-tenant` D1 database and is exposed through
   `ControlPlaneDeps`; the existing control-plane `DB` binding remains the
   registry/control database.
3. Add a storage-level `TenantBackfill` copier. Its table manifest is static
   and identifier-safe, covers every tenant-owned table in the tenant schema,
   excludes object-local migration metadata, and verifies source/target schema
   compatibility. Each page is copied with idempotent inserts in one
   `transactionSync` batch together with a durable cursor marker in the target
   object. A rerun therefore converges without duplicate rows.
4. Record deterministic row counts and checksums for every table on both sides.
   Verification fails if any table is omitted, changed, or has a different
   count/checksum. A source write fence is acquired before copying; object
   writes remain refused until cutover.
5. Make tenant resolution migration-state aware. `shared`, `copying`, and
   `verifying` resolve to the shared source; `cut` and `done` resolve to the
   tenant object. This is tested directly so serving an object during
   `copying` is a regression.
6. Add an operator-only admin operation for `start`, `resume`, `verify`,
   `cutover`, `rollback`, and status. The operation is contract-driven and
   linked to `#824`/`#821`; it is not an unguarded custom route. The response
   includes state, progress, per-table verification, and refusal reasons.
7. Rollback is allowed only before source retention expires and only when the
   object checksum still equals the checksum captured at cutover. Any object
   write makes rollback fail explicitly. Source rows are not deleted by this
   implementation.

## Implementation Tasks

### 1. Registry, bindings, and resolver

- Add the migration columns and indexes in
  `sql/d1-ts/control/0021_tenant_backfill.sql`; update the generated control
  schema artifact if the repository keeps one.
- Update `apps/control-plane/wrangler.toml`, `apps/control-plane/src/ports.ts`,
  and `apps/control-plane/src/adapters.ts` for `LEGACY_TENANT_DB`.
- Extend `packages/storage/src/tenant-router.ts` registration/handle types and
  backend dispatch so pre-cutover states cannot select `TENANT_DATA`.
- Add object-side migration admission/write-fence RPC and storage in
  `packages/storage/src/tenant-data-object.ts` and `packages/storage/src/tenant-do.ts`.

### 2. Copier and state machine

- Add `packages/storage/src/tenant-backfill.ts` with the manifest, safe SQL
  identifier handling, page cursor, idempotent copy, canonical value encoding,
  and table count/checksum calculation.
- Export the copier from `packages/storage/src/index.ts`.
- Add `apps/control-plane/src/store/tenant-backfill.ts` to own the control DB
  CAS transitions, freeze/cutover/rollback orchestration, retention checks,
  and audit event writes.
- Keep transition and marker writes durable and retryable; an interrupted
  page must be safe to rerun.

### 3. Admin operation and contract

- Add the migration operation(s) to
  `docs/openapi/runtime-api-contract.json` with platform-operator auth and the
  existing admin write scope.
- Add the handler in a dedicated control-plane route module and register it in
  `apps/control-plane/src/routes/index.ts`.
- Update the corresponding generated/admin API documentation and the route
  wiring tests. The operation must be listed in the console exclusion metadata
  if the console has no migration UI.

### 4. Tests and documentation

- Add focused control-plane tests covering all state transitions, audit rows,
  interruption/resume, source tenant isolation, resolver state gating, and
  rollback refusal after object writes.
- Add storage tests for all manifest tables, checksum mismatch, idempotent
  reruns, source write fencing, and wallet/reservation/settlement continuity.
- Add the documented freeze/retention runbook under `docs/` and update any
  storage migration notes that still imply an immediate object cutover.
- Run the issue-required commands:

  ```text
  bun run --filter '@ferrogate/app-control-plane' test
  bun run --filter '@ferrogate/storage' test
  bun run typecheck && bun run lint
  ```

  Also run the focused migration tests and `git diff --check` before review.

## Review and Integration Gates

1. Create and link the PR before implementation commits continue.
2. After implementation, run the focused tests and the full issue-required
   verification commands.
3. Use a fresh independent audit agent against the PR tip. Any correctness,
   isolation, rollback, auth, or test-gap finding must be fixed and re-tested.
4. Only after an explicit audit PASS, merge the PR with GitHub administrator
   bypass, close #824, delete the remote/local feature branch, and remove the
   `/home/dev/wt/pr824` worktree. Preserve `/home/dev/wt/pr827` unchanged.
