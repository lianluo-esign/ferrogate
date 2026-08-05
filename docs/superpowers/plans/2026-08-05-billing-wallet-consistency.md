# M9 Step 9: Billing and Wallet Consistency Plan

**Goal:** Make tenant billing state authoritative inside the tenant Durable Object so a settled charge, wallet balance movement, and billing report intent share one atomic transaction, while preserving control-plane reporting and operator replay through derived projections.

**Scope:** `billing_events`, `billing_ledger`, `billing_report_outbox`, wallet reserve/settle/release, workflow-budget tenant routing, gateway metering, outbox recovery, and control-plane billing reads/replay. Existing control billing rows remain as compatibility/projection state until a later retirement slice; they are not treated as the tenant authority.

**Invariants:**

- Every tenant-local billing row carries an explicit `tenant_id`; routing never depends on parsing payload JSON.
- A priced charge claims the billing event, writes the ledger entry, creates its outbox intent, and applies its exact integer-credit wallet delta in one tenant `batch()`/DO transaction.
- Replay is idempotent by charge/settlement id and rejects divergent tenant, event, or credit payloads.
- Admission reserve and release remain guarded atomic operations; a failed or unavailable wallet never becomes an overdraft or a false 429.
- `credits_exact`/decimal-string handling remains lossless past the JavaScript safe-integer range.
- Control-plane views are projections and may lag, but a projection failure never deletes tenant-authoritative billing or outbox state.

## Task 1: Establish the red contract

Add focused failing tests before changing production code:

- Real tenant-DO storage tests prove the billing tables exist in a tenant object, include `tenant_id`, and cannot accept a row for another tenant.
- Real D1/DO tests prove a billing claim, ledger row, outbox row, and wallet settlement either all commit or all roll back.
- Replay tests prove the same charge is a no-op, a changed tenant/credit document is a conflict, and a failed outbox statement does not debit the wallet.
- Gateway metering tests prove a durable-object tenant is selected by the charge tenant rather than the control `BILLING_DB`.
- Outbox recovery tests prove due rows are swept per provisioned tenant and dead-letter replay addresses the tenant object.

Files: `packages/storage/test/d1/*billing*.test.ts`, `packages/storage/test/do/*`, `apps/gateway/test/metering/*`, `apps/control-plane/test/billing-replay.test.ts`.

## Task 2: Add tenant-local billing schema and explicit ownership

Create `sql/d1-ts/tenant/0020_billing_wallet_consistency.sql` and regenerate `packages/storage/src/tenant-schema-sql.ts`.

- Add tenant-local `billing_events`, `billing_ledger`, and `billing_report_outbox` with explicit `tenant_id` columns and tenant/time indexes.
- Keep the lossless `entry_json` document plus `credits_exact` field; do not introduce REAL arithmetic for credits.
- Add any required tenant-local projection/retry table for control-plane synchronization.
- Add a control migration that appends `tenant_id` to existing billing compatibility rows with a safe backfill from the stored documents where possible, leaving legacy/unattributed rows explicitly identifiable.
- Update schema census, migration, and fixture expectations without editing an already-applied migration in place.

## Task 3: Implement one tenant billing transaction

Extend the durable billing storage boundary with a tenant-aware store/factory over `TenantDatabaseHandle`.

- Reuse the existing billing serialization and idempotency contracts.
- Build the tenant batch so billing event claim, ledger insert, outbox insert, wallet settlement claim/debit/finalization, and any usage claim execute in one transaction.
- Use the existing wallet SQL guard semantics and exact decimal-string bindings; avoid calling a second public store method that would open a separate transaction.
- Preserve `recorded`/`duplicate`/`conflict` outcomes and make missing opt-in wallets a no-wallet outcome rather than a swallowed settlement claim.
- Keep workflow budget operations on the same routed tenant handle and add a cross-store consistency test showing billing and budget state cannot be read from the shared control database in durable-object mode.

Likely files: `packages/billing/src/metering/d1.ts`, `packages/billing/src/metering/ports.ts`, `packages/storage/src/d1/wallet-d1.ts`, `packages/storage/src/d1/index.ts`, and the new tenant schema migration.

## Task 4: Route gateway metering by tenant

Update the metering binding resolver and sink so each charge uses its authenticated/persisted tenant authority.

- Resolve `TENANT_DATA`/tenant D1 by `tenantId`; use the control database only for explicitly unscoped compatibility traffic and projections.
- Cache backends per environment and tenant, never only per environment.
- Settle the exact negative wallet delta from the priced charge in the same tenant billing transaction; keep admission hold release independent and idempotent.
- Make unpriced events tenant-local and durable without fabricating a zero-cost ledger charge.
- Preserve Queue delivery, retry, dead-letter, and duplicate-report behavior.

Files: `apps/gateway/src/metering/runtime.ts`, `apps/gateway/src/metering/middleware.ts`, `apps/gateway/src/metering/sink.ts`, `apps/gateway/src/metering/usage-ledger.ts`, and gateway metering tests.

## Task 5: Repair and expose projections

Keep control-plane reporting usable without making control D1 authoritative:

- Project tenant billing events/ledger summaries into control D1 with explicit tenant keys and retry state after the tenant transaction commits.
- Make admin metering feeds and cost/finops reads use tenant-local data for tenant-scoped callers and the control projection for platform-wide callers.
- Make dead-letter replay locate the owner from the explicit tenant column, authorize it, and re-arm the tenant outbox row through the same tenant router.
- Update scheduled gateway recovery to enumerate provisioned tenants, sweep each tenant outbox, and preserve the existing grace/backoff/dead-letter policy.

Files: `apps/gateway/src/index.ts`, `apps/control-plane/src/routes/billing.ts`, `apps/control-plane/src/finops/*`, `apps/control-plane/src/store/*`, and related tests.

## Task 6: Documentation and compatibility cleanup

Update the tenancy split, billing storage comments, migration notes, and operator-facing design documentation to state:

- tenant DOs own billing/wallet/workflow-budget state;
- control D1 contains account-global policy and derived billing projections;
- legacy control billing tables are compatibility state, not the source of truth;
- only the explicit shared-development mode may use a shared tenant database.

Remove stale comments that say `BILLING_DB` is the billing authority, while preserving compatibility tests for the legacy mode.

## Task 7: Verification and audit

Run focused storage, gateway, control-plane, and agent-runtime tests first, then affected package typechecks/lint and the full repository gates where practical. Run mutation checks for the transaction guard, tenant routing, and credit-width paths. Ask an independent auditor to inspect the diff and test evidence before creating the merge commit. Fix every finding, push the final branch, and only then use the requested GitHub admin/bypass merge flow.
