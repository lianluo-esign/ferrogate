# #860 Guardrail Evidence in Tenant Durable Objects

> Execution plan for #860, linked to #831. Guardrail evidence with a tenant
> attribution is authoritative in that tenant's `TenantDataObject`; the
> control-D1 copy remains a tenant-qualified derived projection until #825
> supplies the bounded fleet-read contract. Platform/unattributed evidence
> remains control-owned.

## 1. Establish both schemas and the red isolation contract

- Add `sql/d1-ts/tenant/0013_guardrail_evaluations.sql` with tenant-private
  parent and child tables, a non-null tenant column, the parent-child foreign
  key, policy/evidence lookup indexes, and no platform/unattributed rows.
- Add the control migration
  `sql/d1-ts/control/0015_guardrail_evidence_projection_keys.sql`. Rebuild the
  existing projection tables with a tenant-qualified `projection_key`, retain
  the logical `id` fields used by API documents, add tenant and parent
  projection keys to child rows, backfill existing rows, and preserve cascade
  deletion for projections.
- Regenerate `packages/storage/src/tenant-schema-sql.ts` with
  `node scripts/generate-tenant-schema-sql.mjs`; update schema census/version
  expectations if the focused object test identifies a stale count.
- Before production edits, add a real-object test in
  `packages/storage/test/do/tenant-data-object.test.ts` that writes the same
  evaluation/check ids into two tenant objects and proves both rows remain
  isolated, child rows cascade, and a tenant's schema reaches version 13.
- Run only the new test first and record the expected red failure; then run it
  again after the migration and generator change.

## 2. Make tenant objects authoritative at every gateway write path

- Extend `apps/gateway/src/guardrails/evidence-d1.ts` with separate tenant
  and control-projection UPSERT statements. Use the existing
  `evidenceProjectionKey` format for control rows and reject mixed-tenant or
  unscoped envelopes in a tenant-object batch.
- Update `apps/gateway/src/guardrails/evidence-sink.ts` and `config.ts` to
  resolve `TENANT_DATA`, group direct writes by tenant, write the object first,
  and then update the control projection. A projection failure must not turn a
  durable tenant-object write into a control-D1 fallback; a missing tenant
  object must remain an observable failed write.
- Update `apps/gateway/src/requestlog/queue.ts` so guardrail messages are
  grouped and written to their exact tenant objects before the mixed control
  projection batch. Preserve at-least-once retry behavior and keep
  platform/unattributed envelopes control-only.
- Keep the existing append capacity/refusal behavior and fail-closed guardrail
  enforcement semantics. The change is below `append`, in asynchronous flush
  and queue delivery only.
- Add gateway tests covering direct writes, queue writes, redelivery, same
  logical ids in two tenants, projection absence/failure, and a platform row
  that never enters a tenant object. The raw stored JSON must continue to omit
  detector plaintext.

## 3. Route admin reads to the exact authoritative object

- Update `apps/control-plane/src/routes/admin_request_log.ts` so tenant-scoped
  guardrail list pages read `guardrail_evaluations` and checks from
  `tenantEvidenceDatabaseFor`, while platform-operator pages continue reading
  the control projection and label it as derived.
- Change investigation selector discovery for tenant callers to query the
  exact object. Keep operator discovery on the control projection, then fan
  out attributed request/run/evaluation legs to exact tenant objects and keep
  only unscoped rows in control. Apply the tenant predicate before every object
  query and preserve the 404 behavior for another tenant.
- Update guardrail check joins and retention deletion to use the logical ids in
  tenant objects and the projection keys in control D1, without reintroducing
  a shared-D1 fallback.
- Extend `apps/control-plane/test/guardrail-evidence-read.test.ts` to seed
  authoritative tenant rows plus control projections, prove cross-tenant
  identical ids cannot collide or leak, prove operator pages use the
  projection, and prove tenant investigations ignore forged control rows.

## 4. Update ownership documentation and migration-facing fixtures

- Replace the stale control-authority comments in the guardrail DDL, gateway
  writer/sink, retention path, and control-plane investigation comments with
  the tenant-authoritative/projection contract.
- Update `docs/design/tenant-data-classification-2026-08.md` for C46/C47 and
  mark #860 Step 2 complete while retaining the #825 dependency for fleet
  readers. Update `docs/guardrails/investigation-view.md` to state the
  tenant-object source and operator projection freshness boundary.
- Update direct test harness migrations and seed helpers so they apply the
  deployed `0015` projection migration and the tenant schema rather than
  maintaining a divergent fixture.

## 5. Verify, audit, merge, and clean up

- Run focused red/green tests for storage, gateway guardrail writes/queue, and
  control-plane reads; then run package typechecks, lint/format checks, and
  `git diff --check`.
- Review the final diff for cross-tenant SQL predicates, migration order,
  projection key binding order, queue retry behavior, and fail-closed paths.
- Commit and push each reviewable slice to the already-open PR, then start a
  separate audit agent against the final PR diff and focused test output.
- Only after the audit agent reports no blocking issue, merge the PR into
  `main`, close #860 through the PR linkage, delete the remote/local feature
  branch, remove `/home/dev/wt/pr860`, and verify `main` is clean before
  selecting the next unblocked issue.

## Verification commands

```bash
node scripts/generate-tenant-schema-sql.mjs
bun run --cwd packages/storage test --run test/do/tenant-data-object.test.ts
bun run --cwd apps/gateway test --run test/guardrails/evidence-write.test.ts test/requestlog/write.test.ts
bun run --cwd apps/control-plane test --run test/guardrail-evidence-read.test.ts
bun run typecheck
bun run lint
git diff --check
```
