# Tenant Storage Backfill Runbook

This runbook covers the operator-controlled migration of one tenant from the
legacy shared tenant D1 to its Durable Object. The control-plane migration
state is the routing authority; do not edit `tenant_databases` directly during
an active migration.

## Preconditions

- The control database has the tenant backfill migrations and `0023_tenant_object_placement.sql` applied.
- The legacy shared tenant database has migration `0021_tenant_backfill_fence.sql`
  applied.
- The Worker has `LEGACY_TENANT_DB`, `CONTROL_DB`, and `TENANT_DATA` bindings.
- The tenant is registered in `tenant_databases` and the destination object can
  be addressed by its tenant id.
- An observed `location_hint` from the tenant's traffic is available. The request
  body must include it on every migration action; the control-plane job's own
  location is not a valid substitute. The hint is best effort, and `sam`, `afr`,
  and `me` currently have no Durable Object capacity.
- If the tenant has an EU residency policy, the registry row must carry
  jurisdiction `eu`. Jurisdiction is part of the Durable Object address; changing
  it after creation requires a data migration.
- The operator has confirmed that the source will remain available for the
  configured rollback retention period.

The migration deliberately uses a freeze strategy. Once `start` succeeds,
source-side write triggers reject inserts, updates, and deletes for the tenant.
The object migration RPC is the only write capability during `copying` and
`verifying`; ordinary query, batch, privileged, audit, and schedule writes are
frozen in those states and also in `cut`.

## Procedure

Use the platform-operator endpoint:

```text
POST /admin/v1/tenant-accounts/{tenant_id}/storage-migration

{
  "action": "start",
  "location_hint": "weur"
}
```

1. Call `start`. This freezes the shared source, claims the object migration
   epoch, and moves the control row to `copying`.
2. Call `resume` until the response reports `verifying`. Each call copies a
   bounded page and persists a keyset cursor. Repeating the call is safe after
   a Worker interruption.
3. Inspect the returned receipt. Every manifest table must have matching source
   and destination row counts and SHA-256 checksums. A non-empty table without a
   safe ownership predicate fails closed.
4. Call `cutover`. The source receipt is recomputed before routing changes. The
   object enters `cut` first, the control row becomes `cut`, and only then does
   the object enter `done`. This keeps both sides read-only across the routing
   change.
5. Verify normal tenant operations, including wallet reservation and
   settlement, against the object. The source remains fenced during retention.

`status` is read-only. `verify` is useful for an explicit verification pass but
does not replace the source freeze or the receipt check performed by
`cutover`.

## Recovery and rollback

If a call fails, inspect `migration_last_error` and retry `resume`, `verify`, or
`cutover` according to the current state. State changes use a control-D1 CAS
and the corresponding `audit_events` append in one batch, so a failed transition
does not leave an un-audited state advance. Object mode and epoch are also
checked on every recovery path.

Rollback is allowed only while `migration_retention_until_unix` has not expired
and the object has accepted no writes after verification. Call `rollback` from
`cut` or `done`; it moves the object to a new-epoch `shared` mode, restores the
control router to the legacy source, and then opens the source fence. If the
object write epoch changed, rollback is refused because the two stores no
longer represent the same snapshot.

Do not drop or mutate the shared source until retention has expired and an
independent export/retention decision has been recorded. A source fence left in
`frozen` mode is intentional after cutover and is not evidence that the
migration is stuck.

## Audit and evidence

Each state transition is recorded in the control database `audit_events` chain.
Keep the migration response, receipt, request id, and final status with the
deployment record. The receipt is the verification evidence; a successful
HTTP response alone is not sufficient evidence to delete the source.
