# Tenant Configuration and Policy Migration Matrix

Issue #863 is M9 Step 5 of #831. This matrix is the contract for moving
tenant-owned configuration and policy state into the tenant's
`TenantDataObject`. It follows `docs/design/tenant-data-classification-2026-08.md`:
physical tenant isolation is authoritative, while shared control data remains
available only where the classification requires it.

## Classification Matrix

| Record | Current control table | Authoritative store after Step 5 | Tenant-object table | Shared data retained | Read/write rule |
| --- | --- | --- | --- | --- | --- |
| Provider credentials | `tenant_provider_credentials` | Tenant object | `tenant_provider_credentials` | None; encrypted envelope fields only | Resolve by `(tenant_id, alias)` in the addressed object. Missing or unavailable object fails closed. |
| SSO configuration | `sso_provider_configs` | Tenant object | `sso_provider_configs` | `sso_pending_flows` remains shared because the callback starts with opaque `state` | Start/callback resolves the tenant, then reads the object. Pending-flow lookup never becomes a tenant-object lookup. |
| Tenant role bindings | `tenant_role_bindings` | Tenant object | `tenant_role_bindings` | `roles` and `permissions` remain shared and operator-authored | Binding writes require the privileged object write path. Readers join bindings to the local role snapshot, never to a control binding table. |
| Semantic-cache policy | `semantic_cache_policies` | Tenant object | `semantic_cache_policies` | None | Scope reads and writes are routed to the addressed tenant object. No control fallback on read failure. |
| Delegation revocations | `delegation_revocations` | Tenant object | `delegation_revocations` | None | Revocation checks use the tenant object selected from the authenticated tenant. An unavailable source rejects a presented delegation chain. |
| Replay floors | `control_plane_replay_floors` | Tenant object | `control_plane_replay_floors` | None | Monotonic raise/read operations are executed in the addressed tenant object with the existing high-water semantics. |
| Budget-alert state | `budget_alert_notifications` | Tenant object | `budget_alert_notifications` | Alert thresholds still come from shared quota policy/catalog data | Every claim and read includes an explicit `tenant_id` predicate in addition to scope, period, and threshold. |

## Shared and Derived Boundaries

- `roles` remains a platform-shared, operator-authored catalog. The tenant
  object stores a narrow role snapshot containing the permission keys needed by
  local authorization. A binding is effective only when its local snapshot is
  present and valid.
- Platform catalogs and other account-wide registries remain in CONTROL. They
  are not copied into this migration unless the classification document names a
  tenant-owned projection.
- `sso_pending_flows` remains shared: its opaque callback state is the routing
  key and the callback does not carry a tenant id.
- No compatibility row in CONTROL is an authority read. Any temporary legacy
  projection or reverse projection is write-only compatibility and is updated
  only after the tenant-object write succeeds.

## Fail-Closed Rules

1. Normal tenant-object SQL cannot write role bindings. The dedicated
   privileged write RPC is the only path that can update a binding and its
   role snapshot.
2. A missing role snapshot, a missing shared role, malformed permission data, or
   a failed reverse projection produces no authorization grant. Readers never
   fall back to `CONTROL.tenant_role_bindings` or `CONTROL.roles` for a tenant
   binding decision.
3. A missing or unreadable tenant object does not fall back to the old control
   table for credentials, SSO configuration, semantic-cache policy, delegation
   revocations, replay floors, or budget-alert state.
4. Legacy rows are copied into the object only through an idempotent,
   tenant-scoped backfill. The backfill records completion in the object and
   does not delete the legacy source until the migration policy explicitly
   authorizes retirement.

## Migration and Verification Order

1. Add the tenant-object tables and the operator-only binding/snapshot write
   contract; prove schema shape, privileged writes, rollback, and two-tenant
   isolation.
2. Rename old CONTROL tables to explicit legacy names and add an idempotent
   tenant-scoped backfill. The old names must not remain an authority surface.
3. Switch control-plane writes and all gateway/MCP/agent readers to the object
   route. Verify each read path has no CONTROL fallback and each write carries
   the authenticated tenant.
4. Run focused Durable Object, storage, control-plane, gateway, MCP, and agent
   tests, then the relevant package typechecks and integration suites.

The matrix is intentionally limited to the seven records named by #863.
Quota policy definitions, platform catalogs, MCP identity records, and other
M9 steps remain governed by their own classification rows and issues.
