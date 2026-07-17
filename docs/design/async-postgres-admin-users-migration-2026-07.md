# #221 slice: async-migrate the Admin-Users repo

Part of issue #221 (migrate all PostgreSQL access to `tokio-postgres` +
`deadpool-postgres`). Prior slices merged: mcp_identity, rbac,
billing/wallet/budget-alert, tenancy/quota/api-key, observability, AgentRun,
Worker (managed + self-hosted), Assets. This doc plans the admin-console
identity repo (admin users, tenant memberships, refresh tokens — issue #161).

## Scope — 10 storage methods, all simple-CRUD

`impl PostgresControlPlaneStore` in `crates/ferrogate-storage/src/lib.rs`:
`upsert_admin_user`, `get_admin_user_by_id`, `get_admin_user_by_email`,
`upsert_admin_user_membership`, `list_admin_user_memberships_by_user`,
`list_admin_user_memberships_by_tenant`, `delete_admin_user_membership`,
`upsert_admin_user_refresh_token`, `get_admin_user_refresh_token_by_hash`,
`revoke_all_admin_user_refresh_tokens` — convert from sync `with_client` to
`async_pool.acquire(...).await`. All simple-CRUD (no transactions). Add an
`admin_user_operation()` helper. `RuntimeStorageRepositories` facades become
`async fn` (`.await` the Postgres arm; Memory arms unchanged).

Verify admin users are NOT part of `export/import_migration_snapshot` (grep) —
if absent, no `bridge_runtime` bridge is needed there.

## Architecture — bridge the sync admin-console HTTP server (established pattern)

Every one of the ~44 call sites is in `crates/ferrogate-auth/src/lib.rs`, and
**all are in sync `fn`s** — the admin-console / SCIM / SSO HTTP handlers
(`handle_admin_register`, `handle_admin_login`, `handle_admin_refresh`,
`handle_admin_logout`, `handle_admin_me`, `current_admin_session`,
`handle_admin_team_*`, `handle_scim_*`, `handle_sso_callback`, `issue_session`,
`deactivate_admin_user`, `reactivate_admin_user`, `membership_role_in_tenant`).

`ferrogate-auth` **already owns** a `block_on_sync_bridge` (lib.rs:1124 — same
`Handle::try_current()` + multi-thread-flavor check as the CLI's, falling back
to a scoped current-thread runtime) and already uses it for the tenancy-slice
methods (`upsert_tenant_account`/`upsert_project`/`upsert_workspace`). So this
slice keeps the sync HTTP handlers sync and wraps each now-async
`console.repositories.<admin_user_method>(...)` call in `block_on_sync_bridge`.
No handler signature changes; blast radius confined to `ferrogate-auth/src/lib.rs`.

## Steps

1. Storage: 10 methods → async simple-CRUD; add `admin_user_operation()`.
2. Facades → async, `.await` Postgres arm.
3. Confirm no migration-snapshot involvement (grep); bridge if present.
4. `ferrogate-auth/src/lib.rs`: wrap the ~44 sync call sites in
   `block_on_sync_bridge(...)`, preserving the surrounding `?`/`match`/`if let`
   shapes.
5. Test fixups: storage-lib unit tests + `admin_console_test.rs` (already uses
   `block_on_sync_bridge`) + `supabase_roundtrip.rs` admin-user round-trip if
   present.

## Verification

`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config-validation + Python CI-gate tests;
storage-lib, ferrogate-auth, CLI-bin unit tests; admin-console / SCIM / SSO
integration tests. No reachable Postgres → real async-pool path exercised only
via in-memory + structural tests; docker-gated supabase tests skip gracefully.

Adversarial diff review (ultracode): a verification pass confirming every one
of the ~44 call sites is bridged (none left returning a bare future), no
behavior change in the sync handlers, and fmt/clippy clean.

## After this slice

Remaining sync `lib.rs` repos: document store / schema (initialize_schema,
validate_schema, seed_missing_resources, list_resource_documents,
list_documents, get_document, upsert, replace_kind, delete), guardrail policy
(revisions/bindings incl. CAS), usage-monthly rollups + billing ledger +
billing_events reads; and `guardrail_evidence.rs`'s `spawn_blocking` write path.
Then delete the sync `postgres` driver + `PostgresClientPool` and verify with
`cargo tree -i postgres`.
