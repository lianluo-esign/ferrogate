// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Per-tenant Cloudflare D1 control-plane backend (issue #420): tenant->database
// provisioning over the D1 REST API plus the core-entity subset of `ControlPlaneStore`.

//! # Cloudflare D1 control-plane backend (issue #420)
//!
//! The third [`ControlPlaneStore`] backend: FerroGate control-plane entities
//! persisted in **per-tenant Cloudflare D1 databases** over the D1 HTTP query
//! API (`ferrogate_cloudflare::d1`), replacing shared-Postgres row-level
//! isolation with physical database-per-tenant isolation.
//!
//! **When a family lands (or stops erroring), update `docs/cloudflare-d1-backend.md`
//! in the SAME commit** — specifically its "Implemented vs erroring trait surface"
//! and "Remaining scope" sections. That doc is the operator-facing map of which
//! surfaces work on D1, and it silently drifted across issues #454/#455/#456/#460
//! (corrected in #456) because it is not derived from this list.
//!
//! ## Topology and routing
//!
//! - One **control database** holds the `tenants` table, the generic
//!   `control_plane_resources` config-document table, and the
//!   tenant->database registry document.
//! - One **tenant database** per tenant holds that tenant's `projects`,
//!   `workspaces`, and `api_keys` rows (schema: `sql/d1/001_init_d1.sql`).
//! - Writes route on the entity's `tenant_id`; an EMPTY `tenant_id` routes to
//!   the control database (pre-multi-tenant records). Id-only reads and
//!   unfiltered lists fan out over the control + all registered tenant
//!   databases — acceptable on this admin/low-volume path, see the
//!   rate-limit section below.
//!
//! ## Tenant->database registry
//!
//! [`D1TenantDatabaseRegistry`] maps `tenant_id` -> D1 database uuid and
//! names the control database. It is persisted through the EXISTING
//! config-document surface (kind [`D1_TENANT_DATABASE_REGISTRY_KIND`], id
//! [`D1_TENANT_DATABASE_REGISTRY_ID`]) rather than any new storage: on this
//! backend that document lives in the control database's
//! `control_plane_resources` table, and a deployment whose admin store is
//! Postgres can persist the same document there (the Postgres backend's
//! kind-keyed table accepts arbitrary kinds).
//!
//! ## Rate-limit strategy (issue #420 acceptance)
//!
//! The public Cloudflare REST API allows ~1,200 requests / 5 min / user, so
//! this raw-HTTP backend is the **admin / low-volume** path: provisioning,
//! schema migration, control-plane CRUD, config documents. Hot-path traffic
//! (request logs, usage aggregates, billing events) must instead go through
//! a **proxy Worker holding a D1 binding** (`docs/cloudflare-deploy-topology.md`
//! §bindings `outboundByHost` shim; `docs/cloudflare-integration.md` §6) —
//! which is exactly why the high-write trait surface below is typed as
//! unimplemented instead of being routed over raw HTTP.
//!
//! ## Config-driven construction (issue #440)
//!
//! [`RuntimeStorageRepositories::cloudflare_d1_from_client`] is the storage
//! half of the `storage.provider = "cloudflare_d1"` route: it seeds the
//! tenant->database registry from [`CloudflareD1StorageOptions`] (the
//! operator's `control_database_id` + any resumed tenant databases) and wraps
//! the store. The caller owns the transport — it builds the
//! `CloudflareClient`/[`D1Client`] from the `[cloudflare]` block and passes it
//! in — so this crate stays transport-free and unit-testable. Absent config
//! selects nothing; the backend is opt-in.
//!
//! ## Implemented vs erroring trait surface
//!
//! Implemented against D1 (issue #420 core + #440 auth/quota families):
//! - API keys: `upsert_api_key_record`, `get_api_key_record`,
//!   `list_api_key_records`, `find_api_key_records_by_prefix`.
//! - Tenant accounts: `upsert_tenant_account`, `get_tenant_account`,
//!   `list_tenant_accounts`.
//! - Projects: `upsert_project`, `get_project`, `list_projects`,
//!   `delete_project`, `delete_project_if_unreferenced`.
//! - Workspaces: `upsert_workspace`, `get_workspace`, `list_workspaces`,
//!   `delete_workspace`, `delete_workspace_if_unreferenced`,
//!   `resolve_workspace_scope`.
//! - Admin users (#440, control database): `upsert_admin_user`,
//!   `get_admin_user_by_id`, `get_admin_user_by_email`,
//!   `upsert_admin_user_membership`, `list_admin_user_memberships_by_user`,
//!   `list_admin_user_memberships_by_tenant`, `delete_admin_user_membership`.
//! - Admin refresh tokens (#440, control database):
//!   `upsert_admin_user_refresh_token`, `get_admin_user_refresh_token_by_hash`,
//!   `revoke_all_admin_user_refresh_tokens`,
//!   `revoke_admin_user_refresh_tokens_for_tenant`.
//! - SSO (#440, control database): `upsert_sso_provider_config`,
//!   `get_sso_provider_config`, `delete_sso_provider_config`,
//!   `insert_sso_pending_flow`, `take_sso_pending_flow` (read-then-delete,
//!   since the HTTP query API has no `DELETE ... RETURNING`).
//! - Quota policies + plans (#440, control database): `upsert_quota_policy`,
//!   `get_quota_policy`, `list_quota_policies`, `delete_quota_policy`,
//!   `upsert_plan`, `get_plan`, `list_plans`.
//! - Config documents (generic, kind-keyed, control database):
//!   `upsert_config_document`, `delete_config_document`,
//!   `get_config_document`, `list_config_documents`,
//!   `list_config_resource_documents`, `replace_config_documents`,
//!   `control_plane_snapshot`, `config_documents`.
//! - RBAC (#445, control database): `upsert_permission`, `get_permission`,
//!   `list_permissions`, `delete_permission`, `upsert_role`, `get_role`,
//!   `list_roles`, `delete_role`, `bind_tenant_role`,
//!   `list_tenant_role_bindings`, `unbind_tenant_role`.
//! - Site domains (#445, control database): `upsert_site_domain`,
//!   `get_site_domain`, `list_site_domains`, `delete_site_domain`.
//! - Budget alert idempotency ledger (#445, control database):
//!   `record_budget_alert_notification`, `budget_alert_already_notified`,
//!   `list_budget_alert_notifications`.
//! - Observability append/analytics (#447, control database): agent runs
//!   (`upsert_agent_run`, `agent_run`, `agent_runs`, `agent_runs_by_ids`),
//!   agent run events (`append_agent_run_event`, `agent_run_events`,
//!   `agent_run_events_for_runs`), request logs (`append_request_log`,
//!   `request_logs`, `request_logs_page`, `delete_request_logs`,
//!   `request_logs_for_agent_runs`), audit events (`append_audit_event`,
//!   `audit_events`, `audit_events_page`, `delete_audit_events`,
//!   `audit_events_for_agent_runs`), and the cross-family
//!   `agent_run_summary_seed_ids`. Each row stores the FULL record as a
//!   `*_json` document (deserialized on read) plus projection columns; these
//!   route to the CONTROL database (not per-tenant) because their analytics
//!   reads are cross-tenant whole-table scans and the `tenant` column is a
//!   composite storage key, not a routing tenant id -- so a single-query
//!   control-database mirror of the Postgres single-table ordering/pagination/
//!   UNION seed is cleaner than a lossy per-tenant fan-out merge. The `()`/
//!   `Vec`/`Option`-returning surfaces swallow-with-warn on error like the
//!   Postgres backend; the `Result`-returning ones surface it.
//! - Snapshot replay floors (#206/#447, control database):
//!   `get_snapshot_replay_floor`, `advance_snapshot_replay_floor`. SQLite
//!   `max()` in the upsert keeps the floor monotonic; a follow-up SELECT
//!   returns it (the HTTP query API has no `RETURNING`).
//! - Billing ledger + report outbox + billing events (#449, control database):
//!   `append_billing_ledger_entry` (idempotent INSERT ... DO NOTHING + a
//!   reload/settlement-compare on conflict), `list_billing_ledger_entries`
//!   (scope-filtered, paginated), `billing_ledger_entry`; the report outbox
//!   (`enqueue_billing_report`, `list_due_billing_reports`,
//!   `reschedule_billing_report`, `dead_letter_billing_report`,
//!   `list_dead_lettered_billing_reports`, `replay_dead_lettered_billing_report`
//!   (guarded UPDATE + follow-up SELECT for the terminal state),
//!   `get_billing_report_outbox_entry`, `delete_billing_report`); and settled
//!   metering events (`append_billing_event`, `billing_events`,
//!   `billing_events_page`). Billing is account-global cross-tenant metering
//!   with whole-table reads, so it routes to the CONTROL database like the #447
//!   observability families; each row stores the FULL record as a `*_json`
//!   document plus the filter/order/paginate projection columns, with the
//!   outbox attempt/schedule state kept as columns so reschedule/dead-letter/
//!   replay stay single-statement UPDATEs.
//! - Guardrail policy revisions + bindings (#449, control database):
//!   `insert_guardrail_policy_revision` (idempotent on `(policy_id, revision)`,
//!   typed `Conflict` on replay), `get_guardrail_policy_revision`,
//!   `list_guardrail_policy_revisions`, `get_guardrail_policy_binding`,
//!   `list_guardrail_policy_bindings`. Account-global guardrail configuration
//!   (like plans/RBAC), so the CONTROL database owns them.
//! - Guardrail binding CAS transitions (#454, control database, proxy Worker):
//!   `activate_guardrail_policy_revision`, `archive_guardrail_policy_revision`,
//!   `restore_guardrail_policy_binding` -- the generation-guarded
//!   compare-and-swaps on the single mutable `guardrail_policy_bindings` row.
//!   Each routes through the proxy-Worker `/d1/query` binding as one guarded
//!   `UPDATE`/`INSERT`/`DELETE ... RETURNING policy_id`; an empty `RETURNING`
//!   set is the lost-update signal (the REST query API cannot express it) and
//!   maps to the typed CAS `Conflict`. Account-global, so the proxy's control-DB
//!   binding serves them with no per-tenant binding; they reuse the SAME pure
//!   next-binding planners the Postgres backend uses, so the computed transition
//!   is row-for-row identical across backends. Fail closed (typed
//!   unimplemented-surface) when no proxy Worker is bound.
//! - Wallets + reservations (#455/#456, TENANT databases, proxy Worker): the
//!   FIRST tenant-scoped atomic family. `reserve_wallet_credits` (the no-oversell
//!   guarded conditional insert), `settle_wallet_reservation`,
//!   `release_wallet_reservation`, `settle_wallet_balance`,
//!   `adjust_wallet_balance`, `set_wallet_dunning`, plus
//!   `upsert_wallet`/`get_wallet`/`list_wallets`/`list_wallet_reservations`.
//!   Unlike the account-global families above, a tenant's wallet/holds/
//!   settlements live in THAT tenant's own D1 database, so each op selects
//!   `tenant_database_binding(tenant_id)` onto the proxy `/d1/batch` +
//!   `/d1/query` calls (issue #455 per-tenant routing; there is no runtime
//!   select-a-database-by-id, so the binding must be declared + redeployed per
//!   tenant). `reserve` mirrors the Postgres `FOR UPDATE` + sum-live-holds as one
//!   atomic batch (RETURNING-empty on the guarded insert = not admitted; a
//!   sibling state read splits NoWallet from Insufficient). `settle_wallet_balance`
//!   claims the `settlement_id` and moves the balance as one guarded atomic batch
//!   (idempotent replay = first outcome; records even when there is no wallet
//!   row). `adjust`/`set_dunning` are single `UPDATE ... RETURNING`/`UPDATE`
//!   statements on the tenant DB. `settle`/`release`/`list_wallets`, whose
//!   signatures carry only a hold id or no tenant at all, fan out over the
//!   provisioned tenant bindings — `list_wallets` reads each tenant DB's single
//!   wallet row cross-tenant (issue #456), then orders by `tenant_id` to match
//!   Postgres. A per-tenant mutation (settle-balance/adjust/set-dunning) on an
//!   UNPROVISIONED tenant is a typed `NotFound` (no tenant DB to route to), the
//!   same database-per-tenant divergence `reserve` makes, where Postgres records
//!   the settlement / returns `Ok(None)` / no-ops. Fail closed (typed
//!   unimplemented-surface) with no proxy; see `wallet.rs`.
//! - Usage rollups (#456, TENANT databases, proxy Worker): the usage-report
//!   read surface + the durable usage-aggregate write.
//!   `get_usage_monthly_rollup`/`list_usage_monthly_rollups` fan out over the
//!   provisioned tenant bindings (a scope's rollup lives in the OWNING tenant's
//!   DB, and the signatures carry no tenant id for project/workspace/key scopes),
//!   re-merging to the Postgres `ORDER BY`. `list_usage_metadata_rollups` routes
//!   to the org's own DB for a tenant-scoped read (opt-in: empty for an
//!   unprovisioned/empty org) and fans out for the operator `None` view.
//!   `persist_usage_aggregate` is the durable settlement RMW: a `tenant_contexts`
//!   upsert + a `usage_aggregate_rollups` REPLACE as ONE atomic `/d1/batch` on
//!   the owning tenant's DB (no lost updates), mirroring the Postgres
//!   transaction; an org-less/unprovisioned aggregate is a typed `NotFound` (the
//!   database-per-tenant divergence). The process-local `usage_aggregates` mirror
//!   below stays the read-of-record for `usage_aggregates`/committed-token sum.
//!   Fail closed (typed unimplemented-surface) with no proxy; see `usage.rs`.
//! - Assets + channels + retention (#456, TENANT databases, proxy Worker): the
//!   hosted-asset storage family (issues #176/#260/#263/#366/#371). Tenant-routed
//!   writes/reads (`upsert_asset`, `create_asset_within_quota`/`_if_absent`,
//!   `list_assets`/`list_withheld_assets`, `tenant_asset_storage_bytes_used`,
//!   channel + retention upserts/lists); id-only reads/deletes (`get_asset`,
//!   `delete_asset`, `delete_asset_channel`, `promote_pending_asset_visibility`)
//!   fan out to locate the owning tenant DB; the operator cross-tenant lists
//!   (`list_all_assets`/`list_all_asset_channels`) fan out + re-sort to the
//!   Postgres order. `create_asset_within_quota` mirrors the wallet reserve —
//!   a `CAST(? AS INTEGER)` quota guard admitting only the fitting set, with a
//!   bare `ON CONFLICT DO NOTHING` mapping a dual-unique-constraint first-push
//!   loser to `AlreadyExists`/`Ok(false)` (the #369 fix) not a raw error. The
//!   #367 coordination ops (`move_asset_channel_if_resolvable`,
//!   `set_asset_version_yank`, `delete_asset_variant_if_unreferenced`) replicate
//!   the Postgres `FOR UPDATE` cross-table transitions as guarded single-batch
//!   statements (the resolvability/reference guard and the write share one
//!   implicit SQLite transaction). Inline BYTEA `content` rides a base64 TEXT
//!   column; `promote` fails closed to `Quarantined` on an unknown token. Fail
//!   closed (typed unimplemented-surface) with no proxy; see `assets.rs`.
//! - Workflow-run execution budgets (#456/#279, TENANT databases, proxy Worker):
//!   the durable per-run execution envelope. `open` is an idempotent
//!   insert-then-reload as ONE `/d1/batch` on the run's OWNING tenant DB; `list`
//!   routes to the tenant's own DB (opt-in empty for an unprovisioned tenant);
//!   `debit`/`topup`/`get` carry only the run id, so they FAN OUT over the
//!   provisioned tenant bindings to locate the holding database (the wallet
//!   id-only-locate pattern). D1/SQLite has no `SELECT ... FOR UPDATE`, so `debit`
//!   mirrors the Postgres row-locked read-modify-write with an INTERNAL bounded
//!   optimistic-CAS retry: read the counters, decide `Applied`/`Exceeded` via the
//!   SHARED `dimension_exceeded_by` arithmetic, then a guarded `UPDATE ... WHERE
//!   <status + spent_* counters + caps unchanged since the read> RETURNING` (an
//!   empty RETURNING = a concurrent debit/top-up landed in between → re-read +
//!   retry). This preserves the no-lost-debit / fail-closed-`Exceeded` invariants
//!   while keeping the `WorkflowBudgetDebit` contract UNCHANGED (`Applied`/
//!   `Exceeded`, NO new `Conflict` variant → zero caller changes, no #415
//!   non-exhaustive-match hazard). `topup` reuses the SAME `apply_topup`
//!   arithmetic under a caps-guarded CAS-retry, so the raised envelope is
//!   row-for-row identical across backends. An UNPROVISIONED tenant is `NotFound`
//!   on the writes (`open`), the database-per-tenant divergence. `CAST(? AS
//!   INTEGER)` guards every bound numeric param in the debit fit-arithmetic (the
//!   #455 lesson). Fail closed (typed unimplemented-surface) on `debit`/`topup`
//!   with no proxy; see `workflow_budget.rs`.
//! - Agent schedules + fire history (#460/#246, TENANT databases, proxy Worker):
//!   the time-based schedule DEFINITIONS + the idempotent fire-history ledger.
//!   `upsert_agent_schedule`/`list_agent_schedules` route by tenant (`upsert` is a
//!   write, so an unprovisioned tenant is `NotFound`; `list` is opt-in empty);
//!   `list_all_agent_schedules` fans out + re-sorts to the Postgres
//!   tenant/workspace/name order; `list_due_agent_schedules` fans out with a
//!   per-binding `LIMIT` then re-sorts by next-fire-ascending and truncates to a
//!   GLOBAL `limit`; `get`/`delete`/`insert_agent_schedule_fire`/
//!   `list_agent_schedule_fires` carry only an id, so they fan out to locate the
//!   tenant DB holding the schedule. `delete` cascades the fire rows itself as one
//!   `/d1/batch` (the FK-free D1 dialect drops the Postgres `ON DELETE CASCADE`);
//!   `insert_agent_schedule_fire` locates the schedule's DB then runs the
//!   at-most-once `ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING
//!   RETURNING fire_id` gate (empty RETURNING = a concurrent instance already
//!   recorded the slot), returning `NotFound` for an unknown schedule. No CAST is
//!   needed (no bound param enters an arithmetic expression). Fail closed with no
//!   proxy; see `agent_schedule.rs`.
//! - Observed-agent presence (#460/#357, TENANT databases, proxy Worker): the
//!   durable coalesced presence signal. `touch_observed_agent_presence` routes to
//!   the tenant binding as ONE conditional upsert mirroring the Postgres coalesced
//!   `#357` clause with SQLite's scalar `max(x,y)`/`min(x,y)` (SQLite has NO
//!   `GREATEST`/`LEAST`) over the `excluded.*` columns (already INTEGER-affinity,
//!   so no CAST) + `request_count += excluded.request_count` — so a burst of
//!   touches stays a single-row hot write and a delayed touch never regresses the
//!   row; an unprovisioned tenant is `NotFound`.
//!   `list_observed_agent_presence_since(Some(tenant), ...)` is an opt-in
//!   tenant-scoped window read (empty for an unprovisioned org) and
//!   `(None, ...)` fans out over the provisioned tenant bindings, re-sorting the
//!   union to the Postgres operator order. Fail closed with no proxy; see
//!   `observed_presence.rs`.
//! - Managed worker stores (#449, control database): templates, agent worker
//!   instances, sessions, lifecycle events, and the isolation
//!   selection/policy/evidence trio -- each an `upsert`/`append` of the full
//!   record as a `*_json` document plus an ORDER BY projection column, and a
//!   whole-table list. Routed to the CONTROL database (whole-table admin reads;
//!   the record's `tenant` is a composite storage key, not a routing id).
//! - Self-hosted worker stores (#449, control database): registrations
//!   (+ single-get), heartbeats (+ `latest_self_hosted_worker_heartbeat`),
//!   telemetry events (+ per-run newest-window and per-worker filtered reads),
//!   artifacts (+ single-get), checkpoints (+ single-get), run dispatches (the
//!   Postgres capability side-table folds into the dispatch document), and
//!   `self_hosted_worker_activity_stats` (count/max subselects in one query).
//!   Same CONTROL-database routing as the managed families.
//! - Process-local (backend-independent semantics, mirrors Memory/Postgres):
//!   `set_retention_limits` (no-op like Postgres), `next_audit_event_id`,
//!   `upsert_usage_aggregate_local`, `store_usage_aggregate_local`,
//!   `usage_aggregates`, `sum_api_key_committed_tokens` (process-local view).
//!
//! The #440 auth/quota/plan families are all **account-global control-plane
//! configuration** and therefore route to the CONTROL database (like
//! `tenants`), never fanned out over tenant databases — admin identities span
//! tenants, and quota lookups carry no tenant context.
//!
//! Still erroring (typed `unimplemented-backend-surface`, awaiting a later
//! slice). The proxy-Worker `/d1/batch` + `/d1/query` binding (issue #450) has
//! landed and now serves the control-DB atomic families
//! (`append_billing_event_with_outbox_enqueue`, issue #150; the guardrail
//! activate/archive/restore CAS, issue #454). What remains erroring is the
//! atomic families that DON'T mirror cleanly onto the control-DB-only binding:
//!
//! - The REMAINING wallet/payment surface (the reserve/settle/release trio +
//!   wallet CRUD landed in #455; `settle_wallet_balance`/`adjust_wallet_balance`/
//!   `set_wallet_dunning`/`list_wallets` landed in #456, above):
//!   `sweep_expired_wallet_reservations`, and payment methods/attempts
//!   (`transition_payment_attempt` CAS). `sweep` is deferred because its
//!   money-safety guard reads `payment_attempts.hold_id` — coupling wallets to
//!   the (still-deferred) x402 payment_attempts family into one larger unit.
//! - Agent cost-burn (#428): `add_agent_burn`, `get_agent_burn`,
//!   `list_agent_cost_burn`. The durable per-agent burn ledger lands on the
//!   Postgres control-plane store first; routing its atomic accumulate onto the
//!   per-tenant proxy binding is a follow-up.
//! - MCP identity — the last remaining pre-#425 per-entity dispatch surface
//!   (agent schedules + observed-agent presence landed in issue #460, below).
//! - Guardrail evidence (`append_guardrail_evaluation`,
//!   `query_guardrail_evaluations`, `list_guardrail_evaluations`,
//!   `list_guardrail_check_evaluations`). Enum-dispatched separately from the
//!   #437 per-entity surfaces (see `guardrail_evidence.rs`), so it is NOT
//!   covered by the MCP-identity note above.
//!
//! RBAC, site domains, and the budget-alert idempotency ledger were
//! implemented in issue #445; request/audit logs, agent runs/events, and
//! snapshot replay floors in issue #447; billing ledger/outbox/events,
//! guardrail revisions/bindings, and the managed + self-hosted worker stores in
//! issue #449 -- all above.
//!
//! Everything erroring returns the typed `unimplemented-backend-surface` error
//! ([`is_unimplemented_backend_surface`]) when it can return a `Result`, and
//! logs a warning + returns an empty/default value when its signature cannot
//! carry an error (the append/analytics getters). Nothing fails silently.
//! Inherent provisioning surface: [`D1ControlPlaneStore::provision_control_database`],
//! [`D1ControlPlaneStore::provision_tenant_database`],
//! [`D1ControlPlaneStore::deprovision_tenant_database`],
//! [`D1ControlPlaneStore::list_provisioned_databases`].
//!
//! See `docs/cloudflare-d1-backend.md` for the full design record.

use std::collections::BTreeMap;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{CloudflareError, D1ProxyClient, D1ProxyStatement};

use super::control_plane_store::ControlPlaneStore;
use super::*;

mod agent_schedule;
mod assets;
mod auth_quota;
mod billing;
mod client;
mod client_config;
mod config_documents;
mod core_entities;
mod guardrail;
mod observability;
mod observed_presence;
mod provisioning;
mod rbac_site_domain;
mod rows;
mod usage;
mod wallet;
mod worker_stores;
mod workflow_budget;

pub use client_config::CloudflareD1StorageOptions;

/// Stable machine-checkable prefix carried by every error this backend
/// returns for a trait method outside its implemented surface.
pub const D1_UNIMPLEMENTED_SURFACE: &str = "unimplemented-backend-surface";

/// Config-document kind under which the tenant->database registry persists.
pub const D1_TENANT_DATABASE_REGISTRY_KIND: &str = "d1_tenant_database";

/// Config-document id of the singleton registry document.
pub const D1_TENANT_DATABASE_REGISTRY_ID: &str = "registry";

/// The SQLite-dialect core schema applied to every provisioned database.
const D1_SCHEMA_SQL: &str = include_str!("../../../../sql/d1/001_init_d1.sql");

/// The config-document kinds that make up [`ControlPlaneDocuments`] /
/// [`ControlPlaneSnapshot`] — mirrors the Postgres backend's
/// `replace_config_documents` kind list.
const CONFIG_DOCUMENT_KINDS: [&str; 10] = [
    "api_key",
    "tenant",
    "policy",
    "gateway_config",
    "agent_workflow",
    "skill_package",
    "prompt_template",
    "plugin_registration",
    "mcp_server",
    "agent_upstream",
];

/// True when `error` is this backend's typed "method outside the implemented
/// D1 surface" error — the contract callers/tests match on instead of string
/// scraping.
pub fn is_unimplemented_backend_surface(error: &StorageError) -> bool {
    matches!(error, StorageError::Runtime(message) if message.starts_with(D1_UNIMPLEMENTED_SURFACE))
}

/// Shared by this trait impl AND the per-entity modules' enum-dispatch arms
/// (wallet, RBAC, MCP identity, ... — the pre-#425 surfaces), so every
/// unimplemented path carries the same typed prefix.
pub(crate) fn unimplemented_surface(method: &'static str) -> StorageError {
    StorageError::Runtime(format!(
        "{D1_UNIMPLEMENTED_SURFACE}: {method} is not implemented by the cloudflare_d1 \
         control-plane backend (see control_plane_store_d1 module docs)"
    ))
}

fn d1_error(error: CloudflareError) -> StorageError {
    StorageError::Runtime(format!("cloudflare d1: {error}"))
}

/// Persisted tenant->database mapping plus the control database id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct D1TenantDatabaseRegistry {
    /// D1 database uuid holding tenants + config documents + this registry.
    #[serde(default)]
    pub control_database_id: String,
    /// tenant_id -> D1 database uuid (BTreeMap: deterministic serialization
    /// and fan-out order).
    #[serde(default)]
    pub tenant_databases: BTreeMap<String, String>,
}

impl D1TenantDatabaseRegistry {
    /// A registry with only the control database configured.
    pub fn with_control_database(control_database_id: impl Into<String>) -> Self {
        Self {
            control_database_id: control_database_id.into(),
            tenant_databases: BTreeMap::new(),
        }
    }

    /// Decode the persisted registry document.
    pub fn from_document_json(document_json: &str) -> Result<Self, StorageError> {
        deserialize_storage_document(document_json)
    }

    /// Encode this registry as its config-document JSON.
    pub fn to_document_json(&self) -> Result<String, StorageError> {
        serialize_storage_document(self)
    }
}

/// The per-tenant Cloudflare D1 control-plane backend (issue #420).
pub struct D1ControlPlaneStore {
    client: D1Client,
    /// Proxy-Worker client for the ATOMIC hot path (issue #450). `None` until a
    /// deployment binds the `workers/d1-proxy` Worker; the atomic-transition
    /// families fail closed with the typed unimplemented-surface error while it
    /// is absent (they cannot be served over the REST query API's non-atomic,
    /// no-`RETURNING` surface). The REST `client` above stays the transport for
    /// every non-atomic/admin family.
    proxy: Option<D1ProxyClient>,
    registry: Mutex<D1TenantDatabaseRegistry>,
    /// Process-local usage-aggregate mirror — the same read-modify-write
    /// baseline every backend keeps (see the trait docs on
    /// `upsert_usage_aggregate_local`).
    usage_aggregates_mirror: Mutex<InMemoryRepository<StoredUsageAggregate>>,
}

impl std::fmt::Debug for D1ControlPlaneStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("D1ControlPlaneStore")
            .finish_non_exhaustive()
    }
}

fn poisoned_registry_lock() -> StorageError {
    StorageError::Runtime("d1 tenant database registry lock is poisoned".to_string())
}

/// Serialize an optional integer as a bind param: `NULLIF(?, '')` in the SQL
/// turns the empty string back into SQL NULL, keeping params inside the
/// documented all-strings REST contract.
fn optional_number_param<T: ToString>(value: Option<T>) -> String {
    value.map(|number| number.to_string()).unwrap_or_default()
}

/// Bind a SQL boolean as SQLite's `"1"`/`"0"` integer affinity string.
fn bool_param(value: bool) -> String {
    if value { "1" } else { "0" }.to_string()
}

/// Render an `IN (?, ?, ...)` placeholder list of `count` bound params: the
/// SQLite-dialect stand-in for the Postgres `= ANY($1)` array predicate.
fn in_placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), StorageError> {
    if tenant_id.is_empty()
        || !tenant_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(StorageError::Runtime(format!(
            "cloudflare d1: tenant id {tenant_id:?} cannot name a D1 database \
             (expected ASCII alphanumerics, '-' or '_')"
        )));
    }
    Ok(())
}

/// The wrangler `[[d1_databases]]` binding name the proxy Worker resolves for a
/// tenant's own D1 database (issue #455 per-tenant routing).
///
/// Derived deterministically from the tenant id: uppercased, every character
/// outside `[A-Z0-9_]` folded to `_`, then prefixed `TENANT_DB_`. The prefix +
/// fold guarantee a valid JS/wrangler binding identifier (`^[A-Z_][A-Z0-9_]*$`)
/// that can never collide with the control `DB` binding or the `D1_PROXY_TOKEN`
/// secret. The Workers runtime has NO select-a-database-by-id API (D1 is reached
/// only through a declared binding), so the Rust side sends this NAME and the
/// Worker resolves `env[name]`; onboarding a tenant means adding a matching
/// `[[d1_databases]]` binding + redeploying (the #423 per-binding reality).
///
/// Collision constraint: `-` and `_` both fold to `_` and case is erased, so two
/// tenant ids that differ only by those (e.g. `a-b` vs `a_b`) would share a
/// binding. Provisioned tenant ids are distinct slugs/uuids in practice; the
/// registry's live-deploy binding table is the operator's collision guard.
pub(super) fn tenant_database_binding(tenant_id: &str) -> String {
    let mut sanitized = String::with_capacity(tenant_id.len() + "TENANT_DB_".len());
    sanitized.push_str("TENANT_DB_");
    for character in tenant_id.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_uppercase());
        } else {
            sanitized.push('_');
        }
    }
    sanitized
}

/// The migration file with `--` comment lines stripped, ready to send as one
/// multi-statement D1 batch.
fn schema_batch_sql() -> String {
    D1_SCHEMA_SQL
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn documents_to_snapshot(documents: &ControlPlaneDocuments) -> ControlPlaneSnapshot {
    fn values(documents: &[(String, String)]) -> Vec<String> {
        documents
            .iter()
            .map(|(_, document)| document.clone())
            .collect()
    }
    ControlPlaneSnapshot {
        api_keys: values(&documents.api_keys),
        tenants: values(&documents.tenants),
        policies: values(&documents.policies),
        gateway_configs: values(&documents.gateway_configs),
        agent_workflows: values(&documents.agent_workflows),
        skill_packages: values(&documents.skill_packages),
        prompt_templates: values(&documents.prompt_templates),
        plugin_registrations: values(&documents.plugin_registrations),
        mcp_servers: values(&documents.mcp_servers),
        agent_upstreams: values(&documents.agent_upstreams),
    }
}

#[async_trait::async_trait]
impl ControlPlaneStore for D1ControlPlaneStore {
    // --- Agent cost-burn (#428): NOT YET IMPLEMENTED on D1 ---
    // The durable per-agent burn ledger lands on the Postgres control-plane
    // store first (#428 slice B-storage); routing the atomic accumulate onto the
    // per-tenant D1 proxy binding is a follow-up. Returns the typed
    // unimplemented-backend-surface error so callers can detect it via
    // `is_unimplemented_backend_surface` rather than mistaking it for a zero burn.
    async fn add_agent_burn(
        &self,
        _tenant_id: &str,
        _agent_key: &str,
        _period: &str,
        _delta_usd: f64,
    ) -> Result<f64, StorageError> {
        Err(unimplemented_surface("add_agent_burn"))
    }

    async fn get_agent_burn(
        &self,
        _tenant_id: &str,
        _agent_key: &str,
        _period: &str,
    ) -> Result<Option<f64>, StorageError> {
        Err(unimplemented_surface("get_agent_burn"))
    }

    async fn list_agent_cost_burn(
        &self,
        _tenant_scope: Option<&str>,
        _period: &str,
    ) -> Result<Vec<StoredAgentCostBurn>, StorageError> {
        Err(unimplemented_surface("list_agent_cost_burn"))
    }

    // --- API keys (IMPLEMENTED) ---

    async fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError> {
        self.upsert_api_key_record_async(api_key).await
    }

    async fn create_api_key_record_if_absent(
        &self,
        api_key: StoredApiKey,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        self.create_api_key_record_if_absent_async(api_key).await
    }

    async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        self.get_api_key_record_async(id).await
    }

    async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        self.list_api_key_records_async().await
    }

    async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        self.find_api_key_records_by_prefix_async(key_prefix).await
    }

    // --- Admin users / SSO / refresh tokens (IMPLEMENTED, control database) ---

    async fn upsert_admin_user(&self, user: StoredAdminUser) -> Result<(), StorageError> {
        self.upsert_admin_user_async(user).await
    }

    async fn get_admin_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        self.get_admin_user_by_id_async(id).await
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        self.get_admin_user_by_email_async(email).await
    }

    async fn upsert_admin_user_membership(
        &self,
        membership: StoredAdminUserMembership,
    ) -> Result<(), StorageError> {
        self.upsert_admin_user_membership_async(membership).await
    }

    async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        self.list_admin_user_memberships_by_user_async(user_id)
            .await
    }

    async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        self.list_admin_user_memberships_by_tenant_async(tenant_id)
            .await
    }

    async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        self.delete_admin_user_membership_async(user_id, tenant_id)
            .await
    }

    async fn upsert_sso_provider_config(
        &self,
        config: StoredSsoProviderConfig,
    ) -> Result<(), StorageError> {
        self.upsert_sso_provider_config_async(config).await
    }

    async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError> {
        self.get_sso_provider_config_async(tenant_id).await
    }

    async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError> {
        self.delete_sso_provider_config_async(tenant_id).await
    }

    async fn insert_sso_pending_flow(
        &self,
        flow: StoredSsoPendingFlow,
    ) -> Result<(), StorageError> {
        self.insert_sso_pending_flow_async(flow).await
    }

    async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError> {
        self.take_sso_pending_flow_async(state, now_unix).await
    }

    async fn upsert_admin_user_refresh_token(
        &self,
        token: StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError> {
        self.upsert_admin_user_refresh_token_async(token).await
    }

    async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError> {
        self.get_admin_user_refresh_token_by_hash_async(token_hash)
            .await
    }

    async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        self.revoke_all_admin_user_refresh_tokens_async(user_id, revoked_at_unix)
            .await
    }

    async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        self.revoke_admin_user_refresh_tokens_for_tenant_async(user_id, tenant_id, revoked_at_unix)
            .await
    }

    // --- Tenant accounts (IMPLEMENTED, control database) ---

    async fn upsert_tenant_account(
        &self,
        account: StoredTenantAccount,
    ) -> Result<(), StorageError> {
        self.upsert_tenant_account_async(account).await
    }

    async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        self.get_tenant_account_async(id).await
    }

    async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        self.list_tenant_accounts_async().await
    }

    // --- Projects (IMPLEMENTED, tenant database) ---

    async fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError> {
        self.upsert_project_async(project).await
    }

    async fn create_project_if_absent(
        &self,
        project: StoredProject,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        self.create_project_if_absent_async(project).await
    }

    async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        self.get_project_async(id).await
    }

    async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        self.list_projects_async().await
    }

    async fn delete_project(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_project_async(id).await
    }

    async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        self.delete_project_if_unreferenced_async(id).await
    }

    // --- Workspaces (IMPLEMENTED, tenant database) ---

    async fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError> {
        self.upsert_workspace_async(workspace).await
    }

    async fn create_workspace_if_absent(
        &self,
        workspace: StoredWorkspace,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        self.create_workspace_if_absent_async(workspace).await
    }

    async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        self.get_workspace_async(id).await
    }

    async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        self.list_workspaces_async().await
    }

    async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_workspace_async(id).await
    }

    async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        self.delete_workspace_if_unreferenced_async(id).await
    }

    async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        self.resolve_workspace_scope_async(workspace_id).await
    }

    // --- Quota policies / plans (IMPLEMENTED, control database) ---

    async fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> Result<(), StorageError> {
        self.upsert_quota_policy_async(policy).await
    }

    async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError> {
        self.get_quota_policy_async(scope_type, scope_id).await
    }

    async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        self.list_quota_policies_async().await
    }

    async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError> {
        self.delete_quota_policy_async(scope_type, scope_id).await
    }

    async fn upsert_plan(&self, plan: StoredPlan) -> Result<(), StorageError> {
        self.upsert_plan_async(plan).await
    }

    async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError> {
        self.get_plan_async(id).await
    }

    async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError> {
        self.list_plans_async().await
    }

    // --- Assets + channels + retention (IMPLEMENTED, tenant-DB routed,
    // issue #456) ---
    //
    // The hosted-asset storage family routed through the proxy binding onto
    // per-tenant databases (tenant-routed writes/reads; id-only reads/deletes +
    // the operator cross-tenant lists fan out). The #367 coordination ops
    // (create-within-quota, move-if-resolvable, yank/unyank, variant delete,
    // visibility promotion) mirror the Postgres `FOR UPDATE` transactions as
    // guarded single-`/d1/batch` transitions; inline BYTEA `content` rides a
    // base64 TEXT column. See `assets.rs`.

    async fn upsert_asset(&self, asset: StoredAsset) -> Result<(), StorageError> {
        self.upsert_asset_d1_async(&asset).await
    }

    async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError> {
        self.create_asset_if_absent_d1_async(&asset).await
    }

    async fn create_asset_within_quota(
        &self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        self.create_asset_within_quota_d1_async(&asset, quota_bytes)
            .await
    }

    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError> {
        self.get_asset_d1_async(id).await
    }

    async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        self.list_assets_d1_async(tenant_id, asset_type).await
    }

    async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        self.list_withheld_assets_d1_async(tenant_id, asset_type)
            .await
    }

    async fn tenant_asset_storage_bytes_used(&self, tenant_id: &str) -> Result<u64, StorageError> {
        self.tenant_asset_storage_bytes_used_d1_async(tenant_id)
            .await
    }

    async fn delete_asset(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_asset_d1_async(id).await
    }

    async fn upsert_asset_channel(&self, channel: StoredAssetChannel) -> Result<(), StorageError> {
        self.upsert_asset_channel_d1_async(&channel).await
    }

    async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        self.list_asset_channels_d1_async(tenant_id, asset_type, name)
            .await
    }

    async fn delete_asset_channel(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_asset_channel_d1_async(id).await
    }

    async fn move_asset_channel_if_resolvable(
        &self,
        channel: StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        self.move_asset_channel_if_resolvable_d1_async(&channel)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_asset_version_yank(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> Result<VersionYankOutcome, StorageError> {
        self.set_asset_version_yank_d1_async(tenant_id, asset_type, name, version, yanked, now_unix)
            .await
    }

    async fn delete_asset_variant_if_unreferenced(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError> {
        self.delete_asset_variant_if_unreferenced_d1_async(id, tenant_id, asset_type, name, version)
            .await
    }

    async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        self.promote_pending_asset_visibility_d1_async(id, target, now_unix)
            .await
    }

    async fn upsert_retention_policy(
        &self,
        policy: StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        self.upsert_retention_policy_d1_async(&policy).await
    }

    async fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        self.list_retention_policies_d1_async(tenant_id, resource_type)
            .await
    }

    async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError> {
        self.list_all_assets_d1_async().await
    }

    async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError> {
        self.list_all_asset_channels_d1_async().await
    }

    // --- Usage rollups (IMPLEMENTED, tenant-DB routed, issue #456) ---
    //
    // Per-tenant usage-report reads + the durable `persist_usage_aggregate`
    // RMW, routed through the proxy binding onto per-tenant databases (or fanned
    // out for the id-only/global reads). See `usage.rs`.

    async fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        self.get_usage_monthly_rollup_d1_async(scope_type, scope_id, period_month)
            .await
    }

    async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        self.list_usage_monthly_rollups_d1_async().await
    }

    // --- Billing ledger + report outbox (IMPLEMENTED, control DB, issue #449) ---

    async fn append_billing_ledger_entry(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        self.append_billing_ledger_entry_async(entry).await
    }

    async fn list_billing_ledger_entries(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        self.list_billing_ledger_entries_async(filter, offset, limit)
            .await
    }

    async fn billing_ledger_entry(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        self.billing_ledger_entry_async(id).await
    }

    async fn enqueue_billing_report(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        self.enqueue_billing_report_async(id, event, next_attempt_unix)
            .await
    }

    async fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        self.list_due_billing_reports_async(now_unix, limit).await
    }

    async fn reschedule_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        self.reschedule_billing_report_async(id, next_attempt_unix)
            .await
    }

    async fn dead_letter_billing_report(
        &self,
        id: &str,
        dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError> {
        self.dead_letter_billing_report_async(id, dead_lettered_at_unix)
            .await
    }

    async fn list_dead_lettered_billing_reports(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        self.list_dead_lettered_billing_reports_async(limit).await
    }

    async fn replay_dead_lettered_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        self.replay_dead_lettered_billing_report_async(id, next_attempt_unix)
            .await
    }

    async fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        self.get_billing_report_outbox_entry_async(id).await
    }

    async fn delete_billing_report(&self, id: &str) -> Result<(), StorageError> {
        self.delete_billing_report_async(id).await
    }

    // --- Config documents (IMPLEMENTED, control database) ---

    fn upsert_config_document(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(self.upsert_config_document_async(kind, id, document_json))
    }

    fn delete_config_document(&self, kind: &'static str, id: &str) -> Result<bool, StorageError> {
        block_on_sync_bridge(self.delete_config_document_async(kind, id))
    }

    fn get_config_document(
        &self,
        kind: &'static str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        block_on_sync_bridge(self.get_config_document_async(kind, id))
    }

    fn list_config_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        Ok(
            block_on_sync_bridge(self.list_config_resource_documents_async(kind))?
                .into_iter()
                .map(|(_, document_json)| document_json)
                .collect(),
        )
    }

    fn list_config_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        block_on_sync_bridge(self.list_config_resource_documents_async(kind))
    }

    fn replace_config_documents(
        &self,
        documents: ControlPlaneDocuments,
    ) -> Result<(), StorageError> {
        let ControlPlaneDocuments {
            api_keys,
            tenants,
            policies,
            gateway_configs,
            agent_workflows,
            skill_packages,
            prompt_templates,
            plugin_registrations,
            mcp_servers,
            agent_upstreams,
        } = documents;
        let by_kind: [(&str, Vec<(String, String)>); 10] = [
            (CONFIG_DOCUMENT_KINDS[0], api_keys),
            (CONFIG_DOCUMENT_KINDS[1], tenants),
            (CONFIG_DOCUMENT_KINDS[2], policies),
            (CONFIG_DOCUMENT_KINDS[3], gateway_configs),
            (CONFIG_DOCUMENT_KINDS[4], agent_workflows),
            (CONFIG_DOCUMENT_KINDS[5], skill_packages),
            (CONFIG_DOCUMENT_KINDS[6], prompt_templates),
            (CONFIG_DOCUMENT_KINDS[7], plugin_registrations),
            (CONFIG_DOCUMENT_KINDS[8], mcp_servers),
            (CONFIG_DOCUMENT_KINDS[9], agent_upstreams),
        ];
        for (kind, documents) in by_kind {
            block_on_sync_bridge(self.replace_config_kind_async(kind, documents))?;
        }
        Ok(())
    }

    fn control_plane_snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        let documents = block_on_sync_bridge(self.config_documents_async())?;
        Ok(documents_to_snapshot(&documents))
    }

    fn config_documents(&self) -> Result<ControlPlaneDocuments, StorageError> {
        block_on_sync_bridge(self.config_documents_async())
    }

    // --- Guardrail policy revisions + bindings (control DB, issue #449/#454) ---
    //
    // insert/get/list revisions and get/list bindings are IMPLEMENTED: each is
    // a single-statement document read/write bridged into the async helpers
    // like the config-document methods. The generation-guarded
    // activate/archive/restore CAS transitions below are IMPLEMENTED over the
    // proxy-Worker `/d1/query` binding (issue #454): each is one guarded
    // `UPDATE`/`INSERT`/`DELETE ... RETURNING policy_id` whose presence/absence
    // of a `RETURNING` row is the success/conflict signal the REST query API
    // cannot give. Guardrail configuration is account-global, so the proxy's
    // control-DB binding serves them directly (no per-tenant binding needed).
    // They fail closed with the typed unimplemented-surface error when no proxy
    // Worker is bound. See `guardrail.rs` for the CAS helpers.

    fn insert_guardrail_policy_revision(
        &self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(self.insert_guardrail_policy_revision_async(&revision))
    }

    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        block_on_sync_bridge(self.get_guardrail_policy_revision_async(policy_id, revision))
    }

    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        block_on_sync_bridge(self.list_guardrail_policy_revisions_async(policy_id))
    }

    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        block_on_sync_bridge(self.get_guardrail_policy_binding_async(policy_id))
    }

    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        block_on_sync_bridge(self.list_guardrail_policy_bindings_async())
    }

    fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        block_on_sync_bridge(self.activate_guardrail_policy_revision_async(
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
            rollback_only,
        ))
    }

    fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        block_on_sync_bridge(self.archive_guardrail_policy_revision_async(
            policy_id,
            revision,
            updated_by,
            updated_at_unix,
        ))
    }

    fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(self.restore_guardrail_policy_binding_async(
            policy_id,
            expected_generation,
            binding,
        ))
    }

    // --- Snapshot replay floors (IMPLEMENTED, control database, issue #447) ---
    //
    // Account-global control-plane snapshot-replay state keyed by
    // (tenant_id, deployment_id); the sync surface bridges into the async D1
    // helpers exactly like the config-document methods.

    fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        block_on_sync_bridge(self.get_snapshot_replay_floor_async(tenant_id, deployment_id))
    }

    fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        updated_at_unix: i64,
    ) -> Result<u64, StorageError> {
        block_on_sync_bridge(self.advance_snapshot_replay_floor_async(
            tenant_id,
            deployment_id,
            revision,
            updated_at_unix,
        ))
    }

    // --- High-write append/analytics stores ---
    //
    // These are the HOT paths the rate-limit strategy explicitly keeps OFF
    // the raw REST API (see module docs): erroring where the signature
    // allows, warn + empty where it does not.

    fn set_retention_limits(
        &self,
        _request_log_retention_records: usize,
        _audit_event_retention_records: usize,
    ) {
        // Like the Postgres backend: no in-process bounds to configure; the
        // append stores are not served by this backend in the first place.
    }

    async fn append_request_log(&self, log: StoredRequestLog) {
        // `()`-returning append: swallow-with-warn on error, mirroring the
        // Postgres backend's `let _ = ...` (contract in the module docs).
        if let Err(error) = self.append_request_log_async(&log).await {
            tracing::warn!("cloudflare d1: append_request_log failed: {error}");
        }
    }

    async fn request_logs(&self) -> Vec<StoredRequestLog> {
        self.request_logs_async().await.unwrap_or_else(|error| {
            tracing::warn!("cloudflare d1: request_logs failed: {error}");
            Vec::new()
        })
    }

    async fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredRequestLog> {
        self.request_logs_page_async(offset, limit)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: request_logs_page failed: {error}");
                StoragePage::empty(offset, limit)
            })
    }

    async fn delete_request_logs(&self, request_ids: &[String]) -> Result<u64, StorageError> {
        self.delete_request_logs_async(request_ids).await
    }

    async fn request_logs_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredRequestLog> {
        self.request_logs_for_agent_runs_async(run_ids)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: request_logs_for_agent_runs failed: {error}");
                Vec::new()
            })
    }

    async fn append_audit_event(&self, event: StoredAuditEvent) {
        if let Err(error) = self.append_audit_event_async(&event).await {
            tracing::warn!("cloudflare d1: append_audit_event failed: {error}");
        }
    }

    fn next_audit_event_id(&self) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("audit-{nanos}-{}", std::process::id())
    }

    async fn audit_events(&self) -> Vec<StoredAuditEvent> {
        self.audit_events_async().await.unwrap_or_else(|error| {
            tracing::warn!("cloudflare d1: audit_events failed: {error}");
            Vec::new()
        })
    }

    async fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredAuditEvent> {
        self.audit_events_page_async(offset, limit)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: audit_events_page failed: {error}");
                StoragePage::empty(offset, limit)
            })
    }

    async fn delete_audit_events(&self, ids: &[String]) -> Result<u64, StorageError> {
        self.delete_audit_events_async(ids).await
    }

    async fn audit_events_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredAuditEvent> {
        self.audit_events_for_agent_runs_async(run_ids)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: audit_events_for_agent_runs failed: {error}");
                Vec::new()
            })
    }

    // --- Billing events (IMPLEMENTED, control DB, issue #449/#450) ---
    //
    // Settled metering events stored as full `*_json` documents (idempotent on
    // the ledger-entry id, like Postgres/Memory). The combined
    // `append_billing_event_with_outbox_enqueue` (issue #150) is the KEYSTONE
    // atomic op of issue #450: it must commit the metering write and the outbox
    // enqueue TOGETHER, which the D1 REST query API cannot express — so it routes
    // through the proxy-Worker `/d1/batch` binding (native `env.DB.batch([...])`,
    // atomic, `RETURNING`). It fails closed with the typed unimplemented-surface
    // error when no proxy Worker is bound (a REST-only deployment).

    async fn append_billing_event(&self, event: BillingEvent) -> Result<bool, StorageError> {
        self.append_billing_event_async(&event).await
    }

    async fn append_billing_event_with_outbox_enqueue(
        &self,
        event: BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError> {
        self.append_billing_event_with_outbox_enqueue_async(
            &event,
            outbox_id,
            outbox_next_attempt_unix,
        )
        .await
    }

    async fn billing_events(&self) -> Vec<BillingEvent> {
        self.billing_events_async().await.unwrap_or_else(|error| {
            tracing::warn!("cloudflare d1: billing_events failed: {error}");
            Vec::new()
        })
    }

    async fn billing_events_page(&self, offset: usize, limit: usize) -> StoragePage<BillingEvent> {
        self.billing_events_page_async(offset, limit)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: billing_events_page failed: {error}");
                StoragePage::empty(offset, limit)
            })
    }

    // Process-local usage-aggregate mirror: backend-independent semantics
    // (IMPLEMENTED, mirrors the Postgres backend's local half verbatim).

    fn upsert_usage_aggregate_local(
        &self,
        id: String,
        build: &mut dyn FnMut(Option<StoredUsageAggregate>) -> StoredUsageAggregate,
    ) -> Result<StoredUsageAggregate, StorageError> {
        if let Ok(mut aggregates) = self.usage_aggregates_mirror.lock() {
            let existing = aggregates.get(&id);
            let aggregate = build(existing);
            aggregates.insert(id, aggregate.clone());
            Ok(aggregate)
        } else {
            Err(StorageError::Serialization(
                "usage aggregate repository lock poisoned".into(),
            ))
        }
    }

    fn store_usage_aggregate_local(
        &self,
        aggregate: StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        if let Ok(mut aggregates) = self.usage_aggregates_mirror.lock() {
            aggregates.insert(aggregate.id.clone(), aggregate);
            Ok(())
        } else {
            Err(StorageError::Serialization(
                "usage aggregate repository lock poisoned".into(),
            ))
        }
    }

    async fn persist_usage_aggregate(
        &self,
        aggregate: &StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        // The DURABLE half: one atomic `/d1/batch` (tenant_contexts upsert +
        // usage_aggregate_rollups REPLACE) on the owning tenant's database,
        // mirroring the Postgres transaction. See `usage.rs`.
        self.persist_usage_aggregate_d1_async(aggregate).await
    }

    async fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        // Process-local view (the mirror), matching the Memory backend's
        // store-of-record read; documented in the module docs.
        self.usage_aggregates_mirror
            .lock()
            .map(|aggregates| aggregates.list())
            .unwrap_or_default()
    }

    async fn sum_api_key_committed_tokens(&self, api_key_id: &str) -> u64 {
        self.usage_aggregates_mirror
            .lock()
            .map(|aggregates| {
                aggregates
                    .list()
                    .into_iter()
                    .filter(|aggregate| aggregate.api_key_id.as_deref() == Some(api_key_id))
                    .fold(0_u64, |total, aggregate| {
                        total.saturating_add(aggregate.usage.total_tokens)
                    })
            })
            .unwrap_or_default()
    }

    // --- Agent runs / events (IMPLEMENTED, control database, issue #447) ---
    //
    // See the inherent `*_async` helpers for the routing rationale. The
    // `()`/`Vec`/`Option`-returning surfaces swallow-with-warn on error like
    // the Postgres backend; the `Result`-returning ones surface it.

    async fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError> {
        self.upsert_agent_run_async(&run).await
    }

    async fn agent_run(&self, id: &str) -> Option<StoredAgentRun> {
        self.agent_run_async(id).await.unwrap_or_else(|error| {
            tracing::warn!("cloudflare d1: agent_run failed: {error}");
            None
        })
    }

    async fn agent_runs(&self) -> Vec<StoredAgentRun> {
        self.agent_runs_async().await.unwrap_or_else(|error| {
            tracing::warn!("cloudflare d1: agent_runs failed: {error}");
            Vec::new()
        })
    }

    async fn agent_runs_by_ids(&self, run_ids: &[String]) -> Vec<StoredAgentRun> {
        self.agent_runs_by_ids_async(run_ids)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: agent_runs_by_ids failed: {error}");
                Vec::new()
            })
    }

    async fn append_agent_run_event(&self, event: StoredAgentRunEvent) -> Result<(), StorageError> {
        self.append_agent_run_event_async(&event).await
    }

    async fn agent_run_events(&self) -> Vec<StoredAgentRunEvent> {
        self.agent_run_events_async().await.unwrap_or_else(|error| {
            tracing::warn!("cloudflare d1: agent_run_events failed: {error}");
            Vec::new()
        })
    }

    async fn agent_run_events_for_runs(&self, run_ids: &[String]) -> Vec<StoredAgentRunEvent> {
        self.agent_run_events_for_runs_async(run_ids)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: agent_run_events_for_runs failed: {error}");
                Vec::new()
            })
    }

    async fn agent_run_summary_seed_ids(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Vec<String> {
        self.agent_run_summary_seed_ids_async(request_id, limit)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: agent_run_summary_seed_ids failed: {error}");
                Vec::new()
            })
    }

    // --- Managed worker stores (IMPLEMENTED, control DB, issue #449) ---
    //
    // Each `upsert`/`append` writes the full record as a `*_json` document and
    // surfaces its error; each `Vec`-returning list swallows-with-warn like the
    // #447 observability getters and the Postgres backend.

    async fn upsert_managed_worker_template(
        &self,
        template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        self.upsert_managed_worker_template_async(&template).await
    }

    async fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate> {
        self.managed_worker_templates_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: managed_worker_templates failed: {error}");
                Vec::new()
            })
    }

    async fn upsert_agent_worker_instance(
        &self,
        instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        self.upsert_agent_worker_instance_async(&instance).await
    }

    async fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance> {
        self.agent_worker_instances_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: agent_worker_instances failed: {error}");
                Vec::new()
            })
    }

    async fn upsert_managed_worker_session(
        &self,
        session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        self.upsert_managed_worker_session_async(&session).await
    }

    async fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession> {
        self.managed_worker_sessions_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: managed_worker_sessions failed: {error}");
                Vec::new()
            })
    }

    async fn append_managed_worker_lifecycle_event(
        &self,
        event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        self.append_managed_worker_lifecycle_event_async(&event)
            .await
    }

    async fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent> {
        self.managed_worker_lifecycle_events_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: managed_worker_lifecycle_events failed: {error}");
                Vec::new()
            })
    }

    async fn upsert_managed_worker_isolation_selection(
        &self,
        selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        self.upsert_managed_worker_isolation_selection_async(&selection)
            .await
    }

    async fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection> {
        self.managed_worker_isolation_selections_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(
                    "cloudflare d1: managed_worker_isolation_selections failed: {error}"
                );
                Vec::new()
            })
    }

    async fn upsert_managed_worker_isolation_policy(
        &self,
        policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        self.upsert_managed_worker_isolation_policy_async(&policy)
            .await
    }

    async fn managed_worker_isolation_policies(&self) -> Vec<StoredManagedWorkerIsolationPolicy> {
        self.managed_worker_isolation_policies_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: managed_worker_isolation_policies failed: {error}");
                Vec::new()
            })
    }

    async fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        self.upsert_managed_worker_isolation_evidence_async(&evidence)
            .await
    }

    async fn managed_worker_isolation_evidence(&self) -> Vec<StoredManagedWorkerIsolationEvidence> {
        self.managed_worker_isolation_evidence_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: managed_worker_isolation_evidence failed: {error}");
                Vec::new()
            })
    }

    // --- Self-hosted worker stores (IMPLEMENTED, control DB, issue #449) ---

    async fn upsert_self_hosted_worker_registration(
        &self,
        registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        self.upsert_self_hosted_worker_registration_async(&registration)
            .await
    }

    async fn self_hosted_worker_registrations(&self) -> Vec<StoredSelfHostedWorkerRegistration> {
        self.self_hosted_worker_registrations_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_registrations failed: {error}");
                Vec::new()
            })
    }

    async fn self_hosted_worker_registration(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerRegistration> {
        self.self_hosted_worker_registration_async(worker_id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_registration failed: {error}");
                None
            })
    }

    async fn latest_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerHeartbeat> {
        self.latest_self_hosted_worker_heartbeat_async(worker_id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(
                    "cloudflare d1: latest_self_hosted_worker_heartbeat failed: {error}"
                );
                None
            })
    }

    async fn self_hosted_worker_activity_stats(
        &self,
        worker_id: &str,
    ) -> StoredSelfHostedWorkerActivityStats {
        self.self_hosted_worker_activity_stats_async(worker_id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_activity_stats failed: {error}");
                StoredSelfHostedWorkerActivityStats::default()
            })
    }

    async fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        self.append_self_hosted_worker_heartbeat_async(&heartbeat)
            .await
    }

    async fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat> {
        self.self_hosted_worker_heartbeats_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_heartbeats failed: {error}");
                Vec::new()
            })
    }

    async fn append_self_hosted_worker_telemetry_event(
        &self,
        event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        self.append_self_hosted_worker_telemetry_event_async(&event)
            .await
    }

    async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        self.self_hosted_worker_telemetry_events_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(
                    "cloudflare d1: self_hosted_worker_telemetry_events failed: {error}"
                );
                Vec::new()
            })
    }

    async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        self.self_hosted_worker_telemetry_events_for_run_async(run_id, limit)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(
                    "cloudflare d1: self_hosted_worker_telemetry_events_for_run failed: {error}"
                );
                Vec::new()
            })
    }

    async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        worker_id: &str,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        self.self_hosted_worker_telemetry_events_for_worker_async(worker_id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(
                    "cloudflare d1: self_hosted_worker_telemetry_events_for_worker failed: {error}"
                );
                Vec::new()
            })
    }

    async fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        self.upsert_self_hosted_worker_artifact_async(&artifact)
            .await
    }

    async fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact> {
        self.self_hosted_worker_artifacts_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_artifacts failed: {error}");
                Vec::new()
            })
    }

    async fn self_hosted_worker_artifact(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerArtifact> {
        self.self_hosted_worker_artifact_async(id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_artifact failed: {error}");
                None
            })
    }

    async fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        self.upsert_self_hosted_worker_checkpoint_async(&checkpoint)
            .await
    }

    async fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint> {
        self.self_hosted_worker_checkpoints_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_checkpoints failed: {error}");
                Vec::new()
            })
    }

    async fn self_hosted_worker_checkpoint(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerCheckpoint> {
        self.self_hosted_worker_checkpoint_async(id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_worker_checkpoint failed: {error}");
                None
            })
    }

    async fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        self.upsert_self_hosted_run_dispatch_async(&dispatch).await
    }

    async fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch> {
        self.self_hosted_run_dispatches_async()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("cloudflare d1: self_hosted_run_dispatches failed: {error}");
                Vec::new()
            })
    }

    async fn delete_self_hosted_run_dispatch(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, StorageError> {
        self.delete_self_hosted_run_dispatch_async(dispatch_id)
            .await
    }

    // --- Per-entity module surfaces (#437, UNIMPLEMENTED) ---
    //
    // These families are not part of the first D1 slice (issue #420); each
    // returns the typed `unimplemented-backend-surface` error a proxy-Worker
    // impl will later replace. Same contract as the erroring surfaces above.

    // --- Site domains (IMPLEMENTED, control database, issue #445) ---
    //
    // hostname is the natural key; serve-path lookups carry no tenant context,
    // so these route to the control database rather than fanning out.

    async fn upsert_site_domain(&self, domain: StoredSiteDomain) -> Result<(), StorageError> {
        self.upsert_site_domain_async(domain).await
    }

    async fn claim_site_domain(
        &self,
        domain: StoredSiteDomain,
    ) -> Result<StoredSiteDomain, StorageError> {
        self.claim_site_domain_async(domain).await
    }

    async fn claim_verified_site_domain(
        &self,
        domain: StoredSiteDomain,
        now_unix: i64,
    ) -> Result<StoredSiteDomain, StorageError> {
        self.claim_verified_site_domain_async(domain, now_unix)
            .await
    }

    async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError> {
        self.get_site_domain_async(hostname).await
    }

    async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError> {
        self.list_site_domains_async(tenant_id).await
    }

    async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError> {
        self.delete_site_domain_async(hostname).await
    }

    // --- Site-domain DNS ownership proofs (IMPLEMENTED, control DB, #488) ---

    async fn upsert_site_domain_verification(
        &self,
        verification: StoredSiteDomainVerification,
    ) -> Result<(), StorageError> {
        self.upsert_site_domain_verification_async(verification)
            .await
    }

    async fn get_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomainVerification>, StorageError> {
        self.get_site_domain_verification_async(tenant_id, hostname)
            .await
    }

    async fn try_begin_site_domain_verification_attempt(
        &self,
        tenant_id: &str,
        hostname: &str,
        now_unix: i64,
        cooldown_secs: i64,
    ) -> Result<SiteDomainVerificationAttempt, StorageError> {
        self.try_begin_site_domain_verification_attempt_async(
            tenant_id,
            hostname,
            now_unix,
            cooldown_secs,
        )
        .await
    }

    async fn list_site_domain_verifications(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomainVerification>, StorageError> {
        self.list_site_domain_verifications_async(tenant_id).await
    }

    async fn delete_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<bool, StorageError> {
        self.delete_site_domain_verification_async(tenant_id, hostname)
            .await
    }

    async fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        self.list_usage_metadata_rollups_d1_async(metadata_key, organization_id)
            .await
    }

    // --- Observed-agent presence (IMPLEMENTED, tenant-DB routed, issue #460/#357) ---
    //
    // The durable coalesced presence signal routed through the proxy binding onto
    // per-tenant databases: `touch` is one conditional upsert with SQLite
    // `max`/`min` (not GREATEST/LEAST); `list_since` routes for a tenant scope and
    // fans out for the operator view. See `observed_presence.rs`.

    async fn touch_observed_agent_presence(
        &self,
        touch: ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        self.touch_observed_agent_presence_d1_async(&touch).await
    }

    async fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        self.list_observed_agent_presence_since_d1_async(tenant_scope, since_unix)
            .await
    }

    // --- Budget alert idempotency ledger (IMPLEMENTED, control database,
    // issue #445) ---
    //
    // Scope-keyed, once-per-period-per-tier records: account-global alerting
    // state with no tenant-database routing, so the control database owns them.

    async fn record_budget_alert_notification(
        &self,
        notification: StoredBudgetAlertNotification,
    ) -> Result<(), StorageError> {
        self.record_budget_alert_notification_async(notification)
            .await
    }

    async fn budget_alert_already_notified(&self, id: &str) -> Result<bool, StorageError> {
        self.budget_alert_already_notified_async(id).await
    }

    async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError> {
        self.list_budget_alert_notifications_async(scope_type, scope_id, period_month)
            .await
    }

    // --- Workflow-run execution budgets (IMPLEMENTED, tenant-DB routed,
    // issue #456/#279) ---
    //
    // The durable per-run execution envelope, routed through the proxy binding
    // onto per-tenant databases. `open` is an idempotent insert-then-reload
    // batch; `list` routes to the tenant's own DB; `debit`/`topup`/`get` fan out
    // by run id. `debit`/`topup` have no `SELECT ... FOR UPDATE` on SQLite, so
    // they use an INTERNAL bounded optimistic-CAS retry (read -> guarded
    // `UPDATE ... WHERE <decision read-set unchanged> RETURNING` -> re-read on an
    // empty RETURNING), which keeps the `WorkflowBudgetDebit` contract UNCHANGED
    // (`Applied`/`Exceeded`, no `Conflict` variant, no caller changes) while
    // preserving the no-lost-debit / fail-closed-`Exceeded` invariants. See
    // `workflow_budget.rs`.

    async fn open_workflow_run_budget(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.open_workflow_run_budget_d1_async(
            workflow_id,
            workflow_version,
            run_id,
            tenant_id,
            caps,
            now_unix,
        )
        .await
    }

    async fn debit_workflow_run_budget(
        &self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError> {
        self.debit_workflow_run_budget_d1_async(id, cost_credits, tokens, tool_calls, now_unix)
            .await
    }

    async fn topup_workflow_run_budget(
        &self,
        id: &str,
        add_cost_credits: i64,
        add_tokens: i64,
        add_tool_calls: i64,
        extend_deadline_unix: Option<i64>,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.topup_workflow_run_budget_d1_async(
            id,
            add_cost_credits,
            add_tokens,
            add_tool_calls,
            extend_deadline_unix,
            now_unix,
        )
        .await
    }

    async fn get_workflow_run_budget(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        self.get_workflow_run_budget_d1_async(id).await
    }

    async fn list_workflow_run_budgets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        self.list_workflow_run_budgets_d1_async(tenant_id).await
    }

    // --- RBAC: permissions / roles / tenant role bindings (IMPLEMENTED,
    // control database, issue #445) ---
    //
    // Permissions and roles are shared/global (like plans); tenant role
    // bindings are account-level admin config keyed by a deterministic
    // `tenant_id:role_id` id. All account-global, so the control database owns
    // them -- never fanned out over tenant databases.

    async fn upsert_permission(&self, permission: StoredPermission) -> Result<(), StorageError> {
        self.upsert_permission_async(permission).await
    }

    async fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError> {
        self.get_permission_async(id).await
    }

    async fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError> {
        self.list_permissions_async().await
    }

    async fn delete_permission(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_permission_async(id).await
    }

    async fn upsert_role(&self, role: StoredRole) -> Result<(), StorageError> {
        self.upsert_role_async(role).await
    }

    async fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError> {
        self.get_role_async(id).await
    }

    async fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError> {
        self.list_roles_async().await
    }

    async fn delete_role(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_role_async(id).await
    }

    async fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> Result<(), StorageError> {
        self.bind_tenant_role_async(binding).await
    }

    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError> {
        self.list_tenant_role_bindings_async(tenant_id).await
    }

    async fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<bool, StorageError> {
        self.unbind_tenant_role_async(tenant_id, role_id).await
    }

    // --- Agent schedules + fires (IMPLEMENTED, tenant-DB routed, issue #460/#246) ---
    //
    // The time-based schedule definitions + idempotent fire-history ledger routed
    // through the proxy binding onto per-tenant databases. `upsert`/`list` route by
    // tenant; `list_all`/`list_due` fan out and re-merge; `get`/`delete`/
    // `insert_fire`/`list_fires` fan out by id to locate the holding tenant DB.
    // `delete` cascades the fire log itself (the FK-free D1 dialect), and
    // `insert_fire` keeps the at-most-once `ON CONFLICT DO NOTHING RETURNING` gate.
    // See `agent_schedule.rs`.

    async fn upsert_agent_schedule(
        &self,
        schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        self.upsert_agent_schedule_d1_async(&schedule).await
    }

    async fn get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        self.get_agent_schedule_d1_async(schedule_id).await
    }

    async fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.list_agent_schedules_d1_async(tenant_id, workspace_id)
            .await
    }

    async fn list_all_agent_schedules(&self) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.list_all_agent_schedules_d1_async().await
    }

    async fn delete_agent_schedule(&self, schedule_id: &str) -> Result<bool, StorageError> {
        self.delete_agent_schedule_d1_async(schedule_id).await
    }

    async fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.list_due_agent_schedules_d1_async(now_unix, limit)
            .await
    }

    async fn insert_agent_schedule_fire(
        &self,
        fire: StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        self.insert_agent_schedule_fire_d1_async(&fire).await
    }

    async fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        self.list_agent_schedule_fires_d1_async(schedule_id, limit)
            .await
    }

    async fn settle_wallet_balance(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        self.settle_wallet_balance_d1_async(settlement_id, tenant_id, delta_credits, now_unix)
            .await
    }

    async fn upsert_wallet(&self, wallet: StoredWallet) -> Result<(), StorageError> {
        self.upsert_wallet_d1_async(&wallet).await
    }

    async fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        self.get_wallet_d1_async(tenant_id).await
    }

    async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        self.list_wallets_d1_async().await
    }

    async fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        self.adjust_wallet_balance_d1_async(tenant_id, delta_credits, now_unix)
            .await
    }

    async fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        self.set_wallet_dunning_d1_async(tenant_id, dunning, now_unix)
            .await
    }

    async fn reserve_wallet_credits(
        &self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        self.reserve_wallet_credits_d1_async(
            reservation_id,
            tenant_id,
            amount_credits,
            expires_at_unix,
            now_unix,
        )
        .await
    }

    async fn settle_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        self.settle_wallet_reservation_d1_async(reservation_id, now_unix)
            .await
    }

    async fn release_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        self.release_wallet_reservation_d1_async(reservation_id, now_unix)
            .await
    }

    async fn sweep_expired_wallet_reservations(
        &self,
        _now_unix: i64,
    ) -> Result<Vec<String>, StorageError> {
        Err(unimplemented_surface("sweep_expired_wallet_reservations"))
    }

    async fn list_wallet_reservations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        self.list_wallet_reservations_d1_async(tenant_id).await
    }

    async fn upsert_payment_method(
        &self,
        _payment_method: StoredPaymentMethod,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_payment_method"))
    }

    async fn list_payment_methods(
        &self,
        _tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        Err(unimplemented_surface("list_payment_methods"))
    }

    async fn get_payment_method(
        &self,
        _id: &str,
    ) -> Result<Option<StoredPaymentMethod>, StorageError> {
        Err(unimplemented_surface("get_payment_method"))
    }

    async fn delete_payment_method(&self, _id: &str) -> Result<bool, StorageError> {
        Err(unimplemented_surface("delete_payment_method"))
    }

    async fn create_payment_attempt(
        &self,
        _attempt: StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError> {
        Err(unimplemented_surface("create_payment_attempt"))
    }

    async fn get_payment_attempt(
        &self,
        _id: &str,
    ) -> Result<Option<StoredPaymentAttempt>, StorageError> {
        Err(unimplemented_surface("get_payment_attempt"))
    }

    async fn list_payment_attempts(
        &self,
        _tenant_id: &str,
        _query: &PaymentAttemptQuery,
    ) -> Result<PaymentAttemptPage, StorageError> {
        Err(unimplemented_surface("list_payment_attempts"))
    }

    async fn get_payment_attempt_links(
        &self,
        _id: &str,
        _tenant_id: &str,
    ) -> Result<Option<PaymentAttemptLinks>, StorageError> {
        Err(unimplemented_surface("get_payment_attempt_links"))
    }

    async fn list_expirable_due_payment_attempts(
        &self,
        _due_at_or_before_unix: i64,
        _limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        Err(unimplemented_surface("list_expirable_due_payment_attempts"))
    }

    async fn list_reconcilable_payment_attempts(
        &self,
        _checked_at_or_before_unix: i64,
        _limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        Err(unimplemented_surface("list_reconcilable_payment_attempts"))
    }

    async fn transition_payment_attempt(
        &self,
        _op_name: &'static str,
        _id: &str,
        _allowed_from: &[&str],
        _to_state: &str,
        _evidence: &super::payment_attempt::TransitionEvidence<'_>,
        _now_unix: i64,
    ) -> Result<PaymentAttemptTransition, StorageError> {
        Err(unimplemented_surface("transition_payment_attempt"))
    }

    // schema_evidence / pool_metrics_snapshot: trait defaults (no durable
    // schema evidence probe on this slice; no Postgres pool to report).
}
