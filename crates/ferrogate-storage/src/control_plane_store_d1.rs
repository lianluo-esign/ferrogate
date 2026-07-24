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
//! Still erroring (typed `unimplemented-backend-surface`, awaiting the
//! proxy-Worker path or a later slice): assets/channels/retention, usage
//! monthly + metadata rollups, billing ledger/outbox, billing events,
//! `persist_usage_aggregate` (durable half), guardrail policy
//! revisions/bindings, snapshot replay floors, request/audit logs, agent
//! runs/events, managed + self-hosted worker stores, and the remaining
//! pre-#425 per-entity dispatch surfaces (wallets, payment attempts, agent
//! schedules, workflow budgets, observed agent presence, MCP identity). RBAC,
//! site domains, and the budget-alert idempotency ledger from that group are
//! now implemented (issue #445, see above).
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

use ferrogate_cloudflare::d1::{D1Client, D1CreateDatabaseRequest, D1Database, D1QueryResult};
use ferrogate_cloudflare::CloudflareError;

use super::control_plane_store::ControlPlaneStore;
use super::*;

/// Stable machine-checkable prefix carried by every error this backend
/// returns for a trait method outside its implemented surface.
pub const D1_UNIMPLEMENTED_SURFACE: &str = "unimplemented-backend-surface";

/// Config-document kind under which the tenant->database registry persists.
pub const D1_TENANT_DATABASE_REGISTRY_KIND: &str = "d1_tenant_database";

/// Config-document id of the singleton registry document.
pub const D1_TENANT_DATABASE_REGISTRY_ID: &str = "registry";

/// The SQLite-dialect core schema applied to every provisioned database.
const D1_SCHEMA_SQL: &str = include_str!("../../../sql/d1/001_init_d1.sql");

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

/// The signature of some append/analytics getters cannot carry an error, so
/// the unimplemented contract there is: warn loudly, return empty/default.
pub(crate) fn warn_unimplemented(method: &'static str) {
    tracing::warn!(
        "{D1_UNIMPLEMENTED_SURFACE}: {method} is not implemented by the cloudflare_d1 \
         control-plane backend; returning an empty result"
    );
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

// --- Row DTOs (D1 returns rows as JSON objects keyed by column name) ---

#[derive(Deserialize)]
struct TenantAccountRow {
    id: String,
    name: String,
    slug: String,
    status: String,
    plan_id: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<TenantAccountRow> for StoredTenantAccount {
    fn from(row: TenantAccountRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            slug: row.slug,
            status: row.status,
            plan_id: row.plan_id,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct ProjectRow {
    id: String,
    tenant_id: String,
    name: String,
    slug: String,
    status: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<ProjectRow> for StoredProject {
    fn from(row: ProjectRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            slug: row.slug,
            status: row.status,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct WorkspaceRow {
    id: String,
    project_id: String,
    tenant_id: String,
    name: String,
    slug: String,
    environment: String,
    status: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<WorkspaceRow> for StoredWorkspace {
    fn from(row: WorkspaceRow) -> Self {
        Self {
            id: row.id,
            project_id: row.project_id,
            tenant_id: row.tenant_id,
            name: row.name,
            slug: row.slug,
            environment: row.environment,
            status: row.status,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct ApiKeyRow {
    id: String,
    workspace_id: String,
    tenant_id: String,
    project_id: String,
    name: String,
    key_prefix: String,
    key_hash: String,
    last4: String,
    enabled: i64,
    scopes_json: String,
    allowed_models_json: String,
    allowed_providers_json: String,
    monthly_token_budget: Option<i64>,
    request_limit_per_minute: Option<i64>,
    created_at_unix: i64,
    updated_at_unix: i64,
    rotated_at_unix: Option<i64>,
    expires_at_unix: Option<i64>,
    revoked_at_unix: Option<i64>,
}

impl ApiKeyRow {
    fn into_stored(self) -> Result<StoredApiKey, StorageError> {
        let tenant = api_key_tenant_context(
            &self.id,
            &self.tenant_id,
            &self.project_id,
            &self.workspace_id,
        );
        Ok(StoredApiKey {
            id: self.id,
            workspace_id: self.workspace_id,
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            name: self.name,
            key_prefix: self.key_prefix,
            key_hash: self.key_hash,
            last4: self.last4,
            enabled: self.enabled != 0,
            scopes: deserialize_storage_document(&self.scopes_json)?,
            allowed_models: deserialize_storage_document(&self.allowed_models_json)?,
            allowed_providers: deserialize_storage_document(&self.allowed_providers_json)?,
            tenant,
            monthly_token_budget: self.monthly_token_budget.map(nonnegative_u64),
            request_limit_per_minute: self.request_limit_per_minute.map(nonnegative_u64),
            created_at_unix: nonnegative_u64(self.created_at_unix),
            updated_at_unix: nonnegative_u64(self.updated_at_unix),
            rotated_at_unix: self.rotated_at_unix.map(nonnegative_u64),
            expires_at_unix: self.expires_at_unix.map(nonnegative_u64),
            revoked_at_unix: self.revoked_at_unix.map(nonnegative_u64),
        })
    }
}

#[derive(Deserialize)]
struct DocumentRow {
    document_json: String,
}

#[derive(Deserialize)]
struct ResourceDocumentRow {
    resource_id: String,
    document_json: String,
}

#[derive(Deserialize)]
struct WorkspaceScopeRow {
    tenant_id: String,
    project_id: String,
    id: String,
}

#[derive(Deserialize)]
struct ProjectReferenceCountRow {
    present: i64,
    workspaces: i64,
    virtual_keys: i64,
}

#[derive(Deserialize)]
struct WorkspaceReferenceCountRow {
    present: i64,
    virtual_keys: i64,
}

// --- Row DTOs: account-global control-plane entities (issue #440) ---
//
// SQLite booleans arrive as 0/1 integers and JSONB columns as TEXT; each DTO
// decodes those back into the `Stored*` shape the trait exposes, mirroring
// the Postgres `*_from_row` helpers column-for-column.

#[derive(Deserialize)]
struct AdminUserRow {
    id: String,
    email: String,
    password_hash: String,
    display_name: String,
    superadmin: i64,
    created_at_unix: i64,
    updated_at_unix: i64,
    last_login_at_unix: Option<i64>,
    disabled_at_unix: Option<i64>,
}

impl From<AdminUserRow> for StoredAdminUser {
    fn from(row: AdminUserRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            password_hash: row.password_hash,
            display_name: row.display_name,
            superadmin: row.superadmin != 0,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
            last_login_at_unix: row.last_login_at_unix,
            disabled_at_unix: row.disabled_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct AdminUserMembershipRow {
    id: String,
    user_id: String,
    tenant_id: String,
    role: String,
    created_at_unix: i64,
}

impl From<AdminUserMembershipRow> for StoredAdminUserMembership {
    fn from(row: AdminUserMembershipRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            role: row.role,
            created_at_unix: row.created_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct AdminUserRefreshTokenRow {
    id: String,
    user_id: String,
    token_hash: String,
    tenant_id: Option<String>,
    role: Option<String>,
    created_at_unix: i64,
    expires_at_unix: i64,
    revoked_at_unix: Option<i64>,
}

impl From<AdminUserRefreshTokenRow> for StoredAdminUserRefreshToken {
    fn from(row: AdminUserRefreshTokenRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            tenant_id: row.tenant_id,
            role: row.role,
            created_at_unix: row.created_at_unix,
            expires_at_unix: row.expires_at_unix,
            revoked_at_unix: row.revoked_at_unix,
        }
    }
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct SsoProviderConfigRow {
    tenant_id: String,
    provider_kind: String,
    default_role: String,
    group_role_mapping_json: String,
    oidc_issuer: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret_ref: Option<String>,
    oidc_redirect_uri: Option<String>,
    oidc_group_claim: Option<String>,
    saml_idp_entity_id: Option<String>,
    saml_idp_sso_url: Option<String>,
    saml_idp_certificate: Option<String>,
    saml_sp_entity_id: Option<String>,
    saml_acs_url: Option<String>,
    saml_email_attribute: Option<String>,
    saml_name_attribute: Option<String>,
    saml_groups_attribute: Option<String>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl SsoProviderConfigRow {
    fn into_stored(self) -> Result<StoredSsoProviderConfig, StorageError> {
        Ok(StoredSsoProviderConfig {
            tenant_id: self.tenant_id,
            provider_kind: self.provider_kind,
            default_role: self.default_role,
            group_role_mapping: deserialize_storage_document(&self.group_role_mapping_json)?,
            oidc_issuer: self.oidc_issuer,
            oidc_client_id: self.oidc_client_id,
            oidc_client_secret_ref: self.oidc_client_secret_ref,
            oidc_redirect_uri: self.oidc_redirect_uri,
            oidc_group_claim: self.oidc_group_claim,
            saml_idp_entity_id: self.saml_idp_entity_id,
            saml_idp_sso_url: self.saml_idp_sso_url,
            saml_idp_certificate: self.saml_idp_certificate,
            saml_sp_entity_id: self.saml_sp_entity_id,
            saml_acs_url: self.saml_acs_url,
            saml_email_attribute: self.saml_email_attribute,
            saml_name_attribute: self.saml_name_attribute,
            saml_groups_attribute: self.saml_groups_attribute,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
        })
    }
}

#[derive(Deserialize)]
struct SsoPendingFlowRow {
    state: String,
    tenant_id: String,
    provider_kind: String,
    code_verifier: Option<String>,
    request_id: Option<String>,
    created_at_unix: i64,
    expires_at_unix: i64,
}

impl From<SsoPendingFlowRow> for StoredSsoPendingFlow {
    fn from(row: SsoPendingFlowRow) -> Self {
        Self {
            state: row.state,
            tenant_id: row.tenant_id,
            provider_kind: row.provider_kind,
            code_verifier: row.code_verifier,
            request_id: row.request_id,
            created_at_unix: row.created_at_unix,
            expires_at_unix: row.expires_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct QuotaPolicyRow {
    id: String,
    scope_type: String,
    scope_id: String,
    model_allowlist_json: String,
    rpm_limit: Option<i64>,
    tpm_limit: Option<i64>,
    monthly_budget_usd: Option<f64>,
    enabled: i64,
    created_at_unix: i64,
    updated_at_unix: i64,
    alert_threshold_pcts_json: String,
    asset_storage_quota_bytes: Option<i64>,
    monthly_egress_bytes_budget: Option<i64>,
    download_rpm_limit: Option<i64>,
}

impl QuotaPolicyRow {
    fn into_stored(self) -> Result<StoredQuotaPolicy, StorageError> {
        let scope_type = QuotaScopeKind::from_str_opt(&self.scope_type).ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: unknown quota_policies.scope_type {}",
                self.scope_type
            ))
        })?;
        Ok(StoredQuotaPolicy {
            id: self.id,
            scope_type,
            scope_id: self.scope_id,
            model_allowlist: deserialize_storage_document(&self.model_allowlist_json)?,
            rpm_limit: self.rpm_limit.map(nonnegative_u64),
            tpm_limit: self.tpm_limit.map(nonnegative_u64),
            monthly_budget_usd: self.monthly_budget_usd,
            asset_storage_quota_bytes: self.asset_storage_quota_bytes.map(nonnegative_u64),
            alert_threshold_pcts: deserialize_storage_document(&self.alert_threshold_pcts_json)?,
            enabled: self.enabled != 0,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
            monthly_egress_bytes_budget: self.monthly_egress_bytes_budget.map(nonnegative_u64),
            download_rpm_limit: self.download_rpm_limit.map(nonnegative_u64),
        })
    }
}

#[derive(Deserialize)]
struct PlanRow {
    id: String,
    name: String,
    slug: String,
    mcp_enabled: i64,
    self_hosted_workers_enabled: i64,
    admin_console_seats: Option<i64>,
    default_model_allowlist_json: String,
    default_rpm_limit: Option<i64>,
    default_tpm_limit: Option<i64>,
    default_monthly_budget_usd: Option<f64>,
    created_at_unix: i64,
    updated_at_unix: i64,
    asset_hosting_enabled: i64,
    default_asset_storage_quota_bytes: Option<i64>,
    extension_tools_enabled: i64,
    default_monthly_egress_bytes_budget: Option<i64>,
    default_download_rpm_limit: Option<i64>,
}

impl PlanRow {
    fn into_stored(self) -> Result<StoredPlan, StorageError> {
        Ok(StoredPlan {
            id: self.id,
            name: self.name,
            slug: self.slug,
            mcp_enabled: self.mcp_enabled != 0,
            self_hosted_workers_enabled: self.self_hosted_workers_enabled != 0,
            admin_console_seats: self.admin_console_seats.map(nonnegative_u32),
            default_model_allowlist: deserialize_storage_document(
                &self.default_model_allowlist_json,
            )?,
            default_rpm_limit: self.default_rpm_limit.map(nonnegative_u64),
            default_tpm_limit: self.default_tpm_limit.map(nonnegative_u64),
            default_monthly_budget_usd: self.default_monthly_budget_usd,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
            asset_hosting_enabled: self.asset_hosting_enabled != 0,
            default_asset_storage_quota_bytes: self
                .default_asset_storage_quota_bytes
                .map(nonnegative_u64),
            default_monthly_egress_bytes_budget: self
                .default_monthly_egress_bytes_budget
                .map(nonnegative_u64),
            default_download_rpm_limit: self.default_download_rpm_limit.map(nonnegative_u64),
            extension_tools_enabled: self.extension_tools_enabled != 0,
        })
    }
}

// --- Row DTOs: account-global admin/config entities (issue #445) ---
//
// RBAC (permissions/roles/tenant_role_bindings), site domains, and the budget
// alert idempotency ledger are account-scoped configuration (not per-request
// tenant data), so each routes to the CONTROL database like the #440 families;
// the DTOs decode the SQLite row shape (JSONB -> TEXT, SMALLINT -> INTEGER)
// back into the `Stored*` struct the trait exposes.

#[derive(Deserialize)]
struct PermissionRow {
    id: String,
    key: String,
    name: String,
    description: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<PermissionRow> for StoredPermission {
    fn from(row: PermissionRow) -> Self {
        Self {
            id: row.id,
            key: row.key,
            name: row.name,
            description: row.description,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct RoleRow {
    id: String,
    name: String,
    slug: String,
    description: String,
    permission_keys_json: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl RoleRow {
    fn into_stored(self) -> Result<StoredRole, StorageError> {
        Ok(StoredRole {
            id: self.id,
            name: self.name,
            slug: self.slug,
            description: self.description,
            permission_keys: deserialize_storage_document(&self.permission_keys_json)?,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
        })
    }
}

#[derive(Deserialize)]
struct TenantRoleBindingRow {
    id: String,
    tenant_id: String,
    role_id: String,
    created_at_unix: i64,
}

impl From<TenantRoleBindingRow> for StoredTenantRoleBinding {
    fn from(row: TenantRoleBindingRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            role_id: row.role_id,
            created_at_unix: row.created_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct SiteDomainRow {
    hostname: String,
    tenant_id: String,
    site: String,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<SiteDomainRow> for StoredSiteDomain {
    fn from(row: SiteDomainRow) -> Self {
        Self {
            hostname: row.hostname,
            tenant_id: row.tenant_id,
            site: row.site,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

#[derive(Deserialize)]
struct BudgetAlertNotificationRow {
    id: String,
    scope_type: String,
    scope_id: String,
    period_month: String,
    threshold_pct: i64,
    notified_at_unix: i64,
}

impl BudgetAlertNotificationRow {
    fn into_stored(self) -> Result<StoredBudgetAlertNotification, StorageError> {
        let scope_type = QuotaScopeKind::from_str_opt(&self.scope_type).ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: unknown budget_alert_notifications.scope_type {}",
                self.scope_type
            ))
        })?;
        Ok(StoredBudgetAlertNotification {
            id: self.id,
            scope_type,
            scope_id: self.scope_id,
            period_month: self.period_month,
            threshold_pct: self.threshold_pct.clamp(0, i64::from(u8::MAX)) as u8,
            notified_at_unix: self.notified_at_unix,
        })
    }
}

const SELECT_PERMISSION_COLUMNS: &str = "SELECT id, key, name, description, created_at_unix, \
     updated_at_unix FROM permissions";

const SELECT_ROLE_COLUMNS: &str = "SELECT id, name, slug, description, permission_keys_json, \
     created_at_unix, updated_at_unix FROM roles";

const SELECT_TENANT_ROLE_BINDING_COLUMNS: &str = "SELECT id, tenant_id, role_id, created_at_unix \
     FROM tenant_role_bindings";

const SELECT_SITE_DOMAIN_COLUMNS: &str = "SELECT hostname, tenant_id, site, created_at_unix, \
     updated_at_unix FROM site_domains";

const SELECT_BUDGET_ALERT_NOTIFICATION_COLUMNS: &str = "SELECT id, scope_type, scope_id, \
     period_month, threshold_pct, notified_at_unix FROM budget_alert_notifications";

const SELECT_ADMIN_USER_COLUMNS: &str = "SELECT id, email, password_hash, display_name, \
     superadmin, created_at_unix, updated_at_unix, last_login_at_unix, disabled_at_unix \
     FROM admin_users";

const SELECT_ADMIN_USER_MEMBERSHIP_COLUMNS: &str = "SELECT id, user_id, tenant_id, role, \
     created_at_unix FROM admin_user_tenant_memberships";

const SELECT_ADMIN_USER_REFRESH_TOKEN_COLUMNS: &str = "SELECT id, user_id, token_hash, \
     tenant_id, role, created_at_unix, expires_at_unix, revoked_at_unix \
     FROM admin_user_refresh_tokens";

const SELECT_SSO_PROVIDER_CONFIG_COLUMNS: &str = "SELECT tenant_id, provider_kind, default_role, \
     group_role_mapping_json, oidc_issuer, oidc_client_id, oidc_client_secret_ref, \
     oidc_redirect_uri, oidc_group_claim, saml_idp_entity_id, saml_idp_sso_url, \
     saml_idp_certificate, saml_sp_entity_id, saml_acs_url, saml_email_attribute, \
     saml_name_attribute, saml_groups_attribute, created_at_unix, updated_at_unix \
     FROM sso_provider_configs";

const SELECT_SSO_PENDING_FLOW_COLUMNS: &str = "SELECT state, tenant_id, provider_kind, \
     code_verifier, request_id, created_at_unix, expires_at_unix FROM sso_pending_flows";

const SELECT_QUOTA_POLICY_COLUMNS: &str = "SELECT id, scope_type, scope_id, model_allowlist_json, \
     rpm_limit, tpm_limit, monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
     alert_threshold_pcts_json, asset_storage_quota_bytes, monthly_egress_bytes_budget, \
     download_rpm_limit FROM quota_policies";

const SELECT_PLAN_COLUMNS: &str = "SELECT id, name, slug, mcp_enabled, \
     self_hosted_workers_enabled, admin_console_seats, default_model_allowlist_json, \
     default_rpm_limit, default_tpm_limit, default_monthly_budget_usd, created_at_unix, \
     updated_at_unix, asset_hosting_enabled, default_asset_storage_quota_bytes, \
     extension_tools_enabled, default_monthly_egress_bytes_budget, default_download_rpm_limit \
     FROM plans";

const SELECT_TENANT_COLUMNS: &str =
    "SELECT id, name, slug, status, plan_id, created_at_unix, updated_at_unix FROM tenants";

const SELECT_PROJECT_COLUMNS: &str =
    "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix FROM projects";

const SELECT_WORKSPACE_COLUMNS: &str = "SELECT id, project_id, tenant_id, name, slug, \
     environment, status, created_at_unix, updated_at_unix FROM workspaces";

const SELECT_API_KEY_COLUMNS: &str = "SELECT id, workspace_id, tenant_id, project_id, name, \
     key_prefix, key_hash, last4, enabled, scopes_json, allowed_models_json, \
     allowed_providers_json, monthly_token_budget, request_limit_per_minute, created_at_unix, \
     updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix FROM api_keys";

impl D1ControlPlaneStore {
    /// Build the backend from a D1 endpoint client and a (possibly empty)
    /// registry — load a persisted registry with
    /// [`D1TenantDatabaseRegistry::from_document_json`] first when resuming
    /// an existing deployment.
    pub fn new(client: D1Client, registry: D1TenantDatabaseRegistry) -> Self {
        Self {
            client,
            registry: Mutex::new(registry),
            usage_aggregates_mirror: Mutex::new(InMemoryRepository::new()),
        }
    }

    /// A snapshot of the current tenant->database registry.
    pub fn registry_snapshot(&self) -> Result<D1TenantDatabaseRegistry, StorageError> {
        self.registry
            .lock()
            .map(|registry| registry.clone())
            .map_err(|_| poisoned_registry_lock())
    }

    // --- Provisioning lifecycle (inherent, admin path) ---

    /// Provision the CONTROL database (tenants + config documents + registry
    /// document) if the registry does not name one yet. Idempotent; returns
    /// the control database uuid.
    pub async fn provision_control_database(&self) -> Result<String, StorageError> {
        {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            if !registry.control_database_id.is_empty() {
                return Ok(registry.control_database_id.clone());
            }
        }
        let database_id = self
            .create_database_with_schema("ferrogate-control")
            .await?;
        {
            let mut registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry.control_database_id = database_id.clone();
        }
        self.persist_registry().await?;
        Ok(database_id)
    }

    /// Provision a tenant's D1 database: create it, apply the SQLite core
    /// schema (`sql/d1/001_init_d1.sql`), record it in the registry, and
    /// persist the registry document. Idempotent per tenant; returns the
    /// database uuid.
    pub async fn provision_tenant_database(&self, tenant_id: &str) -> Result<String, StorageError> {
        validate_tenant_id(tenant_id)?;
        {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            if let Some(existing) = registry.tenant_databases.get(tenant_id) {
                return Ok(existing.clone());
            }
        }
        let name = format!("ferrogate-tenant-{}", tenant_id.to_ascii_lowercase());
        let database_id = self.create_database_with_schema(&name).await?;
        {
            let mut registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry
                .tenant_databases
                .insert(tenant_id.to_string(), database_id.clone());
        }
        self.persist_registry().await?;
        Ok(database_id)
    }

    /// Delete a tenant's D1 database (and ALL its data) and drop it from the
    /// registry. Returns `false` when the tenant had no registered database.
    pub async fn deprovision_tenant_database(&self, tenant_id: &str) -> Result<bool, StorageError> {
        let database_id = {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry.tenant_databases.get(tenant_id).cloned()
        };
        let Some(database_id) = database_id else {
            return Ok(false);
        };
        self.client
            .delete_database(&database_id)
            .await
            .map_err(d1_error)?;
        {
            let mut registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry.tenant_databases.remove(tenant_id);
        }
        self.persist_registry().await?;
        Ok(true)
    }

    /// List the account's D1 databases (admin visibility across control +
    /// tenant databases and any unregistered leftovers).
    pub async fn list_provisioned_databases(&self) -> Result<Vec<D1Database>, StorageError> {
        self.client.list_databases().await.map_err(d1_error)
    }

    async fn create_database_with_schema(&self, name: &str) -> Result<String, StorageError> {
        let created = self
            .client
            .create_database(&D1CreateDatabaseRequest::named(name))
            .await
            .map_err(d1_error)?;
        let database_id = created.uuid.ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: create database {name} returned no uuid"
            ))
        })?;
        self.execute(&database_id, &schema_batch_sql(), Vec::new())
            .await?;
        Ok(database_id)
    }

    async fn persist_registry(&self) -> Result<(), StorageError> {
        let (control_database_id, document_json) = {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            (
                registry.control_database_id.clone(),
                registry.to_document_json()?,
            )
        };
        if control_database_id.is_empty() {
            return Err(StorageError::Runtime(
                "cloudflare d1: cannot persist tenant database registry without a control \
                 database (call provision_control_database first)"
                    .to_string(),
            ));
        }
        self.put_document(
            &control_database_id,
            D1_TENANT_DATABASE_REGISTRY_KIND,
            D1_TENANT_DATABASE_REGISTRY_ID,
            &document_json,
        )
        .await
    }

    // --- Routing ---

    fn control_database_id(&self) -> Result<String, StorageError> {
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        if registry.control_database_id.is_empty() {
            return Err(StorageError::Runtime(
                "cloudflare d1: no control database configured (call \
                 provision_control_database or seed the registry)"
                    .to_string(),
            ));
        }
        Ok(registry.control_database_id.clone())
    }

    /// The database an entity write routes to: the tenant's database, or the
    /// control database for an EMPTY tenant id (pre-multi-tenant records).
    fn database_for_tenant(&self, tenant_id: &str) -> Result<String, StorageError> {
        if tenant_id.is_empty() {
            return self.control_database_id();
        }
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        registry
            .tenant_databases
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "no provisioned D1 database for tenant {tenant_id} \
                     (call provision_tenant_database first)"
                ))
            })
    }

    /// Control database first, then every tenant database in registry order —
    /// the fan-out set for id-only reads and unfiltered lists.
    fn fan_out_database_ids(&self) -> Result<Vec<String>, StorageError> {
        let control = self.control_database_id()?;
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        let mut databases = vec![control];
        for database_id in registry.tenant_databases.values() {
            if !databases.contains(database_id) {
                databases.push(database_id.clone());
            }
        }
        Ok(databases)
    }

    // --- Query plumbing ---

    /// Run one statement and return its result, surfacing per-statement
    /// failure as a typed error.
    async fn execute(
        &self,
        database_id: &str,
        sql: &str,
        params: Vec<String>,
    ) -> Result<D1QueryResult, StorageError> {
        let mut results = self
            .client
            .query(database_id, sql, &params)
            .await
            .map_err(d1_error)?;
        if let Some(failed) = results
            .iter()
            .position(|result| result.success == Some(false))
        {
            return Err(StorageError::Runtime(format!(
                "cloudflare d1: statement {failed} of batch reported failure"
            )));
        }
        results.pop().ok_or_else(|| {
            StorageError::Runtime("cloudflare d1: query returned no result".to_string())
        })
    }

    async fn fetch_rows<T: serde::de::DeserializeOwned>(
        &self,
        database_id: &str,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Vec<T>, StorageError> {
        let result = self.execute(database_id, sql, params).await?;
        result
            .results
            .into_iter()
            .map(|row| {
                serde_json::from_value(row)
                    .map_err(|error| StorageError::Serialization(error.to_string()))
            })
            .collect()
    }

    async fn fetch_optional_row<T: serde::de::DeserializeOwned>(
        &self,
        database_id: &str,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Option<T>, StorageError> {
        Ok(self
            .fetch_rows(database_id, sql, params)
            .await?
            .into_iter()
            .next())
    }

    // --- Generic config documents (control database) ---

    async fn put_document(
        &self,
        database_id: &str,
        kind: &str,
        id: &str,
        document_json: &str,
    ) -> Result<(), StorageError> {
        self.execute(
            database_id,
            "INSERT INTO control_plane_resources \
             (resource_kind, resource_id, document_json, revision, created_at_unix, \
              updated_at_unix) \
             VALUES (?, ?, ?, 1, unixepoch(), unixepoch()) \
             ON CONFLICT (resource_kind, resource_id) DO UPDATE SET \
             document_json = excluded.document_json, \
             revision = control_plane_resources.revision + 1, \
             updated_at_unix = unixepoch()",
            vec![kind.to_string(), id.to_string(), document_json.to_string()],
        )
        .await
        .map(|_| ())
    }

    async fn upsert_config_document_async(
        &self,
        kind: &str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.put_document(&database_id, kind, &id, &document_json)
            .await
    }

    async fn delete_config_document_async(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<bool, StorageError> {
        let database_id = self.control_database_id()?;
        let result = self
            .execute(
                &database_id,
                "DELETE FROM control_plane_resources \
                 WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.to_string(), id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    async fn get_config_document_async(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        let database_id = self.control_database_id()?;
        let row: Option<DocumentRow> = self
            .fetch_optional_row(
                &database_id,
                "SELECT document_json FROM control_plane_resources \
                 WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.to_string(), id.to_string()],
            )
            .await?;
        Ok(row.map(|row| row.document_json))
    }

    async fn list_config_resource_documents_async(
        &self,
        kind: &str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let database_id = self.control_database_id()?;
        let rows: Vec<ResourceDocumentRow> = self
            .fetch_rows(
                &database_id,
                "SELECT resource_id, document_json FROM control_plane_resources \
                 WHERE resource_kind = ? ORDER BY resource_id ASC",
                vec![kind.to_string()],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.resource_id, row.document_json))
            .collect())
    }

    async fn replace_config_kind_async(
        &self,
        kind: &str,
        documents: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(
            &database_id,
            "DELETE FROM control_plane_resources WHERE resource_kind = ?",
            vec![kind.to_string()],
        )
        .await?;
        for (id, document_json) in documents {
            self.put_document(&database_id, kind, &id, &document_json)
                .await?;
        }
        Ok(())
    }

    async fn config_documents_async(&self) -> Result<ControlPlaneDocuments, StorageError> {
        Ok(ControlPlaneDocuments {
            api_keys: self.list_config_resource_documents_async("api_key").await?,
            tenants: self.list_config_resource_documents_async("tenant").await?,
            policies: self.list_config_resource_documents_async("policy").await?,
            gateway_configs: self
                .list_config_resource_documents_async("gateway_config")
                .await?,
            agent_workflows: self
                .list_config_resource_documents_async("agent_workflow")
                .await?,
            skill_packages: self
                .list_config_resource_documents_async("skill_package")
                .await?,
            prompt_templates: self
                .list_config_resource_documents_async("prompt_template")
                .await?,
            plugin_registrations: self
                .list_config_resource_documents_async("plugin_registration")
                .await?,
            mcp_servers: self
                .list_config_resource_documents_async("mcp_server")
                .await?,
            agent_upstreams: self
                .list_config_resource_documents_async("agent_upstream")
                .await?,
        })
    }

    // --- Account-global entities: read a single control-database row ---
    //
    // Admin identity, SSO, quota policies, and plans are account-scoped
    // control-plane configuration (issue #440); every one routes to the
    // control database, so these thin helpers factor out the shared
    // `control_database_id()` lookup.

    async fn fetch_control_optional<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Option<T>, StorageError> {
        let database_id = self.control_database_id()?;
        self.fetch_optional_row(&database_id, sql, params).await
    }

    async fn fetch_control_rows<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Vec<T>, StorageError> {
        let database_id = self.control_database_id()?;
        self.fetch_rows(&database_id, sql, params).await
    }

    async fn execute_control(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<D1QueryResult, StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(&database_id, sql, params).await
    }
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

impl RuntimeControlPlaneBackend {
    /// Wrap a D1 store as the active control-plane backend (issue #420).
    pub(crate) fn cloudflare_d1(store: D1ControlPlaneStore) -> Self {
        RuntimeControlPlaneBackend::CloudflareD1(Arc::new(store))
    }
}

impl RuntimeStorageRepositories {
    /// Assemble repositories backed by the per-tenant Cloudflare D1 backend
    /// (issue #420). The non-control-plane repositories (guardrail evidence)
    /// stay in-memory exactly as on the other durable backends.
    pub fn cloudflare_d1(store: D1ControlPlaneStore, audit_event_retention_records: usize) -> Self {
        Self {
            backend: RuntimeStorageBackend::in_memory(vec![StorageProviderKind::Memory]),
            control_plane: RuntimeControlPlaneBackend::cloudflare_d1(store),
            guardrail_evidence: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            guardrail_evaluation_retention_records: Mutex::new(audit_event_retention_records),
        }
    }

    /// The config-driven construction route (issue #440): build the D1
    /// control-plane backend from an already-assembled [`D1Client`] plus the
    /// operator-supplied [`CloudflareD1StorageOptions`], seeding the
    /// tenant->database registry from config so the backend is usable without
    /// a separate runtime bootstrap call.
    ///
    /// This is the storage half of the `storage.provider = "cloudflare_d1"`
    /// route. The caller (the CLI) owns the transport, so it builds the
    /// `CloudflareClient`/`D1Client` from the `[cloudflare]` block and passes
    /// it here — keeping this crate free of any HTTP/transport dependency and
    /// unit-testable against a scripted transport. See the module docs and
    /// `docs/cloudflare-d1-backend.md` for the exact CLI hook.
    pub fn cloudflare_d1_from_client(
        client: D1Client,
        options: CloudflareD1StorageOptions,
    ) -> Result<Self, StorageError> {
        let store = D1ControlPlaneStore::new(client, options.registry());
        Ok(Self::cloudflare_d1(
            store,
            options.audit_event_retention_records,
        ))
    }
}

/// Operator-supplied configuration for the config-driven D1 construction
/// route (issue #440). Seeds the tenant->database registry from config so a
/// deployment resuming against already-provisioned databases boots without a
/// live provisioning round trip; a control database that has not been
/// provisioned yet is expressed as an empty [`control_database_id`], which the
/// backend rejects on first control-plane access until
/// [`D1ControlPlaneStore::provision_control_database`] seeds it.
///
/// [`control_database_id`]: CloudflareD1StorageOptions::control_database_id
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareD1StorageOptions {
    /// D1 uuid of the control database (tenants + config documents + the
    /// registry document). Empty means "not provisioned yet".
    pub control_database_id: String,
    /// Pre-seeded `tenant_id -> D1 database uuid` registry entries, for a
    /// deployment resuming against existing tenant databases.
    pub tenant_databases: BTreeMap<String, String>,
    /// Retention bound for the in-memory guardrail-evidence repository, matching
    /// the other backends' `audit_event_retention_records`.
    pub audit_event_retention_records: usize,
}

impl CloudflareD1StorageOptions {
    /// Assemble the [`D1TenantDatabaseRegistry`] this config describes.
    fn registry(&self) -> D1TenantDatabaseRegistry {
        D1TenantDatabaseRegistry {
            control_database_id: self.control_database_id.clone(),
            tenant_databases: self.tenant_databases.clone(),
        }
    }
}

#[async_trait::async_trait]
impl ControlPlaneStore for D1ControlPlaneStore {
    // --- API keys (IMPLEMENTED) ---

    async fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError> {
        let database_id = self.database_for_tenant(&api_key.tenant_id)?;
        let params = vec![
            api_key.id.clone(),
            api_key.workspace_id.clone(),
            api_key.tenant_id.clone(),
            api_key.project_id.clone(),
            api_key.name.clone(),
            api_key.key_prefix.clone(),
            api_key.key_hash.clone(),
            api_key.last4.clone(),
            if api_key.enabled { "1" } else { "0" }.to_string(),
            serialize_storage_document(&api_key.scopes)?,
            serialize_storage_document(&api_key.allowed_models)?,
            serialize_storage_document(&api_key.allowed_providers)?,
            optional_number_param(api_key.monthly_token_budget),
            optional_number_param(api_key.request_limit_per_minute),
            api_key.created_at_unix.to_string(),
            api_key.updated_at_unix.to_string(),
            optional_number_param(api_key.rotated_at_unix),
            optional_number_param(api_key.expires_at_unix),
            optional_number_param(api_key.revoked_at_unix),
        ];
        self.execute(
            &database_id,
            "INSERT INTO api_keys \
             (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, \
              enabled, scopes_json, allowed_models_json, allowed_providers_json, \
              monthly_token_budget, request_limit_per_minute, created_at_unix, \
              updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, \
              NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (id) DO UPDATE SET \
             workspace_id = excluded.workspace_id, tenant_id = excluded.tenant_id, \
             project_id = excluded.project_id, name = excluded.name, \
             key_prefix = excluded.key_prefix, key_hash = excluded.key_hash, \
             last4 = excluded.last4, enabled = excluded.enabled, \
             scopes_json = excluded.scopes_json, \
             allowed_models_json = excluded.allowed_models_json, \
             allowed_providers_json = excluded.allowed_providers_json, \
             monthly_token_budget = excluded.monthly_token_budget, \
             request_limit_per_minute = excluded.request_limit_per_minute, \
             updated_at_unix = excluded.updated_at_unix, \
             rotated_at_unix = excluded.rotated_at_unix, \
             expires_at_unix = excluded.expires_at_unix, \
             revoked_at_unix = excluded.revoked_at_unix",
            params,
        )
        .await
        .map(|_| ())
    }

    async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        let sql = format!("{SELECT_API_KEY_COLUMNS} WHERE id = ?");
        for database_id in self.fan_out_database_ids()? {
            let row: Option<ApiKeyRow> = self
                .fetch_optional_row(&database_id, &sql, vec![id.to_string()])
                .await?;
            if let Some(row) = row {
                return Ok(Some(row.into_stored()?));
            }
        }
        Ok(None)
    }

    async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        let sql = format!("{SELECT_API_KEY_COLUMNS} ORDER BY id ASC");
        let mut api_keys = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<ApiKeyRow> = self.fetch_rows(&database_id, &sql, Vec::new()).await?;
            for row in rows {
                api_keys.push(row.into_stored()?);
            }
        }
        Ok(api_keys)
    }

    async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        let sql = format!("{SELECT_API_KEY_COLUMNS} WHERE key_prefix = ? ORDER BY id ASC");
        let mut api_keys = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<ApiKeyRow> = self
                .fetch_rows(&database_id, &sql, vec![key_prefix.to_string()])
                .await?;
            for row in rows {
                api_keys.push(row.into_stored()?);
            }
        }
        Ok(api_keys)
    }

    // --- Admin users / SSO / refresh tokens (IMPLEMENTED, control database) ---

    async fn upsert_admin_user(&self, user: StoredAdminUser) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO admin_users \
             (id, email, password_hash, display_name, superadmin, created_at_unix, \
              updated_at_unix, last_login_at_unix, disabled_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (id) DO UPDATE SET \
             email = excluded.email, password_hash = excluded.password_hash, \
             display_name = excluded.display_name, superadmin = excluded.superadmin, \
             updated_at_unix = excluded.updated_at_unix, \
             last_login_at_unix = excluded.last_login_at_unix, \
             disabled_at_unix = excluded.disabled_at_unix",
            vec![
                user.id,
                user.email,
                user.password_hash,
                user.display_name,
                bool_param(user.superadmin),
                user.created_at_unix.to_string(),
                user.updated_at_unix.to_string(),
                optional_number_param(user.last_login_at_unix),
                optional_number_param(user.disabled_at_unix),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_admin_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        let row: Option<AdminUserRow> = self
            .fetch_control_optional(
                &format!("{SELECT_ADMIN_USER_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.map(StoredAdminUser::from))
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        let row: Option<AdminUserRow> = self
            .fetch_control_optional(
                &format!("{SELECT_ADMIN_USER_COLUMNS} WHERE email = ?"),
                vec![email.to_string()],
            )
            .await?;
        Ok(row.map(StoredAdminUser::from))
    }

    async fn upsert_admin_user_membership(
        &self,
        membership: StoredAdminUserMembership,
    ) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO admin_user_tenant_memberships \
             (id, user_id, tenant_id, role, created_at_unix) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = excluded.role",
            vec![
                membership.id,
                membership.user_id,
                membership.tenant_id,
                membership.role,
                membership.created_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        let rows: Vec<AdminUserMembershipRow> = self
            .fetch_control_rows(
                &format!(
                    "{SELECT_ADMIN_USER_MEMBERSHIP_COLUMNS} WHERE user_id = ? ORDER BY id ASC"
                ),
                vec![user_id.to_string()],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(StoredAdminUserMembership::from)
            .collect())
    }

    async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        let rows: Vec<AdminUserMembershipRow> = self
            .fetch_control_rows(
                &format!(
                    "{SELECT_ADMIN_USER_MEMBERSHIP_COLUMNS} WHERE tenant_id = ? ORDER BY id ASC"
                ),
                vec![tenant_id.to_string()],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(StoredAdminUserMembership::from)
            .collect())
    }

    async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM admin_user_tenant_memberships \
                 WHERE user_id = ? AND tenant_id = ?",
                vec![user_id.to_string(), tenant_id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    async fn upsert_sso_provider_config(
        &self,
        config: StoredSsoProviderConfig,
    ) -> Result<(), StorageError> {
        let group_role_mapping_json = serialize_storage_document(&config.group_role_mapping)?;
        self.execute_control(
            "INSERT INTO sso_provider_configs \
             (tenant_id, provider_kind, default_role, group_role_mapping_json, oidc_issuer, \
              oidc_client_id, oidc_client_secret_ref, oidc_redirect_uri, oidc_group_claim, \
              saml_idp_entity_id, saml_idp_sso_url, saml_idp_certificate, saml_sp_entity_id, \
              saml_acs_url, saml_email_attribute, saml_name_attribute, saml_groups_attribute, \
              created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), \
              NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), \
              NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
             provider_kind = excluded.provider_kind, default_role = excluded.default_role, \
             group_role_mapping_json = excluded.group_role_mapping_json, \
             oidc_issuer = excluded.oidc_issuer, oidc_client_id = excluded.oidc_client_id, \
             oidc_client_secret_ref = excluded.oidc_client_secret_ref, \
             oidc_redirect_uri = excluded.oidc_redirect_uri, \
             oidc_group_claim = excluded.oidc_group_claim, \
             saml_idp_entity_id = excluded.saml_idp_entity_id, \
             saml_idp_sso_url = excluded.saml_idp_sso_url, \
             saml_idp_certificate = excluded.saml_idp_certificate, \
             saml_sp_entity_id = excluded.saml_sp_entity_id, \
             saml_acs_url = excluded.saml_acs_url, \
             saml_email_attribute = excluded.saml_email_attribute, \
             saml_name_attribute = excluded.saml_name_attribute, \
             saml_groups_attribute = excluded.saml_groups_attribute, \
             updated_at_unix = excluded.updated_at_unix",
            vec![
                config.tenant_id,
                config.provider_kind,
                config.default_role,
                group_role_mapping_json,
                config.oidc_issuer.unwrap_or_default(),
                config.oidc_client_id.unwrap_or_default(),
                config.oidc_client_secret_ref.unwrap_or_default(),
                config.oidc_redirect_uri.unwrap_or_default(),
                config.oidc_group_claim.unwrap_or_default(),
                config.saml_idp_entity_id.unwrap_or_default(),
                config.saml_idp_sso_url.unwrap_or_default(),
                config.saml_idp_certificate.unwrap_or_default(),
                config.saml_sp_entity_id.unwrap_or_default(),
                config.saml_acs_url.unwrap_or_default(),
                config.saml_email_attribute.unwrap_or_default(),
                config.saml_name_attribute.unwrap_or_default(),
                config.saml_groups_attribute.unwrap_or_default(),
                config.created_at_unix.to_string(),
                config.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError> {
        let row: Option<SsoProviderConfigRow> = self
            .fetch_control_optional(
                &format!("{SELECT_SSO_PROVIDER_CONFIG_COLUMNS} WHERE tenant_id = ?"),
                vec![tenant_id.to_string()],
            )
            .await?;
        row.map(SsoProviderConfigRow::into_stored).transpose()
    }

    async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM sso_provider_configs WHERE tenant_id = ?",
                vec![tenant_id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    async fn insert_sso_pending_flow(
        &self,
        flow: StoredSsoPendingFlow,
    ) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO sso_pending_flows \
             (state, tenant_id, provider_kind, code_verifier, request_id, created_at_unix, \
              expires_at_unix) \
             VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?) \
             ON CONFLICT (state) DO NOTHING",
            vec![
                flow.state,
                flow.tenant_id,
                flow.provider_kind,
                flow.code_verifier.unwrap_or_default(),
                flow.request_id.unwrap_or_default(),
                flow.created_at_unix.to_string(),
                flow.expires_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError> {
        // The D1 HTTP query API exposes neither DELETE ... RETURNING nor a
        // multi-statement-with-params batch, so this reads the row and then
        // deletes it (plus prunes expired rows) in a follow-up statement,
        // rather than as one atomic delete-returning like the Postgres backend.
        // The two calls are not transactional: a rare concurrent double
        // callback for the same `state` could observe the row twice. That is an
        // accepted divergence on this admin/low-volume path (single-use state
        // tokens make the collision improbable, and the callback still
        // re-validates downstream); it is called out in the module docs.
        let row: Option<SsoPendingFlowRow> = self
            .fetch_control_optional(
                &format!("{SELECT_SSO_PENDING_FLOW_COLUMNS} WHERE state = ?"),
                vec![state.to_string()],
            )
            .await?;
        self.execute_control(
            "DELETE FROM sso_pending_flows WHERE state = ? OR expires_at_unix <= ?",
            vec![state.to_string(), now_unix.to_string()],
        )
        .await?;
        let flow = row.map(StoredSsoPendingFlow::from);
        Ok(flow.filter(|flow| flow.expires_at_unix > now_unix))
    }

    async fn upsert_admin_user_refresh_token(
        &self,
        token: StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO admin_user_refresh_tokens \
             (id, user_id, token_hash, tenant_id, role, created_at_unix, expires_at_unix, \
              revoked_at_unix) \
             VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, NULLIF(?, '')) \
             ON CONFLICT (id) DO UPDATE SET revoked_at_unix = excluded.revoked_at_unix",
            vec![
                token.id,
                token.user_id,
                token.token_hash,
                token.tenant_id.unwrap_or_default(),
                token.role.unwrap_or_default(),
                token.created_at_unix.to_string(),
                token.expires_at_unix.to_string(),
                optional_number_param(token.revoked_at_unix),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError> {
        let row: Option<AdminUserRefreshTokenRow> = self
            .fetch_control_optional(
                &format!("{SELECT_ADMIN_USER_REFRESH_TOKEN_COLUMNS} WHERE token_hash = ?"),
                vec![token_hash.to_string()],
            )
            .await?;
        Ok(row.map(StoredAdminUserRefreshToken::from))
    }

    async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        let result = self
            .execute_control(
                "UPDATE admin_user_refresh_tokens SET revoked_at_unix = ? \
                 WHERE user_id = ? AND revoked_at_unix IS NULL",
                vec![revoked_at_unix.to_string(), user_id.to_string()],
            )
            .await?;
        Ok(result.changes())
    }

    async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        let result = self
            .execute_control(
                "UPDATE admin_user_refresh_tokens SET revoked_at_unix = ? \
                 WHERE user_id = ? AND tenant_id = ? AND revoked_at_unix IS NULL",
                vec![
                    revoked_at_unix.to_string(),
                    user_id.to_string(),
                    tenant_id.to_string(),
                ],
            )
            .await?;
        Ok(result.changes())
    }

    // --- Tenant accounts (IMPLEMENTED, control database) ---

    async fn upsert_tenant_account(
        &self,
        account: StoredTenantAccount,
    ) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(
            &database_id,
            "INSERT INTO tenants \
             (id, name, slug, status, plan_id, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             name = excluded.name, slug = excluded.slug, status = excluded.status, \
             plan_id = excluded.plan_id, updated_at_unix = excluded.updated_at_unix",
            vec![
                account.id,
                account.name,
                account.slug,
                account.status,
                account.plan_id,
                account.created_at_unix.to_string(),
                account.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        let database_id = self.control_database_id()?;
        let row: Option<TenantAccountRow> = self
            .fetch_optional_row(
                &database_id,
                &format!("{SELECT_TENANT_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.map(StoredTenantAccount::from))
    }

    async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        let database_id = self.control_database_id()?;
        let rows: Vec<TenantAccountRow> = self
            .fetch_rows(
                &database_id,
                &format!("{SELECT_TENANT_COLUMNS} ORDER BY id ASC"),
                Vec::new(),
            )
            .await?;
        Ok(rows.into_iter().map(StoredTenantAccount::from).collect())
    }

    // --- Projects (IMPLEMENTED, tenant database) ---

    async fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError> {
        let database_id = self.database_for_tenant(&project.tenant_id)?;
        self.execute(
            &database_id,
            "INSERT INTO projects \
             (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             tenant_id = excluded.tenant_id, name = excluded.name, slug = excluded.slug, \
             status = excluded.status, updated_at_unix = excluded.updated_at_unix",
            vec![
                project.id,
                project.tenant_id,
                project.name,
                project.slug,
                project.status,
                project.created_at_unix.to_string(),
                project.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        let sql = format!("{SELECT_PROJECT_COLUMNS} WHERE id = ?");
        for database_id in self.fan_out_database_ids()? {
            let row: Option<ProjectRow> = self
                .fetch_optional_row(&database_id, &sql, vec![id.to_string()])
                .await?;
            if let Some(row) = row {
                return Ok(Some(row.into()));
            }
        }
        Ok(None)
    }

    async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        let sql = format!("{SELECT_PROJECT_COLUMNS} ORDER BY id ASC");
        let mut projects = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<ProjectRow> = self.fetch_rows(&database_id, &sql, Vec::new()).await?;
            projects.extend(rows.into_iter().map(StoredProject::from));
        }
        Ok(projects)
    }

    async fn delete_project(&self, id: &str) -> Result<bool, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let result = self
                .execute(
                    &database_id,
                    "DELETE FROM projects WHERE id = ?",
                    vec![id.to_string()],
                )
                .await?;
            if result.changes() > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            // The guarded DELETE is a single statement, so the
            // reject-if-referenced check is atomic within this database.
            let deleted = self
                .execute(
                    &database_id,
                    "DELETE FROM projects WHERE id = ? \
                     AND NOT EXISTS (SELECT 1 FROM workspaces WHERE project_id = ?) \
                     AND NOT EXISTS (SELECT 1 FROM api_keys WHERE project_id = ?)",
                    vec![id.to_string(), id.to_string(), id.to_string()],
                )
                .await?;
            if deleted.changes() > 0 {
                return Ok(DeleteProjectOutcome::Deleted);
            }
            let counts: Option<ProjectReferenceCountRow> = self
                .fetch_optional_row(
                    &database_id,
                    "SELECT (SELECT COUNT(*) FROM projects WHERE id = ?) AS present, \
                     (SELECT COUNT(*) FROM workspaces WHERE project_id = ?) AS workspaces, \
                     (SELECT COUNT(*) FROM api_keys WHERE project_id = ?) AS virtual_keys",
                    vec![id.to_string(), id.to_string(), id.to_string()],
                )
                .await?;
            if let Some(counts) = counts {
                if counts.present > 0 {
                    return Ok(DeleteProjectOutcome::Referenced {
                        workspaces: counts.workspaces.max(0) as usize,
                        virtual_keys: counts.virtual_keys.max(0) as usize,
                    });
                }
            }
        }
        Ok(DeleteProjectOutcome::NotFound)
    }

    // --- Workspaces (IMPLEMENTED, tenant database) ---

    async fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError> {
        let database_id = self.database_for_tenant(&workspace.tenant_id)?;
        self.execute(
            &database_id,
            "INSERT INTO workspaces \
             (id, project_id, tenant_id, name, slug, environment, status, created_at_unix, \
              updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             project_id = excluded.project_id, tenant_id = excluded.tenant_id, \
             name = excluded.name, slug = excluded.slug, environment = excluded.environment, \
             status = excluded.status, updated_at_unix = excluded.updated_at_unix",
            vec![
                workspace.id,
                workspace.project_id,
                workspace.tenant_id,
                workspace.name,
                workspace.slug,
                workspace.environment,
                workspace.status,
                workspace.created_at_unix.to_string(),
                workspace.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        let sql = format!("{SELECT_WORKSPACE_COLUMNS} WHERE id = ?");
        for database_id in self.fan_out_database_ids()? {
            let row: Option<WorkspaceRow> = self
                .fetch_optional_row(&database_id, &sql, vec![id.to_string()])
                .await?;
            if let Some(row) = row {
                return Ok(Some(row.into()));
            }
        }
        Ok(None)
    }

    async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        let sql = format!("{SELECT_WORKSPACE_COLUMNS} ORDER BY id ASC");
        let mut workspaces = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<WorkspaceRow> = self.fetch_rows(&database_id, &sql, Vec::new()).await?;
            workspaces.extend(rows.into_iter().map(StoredWorkspace::from));
        }
        Ok(workspaces)
    }

    async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let result = self
                .execute(
                    &database_id,
                    "DELETE FROM workspaces WHERE id = ?",
                    vec![id.to_string()],
                )
                .await?;
            if result.changes() > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let deleted = self
                .execute(
                    &database_id,
                    "DELETE FROM workspaces WHERE id = ? \
                     AND NOT EXISTS (SELECT 1 FROM api_keys WHERE workspace_id = ?)",
                    vec![id.to_string(), id.to_string()],
                )
                .await?;
            if deleted.changes() > 0 {
                return Ok(DeleteWorkspaceOutcome::Deleted);
            }
            let counts: Option<WorkspaceReferenceCountRow> = self
                .fetch_optional_row(
                    &database_id,
                    "SELECT (SELECT COUNT(*) FROM workspaces WHERE id = ?) AS present, \
                     (SELECT COUNT(*) FROM api_keys WHERE workspace_id = ?) AS virtual_keys",
                    vec![id.to_string(), id.to_string()],
                )
                .await?;
            if let Some(counts) = counts {
                if counts.present > 0 {
                    return Ok(DeleteWorkspaceOutcome::Referenced {
                        virtual_keys: counts.virtual_keys.max(0) as usize,
                    });
                }
            }
        }
        Ok(DeleteWorkspaceOutcome::NotFound)
    }

    async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let row: Option<WorkspaceScopeRow> = self
                .fetch_optional_row(
                    &database_id,
                    "SELECT tenant_id, project_id, id FROM workspaces WHERE id = ?",
                    vec![workspace_id.to_string()],
                )
                .await?;
            if let Some(row) = row {
                return Ok(Some(WorkspaceScope::new(
                    row.tenant_id,
                    row.project_id,
                    row.id,
                )));
            }
        }
        Ok(None)
    }

    // --- Quota policies / plans (IMPLEMENTED, control database) ---

    async fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> Result<(), StorageError> {
        let model_allowlist_json = serialize_storage_document(&policy.model_allowlist)?;
        let alert_threshold_pcts_json = serialize_storage_document(&policy.alert_threshold_pcts)?;
        self.execute_control(
            "INSERT INTO quota_policies \
             (id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit, \
              monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
              alert_threshold_pcts_json, asset_storage_quota_bytes, monthly_egress_bytes_budget, \
              download_rpm_limit) \
             VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, \
              NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (scope_type, scope_id) DO UPDATE SET \
             model_allowlist_json = excluded.model_allowlist_json, \
             rpm_limit = excluded.rpm_limit, tpm_limit = excluded.tpm_limit, \
             monthly_budget_usd = excluded.monthly_budget_usd, enabled = excluded.enabled, \
             updated_at_unix = excluded.updated_at_unix, \
             alert_threshold_pcts_json = excluded.alert_threshold_pcts_json, \
             asset_storage_quota_bytes = excluded.asset_storage_quota_bytes, \
             monthly_egress_bytes_budget = excluded.monthly_egress_bytes_budget, \
             download_rpm_limit = excluded.download_rpm_limit",
            vec![
                policy.id,
                policy.scope_type.as_str().to_string(),
                policy.scope_id,
                model_allowlist_json,
                optional_number_param(policy.rpm_limit),
                optional_number_param(policy.tpm_limit),
                optional_number_param(policy.monthly_budget_usd),
                bool_param(policy.enabled),
                policy.created_at_unix.to_string(),
                policy.updated_at_unix.to_string(),
                alert_threshold_pcts_json,
                optional_number_param(policy.asset_storage_quota_bytes),
                optional_number_param(policy.monthly_egress_bytes_budget),
                optional_number_param(policy.download_rpm_limit),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError> {
        let row: Option<QuotaPolicyRow> = self
            .fetch_control_optional(
                &format!("{SELECT_QUOTA_POLICY_COLUMNS} WHERE scope_type = ? AND scope_id = ?"),
                vec![scope_type.as_str().to_string(), scope_id.to_string()],
            )
            .await?;
        row.map(QuotaPolicyRow::into_stored).transpose()
    }

    async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        let rows: Vec<QuotaPolicyRow> = self
            .fetch_control_rows(
                &format!("{SELECT_QUOTA_POLICY_COLUMNS} ORDER BY id ASC"),
                Vec::new(),
            )
            .await?;
        rows.into_iter().map(QuotaPolicyRow::into_stored).collect()
    }

    async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM quota_policies WHERE scope_type = ? AND scope_id = ?",
                vec![scope_type.as_str().to_string(), scope_id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    async fn upsert_plan(&self, plan: StoredPlan) -> Result<(), StorageError> {
        let default_model_allowlist_json =
            serialize_storage_document(&plan.default_model_allowlist)?;
        self.execute_control(
            "INSERT INTO plans \
             (id, name, slug, mcp_enabled, self_hosted_workers_enabled, admin_console_seats, \
              default_model_allowlist_json, default_rpm_limit, default_tpm_limit, \
              default_monthly_budget_usd, created_at_unix, updated_at_unix, asset_hosting_enabled, \
              default_asset_storage_quota_bytes, extension_tools_enabled, \
              default_monthly_egress_bytes_budget, default_download_rpm_limit) \
             VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, ''), \
              NULLIF(?, ''), ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (id) DO UPDATE SET \
             name = excluded.name, slug = excluded.slug, mcp_enabled = excluded.mcp_enabled, \
             self_hosted_workers_enabled = excluded.self_hosted_workers_enabled, \
             admin_console_seats = excluded.admin_console_seats, \
             default_model_allowlist_json = excluded.default_model_allowlist_json, \
             default_rpm_limit = excluded.default_rpm_limit, \
             default_tpm_limit = excluded.default_tpm_limit, \
             default_monthly_budget_usd = excluded.default_monthly_budget_usd, \
             updated_at_unix = excluded.updated_at_unix, \
             asset_hosting_enabled = excluded.asset_hosting_enabled, \
             default_asset_storage_quota_bytes = excluded.default_asset_storage_quota_bytes, \
             extension_tools_enabled = excluded.extension_tools_enabled, \
             default_monthly_egress_bytes_budget = excluded.default_monthly_egress_bytes_budget, \
             default_download_rpm_limit = excluded.default_download_rpm_limit",
            vec![
                plan.id,
                plan.name,
                plan.slug,
                bool_param(plan.mcp_enabled),
                bool_param(plan.self_hosted_workers_enabled),
                optional_number_param(plan.admin_console_seats),
                default_model_allowlist_json,
                optional_number_param(plan.default_rpm_limit),
                optional_number_param(plan.default_tpm_limit),
                optional_number_param(plan.default_monthly_budget_usd),
                plan.created_at_unix.to_string(),
                plan.updated_at_unix.to_string(),
                bool_param(plan.asset_hosting_enabled),
                optional_number_param(plan.default_asset_storage_quota_bytes),
                bool_param(plan.extension_tools_enabled),
                optional_number_param(plan.default_monthly_egress_bytes_budget),
                optional_number_param(plan.default_download_rpm_limit),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError> {
        let row: Option<PlanRow> = self
            .fetch_control_optional(
                &format!("{SELECT_PLAN_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        row.map(PlanRow::into_stored).transpose()
    }

    async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError> {
        let rows: Vec<PlanRow> = self
            .fetch_control_rows(
                &format!("{SELECT_PLAN_COLUMNS} ORDER BY id ASC"),
                Vec::new(),
            )
            .await?;
        rows.into_iter().map(PlanRow::into_stored).collect()
    }

    // --- Assets (UNIMPLEMENTED) ---

    async fn upsert_asset(&self, _asset: StoredAsset) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_asset"))
    }

    async fn create_asset_if_absent(&self, _asset: StoredAsset) -> Result<bool, StorageError> {
        Err(unimplemented_surface("create_asset_if_absent"))
    }

    async fn create_asset_within_quota(
        &self,
        _asset: StoredAsset,
        _quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        Err(unimplemented_surface("create_asset_within_quota"))
    }

    async fn get_asset(&self, _id: &str) -> Result<Option<StoredAsset>, StorageError> {
        Err(unimplemented_surface("get_asset"))
    }

    async fn list_assets(
        &self,
        _tenant_id: &str,
        _asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        Err(unimplemented_surface("list_assets"))
    }

    async fn list_withheld_assets(
        &self,
        _tenant_id: &str,
        _asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        Err(unimplemented_surface("list_withheld_assets"))
    }

    async fn tenant_asset_storage_bytes_used(&self, _tenant_id: &str) -> Result<u64, StorageError> {
        Err(unimplemented_surface("tenant_asset_storage_bytes_used"))
    }

    async fn delete_asset(&self, _id: &str) -> Result<bool, StorageError> {
        Err(unimplemented_surface("delete_asset"))
    }

    async fn upsert_asset_channel(&self, _channel: StoredAssetChannel) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_asset_channel"))
    }

    async fn list_asset_channels(
        &self,
        _tenant_id: &str,
        _asset_type: &str,
        _name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        Err(unimplemented_surface("list_asset_channels"))
    }

    async fn delete_asset_channel(&self, _id: &str) -> Result<bool, StorageError> {
        Err(unimplemented_surface("delete_asset_channel"))
    }

    async fn move_asset_channel_if_resolvable(
        &self,
        _channel: StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        Err(unimplemented_surface("move_asset_channel_if_resolvable"))
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_asset_version_yank(
        &self,
        _tenant_id: &str,
        _asset_type: &str,
        _name: &str,
        _version: &str,
        _yanked: bool,
        _now_unix: i64,
    ) -> Result<VersionYankOutcome, StorageError> {
        Err(unimplemented_surface("set_asset_version_yank"))
    }

    async fn delete_asset_variant_if_unreferenced(
        &self,
        _id: &str,
        _tenant_id: &str,
        _asset_type: &str,
        _name: &str,
        _version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError> {
        Err(unimplemented_surface(
            "delete_asset_variant_if_unreferenced",
        ))
    }

    async fn promote_pending_asset_visibility(
        &self,
        _id: &str,
        _target: AssetPromotionTarget,
        _now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        Err(unimplemented_surface("promote_pending_asset_visibility"))
    }

    async fn upsert_retention_policy(
        &self,
        _policy: StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_retention_policy"))
    }

    async fn list_retention_policies(
        &self,
        _tenant_id: &str,
        _resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        Err(unimplemented_surface("list_retention_policies"))
    }

    async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError> {
        Err(unimplemented_surface("list_all_assets"))
    }

    async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError> {
        Err(unimplemented_surface("list_all_asset_channels"))
    }

    // --- Usage rollups / billing ledger + outbox (UNIMPLEMENTED) ---

    async fn get_usage_monthly_rollup(
        &self,
        _scope_type: QuotaScopeKind,
        _scope_id: &str,
        _period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        Err(unimplemented_surface("get_usage_monthly_rollup"))
    }

    async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        Err(unimplemented_surface("list_usage_monthly_rollups"))
    }

    async fn append_billing_ledger_entry(
        &self,
        _entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        Err(unimplemented_surface("append_billing_ledger_entry"))
    }

    async fn list_billing_ledger_entries(
        &self,
        _filter: &ferrogate_billing::LedgerListFilter,
        _offset: usize,
        _limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        Err(unimplemented_surface("list_billing_ledger_entries"))
    }

    async fn billing_ledger_entry(
        &self,
        _id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        Err(unimplemented_surface("billing_ledger_entry"))
    }

    async fn enqueue_billing_report(
        &self,
        _id: &str,
        _event: &ferrogate_billing::BillingEvent,
        _next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("enqueue_billing_report"))
    }

    async fn list_due_billing_reports(
        &self,
        _now_unix: i64,
        _limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        Err(unimplemented_surface("list_due_billing_reports"))
    }

    async fn reschedule_billing_report(
        &self,
        _id: &str,
        _next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("reschedule_billing_report"))
    }

    async fn dead_letter_billing_report(
        &self,
        _id: &str,
        _dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("dead_letter_billing_report"))
    }

    async fn list_dead_lettered_billing_reports(
        &self,
        _limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        Err(unimplemented_surface("list_dead_lettered_billing_reports"))
    }

    async fn replay_dead_lettered_billing_report(
        &self,
        _id: &str,
        _next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        Err(unimplemented_surface("replay_dead_lettered_billing_report"))
    }

    async fn get_billing_report_outbox_entry(
        &self,
        _id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        Err(unimplemented_surface("get_billing_report_outbox_entry"))
    }

    async fn delete_billing_report(&self, _id: &str) -> Result<(), StorageError> {
        Err(unimplemented_surface("delete_billing_report"))
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

    // --- Guardrail policy surface (UNIMPLEMENTED) ---

    fn insert_guardrail_policy_revision(
        &self,
        _revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("insert_guardrail_policy_revision"))
    }

    fn get_guardrail_policy_revision(
        &self,
        _policy_id: &str,
        _revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        Err(unimplemented_surface("get_guardrail_policy_revision"))
    }

    fn list_guardrail_policy_revisions(
        &self,
        _policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        Err(unimplemented_surface("list_guardrail_policy_revisions"))
    }

    fn get_guardrail_policy_binding(
        &self,
        _policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        Err(unimplemented_surface("get_guardrail_policy_binding"))
    }

    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        Err(unimplemented_surface("list_guardrail_policy_bindings"))
    }

    fn activate_guardrail_policy_revision(
        &self,
        _policy_id: &str,
        _revision: u32,
        _updated_by: &str,
        _updated_at_unix: u64,
        _rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        Err(unimplemented_surface("activate_guardrail_policy_revision"))
    }

    fn archive_guardrail_policy_revision(
        &self,
        _policy_id: &str,
        _revision: u32,
        _updated_by: &str,
        _updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        Err(unimplemented_surface("archive_guardrail_policy_revision"))
    }

    fn restore_guardrail_policy_binding(
        &self,
        _policy_id: &str,
        _expected_generation: Option<u64>,
        _binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("restore_guardrail_policy_binding"))
    }

    // --- Snapshot replay floors (UNIMPLEMENTED) ---

    fn get_snapshot_replay_floor(
        &self,
        _tenant_id: &str,
        _deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        Err(unimplemented_surface("get_snapshot_replay_floor"))
    }

    fn advance_snapshot_replay_floor(
        &self,
        _tenant_id: &str,
        _deployment_id: &str,
        _revision: u64,
        _updated_at_unix: i64,
    ) -> Result<u64, StorageError> {
        Err(unimplemented_surface("advance_snapshot_replay_floor"))
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

    async fn append_request_log(&self, _log: StoredRequestLog) {
        warn_unimplemented("append_request_log");
    }

    async fn request_logs(&self) -> Vec<StoredRequestLog> {
        warn_unimplemented("request_logs");
        Vec::new()
    }

    async fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredRequestLog> {
        warn_unimplemented("request_logs_page");
        StoragePage::empty(offset, limit)
    }

    async fn delete_request_logs(&self, _request_ids: &[String]) -> Result<u64, StorageError> {
        Err(unimplemented_surface("delete_request_logs"))
    }

    async fn request_logs_for_agent_runs(&self, _run_ids: &[String]) -> Vec<StoredRequestLog> {
        warn_unimplemented("request_logs_for_agent_runs");
        Vec::new()
    }

    async fn append_audit_event(&self, _event: StoredAuditEvent) {
        warn_unimplemented("append_audit_event");
    }

    fn next_audit_event_id(&self) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("audit-{nanos}-{}", std::process::id())
    }

    async fn audit_events(&self) -> Vec<StoredAuditEvent> {
        warn_unimplemented("audit_events");
        Vec::new()
    }

    async fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredAuditEvent> {
        warn_unimplemented("audit_events_page");
        StoragePage::empty(offset, limit)
    }

    async fn delete_audit_events(&self, _ids: &[String]) -> Result<u64, StorageError> {
        Err(unimplemented_surface("delete_audit_events"))
    }

    async fn audit_events_for_agent_runs(&self, _run_ids: &[String]) -> Vec<StoredAuditEvent> {
        warn_unimplemented("audit_events_for_agent_runs");
        Vec::new()
    }

    async fn append_billing_event(&self, _event: BillingEvent) -> Result<bool, StorageError> {
        Err(unimplemented_surface("append_billing_event"))
    }

    async fn append_billing_event_with_outbox_enqueue(
        &self,
        _event: BillingEvent,
        _outbox_id: &str,
        _outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError> {
        Err(unimplemented_surface(
            "append_billing_event_with_outbox_enqueue",
        ))
    }

    async fn billing_events(&self) -> Vec<BillingEvent> {
        warn_unimplemented("billing_events");
        Vec::new()
    }

    async fn billing_events_page(&self, offset: usize, limit: usize) -> StoragePage<BillingEvent> {
        warn_unimplemented("billing_events_page");
        StoragePage::empty(offset, limit)
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
        _aggregate: &StoredUsageAggregate,
    ) -> Result<(), StorageError> {
        // The DURABLE half is a hot-path write that belongs behind the proxy
        // Worker (see module docs), so it is typed unimplemented rather than
        // silently dropped.
        Err(unimplemented_surface("persist_usage_aggregate"))
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

    // --- Agent runs / workers (UNIMPLEMENTED) ---

    async fn upsert_agent_run(&self, _run: StoredAgentRun) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_agent_run"))
    }

    async fn agent_run(&self, _id: &str) -> Option<StoredAgentRun> {
        warn_unimplemented("agent_run");
        None
    }

    async fn agent_runs(&self) -> Vec<StoredAgentRun> {
        warn_unimplemented("agent_runs");
        Vec::new()
    }

    async fn agent_runs_by_ids(&self, _run_ids: &[String]) -> Vec<StoredAgentRun> {
        warn_unimplemented("agent_runs_by_ids");
        Vec::new()
    }

    async fn append_agent_run_event(
        &self,
        _event: StoredAgentRunEvent,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("append_agent_run_event"))
    }

    async fn agent_run_events(&self) -> Vec<StoredAgentRunEvent> {
        warn_unimplemented("agent_run_events");
        Vec::new()
    }

    async fn agent_run_events_for_runs(&self, _run_ids: &[String]) -> Vec<StoredAgentRunEvent> {
        warn_unimplemented("agent_run_events_for_runs");
        Vec::new()
    }

    async fn agent_run_summary_seed_ids(
        &self,
        _request_id: Option<&str>,
        _limit: usize,
    ) -> Vec<String> {
        warn_unimplemented("agent_run_summary_seed_ids");
        Vec::new()
    }

    async fn upsert_managed_worker_template(
        &self,
        _template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_managed_worker_template"))
    }

    async fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate> {
        warn_unimplemented("managed_worker_templates");
        Vec::new()
    }

    async fn upsert_agent_worker_instance(
        &self,
        _instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_agent_worker_instance"))
    }

    async fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance> {
        warn_unimplemented("agent_worker_instances");
        Vec::new()
    }

    async fn upsert_managed_worker_session(
        &self,
        _session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_managed_worker_session"))
    }

    async fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession> {
        warn_unimplemented("managed_worker_sessions");
        Vec::new()
    }

    async fn append_managed_worker_lifecycle_event(
        &self,
        _event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "append_managed_worker_lifecycle_event",
        ))
    }

    async fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent> {
        warn_unimplemented("managed_worker_lifecycle_events");
        Vec::new()
    }

    async fn upsert_managed_worker_isolation_selection(
        &self,
        _selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "upsert_managed_worker_isolation_selection",
        ))
    }

    async fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection> {
        warn_unimplemented("managed_worker_isolation_selections");
        Vec::new()
    }

    async fn upsert_managed_worker_isolation_policy(
        &self,
        _policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "upsert_managed_worker_isolation_policy",
        ))
    }

    async fn managed_worker_isolation_policies(&self) -> Vec<StoredManagedWorkerIsolationPolicy> {
        warn_unimplemented("managed_worker_isolation_policies");
        Vec::new()
    }

    async fn upsert_managed_worker_isolation_evidence(
        &self,
        _evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "upsert_managed_worker_isolation_evidence",
        ))
    }

    async fn managed_worker_isolation_evidence(&self) -> Vec<StoredManagedWorkerIsolationEvidence> {
        warn_unimplemented("managed_worker_isolation_evidence");
        Vec::new()
    }

    async fn upsert_self_hosted_worker_registration(
        &self,
        _registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "upsert_self_hosted_worker_registration",
        ))
    }

    async fn self_hosted_worker_registrations(&self) -> Vec<StoredSelfHostedWorkerRegistration> {
        warn_unimplemented("self_hosted_worker_registrations");
        Vec::new()
    }

    async fn self_hosted_worker_registration(
        &self,
        _worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerRegistration> {
        warn_unimplemented("self_hosted_worker_registration");
        None
    }

    async fn latest_self_hosted_worker_heartbeat(
        &self,
        _worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerHeartbeat> {
        warn_unimplemented("latest_self_hosted_worker_heartbeat");
        None
    }

    async fn self_hosted_worker_activity_stats(
        &self,
        _worker_id: &str,
    ) -> StoredSelfHostedWorkerActivityStats {
        warn_unimplemented("self_hosted_worker_activity_stats");
        StoredSelfHostedWorkerActivityStats::default()
    }

    async fn append_self_hosted_worker_heartbeat(
        &self,
        _heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("append_self_hosted_worker_heartbeat"))
    }

    async fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat> {
        warn_unimplemented("self_hosted_worker_heartbeats");
        Vec::new()
    }

    async fn append_self_hosted_worker_telemetry_event(
        &self,
        _event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "append_self_hosted_worker_telemetry_event",
        ))
    }

    async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        warn_unimplemented("self_hosted_worker_telemetry_events");
        Vec::new()
    }

    async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        _run_id: &str,
        _limit: usize,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        warn_unimplemented("self_hosted_worker_telemetry_events_for_run");
        Vec::new()
    }

    async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        _worker_id: &str,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        warn_unimplemented("self_hosted_worker_telemetry_events_for_worker");
        Vec::new()
    }

    async fn upsert_self_hosted_worker_artifact(
        &self,
        _artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_self_hosted_worker_artifact"))
    }

    async fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact> {
        warn_unimplemented("self_hosted_worker_artifacts");
        Vec::new()
    }

    async fn self_hosted_worker_artifact(
        &self,
        _id: &str,
    ) -> Option<StoredSelfHostedWorkerArtifact> {
        warn_unimplemented("self_hosted_worker_artifact");
        None
    }

    async fn upsert_self_hosted_worker_checkpoint(
        &self,
        _checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface(
            "upsert_self_hosted_worker_checkpoint",
        ))
    }

    async fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint> {
        warn_unimplemented("self_hosted_worker_checkpoints");
        Vec::new()
    }

    async fn self_hosted_worker_checkpoint(
        &self,
        _id: &str,
    ) -> Option<StoredSelfHostedWorkerCheckpoint> {
        warn_unimplemented("self_hosted_worker_checkpoint");
        None
    }

    async fn upsert_self_hosted_run_dispatch(
        &self,
        _dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_self_hosted_run_dispatch"))
    }

    async fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch> {
        warn_unimplemented("self_hosted_run_dispatches");
        Vec::new()
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
        self.execute_control(
            "INSERT INTO site_domains \
             (hostname, tenant_id, site, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (hostname) DO UPDATE SET \
             tenant_id = excluded.tenant_id, site = excluded.site, \
             updated_at_unix = excluded.updated_at_unix",
            vec![
                domain.hostname,
                domain.tenant_id,
                domain.site,
                domain.created_at_unix.to_string(),
                domain.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError> {
        let row: Option<SiteDomainRow> = self
            .fetch_control_optional(
                &format!("{SELECT_SITE_DOMAIN_COLUMNS} WHERE hostname = ?"),
                vec![hostname.to_string()],
            )
            .await?;
        Ok(row.map(StoredSiteDomain::from))
    }

    async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError> {
        let rows: Vec<SiteDomainRow> = match tenant_id {
            Some(tenant_id) => {
                self.fetch_control_rows(
                    &format!(
                        "{SELECT_SITE_DOMAIN_COLUMNS} WHERE tenant_id = ? ORDER BY hostname ASC"
                    ),
                    vec![tenant_id.to_string()],
                )
                .await?
            }
            None => {
                self.fetch_control_rows(
                    &format!("{SELECT_SITE_DOMAIN_COLUMNS} ORDER BY hostname ASC"),
                    Vec::new(),
                )
                .await?
            }
        };
        Ok(rows.into_iter().map(StoredSiteDomain::from).collect())
    }

    async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM site_domains WHERE hostname = ?",
                vec![hostname.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    async fn list_usage_metadata_rollups(
        &self,
        _metadata_key: &str,
        _organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        Err(unimplemented_surface("list_usage_metadata_rollups"))
    }

    async fn touch_observed_agent_presence(
        &self,
        _touch: ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("touch_observed_agent_presence"))
    }

    async fn list_observed_agent_presence_since(
        &self,
        _tenant_scope: Option<&str>,
        _since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        Err(unimplemented_surface("list_observed_agent_presence_since"))
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
        self.execute_control(
            "INSERT INTO budget_alert_notifications \
             (id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![
                notification.id,
                notification.scope_type.as_str().to_string(),
                notification.scope_id,
                notification.period_month,
                i64::from(notification.threshold_pct).to_string(),
                notification.notified_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn budget_alert_already_notified(&self, id: &str) -> Result<bool, StorageError> {
        let row: Option<BudgetAlertNotificationRow> = self
            .fetch_control_optional(
                &format!("{SELECT_BUDGET_ALERT_NOTIFICATION_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.is_some())
    }

    async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError> {
        let rows: Vec<BudgetAlertNotificationRow> = self
            .fetch_control_rows(
                &format!(
                    "{SELECT_BUDGET_ALERT_NOTIFICATION_COLUMNS} \
                     WHERE scope_type = ? AND scope_id = ? AND period_month = ? \
                     ORDER BY threshold_pct ASC"
                ),
                vec![
                    scope_type.as_str().to_string(),
                    scope_id.to_string(),
                    period_month.to_string(),
                ],
            )
            .await?;
        rows.into_iter()
            .map(BudgetAlertNotificationRow::into_stored)
            .collect()
    }

    async fn open_workflow_run_budget(
        &self,
        _workflow_id: &str,
        _workflow_version: u32,
        _run_id: &str,
        _tenant_id: &str,
        _caps: WorkflowRunBudgetCaps,
        _now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        Err(unimplemented_surface("open_workflow_run_budget"))
    }

    async fn debit_workflow_run_budget(
        &self,
        _id: &str,
        _cost_credits: i64,
        _tokens: i64,
        _tool_calls: i64,
        _now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError> {
        Err(unimplemented_surface("debit_workflow_run_budget"))
    }

    async fn topup_workflow_run_budget(
        &self,
        _id: &str,
        _add_cost_credits: i64,
        _add_tokens: i64,
        _add_tool_calls: i64,
        _extend_deadline_unix: Option<i64>,
        _now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        Err(unimplemented_surface("topup_workflow_run_budget"))
    }

    async fn get_workflow_run_budget(
        &self,
        _id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        Err(unimplemented_surface("get_workflow_run_budget"))
    }

    async fn list_workflow_run_budgets(
        &self,
        _tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        Err(unimplemented_surface("list_workflow_run_budgets"))
    }

    // --- RBAC: permissions / roles / tenant role bindings (IMPLEMENTED,
    // control database, issue #445) ---
    //
    // Permissions and roles are shared/global (like plans); tenant role
    // bindings are account-level admin config keyed by a deterministic
    // `tenant_id:role_id` id. All account-global, so the control database owns
    // them -- never fanned out over tenant databases.

    async fn upsert_permission(&self, permission: StoredPermission) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO permissions \
             (id, key, name, description, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             key = excluded.key, name = excluded.name, description = excluded.description, \
             updated_at_unix = excluded.updated_at_unix",
            vec![
                permission.id,
                permission.key,
                permission.name,
                permission.description,
                permission.created_at_unix.to_string(),
                permission.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError> {
        let row: Option<PermissionRow> = self
            .fetch_control_optional(
                &format!("{SELECT_PERMISSION_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.map(StoredPermission::from))
    }

    async fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError> {
        let rows: Vec<PermissionRow> = self
            .fetch_control_rows(
                &format!("{SELECT_PERMISSION_COLUMNS} ORDER BY key ASC"),
                Vec::new(),
            )
            .await?;
        Ok(rows.into_iter().map(StoredPermission::from).collect())
    }

    async fn delete_permission(&self, id: &str) -> Result<bool, StorageError> {
        let result = self
            .execute_control("DELETE FROM permissions WHERE id = ?", vec![id.to_string()])
            .await?;
        Ok(result.changes() > 0)
    }

    async fn upsert_role(&self, role: StoredRole) -> Result<(), StorageError> {
        let permission_keys_json = serialize_storage_document(&role.permission_keys)?;
        self.execute_control(
            "INSERT INTO roles \
             (id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             name = excluded.name, slug = excluded.slug, description = excluded.description, \
             permission_keys_json = excluded.permission_keys_json, \
             updated_at_unix = excluded.updated_at_unix",
            vec![
                role.id,
                role.name,
                role.slug,
                role.description,
                permission_keys_json,
                role.created_at_unix.to_string(),
                role.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError> {
        let row: Option<RoleRow> = self
            .fetch_control_optional(
                &format!("{SELECT_ROLE_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        row.map(RoleRow::into_stored).transpose()
    }

    async fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError> {
        let rows: Vec<RoleRow> = self
            .fetch_control_rows(
                &format!("{SELECT_ROLE_COLUMNS} ORDER BY slug ASC"),
                Vec::new(),
            )
            .await?;
        rows.into_iter().map(RoleRow::into_stored).collect()
    }

    async fn delete_role(&self, id: &str) -> Result<bool, StorageError> {
        let result = self
            .execute_control("DELETE FROM roles WHERE id = ?", vec![id.to_string()])
            .await?;
        Ok(result.changes() > 0)
    }

    async fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (id) DO NOTHING",
            vec![
                binding.id,
                binding.tenant_id,
                binding.role_id,
                binding.created_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError> {
        let rows: Vec<TenantRoleBindingRow> = self
            .fetch_control_rows(
                &format!(
                    "{SELECT_TENANT_ROLE_BINDING_COLUMNS} WHERE tenant_id = ? ORDER BY role_id ASC"
                ),
                vec![tenant_id.to_string()],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(StoredTenantRoleBinding::from)
            .collect())
    }

    async fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<bool, StorageError> {
        // tenant_role_bindings carries UNIQUE (tenant_id, role_id), so deleting
        // by the natural key pair is equivalent to the Postgres delete-by-id.
        let result = self
            .execute_control(
                "DELETE FROM tenant_role_bindings WHERE tenant_id = ? AND role_id = ?",
                vec![tenant_id.to_string(), role_id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    async fn upsert_agent_schedule(
        &self,
        _schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_agent_schedule"))
    }

    async fn get_agent_schedule(
        &self,
        _schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        Err(unimplemented_surface("get_agent_schedule"))
    }

    async fn list_agent_schedules(
        &self,
        _tenant_id: &str,
        _workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        Err(unimplemented_surface("list_agent_schedules"))
    }

    async fn list_all_agent_schedules(&self) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        Err(unimplemented_surface("list_all_agent_schedules"))
    }

    async fn delete_agent_schedule(&self, _schedule_id: &str) -> Result<bool, StorageError> {
        Err(unimplemented_surface("delete_agent_schedule"))
    }

    async fn list_due_agent_schedules(
        &self,
        _now_unix: i64,
        _limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        Err(unimplemented_surface("list_due_agent_schedules"))
    }

    async fn insert_agent_schedule_fire(
        &self,
        _fire: StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        Err(unimplemented_surface("insert_agent_schedule_fire"))
    }

    async fn list_agent_schedule_fires(
        &self,
        _schedule_id: &str,
        _limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        Err(unimplemented_surface("list_agent_schedule_fires"))
    }

    async fn settle_wallet_balance(
        &self,
        _settlement_id: &str,
        _tenant_id: &str,
        _delta_credits: i64,
        _now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        Err(unimplemented_surface("settle_wallet_balance"))
    }

    async fn upsert_wallet(&self, _wallet: StoredWallet) -> Result<(), StorageError> {
        Err(unimplemented_surface("upsert_wallet"))
    }

    async fn get_wallet(&self, _tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        Err(unimplemented_surface("get_wallet"))
    }

    async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        Err(unimplemented_surface("list_wallets"))
    }

    async fn adjust_wallet_balance(
        &self,
        _tenant_id: &str,
        _delta_credits: i64,
        _now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        Err(unimplemented_surface("adjust_wallet_balance"))
    }

    async fn set_wallet_dunning(
        &self,
        _tenant_id: &str,
        _dunning: bool,
        _now_unix: i64,
    ) -> Result<(), StorageError> {
        Err(unimplemented_surface("set_wallet_dunning"))
    }

    async fn reserve_wallet_credits(
        &self,
        _reservation_id: &str,
        _tenant_id: &str,
        _amount_credits: i64,
        _expires_at_unix: i64,
        _now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        Err(unimplemented_surface("reserve_wallet_credits"))
    }

    async fn settle_wallet_reservation(
        &self,
        _reservation_id: &str,
        _now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        Err(unimplemented_surface("settle_wallet_reservation"))
    }

    async fn release_wallet_reservation(
        &self,
        _reservation_id: &str,
        _now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        Err(unimplemented_surface("release_wallet_reservation"))
    }

    async fn sweep_expired_wallet_reservations(
        &self,
        _now_unix: i64,
    ) -> Result<Vec<String>, StorageError> {
        Err(unimplemented_surface("sweep_expired_wallet_reservations"))
    }

    async fn list_wallet_reservations(
        &self,
        _tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        Err(unimplemented_surface("list_wallet_reservations"))
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
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
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
