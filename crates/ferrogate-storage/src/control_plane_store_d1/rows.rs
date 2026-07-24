// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: row DTOs + SELECT column lists decoding D1 JSON rows into Stored* shapes.

//! D1 backend: row DTOs + SELECT column lists decoding D1 JSON rows into Stored* shapes.
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use serde::Deserialize;

use super::*;

// --- Row DTOs (D1 returns rows as JSON objects keyed by column name) ---

#[derive(Deserialize)]
pub(super) struct TenantAccountRow {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) status: String,
    pub(super) plan_id: String,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
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
pub(super) struct ProjectRow {
    pub(super) id: String,
    pub(super) tenant_id: String,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) status: String,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
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
pub(super) struct WorkspaceRow {
    pub(super) id: String,
    pub(super) project_id: String,
    pub(super) tenant_id: String,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) environment: String,
    pub(super) status: String,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
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
pub(super) struct ApiKeyRow {
    pub(super) id: String,
    pub(super) workspace_id: String,
    pub(super) tenant_id: String,
    pub(super) project_id: String,
    pub(super) name: String,
    pub(super) key_prefix: String,
    pub(super) key_hash: String,
    pub(super) last4: String,
    pub(super) enabled: i64,
    pub(super) scopes_json: String,
    pub(super) allowed_models_json: String,
    pub(super) allowed_providers_json: String,
    pub(super) monthly_token_budget: Option<i64>,
    pub(super) request_limit_per_minute: Option<i64>,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
    pub(super) rotated_at_unix: Option<i64>,
    pub(super) expires_at_unix: Option<i64>,
    pub(super) revoked_at_unix: Option<i64>,
}

impl ApiKeyRow {
    pub(super) fn into_stored(self) -> Result<StoredApiKey, StorageError> {
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
pub(super) struct DocumentRow {
    pub(super) document_json: String,
}

#[derive(Deserialize)]
pub(super) struct ResourceDocumentRow {
    pub(super) resource_id: String,
    pub(super) document_json: String,
}

#[derive(Deserialize)]
pub(super) struct WorkspaceScopeRow {
    pub(super) tenant_id: String,
    pub(super) project_id: String,
    pub(super) id: String,
}

#[derive(Deserialize)]
pub(super) struct ProjectReferenceCountRow {
    pub(super) present: i64,
    pub(super) workspaces: i64,
    pub(super) virtual_keys: i64,
}

#[derive(Deserialize)]
pub(super) struct WorkspaceReferenceCountRow {
    pub(super) present: i64,
    pub(super) virtual_keys: i64,
}

// --- Row DTOs: account-global control-plane entities (issue #440) ---
//
// SQLite booleans arrive as 0/1 integers and JSONB columns as TEXT; each DTO
// decodes those back into the `Stored*` shape the trait exposes, mirroring
// the Postgres `*_from_row` helpers column-for-column.

#[derive(Deserialize)]
pub(super) struct AdminUserRow {
    pub(super) id: String,
    pub(super) email: String,
    pub(super) password_hash: String,
    pub(super) display_name: String,
    pub(super) superadmin: i64,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
    pub(super) last_login_at_unix: Option<i64>,
    pub(super) disabled_at_unix: Option<i64>,
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
pub(super) struct AdminUserMembershipRow {
    pub(super) id: String,
    pub(super) user_id: String,
    pub(super) tenant_id: String,
    pub(super) role: String,
    pub(super) created_at_unix: i64,
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
pub(super) struct AdminUserRefreshTokenRow {
    pub(super) id: String,
    pub(super) user_id: String,
    pub(super) token_hash: String,
    pub(super) tenant_id: Option<String>,
    pub(super) role: Option<String>,
    pub(super) created_at_unix: i64,
    pub(super) expires_at_unix: i64,
    pub(super) revoked_at_unix: Option<i64>,
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
pub(super) struct SsoProviderConfigRow {
    pub(super) tenant_id: String,
    pub(super) provider_kind: String,
    pub(super) default_role: String,
    pub(super) group_role_mapping_json: String,
    pub(super) oidc_issuer: Option<String>,
    pub(super) oidc_client_id: Option<String>,
    pub(super) oidc_client_secret_ref: Option<String>,
    pub(super) oidc_redirect_uri: Option<String>,
    pub(super) oidc_group_claim: Option<String>,
    pub(super) saml_idp_entity_id: Option<String>,
    pub(super) saml_idp_sso_url: Option<String>,
    pub(super) saml_idp_certificate: Option<String>,
    pub(super) saml_sp_entity_id: Option<String>,
    pub(super) saml_acs_url: Option<String>,
    pub(super) saml_email_attribute: Option<String>,
    pub(super) saml_name_attribute: Option<String>,
    pub(super) saml_groups_attribute: Option<String>,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
}

impl SsoProviderConfigRow {
    pub(super) fn into_stored(self) -> Result<StoredSsoProviderConfig, StorageError> {
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
pub(super) struct SsoPendingFlowRow {
    pub(super) state: String,
    pub(super) tenant_id: String,
    pub(super) provider_kind: String,
    pub(super) code_verifier: Option<String>,
    pub(super) request_id: Option<String>,
    pub(super) created_at_unix: i64,
    pub(super) expires_at_unix: i64,
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
pub(super) struct QuotaPolicyRow {
    pub(super) id: String,
    pub(super) scope_type: String,
    pub(super) scope_id: String,
    pub(super) model_allowlist_json: String,
    pub(super) rpm_limit: Option<i64>,
    pub(super) tpm_limit: Option<i64>,
    pub(super) monthly_budget_usd: Option<f64>,
    pub(super) enabled: i64,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
    pub(super) alert_threshold_pcts_json: String,
    pub(super) asset_storage_quota_bytes: Option<i64>,
    pub(super) monthly_egress_bytes_budget: Option<i64>,
    pub(super) download_rpm_limit: Option<i64>,
}

impl QuotaPolicyRow {
    pub(super) fn into_stored(self) -> Result<StoredQuotaPolicy, StorageError> {
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
pub(super) struct PlanRow {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) mcp_enabled: i64,
    pub(super) self_hosted_workers_enabled: i64,
    pub(super) admin_console_seats: Option<i64>,
    pub(super) default_model_allowlist_json: String,
    pub(super) default_rpm_limit: Option<i64>,
    pub(super) default_tpm_limit: Option<i64>,
    pub(super) default_monthly_budget_usd: Option<f64>,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
    pub(super) asset_hosting_enabled: i64,
    pub(super) default_asset_storage_quota_bytes: Option<i64>,
    pub(super) extension_tools_enabled: i64,
    pub(super) default_monthly_egress_bytes_budget: Option<i64>,
    pub(super) default_download_rpm_limit: Option<i64>,
}

impl PlanRow {
    pub(super) fn into_stored(self) -> Result<StoredPlan, StorageError> {
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
pub(super) struct PermissionRow {
    pub(super) id: String,
    pub(super) key: String,
    pub(super) name: String,
    pub(super) description: String,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
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
pub(super) struct RoleRow {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) description: String,
    pub(super) permission_keys_json: String,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
}

impl RoleRow {
    pub(super) fn into_stored(self) -> Result<StoredRole, StorageError> {
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
pub(super) struct TenantRoleBindingRow {
    pub(super) id: String,
    pub(super) tenant_id: String,
    pub(super) role_id: String,
    pub(super) created_at_unix: i64,
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
pub(super) struct SiteDomainRow {
    pub(super) hostname: String,
    pub(super) tenant_id: String,
    pub(super) site: String,
    pub(super) created_at_unix: i64,
    pub(super) updated_at_unix: i64,
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
pub(super) struct BudgetAlertNotificationRow {
    pub(super) id: String,
    pub(super) scope_type: String,
    pub(super) scope_id: String,
    pub(super) period_month: String,
    pub(super) threshold_pct: i64,
    pub(super) notified_at_unix: i64,
}

impl BudgetAlertNotificationRow {
    pub(super) fn into_stored(self) -> Result<StoredBudgetAlertNotification, StorageError> {
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

pub(super) const SELECT_PERMISSION_COLUMNS: &str =
    "SELECT id, key, name, description, created_at_unix, \
     updated_at_unix FROM permissions";

pub(super) const SELECT_ROLE_COLUMNS: &str =
    "SELECT id, name, slug, description, permission_keys_json, \
     created_at_unix, updated_at_unix FROM roles";

pub(super) const SELECT_TENANT_ROLE_BINDING_COLUMNS: &str =
    "SELECT id, tenant_id, role_id, created_at_unix \
     FROM tenant_role_bindings";

pub(super) const SELECT_SITE_DOMAIN_COLUMNS: &str =
    "SELECT hostname, tenant_id, site, created_at_unix, \
     updated_at_unix FROM site_domains";

pub(super) const SELECT_BUDGET_ALERT_NOTIFICATION_COLUMNS: &str =
    "SELECT id, scope_type, scope_id, \
     period_month, threshold_pct, notified_at_unix FROM budget_alert_notifications";

pub(super) const SELECT_ADMIN_USER_COLUMNS: &str =
    "SELECT id, email, password_hash, display_name, \
     superadmin, created_at_unix, updated_at_unix, last_login_at_unix, disabled_at_unix \
     FROM admin_users";

pub(super) const SELECT_ADMIN_USER_MEMBERSHIP_COLUMNS: &str =
    "SELECT id, user_id, tenant_id, role, \
     created_at_unix FROM admin_user_tenant_memberships";

pub(super) const SELECT_ADMIN_USER_REFRESH_TOKEN_COLUMNS: &str = "SELECT id, user_id, token_hash, \
     tenant_id, role, created_at_unix, expires_at_unix, revoked_at_unix \
     FROM admin_user_refresh_tokens";

pub(super) const SELECT_SSO_PROVIDER_CONFIG_COLUMNS: &str =
    "SELECT tenant_id, provider_kind, default_role, \
     group_role_mapping_json, oidc_issuer, oidc_client_id, oidc_client_secret_ref, \
     oidc_redirect_uri, oidc_group_claim, saml_idp_entity_id, saml_idp_sso_url, \
     saml_idp_certificate, saml_sp_entity_id, saml_acs_url, saml_email_attribute, \
     saml_name_attribute, saml_groups_attribute, created_at_unix, updated_at_unix \
     FROM sso_provider_configs";

pub(super) const SELECT_SSO_PENDING_FLOW_COLUMNS: &str = "SELECT state, tenant_id, provider_kind, \
     code_verifier, request_id, created_at_unix, expires_at_unix FROM sso_pending_flows";

pub(super) const SELECT_QUOTA_POLICY_COLUMNS: &str =
    "SELECT id, scope_type, scope_id, model_allowlist_json, \
     rpm_limit, tpm_limit, monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
     alert_threshold_pcts_json, asset_storage_quota_bytes, monthly_egress_bytes_budget, \
     download_rpm_limit FROM quota_policies";

pub(super) const SELECT_PLAN_COLUMNS: &str = "SELECT id, name, slug, mcp_enabled, \
     self_hosted_workers_enabled, admin_console_seats, default_model_allowlist_json, \
     default_rpm_limit, default_tpm_limit, default_monthly_budget_usd, created_at_unix, \
     updated_at_unix, asset_hosting_enabled, default_asset_storage_quota_bytes, \
     extension_tools_enabled, default_monthly_egress_bytes_budget, default_download_rpm_limit \
     FROM plans";

pub(super) const SELECT_TENANT_COLUMNS: &str =
    "SELECT id, name, slug, status, plan_id, created_at_unix, updated_at_unix FROM tenants";

pub(super) const SELECT_PROJECT_COLUMNS: &str =
    "SELECT id, tenant_id, name, slug, status, created_at_unix, updated_at_unix FROM projects";

pub(super) const SELECT_WORKSPACE_COLUMNS: &str = "SELECT id, project_id, tenant_id, name, slug, \
     environment, status, created_at_unix, updated_at_unix FROM workspaces";

pub(super) const SELECT_API_KEY_COLUMNS: &str =
    "SELECT id, workspace_id, tenant_id, project_id, name, \
     key_prefix, key_hash, last4, enabled, scopes_json, allowed_models_json, \
     allowed_providers_json, monthly_token_budget, request_limit_per_minute, created_at_unix, \
     updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix FROM api_keys";

// --- Row DTOs: observability append/analytics families (issue #447) ---
//
// Agent runs/events and request/audit logs store the FULL record as a JSON
// TEXT document that the read paths deserialize (like the Postgres backend's
// `*_json::text` selects), so a single reusable [`DocumentRow`] carries every
// list/get read when the JSON column is aliased to `document_json`. The paged
// reads additionally project a window `count(*) OVER()` total, and the summary
// seed query projects a bare `run_id`.

/// One page row: the serialized record plus the window total the paginated
/// reads carry alongside every row (`count(*) OVER() AS total`).
#[derive(Deserialize)]
pub(super) struct PagedDocumentRow {
    pub(super) document_json: String,
    pub(super) total: i64,
}

/// A single `run_id` projected by the agent-run summary seed query.
#[derive(Deserialize)]
pub(super) struct SeedIdRow {
    pub(super) run_id: String,
}

/// The persisted monotonic replay floor revision (issue #206).
#[derive(Deserialize)]
pub(super) struct ReplayFloorRow {
    pub(super) last_accepted_revision: i64,
}

// --- Row DTOs: billing / worker families (issue #449) ---
//
// Most #449 reads deserialize a full `*_json` record document (via
// [`D1ControlPlaneStore::fetch_control_documents`]), but two carry additional
// projection columns the domain type needs: the billing report-outbox
// attempt/schedule state (kept as columns so reschedule/dead-letter/replay are
// single-statement UPDATEs like the Postgres backend) and the SQL-computed
// self-hosted worker activity aggregates.

/// A billing report-outbox row: the serialized [`BillingEvent`] plus the
/// mutable attempt/schedule/dead-letter columns.
#[derive(Deserialize)]
pub(super) struct BillingOutboxRow {
    pub(super) id: String,
    pub(super) event_json: String,
    pub(super) attempts: i64,
    pub(super) next_attempt_unix: i64,
    pub(super) dead_lettered_at_unix: Option<i64>,
}

impl BillingOutboxRow {
    pub(super) fn into_stored(self) -> Result<StoredBillingReportOutboxEntry, StorageError> {
        Ok(StoredBillingReportOutboxEntry {
            id: self.id,
            event: deserialize_storage_document(&self.event_json)?,
            attempts: self.attempts,
            next_attempt_unix: self.next_attempt_unix,
            dead_lettered_at_unix: self.dead_lettered_at_unix,
        })
    }
}

/// Per-worker activity aggregates computed in one control-database query
/// (issue #231 parity): counts + max timestamps across the telemetry,
/// artifact, and checkpoint tables for a single worker.
#[derive(Deserialize)]
pub(super) struct SelfHostedWorkerActivityStatsRow {
    pub(super) telemetry_event_count: i64,
    pub(super) latest_event_at_unix: Option<i64>,
    pub(super) artifact_count: i64,
    pub(super) latest_artifact_at_unix: Option<i64>,
    pub(super) checkpoint_count: i64,
    pub(super) latest_checkpoint_at_unix: Option<i64>,
}

impl From<SelfHostedWorkerActivityStatsRow> for StoredSelfHostedWorkerActivityStats {
    fn from(row: SelfHostedWorkerActivityStatsRow) -> Self {
        let count = |value: i64| usize::try_from(value).unwrap_or_default();
        let at_unix = |value: Option<i64>| value.and_then(|value| u64::try_from(value).ok());
        Self {
            telemetry_event_count: count(row.telemetry_event_count),
            artifact_count: count(row.artifact_count),
            checkpoint_count: count(row.checkpoint_count),
            latest_event_at_unix: at_unix(row.latest_event_at_unix),
            latest_artifact_at_unix: at_unix(row.latest_artifact_at_unix),
            latest_checkpoint_at_unix: at_unix(row.latest_checkpoint_at_unix),
        }
    }
}

/// The `SELECT` column lists for the billing report-outbox reads: the
/// serialized event plus the mutable attempt/schedule/dead-letter state.
pub(super) const SELECT_BILLING_OUTBOX_COLUMNS: &str =
    "SELECT id, event_json, attempts, next_attempt_unix, \
     dead_lettered_at_unix FROM billing_report_outbox";
