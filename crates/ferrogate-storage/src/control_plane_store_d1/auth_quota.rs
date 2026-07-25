// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: admin users, SSO, refresh tokens, quota policies, plans (issue #440).

//! D1 backend: admin users, SSO, refresh tokens, quota policies, plans (issue #440).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    pub(super) async fn upsert_admin_user_async(
        &self,
        user: StoredAdminUser,
    ) -> Result<(), StorageError> {
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

    pub(super) async fn get_admin_user_by_id_async(
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

    pub(super) async fn get_admin_user_by_email_async(
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

    pub(super) async fn upsert_admin_user_membership_async(
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

    pub(super) async fn list_admin_user_memberships_by_user_async(
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

    pub(super) async fn list_admin_user_memberships_by_tenant_async(
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

    pub(super) async fn delete_admin_user_membership_async(
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

    pub(super) async fn upsert_sso_provider_config_async(
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

    pub(super) async fn get_sso_provider_config_async(
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

    pub(super) async fn delete_sso_provider_config_async(
        &self,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM sso_provider_configs WHERE tenant_id = ?",
                vec![tenant_id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    pub(super) async fn insert_sso_pending_flow_async(
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

    pub(super) async fn take_sso_pending_flow_async(
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

    pub(super) async fn upsert_admin_user_refresh_token_async(
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

    pub(super) async fn get_admin_user_refresh_token_by_hash_async(
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

    pub(super) async fn revoke_all_admin_user_refresh_tokens_async(
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

    pub(super) async fn revoke_admin_user_refresh_tokens_for_tenant_async(
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

    pub(super) async fn upsert_quota_policy_async(
        &self,
        policy: StoredQuotaPolicy,
    ) -> Result<(), StorageError> {
        let model_allowlist_json = serialize_storage_document(&policy.model_allowlist)?;
        let alert_threshold_pcts_json = serialize_storage_document(&policy.alert_threshold_pcts)?;
        self.execute_control(
            "INSERT INTO quota_policies \
             (id, scope_type, scope_id, model_allowlist_json, rpm_limit, tpm_limit, \
              monthly_budget_usd, enabled, created_at_unix, updated_at_unix, \
              alert_threshold_pcts_json, asset_storage_quota_bytes, monthly_egress_bytes_budget, \
              download_rpm_limit, asset_max_object_bytes) \
             VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, \
              NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (scope_type, scope_id) DO UPDATE SET \
             model_allowlist_json = excluded.model_allowlist_json, \
             rpm_limit = excluded.rpm_limit, tpm_limit = excluded.tpm_limit, \
             monthly_budget_usd = excluded.monthly_budget_usd, enabled = excluded.enabled, \
             updated_at_unix = excluded.updated_at_unix, \
             alert_threshold_pcts_json = excluded.alert_threshold_pcts_json, \
             asset_storage_quota_bytes = excluded.asset_storage_quota_bytes, \
             monthly_egress_bytes_budget = excluded.monthly_egress_bytes_budget, \
             download_rpm_limit = excluded.download_rpm_limit, \
             asset_max_object_bytes = excluded.asset_max_object_bytes",
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
                optional_number_param(policy.asset_max_object_bytes),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn get_quota_policy_async(
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

    pub(super) async fn list_quota_policies_async(
        &self,
    ) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        let rows: Vec<QuotaPolicyRow> = self
            .fetch_control_rows(
                &format!("{SELECT_QUOTA_POLICY_COLUMNS} ORDER BY id ASC"),
                Vec::new(),
            )
            .await?;
        rows.into_iter().map(QuotaPolicyRow::into_stored).collect()
    }

    pub(super) async fn delete_quota_policy_async(
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

    pub(super) async fn upsert_plan_async(&self, plan: StoredPlan) -> Result<(), StorageError> {
        let default_model_allowlist_json =
            serialize_storage_document(&plan.default_model_allowlist)?;
        self.execute_control(
            "INSERT INTO plans \
             (id, name, slug, mcp_enabled, self_hosted_workers_enabled, admin_console_seats, \
              default_model_allowlist_json, default_rpm_limit, default_tpm_limit, \
              default_monthly_budget_usd, created_at_unix, updated_at_unix, asset_hosting_enabled, \
              default_asset_storage_quota_bytes, extension_tools_enabled, \
              default_monthly_egress_bytes_budget, default_download_rpm_limit, \
              default_asset_max_object_bytes) \
             VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, ''), \
              NULLIF(?, ''), ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, ''), \
              NULLIF(?, '')) \
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
             default_download_rpm_limit = excluded.default_download_rpm_limit, \
             default_asset_max_object_bytes = excluded.default_asset_max_object_bytes",
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
                optional_number_param(plan.default_asset_max_object_bytes),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn get_plan_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredPlan>, StorageError> {
        let row: Option<PlanRow> = self
            .fetch_control_optional(
                &format!("{SELECT_PLAN_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        row.map(PlanRow::into_stored).transpose()
    }

    pub(super) async fn list_plans_async(&self) -> Result<Vec<StoredPlan>, StorageError> {
        let rows: Vec<PlanRow> = self
            .fetch_control_rows(
                &format!("{SELECT_PLAN_COLUMNS} ORDER BY id ASC"),
                Vec::new(),
            )
            .await?;
        rows.into_iter().map(PlanRow::into_stored).collect()
    }
}
