// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: RBAC, site domains, budget-alert idempotency ledger (issue #445).

//! D1 backend: RBAC, site domains, budget-alert idempotency ledger (issue #445).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    pub(super) async fn upsert_site_domain_async(
        &self,
        domain: StoredSiteDomain,
    ) -> Result<(), StorageError> {
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

    pub(super) async fn claim_site_domain_async(
        &self,
        domain: StoredSiteDomain,
    ) -> Result<StoredSiteDomain, StorageError> {
        let hostname = domain.hostname.clone();
        let result = self
            .execute_control(
                "INSERT INTO site_domains \
                 (hostname, tenant_id, site, created_at_unix, updated_at_unix) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (hostname) DO UPDATE SET \
                 site = excluded.site, updated_at_unix = excluded.updated_at_unix \
                 WHERE site_domains.tenant_id = excluded.tenant_id",
                vec![
                    domain.hostname,
                    domain.tenant_id,
                    domain.site,
                    domain.created_at_unix.to_string(),
                    domain.updated_at_unix.to_string(),
                ],
            )
            .await?;
        if result.changes() == 0 {
            return Err(StorageError::Conflict(
                SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE.to_string(),
            ));
        }
        self.get_site_domain_async(&hostname).await?.ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: site domain {hostname} claim succeeded but row could not be \
                 reloaded"
            ))
        })
    }

    pub(super) async fn claim_verified_site_domain_async(
        &self,
        domain: StoredSiteDomain,
        now_unix: i64,
    ) -> Result<StoredSiteDomain, StorageError> {
        let hostname = domain.hostname.clone();
        let result = self
            .execute_control(
                "INSERT INTO site_domains \
                 (hostname, tenant_id, site, created_at_unix, updated_at_unix) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (hostname) DO UPDATE SET \
                 tenant_id = excluded.tenant_id, \
                 site = excluded.site, \
                 created_at_unix = CASE \
                     WHEN site_domains.tenant_id = excluded.tenant_id \
                     THEN site_domains.created_at_unix \
                     ELSE excluded.created_at_unix \
                 END, \
                 updated_at_unix = excluded.updated_at_unix \
                 WHERE site_domains.tenant_id = excluded.tenant_id \
                    OR NOT EXISTS ( \
                        SELECT 1 FROM site_domain_verifications holder \
                        WHERE holder.tenant_id = site_domains.tenant_id \
                          AND holder.hostname = site_domains.hostname \
                          AND holder.state = 'verified' \
                          AND (holder.verification_expires_at_unix IS NULL \
                               OR holder.verification_expires_at_unix > ?) \
                    )",
                vec![
                    domain.hostname,
                    domain.tenant_id,
                    domain.site,
                    domain.created_at_unix.to_string(),
                    domain.updated_at_unix.to_string(),
                    now_unix.to_string(),
                ],
            )
            .await?;
        if result.changes() == 0 {
            return Err(StorageError::Conflict(
                SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE.to_string(),
            ));
        }
        self.get_site_domain_async(&hostname).await?.ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: verified site domain {hostname} claim succeeded but row could \
                 not be reloaded"
            ))
        })
    }

    pub(super) async fn get_site_domain_async(
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

    pub(super) async fn list_site_domains_async(
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

    pub(super) async fn delete_site_domain_async(
        &self,
        hostname: &str,
    ) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM site_domains WHERE hostname = ?",
                vec![hostname.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    // --- Site-domain DNS ownership proofs (#488, control database) ---
    //
    // Same control-DB routing as `site_domains` (the binding and its proof are
    // read together on the serve path). Nullable columns ride the crate's
    // `NULLIF(?, '')` idiom because the D1 HTTP binding is all-text.

    pub(super) async fn upsert_site_domain_verification_async(
        &self,
        verification: StoredSiteDomainVerification,
    ) -> Result<(), StorageError> {
        self.execute_control(
            "INSERT INTO site_domain_verifications \
             (tenant_id, hostname, site, state, challenge_token, issued_at_unix, \
              token_expires_at_unix, verified_at_unix, verification_expires_at_unix, \
              last_checked_at_unix, last_failure_reason, attempt_count, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), \
              NULLIF(?, ''), ?, ?) \
             ON CONFLICT (tenant_id, hostname) DO UPDATE SET \
             site = excluded.site, state = excluded.state, \
             challenge_token = excluded.challenge_token, \
             issued_at_unix = excluded.issued_at_unix, \
             token_expires_at_unix = excluded.token_expires_at_unix, \
             verified_at_unix = excluded.verified_at_unix, \
             verification_expires_at_unix = excluded.verification_expires_at_unix, \
             last_checked_at_unix = excluded.last_checked_at_unix, \
             last_failure_reason = excluded.last_failure_reason, \
             attempt_count = excluded.attempt_count, \
             updated_at_unix = excluded.updated_at_unix",
            vec![
                verification.tenant_id,
                verification.hostname,
                verification.site,
                verification.state.as_str().to_string(),
                verification.challenge_token,
                verification.issued_at_unix.to_string(),
                verification.token_expires_at_unix.to_string(),
                optional_number_param(verification.verified_at_unix),
                optional_number_param(verification.verification_expires_at_unix),
                optional_number_param(verification.last_checked_at_unix),
                verification.last_failure_reason.unwrap_or_default(),
                verification.attempt_count.to_string(),
                verification.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn get_site_domain_verification_async(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomainVerification>, StorageError> {
        let row: Option<SiteDomainVerificationRow> = self
            .fetch_control_optional(
                &format!(
                    "{SELECT_SITE_DOMAIN_VERIFICATION_COLUMNS} \
                     WHERE tenant_id = ? AND hostname = ?"
                ),
                vec![tenant_id.to_string(), hostname.to_string()],
            )
            .await?;
        row.map(SiteDomainVerificationRow::into_stored).transpose()
    }

    pub(super) async fn list_site_domain_verifications_async(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomainVerification>, StorageError> {
        let rows: Vec<SiteDomainVerificationRow> = match tenant_id {
            Some(tenant_id) => {
                self.fetch_control_rows(
                    &format!(
                        "{SELECT_SITE_DOMAIN_VERIFICATION_COLUMNS} \
                         WHERE tenant_id = ? ORDER BY hostname ASC"
                    ),
                    vec![tenant_id.to_string()],
                )
                .await?
            }
            None => {
                self.fetch_control_rows(
                    &format!(
                        "{SELECT_SITE_DOMAIN_VERIFICATION_COLUMNS} \
                         ORDER BY tenant_id ASC, hostname ASC"
                    ),
                    Vec::new(),
                )
                .await?
            }
        };
        rows.into_iter()
            .map(SiteDomainVerificationRow::into_stored)
            .collect()
    }

    pub(super) async fn delete_site_domain_verification_async(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<bool, StorageError> {
        let result = self
            .execute_control(
                "DELETE FROM site_domain_verifications WHERE tenant_id = ? AND hostname = ?",
                vec![tenant_id.to_string(), hostname.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    pub(super) async fn record_budget_alert_notification_async(
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

    pub(super) async fn budget_alert_already_notified_async(
        &self,
        id: &str,
    ) -> Result<bool, StorageError> {
        let row: Option<BudgetAlertNotificationRow> = self
            .fetch_control_optional(
                &format!("{SELECT_BUDGET_ALERT_NOTIFICATION_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.is_some())
    }

    pub(super) async fn list_budget_alert_notifications_async(
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

    pub(super) async fn upsert_permission_async(
        &self,
        permission: StoredPermission,
    ) -> Result<(), StorageError> {
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

    pub(super) async fn get_permission_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredPermission>, StorageError> {
        let row: Option<PermissionRow> = self
            .fetch_control_optional(
                &format!("{SELECT_PERMISSION_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.map(StoredPermission::from))
    }

    pub(super) async fn list_permissions_async(
        &self,
    ) -> Result<Vec<StoredPermission>, StorageError> {
        let rows: Vec<PermissionRow> = self
            .fetch_control_rows(
                &format!("{SELECT_PERMISSION_COLUMNS} ORDER BY key ASC"),
                Vec::new(),
            )
            .await?;
        Ok(rows.into_iter().map(StoredPermission::from).collect())
    }

    pub(super) async fn delete_permission_async(&self, id: &str) -> Result<bool, StorageError> {
        let result = self
            .execute_control("DELETE FROM permissions WHERE id = ?", vec![id.to_string()])
            .await?;
        Ok(result.changes() > 0)
    }

    pub(super) async fn upsert_role_async(&self, role: StoredRole) -> Result<(), StorageError> {
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

    pub(super) async fn get_role_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredRole>, StorageError> {
        let row: Option<RoleRow> = self
            .fetch_control_optional(
                &format!("{SELECT_ROLE_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        row.map(RoleRow::into_stored).transpose()
    }

    pub(super) async fn list_roles_async(&self) -> Result<Vec<StoredRole>, StorageError> {
        let rows: Vec<RoleRow> = self
            .fetch_control_rows(
                &format!("{SELECT_ROLE_COLUMNS} ORDER BY slug ASC"),
                Vec::new(),
            )
            .await?;
        rows.into_iter().map(RoleRow::into_stored).collect()
    }

    pub(super) async fn delete_role_async(&self, id: &str) -> Result<bool, StorageError> {
        let result = self
            .execute_control("DELETE FROM roles WHERE id = ?", vec![id.to_string()])
            .await?;
        Ok(result.changes() > 0)
    }

    pub(super) async fn bind_tenant_role_async(
        &self,
        binding: StoredTenantRoleBinding,
    ) -> Result<(), StorageError> {
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

    pub(super) async fn list_tenant_role_bindings_async(
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

    pub(super) async fn unbind_tenant_role_async(
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
}
