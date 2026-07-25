// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: `impl ControlPlaneStore for MemoryControlPlaneStore` (#419/
// #425): the in-memory backend. Durable-CRUD methods lock the
// `RuntimeControlPlaneState` (the pre-#419 Memory match-arm bodies verbatim,
// same lock-poison fallbacks); the #425 append/analytics methods use the
// store-local bounded repositories relocated from `RuntimeStorageRepositories`.

use super::control_plane_store::ControlPlaneStore;
use super::*;

#[async_trait::async_trait]
impl ControlPlaneStore for MemoryControlPlaneStore {
    async fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_api_key_record(api_key);
        }
        Ok(())
    }

    async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_api_key_record(id))
            .unwrap_or(None))
    }

    async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_api_key_records())
            .unwrap_or_default())
    }

    async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.find_api_key_records_by_prefix(key_prefix))
            .unwrap_or_default())
    }

    async fn upsert_admin_user(&self, user: StoredAdminUser) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_admin_user(user);
        }
        Ok(())
    }

    async fn get_admin_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_admin_user_by_id(id))
            .unwrap_or(None))
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_admin_user_by_email(email))
            .unwrap_or(None))
    }

    async fn upsert_admin_user_membership(
        &self,
        membership: StoredAdminUserMembership,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_admin_user_membership(membership);
        }
        Ok(())
    }

    async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_admin_user_memberships_by_user(user_id))
            .unwrap_or_default())
    }

    async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_admin_user_memberships_by_tenant(tenant_id))
            .unwrap_or_default())
    }

    async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_admin_user_membership(user_id, tenant_id))
            .unwrap_or(false))
    }

    async fn upsert_sso_provider_config(
        &self,
        config: StoredSsoProviderConfig,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_sso_provider_config(config);
        }
        Ok(())
    }

    async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_sso_provider_config(tenant_id))
            .unwrap_or(None))
    }

    async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_sso_provider_config(tenant_id))
            .unwrap_or(false))
    }

    async fn insert_sso_pending_flow(
        &self,
        flow: StoredSsoPendingFlow,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.insert_sso_pending_flow(flow);
        }
        Ok(())
    }

    async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.take_sso_pending_flow(state, now_unix))
            .unwrap_or(None))
    }

    async fn upsert_admin_user_refresh_token(
        &self,
        token: StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_admin_user_refresh_token(token);
        }
        Ok(())
    }

    async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_admin_user_refresh_token_by_hash(token_hash))
            .unwrap_or(None))
    }

    async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| {
                control_plane.revoke_all_admin_user_refresh_tokens(user_id, revoked_at_unix)
            })
            .unwrap_or(0))
    }

    async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| {
                control_plane.revoke_admin_user_refresh_tokens_for_tenant(
                    user_id,
                    tenant_id,
                    revoked_at_unix,
                )
            })
            .unwrap_or(0))
    }

    async fn upsert_tenant_account(
        &self,
        account: StoredTenantAccount,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_tenant_account(account);
        }
        Ok(())
    }

    async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_tenant_account(id))
            .unwrap_or(None))
    }

    async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_tenant_accounts())
            .unwrap_or_default())
    }

    async fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_project(project);
        }
        Ok(())
    }

    async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_project(id))
            .unwrap_or(None))
    }

    async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_projects())
            .unwrap_or_default())
    }

    async fn delete_project(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_project(id))
            .unwrap_or(false))
    }

    async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.delete_project_if_unreferenced(id))
            .map_err(|_| {
                StorageError::Runtime(
                    "in-memory control-plane mutex poisoned during project delete".to_string(),
                )
            })
    }

    async fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_workspace(workspace);
        }
        Ok(())
    }

    async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_workspace(id))
            .unwrap_or(None))
    }

    async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_workspaces())
            .unwrap_or_default())
    }

    async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_workspace(id))
            .unwrap_or(false))
    }

    async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.delete_workspace_if_unreferenced(id))
            .map_err(|_| {
                StorageError::Runtime(
                    "in-memory control-plane mutex poisoned during workspace delete".to_string(),
                )
            })
    }

    async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.resolve_workspace_scope(workspace_id))
            .unwrap_or(None))
    }

    async fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_quota_policy(policy);
        }
        Ok(())
    }

    async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_quota_policy(scope_type, scope_id))
            .unwrap_or(None))
    }

    async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_quota_policies())
            .unwrap_or_default())
    }

    async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_quota_policy(scope_type, scope_id))
            .unwrap_or(false))
    }

    async fn upsert_plan(&self, plan: StoredPlan) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_plan(plan);
        }
        Ok(())
    }

    async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_plan(id))
            .unwrap_or(None))
    }

    async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_plans())
            .unwrap_or_default())
    }

    async fn upsert_asset(&self, asset: StoredAsset) -> Result<(), StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.upsert_asset(asset))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.create_asset_if_absent(asset))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn create_asset_within_quota(
        &self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.create_asset_within_quota(asset, quota_bytes))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError> {
        self.lock()
            .map(|control_plane| control_plane.get_asset(id))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        self.lock()
            .map(|control_plane| control_plane.list_assets(tenant_id, asset_type))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        self.lock()
            .map(|control_plane| control_plane.list_withheld_assets(tenant_id, asset_type))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn tenant_asset_storage_bytes_used(&self, tenant_id: &str) -> Result<u64, StorageError> {
        self.lock()
            .map(|control_plane| control_plane.tenant_asset_storage_bytes_used(tenant_id))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn delete_asset(&self, id: &str) -> Result<bool, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.delete_asset(id))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn upsert_asset_channel(&self, channel: StoredAssetChannel) -> Result<(), StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.upsert_asset_channel(channel))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        self.lock()
            .map(|control_plane| control_plane.list_asset_channels(tenant_id, asset_type, name))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn delete_asset_channel(&self, id: &str) -> Result<bool, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.delete_asset_channel(id))
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn move_asset_channel_if_resolvable(
        &self,
        channel: StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        self.lock()
            .map(|mut control_plane| control_plane.move_asset_channel_if_resolvable(channel))
            .map_err(|_| poisoned_asset_repository_lock())
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
        self.lock()
            .map(|mut control_plane| {
                control_plane
                    .set_asset_version_yank(tenant_id, asset_type, name, version, yanked, now_unix)
            })
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn delete_asset_variant_if_unreferenced(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError> {
        self.lock()
            .map(|mut control_plane| {
                control_plane
                    .delete_asset_variant_if_unreferenced(id, tenant_id, asset_type, name, version)
            })
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        self.lock()
            .map(|mut control_plane| {
                control_plane.promote_pending_asset_visibility(id, target, now_unix)
            })
            .map_err(|_| poisoned_asset_repository_lock())
    }

    async fn upsert_retention_policy(
        &self,
        policy: StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_retention_policy(policy);
        }
        Ok(())
    }

    async fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_retention_policies(tenant_id, resource_type))
            .unwrap_or_default())
    }

    async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_all_assets())
            .unwrap_or_default())
    }

    async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_all_asset_channels())
            .unwrap_or_default())
    }

    async fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| {
                control_plane.get_usage_monthly_rollup(scope_type, scope_id, period_month)
            })
            .unwrap_or(None))
    }

    async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_usage_monthly_rollups())
            .unwrap_or_default())
    }

    async fn append_billing_ledger_entry(
        &self,
        _entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        Err(billing_ledger_supabase_only_error())
    }

    async fn list_billing_ledger_entries(
        &self,
        _filter: &ferrogate_billing::LedgerListFilter,
        _offset: usize,
        _limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        Err(billing_ledger_supabase_only_error())
    }

    async fn billing_ledger_entry(
        &self,
        _id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        Err(billing_ledger_supabase_only_error())
    }

    async fn enqueue_billing_report(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.enqueue_billing_report(id, event, next_attempt_unix);
        }
        Ok(())
    }

    async fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_due_billing_reports(now_unix, limit))
            .unwrap_or_default())
    }

    async fn reschedule_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.reschedule_billing_report(id, next_attempt_unix);
        }
        Ok(())
    }

    async fn dead_letter_billing_report(
        &self,
        id: &str,
        dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.dead_letter_billing_report(id, dead_lettered_at_unix);
        }
        Ok(())
    }

    async fn list_dead_lettered_billing_reports(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_dead_lettered_billing_reports(limit))
            .unwrap_or_default())
    }

    async fn replay_dead_lettered_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        self.lock()
            .map(|mut control_plane| {
                control_plane.replay_dead_lettered_billing_report(id, next_attempt_unix)
            })
            .map_err(|_| {
                StorageError::Runtime(
                    "in-memory control-plane mutex poisoned during dead-letter replay".to_string(),
                )
            })
    }

    async fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_billing_report_outbox_entry(id))
            .unwrap_or(None))
    }

    async fn delete_billing_report(&self, id: &str) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.delete_billing_report(id);
        }
        Ok(())
    }

    fn upsert_config_document(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            match kind {
                "api_key" => control_plane.upsert_api_key(id, document_json),
                "tenant" => control_plane.upsert_tenant(id, document_json),
                "policy" => control_plane.upsert_policy(id, document_json),
                "gateway_config" => control_plane.upsert_gateway_config(id, document_json),
                "agent_workflow" => control_plane.upsert_agent_workflow(id, document_json),
                "skill_package" => control_plane.upsert_skill_package(id, document_json),
                "prompt_template" => control_plane.upsert_prompt_template(id, document_json),
                "plugin_registration" => {
                    control_plane.upsert_plugin_registration(id, document_json)
                }
                "mcp_server" => control_plane.upsert_mcp_server(id, document_json),
                "agent_upstream" => control_plane.upsert_agent_upstream(id, document_json),
                "tool_approval" => control_plane.upsert_tool_approval(id, document_json),
                other => {
                    return Err(StorageError::Runtime(format!(
                        "unsupported config document kind {other}"
                    )))
                }
            }
        }
        Ok(())
    }

    fn delete_config_document(&self, kind: &'static str, id: &str) -> Result<bool, StorageError> {
        let Ok(mut control_plane) = self.lock() else {
            return Ok(false);
        };
        Ok(match kind {
            "api_key" => control_plane.delete_api_key(id),
            "policy" => control_plane.delete_policy(id),
            "gateway_config" => control_plane.delete_gateway_config(id),
            "agent_workflow" => control_plane.delete_agent_workflow(id),
            "skill_package" => control_plane.delete_skill_package(id),
            "plugin_registration" => control_plane.delete_plugin_registration(id),
            "mcp_server" => control_plane.delete_mcp_server(id),
            "agent_upstream" => control_plane.delete_agent_upstream(id),
            other => {
                return Err(StorageError::Runtime(format!(
                    "unsupported config document kind {other}"
                )))
            }
        })
    }

    fn get_config_document(
        &self,
        kind: &'static str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        match kind {
            "tool_approval" => Ok(self
                .lock()
                .ok()
                .and_then(|control_plane| control_plane.tool_approval(id))),
            other => Err(StorageError::Runtime(format!(
                "unsupported config document kind {other}"
            ))),
        }
    }

    fn list_config_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        match kind {
            "tool_approval" => Ok(self
                .lock()
                .map(|control_plane| control_plane.tool_approvals())
                .unwrap_or_default()),
            other => Err(StorageError::Runtime(format!(
                "unsupported config document kind {other}"
            ))),
        }
    }

    fn list_config_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        match kind {
            "tool_approval" => Ok(self
                .lock()
                .map(|control_plane| control_plane.tool_approval_documents())
                .unwrap_or_default()),
            other => Err(StorageError::Runtime(format!(
                "unsupported config document kind {other}"
            ))),
        }
    }

    fn replace_config_documents(
        &self,
        documents: ControlPlaneDocuments,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.replace_config_documents(documents);
        }
        Ok(())
    }

    fn insert_guardrail_policy_revision(
        &self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .insert_guardrail_policy_revision(revision)
    }

    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .get_guardrail_policy_revision(policy_id, revision))
    }

    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .list_guardrail_policy_revisions(policy_id))
    }

    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .get_guardrail_policy_binding(policy_id))
    }

    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .list_guardrail_policy_bindings())
    }

    fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .activate_guardrail_policy_revision(
                policy_id,
                revision,
                updated_by,
                updated_at_unix,
                rollback_only,
            )
    }

    fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .archive_guardrail_policy_revision(policy_id, revision, updated_by, updated_at_unix)
    }

    fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("guardrail policy repository lock poisoned".into()))?
            .restore_guardrail_policy_binding(policy_id, expected_generation, binding)
    }

    fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| {
                StorageError::Runtime("snapshot replay floor repository lock poisoned".into())
            })?
            .get_snapshot_replay_floor(tenant_id, deployment_id))
    }

    fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        _updated_at_unix: i64,
    ) -> Result<u64, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| {
                StorageError::Runtime("snapshot replay floor repository lock poisoned".into())
            })?
            .advance_snapshot_replay_floor(tenant_id, deployment_id, revision))
    }

    fn control_plane_snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.snapshot())
            .unwrap_or_else(|_| ControlPlaneSnapshot {
                api_keys: Vec::new(),
                tenants: Vec::new(),
                policies: Vec::new(),
                gateway_configs: Vec::new(),
                agent_workflows: Vec::new(),
                skill_packages: Vec::new(),
                prompt_templates: Vec::new(),
                plugin_registrations: Vec::new(),
                mcp_servers: Vec::new(),
                agent_upstreams: Vec::new(),
            }))
    }

    fn config_documents(&self) -> Result<ControlPlaneDocuments, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.documents())
            .unwrap_or_default())
    }

    fn set_retention_limits(
        &self,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) {
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.set_retention_limit(request_log_retention_records);
        }
        if let Ok(mut events) = self.audit_events.lock() {
            events.set_retention_limit(audit_event_retention_records);
        }
    }

    async fn append_request_log(&self, log: StoredRequestLog) {
        if let Ok(mut logs) = self.request_logs.lock() {
            logs.append(log);
        }
    }

    async fn request_logs(&self) -> Vec<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| logs.list())
            .unwrap_or_default()
    }

    async fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredRequestLog> {
        self.request_logs
            .lock()
            .map(|logs| StoragePage {
                data: logs.list_paginated(offset, limit),
                total: logs.len(),
                offset,
                limit,
            })
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

    async fn delete_request_logs(&self, request_ids: &[String]) -> Result<u64, StorageError> {
        let drop: std::collections::HashSet<&str> =
            request_ids.iter().map(String::as_str).collect();
        let removed = self
            .request_logs
            .lock()
            .map(|mut logs| logs.retain(|log| !drop.contains(log.request_id.as_str())))
            .unwrap_or(0);
        Ok(removed as u64)
    }

    async fn request_logs_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredRequestLog> {
        let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
        self.request_logs
            .lock()
            .map(|logs| {
                logs.list()
                    .into_iter()
                    .filter(|log| {
                        log.agent_run_id
                            .as_deref()
                            .is_some_and(|run_id| wanted.contains(run_id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn append_audit_event(&self, event: StoredAuditEvent) {
        if let Ok(mut events) = self.audit_events.lock() {
            events.append(event);
        }
    }

    fn next_audit_event_id(&self) -> String {
        self.audit_events
            .lock()
            .map(|events| format!("audit-{}", events.len() + 1))
            .unwrap_or_else(|_| "audit-unknown".to_string())
    }

    async fn audit_events(&self) -> Vec<StoredAuditEvent> {
        self.audit_events
            .lock()
            .map(|events| events.list())
            .unwrap_or_default()
    }

    async fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredAuditEvent> {
        self.audit_events
            .lock()
            .map(|events| StoragePage {
                data: events.list_paginated(offset, limit),
                total: events.len(),
                offset,
                limit,
            })
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

    async fn delete_audit_events(&self, ids: &[String]) -> Result<u64, StorageError> {
        let drop: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
        let removed = self
            .audit_events
            .lock()
            .map(|mut events| events.retain(|event| !drop.contains(event.id.as_str())))
            .unwrap_or(0);
        Ok(removed as u64)
    }

    async fn audit_events_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredAuditEvent> {
        let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
        self.audit_events
            .lock()
            .map(|events| {
                events
                    .list()
                    .into_iter()
                    .filter(|event| {
                        event
                            .agent_run_id
                            .as_deref()
                            .is_some_and(|run_id| wanted.contains(run_id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn append_billing_event(&self, event: BillingEvent) -> Result<bool, StorageError> {
        let billing_event_id = ferrogate_billing::ledger::ledger_entry_id(&event);
        let mut control_plane = self
            .state
            .lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?;
        if let Some(existing) = control_plane.billing_event_ids.get(&billing_event_id) {
            if same_billing_event_settlement(&existing, &event) {
                return Ok(false);
            }
            return Err(StorageError::Conflict(format!(
                "billing event id {billing_event_id} was replayed with different provider-attempt settlement data"
            )));
        }
        control_plane
            .billing_event_ids
            .insert(billing_event_id, event.clone());
        let period_month = period_month_from_unix(saturating_i64(
            event.occurred_at_unix.unwrap_or_else(now_unix_seconds),
        ));
        let usage_delta = UsageMonthlyDelta {
            prompt_tokens: event.usage.prompt_tokens,
            completion_tokens: event.usage.completion_tokens,
            total_tokens: event.usage.total_tokens,
            cost_usd: event.cost_usd.unwrap_or(0.0),
            is_error: event.status_code >= 400,
        };
        control_plane.increment_usage_monthly_rollups(&event.tenant, &period_month, &usage_delta);
        control_plane.increment_usage_metadata_rollups(
            &event.tenant,
            &event.metadata,
            &period_month,
            &usage_delta,
        );
        drop(control_plane);
        self.upsert_in_memory_usage_aggregate(&event);
        Ok(true)
    }

    async fn append_billing_event_with_outbox_enqueue(
        &self,
        event: BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError> {
        // No real round-trip to save on the in-memory backend: append then
        // enqueue, preserving the prior non-fatal enqueue-failure semantics
        // via `BillingEventAppendOutcome::enqueue_error` (issue #150).
        let recorded = ControlPlaneStore::append_billing_event(self, event.clone()).await?;
        let enqueue_error = if recorded {
            ControlPlaneStore::enqueue_billing_report(
                self,
                outbox_id,
                &event,
                outbox_next_attempt_unix,
            )
            .await
            .err()
        } else {
            None
        };
        Ok(BillingEventAppendOutcome {
            recorded,
            enqueue_error,
        })
    }

    async fn billing_events(&self) -> Vec<BillingEvent> {
        Vec::new()
    }

    async fn billing_events_page(&self, offset: usize, limit: usize) -> StoragePage<BillingEvent> {
        StoragePage::empty(offset, limit)
    }

    fn upsert_usage_aggregate_local(
        &self,
        id: String,
        build: &mut dyn FnMut(Option<StoredUsageAggregate>) -> StoredUsageAggregate,
    ) -> Result<StoredUsageAggregate, StorageError> {
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
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
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
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
        Ok(())
    }

    async fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        self.usage_aggregates
            .lock()
            .map(|aggregates| aggregates.list())
            .unwrap_or_default()
    }

    async fn sum_api_key_committed_tokens(&self, api_key_id: &str) -> u64 {
        self.usage_aggregates
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

    async fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError> {
        if let Ok(mut runs) = self.agent_runs.lock() {
            runs.insert(run.id.clone(), run);
        }
        Ok(())
    }

    async fn agent_run(&self, id: &str) -> Option<StoredAgentRun> {
        self.agent_runs.lock().ok().and_then(|runs| runs.get(id))
    }

    async fn agent_runs(&self) -> Vec<StoredAgentRun> {
        self.agent_runs
            .lock()
            .map(|runs| runs.list())
            .unwrap_or_default()
    }

    async fn agent_runs_by_ids(&self, run_ids: &[String]) -> Vec<StoredAgentRun> {
        let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
        self.agent_runs
            .lock()
            .map(|runs| {
                runs.list()
                    .into_iter()
                    .filter(|run| wanted.contains(run.id.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn append_agent_run_event(&self, event: StoredAgentRunEvent) -> Result<(), StorageError> {
        if let Ok(mut events) = self.agent_run_events.lock() {
            events.append(event);
        }
        Ok(())
    }

    async fn agent_run_events(&self) -> Vec<StoredAgentRunEvent> {
        self.agent_run_events
            .lock()
            .map(|events| events.list())
            .unwrap_or_default()
    }

    async fn agent_run_events_for_runs(&self, run_ids: &[String]) -> Vec<StoredAgentRunEvent> {
        let wanted: HashSet<&str> = run_ids.iter().map(String::as_str).collect();
        self.agent_run_events
            .lock()
            .map(|events| {
                events
                    .list()
                    .into_iter()
                    .filter(|event| wanted.contains(event.run_id.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn agent_run_summary_seed_ids(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Vec<String> {
        let mut last_seen: HashMap<String, u64> = HashMap::new();
        let mut observe = |run_id: &str, seen_at: Option<u64>| {
            let seen_at = seen_at.unwrap_or_default();
            let entry = last_seen.entry(run_id.to_string()).or_insert(seen_at);
            *entry = (*entry).max(seen_at);
        };
        if let Ok(runs) = self.agent_runs.lock() {
            for run in runs.list() {
                if request_id.is_none_or(|expected| run.request_id == expected) {
                    observe(&run.id, run.completed_at_unix.or(run.started_at_unix));
                }
            }
        }
        if let Ok(events) = self.agent_run_events.lock() {
            for event in events.list() {
                if request_id.is_none_or(|expected| event.request_id == expected) {
                    observe(&event.run_id, event.occurred_at_unix);
                }
            }
        }
        if let Ok(logs) = self.request_logs.lock() {
            for log in logs.list() {
                if let Some(run_id) = log.agent_run_id.as_deref() {
                    if request_id.is_none_or(|expected| log.request_id == expected) {
                        observe(run_id, log.completed_at_unix.or(log.started_at_unix));
                    }
                }
            }
        }
        if let Ok(events) = self.audit_events.lock() {
            for event in events.list() {
                if let Some(run_id) = event.agent_run_id.as_deref() {
                    if request_id.is_none_or(|expected| event.request_id == expected) {
                        observe(run_id, event.occurred_at_unix);
                    }
                }
            }
        }
        let mut seeds: Vec<(String, u64)> = last_seen.into_iter().collect();
        seeds.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        seeds.truncate(limit);
        seeds.into_iter().map(|(run_id, _)| run_id).collect()
    }

    async fn upsert_managed_worker_template(
        &self,
        template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        if let Ok(mut templates) = self.managed_worker_templates.lock() {
            templates.insert(template.id.clone(), template);
        }
        Ok(())
    }

    async fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate> {
        self.managed_worker_templates
            .lock()
            .map(|templates| templates.list())
            .unwrap_or_default()
    }

    async fn upsert_agent_worker_instance(
        &self,
        instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        if let Ok(mut instances) = self.agent_worker_instances.lock() {
            instances.insert(instance.id.clone(), instance);
        }
        Ok(())
    }

    async fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance> {
        self.agent_worker_instances
            .lock()
            .map(|instances| instances.list())
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_session(
        &self,
        session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        if let Ok(mut sessions) = self.managed_worker_sessions.lock() {
            sessions.insert(session.id.clone(), session);
        }
        Ok(())
    }

    async fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession> {
        self.managed_worker_sessions
            .lock()
            .map(|sessions| sessions.list())
            .unwrap_or_default()
    }

    async fn append_managed_worker_lifecycle_event(
        &self,
        event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        if let Ok(mut events) = self.managed_worker_lifecycle_events.lock() {
            events.append(event);
        }
        Ok(())
    }

    async fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent> {
        self.managed_worker_lifecycle_events
            .lock()
            .map(|events| events.list())
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_isolation_selection(
        &self,
        selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        if let Ok(mut selections) = self.managed_worker_isolation_selections.lock() {
            selections.insert(selection.session_id.clone(), selection);
        }
        Ok(())
    }

    async fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection> {
        self.managed_worker_isolation_selections
            .lock()
            .map(|selections| selections.list())
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_isolation_policy(
        &self,
        policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        if let Ok(mut policies) = self.managed_worker_isolation_policies.lock() {
            policies.insert(policy.session_id.clone(), policy);
        }
        Ok(())
    }

    async fn managed_worker_isolation_policies(&self) -> Vec<StoredManagedWorkerIsolationPolicy> {
        self.managed_worker_isolation_policies
            .lock()
            .map(|policies| policies.list())
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        if let Ok(mut records) = self.managed_worker_isolation_evidence.lock() {
            records.insert(evidence.id.clone(), evidence);
        }
        Ok(())
    }

    async fn managed_worker_isolation_evidence(&self) -> Vec<StoredManagedWorkerIsolationEvidence> {
        self.managed_worker_isolation_evidence
            .lock()
            .map(|records| records.list())
            .unwrap_or_default()
    }

    async fn upsert_self_hosted_worker_registration(
        &self,
        registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        if let Ok(mut registrations) = self.self_hosted_worker_registrations.lock() {
            registrations.insert(registration.id.clone(), registration);
        }
        Ok(())
    }

    async fn self_hosted_worker_registrations(&self) -> Vec<StoredSelfHostedWorkerRegistration> {
        self.self_hosted_worker_registrations
            .lock()
            .map(|registrations| registrations.list())
            .unwrap_or_default()
    }

    async fn self_hosted_worker_registration(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerRegistration> {
        self.self_hosted_worker_registrations
            .lock()
            .ok()
            .and_then(|registrations| registrations.get(worker_id))
    }

    async fn latest_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerHeartbeat> {
        self.self_hosted_worker_heartbeats
            .lock()
            .ok()
            .and_then(|heartbeats| {
                heartbeats
                    .list()
                    .into_iter()
                    .filter(|heartbeat| heartbeat.worker_id == worker_id)
                    .max_by(|left, right| {
                        left.reported_at_unix
                            .cmp(&right.reported_at_unix)
                            .then_with(|| left.id.cmp(&right.id))
                    })
            })
    }

    async fn self_hosted_worker_activity_stats(
        &self,
        worker_id: &str,
    ) -> StoredSelfHostedWorkerActivityStats {
        let mut stats = StoredSelfHostedWorkerActivityStats::default();
        if let Ok(events) = self.self_hosted_worker_telemetry_events.lock() {
            for event in events.list() {
                if event.worker_id == worker_id {
                    stats.telemetry_event_count += 1;
                    stats.latest_event_at_unix =
                        stats.latest_event_at_unix.max(event.occurred_at_unix);
                }
            }
        }
        if let Ok(artifacts) = self.self_hosted_worker_artifacts.lock() {
            for artifact in artifacts.list() {
                if artifact.worker_id == worker_id {
                    stats.artifact_count += 1;
                    stats.latest_artifact_at_unix =
                        stats.latest_artifact_at_unix.max(artifact.created_at_unix);
                }
            }
        }
        if let Ok(checkpoints) = self.self_hosted_worker_checkpoints.lock() {
            for checkpoint in checkpoints.list() {
                if checkpoint.worker_id == worker_id {
                    stats.checkpoint_count += 1;
                    stats.latest_checkpoint_at_unix = stats
                        .latest_checkpoint_at_unix
                        .max(checkpoint.created_at_unix);
                }
            }
        }
        stats
    }

    async fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        if let Ok(mut heartbeats) = self.self_hosted_worker_heartbeats.lock() {
            heartbeats.append(heartbeat);
        }
        Ok(())
    }

    async fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat> {
        self.self_hosted_worker_heartbeats
            .lock()
            .map(|heartbeats| heartbeats.list())
            .unwrap_or_default()
    }

    async fn append_self_hosted_worker_telemetry_event(
        &self,
        event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        if let Ok(mut events) = self.self_hosted_worker_telemetry_events.lock() {
            events.append(event);
        }
        Ok(())
    }

    async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        self.self_hosted_worker_telemetry_events
            .lock()
            .map(|events| events.list())
            .unwrap_or_default()
    }

    async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        let mut events = self
            .self_hosted_worker_telemetry_events
            .lock()
            .map(|events| {
                events
                    .list()
                    .into_iter()
                    .filter(|event| event.run_id.as_deref() == Some(run_id))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        events.sort_by(|left, right| {
            left.occurred_at_unix
                .cmp(&right.occurred_at_unix)
                .then_with(|| left.ingested_at_unix.cmp(&right.ingested_at_unix))
                .then_with(|| left.id.cmp(&right.id))
        });
        if limit > 0 && events.len() > limit {
            events.drain(..events.len() - limit);
        }
        events
    }

    async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        worker_id: &str,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        self.self_hosted_worker_telemetry_events
            .lock()
            .map(|events| {
                events
                    .list()
                    .into_iter()
                    .filter(|event| event.worker_id == worker_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        if let Ok(mut artifacts) = self.self_hosted_worker_artifacts.lock() {
            artifacts.insert(artifact.id.clone(), artifact);
        }
        Ok(())
    }

    async fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact> {
        self.self_hosted_worker_artifacts
            .lock()
            .map(|artifacts| artifacts.list())
            .unwrap_or_default()
    }

    async fn self_hosted_worker_artifact(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerArtifact> {
        self.self_hosted_worker_artifacts
            .lock()
            .ok()
            .and_then(|artifacts| artifacts.get(id))
    }

    async fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        if let Ok(mut checkpoints) = self.self_hosted_worker_checkpoints.lock() {
            checkpoints.insert(checkpoint.id.clone(), checkpoint);
        }
        Ok(())
    }

    async fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint> {
        self.self_hosted_worker_checkpoints
            .lock()
            .map(|checkpoints| checkpoints.list())
            .unwrap_or_default()
    }

    async fn self_hosted_worker_checkpoint(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerCheckpoint> {
        self.self_hosted_worker_checkpoints
            .lock()
            .ok()
            .and_then(|checkpoints| checkpoints.get(id))
    }

    async fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        if let Ok(mut dispatches) = self.self_hosted_run_dispatches.lock() {
            dispatches.insert(dispatch.dispatch_id.clone(), dispatch);
        }
        Ok(())
    }

    async fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch> {
        self.self_hosted_run_dispatches
            .lock()
            .map(|dispatches| dispatches.list())
            .unwrap_or_default()
    }

    // --- Per-entity module surfaces (#437): lock the control-plane state ---
    //
    // Each body is the pre-#437 Memory match-arm verbatim (same lock-poison
    // fallbacks), with `control_plane.lock()` now `self.lock()`.

    async fn upsert_site_domain(&self, domain: StoredSiteDomain) -> Result<(), StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("site domain repository lock poisoned".into()))?
            .upsert_site_domain(domain);
        Ok(())
    }

    async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("site domain repository lock poisoned".into()))?
            .get_site_domain(hostname))
    }

    async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("site domain repository lock poisoned".into()))?
            .list_site_domains(tenant_id))
    }

    async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("site domain repository lock poisoned".into()))?
            .delete_site_domain(hostname))
    }

    async fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| {
                control_plane.list_usage_metadata_rollups(metadata_key, organization_id)
            })
            .unwrap_or_default())
    }

    async fn touch_observed_agent_presence(
        &self,
        touch: ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        self.lock()
            .map_err(|_| {
                StorageError::Runtime("observed agent presence repository lock poisoned".into())
            })?
            .touch_observed_agent_presence(&touch);
        Ok(())
    }

    async fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| {
                StorageError::Runtime("observed agent presence repository lock poisoned".into())
            })?
            .list_observed_agent_presence_since(tenant_scope, since_unix))
    }

    async fn add_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
        delta_usd: f64,
    ) -> Result<f64, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent cost burn repository lock poisoned".into()))?
            .add_agent_burn(tenant_id, agent_key, period, delta_usd))
    }

    async fn get_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
    ) -> Result<Option<f64>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent cost burn repository lock poisoned".into()))?
            .get_agent_burn(tenant_id, agent_key, period))
    }

    async fn list_agent_cost_burn(
        &self,
        tenant_scope: Option<&str>,
        period: &str,
    ) -> Result<Vec<StoredAgentCostBurn>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent cost burn repository lock poisoned".into()))?
            .list_agent_cost_burn(tenant_scope, period))
    }

    async fn record_budget_alert_notification(
        &self,
        notification: StoredBudgetAlertNotification,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.record_budget_alert_notification(notification);
        }
        Ok(())
    }

    async fn budget_alert_already_notified(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.budget_alert_already_notified(id))
            .unwrap_or(false))
    }

    async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| {
                control_plane.list_budget_alert_notifications(scope_type, scope_id, period_month)
            })
            .unwrap_or_default())
    }

    async fn open_workflow_run_budget(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .open_workflow_run_budget(
                workflow_id,
                workflow_version,
                run_id,
                tenant_id,
                caps,
                now_unix,
            )
    }

    async fn debit_workflow_run_budget(
        &self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .debit_workflow_run_budget(id, cost_credits, tokens, tool_calls, now_unix)
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
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .topup_workflow_run_budget(
                id,
                add_cost_credits,
                add_tokens,
                add_tool_calls,
                extend_deadline_unix,
                now_unix,
            )
    }

    async fn get_workflow_run_budget(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_workflow_run_budget(id))
            .unwrap_or(None))
    }

    async fn list_workflow_run_budgets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_workflow_run_budgets(tenant_id))
            .unwrap_or_default())
    }

    async fn upsert_permission(&self, permission: StoredPermission) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_permission(permission);
        }
        Ok(())
    }

    async fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_permission(id))
            .unwrap_or(None))
    }

    async fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_permissions())
            .unwrap_or_default())
    }

    async fn delete_permission(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_permission(id))
            .unwrap_or(false))
    }

    async fn upsert_role(&self, role: StoredRole) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_role(role);
        }
        Ok(())
    }

    async fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_role(id))
            .unwrap_or(None))
    }

    async fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_roles())
            .unwrap_or_default())
    }

    async fn delete_role(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_role(id))
            .unwrap_or(false))
    }

    async fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.bind_tenant_role(binding);
        }
        Ok(())
    }

    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_tenant_role_bindings(tenant_id))
            .unwrap_or_default())
    }

    async fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.unbind_tenant_role(tenant_id, role_id))
            .unwrap_or(false))
    }

    async fn upsert_agent_schedule(
        &self,
        schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .upsert_agent_schedule(schedule);
        Ok(())
    }

    async fn get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .get_agent_schedule(schedule_id))
    }

    async fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .list_agent_schedules(tenant_id, workspace_id))
    }

    async fn list_all_agent_schedules(&self) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .list_all_agent_schedules())
    }

    async fn delete_agent_schedule(&self, schedule_id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .delete_agent_schedule(schedule_id))
    }

    async fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .list_due_agent_schedules(now_unix, limit.max(0) as usize))
    }

    async fn insert_agent_schedule_fire(
        &self,
        fire: StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .insert_agent_schedule_fire(fire))
    }

    async fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("agent schedule repository lock poisoned".into()))?
            .list_agent_schedule_fires(schedule_id, limit.max(0) as usize))
    }

    async fn settle_wallet_balance(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .settle_wallet_balance(settlement_id, tenant_id, delta_credits, now_unix)
    }

    async fn upsert_wallet(&self, wallet: StoredWallet) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_wallet(wallet);
        }
        Ok(())
    }

    async fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_wallet(tenant_id))
            .unwrap_or(None))
    }

    async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_wallets())
            .unwrap_or_default())
    }

    async fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| {
                control_plane.adjust_wallet_balance(tenant_id, delta_credits, now_unix)
            })
            .unwrap_or(None))
    }

    async fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.set_wallet_dunning(tenant_id, dunning, now_unix);
        }
        Ok(())
    }

    async fn reserve_wallet_credits(
        &self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .reserve_wallet_credits(
                reservation_id,
                tenant_id,
                amount_credits,
                expires_at_unix,
                now_unix,
            )
    }

    async fn settle_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .settle_wallet_reservation(reservation_id, now_unix)
    }

    async fn release_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .release_wallet_reservation(reservation_id, now_unix)
    }

    async fn sweep_expired_wallet_reservations(
        &self,
        now_unix: i64,
    ) -> Result<Vec<String>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .sweep_expired_wallet_reservations(now_unix))
    }

    async fn list_wallet_reservations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_wallet_reservations(tenant_id))
            .unwrap_or_default())
    }

    async fn upsert_payment_method(
        &self,
        payment_method: StoredPaymentMethod,
    ) -> Result<(), StorageError> {
        if let Ok(mut control_plane) = self.lock() {
            control_plane.upsert_payment_method(payment_method);
        }
        Ok(())
    }

    async fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_payment_methods(tenant_id))
            .unwrap_or_default())
    }

    async fn get_payment_method(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentMethod>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_payment_method(id))
            .unwrap_or(None))
    }

    async fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self
            .lock()
            .map(|mut control_plane| control_plane.delete_payment_method(id))
            .unwrap_or(false))
    }

    async fn create_payment_attempt(
        &self,
        attempt: StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .create_payment_attempt(attempt)
    }

    async fn get_payment_attempt(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentAttempt>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_payment_attempt(id))
            .unwrap_or(None))
    }

    async fn list_payment_attempts(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.list_payment_attempts(tenant_id))
            .unwrap_or_default())
    }

    async fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<Option<PaymentAttemptLinks>, StorageError> {
        Ok(self
            .lock()
            .map(|control_plane| control_plane.get_payment_attempt_links(id, tenant_id))
            .unwrap_or(None))
    }

    async fn list_expirable_due_payment_attempts(
        &self,
        due_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .list_expirable_due_payment_attempts(due_at_or_before_unix, limit))
    }

    async fn list_reconcilable_payment_attempts(
        &self,
        checked_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        Ok(self
            .lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .list_reconcilable_payment_attempts(checked_at_or_before_unix, limit))
    }

    async fn transition_payment_attempt(
        &self,
        _op_name: &'static str,
        id: &str,
        allowed_from: &[&str],
        to_state: &str,
        evidence: &super::payment_attempt::TransitionEvidence<'_>,
        now_unix: i64,
    ) -> Result<PaymentAttemptTransition, StorageError> {
        self.lock()
            .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
            .transition_payment_attempt(id, allowed_from, to_state, evidence, now_unix)
    }
}

impl MemoryControlPlaneStore {
    fn upsert_in_memory_usage_aggregate(&self, event: &BillingEvent) {
        if let Ok(mut aggregates) = self.usage_aggregates.lock() {
            let id = usage_aggregate_id(&event.tenant, &event.logical_model, &event.provider);
            let existing = aggregates.get(&id);
            let mut aggregate = existing.unwrap_or_else(|| StoredUsageAggregate {
                id: id.clone(),
                organization_id: event.tenant.organization_id.clone(),
                project_id: event.tenant.project_id.clone(),
                api_key_id: event.tenant.api_key_id.clone(),
                logical_model: event.logical_model.clone(),
                provider: event.provider.clone(),
                usage: TokenUsage::default(),
            });
            aggregate.usage.prompt_tokens = aggregate
                .usage
                .prompt_tokens
                .saturating_add(event.usage.prompt_tokens);
            aggregate.usage.completion_tokens = aggregate
                .usage
                .completion_tokens
                .saturating_add(event.usage.completion_tokens);
            aggregate.usage.total_tokens = aggregate
                .usage
                .total_tokens
                .saturating_add(event.usage.total_tokens);
            aggregates.insert(id, aggregate);
        }
    }
}
