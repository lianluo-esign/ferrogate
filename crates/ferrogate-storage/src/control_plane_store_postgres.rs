// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: `impl ControlPlaneStore for PostgresControlPlaneStore` (#419/
// #425). Every method forwards to the same-named inherent tokio-postgres
// method (inherent-method resolution priority keeps the forwarders
// recursion-free), so the ~8000-line SQL block in lib.rs stays untouched.

use super::control_plane_store::ControlPlaneStore;
use super::*;

#[async_trait::async_trait]
impl ControlPlaneStore for PostgresControlPlaneStore {
    async fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError> {
        self.upsert_api_key_record(&api_key).await
    }

    async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError> {
        self.get_api_key_record(id).await
    }

    async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError> {
        self.list_api_key_records().await
    }

    async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        self.find_api_key_records_by_prefix(key_prefix).await
    }

    async fn upsert_admin_user(&self, user: StoredAdminUser) -> Result<(), StorageError> {
        self.upsert_admin_user(&user).await
    }

    async fn get_admin_user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        self.get_admin_user_by_id(id).await
    }

    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError> {
        self.get_admin_user_by_email(email).await
    }

    async fn upsert_admin_user_membership(
        &self,
        membership: StoredAdminUserMembership,
    ) -> Result<(), StorageError> {
        self.upsert_admin_user_membership(&membership).await
    }

    async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        self.list_admin_user_memberships_by_user(user_id).await
    }

    async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError> {
        self.list_admin_user_memberships_by_tenant(tenant_id).await
    }

    async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        self.delete_admin_user_membership(user_id, tenant_id).await
    }

    async fn upsert_sso_provider_config(
        &self,
        config: StoredSsoProviderConfig,
    ) -> Result<(), StorageError> {
        self.upsert_sso_provider_config(&config).await
    }

    async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError> {
        self.get_sso_provider_config(tenant_id).await
    }

    async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError> {
        self.delete_sso_provider_config(tenant_id).await
    }

    async fn insert_sso_pending_flow(
        &self,
        flow: StoredSsoPendingFlow,
    ) -> Result<(), StorageError> {
        self.insert_sso_pending_flow(&flow).await
    }

    async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError> {
        self.take_sso_pending_flow(state, now_unix).await
    }

    async fn upsert_admin_user_refresh_token(
        &self,
        token: StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError> {
        self.upsert_admin_user_refresh_token(&token).await
    }

    async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError> {
        self.get_admin_user_refresh_token_by_hash(token_hash).await
    }

    async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        self.revoke_all_admin_user_refresh_tokens(user_id, revoked_at_unix)
            .await
    }

    async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError> {
        self.revoke_admin_user_refresh_tokens_for_tenant(user_id, tenant_id, revoked_at_unix)
            .await
    }

    async fn upsert_tenant_account(
        &self,
        account: StoredTenantAccount,
    ) -> Result<(), StorageError> {
        self.upsert_tenant_account(&account).await
    }

    async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        self.get_tenant_account(id).await
    }

    async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError> {
        self.list_tenant_accounts().await
    }

    async fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError> {
        self.upsert_project(&project).await
    }

    async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        self.get_project(id).await
    }

    async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError> {
        self.list_projects().await
    }

    async fn delete_project(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_project(id).await
    }

    async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        self.delete_project_if_unreferenced(id).await
    }

    async fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError> {
        self.upsert_workspace(&workspace).await
    }

    async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        self.get_workspace(id).await
    }

    async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        self.list_workspaces().await
    }

    async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_workspace(id).await
    }

    async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        self.delete_workspace_if_unreferenced(id).await
    }

    async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        self.resolve_workspace_scope(workspace_id).await
    }

    async fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> Result<(), StorageError> {
        self.upsert_quota_policy(&policy).await
    }

    async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError> {
        self.get_quota_policy(scope_type, scope_id).await
    }

    async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError> {
        self.list_quota_policies().await
    }

    async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError> {
        self.delete_quota_policy(scope_type, scope_id).await
    }

    async fn upsert_plan(&self, plan: StoredPlan) -> Result<(), StorageError> {
        self.upsert_plan(&plan).await
    }

    async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError> {
        self.get_plan(id).await
    }

    async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError> {
        self.list_plans().await
    }

    async fn upsert_asset(&self, asset: StoredAsset) -> Result<(), StorageError> {
        self.upsert_asset(&asset).await
    }

    async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError> {
        self.create_asset_if_absent(&asset).await
    }

    async fn create_asset_within_quota(
        &self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError> {
        self.create_asset_within_quota(&asset, quota_bytes).await
    }

    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError> {
        self.get_asset(id).await
    }

    async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        self.list_assets(tenant_id, asset_type).await
    }

    async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError> {
        self.list_withheld_assets(tenant_id, asset_type).await
    }

    async fn tenant_asset_storage_bytes_used(&self, tenant_id: &str) -> Result<u64, StorageError> {
        self.tenant_asset_storage_bytes_used(tenant_id).await
    }

    async fn delete_asset(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_asset(id).await
    }

    async fn upsert_asset_channel(&self, channel: StoredAssetChannel) -> Result<(), StorageError> {
        self.upsert_asset_channel(&channel).await
    }

    async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError> {
        self.list_asset_channels(tenant_id, asset_type, name).await
    }

    async fn delete_asset_channel(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_asset_channel(id).await
    }

    async fn move_asset_channel_if_resolvable(
        &self,
        channel: StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError> {
        self.move_asset_channel_if_resolvable(&channel).await
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
        self.set_asset_version_yank(tenant_id, asset_type, name, version, yanked, now_unix)
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
        self.delete_asset_variant_if_unreferenced(id, tenant_id, asset_type, name, version)
            .await
    }

    async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError> {
        self.promote_pending_asset_visibility(id, target, now_unix)
            .await
    }

    async fn upsert_retention_policy(
        &self,
        policy: StoredRetentionPolicy,
    ) -> Result<(), StorageError> {
        self.upsert_retention_policy(&policy).await
    }

    async fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError> {
        self.list_retention_policies(tenant_id, resource_type).await
    }

    async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError> {
        self.list_all_assets().await
    }

    async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError> {
        self.list_all_asset_channels().await
    }

    async fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError> {
        self.get_usage_monthly_rollup(scope_type, scope_id, period_month)
            .await
    }

    async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError> {
        self.list_usage_monthly_rollups().await
    }

    /// Override the trait default (#339): push every count/sum into the
    /// database instead of streaming whole control-plane tables back to fold in
    /// the gateway.
    async fn overview_aggregate(
        &self,
        tenant_scope: Option<&str>,
        current_period_month: &str,
    ) -> Result<ControlPlaneOverviewAggregate, StorageError> {
        self.overview_aggregate_pushdown(tenant_scope, current_period_month)
            .await
    }

    async fn append_billing_ledger_entry(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError> {
        self.append_billing_ledger_entry(entry).await
    }

    async fn list_billing_ledger_entries(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError> {
        self.list_billing_ledger_entries(
            filter,
            saturating_i64(offset as u64),
            saturating_i64(limit as u64),
        )
        .await
    }

    async fn billing_ledger_entry(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError> {
        self.get_billing_ledger_entry(id).await
    }

    async fn enqueue_billing_report(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        self.enqueue_billing_report(id, event, next_attempt_unix)
            .await
    }

    async fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        self.list_due_billing_reports(now_unix, saturating_i64(limit as u64))
            .await
    }

    async fn reschedule_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError> {
        self.reschedule_billing_report(id, next_attempt_unix).await
    }

    async fn dead_letter_billing_report(
        &self,
        id: &str,
        _dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError> {
        self.dead_letter_billing_report(id).await
    }

    async fn list_dead_lettered_billing_reports(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError> {
        self.list_dead_lettered_billing_reports(saturating_i64(limit as u64))
            .await
    }

    async fn replay_dead_lettered_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError> {
        self.replay_dead_lettered_billing_report(id, next_attempt_unix)
            .await
    }

    async fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError> {
        self.get_billing_report_outbox_entry(id).await
    }

    async fn delete_billing_report(&self, id: &str) -> Result<(), StorageError> {
        self.delete_billing_report(id).await
    }

    fn upsert_config_document(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(self.upsert(kind, id, document_json))
    }

    fn delete_config_document(&self, kind: &'static str, id: &str) -> Result<bool, StorageError> {
        block_on_sync_bridge(self.delete(kind, id.to_string()))
    }

    fn get_config_document(
        &self,
        kind: &'static str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        block_on_sync_bridge(self.get_document(kind, id.to_string()))
    }

    fn list_config_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError> {
        block_on_sync_bridge(self.list_documents(kind))
    }

    fn list_config_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        block_on_sync_bridge(self.list_resource_documents(kind))
    }

    fn replace_config_documents(
        &self,
        documents: ControlPlaneDocuments,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(self.replace_kind("api_key", documents.api_keys))?;
        block_on_sync_bridge(self.replace_kind("tenant", documents.tenants))?;
        block_on_sync_bridge(self.replace_kind("policy", documents.policies))?;
        block_on_sync_bridge(self.replace_kind("gateway_config", documents.gateway_configs))?;
        block_on_sync_bridge(self.replace_kind("agent_workflow", documents.agent_workflows))?;
        block_on_sync_bridge(self.replace_kind("skill_package", documents.skill_packages))?;
        block_on_sync_bridge(self.replace_kind("prompt_template", documents.prompt_templates))?;
        block_on_sync_bridge(
            self.replace_kind("plugin_registration", documents.plugin_registrations),
        )?;
        block_on_sync_bridge(self.replace_kind("mcp_server", documents.mcp_servers))?;
        block_on_sync_bridge(self.replace_kind("agent_upstream", documents.agent_upstreams))?;
        Ok(())
    }

    fn control_plane_snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError> {
        block_on_sync_bridge(self.snapshot())
    }

    fn config_documents(&self) -> Result<ControlPlaneDocuments, StorageError> {
        block_on_sync_bridge(self.documents())
    }

    fn insert_guardrail_policy_revision(
        &self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::insert_guardrail_policy_revision(
            self, &revision,
        ))
    }

    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::get_guardrail_policy_revision(
            self, policy_id, revision,
        ))
    }

    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::list_guardrail_policy_revisions(
            self, policy_id,
        ))
    }

    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::get_guardrail_policy_binding(
            self, policy_id,
        ))
    }

    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::list_guardrail_policy_bindings(
            self,
        ))
    }

    fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        block_on_sync_bridge(
            PostgresControlPlaneStore::activate_guardrail_policy_revision(
                self,
                policy_id,
                revision,
                updated_by,
                updated_at_unix,
                rollback_only,
            ),
        )
    }

    fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError> {
        block_on_sync_bridge(
            PostgresControlPlaneStore::archive_guardrail_policy_revision(
                self,
                policy_id,
                revision,
                updated_by,
                updated_at_unix,
            ),
        )
    }

    fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::restore_guardrail_policy_binding(
            self,
            policy_id,
            expected_generation,
            binding.as_ref(),
        ))
    }

    fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::get_snapshot_replay_floor(
            self,
            tenant_id,
            deployment_id,
        ))
    }

    fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        updated_at_unix: i64,
    ) -> Result<u64, StorageError> {
        block_on_sync_bridge(PostgresControlPlaneStore::advance_snapshot_replay_floor(
            self,
            tenant_id,
            deployment_id,
            revision,
            updated_at_unix,
        ))
    }

    fn schema_evidence(&self) -> Option<StorageSchemaEvidence> {
        Some(PostgresControlPlaneStore::schema_evidence(self))
    }

    fn pool_metrics_snapshot(&self) -> PostgresPoolMetricsSnapshot {
        self.async_pool.metrics_snapshot()
    }

    fn set_retention_limits(
        &self,
        _request_log_retention_records: usize,
        _audit_event_retention_records: usize,
    ) {
        // Durable request-log/audit retention is enforced by the compliance
        // sweeper (#284), not by in-process bounds; nothing to configure here
        // (behavior-identical to the pre-#425 dispatch, which only adjusted
        // the unused in-memory repositories).
    }

    async fn append_request_log(&self, log: StoredRequestLog) {
        let _ = PostgresControlPlaneStore::append_request_log(self, &log).await;
    }

    async fn request_logs(&self) -> Vec<StoredRequestLog> {
        PostgresControlPlaneStore::request_logs(self)
            .await
            .unwrap_or_default()
    }

    async fn request_logs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredRequestLog> {
        PostgresControlPlaneStore::request_logs_page(self, offset, limit)
            .await
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

    async fn delete_request_logs(&self, request_ids: &[String]) -> Result<u64, StorageError> {
        PostgresControlPlaneStore::delete_request_logs(self, request_ids).await
    }

    async fn request_logs_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredRequestLog> {
        PostgresControlPlaneStore::request_logs_for_agent_runs(self, run_ids)
            .await
            .unwrap_or_default()
    }

    async fn append_audit_event(&self, event: StoredAuditEvent) {
        let _ = PostgresControlPlaneStore::append_audit_event(self, &event).await;
    }

    fn next_audit_event_id(&self) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("audit-{nanos}-{}", std::process::id())
    }

    async fn audit_events(&self) -> Vec<StoredAuditEvent> {
        PostgresControlPlaneStore::audit_events(self)
            .await
            .unwrap_or_default()
    }

    async fn audit_events_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StoragePage<StoredAuditEvent> {
        PostgresControlPlaneStore::audit_events_page(self, offset, limit)
            .await
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

    async fn delete_audit_events(&self, ids: &[String]) -> Result<u64, StorageError> {
        PostgresControlPlaneStore::delete_audit_events(self, ids).await
    }

    async fn audit_events_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredAuditEvent> {
        PostgresControlPlaneStore::audit_events_for_agent_runs(self, run_ids)
            .await
            .unwrap_or_default()
    }

    async fn append_billing_event(&self, event: BillingEvent) -> Result<bool, StorageError> {
        PostgresControlPlaneStore::append_billing_event(self, &event).await
    }

    async fn append_billing_event_with_outbox_enqueue(
        &self,
        event: BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError> {
        let recorded = PostgresControlPlaneStore::append_billing_event_with_outbox_enqueue(
            self,
            &event,
            outbox_id,
            outbox_next_attempt_unix,
        )
        .await?;
        Ok(BillingEventAppendOutcome {
            recorded,
            enqueue_error: None,
        })
    }

    async fn billing_events(&self) -> Vec<BillingEvent> {
        PostgresControlPlaneStore::billing_events(self)
            .await
            .unwrap_or_default()
    }

    async fn billing_events_page(&self, offset: usize, limit: usize) -> StoragePage<BillingEvent> {
        PostgresControlPlaneStore::billing_events_page(self, offset, limit)
            .await
            .unwrap_or_else(|_| StoragePage::empty(offset, limit))
    }

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
        PostgresControlPlaneStore::upsert_usage_aggregate(self, aggregate).await
    }

    async fn usage_aggregates(&self) -> Vec<StoredUsageAggregate> {
        PostgresControlPlaneStore::usage_aggregates(self)
            .await
            .unwrap_or_default()
    }

    async fn sum_api_key_committed_tokens(&self, api_key_id: &str) -> u64 {
        PostgresControlPlaneStore::sum_api_key_committed_tokens(self, api_key_id)
            .await
            .unwrap_or_default()
    }

    async fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_agent_run(self, &run).await
    }

    async fn agent_run(&self, id: &str) -> Option<StoredAgentRun> {
        PostgresControlPlaneStore::agent_run(self, id)
            .await
            .unwrap_or_default()
    }

    async fn agent_runs(&self) -> Vec<StoredAgentRun> {
        PostgresControlPlaneStore::agent_runs(self)
            .await
            .unwrap_or_default()
    }

    async fn agent_runs_by_ids(&self, run_ids: &[String]) -> Vec<StoredAgentRun> {
        PostgresControlPlaneStore::agent_runs_by_ids(self, run_ids)
            .await
            .unwrap_or_default()
    }

    async fn append_agent_run_event(&self, event: StoredAgentRunEvent) -> Result<(), StorageError> {
        PostgresControlPlaneStore::append_agent_run_event(self, &event).await?;
        if self.durable_prune_due(&self.agent_run_event_prune_ticks) {
            // Best-effort retention (issue #231): a prune failure
            // must not fail ingestion of the already-written event.
            if let Err(error) = self
                .prune_agent_run_events(&event.run_id, self.durable_worker_retention_records)
                .await
            {
                tracing::warn!("agent run event retention prune failed: {error}");
            }
        }
        Ok(())
    }

    async fn agent_run_events(&self) -> Vec<StoredAgentRunEvent> {
        PostgresControlPlaneStore::agent_run_events(self)
            .await
            .unwrap_or_default()
    }

    async fn agent_run_events_for_runs(&self, run_ids: &[String]) -> Vec<StoredAgentRunEvent> {
        PostgresControlPlaneStore::agent_run_events_for_runs(self, run_ids)
            .await
            .unwrap_or_default()
    }

    async fn agent_run_summary_seed_ids(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Vec<String> {
        PostgresControlPlaneStore::agent_run_summary_seed_ids(self, request_id, limit)
            .await
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_template(
        &self,
        template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_managed_worker_template(self, &template).await
    }

    async fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate> {
        PostgresControlPlaneStore::managed_worker_templates(self)
            .await
            .unwrap_or_default()
    }

    async fn upsert_agent_worker_instance(
        &self,
        instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_agent_worker_instance(self, &instance).await
    }

    async fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance> {
        PostgresControlPlaneStore::agent_worker_instances(self)
            .await
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_session(
        &self,
        session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_managed_worker_session(self, &session).await
    }

    async fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession> {
        PostgresControlPlaneStore::managed_worker_sessions(self)
            .await
            .unwrap_or_default()
    }

    async fn append_managed_worker_lifecycle_event(
        &self,
        event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::append_managed_worker_lifecycle_event(self, &event).await
    }

    async fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent> {
        PostgresControlPlaneStore::managed_worker_lifecycle_events(self)
            .await
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_isolation_selection(
        &self,
        selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_managed_worker_isolation_selection(self, &selection).await
    }

    async fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection> {
        PostgresControlPlaneStore::managed_worker_isolation_selections(self)
            .await
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_isolation_policy(
        &self,
        policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_managed_worker_isolation_policy(self, &policy).await
    }

    async fn managed_worker_isolation_policies(&self) -> Vec<StoredManagedWorkerIsolationPolicy> {
        PostgresControlPlaneStore::managed_worker_isolation_policies(self)
            .await
            .unwrap_or_default()
    }

    async fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_managed_worker_isolation_evidence(self, &evidence).await
    }

    async fn managed_worker_isolation_evidence(&self) -> Vec<StoredManagedWorkerIsolationEvidence> {
        PostgresControlPlaneStore::managed_worker_isolation_evidence(self)
            .await
            .unwrap_or_default()
    }

    async fn upsert_self_hosted_worker_registration(
        &self,
        registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_self_hosted_worker_registration(self, &registration).await
    }

    async fn self_hosted_worker_registrations(&self) -> Vec<StoredSelfHostedWorkerRegistration> {
        PostgresControlPlaneStore::self_hosted_worker_registrations(self)
            .await
            .unwrap_or_default()
    }

    async fn self_hosted_worker_registration(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerRegistration> {
        PostgresControlPlaneStore::self_hosted_worker_registration(self, worker_id)
            .await
            .unwrap_or_default()
    }

    async fn latest_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerHeartbeat> {
        PostgresControlPlaneStore::latest_self_hosted_worker_heartbeat(self, worker_id)
            .await
            .unwrap_or_default()
    }

    async fn self_hosted_worker_activity_stats(
        &self,
        worker_id: &str,
    ) -> StoredSelfHostedWorkerActivityStats {
        PostgresControlPlaneStore::self_hosted_worker_activity_stats(self, worker_id)
            .await
            .unwrap_or_default()
    }

    async fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::append_self_hosted_worker_heartbeat(self, &heartbeat).await?;
        if self.durable_prune_due(&self.heartbeat_prune_ticks) {
            // Best-effort retention (issue #231): a prune failure
            // must not fail ingestion of the already-written record.
            if let Err(error) = self
                .prune_self_hosted_worker_heartbeats(
                    &heartbeat.worker_id,
                    self.durable_worker_retention_records,
                )
                .await
            {
                tracing::warn!("self-hosted heartbeat retention prune failed: {error}");
            }
        }
        Ok(())
    }

    async fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat> {
        PostgresControlPlaneStore::self_hosted_worker_heartbeats(self)
            .await
            .unwrap_or_default()
    }

    async fn append_self_hosted_worker_telemetry_event(
        &self,
        event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::append_self_hosted_worker_telemetry_event(self, &event).await?;
        if self.durable_prune_due(&self.telemetry_prune_ticks) {
            // Best-effort retention (issue #231); see heartbeat twin.
            if let Err(error) = self
                .prune_self_hosted_worker_telemetry_events(
                    &event.worker_id,
                    self.durable_worker_retention_records,
                )
                .await
            {
                tracing::warn!("self-hosted telemetry retention prune failed: {error}");
            }
        }
        Ok(())
    }

    async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        PostgresControlPlaneStore::self_hosted_worker_telemetry_events(self)
            .await
            .unwrap_or_default()
    }

    async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        PostgresControlPlaneStore::self_hosted_worker_telemetry_events_for_run(self, run_id, limit)
            .await
            .unwrap_or_default()
    }

    async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        worker_id: &str,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent> {
        PostgresControlPlaneStore::self_hosted_worker_telemetry_events_for_worker(self, worker_id)
            .await
            .unwrap_or_default()
    }

    async fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_self_hosted_worker_artifact(self, &artifact).await?;
        if self.durable_prune_due(&self.artifact_prune_ticks) {
            // Best-effort retention (issue #231); see heartbeat twin.
            if let Err(error) = self
                .prune_self_hosted_worker_artifacts(
                    &artifact.worker_id,
                    self.durable_worker_retention_records,
                )
                .await
            {
                tracing::warn!("self-hosted artifact retention prune failed: {error}");
            }
        }
        Ok(())
    }

    async fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact> {
        PostgresControlPlaneStore::self_hosted_worker_artifacts(self)
            .await
            .unwrap_or_default()
    }

    async fn self_hosted_worker_artifact(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerArtifact> {
        PostgresControlPlaneStore::self_hosted_worker_artifact(self, id)
            .await
            .unwrap_or_default()
    }

    async fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_self_hosted_worker_checkpoint(self, &checkpoint).await?;
        if self.durable_prune_due(&self.checkpoint_prune_ticks) {
            // Best-effort retention (issue #231); see heartbeat twin.
            if let Err(error) = self
                .prune_self_hosted_worker_checkpoints(
                    &checkpoint.worker_id,
                    self.durable_worker_retention_records,
                )
                .await
            {
                tracing::warn!("self-hosted checkpoint retention prune failed: {error}");
            }
        }
        Ok(())
    }

    async fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint> {
        PostgresControlPlaneStore::self_hosted_worker_checkpoints(self)
            .await
            .unwrap_or_default()
    }

    async fn self_hosted_worker_checkpoint(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerCheckpoint> {
        PostgresControlPlaneStore::self_hosted_worker_checkpoint(self, id)
            .await
            .unwrap_or_default()
    }

    async fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError> {
        PostgresControlPlaneStore::upsert_self_hosted_run_dispatch(self, &dispatch).await
    }

    async fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch> {
        PostgresControlPlaneStore::self_hosted_run_dispatches(self)
            .await
            .unwrap_or_default()
    }

    async fn delete_self_hosted_run_dispatch(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, StorageError> {
        PostgresControlPlaneStore::delete_self_hosted_run_dispatch(self, dispatch_id).await
    }

    // --- Per-entity module surfaces (#437): forward to inherent SQL ---

    async fn upsert_site_domain(&self, domain: StoredSiteDomain) -> Result<(), StorageError> {
        self.upsert_site_domain(&domain).await
    }

    async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError> {
        self.get_site_domain(hostname).await
    }

    async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError> {
        self.list_site_domains(tenant_id).await
    }

    async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError> {
        self.delete_site_domain(hostname).await
    }

    // Site-domain DNS ownership proofs (#488).
    async fn upsert_site_domain_verification(
        &self,
        verification: StoredSiteDomainVerification,
    ) -> Result<(), StorageError> {
        self.upsert_site_domain_verification(&verification).await
    }

    async fn get_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomainVerification>, StorageError> {
        self.get_site_domain_verification(tenant_id, hostname).await
    }

    async fn list_site_domain_verifications(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomainVerification>, StorageError> {
        self.list_site_domain_verifications(tenant_id).await
    }

    async fn delete_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<bool, StorageError> {
        self.delete_site_domain_verification(tenant_id, hostname)
            .await
    }

    async fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError> {
        self.list_usage_metadata_rollups(metadata_key, organization_id)
            .await
    }

    async fn touch_observed_agent_presence(
        &self,
        touch: ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        self.touch_observed_agent_presence(&touch).await
    }

    async fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        self.list_observed_agent_presence_since(tenant_scope, since_unix)
            .await
    }

    async fn add_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
        delta_usd: f64,
    ) -> Result<f64, StorageError> {
        self.add_agent_burn(tenant_id, agent_key, period, delta_usd)
            .await
    }

    async fn get_agent_burn(
        &self,
        tenant_id: &str,
        agent_key: &str,
        period: &str,
    ) -> Result<Option<f64>, StorageError> {
        self.get_agent_burn(tenant_id, agent_key, period).await
    }

    async fn list_agent_cost_burn(
        &self,
        tenant_scope: Option<&str>,
        period: &str,
    ) -> Result<Vec<StoredAgentCostBurn>, StorageError> {
        self.list_agent_cost_burn(tenant_scope, period).await
    }

    async fn record_budget_alert_notification(
        &self,
        notification: StoredBudgetAlertNotification,
    ) -> Result<(), StorageError> {
        self.record_budget_alert_notification(&notification).await
    }

    async fn budget_alert_already_notified(&self, id: &str) -> Result<bool, StorageError> {
        self.budget_alert_already_notified(id).await
    }

    async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError> {
        self.list_budget_alert_notifications(scope_type, scope_id, period_month)
            .await
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
        self.open_workflow_run_budget(
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
        self.debit_workflow_run_budget(id, cost_credits, tokens, tool_calls, now_unix)
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
        self.topup_workflow_run_budget(
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
        self.get_workflow_run_budget(id).await
    }

    async fn list_workflow_run_budgets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError> {
        self.list_workflow_run_budgets(tenant_id).await
    }

    async fn upsert_permission(&self, permission: StoredPermission) -> Result<(), StorageError> {
        self.upsert_permission(&permission).await
    }

    async fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError> {
        self.get_permission(id).await
    }

    async fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError> {
        self.list_permissions().await
    }

    async fn delete_permission(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_permission(id).await
    }

    async fn upsert_role(&self, role: StoredRole) -> Result<(), StorageError> {
        self.upsert_role(&role).await
    }

    async fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError> {
        self.get_role(id).await
    }

    async fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError> {
        self.list_roles().await
    }

    async fn delete_role(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_role(id).await
    }

    async fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> Result<(), StorageError> {
        self.bind_tenant_role(&binding).await
    }

    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError> {
        self.list_tenant_role_bindings(tenant_id).await
    }

    async fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<bool, StorageError> {
        self.unbind_tenant_role(tenant_id, role_id).await
    }

    async fn upsert_agent_schedule(
        &self,
        schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError> {
        self.upsert_agent_schedule(&schedule).await
    }

    async fn get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError> {
        self.get_agent_schedule(schedule_id).await
    }

    async fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.list_agent_schedules(tenant_id, workspace_id).await
    }

    async fn list_all_agent_schedules(&self) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.list_all_agent_schedules().await
    }

    async fn delete_agent_schedule(&self, schedule_id: &str) -> Result<bool, StorageError> {
        self.delete_agent_schedule(schedule_id).await
    }

    async fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError> {
        self.list_due_agent_schedules(now_unix, limit).await
    }

    async fn insert_agent_schedule_fire(
        &self,
        fire: StoredAgentScheduleFire,
    ) -> Result<bool, StorageError> {
        self.insert_agent_schedule_fire(&fire).await
    }

    async fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError> {
        self.list_agent_schedule_fires(schedule_id, limit).await
    }

    async fn settle_wallet_balance(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        self.settle_wallet_balance(settlement_id, tenant_id, delta_credits, now_unix)
            .await
    }

    async fn upsert_wallet(&self, wallet: StoredWallet) -> Result<(), StorageError> {
        self.upsert_wallet(&wallet).await
    }

    async fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        self.get_wallet(tenant_id).await
    }

    async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        self.list_wallets().await
    }

    async fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        self.adjust_wallet_balance(tenant_id, delta_credits, now_unix)
            .await
    }

    async fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        self.set_wallet_dunning(tenant_id, dunning, now_unix).await
    }

    async fn reserve_wallet_credits(
        &self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        self.reserve_wallet_credits(
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
        self.settle_wallet_reservation(reservation_id, now_unix)
            .await
    }

    async fn release_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        self.release_wallet_reservation(reservation_id, now_unix)
            .await
    }

    async fn sweep_expired_wallet_reservations(
        &self,
        now_unix: i64,
    ) -> Result<Vec<String>, StorageError> {
        self.sweep_expired_wallet_reservations(now_unix).await
    }

    async fn list_wallet_reservations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        self.list_wallet_reservations(tenant_id).await
    }

    async fn upsert_payment_method(
        &self,
        payment_method: StoredPaymentMethod,
    ) -> Result<(), StorageError> {
        self.upsert_payment_method(&payment_method).await
    }

    async fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        self.list_payment_methods(tenant_id).await
    }

    async fn get_payment_method(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentMethod>, StorageError> {
        self.get_payment_method(id).await
    }

    async fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError> {
        self.delete_payment_method(id).await
    }

    async fn create_payment_attempt(
        &self,
        attempt: StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError> {
        self.create_payment_attempt(&attempt).await
    }

    async fn get_payment_attempt(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentAttempt>, StorageError> {
        self.get_payment_attempt(id).await
    }

    async fn list_payment_attempts(
        &self,
        tenant_id: &str,
        query: &PaymentAttemptQuery,
    ) -> Result<PaymentAttemptPage, StorageError> {
        self.list_payment_attempts(tenant_id, query).await
    }

    async fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<Option<PaymentAttemptLinks>, StorageError> {
        self.get_payment_attempt_links(id, tenant_id).await
    }

    async fn list_expirable_due_payment_attempts(
        &self,
        due_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        self.list_expirable_due_payment_attempts(due_at_or_before_unix, limit as i64)
            .await
    }

    async fn list_reconcilable_payment_attempts(
        &self,
        checked_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        self.list_reconcilable_payment_attempts(checked_at_or_before_unix, limit as i64)
            .await
    }

    async fn transition_payment_attempt(
        &self,
        op_name: &'static str,
        id: &str,
        allowed_from: &[&str],
        to_state: &str,
        evidence: &super::payment_attempt::TransitionEvidence<'_>,
        now_unix: i64,
    ) -> Result<PaymentAttemptTransition, StorageError> {
        self.transition_payment_attempt(op_name, id, allowed_from, to_state, evidence, now_unix)
            .await
    }
}

/// Inherent COUNT/SUM aggregation backing the #339 control-plane overview. Kept
/// out of `lib.rs` (module-layout cap, #429/#433); reuses the same
/// pool-acquire + `search_path`-pinned transaction shape as the surrounding
/// control-plane reads.
impl PostgresControlPlaneStore {
    /// Bounded COUNT/SUM pushdown backing [`ControlPlaneStore::overview_aggregate`]
    /// (#339). Every table is aggregated in the database — no control-plane
    /// collection is streamed back to be counted in the gateway. `$1` is the
    /// tenant scope: `NULL` for the platform-operator global view, otherwise the
    /// caller's own tenant id (so a tenant-scoped console can never read another
    /// tenant's counts). Token totals sum only `scope_type = 'tenant'` rollup
    /// rows so the tenant/project/workspace/key fan-out never multiplies a
    /// request; `$2` selects the current calendar month for the month window.
    pub(crate) async fn overview_aggregate_pushdown(
        &self,
        tenant_scope: Option<&str>,
        current_period_month: &str,
    ) -> Result<ControlPlaneOverviewAggregate, StorageError> {
        let operation = self.tenancy_operation("control-plane overview aggregate");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so every
        // aggregate below resolves its table in the control-plane schema.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let scope: Option<&str> = tenant_scope;

        let tenants = Self::overview_scalar_count(
            &transaction,
            "SELECT COUNT(*)::bigint FROM tenants WHERE ($1::text IS NULL OR id = $1)",
            scope,
        )
        .await?;
        let projects = Self::overview_scalar_count(
            &transaction,
            "SELECT COUNT(*)::bigint FROM projects WHERE ($1::text IS NULL OR tenant_id = $1)",
            scope,
        )
        .await?;
        let workspaces = Self::overview_scalar_count(
            &transaction,
            "SELECT COUNT(*)::bigint FROM workspaces WHERE ($1::text IS NULL OR tenant_id = $1)",
            scope,
        )
        .await?;
        let virtual_keys = Self::overview_scalar_count(
            &transaction,
            "SELECT COUNT(*)::bigint FROM api_keys WHERE ($1::text IS NULL OR tenant_id = $1)",
            scope,
        )
        .await?;
        // #458: the enabled subset. Disabled is derived (`total - enabled`) so
        // the two can never contradict.
        let virtual_keys_enabled = Self::overview_scalar_count(
            &transaction,
            "SELECT COUNT(*)::bigint FROM api_keys \
             WHERE enabled AND ($1::text IS NULL OR tenant_id = $1)",
            scope,
        )
        .await?;

        let assets_row = transaction
            .query_one(
                "SELECT COUNT(*)::bigint, COALESCE(SUM(size_bytes), 0)::bigint \
                 FROM stored_assets WHERE ($1::text IS NULL OR tenant_id = $1)",
                &[&scope],
            )
            .await
            .map_err(postgres_error)?;
        let assets = nonnegative_u64(assets_row.get::<_, i64>(0));
        let asset_storage_bytes = nonnegative_u64(assets_row.get::<_, i64>(1));
        // #458: "referenced" = a channel pins the exact
        // (tenant, type, name, version); a bounded COUNT with a correlated
        // EXISTS, aggregated in the database (no rows streamed to count them).
        let assets_referenced = Self::overview_scalar_count(
            &transaction,
            "SELECT COUNT(*)::bigint FROM stored_assets sa \
             WHERE ($1::text IS NULL OR sa.tenant_id = $1) \
               AND EXISTS ( \
                 SELECT 1 FROM asset_channels c \
                 WHERE c.tenant_id = sa.tenant_id AND c.asset_type = sa.asset_type \
                   AND c.name = sa.name AND c.version = sa.version)",
            scope,
        )
        .await?;

        // agent_runs / self_hosted_worker_registrations key `tenant` as the
        // org:-prefixed composite storage key built by `tenant_storage_key`
        // (`org:{org}|team:{team}|project:{project}|workspace:{workspace}|user:{user}|api_key:{api_key}`),
        // NOT a bare tenant id. The in-memory fold scopes these two by the bare
        // `tenant.organization_id`, so raw `tenant = $1` equality would match
        // nothing under tenant scope and return a false-zero (#339). Scope by the
        // `org:{scope}|` prefix instead: the `|` delimiter right after the org
        // segment makes the prefix true iff `organization_id == $1`, producing the
        // identical membership set to `in_scope`. `starts_with` is a literal prefix
        // test (no LIKE metacharacter interpretation), so no escaping is needed.
        let (agent_runs, agent_runs_by_status) = Self::overview_status_histogram(
            &transaction,
            "SELECT status, COUNT(*)::bigint FROM agent_runs \
             WHERE ($1::text IS NULL OR starts_with(tenant, 'org:' || $1 || '|')) \
             GROUP BY status",
            scope,
        )
        .await?;
        let (self_hosted_workers, self_hosted_workers_by_status) = Self::overview_status_histogram(
            &transaction,
            "SELECT status, COUNT(*)::bigint FROM self_hosted_worker_registrations \
             WHERE ($1::text IS NULL OR starts_with(tenant, 'org:' || $1 || '|')) \
             GROUP BY status",
            scope,
        )
        .await?;

        let usage_row = transaction
            .query_one(
                "SELECT \
                    COALESCE(SUM(prompt_tokens), 0)::bigint, \
                    COALESCE(SUM(completion_tokens), 0)::bigint, \
                    COALESCE(SUM(total_tokens), 0)::bigint, \
                    COALESCE(SUM(cost_usd), 0)::double precision, \
                    COALESCE(SUM(request_count), 0)::bigint, \
                    COALESCE(SUM(error_count), 0)::bigint, \
                    COALESCE(SUM(prompt_tokens) FILTER (WHERE period_month = $2), 0)::bigint, \
                    COALESCE(SUM(completion_tokens) FILTER (WHERE period_month = $2), 0)::bigint, \
                    COALESCE(SUM(total_tokens) FILTER (WHERE period_month = $2), 0)::bigint, \
                    COALESCE(SUM(cost_usd) FILTER (WHERE period_month = $2), 0)::double precision, \
                    COALESCE(SUM(request_count) FILTER (WHERE period_month = $2), 0)::bigint, \
                    COALESCE(SUM(error_count) FILTER (WHERE period_month = $2), 0)::bigint \
                 FROM usage_monthly_rollups \
                 WHERE scope_type = 'tenant' AND ($1::text IS NULL OR scope_id = $1)",
                &[&scope, &current_period_month],
            )
            .await
            .map_err(postgres_error)?;
        let usage_lifetime = OverviewUsageTotals {
            prompt_tokens: nonnegative_u64(usage_row.get::<_, i64>(0)),
            completion_tokens: nonnegative_u64(usage_row.get::<_, i64>(1)),
            total_tokens: nonnegative_u64(usage_row.get::<_, i64>(2)),
            cost_usd: usage_row.get::<_, f64>(3),
            request_count: nonnegative_u64(usage_row.get::<_, i64>(4)),
            error_count: nonnegative_u64(usage_row.get::<_, i64>(5)),
        };
        let usage_current_month = OverviewUsageTotals {
            prompt_tokens: nonnegative_u64(usage_row.get::<_, i64>(6)),
            completion_tokens: nonnegative_u64(usage_row.get::<_, i64>(7)),
            total_tokens: nonnegative_u64(usage_row.get::<_, i64>(8)),
            cost_usd: usage_row.get::<_, f64>(9),
            request_count: nonnegative_u64(usage_row.get::<_, i64>(10)),
            error_count: nonnegative_u64(usage_row.get::<_, i64>(11)),
        };

        // #458: per-scope applicable asset-storage quota override (tenant-only).
        // `None` for the global view (no single global number) and for a tenant
        // without an override; never a fabricated aggregate.
        let asset_storage_quota_bytes = match scope {
            Some(tenant) => transaction
                .query_opt(
                    "SELECT asset_storage_quota_bytes FROM quota_policies \
                     WHERE scope_type = 'tenant' AND scope_id = $1",
                    &[&tenant],
                )
                .await
                .map_err(postgres_error)?
                .and_then(|row| row.get::<_, Option<i64>>(0))
                .map(nonnegative_u64),
            None => None,
        };

        // #458: tenant-scope quota pressure. The current-month cost and the
        // stored-asset bytes are aggregated server-side (GROUP BY, not streamed)
        // and joined to each tenant quota policy that defines a cap. Tenant scope
        // is a direct `scope_id` match, so no cross-tenant number is built.
        let pressure_rows = transaction
            .query(
                "SELECT qp.scope_id, qp.monthly_budget_usd, qp.asset_storage_quota_bytes, \
                        COALESCE(c.cost, 0)::double precision, COALESCE(a.bytes, 0)::bigint \
                 FROM quota_policies qp \
                 LEFT JOIN ( \
                     SELECT scope_id, SUM(cost_usd) AS cost FROM usage_monthly_rollups \
                     WHERE scope_type = 'tenant' AND period_month = $2 GROUP BY scope_id \
                 ) c ON c.scope_id = qp.scope_id \
                 LEFT JOIN ( \
                     SELECT tenant_id, SUM(size_bytes) AS bytes FROM stored_assets GROUP BY tenant_id \
                 ) a ON a.tenant_id = qp.scope_id \
                 WHERE qp.scope_type = 'tenant' \
                   AND (qp.monthly_budget_usd IS NOT NULL OR qp.asset_storage_quota_bytes IS NOT NULL) \
                   AND ($1::text IS NULL OR qp.scope_id = $1)",
                &[&scope, &current_period_month],
            )
            .await
            .map_err(postgres_error)?;
        let mut quota_pressure_candidates = Vec::new();
        for row in &pressure_rows {
            let scope_id: String = row.get(0);
            let budget: Option<f64> = row.get(1);
            let asset_cap: Option<i64> = row.get(2);
            let cost: f64 = row.get(3);
            let bytes = nonnegative_u64(row.get::<_, i64>(4));
            if let Some(budget) = budget {
                quota_pressure_candidates.push(quota_pressure_scope(
                    &scope_id,
                    "monthly_budget_usd",
                    "usd",
                    cost,
                    budget,
                ));
            }
            if let Some(cap) = asset_cap {
                quota_pressure_candidates.push(quota_pressure_scope(
                    &scope_id,
                    "asset_storage_bytes",
                    "bytes",
                    bytes as f64,
                    cap as f64,
                ));
            }
        }
        let quota_pressure = build_quota_pressure(quota_pressure_candidates);

        // #458: pending tool approvals, tenant-scoped by the record's
        // organization_id. Read the bounded tool_approval documents and classify
        // in-process (their `status` lives inside the JSON payload).
        let approval_rows = transaction
            .query(
                "SELECT document_json::text FROM control_plane_resources \
                 WHERE resource_kind = 'tool_approval'",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        let approval_documents: Vec<String> = approval_rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();
        let pending_tool_approvals = count_pending_tool_approvals(&approval_documents, scope);

        // #458: policy-governance inventory is global-only (guardrail revisions/
        // bindings carry no tenant column; quota/policy tables are not per-tenant
        // attributable without a join). A tenant-scoped caller gets `None`.
        let policy_governance = if scope.is_none() {
            Some(PolicyGovernanceCounts {
                guardrail_policy_revisions: Self::overview_total_count(
                    &transaction,
                    "SELECT COUNT(*)::bigint FROM guardrail_policy_revisions",
                )
                .await?,
                guardrail_policy_bindings: Self::overview_total_count(
                    &transaction,
                    "SELECT COUNT(*)::bigint FROM guardrail_policy_bindings",
                )
                .await?,
                quota_policies: Self::overview_total_count(
                    &transaction,
                    "SELECT COUNT(*)::bigint FROM quota_policies",
                )
                .await?,
                policy_rules: Self::overview_total_count(
                    &transaction,
                    "SELECT COUNT(*)::bigint FROM control_plane_resources \
                     WHERE resource_kind = 'policy'",
                )
                .await?,
            })
        } else {
            None
        };

        transaction.commit().await.map_err(postgres_error)?;
        Ok(ControlPlaneOverviewAggregate {
            tenants,
            projects,
            workspaces,
            virtual_keys,
            virtual_keys_enabled,
            assets,
            asset_storage_bytes,
            assets_referenced,
            asset_storage_quota_bytes,
            agent_runs,
            agent_runs_by_status,
            self_hosted_workers,
            self_hosted_workers_by_status,
            pending_tool_approvals,
            quota_pressure,
            policy_governance,
            usage_lifetime,
            usage_current_month,
        })
    }

    /// Reads a single-row scalar `COUNT(*)::bigint` aggregate (bound param
    /// `$1` is the tenant scope) for the overview pushdown.
    async fn overview_scalar_count(
        transaction: &deadpool_postgres::Transaction<'_>,
        sql: &'static str,
        scope: Option<&str>,
    ) -> Result<u64, StorageError> {
        let row = transaction
            .query_one(sql, &[&scope])
            .await
            .map_err(postgres_error)?;
        Ok(nonnegative_u64(row.get::<_, i64>(0)))
    }

    /// Reads a single-row scalar `COUNT(*)::bigint` aggregate that takes no bound
    /// parameters (#458), used for the global-only policy-governance counts.
    async fn overview_total_count(
        transaction: &deadpool_postgres::Transaction<'_>,
        sql: &'static str,
    ) -> Result<u64, StorageError> {
        let row = transaction
            .query_one(sql, &[])
            .await
            .map_err(postgres_error)?;
        Ok(nonnegative_u64(row.get::<_, i64>(0)))
    }

    /// Runs one `SELECT status, COUNT(*) ... GROUP BY status` histogram query
    /// and returns `(total, status -> count)`. Keeping the status buckets a
    /// database GROUP BY (rather than hardcoded status strings) means new
    /// run/worker states surface in the overview without a schema change.
    async fn overview_status_histogram(
        transaction: &deadpool_postgres::Transaction<'_>,
        sql: &'static str,
        scope: Option<&str>,
    ) -> Result<(u64, std::collections::BTreeMap<String, u64>), StorageError> {
        let rows = transaction
            .query(sql, &[&scope])
            .await
            .map_err(postgres_error)?;
        let mut total = 0_u64;
        let mut by_status = std::collections::BTreeMap::new();
        for row in &rows {
            let status: String = row.get(0);
            let count = nonnegative_u64(row.get::<_, i64>(1));
            total = total.saturating_add(count);
            by_status.insert(status, count);
        }
        Ok((total, by_status))
    }
}
