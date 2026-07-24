// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: The `ControlPlaneStore` engine-abstraction trait (#419/#425),
// the in-memory backend struct (`MemoryControlPlaneStore`), and the
// `RuntimeControlPlaneBackend::store()` dispatch seam. The two backend impls
// live in the sibling `control_plane_store_postgres` /
// `control_plane_store_memory` modules per the thin-lib.rs modular layout
// standard (#429).

use super::*;

/// Async engine abstraction over the control-plane store surface (#419/#425).
///
/// Extracted from the inherent CRUD methods of [`PostgresControlPlaneStore`] so
/// a third backend (e.g. per-tenant Cloudflare D1) can be added by implementing
/// this trait and adding one arm to [`RuntimeControlPlaneBackend::store`],
/// instead of editing every dispatch method. The Postgres backend forwards to
/// its existing inherent methods; the in-memory backend is
/// [`MemoryControlPlaneStore`].
///
/// #425 scope decisions for the surfaces that are NOT (fully) on this trait:
///
/// * [`GuardrailPolicyRepository`] and [`SnapshotReplayFloorRepository`] stay
///   as separate PUBLIC traits (they are the caller-facing seams and tests
///   implement them with non-backend fakes), but their
///   `RuntimeStorageRepositories` impls forward through `store()`: the whole
///   method surface is mirrored on this trait, so a new backend implements it
///   here and touches no enum arm.
/// * `McpCredentialRepository` stays SEPARATE and enum-dispatched inside
///   `mcp_identity.rs`: its methods thread `StorageOperation` commit fences
///   through both arms and its memory path borrows the locked state directly
///   (`memory_authorize_mcp_actor(&store, ..)`), which does not reduce to the
///   uniform forwarding shape used here. A D1 backend implements
///   `McpCredentialRepository`'s postgres-side inherent methods and adds arms
///   in that one module.
/// * `GuardrailEvaluationRepository` (in `guardrail_evidence.rs`) also stays
///   SEPARATE and enum-dispatched (#437): its Memory path does NOT touch the
///   control-plane backend at all — it borrows the in-memory
///   `RuntimeStorageRepositories::guardrail_evidence` append store directly,
///   and its Postgres path threads the store-level
///   `guardrail_evaluation_retention_records` count into the durable write.
///   Neither reduces to the `self.store()...` forwarding shape (the evidence
///   store is a `RuntimeStorageRepositories` field shared across all backends,
///   not owned by any one `ControlPlaneStore`), so a D1 backend implements the
///   postgres-side inherent guardrail methods and adds arms in that one module,
///   exactly like `McpCredentialRepository`.
/// * The remaining per-entity modules (wallet, payment attempts, RBAC, agent
///   schedules, site domains, budget alerts, workflow budgets, observed agent
///   presence, metadata rollups) ARE routed onto this trait as of #437 — their
///   `RuntimeStorageRepositories` methods now call `self.store()...` with the
///   same forwarding contract as the #425 surfaces. The asset-lifecycle
///   transactions were already on this trait (the asset/channel CRUD methods
///   above); `asset_lifecycle.rs` itself is pure retention-planning helpers
///   with no backend dispatch.
#[async_trait::async_trait]
pub(crate) trait ControlPlaneStore: Send + Sync {
    async fn upsert_api_key_record(&self, api_key: StoredApiKey) -> Result<(), StorageError>;
    async fn get_api_key_record(&self, id: &str) -> Result<Option<StoredApiKey>, StorageError>;
    async fn list_api_key_records(&self) -> Result<Vec<StoredApiKey>, StorageError>;
    async fn find_api_key_records_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError>;
    async fn upsert_admin_user(&self, user: StoredAdminUser) -> Result<(), StorageError>;
    async fn get_admin_user_by_id(&self, id: &str)
        -> Result<Option<StoredAdminUser>, StorageError>;
    async fn get_admin_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAdminUser>, StorageError>;
    async fn upsert_admin_user_membership(
        &self,
        membership: StoredAdminUserMembership,
    ) -> Result<(), StorageError>;
    async fn list_admin_user_memberships_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError>;
    async fn list_admin_user_memberships_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredAdminUserMembership>, StorageError>;
    async fn delete_admin_user_membership(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError>;
    async fn upsert_sso_provider_config(
        &self,
        config: StoredSsoProviderConfig,
    ) -> Result<(), StorageError>;
    async fn get_sso_provider_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredSsoProviderConfig>, StorageError>;
    async fn delete_sso_provider_config(&self, tenant_id: &str) -> Result<bool, StorageError>;
    async fn insert_sso_pending_flow(&self, flow: StoredSsoPendingFlow)
        -> Result<(), StorageError>;
    async fn take_sso_pending_flow(
        &self,
        state: &str,
        now_unix: i64,
    ) -> Result<Option<StoredSsoPendingFlow>, StorageError>;
    async fn upsert_admin_user_refresh_token(
        &self,
        token: StoredAdminUserRefreshToken,
    ) -> Result<(), StorageError>;
    async fn get_admin_user_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredAdminUserRefreshToken>, StorageError>;
    async fn revoke_all_admin_user_refresh_tokens(
        &self,
        user_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError>;
    async fn revoke_admin_user_refresh_tokens_for_tenant(
        &self,
        user_id: &str,
        tenant_id: &str,
        revoked_at_unix: i64,
    ) -> Result<u64, StorageError>;
    async fn upsert_tenant_account(&self, account: StoredTenantAccount)
        -> Result<(), StorageError>;
    async fn get_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError>;
    async fn list_tenant_accounts(&self) -> Result<Vec<StoredTenantAccount>, StorageError>;
    async fn upsert_project(&self, project: StoredProject) -> Result<(), StorageError>;
    async fn get_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError>;
    async fn list_projects(&self) -> Result<Vec<StoredProject>, StorageError>;
    async fn delete_project(&self, id: &str) -> Result<bool, StorageError>;
    async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError>;
    async fn upsert_workspace(&self, workspace: StoredWorkspace) -> Result<(), StorageError>;
    async fn get_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError>;
    async fn list_workspaces(&self) -> Result<Vec<StoredWorkspace>, StorageError>;
    async fn delete_workspace(&self, id: &str) -> Result<bool, StorageError>;
    async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError>;
    async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError>;
    async fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> Result<(), StorageError>;
    async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<Option<StoredQuotaPolicy>, StorageError>;
    async fn list_quota_policies(&self) -> Result<Vec<StoredQuotaPolicy>, StorageError>;
    async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> Result<bool, StorageError>;
    async fn upsert_plan(&self, plan: StoredPlan) -> Result<(), StorageError>;
    async fn get_plan(&self, id: &str) -> Result<Option<StoredPlan>, StorageError>;
    async fn list_plans(&self) -> Result<Vec<StoredPlan>, StorageError>;
    async fn upsert_asset(&self, asset: StoredAsset) -> Result<(), StorageError>;
    async fn create_asset_if_absent(&self, asset: StoredAsset) -> Result<bool, StorageError>;
    async fn create_asset_within_quota(
        &self,
        asset: StoredAsset,
        quota_bytes: Option<u64>,
    ) -> Result<AssetQuotaAdmission, StorageError>;
    async fn get_asset(&self, id: &str) -> Result<Option<StoredAsset>, StorageError>;
    async fn list_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError>;
    async fn list_withheld_assets(
        &self,
        tenant_id: &str,
        asset_type: Option<&str>,
    ) -> Result<Vec<StoredAsset>, StorageError>;
    async fn tenant_asset_storage_bytes_used(&self, tenant_id: &str) -> Result<u64, StorageError>;
    async fn delete_asset(&self, id: &str) -> Result<bool, StorageError>;
    async fn upsert_asset_channel(&self, channel: StoredAssetChannel) -> Result<(), StorageError>;
    async fn list_asset_channels(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
    ) -> Result<Vec<StoredAssetChannel>, StorageError>;
    async fn delete_asset_channel(&self, id: &str) -> Result<bool, StorageError>;
    async fn move_asset_channel_if_resolvable(
        &self,
        channel: StoredAssetChannel,
    ) -> Result<ChannelMoveOutcome, StorageError>;
    #[allow(clippy::too_many_arguments)]
    async fn set_asset_version_yank(
        &self,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
        yanked: bool,
        now_unix: i64,
    ) -> Result<VersionYankOutcome, StorageError>;
    async fn delete_asset_variant_if_unreferenced(
        &self,
        id: &str,
        tenant_id: &str,
        asset_type: &str,
        name: &str,
        version: &str,
    ) -> Result<VariantDeleteOutcome, StorageError>;
    async fn promote_pending_asset_visibility(
        &self,
        id: &str,
        target: AssetPromotionTarget,
        now_unix: i64,
    ) -> Result<AssetVisibilityPromotionOutcome, StorageError>;
    async fn upsert_retention_policy(
        &self,
        policy: StoredRetentionPolicy,
    ) -> Result<(), StorageError>;
    async fn list_retention_policies(
        &self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Vec<StoredRetentionPolicy>, StorageError>;
    async fn list_all_assets(&self) -> Result<Vec<StoredAsset>, StorageError>;
    async fn list_all_asset_channels(&self) -> Result<Vec<StoredAssetChannel>, StorageError>;
    async fn get_usage_monthly_rollup(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Option<StoredUsageMonthlyRollup>, StorageError>;
    async fn list_usage_monthly_rollups(
        &self,
    ) -> Result<Vec<StoredUsageMonthlyRollup>, StorageError>;
    async fn append_billing_ledger_entry(
        &self,
        entry: &ferrogate_billing::LedgerEntry,
    ) -> Result<bool, StorageError>;
    async fn list_billing_ledger_entries(
        &self,
        filter: &ferrogate_billing::LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ferrogate_billing::LedgerEntry>, StorageError>;
    async fn billing_ledger_entry(
        &self,
        id: &str,
    ) -> Result<Option<ferrogate_billing::LedgerEntry>, StorageError>;
    async fn enqueue_billing_report(
        &self,
        id: &str,
        event: &ferrogate_billing::BillingEvent,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError>;
    async fn list_due_billing_reports(
        &self,
        now_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError>;
    async fn reschedule_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<(), StorageError>;
    async fn dead_letter_billing_report(
        &self,
        id: &str,
        dead_lettered_at_unix: i64,
    ) -> Result<(), StorageError>;
    async fn list_dead_lettered_billing_reports(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBillingReportOutboxEntry>, StorageError>;
    async fn replay_dead_lettered_billing_report(
        &self,
        id: &str,
        next_attempt_unix: i64,
    ) -> Result<ReplayDeadLetterOutcome, StorageError>;
    async fn get_billing_report_outbox_entry(
        &self,
        id: &str,
    ) -> Result<Option<StoredBillingReportOutboxEntry>, StorageError>;
    async fn delete_billing_report(&self, id: &str) -> Result<(), StorageError>;

    // --- Sync document-config surface (#425) ---
    //
    // The JSON control-plane config documents (policy / gateway_config /
    // agent_workflow / skill_package / prompt_template / plugin_registration /
    // mcp_server / agent_upstream / tool_approval / api_key / tenant) are
    // stored kind-keyed on every backend, so the trait carries ONE generic
    // kind-based method per operation instead of per-kind methods. The
    // in-memory backend maps each kind onto its per-kind state methods; the
    // Postgres backend forwards to its generic kind-based SQL methods.
    fn upsert_config_document(
        &self,
        kind: &'static str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError>;
    fn delete_config_document(&self, kind: &'static str, id: &str) -> Result<bool, StorageError>;
    fn get_config_document(
        &self,
        kind: &'static str,
        id: &str,
    ) -> Result<Option<String>, StorageError>;
    fn list_config_documents(&self, kind: &'static str) -> Result<Vec<String>, StorageError>;
    fn list_config_resource_documents(
        &self,
        kind: &'static str,
    ) -> Result<Vec<(String, String)>, StorageError>;
    fn replace_config_documents(
        &self,
        documents: ControlPlaneDocuments,
    ) -> Result<(), StorageError>;
    fn control_plane_snapshot(&self) -> Result<ControlPlaneSnapshot, StorageError>;
    fn config_documents(&self) -> Result<ControlPlaneDocuments, StorageError>;

    // --- Guardrail policy revisions + bindings (#425) ---
    //
    // Mirrors the public [`GuardrailPolicyRepository`] trait so its
    // `RuntimeStorageRepositories` impl forwards through `store()` instead of
    // matching the backend enum per method. The public trait stays separate:
    // it is the caller-facing seam and is also implemented by non-backend
    // fakes in tests.
    fn insert_guardrail_policy_revision(
        &self,
        revision: StoredGuardrailPolicyRevision,
    ) -> Result<(), StorageError>;
    fn get_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
    ) -> Result<Option<StoredGuardrailPolicyRevision>, StorageError>;
    fn list_guardrail_policy_revisions(
        &self,
        policy_id: Option<&str>,
    ) -> Result<Vec<StoredGuardrailPolicyRevision>, StorageError>;
    fn get_guardrail_policy_binding(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredGuardrailPolicyBinding>, StorageError>;
    fn list_guardrail_policy_bindings(
        &self,
    ) -> Result<Vec<StoredGuardrailPolicyBinding>, StorageError>;
    fn activate_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
        rollback_only: bool,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError>;
    fn archive_guardrail_policy_revision(
        &self,
        policy_id: &str,
        revision: u32,
        updated_by: &str,
        updated_at_unix: u64,
    ) -> Result<GuardrailPolicyBindingTransition, StorageError>;
    fn restore_guardrail_policy_binding(
        &self,
        policy_id: &str,
        expected_generation: Option<u64>,
        binding: Option<StoredGuardrailPolicyBinding>,
    ) -> Result<(), StorageError>;

    // --- Signed-snapshot replay floors (#425) ---
    //
    // Mirrors the public [`SnapshotReplayFloorRepository`] trait; same
    // forwarding rationale as the guardrail surface above.
    fn get_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
    ) -> Result<Option<u64>, StorageError>;
    fn advance_snapshot_replay_floor(
        &self,
        tenant_id: &str,
        deployment_id: &str,
        revision: u64,
        updated_at_unix: i64,
    ) -> Result<u64, StorageError>;

    // --- High-write append/analytics stores (#425) ---
    //
    // Relocated from per-method enum dispatch in `RuntimeStorageRepositories`.
    // The in-memory backend serves these from bounded store-local repositories
    // (previously fields on `RuntimeStorageRepositories`); the Postgres
    // backend forwards to its inherent SQL methods and owns the opportunistic
    // durable prune-on-write scheduling (issue #231).
    fn set_retention_limits(
        &self,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    );
    async fn append_request_log(&self, log: StoredRequestLog);
    async fn request_logs(&self) -> Vec<StoredRequestLog>;
    async fn request_logs_page(&self, offset: usize, limit: usize)
        -> StoragePage<StoredRequestLog>;
    async fn delete_request_logs(&self, request_ids: &[String]) -> Result<u64, StorageError>;
    async fn request_logs_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredRequestLog>;
    async fn append_audit_event(&self, event: StoredAuditEvent);
    fn next_audit_event_id(&self) -> String;
    async fn audit_events(&self) -> Vec<StoredAuditEvent>;
    async fn audit_events_page(&self, offset: usize, limit: usize)
        -> StoragePage<StoredAuditEvent>;
    async fn delete_audit_events(&self, ids: &[String]) -> Result<u64, StorageError>;
    async fn audit_events_for_agent_runs(&self, run_ids: &[String]) -> Vec<StoredAuditEvent>;
    async fn append_billing_event(&self, event: BillingEvent) -> Result<bool, StorageError>;
    async fn append_billing_event_with_outbox_enqueue(
        &self,
        event: BillingEvent,
        outbox_id: &str,
        outbox_next_attempt_unix: i64,
    ) -> Result<BillingEventAppendOutcome, StorageError>;
    async fn billing_events(&self) -> Vec<BillingEvent>;
    async fn billing_events_page(&self, offset: usize, limit: usize) -> StoragePage<BillingEvent>;
    /// Read-modify-write of the PROCESS-LOCAL usage-aggregate store under one
    /// lock. Every backend keeps this local mirror: it is the store of record
    /// on Memory and the read-modify-write baseline on durable backends
    /// (pre-existing semantics, preserved verbatim by #425).
    fn upsert_usage_aggregate_local(
        &self,
        id: String,
        build: &mut dyn FnMut(Option<StoredUsageAggregate>) -> StoredUsageAggregate,
    ) -> Result<StoredUsageAggregate, StorageError>;
    fn store_usage_aggregate_local(
        &self,
        aggregate: StoredUsageAggregate,
    ) -> Result<(), StorageError>;
    /// Durable write-through half of the usage-aggregate upsert; a no-op on
    /// the in-memory backend.
    async fn persist_usage_aggregate(
        &self,
        aggregate: &StoredUsageAggregate,
    ) -> Result<(), StorageError>;
    async fn usage_aggregates(&self) -> Vec<StoredUsageAggregate>;
    async fn sum_api_key_committed_tokens(&self, api_key_id: &str) -> u64;
    async fn upsert_agent_run(&self, run: StoredAgentRun) -> Result<(), StorageError>;
    async fn agent_run(&self, id: &str) -> Option<StoredAgentRun>;
    async fn agent_runs(&self) -> Vec<StoredAgentRun>;
    async fn agent_runs_by_ids(&self, run_ids: &[String]) -> Vec<StoredAgentRun>;
    async fn append_agent_run_event(&self, event: StoredAgentRunEvent) -> Result<(), StorageError>;
    async fn agent_run_events(&self) -> Vec<StoredAgentRunEvent>;
    async fn agent_run_events_for_runs(&self, run_ids: &[String]) -> Vec<StoredAgentRunEvent>;
    async fn agent_run_summary_seed_ids(
        &self,
        request_id: Option<&str>,
        limit: usize,
    ) -> Vec<String>;
    async fn upsert_managed_worker_template(
        &self,
        template: StoredManagedWorkerTemplate,
    ) -> Result<(), StorageError>;
    async fn managed_worker_templates(&self) -> Vec<StoredManagedWorkerTemplate>;
    async fn upsert_agent_worker_instance(
        &self,
        instance: StoredAgentWorkerInstance,
    ) -> Result<(), StorageError>;
    async fn agent_worker_instances(&self) -> Vec<StoredAgentWorkerInstance>;
    async fn upsert_managed_worker_session(
        &self,
        session: StoredManagedWorkerSession,
    ) -> Result<(), StorageError>;
    async fn managed_worker_sessions(&self) -> Vec<StoredManagedWorkerSession>;
    async fn append_managed_worker_lifecycle_event(
        &self,
        event: StoredManagedWorkerLifecycleEvent,
    ) -> Result<(), StorageError>;
    async fn managed_worker_lifecycle_events(&self) -> Vec<StoredManagedWorkerLifecycleEvent>;
    async fn upsert_managed_worker_isolation_selection(
        &self,
        selection: StoredManagedWorkerIsolationSelection,
    ) -> Result<(), StorageError>;
    async fn managed_worker_isolation_selections(
        &self,
    ) -> Vec<StoredManagedWorkerIsolationSelection>;
    async fn upsert_managed_worker_isolation_policy(
        &self,
        policy: StoredManagedWorkerIsolationPolicy,
    ) -> Result<(), StorageError>;
    async fn managed_worker_isolation_policies(&self) -> Vec<StoredManagedWorkerIsolationPolicy>;
    async fn upsert_managed_worker_isolation_evidence(
        &self,
        evidence: StoredManagedWorkerIsolationEvidence,
    ) -> Result<(), StorageError>;
    async fn managed_worker_isolation_evidence(&self) -> Vec<StoredManagedWorkerIsolationEvidence>;
    async fn upsert_self_hosted_worker_registration(
        &self,
        registration: StoredSelfHostedWorkerRegistration,
    ) -> Result<(), StorageError>;
    async fn self_hosted_worker_registrations(&self) -> Vec<StoredSelfHostedWorkerRegistration>;
    async fn self_hosted_worker_registration(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerRegistration>;
    async fn latest_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
    ) -> Option<StoredSelfHostedWorkerHeartbeat>;
    async fn self_hosted_worker_activity_stats(
        &self,
        worker_id: &str,
    ) -> StoredSelfHostedWorkerActivityStats;
    async fn append_self_hosted_worker_heartbeat(
        &self,
        heartbeat: StoredSelfHostedWorkerHeartbeat,
    ) -> Result<(), StorageError>;
    async fn self_hosted_worker_heartbeats(&self) -> Vec<StoredSelfHostedWorkerHeartbeat>;
    async fn append_self_hosted_worker_telemetry_event(
        &self,
        event: StoredSelfHostedWorkerTelemetryEvent,
    ) -> Result<(), StorageError>;
    async fn self_hosted_worker_telemetry_events(
        &self,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent>;
    async fn self_hosted_worker_telemetry_events_for_run(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent>;
    async fn self_hosted_worker_telemetry_events_for_worker(
        &self,
        worker_id: &str,
    ) -> Vec<StoredSelfHostedWorkerTelemetryEvent>;
    async fn upsert_self_hosted_worker_artifact(
        &self,
        artifact: StoredSelfHostedWorkerArtifact,
    ) -> Result<(), StorageError>;
    async fn self_hosted_worker_artifacts(&self) -> Vec<StoredSelfHostedWorkerArtifact>;
    async fn self_hosted_worker_artifact(&self, id: &str)
        -> Option<StoredSelfHostedWorkerArtifact>;
    async fn upsert_self_hosted_worker_checkpoint(
        &self,
        checkpoint: StoredSelfHostedWorkerCheckpoint,
    ) -> Result<(), StorageError>;
    async fn self_hosted_worker_checkpoints(&self) -> Vec<StoredSelfHostedWorkerCheckpoint>;
    async fn self_hosted_worker_checkpoint(
        &self,
        id: &str,
    ) -> Option<StoredSelfHostedWorkerCheckpoint>;
    async fn upsert_self_hosted_run_dispatch(
        &self,
        dispatch: StoredSelfHostedRunDispatch,
    ) -> Result<(), StorageError>;
    async fn self_hosted_run_dispatches(&self) -> Vec<StoredSelfHostedRunDispatch>;

    // --- Per-entity module surfaces (#437) ---
    //
    // Relocated here from the per-module `RuntimeStorageRepositories`
    // backend-enum dispatch (wallet, payment attempts, RBAC, agent schedules,
    // site domains, budget alerts, workflow budgets, observed agent presence,
    // metadata rollups). Same forwarding contract as the #425 surfaces above:
    // Postgres forwards to its inherent SQL method, Memory locks its
    // `RuntimeControlPlaneState`, and the D1 backend returns the typed
    // `unimplemented-backend-surface` error until a proxy-Worker impl fills it.
    // `guardrail_evidence` and `mcp_identity` stay SEPARATE and enum-dispatched
    // (see the keep-separate notes above / in `guardrail_evidence.rs`).

    // Site domains (#265).
    async fn upsert_site_domain(&self, domain: StoredSiteDomain) -> Result<(), StorageError>;
    async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError>;
    async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError>;
    async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError>;

    // Per-metadata usage rollups (#171).
    async fn list_usage_metadata_rollups(
        &self,
        metadata_key: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<StoredUsageMetadataRollup>, StorageError>;

    // Observed-agent presence (#357).
    async fn touch_observed_agent_presence(
        &self,
        touch: ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError>;
    async fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError>;

    // Budget-alert idempotency ledger (#170).
    async fn record_budget_alert_notification(
        &self,
        notification: StoredBudgetAlertNotification,
    ) -> Result<(), StorageError>;
    async fn budget_alert_already_notified(&self, id: &str) -> Result<bool, StorageError>;
    async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError>;

    // Workflow-run execution budgets (#279).
    #[allow(clippy::too_many_arguments)]
    async fn open_workflow_run_budget(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError>;
    async fn debit_workflow_run_budget(
        &self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Result<WorkflowBudgetDebit, StorageError>;
    #[allow(clippy::too_many_arguments)]
    async fn topup_workflow_run_budget(
        &self,
        id: &str,
        add_cost_credits: i64,
        add_tokens: i64,
        add_tool_calls: i64,
        extend_deadline_unix: Option<i64>,
        now_unix: i64,
    ) -> Result<StoredWorkflowRunBudget, StorageError>;
    async fn get_workflow_run_budget(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkflowRunBudget>, StorageError>;
    async fn list_workflow_run_budgets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWorkflowRunBudget>, StorageError>;

    // Tenant RBAC entitlements (#182).
    async fn upsert_permission(&self, permission: StoredPermission) -> Result<(), StorageError>;
    async fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError>;
    async fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError>;
    async fn delete_permission(&self, id: &str) -> Result<bool, StorageError>;
    async fn upsert_role(&self, role: StoredRole) -> Result<(), StorageError>;
    async fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError>;
    async fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError>;
    async fn delete_role(&self, id: &str) -> Result<bool, StorageError>;
    async fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> Result<(), StorageError>;
    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError>;
    async fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<bool, StorageError>;

    // Agent schedules + fires (#356/#426).
    async fn upsert_agent_schedule(
        &self,
        schedule: StoredAgentSchedule,
    ) -> Result<(), StorageError>;
    async fn get_agent_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Option<StoredAgentSchedule>, StorageError>;
    async fn list_agent_schedules(
        &self,
        tenant_id: &str,
        workspace_id: Option<&str>,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError>;
    async fn list_all_agent_schedules(&self) -> Result<Vec<StoredAgentSchedule>, StorageError>;
    async fn delete_agent_schedule(&self, schedule_id: &str) -> Result<bool, StorageError>;
    async fn list_due_agent_schedules(
        &self,
        now_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredAgentSchedule>, StorageError>;
    async fn insert_agent_schedule_fire(
        &self,
        fire: StoredAgentScheduleFire,
    ) -> Result<bool, StorageError>;
    async fn list_agent_schedule_fires(
        &self,
        schedule_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredAgentScheduleFire>, StorageError>;

    // Wallets, reservations + payment methods (#169/#281).
    async fn settle_wallet_balance(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError>;
    async fn upsert_wallet(&self, wallet: StoredWallet) -> Result<(), StorageError>;
    async fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError>;
    async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError>;
    async fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError>;
    async fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError>;
    #[allow(clippy::too_many_arguments)]
    async fn reserve_wallet_credits(
        &self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError>;
    async fn settle_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError>;
    async fn release_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError>;
    async fn sweep_expired_wallet_reservations(
        &self,
        now_unix: i64,
    ) -> Result<Vec<String>, StorageError>;
    async fn list_wallet_reservations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError>;
    async fn upsert_payment_method(
        &self,
        payment_method: StoredPaymentMethod,
    ) -> Result<(), StorageError>;
    async fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError>;
    async fn get_payment_method(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentMethod>, StorageError>;
    async fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError>;

    // Payment attempts + the single CAS transition seam (#352/#354/#399).
    async fn create_payment_attempt(
        &self,
        attempt: StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError>;
    async fn get_payment_attempt(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentAttempt>, StorageError>;
    async fn list_payment_attempts(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError>;
    async fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<Option<PaymentAttemptLinks>, StorageError>;
    async fn list_expirable_due_payment_attempts(
        &self,
        due_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError>;
    async fn list_reconcilable_payment_attempts(
        &self,
        checked_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError>;
    /// The one CAS seam every typed payment-attempt transition edge routes
    /// through (#399). `op_name` labels the Postgres StorageOperation; the
    /// Memory backend ignores it. `evidence` is the write-once column bundle
    /// (`super::payment_attempt::TransitionEvidence`).
    #[allow(clippy::too_many_arguments)]
    async fn transition_payment_attempt(
        &self,
        op_name: &'static str,
        id: &str,
        allowed_from: &[&str],
        to_state: &str,
        evidence: &super::payment_attempt::TransitionEvidence<'_>,
        now_unix: i64,
    ) -> Result<PaymentAttemptTransition, StorageError>;

    // --- Backend introspection (#425) ---
    //
    // Default implementations describe a backend with no schema evidence and
    // no connection pool (the in-memory backend); durable backends override.
    fn schema_evidence(&self) -> Option<StorageSchemaEvidence> {
        None
    }
    fn pool_metrics_snapshot(&self) -> PostgresPoolMetricsSnapshot {
        PostgresPoolMetricsSnapshot::default()
    }
}

/// The in-memory control-plane backend (#425).
///
/// Owns the durable-CRUD document state (`RuntimeControlPlaneState`) AND the
/// bounded append/analytics repositories that used to live as fields on
/// `RuntimeStorageRepositories`, so the whole Memory surface sits behind
/// [`ControlPlaneStore`] and adding a backend no longer edits per-method enum
/// arms. Fields are `pub(crate)` because the trait impl lives in the sibling
/// `control_plane_store_memory` module.
pub(crate) struct MemoryControlPlaneStore {
    pub(crate) state: Mutex<RuntimeControlPlaneState>,
    pub(crate) request_logs: Mutex<InMemoryAppendRepository<StoredRequestLog>>,
    pub(crate) audit_events: Mutex<InMemoryAppendRepository<StoredAuditEvent>>,
    pub(crate) usage_aggregates: Mutex<InMemoryRepository<StoredUsageAggregate>>,
    pub(crate) agent_runs: Mutex<InMemoryRepository<StoredAgentRun>>,
    pub(crate) agent_run_events: Mutex<InMemoryAgentRunEventRepository>,
    pub(crate) managed_worker_templates: Mutex<InMemoryRepository<StoredManagedWorkerTemplate>>,
    pub(crate) agent_worker_instances: Mutex<InMemoryRepository<StoredAgentWorkerInstance>>,
    pub(crate) managed_worker_sessions: Mutex<InMemoryRepository<StoredManagedWorkerSession>>,
    pub(crate) managed_worker_lifecycle_events:
        Mutex<InMemoryAppendRepository<StoredManagedWorkerLifecycleEvent>>,
    pub(crate) managed_worker_isolation_selections:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationSelection>>,
    pub(crate) managed_worker_isolation_policies:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationPolicy>>,
    pub(crate) managed_worker_isolation_evidence:
        Mutex<InMemoryRepository<StoredManagedWorkerIsolationEvidence>>,
    pub(crate) self_hosted_worker_registrations:
        Mutex<InMemoryRepository<StoredSelfHostedWorkerRegistration>>,
    pub(crate) self_hosted_worker_heartbeats:
        Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerHeartbeat>>,
    pub(crate) self_hosted_worker_telemetry_events:
        Mutex<InMemoryAppendRepository<StoredSelfHostedWorkerTelemetryEvent>>,
    pub(crate) self_hosted_worker_artifacts:
        Mutex<InMemoryWorkerScopedRepository<StoredSelfHostedWorkerArtifact>>,
    pub(crate) self_hosted_worker_checkpoints:
        Mutex<InMemoryWorkerScopedRepository<StoredSelfHostedWorkerCheckpoint>>,
    pub(crate) self_hosted_run_dispatches: Mutex<InMemoryRepository<StoredSelfHostedRunDispatch>>,
}

impl std::fmt::Debug for MemoryControlPlaneStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryControlPlaneStore")
            .finish_non_exhaustive()
    }
}

impl MemoryControlPlaneStore {
    pub(crate) fn new(
        state: RuntimeControlPlaneState,
        request_log_retention_records: usize,
        audit_event_retention_records: usize,
    ) -> Self {
        Self {
            state: Mutex::new(state),
            request_logs: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                request_log_retention_records,
            )),
            audit_events: Mutex::new(InMemoryAppendRepository::with_retention_limit(
                audit_event_retention_records,
            )),
            usage_aggregates: Mutex::new(InMemoryRepository::new()),
            agent_runs: Mutex::new(InMemoryRepository::new()),
            // Bounded (issue #231): agent-run events previously grew without
            // limit. Per-run cap = the audit retention bound; global cap = a
            // generous multiple, evicting idle runs' events first so an
            // ACTIVE run's timeline is never truncated by another run's
            // flood. See `InMemoryAgentRunEventRepository` for the exact
            // semantics.
            agent_run_events: Mutex::new(InMemoryAgentRunEventRepository::with_limits(
                audit_event_retention_records,
                audit_event_retention_records
                    .saturating_mul(AGENT_RUN_EVENT_GLOBAL_RETENTION_MULTIPLIER),
            )),
            managed_worker_templates: Mutex::new(InMemoryRepository::new()),
            agent_worker_instances: Mutex::new(InMemoryRepository::new()),
            managed_worker_sessions: Mutex::new(InMemoryRepository::new()),
            managed_worker_lifecycle_events: Mutex::new(InMemoryAppendRepository::new()),
            managed_worker_isolation_selections: Mutex::new(InMemoryRepository::new()),
            managed_worker_isolation_policies: Mutex::new(InMemoryRepository::new()),
            managed_worker_isolation_evidence: Mutex::new(InMemoryRepository::new()),
            self_hosted_worker_registrations: Mutex::new(InMemoryRepository::new()),
            // Bounded like the other append-only analytics stores: heartbeats
            // and telemetry are ingested from UNTRUSTED, customer-hosted
            // self-hosted workers over an endpoint that performs no per-worker
            // count/rate cap, so an uncapped store is a memory/DoS vector (and
            // every write clones the whole store). Reuse the audit retention
            // bound so the oldest records are evicted instead of growing without
            // limit.
            self_hosted_worker_heartbeats: Mutex::new(
                InMemoryAppendRepository::with_retention_limit(audit_event_retention_records),
            ),
            self_hosted_worker_telemetry_events: Mutex::new(
                InMemoryAppendRepository::with_retention_limit(audit_event_retention_records),
            ),
            // Bounded (issue #231): a worker can create unbounded DISTINCT
            // artifact/checkpoint ids for its own rows, so the keyed stores
            // get a per-worker distinct-id cap with oldest-eviction. See
            // `InMemoryWorkerScopedRepository` for the exact semantics.
            self_hosted_worker_artifacts: Mutex::new(
                InMemoryWorkerScopedRepository::with_per_worker_limit(
                    audit_event_retention_records,
                ),
            ),
            self_hosted_worker_checkpoints: Mutex::new(
                InMemoryWorkerScopedRepository::with_per_worker_limit(
                    audit_event_retention_records,
                ),
            ),
            self_hosted_run_dispatches: Mutex::new(InMemoryRepository::new()),
        }
    }

    /// Lock the durable-CRUD document state. Named `lock` so the pre-#425
    /// enum-dispatch call sites in the entity modules
    /// (`control_plane.lock()`, previously on `Mutex<RuntimeControlPlaneState>`)
    /// compile unchanged against the relocated store.
    pub(crate) fn lock(
        &self,
    ) -> std::sync::LockResult<std::sync::MutexGuard<'_, RuntimeControlPlaneState>> {
        self.state.lock()
    }
}

impl RuntimeControlPlaneBackend {
    /// Returns the active backend as a `ControlPlaneStore` trait object so
    /// dispatch methods route through one trait call instead of matching the
    /// enum per method (#419).
    pub(crate) fn store(&self) -> &dyn ControlPlaneStore {
        match self {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane.as_ref(),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.as_ref(),
            RuntimeControlPlaneBackend::CloudflareD1(control_plane) => control_plane.as_ref(),
        }
    }
}
