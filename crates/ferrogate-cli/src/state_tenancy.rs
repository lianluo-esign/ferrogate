// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the multi-tenant control-plane
// hierarchy (TOK-11/TOK-12) -- tenant-account, sellable-plan, project,
// workspace, virtual-key, and quota-policy CRUD.

use super::*;

use crate::auth::AuthError;
use crate::lifecycle_gate::{LifecycleSeam, TenancyRefs};

impl AppState {
    pub(crate) async fn list_tenant_accounts(&self) -> anyhow::Result<Vec<StoredTenantAccount>> {
        Ok(self.repositories.list_tenant_accounts().await?)
    }

    pub(crate) async fn get_tenant_account(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<StoredTenantAccount>> {
        Ok(self.repositories.get_tenant_account(id).await?)
    }

    pub(crate) async fn upsert_tenant_account(
        &self,
        account: StoredTenantAccount,
    ) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_tenant_account(account).await?)
    }

    /// Resolves a tenant's assigned plan (issue #168), if any -- the tenant
    /// account's `plan_id` may point at a plan that no longer exists, in
    /// which case this returns `Ok(None)` rather than an error, matching
    /// [`resolve_effective_quota`]'s existing fail-open-to-no-plan-defaults
    /// behavior for a missing plan row.
    pub(crate) async fn resolve_tenant_plan(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<StoredPlan>> {
        let Some(account) = self.repositories.get_tenant_account(tenant_id).await? else {
            return Ok(None);
        };
        Ok(self.repositories.get_plan(&account.plan_id).await?)
    }

    pub(crate) async fn list_plans(&self) -> anyhow::Result<Vec<StoredPlan>> {
        Ok(self.repositories.list_plans().await?)
    }

    pub(crate) async fn get_plan(&self, id: &str) -> anyhow::Result<Option<StoredPlan>> {
        Ok(self.repositories.get_plan(id).await?)
    }

    pub(crate) async fn upsert_plan(&self, plan: StoredPlan) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_plan(plan).await?)
    }

    pub(crate) async fn list_projects(&self) -> anyhow::Result<Vec<StoredProject>> {
        Ok(self.repositories.list_projects().await?)
    }

    /// Bounded control-plane inventory + durable-usage aggregate for the #339
    /// `GET /admin/v1/overview` endpoint. `tenant_scope = Some(tenant_id)`
    /// restricts every count/sum to that tenant (a tenant-scoped console can
    /// never read another tenant's totals); `None` is the platform-operator
    /// global view. Backed by COUNT/SUM pushdown on Postgres and an in-process
    /// fold over the same repositories elsewhere.
    pub(crate) async fn control_plane_overview_aggregate(
        &self,
        tenant_scope: Option<&str>,
        current_period_month: &str,
    ) -> anyhow::Result<ferrogate_storage::ControlPlaneOverviewAggregate> {
        Ok(self
            .repositories
            .overview_aggregate(tenant_scope, current_period_month)
            .await?)
    }

    /// Durable per-agent cost-burn rows for `period`, biggest accumulated total
    /// first (#428 slice B-surface). `tenant_scope = Some(tenant_id)` restricts
    /// to that tenant so a tenant-scoped admin surface can never read another
    /// tenant's burn; `None` is the platform-operator cross-tenant view. Backs
    /// the `GET /admin/v1/agent-cost-burn` observability read.
    pub(crate) async fn list_agent_cost_burn(
        &self,
        tenant_scope: Option<&str>,
        period: &str,
    ) -> anyhow::Result<Vec<ferrogate_storage::StoredAgentCostBurn>> {
        Ok(self
            .repositories
            .list_agent_cost_burn(tenant_scope, period)
            .await?)
    }

    pub(crate) async fn get_project(&self, id: &str) -> anyhow::Result<Option<StoredProject>> {
        Ok(self.repositories.get_project(id).await?)
    }

    pub(crate) async fn upsert_project(&self, project: StoredProject) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_project(project).await?)
    }

    /// Atomic reject-if-referenced project delete (issue #328, finding 4).
    /// Replaces the former separate list-children + `delete_project` round
    /// trips, closing the TOCTOU window where a workspace/key created
    /// between the count and the delete was silently `ON DELETE CASCADE`d.
    pub(crate) async fn delete_project_if_unreferenced(
        &self,
        id: &str,
    ) -> anyhow::Result<DeleteProjectOutcome> {
        Ok(self.repositories.delete_project_if_unreferenced(id).await?)
    }

    pub(crate) async fn list_workspaces(&self) -> anyhow::Result<Vec<StoredWorkspace>> {
        Ok(self.repositories.list_workspaces().await?)
    }

    pub(crate) async fn get_workspace(&self, id: &str) -> anyhow::Result<Option<StoredWorkspace>> {
        Ok(self.repositories.get_workspace(id).await?)
    }

    pub(crate) async fn upsert_workspace(&self, workspace: StoredWorkspace) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_workspace(workspace).await?)
    }

    /// Atomic reject-if-referenced workspace delete (issue #328, finding 4).
    /// See [`AppState::delete_project_if_unreferenced`].
    pub(crate) async fn delete_workspace_if_unreferenced(
        &self,
        id: &str,
    ) -> anyhow::Result<DeleteWorkspaceOutcome> {
        Ok(self
            .repositories
            .delete_workspace_if_unreferenced(id)
            .await?)
    }

    pub(crate) async fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Option<WorkspaceScope>> {
        Ok(self
            .repositories
            .resolve_workspace_scope(workspace_id)
            .await?)
    }

    /// Build the attribution [`ferrogate_core::TenantContext`] for a runtime
    /// record that only carries the `(tenant_id, workspace_id)` pair -- managed
    /// worker lifecycle records and framework-adapter sessions both do.
    ///
    /// Issue #519: these call sites used to write the workspace id into the
    /// `project_id` slot, which is a different entity in the
    /// `tenant -> project -> workspace` hierarchy. Everything that keys on
    /// `TenantContext::project_id` -- the `QuotaScopeKind::Project` lookup in
    /// [`AppState::resolve_effective_quota`], billing attribution, and the
    /// project column of every persisted audit/evidence row -- was therefore
    /// keyed on a scope id that does not name a project at all.
    ///
    /// The project is never guessed: it is read back off the workspace row,
    /// the same #514 "backfill ancestors from resolved rows, do not trust a
    /// declared triple" rule the lifecycle gate uses. `project_id` stays
    /// `None` -- meaning "no project scope", which every consumer already
    /// handles -- when the workspace is unknown, when the control-plane read
    /// fails, or when the resolved chain roots in a *different* tenant than
    /// the record declares (a mismatch must never leak one tenant's project id
    /// onto another tenant's row).
    pub(crate) fn workspace_attribution_context(
        &self,
        tenant_id: &str,
        workspace_id: &str,
    ) -> ferrogate_core::TenantContext {
        // Both callers are synchronous (the external-action authorizer runs on
        // a plain std::thread worker with no tokio runtime); bridge with the
        // same helper `managed_worker_capability_policy_for_tenant` uses.
        let resolved = match crate::gateway::block_on_sync_bridge(
            self.repositories.resolve_workspace_scope(workspace_id),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                warn!(
                    "failed to resolve project attribution for workspace {workspace_id}: {error}"
                );
                None
            }
        };
        let project_id = resolved
            .filter(|scope| scope.tenant_id == tenant_id)
            .map(|scope| scope.project_id);
        ferrogate_core::TenantContext {
            organization_id: Some(tenant_id.to_string()),
            team_id: None,
            project_id,
            workspace_id: Some(workspace_id.to_string()),
            user_id: None,
            api_key_id: None,
        }
    }

    /// The gateway's entry into the shared #514 lifecycle gate.
    ///
    /// Everything of substance -- the hierarchy walk that backfills ancestors
    /// a credential never named, the pure per-seam decision, and the
    /// fail-CLOSED mapping of a control-plane read failure onto a retryable
    /// 503 -- lives in `ferrogate_storage::check_usable_tenancy`, shared with
    /// `ferrogate-auth`'s admin-console credential mints. This method exists
    /// only to hand back this crate's [`AuthError`], so a lifecycle refusal is
    /// rendered by the same three lines every `authenticate()` refusal is.
    pub(crate) async fn require_usable_tenancy(
        &self,
        seam: LifecycleSeam,
        refs: TenancyRefs<'_>,
    ) -> Result<(), AuthError> {
        self.repositories
            .require_usable_tenancy(seam, refs)
            .await
            .map_err(AuthError::from)
    }

    pub(crate) async fn list_virtual_api_keys(&self) -> anyhow::Result<Vec<StoredApiKey>> {
        Ok(self.repositories.list_api_key_records().await?)
    }

    pub(crate) async fn get_virtual_api_key(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<StoredApiKey>> {
        Ok(self.repositories.get_api_key_record(id).await?)
    }

    pub(crate) async fn upsert_virtual_api_key(&self, key: StoredApiKey) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_api_key_record(key).await?)
    }

    // --- Multi-level quota/rate-limit policies (P1-3) ---

    pub(crate) async fn list_quota_policies(&self) -> anyhow::Result<Vec<StoredQuotaPolicy>> {
        Ok(self.repositories.list_quota_policies().await?)
    }

    pub(crate) async fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> anyhow::Result<Option<StoredQuotaPolicy>> {
        Ok(self
            .repositories
            .get_quota_policy(scope_type, scope_id)
            .await?)
    }

    pub(crate) async fn upsert_quota_policy(
        &self,
        policy: StoredQuotaPolicy,
    ) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_quota_policy(policy).await?)
    }

    pub(crate) async fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .repositories
            .delete_quota_policy(scope_type, scope_id)
            .await?)
    }
}
