// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the multi-tenant control-plane
// hierarchy (TOK-11/TOK-12) -- tenant-account, sellable-plan, project,
// workspace, virtual-key, and quota-policy CRUD.

use super::*;

use crate::lifecycle_gate::{
    check_lifecycle_chain, LifecycleGateError, LifecycleRef, LifecycleSeam,
};

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

    /// Resolve the lifecycle `status` of every row a `tenant -> project ->
    /// workspace` triple names, shallowest first (issue #514).
    ///
    /// This is the ONE reader of the lifecycle columns for both enforcement
    /// seams: [`AppState::require_usable_tenancy`] is built on it, and nothing
    /// else compares `status` strings. Ids that are `None`, blank, or that name
    /// no row are skipped -- absence is not suspension (see [`LifecycleRef`]).
    pub(crate) async fn resolve_lifecycle_chain(
        &self,
        tenant_id: Option<&str>,
        project_id: Option<&str>,
        workspace_id: Option<&str>,
    ) -> anyhow::Result<Vec<LifecycleRef>> {
        fn present(value: Option<&str>) -> Option<&str> {
            value.map(str::trim).filter(|value| !value.is_empty())
        }

        let mut chain = Vec::new();
        if let Some(tenant_id) = present(tenant_id) {
            if let Some(account) = self.repositories.get_tenant_account(tenant_id).await? {
                chain.push(LifecycleRef::new("tenant", account.id, &account.status));
            }
        }
        if let Some(project_id) = present(project_id) {
            if let Some(project) = self.repositories.get_project(project_id).await? {
                chain.push(LifecycleRef::new("project", project.id, &project.status));
            }
        }
        if let Some(workspace_id) = present(workspace_id) {
            if let Some(workspace) = self.repositories.get_workspace(workspace_id).await? {
                chain.push(LifecycleRef::new(
                    "workspace",
                    workspace.id,
                    &workspace.status,
                ));
            }
        }
        Ok(chain)
    }

    /// The single chokepoint both #514 seams call: resolve the chain, then run
    /// the shared pure decision over it.
    ///
    /// A storage failure is reported as [`LifecycleGateError::Unavailable`]
    /// (retryable 503), never swallowed into "active" -- otherwise a flapping
    /// control plane would be a suspension bypass.
    pub(crate) async fn require_usable_tenancy(
        &self,
        seam: LifecycleSeam,
        tenant_id: Option<&str>,
        project_id: Option<&str>,
        workspace_id: Option<&str>,
    ) -> Result<(), LifecycleGateError> {
        let chain = self
            .resolve_lifecycle_chain(tenant_id, project_id, workspace_id)
            .await
            .map_err(|error| LifecycleGateError::Unavailable(error.to_string()))?;
        check_lifecycle_chain(seam, &chain).map_err(LifecycleGateError::Inactive)
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
