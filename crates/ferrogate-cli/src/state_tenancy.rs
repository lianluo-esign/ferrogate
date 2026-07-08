// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the multi-tenant control-plane
// hierarchy (TOK-11/TOK-12) -- tenant-account, sellable-plan, project,
// workspace, virtual-key, and quota-policy CRUD.

use super::*;

impl AppState {
    pub(crate) fn list_tenant_accounts(&self) -> anyhow::Result<Vec<StoredTenantAccount>> {
        Ok(self.repositories.list_tenant_accounts()?)
    }

    pub(crate) fn get_tenant_account(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<StoredTenantAccount>> {
        Ok(self.repositories.get_tenant_account(id)?)
    }

    pub(crate) fn upsert_tenant_account(&self, account: StoredTenantAccount) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_tenant_account(account)?)
    }

    /// Resolves a tenant's assigned plan (issue #168), if any -- the tenant
    /// account's `plan_id` may point at a plan that no longer exists, in
    /// which case this returns `Ok(None)` rather than an error, matching
    /// [`resolve_effective_quota`]'s existing fail-open-to-no-plan-defaults
    /// behavior for a missing plan row.
    pub(crate) fn resolve_tenant_plan(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<StoredPlan>> {
        let Some(account) = self.repositories.get_tenant_account(tenant_id)? else {
            return Ok(None);
        };
        Ok(self.repositories.get_plan(&account.plan_id)?)
    }

    pub(crate) fn list_plans(&self) -> anyhow::Result<Vec<StoredPlan>> {
        Ok(self.repositories.list_plans()?)
    }

    pub(crate) fn get_plan(&self, id: &str) -> anyhow::Result<Option<StoredPlan>> {
        Ok(self.repositories.get_plan(id)?)
    }

    pub(crate) fn upsert_plan(&self, plan: StoredPlan) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_plan(plan)?)
    }

    pub(crate) fn list_projects(&self) -> anyhow::Result<Vec<StoredProject>> {
        Ok(self.repositories.list_projects()?)
    }

    pub(crate) fn get_project(&self, id: &str) -> anyhow::Result<Option<StoredProject>> {
        Ok(self.repositories.get_project(id)?)
    }

    pub(crate) fn upsert_project(&self, project: StoredProject) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_project(project)?)
    }

    pub(crate) fn list_workspaces(&self) -> anyhow::Result<Vec<StoredWorkspace>> {
        Ok(self.repositories.list_workspaces()?)
    }

    pub(crate) fn get_workspace(&self, id: &str) -> anyhow::Result<Option<StoredWorkspace>> {
        Ok(self.repositories.get_workspace(id)?)
    }

    pub(crate) fn upsert_workspace(&self, workspace: StoredWorkspace) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_workspace(workspace)?)
    }

    pub(crate) fn resolve_workspace_scope(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<Option<WorkspaceScope>> {
        Ok(self.repositories.resolve_workspace_scope(workspace_id)?)
    }

    pub(crate) fn list_virtual_api_keys(&self) -> anyhow::Result<Vec<StoredApiKey>> {
        Ok(self.repositories.list_api_key_records()?)
    }

    pub(crate) fn get_virtual_api_key(&self, id: &str) -> anyhow::Result<Option<StoredApiKey>> {
        Ok(self.repositories.get_api_key_record(id)?)
    }

    pub(crate) fn upsert_virtual_api_key(&self, key: StoredApiKey) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_api_key_record(key)?)
    }

    // --- Multi-level quota/rate-limit policies (P1-3) ---

    pub(crate) fn list_quota_policies(&self) -> anyhow::Result<Vec<StoredQuotaPolicy>> {
        Ok(self.repositories.list_quota_policies()?)
    }

    pub(crate) fn get_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> anyhow::Result<Option<StoredQuotaPolicy>> {
        Ok(self.repositories.get_quota_policy(scope_type, scope_id)?)
    }

    pub(crate) fn upsert_quota_policy(&self, policy: StoredQuotaPolicy) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_quota_policy(policy)?)
    }

    pub(crate) fn delete_quota_policy(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .repositories
            .delete_quota_policy(scope_type, scope_id)?)
    }
}
