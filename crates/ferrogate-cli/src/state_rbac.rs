// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for tenant-level RBAC entitlements (issue
// #182) -- Permission -> Role -> TenantRoleBinding CRUD and effective
// permission resolution.

use super::*;

impl AppState {
    pub(crate) async fn tenant_tool_entitlement_denied(
        &self,
        tenant_id: String,
        permission_key: String,
        plan_enabled: fn(&StoredPlan) -> bool,
    ) -> bool {
        // get_tenant_account/get_plan are still sync (not yet migrated to the
        // async pool), so they stay in spawn_blocking to avoid stalling the
        // tokio worker thread; list_permissions/list_tenant_role_bindings/
        // get_role are async now (issue #221's rbac slice) and are awaited
        // directly rather than blocked-on inside the closure.
        let repositories = Arc::clone(&self.repositories);
        let account_tenant_id = tenant_id.clone();
        let (tenant_account_exists, plan_grants_access) = tokio::task::spawn_blocking(move || {
            let account = repositories
                .get_tenant_account(&account_tenant_id)
                .ok()
                .flatten();
            let tenant_account_exists = account.is_some();
            let plan_grants_access = account
                .as_ref()
                .and_then(|account| repositories.get_plan(&account.plan_id).ok().flatten())
                .is_some_and(|plan| plan_enabled(&plan));
            (tenant_account_exists, plan_grants_access)
        })
        .await
        .unwrap_or((true, false));

        let permission_exists =
            self.repositories
                .list_permissions()
                .await
                .ok()
                .is_some_and(|permissions| {
                    permissions
                        .iter()
                        .any(|permission| permission.key == permission_key)
                });
        let mut role_grants_access = false;
        if permission_exists {
            if let Ok(bindings) = self
                .repositories
                .list_tenant_role_bindings(&tenant_id)
                .await
            {
                for binding in bindings {
                    if let Ok(Some(role)) = self.repositories.get_role(&binding.role_id).await {
                        if role
                            .permission_keys
                            .iter()
                            .any(|key| key == &permission_key)
                        {
                            role_grants_access = true;
                            break;
                        }
                    }
                }
            }
        }
        tenant_account_exists && !plan_grants_access && !role_grants_access
    }

    pub(crate) async fn upsert_permission(
        &self,
        permission: StoredPermission,
    ) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_permission(permission).await?)
    }

    pub(crate) async fn get_permission(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<StoredPermission>> {
        Ok(self.repositories.get_permission(id).await?)
    }

    pub(crate) async fn list_permissions(&self) -> anyhow::Result<Vec<StoredPermission>> {
        Ok(self.repositories.list_permissions().await?)
    }

    pub(crate) async fn delete_permission(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_permission(id).await?)
    }

    pub(crate) async fn upsert_role(&self, role: StoredRole) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_role(role).await?)
    }

    pub(crate) async fn get_role(&self, id: &str) -> anyhow::Result<Option<StoredRole>> {
        Ok(self.repositories.get_role(id).await?)
    }

    pub(crate) async fn list_roles(&self) -> anyhow::Result<Vec<StoredRole>> {
        Ok(self.repositories.list_roles().await?)
    }

    pub(crate) async fn delete_role(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_role(id).await?)
    }

    pub(crate) async fn bind_tenant_role(
        &self,
        binding: StoredTenantRoleBinding,
    ) -> anyhow::Result<()> {
        Ok(self.repositories.bind_tenant_role(binding).await?)
    }

    pub(crate) async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<StoredTenantRoleBinding>> {
        Ok(self
            .repositories
            .list_tenant_role_bindings(tenant_id)
            .await?)
    }

    pub(crate) async fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .repositories
            .unbind_tenant_role(tenant_id, role_id)
            .await?)
    }

    /// Resolves a tenant's effective permission set from the durable
    /// Permission -> Role -> TenantRoleBinding graph. Callers that need to
    /// distinguish a denied action from an unavailable control plane use the
    /// result-returning form so a database outage cannot masquerade as a
    /// normal authorization decision.
    pub(crate) async fn tenant_has_permission_result(
        &self,
        tenant_id: &str,
        permission_key: &str,
    ) -> anyhow::Result<bool> {
        let permission_exists = self
            .repositories
            .list_permissions()
            .await?
            .iter()
            .any(|permission| permission.key == permission_key);
        if !permission_exists {
            return Ok(false);
        }
        let bindings = self
            .repositories
            .list_tenant_role_bindings(tenant_id)
            .await?;
        for binding in bindings {
            let Some(role) = self.repositories.get_role(&binding.role_id).await? else {
                continue;
            };
            if role.permission_keys.iter().any(|key| key == permission_key) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Compatibility helper for existing product-entitlement call sites.
    /// Storage failures remain fail-closed for those boolean gates.
    pub(crate) async fn tenant_has_permission(
        &self,
        tenant_id: &str,
        permission_key: &str,
    ) -> bool {
        self.tenant_has_permission_result(tenant_id, permission_key)
            .await
            .unwrap_or(false)
    }
}
