// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for tenant-level RBAC entitlements (issue
// #182) -- Permission -> Role -> TenantRoleBinding CRUD and effective
// permission resolution.

use super::*;

impl AppState {
    pub(crate) fn upsert_permission(&self, permission: StoredPermission) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_permission(permission)?)
    }

    pub(crate) fn get_permission(&self, id: &str) -> anyhow::Result<Option<StoredPermission>> {
        Ok(self.repositories.get_permission(id)?)
    }

    pub(crate) fn list_permissions(&self) -> anyhow::Result<Vec<StoredPermission>> {
        Ok(self.repositories.list_permissions()?)
    }

    pub(crate) fn delete_permission(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_permission(id)?)
    }

    pub(crate) fn upsert_role(&self, role: StoredRole) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_role(role)?)
    }

    pub(crate) fn get_role(&self, id: &str) -> anyhow::Result<Option<StoredRole>> {
        Ok(self.repositories.get_role(id)?)
    }

    pub(crate) fn list_roles(&self) -> anyhow::Result<Vec<StoredRole>> {
        Ok(self.repositories.list_roles()?)
    }

    pub(crate) fn delete_role(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_role(id)?)
    }

    pub(crate) fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> anyhow::Result<()> {
        Ok(self.repositories.bind_tenant_role(binding)?)
    }

    pub(crate) fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<StoredTenantRoleBinding>> {
        Ok(self.repositories.list_tenant_role_bindings(tenant_id)?)
    }

    pub(crate) fn unbind_tenant_role(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(self.repositories.unbind_tenant_role(tenant_id, role_id)?)
    }

    /// Resolves a tenant's effective permission set from the durable
    /// Permission -> Role -> TenantRoleBinding graph. Callers that need to
    /// distinguish a denied action from an unavailable control plane use the
    /// result-returning form so a database outage cannot masquerade as a
    /// normal authorization decision.
    pub(crate) fn tenant_has_permission_result(
        &self,
        tenant_id: &str,
        permission_key: &str,
    ) -> anyhow::Result<bool> {
        let permission_exists = self
            .repositories
            .list_permissions()?
            .iter()
            .any(|permission| permission.key == permission_key);
        if !permission_exists {
            return Ok(false);
        }
        let bindings = self.repositories.list_tenant_role_bindings(tenant_id)?;
        for binding in bindings {
            let Some(role) = self.repositories.get_role(&binding.role_id)? else {
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
    pub(crate) fn tenant_has_permission(&self, tenant_id: &str, permission_key: &str) -> bool {
        self.tenant_has_permission_result(tenant_id, permission_key)
            .unwrap_or(false)
    }
}
