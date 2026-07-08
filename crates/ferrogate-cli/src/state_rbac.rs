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

    /// Resolves a tenant's effective permission set: the union of every
    /// bound role's `permission_keys` (issue #182). Storage errors fail
    /// closed (empty set) via `unwrap_or_default`, matching the
    /// fail-closed convention `resolve_tenant_plan`'s callers already use
    /// for missing/errored plan lookups.
    pub(crate) fn tenant_has_permission(&self, tenant_id: &str, permission_key: &str) -> bool {
        let bindings = self
            .repositories
            .list_tenant_role_bindings(tenant_id)
            .unwrap_or_default();
        bindings.iter().any(|binding| {
            self.repositories
                .get_role(&binding.role_id)
                .ok()
                .flatten()
                .is_some_and(|role| role.permission_keys.iter().any(|key| key == permission_key))
        })
    }
}
