// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Tenant-level RBAC entitlements (issue #182): a
// Permission -> Role -> TenantRoleBinding system generalizing the ad-hoc
// boolean feature flags on `StoredPlan` (#168/#176/#177). A permission is
// a dynamically-definable, finest-grained capability unit; a role is a
// named, horizontally-extensible bundle of permission keys; a tenant may
// hold multiple roles, and its effective permission set is the union of
// every bound role's permissions. Split into its own file per the "one
// business entity per file" convention -- see `StoredPlan`/`StoredAsset`
// in `lib.rs` for the pattern this mirrors.

use serde::{Deserialize, Serialize};

use super::{
    deserialize_storage_document, serialize_storage_document, PostgresControlPlaneStore,
    PostgresRow, Repository, RuntimeControlPlaneBackend, RuntimeControlPlaneState,
    RuntimeStorageRepositories, StorageError,
};

/// A dynamically-definable, finest-grained capability unit (issue #182).
/// String-keyed rather than a fixed enum/struct-field so an operator can
/// create a new permission through the admin API with no code change --
/// only the specific enforcement call site that wants to check a new key
/// needs a code change, not the permission catalog itself. This is the
/// generalization of ad-hoc booleans like `StoredPlan::asset_hosting_enabled`
/// (#176/#177): those still work for existing capabilities, but new ones
/// can be granted via role assignment instead of a new struct field + a
/// migration + touching every `StoredPlan` literal in the codebase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredPermission {
    pub id: String,
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// A named, horizontally-extensible bundle of permission keys (issue #182).
/// Adding a permission to a role is a data change to `permission_keys`,
/// not a schema migration -- mirrors how `StoredPlan::default_model_allowlist`
/// is a plain string list rather than one struct field per allowed model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRole {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permission_keys: Vec<String>,
    #[serde(default)]
    pub created_at_unix: i64,
    #[serde(default)]
    pub updated_at_unix: i64,
}

/// Many-to-many: a tenant may hold multiple roles, and its effective
/// permission set is the union of every bound role's `permission_keys`
/// (issue #182). Granting a tenant a new capability becomes "bind role Y
/// to tenant X" -- one write, no redeploy -- rather than adding a new
/// `StoredPlan` field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredTenantRoleBinding {
    pub id: String,
    pub tenant_id: String,
    pub role_id: String,
    #[serde(default)]
    pub created_at_unix: i64,
}

/// Deterministic id for a tenant-role binding so binding the same role to
/// the same tenant twice is naturally idempotent, mirroring
/// `quota_policy_id`/`stored_asset_id` in `lib.rs`.
pub fn tenant_role_binding_id(tenant_id: &str, role_id: &str) -> String {
    format!("{tenant_id}:{role_id}")
}

fn permission_from_row(row: &PostgresRow) -> StoredPermission {
    StoredPermission {
        id: row.get::<_, String>(0),
        key: row.get::<_, String>(1),
        name: row.get::<_, String>(2),
        description: row.get::<_, String>(3),
        created_at_unix: row.get::<_, i64>(4),
        updated_at_unix: row.get::<_, i64>(5),
    }
}

fn role_from_row(row: &PostgresRow) -> Result<StoredRole, StorageError> {
    let permission_keys = deserialize_storage_document(&row.get::<_, String>(4))?;
    Ok(StoredRole {
        id: row.get::<_, String>(0),
        name: row.get::<_, String>(1),
        slug: row.get::<_, String>(2),
        description: row.get::<_, String>(3),
        permission_keys,
        created_at_unix: row.get::<_, i64>(5),
        updated_at_unix: row.get::<_, i64>(6),
    })
}

fn tenant_role_binding_from_row(row: &PostgresRow) -> StoredTenantRoleBinding {
    StoredTenantRoleBinding {
        id: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        role_id: row.get::<_, String>(2),
        created_at_unix: row.get::<_, i64>(3),
    }
}

fn rbac_supabase_only_error() -> StorageError {
    StorageError::Runtime(
        "permissions/roles are Supabase/Postgres-only; set storage.provider = supabase".into(),
    )
}

impl PostgresControlPlaneStore {
    pub(super) fn upsert_permission(&self, permission: &StoredPermission) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO permissions (id, key, name, description, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (id) DO UPDATE SET \
                 key = EXCLUDED.key, name = EXCLUDED.name, description = EXCLUDED.description, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &permission.id,
                    &permission.key,
                    &permission.name,
                    &permission.description,
                    &permission.created_at_unix,
                    &permission.updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    pub(super) fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError> {
        let row = self.with_client(|client| {
            client.query_opt(
                "SELECT id, key, name, description, created_at_unix, updated_at_unix \
                 FROM permissions WHERE id = $1",
                &[&id],
            )
        })?;
        Ok(row.as_ref().map(permission_from_row))
    }

    pub(super) fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, key, name, description, created_at_unix, updated_at_unix \
                 FROM permissions ORDER BY key ASC",
                &[],
            )
        })?;
        Ok(rows.iter().map(permission_from_row).collect())
    }

    pub(super) fn delete_permission(&self, id: &str) -> Result<bool, StorageError> {
        let affected = self
            .with_client(|client| client.execute("DELETE FROM permissions WHERE id = $1", &[&id]))?;
        Ok(affected > 0)
    }

    pub(super) fn upsert_role(&self, role: &StoredRole) -> Result<(), StorageError> {
        let permission_keys_json = serialize_storage_document(&role.permission_keys)?;
        self.with_client(|client| {
            client.execute(
                "INSERT INTO roles \
                 (id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET \
                 name = EXCLUDED.name, slug = EXCLUDED.slug, description = EXCLUDED.description, \
                 permission_keys_json = EXCLUDED.permission_keys_json, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &role.id,
                    &role.name,
                    &role.slug,
                    &role.description,
                    &permission_keys_json,
                    &role.created_at_unix,
                    &role.updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    pub(super) fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError> {
        let row = self.with_client(|client| {
            client.query_opt(
                "SELECT id, name, slug, description, permission_keys_json::text, \
                 created_at_unix, updated_at_unix \
                 FROM roles WHERE id = $1",
                &[&id],
            )
        })?;
        row.as_ref().map(role_from_row).transpose()
    }

    pub(super) fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, name, slug, description, permission_keys_json::text, \
                 created_at_unix, updated_at_unix \
                 FROM roles ORDER BY slug ASC",
                &[],
            )
        })?;
        rows.iter().map(role_from_row).collect()
    }

    pub(super) fn delete_role(&self, id: &str) -> Result<bool, StorageError> {
        let affected =
            self.with_client(|client| client.execute("DELETE FROM roles WHERE id = $1", &[&id]))?;
        Ok(affected > 0)
    }

    pub(super) fn bind_tenant_role(&self, binding: &StoredTenantRoleBinding) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &binding.id,
                    &binding.tenant_id,
                    &binding.role_id,
                    &binding.created_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    pub(super) fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, tenant_id, role_id, created_at_unix \
                 FROM tenant_role_bindings WHERE tenant_id = $1 ORDER BY role_id ASC",
                &[&tenant_id],
            )
        })?;
        Ok(rows.iter().map(tenant_role_binding_from_row).collect())
    }

    pub(super) fn unbind_tenant_role(&self, tenant_id: &str, role_id: &str) -> Result<bool, StorageError> {
        let affected = self.with_client(|client| {
            client.execute(
                "DELETE FROM tenant_role_bindings WHERE id = $1",
                &[&tenant_role_binding_id(tenant_id, role_id)],
            )
        })?;
        Ok(affected > 0)
    }
}

impl RuntimeControlPlaneState {
    pub fn upsert_permission(&mut self, permission: StoredPermission) {
        self.permissions.insert(permission.id.clone(), permission);
    }

    pub fn get_permission(&self, id: &str) -> Option<StoredPermission> {
        self.permissions.get(id)
    }

    pub fn list_permissions(&self) -> Vec<StoredPermission> {
        self.permissions.list()
    }

    pub fn delete_permission(&mut self, id: &str) -> bool {
        self.permissions.remove(id).is_some()
    }

    pub fn upsert_role(&mut self, role: StoredRole) {
        self.roles.insert(role.id.clone(), role);
    }

    pub fn get_role(&self, id: &str) -> Option<StoredRole> {
        self.roles.get(id)
    }

    pub fn list_roles(&self) -> Vec<StoredRole> {
        self.roles.list()
    }

    pub fn delete_role(&mut self, id: &str) -> bool {
        self.roles.remove(id).is_some()
    }

    pub fn bind_tenant_role(&mut self, binding: StoredTenantRoleBinding) {
        self.tenant_role_bindings
            .insert(binding.id.clone(), binding);
    }

    pub fn list_tenant_role_bindings(&self, tenant_id: &str) -> Vec<StoredTenantRoleBinding> {
        self.tenant_role_bindings
            .list()
            .into_iter()
            .filter(|binding| binding.tenant_id == tenant_id)
            .collect()
    }

    pub fn unbind_tenant_role(&mut self, tenant_id: &str, role_id: &str) -> bool {
        self.tenant_role_bindings
            .remove(&tenant_role_binding_id(tenant_id, role_id))
            .is_some()
    }
}

impl RuntimeStorageRepositories {
    /// Creates or replaces a permission (issue #182). Permissions are
    /// shared/global, like plans -- same trust model as `Self::upsert_plan`.
    pub fn upsert_permission(&self, permission: StoredPermission) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_permission(permission);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_permission(&permission)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn get_permission(&self, id: &str) -> Result<Option<StoredPermission>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_permission(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.get_permission(id),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn list_permissions(&self) -> Result<Vec<StoredPermission>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_permissions())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.list_permissions(),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn delete_permission(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_permission(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.delete_permission(id),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    /// Creates or replaces a role (issue #182): a named, horizontally
    /// extensible bundle of permission keys. Shared/global, like plans.
    pub fn upsert_role(&self, role: StoredRole) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_role(role);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.upsert_role(&role),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn get_role(&self, id: &str) -> Result<Option<StoredRole>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_role(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.get_role(id),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn list_roles(&self) -> Result<Vec<StoredRole>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_roles())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.list_roles(),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn delete_role(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_role(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.delete_role(id),
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    /// Binds a role to a tenant (issue #182) -- the tenant's effective
    /// permission set becomes the union of every bound role's
    /// `permission_keys`. Idempotent: binding the same role twice is a
    /// no-op (deterministic id, `ON CONFLICT DO NOTHING` on Postgres).
    pub fn bind_tenant_role(&self, binding: StoredTenantRoleBinding) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.bind_tenant_role(binding);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.bind_tenant_role(&binding)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredTenantRoleBinding>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_tenant_role_bindings(tenant_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_tenant_role_bindings(tenant_id)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }

    pub fn unbind_tenant_role(&self, tenant_id: &str, role_id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.unbind_tenant_role(tenant_id, role_id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.unbind_tenant_role(tenant_id, role_id)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(rbac_supabase_only_error()),
        }
    }
}
