// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! RBAC data model and in-memory role/binding evaluation (issues #162/#232),
//! plus the request/decision types of the authorize REST surface.

use anyhow::Context;
use ferrogate_core::TenantContext;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, RwLock},
};

use crate::api_key::ApiKeyAuthenticator;
use crate::util::constant_time_eq;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthServiceData {
    #[serde(default)]
    pub tenants: Vec<TenantRecord>,
    #[serde(default)]
    pub api_keys: Vec<AuthApiKey>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub bindings: Vec<PolicyBinding>,
}

impl AuthServiceData {
    pub fn load_yaml(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read auth service data {}", path.display()))?;
        serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse auth service data {}", path.display()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub context: TenantContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthApiKey {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tenant: TenantContext,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub action: String,
    pub resource: String,
}

/// A named permission bundle. Roles are namespaced per tenant (issue #232):
/// `tenant_id: Some(..)` marks a role owned by (and only writable/resolvable
/// for) that tenant, while `tenant_id: None` marks a GLOBAL role -- either a
/// platform built-in loaded from the static YAML file or a legacy role
/// created before per-tenant namespacing. Global roles are read-only through
/// the runtime REST API: every tenant can see and bind them, but no tenant
/// can overwrite or delete them (that would tamper with another tenant's
/// bindings that resolve to the same id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBinding {
    pub id: String,
    pub role_id: String,
    pub tenant: TenantContext,
    pub subject: PolicySubject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicySubject {
    User { user_id: String },
    ServiceAccount { service_account_id: String },
    ApiKey { api_key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthDecision {
    pub tenant: TenantContext,
    pub subject: PolicySubject,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub request_limit_per_minute: Option<u64>,
}

/// Holds `AuthServiceData` behind a lock (issue #162) so `Role`/`PolicyBinding`
/// records can be created, updated, and deleted at runtime through a REST
/// API instead of only via the static YAML file loaded at process start.
/// `tenants`/`api_keys` remain effectively read-only (no mutation API is
/// exposed for them here; that boundary is unchanged from before #162).
#[derive(Debug, Clone)]
pub struct RbacAuthService {
    data: Arc<RwLock<AuthServiceData>>,
}

impl RbacAuthService {
    pub fn new(data: AuthServiceData) -> Self {
        Self {
            data: Arc::new(RwLock::new(data)),
        }
    }

    fn read_data(&self) -> std::sync::RwLockReadGuard<'_, AuthServiceData> {
        match self.data.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn write_data(&self) -> std::sync::RwLockWriteGuard<'_, AuthServiceData> {
        match self.data.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn tenants(&self) -> Vec<TenantRecord> {
        self.read_data().tenants.clone()
    }

    pub fn authorize(&self, request: &AuthorizeRequest) -> AuthorizationDecision {
        let data = self.read_data();
        // Roles are namespaced per tenant (issue #232): a binding resolves
        // its role WITHIN the binding's own tenant first, falling back to
        // the global (tenant-less) catalog. A role another tenant defined
        // under the same id can therefore never alter this binding's grant.
        let roles_by_id: HashMap<(Option<&str>, &str), &Role> = data
            .roles
            .iter()
            .map(|role| ((role.tenant_id.as_deref(), role.id.as_str()), role))
            .collect();
        let allowed = data
            .bindings
            .iter()
            .filter(|binding| binding.subject == request.subject)
            .filter(|binding| tenant_matches(&binding.tenant, &request.tenant))
            .filter_map(|binding| {
                let binding_tenant = binding.tenant.organization_id.as_deref();
                roles_by_id
                    .get(&(binding_tenant, binding.role_id.as_str()))
                    .or_else(|| roles_by_id.get(&(None, binding.role_id.as_str())))
            })
            .flat_map(|role| role.permissions.iter())
            .any(|permission| {
                matches_pattern(&permission.action, &request.action)
                    && matches_pattern(&permission.resource, &request.resource)
            });

        AuthorizationDecision {
            allowed,
            tenant: request.tenant.clone(),
            reason: if allowed {
                "matched_rbac_binding".into()
            } else {
                "no_matching_rbac_binding".into()
            },
        }
    }

    // -- issue #162: runtime Role/PolicyBinding CRUD -----------------------

    pub fn list_roles(&self) -> Vec<Role> {
        self.read_data().roles.clone()
    }

    /// Lists the roles a tenant may see and bind (issue #232): its own
    /// tenant-scoped roles plus the read-only global catalog. Another
    /// tenant's roles are never returned.
    pub fn list_roles_visible_to_tenant(&self, tenant_id: &str) -> Vec<Role> {
        self.read_data()
            .roles
            .iter()
            .filter(|role| role.tenant_id.is_none() || role.tenant_id.as_deref() == Some(tenant_id))
            .cloned()
            .collect()
    }

    /// Creates a new role, or replaces an existing one with the same
    /// `(tenant_id, id)` pair (issue #232): two tenants reusing an id own
    /// two independent roles, and neither can touch a global (tenant-less)
    /// role this way.
    pub fn upsert_role(&self, role: Role) {
        let mut data = self.write_data();
        match data
            .roles
            .iter_mut()
            .find(|existing| existing.id == role.id && existing.tenant_id == role.tenant_id)
        {
            Some(existing) => *existing = role,
            None => data.roles.push(role),
        }
    }

    /// Deletes one tenant's own role by id (issue #232) -- global roles and
    /// other tenants' roles are invisible to this call. Fails rather than
    /// leaving dangling references if any of the owning tenant's bindings
    /// still uses the id -- delete the binding(s) first.
    pub fn delete_tenant_role(&self, tenant_id: &str, role_id: &str) -> Result<bool, &'static str> {
        let mut data = self.write_data();
        if !data
            .roles
            .iter()
            .any(|role| role.id == role_id && role.tenant_id.as_deref() == Some(tenant_id))
        {
            return Ok(false);
        }
        if data.bindings.iter().any(|binding| {
            binding.role_id == role_id
                && binding.tenant.organization_id.as_deref() == Some(tenant_id)
        }) {
            return Err("role is still referenced by one or more bindings");
        }
        let before = data.roles.len();
        data.roles
            .retain(|role| !(role.id == role_id && role.tenant_id.as_deref() == Some(tenant_id)));
        Ok(data.roles.len() != before)
    }

    pub fn list_bindings_for_tenant(&self, tenant: &TenantContext) -> Vec<PolicyBinding> {
        self.read_data()
            .bindings
            .iter()
            .filter(|binding| tenant_matches(&binding.tenant, tenant))
            .cloned()
            .collect()
    }

    /// Creates or replaces a binding. Fails if `role_id` doesn't name a role
    /// the binding's tenant can actually resolve (its own, or a global one),
    /// so bindings can't silently grant nothing -- or resolve to another
    /// tenant's role (issue #232).
    pub fn upsert_binding(&self, binding: PolicyBinding) -> Result<(), &'static str> {
        let mut data = self.write_data();
        let binding_tenant = binding.tenant.organization_id.as_deref();
        if !data.roles.iter().any(|role| {
            role.id == binding.role_id
                && (role.tenant_id.is_none() || role.tenant_id.as_deref() == binding_tenant)
        }) {
            return Err("role_id does not name an existing role");
        }
        match data
            .bindings
            .iter_mut()
            .find(|existing| existing.id == binding.id)
        {
            Some(existing) => *existing = binding,
            None => data.bindings.push(binding),
        }
        Ok(())
    }

    pub fn delete_binding(&self, binding_id: &str) -> bool {
        let mut data = self.write_data();
        let before = data.bindings.len();
        data.bindings.retain(|binding| binding.id != binding_id);
        data.bindings.len() != before
    }
}

impl ApiKeyAuthenticator for RbacAuthService {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        let data = self.read_data();
        // Compare the presented secret in constant time (CWE-208): a plain `==`
        // on the secret string leaks, via timing, how many leading bytes matched
        // -- matching the constant_time_eq the hashed-key path already uses.
        let api_key = data.api_keys.iter().find(|api_key| {
            api_key.enabled
                && api_key.secret.as_deref().is_some_and(|secret| {
                    constant_time_eq(secret.as_bytes(), presented_key.as_bytes())
                })
        })?;

        Some(AuthDecision {
            tenant: api_key.tenant.clone(),
            subject: PolicySubject::ApiKey {
                api_key_id: api_key.id.clone(),
            },
            scopes: api_key.scopes.clone(),
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub tenant: TenantContext,
    pub subject: PolicySubject,
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub tenant: TenantContext,
    pub reason: String,
}

fn tenant_matches(expected: &TenantContext, actual: &TenantContext) -> bool {
    tenant_field_matches(&expected.organization_id, &actual.organization_id)
        && tenant_field_matches(&expected.team_id, &actual.team_id)
        && tenant_field_matches(&expected.project_id, &actual.project_id)
        // workspace_id is the environment (dev/staging/prod) scoping dimension.
        // Omitting it let a binding scoped to one workspace match a request from
        // another (staging -> prod privilege leak); a binding with no
        // workspace_id still matches any workspace, consistent with the others.
        && tenant_field_matches(&expected.workspace_id, &actual.workspace_id)
        && tenant_field_matches(&expected.user_id, &actual.user_id)
        && tenant_field_matches(&expected.api_key_id, &actual.api_key_id)
}

fn tenant_field_matches(expected: &Option<String>, actual: &Option<String>) -> bool {
    expected.as_deref().is_none_or(|expected| {
        actual
            .as_deref()
            .is_some_and(|actual| expected == "*" || expected == actual)
    })
}

fn matches_pattern(expected: &str, actual: &str) -> bool {
    expected == "*" || expected == actual
}

fn default_true() -> bool {
    true
}
