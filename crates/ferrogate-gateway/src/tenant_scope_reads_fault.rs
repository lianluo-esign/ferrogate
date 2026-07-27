// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Test-only fault injection for the tenant-scope read seam
// (issue #543): a `TenantScopeReads` implementation whose individual reads can
// be armed to fail, plus the two caller fixtures the scope resolvers branch on.

use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;

use ferrogate_storage::{
    StoredApiKey, StoredProject, StoredRole, StoredTenantRoleBinding, StoredWorkspace,
};

use crate::auth::AuthContext;
use crate::tenant_scope_reads::TenantScopeReads;

/// One read on the [`TenantScopeReads`] seam, addressable so a test can arm
/// exactly the read whose failure branch it means to pin. A new seam method
/// adds a variant here and nothing else changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TenantScopeRead {
    ListRoles,
    ListTenantRoleBindings,
    GetProject,
    GetWorkspace,
    GetVirtualApiKey,
}

/// A [`TenantScopeReads`] store that answers from canned rows, records every
/// read attempted, and returns `Err` for the reads it was armed to fail.
///
/// The distinction that matters for #543 is between an **absent row**
/// (`Ok(None)` / an empty list -- the control plane answered, and the answer
/// was "nothing") and an **unavailable control plane** (`Err` -- the answer is
/// unknown). No other test double in the tree can produce the second: the
/// in-memory backend behind a real `AppState` swallows even a poisoned lock
/// into `unwrap_or_default()`, so every storage read it serves succeeds.
pub(crate) struct FaultyTenantScopeReads {
    failing: HashSet<TenantScopeRead>,
    roles: Vec<StoredRole>,
    bindings: Vec<StoredTenantRoleBinding>,
    projects: Vec<StoredProject>,
    workspaces: Vec<StoredWorkspace>,
    virtual_keys: Vec<StoredApiKey>,
    reads: Mutex<Vec<TenantScopeRead>>,
}

impl FaultyTenantScopeReads {
    /// A store whose reads all succeed. Arm failures with [`Self::failing`].
    pub(crate) fn healthy() -> Self {
        Self {
            failing: HashSet::new(),
            roles: Vec::new(),
            bindings: Vec::new(),
            projects: Vec::new(),
            workspaces: Vec::new(),
            virtual_keys: Vec::new(),
            reads: Mutex::new(Vec::new()),
        }
    }

    /// Arms `read` to fail. Every other read still answers from canned rows,
    /// so a test pins ONE failure branch at a time rather than a store that is
    /// dead in every direction.
    pub(crate) fn failing(mut self, read: TenantScopeRead) -> Self {
        self.failing.insert(read);
        self
    }

    pub(crate) fn with_role(mut self, id: &str, permission_keys: &[&str]) -> Self {
        self.roles.push(StoredRole {
            id: id.to_string(),
            name: id.to_string(),
            slug: id.to_string(),
            description: String::new(),
            permission_keys: permission_keys.iter().map(|key| key.to_string()).collect(),
            created_at_unix: 1,
            updated_at_unix: 1,
        });
        self
    }

    pub(crate) fn with_binding(mut self, tenant_id: &str, role_id: &str) -> Self {
        self.bindings.push(StoredTenantRoleBinding {
            id: ferrogate_storage::tenant_role_binding_id(tenant_id, role_id),
            tenant_id: tenant_id.to_string(),
            role_id: role_id.to_string(),
            created_at_unix: 1,
        });
        self
    }

    pub(crate) fn with_project(mut self, id: &str, tenant_id: &str) -> Self {
        self.projects.push(StoredProject {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            name: id.to_string(),
            slug: id.to_string(),
            status: "active".to_string(),
            created_at_unix: 1,
            updated_at_unix: 1,
        });
        self
    }

    pub(crate) fn with_workspace(mut self, id: &str, tenant_id: &str) -> Self {
        self.workspaces.push(StoredWorkspace {
            id: id.to_string(),
            project_id: format!("{id}-project"),
            tenant_id: tenant_id.to_string(),
            name: id.to_string(),
            slug: id.to_string(),
            environment: "prod".to_string(),
            status: "active".to_string(),
            created_at_unix: 1,
            updated_at_unix: 1,
        });
        self
    }

    pub(crate) fn with_virtual_api_key(mut self, id: &str, tenant_id: &str) -> Self {
        self.virtual_keys.push(StoredApiKey {
            id: id.to_string(),
            workspace_id: String::new(),
            tenant_id: tenant_id.to_string(),
            project_id: String::new(),
            name: id.to_string(),
            key_prefix: String::new(),
            key_hash: String::new(),
            last4: String::new(),
            enabled: true,
            scopes: Vec::new(),
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            tenant: ferrogate_core::TenantContext::default(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            created_at_unix: 1,
            updated_at_unix: 1,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        });
        self
    }

    /// Every read the resolver under test actually attempted, in order. Lets a
    /// test assert that a decision was reached WITHOUT touching storage (the
    /// platform-operator short-circuits), which an outcome assertion alone
    /// cannot distinguish from a lucky read.
    pub(crate) fn reads(&self) -> Vec<TenantScopeRead> {
        self.reads.lock().expect("fault store lock").clone()
    }

    fn observe(&self, read: TenantScopeRead) -> anyhow::Result<()> {
        self.reads.lock().expect("fault store lock").push(read);
        if self.failing.contains(&read) {
            anyhow::bail!("injected control-plane failure on {read:?}");
        }
        Ok(())
    }
}

#[async_trait]
impl TenantScopeReads for FaultyTenantScopeReads {
    async fn list_roles(&self) -> anyhow::Result<Vec<StoredRole>> {
        self.observe(TenantScopeRead::ListRoles)?;
        Ok(self.roles.clone())
    }

    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<StoredTenantRoleBinding>> {
        self.observe(TenantScopeRead::ListTenantRoleBindings)?;
        Ok(self
            .bindings
            .iter()
            .filter(|binding| binding.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn get_project(&self, id: &str) -> anyhow::Result<Option<StoredProject>> {
        self.observe(TenantScopeRead::GetProject)?;
        Ok(self
            .projects
            .iter()
            .find(|project| project.id == id)
            .cloned())
    }

    async fn get_workspace(&self, id: &str) -> anyhow::Result<Option<StoredWorkspace>> {
        self.observe(TenantScopeRead::GetWorkspace)?;
        Ok(self
            .workspaces
            .iter()
            .find(|workspace| workspace.id == id)
            .cloned())
    }

    async fn get_virtual_api_key(&self, id: &str) -> anyhow::Result<Option<StoredApiKey>> {
        self.observe(TenantScopeRead::GetVirtualApiKey)?;
        Ok(self.virtual_keys.iter().find(|key| key.id == id).cloned())
    }
}

/// A credential that declares a tenant: `caller_scope()` is
/// `CallerScope::Tenant(tenant_id)`, so it takes the storage-reading branch of
/// every scope resolver.
pub(crate) fn tenant_auth(tenant_id: &str) -> AuthContext {
    AuthContext {
        api_key_id: Some(format!("{tenant_id}-console")),
        scopes: ["admin.read".to_string()].into_iter().collect(),
        allowed_models: HashSet::new(),
        denied_models: HashSet::new(),
        allowed_providers: HashSet::new(),
        denied_providers: HashSet::new(),
        region_allowlist: HashSet::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        organization_id: Some(tenant_id.to_string()),
        platform_operator: false,
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    }
}

/// A credential that DECLARED platform root (#515), not one that merely
/// omitted its tenant: `caller_scope()` is `CallerScope::PlatformOperator`.
pub(crate) fn platform_operator_auth() -> AuthContext {
    AuthContext {
        platform_operator: true,
        organization_id: None,
        ..tenant_auth("ignored-when-platform-operator")
    }
}

/// Runs `future` to completion on a fresh current-thread runtime, so the test
/// bodies below stay synchronous (the convention in `auth_admission_test.rs`).
pub(crate) fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}
