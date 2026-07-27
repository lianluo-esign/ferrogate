// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: The control-plane read seam every tenant-scope decision goes
// through (issue #543), so a storage FAILURE inside a scope resolver can be
// produced by a test instead of only reasoned about in a doc comment.

use async_trait::async_trait;

use ferrogate_storage::{
    StoredApiKey, StoredProject, StoredRole, StoredTenantRoleBinding, StoredWorkspace,
};

use crate::state::AppState;

/// The control-plane reads a **tenant-scope decision** makes (issue #543).
///
/// # Why this exists
///
/// Every resolver that answers "how much of this catalog may this caller see"
/// has to read storage first, and each one therefore has a *failure* branch
/// that is a security decision in its own right:
///
/// * `server::rbac::rbac_catalog_scope` propagates the error, so the
///   four `/admin/v1/permissions*`/`/admin/v1/roles*` GETs answer
///   `503 storage_unavailable`. Degrading instead -- to an empty scope, or far
///   worse to `RbacCatalogScope::Full` -- would hand every tenant-scoped
///   caller the entire platform RBAC catalog through the error path, which is
///   precisely the disclosure #518 was filed to close.
/// * `auth::authorize_scoped_resource` deliberately does NOT
///   propagate: a failed project/workspace/key lookup collapses to "no
///   resolved tenant", which denies. Fail-closed, but only because the
///   comparison against the caller's own tenant can never match `None`.
///
/// Both properties were **unheld** before #543: `AppState`'s storage is a
/// concrete `RuntimeStorageRepositories`, its in-memory backend swallows even
/// a poisoned lock into `unwrap_or_default()`, and nothing else in the repo
/// can make a control-plane read fail. So the failure branches were
/// unreachable from any test, and either could have been inverted with every
/// suite still green (#500: an assertion that cannot fail holds nothing).
///
/// # Shape
///
/// This is a *read-only* seam, not a repository abstraction: it carries only
/// the reads the scope resolvers themselves perform, and the resolvers take
/// `&impl TenantScopeReads` rather than `&AppState`. Production keeps its one
/// implementation ([`AppState`], forwarding to the same inherent methods it
/// always called), and tests supply
/// `fault::FaultyTenantScopeReads`, which can be armed to fail any
/// individual read.
///
/// The next resolver that reads storage to decide a scope extends this trait
/// with its read and gets fault injection for free -- add the method here,
/// forward it in the `AppState` impl, add the `fault::TenantScopeRead`
/// variant, and the failing store already covers it.
#[async_trait]
pub(crate) trait TenantScopeReads: Send + Sync {
    /// Every role in the platform catalog. Read by `rbac_catalog_scope` to
    /// expand a tenant's bound role ids into the permission keys they compose.
    async fn list_roles(&self) -> anyhow::Result<Vec<StoredRole>>;

    /// The role bindings held by one tenant -- the reachable slice of the RBAC
    /// catalog for a tenant-scoped caller.
    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<StoredTenantRoleBinding>>;

    /// Resolves a `QuotaScopeKind::Project` id to its owning tenant.
    async fn get_project(&self, id: &str) -> anyhow::Result<Option<StoredProject>>;

    /// Resolves a `QuotaScopeKind::Workspace` id to its owning tenant.
    async fn get_workspace(&self, id: &str) -> anyhow::Result<Option<StoredWorkspace>>;

    /// Resolves a `QuotaScopeKind::Key` id to its owning tenant.
    async fn get_virtual_api_key(&self, id: &str) -> anyhow::Result<Option<StoredApiKey>>;
}

/// The one production implementation: straight forwarding to the inherent
/// `AppState` methods the resolvers called before the seam existed, so the
/// seam adds no behavior of its own to the request path.
#[async_trait]
impl TenantScopeReads for AppState {
    async fn list_roles(&self) -> anyhow::Result<Vec<StoredRole>> {
        // Inherent methods shadow trait methods, so these are the `AppState`
        // storage calls, not a recursion back into this impl.
        AppState::list_roles(self).await
    }

    async fn list_tenant_role_bindings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<StoredTenantRoleBinding>> {
        AppState::list_tenant_role_bindings(self, tenant_id).await
    }

    async fn get_project(&self, id: &str) -> anyhow::Result<Option<StoredProject>> {
        AppState::get_project(self, id).await
    }

    async fn get_workspace(&self, id: &str) -> anyhow::Result<Option<StoredWorkspace>> {
        AppState::get_workspace(self, id).await
    }

    async fn get_virtual_api_key(&self, id: &str) -> anyhow::Result<Option<StoredApiKey>> {
        AppState::get_virtual_api_key(self, id).await
    }
}

/// The test-only failing store that the seam exists for. Kept in its own
/// `#[cfg(test)]` module so no production build compiles a fault path.
#[cfg(test)]
#[path = "tenant_scope_reads_fault.rs"]
pub(crate) mod fault;
