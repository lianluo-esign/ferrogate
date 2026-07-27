// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: THE lifecycle decision for the control-plane `status` column
// (issue #514) plus the repository-level chain resolver both enforcement seams
// share. This lives in `ferrogate-storage` -- the crate that owns the rows --
// rather than in `ferrogate-cli`, because "one place per seam" is only true if
// EVERY credential-minting caller can reach it. The first landing put the
// decision in `ferrogate-cli`, which left `ferrogate-auth-service`'s admin-console
// login/register/SSO paths unable to call it: they kept minting live gateway
// keys under a suspended tenant, which is literally the probe row the issue
// enumerates.

use async_trait::async_trait;

use crate::{
    LifecycleStatus, RuntimeStorageRepositories, StorageError, StoredProject, StoredTenantAccount,
    StoredWorkspace,
};

/// Which seam is asking. The three are separate because they answer different
/// questions and are reached by different code paths -- but they share the
/// vocabulary, the chain resolution and the rejection shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleSeam {
    /// A credential is being used to serve a request. This is the seam that
    /// matters for billing: a suspended tenant must stop generating spend.
    Request,
    /// The request being authenticated is one of the few that exist to get an
    /// off hierarchy back on: reading/writing a row's own lifecycle `status`,
    /// and minting the admin-console session credential needed to do it.
    ///
    /// `disabled` is documented as the TENANT's own "turn this project off"
    /// switch ([`LifecycleStatus::Disabled`]). Gating the re-enable path on it
    /// would make it a one-way door: a tenant whose console key is scoped to
    /// the project it just disabled could never reach the PUT that reverses it,
    /// and would need platform-operator intervention to undo its own,
    /// self-service action. So `disabled` is allowed through HERE and only
    /// here. `suspended` and `deleted` still deny: both are platform-operator
    /// actions, and reversing them is a platform-operator job by design (an
    /// operator key carries no tenancy chain, so it is never gated at all).
    Recovery,
    /// A new row is being created under, or pointed at, an existing hierarchy
    /// row. Without this, "suspend the tenant" is undone by minting a fresh
    /// key under it.
    Attach,
}

impl LifecycleSeam {
    fn allows(self, status: LifecycleStatus) -> bool {
        match self {
            Self::Request => status.allows_requests(),
            Self::Recovery => status.allows_recovery(),
            Self::Attach => status.allows_attach(),
        }
    }
}

/// The `tenant -> project -> workspace` ids a caller declares. Passed as one
/// value (rather than three positional `Option<&str>`s that are trivially
/// transposed at a call site) because every seam takes exactly this triple.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenancyRefs<'a> {
    pub tenant_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
}

impl<'a> TenancyRefs<'a> {
    pub fn new(
        tenant_id: Option<&'a str>,
        project_id: Option<&'a str>,
        workspace_id: Option<&'a str>,
    ) -> Self {
        Self {
            tenant_id,
            project_id,
            workspace_id,
        }
    }

    /// A tenant-only reference (the admin-console session and refresh-token
    /// seams, which know nothing deeper than the session's tenant).
    pub fn tenant(tenant_id: &'a str) -> Self {
        Self {
            tenant_id: Some(tenant_id),
            ..Self::default()
        }
    }

    fn is_empty(&self) -> bool {
        present(self.tenant_id).is_none()
            && present(self.project_id).is_none()
            && present(self.workspace_id).is_none()
    }
}

fn present(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// One resolved ancestor in the `tenant -> project -> workspace` chain.
///
/// A reference whose row does NOT exist is simply absent from the chain: the
/// api-key tenancy rules already treat a dangling reference as "resolves to
/// nothing" rather than a rejection (see `ApiKeyTenancyOutcome::unresolved`),
/// and inventing a denial here would make a typo indistinguishable from a
/// suspension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRef {
    /// `"tenant"`, `"project"` or `"workspace"` -- used verbatim in the
    /// rejection message.
    pub kind: &'static str,
    pub id: String,
    pub status: LifecycleStatus,
}

impl LifecycleRef {
    pub fn new(kind: &'static str, id: impl Into<String>, raw_status: &str) -> Self {
        Self {
            kind,
            id: id.into(),
            status: LifecycleStatus::parse(raw_status),
        }
    }
}

/// A typed refusal. Rendered as a 403 with a distinguishable, machine-readable
/// code -- never a panic, never a generic 500, and deliberately not a 404 (the
/// resource exists; the caller is simply not allowed to use it right now, and
/// hiding that would make "suspended" indistinguishable from "typo").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRejection {
    pub seam: LifecycleSeam,
    pub reference: LifecycleRef,
}

impl LifecycleRejection {
    /// Kept as a bare `u16` rather than an `http::StatusCode` so the storage
    /// crate does not grow an HTTP dependency for one enum; both HTTP surfaces
    /// (`ferrogate-cli`'s pingora handlers and `ferrogate-auth-service`'s hand-rolled
    /// side-service responder) already speak in codes at their boundary.
    pub fn http_status(&self) -> u16 {
        403
    }

    /// Distinguishable per seam AND per state, so a client can tell "your
    /// account is suspended, pay the bill" from "you pointed a new key at a
    /// deleted workspace".
    pub fn code(&self) -> &'static str {
        match (self.seam, self.reference.status) {
            (LifecycleSeam::Attach, _) => "inactive_tenancy_reference",
            (_, LifecycleStatus::Suspended) => "tenancy_suspended",
            (_, LifecycleStatus::Disabled) => "tenancy_disabled",
            (_, LifecycleStatus::Deleted) => "tenancy_deleted",
            // Unreachable: an Active status never produces a rejection. Kept
            // total rather than `unreachable!()` so a future variant can never
            // turn this seam into a panic.
            (_, LifecycleStatus::Active) => "tenancy_inactive",
        }
    }

    pub fn message(&self) -> String {
        let LifecycleRef { kind, id, status } = &self.reference;
        match self.seam {
            LifecycleSeam::Request | LifecycleSeam::Recovery => format!(
                "{kind} {id} is {}; requests authenticated against this tenancy chain are refused",
                status.as_str()
            ),
            LifecycleSeam::Attach => format!(
                "{kind} {id} is {}; it cannot be referenced by a new resource",
                status.as_str()
            ),
        }
    }
}

/// THE decision, for every seam.
///
/// `chain` must be ordered shallowest-first (tenant, then project, then
/// workspace) so the rejection names the ROOT cause: when an operator suspends
/// a tenant and the cascade marks its project and workspace too, the caller is
/// told the tenant is suspended rather than being sent chasing the workspace.
/// [`resolve_lifecycle_chain`] is the only supported way to build one.
pub fn check_lifecycle_chain(
    seam: LifecycleSeam,
    chain: &[LifecycleRef],
) -> Result<(), LifecycleRejection> {
    for reference in chain {
        if !seam.allows(reference.status) {
            return Err(LifecycleRejection {
                seam,
                reference: reference.clone(),
            });
        }
    }
    Ok(())
}

/// What a seam check can go wrong with. Storage being unreachable is NOT
/// silently treated as "active": it is a retryable 503, matching how
/// `finalize_auth` already surfaces a failed quota-policy lookup. Fail-open
/// here would hand every suspended tenant a trivial bypass (make the control
/// plane flap and keep serving).
#[derive(Debug)]
pub enum LifecycleGateError {
    Unavailable(String),
    Inactive(LifecycleRejection),
}

impl LifecycleGateError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Unavailable(_) => 503,
            Self::Inactive(rejection) => rejection.http_status(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "lifecycle_status_unavailable",
            Self::Inactive(rejection) => rejection.code(),
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Unavailable(error) => format!("tenancy lifecycle lookup failed: {error}"),
            Self::Inactive(rejection) => rejection.message(),
        }
    }
}

/// The three row reads [`resolve_lifecycle_chain`] needs, as a trait rather
/// than a concrete handle for two reasons: `ferrogate-auth-service` and
/// `ferrogate-cli` reach storage through different wrappers, and a test can
/// implement a *failing* source to hold the fail-closed claim (a claim that,
/// as landed, no test held -- swapping the error mapping for
/// `unwrap_or_default()` changed no assertion).
#[async_trait]
pub trait LifecycleRowSource: Sync {
    async fn lifecycle_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError>;
    async fn lifecycle_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError>;
    async fn lifecycle_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError>;
}

#[async_trait]
impl LifecycleRowSource for RuntimeStorageRepositories {
    async fn lifecycle_tenant_account(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        self.get_tenant_account(id).await
    }

    async fn lifecycle_project(&self, id: &str) -> Result<Option<StoredProject>, StorageError> {
        self.get_project(id).await
    }

    async fn lifecycle_workspace(&self, id: &str) -> Result<Option<StoredWorkspace>, StorageError> {
        self.get_workspace(id).await
    }
}

fn push_unique(ids: &mut Vec<String>, candidate: &str) {
    let candidate = candidate.trim();
    if candidate.is_empty() || ids.iter().any(|existing| existing == candidate) {
        return;
    }
    ids.push(candidate.to_string());
}

/// Resolve the lifecycle `status` of every row in the caller's tenancy chain,
/// shallowest first -- **walking the hierarchy, not the caller's declaration**.
///
/// This is the fix for the issue's headline symptom. The first landing did
/// three independent lookups and pushed only the rows the caller NAMED, which
/// meant a credential that declares only a `project_id` (entirely legal: a
/// native api-key's `organization_id` is optional) produced the chain
/// `[project(active)]` and the suspended TENANT above it was never read at all.
/// Suspending a tenant therefore did not stop its projects' keys -- the exact
/// bypass the gate exists to close, reproduced inside the gate.
///
/// The rule now:
///
/// 1. resolve the declared workspace, if any; it carries `project_id` and
///    `tenant_id`, so its ancestors join the chain even when the caller named
///    neither;
/// 2. resolve every candidate project -- the declared one AND the workspace's
///    parent -- each of which carries `tenant_id`;
/// 3. resolve every candidate tenant -- the declared one AND every ancestor
///    discovered above.
///
/// Declared and derived ids are UNIONed, not substituted: when a caller names a
/// tenant that disagrees with the row's own parent (a shape
/// `check_api_key_tenancy` refuses with a 400, but which pre-existing rows may
/// still hold), both are checked and either one being inactive denies. There is
/// no ordering in which a suspended ancestor is skipped.
///
/// Ids that are `None`, blank, or that name no row are skipped -- absence is
/// not suspension (see [`LifecycleRef`]). Lookups are deduped, so a fully
/// declared, self-consistent triple still costs exactly three reads.
pub async fn resolve_lifecycle_chain<S>(
    source: &S,
    refs: TenancyRefs<'_>,
) -> Result<Vec<LifecycleRef>, StorageError>
where
    S: LifecycleRowSource + ?Sized,
{
    if refs.is_empty() {
        return Ok(Vec::new());
    }

    let mut tenant_ids: Vec<String> = Vec::new();
    let mut project_ids: Vec<String> = Vec::new();
    let mut workspaces: Vec<StoredWorkspace> = Vec::new();

    if let Some(tenant_id) = present(refs.tenant_id) {
        push_unique(&mut tenant_ids, tenant_id);
    }
    if let Some(project_id) = present(refs.project_id) {
        push_unique(&mut project_ids, project_id);
    }
    if let Some(workspace_id) = present(refs.workspace_id) {
        if let Some(workspace) = source.lifecycle_workspace(workspace_id).await? {
            // Backfill from the row itself: this is what makes the walk a walk.
            push_unique(&mut project_ids, &workspace.project_id);
            push_unique(&mut tenant_ids, &workspace.tenant_id);
            workspaces.push(workspace);
        }
    }

    let mut projects: Vec<StoredProject> = Vec::new();
    for project_id in &project_ids {
        if let Some(project) = source.lifecycle_project(project_id).await? {
            push_unique(&mut tenant_ids, &project.tenant_id);
            projects.push(project);
        }
    }

    let mut chain = Vec::with_capacity(tenant_ids.len() + projects.len() + workspaces.len());
    for tenant_id in &tenant_ids {
        if let Some(account) = source.lifecycle_tenant_account(tenant_id).await? {
            chain.push(LifecycleRef::new("tenant", account.id, &account.status));
        }
    }
    for project in projects {
        chain.push(LifecycleRef::new("project", project.id, &project.status));
    }
    for workspace in workspaces {
        chain.push(LifecycleRef::new(
            "workspace",
            workspace.id,
            &workspace.status,
        ));
    }
    Ok(chain)
}

/// The single chokepoint every #514 seam calls: resolve the chain by walking
/// the hierarchy, then run the shared pure decision over it.
///
/// A storage failure is reported as [`LifecycleGateError::Unavailable`]
/// (retryable 503), never swallowed into "active" -- otherwise a flapping
/// control plane would be a suspension bypass.
pub async fn check_usable_tenancy<S>(
    source: &S,
    seam: LifecycleSeam,
    refs: TenancyRefs<'_>,
) -> Result<(), LifecycleGateError>
where
    S: LifecycleRowSource + ?Sized,
{
    let chain = resolve_lifecycle_chain(source, refs)
        .await
        .map_err(|error| LifecycleGateError::Unavailable(error.to_string()))?;
    check_lifecycle_chain(seam, &chain).map_err(LifecycleGateError::Inactive)
}

impl RuntimeStorageRepositories {
    /// Convenience wrapper over [`check_usable_tenancy`] so callers holding an
    /// `Arc<RuntimeStorageRepositories>` (the admin console, the gateway's
    /// `AppState`) reach the shared gate through method syntax.
    pub async fn require_usable_tenancy(
        &self,
        seam: LifecycleSeam,
        refs: TenancyRefs<'_>,
    ) -> Result<(), LifecycleGateError> {
        check_usable_tenancy(self, seam, refs).await
    }
}

#[cfg(test)]
#[path = "lifecycle_gate_test.rs"]
mod lifecycle_gate_test;
