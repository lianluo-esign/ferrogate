// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the multi-tenant control-plane
// hierarchy (TOK-11/TOK-12) -- tenant-account, sellable-plan, project,
// workspace, virtual-key, and quota-policy CRUD.

use super::*;

use crate::auth::AuthError;
use crate::lifecycle_gate::{LifecycleSeam, TenancyRefs};

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

    /// Build the attribution [`ferrogate_core::TenantContext`] for a runtime
    /// record that only carries the `(tenant_id, workspace_id)` pair -- managed
    /// worker lifecycle records and framework-adapter sessions both do.
    ///
    /// Issue #519: these call sites used to write the workspace id into the
    /// `project_id` slot, which is a different entity in the
    /// `tenant -> project -> workspace` hierarchy. Everything that keys on
    /// `TenantContext::project_id` -- the `QuotaScopeKind::Project` lookup in
    /// [`AppState::resolve_effective_quota`], billing attribution, and the
    /// project column of every persisted audit/evidence row -- was therefore
    /// keyed on a scope id that does not name a project at all.
    ///
    /// The project is never guessed: it is read back off the workspace row,
    /// the same #514 "backfill ancestors from resolved rows, do not trust a
    /// declared triple" rule the lifecycle gate uses. `project_id` stays
    /// `None` -- meaning "no project scope", which every consumer already
    /// handles -- when the workspace is unknown, when the control-plane read
    /// fails, or when the resolved chain roots in a *different* tenant than
    /// the record declares (a mismatch must never leak one tenant's project id
    /// onto another tenant's row).
    ///
    /// Callers that make an *enforcement* decision on this context must use
    /// [`AppState::workspace_attribution`] instead: `project_id: None` is
    /// ambiguous between "this record has no project" and "we could not find
    /// out", and the two are not interchangeable at a seam where a
    /// project-scoped policy is what decides. This method is for the evidence
    /// writers, which only need the row's attribution.
    pub(crate) fn workspace_attribution_context(
        &self,
        tenant_id: &str,
        workspace_id: &str,
    ) -> ferrogate_core::TenantContext {
        self.workspace_attribution(tenant_id, workspace_id).tenant
    }

    /// [`AppState::workspace_attribution_context`] plus the reason the project
    /// slot holds what it holds (issue #519 review).
    pub(crate) fn workspace_attribution(
        &self,
        tenant_id: &str,
        workspace_id: &str,
    ) -> WorkspaceAttribution {
        // Both callers are synchronous (the external-action authorizer runs on
        // a plain std::thread worker with no tokio runtime); bridge with the
        // same helper `managed_worker_capability_policy_for_tenant` uses.
        let project = project_attribution_from_lookup(
            tenant_id,
            workspace_id,
            ferrogate_sync_bridge::block_on_sync_bridge(
                self.repositories.resolve_workspace_scope(workspace_id),
            ),
        );
        WorkspaceAttribution {
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(tenant_id.to_string()),
                team_id: None,
                project_id: project.project_id().map(str::to_string),
                workspace_id: Some(workspace_id.to_string()),
                user_id: None,
                api_key_id: None,
            },
            project,
        }
    }

    /// The id of an enforcing managed-action guardrail policy that declares
    /// `project_ids` and would be *selected* for `action` under `tenant` if the
    /// project were known (issue #519 review).
    ///
    /// This exists because guardrail policy selection is an enforcement input,
    /// not an audit field: `PolicyScopeSelector::matches` runs
    /// `matches_optional(&self.project_ids, context.project_id)`, which is
    /// `false` for `project_id: None`. So an unresolved project silently
    /// *deselects* every project-scoped policy and the action is allowed --
    /// exactly the "project scoping does not bind" failure #519 is about, only
    /// now on the enforcement side. The caller refuses instead.
    ///
    /// The predicate does not restate the matcher's rules, it *runs* them: a
    /// policy could have applied iff substituting one of its own declared
    /// project ids for the unknown one makes every other dimension match. The
    /// non-project dimensions are pinned to the values
    /// `evaluate_managed_action_guardrail_async` passes (all `None` but the
    /// tenant and the managed action), so the two cannot drift apart silently.
    ///
    /// It is deliberately conservative in one direction: a selected policy's
    /// *verdict* is unknowable without running its detectors, so any enforcing
    /// (non-shadow) policy with an enabled request-stage check counts, even
    /// though it might have passed the action. Shadow policies and policies
    /// with no enabled request-stage check are excluded because
    /// `match_guardrail` can never block on them.
    pub(crate) fn project_scoped_managed_action_guardrail_policy(
        &self,
        tenant: &ferrogate_core::TenantContext,
        action: ferrogate_guardrails::ManagedActionContext<'_>,
    ) -> Option<String> {
        self.guardrail_policies.iter().find_map(|policy| {
            let scope = &policy.revision.scope;
            if scope.project_ids.is_empty() || policy.revision.mode == PolicyMode::Shadow {
                return None;
            }
            if !policy
                .checks
                .iter()
                .any(|check| check.enabled && check.stage == DetectorStage::Request)
            {
                return None;
            }
            scope
                .project_ids
                .iter()
                .any(|project_id| {
                    scope.matches(PolicySelectionContext {
                        organization_id: tenant.organization_id.as_deref(),
                        project_id: Some(project_id.as_str()),
                        workspace_id: tenant.workspace_id.as_deref(),
                        api_key_id: tenant.api_key_id.as_deref(),
                        service_account_id: None,
                        gateway_config_id: None,
                        model: None,
                        provider: None,
                        managed_action: Some(action),
                    })
                })
                .then(|| policy.revision.policy_id.clone())
        })
    }

    /// The gateway's entry into the shared #514 lifecycle gate.
    ///
    /// Everything of substance -- the hierarchy walk that backfills ancestors
    /// a credential never named, the pure per-seam decision, and the
    /// fail-CLOSED mapping of a control-plane read failure onto a retryable
    /// 503 -- lives in `ferrogate_storage::check_usable_tenancy`, shared with
    /// `ferrogate-auth`'s admin-console credential mints. This method exists
    /// only to hand back this crate's [`AuthError`], so a lifecycle refusal is
    /// rendered by the same three lines every `authenticate()` refusal is.
    pub(crate) async fn require_usable_tenancy(
        &self,
        seam: LifecycleSeam,
        refs: TenancyRefs<'_>,
    ) -> Result<(), AuthError> {
        self.repositories
            .require_usable_tenancy(seam, refs)
            .await
            .map_err(AuthError::from)
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

/// The attribution built for a runtime record that carries only
/// `(tenant_id, workspace_id)` -- see
/// [`AppState::workspace_attribution_context`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceAttribution {
    pub(crate) tenant: ferrogate_core::TenantContext,
    pub(crate) project: ProjectAttribution,
}

/// What the control plane was able to say about the project a workspace rolls
/// up to (issue #519).
///
/// The two unresolved cases are kept apart from each other and from `Resolved`
/// because `project_id: None` alone cannot distinguish them, and an
/// enforcement seam needs the difference: `Unknown` is an *answer* (the
/// control plane holds no chain for this workspace, or holds one rooted in a
/// different tenant than the record declares), while `Unavailable` is the
/// absence of an answer -- a transient read failure. Neither may be read as
/// "no project scope applies here".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectAttribution {
    /// The workspace resolved and its chain roots in the declared tenant.
    Resolved(String),
    /// The control plane answered, and the answer names no usable project.
    Unknown,
    /// The control-plane read failed; the project is not knowable right now.
    Unavailable,
}

impl ProjectAttribution {
    pub(crate) fn project_id(&self) -> Option<&str> {
        match self {
            Self::Resolved(project_id) => Some(project_id.as_str()),
            Self::Unknown | Self::Unavailable => None,
        }
    }

    pub(crate) fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }
}

/// The whole of #519's decision, as a pure function of the control-plane
/// lookup, so every arm -- including the read-failure arm, which no storage
/// backend in the repo can produce -- is reachable from a test without a
/// fault-injecting `ControlPlaneStore`.
///
/// Generic over the error so a test can hand it any failure; the production
/// caller passes `Result<_, StorageError>`.
fn project_attribution_from_lookup<E: std::fmt::Display>(
    tenant_id: &str,
    workspace_id: &str,
    lookup: Result<Option<WorkspaceScope>, E>,
) -> ProjectAttribution {
    match lookup {
        Ok(Some(scope)) if scope.tenant_id == tenant_id => {
            ProjectAttribution::Resolved(scope.project_id)
        }
        // A chain rooted in a different tenant than the record declares:
        // attributing tenant B's project id onto tenant A's row would be a
        // cross-tenant leak into the billing and audit key, so it is dropped
        // rather than trusted.
        Ok(Some(scope)) => {
            warn!(
                "workspace {workspace_id} resolves under tenant {} but the record declares {tenant_id}; dropping project attribution",
                scope.tenant_id
            );
            ProjectAttribution::Unknown
        }
        Ok(None) => ProjectAttribution::Unknown,
        Err(error) => {
            warn!("failed to resolve project attribution for workspace {workspace_id}: {error}");
            ProjectAttribution::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(tenant_id: &str) -> Result<Option<WorkspaceScope>, String> {
        Ok(Some(WorkspaceScope::new(
            tenant_id,
            "project-1",
            "workspace-1",
        )))
    }

    /// #519: the happy path -- the project comes off the resolved row, never
    /// off the workspace id.
    #[test]
    fn resolved_chain_in_the_declared_tenant_yields_its_project() {
        assert_eq!(
            project_attribution_from_lookup("tenant-1", "workspace-1", scope("tenant-1")),
            ProjectAttribution::Resolved("project-1".to_string())
        );
    }

    /// #519: a chain rooted in another tenant is dropped, not borrowed.
    #[test]
    fn resolved_chain_in_another_tenant_is_not_attributed() {
        assert_eq!(
            project_attribution_from_lookup("tenant-1", "workspace-1", scope("tenant-2")),
            ProjectAttribution::Unknown
        );
    }

    /// #519: an unknown workspace is an answer -- there is no project to name.
    #[test]
    fn unknown_workspace_is_a_definite_absence_of_project() {
        assert_eq!(
            project_attribution_from_lookup::<String>("tenant-1", "workspace-1", Ok(None)),
            ProjectAttribution::Unknown
        );
    }

    /// #519 review: the read-failure arm. No `ControlPlaneStore` in the repo
    /// can return `Err` from `resolve_workspace_scope` (the in-memory store
    /// returns `Ok(None)` unconditionally), so this arm is reachable only
    /// through the pure function -- which is why it is one.
    ///
    /// It must NOT fabricate the workspace id into the project slot (that is
    /// #519 itself, on the error branch) and it must NOT collapse into
    /// `Unknown`: the caller's enforcement seam distinguishes "no project" from
    /// "no answer".
    #[test]
    fn read_failure_is_unavailable_rather_than_a_fabricated_project() {
        let attribution = project_attribution_from_lookup(
            "tenant-1",
            "workspace-1",
            Err("control plane unreachable"),
        );
        assert_eq!(attribution, ProjectAttribution::Unavailable);
        assert_eq!(attribution.project_id(), None);
        assert!(!attribution.is_resolved());
    }
}
