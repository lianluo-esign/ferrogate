// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Authoritative server-side validation of a native API key's
// tenancy references (issue #340) -- the API-side half of the admin console's
// project -> workspace cascade.

use http::StatusCode;

use crate::config::ApiKey;
use ferrogate_storage::{StoredProject, StoredWorkspace};

/// Why an api-key upsert's `organization_id`/`project_id`/`workspace_id`
/// combination was refused.
///
/// Before issue #340 the upsert handler copied all three fields verbatim, so
/// `POST`/`PUT /admin/v1/api-keys` happily persisted project A paired with a
/// workspace that lives under project B (and therefore, transitively, under a
/// different tenant). The admin console blocked that combination client-side
/// only, which is a UI convention rather than an invariant: any curl, SDK or
/// stale console build could still write it, and the runtime would then resolve
/// quota/attribution scopes against a hierarchy that contradicts itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ApiKeyTenancyRejection {
    /// The workspace exists but is parented by a different project than the one
    /// the payload pairs it with -- the exact combination the console cascade
    /// prevents.
    WorkspaceProjectMismatch {
        workspace_id: String,
        workspace_project_id: String,
        project_id: String,
    },
    /// A referenced project/workspace is owned by a tenant other than the key's
    /// declared `organization_id`.
    TenantMismatch {
        reference: &'static str,
        reference_id: String,
        owner_tenant_id: String,
        organization_id: String,
    },
}

impl ApiKeyTenancyRejection {
    /// Both edges are malformed *input* rather than a missing resource: every
    /// id in the payload names a real row, they just contradict each other.
    pub(super) fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    pub(super) fn code(&self) -> &'static str {
        "invalid_api_key"
    }

    pub(super) fn message(&self) -> String {
        match self {
            Self::WorkspaceProjectMismatch {
                workspace_id,
                workspace_project_id,
                project_id,
            } => format!(
                "workspace {workspace_id} belongs to project {workspace_project_id}, not to \
                 project {project_id}"
            ),
            Self::TenantMismatch {
                reference,
                reference_id,
                owner_tenant_id,
                organization_id,
            } => format!(
                "{reference} {reference_id} belongs to tenant {owner_tenant_id}, not to \
                 organization {organization_id}"
            ),
        }
    }
}

fn present(value: Option<&String>) -> Option<&str> {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

/// The tenancy references an api-key upsert needs resolved before it can be
/// validated. `None` means the payload left that field empty (a key that is not
/// scoped to a project/workspace at all stays legal -- this validation
/// constrains the *combination*, it does not make the hierarchy mandatory).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ApiKeyTenancyRefs<'a> {
    pub(super) organization_id: Option<&'a str>,
    pub(super) project_id: Option<&'a str>,
    pub(super) workspace_id: Option<&'a str>,
}

impl<'a> ApiKeyTenancyRefs<'a> {
    pub(super) fn from_key(key: &'a ApiKey) -> Self {
        Self {
            organization_id: present(key.organization_id.as_ref()),
            project_id: present(key.project_id.as_ref()),
            workspace_id: present(key.workspace_id.as_ref()),
        }
    }

    pub(super) fn needs_lookup(&self) -> bool {
        self.project_id.is_some() || self.workspace_id.is_some()
    }
}

/// What an accepted api-key upsert's tenancy references resolved to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ApiKeyTenancyOutcome {
    /// The tenant that owns the resolved project/workspace, when either
    /// resolved. The handler authorizes the caller against it.
    pub(super) owner_tenant_id: Option<String>,
    /// References that name no control-plane row (`"project ghost-1"`).
    ///
    /// These are deliberately *not* a rejection. A native api-key is a
    /// config-plane credential: the very same key can be declared in
    /// `ferrogate.toml`, where `Config::validate` performs no storage lookup at
    /// all (it is sync and storage-free), and operator bootstrap flows routinely
    /// scope a key to a project/workspace that is created later or in another
    /// system. Refusing here would make the admin API stricter than the config
    /// path for no invariant gain: an id that resolves to nothing cannot form a
    /// cross-tenant *combination*, and the runtime already falls back to "no
    /// override at that scope". They are surfaced in the audit trail and the
    /// gateway log instead of being swallowed silently.
    pub(super) unresolved: Vec<String>,
}

/// Pure decision for the api-key tenancy invariant, given the rows the handler
/// resolved (`None` = the id was not found in storage).
///
/// The rules, in order:
/// 1. when both a project and a workspace resolve, the workspace must be
///    parented by that project;
/// 2. when `organization_id` is set, every row that resolved must be owned by
///    it;
/// 3. anything that did not resolve is reported as `unresolved` (see
///    [`ApiKeyTenancyOutcome::unresolved`]) rather than refused.
pub(super) fn check_api_key_tenancy(
    refs: ApiKeyTenancyRefs<'_>,
    project: Option<&StoredProject>,
    workspace: Option<&StoredWorkspace>,
) -> Result<ApiKeyTenancyOutcome, ApiKeyTenancyRejection> {
    let project = refs.project_id.and(project);
    let workspace = refs.workspace_id.and(workspace);

    if let (Some(project), Some(workspace)) = (project, workspace) {
        if workspace.project_id != project.id {
            return Err(ApiKeyTenancyRejection::WorkspaceProjectMismatch {
                workspace_id: workspace.id.clone(),
                workspace_project_id: workspace.project_id.clone(),
                project_id: project.id.clone(),
            });
        }
    }

    if let Some(organization_id) = refs.organization_id {
        if let Some(project) = project {
            if project.tenant_id != organization_id {
                return Err(ApiKeyTenancyRejection::TenantMismatch {
                    reference: "project",
                    reference_id: project.id.clone(),
                    owner_tenant_id: project.tenant_id.clone(),
                    organization_id: organization_id.to_string(),
                });
            }
        }
        if let Some(workspace) = workspace {
            if workspace.tenant_id != organization_id {
                return Err(ApiKeyTenancyRejection::TenantMismatch {
                    reference: "workspace",
                    reference_id: workspace.id.clone(),
                    owner_tenant_id: workspace.tenant_id.clone(),
                    organization_id: organization_id.to_string(),
                });
            }
        }
    }

    let mut unresolved = Vec::new();
    if let Some(project_id) = refs.project_id.filter(|_| project.is_none()) {
        unresolved.push(format!("project {project_id}"));
    }
    if let Some(workspace_id) = refs.workspace_id.filter(|_| workspace.is_none()) {
        unresolved.push(format!("workspace {workspace_id}"));
    }

    Ok(ApiKeyTenancyOutcome {
        // Prefer the workspace's tenant: it is the deepest resolved row, and
        // rule 1 already proved it agrees with the project's when both resolved.
        owner_tenant_id: workspace
            .map(|workspace| workspace.tenant_id.clone())
            .or_else(|| project.map(|project| project.tenant_id.clone())),
        unresolved,
    })
}

#[cfg(test)]
#[path = "api_key_tenancy_test.rs"]
mod api_key_tenancy_test;
