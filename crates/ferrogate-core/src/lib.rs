// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Shared FerroGate domain primitives.
//!
//! # What belongs here (issue #553's open question, answered)
//!
//! The rule this crate is held to: a type belongs here when more than one
//! layer must AGREE on how to read it, and reading it needs nothing from a
//! layer above. [`TenantContext`] and [`WorkspaceScope`] are the model: they
//! say who a request is attributed to, and every crate that touches
//! attribution reads them the same way.
//!
//! Two types were named explicitly by the `ferrogate-gateway` extraction, and
//! they come out opposite ways:
//!
//! * `CallerScope` (today `ferrogate-cli`'s `auth.rs`) **belongs here**. It is
//!   the authorization reading of the identity [`TenantContext`] is the
//!   attribution reading of, and issue #515 exists precisely because that
//!   question used to be re-derived as `organization_id.is_none()` at a dozen
//!   call sites. Once the Admin API surface lives in `ferrogate-gateway` while
//!   `ctl` and the standalone admin-api service stay in `ferrogate-cli`, both
//!   sides must read a caller's scope; if the type does not sit under both,
//!   one of them re-derives it and #515's defect returns. `UNSCOPED_TENANT_ID`
//!   moves with it -- the sentinel is part of the type's meaning.
//! * `AuthContext` **does not**. It is the OUTPUT of the authentication
//!   pipeline, carrying a `ferrogate_policy::EffectiveQuota` and a
//!   `ferrogate_auth::PolicySubject`, so moving it down would drag
//!   `ferrogate-policy` and `ferrogate-auth` underneath the crate they are
//!   built on. It travels sideways into `ferrogate-gateway` with the handlers
//!   that consume it, not downward.
//!
//! Neither move is made yet: see `ferrogate-gateway/src/lib.rs` for why stage
//! 2 did not need either one.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Key-name fragments that must never appear anywhere in an admin/diagnostics
/// response, at any nesting depth.
///
/// Shared so a guard and the surface it guards cannot drift: the x402
/// spend-policy slice (issue #351) shipped two independent copies of this list,
/// one of which had already lost `seed` and `token`, which silently made the
/// weaker copy the effective bar. A single definition means adding a fragment
/// tightens every guard at once.
///
/// Matching is substring, case-insensitive: callers lowercase the key and test
/// `contains`.
pub const SECRET_SHAPED_KEY_FRAGMENTS: &[&str] = &[
    "secret",
    "signer",
    "signature",
    "private",
    "keypair",
    "mnemonic",
    "seed",
    "credential",
    "password",
    "token",
];

/// Approval policy attached to a tool or MCP binding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPolicy {
    #[default]
    Never,
    Always,
}

/// Request identity that can be passed across runtime, auth, routing, and logs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub trace_id: Option<String>,
    #[serde(default)]
    pub agent_run_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub workflow_version: Option<u32>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    pub route: Option<String>,
    pub upstream: Option<String>,
    pub tenant: TenantContext,
}

/// Tenant fields resolved from virtual API keys or future admin control-plane data.
///
/// `organization_id` is the top-level tenant/billing boundary, `project_id` the
/// business-line grouping, and `workspace_id` the environment (dev/staging/prod)
/// that a virtual API key ultimately binds to. `workspace_id` is additive and
/// `#[serde(default)]` so existing serialized contexts (which predate the
/// multi-tenant hierarchy) still deserialize unchanged.
///
/// `organization_id` IS the tenant id (`tenants.id`, `StoredProject.tenant_id`,
/// `StoredVirtualApiKey.tenant_id`) -- the field is named for the API-facing
/// spelling, not for a second, looser concept. It is load-bearing for
/// authorization, not merely attribution: the gateway's tenant-isolation
/// checks compare the caller's `organization_id` against the tenant that owns
/// the resource being reached. `None` therefore means "this identity names no
/// tenant", which is only legitimate for a platform operator, and since issue
/// #515 that has to be declared (`ApiKey::platform_operator`) rather than
/// inferred from this field being absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    pub organization_id: Option<String>,
    pub team_id: Option<String>,
    pub project_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub user_id: Option<String>,
    pub api_key_id: Option<String>,
}

/// Fully resolved attribution chain for a workspace: the workspace itself plus the
/// project and tenant it rolls up to. Produced when a virtual API key (bound to a
/// workspace) is resolved, and reused for routing, quota, metering, and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceScope {
    pub tenant_id: String,
    pub project_id: String,
    pub workspace_id: String,
}

impl WorkspaceScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        workspace_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            workspace_id: workspace_id.into(),
        }
    }

    /// Overlay this scope onto a [`TenantContext`], mapping the tenant to
    /// `organization_id`, and filling `project_id` / `workspace_id`.
    pub fn apply_to(&self, tenant: &mut TenantContext) {
        tenant.organization_id = Some(self.tenant_id.clone());
        tenant.project_id = Some(self.project_id.clone());
        tenant.workspace_id = Some(self.workspace_id.clone());
    }
}

/// Canonical tool definition shared by provider adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
}

/// Canonical tool call emitted by a model response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// Canonical tool result appended to a follow-up model request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub content: Value,
    pub is_error: bool,
}

pub type Result<T> = std::result::Result<T, GatewayError>;

/// Boundary error used by skeleton crates until domain-specific errors are added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayError {
    pub code: String,
    pub message: String,
}

impl GatewayError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_context_deserializes_legacy_payload_without_workspace_id() {
        // Payload written before the multi-tenant hierarchy existed: no workspace_id.
        let legacy = r#"{
            "organization_id": "org-1",
            "team_id": "team-1",
            "project_id": "proj-1",
            "user_id": "user-1",
            "api_key_id": "key-1"
        }"#;

        let tenant: TenantContext =
            serde_json::from_str(legacy).expect("legacy payload deserializes");
        assert_eq!(tenant.organization_id.as_deref(), Some("org-1"));
        assert_eq!(tenant.project_id.as_deref(), Some("proj-1"));
        assert_eq!(tenant.workspace_id, None);
    }

    #[test]
    fn tenant_context_roundtrips_with_workspace_id() {
        let tenant = TenantContext {
            organization_id: Some("org-1".into()),
            team_id: None,
            project_id: Some("proj-1".into()),
            workspace_id: Some("ws-1".into()),
            user_id: None,
            api_key_id: Some("key-1".into()),
        };

        let encoded = serde_json::to_string(&tenant).expect("serialize");
        let decoded: TenantContext = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, tenant);
        assert_eq!(decoded.workspace_id.as_deref(), Some("ws-1"));
    }

    #[test]
    fn workspace_scope_applies_attribution_chain() {
        let scope = WorkspaceScope::new("tenant-1", "project-1", "workspace-1");
        let mut tenant = TenantContext::default();
        scope.apply_to(&mut tenant);

        assert_eq!(tenant.organization_id.as_deref(), Some("tenant-1"));
        assert_eq!(tenant.project_id.as_deref(), Some("project-1"));
        assert_eq!(tenant.workspace_id.as_deref(), Some("workspace-1"));
    }
}
