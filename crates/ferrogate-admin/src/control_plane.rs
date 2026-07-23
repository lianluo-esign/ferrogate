// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! FerroGate Control Plane API — versioned public surface and stability contract.
//!
//! Issue #359 promotes the standalone admin-api into the supported, externally
//! consumable **FerroGate Control Plane API** without breaking existing admin
//! clients. This module is the typed source of truth for two things that were
//! previously only implicit:
//!
//! 1. **Naming.** The service's product name is *FerroGate Control Plane API*.
//!    "Admin API" and the `admin-api` command/config names are retained as a
//!    documented deprecated compatibility alias for the migration window.
//!    OpenAPI describes the interface; it is not the service's product name.
//!
//! 2. **Stability.** Not every runtime admin operation is a public promise.
//!    [`Stability::Stable`] operations form the versioned public surface: their
//!    path, method, `operationId`, auth scope, and request/response schema are
//!    covered by the compatibility baseline gate (`scripts/check-openapi.py`)
//!    and may only change in backward-compatible ways. Everything else stays
//!    [`Stability::Internal`] admin surface that may still evolve.
//!
//! ## What this slice does and does not do
//!
//! This is the first coherent slice of an L-sized epic. It establishes the
//! naming + stability contract and promotes exactly one coherent resource
//! family — **guardrail policies** — as the reference public-stable group.
//! Promotion here is a *stability guarantee expressed additively over the
//! existing routes*: the stable `/admin/v1` paths are unchanged, so existing
//! admin clients keep working byte-for-byte. Per issue #359 the alternate
//! `control-api` command, the `admin_api` → control-plane config migration,
//! and any second URI namespace (`/control/v1` style) are **deferred** to
//! later slices; a URI alias is only allowed once both paths are generated
//! from one route contract with tested behavior parity.
//!
//! Public means *supported and externally consumable*. It does not mean
//! unauthenticated: authentication, `admin.read` / `admin.write` scope
//! enforcement, tenant isolation, and audit evidence remain mandatory on
//! every promoted operation exactly as on the internal admin surface.

use serde::Serialize;

/// Canonical product/service name for the promoted public API.
pub const CONTROL_PLANE_API_TITLE: &str = "FerroGate Control Plane API";

/// Legacy name kept as a documented, deprecated compatibility alias while the
/// migration window is open. Existing `admin-api` clients and tooling that key
/// off this string keep working.
pub const ADMIN_API_LEGACY_TITLE: &str = "FerroGate Admin API";

/// Deprecated command/config alias for the canonical service, retained for the
/// compatibility window (`ferrogate admin-api serve`, the `[admin_api]` config
/// section, and `FERROGATE_ADMIN_*` environment names).
pub const DEPRECATED_ALIAS: &str = "admin-api";

/// Major version of the public Control Plane surface. The stable route prefix
/// already carries this major (`/admin/v1`), so the first slice keeps the
/// public major pinned at `v1` and does not mint a second URI namespace.
pub const PUBLIC_API_MAJOR: &str = "v1";

/// Stable, backward-compatible route prefix for the promoted surface. Held
/// constant this slice so existing admin clients are not broken.
pub const STABLE_PATH_PREFIX: &str = "/admin/v1";

/// HTTP method of a promoted operation. Uppercase string form matches the
/// method keys used in the OpenAPI document and the runtime contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    /// Uppercase wire form, e.g. `"GET"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }

    /// Lowercase form used as an OpenAPI path-item key, e.g. `"get"`.
    #[must_use]
    pub const fn as_openapi_key(self) -> &'static str {
        match self {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Patch => "patch",
            HttpMethod::Delete => "delete",
        }
    }
}

/// Stability tier of a Control Plane operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stability {
    /// Promoted into the versioned public surface. Backward-compatible only;
    /// covered by the compatibility baseline gate. Mirrored in the OpenAPI
    /// document as `x-ferrogate-stability: "stable"`.
    Stable,
    /// Internal admin surface. Still authenticated and enforced, but not part
    /// of the public stability promise; may evolve in later slices.
    Internal,
}

impl Stability {
    /// Lowercase wire form used in the OpenAPI `x-ferrogate-stability` marker.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stability::Stable => "stable",
            Stability::Internal => "internal",
        }
    }
}

/// A single operation on the FerroGate Control Plane API.
///
/// `operation_id`, `method`, and `path` must match the OpenAPI document exactly
/// — the sibling contract test enforces that, so this table cannot silently
/// drift from the enforced contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PublicOperation {
    /// Stable OpenAPI `operationId`. Never changes after promotion.
    pub operation_id: &'static str,
    /// HTTP method.
    pub method: HttpMethod,
    /// Stable request path. Backward-compatible; unchanged this slice.
    pub path: &'static str,
    /// Resource family this operation belongs to (e.g. `guardrail-policies`).
    pub resource: &'static str,
    /// Stability tier. Everything in [`PROMOTED_OPERATIONS`] is
    /// [`Stability::Stable`] by construction.
    pub stability: Stability,
}

/// The first coherent resource family promoted to the public-stable surface.
///
/// Guardrail policies were chosen as the reference group because they are a
/// complete, mature lifecycle (list / read / revisions / activate / rollback /
/// dry-run / archive) with real database RBAC action keys, and are already
/// named in the parent CLI epic's command model
/// (`ferrogate guardrail-policies activate ...`). Read operations require
/// `admin.read`; mutations require `admin.write`; both additionally gate on
/// `guardrails.policy.*` database actions — none of which this promotion
/// changes.
pub const PROMOTED_RESOURCES: &[&str] = &["guardrail-policies"];

/// The promoted public-stable operations. Keep sorted by path then method for
/// reviewability. Adding an entry here without also marking the operation
/// `x-ferrogate-stability: "stable"` in the OpenAPI document fails the sibling
/// contract test.
pub const PROMOTED_OPERATIONS: &[PublicOperation] = &[
    PublicOperation {
        operation_id: "listGuardrailPolicyRevisions",
        method: HttpMethod::Get,
        path: "/admin/v1/guardrail-policies",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "createGuardrailPolicyRevision",
        method: HttpMethod::Post,
        path: "/admin/v1/guardrail-policies",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "listGuardrailPolicyRevisionsByPolicy",
        method: HttpMethod::Get,
        path: "/admin/v1/guardrail-policies/{policy_id}",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "activateGuardrailPolicyRevision",
        method: HttpMethod::Post,
        path: "/admin/v1/guardrail-policies/{policy_id}/activate",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "rollbackGuardrailPolicyRevision",
        method: HttpMethod::Post,
        path: "/admin/v1/guardrail-policies/{policy_id}/rollback",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "dryRunGuardrailPolicyRevision",
        method: HttpMethod::Post,
        path: "/admin/v1/guardrail-policies/{policy_id}/dry-run",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "listGuardrailPolicyRevisionHistory",
        method: HttpMethod::Get,
        path: "/admin/v1/guardrail-policies/{policy_id}/revisions",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "createNextGuardrailPolicyRevision",
        method: HttpMethod::Post,
        path: "/admin/v1/guardrail-policies/{policy_id}/revisions",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "getGuardrailPolicyRevision",
        method: HttpMethod::Get,
        path: "/admin/v1/guardrail-policies/{policy_id}/revisions/{revision}",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
    PublicOperation {
        operation_id: "archiveGuardrailPolicyRevision",
        method: HttpMethod::Delete,
        path: "/admin/v1/guardrail-policies/{policy_id}/revisions/{revision}",
        resource: "guardrail-policies",
        stability: Stability::Stable,
    },
];

/// A serializable snapshot of the public Control Plane surface: identity,
/// version, stability contract, and the promoted operations. Suitable for
/// rendering into docs, `--version`-style evidence, or diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlPlaneSurface {
    /// Canonical product name.
    pub title: &'static str,
    /// Deprecated compatibility alias name.
    pub deprecated_alias: &'static str,
    /// Public major version.
    pub public_major: &'static str,
    /// Stable route prefix.
    pub stable_path_prefix: &'static str,
    /// Resource families promoted this slice.
    pub promoted_resources: &'static [&'static str],
    /// Promoted operations.
    pub promoted_operations: &'static [PublicOperation],
}

/// Describe the current public Control Plane surface.
#[must_use]
pub fn public_surface() -> ControlPlaneSurface {
    ControlPlaneSurface {
        title: CONTROL_PLANE_API_TITLE,
        deprecated_alias: DEPRECATED_ALIAS,
        public_major: PUBLIC_API_MAJOR,
        stable_path_prefix: STABLE_PATH_PREFIX,
        promoted_resources: PROMOTED_RESOURCES,
        promoted_operations: PROMOTED_OPERATIONS,
    }
}

/// The promoted public-stable operations.
#[must_use]
pub fn promoted_operations() -> &'static [PublicOperation] {
    PROMOTED_OPERATIONS
}

/// Whether an `operationId` is part of the promoted public-stable surface.
#[must_use]
pub fn is_promoted(operation_id: &str) -> bool {
    PROMOTED_OPERATIONS
        .iter()
        .any(|operation| operation.operation_id == operation_id)
}

#[cfg(test)]
#[path = "control_plane_test.rs"]
mod control_plane_test;
