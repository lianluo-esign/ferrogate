// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Cross-tenant publish approval gate for hosted assets (issue
// #261, slice 4). An asset that only its own tenant can consume needs no extra
// review, but the moment a push makes content visible to *other* tenants
// (public sites, shared catalogs) it can reach an agent outside the
// publisher's trust boundary -- so it must pass an explicit approval gate
// before becoming visible, fail-closed by default. This reuses the existing
// approval semantics (`approval.rs`'s `ApprovalStatus`) and produces an
// immutable evidence record, mirroring the `tool_approvals` pattern rather
// than inventing a parallel governance mechanism.

use serde::Serialize;

use crate::approval::ApprovalStatus;

/// Who a published asset version is visible to. Only `TenantPrivate` bypasses
/// the approval gate; anything cross-tenant-visible must be approved first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublishVisibility {
    /// Consumable only by the publishing tenant.
    TenantPrivate,
    /// Consumable by an explicit set of other tenants (a shared catalog).
    CrossTenantShared,
    /// Consumable by anyone (a public site / open catalog).
    Public,
}

impl PublishVisibility {
    /// Parse the `X-Asset-Visibility` header; defaults to tenant-private (the
    /// safe default -- an unspecified visibility never silently goes public).
    pub(super) fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "private" | "tenant" | "tenant_private" => Some(Self::TenantPrivate),
            "shared" | "cross_tenant" | "cross_tenant_shared" => Some(Self::CrossTenantShared),
            "public" => Some(Self::Public),
            _ => None,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            PublishVisibility::TenantPrivate => "tenant_private",
            PublishVisibility::CrossTenantShared => "cross_tenant_shared",
            PublishVisibility::Public => "public",
        }
    }

    /// Whether this visibility exposes the asset outside its publishing tenant.
    pub(super) fn is_cross_tenant(self) -> bool {
        !matches!(self, PublishVisibility::TenantPrivate)
    }
}

/// The decision the gate reaches for a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PublishGateDecision {
    /// No approval needed (tenant-private) -- publish and make visible.
    Allow,
    /// Cross-tenant visibility with a terminal `Approved` on record -- publish
    /// visibly, carrying the approving evidence id.
    Approved { approval_id: String },
    /// Cross-tenant visibility without an approval -- fail closed. The asset
    /// may be stored but must not be made cross-tenant-visible.
    Blocked { reason: String },
}

impl PublishGateDecision {
    /// Whether the publish may become visible at the requested visibility.
    pub(super) fn permits_visibility(&self) -> bool {
        !matches!(self, PublishGateDecision::Blocked { .. })
    }

    pub(super) fn approval_state(&self) -> &'static str {
        match self {
            PublishGateDecision::Allow => "not_required",
            PublishGateDecision::Approved { .. } => "approved",
            PublishGateDecision::Blocked { .. } => "blocked",
        }
    }
}

/// Evaluate the publish approval gate, fail-closed.
///
/// * tenant-private -> [`PublishGateDecision::Allow`] (no gate).
/// * cross-tenant with a terminal `Approved` status -> `Approved`.
/// * cross-tenant with any other (or absent) status -> `Blocked`.
pub(super) fn evaluate_publish_gate(
    visibility: PublishVisibility,
    approval: Option<(&str, ApprovalStatus)>,
) -> PublishGateDecision {
    if !visibility.is_cross_tenant() {
        return PublishGateDecision::Allow;
    }
    match approval {
        Some((id, ApprovalStatus::Approved)) => PublishGateDecision::Approved {
            approval_id: id.to_string(),
        },
        Some((_, ApprovalStatus::Pending)) => PublishGateDecision::Blocked {
            reason:
                "cross-tenant publish requires an approved review; the approval is still pending"
                    .to_string(),
        },
        Some((_, status)) => PublishGateDecision::Blocked {
            reason: format!(
                "cross-tenant publish requires an approved review; the approval is {}",
                approval_status_label(status)
            ),
        },
        None => PublishGateDecision::Blocked {
            reason: "cross-tenant publish requires an approval that has not been requested"
                .to_string(),
        },
    }
}

fn approval_status_label(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
    }
}

/// Immutable evidence that a cross-tenant publish passed (or was blocked by)
/// the gate, retrievable via the Admin audit surface. Never mutated after
/// creation -- a superseding publish creates a new record.
#[derive(Debug, Clone, Serialize)]
pub(super) struct PublishApprovalEvidence {
    pub(super) object: &'static str,
    pub(super) asset_id: String,
    pub(super) publisher_tenant_id: String,
    pub(super) visibility: &'static str,
    pub(super) decision: &'static str,
    pub(super) approval_id: Option<String>,
    pub(super) reason: Option<String>,
    pub(super) content_sha256: String,
    pub(super) recorded_at_unix: i64,
}

impl PublishApprovalEvidence {
    pub(super) fn from_decision(
        asset_id: &str,
        publisher_tenant_id: &str,
        visibility: PublishVisibility,
        decision: &PublishGateDecision,
        content_sha256: &str,
        recorded_at_unix: i64,
    ) -> Self {
        let (approval_id, reason) = match decision {
            PublishGateDecision::Allow => (None, None),
            PublishGateDecision::Approved { approval_id } => (Some(approval_id.clone()), None),
            PublishGateDecision::Blocked { reason } => (None, Some(reason.clone())),
        };
        Self {
            object: "asset.publish_approval",
            asset_id: asset_id.to_string(),
            publisher_tenant_id: publisher_tenant_id.to_string(),
            visibility: visibility.as_str(),
            decision: decision.approval_state(),
            approval_id,
            reason,
            content_sha256: content_sha256.to_string(),
            recorded_at_unix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_private_never_needs_approval() {
        assert!(!PublishVisibility::TenantPrivate.is_cross_tenant());
        assert_eq!(
            evaluate_publish_gate(PublishVisibility::TenantPrivate, None),
            PublishGateDecision::Allow
        );
    }

    #[test]
    fn cross_tenant_without_approval_is_fail_closed() {
        let decision = evaluate_publish_gate(PublishVisibility::Public, None);
        assert!(matches!(decision, PublishGateDecision::Blocked { .. }));
        assert!(!decision.permits_visibility());
        assert_eq!(decision.approval_state(), "blocked");
    }

    #[test]
    fn cross_tenant_pending_approval_is_blocked() {
        let decision = evaluate_publish_gate(
            PublishVisibility::CrossTenantShared,
            Some(("approval-1", ApprovalStatus::Pending)),
        );
        assert!(
            matches!(decision, PublishGateDecision::Blocked { reason } if reason.contains("pending"))
        );
    }

    #[test]
    fn cross_tenant_denied_approval_is_blocked() {
        let decision = evaluate_publish_gate(
            PublishVisibility::Public,
            Some(("approval-2", ApprovalStatus::Denied)),
        );
        assert!(
            matches!(decision, PublishGateDecision::Blocked { reason } if reason.contains("denied"))
        );
    }

    #[test]
    fn cross_tenant_approved_is_allowed_with_evidence() {
        let decision = evaluate_publish_gate(
            PublishVisibility::Public,
            Some(("approval-9", ApprovalStatus::Approved)),
        );
        assert_eq!(
            decision,
            PublishGateDecision::Approved {
                approval_id: "approval-9".to_string()
            }
        );
        assert!(decision.permits_visibility());
        let evidence = PublishApprovalEvidence::from_decision(
            "asset-1",
            "tenant-a",
            PublishVisibility::Public,
            &decision,
            "abcd",
            1000,
        );
        assert_eq!(evidence.decision, "approved");
        assert_eq!(evidence.approval_id.as_deref(), Some("approval-9"));
        // Evidence serializes for the Admin audit surface.
        let json = serde_json::to_string(&evidence).expect("serialize");
        assert!(json.contains("asset.publish_approval"));
        assert!(json.contains("approval-9"));
    }

    #[test]
    fn visibility_parsing_defaults_safe() {
        assert_eq!(
            PublishVisibility::parse(""),
            Some(PublishVisibility::TenantPrivate)
        );
        assert_eq!(
            PublishVisibility::parse("public"),
            Some(PublishVisibility::Public)
        );
        assert_eq!(
            PublishVisibility::parse("shared"),
            Some(PublishVisibility::CrossTenantShared)
        );
        assert_eq!(PublishVisibility::parse("nonsense"), None);
    }
}
