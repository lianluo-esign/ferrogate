// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Unit tests for the shared lifecycle-status vocabulary (#514).

use super::*;

#[test]
fn recognized_tokens_parse_to_their_variant() {
    assert_eq!(LifecycleStatus::parse("active"), LifecycleStatus::Active);
    assert_eq!(
        LifecycleStatus::parse("suspended"),
        LifecycleStatus::Suspended
    );
    assert_eq!(
        LifecycleStatus::parse("disabled"),
        LifecycleStatus::Disabled
    );
    assert_eq!(LifecycleStatus::parse("deleted"), LifecycleStatus::Deleted);
}

#[test]
fn parsing_is_case_and_whitespace_insensitive() {
    assert_eq!(
        LifecycleStatus::parse("  SUSPENDED \n"),
        LifecycleStatus::Suspended
    );
    assert_eq!(LifecycleStatus::parse("Deleted"), LifecycleStatus::Deleted);
}

/// The dangerous-default guard: a legacy row whose `status` was never written
/// (NULL -> `""` on read) must stay fully usable. If this ever flips, shipping
/// #514 would black-hole every tenant created before it.
#[test]
fn absent_status_is_active_at_both_seams() {
    for raw in ["", "   ", "\t"] {
        let status = LifecycleStatus::parse(raw);
        assert_eq!(status, LifecycleStatus::Active, "raw {raw:?}");
        assert!(status.allows_requests(), "raw {raw:?}");
        assert!(status.allows_attach(), "raw {raw:?}");
    }
}

/// Same rule for a token this build does not know about: schema drift must not
/// become an outage.
#[test]
fn unrecognized_status_is_active_at_both_seams() {
    let status = LifecycleStatus::parse("pending_review");
    assert_eq!(status, LifecycleStatus::Active);
    assert!(status.allows_requests());
    assert!(status.allows_attach());
}

#[test]
fn suspended_disabled_and_deleted_deny_both_seams() {
    for status in [
        LifecycleStatus::Suspended,
        LifecycleStatus::Disabled,
        LifecycleStatus::Deleted,
    ] {
        assert!(
            !status.allows_requests(),
            "{} must stop request-time traffic",
            status.as_str()
        );
        assert!(
            !status.allows_attach(),
            "{} must stop new attachments",
            status.as_str()
        );
        assert!(!status.is_active());
    }
}

#[test]
fn active_allows_both_seams() {
    assert!(LifecycleStatus::Active.allows_requests());
    assert!(LifecycleStatus::Active.allows_attach());
    assert_eq!(LifecycleStatus::Active.as_str(), "active");
}
