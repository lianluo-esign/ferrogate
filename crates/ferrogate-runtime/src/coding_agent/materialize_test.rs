// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for coding-agent contract phase 1
//   (issue #472): pinned refs, reference-not-material credentials, and grant-gated write scope.

use std::collections::BTreeSet;

use super::*;
use crate::coding_agent::write_back::{WriteBackGrant, WriteBackOperation};
use crate::ActingPrincipal;

const SHA_A: &str = "1111111111111111111111111111111111111111";
const SHA_B: &str = "2222222222222222222222222222222222222222";

fn repo() -> RepoCoordinates {
    RepoCoordinates::new("github", "github.com", "acme", "widget").expect("valid coordinates")
}

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        subject: "api-key-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        worker_id: None,
        delegated_user: Some("alice".to_string()),
    }
}

fn write_back_grant(repo: &RepoCoordinates, run_id: &str) -> WriteBackGrant {
    let mut operations = BTreeSet::new();
    operations.insert(WriteBackOperation::PushBranch);
    operations.insert(WriteBackOperation::OpenPullRequest);
    WriteBackGrant::issue(
        "grant-wb-1",
        run_id,
        repo,
        operations,
        "ferrogate/run-",
        principal(),
        1_000,
        1_600,
    )
    .expect("valid grant")
}

fn brokered() -> CredentialDelivery {
    CredentialDelivery::BrokeredPerOperation {
        broker_url: "https://gateway.example/git-credential".to_string(),
    }
}

fn grant(scope: RepoCredentialScope, delivery: CredentialDelivery) -> RepoCredentialGrant {
    RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope,
        CredentialReference::parse("cf://repo-creds/acme-widget").expect("reference"),
        1_000,
        1_600,
        delivery,
        RevocationPoint {
            endpoint: "control-plane://credentials/revoke".to_string(),
        },
    )
    .expect("valid grant")
}

#[test]
fn credential_reference_refuses_bare_material_and_the_process_environment() {
    // A raw value is treated as key material, not a reference.
    let bare = CredentialReference::parse("ghp_averyrealisticlookingtokenvalue");
    assert!(matches!(
        bare,
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // env:// is refused specifically: the container's environment is readable
    // by the model-authored code running inside it (#475).
    let env = CredentialReference::parse("env://GITHUB_TOKEN");
    let Err(CodingAgentError::CredentialRejected { detail }) = env else {
        panic!("env:// must be refused");
    };
    assert!(detail.contains("readable by that code"), "detail: {detail}");
    assert_eq!(DENIED_CREDENTIAL_SCHEMES, ["env"]);
}

#[test]
fn credential_reference_accepts_store_schemes_and_fingerprints_them() {
    for raw in ["cf://repo-creds/acme-widget", "vault://secret/repo#token"] {
        let reference = CredentialReference::parse(raw).expect("supported scheme");
        assert_eq!(reference.as_str(), raw);
        assert!(ALLOWED_CREDENTIAL_SCHEMES.contains(&reference.scheme()));
        let fingerprint = reference.fingerprint();
        assert!(crate::is_canonical_action_fingerprint(&fingerprint));
    }
}

#[test]
fn a_moving_ref_is_not_a_pin() {
    for moving in ["main", "HEAD", "v1.2.3", "1111111", ""] {
        assert!(
            matches!(
                PinnedRef::new(moving),
                Err(CodingAgentError::UnpinnedRef { .. })
            ),
            "{moving:?} must not be accepted as a pin"
        );
    }
    let pinned = PinnedRef::new(SHA_A)
        .expect("full commit id")
        .resolved_from("refs/heads/main");
    assert_eq!(pinned.commit_id(), SHA_A);
    assert_eq!(pinned.symbolic_ref(), Some("refs/heads/main"));
}

#[test]
fn write_capable_scope_requires_a_write_back_grant() {
    let repo = repo();
    let read_only = RepoCredentialScope::read_only(&repo);
    assert!(!read_only.is_write_capable());
    assert_eq!(read_only.write_back_grant_id(), None);

    let grant = write_back_grant(&repo, "run-1");
    let writable = RepoCredentialScope::with_write_back(&repo, &grant).expect("granted");
    assert!(writable.is_write_capable());
    assert_eq!(writable.write_back_grant_id(), Some("grant-wb-1"));
    assert!(writable
        .permissions()
        .contains(&RepoPermission::PullRequestWrite));

    // A grant for a different repo cannot be laundered into a write scope.
    let other = RepoCoordinates::new("github", "github.com", "acme", "other").expect("coordinates");
    assert!(matches!(
        RepoCredentialScope::with_write_back(&other, &grant),
        Err(CodingAgentError::CredentialRejected { .. })
    ));
}

#[test]
fn credential_ttl_is_capped_and_must_be_positive() {
    let scope = RepoCredentialScope::read_only(&repo());
    let reference = CredentialReference::parse("cf://repo-creds/acme-widget").expect("reference");
    let revocation = RevocationPoint {
        endpoint: "control-plane://credentials/revoke".to_string(),
    };
    let too_long = RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope.clone(),
        reference.clone(),
        0,
        MAX_REPO_CREDENTIAL_TTL_SECS + 1,
        brokered(),
        revocation.clone(),
    );
    assert!(matches!(
        too_long,
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    let never_expires = RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope.clone(),
        reference.clone(),
        1_000,
        1_000,
        brokered(),
        revocation.clone(),
    );
    assert!(matches!(
        never_expires,
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    let no_revocation_point = RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope,
        reference,
        1_000,
        1_600,
        brokered(),
        RevocationPoint {
            endpoint: "  ".to_string(),
        },
    );
    assert!(matches!(
        no_revocation_point,
        Err(CodingAgentError::CredentialRejected { .. })
    ));
}

#[test]
fn the_grant_carries_no_key_material() {
    let grant = grant(RepoCredentialScope::read_only(&repo()), brokered());
    let rendered = format!("{grant:?}");
    // The only credential-shaped thing in the record is the store reference.
    assert!(rendered.contains("cf://repo-creds/acme-widget"));
    assert!(!rendered.to_ascii_lowercase().contains("token"));
    assert!(!grant.delivery().readable_in_instance());
    assert_eq!(grant.delivery().as_str(), "brokered_per_operation");
}

#[test]
fn ephemeral_file_delivery_is_kept_out_of_the_workspace_and_off_group_world() {
    let request = |delivery: CredentialDelivery| RepoMaterializationRequest {
        run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
        repo: repo(),
        pinned_ref: PinnedRef::new(SHA_A).expect("pin"),
        workspace_path: "/workspace".to_string(),
        credential: grant(RepoCredentialScope::read_only(&repo()), delivery),
        fetch_depth: None,
        include_submodules: false,
    };

    let inside = request(CredentialDelivery::EphemeralFile {
        path: "/workspace/.git-credentials".to_string(),
        mode: 0o600,
    });
    assert!(matches!(
        inside.validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    let loose = request(CredentialDelivery::EphemeralFile {
        path: "/run/secrets/git".to_string(),
        mode: 0o644,
    });
    assert!(matches!(
        loose.validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    let ok = request(CredentialDelivery::EphemeralFile {
        path: "/run/secrets/git".to_string(),
        mode: 0o600,
    });
    ok.validate(1_100).expect("delivery outside the workspace");
    // ...but it is still recorded as readable from inside the instance.
    assert!(ok.credential.delivery().readable_in_instance());
}

#[test]
fn materialization_rejects_a_foreign_repo_run_or_expired_grant() {
    let base = RepoMaterializationRequest {
        run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
        repo: repo(),
        pinned_ref: PinnedRef::new(SHA_A).expect("pin"),
        workspace_path: "/workspace".to_string(),
        credential: grant(RepoCredentialScope::read_only(&repo()), brokered()),
        fetch_depth: None,
        include_submodules: false,
    };
    base.validate(1_100).expect("well-formed request");

    // Expired.
    assert!(matches!(
        base.validate(1_600),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // Grant issued for another run.
    let mut foreign_run = base.clone();
    foreign_run.run = CodingRunIdentity::new("tenant-a", "session-1", "run-2");
    assert!(matches!(
        foreign_run.validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // Grant scoped to another repo.
    let mut foreign_repo = base.clone();
    foreign_repo.repo =
        RepoCoordinates::new("github", "github.com", "acme", "other").expect("coordinates");
    assert!(matches!(
        foreign_repo.validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // Relative workspace path.
    let mut relative = base;
    relative.workspace_path = "workspace".to_string();
    assert!(matches!(
        relative.validate(1_100),
        Err(CodingAgentError::InvalidRequest { .. })
    ));
}

#[test]
fn a_clone_that_lands_off_the_pin_is_a_hard_failure() {
    let workspace = MaterializedWorkspace {
        run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
        repo: repo(),
        workspace_path: "/workspace".to_string(),
        materialized_ref: PinnedRef::new(SHA_B).expect("pin"),
        credential_grant_id: "grant-1".to_string(),
        materialized_at_unix: 1_100,
    };
    let requested = PinnedRef::new(SHA_A).expect("pin");
    let error = workspace.verify(&requested).expect_err("mismatch");
    assert_eq!(
        error,
        CodingAgentError::RefMismatch {
            requested: SHA_A.to_string(),
            materialized: SHA_B.to_string(),
        }
    );
    workspace
        .verify(&PinnedRef::new(SHA_B).expect("pin"))
        .expect("matching pin verifies");
}

#[test]
fn repo_coordinates_reject_ambiguous_components_and_expose_one_canonical_id() {
    assert!(RepoCoordinates::new("github", "github.com/acme", "a", "b").is_err());
    assert!(RepoCoordinates::new("github", "github.com", "acme", "a/b").is_err());
    assert!(RepoCoordinates::new("github", "github.com", "..", "b").is_err());
    assert!(RepoCoordinates::new("github", "", "acme", "b").is_err());

    let repo = repo();
    assert_eq!(repo.canonical_id(), "github:github.com/acme/widget");
    assert_eq!(repo.https_remote(), "https://github.com/acme/widget.git");
}

#[test]
fn revocation_receipt_reports_failure_instead_of_swallowing_it() {
    let grant = grant(RepoCredentialScope::read_only(&repo()), brokered());
    let failed = CredentialRevocation::for_grant(
        &grant,
        1_500,
        RevocationOutcome::Failed {
            code: "revoke_endpoint_unreachable".to_string(),
        },
    );
    assert!(!failed.outcome.is_credential_neutralized());
    assert_eq!(failed.grant_id, "grant-1");
    assert_eq!(
        failed.credential_fingerprint,
        grant.credential_ref().fingerprint()
    );

    for outcome in [
        RevocationOutcome::Revoked,
        RevocationOutcome::AlreadyExpired,
    ] {
        let receipt = CredentialRevocation::for_grant(&grant, 1_500, outcome);
        assert!(receipt.outcome.is_credential_neutralized());
    }
}
