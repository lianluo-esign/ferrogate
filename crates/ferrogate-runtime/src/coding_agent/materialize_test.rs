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
/// The governed gateway host the instance is tethered to. A brokered
/// credential callback is only valid on this host.
const GATEWAY_HOST: &str = "gateway.example";

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
    let held =
        |delivery: CredentialDelivery| grant(RepoCredentialScope::read_only(&repo()), delivery);
    fn request(credential: &RepoCredentialGrant) -> RepoMaterializationRequest<'_> {
        RepoMaterializationRequest {
            run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
            repo: repo(),
            pinned_ref: PinnedRef::new(SHA_A).expect("pin"),
            workspace_path: "/workspace".to_string(),
            credential,
            governed_gateway_host: GATEWAY_HOST.to_string(),
            fetch_depth: None,
            include_submodules: false,
        }
    }

    let inside_grant = held(CredentialDelivery::EphemeralFile {
        path: "/workspace/.git-credentials".to_string(),
        mode: 0o600,
    });
    assert!(matches!(
        request(&inside_grant).validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    let loose_grant = held(CredentialDelivery::EphemeralFile {
        path: "/run/secrets/git".to_string(),
        mode: 0o644,
    });
    assert!(matches!(
        request(&loose_grant).validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    let ok_grant = held(CredentialDelivery::EphemeralFile {
        path: "/run/secrets/git".to_string(),
        mode: 0o600,
    });
    request(&ok_grant)
        .validate(1_100)
        .expect("delivery outside the workspace");
    // ...but it is still recorded as readable from inside the instance.
    assert!(ok_grant.delivery().readable_in_instance());
}

#[test]
fn materialization_rejects_a_foreign_repo_run_or_expired_grant() {
    // A fresh request each time: the grant is linear, so there is no `.clone()`
    // to mutate a copy of.
    let held = grant(RepoCredentialScope::read_only(&repo()), brokered());
    let base = || RepoMaterializationRequest {
        run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
        repo: repo(),
        pinned_ref: PinnedRef::new(SHA_A).expect("pin"),
        workspace_path: "/workspace".to_string(),
        credential: &held,
        governed_gateway_host: GATEWAY_HOST.to_string(),
        fetch_depth: None,
        include_submodules: false,
    };
    base().validate(1_100).expect("well-formed request");

    // Expired.
    assert!(matches!(
        base().validate(1_600),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // Grant issued for another run.
    let mut foreign_run = base();
    foreign_run.run = CodingRunIdentity::new("tenant-a", "session-1", "run-2");
    assert!(matches!(
        foreign_run.validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // Grant scoped to another repo.
    let mut foreign_repo = base();
    foreign_repo.repo =
        RepoCoordinates::new("github", "github.com", "acme", "other").expect("coordinates");
    assert!(matches!(
        foreign_repo.validate(1_100),
        Err(CodingAgentError::CredentialRejected { .. })
    ));

    // Relative workspace path.
    let mut relative = base();
    relative.workspace_path = "workspace".to_string();
    assert!(matches!(
        relative.validate(1_100),
        Err(CodingAgentError::InvalidRequest { .. })
    ));
}

/// Defect 6 from the #472 review: the strongest delivery — the one whose whole
/// claim is "the credential never enters the instance" — was validated only as
/// `https://`, so the git credential helper could be pointed anywhere.
#[test]
fn a_brokered_callback_is_refused_off_the_governed_gateway_host() {
    let validate = |broker_url: &str| {
        let credential = grant(
            RepoCredentialScope::read_only(&repo()),
            CredentialDelivery::BrokeredPerOperation {
                broker_url: broker_url.to_string(),
            },
        );
        RepoMaterializationRequest {
            run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
            repo: repo(),
            pinned_ref: PinnedRef::new(SHA_A).expect("pin"),
            workspace_path: "/workspace".to_string(),
            credential: &credential,
            governed_gateway_host: GATEWAY_HOST.to_string(),
            fetch_depth: None,
            include_submodules: false,
        }
        .validate(1_100)
    };

    // The case the review named: https, well-formed, and off-platform.
    let error = validate("https://attacker.example/git-credential")
        .expect_err("an off-gateway broker must be refused");
    assert!(matches!(error, CodingAgentError::CredentialRejected { .. }));

    // Userinfo must not be readable as the host.
    assert!(validate("https://gateway.example@attacker.example/cb").is_err());
    // A suffix of the gateway host is a different host.
    assert!(validate("https://evilgateway.example/cb").is_err());
    // Not https at all.
    assert!(validate("http://gateway.example/cb").is_err());

    // The governed host itself is accepted, with or without a port, in any case.
    validate("https://gateway.example/git-credential")
        .expect("the governed gateway host is the one accepted host");
    validate("https://GATEWAY.example:8443/git-credential")
        .expect("host comparison is case-insensitive and port-insensitive");
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
    let reference = grant(RepoCredentialScope::read_only(&repo()), brokered());
    let fingerprint = reference.credential_ref().fingerprint();
    let endpoint = reference.revocation_point().endpoint.clone();
    let failed = CredentialRevocation::for_grant(
        reference,
        1_500,
        RevocationOutcome::Failed {
            code: "revoke_endpoint_unreachable".to_string(),
        },
    );
    assert!(!failed.is_credential_neutralized());
    assert_eq!(failed.grant_id, "grant-1");
    assert_eq!(failed.credential_fingerprint, fingerprint);
    // The record names the endpoint the attempt was made against, copied off
    // the surrendered grant rather than supplied by the caller.
    assert_eq!(failed.revocation_endpoint, endpoint);

    for outcome in [
        RevocationOutcome::Revoked,
        RevocationOutcome::AlreadyExpired,
    ] {
        let receipt = CredentialRevocation::for_grant(
            grant(RepoCredentialScope::read_only(&repo()), brokered()),
            1_500,
            outcome,
        );
        assert!(receipt.is_credential_neutralized());
    }
}

/// Defect 4 from the #472 review: `#[must_use]` plus by-value passing bought no
/// linearity while the grant was `Clone`. It is now neither `Clone` nor
/// `Deserialize`, so a caller cannot keep a usable handle past revocation — by
/// copy *or* by JSON round-trip.
#[test]
fn a_credential_grant_cannot_be_duplicated_or_reparsed() {
    // The absence of `Clone`/`Deserialize` is enforced by the compiler, not by
    // this test: `credential.clone()` and `serde_json::from_str::<
    // RepoCredentialGrant>(..)` no longer compile. What is checkable at
    // runtime is that the escape hatch a `Serialize + Deserialize` pair would
    // have opened is closed, and that surrender is the only exit.
    let held = grant(RepoCredentialScope::read_only(&repo()), brokered());
    // A grant serializes (it holds a reference, not material) but the emitted
    // JSON is not accepted back as a grant, so `Serialize + Deserialize` cannot
    // stand in for the `Clone` that was removed.
    let json = serde_json::to_string(&held).expect("grants serialize for the control plane");
    assert!(json.contains("repo-creds/acme-widget"), "json: {json}");
    assert!(!json.to_ascii_lowercase().contains("token"), "json: {json}");
    assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());

    // The only exit is surrender.
    let revocation = CredentialRevocation::for_grant(held, 1_500, RevocationOutcome::Revoked);
    assert_eq!(revocation.grant_id, "grant-1");
}
