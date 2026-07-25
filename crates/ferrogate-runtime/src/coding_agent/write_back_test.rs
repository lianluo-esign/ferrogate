// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for coding-agent contract phase 5
//   (issue #472): write-back is denied without an explicit grant and always leaves an audit
//   receipt carrying the canonical action identity.

use std::collections::BTreeSet;

use super::*;
use crate::coding_agent::materialize::RepoCoordinates;
use crate::coding_agent::run::CodingRunIdentity;
use crate::{is_canonical_action_fingerprint, ActingPrincipal, ActionContext};

fn repo() -> RepoCoordinates {
    RepoCoordinates::new("github", "github.com", "acme", "widget").expect("coordinates")
}

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        subject: "api-key-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        worker_id: Some("worker-7".to_string()),
        delegated_user: Some("alice".to_string()),
    }
}

fn context() -> ActionContext {
    let mut context = ActionContext::for_request("req-1");
    context.agent_run_id = Some("run-1".to_string());
    context.session_id = Some("session-1".to_string());
    context
}

fn operations(items: &[WriteBackOperation]) -> BTreeSet<WriteBackOperation> {
    items.iter().copied().collect()
}

fn grant() -> WriteBackGrant {
    WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations(&[
            WriteBackOperation::PushBranch,
            WriteBackOperation::OpenPullRequest,
        ]),
        "ferrogate/run-",
        principal(),
        1_000,
        1_600,
    )
    .expect("valid grant")
}

fn request() -> WriteBackRequest {
    WriteBackRequest {
        run: CodingRunIdentity::new("tenant-a", "session-1", "run-1"),
        repo: repo(),
        operation: WriteBackOperation::PushBranch,
        branch: "ferrogate/run-1-fix".to_string(),
        work_product_id: "sha256:deadbeef".to_string(),
        head_commit: "3333333333333333333333333333333333333333".to_string(),
        title: Some("Fix the widget".to_string()),
        body: None,
    }
}

fn deny_code(grant: Option<&WriteBackGrant>, request: &WriteBackRequest, now: u64) -> String {
    let authorization = authorize_write_back(grant, request, &principal(), &context(), now)
        .expect("authorization is evaluable");
    assert!(!authorization.is_allowed());
    assert_eq!(authorization.audit_outcome().as_str(), "rejected");
    // The denial still produced an audit event.
    assert_eq!(
        authorization.receipt().identity.action,
        VCS_WRITE_BACK_ACTION
    );
    authorization.decision().code().to_string()
}

#[test]
fn a_run_with_no_grant_cannot_write_back() {
    assert_eq!(
        deny_code(None, &request(), 1_100),
        write_back_codes::NOT_GRANTED
    );
}

/// Defect 3 from the #472 review: the grant bound only `run_id` + `repo_id`.
/// `run_id` is unique only inside a tenant, so a grant issued in tenant A
/// authorized a same-named run in tenant B against the same repo, and the #475
/// implementer inherited no tenant check from the contract at all.
#[test]
fn a_grant_cannot_carry_a_write_back_across_a_tenant_boundary() {
    // The grant takes its tenant from the granting principal, so it is
    // `tenant-a`'s grant for `run-1`.
    let grant = grant();
    assert_eq!(grant.tenant_id(), "tenant-a");

    // Same run id, same repo, different tenant: refused, and refused as a
    // tenant mismatch rather than sliding through to the run check.
    let mut other_tenant = request();
    other_tenant.run = CodingRunIdentity::new("tenant-b", "session-1", "run-1");
    let tenant_b = ActingPrincipal {
        tenant_id: "tenant-b".to_string(),
        ..principal()
    };
    let authorization =
        authorize_write_back(Some(&grant), &other_tenant, &tenant_b, &context(), 1_100)
            .expect("evaluable");
    assert!(!authorization.is_allowed());
    assert_eq!(
        authorization.decision().code(),
        write_back_codes::TENANT_MISMATCH
    );
    assert_eq!(authorization.audit_outcome().as_str(), "rejected");

    // A principal acting outside the run's tenant is refused before the grant
    // is even consulted, so a valid grant cannot repair it.
    let authorization =
        authorize_write_back(Some(&grant), &request(), &tenant_b, &context(), 1_100)
            .expect("evaluable");
    assert!(!authorization.is_allowed());
    assert_eq!(
        authorization.decision().code(),
        write_back_codes::PRINCIPAL_TENANT_MISMATCH
    );
    assert_eq!(
        authorization.receipt().identity.action,
        VCS_WRITE_BACK_ACTION
    );

    // An untenanted principal cannot issue a grant at all — otherwise the
    // tenant field would be empty and the binding would collapse back to two
    // parts.
    let untenanted = WriteBackGrant::issue(
        "grant-wb-2",
        "run-1",
        &repo(),
        operations(&[WriteBackOperation::PushBranch]),
        "ferrogate/run-",
        ActingPrincipal {
            tenant_id: "  ".to_string(),
            ..principal()
        },
        1_000,
        1_600,
    );
    assert!(untenanted.is_err());

    // The receipt carries the tenant so an audit join on run_id is unambiguous.
    let authorized =
        authorize_write_back(Some(&grant), &request(), &principal(), &context(), 1_100)
            .expect("evaluable")
            .into_authorized()
            .expect("granted");
    let receipt =
        WriteBackReceipt::from_authorized(&authorized, None, 1_220, WriteBackOutcome::Completed);
    assert_eq!(receipt.tenant_id, "tenant-a");
}

#[test]
fn every_grant_mismatch_is_its_own_recorded_denial() {
    let grant = grant();

    let mut other_run = request();
    other_run.run = CodingRunIdentity::new("tenant-a", "session-1", "run-9");
    assert_eq!(
        deny_code(Some(&grant), &other_run, 1_100),
        write_back_codes::RUN_MISMATCH
    );

    let mut other_repo = request();
    other_repo.repo =
        RepoCoordinates::new("github", "github.com", "acme", "other").expect("coordinates");
    assert_eq!(
        deny_code(Some(&grant), &other_repo, 1_100),
        write_back_codes::REPO_MISMATCH
    );

    assert_eq!(
        deny_code(Some(&grant), &request(), 1_600),
        write_back_codes::EXPIRED
    );

    let mut tag = request();
    tag.operation = WriteBackOperation::PushTag;
    assert_eq!(
        deny_code(Some(&grant), &tag, 1_100),
        write_back_codes::OPERATION_NOT_GRANTED
    );

    let mut main_branch = request();
    main_branch.branch = "main".to_string();
    assert_eq!(
        deny_code(Some(&grant), &main_branch, 1_100),
        write_back_codes::BRANCH_OUTSIDE_NAMESPACE
    );

    let mut unattributed = request();
    unattributed.work_product_id = String::new();
    assert_eq!(
        deny_code(Some(&grant), &unattributed, 1_100),
        write_back_codes::NO_WORK_PRODUCT
    );
}

#[test]
fn an_allowed_write_back_mints_a_token_carrying_the_canonical_action_identity() {
    let grant = grant().with_approval_reference("approval-42");
    let request = request();
    let authorization =
        authorize_write_back(Some(&grant), &request, &principal(), &context(), 1_100)
            .expect("evaluable");
    assert!(authorization.is_allowed());
    assert_eq!(authorization.audit_outcome().as_str(), "allowed");
    assert_eq!(authorization.decision().code(), write_back_codes::GRANTED);
    assert!(authorization
        .decision()
        .reason()
        .detail
        .as_deref()
        .expect("detail")
        .contains("approval-42"));

    let receipt_identity = authorization.receipt().identity.clone();
    let authorized = authorization
        .into_authorized()
        .expect("allow yields the capability token");

    let identity = authorized.action_identity();
    assert_eq!(identity, &receipt_identity);
    assert_eq!(identity.action, VCS_WRITE_BACK_ACTION);
    assert!(is_canonical_action_fingerprint(
        &identity.action_fingerprint
    ));

    // The canonical target is the repo's git remote, not an invented
    // provider-specific API URL.
    let target = canonical_write_back_target(&repo()).expect("canonical target");
    assert_eq!(identity.canonical_target, target.canonical_json());
    assert_eq!(identity.action_fingerprint, target.fingerprint());
    assert!(identity.canonical_target.contains("github.com"));

    // Invocation-level binding is distinct from the target-level fingerprint.
    assert_ne!(
        authorized.invocation_fingerprint(),
        identity.action_fingerprint
    );
    assert_eq!(authorized.grant_id(), "grant-wb-1");
    assert_eq!(authorized.authorized_at_unix(), 1_100);
}

#[test]
fn the_invocation_fingerprint_separates_concrete_mutations() {
    let base = request();
    let mut other_branch = base.clone();
    other_branch.branch = "ferrogate/run-1-other".to_string();
    let mut other_operation = base.clone();
    other_operation.operation = WriteBackOperation::OpenPullRequest;

    assert_ne!(
        base.invocation_fingerprint(),
        other_branch.invocation_fingerprint()
    );
    assert_ne!(
        base.invocation_fingerprint(),
        other_operation.invocation_fingerprint()
    );
    assert_eq!(base.invocation_fingerprint(), base.invocation_fingerprint());
}

#[test]
fn require_authorized_surfaces_the_denial_code_as_an_error() {
    let authorization =
        authorize_write_back(None, &request(), &principal(), &context(), 1_100).expect("evaluable");
    let error = authorization.require_authorized().expect_err("denied");
    let CodingAgentError::WriteBackNotAuthorized { code, .. } = error else {
        panic!("expected a write-back authorization error");
    };
    assert_eq!(code, write_back_codes::NOT_GRANTED);
}

#[test]
fn a_receipt_can_only_describe_an_authorized_mutation() {
    let grant = grant();
    let request = request();
    let authorized = authorize_write_back(Some(&grant), &request, &principal(), &context(), 1_100)
        .expect("evaluable")
        .into_authorized()
        .expect("allowed");
    let receipt = WriteBackReceipt::from_authorized(
        &authorized,
        Some("https://github.com/acme/widget/pull/7".to_string()),
        1_200,
        WriteBackOutcome::Completed,
    );
    assert_eq!(receipt.run_id, "run-1");
    assert_eq!(receipt.grant_id, "grant-wb-1");
    assert_eq!(receipt.repo_id, repo().canonical_id());
    assert_eq!(receipt.work_product_id, request.work_product_id);
    assert_eq!(
        receipt.action_fingerprint,
        authorized.action_identity().action_fingerprint
    );
    assert_eq!(
        receipt.invocation_fingerprint,
        authorized.invocation_fingerprint()
    );
    assert_eq!(receipt.outcome.audit_outcome().as_str(), "success");

    let refused = WriteBackReceipt::from_authorized(
        &authorized,
        None,
        1_200,
        WriteBackOutcome::Refused {
            code: "protected_branch".to_string(),
        },
    );
    assert_eq!(refused.outcome.audit_outcome().as_str(), "rejected");
    assert_eq!(refused.outcome.as_str(), "refused");
}

#[test]
fn a_grant_must_be_bounded_in_operations_time_and_branch_namespace() {
    let unbounded_operations = WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        BTreeSet::new(),
        "ferrogate/run-",
        principal(),
        1_000,
        1_600,
    );
    assert!(unbounded_operations.is_err());

    let unbounded_branches = WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations(&[WriteBackOperation::PushBranch]),
        "   ",
        principal(),
        1_000,
        1_600,
    );
    assert!(unbounded_branches.is_err());

    let standing_permission = WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations(&[WriteBackOperation::PushBranch]),
        "ferrogate/run-",
        principal(),
        0,
        MAX_WRITE_BACK_GRANT_TTL_SECS + 1,
    );
    assert!(standing_permission.is_err());

    let anonymous = WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations(&[WriteBackOperation::PushBranch]),
        "ferrogate/run-",
        ActingPrincipal {
            subject: String::new(),
            tenant_id: "tenant-a".to_string(),
            worker_id: None,
            delegated_user: None,
        },
        1_000,
        1_600,
    );
    assert!(anonymous.is_err());
}
