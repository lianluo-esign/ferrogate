// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for the coding-agent adapter contract
//   (issue #472) driven end to end by a mock container + mock VCS: no live GitHub, no live model.

use std::collections::BTreeSet;

use super::*;
use crate::coding_agent::bootstrap::{
    CodingAgentImage, EgressEnforcement, EgressPosture, GovernedLlmEgress, TaskBrief,
    UnenforcedEgressAcknowledgement,
};
use crate::coding_agent::error::CodingAgentError;
use crate::coding_agent::extract::{DiffStats, ProducedBranch, UnifiedDiff, WorkProduct};
use crate::coding_agent::materialize::{
    CredentialDelivery, CredentialReference, CredentialRevocation, MaterializedWorkspace,
    PinnedRef, RepoCoordinates, RepoCredentialGrant, RepoCredentialScope,
    RepoMaterializationRequest, RevocationOutcome, RevocationPoint,
};
use crate::coding_agent::run::{
    CodingRunIdentity, CodingRunOutcome, CodingRunReceipt, CodingRunRequest, CodingRunStatus,
    RunFinalization,
};
use crate::coding_agent::write_back::{
    authorize_write_back, write_back_codes, AuthorizedWriteBack, WriteBackGrant,
    WriteBackOperation, WriteBackOutcome, WriteBackReceipt, WriteBackRequest,
};
use crate::{ActingPrincipal, ActionContext};

const BASE: &str = "1111111111111111111111111111111111111111";
const HEAD: &str = "3333333333333333333333333333333333333333";
const PATCH: &str = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

/// Mock VCS: records what an implementation actually did, so the test can
/// assert on side effects instead of on return values alone.
#[derive(Debug, Default, PartialEq, Eq)]
struct MockVcs {
    clones: Vec<(String, String)>,
    pushes: Vec<(String, String)>,
    revoked_grants: Vec<String>,
}

/// Mock coding agent. Stands in for "a container plus some agent process"; it
/// never touches a network, a filesystem, or a model.
struct MockCodingAgent {
    descriptor: CodingAgentDescriptor,
    vcs: MockVcs,
    patch: String,
    run_status: CodingRunStatus,
    revocation: RevocationOutcome,
}

impl MockCodingAgent {
    fn new(capabilities: CodingAgentCapabilities) -> Self {
        Self {
            descriptor: CodingAgentDescriptor {
                adapter_name: "mock-coding-agent".to_string(),
                adapter_version: "0.1.0".to_string(),
                agent_name: "mock-agent".to_string(),
                isolation_backend: crate::CLOUDFLARE_CONTAINER_BACKEND_NAME.to_string(),
                capabilities,
            },
            vcs: MockVcs::default(),
            patch: PATCH.to_string(),
            run_status: CodingRunStatus::Completed,
            revocation: RevocationOutcome::Revoked,
        }
    }

    fn full() -> Self {
        Self::new(CodingAgentCapabilities {
            materialize_repo: true,
            shallow_clone: true,
            submodules: false,
            brokered_credentials: true,
            diff_extraction: true,
            branch_extraction: true,
            push_branch: true,
            pull_request: true,
            resume: false,
        })
    }
}

impl CodingAgentAdapter for MockCodingAgent {
    fn descriptor(&self) -> &CodingAgentDescriptor {
        &self.descriptor
    }

    fn materialize_repo(
        &mut self,
        request: RepoMaterializationRequest,
    ) -> Result<MaterializedWorkspace, CodingAgentError> {
        self.descriptor.capabilities.preflight(&request)?;
        request.validate(1_100)?;
        self.vcs.clones.push((
            request.repo.canonical_id(),
            request.pinned_ref.commit_id().to_string(),
        ));
        let workspace = MaterializedWorkspace {
            run: request.run.clone(),
            repo: request.repo.clone(),
            workspace_path: request.workspace_path.clone(),
            materialized_ref: request.pinned_ref.clone(),
            credential_grant_id: request.credential.grant_id().to_string(),
            materialized_at_unix: 1_100,
        };
        workspace.verify(&request.pinned_ref)?;
        Ok(workspace)
    }

    fn bootstrap(
        &mut self,
        request: AgentBootstrapRequest,
    ) -> Result<BootstrappedAgent, CodingAgentError> {
        let instance_name = request.run.instance_name()?;
        BootstrappedAgent::new(&request, instance_name, 1_120)
    }

    fn run(&mut self, request: CodingRunRequest) -> Result<CodingRunOutcome, CodingAgentError> {
        request.validate(1_120)?;
        Ok(CodingRunOutcome {
            run: request.run.clone(),
            status: self.run_status,
            started_at_unix: 1_120,
            finished_at_unix: 1_180,
            steps: 12,
            failure_detail: None,
        })
    }

    fn extract(
        &mut self,
        request: WorkProductRequest,
    ) -> Result<Option<WorkProduct>, CodingAgentError> {
        if self.patch.trim().is_empty() {
            return Ok(None);
        }
        let branch = ProducedBranch::new("ferrogate/run-1-fix", HEAD, request.base.clone())?;
        let product = WorkProduct::assemble(
            request.run.clone(),
            request.workspace.repo.clone(),
            request.base.clone(),
            Some(branch),
            UnifiedDiff::inline(self.patch.clone())?,
            DiffStats {
                files_changed: 1,
                insertions: 1,
                deletions: 1,
            },
            Some("mock agent narration".to_string()),
            1_200,
        )?;
        Ok(Some(product))
    }

    fn write_back(
        &mut self,
        authorized: AuthorizedWriteBack,
    ) -> Result<WriteBackReceipt, CodingAgentError> {
        let request = authorized.request();
        if !self
            .descriptor
            .capabilities
            .supports_write_back(request.operation)
        {
            return Err(CodingAgentError::Unsupported {
                phase: CodingAgentPhase::WriteBack,
                capability: "write_back",
            });
        }
        self.vcs
            .pushes
            .push((request.branch.clone(), request.head_commit.clone()));
        Ok(WriteBackReceipt::from_authorized(
            &authorized,
            Some("https://github.com/acme/widget/pull/7".to_string()),
            1_220,
            WriteBackOutcome::Completed,
        ))
    }

    fn finalize(
        &mut self,
        finalization: RunFinalization,
    ) -> Result<CodingRunReceipt, CodingAgentError> {
        self.vcs
            .revoked_grants
            .push(finalization.credential.grant_id().to_string());
        let revocation = CredentialRevocation::for_grant(
            &finalization.credential,
            finalization.finalized_at_unix,
            self.revocation.clone(),
        );
        CodingRunReceipt::assemble(&finalization, revocation)
    }
}

fn repo() -> RepoCoordinates {
    RepoCoordinates::new("github", "github.com", "acme", "widget").expect("coordinates")
}

fn run() -> CodingRunIdentity {
    CodingRunIdentity::new("tenant-a", "session-1", "run-1")
}

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        subject: "api-key-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        worker_id: Some("worker-7".to_string()),
        delegated_user: Some("alice".to_string()),
    }
}

fn write_back_grant() -> WriteBackGrant {
    let mut operations = BTreeSet::new();
    operations.insert(WriteBackOperation::PushBranch);
    WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations,
        "ferrogate/run-",
        principal(),
        1_000,
        1_600,
    )
    .expect("grant")
}

fn credential(scope: RepoCredentialScope) -> RepoCredentialGrant {
    RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope,
        CredentialReference::parse("cf://repo-creds/acme-widget").expect("reference"),
        1_000,
        1_600,
        CredentialDelivery::BrokeredPerOperation {
            broker_url: "https://gateway.example/git-credential".to_string(),
        },
        RevocationPoint {
            endpoint: "control-plane://credentials/revoke".to_string(),
        },
    )
    .expect("credential grant")
}

fn materialization(credential: RepoCredentialGrant) -> RepoMaterializationRequest {
    RepoMaterializationRequest {
        run: run(),
        repo: repo(),
        pinned_ref: PinnedRef::new(BASE)
            .expect("pin")
            .resolved_from("refs/heads/main"),
        workspace_path: "/workspace".to_string(),
        credential,
        fetch_depth: Some(1),
        include_submodules: false,
    }
}

fn bootstrap_request(workspace: MaterializedWorkspace) -> AgentBootstrapRequest {
    let mut hosts = BTreeSet::new();
    hosts.insert("gateway.example".to_string());
    hosts.insert("github.com".to_string());
    AgentBootstrapRequest {
        run: run(),
        workspace,
        image: CodingAgentImage::new(
            "mock-agent",
            "1.0.0",
            "registry.example/mock-agent:1.0.0",
            vec!["/usr/bin/mock-agent".to_string()],
        )
        .expect("image"),
        task: TaskBrief::new("task-1", "fix the widget bug").expect("brief"),
        llm_egress: GovernedLlmEgress::new(
            "https://gateway.example",
            "gateway.example",
            CredentialReference::parse("cf://run-tokens/run-1").expect("reference"),
        )
        .expect("egress"),
        egress: EgressPosture::Allowlist { hosts },
    }
}

fn context() -> ActionContext {
    let mut context = ActionContext::for_request("req-1");
    context.agent_run_id = Some("run-1".to_string());
    context
}

/// Drive all five phases plus the close-out against the mock.
fn drive(
    adapter: &mut MockCodingAgent,
    grant: Option<&WriteBackGrant>,
) -> Result<CodingRunReceipt, CodingAgentError> {
    let scope = match grant {
        Some(grant) => RepoCredentialScope::with_write_back(&repo(), grant)?,
        None => RepoCredentialScope::read_only(&repo()),
    };
    let credential = credential(scope);
    let kept = credential.clone();

    let workspace = adapter.materialize_repo(materialization(credential))?;
    let agent = adapter.bootstrap(bootstrap_request(workspace.clone()))?;
    let outcome = adapter.run(CodingRunRequest {
        run: run(),
        agent: agent.clone(),
        deadline_unix: 2_000,
        budget: None,
    })?;

    let product = if outcome.status.may_have_work_product() {
        adapter.extract(WorkProductRequest::new(
            run(),
            workspace,
            PinnedRef::new(BASE).expect("pin"),
        ))?
    } else {
        None
    };

    let write_back = match &product {
        Some(product) => {
            let request = WriteBackRequest {
                run: run(),
                repo: repo(),
                operation: WriteBackOperation::PushBranch,
                branch: "ferrogate/run-1-fix".to_string(),
                work_product_id: product.product_id().to_string(),
                head_commit: HEAD.to_string(),
                title: Some("Fix the widget".to_string()),
                body: None,
            };
            let authorization =
                authorize_write_back(grant, &request, &principal(), &context(), 1_210)?;
            match authorization.into_authorized() {
                Some(authorized) => Some(adapter.write_back(authorized)?),
                None => None,
            }
        }
        None => None,
    };

    adapter.finalize(RunFinalization {
        run: run(),
        outcome,
        credential: kept,
        work_product: product,
        write_back,
        egress_posture: agent.egress_posture.clone(),
        finalized_at_unix: 1_300,
    })
}

#[test]
fn the_five_phases_close_one_loop_with_an_explicit_grant() {
    let mut adapter = MockCodingAgent::full();
    let grant = write_back_grant();
    let receipt = drive(&mut adapter, Some(&grant)).expect("run closes");

    assert_eq!(receipt.status, CodingRunStatus::Completed);
    assert!(receipt.work_product_id.is_some());
    assert!(receipt.credential_is_closed());
    assert_eq!(receipt.egress_posture, "allowlist");
    assert_eq!(
        receipt.egress_enforcement,
        EgressEnforcement::NetworkEnforced
    );
    assert!(!receipt.credential_readable_in_instance);

    let write_back = receipt.write_back.expect("push happened");
    assert_eq!(write_back.grant_id, "grant-wb-1");
    assert_eq!(write_back.work_product_id, receipt.work_product_id.unwrap());
    assert_eq!(write_back.outcome, WriteBackOutcome::Completed);

    assert_eq!(
        adapter.vcs,
        MockVcs {
            clones: vec![(repo().canonical_id(), BASE.to_string())],
            pushes: vec![("ferrogate/run-1-fix".to_string(), HEAD.to_string())],
            revoked_grants: vec!["grant-1".to_string()],
        }
    );
}

#[test]
fn without_a_grant_the_run_still_produces_a_diff_but_nothing_leaves() {
    let mut adapter = MockCodingAgent::full();
    let receipt = drive(&mut adapter, None).expect("run closes");

    assert!(receipt.work_product_id.is_some());
    assert!(receipt.write_back.is_none());
    assert!(adapter.vcs.pushes.is_empty(), "nothing may be pushed");
    assert_eq!(adapter.vcs.revoked_grants, vec!["grant-1".to_string()]);

    // The refusal is a recorded decision, not a silent no-op.
    let request = WriteBackRequest {
        run: run(),
        repo: repo(),
        operation: WriteBackOperation::PushBranch,
        branch: "ferrogate/run-1-fix".to_string(),
        work_product_id: "sha256:whatever".to_string(),
        head_commit: HEAD.to_string(),
        title: None,
        body: None,
    };
    let authorization =
        authorize_write_back(None, &request, &principal(), &context(), 1_210).expect("evaluable");
    assert_eq!(
        authorization.decision().code(),
        write_back_codes::NOT_GRANTED
    );
    assert_eq!(authorization.audit_outcome().as_str(), "rejected");
}

#[test]
fn the_credential_is_revoked_on_the_failure_path_too() {
    for status in [
        CodingRunStatus::Failed,
        CodingRunStatus::TimedOut,
        CodingRunStatus::BudgetExhausted,
        CodingRunStatus::PolicyBlocked,
    ] {
        let mut adapter = MockCodingAgent::full();
        adapter.run_status = status;
        let receipt = drive(&mut adapter, None).expect("run closes");
        assert_eq!(receipt.status, status);
        assert!(receipt.credential_is_closed());
        assert_eq!(adapter.vcs.revoked_grants, vec!["grant-1".to_string()]);
        assert!(adapter.vcs.pushes.is_empty());
        // Budget/policy kills stop before extraction; timeouts do not throw the
        // partial work away.
        assert_eq!(
            receipt.work_product_id.is_some(),
            status.may_have_work_product()
        );
    }
}

#[test]
fn a_failed_revocation_is_recorded_rather_than_swallowed() {
    let mut adapter = MockCodingAgent::full();
    adapter.revocation = RevocationOutcome::Failed {
        code: "revoke_endpoint_unreachable".to_string(),
    };
    let receipt = drive(&mut adapter, None).expect("run still closes");
    assert!(
        !receipt.credential_is_closed(),
        "a live credential outliving its run must be visible"
    );
}

#[test]
fn a_run_that_changed_nothing_yields_no_work_product() {
    let mut adapter = MockCodingAgent::full();
    adapter.patch = String::new();
    let receipt = drive(&mut adapter, Some(&write_back_grant())).expect("run closes");
    assert_eq!(receipt.status, CodingRunStatus::Completed);
    assert!(receipt.work_product_id.is_none());
    assert!(receipt.write_back.is_none());
    assert!(adapter.vcs.pushes.is_empty());
}

#[test]
fn capability_preflight_fails_closed_before_a_credential_is_used() {
    let mut adapter = MockCodingAgent::new(CodingAgentCapabilities::diff_only());
    let mut request = materialization(credential(RepoCredentialScope::read_only(&repo())));
    request.fetch_depth = None;
    request.include_submodules = true;
    let error = adapter
        .materialize_repo(request)
        .expect_err("submodules are not implemented");
    assert_eq!(
        error,
        CodingAgentError::Unsupported {
            phase: CodingAgentPhase::Materialize,
            capability: "submodules",
        }
    );

    // `materialization` asks for a shallow clone, which this adapter also does
    // not implement — refused, not silently upgraded to a full clone.
    let error = adapter
        .materialize_repo(materialization(credential(RepoCredentialScope::read_only(
            &repo(),
        ))))
        .expect_err("shallow clone is not implemented");
    assert_eq!(
        error,
        CodingAgentError::Unsupported {
            phase: CodingAgentPhase::Materialize,
            capability: "shallow_clone",
        }
    );

    // The brokered-credential delivery is likewise refused rather than
    // downgraded to a credential file the agent could read.
    let mut plain = materialization(credential(RepoCredentialScope::read_only(&repo())));
    plain.fetch_depth = None;
    let error = adapter
        .materialize_repo(plain)
        .expect_err("brokered credentials are not implemented");
    assert_eq!(
        error,
        CodingAgentError::Unsupported {
            phase: CodingAgentPhase::Materialize,
            capability: "brokered_credentials",
        }
    );
    assert!(adapter.vcs.clones.is_empty());
}

#[test]
fn finalize_refuses_evidence_that_does_not_belong_to_the_run() {
    let mut adapter = MockCodingAgent::full();
    let credential = credential(RepoCredentialScope::read_only(&repo()));
    let outcome = CodingRunOutcome {
        run: run(),
        status: CodingRunStatus::Completed,
        started_at_unix: 1_120,
        finished_at_unix: 1_180,
        steps: 3,
        failure_detail: None,
    };

    // A work product minted for another run cannot be attached.
    let foreign = WorkProduct::assemble(
        CodingRunIdentity::new("tenant-a", "session-1", "run-9"),
        repo(),
        PinnedRef::new(BASE).expect("pin"),
        None,
        UnifiedDiff::inline(PATCH).expect("diff"),
        DiffStats::default(),
        None,
        1_200,
    )
    .expect("work product");
    let error = adapter
        .finalize(RunFinalization {
            run: run(),
            outcome: outcome.clone(),
            credential: credential.clone(),
            work_product: Some(foreign),
            write_back: None,
            egress_posture: EgressPosture::GatewayProxied,
            finalized_at_unix: 1_300,
        })
        .expect_err("foreign work product");
    assert!(matches!(error, CodingAgentError::InvalidRequest { .. }));

    // A credential grant from another run cannot be closed out here either.
    let foreign_credential = RepoCredentialGrant::issue(
        "grant-9",
        "run-9",
        RepoCredentialScope::read_only(&repo()),
        CredentialReference::parse("cf://repo-creds/acme-widget").expect("reference"),
        1_000,
        1_600,
        CredentialDelivery::BrokeredPerOperation {
            broker_url: "https://gateway.example/git-credential".to_string(),
        },
        RevocationPoint {
            endpoint: "control-plane://credentials/revoke".to_string(),
        },
    )
    .expect("grant");
    let error = adapter
        .finalize(RunFinalization {
            run: run(),
            outcome,
            credential: foreign_credential,
            work_product: None,
            write_back: None,
            egress_posture: EgressPosture::GatewayProxied,
            finalized_at_unix: 1_300,
        })
        .expect_err("foreign credential");
    assert!(matches!(error, CodingAgentError::CredentialRejected { .. }));
}

#[test]
fn an_open_egress_run_cannot_claim_the_gateway_was_enforced() {
    let mut adapter = MockCodingAgent::full();
    let credential = credential(RepoCredentialScope::read_only(&repo()));
    let workspace = adapter
        .materialize_repo(materialization(credential.clone()))
        .expect("workspace");

    let acknowledgement = UnenforcedEgressAcknowledgement::new(
        principal(),
        "legacy provider requires direct egress",
        1_050,
    )
    .expect("acknowledged");
    let mut request = bootstrap_request(workspace);
    request.egress = EgressPosture::OpenWithDetection { acknowledgement };
    let agent = adapter.bootstrap(request).expect("bootstrapped");
    assert!(agent.egress_is_bypassable());
    assert_eq!(agent.egress_enforcement, EgressEnforcement::Cooperative);

    // Unacknowledged weakening is unconstructible.
    assert!(UnenforcedEgressAcknowledgement::new(
        ActingPrincipal {
            subject: String::new(),
            tenant_id: "tenant-a".to_string(),
            worker_id: None,
            delegated_user: None,
        },
        "because",
        1_050,
    )
    .is_err());
}

#[test]
fn an_allowlist_that_cannot_reach_the_gateway_is_refused() {
    let mut adapter = MockCodingAgent::full();
    let credential = credential(RepoCredentialScope::read_only(&repo()));
    let workspace = adapter
        .materialize_repo(materialization(credential))
        .expect("workspace");

    let mut hosts = BTreeSet::new();
    hosts.insert("github.com".to_string());
    let mut request = bootstrap_request(workspace.clone());
    request.egress = EgressPosture::Allowlist { hosts };
    assert!(matches!(
        adapter.bootstrap(request),
        Err(CodingAgentError::EgressNotGoverned { .. })
    ));

    let mut empty = bootstrap_request(workspace);
    empty.egress = EgressPosture::Allowlist {
        hosts: BTreeSet::new(),
    };
    assert!(matches!(
        adapter.bootstrap(empty),
        Err(CodingAgentError::EgressNotGoverned { .. })
    ));
}

#[test]
fn the_descriptor_names_the_agent_without_a_closed_vendor_enum() {
    let adapter = MockCodingAgent::full();
    let descriptor = adapter.descriptor();
    assert_eq!(descriptor.agent_name, "mock-agent");
    assert_eq!(
        descriptor.isolation_backend,
        crate::CLOUDFLARE_CONTAINER_BACKEND_NAME
    );
    assert!(descriptor
        .capabilities
        .supports_write_back(WriteBackOperation::PushBranch));

    let diff_only = CodingAgentCapabilities::diff_only();
    assert!(!diff_only.supports_write_back(WriteBackOperation::PushBranch));
    assert!(!diff_only.supports_write_back(WriteBackOperation::OpenPullRequest));
    assert!(!diff_only.brokered_credentials);
}

#[test]
fn the_run_identity_projects_onto_the_shared_instance_and_cost_keys() {
    let run = run();
    assert_eq!(
        run.instance_name().expect("name"),
        "fg.tenant-a.session-1.run-1"
    );
    let attribution = run.cost_attribution().expect("attribution");
    assert_eq!(attribution.run_id, "run-1");
    assert_eq!(attribution.instance_name, "fg.tenant-a.session-1.run-1");

    let invalid = CodingRunIdentity::new("tenant a", "session-1", "run-1");
    assert!(invalid.instance_name().is_err());
}
