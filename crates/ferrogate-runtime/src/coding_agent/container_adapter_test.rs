// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for the container-backed
//   CodingAgentAdapter (issue #472): a real clone at a pinned ref driven through a mock
//   /container/exec transport — no live GitHub, no live model, no network.

use std::collections::VecDeque;
use std::sync::Mutex;

use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};

use super::*;
use crate::cloudflare_worker::CloudflareControlSurfaceError;
use crate::coding_agent::bootstrap::{
    AgentBootstrapRequest, CodingAgentImage, EgressPosture, GovernedLlmEgress, TaskBrief,
};
use crate::coding_agent::materialize::{
    CredentialReference, RepoCoordinates, RepoCredentialScope, RevocationPoint,
};
use crate::coding_agent::run::CodingRunIdentity;
use crate::coding_agent::write_back::{authorize_write_back, WriteBackGrant, WriteBackRequest};
use crate::{ActingPrincipal, ActionContext};

const BASE: &str = "1111111111111111111111111111111111111111";
const HEAD: &str = "3333333333333333333333333333333333333333";
const NOW: u64 = 1_100;
const WORKSPACE: &str = "/workspace/repo";
const GATEWAY_HOST: &str = "gateway.example";

fn now() -> u64 {
    NOW
}

/// A scripted `/container/exec` transport. Records every request so the test
/// asserts on the commands that actually ran, not on the return value.
struct MockContainer {
    responses: Mutex<VecDeque<HttpResponse>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockContainer {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    /// The argv of every `container/exec` call, in order.
    fn commands(&self) -> Vec<Vec<String>> {
        self.captured
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.url.ends_with("/container/exec"))
            .filter_map(|request| {
                let body: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).ok()?;
                let command = body.get("step")?.get("command")?.as_array()?.clone();
                Some(
                    command
                        .into_iter()
                        .map(|part| part.as_str().unwrap_or_default().to_string())
                        .collect(),
                )
            })
            .collect()
    }

    fn joined(&self) -> Vec<String> {
        self.commands()
            .into_iter()
            .map(|argv| argv.join(" "))
            .collect()
    }
}

impl GatewayControlTransport for MockContainer {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        assert_eq!(request.method, HttpMethod::Post);
        self.captured.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock container ran out of scripted responses"))
    }
}

/// One `exec` reply.
fn exec(exit_code: i32, stdout: &str) -> HttpResponse {
    let body = serde_json::json!({
        "instance": "fg.tenant-a.session-1.run-1",
        "exitCode": exit_code,
        "stdout": stdout,
        "stderr": "",
    });
    HttpResponse {
        status: 200,
        retry_after: None,
        body: serde_json::to_vec(&body).expect("json"),
    }
}

fn ok(exit_code: i32) -> HttpResponse {
    exec(exit_code, "")
}

/// A `stop`/`cleanup` reply, which `finalize` makes best-effort.
fn teardown() -> Vec<HttpResponse> {
    vec![
        HttpResponse {
            status: 200,
            retry_after: None,
            body: serde_json::to_vec(&serde_json::json!({
                "instance": "fg.tenant-a.session-1.run-1",
                "signal": "SIGTERM",
                "running": false,
            }))
            .expect("json"),
        },
        HttpResponse {
            status: 200,
            retry_after: None,
            body: serde_json::to_vec(&serde_json::json!({
                "instance": "fg.tenant-a.session-1.run-1",
                "destroyed": true,
            }))
            .expect("json"),
        },
    ]
}

/// A revoker that records the calls it was actually asked to make.
#[derive(Debug, Default)]
struct RecordingRevoker {
    calls: std::sync::Arc<Mutex<Vec<(String, String)>>>,
    outcome: Option<RevocationOutcome>,
}

impl RepoCredentialRevoker for RecordingRevoker {
    fn revoke(
        &mut self,
        point: &RevocationPoint,
        grant_id: &str,
        _now_unix: u64,
    ) -> RevocationOutcome {
        self.calls
            .lock()
            .unwrap()
            .push((point.endpoint.clone(), grant_id.to_string()));
        self.outcome.clone().unwrap_or(RevocationOutcome::Revoked)
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
        worker_id: None,
        delegated_user: None,
    }
}

fn credential() -> RepoCredentialGrant {
    RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        RepoCredentialScope::read_only(&repo()),
        CredentialReference::parse("cf://repo-creds/acme-widget").expect("reference"),
        1_000,
        1_600,
        CredentialDelivery::BrokeredPerOperation {
            broker_url: "https://gateway.example/git-credential".to_string(),
        },
        RevocationPoint {
            endpoint: "DELETE https://api.github.com/installation/token".to_string(),
        },
    )
    .expect("grant")
}

fn materialization(credential: &RepoCredentialGrant) -> RepoMaterializationRequest<'_> {
    RepoMaterializationRequest {
        run: run(),
        repo: repo(),
        pinned_ref: PinnedRef::new(BASE).expect("pin"),
        workspace_path: WORKSPACE.to_string(),
        credential,
        governed_gateway_host: GATEWAY_HOST.to_string(),
        fetch_depth: Some(1),
        include_submodules: false,
    }
}

fn adapter(responses: Vec<HttpResponse>) -> ContainerCodingAgentAdapter<MockContainer> {
    ContainerCodingAgentAdapter::new(
        "0.1.0",
        "mock-agent",
        ContainerControlClient::new(
            "https://gateway.example",
            "control-token",
            MockContainer::new(responses),
        ),
        Box::<RecordingRevoker>::default(),
    )
    .with_clock(now)
}

/// The number of `git` steps materialization runs before `rev-parse HEAD`:
/// `init`, seven config lines from #475's helper config, `remote add`, `fetch`,
/// `checkout`.
fn materialize_responses(head: &str) -> Vec<HttpResponse> {
    let mut responses = vec![ok(0); 11];
    responses.push(exec(0, head));
    responses
}

#[test]
fn materialization_clones_at_the_pin_through_the_container_exec_seam() {
    let mut adapter = adapter(materialize_responses(&format!("{BASE}\n")));
    let credential = credential();
    let workspace = adapter
        .materialize_repo(materialization(&credential))
        .expect("the repo materializes");

    assert_eq!(workspace.materialized_ref.commit_id(), BASE);
    assert_eq!(workspace.workspace_path, WORKSPACE);
    assert_eq!(workspace.credential_grant_id, "grant-1");

    let commands = adapter.containers().transport().joined();
    assert_eq!(
        commands.first().unwrap(),
        &format!("git init --quiet {WORKSPACE}")
    );
    // #475's credential-helper configuration is applied, including the
    // load-bearing `useHttpPath` that keeps repo scoping from collapsing to
    // host scoping.
    assert!(commands.iter().any(|command| command
        == &format!(
            "git -C {WORKSPACE} config --local credential.helper {BROKERED_CREDENTIAL_HELPER}"
        )));
    assert!(commands
        .iter()
        .any(|command| command.ends_with("config --local credential.useHttpPath true")));
    assert!(commands
        .iter()
        .any(|command| command.ends_with("config --local http.sslVerify true")));
    // The remote is the repo's canonical HTTPS remote, and the fetch names the
    // COMMIT, never a branch: a pin that gets re-resolved inside the container
    // is not a pin.
    assert!(commands
        .iter()
        .any(|command| command.ends_with("remote add origin https://github.com/acme/widget.git")));
    assert_eq!(
        commands[commands.len() - 3],
        format!("git -C {WORKSPACE} fetch --no-tags --quiet --depth 1 origin {BASE}")
    );
    assert_eq!(
        commands[commands.len() - 2],
        format!("git -C {WORKSPACE} checkout --quiet --detach FETCH_HEAD")
    );
    // The pin is read back out of the workspace, not assumed from exit 0.
    assert_eq!(
        commands[commands.len() - 1],
        format!("git -C {WORKSPACE} rev-parse HEAD")
    );
    // No credential material anywhere in what crossed the wire.
    let all = commands.join(" ").to_ascii_lowercase();
    assert!(!all.contains("ghp_"));
    assert!(!all.contains("token"));
}

#[test]
fn a_clone_that_lands_off_the_pin_fails_closed() {
    let mut adapter = adapter(materialize_responses(&format!("{HEAD}\n")));
    let credential = credential();
    let error = adapter
        .materialize_repo(materialization(&credential))
        .expect_err("a clone off the pin is a hard failure");
    assert_eq!(
        error,
        CodingAgentError::RefMismatch {
            requested: BASE.to_string(),
            materialized: HEAD.to_string(),
        }
    );
}

#[test]
fn a_failing_git_step_stops_materialization_with_the_command_that_failed() {
    let mut responses = vec![ok(0)];
    responses.push(HttpResponse {
        status: 200,
        retry_after: None,
        body: serde_json::to_vec(&serde_json::json!({
            "instance": "fg.tenant-a.session-1.run-1",
            "exitCode": 128,
            "stdout": "",
            "stderr": "fatal: could not read Username",
        }))
        .expect("json"),
    });
    let mut adapter = adapter(responses);
    let credential = credential();
    let error = adapter
        .materialize_repo(materialization(&credential))
        .expect_err("a failed git step is a backend error");
    let CodingAgentError::Backend { phase, detail } = error else {
        panic!("expected a backend error");
    };
    assert_eq!(phase, CodingAgentPhase::Materialize);
    assert!(
        detail.contains("could not read Username"),
        "detail: {detail}"
    );
}

#[test]
fn a_credential_the_contract_refuses_never_reaches_the_container() {
    // An off-gateway broker callback: refused before a single exec.
    let credential = RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        RepoCredentialScope::read_only(&repo()),
        CredentialReference::parse("cf://repo-creds/acme-widget").expect("reference"),
        1_000,
        1_600,
        CredentialDelivery::BrokeredPerOperation {
            broker_url: "https://attacker.example/git-credential".to_string(),
        },
        RevocationPoint {
            endpoint: "control-plane://credentials/revoke".to_string(),
        },
    )
    .expect("grant");
    let mut adapter = adapter(Vec::new());
    let error = adapter
        .materialize_repo(materialization(&credential))
        .expect_err("an off-gateway broker is refused");
    assert!(matches!(error, CodingAgentError::CredentialRejected { .. }));
    assert!(adapter.containers().transport().commands().is_empty());
}

fn bootstrap_request(workspace: MaterializedWorkspace) -> AgentBootstrapRequest {
    AgentBootstrapRequest {
        run: run(),
        workspace,
        image: CodingAgentImage::new(
            "mock-agent",
            "1.0.0",
            "registry.example/mock-agent:1.0.0",
            vec!["/usr/bin/mock-agent".to_string(), "--task".to_string()],
        )
        .expect("image"),
        task: TaskBrief::new("task-1", "fix the widget bug").expect("brief"),
        llm_egress: GovernedLlmEgress::new(
            "https://gateway.example",
            GATEWAY_HOST,
            CredentialReference::parse("cf://run-tokens/run-1").expect("reference"),
        )
        .expect("egress"),
        egress: EgressPosture::GatewayProxied,
    }
}

/// Drive materialize -> bootstrap -> run -> extract -> finalize against the
/// mock container, and assert on the git the adapter actually ran.
#[test]
fn the_five_phases_run_against_a_mock_container_and_produce_a_run_attributed_diff() {
    let patch = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";
    let mut responses = materialize_responses(&format!("{BASE}\n"));
    // run: the agent's own argv
    responses.push(ok(0));
    // extract: add -N, diff, numstat, rev-parse HEAD, rev-parse --abbrev-ref
    responses.push(ok(0));
    responses.push(exec(0, patch));
    responses.push(exec(0, "1\t1\tsrc/lib.rs\n"));
    responses.push(exec(0, &format!("{HEAD}\n")));
    responses.push(exec(0, "ferrogate/run-1-fix\n"));
    // finalize: stop + cleanup
    responses.extend(teardown());

    let mut adapter = adapter(responses);
    let credential = credential();
    let workspace = adapter
        .materialize_repo(materialization(&credential))
        .expect("workspace");
    let agent = adapter
        .bootstrap(bootstrap_request(workspace.clone()))
        .expect("bootstrapped");
    assert!(!agent.egress_is_bypassable());

    let outcome = adapter
        .run(CodingRunRequest {
            run: run(),
            agent: agent.clone(),
            deadline_unix: NOW + 600,
            budget: None,
        })
        .expect("run");
    assert_eq!(outcome.status, CodingRunStatus::Completed);

    let product = adapter
        .extract(WorkProductRequest::new(
            run(),
            workspace,
            PinnedRef::new(BASE).expect("pin"),
        ))
        .expect("extract")
        .expect("the agent changed something");
    assert!(product.attributed_to("run-1"));
    assert!(product.extracted_from(&repo()));
    assert_eq!(product.stats.files_changed, 1);
    assert_eq!(product.diff.inline_patch(), Some(patch));
    let branch = product.branch.clone().expect("a branch was produced");
    assert_eq!(branch.name, "ferrogate/run-1-fix");
    assert_eq!(branch.head_commit, HEAD);

    let receipt = adapter
        .finalize(RunFinalization {
            run: run(),
            outcome,
            credential,
            work_product: Some(product),
            write_back: None,
            egress_posture: agent.egress_posture.clone(),
            finalized_at_unix: NOW + 300,
        })
        .expect("finalized");
    assert!(receipt.credential_is_closed());
    assert!(
        receipt.write_back.is_none(),
        "nothing may leave without a grant"
    );
    assert_eq!(
        receipt.credential_revocation.revocation_endpoint,
        "DELETE https://api.github.com/installation/token"
    );

    let commands = adapter.containers().transport().joined();
    assert!(commands.iter().any(|c| c == "/usr/bin/mock-agent --task"));
    assert!(commands
        .iter()
        .any(|c| c == &format!("git -C {WORKSPACE} add --intent-to-add --all")));
    assert!(commands
        .iter()
        .any(|c| c == &format!("git -C {WORKSPACE} --no-pager diff --no-color {BASE}")));
    // No push happened: no grant was ever issued.
    assert!(!commands.iter().any(|c| c.contains(" push ")));
}

#[test]
fn an_unchanged_workspace_extracts_to_no_work_product_not_an_empty_patch() {
    let mut responses = materialize_responses(&format!("{BASE}\n"));
    responses.push(ok(0)); // add -N
    responses.push(exec(0, "   \n")); // diff: nothing
    let mut adapter = adapter(responses);
    let credential = credential();
    let workspace = adapter
        .materialize_repo(materialization(&credential))
        .expect("workspace");
    let product = adapter
        .extract(WorkProductRequest::new(
            run(),
            workspace,
            PinnedRef::new(BASE).expect("pin"),
        ))
        .expect("extract is not an error");
    assert!(product.is_none());
}

#[test]
fn an_authorized_push_runs_git_push_and_a_pull_request_is_refused_not_downgraded() {
    let mut responses = materialize_responses(&format!("{BASE}\n"));
    responses.push(ok(0)); // push
    let mut adapter = adapter(responses);
    let credential = credential();
    let workspace = adapter
        .materialize_repo(materialization(&credential))
        .expect("workspace");
    adapter
        .bootstrap(bootstrap_request(workspace))
        .expect("bootstrapped");

    let mut operations = std::collections::BTreeSet::new();
    operations.insert(WriteBackOperation::PushBranch);
    operations.insert(WriteBackOperation::OpenPullRequest);
    let grant = WriteBackGrant::issue(
        "grant-wb-1",
        "run-1",
        &repo(),
        operations,
        "ferrogate/run-",
        principal(),
        1_000,
        1_600,
    )
    .expect("grant");
    let request = |operation: WriteBackOperation| WriteBackRequest {
        run: run(),
        repo: repo(),
        operation,
        branch: "ferrogate/run-1-fix".to_string(),
        work_product_id: "sha256:deadbeef".to_string(),
        head_commit: HEAD.to_string(),
        title: None,
        body: None,
    };
    let context = ActionContext::for_request("req-1");

    let authorized = authorize_write_back(
        Some(&grant),
        &request(WriteBackOperation::PushBranch),
        &principal(),
        &context,
        NOW,
    )
    .expect("evaluable")
    .into_authorized()
    .expect("granted");
    let receipt = adapter.write_back(authorized).expect("pushed");
    assert_eq!(receipt.outcome, WriteBackOutcome::Completed);
    assert!(adapter
        .containers()
        .transport()
        .joined()
        .iter()
        .any(|command| command
            == &format!("git -C {WORKSPACE} push origin {HEAD}:refs/heads/ferrogate/run-1-fix")));

    // A pull request is a provider API call, not a git verb. The adapter says
    // so instead of pushing a branch and calling it a review request.
    let authorized = authorize_write_back(
        Some(&grant),
        &request(WriteBackOperation::OpenPullRequest),
        &principal(),
        &context,
        NOW,
    )
    .expect("evaluable")
    .into_authorized()
    .expect("granted");
    assert_eq!(
        adapter.write_back(authorized).expect_err("not implemented"),
        CodingAgentError::Unsupported {
            phase: CodingAgentPhase::WriteBack,
            capability: "pull_request",
        }
    );
}

#[test]
fn a_failed_revocation_is_recorded_as_an_incident_rather_than_swallowed() {
    let mut responses = materialize_responses(&format!("{BASE}\n"));
    responses.extend(teardown());
    let mut adapter = ContainerCodingAgentAdapter::new(
        "0.1.0",
        "mock-agent",
        ContainerControlClient::new(
            "https://gateway.example",
            "control-token",
            MockContainer::new(responses),
        ),
        Box::new(RecordingRevoker {
            outcome: Some(RevocationOutcome::Failed {
                code: "revoke_endpoint_unreachable".to_string(),
            }),
            ..RecordingRevoker::default()
        }),
    )
    .with_clock(now);
    let credential = credential();
    adapter
        .materialize_repo(materialization(&credential))
        .expect("workspace");

    let receipt = adapter
        .finalize(RunFinalization {
            run: run(),
            outcome: CodingRunOutcome {
                run: run(),
                status: CodingRunStatus::Failed,
                started_at_unix: NOW,
                finished_at_unix: NOW + 10,
                steps: 0,
                failure_detail: Some("agent crashed".to_string()),
            },
            credential,
            work_product: None,
            write_back: None,
            egress_posture: EgressPosture::GatewayProxied,
            finalized_at_unix: NOW + 20,
        })
        .expect("a failed revocation still produces the terminal record");
    // The record exists on the failure path — and says the credential is NOT
    // closed, which is the incident.
    assert!(!receipt.credential_is_closed());
    assert_eq!(receipt.status, CodingRunStatus::Failed);
}

#[test]
fn the_descriptor_advertises_only_what_this_adapter_implements() {
    let adapter = adapter(Vec::new());
    let descriptor = adapter.descriptor();
    assert_eq!(descriptor.adapter_name, "container-git");
    assert_eq!(
        descriptor.isolation_backend,
        CLOUDFLARE_CONTAINER_BACKEND_NAME
    );
    assert!(descriptor.capabilities.materialize_repo);
    assert!(descriptor.capabilities.brokered_credentials);
    assert!(descriptor.capabilities.push_branch);
    // Advertised false, and therefore refused by preflight rather than
    // silently ignored.
    assert!(!descriptor.capabilities.pull_request);
    assert!(!descriptor.capabilities.submodules);
}

#[test]
fn numstat_counts_binary_files_without_failing_the_parse() {
    let stats = parse_numstat("1\t2\tsrc/lib.rs\n-\t-\tlogo.png\n\n");
    assert_eq!(stats.files_changed, 2);
    assert_eq!(stats.insertions, 1);
    assert_eq!(stats.deletions, 2);
}
