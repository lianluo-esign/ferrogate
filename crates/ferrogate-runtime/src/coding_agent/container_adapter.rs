// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, the container-backed CodingAgentAdapter
//   (issue #472): the first real implementation of the five phases, driving git through the
//   #415 /container/exec seam so materialization is a clone that happens, not a shape.

//! **The container-backed implementation of the contract.**
//!
//! The contract in this module's siblings is types and a trait. This is the
//! implementation that makes it non-vacuous: [`ContainerCodingAgentAdapter`]
//! runs the five phases by driving `git` inside a #415 Cloudflare Container
//! through [`ContainerControlClient`]'s `/container/exec` route — the same
//! governed channel the lifecycle, memory and schedule verbs use.
//!
//! It is deliberately **agent-agnostic**. It knows `git` and it knows the
//! container exec seam; it does not know Claude Code, aider, or any other
//! harness. [`CodingAgentImage::entrypoint`] is argv the adapter runs, so the
//! second coding agent is a different `image_ref` and a different argv, not a
//! new adapter — which is exactly what the issue's "define the contract first"
//! non-goal was protecting.
//!
//! ## Why this shape
//!
//! * **No shell.** Every step is `execve`-style argv
//!   ([`ContainerExecKind::Command`]). Nothing in this file interpolates a repo
//!   name, a branch, or a task instruction into a shell string, so no repo can
//!   name itself into a command.
//! * **The pin is verified from the container's own answer.** The last step of
//!   materialization is `git rev-parse HEAD` inside the instance, parsed back
//!   through [`PinnedRef`] and checked with
//!   [`MaterializedWorkspace::verify`]. "The clone landed on the pin" is read
//!   out of the workspace, not assumed from the fetch having exited 0.
//! * **The credential is configured, never carried.** For
//!   [`CredentialDelivery::BrokeredPerOperation`] the adapter applies #475's
//!   [`git_helper_config_lines`] so `git` calls the broker back; for
//!   [`CredentialDelivery::EphemeralFile`] it points `credential.store` at the
//!   file the isolation tier wrote outside the workspace. Neither path has a
//!   token in it, because no type here can hold one.
//! * **Revocation is a seam, not an assumption.** [`RepoCredentialRevoker`] is
//!   injected; if it fails, the close-out records
//!   [`RevocationOutcome::Failed`] and
//!   [`CodingRunReceipt::credential_is_closed`] answers `false`. A live
//!   credential that outlived its run is data, not a swallowed log line.
//!
//! ## What it deliberately does not do
//!
//! Opening a pull request is a provider API call, not a git operation, so
//! [`WriteBackOperation::OpenPullRequest`] is
//! [`CodingAgentError::Unsupported`] here rather than quietly downgraded to a
//! push. The descriptor advertises that up front
//! ([`CodingAgentCapabilities::pull_request`] is `false`), so a caller fails
//! closed before a credential is issued.

use crate::cloudflare_container::{
    ContainerControlClient, ContainerControlError, ContainerExecOutput, ContainerExecSpec,
    ContainerSignal,
};
use crate::cloudflare_gateway_control::GatewayControlTransport;
use crate::coding_agent::adapter::{
    CodingAgentAdapter, CodingAgentCapabilities, CodingAgentDescriptor,
};
use crate::coding_agent::bootstrap::{AgentBootstrapRequest, BootstrappedAgent};
use crate::coding_agent::credential_broker::git_helper_config_lines;
use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::extract::{
    DiffStats, ProducedBranch, UnifiedDiff, WorkProduct, WorkProductRequest,
};
use crate::coding_agent::materialize::{
    CredentialDelivery, MaterializedWorkspace, PinnedRef, RepoCredentialGrant,
    RepoMaterializationRequest, RevocationOutcome, RevocationPoint,
};
use crate::coding_agent::run::{
    CodingRunOutcome, CodingRunReceipt, CodingRunRequest, CodingRunStatus, RunFinalization,
};
use crate::coding_agent::write_back::{
    AuthorizedWriteBack, WriteBackOperation, WriteBackOutcome, WriteBackReceipt,
};
use crate::opaque_reference_fingerprint;
use crate::CLOUDFLARE_CONTAINER_BACKEND_NAME;

/// The git credential helper command the brokered delivery installs. It is a
/// program the image ships, not a shell fragment: `git` invokes it directly.
pub const BROKERED_CREDENTIAL_HELPER: &str = "ferrogate-git-credential";

/// Close out one run's credential at its [`RevocationPoint`].
///
/// A seam rather than an inlined HTTP call: the revocation point is a
/// control-plane endpoint (for a GitHub App installation token, `DELETE
/// /installation/token`), and which client reaches it is a deployment
/// question. Injecting it keeps the adapter testable with no network and makes
/// a *failed* revocation representable instead of unthinkable.
pub trait RepoCredentialRevoker {
    /// Attempt the revocation and report honestly what happened. Returning
    /// [`RevocationOutcome::Failed`] is a supported answer; it lands on the
    /// run receipt and makes [`CodingRunReceipt::credential_is_closed`] false.
    fn revoke(
        &mut self,
        point: &RevocationPoint,
        grant_id: &str,
        now_unix: u64,
    ) -> RevocationOutcome;
}

/// What bootstrap learned and `run` needs. The exec seam is synchronous, so
/// the agent process is launched by [`CodingAgentAdapter::run`]; bootstrap
/// settles *what* will be launched, under which posture, and refuses the
/// request if the posture does not admit the gateway.
#[derive(Debug, Clone)]
struct LaunchPlan {
    run_id: String,
    workspace_path: String,
    argv: Vec<String>,
}

/// Drives the five phases by running `git` and the agent's own argv inside a
/// #415 container.
pub struct ContainerCodingAgentAdapter<T: GatewayControlTransport> {
    descriptor: CodingAgentDescriptor,
    containers: ContainerControlClient<T>,
    revoker: Box<dyn RepoCredentialRevoker>,
    clock: fn() -> u64,
    plan: Option<LaunchPlan>,
}

/// Capabilities this adapter honestly implements.
///
/// `pull_request` is `false` and `submodules` is `false` on purpose: an
/// adapter that advertises a capability it does not implement is the #188
/// failure mode (the API accepted a value the runtime ignored), and
/// [`CodingAgentCapabilities::preflight`] turns each `false` into a refusal
/// before a container is started.
pub fn container_coding_agent_capabilities() -> CodingAgentCapabilities {
    CodingAgentCapabilities {
        materialize_repo: true,
        shallow_clone: true,
        submodules: false,
        brokered_credentials: true,
        diff_extraction: true,
        branch_extraction: true,
        push_branch: true,
        pull_request: false,
        resume: false,
    }
}

impl<T: GatewayControlTransport> ContainerCodingAgentAdapter<T> {
    /// Build an adapter that drives `agent_name` inside `containers`.
    pub fn new(
        adapter_version: impl Into<String>,
        agent_name: impl Into<String>,
        containers: ContainerControlClient<T>,
        revoker: Box<dyn RepoCredentialRevoker>,
    ) -> Self {
        Self {
            descriptor: CodingAgentDescriptor {
                adapter_name: "container-git".to_string(),
                adapter_version: adapter_version.into(),
                agent_name: agent_name.into(),
                isolation_backend: CLOUDFLARE_CONTAINER_BACKEND_NAME.to_string(),
                capabilities: container_coding_agent_capabilities(),
            },
            containers,
            revoker,
            clock: system_now_unix,
            plan: None,
        }
    }

    /// Override the clock. Tests pin it; production leaves it alone.
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    pub fn containers(&self) -> &ContainerControlClient<T> {
        &self.containers
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Run one argv in the run's instance and require exit 0.
    fn must_exec(
        &self,
        phase: CodingAgentPhase,
        run: &crate::coding_agent::run::CodingRunIdentity,
        argv: &[String],
        timeout_millis: Option<u64>,
    ) -> Result<ContainerExecOutput, CodingAgentError> {
        let output = self.exec(phase, run, argv, timeout_millis)?;
        if output.exit_code != Some(0) {
            return Err(CodingAgentError::backend(
                phase,
                format!(
                    "`{}` exited {:?} in {}: {}",
                    argv.join(" "),
                    output.exit_code,
                    output.instance,
                    truncate(output.stderr.trim(), 400)
                ),
            ));
        }
        Ok(output)
    }

    fn exec(
        &self,
        phase: CodingAgentPhase,
        run: &crate::coding_agent::run::CodingRunIdentity,
        argv: &[String],
        timeout_millis: Option<u64>,
    ) -> Result<ContainerExecOutput, CodingAgentError> {
        let mut spec = ContainerExecSpec::command(argv.iter().map(String::as_str));
        if let Some(timeout) = timeout_millis {
            spec = spec.with_timeout_millis(timeout);
        }
        self.containers
            .exec(&run.instance_identity(), &spec)
            .map_err(|error| container_error(phase, error))
    }
}

/// Steps the git config phase applies for a delivery.
///
/// Both arms end with `git` able to authenticate without this process ever
/// seeing a credential: the brokered arm points git at #475's helper, the file
/// arm points git at a file the isolation tier wrote *outside* the workspace
/// (which [`RepoMaterializationRequest::validate`] has already checked).
fn credential_config_lines(delivery: &CredentialDelivery) -> Vec<String> {
    match delivery {
        CredentialDelivery::BrokeredPerOperation { .. } => {
            git_helper_config_lines(BROKERED_CREDENTIAL_HELPER)
        }
        CredentialDelivery::EphemeralFile { path, .. } => vec![
            "credential.helper=".to_string(),
            format!("credential.helper=store --file={path}"),
            "credential.useHttpPath=true".to_string(),
            "http.sslVerify=true".to_string(),
            "protocol.file.allow=never".to_string(),
            "protocol.ext.allow=never".to_string(),
        ],
    }
}

impl<T: GatewayControlTransport> CodingAgentAdapter for ContainerCodingAgentAdapter<T> {
    fn descriptor(&self) -> &CodingAgentDescriptor {
        &self.descriptor
    }

    fn materialize_repo(
        &mut self,
        request: RepoMaterializationRequest<'_>,
    ) -> Result<MaterializedWorkspace, CodingAgentError> {
        let phase = CodingAgentPhase::Materialize;
        // Fail closed before any side effect: capabilities first, then the
        // structural checks (grant belongs to this run, is scoped to this repo,
        // is unexpired, and its delivery is not inside the workspace or off the
        // governed gateway host).
        self.descriptor.capabilities.preflight(&request)?;
        let now = self.now();
        request.validate(now)?;

        let ws = request.workspace_path.as_str();
        let mut steps: Vec<Vec<String>> = vec![argv(&["git", "init", "--quiet", ws])];
        for line in credential_config_lines(request.credential.delivery()) {
            let (key, value) = line.split_once('=').unwrap_or((line.as_str(), ""));
            steps.push(argv(&["git", "-C", ws, "config", "--local", key, value]));
        }
        steps.push(argv(&[
            "git",
            "-C",
            ws,
            "remote",
            "add",
            "origin",
            &request.repo.https_remote(),
        ]));
        // Fetch the commit id itself, never a branch name: the pin is the
        // request, so resolving a symbolic ref inside the container would
        // reintroduce exactly the moving target `PinnedRef` exists to remove.
        let mut fetch = argv(&["git", "-C", ws, "fetch", "--no-tags", "--quiet"]);
        if let Some(depth) = request.fetch_depth {
            fetch.push("--depth".to_string());
            fetch.push(depth.to_string());
        }
        fetch.push("origin".to_string());
        fetch.push(request.pinned_ref.commit_id().to_string());
        steps.push(fetch);
        steps.push(argv(&[
            "git",
            "-C",
            ws,
            "checkout",
            "--quiet",
            "--detach",
            "FETCH_HEAD",
        ]));

        for step in &steps {
            self.must_exec(phase, &request.run, step, None)?;
        }

        // Read the pin back out of the workspace rather than assuming it.
        let head = self.must_exec(
            phase,
            &request.run,
            &argv(&["git", "-C", ws, "rev-parse", "HEAD"]),
            None,
        )?;
        let materialized_ref = PinnedRef::new(head.stdout.trim())?;
        let workspace = MaterializedWorkspace {
            run: request.run.clone(),
            repo: request.repo.clone(),
            workspace_path: request.workspace_path.clone(),
            materialized_ref,
            credential_grant_id: request.credential.grant_id().to_string(),
            materialized_at_unix: now,
        };
        workspace.verify(&request.pinned_ref)?;
        Ok(workspace)
    }

    fn bootstrap(
        &mut self,
        request: AgentBootstrapRequest,
    ) -> Result<BootstrappedAgent, CodingAgentError> {
        // `BootstrappedAgent::new` runs `AgentBootstrapRequest::validate`,
        // which is where an egress posture that does not admit the governed
        // gateway is refused.
        let instance_name = request.run.instance_name()?;
        let agent = BootstrappedAgent::new(&request, instance_name, self.now())?;
        // The exec seam is synchronous, so the agent process is started by
        // `run`. What bootstrap settles is *what* will be started, against
        // which workspace — recorded here so `run` cannot be handed a
        // different argv than the one the posture was validated for.
        self.plan = Some(LaunchPlan {
            run_id: request.run.run_id.clone(),
            workspace_path: request.workspace.workspace_path.clone(),
            argv: request.image.entrypoint.clone(),
        });
        Ok(agent)
    }

    fn run(&mut self, request: CodingRunRequest) -> Result<CodingRunOutcome, CodingAgentError> {
        let started_at_unix = self.now();
        request.validate(started_at_unix)?;
        let Some(plan) = self.plan.clone() else {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Run,
                "agent",
                "run was called before bootstrap; there is no launch plan",
            ));
        };
        if plan.run_id != request.run.run_id {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Run,
                "agent",
                "the launch plan belongs to a different run",
            ));
        }
        // The deadline is the caller's: a coding agent with no wall clock is a
        // container that never stops billing.
        let timeout_millis = request
            .deadline_unix
            .saturating_sub(started_at_unix)
            .saturating_mul(1_000);
        let output = self.exec(
            CodingAgentPhase::Run,
            &request.run,
            &plan.argv,
            Some(timeout_millis),
        )?;
        let finished_at_unix = self.now();
        let status = match output.exit_code {
            Some(0) => CodingRunStatus::Completed,
            // The exec seam reports no exit code when the step was cut off at
            // its timeout rather than exiting.
            None => CodingRunStatus::TimedOut,
            Some(_) => CodingRunStatus::Failed,
        };
        Ok(CodingRunOutcome {
            run: request.run,
            status,
            started_at_unix,
            finished_at_unix,
            steps: 0,
            failure_detail: match status {
                CodingRunStatus::Completed => None,
                _ => Some(format!(
                    "agent exited {:?}: {}",
                    output.exit_code,
                    truncate(output.stderr.trim(), 400)
                )),
            },
        })
    }

    fn extract(
        &mut self,
        request: WorkProductRequest,
    ) -> Result<Option<WorkProduct>, CodingAgentError> {
        let phase = CodingAgentPhase::Extract;
        let ws = request.workspace.workspace_path.as_str();
        let base = request.base.commit_id().to_string();
        // `--intent-to-add` so files the agent created show up in the diff.
        // Without it "the agent added a new module" extracts as no change.
        self.must_exec(
            phase,
            &request.run,
            &argv(&["git", "-C", ws, "add", "--intent-to-add", "--all"]),
            None,
        )?;
        let patch = self
            .must_exec(
                phase,
                &request.run,
                &argv(&["git", "-C", ws, "--no-pager", "diff", "--no-color", &base]),
                None,
            )?
            .stdout;
        if patch.trim().is_empty() {
            // "The agent changed nothing" is a real outcome and must surface as
            // *no work product*, never as an empty patch.
            return Ok(None);
        }
        let numstat = self
            .must_exec(
                phase,
                &request.run,
                &argv(&["git", "-C", ws, "--no-pager", "diff", "--numstat", &base]),
                None,
            )?
            .stdout;
        let head = self
            .must_exec(
                phase,
                &request.run,
                &argv(&["git", "-C", ws, "rev-parse", "HEAD"]),
                None,
            )?
            .stdout
            .trim()
            .to_string();
        let branch_name = self
            .must_exec(
                phase,
                &request.run,
                &argv(&["git", "-C", ws, "rev-parse", "--abbrev-ref", "HEAD"]),
                None,
            )?
            .stdout
            .trim()
            .to_string();
        // A detached HEAD reports `HEAD`, and a head still at the base
        // committed nothing: either way there is no branch to publish, only a
        // working-tree diff.
        let branch = if branch_name == "HEAD" || head == base {
            None
        } else {
            Some(ProducedBranch::new(
                branch_name,
                head,
                request.base.clone(),
            )?)
        };

        let byte_len = patch.len() as u64;
        let diff = if byte_len > request.max_inline_diff_bytes {
            // Too big to carry: it belongs in the #415 artifact channel,
            // referenced by a digest over the same bytes.
            UnifiedDiff::artifact(
                format!("artifact://{}/diff", request.run.run_id),
                opaque_reference_fingerprint(&patch),
                byte_len,
            )?
        } else {
            UnifiedDiff::inline(patch)?
        };

        WorkProduct::assemble(
            request.run.clone(),
            request.workspace.repo.clone(),
            request.base.clone(),
            branch,
            diff,
            parse_numstat(&numstat),
            None,
            self.now(),
        )
        .map(Some)
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
            // Opening a review request is a provider API call, not a git verb.
            // Refused, never downgraded to "we pushed the branch, close enough".
            return Err(CodingAgentError::Unsupported {
                phase: CodingAgentPhase::WriteBack,
                capability: "pull_request",
            });
        }
        let Some(plan) = self.plan.clone() else {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::WriteBack,
                "workspace",
                "write-back was called before bootstrap; there is no workspace",
            ));
        };
        let refspec = match request.operation {
            WriteBackOperation::PushTag => {
                format!("{}:refs/tags/{}", request.head_commit, request.branch)
            }
            _ => format!("{}:refs/heads/{}", request.head_commit, request.branch),
        };
        let output = self.exec(
            CodingAgentPhase::WriteBack,
            &request.run,
            &argv(&[
                "git",
                "-C",
                &plan.workspace_path,
                "push",
                "origin",
                &refspec,
            ]),
            None,
        )?;
        let outcome = match output.exit_code {
            Some(0) => WriteBackOutcome::Completed,
            // The remote said no (protected branch, non-fast-forward,
            // permission). The mutation failed; the run did not.
            Some(_) => WriteBackOutcome::Refused {
                code: truncate(output.stderr.trim(), 200),
            },
            None => WriteBackOutcome::Failed {
                code: "push_did_not_complete".to_string(),
            },
        };
        Ok(WriteBackReceipt::from_authorized(
            &authorized,
            None,
            self.now(),
            outcome,
        ))
    }

    fn finalize(
        &mut self,
        finalization: RunFinalization,
    ) -> Result<CodingRunReceipt, CodingAgentError> {
        let now = self.now();
        let outcome = revoke_grant(self.revoker.as_mut(), &finalization.credential, now);
        // Tear the instance down after the credential is closed, and do not let
        // a teardown failure hide the revocation record — the receipt is the
        // evidence and must exist either way.
        let identity = finalization.run.instance_identity();
        let _ = self.containers.stop(&identity, ContainerSignal::Term);
        let _ = self.containers.cleanup(&identity);
        self.plan = None;
        CodingRunReceipt::assemble(finalization, outcome)
    }
}

/// Close out the grant, short-circuiting when its TTL has already elapsed:
/// there is nothing to revoke, and calling anyway would turn a normal
/// expiry into a spurious failure.
fn revoke_grant(
    revoker: &mut dyn RepoCredentialRevoker,
    grant: &RepoCredentialGrant,
    now_unix: u64,
) -> RevocationOutcome {
    if grant.is_expired_at(now_unix) {
        return RevocationOutcome::AlreadyExpired;
    }
    revoker.revoke(grant.revocation_point(), grant.grant_id(), now_unix)
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect()
}

/// Parse `git diff --numstat`. Binary files report `-` for both counts, which
/// is counted as a changed file with no line delta rather than as a parse
/// failure.
fn parse_numstat(numstat: &str) -> DiffStats {
    let mut stats = DiffStats::default();
    for line in numstat.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let added = fields.next().unwrap_or("-");
        let removed = fields.next().unwrap_or("-");
        if fields.next().is_none() {
            continue;
        }
        stats.files_changed = stats.files_changed.saturating_add(1);
        stats.insertions = stats
            .insertions
            .saturating_add(added.parse::<u64>().unwrap_or(0));
        stats.deletions = stats
            .deletions
            .saturating_add(removed.parse::<u64>().unwrap_or(0));
    }
    stats
}

fn container_error(phase: CodingAgentPhase, error: ContainerControlError) -> CodingAgentError {
    CodingAgentError::backend(phase, error.to_string())
}

fn system_now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "container_adapter_test.rs"]
mod tests;
