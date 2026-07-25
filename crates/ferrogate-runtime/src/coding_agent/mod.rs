// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472):
//   the five-phase contract (materialize -> bootstrap -> run -> extract -> write-back) for
//   running a repo-aware coding agent in a governed container. Types + trait + doc only.

//! # The coding-agent adapter contract (issue #472)
//!
//! "Fix this bug in my repo" is the product story the Cloudflare stack exists
//! to serve. The infrastructure already exists — container lifecycle and exec
//! (#415, via the agent-gateway Worker's `/container/*` routes), agent
//! lifecycle (#414), memory (#427), cost governance (#428). What did not exist
//! is the contract that turns those into a reviewable change.
//!
//! This module is **types, a trait, and this document**. It starts no
//! container, opens no socket, resolves no secret, and integrates no specific
//! coding agent. See [What this module deliberately does not
//! decide](#what-this-module-deliberately-does-not-decide).
//!
//! ## The five phases
//!
//! | Phase | Module | Question it settles |
//! |---|---|---|
//! | 1. Materialize | [`materialize`] | Which commit, cloned with which credential, revoked where? |
//! | 2. Bootstrap | [`bootstrap`] | Which agent, given which task, with model traffic pointed where? |
//! | 3. Run | [`run`] | Long-running, filesystem-mutating execution to a terminal status. |
//! | 4. Extract | [`extract`] | What did it produce, and to which `run_id` does that belong? |
//! | 5. Write back | [`write_back`] | Who authorized the outward side effect, and where is the audit event? |
//!
//! Plus a mandatory close-out ([`CodingAgentAdapter::finalize`]) that
//! discharges phase 1's credential obligation. It is not a sixth feature; it is
//! the reason phase 1 is safe.
//!
//! ## Five invariants, carried by types rather than by discipline
//!
//! 1. **A branch is not a pin.** [`PinnedRef`] accepts only a full commit id,
//!    and [`MaterializedWorkspace::verify`] makes "the clone landed elsewhere"
//!    a hard failure. Every artifact downstream is attributed to the pin.
//! 2. **Credentials are references, never material.** [`CredentialReference`]
//!    holds a secret-store URI, refuses bare values, and specifically refuses
//!    `env://` — a container running model-authored code can read its own
//!    environment (#475). There is no field in this contract that can hold a
//!    token, so no implementation can log, persist, or bake one into an image
//!    by accident. [`CredentialDelivery`] has no `EnvVar` variant; adding one
//!    would be a contract change, which is the point.
//! 3. **Write capability cannot be self-granted.**
//!    [`RepoCredentialScope::with_write_back`] requires a [`WriteBackGrant`] by
//!    reference, so a write-capable credential is unconstructible without one.
//!    [`CodingAgentAdapter::write_back`] accepts only an
//!    [`AuthorizedWriteBack`], which has private fields, no public constructor,
//!    and no `Deserialize` — it cannot be forged from JSON, and the only mint
//!    is [`authorize_write_back`], which emits an [`crate::ActionReceipt`] on
//!    the allow path *and* the deny path.
//! 4. **The deliverable is a diff, not a chat completion.**
//!    [`WorkProduct::product_id`] is derived —
//!    `sha256(tenant|run|base_commit|diff_digest)` — so attribution is
//!    checkable ([`WorkProduct::attributed_to`]) rather than asserted. An empty
//!    diff is refused: "the agent changed nothing" surfaces as *no work
//!    product*, never as an empty patch that reads like a reviewable change.
//!    Agent prose is [`WorkProduct::summary`] and is explicitly advisory.
//! 5. **The gateway cannot claim enforcement it does not have.**
//!    [`EgressPosture::enforcement`] is *derived* from the posture, so no
//!    implementation can record `network_enforced` for an open-egress run. The
//!    only bypassable posture, [`EgressPosture::OpenWithDetection`], requires a
//!    named approver, and that weakening lands on the run receipt.
//!
//! ## Why this is not [`crate::FrameworkAdapter`]
//!
//! `FrameworkAdapter` models a request/response worker: start a session, submit
//! a run, stream normalized events, collect artifacts. A coding agent is a
//! different shape — long-running, filesystem-mutating, VCS-writing — and three
//! of its five phases (materialization, extraction, write-back authorization)
//! have no counterpart there at all. Bolting them onto `FrameworkAdapter`
//! would mean either widening every existing adapter with methods it cannot
//! implement, or smuggling repo state through `artifacts`. They stay separate;
//! an implementation that wants both can implement both.
//!
//! ## Why there is no `SupportedCodingAgent` enum
//!
//! [`crate::SupportedFramework`] is a closed enum. This contract deliberately
//! does not mirror it: [`CodingAgentDescriptor::agent_name`] is a free string
//! and nothing in the contract branches on it. The issue's warning is exact —
//! a vendor-shaped abstraction taken from one implementation is how the wrong
//! contract gets frozen, as it was across five merged slices in #350. A closed
//! list would have to be edited, and every `match` on it revisited, to admit
//! the second coding agent.
//!
//! ## Consistency with decision #470
//!
//! `docs/cloudflare-data-plane-decision.md` keeps the governed data plane as
//! **Pingora in a Cloudflare Container** — one Rust implementation, no second
//! governed path. This contract assumes exactly that: [`GovernedLlmEgress`]
//! points at one tethered governed endpoint reachable from the agent's
//! container, and the strongest posture ([`EgressPosture::GatewayProxied`])
//! proxies git through it too, keeping public egress off entirely. Nothing here
//! introduces a second policy implementation, and nothing here assumes a Worker
//! can be the governed proxy.
//!
//! ## What this module deliberately does not decide
//!
//! * **Any specific coding-agent integration.** No Claude Code, no aider, no
//!   in-house harness. The contract exists so the second one costs nothing.
//! * **Transport and lifecycle.** How `materialize_repo` actually runs `git` is
//!   the isolation tier's business (#415's `/container/exec`). This contract
//!   never touches the network.
//! * **Credential resolution.** Resolving the store reference to a value is the
//!   secret backend's business ([`ferrogate_secrets`]), and on Cloudflare it
//!   happens only inside a Worker binding (#423). This contract fixes only the
//!   *shape* — short-lived, single-repo, reference-not-material, explicitly
//!   revoked. The [`credential_broker`] module (#475) supplies the mechanism
//!   behind [`CredentialDelivery::BrokeredPerOperation`]: the credential-helper
//!   callback, repo-scoped GitHub App installation-token issuance, the
//!   revocation point, and the pinned host keys.
//! * **Egress enforcement mechanics.** Whether the platform can actually pin an
//!   allowlist is #471/#475. This contract makes the posture declarable,
//!   derivable, and auditable; it cannot make Cloudflare enforce it.
//! * **Persistence and the control-plane read path.** Storing work products and
//!   serving `GET /admin/v1/.../work-products/{id}` is a separate slice; the
//!   types here are serde-ready for it, but no repository trait is frozen yet
//!   on the strength of a guess about the query shape.
//! * **Approval workflow.** [`WriteBackGrant::approval_reference`] links to the
//!   existing approval machinery; this contract does not re-implement it.
//! * **Prompt construction.** [`TaskBrief`] carries the requester's instruction
//!   verbatim. How an implementation turns that into its agent's prompt format
//!   is its own business, and should stay that way.

mod adapter;
mod bootstrap;
mod credential_broker;
mod error;
mod extract;
mod materialize;
mod run;
mod write_back;

pub use adapter::{CodingAgentAdapter, CodingAgentCapabilities, CodingAgentDescriptor};
pub use bootstrap::{
    AgentBootstrapRequest, BootstrappedAgent, CodingAgentImage, EgressEnforcement, EgressPosture,
    GovernedLlmEgress, TaskBrief, UnenforcedEgressAcknowledgement,
};
pub use credential_broker::{
    broker_audience, broker_capability_fingerprint, broker_deny_codes, git_helper_config_lines,
    github_known_hosts, validate_ssh_hardening, validate_transport_env, BrokerCallbackBinding,
    BrokerDecision, BrokerGrantRecord, BrokerGrantRegistration, BrokeredCredentialLease,
    ContainerGitEnvironment, GitCredentialAuditEvent, GitCredentialBroker, GitCredentialCallback,
    GitCredentialQuery, GitOperation, InstallationTokenRequest, DEFAULT_BROKER_OPERATION_BUDGET,
    FORBIDDEN_TRANSPORT_ENV, GITHUB_INSTALLATION_TOKEN_TTL_SECS, GITHUB_SSH_HOST_KEYS,
    INSTALLATION_TOKEN_USERNAME,
};
pub use error::{CodingAgentError, CodingAgentPhase};
pub use extract::{
    DiffBody, DiffStats, ProducedBranch, UnifiedDiff, WorkProduct, WorkProductRequest,
    DEFAULT_MAX_INLINE_DIFF_BYTES, WORK_PRODUCT_ID_CONTRACT,
};
pub use materialize::{
    CredentialDelivery, CredentialReference, CredentialRevocation, MaterializedWorkspace,
    PinnedRef, RepoCoordinates, RepoCredentialGrant, RepoCredentialScope,
    RepoMaterializationRequest, RepoPermission, RevocationOutcome, RevocationPoint,
    ALLOWED_CREDENTIAL_SCHEMES, DENIED_CREDENTIAL_SCHEMES, MAX_REPO_CREDENTIAL_TTL_SECS,
};
pub use run::{
    CodingRunIdentity, CodingRunOutcome, CodingRunReceipt, CodingRunRequest, CodingRunStatus,
    RunBudgetBinding, RunFinalization,
};
pub use write_back::{
    authorize_write_back, canonical_write_back_target, write_back_codes, AuthorizedWriteBack,
    WriteBackAuthorization, WriteBackGrant, WriteBackOperation, WriteBackOutcome, WriteBackReceipt,
    WriteBackRequest, MAX_WRITE_BACK_GRANT_TTL_SECS, VCS_WRITE_BACK_ACTION,
};
