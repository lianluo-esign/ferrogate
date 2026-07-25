// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472),
//   phase 1: repo materialization at a pinned ref with a short-lived, repo-scoped credential
//   that is a store reference (never material), plus its explicit revocation point.

//! **Phase 1 — repo materialization.**
//!
//! Turn "a repo" into "a workspace at exactly this commit, cloned with a
//! credential that expires and is revoked at run end".
//!
//! Three properties are enforced by the *types*, not by convention:
//!
//! 1. **The ref is a pin.** [`PinnedRef`] only accepts a full commit id. A
//!    branch name is not a pin — it moves, and every downstream artifact (diff
//!    base, work-product id, review) is attributed to the pin.
//! 2. **The credential is a reference, never material.** [`CredentialReference`]
//!    holds a secret-store URI and refuses both raw values and `env://`. There
//!    is no field anywhere in this module that can hold a token, so no
//!    implementation can accidentally log, persist, or bake one in. `env://` is
//!    refused specifically because the process environment of a container
//!    running model-authored code is readable by that code (issue #475).
//! 3. **Write capability cannot be self-granted.** A credential scope that
//!    includes write permissions is only constructible from a
//!    [`crate::coding_agent::WriteBackGrant`] — see
//!    [`RepoCredentialScope::with_write_back`]. Read-only is the only scope you
//!    can build from nothing.
//!
//! The grant carries an explicit [`RevocationPoint`], and the terminal run
//! record ([`crate::coding_agent::CodingRunReceipt`]) cannot be constructed
//! without a [`CredentialRevocation`] — so "revoked on success and failure
//! alike" is structural rather than a code-review promise.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::run::CodingRunIdentity;
use crate::coding_agent::write_back::WriteBackGrant;
use crate::opaque_reference_fingerprint;

/// Upper bound on a repo credential's lifetime. A coding run is minutes, not
/// hours; anything longer is a long-lived credential wearing a TTL.
pub const MAX_REPO_CREDENTIAL_TTL_SECS: u64 = 3_600;

/// Secret-reference schemes the contract will carry.
pub const ALLOWED_CREDENTIAL_SCHEMES: [&str; 2] = ["cf", "vault"];

/// Schemes explicitly refused, with the reason attached to the refusal.
/// `env://` resolves out of the process environment, which is exactly what an
/// untrusted, model-authored process inside the container can read.
pub const DENIED_CREDENTIAL_SCHEMES: [&str; 1] = ["env"];

/// Where a repo lives, without assuming a vendor.
///
/// `provider` is a free string (`github`, `gitlab`, `gitea`, an internal
/// forge). Nothing in the contract branches on its value; it exists so audit
/// records and adapters can be selected by it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoCoordinates {
    pub provider: String,
    pub host: String,
    pub namespace: String,
    pub name: String,
}

impl RepoCoordinates {
    pub fn new(
        provider: impl Into<String>,
        host: impl Into<String>,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, CodingAgentError> {
        let coordinates = Self {
            provider: provider.into().trim().to_ascii_lowercase(),
            host: host.into().trim().to_ascii_lowercase(),
            namespace: namespace.into().trim().to_string(),
            name: name.into().trim().to_string(),
        };
        component("provider", &coordinates.provider)?;
        component("host", &coordinates.host)?;
        component("namespace", &coordinates.namespace)?;
        component("name", &coordinates.name)?;
        if coordinates.host.contains('/') || coordinates.host.contains('@') {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Materialize,
                "repo.host",
                "host must not contain a path or userinfo",
            ));
        }
        if coordinates.name.contains('/') {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Materialize,
                "repo.name",
                "name must not contain a path separator",
            ));
        }
        Ok(coordinates)
    }

    /// Stable identity used for grant matching and audit joins:
    /// `provider:host/namespace/name`.
    pub fn canonical_id(&self) -> String {
        format!(
            "{}:{}/{}/{}",
            self.provider, self.host, self.namespace, self.name
        )
    }

    /// The git HTTPS remote. This is the URL the write-back capability's
    /// canonical target is derived from.
    pub fn https_remote(&self) -> String {
        format!("https://{}/{}/{}.git", self.host, self.namespace, self.name)
    }
}

fn component(field: &'static str, value: &str) -> Result<(), CodingAgentError> {
    if value.is_empty() {
        return Err(CodingAgentError::invalid(
            CodingAgentPhase::Materialize,
            field,
            "must not be empty",
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(CodingAgentError::invalid(
            CodingAgentPhase::Materialize,
            field,
            "must not contain whitespace",
        ));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err(CodingAgentError::invalid(
            CodingAgentPhase::Materialize,
            field,
            "must not contain path traversal",
        ));
    }
    Ok(())
}

/// An immutable ref: a full commit id, plus the symbolic name it was resolved
/// from (advisory — recorded for humans, never used to re-resolve).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedRef {
    commit_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbolic_ref: Option<String>,
}

impl PinnedRef {
    /// Accepts a 40-hex (SHA-1) or 64-hex (SHA-256 object format) commit id.
    /// Anything else — `main`, `HEAD`, `v1.2.3`, an abbreviated id — is
    /// [`CodingAgentError::UnpinnedRef`].
    pub fn new(commit_id: impl Into<String>) -> Result<Self, CodingAgentError> {
        let commit_id = commit_id.into().trim().to_ascii_lowercase();
        let is_hex = !commit_id.is_empty()
            && commit_id
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase());
        if !is_hex || !matches!(commit_id.len(), 40 | 64) {
            return Err(CodingAgentError::UnpinnedRef {
                detail: format!(
                    "expected a full 40- or 64-hex commit id, got {commit_id:?}; \
                     branch and tag names move and are not pins"
                ),
            });
        }
        Ok(Self {
            commit_id,
            symbolic_ref: None,
        })
    }

    /// Record the symbolic ref the pin was resolved from (`refs/heads/main`).
    /// Advisory only.
    pub fn resolved_from(mut self, symbolic_ref: impl Into<String>) -> Self {
        self.symbolic_ref = Some(symbolic_ref.into());
        self
    }

    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    pub fn symbolic_ref(&self) -> Option<&str> {
        self.symbolic_ref.as_deref()
    }
}

/// A reference to a credential held in a secret store. **Never the credential.**
///
/// This type has no variant, field, or constructor that can hold key material,
/// which is the point: an implementation cannot write a token into the
/// contract even by mistake, so nothing here can reach a log line, a run event,
/// #427 memory, or a container image layer.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReference {
    scheme: String,
    locator: String,
}

/// Renders the reference URI. Safe by construction — there is nothing else in
/// this type to leak.
impl fmt::Debug for CredentialReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialReference({}://{})", self.scheme, self.locator)
    }
}

impl CredentialReference {
    /// Parse `<scheme>://<locator>` against [`ALLOWED_CREDENTIAL_SCHEMES`].
    ///
    /// The spelling matches `ferrogate_secrets::SecretRef` so a reference can
    /// be handed to the existing resolver registry unchanged; this module does
    /// not resolve it, on purpose — resolution happens in the control plane,
    /// outside the container.
    pub fn parse(raw: &str) -> Result<Self, CodingAgentError> {
        let raw = raw.trim();
        let Some((scheme, locator)) = raw.split_once("://") else {
            return Err(CodingAgentError::credential(
                "credential must be a secret-store reference such as \
                 cf://<store>/<name>; a bare value is treated as key material \
                 and refused",
            ));
        };
        let scheme = scheme.trim().to_ascii_lowercase();
        if DENIED_CREDENTIAL_SCHEMES.contains(&scheme.as_str()) {
            return Err(CodingAgentError::credential(format!(
                "{scheme}:// is refused for repo credentials: the process \
                 environment of a container running model-authored code is \
                 readable by that code"
            )));
        }
        if !ALLOWED_CREDENTIAL_SCHEMES.contains(&scheme.as_str()) {
            return Err(CodingAgentError::credential(format!(
                "unsupported credential reference scheme {scheme}://; expected \
                 one of {ALLOWED_CREDENTIAL_SCHEMES:?}"
            )));
        }
        if locator.trim().is_empty() {
            return Err(CodingAgentError::credential(
                "credential reference locator must not be empty",
            ));
        }
        Ok(Self {
            scheme,
            locator: locator.trim().to_string(),
        })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn as_str(&self) -> String {
        format!("{}://{}", self.scheme, self.locator)
    }

    /// Audit-safe identifier for the reference. Records *which* credential was
    /// used without recording the reference path itself.
    pub fn fingerprint(&self) -> String {
        opaque_reference_fingerprint(&self.as_str())
    }
}

/// Permissions a repo credential may carry. Write permissions are only
/// reachable through a [`WriteBackGrant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoPermission {
    ContentsRead,
    ContentsWrite,
    PullRequestWrite,
}

impl RepoPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContentsRead => "contents.read",
            Self::ContentsWrite => "contents.write",
            Self::PullRequestWrite => "pull_request.write",
        }
    }

    pub fn is_write(self) -> bool {
        matches!(self, Self::ContentsWrite | Self::PullRequestWrite)
    }
}

/// What the credential is allowed to do, and to which repo. Single-repo by
/// construction: there is no multi-repo constructor, because "least privilege"
/// for a run that clones one repo is one repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoCredentialScope {
    repo_id: String,
    permissions: Vec<RepoPermission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    write_back_grant_id: Option<String>,
}

impl RepoCredentialScope {
    /// The only scope constructible without an explicit write-back grant.
    pub fn read_only(repo: &RepoCoordinates) -> Self {
        Self {
            repo_id: repo.canonical_id(),
            permissions: vec![RepoPermission::ContentsRead],
            write_back_grant_id: None,
        }
    }

    /// A write-capable scope. Requires the grant *by reference*, so a
    /// write-capable credential literally cannot be minted by an adapter that
    /// was never handed one, and the resulting scope records which grant
    /// justified it.
    pub fn with_write_back(
        repo: &RepoCoordinates,
        grant: &WriteBackGrant,
    ) -> Result<Self, CodingAgentError> {
        if grant.repo_id() != repo.canonical_id() {
            return Err(CodingAgentError::credential(format!(
                "write-back grant {} is for {} but the credential scope is {}",
                grant.grant_id(),
                grant.repo_id(),
                repo.canonical_id()
            )));
        }
        let mut permissions = vec![RepoPermission::ContentsRead, RepoPermission::ContentsWrite];
        if grant.grants_pull_requests() {
            permissions.push(RepoPermission::PullRequestWrite);
        }
        Ok(Self {
            repo_id: repo.canonical_id(),
            permissions,
            write_back_grant_id: Some(grant.grant_id().to_string()),
        })
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn permissions(&self) -> &[RepoPermission] {
        &self.permissions
    }

    pub fn write_back_grant_id(&self) -> Option<&str> {
        self.write_back_grant_id.as_deref()
    }

    pub fn is_write_capable(&self) -> bool {
        self.permissions.iter().any(|p| p.is_write())
    }
}

/// How the credential reaches the git client inside the instance.
///
/// There is deliberately **no `EnvVar` variant**. Adding one would be a
/// contract change and a review-visible event, not a convenience an
/// implementation can reach for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "delivery", rename_all = "snake_case")]
pub enum CredentialDelivery {
    /// The credential never enters the instance. A git credential helper calls
    /// back to the gateway per operation; the gateway authenticates the run,
    /// authorizes the operation, and answers. Every use is audited and nothing
    /// rests in the container. This is the only delivery that survives an
    /// untrusted-process threat model (issue #475).
    BrokeredPerOperation { broker_url: String },
    /// A short-lived credential is written to a file at instance start,
    /// outside the workspace, and removed at finalize. Defense in depth only:
    /// a shell inside the instance can still read it, so this is the weaker
    /// option and is labelled as such rather than defaulted to.
    EphemeralFile { path: String, mode: u32 },
}

impl CredentialDelivery {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BrokeredPerOperation { .. } => "brokered_per_operation",
            Self::EphemeralFile { .. } => "ephemeral_file",
        }
    }

    /// Whether the credential is readable by a process inside the instance.
    /// Recorded on the run receipt so the weakening is visible after the fact.
    pub fn readable_in_instance(&self) -> bool {
        matches!(self, Self::EphemeralFile { .. })
    }

    fn validate(&self, workspace_path: &str) -> Result<(), CodingAgentError> {
        match self {
            Self::BrokeredPerOperation { broker_url } => {
                if !broker_url.starts_with("https://") {
                    return Err(CodingAgentError::credential(
                        "credential broker URL must be https",
                    ));
                }
                Ok(())
            }
            Self::EphemeralFile { path, mode } => {
                if !path.starts_with('/') {
                    return Err(CodingAgentError::credential(
                        "ephemeral credential path must be absolute",
                    ));
                }
                if path.starts_with(workspace_path) {
                    return Err(CodingAgentError::credential(format!(
                        "ephemeral credential path {path} is inside the agent \
                         workspace {workspace_path}"
                    )));
                }
                if mode & 0o077 != 0 {
                    return Err(CodingAgentError::credential(format!(
                        "ephemeral credential file mode {mode:#o} is group/world accessible"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Where a grant is revoked. Named explicitly so "revoke it" is a location in
/// the system, not an intention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationPoint {
    /// Control-plane endpoint or seam id that performs the revocation. It is
    /// reached from the control plane, never from inside the instance.
    pub endpoint: String,
}

/// A short-lived, repo-scoped credential grant.
///
/// `#[must_use]` and consumed by value in
/// [`crate::coding_agent::RunFinalization`], so dropping it without revoking is
/// visible at the call site.
#[must_use = "a repo credential grant must be revoked through CodingAgentAdapter::finalize"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoCredentialGrant {
    grant_id: String,
    run_id: String,
    scope: RepoCredentialScope,
    credential_ref: CredentialReference,
    issued_at_unix: u64,
    expires_at_unix: u64,
    delivery: CredentialDelivery,
    revocation: RevocationPoint,
}

impl RepoCredentialGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        grant_id: impl Into<String>,
        run_id: impl Into<String>,
        scope: RepoCredentialScope,
        credential_ref: CredentialReference,
        issued_at_unix: u64,
        expires_at_unix: u64,
        delivery: CredentialDelivery,
        revocation: RevocationPoint,
    ) -> Result<Self, CodingAgentError> {
        let grant_id = grant_id.into();
        let run_id = run_id.into();
        if grant_id.trim().is_empty() || run_id.trim().is_empty() {
            return Err(CodingAgentError::credential(
                "credential grant requires a grant id and a run id",
            ));
        }
        if expires_at_unix <= issued_at_unix {
            return Err(CodingAgentError::credential(
                "credential grant must expire strictly after it is issued",
            ));
        }
        let ttl = expires_at_unix - issued_at_unix;
        if ttl > MAX_REPO_CREDENTIAL_TTL_SECS {
            return Err(CodingAgentError::credential(format!(
                "credential TTL {ttl}s exceeds the {MAX_REPO_CREDENTIAL_TTL_SECS}s cap; \
                 a longer-lived credential is a long-lived credential wearing a TTL"
            )));
        }
        if revocation.endpoint.trim().is_empty() {
            return Err(CodingAgentError::credential(
                "credential grant requires an explicit revocation point",
            ));
        }
        Ok(Self {
            grant_id,
            run_id,
            scope,
            credential_ref,
            issued_at_unix,
            expires_at_unix,
            delivery,
            revocation,
        })
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn scope(&self) -> &RepoCredentialScope {
        &self.scope
    }

    pub fn credential_ref(&self) -> &CredentialReference {
        &self.credential_ref
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn delivery(&self) -> &CredentialDelivery {
        &self.delivery
    }

    pub fn revocation_point(&self) -> &RevocationPoint {
        &self.revocation
    }

    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }
}

/// Result of revoking a grant. Honest about failure: a failed revocation is
/// recorded, not swallowed, because it is the incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RevocationOutcome {
    /// The credential was actively revoked at the revocation point.
    Revoked,
    /// The credential's TTL had already elapsed; no revocation call was needed.
    AlreadyExpired,
    /// The revocation call failed. The credential may still be live until its
    /// TTL elapses — this must page someone, not be logged and forgotten.
    Failed { code: String },
}

impl RevocationOutcome {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Revoked => "revoked",
            Self::AlreadyExpired => "already_expired",
            Self::Failed { .. } => "failed",
        }
    }

    pub fn is_credential_neutralized(&self) -> bool {
        matches!(self, Self::Revoked | Self::AlreadyExpired)
    }
}

/// Receipt proving the credential opened in phase 1 was closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRevocation {
    pub grant_id: String,
    pub credential_fingerprint: String,
    pub revoked_at_unix: u64,
    pub outcome: RevocationOutcome,
}

impl CredentialRevocation {
    pub fn for_grant(
        grant: &RepoCredentialGrant,
        revoked_at_unix: u64,
        outcome: RevocationOutcome,
    ) -> Self {
        Self {
            grant_id: grant.grant_id.clone(),
            credential_fingerprint: grant.credential_ref.fingerprint(),
            revoked_at_unix,
            outcome,
        }
    }
}

/// Phase-1 request: clone `repo` at `pinned_ref` into `workspace_path` using
/// `credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoMaterializationRequest {
    pub run: CodingRunIdentity,
    pub repo: RepoCoordinates,
    pub pinned_ref: PinnedRef,
    pub workspace_path: String,
    pub credential: RepoCredentialGrant,
    /// Shallow-clone depth; `None` for a full clone.
    pub fetch_depth: Option<u32>,
    pub include_submodules: bool,
}

impl RepoMaterializationRequest {
    /// Structural validation, performed before any side effect: the credential
    /// belongs to this run, is scoped to this repo, has not already expired,
    /// and is delivered in a way that does not put it inside the workspace.
    pub fn validate(&self, now_unix: u64) -> Result<(), CodingAgentError> {
        if !self.workspace_path.starts_with('/') {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Materialize,
                "workspace_path",
                "must be an absolute path inside the instance",
            ));
        }
        if self.credential.run_id() != self.run.run_id {
            return Err(CodingAgentError::credential(format!(
                "credential grant {} belongs to run {} but was presented for run {}",
                self.credential.grant_id(),
                self.credential.run_id(),
                self.run.run_id
            )));
        }
        if self.credential.scope().repo_id() != self.repo.canonical_id() {
            return Err(CodingAgentError::credential(format!(
                "credential grant {} is scoped to {} but the repo is {}",
                self.credential.grant_id(),
                self.credential.scope().repo_id(),
                self.repo.canonical_id()
            )));
        }
        if self.credential.is_expired_at(now_unix) {
            return Err(CodingAgentError::credential(format!(
                "credential grant {} expired at {}",
                self.credential.grant_id(),
                self.credential.expires_at_unix()
            )));
        }
        self.credential.delivery().validate(&self.workspace_path)?;
        Ok(())
    }
}

/// Phase-1 result: the workspace, and proof it landed on the pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedWorkspace {
    pub run: CodingRunIdentity,
    pub repo: RepoCoordinates,
    pub workspace_path: String,
    /// The commit the workspace actually holds. [`Self::verify`] refuses any
    /// value other than the requested pin.
    pub materialized_ref: PinnedRef,
    pub credential_grant_id: String,
    pub materialized_at_unix: u64,
}

impl MaterializedWorkspace {
    /// Fail closed when the clone landed somewhere other than the pin.
    pub fn verify(&self, requested: &PinnedRef) -> Result<(), CodingAgentError> {
        if self.materialized_ref.commit_id() != requested.commit_id() {
            return Err(CodingAgentError::RefMismatch {
                requested: requested.commit_id().to_string(),
                materialized: self.materialized_ref.commit_id().to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "materialize_test.rs"]
mod tests;
