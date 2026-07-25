// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, brokered per-operation git credential path
//   (issue #475): the credential-helper callback contract, repo-scoped GitHub App installation
//   token issuance + revocation, and pinned-host-key transport hardening.

//! **The brokered per-operation git credential path (issue #475).**
//!
//! [`CredentialDelivery::BrokeredPerOperation`] is the only delivery in the
//! #472 contract that survives the threat model, and this module is the
//! mechanism behind it. The container never receives a GitHub credential. It
//! receives a *callback binding*: a URL, a run id, a grant id, and a run-scoped
//! capability that is worthless anywhere except this gateway. Each time `git`
//! needs to authenticate it runs a credential helper, the helper asks the
//! gateway, the gateway authorizes the specific operation against the specific
//! repo, mints a repo-scoped token that lives for that operation, and records
//! an audit event.
//!
//! ## What actually rests inside the container
//!
//! Honest accounting, because "the token never touches the container" is a
//! claim that is easy to overstate:
//!
//! | Artifact | Where it lives | What an injected process gets from it |
//! |---|---|---|
//! | GitHub App private key | Worker secret, control plane only | nothing — never crosses the boundary |
//! | Installation token | Worker memory + the `git` process for one operation | must win a race against a live `git` |
//! | Callback capability | Container (env/file) | can ask *this gateway* for git ops on *one* repo, every one audited and counted |
//! | `known_hosts` / git config | Container, world-readable on purpose | nothing; it is public key material |
//!
//! The exchange the design makes is deliberate: a stolen callback capability
//! buys an attacker exactly the access the run already had (one repo, until the
//! grant expires or is revoked, with every use logged and budgeted), whereas a
//! stolen PAT or a stolen `GITHUB_TOKEN` env var buys durable, silent,
//! off-platform access to everything that token could reach. There is no
//! delivery where a `git` subprocess authenticates to GitHub without a
//! credential existing in that subprocess's memory for the length of the
//! request; what this path removes is *rest*, *scope*, *duration*, and
//! *silence*.
//!
//! ## Why this also fixes the Secrets Store scaling problem
//!
//! Brokering converts a **per-user** credential problem into a **single
//! platform** credential problem. Under a PAT-per-user model the platform would
//! need one stored secret per user; Cloudflare Secrets Store is capped at 100
//! secrets per account and its Worker bindings name a single secret at deploy
//! time, so that model is unimplementable there (see
//! `docs/cloudflare-git-credential-broker.md` for the verification). Under this
//! model the platform stores **one** GitHub App private key, and a user's
//! authorization is an *installation id* — a non-secret integer that belongs in
//! D1 next to the tenant row. Per-user credentials stop being secrets to store.
//!
//! ## What this module deliberately does not do
//!
//! It never holds, receives, parses, or returns key material. [`BrokerDecision`]
//! carries an *authorization*, and the token itself is minted by the Worker at
//! the moment it writes the helper response — see
//! [`InstallationTokenRequest`], which is a request *shape*, not a client. That
//! split is the reason no Rust type here can be logged into leaking a token:
//! there is nothing in any of them to leak.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::materialize::{
    CredentialDelivery, RepoCoordinates, RepoCredentialGrant, RepoCredentialScope, RepoPermission,
    RevocationPoint, MAX_REPO_CREDENTIAL_TTL_SECS,
};
use crate::opaque_reference_fingerprint;

/// Fixed lifetime of a GitHub App installation access token. GitHub does not
/// accept a requested expiry — "Installation tokens expire one hour from the
/// time you create them" — so the *usable* window is always the shorter of this
/// and the run's [`RepoCredentialGrant`] TTL, which the broker enforces.
pub const GITHUB_INSTALLATION_TOKEN_TTL_SECS: u64 = 3_600;

/// The username git must present alongside an installation token over HTTPS.
/// GitHub ignores the value's identity and reads only the password field, but
/// the literal is required — an empty username makes git prompt.
pub const INSTALLATION_TOKEN_USERNAME: &str = "x-access-token";

/// Default cap on how many times one run may ask the broker to authenticate.
/// A coding run clones once and pushes at most a few times; an order of
/// magnitude above that is a compromise indicator, not traffic.
pub const DEFAULT_BROKER_OPERATION_BUDGET: u32 = 32;

/// Stable machine-readable denial codes. The helper renders a refusal to git as
/// an empty credential (git then fails the operation); the code is what lands on
/// the audit event and the alarm.
pub mod broker_deny_codes {
    /// The callback named a run that is not the grant's run.
    pub const RUN_MISMATCH: &str = "run_mismatch";
    /// The callback named a grant this broker does not hold.
    pub const GRANT_MISMATCH: &str = "grant_mismatch";
    /// The grant's TTL elapsed before the operation was requested.
    pub const GRANT_EXPIRED: &str = "grant_expired";
    /// The grant is not a brokered grant, so there is no callback to serve.
    pub const DELIVERY_NOT_BROKERED: &str = "delivery_not_brokered";
    /// The helper asked for a non-HTTPS protocol.
    pub const PROTOCOL_NOT_HTTPS: &str = "protocol_not_https";
    /// The helper asked for a host the grant does not cover — the signature of
    /// a redirected remote, a hostile submodule, or an `insteadOf` rewrite.
    pub const HOST_NOT_GRANTED: &str = "host_not_granted";
    /// The helper sent no repository path, so the request cannot be proven to
    /// be for the granted repo (`credential.useHttpPath` was not set).
    pub const PATH_MISSING: &str = "path_missing";
    /// The helper asked for a repository the grant does not cover.
    pub const REPO_NOT_GRANTED: &str = "repo_not_granted";
    /// A write operation was requested under a read-only grant.
    pub const WRITE_NOT_GRANTED: &str = "write_not_granted";
    /// The run exhausted its per-run operation budget.
    pub const OPERATION_BUDGET_EXHAUSTED: &str = "operation_budget_exhausted";
}

/// The git operation the helper is authenticating.
///
/// git's credential protocol does not report intent, so the helper derives it
/// from the process it is embedded in (`GIT_HTTP_*`/the `git-upload-pack` vs
/// `git-receive-pack` service) and states it explicitly. A helper that lies and
/// claims `Fetch` gets a read-only lease, which is the safe direction; a helper
/// that claims `Push` under a read-only grant is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitOperation {
    /// `git clone` / `git fetch` — `git-upload-pack`.
    Fetch,
    /// `git push` — `git-receive-pack`.
    Push,
}

impl GitOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Push => "push",
        }
    }

    /// The git wire service that identifies the operation, which is what the
    /// helper actually observes.
    pub fn service(self) -> &'static str {
        match self {
            Self::Fetch => "git-upload-pack",
            Self::Push => "git-receive-pack",
        }
    }

    pub fn is_write(self) -> bool {
        matches!(self, Self::Push)
    }
}

impl fmt::Display for GitOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The key/value block git writes to a credential helper's stdin, as received.
///
/// Only the fields the broker authorizes on are modelled. Notably **absent**:
/// `password`. git sends one on `store`/`erase`, and this type having no field
/// for it is why a credential cannot ride back into the control plane on the
/// request path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCredentialQuery {
    /// `protocol=` — must be `https`.
    pub protocol: String,
    /// `host=` — may carry a `:port` suffix, which is stripped for comparison.
    pub host: String,
    /// `path=` — present only when `credential.useHttpPath=true`, which the
    /// container's git config sets ([`git_helper_config_lines`]). Without it
    /// the broker cannot prove the request is for the granted repo, and denies.
    #[serde(default)]
    pub path: Option<String>,
    /// `username=` — advisory; git echoes back whatever the remote URL carried.
    #[serde(default)]
    pub username: Option<String>,
}

impl GitCredentialQuery {
    /// Parse git's credential-helper stdin format: `key=value` lines, LF
    /// separated, terminated by a blank line or EOF. Unknown keys (`wwwauth[]`,
    /// `capability[]`, `password`, …) are ignored rather than rejected —
    /// forward compatibility with newer git — and `password` in particular is
    /// dropped on the floor because this type has nowhere to put it.
    pub fn parse(stdin_block: &str) -> Result<Self, CodingAgentError> {
        let mut query = Self::default();
        for line in stdin_block.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "protocol" => query.protocol = value.trim().to_ascii_lowercase(),
                "host" => query.host = value.trim().to_ascii_lowercase(),
                "path" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        query.path = Some(value.to_string());
                    }
                }
                "username" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        query.username = Some(value.to_string());
                    }
                }
                _ => {}
            }
        }
        if query.protocol.is_empty() || query.host.is_empty() {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Materialize,
                "git_credential_query",
                "git credential input must carry protocol= and host=",
            ));
        }
        Ok(query)
    }

    /// Host with any `:port` suffix removed, for comparison against the grant's
    /// repo host.
    pub fn host_without_port(&self) -> &str {
        self.host.split(':').next().unwrap_or(&self.host)
    }

    /// `path` reduced to `namespace/name`: leading slashes and a trailing
    /// `.git` removed. `None` when git sent no path.
    pub fn normalized_repo_path(&self) -> Option<String> {
        let path = self.path.as_deref()?.trim();
        let path = path.trim_start_matches('/').trim_end_matches('/');
        let path = path.strip_suffix(".git").unwrap_or(path);
        if path.is_empty() {
            return None;
        }
        Some(path.to_string())
    }
}

/// One credential-helper callback, as the container's helper POSTs it to the
/// gateway. This is the request half of the wire contract; see
/// `docs/cloudflare-git-credential-broker.md` for the JSON rendering.
///
/// The callback capability itself is **not** a field here: it travels in the
/// `Authorization` header, is checked by the Worker's bearer gate before this
/// body is ever parsed, and never enters the Rust authorization types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCredentialCallback {
    pub run_id: String,
    pub grant_id: String,
    pub operation: GitOperation,
    pub query: GitCredentialQuery,
}

/// An authorization to mint one repo-scoped token for one git operation.
///
/// Carries no key material. It tells the Worker *what* to mint and *for how
/// long*; the Worker performs the mint and streams the answer straight into the
/// helper response without it passing back through here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokeredCredentialLease {
    /// `sha256:` id of this specific authorization. Joins the helper response,
    /// the audit event, and the GitHub-side token in one row.
    pub operation_id: String,
    /// The literal git must send as the username ([`INSTALLATION_TOKEN_USERNAME`]).
    pub username: String,
    pub repo_id: String,
    pub operation: GitOperation,
    pub permissions: Vec<RepoPermission>,
    pub issued_at_unix: u64,
    /// `min(grant expiry, now + 1h)`. GitHub fixes the token's own expiry at
    /// one hour; the grant is what can make the usable window shorter, never
    /// longer.
    pub expires_at_unix: u64,
    /// Fingerprint of the grant's [`CredentialReference`](crate::coding_agent::CredentialReference),
    /// so audit rows say *which* credential without saying where it lives.
    pub credential_fingerprint: String,
    /// The mint the Worker must perform to satisfy this lease.
    pub token_request: InstallationTokenRequest,
}

impl BrokeredCredentialLease {
    pub fn ttl_secs(&self) -> u64 {
        self.expires_at_unix.saturating_sub(self.issued_at_unix)
    }
}

/// Outcome of authorizing one callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum BrokerDecision {
    Approve(Box<BrokeredCredentialLease>),
    /// Refused. The helper answers git with an empty credential block, so git
    /// fails the operation rather than prompting or retrying forever.
    Deny {
        code: String,
        detail: String,
    },
}

impl BrokerDecision {
    fn deny(code: &str, detail: impl Into<String>) -> Self {
        Self::Deny {
            code: code.to_string(),
            detail: detail.into(),
        }
    }

    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approve(_))
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Approve(_) => "approved",
            Self::Deny { code, .. } => code,
        }
    }

    pub fn lease(&self) -> Option<&BrokeredCredentialLease> {
        match self {
            Self::Approve(lease) => Some(lease),
            Self::Deny { .. } => None,
        }
    }
}

/// The GitHub App installation-token mint the Worker performs for an approved
/// lease: `POST /app/installations/{installation_id}/access_tokens`, scoped to
/// exactly one repository.
///
/// Repo scoping is structural. There is no constructor that takes more than one
/// repository name, so an over-broad token cannot be requested by an
/// implementation that was lazy about building the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationTokenRequest {
    /// GitHub API origin (`https://api.github.com`, or a GHES `/api/v3` base).
    pub api_base_url: String,
    /// The installation authorizing this run. **Not a secret** — an integer id
    /// that lives in the tenant row, which is what makes per-user authorization
    /// storable without a per-user secret.
    pub installation_id: u64,
    /// Single-element by construction; `repositories` (names) rather than
    /// `repository_ids` so the body is legible in an audit trail.
    repositories: Vec<String>,
    /// GitHub permission map, e.g. `{"contents": "read"}`.
    permissions: BTreeMap<String, String>,
}

impl InstallationTokenRequest {
    /// Build the mint for one repo under one scope. Permissions are *derived*
    /// from [`RepoCredentialScope`] rather than passed in, so a caller cannot
    /// widen them past what the grant justified.
    pub fn for_scope(
        api_base_url: impl Into<String>,
        installation_id: u64,
        repo: &RepoCoordinates,
        scope: &RepoCredentialScope,
    ) -> Result<Self, CodingAgentError> {
        let api_base_url = api_base_url.into().trim().trim_end_matches('/').to_string();
        if !api_base_url.starts_with("https://") {
            return Err(CodingAgentError::credential(
                "GitHub API base URL must be https",
            ));
        }
        if installation_id == 0 {
            return Err(CodingAgentError::credential(
                "installation id must be a real installation; 0 is not one",
            ));
        }
        if scope.repo_id() != repo.canonical_id() {
            return Err(CodingAgentError::credential(format!(
                "credential scope {} does not cover repo {}",
                scope.repo_id(),
                repo.canonical_id()
            )));
        }
        let mut permissions = BTreeMap::new();
        for permission in scope.permissions() {
            let (key, level) = match permission {
                RepoPermission::ContentsRead => ("contents", "read"),
                RepoPermission::ContentsWrite => ("contents", "write"),
                RepoPermission::PullRequestWrite => ("pull_requests", "write"),
            };
            // `write` must win over a `read` for the same key.
            let entry = permissions.entry(key.to_string()).or_insert("read");
            if level == "write" {
                *entry = "write";
            }
        }
        // `metadata: read` is implied by every other permission; stating it
        // keeps the minted token usable for the ref advertisement.
        permissions.entry("metadata".to_string()).or_insert("read");
        Ok(Self {
            api_base_url,
            installation_id,
            repositories: vec![repo.name.clone()],
            permissions: permissions
                .into_iter()
                .map(|(key, level)| (key, level.to_string()))
                .collect(),
        })
    }

    /// `POST` — the only method that mints a token.
    pub fn method(&self) -> &'static str {
        "POST"
    }

    pub fn url(&self) -> String {
        format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base_url, self.installation_id
        )
    }

    pub fn repositories(&self) -> &[String] {
        &self.repositories
    }

    pub fn permissions(&self) -> &BTreeMap<String, String> {
        &self.permissions
    }

    /// The JSON body, exactly as GitHub expects it.
    pub fn body_json(&self) -> serde_json::Value {
        serde_json::json!({
            "repositories": self.repositories,
            "permissions": self.permissions,
        })
    }

    /// The matching revocation: `DELETE {api_base}/installation/token`,
    /// authenticated *with the token being revoked*. Handed to
    /// [`RepoCredentialGrant`] as its [`RevocationPoint`] so phase 1's
    /// obligation names a real endpoint rather than an intention.
    pub fn revocation_point(&self) -> RevocationPoint {
        RevocationPoint {
            endpoint: format!("DELETE {}/installation/token", self.api_base_url),
        }
    }
}

/// A material-free audit row for one callback. Emitted on **both** the approve
/// and the deny path — a denied callback is the interesting one.
///
/// Every field is either an id, a fingerprint, or a timestamp. There is no
/// field a token could be written into, which is how "the credential never
/// reaches logs, run events, or #427 memory" is enforced here rather than
/// promised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCredentialAuditEvent {
    pub run_id: String,
    pub grant_id: String,
    pub repo_id: String,
    pub operation: GitOperation,
    /// [`BrokerDecision::code`] — `approved` or a [`broker_deny_codes`] value.
    pub decision_code: String,
    /// Present only on the approve path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub credential_fingerprint: String,
    /// 1-based position of this callback within the run's operation budget.
    pub sequence: u32,
    pub occurred_at_unix: u64,
}

/// What the container is configured with so `git` can call the broker.
///
/// Note what is in here and what is not: a URL, two ids, and an audience
/// string. The callback capability that authenticates the helper is delivered
/// separately by the isolation tier and is a *gateway* capability, not a GitHub
/// credential — presenting it to github.com achieves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerCallbackBinding {
    /// HTTPS endpoint the helper POSTs to.
    pub broker_url: String,
    pub run_id: String,
    pub grant_id: String,
    /// Audience the callback capability is minted for, so a capability lifted
    /// out of one run cannot be replayed against another gateway route.
    pub audience: String,
}

impl BrokerCallbackBinding {
    pub fn new(
        broker_url: impl Into<String>,
        run_id: impl Into<String>,
        grant_id: impl Into<String>,
    ) -> Result<Self, CodingAgentError> {
        let broker_url = broker_url.into().trim().trim_end_matches('/').to_string();
        if !broker_url.starts_with("https://") {
            return Err(CodingAgentError::credential(
                "credential broker URL must be https",
            ));
        }
        let run_id = run_id.into();
        let grant_id = grant_id.into();
        if run_id.trim().is_empty() || grant_id.trim().is_empty() {
            return Err(CodingAgentError::credential(
                "broker callback binding requires a run id and a grant id",
            ));
        }
        let audience = format!("ferrogate:git-credential:{run_id}");
        Ok(Self {
            broker_url,
            run_id,
            grant_id,
            audience,
        })
    }

    /// Project onto the #472 delivery variant, so the grant that phase 1
    /// validates and the binding the container is handed cannot drift.
    pub fn delivery(&self) -> CredentialDelivery {
        CredentialDelivery::BrokeredPerOperation {
            broker_url: self.broker_url.clone(),
        }
    }
}

/// git config lines the container image applies so `git` uses the broker and
/// refuses to weaken transport security.
///
/// `credential.useHttpPath=true` is **load-bearing, not tidiness**: without it
/// git sends only `protocol` and `host`, the broker cannot tell
/// `github.com/acme/app` from `github.com/attacker/exfil`, and repo scoping
/// collapses to host scoping. [`GitCredentialBroker::authorize`] denies a
/// pathless callback for exactly that reason.
pub fn git_helper_config_lines(helper_command: &str) -> Vec<String> {
    vec![
        // Only this helper answers; the empty value clears anything inherited
        // from a system/global config or a repo-supplied include.
        "credential.helper=".to_string(),
        format!("credential.helper={helper_command}"),
        "credential.useHttpPath=true".to_string(),
        // A repo cannot rewrite its own remote into somewhere else.
        "url.https://github.com/.insteadOf=".to_string(),
        // TLS verification stays on; the negative form is stated so a later
        // `git config --global http.sslVerify false` is a visible diff.
        "http.sslVerify=true".to_string(),
        // Submodule URLs from repo content are the classic redirect vector.
        "protocol.file.allow=never".to_string(),
        "protocol.ext.allow=never".to_string(),
    ]
}

/// Environment variables that disable transport verification. The bootstrap
/// path refuses to start an instance whose environment contains any of them.
pub const FORBIDDEN_TRANSPORT_ENV: [&str; 3] =
    ["GIT_SSL_NO_VERIFY", "GIT_SSH_VARIANT", "SSH_ASKPASS"];

/// GitHub's published SSH host keys, pinned.
///
/// Retrieved from GitHub's own `GET /meta` (`ssh_keys`) and cross-checked
/// against the published SHA256 fingerprints (`ssh_key_fingerprints`) on
/// 2026-07-25. Pinning means a GitHub key rotation — as in March 2023, when the
/// RSA key was replaced — requires editing this constant; that is the cost of
/// verification, and it is the correct cost. `StrictHostKeyChecking no` is the
/// alternative and it is not an alternative.
pub const GITHUB_SSH_HOST_KEYS: [(&str, &str, &str); 3] = [
    (
        "ssh-ed25519",
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
    ),
    (
        "ecdsa-sha2-nistp256",
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
        "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
    ),
    (
        "ssh-rsa",
        "AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
        "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
    ),
];

/// The `known_hosts` file body baked into the image for `host`, from
/// [`GITHUB_SSH_HOST_KEYS`]. Public key material — safe to ship in a layer, and
/// the reason no key exchange has to be trusted on first use.
pub fn github_known_hosts(host: &str) -> String {
    let mut body = String::new();
    for (algorithm, key, _) in GITHUB_SSH_HOST_KEYS {
        body.push_str(host);
        body.push(' ');
        body.push_str(algorithm);
        body.push(' ');
        body.push_str(key);
        body.push('\n');
    }
    body
}

/// Refuse an SSH configuration that turns host-key verification off.
///
/// Checks the effective option value, not the literal string, so
/// `StrictHostKeyChecking=no`, `stricthostkeychecking  NO` and the `off`
/// spelling are all caught. `accept-new` is refused too: it is trust-on-first-
/// use, and a container that starts fresh every run is *always* on its first
/// use, which makes `accept-new` indistinguishable from `no`.
pub fn validate_ssh_hardening(ssh_config: &str) -> Result<(), CodingAgentError> {
    for raw_line in ssh_config.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let normalized = line.replace('=', " ");
        let mut parts = normalized.split_whitespace();
        let Some(keyword) = parts.next() else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("StrictHostKeyChecking") {
            continue;
        }
        let value = parts.next().unwrap_or("").to_ascii_lowercase();
        if matches!(value.as_str(), "yes" | "ask") {
            continue;
        }
        return Err(CodingAgentError::credential(format!(
            "ssh config disables host-key verification ({raw_line:?}); host-key \
             verification stays on and GitHub's published keys are pinned in \
             known_hosts — see GITHUB_SSH_HOST_KEYS"
        )));
    }
    Ok(())
}

/// Refuse an instance environment that would weaken git's transport checks.
pub fn validate_transport_env<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), CodingAgentError> {
    for name in names {
        if FORBIDDEN_TRANSPORT_ENV
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(name))
        {
            return Err(CodingAgentError::credential(format!(
                "instance environment sets {name}, which disables or reroutes git \
                 transport verification"
            )));
        }
    }
    Ok(())
}

/// The gateway-side authorization engine for one run's credential callbacks.
///
/// Holds the grant, the repo it covers, and the mint parameters. Every callback
/// is authorized against all of them, counted against the run's budget, and
/// answered with a [`BrokerDecision`] plus a material-free
/// [`GitCredentialAuditEvent`].
#[derive(Debug, Clone)]
pub struct GitCredentialBroker {
    repo: RepoCoordinates,
    grant: RepoCredentialGrant,
    token_request: InstallationTokenRequest,
    operation_budget: u32,
    operations_used: u32,
}

impl GitCredentialBroker {
    /// Bind a broker to a grant. Refuses a grant that is not brokered — an
    /// [`CredentialDelivery::EphemeralFile`] grant has no callback to serve, and
    /// serving one anyway would hand out a second credential.
    pub fn bind(
        repo: RepoCoordinates,
        grant: RepoCredentialGrant,
        token_request: InstallationTokenRequest,
    ) -> Result<Self, CodingAgentError> {
        if !matches!(
            grant.delivery(),
            CredentialDelivery::BrokeredPerOperation { .. }
        ) {
            return Err(CodingAgentError::credential(format!(
                "grant {} uses {} delivery; the broker only serves \
                 brokered_per_operation grants",
                grant.grant_id(),
                grant.delivery().as_str()
            )));
        }
        if grant.scope().repo_id() != repo.canonical_id() {
            return Err(CodingAgentError::credential(format!(
                "grant {} is scoped to {} but the broker was bound to {}",
                grant.grant_id(),
                grant.scope().repo_id(),
                repo.canonical_id()
            )));
        }
        if token_request.repositories() != [repo.name.clone()] {
            return Err(CodingAgentError::credential(
                "installation token request must name exactly the bound repo",
            ));
        }
        Ok(Self {
            repo,
            grant,
            token_request,
            operation_budget: DEFAULT_BROKER_OPERATION_BUDGET,
            operations_used: 0,
        })
    }

    /// Tighten (never widen) the per-run operation budget.
    pub fn with_operation_budget(mut self, budget: u32) -> Self {
        self.operation_budget = budget.min(DEFAULT_BROKER_OPERATION_BUDGET);
        self
    }

    pub fn operations_used(&self) -> u32 {
        self.operations_used
    }

    pub fn operation_budget(&self) -> u32 {
        self.operation_budget
    }

    pub fn grant(&self) -> &RepoCredentialGrant {
        &self.grant
    }

    /// The revocation point this run's grant must be closed at.
    pub fn revocation_point(&self) -> RevocationPoint {
        self.token_request.revocation_point()
    }

    /// Authorize one callback.
    ///
    /// Returns the decision and the audit event to emit, always as a pair, so
    /// there is no path that authorizes without recording. Denials consume
    /// budget too — otherwise probing the broker is free.
    pub fn authorize(
        &mut self,
        callback: &GitCredentialCallback,
        now_unix: u64,
    ) -> (BrokerDecision, GitCredentialAuditEvent) {
        self.operations_used = self.operations_used.saturating_add(1);
        let sequence = self.operations_used;
        let decision = self.decide(callback, now_unix, sequence);
        let event = GitCredentialAuditEvent {
            run_id: self.grant.run_id().to_string(),
            grant_id: self.grant.grant_id().to_string(),
            repo_id: self.repo.canonical_id(),
            operation: callback.operation,
            decision_code: decision.code().to_string(),
            operation_id: decision.lease().map(|lease| lease.operation_id.clone()),
            credential_fingerprint: self.grant.credential_ref().fingerprint(),
            sequence,
            occurred_at_unix: now_unix,
        };
        (decision, event)
    }

    fn decide(
        &self,
        callback: &GitCredentialCallback,
        now_unix: u64,
        sequence: u32,
    ) -> BrokerDecision {
        use broker_deny_codes as codes;

        if sequence > self.operation_budget {
            return BrokerDecision::deny(
                codes::OPERATION_BUDGET_EXHAUSTED,
                format!(
                    "run {} has used its {} credential operations",
                    self.grant.run_id(),
                    self.operation_budget
                ),
            );
        }
        if callback.run_id != self.grant.run_id() {
            return BrokerDecision::deny(
                codes::RUN_MISMATCH,
                "callback names a different run than the grant",
            );
        }
        if callback.grant_id != self.grant.grant_id() {
            return BrokerDecision::deny(
                codes::GRANT_MISMATCH,
                "callback names a grant this broker does not hold",
            );
        }
        if self.grant.is_expired_at(now_unix) {
            return BrokerDecision::deny(
                codes::GRANT_EXPIRED,
                format!("grant expired at {}", self.grant.expires_at_unix()),
            );
        }
        if !matches!(
            self.grant.delivery(),
            CredentialDelivery::BrokeredPerOperation { .. }
        ) {
            return BrokerDecision::deny(
                codes::DELIVERY_NOT_BROKERED,
                "grant is not a brokered grant",
            );
        }
        if callback.query.protocol != "https" {
            return BrokerDecision::deny(
                codes::PROTOCOL_NOT_HTTPS,
                format!(
                    "protocol {:?} is not https; credentials are brokered over TLS only",
                    callback.query.protocol
                ),
            );
        }
        if callback.query.host_without_port() != self.repo.host {
            return BrokerDecision::deny(
                codes::HOST_NOT_GRANTED,
                format!(
                    "callback asked for host {:?} but the grant covers {:?}",
                    callback.query.host_without_port(),
                    self.repo.host
                ),
            );
        }
        let Some(path) = callback.query.normalized_repo_path() else {
            return BrokerDecision::deny(
                codes::PATH_MISSING,
                "callback carried no repository path; set credential.useHttpPath=true \
                 so the broker can scope the answer to one repo",
            );
        };
        let granted_path = format!("{}/{}", self.repo.namespace, self.repo.name);
        if !path.eq_ignore_ascii_case(&granted_path) {
            return BrokerDecision::deny(
                codes::REPO_NOT_GRANTED,
                format!("callback asked for {path:?} but the grant covers {granted_path:?}"),
            );
        }
        if callback.operation.is_write() && !self.grant.scope().is_write_capable() {
            return BrokerDecision::deny(
                codes::WRITE_NOT_GRANTED,
                "push requires a write-capable grant, which requires a write-back grant",
            );
        }

        let expires_at_unix = self
            .grant
            .expires_at_unix()
            .min(now_unix.saturating_add(GITHUB_INSTALLATION_TOKEN_TTL_SECS))
            .min(now_unix.saturating_add(MAX_REPO_CREDENTIAL_TTL_SECS));
        let operation_id = opaque_reference_fingerprint(&format!(
            "{}|{}|{}|{}|{}",
            self.grant.grant_id(),
            self.grant.run_id(),
            self.repo.canonical_id(),
            callback.operation.as_str(),
            sequence
        ));
        BrokerDecision::Approve(Box::new(BrokeredCredentialLease {
            operation_id,
            username: INSTALLATION_TOKEN_USERNAME.to_string(),
            repo_id: self.repo.canonical_id(),
            operation: callback.operation,
            permissions: self.grant.scope().permissions().to_vec(),
            issued_at_unix: now_unix,
            expires_at_unix,
            credential_fingerprint: self.grant.credential_ref().fingerprint(),
            token_request: self.token_request.clone(),
        }))
    }
}

#[cfg(test)]
#[path = "credential_broker_test.rs"]
mod tests;
