// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, tests for the brokered per-operation
//   git credential path (issue #475).

use std::collections::BTreeSet;

use super::*;

use crate::coding_agent::materialize::{CredentialReference, RepoCredentialScope};
use crate::coding_agent::write_back::{WriteBackGrant, WriteBackOperation};
use crate::ActingPrincipal;

const NOW: u64 = 1_800_000_000;

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        subject: "api-key-1".to_string(),
        tenant_id: "tenant-a".to_string(),
        worker_id: None,
        delegated_user: Some("alice".to_string()),
    }
}

fn write_back_grant(operation: WriteBackOperation) -> WriteBackGrant {
    WriteBackGrant::issue(
        "wb-1",
        "run-1",
        &repo(),
        BTreeSet::from([operation]),
        "ferrogate/run-",
        principal(),
        NOW,
        NOW + 900,
    )
    .expect("write-back grant")
}

fn repo() -> RepoCoordinates {
    RepoCoordinates::new("github", "github.com", "acme", "app").expect("repo")
}

fn credential_ref() -> CredentialReference {
    CredentialReference::parse("cf://ferrogate/github-app-key").expect("reference")
}

fn token_request(scope: &RepoCredentialScope) -> InstallationTokenRequest {
    InstallationTokenRequest::for_scope("https://api.github.com", 4242, &repo(), scope)
        .expect("token request")
}

fn grant(scope: RepoCredentialScope) -> RepoCredentialGrant {
    let binding = BrokerCallbackBinding::new(
        "https://gateway.example.com/git-credential",
        "run-1",
        "grant-1",
    )
    .expect("binding");
    RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope,
        credential_ref(),
        NOW,
        NOW + 900,
        binding.delivery(),
        token_request(&RepoCredentialScope::read_only(&repo())).revocation_point(),
    )
    .expect("grant")
}

fn read_only_broker() -> GitCredentialBroker {
    let scope = RepoCredentialScope::read_only(&repo());
    let request = token_request(&scope);
    GitCredentialBroker::bind(repo(), grant(scope), request).expect("broker")
}

fn write_broker() -> GitCredentialBroker {
    let write_grant = write_back_grant(WriteBackOperation::PushBranch);
    let scope = RepoCredentialScope::with_write_back(&repo(), &write_grant).expect("scope");
    let request = token_request(&scope);
    GitCredentialBroker::bind(repo(), grant(scope), request).expect("broker")
}

fn callback(operation: GitOperation, stdin: &str) -> GitCredentialCallback {
    GitCredentialCallback {
        run_id: "run-1".into(),
        grant_id: "grant-1".into(),
        operation,
        query: GitCredentialQuery::parse(stdin).expect("query"),
    }
}

const GRANTED_STDIN: &str = "protocol=https\nhost=github.com\npath=acme/app.git\n\n";

// ---- git credential wire parsing ---------------------------------------

#[test]
fn parses_git_credential_stdin_block() {
    let query = GitCredentialQuery::parse(
        "protocol=https\nhost=github.com:443\npath=acme/app.git\nusername=x-access-token\n\n",
    )
    .expect("query");
    assert_eq!(query.protocol, "https");
    assert_eq!(query.host_without_port(), "github.com");
    assert_eq!(query.normalized_repo_path().as_deref(), Some("acme/app"));
    assert_eq!(query.username.as_deref(), Some("x-access-token"));
}

/// git sends `password=` on `store`/`erase`. The query type has no field for
/// it, so a credential cannot ride back into the control plane on the request
/// path even if a helper forwards the whole block verbatim.
#[test]
fn parsed_query_cannot_carry_a_password() {
    let query = GitCredentialQuery::parse(
        "protocol=https\nhost=github.com\npath=acme/app\npassword=ghs_supersecret\n",
    )
    .expect("query");
    let rendered = format!("{query:?}");
    assert!(!rendered.contains("ghs_supersecret"), "{rendered}");
    let json = serde_json::to_string(&query).expect("json");
    assert!(!json.contains("ghs_supersecret"), "{json}");
}

#[test]
fn parse_requires_protocol_and_host() {
    assert!(GitCredentialQuery::parse("path=acme/app\n").is_err());
}

// ---- the happy path -----------------------------------------------------

#[test]
fn approves_a_fetch_for_the_granted_repo() {
    let mut broker = read_only_broker();
    let (decision, event) = broker.authorize(&callback(GitOperation::Fetch, GRANTED_STDIN), NOW);
    let lease = decision.lease().expect("approved");
    assert_eq!(lease.username, INSTALLATION_TOKEN_USERNAME);
    assert_eq!(lease.repo_id, "github:github.com/acme/app");
    assert_eq!(lease.permissions, vec![RepoPermission::ContentsRead]);
    assert!(lease.operation_id.starts_with("sha256:"));
    assert_eq!(event.decision_code, "approved");
    assert_eq!(event.sequence, 1);
}

/// The lease can never outlive the grant, even though GitHub always stamps an
/// installation token with a full hour.
#[test]
fn lease_expiry_is_clamped_to_the_grant_not_githubs_hour() {
    let mut broker = read_only_broker();
    let (decision, _) = broker.authorize(&callback(GitOperation::Fetch, GRANTED_STDIN), NOW);
    let lease = decision.lease().expect("approved");
    assert_eq!(lease.expires_at_unix, NOW + 900);
    assert!(lease.ttl_secs() < GITHUB_INSTALLATION_TOKEN_TTL_SECS);
}

// ---- scoping denials ----------------------------------------------------

/// A hostile submodule / `insteadOf` rewrite pointing at another host must not
/// be answered. This is the attack the helper exists to survive.
#[test]
fn denies_a_host_the_grant_does_not_cover() {
    let mut broker = read_only_broker();
    let stdin = "protocol=https\nhost=evil.example.com\npath=acme/app\n";
    let (decision, event) = broker.authorize(&callback(GitOperation::Fetch, stdin), NOW);
    assert_eq!(decision.code(), broker_deny_codes::HOST_NOT_GRANTED);
    assert_eq!(event.decision_code, broker_deny_codes::HOST_NOT_GRANTED);
    assert!(decision.lease().is_none());
}

#[test]
fn denies_another_repo_on_the_granted_host() {
    let mut broker = read_only_broker();
    let stdin = "protocol=https\nhost=github.com\npath=attacker/exfil.git\n";
    let (decision, _) = broker.authorize(&callback(GitOperation::Fetch, stdin), NOW);
    assert_eq!(decision.code(), broker_deny_codes::REPO_NOT_GRANTED);
}

/// Without `credential.useHttpPath=true` git sends no path, and repo scoping
/// would silently degrade to host scoping. Fail closed instead.
#[test]
fn denies_a_pathless_callback() {
    let mut broker = read_only_broker();
    let (decision, _) = broker.authorize(
        &callback(GitOperation::Fetch, "protocol=https\nhost=github.com\n"),
        NOW,
    );
    assert_eq!(decision.code(), broker_deny_codes::PATH_MISSING);
}

#[test]
fn denies_plaintext_http() {
    let mut broker = read_only_broker();
    let stdin = "protocol=http\nhost=github.com\npath=acme/app\n";
    let (decision, _) = broker.authorize(&callback(GitOperation::Fetch, stdin), NOW);
    assert_eq!(decision.code(), broker_deny_codes::PROTOCOL_NOT_HTTPS);
}

#[test]
fn denies_push_under_a_read_only_grant() {
    let mut broker = read_only_broker();
    let (decision, _) = broker.authorize(&callback(GitOperation::Push, GRANTED_STDIN), NOW);
    assert_eq!(decision.code(), broker_deny_codes::WRITE_NOT_GRANTED);
}

#[test]
fn allows_push_under_a_write_back_backed_grant() {
    let mut broker = write_broker();
    let (decision, _) = broker.authorize(&callback(GitOperation::Push, GRANTED_STDIN), NOW);
    let lease = decision.lease().expect("approved");
    assert!(lease.permissions.contains(&RepoPermission::ContentsWrite));
}

#[test]
fn denies_a_callback_for_another_run() {
    let mut broker = read_only_broker();
    let mut call = callback(GitOperation::Fetch, GRANTED_STDIN);
    call.run_id = "run-2".into();
    let (decision, _) = broker.authorize(&call, NOW);
    assert_eq!(decision.code(), broker_deny_codes::RUN_MISMATCH);
}

#[test]
fn denies_after_the_grant_expires() {
    let mut broker = read_only_broker();
    let (decision, _) = broker.authorize(&callback(GitOperation::Fetch, GRANTED_STDIN), NOW + 901);
    assert_eq!(decision.code(), broker_deny_codes::GRANT_EXPIRED);
}

/// Denials consume budget too — otherwise probing the broker is free.
#[test]
fn exhausts_the_per_run_operation_budget() {
    let mut broker = read_only_broker().with_operation_budget(2);
    for _ in 0..2 {
        let (decision, _) = broker.authorize(&callback(GitOperation::Fetch, GRANTED_STDIN), NOW);
        assert!(decision.is_approved());
    }
    let (decision, _) = broker.authorize(&callback(GitOperation::Fetch, GRANTED_STDIN), NOW);
    assert_eq!(
        decision.code(),
        broker_deny_codes::OPERATION_BUDGET_EXHAUSTED
    );
}

#[test]
fn budget_cannot_be_widened_past_the_default() {
    let broker = read_only_broker().with_operation_budget(u32::MAX);
    assert_eq!(broker.operation_budget(), DEFAULT_BROKER_OPERATION_BUDGET);
}

// ---- binding refusals ---------------------------------------------------

#[test]
fn refuses_to_broker_a_file_delivered_grant() {
    let scope = RepoCredentialScope::read_only(&repo());
    let file_grant = RepoCredentialGrant::issue(
        "grant-1",
        "run-1",
        scope.clone(),
        credential_ref(),
        NOW,
        NOW + 900,
        CredentialDelivery::EphemeralFile {
            path: "/run/ferrogate/cred".into(),
            mode: 0o600,
        },
        token_request(&scope).revocation_point(),
    )
    .expect("grant");
    let error = GitCredentialBroker::bind(repo(), file_grant, token_request(&scope))
        .expect_err("must refuse");
    assert!(format!("{error}").contains("brokered_per_operation"));
}

#[test]
fn refuses_a_grant_scoped_to_another_repo() {
    let other = RepoCoordinates::new("github", "github.com", "acme", "other").expect("repo");
    let scope = RepoCredentialScope::read_only(&other);
    let request =
        InstallationTokenRequest::for_scope("https://api.github.com", 4242, &other, &scope)
            .expect("token request");
    let error = GitCredentialBroker::bind(repo(), grant(scope), request).expect_err("must refuse");
    assert!(format!("{error}").contains("scoped to"));
}

// ---- installation token issuance ---------------------------------------

#[test]
fn token_request_is_single_repo_and_scope_derived() {
    let scope = RepoCredentialScope::read_only(&repo());
    let request = token_request(&scope);
    assert_eq!(request.method(), "POST");
    assert_eq!(
        request.url(),
        "https://api.github.com/app/installations/4242/access_tokens"
    );
    assert_eq!(request.repositories(), ["app"]);
    assert_eq!(request.permissions()["contents"], "read");
    assert_eq!(request.permissions()["metadata"], "read");
    assert!(!request.permissions().contains_key("pull_requests"));
}

#[test]
fn write_scope_upgrades_contents_and_adds_pull_requests() {
    let write_grant = write_back_grant(WriteBackOperation::OpenPullRequest);
    let scope = RepoCredentialScope::with_write_back(&repo(), &write_grant).expect("scope");
    let request = token_request(&scope);
    assert_eq!(request.permissions()["contents"], "write");
    assert_eq!(request.permissions()["pull_requests"], "write");
}

#[test]
fn token_request_refuses_plaintext_api_base() {
    let scope = RepoCredentialScope::read_only(&repo());
    assert!(
        InstallationTokenRequest::for_scope("http://api.github.com", 4242, &repo(), &scope)
            .is_err()
    );
}

#[test]
fn revocation_point_names_the_github_revoke_endpoint() {
    let scope = RepoCredentialScope::read_only(&repo());
    assert_eq!(
        token_request(&scope).revocation_point().endpoint,
        "DELETE https://api.github.com/installation/token"
    );
}

// ---- transport hardening ------------------------------------------------

#[test]
fn known_hosts_pins_all_three_published_github_keys() {
    let body = github_known_hosts("github.com");
    assert_eq!(body.lines().count(), 3);
    for (algorithm, key, _) in GITHUB_SSH_HOST_KEYS {
        assert!(
            body.contains(&format!("github.com {algorithm} {key}")),
            "{algorithm}"
        );
    }
}

#[test]
fn ssh_hardening_refuses_every_spelling_of_disabled_host_key_checking() {
    for config in [
        "StrictHostKeyChecking no",
        "  stricthostkeychecking=NO",
        "StrictHostKeyChecking off",
        "StrictHostKeyChecking accept-new",
    ] {
        assert!(
            validate_ssh_hardening(config).is_err(),
            "must refuse {config:?}"
        );
    }
}

#[test]
fn ssh_hardening_accepts_verification_on() {
    assert!(validate_ssh_hardening("Host github.com\n  StrictHostKeyChecking yes\n").is_ok());
    assert!(validate_ssh_hardening("# StrictHostKeyChecking no\n").is_ok());
}

#[test]
fn transport_env_refuses_verification_disabling_variables() {
    assert!(validate_transport_env(["PATH", "HOME"]).is_ok());
    assert!(validate_transport_env(["GIT_SSL_NO_VERIFY"]).is_err());
    assert!(validate_transport_env(["git_ssl_no_verify"]).is_err());
}

#[test]
fn helper_config_forces_the_repo_path_onto_every_callback() {
    let lines = git_helper_config_lines("/usr/local/bin/ferrogate-git-credential");
    assert!(lines.contains(&"credential.useHttpPath=true".to_string()));
    assert!(lines.contains(&"http.sslVerify=true".to_string()));
    // The empty first entry clears inherited helpers.
    assert_eq!(lines[0], "credential.helper=");
    assert!(!lines.iter().any(|line| line.contains("sslVerify=false")));
}

// ---- nothing here can carry key material -------------------------------

/// Structural proof for the "credential must never reach logs, run events, or
/// #427 memory" requirement: render every type on the approve path through both
/// `Debug` and serde and assert no token-shaped material can appear, because
/// none of them has a field to hold one.
#[test]
fn no_broker_type_can_render_key_material() {
    let mut broker = write_broker();
    let call = callback(GitOperation::Push, GRANTED_STDIN);
    let (decision, event) = broker.authorize(&call, NOW);
    let rendered = format!(
        "{:?}{:?}{:?}{}{}",
        broker,
        decision,
        event,
        serde_json::to_string(&decision).expect("decision json"),
        serde_json::to_string(&event).expect("event json"),
    );
    for material in ["ghs_", "ghp_", "github_pat_", "BEGIN RSA", "PRIVATE KEY"] {
        assert!(
            !rendered.contains(material),
            "broker rendering leaked {material}"
        );
    }
    // What *is* recorded: opaque fingerprints and ids.
    assert!(event.credential_fingerprint.starts_with("sha256:"));
    assert!(
        rendered.contains("cf://"),
        "reference URI is safe to record"
    );
}

#[test]
fn callback_binding_projects_onto_the_contract_delivery() {
    let binding = BrokerCallbackBinding::new(
        "https://gateway.example.com/git-credential/",
        "run-1",
        "g-1",
    )
    .expect("binding");
    assert_eq!(binding.audience, "ferrogate:git-credential:run-1");
    assert_eq!(
        binding.delivery(),
        CredentialDelivery::BrokeredPerOperation {
            broker_url: "https://gateway.example.com/git-credential".into()
        }
    );
    assert!(!binding.delivery().readable_in_instance());
}

#[test]
fn callback_binding_refuses_plaintext_broker_url() {
    assert!(BrokerCallbackBinding::new("http://gateway.example.com", "run-1", "g-1").is_err());
}
