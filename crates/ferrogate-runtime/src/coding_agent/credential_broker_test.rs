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

/// Every record on the credential path is attributable to a tenant (#472 gap).
const TENANT: &str = "tenant-a";

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
        TENANT,
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
    GitCredentialBroker::bind(TENANT, repo(), grant(scope), request).expect("broker")
}

fn write_broker() -> GitCredentialBroker {
    let write_grant = write_back_grant(WriteBackOperation::PushBranch);
    let scope = RepoCredentialScope::with_write_back(&repo(), &write_grant).expect("scope");
    let request = token_request(&scope);
    GitCredentialBroker::bind(TENANT, repo(), grant(scope), request).expect("broker")
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
    let error = GitCredentialBroker::bind(TENANT, repo(), file_grant, token_request(&scope))
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
    let error =
        GitCredentialBroker::bind(TENANT, repo(), grant(scope), request).expect_err("must refuse");
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

/// TEST GATE (#475 box 4). `known_hosts_pins_all_three_published_github_keys`
/// above is tautological: it renders the body FROM `GITHUB_SSH_HOST_KEYS` and
/// then asserts the body contains `GITHUB_SSH_HOST_KEYS`. A key edited to an
/// attacker's would pass it, and the pinned `SHA256:` fingerprint — the only
/// field cross-checkable against GitHub's published `ssh_key_fingerprints` — was
/// never read by any test at all.
///
/// This derives the fingerprint from the key bytes the way OpenSSH does
/// (base64 of the SHA-256 of the wire-format blob, unpadded) and compares it to
/// the pinned one. Change any byte of any key and it goes red.
///
/// The three pinned fingerprints were checked against
/// <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>
/// on 2026-07-26 and matched.
#[test]
fn every_pinned_host_key_hashes_to_its_pinned_fingerprint() {
    use base64::{
        engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD},
        Engine as _,
    };

    assert_eq!(GITHUB_SSH_HOST_KEYS.len(), 3, "all three published keys");
    for (algorithm, key, fingerprint) in GITHUB_SSH_HOST_KEYS {
        let blob = B64.decode(key).expect("pinned key must be valid base64");
        // The blob is SSH wire format: a length-prefixed algorithm name first.
        let name_len = u32::from_be_bytes(blob[..4].try_into().expect("length prefix")) as usize;
        assert_eq!(
            &blob[4..4 + name_len],
            algorithm.as_bytes(),
            "{algorithm}: the key blob names a different algorithm"
        );
        let derived = format!("SHA256:{}", B64_NO_PAD.encode(Sha256::digest(&blob)));
        assert_eq!(
            derived, fingerprint,
            "{algorithm}: the pinned key does not hash to the pinned fingerprint"
        );
    }
}

/// TEST GATE (#475 box 4). "What happens if the pin file is missing or empty —
/// does it fail closed or fall through?" Executed rather than reasoned about:
/// there is no pin *file*. The pin is a compile-time constant, so the
/// missing-file state is unrepresentable, and `github_known_hosts` cannot render
/// an empty body for any host.
#[test]
fn the_host_key_pin_has_no_missing_or_empty_state() {
    for (algorithm, key, fingerprint) in GITHUB_SSH_HOST_KEYS {
        assert!(!algorithm.is_empty() && !key.is_empty());
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
    }
    let body = github_known_hosts("github.com");
    assert_eq!(body.lines().count(), 3);
    assert!(body.lines().all(|line| line.split(' ').count() == 3));
    // `prepare` renders it unconditionally: there is no argument that turns the
    // pin off, and no code path that hands back an environment without one.
    let prepared = ContainerGitEnvironment::prepare(
        callback_binding(),
        "/usr/local/bin/ferrogate-git-credential",
        "github.com",
        "",
        ["PATH"],
    )
    .expect("environment");
    assert_eq!(prepared.known_hosts, body);
}

/// TEST GATE (#475 box 4). An `ssh_config` that never mentions
/// `StrictHostKeyChecking` is ACCEPTED. That is the documented behaviour and it
/// is only safe for the two reasons pinned above and below: OpenSSH's default is
/// `ask` (which refuses an unknown key non-interactively), and `known_hosts` is
/// rendered unconditionally. Pinned so that "silence is accepted" is a decision
/// on the record rather than an accident, and so that a future default of
/// `accept-new` in the image would have to change this test.
#[test]
fn silence_about_host_key_checking_is_accepted_but_the_pin_is_still_rendered() {
    assert!(validate_ssh_hardening("").is_ok());
    assert!(validate_ssh_hardening("Host github.com\n  User git\n").is_ok());
    let prepared =
        ContainerGitEnvironment::prepare(callback_binding(), "/bin/helper", "github.com", "", [])
            .expect("environment");
    assert!(prepared.known_hosts.contains("ssh-ed25519"));
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

/// Regression guard for the "credential must never reach logs, run events, or
/// #427 memory" requirement on the Rust half: render every type on the approve
/// path through `Debug` and serde and assert no token-shaped material appears.
///
/// Read this for what it is. It cannot fail *today*, because none of these
/// types has a field a token could be written into — that is the property, and
/// the test is what makes adding such a field a red build rather than a review
/// catch. It proves nothing about the component that actually holds a token,
/// which is the Worker; the tests that cover that are in
/// `workers/agent-gateway/test/git-credential.test.ts`, where the audit surface
/// the control plane reads back is asserted to be material-free. The genuinely
/// falsifiable Rust twin is
/// `a_registration_carries_the_fingerprint_and_never_the_capability`, which
/// feeds a real secret in and asserts it does not come back out.
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
        TENANT,
        "run-1",
        "g-1",
    )
    .expect("binding");
    assert_eq!(binding.audience, "ferrogate:git-credential:tenant-a:run-1");
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
    assert!(
        BrokerCallbackBinding::new("http://gateway.example.com", TENANT, "run-1", "g-1").is_err()
    );
}

// ---- the run-scoped callback capability --------------------------------

/// The gateway stores a FINGERPRINT of the run's capability, never the
/// capability. Rust computes it here and TypeScript computes it in
/// `capabilityFingerprint`; if the two ever disagree no capability verifies, so
/// the expected value is pinned as a literal in BOTH suites (the TS twin is
/// `workers/agent-gateway/test/git-credential.test.ts`).
#[test]
fn capability_fingerprint_matches_the_worker_derivation() {
    let audience = broker_audience(TENANT, "run-1");
    assert_eq!(audience, "ferrogate:git-credential:tenant-a:run-1");
    assert_eq!(
        broker_capability_fingerprint(&audience, "0123456789abcdef0123456789abcdef"),
        "ee84134bacdd989b5ebaa6cabb4e28b5d73279590d78de0f63d94019ec443719"
    );
}

/// The audience is mixed in, so the SAME secret string fingerprints differently
/// for another tenant or another run. That is what stops a capability lifted
/// out of one container from authenticating another run.
#[test]
fn the_same_secret_is_a_different_capability_in_another_run() {
    let secret = "0123456789abcdef0123456789abcdef";
    let mine = broker_capability_fingerprint(&broker_audience(TENANT, "run-1"), secret);
    assert_ne!(
        mine,
        broker_capability_fingerprint(&broker_audience(TENANT, "run-2"), secret)
    );
    assert_ne!(
        mine,
        broker_capability_fingerprint(&broker_audience("tenant-b", "run-1"), secret)
    );
}

#[test]
fn a_registration_carries_the_fingerprint_and_never_the_capability() {
    let scope = RepoCredentialScope::read_only(&repo());
    let capability = "0123456789abcdef0123456789abcdef";
    let binding = BrokerCallbackBinding::new(
        "https://gateway.example.com/git-credential",
        TENANT,
        "run-1",
        "grant-1",
    )
    .expect("binding");
    let registration = BrokerGrantRegistration::build(
        &binding,
        &repo(),
        &grant(scope.clone()),
        &token_request(&scope),
        capability,
    )
    .expect("registration");

    assert_eq!(registration.grant.tenant_id, TENANT);
    assert_eq!(registration.grant.delivery, "brokered_per_operation");
    assert_eq!(registration.grant.installation_id, 4242);
    assert!(!registration.grant.write_capable);
    assert_eq!(
        registration.capability_fingerprint,
        binding.capability_fingerprint(capability)
    );
    // The whole point: the secret is not recoverable from what was registered.
    let rendered = format!(
        "{registration:?}{}",
        serde_json::to_string(&registration).expect("registration json")
    );
    assert!(!rendered.contains(capability));
    // camelCase, because this type IS the Worker's wire shape.
    let wire = serde_json::to_value(&registration).expect("wire");
    assert!(wire["capabilityFingerprint"].is_string());
    assert!(wire["grant"]["installationId"].is_number());
}

#[test]
fn a_registration_refuses_a_low_entropy_capability() {
    let scope = RepoCredentialScope::read_only(&repo());
    let binding = BrokerCallbackBinding::new(
        "https://gateway.example.com/git-credential",
        TENANT,
        "run-1",
        "grant-1",
    )
    .expect("binding");
    assert!(BrokerGrantRegistration::build(
        &binding,
        &repo(),
        &grant(scope.clone()),
        &token_request(&scope),
        "short",
    )
    .is_err());
}

#[test]
fn a_broker_must_be_bound_to_a_tenant() {
    let scope = RepoCredentialScope::read_only(&repo());
    let request = token_request(&scope);
    assert!(GitCredentialBroker::bind("  ", repo(), grant(scope), request).is_err());
}

#[test]
fn the_audit_event_and_the_lease_are_attributable_to_a_tenant() {
    let mut broker = read_only_broker();
    let (decision, event) = broker.authorize(&callback(GitOperation::Fetch, GRANTED_STDIN), NOW);
    assert_eq!(event.tenant_id, TENANT);
    assert_eq!(decision.lease().expect("lease").tenant_id, TENANT);
}

// ---- the container git environment -------------------------------------

fn callback_binding() -> BrokerCallbackBinding {
    BrokerCallbackBinding::new(
        "https://gateway.example.com/git-credential",
        TENANT,
        "run-1",
        "grant-1",
    )
    .expect("binding")
}

#[test]
fn the_container_git_environment_pins_host_keys_and_the_helper() {
    let prepared = ContainerGitEnvironment::prepare(
        callback_binding(),
        "/usr/local/bin/ferrogate-git-credential",
        "github.com",
        "Host *\n  StrictHostKeyChecking yes\n",
        ["PATH", "HOME"],
    )
    .expect("environment");
    assert_eq!(prepared.known_hosts_path, "/etc/ssh/ssh_known_hosts");
    assert_eq!(prepared.known_hosts.lines().count(), 3);
    assert!(prepared
        .git_config
        .iter()
        .any(|line| line == "credential.useHttpPath=true"));
    assert!(prepared
        .git_config
        .iter()
        .any(|line| line.contains("ferrogate-git-credential")));
}

/// The claim this replaces used to be "the bootstrap path refuses to start an
/// instance whose environment contains any of them" — with no bootstrap path.
/// There is one now, and these are the refusals it performs.
#[test]
fn the_container_git_environment_refuses_weakened_verification() {
    for env in [
        vec!["PATH", "GIT_SSL_NO_VERIFY"],
        vec!["SSH_ASKPASS"],
        vec!["git_ssh_variant"],
    ] {
        assert!(ContainerGitEnvironment::prepare(
            callback_binding(),
            "/usr/local/bin/helper",
            "github.com",
            "",
            env.clone(),
        )
        .is_err());
    }
    assert!(ContainerGitEnvironment::prepare(
        callback_binding(),
        "/usr/local/bin/helper",
        "github.com",
        "Host github.com\n  StrictHostKeyChecking accept-new\n",
        ["PATH"],
    )
    .is_err());
    assert!(ContainerGitEnvironment::prepare(
        callback_binding(),
        "   ",
        "github.com",
        "",
        ["PATH"],
    )
    .is_err());
}
