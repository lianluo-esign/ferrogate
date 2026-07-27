// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the Cloudflare Worker branch of the function egress broker
//! (#435), mirroring the Supabase route tests in `function_egress_test.rs`:
//! config gating (deny paths included), the fail-closed prepare pipeline, and
//! a TLS round-trip through the shared egress executor.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use ferrogate_runtime::DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS;

use super::*;

const WORKER_BASE_URL: &str = "https://tool-runner.acme.workers.dev";

fn worker_json_for(base_url: &str) -> String {
    format!(
        r#"{{"base_url":"{base_url}","invoke_path":"charge-credits","auth_key_ref":"secret:worker-bearer"}}"#
    )
}

fn allowlist_json_for(base_url: &str) -> String {
    format!(r#"[{{"tenant":"org_a","base_url":"{base_url}","function_slugs":["charge-credits"]}}]"#)
}

fn cf_broker_config_for(base_url: &str) -> CloudflareFunctionEgressGatewayConfig {
    CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".to_string()),
        Some("signing-secret".to_string()),
        Some(worker_json_for(base_url)),
        Some(allowlist_json_for(base_url)),
    )
    .expect("cloudflare branch enabled when kind, secret, and worker are configured")
}

fn cf_broker_config() -> CloudflareFunctionEgressGatewayConfig {
    cf_broker_config_for(WORKER_BASE_URL)
}

fn worker_request_for(base_url: &str, invoke_path: &str) -> WorkerInvocationRequest {
    WorkerInvocationRequest {
        tenant: "ignored-by-server".to_string(),
        target: CloudflareWorkerTarget {
            base_url: base_url.to_string(),
            invoke_path: invoke_path.to_string(),
            auth_key_ref: "secret:wire-supplied".to_string(),
        },
        method: "POST".to_string(),
        body_json: r#"{"amount":5}"#.to_string(),
    }
}

fn worker_request(invoke_path: &str) -> WorkerInvocationRequest {
    worker_request_for(WORKER_BASE_URL, invoke_path)
}

#[test]
fn target_kind_discriminant_parses_fail_closed() {
    // Absent/blank/supabase → the pre-#435 Supabase default.
    assert_eq!(
        parse_function_target_kind(None),
        Some(FunctionTargetKind::Supabase)
    );
    assert_eq!(
        parse_function_target_kind(Some("  ")),
        Some(FunctionTargetKind::Supabase)
    );
    assert_eq!(
        parse_function_target_kind(Some("supabase")),
        Some(FunctionTargetKind::Supabase)
    );
    assert_eq!(
        parse_function_target_kind(Some("cloudflare_worker")),
        Some(FunctionTargetKind::CloudflareWorker)
    );
    // Unknown kinds disable BOTH branches instead of silently defaulting.
    assert_eq!(parse_function_target_kind(Some("azure_function")), None);
}

#[test]
fn cf_branch_disabled_unless_kind_secret_and_worker_are_all_configured() {
    // Kind unset or Supabase → the Cloudflare branch never activates.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        None,
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        None,
    )
    .is_none());
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("supabase".into()),
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        None,
    )
    .is_none());
    // Unknown kind → disabled (fail-closed).
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("azure_function".into()),
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        None,
    )
    .is_none());
    // No signing secret → disabled.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        None,
        Some(worker_json_for(WORKER_BASE_URL)),
        None,
    )
    .is_none());
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("   ".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        None,
    )
    .is_none());
    // No declared worker target → disabled.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        None,
        None,
    )
    .is_none());
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some("   ".into()),
        None,
    )
    .is_none());
    // All present → enabled (allowlist optional: deny-by-default when empty).
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        None,
    )
    .is_some());
}

#[test]
fn cf_branch_disabled_when_worker_target_is_invalid() {
    // Malformed JSON.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(r#"{"base_url":"#.into()),
        None,
    )
    .is_none());
    // Plaintext http base URL.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(worker_json_for("http://tool-runner.acme.workers.dev")),
        None,
    )
    .is_none());
    // Traversal in the invoke path.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(
            r#"{"base_url":"https://tool-runner.acme.workers.dev","invoke_path":"../secrets","auth_key_ref":"secret:worker-bearer"}"#
                .into()
        ),
        None,
    )
    .is_none());
    // Empty secret-ref credential.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(
            r#"{"base_url":"https://tool-runner.acme.workers.dev","invoke_path":"charge-credits","auth_key_ref":""}"#
                .into()
        ),
        None,
    )
    .is_none());
}

#[test]
fn cf_branch_disabled_when_allowlist_json_is_malformed() {
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        Some(r#"{"tenant":"org_a""#.into()),
    )
    .is_none());
}

#[test]
fn cf_branch_disabled_when_allowlist_points_at_another_base_url() {
    // A rule targeting a different Worker than the declared one can never be
    // served coherently by the single declared target — fail closed, mirroring
    // the Supabase single-project rule (TOK-6).
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        Some(allowlist_json_for("https://other-worker.acme.workers.dev")),
    )
    .is_none());

    // The declared base with a trailing slash is still the same Worker after
    // normalization → the branch stays enabled.
    assert!(CloudflareFunctionEgressGatewayConfig::from_values(
        Some("cloudflare_worker".into()),
        Some("secret".into()),
        Some(worker_json_for(WORKER_BASE_URL)),
        Some(allowlist_json_for("https://tool-runner.acme.workers.dev/")),
    )
    .is_some());
}

#[test]
fn prepare_builds_request_with_scoped_bearer_and_no_apikey() {
    let config = cf_broker_config();
    let (request, invoke_path, timeout_millis) =
        prepare_cloudflare_invocation(&config, "org_a", &worker_request("charge-credits"), 1_000)
            .unwrap();
    assert_eq!(invoke_path, "charge-credits");
    assert_eq!(timeout_millis, DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS);
    assert_eq!(
        request.url,
        "https://tool-runner.acme.workers.dev/charge-credits"
    );
    let auth = request.headers.get("authorization").unwrap();
    assert!(auth.starts_with("Bearer "));
    // Bearer is a minted JWT (three dot-separated segments), not a raw key.
    assert_eq!(auth.trim_start_matches("Bearer ").split('.').count(), 3);
    // Workers have no Supabase apikey concept; the header must not be emitted.
    assert!(!request.headers.contains_key("apikey"));
    assert_eq!(request.body, r#"{"amount":5}"#);
}

#[test]
fn prepare_uses_configured_secret_ref_never_the_wire_one() {
    // The wire target's auth_key_ref is untrusted and replaced with the
    // operator-declared FG_FN_CF_WORKER secret-ref: even an empty wire ref
    // (which the runtime would otherwise reject fail-closed) prepares fine.
    let config = cf_broker_config();
    let mut request = worker_request("charge-credits");
    request.target.auth_key_ref = String::new();
    assert!(prepare_cloudflare_invocation(&config, "org_a", &request, 1).is_ok());
}

#[test]
fn prepare_denies_non_allowlisted_tenant_path_or_base_url() {
    let config = cf_broker_config();
    // Unknown tenant → denied.
    assert!(matches!(
        prepare_cloudflare_invocation(&config, "org_ghost", &worker_request("charge-credits"), 1),
        Err(WorkerBrokerError::Denied(_))
    ));
    // Non-allowlisted invoke path → denied.
    assert!(matches!(
        prepare_cloudflare_invocation(&config, "org_a", &worker_request("delete-all"), 1),
        Err(WorkerBrokerError::Denied(_))
    ));
    // A base_url other than the declared Worker → denied.
    assert!(matches!(
        prepare_cloudflare_invocation(
            &config,
            "org_a",
            &worker_request_for("https://other-worker.acme.workers.dev", "charge-credits"),
            1
        ),
        Err(WorkerBrokerError::Denied(_))
    ));
}

// --- TLS round-trip through the shared egress executor -----------------------

fn test_tls_config() -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap(),
    )
}

#[tokio::test]
async fn prepared_worker_invocation_executes_over_tls_with_bearer_only() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let tls = test_tls_config();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let connection = rustls::ServerConnection::new(tls).unwrap();
        let mut stream: rustls::StreamOwned<rustls::ServerConnection, TcpStream> =
            rustls::StreamOwned::new(connection, stream);
        let mut buffer = [0_u8; 2048];
        let read = stream.read(&mut buffer).unwrap();
        let received = String::from_utf8_lossy(&buffer[..read]).to_string();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"charged\":true}",
            )
            .unwrap();
        received
    });

    let config = cf_broker_config_for(&base_url);
    let (request, invoke_path, _) = prepare_cloudflare_invocation(
        &config,
        "org_a",
        &worker_request_for(&base_url, "charge-credits"),
        1_000,
    )
    .unwrap();
    let outcome = super::super::function_egress::execute_edge_function_request(
        &request,
        &invoke_path,
        Duration::from_secs(2),
        64 * 1024,
    )
    .await
    .unwrap();

    assert_eq!(outcome.status_code, 200);
    assert_eq!(outcome.function_slug, "charge-credits");
    assert_eq!(outcome.body_excerpt, r#"{"charged":true}"#);

    // The gateway forwarded the request line, the scoped bearer, the body —
    // and no Supabase apikey header (Workers have no apikey concept).
    let received = handle.join().unwrap();
    assert!(received.contains("POST /charge-credits"));
    assert!(received.to_lowercase().contains("authorization: bearer "));
    assert!(!received.to_lowercase().contains("apikey"));
    assert!(received.contains(r#"{"amount":5}"#));
}
