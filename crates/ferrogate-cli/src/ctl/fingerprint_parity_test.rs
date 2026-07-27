// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Cross-crate proof that the CLI's action fingerprint IS the runtime's
//! (issue #505, acceptance box 3).
//!
//! `ferrogate-cli-core` deliberately does not depend on `ferrogate-runtime`:
//! the runtime crate pulls in storage, TLS, `rcgen` and a tokio runtime, which
//! is the wrong weight for a client library that ships inside a CLI. So
//! `receipt::CliActionTarget` mirrors the runtime's
//! `CanonicalCapabilityTarget::Network` variant instead of reusing the type —
//! and a mirror is only as good as the test that pins it.
//!
//! This module is that pin. `ferrogate-cli` depends on **both** crates, so it
//! can construct the same logical target twice and assert byte equality of the
//! canonical JSON and of the `canonical_target_sha256` fingerprint. If anyone
//! renames a field, reorders the struct, adds a `skip_serializing_if`, or
//! changes the digest scheme on either side, this fails — which is the point:
//! the CLI's fingerprint must join to the runtime's action-identity space, not
//! merely look like it.

use ferrogate_cli_core::receipt::{
    is_canonical_action_fingerprint, CliActionTarget, ACTION_FINGERPRINT_CONTRACT,
};
use ferrogate_cli_core::transport::RequestSpec;
use ferrogate_runtime::{
    is_canonical_action_fingerprint as runtime_is_canonical, CanonicalCapabilityTarget,
    ACTION_FINGERPRINT_CONTRACT as RUNTIME_CONTRACT,
};
use http::Method;

/// The runtime target the CLI target is claimed to mirror, built by hand from
/// the same inputs.
fn runtime_target(
    scheme: &str,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
) -> CanonicalCapabilityTarget {
    CanonicalCapabilityTarget::Network {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
        method: Some(method.to_string()),
        path: path.to_string(),
        resolved_ips: Vec::new(),
        redirects: Vec::new(),
    }
}

/// The contract label the CLI carries on every receipt is the runtime's own
/// constant, not a lookalike string.
#[test]
fn contract_label_is_the_runtime_constant() {
    assert_eq!(ACTION_FINGERPRINT_CONTRACT, RUNTIME_CONTRACT);
    assert_eq!(ACTION_FINGERPRINT_CONTRACT, "canonical_target_sha256");
}

/// The CLI's canonical JSON and fingerprint are byte-identical to the
/// runtime's for the same target — across every method/scheme/port/path shape
/// a Control Plane API mutation can take.
#[test]
fn cli_action_fingerprint_byte_matches_canonical_capability_target() {
    let cases: &[(&str, Method, &str)] = &[
        (
            "https://control.example.com",
            Method::POST,
            "/admin/v1/guardrail-policies",
        ),
        (
            "https://control.example.com",
            Method::DELETE,
            "/admin/v1/guardrail-policies/gp_1/revisions/7",
        ),
        (
            "https://control.example.com:8443",
            Method::PUT,
            "/admin/v1/tenant-accounts/acme/plan",
        ),
        (
            "http://127.0.0.1:6188",
            Method::PATCH,
            "/admin/v1/wallets/org_acme",
        ),
        // An endpoint carrying a base path prefix: both sides must see the
        // joined path, not just the spec path.
        (
            "https://edge.example.com/gw",
            Method::POST,
            "/admin/v1/virtual-keys",
        ),
    ];

    for (endpoint, method, path) in cases {
        let spec = RequestSpec::new(method.clone(), *path)
            .with_json_body(serde_json::json!({"ignored": "by the target fingerprint"}));
        let cli = CliActionTarget::for_request(endpoint, &spec).expect("CLI target");

        // Rebuild the expected runtime target from the same URL the CLI saw.
        let url = reqwest::Url::parse(&format!("{}{}", endpoint.trim_end_matches('/'), path))
            .expect("endpoint URL parses");
        let runtime = runtime_target(
            url.scheme(),
            url.host_str().expect("host"),
            url.port_or_known_default().expect("port"),
            method.as_str(),
            url.path(),
        );

        assert_eq!(
            cli.canonical_json(),
            runtime.canonical_json(),
            "canonical JSON drifted for {method} {endpoint}{path}"
        );
        assert_eq!(
            cli.fingerprint(),
            runtime.fingerprint(),
            "action fingerprint drifted for {method} {endpoint}{path}"
        );
        // Both crates' syntactic validators accept the other's output.
        assert!(is_canonical_action_fingerprint(&runtime.fingerprint()));
        assert!(runtime_is_canonical(&cli.fingerprint()));
    }
}

/// A query string is part of the addressed object, so it participates in the
/// fingerprint on the CLI side — and the runtime agrees when handed the same
/// path string. This pins the one place the CLI mirror makes a *choice* the
/// runtime type does not make for it.
#[test]
fn query_parameters_participate_and_still_match_the_runtime() {
    let spec = RequestSpec::new(Method::DELETE, "/admin/v1/quota-policies/tenant/acme")
        .with_query("scope", "tenant");
    let cli = CliActionTarget::for_request("https://control.example.com", &spec).expect("target");
    let runtime = runtime_target(
        "https",
        "control.example.com",
        443,
        "DELETE",
        "/admin/v1/quota-policies/tenant/acme?scope=tenant",
    );
    assert_eq!(cli.canonical_json(), runtime.canonical_json());
    assert_eq!(cli.fingerprint(), runtime.fingerprint());

    // …and it is genuinely load-bearing: dropping the query changes the
    // fingerprint, so the receipt cannot attribute two different targets to
    // the same action identity.
    let bare = CliActionTarget::for_request(
        "https://control.example.com",
        &RequestSpec::new(Method::DELETE, "/admin/v1/quota-policies/tenant/acme"),
    )
    .expect("target");
    assert_ne!(cli.fingerprint(), bare.fingerprint());
}
