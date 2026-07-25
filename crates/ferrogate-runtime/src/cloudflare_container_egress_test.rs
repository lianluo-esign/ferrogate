// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Egress-posture tests (issue #471): prove direct public egress is
//   unrepresentable, that wildcards and provider endpoints cannot be allowlisted, that the
//   provider denylist rides every tethered start, and that an un/mis-attested posture is
//   refused.

use super::{
    host_matches_pattern, ContainerEgressPosture, EgressPostureAttestation, EgressPostureError,
    GovernedEgressAllowlist, PROVIDER_EGRESS_DENYLIST,
};
use crate::isolation::IsolationNetworkPolicy;

fn attestation(posture: &ContainerEgressPosture) -> EgressPostureAttestation {
    EgressPostureAttestation {
        direct_public_egress: false,
        posture: posture.wire_label().to_string(),
        allowed_hosts: posture.allowed_hosts().to_vec(),
        denied_hosts: posture
            .denied_hosts()
            .iter()
            .map(|h| (*h).to_string())
            .collect(),
    }
}

// ---- the posture cannot express open egress ---------------------------------

#[test]
fn every_posture_denies_direct_public_egress() {
    assert!(!ContainerEgressPosture::Sealed.direct_public_egress());
    let tethered = ContainerEgressPosture::tethered_to("gateway.ferrogate.internal").unwrap();
    assert!(!tethered.direct_public_egress());
}

#[test]
fn default_posture_is_sealed_with_no_allowlist() {
    let posture = ContainerEgressPosture::default();
    assert_eq!(posture.wire_label(), "sealed");
    assert!(posture.allowed_hosts().is_empty());
    // The sealed path stays free of the interception dependency: no denylist,
    // because nothing is reachable in the first place.
    assert!(posture.denied_hosts().is_empty());
}

// ---- allowlist validation ----------------------------------------------------

#[test]
fn wildcard_allowlist_entry_is_rejected() {
    for pattern in ["*", "*.example.com", "api.*.com"] {
        let err = GovernedEgressAllowlist::try_new([pattern]).unwrap_err();
        assert!(
            matches!(err, EgressPostureError::Wildcard(_)),
            "{pattern} -> {err:?}"
        );
    }
}

#[test]
fn provider_endpoints_cannot_be_allowlisted() {
    for host in [
        "api.anthropic.com",
        "API.OpenAI.com",
        "generativelanguage.googleapis.com",
        "bedrock-runtime.us-east-1.amazonaws.com",
        "acme.openai.azure.com",
        "openrouter.ai",
    ] {
        let err = GovernedEgressAllowlist::try_new([host]).unwrap_err();
        assert!(
            matches!(err, EgressPostureError::ProviderHost(_)),
            "{host} -> {err:?}"
        );
    }
}

#[test]
fn malformed_entries_are_rejected() {
    for host in [
        "https://gateway.example.com",
        "gateway.example.com/v1",
        "gateway.example.com:8443",
        "user@gateway.example.com",
        "gateway example.com",
        ".example.com",
        "example..com",
        "-bad.example.com",
        "",
    ] {
        let err = GovernedEgressAllowlist::try_new([host]).unwrap_err();
        assert!(
            matches!(
                err,
                EgressPostureError::MalformedHost(_) | EgressPostureError::EmptyAllowlist
            ),
            "{host} -> {err:?}"
        );
    }
}

#[test]
fn empty_tether_is_rejected_rather_than_silently_sealed() {
    let err = GovernedEgressAllowlist::try_new(Vec::<String>::new()).unwrap_err();
    assert_eq!(err, EgressPostureError::EmptyAllowlist);
}

#[test]
fn hosts_are_normalized_and_deduplicated() {
    let list = GovernedEgressAllowlist::try_new(["  GW.Example.COM ", "gw.example.com"]).unwrap();
    assert_eq!(list.hosts(), ["gw.example.com"]);
}

#[test]
fn tethered_posture_carries_the_provider_denylist() {
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    assert_eq!(posture.wire_label(), "gateway-tethered");
    assert_eq!(posture.allowed_hosts(), ["gw.example.com"]);
    assert_eq!(posture.denied_hosts(), PROVIDER_EGRESS_DENYLIST);
    assert!(posture.denied_hosts().contains(&"api.anthropic.com"));
}

// ---- policy derivation -------------------------------------------------------

#[test]
fn policy_requesting_direct_public_egress_fails_closed() {
    let policy = IsolationNetworkPolicy {
        direct_public_egress: true,
        gateway_control_channel: true,
        governed_egress: true,
    };
    let err =
        ContainerEgressPosture::from_network_policy(&policy, Some("gw.example.com")).unwrap_err();
    assert!(
        matches!(err, EgressPostureError::DirectPublicEgress(_)),
        "got {err:?}"
    );
}

#[test]
fn policy_without_governed_egress_fails_closed() {
    let policy = IsolationNetworkPolicy {
        direct_public_egress: false,
        gateway_control_channel: true,
        governed_egress: false,
    };
    let err = ContainerEgressPosture::from_network_policy(&policy, None).unwrap_err();
    assert!(
        matches!(err, EgressPostureError::DirectPublicEgress(_)),
        "got {err:?}"
    );
}

#[test]
fn default_policy_without_a_gateway_host_is_sealed() {
    let posture =
        ContainerEgressPosture::from_network_policy(&IsolationNetworkPolicy::default(), None)
            .unwrap();
    assert_eq!(posture, ContainerEgressPosture::Sealed);
    let posture = ContainerEgressPosture::from_network_policy(
        &IsolationNetworkPolicy::default(),
        Some("   "),
    )
    .unwrap();
    assert_eq!(posture, ContainerEgressPosture::Sealed);
}

#[test]
fn default_policy_with_a_gateway_host_tethers_to_it() {
    let posture = ContainerEgressPosture::from_network_policy(
        &IsolationNetworkPolicy::default(),
        Some("gw.example.com"),
    )
    .unwrap();
    assert_eq!(posture.allowed_hosts(), ["gw.example.com"]);
}

// ---- attestation -------------------------------------------------------------

#[test]
fn matching_attestation_verifies() {
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    attestation(&posture).verify(&posture).unwrap();
    let sealed = ContainerEgressPosture::Sealed;
    attestation(&sealed).verify(&sealed).unwrap();
}

#[test]
fn attested_direct_public_egress_is_refused() {
    let posture = ContainerEgressPosture::Sealed;
    let mut applied = attestation(&posture);
    applied.direct_public_egress = true;
    let err = applied.verify(&posture).unwrap_err();
    assert!(
        matches!(err, EgressPostureError::DirectPublicEgress(_)),
        "got {err:?}"
    );
}

#[test]
fn a_worker_that_dropped_the_allowlist_fails_the_start() {
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    let mut applied = attestation(&posture);
    applied.allowed_hosts.clear();
    let err = applied.verify(&posture).unwrap_err();
    assert!(
        matches!(err, EgressPostureError::AttestationMismatch(_)),
        "got {err:?}"
    );
}

#[test]
fn a_worker_that_widened_the_allowlist_fails_the_start() {
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    let mut applied = attestation(&posture);
    applied.allowed_hosts.push("api.anthropic.com".to_string());
    assert!(applied.verify(&posture).is_err());
}

#[test]
fn a_worker_that_dropped_the_provider_denylist_fails_the_start() {
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    let mut applied = attestation(&posture);
    applied.denied_hosts.clear();
    let err = applied.verify(&posture).unwrap_err();
    assert!(
        matches!(err, EgressPostureError::AttestationMismatch(_)),
        "got {err:?}"
    );
    // Dropping even ONE entry is a refusal.
    let mut applied = attestation(&posture);
    applied.denied_hosts.retain(|h| h != "api.anthropic.com");
    assert!(applied.verify(&posture).is_err());
}

#[test]
fn a_worker_that_denies_more_than_asked_is_accepted() {
    // A Worker carrying a newer/wider provider denylist is strictly safer, so a
    // superset must not fail the start.
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    let mut applied = attestation(&posture);
    applied
        .denied_hosts
        .push("api.some-new-provider.com".to_string());
    applied.verify(&posture).unwrap();
}

#[test]
fn a_worker_that_reported_a_different_posture_fails_the_start() {
    let posture = ContainerEgressPosture::tethered_to("gw.example.com").unwrap();
    let mut applied = attestation(&posture);
    applied.posture = "sealed".to_string();
    assert!(applied.verify(&posture).is_err());
}

// ---- glob matcher ------------------------------------------------------------

#[test]
fn glob_matcher_handles_prefix_infix_and_exact_patterns() {
    assert!(host_matches_pattern(
        "api.anthropic.com",
        "api.anthropic.com"
    ));
    assert!(!host_matches_pattern(
        "api.anthropic.com.evil.net",
        "api.anthropic.com"
    ));
    assert!(host_matches_pattern(
        "acme.openai.azure.com",
        "*.openai.azure.com"
    ));
    assert!(!host_matches_pattern(
        "openai.azure.com.evil.net",
        "*.openai.azure.com"
    ));
    assert!(host_matches_pattern(
        "bedrock-runtime.eu-west-1.amazonaws.com",
        "bedrock-runtime.*.amazonaws.com"
    ));
    assert!(!host_matches_pattern(
        "bedrock-runtime.amazonaws.com.evil.net",
        "bedrock-runtime.*.amazonaws.com"
    ));
    assert!(host_matches_pattern("anything", "*"));
}
