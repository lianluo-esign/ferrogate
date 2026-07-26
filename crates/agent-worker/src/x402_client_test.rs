// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the non-custodial x402 client + spend-authorization handoff
//! (#353): the client parses a valid `402` challenge through the frozen wire
//! contract, builds the authorization-request evidence, fails closed on a
//! local-signing/custody request, and honors a policy deny without ever
//! proceeding. A proptest pins the core invariant: a handoff is produced only
//! for an `Allow` bound to the challenge with an external signer.

use super::*;

use ferrogate_payments::{RequirementFilter, SvmTransferIntent, SvmTransferSigner};
use ferrogate_policy::{
    authorize_x402_payment, AllowedAsset, ApprovalPolicy, ConversionRule, PaymentAuthorization,
    PaymentDecision, PolicyNetwork, ResourceRule, Rounding, SpendScope, SpendSnapshot,
    ValidatedX402SpendPolicy, X402SpendCaps, X402SpendPolicy, REASON_DISABLED,
};
use proptest::prelude::*;

// The checked-in golden devnet `PAYMENT-REQUIRED` header (base64 of
// `ferrogate-payments/fixtures/payment_required_devnet.json`): devnet, amount
// 2500, mint / recipient / feePayer below, resource https://pay.example.com/weather.
const DEVNET_HEADER: &str = "ewogICJ4NDAyVmVyc2lvbiI6IDIsCiAgInJlc291cmNlIjogewogICAgInVybCI6ICJodHRwczovL3BheS5leGFtcGxlLmNvbS93ZWF0aGVyIiwKICAgICJtaW1lVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIgogIH0sCiAgImFjY2VwdHMiOiBbCiAgICB7CiAgICAgICJzY2hlbWUiOiAiZXhhY3QiLAogICAgICAibmV0d29yayI6ICJzb2xhbmE6RXRXVFJBQlphWXE2aU1mZVlLb3VSdTE2NlZVMnhxYTEiLAogICAgICAiYW1vdW50IjogIjI1MDAiLAogICAgICAiYXNzZXQiOiAiNHpNTUM5c3J0NVJpNVgxNEdBZ1hoYUhpaTNHblBBRUVSWVBKZ1pKRG5jRFUiLAogICAgICAicGF5VG8iOiAiMndLdXBMUjlxNndYWXBwdzhHcjJOdld4S0JVcW00UFBKS2tRZm94SERCZzQiLAogICAgICAibWF4VGltZW91dFNlY29uZHMiOiAxMjAsCiAgICAgICJleHRyYSI6IHsKICAgICAgICAiZmVlUGF5ZXIiOiAiRXdXcUdFNFpGS0xvZnVlc3RtVTRMRGRLN1hNMU40QUxnZFpjY3dZdWd3R2QiCiAgICAgIH0KICAgIH0KICBdCn0K";

const DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
const RESOURCE_URL: &str = "https://pay.example.com/weather";
const RESOURCE_ORIGIN: &str = "https://pay.example.com";
const ATOMIC_AMOUNT: u64 = 2500;

/// A fake EXTERNAL signer standing in for a KMS / OS key store / self-hosted
/// signer daemon: it holds the wallet identity outside the worker and returns
/// opaque transaction bytes. The worker never sees key material.
struct FakeExternalSigner {
    address: String,
    tx_bytes: Vec<u8>,
}

impl SvmTransferSigner for FakeExternalSigner {
    fn payer_address(&self) -> String {
        self.address.clone()
    }

    fn sign_transfer(&self, _intent: &SvmTransferIntent) -> Result<Vec<u8>, String> {
        Ok(self.tx_bytes.clone())
    }
}

fn authorized_request() -> AuthorizedRequest {
    AuthorizedRequest::new("GET", RESOURCE_URL).with_body(b"{\"q\":\"weather\"}")
}

fn parse_devnet_challenge() -> ParsedChallenge {
    ParsedChallenge::parse(
        DEVNET_HEADER,
        authorized_request(),
        &RequirementFilter::default(),
    )
    .expect("golden devnet challenge parses and binds to the authorized url")
}

fn base_policy(enabled: bool, approval_threshold: Option<u64>) -> X402SpendPolicy {
    X402SpendPolicy {
        enabled,
        revision: 7,
        allowed_networks: vec![PolicyNetwork::DEVNET],
        allowed_assets: vec![AllowedAsset {
            network: PolicyNetwork::DEVNET,
            mint: MINT.to_string(),
        }],
        allowed_recipients: vec![RECIPIENT.to_string()],
        allowed_resources: vec![ResourceRule {
            origin: RESOURCE_ORIGIN.to_string(),
            path_prefix: "/weather".to_string(),
        }],
        caps: X402SpendCaps {
            max_credits_per_payment: Some(1_000_000),
            ..X402SpendCaps::default()
        },
        conversion: ConversionRule {
            numerator: 1,
            denominator: 1,
            rounding: Rounding::Up,
            version: "test-v1".to_string(),
            expires_at_unix: None,
        },
        approval: ApprovalPolicy {
            threshold_credits: approval_threshold,
        },
        allow_insecure_local_resources: false,
    }
}

fn allow_policy() -> ValidatedX402SpendPolicy {
    base_policy(true, None)
        .validate()
        .expect("allow policy validates")
}

fn decision_for(
    challenge: &ParsedChallenge,
    policy: &ValidatedX402SpendPolicy,
) -> PaymentAuthorization {
    let scope = SpendScope {
        tenant_id: "tenant-a",
        ..SpendScope::default()
    };
    let principal = SpendPrincipal {
        tenant_id: "tenant-a".to_string(),
        ..SpendPrincipal::default()
    };
    let intent = challenge
        .payment_intent(&principal)
        .expect("the authorized request forms a valid payment intent");
    authorize_x402_payment(
        policy,
        &challenge.policy_request(&intent, scope),
        &SpendSnapshot::default(),
    )
}

fn external_signer() -> SignerBinding {
    SignerBinding::ExternalAuthority {
        authority_ref: "kms://tenant-a/x402-signer".to_string(),
        public_signer_address: FEE_PAYER.to_string(),
    }
}

#[test]
fn parse_valid_challenge_selects_wire_requirement() {
    let challenge = parse_devnet_challenge();
    let selected = challenge.selected();

    assert_eq!(selected.network.caip2(), DEVNET_CAIP2);
    assert_eq!(selected.mint, MINT);
    assert_eq!(selected.atomic_amount, ATOMIC_AMOUNT);
    assert_eq!(selected.recipient, RECIPIENT);
    assert_eq!(selected.fee_payer, FEE_PAYER);
    assert_eq!(selected.resource_url, RESOURCE_URL);
    // The challenge hash is the stable audit/idempotency key.
    assert_eq!(challenge.challenge_hash_hex().len(), 64);
}

#[test]
fn spend_authorization_request_carries_wire_binding() {
    let challenge = parse_devnet_challenge();
    let principal = SpendPrincipal {
        tenant_id: "tenant-a".to_string(),
        run_id: Some("run-9".to_string()),
        worker_id: Some("worker-3".to_string()),
        ..SpendPrincipal::default()
    };
    let request = challenge.spend_authorization_request(&principal);

    assert_eq!(request.method, "GET");
    assert_eq!(request.canonical_url, RESOURCE_URL);
    assert_eq!(request.resource_url, RESOURCE_URL);
    assert_eq!(request.network_caip2, DEVNET_CAIP2);
    assert_eq!(request.mint, MINT);
    assert_eq!(request.atomic_amount, ATOMIC_AMOUNT);
    assert_eq!(request.recipient, RECIPIENT);
    assert_eq!(request.fee_payer, FEE_PAYER);
    assert_eq!(request.challenge_hash_hex, challenge.challenge_hash_hex());
    assert_eq!(request.tenant_id, "tenant-a");
    assert_eq!(request.run_id.as_deref(), Some("run-9"));
    // The body hash is bound as evidence; the raw body never crosses the wire.
    assert_eq!(request.body_sha256_hex.as_deref().map(str::len), Some(64));

    // The serialized handoff must never contain key/secret material.
    let json = serde_json::to_string(&request).expect("serializes");
    assert!(!json.to_lowercase().contains("secret"));
    assert!(!json.to_lowercase().contains("private"));
    assert!(!json.to_lowercase().contains("seed"));
}

#[test]
fn parse_rejects_payment_redirect() {
    // The challenge advertises pay.example.com/weather, but the gateway
    // authorized egress to a different origin: fail closed, never pay.
    let request = AuthorizedRequest::new("GET", "https://evil.example.com/weather");
    let err = ParsedChallenge::parse(DEVNET_HEADER, request, &RequirementFilter::default())
        .expect_err("resource redirect must fail closed");
    assert!(matches!(err, X402ClientError::ResourceRedirect { .. }));
}

#[test]
fn parse_rejects_malformed_challenge() {
    let request = authorized_request();
    let err = ParsedChallenge::parse("not-base64-@@@", request, &RequirementFilter::default())
        .expect_err("malformed challenge must fail closed");
    assert!(matches!(err, X402ClientError::ChallengeParse(_)));
}

#[test]
fn authorize_spend_honors_allow_and_hands_off_to_external_signer() {
    let challenge = parse_devnet_challenge();
    let decision = decision_for(&challenge, &allow_policy());
    assert!(decision.is_allowed(), "policy allows the golden payment");

    let handoff = challenge
        .authorize_spend(&decision, external_signer())
        .expect("an allowed, bound, externally-signed spend yields a handoff");

    assert_eq!(handoff.public_signer_address(), FEE_PAYER);
    assert_eq!(handoff.authority_ref(), "kms://tenant-a/x402-signer");
    assert_eq!(handoff.intent().atomic_amount, ATOMIC_AMOUNT);
    assert_eq!(handoff.intent().recipient, RECIPIENT);

    // Signing happens entirely behind the external trait; the worker holds no
    // key material. The result is the base64 PAYMENT-SIGNATURE header value.
    let signer = FakeExternalSigner {
        address: FEE_PAYER.to_string(),
        tx_bytes: vec![7u8; 256],
    };
    let signature = handoff
        .sign_via(&signer)
        .expect("external signer assembles the PAYMENT-SIGNATURE");
    assert!(!signature.is_empty());
}

#[test]
fn authorize_spend_never_proceeds_on_deny() {
    let challenge = parse_devnet_challenge();
    let disabled = X402SpendPolicy::disabled()
        .validate()
        .expect("disabled policy validates");
    let decision = decision_for(&challenge, &disabled);
    assert_eq!(decision.decision, PaymentDecision::Deny);

    // A deny is honored, never overridden — even with a valid external signer.
    let err = challenge
        .authorize_spend(&decision, external_signer())
        .expect_err("a policy deny must stop the worker");
    match err {
        X402ClientError::PolicyDenied { reason_code, .. } => {
            assert_eq!(reason_code, REASON_DISABLED);
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
}

#[test]
fn authorize_spend_refuses_local_key_custody() {
    let challenge = parse_devnet_challenge();
    let decision = decision_for(&challenge, &allow_policy());
    assert!(decision.is_allowed());

    // Even on an allow, the worker refuses to hold a key and sign locally.
    let err = challenge
        .authorize_spend(&decision, SignerBinding::LocalKeyCustody)
        .expect_err("local key custody must fail closed");
    assert!(matches!(err, X402ClientError::KeyCustodyRefused { .. }));
}

#[test]
fn authorize_spend_refuses_headless_approval_required() {
    let challenge = parse_devnet_challenge();
    // Threshold of 1 credit with a 2500 atomic (1:1) payment forces approval.
    let policy = base_policy(true, Some(1))
        .validate()
        .expect("approval policy validates");
    let decision = decision_for(&challenge, &policy);
    assert!(matches!(
        decision.decision,
        PaymentDecision::ApprovalRequired { .. }
    ));

    let err = challenge
        .authorize_spend(&decision, external_signer())
        .expect_err("approval-required must not headless auto-pay");
    assert!(matches!(err, X402ClientError::ApprovalRequired { .. }));
}

#[test]
fn authorize_spend_rejects_decision_not_bound_to_challenge() {
    let challenge = parse_devnet_challenge();
    let mut decision = decision_for(&challenge, &allow_policy());
    assert!(decision.is_allowed());

    // Tamper: an allow computed for a DIFFERENT challenge hash must not be
    // accepted for this one.
    decision.challenge_hash_hex = "00".repeat(32);
    let err = challenge
        .authorize_spend(&decision, external_signer())
        .expect_err("an unbound decision must fail closed");
    match err {
        X402ClientError::BindingMismatch { field, .. } => assert_eq!(field, "challenge_hash"),
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
}

#[test]
fn sign_via_rejects_wrong_signer_address() {
    let challenge = parse_devnet_challenge();
    let decision = decision_for(&challenge, &allow_policy());
    let handoff = challenge
        .authorize_spend(&decision, external_signer())
        .expect("handoff");

    // The injected signer's public address differs from the authorized payer.
    let wrong = FakeExternalSigner {
        address: RECIPIENT.to_string(),
        tx_bytes: vec![1u8; 128],
    };
    let err = handoff
        .sign_via(&wrong)
        .expect_err("a signer that is not the authorized payer must fail closed");
    match err {
        X402ClientError::BindingMismatch { field, .. } => assert_eq!(field, "signer_address"),
        other => panic!("expected signer_address BindingMismatch, got {other:?}"),
    }
}

#[test]
fn external_authority_requires_a_valid_signer_address() {
    let challenge = parse_devnet_challenge();
    let decision = decision_for(&challenge, &allow_policy());
    let bad = SignerBinding::ExternalAuthority {
        authority_ref: "kms://x".to_string(),
        public_signer_address: "not-a-solana-address".to_string(),
    };
    let err = challenge
        .authorize_spend(&decision, bad)
        .expect_err("invalid external signer address fails closed");
    assert!(matches!(err, X402ClientError::InvalidSigner { .. }));
}

proptest! {
    /// Core non-custodial invariant: [`ParsedChallenge::authorize_spend`] yields
    /// a handoff ONLY when the decision is `Allow`, bound to this exact challenge,
    /// AND backed by an external signer. Any deny, approval-required, unbound
    /// decision, or local-custody request never produces a handoff.
    #[test]
    fn authorize_spend_proceeds_only_when_allowed_bound_and_external(
        decision_kind in 0u8..3,
        hash_matches in any::<bool>(),
        signer_external in any::<bool>(),
    ) {
        let challenge = parse_devnet_challenge();
        let mut decision = decision_for(&challenge, &allow_policy());

        // Impose the generated decision variant.
        decision.decision = match decision_kind {
            0 => PaymentDecision::Allow,
            1 => PaymentDecision::Deny,
            _ => PaymentDecision::ApprovalRequired { threshold_credits: 5 },
        };
        if !hash_matches {
            decision.challenge_hash_hex = "ab".repeat(32);
        }

        let signer = if signer_external {
            external_signer()
        } else {
            SignerBinding::LocalKeyCustody
        };

        let result = challenge.authorize_spend(&decision, signer);
        let should_proceed = decision_kind == 0 && hash_matches && signer_external;
        prop_assert_eq!(result.is_ok(), should_proceed);

        // A deny is NEVER a proceed, regardless of signer or binding.
        if decision_kind == 1 {
            prop_assert!(result.is_err());
        }
    }
}
