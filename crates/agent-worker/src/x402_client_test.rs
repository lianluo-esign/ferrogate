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

// The same challenge with `amount` 3000 instead of 2500. Identical network,
// mint, recipient, fee payer, timeout and resource, so a decision computed for
// it differs from the golden one in exactly ONE observable way: the wire
// contract's challenge hash.
const ALT_AMOUNT_HEADER: &str = "ewogICJ4NDAyVmVyc2lvbiI6IDIsCiAgInJlc291cmNlIjogewogICAgInVybCI6ICJodHRwczovL3BheS5leGFtcGxlLmNvbS93ZWF0aGVyIiwKICAgICJtaW1lVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIgogIH0sCiAgImFjY2VwdHMiOiBbCiAgICB7CiAgICAgICJzY2hlbWUiOiAiZXhhY3QiLAogICAgICAibmV0d29yayI6ICJzb2xhbmE6RXRXVFJBQlphWXE2aU1mZVlLb3VSdTE2NlZVMnhxYTEiLAogICAgICAiYW1vdW50IjogIjMwMDAiLAogICAgICAiYXNzZXQiOiAiNHpNTUM5c3J0NVJpNVgxNEdBZ1hoYUhpaTNHblBBRUVSWVBKZ1pKRG5jRFUiLAogICAgICAicGF5VG8iOiAiMndLdXBMUjlxNndYWXBwdzhHcjJOdld4S0JVcW00UFBKS2tRZm94SERCZzQiLAogICAgICAibWF4VGltZW91dFNlY29uZHMiOiAxMjAsCiAgICAgICJleHRyYSI6IHsKICAgICAgICAiZmVlUGF5ZXIiOiAiRXdXcUdFNFpGS0xvZnVlc3RtVTRMRGRLN1hNMU40QUxnZFpjY3dZdWd3R2QiCiAgICAgIH0KICAgIH0KICBdCn0K";

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
    challenge_for(authorized_request())
}

/// Parse the SAME golden challenge on a different already-authorized request.
/// This is how the method/body binding is exercised without poking at a
/// decision's fields: the merchant challenge is byte-identical, so every
/// wire-derived field (challenge hash, network, mint, recipient, resource)
/// matches, and only the request the payment is for differs.
fn challenge_for(request: AuthorizedRequest) -> ParsedChallenge {
    challenge_for_header(DEVNET_HEADER, request)
}

fn challenge_for_header(header: &str, request: AuthorizedRequest) -> ParsedChallenge {
    ParsedChallenge::parse(header, request, &RequirementFilter::default())
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

/// Run the real policy over a challenge and return BOTH artifacts the worker
/// consumes: the immutable intent the decision was computed for, and the
/// decision itself. `PaymentAuthorization`'s fields are sealed, so a test can
/// only obtain a decision the way production does — which is the point.
fn authorize(
    challenge: &ParsedChallenge,
    policy: &ValidatedX402SpendPolicy,
) -> (PaymentIntent, PaymentAuthorization) {
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
    let decision = authorize_x402_payment(
        policy,
        &challenge.policy_request(&intent, scope),
        &SpendSnapshot::default(),
    );
    (intent, decision)
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
    let (intent, decision) = authorize(&challenge, &allow_policy());
    assert!(decision.is_allowed(), "policy allows the golden payment");

    let handoff = challenge
        .authorize_spend(&intent, &decision, external_signer())
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
    let (intent, decision) = authorize(&challenge, &disabled);
    assert_eq!(decision.decision(), &PaymentDecision::Deny);

    // A deny is honored, never overridden — even with a valid external signer.
    let err = challenge
        .authorize_spend(&intent, &decision, external_signer())
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
    let (intent, decision) = authorize(&challenge, &allow_policy());
    assert!(decision.is_allowed());

    // Even on an allow, the worker refuses to hold a key and sign locally.
    let err = challenge
        .authorize_spend(&intent, &decision, SignerBinding::LocalKeyCustody)
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
    let (intent, decision) = authorize(&challenge, &policy);
    assert!(matches!(
        decision.decision(),
        PaymentDecision::ApprovalRequired { .. }
    ));

    let err = challenge
        .authorize_spend(&intent, &decision, external_signer())
        .expect_err("approval-required must not headless auto-pay");
    assert!(matches!(err, X402ClientError::ApprovalRequired { .. }));
}

#[test]
fn authorize_spend_rejects_decision_not_bound_to_challenge() {
    let challenge = parse_devnet_challenge();
    // A real `Allow`, computed by real policy — for the 3000-unit challenge.
    // Everything else about the two challenges is identical, so the ONLY thing
    // that can catch this is the challenge-hash binding.
    let other = challenge_for_header(ALT_AMOUNT_HEADER, authorized_request());
    let (other_intent, other_decision) = authorize(&other, &allow_policy());
    assert!(other_decision.is_allowed());

    let err = challenge
        .authorize_spend(&other_intent, &other_decision, external_signer())
        .expect_err("an unbound decision must fail closed");
    match err {
        X402ClientError::BindingMismatch { field, .. } => assert_eq!(field, "challenge_hash"),
        other => panic!("expected BindingMismatch, got {other:?}"),
    }
}

/// The redirect half the challenge hash cannot cover. An `Allow` computed for
/// `GET https://pay.example.com/weather` with no body is handed to
/// `authorize_spend` for a `POST` of an attacker-chosen body to the SAME URL
/// carrying the SAME challenge: challenge hash, network, mint, recipient and
/// resource all match, and only the method binding stands between that decision
/// and a signed transfer.
#[test]
fn authorize_spend_rejects_a_decision_bound_to_another_method() {
    let get = challenge_for(AuthorizedRequest::new("GET", RESOURCE_URL));
    let (intent, decision) = authorize(&get, &allow_policy());
    assert!(decision.is_allowed(), "policy allows the GET");

    let post = challenge_for(AuthorizedRequest::new("POST", RESOURCE_URL));
    let err = post
        .authorize_spend(&intent, &decision, external_signer())
        .expect_err("an allow computed for a GET must not authorize a POST");
    match err {
        X402ClientError::BindingMismatch {
            field,
            expected,
            actual,
        } => {
            assert_eq!(field, "http_method");
            assert_eq!(expected, "POST");
            assert_eq!(actual, "GET");
        }
        other => panic!("expected an http_method BindingMismatch, got {other:?}"),
    }
}

/// Same challenge, same URL, same method — a different request BODY. The
/// decision names the body it authorized; paying it for another one is the
/// "cannot redirect payment to another body" half of the invariant.
#[test]
fn authorize_spend_rejects_a_decision_bound_to_another_request_body() {
    let authorized = challenge_for(
        AuthorizedRequest::new("POST", RESOURCE_URL).with_body(b"{\"q\":\"weather\"}"),
    );
    let (intent, decision) = authorize(&authorized, &allow_policy());
    assert!(decision.is_allowed(), "policy allows the authorized POST");

    let swapped =
        challenge_for(AuthorizedRequest::new("POST", RESOURCE_URL).with_body(b"{\"q\":\"drain\"}"));
    let err = swapped
        .authorize_spend(&intent, &decision, external_signer())
        .expect_err("an allow computed for one body must not authorize another");
    match err {
        X402ClientError::BindingMismatch { field, .. } => {
            assert_eq!(field, "request_body_hash")
        }
        other => panic!("expected a request_body_hash BindingMismatch, got {other:?}"),
    }
}

/// The identity half: an `Allow` computed for one run's intent must not be
/// spendable under another run's intent, even though the challenge, method and
/// body are identical. Only the intent hash sees this.
#[test]
fn authorize_spend_rejects_a_decision_bound_to_another_intent() {
    let challenge = parse_devnet_challenge();
    let (_, decision) = authorize(&challenge, &allow_policy());
    assert!(decision.is_allowed());

    let other_intent = challenge
        .payment_intent(&SpendPrincipal {
            tenant_id: "tenant-a".to_string(),
            run_id: Some("some-other-run".to_string()),
            ..SpendPrincipal::default()
        })
        .expect("a second intent for the same request");
    let err = challenge
        .authorize_spend(&other_intent, &decision, external_signer())
        .expect_err("a decision naming another intent must fail closed");
    match err {
        X402ClientError::BindingMismatch { field, .. } => assert_eq!(field, "intent_hash"),
        other => panic!("expected an intent_hash BindingMismatch, got {other:?}"),
    }
}

// --- Gate-owned coverage (#351 test gate): binding canonicalization symmetry ---

/// The method binding is only sound if BOTH sides canonicalize the same way.
/// `ParsedChallenge::method()` trims and uppercases; `PaymentIntent`'s
/// `normalize_http_method` trims and uppercases. If either side ever stopped,
/// a lowercase or padded method would make a legitimate `Allow` un-spendable
/// (a fail-closed break, but a break), or -- worse, if only the intent
/// normalized -- would let `get` and `GET` name two different intents for one
/// request. Neither direction was covered: every existing case uses an already
/// canonical method.
#[test]
fn a_lowercase_or_padded_method_canonicalizes_identically_on_both_sides() {
    for spelling in ["get", "  GeT  ", "GET"] {
        let challenge = challenge_for(
            AuthorizedRequest::new(spelling, RESOURCE_URL).with_body(b"{\"q\":\"weather\"}"),
        );
        let (intent, decision) = authorize(&challenge, &allow_policy());
        assert!(decision.is_allowed(), "policy allows {spelling:?}");
        assert_eq!(
            decision.http_method(),
            "GET",
            "the decision must name the canonical method for {spelling:?}"
        );
        challenge
            .authorize_spend(&intent, &decision, external_signer())
            .unwrap_or_else(|error| {
                panic!("a decision for {spelling:?} must still be spendable: {error:?}")
            });
    }
}

/// A decision computed for `GET` must not become spendable for a *different*
/// method merely because the two spellings differ in case -- the canonical form
/// is what is compared, so `post` is still a mismatch against a `GET` decision.
#[test]
fn method_canonicalization_does_not_collapse_two_different_methods() {
    let get = challenge_for(AuthorizedRequest::new("get", RESOURCE_URL));
    let (intent, decision) = authorize(&get, &allow_policy());
    let post = challenge_for(AuthorizedRequest::new("  post ", RESOURCE_URL));

    let err = post
        .authorize_spend(&intent, &decision, external_signer())
        .expect_err("a lowercase POST must not consume a lowercase GET decision");
    match err {
        X402ClientError::BindingMismatch {
            field,
            expected,
            actual,
        } => {
            assert_eq!(field, "http_method");
            assert_eq!(expected, "POST");
            assert_eq!(actual, "GET");
        }
        other => panic!("expected an http_method BindingMismatch, got {other:?}"),
    }
}

/// "No body" must be a concrete value on both sides, not an absence. A bodyless
/// request and one whose body is explicitly empty are the SAME request, so a
/// decision for either must be spendable for the other -- and both must compare
/// against the canonical empty-body hash rather than skipping the check.
#[test]
fn a_bodyless_request_binds_to_the_canonical_empty_body_hash() {
    let empty_hex = RequestBodyHash::empty().as_hex();

    let bodyless = challenge_for(AuthorizedRequest::new("GET", RESOURCE_URL));
    let (intent, decision) = authorize(&bodyless, &allow_policy());
    assert_eq!(
        decision.request_body_hash_hex(),
        empty_hex,
        "a bodyless request must bind to the empty-body hash, not to an absence"
    );

    // The bodyless request must be able to spend its OWN decision: both sides
    // have to reach for the same canonical empty-body value, not just the
    // decision side.
    bodyless
        .authorize_spend(&intent, &decision, external_signer())
        .expect("a bodyless request must be able to spend its own decision");

    // An explicitly-empty body is the same request and must interoperate.
    let explicitly_empty =
        challenge_for(AuthorizedRequest::new("GET", RESOURCE_URL).with_body(b""));
    explicitly_empty
        .authorize_spend(&intent, &decision, external_signer())
        .expect("an explicitly-empty body is the same request as a bodyless one");

    // ...but any real body is not.
    let with_body = challenge_for(AuthorizedRequest::new("GET", RESOURCE_URL).with_body(b"x"));
    let err = with_body
        .authorize_spend(&intent, &decision, external_signer())
        .expect_err("a bodyless decision must not authorize a request that carries a body");
    assert!(matches!(
        err,
        X402ClientError::BindingMismatch {
            field: "request_body_hash",
            ..
        }
    ));
}

#[test]
fn sign_via_rejects_wrong_signer_address() {
    let challenge = parse_devnet_challenge();
    let (intent, decision) = authorize(&challenge, &allow_policy());
    let handoff = challenge
        .authorize_spend(&intent, &decision, external_signer())
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
    let (intent, decision) = authorize(&challenge, &allow_policy());
    let bad = SignerBinding::ExternalAuthority {
        authority_ref: "kms://x".to_string(),
        public_signer_address: "not-a-solana-address".to_string(),
    };
    let err = challenge
        .authorize_spend(&intent, &decision, bad)
        .expect_err("invalid external signer address fails closed");
    assert!(matches!(err, X402ClientError::InvalidSigner { .. }));
}

proptest! {
    /// Core non-custodial invariant: [`ParsedChallenge::authorize_spend`] yields
    /// a handoff ONLY when the decision is `Allow`, bound to this exact challenge
    /// AND to the exact request being paid for, AND backed by an external
    /// signer. Any deny, approval-required, differently-bound decision, or
    /// local-custody request never produces a handoff.
    ///
    /// Every decision here is produced by real policy over real inputs — the
    /// artifact is sealed, so there is no shortcut — which means the `Deny` and
    /// `ApprovalRequired` arms are the policy's own and the binding arms are a
    /// genuinely different request rather than an edited field.
    #[test]
    fn authorize_spend_proceeds_only_when_allowed_bound_and_external(
        decision_kind in 0u8..3,
        request_matches in any::<bool>(),
        signer_external in any::<bool>(),
    ) {
        let challenge = parse_devnet_challenge();
        let policy = match decision_kind {
            // Allow.
            0 => allow_policy(),
            // Deny: x402 spending disabled for the scope.
            1 => X402SpendPolicy::disabled().validate().expect("disabled policy validates"),
            // ApprovalRequired: a 1-credit threshold against a 2500-credit payment.
            _ => base_policy(true, Some(1)).validate().expect("approval policy validates"),
        };

        // The decision is computed either for THIS request, or for a POST of a
        // different body to the same URL under the same challenge.
        let evaluated = if request_matches {
            challenge_for(authorized_request())
        } else {
            challenge_for(AuthorizedRequest::new("POST", RESOURCE_URL).with_body(b"drain"))
        };
        let (intent, decision) = authorize(&evaluated, &policy);
        prop_assert_eq!(decision.is_allowed(), decision_kind == 0);

        let signer = if signer_external {
            external_signer()
        } else {
            SignerBinding::LocalKeyCustody
        };

        let result = challenge.authorize_spend(&intent, &decision, signer);
        let should_proceed = decision_kind == 0 && request_matches && signer_external;
        prop_assert_eq!(result.is_ok(), should_proceed);

        // A deny is NEVER a proceed, regardless of signer or binding.
        if decision_kind == 1 {
            prop_assert!(result.is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// Bearer-material redaction (#353) — pure-function edge cases. The wiring into
// the real REST response path is proven in `external_actions_x402_test.rs`.
// ---------------------------------------------------------------------------

/// The status line is never a header, even though it contains no colon — and a
/// header whose NAME merely resembles a bearer header is not redacted.
#[test]
fn redaction_rewrites_only_bearer_header_values() {
    let raw = "HTTP/1.1 200 OK\r\n\
               content-type: text/plain\r\n\
               x-authorization-scheme: bearer-ish\r\n\
               Authorization: Bearer secret-token\r\n\
               \r\n\
               body";

    let redacted = redact_bearer_headers(raw);

    assert!(redacted.starts_with("HTTP/1.1 200 OK\r\n"), "{redacted}");
    assert!(redacted.contains("content-type: text/plain"), "{redacted}");
    assert!(
        redacted.contains("x-authorization-scheme: bearer-ish"),
        "a non-bearer header must survive verbatim: {redacted}"
    );
    assert!(
        redacted.contains(&format!("Authorization: {REDACTED_HEADER_VALUE}")),
        "{redacted}"
    );
    assert!(!redacted.contains("secret-token"), "{redacted}");
    assert!(redacted.ends_with("body"), "{redacted}");
}

/// Header matching is case-insensitive on both the x402 proof header and the
/// standard credential headers.
#[test]
fn redaction_matches_header_names_case_insensitively() {
    let raw = "HTTP/1.1 200 OK\r\npayment-signature: proof\r\nSET-COOKIE: s=1\r\n\r\n";

    let redacted = redact_bearer_headers(raw);

    assert!(!redacted.contains("proof"), "{redacted}");
    assert!(!redacted.contains("s=1"), "{redacted}");
    assert_eq!(redacted.matches(REDACTED_HEADER_VALUE).count(), 2);
}

/// A response body is not the header section: once the separator is passed,
/// content is left alone. A line in the body that looks like a credential
/// header is body text, not a header.
#[test]
fn redaction_stops_at_the_header_separator() {
    let raw = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nauthorization: in-the-body";

    let redacted = redact_bearer_headers(raw);

    assert!(
        redacted.ends_with("authorization: in-the-body"),
        "{redacted}"
    );
    assert!(!redacted.contains(REDACTED_HEADER_VALUE), "{redacted}");
}

/// A truncated or malformed response with no separator is treated as ALL
/// headers, which over-redacts rather than under-redacts.
#[test]
fn a_response_without_a_separator_is_treated_as_all_headers() {
    let raw = "HTTP/1.1 200 OK\r\nAuthorization: Bearer secret-token";

    let redacted = redact_bearer_headers(raw);

    assert!(!redacted.contains("secret-token"), "{redacted}");
}

/// The public x402 protocol headers are deliberately NOT bearer material:
/// redacting them would destroy the audit trail #354 needs.
#[test]
fn public_x402_headers_are_not_treated_as_bearer_material() {
    let raw = "HTTP/1.1 402 Payment Required\r\n\
               PAYMENT-REQUIRED: challenge-blob\r\n\
               PAYMENT-RESPONSE: settlement-blob\r\n\
               \r\n";

    let redacted = redact_bearer_headers(raw);

    assert_eq!(redacted, raw);
}

/// An `obs-fold` continuation line (RFC 7230 §3.2.4) carries the tail of the
/// PREVIOUS field's value and has no colon of its own, so a per-line parse would
/// wave it straight through. The credential is split across the fold here so
/// that letting the continuation past leaks a usable piece of it.
#[test]
fn a_folded_bearer_header_value_is_redacted_across_the_fold() {
    let raw = "HTTP/1.1 200 OK\r\n\
               Authorization: Bearer first-half\r\n\
               \tsecond-half-of-the-secret\r\n\
               content-type: text/plain\r\n\
               \tcharset=utf-8\r\n\
               \r\n\
               body";

    let redacted = redact_bearer_headers(raw);

    assert!(!redacted.contains("first-half"), "{redacted}");
    assert!(
        !redacted.contains("second-half-of-the-secret"),
        "the folded tail of a credential leaked: {redacted}"
    );
    // A fold on a NON-bearer header is untouched — this must not become a
    // blanket "drop every continuation line".
    assert!(redacted.contains("charset=utf-8"), "{redacted}");
    assert!(redacted.ends_with("body"), "{redacted}");
}

/// A fold in the BODY is body text, not a continuation: the header/body
/// separator still ends the header section.
#[test]
fn a_fold_after_the_header_separator_is_body_text() {
    let raw = "HTTP/1.1 200 OK\r\n\
               Authorization: Bearer secret\r\n\
               \r\n\
               \tindented body line";

    let redacted = redact_bearer_headers(raw);

    assert!(redacted.ends_with("\tindented body line"), "{redacted}");
    assert!(!redacted.contains("secret"), "{redacted}");
}

/// Credential headers outside the IANA registry authenticate their holder just
/// as completely as `authorization` does.
#[test]
fn non_registered_credential_headers_are_bearer_material() {
    let raw = "HTTP/1.1 200 OK\r\n\
               x-api-key: key-material\r\n\
               X-Auth-Token: token-material\r\n\
               Authentication: auth-material\r\n\
               \r\n";

    let redacted = redact_bearer_headers(raw);

    assert!(!redacted.contains("key-material"), "{redacted}");
    assert!(!redacted.contains("token-material"), "{redacted}");
    assert!(!redacted.contains("auth-material"), "{redacted}");
    assert_eq!(redacted.matches(REDACTED_HEADER_VALUE).count(), 3);
}

// ---------------------------------------------------------------------------
// Wire stage → hold disposition (#353). Socket-level coverage lives in
// `external_actions_x402_test.rs`; this pins the mapping itself.
// ---------------------------------------------------------------------------

/// The asymmetry, stated directly: only a PROVEN-unsent request may release a
/// hold. Swapping either arm of `hold_disposition` fails this.
#[test]
fn only_a_proven_unsent_request_may_release_a_hold() {
    assert_eq!(
        RequestWireStage::ProvenNotSent.hold_disposition(),
        HoldDisposition::ReleasableBeforeSubmission
    );
    assert_eq!(
        RequestWireStage::SentOrUnknown.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
    // The default must be the money-safe one: retaining a hold costs a sweeper
    // tick, releasing one for a settled payment costs the stablecoin.
    assert_eq!(
        RequestWireStage::default().hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
}

// ---------------------------------------------------------------------------
// Non-custodial 402 detection (#353).
// ---------------------------------------------------------------------------

/// Detection surfaces the public evidence needed to ask the gateway for a
/// decision — and nothing else. It performs no policy act and produces no
/// proof.
#[test]
fn detection_surfaces_public_challenge_evidence_only() {
    let detected = detect_payment_required(DEVNET_HEADER, authorized_request())
        .expect("the golden devnet challenge is detected");

    assert_eq!(detected.network_caip2, DEVNET_CAIP2);
    assert_eq!(detected.atomic_amount, ATOMIC_AMOUNT);
    assert_eq!(detected.recipient, RECIPIENT);
    assert_eq!(detected.resource_url, RESOURCE_URL);
    // The challenge hash is the deterministic join key the gateway's decision,
    // attempt and hold all key on.
    assert_eq!(
        detected.challenge_hash_hex,
        parse_devnet_challenge().challenge_hash_hex()
    );
}

/// Detection inherits the redirect guard: a challenge that points somewhere
/// other than the authorized egress URL is refused before anything else.
#[test]
fn detection_refuses_a_payment_redirect() {
    let error = detect_payment_required(
        DEVNET_HEADER,
        AuthorizedRequest::new("GET", "https://pay.example.com/other"),
    )
    .expect_err("a challenge for a different resource is a payment redirect");

    assert!(matches!(error, X402ClientError::ResourceRedirect { .. }));
}

/// A malformed challenge is a refusal delegated to the frozen wire contract,
/// never a best-effort payment.
#[test]
fn detection_fails_closed_on_a_malformed_challenge() {
    let error = detect_payment_required("not-base64-at-all!!", authorized_request())
        .expect_err("a malformed challenge is never paid");

    assert!(matches!(error, X402ClientError::ChallengeParse(_)));
}
