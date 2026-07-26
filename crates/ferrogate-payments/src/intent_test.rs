// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit tests for the immutable x402 payment-intent contract
// (issue #351): the method + request-body binding that makes a GET and a POST
// of a different body to the same URL distinguishable, sealed construction,
// validation rejections, the deterministic intent hash, and the challenge
// binding check. Sibling test file per AGENTS.md (no inline `mod tests {}`).

use super::*;

use base64::Engine as _;

use crate::wire::{parse_payment_required, select_requirement, RequirementFilter};

const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const CAIP2_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MERCHANT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const OTHER_MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
const RESOURCE: &str = "https://pay.example.com/weather";

fn selected(atomic: u64, recipient: &str) -> SelectedPayment {
    let body = serde_json::json!({
        "x402Version": 2,
        "resource": {"url": RESOURCE, "mimeType": "application/json"},
        "accepts": [{
            "scheme": "exact",
            "network": CAIP2_DEVNET,
            "amount": atomic.to_string(),
            "asset": USDC_DEVNET,
            "payTo": recipient,
            "maxTimeoutSeconds": 120,
            "extra": {"feePayer": FEE_PAYER}
        }]
    });
    let header = base64::engine::general_purpose::STANDARD.encode(body.to_string());
    let required = parse_payment_required(&header).expect("fixture challenge parses");
    select_requirement(&required, &RequirementFilter::default()).expect("fixture requirement")
}

fn identity() -> PaymentIntentIdentity {
    PaymentIntentIdentity {
        tenant_id: "tenant-1".into(),
        project_id: Some("project-1".into()),
        workspace_id: Some("workspace-1".into()),
        key_id: Some("key-1".into()),
        run_id: Some("run-1".into()),
        worker_id: Some("worker-1".into()),
        request_id: "req-1".into(),
    }
}

fn intent(method: &str, body: &[u8]) -> PaymentIntent {
    PaymentIntent::from_selected(
        &selected(2_500, MERCHANT),
        method,
        RESOURCE,
        body,
        identity(),
    )
    .expect("fixture intent is valid")
}

/// The gap this whole type exists to close: without the method + body binding,
/// an authorized `GET` and a `POST` of a different body to the SAME url carry
/// identical payment terms and are indistinguishable to anything downstream.
#[test]
fn a_get_and_a_post_of_a_different_body_to_the_same_url_are_distinguishable() {
    let read = intent("GET", &[]);
    let write = intent("POST", br#"{"drain":"everything"}"#);

    // Same merchant terms, same URL, same challenge...
    assert_eq!(read.challenge_hash_hex(), write.challenge_hash_hex());
    assert_eq!(
        read.authorized_resource_url(),
        write.authorized_resource_url()
    );
    assert_eq!(read.atomic_amount(), write.atomic_amount());
    // ...and yet the two intents are not the same intent.
    assert_ne!(read.http_method(), write.http_method());
    assert_ne!(read.request_body_hash(), write.request_body_hash());
    assert_ne!(
        read.intent_hash_hex(),
        write.intent_hash_hex(),
        "the intent hash must separate two different requests paying one challenge"
    );
}

#[test]
fn the_same_request_always_produces_the_same_intent_hash() {
    let first = intent("POST", b"body");
    let second = intent("post", b"body");

    // The method is normalized, so casing cannot fork the audit key.
    assert_eq!(second.http_method(), "POST");
    assert_eq!(first.intent_hash_hex(), second.intent_hash_hex());
    assert_eq!(first.intent_hash_hex().len(), 64);
    assert!(first
        .intent_hash_hex()
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn changing_any_bound_field_changes_the_intent_hash() {
    let base = intent("GET", &[]);
    let baseline = base.intent_hash_hex();

    let other_amount =
        PaymentIntent::from_selected(&selected(2_501, MERCHANT), "GET", RESOURCE, &[], identity())
            .expect("valid");
    let other_recipient = PaymentIntent::from_selected(
        &selected(2_500, OTHER_MERCHANT),
        "GET",
        RESOURCE,
        &[],
        identity(),
    )
    .expect("valid");
    let other_url = PaymentIntent::from_selected(
        &selected(2_500, MERCHANT),
        "GET",
        "https://pay.example.com/other",
        &[],
        identity(),
    )
    .expect("valid");
    let mut other_run = identity();
    other_run.run_id = Some("run-2".into());
    let other_identity =
        PaymentIntent::from_selected(&selected(2_500, MERCHANT), "GET", RESOURCE, &[], other_run)
            .expect("valid");

    for (what, other) in [
        ("amount", other_amount),
        ("recipient", other_recipient),
        ("resource url", other_url),
        ("run id", other_identity),
    ] {
        assert_ne!(
            baseline,
            other.intent_hash_hex(),
            "a different {what} must produce a different intent hash"
        );
    }
}

/// An absent optional id and an empty-string one must not hash alike; the
/// latter is rejected outright, which is the stronger guarantee.
#[test]
fn an_absent_optional_id_is_not_the_same_as_a_blank_one() {
    let mut absent = identity();
    absent.run_id = None;
    let without_run =
        PaymentIntent::from_selected(&selected(2_500, MERCHANT), "GET", RESOURCE, &[], absent)
            .expect("an absent run id is legitimate");
    assert!(without_run.identity().run_id.is_none());
    assert_ne!(
        without_run.intent_hash_hex(),
        intent("GET", &[]).intent_hash_hex()
    );

    let mut blank = identity();
    blank.run_id = Some("   ".into());
    let error =
        PaymentIntent::from_selected(&selected(2_500, MERCHANT), "GET", RESOURCE, &[], blank)
            .expect_err("a blank run id is a caller bug, not an absence");
    assert!(matches!(
        error,
        PaymentIntentError::InvalidIdentity {
            field: "run_id",
            ..
        }
    ));
}

#[test]
fn an_intent_binds_to_exactly_one_challenge() {
    let bound = intent("GET", &[]);
    assert_eq!(bound.binding_mismatch(&selected(2_500, MERCHANT)), None);
    // A challenge for a different amount or payee is a different payment, and
    // the mismatch names the field so the caller can emit a specific reason.
    assert_eq!(
        bound.binding_mismatch(&selected(9_999, MERCHANT)),
        Some("challenge_hash")
    );
    assert_eq!(
        bound.binding_mismatch(&selected(2_500, OTHER_MERCHANT)),
        Some("challenge_hash")
    );
}

/// The binding check must not depend solely on the challenge hash: a caller
/// that hands over a hash-matching but field-tampered pair still fails.
#[test]
fn a_tampered_payment_term_is_caught_even_when_the_challenge_hash_matches() {
    let bound = intent("GET", &[]);
    let mut tampered = selected(2_500, MERCHANT);
    tampered.atomic_amount = 2_500_000;
    assert_eq!(bound.binding_mismatch(&tampered), Some("atomic_amount"));

    let mut tampered = selected(2_500, MERCHANT);
    tampered.recipient = OTHER_MERCHANT.to_string();
    assert_eq!(bound.binding_mismatch(&tampered), Some("recipient"));

    let mut tampered = selected(2_500, MERCHANT);
    tampered.mint = OTHER_MERCHANT.to_string();
    assert_eq!(bound.binding_mismatch(&tampered), Some("mint"));
}

#[test]
fn a_bodyless_request_has_a_concrete_hash_not_an_absence() {
    assert_eq!(RequestBodyHash::empty(), RequestBodyHash::of(&[]));
    assert_ne!(RequestBodyHash::empty(), RequestBodyHash::of(b"{}"));
    assert_eq!(RequestBodyHash::empty().as_hex().len(), 64);
    // Round-trips through the wire form.
    let hash = RequestBodyHash::of(b"payload");
    assert_eq!(RequestBodyHash::from_hex(&hash.as_hex()), Ok(hash));
    assert!(RequestBodyHash::from_hex("deadbeef").is_err());
    assert!(RequestBodyHash::from_hex(&hash.as_hex().to_uppercase()).is_err());
}

#[test]
fn construction_rejects_every_field_a_decision_would_later_depend_on() {
    let base = || PaymentIntentDraft {
        x402_version: 2,
        scheme: "exact".into(),
        network_caip2: CAIP2_DEVNET.into(),
        mint: USDC_DEVNET.into(),
        atomic_amount: 2_500,
        recipient: MERCHANT.into(),
        authorized_resource_url: RESOURCE.into(),
        http_method: "GET".into(),
        request_body_hash: RequestBodyHash::empty(),
        challenge_hash_hex: selected(2_500, MERCHANT).challenge_hash_hex(),
        max_timeout_seconds: 120,
        identity: identity(),
    };
    assert!(PaymentIntent::new(base()).is_ok());

    let cases: Vec<(&str, PaymentIntentDraft)> = vec![
        (
            "version",
            PaymentIntentDraft {
                x402_version: 1,
                ..base()
            },
        ),
        (
            "scheme",
            PaymentIntentDraft {
                scheme: "upto".into(),
                ..base()
            },
        ),
        (
            "network",
            PaymentIntentDraft {
                network_caip2: "solana:whatever".into(),
                ..base()
            },
        ),
        // A token symbol is never a mint.
        (
            "mint",
            PaymentIntentDraft {
                mint: "USDC".into(),
                ..base()
            },
        ),
        (
            "recipient",
            PaymentIntentDraft {
                recipient: "not-base58!".into(),
                ..base()
            },
        ),
        (
            "zero amount",
            PaymentIntentDraft {
                atomic_amount: 0,
                ..base()
            },
        ),
        (
            "relative url",
            PaymentIntentDraft {
                authorized_resource_url: "/weather".into(),
                ..base()
            },
        ),
        (
            "non-http url",
            PaymentIntentDraft {
                authorized_resource_url: "file:///etc/passwd".into(),
                ..base()
            },
        ),
        (
            "blank method",
            PaymentIntentDraft {
                http_method: "  ".into(),
                ..base()
            },
        ),
        (
            "smuggled method",
            PaymentIntentDraft {
                http_method: "GET /other HTTP/1.1".into(),
                ..base()
            },
        ),
        (
            "challenge hash",
            PaymentIntentDraft {
                challenge_hash_hex: "abc".into(),
                ..base()
            },
        ),
        (
            "zero timeout",
            PaymentIntentDraft {
                max_timeout_seconds: 0,
                ..base()
            },
        ),
        (
            "oversize timeout",
            PaymentIntentDraft {
                max_timeout_seconds: 86_401,
                ..base()
            },
        ),
        (
            "blank tenant",
            PaymentIntentDraft {
                identity: PaymentIntentIdentity {
                    tenant_id: " ".into(),
                    ..identity()
                },
                ..base()
            },
        ),
        (
            "blank request id",
            PaymentIntentDraft {
                identity: PaymentIntentIdentity {
                    request_id: String::new(),
                    ..identity()
                },
                ..base()
            },
        ),
    ];
    for (what, draft) in cases {
        assert!(
            PaymentIntent::new(draft).is_err(),
            "an invalid {what} must not produce an intent"
        );
    }
}

/// Deserialization must go through the same validation as construction, or a
/// persisted-then-reloaded intent could be weaker than a freshly built one.
#[test]
fn deserialization_cannot_bypass_validation() {
    let original = intent("POST", b"payload");
    let encoded = serde_json::to_string(&original).expect("intent serializes");
    let decoded: PaymentIntent = serde_json::from_str(&encoded).expect("round-trips");
    assert_eq!(decoded, original);
    assert_eq!(decoded.intent_hash_hex(), original.intent_hash_hex());
    // The atomic amount survives serialization as an integer, losslessly.
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("json");
    assert_eq!(value["atomic_amount"], serde_json::json!(2_500u64));

    let tampered = encoded.replace(r#""scheme":"exact""#, r#""scheme":"upto""#);
    assert_ne!(
        tampered, encoded,
        "the fixture must actually be tampered with"
    );
    serde_json::from_str::<PaymentIntent>(&tampered)
        .expect_err("an unsupported scheme must not deserialize into a valid intent");

    let tampered = encoded.replace(r#""atomic_amount":2500"#, r#""atomic_amount":0"#);
    assert_ne!(tampered, encoded);
    serde_json::from_str::<PaymentIntent>(&tampered)
        .expect_err("a zero amount must not deserialize into a valid intent");
}
