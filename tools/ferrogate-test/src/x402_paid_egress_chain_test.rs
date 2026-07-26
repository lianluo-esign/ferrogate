// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the x402 paid-egress chain's merchant double
// and money assertions (issue #354). These run with no gateway and no socket:
// the double's decision table is a pure function, so the properties the chain
// leans on are pinned here rather than only observed inside a scenario run.

use super::*;

use ferrogate_storage::{StoredWalletReservation, StoredWalletSettlement};

fn paid_request(path: &str, signature: &str) -> String {
    let proof = base64::engine::general_purpose::STANDARD.encode(
        json!({
            "x402Version": X402_VERSION,
            "scheme": SCHEME,
            "network": CAIP2_DEVNET,
            "payload": { "transaction": signature }
        })
        .to_string(),
    );
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nX-PAYMENT: {proof}\r\n\r\n")
}

fn unpaid_request(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
}

fn decode_challenge(response: &str) -> Value {
    let header = header_value(response, "x-payment-required").expect("challenge header");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header.as_bytes())
        .expect("challenge is base64");
    serde_json::from_slice(&decoded).expect("challenge is JSON")
}

#[test]
fn unpaid_dispatch_quotes_the_declared_resource_not_the_transport_path() {
    let mut state = OriginState::default();
    let response = respond(&mut state, &unpaid_request(PATH_SETTLED));

    assert!(response.starts_with("HTTP/1.1 402 "), "{response}");
    let challenge = decode_challenge(&response);
    // The policy binds payment to a resource IDENTITY. If the double ever quoted
    // its own loopback URL the gateway would (correctly) deny every leg, and the
    // chain would be proving nothing about the allow path.
    assert_eq!(challenge["resource"]["url"], RESOURCE_URL);
    assert_eq!(challenge["accepts"][0]["network"], CAIP2_DEVNET);
    assert_eq!(challenge["accepts"][0]["asset"], USDC_DEVNET_MINT);
    assert_eq!(challenge["accepts"][0]["payTo"], MERCHANT);
    assert_eq!(
        challenge["accepts"][0]["amount"],
        ALLOWED_ATOMIC_AMOUNT.to_string()
    );
    assert!(state.paid_requests.is_empty());
    assert!(state.side_effects.is_empty());
}

#[test]
fn the_over_cap_path_quotes_the_amount_the_policy_must_refuse() {
    let mut state = OriginState::default();
    let response = respond(&mut state, &unpaid_request(PATH_PREMIUM));

    let challenge = decode_challenge(&response);
    assert_eq!(
        challenge["accepts"][0]["amount"],
        DENIED_ATOMIC_AMOUNT.to_string()
    );
}

#[test]
fn a_replayed_proof_is_served_from_cache_without_a_second_side_effect() {
    let mut state = OriginState::default();
    let signature = transaction_signature("replay");
    let first = respond(&mut state, &paid_request(PATH_SETTLED, &signature));
    let second = respond(&mut state, &paid_request(PATH_SETTLED, &signature));

    assert!(first.starts_with("HTTP/1.1 200 "), "{first}");
    assert!(second.starts_with("HTTP/1.1 200 "), "{second}");
    // Two dispatches, ONE fulfilment: the merchant half of "a duplicate replay
    // cannot pay twice".
    assert_eq!(state.paid_requests.get(PATH_SETTLED).copied(), Some(2));
    assert_eq!(state.side_effects.get(PATH_SETTLED).copied(), Some(1));
    assert_eq!(
        header_value(&first, "payment-response"),
        header_value(&second, "payment-response"),
        "a replay returned different settlement evidence"
    );
}

#[test]
fn a_distinct_payment_produces_its_own_side_effect() {
    let mut state = OriginState::default();
    respond(
        &mut state,
        &paid_request(PATH_SETTLED, &transaction_signature("one")),
    );
    respond(
        &mut state,
        &paid_request(PATH_SETTLED, &transaction_signature("two")),
    );

    assert_eq!(state.side_effects.get(PATH_SETTLED).copied(), Some(2));
}

#[test]
fn the_ambiguous_path_delivers_the_resource_without_settlement_evidence() {
    let mut state = OriginState::default();
    let raw = respond(
        &mut state,
        &paid_request(PATH_AMBIGUOUS, &transaction_signature("ambiguous")),
    );

    let response = OriginResponse {
        status: 200,
        raw: raw.clone(),
    };
    assert!(raw.starts_with("HTTP/1.1 200 "), "{raw}");
    // The side effect happened; the money is unknown. That asymmetry is the
    // whole reason `outcome_unknown` retains the hold.
    assert_eq!(state.side_effects.get(PATH_AMBIGUOUS).copied(), Some(1));
    assert!(response.settlement_evidence().is_none());
}

#[test]
fn the_facilitator_answers_pending_first_then_converges_to_confirmed() {
    let mut state = OriginState::default();
    let signature = transaction_signature("converge");
    let request = format!(
        "GET /facilitator/settlement?signature={signature} HTTP/1.1\r\nHost: localhost\r\n\r\n"
    );

    let first: Value = serde_json::from_str(body_of(&respond(&mut state, &request))).unwrap();
    let second: Value = serde_json::from_str(body_of(&respond(&mut state, &request))).unwrap();
    let third: Value = serde_json::from_str(body_of(&respond(&mut state, &request))).unwrap();

    // A freshly submitted proof may still be propagating: the first answer must
    // NOT be a definite outcome, or the reconciler would fail a live payment.
    assert_eq!(first["status"], "pending");
    assert!(first["amount"].is_null());
    assert_eq!(second["status"], "confirmed");
    assert_eq!(second["amount"], ALLOWED_ATOMIC_AMOUNT.to_string());
    // Convergence is stable: re-running reconciliation keeps returning the same
    // definite answer rather than oscillating.
    assert_eq!(third, second);
}

fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").expect("response body").1
}

#[test]
fn settlement_evidence_short_of_the_owed_amount_is_refused() {
    let evidence = SettlementEvidence {
        transaction_signature: transaction_signature("short"),
        atomic_amount: "2499".to_string(),
        raw: String::new(),
    };

    // A merchant claiming success is never trusted about HOW MUCH it settled.
    assert!(evidence
        .expect_pays_at_least(ALLOWED_ATOMIC_AMOUNT)
        .is_err());
    assert!(SettlementEvidence {
        atomic_amount: ALLOWED_ATOMIC_AMOUNT.to_string(),
        ..evidence
    }
    .expect_pays_at_least(ALLOWED_ATOMIC_AMOUNT)
    .is_ok());
}

#[test]
fn a_non_integer_settlement_amount_is_refused_rather_than_coerced() {
    let evidence = SettlementEvidence {
        transaction_signature: transaction_signature("float"),
        // Money is never parsed as a float here: `0.0025` USDC is not 2500
        // atomic units, and silently coercing it would under-charge.
        atomic_amount: "2.5e3".to_string(),
        raw: String::new(),
    };

    assert!(evidence
        .expect_pays_at_least(ALLOWED_ATOMIC_AMOUNT)
        .is_err());
}

// The former `every_state_the_loop_can_leave_an_attempt_in_is_documented` is
// deliberately gone rather than repaired. It iterated the same eight constants
// its subject list was built from, so its own comment -- "if a new state is ever
// added ... the chain would silently accept it" -- described a failure it could
// not detect. The all-states list it defended is gone too: the chain now asserts
// the EXACT expected state per leg, which a membership test can never do.

#[test]
fn a_transfer_that_covers_what_is_owed_settles_including_an_overpayment() {
    let owed = ALLOWED_ATOMIC_AMOUNT.to_string();

    assert!(
        covers_owed_amount(&owed, &owed),
        "an exact transfer settles"
    );
    // THE #469 CASE. The x402 SVM `exact` scheme permits a transfer to EXCEED
    // the required amount, and `classify_settled_amount` returns `Covers` for it
    // (carrying the excess so the evidence stays honest). A scenario demanding
    // equality would bail! the chain on a case production deliberately settles.
    assert!(
        covers_owed_amount(&owed, "2501"),
        "a spec-valid overpayment settles"
    );
    assert!(
        covers_owed_amount(&owed, "999999999999"),
        "a large overpayment still settles"
    );
    // Leading zeros are the same integer, which a string comparison would miss.
    assert!(covers_owed_amount(&owed, "02500"));
    assert!(covers_owed_amount("02500", &owed));
}

#[test]
fn a_transfer_short_of_what_is_owed_never_settles() {
    let owed = ALLOWED_ATOMIC_AMOUNT.to_string();

    assert!(!covers_owed_amount(&owed, "2499"));
    assert!(!covers_owed_amount(&owed, "0"));
    // The mirror-direction string bug: lexically "10" < "9", so a string
    // comparison would read this 9-unit transfer as covering 10 owed.
    assert!(!covers_owed_amount("10", "9"));
    // ...and would read this one as short when it covers.
    assert!(covers_owed_amount("9", "10"));
}

#[test]
fn an_unparseable_amount_is_fail_closed_rather_than_coerced() {
    let owed = ALLOWED_ATOMIC_AMOUNT.to_string();

    // Every one of these must be refused, never silently taken as covering:
    // `2.5e3` and `2500.0` are floats (money is never parsed as a float here),
    // `-1` is signed, and the rest are not amounts at all.
    for reported in [
        "2.5e3", "2500.0", "-1", "", " 2500", "2500 ", "0x9c4", "n/a",
    ] {
        assert!(
            !covers_owed_amount(&owed, reported),
            "{reported:?} must not be read as covering {owed}"
        );
    }
    // Fail-closed on the OWED side too: an unparseable owed amount must not make
    // everything look like it covers.
    assert!(!covers_owed_amount("n/a", "2500"));
}

// ---------------------------------------------------------------------------
// The resting-state money disposition table
// ---------------------------------------------------------------------------

fn allowed_authorization() -> Authorization {
    Authorization {
        decision: DECISION_ALLOW.to_string(),
        reason_code: REASON_ALLOWED.to_string(),
        policy_revision: TENANT_REVISION,
        atomic_amount: ALLOWED_ATOMIC_AMOUNT,
        computed_credits: Some(ALLOWED_CREDITS),
        challenge_hash_hex: "c0ffee".to_string(),
        request_body_sha256_hex: "beef".to_string(),
        decision_hash_hex: "d00d".to_string(),
    }
}

/// Links for an attempt resting in `state`, holding `hold_status` (if any) and
/// carrying a capture record when `captured`.
fn links_in(state: &str, hold_status: Option<&str>, captured: bool) -> PaymentAttemptLinks {
    let leg = Leg::new("disposition", PATH_SETTLED);
    let mut attempt = leg.attempt_record(&allowed_authorization(), Some(&leg.hold_id));
    attempt.state = state.to_string();
    PaymentAttemptLinks {
        reservation: hold_status.map(|status| StoredWalletReservation {
            id: leg.hold_id.clone(),
            tenant_id: TENANT_ID.to_string(),
            amount_credits: ALLOWED_CREDITS,
            status: status.to_string(),
            expires_at_unix: CHAIN_UNIX + HOLD_TTL_SECONDS,
            settlement_id: captured.then(|| leg.hold_id.clone()),
            created_at_unix: CHAIN_UNIX,
            updated_at_unix: CHAIN_UNIX,
        }),
        settlement: captured.then(|| StoredWalletSettlement {
            id: leg.hold_id.clone(),
            tenant_id: TENANT_ID.to_string(),
            delta_credits: -ALLOWED_CREDITS,
            balance_after_credits: Some(WALLET_BALANCE_CREDITS - ALLOWED_CREDITS),
            created_at_unix: CHAIN_UNIX,
        }),
        attempt,
    }
}

#[test]
fn each_resting_state_admits_only_its_own_money_disposition() {
    // The dispositions the chain's legs actually come to rest in.
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_SETTLED,
            Some(WALLET_RESERVATION_SETTLED),
            true
        ),
        PAYMENT_ATTEMPT_SETTLED
    )
    .is_ok());
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
            Some(WALLET_RESERVATION_ACTIVE),
            false
        ),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    )
    .is_ok());
    assert!(expect_hold_disposition(
        &links_in(PAYMENT_ATTEMPT_DENIED, None, false),
        PAYMENT_ATTEMPT_DENIED
    )
    .is_ok());
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_RELEASED,
            Some(WALLET_RESERVATION_RELEASED),
            false
        ),
        PAYMENT_ATTEMPT_RELEASED
    )
    .is_ok());

    // A settled attempt whose hold was never captured is free stablecoin.
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_SETTLED,
            Some(WALLET_RESERVATION_ACTIVE),
            false
        ),
        PAYMENT_ATTEMPT_SETTLED
    )
    .is_err());
    // THE #354 MONEY RULE: ambiguity RETAINS the hold. Both ways of losing it --
    // releasing it and capturing it -- are refused.
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
            Some(WALLET_RESERVATION_RELEASED),
            false
        ),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    )
    .is_err());
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
            Some(WALLET_RESERVATION_SETTLED),
            true
        ),
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN
    )
    .is_err());
    // A refused payment must cost nothing at all.
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_DENIED,
            Some(WALLET_RESERVATION_ACTIVE),
            false
        ),
        PAYMENT_ATTEMPT_DENIED
    )
    .is_err());
    // Terminal-without-payment must give the money back, not keep it held...
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_RELEASED,
            Some(WALLET_RESERVATION_ACTIVE),
            false
        ),
        PAYMENT_ATTEMPT_RELEASED
    )
    .is_err());
    // ...and must certainly not have charged for it.
    assert!(expect_hold_disposition(
        &links_in(
            PAYMENT_ATTEMPT_FAILED,
            Some(WALLET_RESERVATION_SETTLED),
            true
        ),
        PAYMENT_ATTEMPT_FAILED
    )
    .is_err());
}

#[test]
fn a_mid_flight_or_invented_resting_state_is_refused_rather_than_ignored() {
    // These three were an unexamined `_ => {}` before: the chain would come to
    // rest with a live hold and an in-flight attempt and say nothing. An
    // authorized-but-never-finished payment is a stuck hold, which is the exact
    // failure the TTL sweeper exists for.
    for state in [
        PAYMENT_ATTEMPT_CHALLENGED,
        PAYMENT_ATTEMPT_AUTHORIZED,
        PAYMENT_ATTEMPT_SUBMITTED,
    ] {
        assert!(
            expect_hold_disposition(
                &links_in(state, Some(WALLET_RESERVATION_ACTIVE), false),
                state
            )
            .is_err(),
            "{state} must not be accepted as a resting state"
        );
    }
    assert!(expect_hold_disposition(
        &links_in("invented", Some(WALLET_RESERVATION_ACTIVE), false),
        "invented"
    )
    .is_err());
}

#[test]
fn header_lookup_is_case_insensitive_and_stops_at_the_body() {
    let raw = "HTTP/1.1 200 OK\r\nPAYMENT-RESPONSE: abc\r\n\r\nx-payment: not-a-header";

    assert_eq!(
        header_value(raw, "payment-response").as_deref(),
        Some("abc")
    );
    // A body that happens to look like a header must not be read as one.
    assert!(header_value(raw, "x-payment").is_none());
}

#[test]
fn an_undecodable_payment_proof_is_rejected_rather_than_fulfilled() {
    let mut state = OriginState::default();
    let request = format!("GET {PATH_SETTLED} HTTP/1.1\r\nX-PAYMENT: not-base64!!\r\n\r\n");

    let response = respond(&mut state, &request);

    assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    // It still counted as a paid REQUEST -- the denial assertion counts attempts
    // to pay, not successes, so a malformed proof cannot hide one.
    assert_eq!(state.paid_requests.get(PATH_SETTLED).copied(), Some(1));
    assert!(state.side_effects.is_empty());
}
