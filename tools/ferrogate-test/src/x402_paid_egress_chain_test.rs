// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the x402 paid-egress chain's merchant double
// and money assertions (issue #354). These run with no gateway and no socket:
// the double's decision table is a pure function, so the properties the chain
// leans on are pinned here rather than only observed inside a scenario run.

use super::*;

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

#[test]
fn every_state_the_loop_can_leave_an_attempt_in_is_documented() {
    // The restart assertion is only as good as this list. If a new state is ever
    // added to the storage contract without being documented here, the chain
    // would silently accept it as "documented".
    for state in [
        PAYMENT_ATTEMPT_CHALLENGED,
        PAYMENT_ATTEMPT_AUTHORIZED,
        PAYMENT_ATTEMPT_SUBMITTED,
        PAYMENT_ATTEMPT_SETTLED,
        PAYMENT_ATTEMPT_DENIED,
        PAYMENT_ATTEMPT_RELEASED,
        PAYMENT_ATTEMPT_FAILED,
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
    ] {
        assert!(
            DOCUMENTED_ATTEMPT_STATES.contains(&state),
            "{state} is reachable but undocumented"
        );
    }
    assert!(!DOCUMENTED_ATTEMPT_STATES.contains(&"invented"));
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
