// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Coverage for the read-only payment-attempt Admin API (issue
// #352): routing/contract classification, the BOUNDED page-query parsing (the
// limit is not something a caller can opt out of), and the projection that
// carries the attempt -> reservation -> settlement evidence chain with money
// transported exactly as stored.

use super::*;
use ferrogate_storage::{
    StoredPaymentAttempt, StoredWalletReservation, StoredWalletSettlement,
    PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
};

fn stuck_attempt() -> StoredPaymentAttempt {
    StoredPaymentAttempt {
        id: "att-stuck".into(),
        tenant_id: "tenant-a".into(),
        project_id: Some("proj-1".into()),
        workspace_id: Some("ws-1".into()),
        run_id: Some("run-1".into()),
        worker_id: Some("worker-1".into()),
        request_id: Some("req-1".into()),
        trace_id: Some("trace-1".into()),
        method: "POST".into(),
        resource_url: "https://api.example.com/v1/tool".into(),
        request_body_hash: Some("a".repeat(64)),
        challenge_hash: "b".repeat(64),
        x402_version: 2,
        scheme: "exact".into(),
        network_caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".into(),
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
        // The full u64 range, which is exactly why the column is TEXT.
        atomic_amount: "18446744073709551615".into(),
        recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM".into(),
        credits_amount: Some(250),
        conversion_version: Some("rate-2026-07".into()),
        policy_revision: 7,
        decision: "allow".into(),
        reason_code: "x402_allowed".into(),
        hold_id: Some("hold-stuck".into()),
        state: PAYMENT_ATTEMPT_OUTCOME_UNKNOWN.into(),
        generation: 3,
        submitted_at_unix: Some(1_753_500_050),
        transaction_signature: Some("5".repeat(88)),
        settled_atomic_amount: None,
        settlement_response: Some("{\"status\":\"pending\"}".into()),
        failure_code: None,
        created_at_unix: 1_753_500_000,
        updated_at_unix: 1_753_500_060,
    }
}

// ---------------------------------------------------------------------------
// Routing + contract classification
// ---------------------------------------------------------------------------

#[test]
fn every_path_under_the_prefix_routes_to_this_group() {
    use crate::server::{api_contract::match_route_group, route_groups::RouteGroup};

    for path in [
        "/admin/v1/payment-attempts",
        "/admin/v1/payment-attempts/att-1",
        // A typo'd subpath must still land in this group so the handler answers
        // an explicit 404 rather than falling through to dynamic proxy routing.
        "/admin/v1/payment-attempts/att-1/extra",
    ] {
        assert_eq!(
            match_route_group(path),
            Some(RouteGroup::PaymentAttempt),
            "{path} must route to the payment-attempt group"
        );
    }
}

#[test]
fn only_the_documented_read_methods_are_contract_operations() {
    use crate::server::api_contract::{operation, path_is_documented};

    assert!(path_is_documented("/admin/v1/payment-attempts"));
    assert_eq!(
        operation(&Method::GET, "/admin/v1/payment-attempts").map(|op| op.operation_id.as_str()),
        Some("listPaymentAttempts")
    );
    assert_eq!(
        operation(&Method::GET, "/admin/v1/payment-attempts/att-1")
            .map(|op| op.operation_id.as_str()),
        Some("getPaymentAttemptLinks")
    );
    // The surface is read-only: an attempt is minted by a paid egress request,
    // never by an operator, so no mutating operation is documented and the
    // shared contract layer answers 405 before any handler runs.
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        assert!(
            operation(&method, "/admin/v1/payment-attempts").is_none(),
            "{method} on the collection must not be a documented operation"
        );
        assert!(
            operation(&method, "/admin/v1/payment-attempts/att-1").is_none(),
            "{method} on an attempt must not be a documented operation"
        );
    }
    for path in [
        "/admin/v1/payment-attempts",
        "/admin/v1/payment-attempts/att-1",
    ] {
        let operation = operation(&Method::GET, path).expect("documented operation");
        assert_eq!(operation.visibility, "admin");
        assert_eq!(operation.auth.kind, "bearer");
        assert_eq!(operation.auth.scope.as_deref(), Some("admin.read"));
    }
}

// ---------------------------------------------------------------------------
// Page-query parsing (acceptance box 6: the bound is structural)
// ---------------------------------------------------------------------------

#[test]
fn a_listing_without_a_tenant_is_refused() {
    assert_eq!(
        page_query(None).unwrap_err(),
        PaymentAttemptQueryError::MissingTenant
    );
    assert_eq!(
        page_query(Some("limit=10")).unwrap_err(),
        PaymentAttemptQueryError::MissingTenant
    );
    // A blank value is absent, not an empty-id tenant.
    assert_eq!(
        page_query(Some("tenant_id=")).unwrap_err(),
        PaymentAttemptQueryError::MissingTenant
    );
}

/// The bound cannot be opted out of. An omitted `limit` defaults, an oversized
/// one is clamped, and there is no spelling that asks for the whole table.
///
/// Delete the clamp in `PaymentAttemptQuery::new` and the `limit=100000` case
/// goes red.
#[test]
fn the_page_limit_is_defaulted_and_clamped_never_unbounded() {
    let (tenant, query) = page_query(Some("tenant_id=tenant-a")).unwrap();
    assert_eq!(tenant, "tenant-a");
    assert_eq!(query.limit(), PAYMENT_ATTEMPT_PAGE_DEFAULT_LIMIT);
    assert!(query.cursor().is_none());

    let (_, query) = page_query(Some("tenant_id=tenant-a&limit=7")).unwrap();
    assert_eq!(query.limit(), 7);

    let (_, query) = page_query(Some("tenant_id=tenant-a&limit=100000")).unwrap();
    assert_eq!(
        query.limit(),
        PAYMENT_ATTEMPT_PAGE_MAX_LIMIT,
        "an oversized limit must be clamped, not honoured"
    );
}

/// A malformed page parameter is a 400, never a silent default: a caller sending
/// `limit=abc` must learn its paging is wrong rather than quietly receive a
/// different page size, and a malformed cursor must not restart at page one
/// (which would loop a paging client forever).
#[test]
fn malformed_pagination_is_refused_rather_than_silently_defaulted() {
    for bad_limit in ["abc", "0", "-1", "1.5"] {
        let error = page_query(Some(&format!("tenant_id=tenant-a&limit={bad_limit}"))).unwrap_err();
        assert_eq!(
            error,
            PaymentAttemptQueryError::InvalidLimit(bad_limit.to_string()),
            "limit={bad_limit} must be refused"
        );
        assert_eq!(error.code(), "invalid_pagination");
    }
    for bad_cursor in ["abc", "100", "100:", "not-a-number:att-1"] {
        let error =
            page_query(Some(&format!("tenant_id=tenant-a&cursor={bad_cursor}"))).unwrap_err();
        assert_eq!(
            error,
            PaymentAttemptQueryError::InvalidCursor(bad_cursor.to_string()),
            "cursor={bad_cursor} must be refused"
        );
        assert_eq!(error.code(), "invalid_pagination");
    }
}

#[test]
fn a_well_formed_cursor_is_carried_through_verbatim() {
    let (_, query) =
        page_query(Some("tenant_id=tenant-a&limit=5&cursor=1753500000:att-9")).unwrap();
    assert_eq!(query.limit(), 5);
    assert_eq!(
        query.cursor(),
        Some(&PaymentAttemptCursor {
            created_at_unix: 1_753_500_000,
            id: "att-9".into()
        })
    );
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/// The evidence chain acceptance box 5 requires: the stuck `outcome_unknown`
/// attempt, its still-live hold, and (here) no settlement, all readable in one
/// response — with the state reported as `outcome_unknown` rather than
/// failed/released, and the hold still `active`.
#[test]
fn the_links_projection_carries_the_attempt_hold_and_settlement_chain() {
    let links = PaymentAttemptLinks {
        attempt: stuck_attempt(),
        reservation: Some(StoredWalletReservation {
            id: "hold-stuck".into(),
            tenant_id: "tenant-a".into(),
            amount_credits: 250,
            status: "active".into(),
            expires_at_unix: 1_753_500_600,
            settlement_id: None,
            created_at_unix: 1_753_500_000,
            updated_at_unix: 1_753_500_000,
        }),
        settlement: None,
    };
    let view = admin_payment_attempt_links(&links);

    assert_eq!(view.object, "payment_attempt_links");
    assert_eq!(view.attempt.state, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN);
    assert_eq!(view.attempt.generation, 3);
    let reservation = view.reservation.as_ref().expect("hold is linked");
    assert_eq!(
        reservation.status, "active",
        "an outcome_unknown attempt RETAINS its hold; the surface must say so"
    );
    assert_eq!(reservation.amount_credits, 250);
    assert!(
        view.settlement.is_none(),
        "nothing was captured, so no settlement is reported"
    );

    // The whole point of the surface: the operator can see the transaction
    // evidence that makes this attempt ambiguous rather than failed.
    assert_eq!(view.attempt.transaction_signature, Some("5".repeat(88)));
    assert_eq!(view.attempt.settled_atomic_amount, None);
    assert_eq!(view.attempt.failure_code, None);
}

/// Money is transported exactly as stored. `atomic_amount` must stay a decimal
/// STRING through serialization — rendered as a JSON number, `u64::MAX` would
/// come back as 18446744073709552000.
#[test]
fn amounts_serialize_as_exact_strings_never_as_json_numbers() {
    let view = admin_payment_attempt(&stuck_attempt());
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["atomic_amount"], "18446744073709551615");
    assert!(
        json["atomic_amount"].is_string(),
        "a u64 atomic amount must not be a JSON number: {json}"
    );
    assert_eq!(json["credits_amount"], 250);
    assert_eq!(json["object"], "payment_attempt");
}

/// The settled leg: the captured settlement is reported with its exact ledger
/// delta, and the reservation reports the settlement it produced.
#[test]
fn the_settled_leg_reports_its_capture() {
    let mut attempt = stuck_attempt();
    attempt.state = ferrogate_storage::PAYMENT_ATTEMPT_SETTLED.into();
    attempt.settled_atomic_amount = Some("18446744073709551615".into());
    let links = PaymentAttemptLinks {
        attempt,
        reservation: Some(StoredWalletReservation {
            id: "hold-stuck".into(),
            tenant_id: "tenant-a".into(),
            amount_credits: 250,
            status: "settled".into(),
            expires_at_unix: 1_753_500_600,
            settlement_id: Some("hold-stuck".into()),
            created_at_unix: 1_753_500_000,
            updated_at_unix: 1_753_500_100,
        }),
        settlement: Some(StoredWalletSettlement {
            id: "hold-stuck".into(),
            tenant_id: "tenant-a".into(),
            delta_credits: -250,
            balance_after_credits: Some(750),
            created_at_unix: 1_753_500_100,
        }),
    };
    let view = admin_payment_attempt_links(&links);
    let settlement = view.settlement.as_ref().expect("captured");
    assert_eq!(settlement.delta_credits, -250);
    assert_eq!(settlement.balance_after_credits, Some(750));
    assert_eq!(
        view.reservation.as_ref().map(|r| r.settlement_id.clone()),
        Some(Some("hold-stuck".to_string())),
        "the hold references the settlement it produced"
    );
}
