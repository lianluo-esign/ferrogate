// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Regression tests for the shared harness gateway readiness identity + port-hijack classification.

use super::*;

fn response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        body: body.to_string(),
        raw: format!("HTTP/1.1 {status}\r\n\r\n{body}"),
    }
}

fn ok(status: u16, body: &str) -> Result<HttpResponse> {
    Ok(response(status, body))
}

/// A response the way FerroGate actually writes one: every gateway-authored
/// answer carries `x-ferrogate-runtime: pingora`.
fn ferrogate_stamped(status: u16, body: &str) -> Result<HttpResponse> {
    Ok(HttpResponse {
        status,
        body: body.to_string(),
        raw: format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nx-ferrogate-runtime: pingora\r\n\r\n{body}"
        ),
    })
}

#[test]
fn readiness_accepts_only_a_live_ferrogate_healthz() {
    let healthz = ok(200, r#"{"service":"ferrogate","status":"ok"}"#);

    // The readiness *decision* — the only thing `wait_for_gateway_start` acts on —
    // must treat a live FerroGate as ready. If the gate regresses to status-only,
    // the hijack cases below go red, not this one.
    assert_eq!(
        classify_gateway_readiness(&healthz),
        GatewayReadiness::Ready
    );
    assert!(healthz_identifies_ferrogate(healthz.as_ref().unwrap()));
}

#[test]
fn readiness_flags_a_squatting_mock_models_200_as_port_hijack_not_ready() {
    // The exact #444 signature: a parallel-harness mock that won the released
    // gateway port answers with HTTP 200 and a valid body that is not FerroGate's
    // healthz (here a provider `/v1/models` list). Accepting it as ready is the
    // original flake, so the readiness decision must classify it as a port hijack
    // — never Ready — which is what drives the harness to rotate to a fresh port
    // (LocalHarness) or fail by name (scenario-owned gateways).
    let provider_models = ok(200, r#"{"object":"list","data":[{"id":"provider-chat"}]}"#);

    let verdict = classify_gateway_readiness(&provider_models);

    assert_eq!(verdict, GatewayReadiness::PortHijacked);
    assert_ne!(verdict, GatewayReadiness::Ready);
}

#[test]
fn readiness_flags_any_non_ferrogate_positive_answer_as_port_hijack() {
    let wrong_service = ok(200, r#"{"service":"ferrogate-auth","status":"ok"}"#);
    let plain_200 = ok(200, "ok");
    let mock_404 = ok(404, r#"{"error":"not found"}"#);

    assert_eq!(
        classify_gateway_readiness(&wrong_service),
        GatewayReadiness::PortHijacked
    );
    assert_eq!(
        classify_gateway_readiness(&plain_200),
        GatewayReadiness::PortHijacked
    );
    assert_eq!(
        classify_gateway_readiness(&mock_404),
        GatewayReadiness::PortHijacked
    );
}

#[test]
fn readiness_keeps_polling_when_nobody_has_bound_the_port_yet() {
    // Connection refused / read timeout before Pingora binds: keep polling the
    // same address rather than misreading the absence of an answer as a hijack.
    let refused: Result<HttpResponse> = Err(anyhow::anyhow!("connection refused"));

    assert_eq!(
        classify_gateway_readiness(&refused),
        GatewayReadiness::Pending
    );
}

#[test]
fn readiness_treats_a_ferrogate_stamped_error_answer_as_pending_not_hijack() {
    // Our own gateway can legitimately answer a readiness probe with something
    // other than a ready healthz: an unauthenticated rate limit, an IP deny, any
    // error envelope. Those bodies carry no `service` field, so only the runtime
    // header FerroGate stamps on every response it writes tells them apart from a
    // squatting mock. Misreading one as a hijack would fail the scenario at start
    // on the gateway's own answer.
    let rate_limited = ferrogate_stamped(
        429,
        r#"{"error":{"code":"unauthenticated_rate_limited","type":"ferrogate_error"}}"#,
    );

    assert_eq!(
        classify_gateway_readiness(&rate_limited),
        GatewayReadiness::Pending
    );
}

#[test]
fn readiness_treats_our_own_gateway_answering_not_ready_as_pending_not_hijack() {
    // Defensive: a body that claims `service:ferrogate` but is not a ready 200 is
    // still our process, so keep polling instead of rotating ports away from it.
    let ours_not_ready = ok(503, r#"{"service":"ferrogate","status":"starting"}"#);

    assert!(!healthz_identifies_ferrogate(
        ours_not_ready.as_ref().unwrap()
    ));
    assert_eq!(
        classify_gateway_readiness(&ours_not_ready),
        GatewayReadiness::Pending
    );
}
