// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The x402 seam of the worker's governed REST response path (#353).
//!
//! Read the honesty note first. The executor these tests drive
//! (`run_authorized_rest_action`) is a LOOPBACK SMOKE executor: `http://` only,
//! loopback only, `GET` only, and its sole non-test caller points a hardcoded
//! action at a listener it spawns itself. So these tests prove the functions are
//! correct on a real socket; they do NOT prove the 402 branch runs in the shipped
//! binary, because it cannot — no x402 merchant is reachable from here. See the
//! boundary note in `x402_client.rs`.
//!
//! What survives that caveat intact is everything below that is
//! executor-independent: the redaction ordering, the wire-stage classification,
//! and the typed carrier that ships it across the process boundary. Those apply
//! to whatever real egress executor eventually exists.
//!
//! Three properties are proven here against live loopback sockets, because all
//! three are properties of a wired code path rather than of a pure function:
//!
//! 1. **Redaction.** Bearer material never reaches recorded evidence.
//!    `run_authorized_rest_action` records an excerpt of the raw HTTP response —
//!    headers included — into `rest.requested` event metadata and into the
//!    self-hosted governed-workload output. A `PAYMENT-SIGNATURE` there is a
//!    signed, submittable SVM transaction; an `authorization` or `set-cookie`
//!    there is a live credential. Public x402 protocol evidence
//!    (`PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`) must survive, or the audit trail
//!    #354 depends on is destroyed.
//!
//! 2. **Wire stage.** A failed dispatch is classified by how far the request
//!    got, and the classification is asymmetric on purpose: only a failure
//!    PROVEN to be pre-send may release a wallet hold. Every other outcome —
//!    including the genuinely ambiguous ones — must retain it.
//!
//! 3. **The classification crosses the process boundary as a discriminant.**
//!    The gateway owns the durable attempt API and runs in another process. If
//!    the only carrier were the English suffix on the error message, the gateway
//!    would have to substring-match a sentence to choose between releasing and
//!    retaining a wallet hold, and any reword would silently flip every hold to
//!    the wrong edge. So the stage is written into worker event metadata as a
//!    frozen token and read back through a typed, fail-safe accessor — asserted
//!    here across the real management-protocol serialization, not in memory.
//!
//! Plus the worker's non-custodial `402` detection: it surfaces the challenge
//! and refuses. It never pays, and it never replays.

use std::sync::mpsc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ferrogate_runtime::{
    AgentWorkerFrameworkEventResult, EGRESS_HOLD_DISPOSITION_KEY, EGRESS_REQUEST_WIRE_STAGE_KEY,
};
use serde_json::json;

use super::*;
use crate::x402_client::{HoldDisposition, RequestWireStage, REDACTED_HEADER_VALUE};

// Golden devnet payment terms, matching `x402_client_test.rs` so the two files
// describe the same merchant. Only the resource URL varies, because the
// authorized egress URL is a loopback address chosen at runtime.
const DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
const ATOMIC_AMOUNT: u64 = 2500;

/// Stand-in for a signed SVM transaction. Long enough that a 512-character
/// excerpt of an unredacted response would still carry a usable prefix of it,
/// which is what makes the redact-before-truncate ordering load-bearing.
fn proof_bytes() -> String {
    "PROOFSIGNATUREDONOTLOG".repeat(24)
}

fn x402_session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "x402-session".to_string(),
        run_id: "x402-run".to_string(),
        tenant_id: "x402-tenant".to_string(),
        workspace_id: "x402-workspace".to_string(),
        worker_id: "x402-worker".to_string(),
        isolation_backend: "firecracker".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::Managed,
    }
}

fn allowing_gate() -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
        class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

fn rest_action(endpoint: SocketAddr, timeout_millis: u64) -> ManagedRestAction {
    ManagedRestAction {
        method: "GET".to_string(),
        url: format!("http://{endpoint}/authorized"),
        headers_policy: "deny_credentials".to_string(),
        body_policy: "empty_body".to_string(),
        timeout_millis,
        retry_limit: 0,
        resolved_ips: vec!["127.0.0.1".to_string()],
        redirect_chain: Vec::new(),
    }
}

/// Base64 `PAYMENT-REQUIRED` challenge for `resource_url`, on the golden devnet
/// terms. Built rather than checked in because the authorized loopback URL is
/// only known at runtime.
fn challenge_header(resource_url: &str) -> String {
    let challenge = json!({
        "x402Version": 2,
        "resource": { "url": resource_url, "mimeType": "application/json" },
        "accepts": [{
            "scheme": "exact",
            "network": DEVNET_CAIP2,
            "amount": ATOMIC_AMOUNT.to_string(),
            "asset": MINT,
            "payTo": RECIPIENT,
            "maxTimeoutSeconds": 120,
            "extra": { "feePayer": FEE_PAYER },
        }],
    });
    BASE64_STANDARD.encode(challenge.to_string().as_bytes())
}

/// A loopback origin serving a canned raw response, which records every request
/// it receives — so "the worker never replayed" is observed at the origin
/// rather than inferred from a return value.
///
/// The accept loop is detached: after the worker's single synchronous dispatch
/// returns, any replay would already have been recorded, so the channel can be
/// drained without blocking.
struct CannedOrigin {
    endpoint: SocketAddr,
    requests: mpsc::Receiver<String>,
}

impl CannedOrigin {
    fn spawn(response: String) -> Self {
        Self::spawn_with(|_| response)
    }

    /// Bind first, then let the caller build a response that names the bound
    /// address — a challenge must be able to point at the very URL the action
    /// authorizes.
    fn spawn_with(build_response: impl FnOnce(SocketAddr) -> String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let response = build_response(endpoint);
        let (tx, requests) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = [0_u8; 2048];
                let read = stream.read(&mut buffer).unwrap_or(0);
                if tx
                    .send(String::from_utf8_lossy(&buffer[..read]).to_string())
                    .is_err()
                {
                    break;
                }
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
            }
        });
        Self { endpoint, requests }
    }

    fn served_requests(&self) -> Vec<String> {
        self.requests.try_iter().collect()
    }
}

fn http_response(status_line: &str, headers: &[(&str, String)], body: &str) -> String {
    let mut response = format!("{status_line}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("content-length: {}\r\n", body.len()));
    response.push_str("connection: close\r\n\r\n");
    response.push_str(body);
    response
}

/// Drive the REAL governed path end to end and return the `rest.requested`
/// event metadata the worker recorded.
fn rest_event_metadata(
    action: ManagedRestAction,
) -> Result<BTreeMap<String, String>, GovernedRestRejection> {
    let events = execute_governed_rest_action(&allowing_gate(), x402_session(), action, false)?;
    Ok(events[1].metadata.clone())
}

/// Drive the REAL governed path against a target that cannot answer and return
/// the typed rejection.
fn rest_rejection(action: ManagedRestAction) -> GovernedRestRejection {
    execute_governed_rest_action(&allowing_gate(), x402_session(), action, false).unwrap_err()
}

/// An address with nothing listening on it. Binding then dropping guarantees the
/// port was free, so the connect is refused rather than answered.
fn unbound_endpoint() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener);
    endpoint
}

// ---------------------------------------------------------------------------
// 1. Redaction on the real response path
// ---------------------------------------------------------------------------

/// The load-bearing leak test: a response carrying a signed payment proof and
/// two live credentials must leave none of them in recorded evidence.
///
/// Reverting `response_excerpt` to `response.chars().take(512).collect()` makes
/// this fail on the first assertion.
#[test]
fn recorded_rest_evidence_never_carries_bearer_material() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[
            ("PAYMENT-SIGNATURE", proof_bytes()),
            ("authorization", "Bearer super-secret-token".to_string()),
            ("set-cookie", "session=abc123; HttpOnly".to_string()),
            ("content-type", "text/plain".to_string()),
        ],
        "ferrogate governed rest smoke\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();
    let excerpt = metadata.get("response_excerpt").expect("excerpt recorded");

    assert!(
        !excerpt.contains("PROOFSIGNATUREDONOTLOG"),
        "signed payment proof leaked into recorded evidence: {excerpt}"
    );
    assert!(
        !excerpt.contains("super-secret-token"),
        "authorization credential leaked into recorded evidence: {excerpt}"
    );
    assert!(
        !excerpt.contains("abc123"),
        "session cookie leaked into recorded evidence: {excerpt}"
    );
    // The header NAMES survive, so an operator can still see that a proof and
    // credentials were present.
    assert!(excerpt.contains("PAYMENT-SIGNATURE"), "{excerpt}");
    assert!(excerpt.contains("authorization"), "{excerpt}");
    assert_eq!(
        excerpt.matches(REDACTED_HEADER_VALUE).count(),
        3,
        "expected exactly the three bearer headers redacted: {excerpt}"
    );
    // Non-bearer headers and the body are untouched.
    assert!(excerpt.contains("text/plain"), "{excerpt}");
    assert!(
        excerpt.contains("ferrogate governed rest smoke"),
        "{excerpt}"
    );
}

/// Redaction must not become censorship: the two PUBLIC x402 protocol headers
/// are the audit trail that answers "why was this payment made and what
/// happened to it?" (#354). Over-redacting them destroys evidence and protects
/// nothing — neither is bearer material.
#[test]
fn public_x402_protocol_evidence_survives_redaction() {
    let settlement = BASE64_STANDARD.encode(br#"{"success":true}"#);
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[
            ("PAYMENT-RESPONSE", settlement.clone()),
            ("content-type", "text/plain".to_string()),
        ],
        "paid resource\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();
    let excerpt = metadata.get("response_excerpt").expect("excerpt recorded");

    assert!(
        excerpt.contains(&settlement),
        "settlement evidence must be preserved verbatim: {excerpt}"
    );
    assert!(!excerpt.contains(REDACTED_HEADER_VALUE), "{excerpt}");
}

/// The excerpt is capped at 512 characters and the proof sits FIRST, exactly
/// where a surviving prefix would land. Not one character of it may be
/// recorded.
///
/// The name is #353's and is kept for continuity, but the claim it was written
/// with — that redaction must precede truncation or a usable prefix survives —
/// was withdrawn in the #526 rework: this redactor is line-anchored and
/// prefix-stable, so swapping the two steps changes only the LENGTH of the
/// record, and this test does NOT fail under that swap. See the module docs on
/// `recorded_evidence.rs` for the invariant that makes the order irrelevant and
/// for what would make it load-bearing again. What this test does hold, and it
/// is the assertion that matters, is that the recorded `response_excerpt`
/// carries no prefix of the proof at all.
#[test]
fn redaction_precedes_truncation_so_no_proof_prefix_survives() {
    let proof = proof_bytes();
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[("PAYMENT-SIGNATURE", proof.clone())],
        "body\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();
    let excerpt = metadata.get("response_excerpt").expect("excerpt recorded");

    // Not just the whole proof — no prefix of it either.
    for prefix_len in [8, 16, 32, 64] {
        assert!(
            !excerpt.contains(&proof[..prefix_len]),
            "a {prefix_len}-char proof prefix survived truncation: {excerpt}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Non-custodial 402 detection
// ---------------------------------------------------------------------------

/// A merchant demanding payment gets a typed refusal naming the challenge, and
/// exactly one request at the origin. The worker surfaces; it does not pay and
/// does not replay.
#[test]
fn a_payment_required_challenge_is_surfaced_and_refused_not_paid() {
    let origin = CannedOrigin::spawn_with(|endpoint| {
        http_response(
            "HTTP/1.1 402 Payment Required",
            &[(
                "PAYMENT-REQUIRED",
                challenge_header(&format!("http://{endpoint}/authorized")),
            )],
            "payment required\n",
        )
    });

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(
        message.contains("will not self-authorize"),
        "the refusal must say the worker does not authorize its own spend: {message}"
    );
    assert!(
        message.contains(&ATOMIC_AMOUNT.to_string()),
        "the refusal must name the amount demanded: {message}"
    );
    assert!(
        message.contains(RECIPIENT),
        "the refusal must name the payee: {message}"
    );
    assert!(
        message.contains(DEVNET_CAIP2),
        "the refusal must name the network: {message}"
    );
    // No proof, no signer, no key material anywhere in the refusal.
    assert!(!message.contains("PAYMENT-SIGNATURE"), "{message}");

    assert_eq!(
        origin.served_requests().len(),
        1,
        "a 402 must not trigger a replay"
    );
}

/// A challenge whose protected resource is NOT the egress URL FerroGate
/// authorized is a payment redirect: it fails closed, and the refusal says so.
#[test]
fn a_redirected_payment_challenge_fails_closed() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[(
            "PAYMENT-REQUIRED",
            challenge_header("https://attacker.example.com/drain"),
        )],
        "payment required\n",
    ));

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(
        message.contains("failed closed"),
        "a redirected challenge must fail closed: {message}"
    );
    assert!(
        message.contains("attacker.example.com"),
        "the refusal must name the resource it refused: {message}"
    );
}

/// A 402 with no challenge header at all is still a refusal — not a payment,
/// not a panic.
#[test]
fn a_payment_required_without_a_challenge_header_fails_closed() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[("content-type", "text/plain".to_string())],
        "pay me somehow\n",
    ));

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(
        message.contains("without a PAYMENT-REQUIRED challenge header"),
        "{message}"
    );
    assert!(message.contains("nothing was paid"), "{message}");
}

/// An unparseable challenge is refused, and the refusal does not echo the
/// merchant's raw header back — it is attacker-controlled input.
#[test]
fn a_malformed_payment_challenge_fails_closed() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[("PAYMENT-REQUIRED", "not-base64-at-all!!".to_string())],
        "payment required\n",
    ));

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed closed"), "{message}");
    assert!(!message.contains("not-base64-at-all"), "{message}");
}

// ---------------------------------------------------------------------------
// 3. Wire stage → hold disposition, and its asymmetry
// ---------------------------------------------------------------------------

/// The ONLY case that may release a hold: the connection never came up, so no
/// request byte can have reached anyone.
#[test]
fn a_refused_connection_is_proven_unsent_and_may_release_the_hold() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener); // nothing is listening now

    let failure = run_authorized_rest_action(&rest_action(endpoint, 200)).unwrap_err();

    assert_eq!(failure.stage, RequestWireStage::ProvenNotSent);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::ReleasableBeforeSubmission
    );
}

/// Validation failures are proven pre-send too — the socket is never opened.
#[test]
fn a_rejected_action_is_proven_unsent() {
    let mut action = rest_action("127.0.0.1:9".parse().unwrap(), 200);
    action.method = "POST".to_string();

    let failure = run_authorized_rest_action(&action).unwrap_err();

    assert_eq!(failure.stage, RequestWireStage::ProvenNotSent);
}

/// The request was fully written and the peer went silent. The proof — if #381
/// had attached one — is on the wire and may have settled, so the hold must be
/// RETAINED, never released.
///
/// The peer is released by a CHANNEL, not a sleep (acceptance box 6): it holds
/// the connection open silently until the client's read timeout has already
/// fired and `run_authorized_rest_action` has returned. There is no timing
/// assumption left to be wrong on a loaded box.
#[test]
fn a_silent_peer_after_a_complete_request_retains_the_hold() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (release, released) = mpsc::channel::<()>();
    let accepted = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // Silent for as long as the client is still reading; the sender side is
        // only signalled once the client's read timeout has expired.
        let _ = released.recv();
        drop(stream);
    });

    let failure = run_authorized_rest_action(&rest_action(endpoint, 60)).unwrap_err();
    release.send(()).unwrap();

    assert_eq!(failure.stage, RequestWireStage::SentOrUnknown);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );

    accepted.join().unwrap();
}

/// The explicitly AMBIGUOUS case, which is the one that matters.
///
/// The peer accepts and tears the connection down without reading or replying,
/// so depending on kernel buffering and scheduling the client may fail inside
/// `write_all`, inside `shutdown`, or by reading an empty response — and it
/// cannot tell which bytes, if any, the peer consumed.
///
/// Whichever syscall loses the race, the classification must be identical and
/// must be RETAIN. That invariance across interleavings is the assertion: there
/// is no timing in which an ambiguous teardown yields a release.
#[test]
fn an_ambiguous_teardown_always_retains_the_hold() {
    for attempt in 0..8 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let accepted = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream); // neither read nor reply
        });

        let failure = run_authorized_rest_action(&rest_action(endpoint, 200)).unwrap_err();

        assert_eq!(
            failure.stage,
            RequestWireStage::SentOrUnknown,
            "attempt {attempt}: an ambiguous teardown must never be classified as unsent \
             (error was: {})",
            failure.error
        );
        assert_eq!(
            failure.stage.hold_disposition(),
            HoldDisposition::RetainOutcomeUnknown,
            "attempt {attempt}"
        );

        let _ = accepted.join();
    }
}

/// A 402 is by definition post-send. Had the #381 binding attached a proof to
/// this dispatch, the merchant received it, so this may never release.
#[test]
fn a_payment_required_response_retains_the_hold() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[("content-type", "text/plain".to_string())],
        "pay me\n",
    ));

    let failure = run_authorized_rest_action(&rest_action(origin.endpoint, 1_000)).unwrap_err();

    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
}

/// The stage is not test-only bookkeeping: it reaches the operator. A refused
/// connection and a silent peer produce visibly different answers to "did my
/// request actually reach the upstream?" on the very same code path.
#[test]
fn the_wire_stage_reaches_the_operator_facing_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let unbound = listener.local_addr().unwrap();
    drop(listener);
    let refused = run_authorized_rest_action(&rest_action(unbound, 200))
        .unwrap_err()
        .into_error()
        .to_string();
    assert!(
        refused.contains("no request byte reached the upstream"),
        "{refused}"
    );

    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 500 Internal Server Error",
        &[],
        "boom\n",
    ));
    let sent = run_authorized_rest_action(&rest_action(origin.endpoint, 1_000))
        .unwrap_err()
        .into_error()
        .to_string();
    assert!(
        sent.contains("the request may have reached the upstream"),
        "{sent}"
    );
}

/// The structural guarantee behind all of the above: a failure nobody
/// explicitly classified converts to RETAIN. Adding a new `?` to the dispatch
/// without thinking about the wire stage is therefore safe by construction;
/// only a deliberate `proven_not_sent` can authorize a release.
///
/// Flipping `RequestWireStage::default()` to `ProvenNotSent` fails this test and
/// `an_ambiguous_teardown_always_retains_the_hold` together.
#[test]
fn an_unclassified_dispatch_failure_defaults_to_retaining_the_hold() {
    let failure: RestDispatchFailure =
        FrameworkAdapterError::CapabilityDenied("something new and unclassified".to_string())
            .into();

    assert_eq!(failure.stage, RequestWireStage::SentOrUnknown);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
    assert_eq!(RequestWireStage::default(), RequestWireStage::SentOrUnknown);
}

// ---------------------------------------------------------------------------
// 4. The classification crosses the process boundary as a DISCRIMINANT
// ---------------------------------------------------------------------------
//
// Everything in section 3 proves the worker classifies correctly in-process.
// None of it proved the classification is consumable: `into_error` discards the
// stage and appends a sentence, so a gateway wanting the RELEASE edge would have
// had to substring-match prose on a money decision. These tests assert the typed
// carrier instead.

/// The only case that may release a hold, delivered as a typed discriminant on
/// the worker's own event surface — not as a sentence.
#[test]
fn a_proven_unsent_dispatch_ships_a_typed_release_discriminant() {
    let rejection = rest_rejection(rest_action(unbound_endpoint(), 200));

    assert_eq!(rejection.wire_stage, RequestWireStage::ProvenNotSent);
    assert_eq!(
        rejection.hold_disposition(),
        HoldDisposition::ReleasableBeforeSubmission
    );
    // What a #381 consumer actually reads: two frozen tokens on the event map.
    assert_eq!(
        rejection
            .event
            .metadata
            .get(EGRESS_REQUEST_WIRE_STAGE_KEY)
            .map(String::as_str),
        Some("proven_not_sent"),
        "metadata: {:?}",
        rejection.event.metadata
    );
    assert_eq!(
        rejection
            .event
            .metadata
            .get(EGRESS_HOLD_DISPOSITION_KEY)
            .map(String::as_str),
        Some("releasable_before_submission")
    );
    assert_eq!(
        RequestWireStage::from_event_metadata(&rejection.event.metadata),
        RequestWireStage::ProvenNotSent
    );
}

/// The ambiguous dispatch ships the RETAIN discriminant. Same surface, opposite
/// edge, so the two are distinguishable by a consumer that never reads prose.
#[test]
fn an_ambiguous_dispatch_ships_a_typed_retain_discriminant() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 500 Internal Server Error",
        &[],
        "boom\n",
    ));

    let rejection = rest_rejection(rest_action(origin.endpoint, 1_000));

    assert_eq!(rejection.wire_stage, RequestWireStage::SentOrUnknown);
    assert_eq!(
        rejection
            .event
            .metadata
            .get(EGRESS_REQUEST_WIRE_STAGE_KEY)
            .map(String::as_str),
        Some("sent_or_unknown")
    );
    assert_eq!(
        RequestWireStage::from_event_metadata(&rejection.event.metadata).hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
}

/// The load-bearing boundary test: lower the event onto the management wire
/// exactly as the worker ships it to the control plane, serialize, deserialize
/// on the receiving side, and read the edge off the reconstructed map.
///
/// This is the step nothing previously covered. Both edges are checked, so a
/// carrier that always answers "retain" does not pass either.
#[test]
fn the_hold_edge_survives_the_management_wire_in_both_directions() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 500 Internal Server Error",
        &[],
        "boom\n",
    ));
    let cases = [
        (
            rest_rejection(rest_action(unbound_endpoint(), 200)),
            RequestWireStage::ProvenNotSent,
            HoldDisposition::ReleasableBeforeSubmission,
        ),
        (
            rest_rejection(rest_action(origin.endpoint, 1_000)),
            RequestWireStage::SentOrUnknown,
            HoldDisposition::RetainOutcomeUnknown,
        ),
    ];

    for (rejection, expected_stage, expected_disposition) in cases {
        let shipped = crate::events::NormalizedWorkerEvent::from(&*rejection.event)
            .into_management_event_result();
        let on_the_wire = serde_json::to_string(&shipped).unwrap();
        let received: AgentWorkerFrameworkEventResult =
            serde_json::from_str(&on_the_wire).expect("the control plane parses the event");

        let stage = RequestWireStage::from_wire_token(
            received
                .metadata
                .get(EGRESS_REQUEST_WIRE_STAGE_KEY)
                .map(String::as_str),
        );
        assert_eq!(stage, expected_stage, "wire form: {on_the_wire}");
        assert_eq!(stage.hold_disposition(), expected_disposition);
        assert_eq!(
            received
                .metadata
                .get(EGRESS_HOLD_DISPOSITION_KEY)
                .map(String::as_str),
            Some(expected_disposition.as_wire_token())
        );
    }
}

/// The point of the whole exercise: rewording the diagnostics cannot move the
/// money edge.
///
/// The event's `message` and its `failure_reason` are replaced with text that
/// says the OPPOSITE of the truth — the retain case is relabelled with the
/// release sentence and vice versa — and the edge each one yields is unchanged,
/// because it is read off the typed key. A consumer implemented by substring
/// matching would report both of these backwards.
#[test]
fn rewording_the_diagnostics_cannot_flip_the_hold_edge() {
    const RELEASE_PROSE: &str = "no request byte reached the upstream";
    const RETAIN_PROSE: &str = "the request may have reached the upstream";

    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 500 Internal Server Error",
        &[],
        "boom\n",
    ));
    // Each rejection is paired with the prose of the OTHER edge.
    let cases = [
        (
            rest_rejection(rest_action(unbound_endpoint(), 200)),
            RETAIN_PROSE,
            RequestWireStage::ProvenNotSent,
            HoldDisposition::ReleasableBeforeSubmission,
        ),
        (
            rest_rejection(rest_action(origin.endpoint, 1_000)),
            RELEASE_PROSE,
            RequestWireStage::SentOrUnknown,
            HoldDisposition::RetainOutcomeUnknown,
        ),
    ];

    for (mut rejection, misleading_prose, expected_stage, expected_disposition) in cases {
        // Sanity: the honest prose really is there before it is corrupted, so
        // this test cannot pass by the prose having quietly disappeared.
        let honest = rejection.error.to_string();
        assert!(
            honest.contains(RELEASE_PROSE) || honest.contains(RETAIN_PROSE),
            "the human diagnostic should still say how far the request got: {honest}"
        );

        rejection.event.message = Some(misleading_prose.to_string());
        rejection.event.metadata.insert(
            "failure_reason".to_string(),
            format!("managed REST action failed ({misleading_prose})"),
        );

        let stage = RequestWireStage::from_event_metadata(&rejection.event.metadata);
        assert_eq!(
            stage, expected_stage,
            "the edge must come from the typed key, not the prose"
        );
        assert_eq!(stage.hold_disposition(), expected_disposition);
    }
}

/// A completed dispatch carries the discriminant too, so a consumer never has to
/// treat "key absent" as a meaningful state. (It is safe if it does: absent
/// reads as retain.)
#[test]
fn a_completed_dispatch_also_records_the_wire_stage() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[("content-type", "text/plain".to_string())],
        "served\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();

    assert_eq!(
        RequestWireStage::from_event_metadata(&metadata),
        RequestWireStage::SentOrUnknown,
        "a completed dispatch reached the upstream by definition"
    );
    assert_eq!(
        metadata
            .get(EGRESS_HOLD_DISPOSITION_KEY)
            .map(String::as_str),
        Some("retain_outcome_unknown")
    );
}

/// A gate refusal never opened a socket, so it is provably unsent — and it says
/// so on the typed key, without borrowing the dispatch path's prose.
#[test]
fn a_gate_refusal_is_typed_as_proven_unsent() {
    let denying_gate =
        RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

    let rejection = execute_governed_rest_action(
        &denying_gate,
        x402_session(),
        rest_action(unbound_endpoint(), 200),
        false,
    )
    .unwrap_err();

    assert_eq!(rejection.wire_stage, RequestWireStage::ProvenNotSent);
    assert_eq!(
        RequestWireStage::from_event_metadata(&rejection.event.metadata),
        RequestWireStage::ProvenNotSent
    );
    assert_eq!(
        rejection
            .event
            .metadata
            .get("executed_after_authorization")
            .map(String::as_str),
        Some("false"),
        "a refused action was never executed"
    );
}

// ---------------------------------------------------------------------------
// 4. Box 8 of #354: the merchant does not get to size this process's heap
// ---------------------------------------------------------------------------

/// A merchant that keeps serving until the client stops reading, counting the
/// bytes it actually got onto the wire.
///
/// The count is what makes the test non-vacuous. The refusal message alone
/// cannot distinguish a bounded read from `read_to_end` followed by a length
/// check — both refuse — so the assertion has to be about how much the peer was
/// ABLE to push, not about the error text.
struct FirehoseOrigin {
    endpoint: SocketAddr,
    served_bytes: mpsc::Receiver<usize>,
}

impl FirehoseOrigin {
    /// Serves `200 OK` with a `body_bytes`-long body written in 64 KiB chunks,
    /// stopping early if the client hangs up. Nothing here allocates the body:
    /// one chunk is reused, so an unbounded reader is what pays for the size.
    fn spawn(body_bytes: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (tx, served_bytes) = mpsc::channel();
        thread::spawn(move || {
            let Some(Ok(mut stream)) = listener.incoming().next() else {
                return;
            };
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n\
                 content-length: {body_bytes}\r\nconnection: close\r\n\r\n"
            );
            let mut written = 0_usize;
            if stream.write_all(head.as_bytes()).is_ok() {
                written += head.len();
                let chunk = vec![b'a'; 64 * 1024];
                while written < body_bytes {
                    let take = chunk.len().min(body_bytes - written);
                    // A broken pipe here is the SUCCESS signal: the reader
                    // stopped at its bound and hung up.
                    if stream.write_all(&chunk[..take]).is_err() {
                        break;
                    }
                    written += take;
                }
            }
            let _ = tx.send(written);
        });
        Self {
            endpoint,
            served_bytes,
        }
    }

    /// Bytes the merchant got onto the wire before the reader hung up. Waits for
    /// the serving thread rather than sampling it, so there is no timing race.
    fn served_bytes(self) -> usize {
        self.served_bytes
            .recv_timeout(Duration::from_secs(30))
            .expect("the merchant thread reports what it managed to serve")
    }
}

/// The paid-egress read is bounded by FerroGate's cap, not by the merchant's
/// `content-length`.
///
/// Before this was bounded, `run_authorized_rest_action` called
/// `stream.read_to_end` with no cap and the only limit — the 512-character
/// excerpt — was applied AFTER the whole body was already resident. Measured
/// `VmHWM` deltas on the unbounded path were +4 MB / +65 MB / +196 MB for served
/// bodies of 1 / 64 / 256 MiB: peak RSS tracked the served body roughly 1:1, so
/// a merchant chose the worker's heap size.
///
/// Two independent assertions, because either alone is satisfiable by code that
/// does not bound the read:
///
///  1. the dispatch is REFUSED by name, and
///  2. the merchant could not push the whole body — it is stopped near the cap,
///     nowhere near the 64 MiB it advertised.
///
/// Deleting the `Read::take` reddens (2) while leaving (1) green, which is
/// exactly the mutation this test exists to catch.
#[test]
fn a_merchant_cannot_make_the_worker_buffer_more_than_the_message_cap() {
    const SERVED_BYTES: usize = 64 * 1024 * 1024;
    let origin = FirehoseOrigin::spawn(SERVED_BYTES);
    let endpoint = origin.endpoint;

    let failure = run_authorized_rest_action(&rest_action(endpoint, 30_000)).unwrap_err();

    let message = failure.error.to_string();
    assert!(
        message.contains("exceeds the") && message.contains("maximum message size"),
        "an over-cap response must be refused by name: {message}"
    );
    // The request is on the wire and the merchant may have served (and charged
    // for) the resource, so refusing to buffer it is never grounds to release a
    // hold.
    assert_eq!(failure.stage, RequestWireStage::SentOrUnknown);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );

    // The bound is the memory claim. The reader takes the cap plus one byte and
    // hangs up; what the merchant additionally lands is bounded by the kernel's
    // socket buffers, not by anything this process chose. 16 MiB is a ceiling
    // far above any plausible loopback buffer and far below the 64 MiB an
    // unbounded `read_to_end` would drain in full.
    let served = origin.served_bytes();
    assert!(
        served < 16 * 1024 * 1024,
        "the merchant pushed {served} bytes of the {SERVED_BYTES} it advertised; \
         the paid response read is not bounded by the gateway's own cap"
    );
}

/// The bound is one byte past the cap, deliberately: a read stopped at exactly
/// the cap is indistinguishable from a complete message and would be parsed as
/// one, which is how a truncated body becomes a silently accepted response.
#[test]
fn the_read_budget_is_one_byte_past_the_cap_so_over_cap_is_detectable() {
    assert_eq!(
        over_cap_probe_limit(),
        EXTERNAL_ACTION_MAX_MESSAGE_BYTES as u64 + 1
    );
}
