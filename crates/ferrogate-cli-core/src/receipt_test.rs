// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tests for the mutation decision receipt (issue #505).
//!
//! The load-bearing ones are the two that hold the *contract* rather than the
//! code:
//!
//! * [`declared_verb_effect_matches_the_method_the_builder_emits`] — the
//!   render gate is structural, but the classification feeding it is data, so
//!   a verb could be mis-declared. This test derives the truth independently
//!   (it rebuilds every registered verb's `RequestSpec` through the real
//!   family builders and reads the HTTP method) and fails on any disagreement.
//!   Flipping any single `VerbDescriptor::read`/`mutating` in the crate fails
//!   it.
//! * [`dry_run_issues_no_request_at_the_transport`] — asserts on a recording
//!   `Transport` (zero requests seen), not on output text, exactly as the
//!   acceptance criterion demands.

use super::*;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::dispatch::build_request;
use crate::output::{render_output, OutputFormat};
use crate::registry_helpers::ResourceInput;
use crate::transport::{PreparedRequest, RawResponse};
use crate::{register_resource_families, Registry};
use http::Method;
use std::sync::Mutex;
use std::task::{Context as TaskContext, Poll, Waker};

fn test_context() -> EffectiveContext {
    EffectiveContext {
        context_name: Some("prod".to_string()),
        endpoint: "https://control.example.com".to_string(),
        tenant: Some("org_acme".to_string()),
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: crate::auth::AuthSource::Env {
            var: "FERROGATE_TOKEN".to_string(),
        },
        output: OutputFormat::Json,
        non_interactive: true,
    }
}

/// Minimal single-poll executor (mirrors `transport_test.rs`): the fake
/// transport's future is always ready.
fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    // Safety: the future is owned locally and never moved after pinning.
    let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => continue,
        }
    }
}

/// Transport that records every request it is handed. A dry run must leave
/// `seen` empty — the assertion the acceptance criterion asks for is on THIS,
/// not on a string in stdout.
#[derive(Default)]
struct RecordingTransport {
    seen: Mutex<Vec<PreparedRequest>>,
    body: Vec<u8>,
}

impl RecordingTransport {
    fn with_body(body: &str) -> RecordingTransport {
        RecordingTransport {
            seen: Mutex::new(Vec::new()),
            body: body.as_bytes().to_vec(),
        }
    }

    fn request_count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Transport for RecordingTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        self.seen.lock().unwrap().push(request);
        let body = self.body.clone();
        Box::pin(async move {
            Ok(RawResponse {
                status: 201,
                headers: vec![
                    ("x-request-id".to_string(), "fgadm-receipt-1".to_string()),
                    ("x-trace-id".to_string(), "trace-receipt-1".to_string()),
                ],
                body,
            })
        })
    }
}

fn full_registry() -> Registry {
    let mut registry = Registry::new();
    register_resource_families(&mut registry).expect("register every resource family");
    registry
}

/// Build a request for `group verb`, trying progressively shorter id-segment
/// lists so every family's addressing shape is satisfied by one probe.
fn probe_spec(group: &str, verb: &str) -> CliResult<(RequestSpec, Vec<String>)> {
    let mut last = None;
    for arity in (0..=3).rev() {
        let segments: Vec<String> = (0..arity).map(|index| format!("probe-{index}")).collect();
        let input = ResourceInput::new()
            .with_segments(segments.clone())
            .with_body(serde_json::json!({"probe": true}));
        match build_request(group, verb, &input) {
            Ok(spec) => return Ok((spec, segments)),
            Err(error) => last = Some(error),
        }
    }
    Err(last.expect("at least one arity was attempted"))
}

/// Every registered verb's DECLARED effect agrees with the HTTP method its
/// family builder actually emits.
///
/// This is the anti-vacuity guard on the whole slice: the render gate is a
/// type-level barrier, but which side of the barrier a verb lands on is a
/// `VerbEffect` field an author types. Deriving the same fact from the request
/// builder — which is what really talks to the server — means a
/// misclassification cannot hide behind a green suite.
#[test]
fn declared_verb_effect_matches_the_method_the_builder_emits() {
    let registry = full_registry();
    let mut checked = 0usize;
    let mut mutating = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            let (spec, _) = probe_spec(&group.name, &verb.name).unwrap_or_else(|error| {
                panic!(
                    "registered verb '{} {}' could not build a request with any probe input: \
                     {error}",
                    group.name, verb.name
                )
            });
            let method_is_safe =
                matches!(spec.method, Method::GET | Method::HEAD | Method::OPTIONS);
            checked += 1;
            if verb.is_mutating() {
                mutating += 1;
            }
            assert_eq!(
                !method_is_safe,
                verb.is_mutating(),
                "'{} {}' is declared '{}' but its builder emits {}; fix the VerbDescriptor \
                 constructor or the builder",
                group.name,
                verb.name,
                verb.effect.as_str(),
                spec.method
            );
        }
    }
    // Guard against the test silently covering nothing if the registry ever
    // stops being populated.
    assert!(
        checked > 200,
        "expected the full registry to expose 200+ verbs, saw {checked}"
    );
    assert!(
        mutating > 90,
        "expected 90+ mutating verbs across the registry, saw {mutating}"
    );
}

/// The registry-level enforcement, enumerated: every mutating verb's gate
/// yields a receipt obligation and NO bare renderer, and every read verb's
/// yields a bare renderer.
///
/// The stronger half of this guarantee is not expressible as an assertion at
/// all — `ReceiptRenderer` has no `render(Value)` method and `VerbOutput` wraps
/// a private payload, so "a mutating verb rendered a bare body" does not
/// compile. This test covers the residual runtime question: that the gate is
/// opened for every registered verb and lands on the arm the effect declares.
#[test]
fn every_mutating_verb_is_gated_to_a_receipt() {
    let registry = full_registry();
    for group in registry.groups() {
        for verb in &group.verbs {
            match verb.render_gate() {
                RenderGate::Receipt(renderer) => {
                    assert!(
                        verb.is_mutating(),
                        "'{} {}' opened a receipt gate but is not declared mutating",
                        group.name,
                        verb.name
                    );
                    assert_eq!(renderer.verb().name, verb.name);
                }
                RenderGate::Bare(renderer) => {
                    assert!(
                        !verb.is_mutating(),
                        "'{} {}' is declared mutating but opened a BARE render gate: a mutating \
                         verb must be unable to render a raw body",
                        group.name,
                        verb.name
                    );
                    assert_eq!(renderer.verb().name, verb.name);
                }
            }
        }
    }
}

/// Every mutating verb can actually produce a receipt end to end, and every
/// receipt it produces is well formed (no silent nulls, canonical fingerprint,
/// stated absence reasons).
#[test]
fn every_mutating_verb_produces_a_well_formed_receipt() {
    let registry = full_registry();
    let context = test_context();
    let mut produced = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            let RenderGate::Receipt(renderer) = verb.render_gate() else {
                continue;
            };
            let (spec, segments) = probe_spec(&group.name, &verb.name).expect("probe request");
            let plan = MutationPlan::new(
                renderer,
                group.name.clone(),
                spec,
                &segments,
                &context,
                true,
            )
            .expect("plan the mutation");
            let output = plan.dry_run();
            let receipt = output
                .receipt()
                .expect("a mutating verb's output is always a receipt");
            let problems = receipt.validate();
            assert!(
                problems.is_empty(),
                "receipt for '{} {}' is malformed: {problems:?}",
                group.name,
                verb.name
            );
            assert!(receipt.dry_run, "dry_run must be echoed as true");
            assert!(
                output.body().is_none(),
                "a receipt output must never expose a bare body"
            );
            produced += 1;
        }
    }
    assert!(produced > 90, "expected 90+ mutating verbs, saw {produced}");
}

/// A dry run issues **no** state-changing request. Asserted on the transport.
#[test]
fn dry_run_issues_no_request_at_the_transport() {
    let registry = full_registry();
    let verb = registry
        .resolve("guardrail-policies", "create-revision")
        .expect("guardrail-policies create-revision is registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("create-revision must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("guardrail-policies", "create-revision").expect("probe");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        true,
    )
    .expect("plan");

    let transport = RecordingTransport::with_body(r#"{"object":"guardrail_policy_revision"}"#);
    let transport = std::sync::Arc::new(transport);
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));

    let output = block_on(plan.execute(&client)).expect("dry run succeeds");

    assert_eq!(
        transport.request_count(),
        0,
        "a dry run must not reach the transport at all"
    );
    let receipt = output.receipt().expect("receipt");
    assert!(receipt.dry_run);
    assert_eq!(
        receipt.http_status.absent_code(),
        Some(absence_codes::DRY_RUN_NOT_EXECUTED)
    );
    assert!(receipt.response.is_none());
}

/// The control for the test above: without `--dry-run` exactly one request is
/// issued, so the zero-request assertion is proving the flag, not proving that
/// the plumbing never works.
#[test]
fn a_real_mutation_issues_exactly_one_request() {
    let registry = full_registry();
    let verb = registry
        .resolve("guardrail-policies", "create-revision")
        .expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("guardrail-policies", "create-revision").expect("probe");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        false,
    )
    .expect("plan");

    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_1","revision":4}}"#,
    ));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));

    let output = block_on(plan.execute(&client)).expect("mutation succeeds");
    assert_eq!(transport.request_count(), 1);
    let receipt = output.receipt().expect("receipt");
    assert!(!receipt.dry_run);
    assert_eq!(receipt.http_status.value, Some(201));
    assert_eq!(
        receipt.correlation.request_id.value.as_deref(),
        Some("fgadm-receipt-1")
    );
    assert_eq!(
        receipt.correlation.trace_id.value.as_deref(),
        Some("trace-receipt-1")
    );
}

/// `Arc` sharing so the test can inspect the recorder after the client has
/// consumed the transport by value.
impl Transport for std::sync::Arc<RecordingTransport> {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        RecordingTransport::execute(self.as_ref(), request)
    }
}

/// A `--output json` receipt round-trips losslessly and keeps every absent
/// field as an explicit `null` **with a reason code** — the property that lets
/// it be piped into an audit query.
#[test]
fn receipt_json_round_trips_and_states_every_absence() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("projects create must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("projects", "create").expect("probe");
    let context = test_context();
    let plan =
        MutationPlan::new(renderer, "projects", spec, &segments, &context, false).expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"project","project":{"id":"proj_1","name":"n","status":"active"}}"#,
    ));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let output = block_on(plan.execute(&client)).expect("mutation");
    let receipt = output.receipt().expect("receipt").clone();

    let rendered = render_output(OutputFormat::Json, &output, |_| {
        panic!("a receipt must never route through the bare-body table projection")
    })
    .expect("render json");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("receipt is valid JSON");

    // The audit id is null WITH a reason, not omitted: an absent audit id is a
    // finding a downstream query must be able to select on.
    assert!(parsed["audit_id"].is_object());
    assert!(parsed["audit_id"]["value"].is_null());
    assert_eq!(
        parsed["audit_id"]["absent_reason"]["code"],
        absence_codes::NO_AUDIT_ID_IN_CONTRACT
    );
    assert!(parsed["audit_id"]["absent_reason"]["detail"]
        .as_str()
        .is_some_and(|detail| !detail.trim().is_empty()));
    // Stable envelope keys a query can pin.
    assert_eq!(parsed["object"], RECEIPT_OBJECT);
    assert_eq!(parsed["receipt_version"], RECEIPT_VERSION);
    assert_eq!(parsed["dry_run"], false);
    assert_eq!(
        parsed["target"]["action_fingerprint_contract"],
        ACTION_FINGERPRINT_CONTRACT
    );
    // Projects have no revision chain, so the rollback pointer is a stated
    // null rather than a missing key.
    assert!(parsed["rollback"]["value"].is_null());
    assert_eq!(
        parsed["rollback"]["absent_reason"]["code"],
        absence_codes::RESOURCE_HAS_NO_REVISIONS
    );
    // The server document survives, nested under the envelope.
    assert_eq!(parsed["response"]["project"]["id"], "proj_1");

    let restored: MutationReceipt = serde_json::from_str(&rendered).expect("round-trip");
    assert_eq!(restored, receipt);
    assert!(restored.validate().is_empty());
}

/// The table rendering says the same thing the JSON does: a null field shows
/// its reason code instead of vanishing.
#[test]
fn table_render_states_the_nulls() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "delete").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("gated");
    };
    let (spec, segments) = probe_spec("projects", "delete").expect("probe");
    let context = test_context();
    let plan =
        MutationPlan::new(renderer, "projects", spec, &segments, &context, true).expect("plan");
    let output = plan.dry_run();
    let rendered = render_output(OutputFormat::Table, &output, |_| {
        panic!("a receipt must never route through the bare-body table projection")
    })
    .expect("render table");
    assert!(rendered.contains("audit_id"));
    assert!(rendered.contains(absence_codes::DRY_RUN_NOT_EXECUTED));
    assert!(rendered.contains("dry_run"));
    assert!(rendered.contains("target.action_fingerprint"));
}

/// A revisioned family yields a complete reversal command: every identifier in
/// it comes from the response or the invocation, never from the operator.
#[test]
fn rollback_pointer_is_a_complete_command() {
    let registry = full_registry();
    let verb = registry
        .resolve("guardrail-policies", "create-revision")
        .expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("gated");
    };
    let (spec, segments) = probe_spec("guardrail-policies", "create-revision").expect("probe");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_42","revision":7,"status":"active"}}"#,
    ));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let output = block_on(plan.execute(&client)).expect("mutation");
    let receipt = output.receipt().expect("receipt");

    let pointer = receipt
        .rollback
        .value
        .as_ref()
        .expect("a guardrail policy revision has a rollback pointer");
    assert_eq!(
        pointer.command,
        vec![
            "ctl".to_string(),
            "guardrail-policies".to_string(),
            "rollback".to_string(),
            "gp_42".to_string(),
            "--data".to_string(),
            "{\"revision\":6}".to_string(),
        ]
    );
    assert_eq!(pointer.created_revision.value.as_deref(), Some("7"));
    assert_eq!(pointer.restores_revision.value.as_deref(), Some("6"));
    assert_eq!(receipt.target.object_version.value.as_deref(), Some("7"));
}

/// The first revision in a chain has nothing to roll back TO, so the pointer
/// is an archive rather than a rollback — and says so.
#[test]
fn first_revision_reversal_is_an_archive_not_a_rollback() {
    let registry = full_registry();
    let verb = registry
        .resolve("guardrail-policies", "create")
        .expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("gated");
    };
    let (spec, segments) = probe_spec("guardrail-policies", "create").expect("probe");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_new","revision":1}}"#,
    ));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let output = block_on(plan.execute(&client)).expect("mutation");
    let pointer = output
        .receipt()
        .expect("receipt")
        .rollback
        .value
        .clone()
        .expect("pointer");
    assert_eq!(pointer.command[2], "archive");
    assert_eq!(
        pointer.restores_revision.absent_code(),
        Some(absence_codes::NO_PRIOR_REVISION)
    );
}

/// The canonical target's JSON is byte-stable in the exact shape the runtime
/// `CanonicalCapabilityTarget::Network` variant emits, and the fingerprint
/// follows the `canonical_target_sha256` contract. Cross-crate byte equality
/// against the runtime type is asserted in
/// `crates/ferrogate-cli/src/ctl/fingerprint_parity_test.rs`.
#[test]
fn canonical_target_json_and_fingerprint_follow_the_runtime_contract() {
    let spec = RequestSpec::new(Method::POST, "/admin/v1/guardrail-policies/gp_1/rollback")
        .with_json_body(serde_json::json!({"revision": 3}));
    let target =
        CliActionTarget::for_request("https://control.example.com", &spec).expect("target");
    assert_eq!(
        target.canonical_json(),
        r#"{"kind":"network","scheme":"https","host":"control.example.com","port":443,"method":"POST","path":"/admin/v1/guardrail-policies/gp_1/rollback","resolved_ips":[],"redirects":[]}"#
    );
    let fingerprint = target.fingerprint();
    assert!(is_canonical_action_fingerprint(&fingerprint));
    assert_eq!(fingerprint.len(), "sha256:".len() + 64);
    // The body does NOT participate: the fingerprint identifies the target, not
    // the payload, exactly like the runtime's target-level fingerprint.
    let without_body = RequestSpec::new(Method::POST, "/admin/v1/guardrail-policies/gp_1/rollback");
    assert_eq!(
        CliActionTarget::for_request("https://control.example.com", &without_body)
            .expect("target")
            .fingerprint(),
        fingerprint
    );
    // The method DOES participate: a DELETE on the same path is a different
    // action.
    let delete = RequestSpec::new(Method::DELETE, "/admin/v1/guardrail-policies/gp_1/rollback");
    assert_ne!(
        CliActionTarget::for_request("https://control.example.com", &delete)
            .expect("target")
            .fingerprint(),
        fingerprint
    );
    // Query parameters select the object, so they participate too.
    let filtered = RequestSpec::new(Method::DELETE, "/admin/v1/quota-policies/tenant/t1")
        .with_query("scope", "tenant");
    assert_ne!(
        CliActionTarget::for_request("https://control.example.com", &filtered)
            .expect("target")
            .fingerprint(),
        CliActionTarget::for_request(
            "https://control.example.com",
            &RequestSpec::new(Method::DELETE, "/admin/v1/quota-policies/tenant/t1")
        )
        .expect("target")
        .fingerprint()
    );
}

/// An endpoint that *does* return a decision has it projected onto the runtime
/// vocabulary; an unrecognized value is reported absent rather than coerced to
/// `allow`.
#[test]
fn decision_projection_never_invents_an_allow() {
    let approved =
        serde_json::json!({"approval": {"decision": "approved", "decision_reason": "operator"}});
    let decision = decision_from_body(&approved).expect("decision");
    assert_eq!(decision.decision, DecisionClass::Allow);
    assert_eq!(decision.reason.code, "approved");
    assert_eq!(decision.reason.detail.as_deref(), Some("operator"));

    let denied = serde_json::json!({"decision": "expired"});
    assert_eq!(
        decision_from_body(&denied).expect("decision").decision,
        DecisionClass::Deny
    );

    let unknown = serde_json::json!({"decision": "something-new"});
    assert!(
        decision_from_body(&unknown).is_none(),
        "an unrecognized decision must not be coerced to a permissive one"
    );
}

/// `Attested` refuses to be silently empty: the validator catches a hand-built
/// receipt whose field is null with no reason.
#[test]
fn validate_rejects_a_null_without_a_reason() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("gated");
    };
    let (spec, segments) = probe_spec("projects", "create").expect("probe");
    let context = test_context();
    let plan =
        MutationPlan::new(renderer, "projects", spec, &segments, &context, true).expect("plan");
    let output = plan.dry_run();
    let mut receipt = output.receipt().expect("receipt").clone();
    assert!(receipt.validate().is_empty());

    receipt.audit_id = Attested {
        value: None,
        absent_reason: None,
    };
    let problems = receipt.validate();
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("audit_id"));

    receipt.audit_id = Attested::present("audit_1".to_string());
    receipt.target.action_fingerprint = "sha256:not-a-digest".to_string();
    assert!(receipt
        .validate()
        .iter()
        .any(|problem| problem.contains("action_fingerprint")));
}

/// `dry_run` describes what the CLIENT did, never what the verb is called: the
/// `guardrail-policies dry-run` verb issues a real POST and reports
/// `dry_run: false` unless `--dry-run` was passed.
#[test]
fn dry_run_is_not_inferred_from_the_verb_name() {
    let registry = full_registry();
    let verb = registry
        .resolve("guardrail-policies", "dry-run")
        .expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("the dry-run verb is a POST, so it is gated to a receipt");
    };
    let (spec, segments) = probe_spec("guardrail-policies", "dry-run").expect("probe");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(r#"{"object":"ok"}"#));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let output = block_on(plan.execute(&client)).expect("mutation");
    assert_eq!(transport.request_count(), 1);
    assert!(
        !output.receipt().expect("receipt").dry_run,
        "the verb is named dry-run but the client executed it for real"
    );
}
