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
//! * [`rollback_pointer_argv_round_trips_through_every_familys_own_builder`] —
//!   `RollbackPointer::command` promises the argv is safe for a script to run
//!   verbatim, so every entry in `REVISIONED_FAMILIES` has its emitted argv fed
//!   back through that family's own request builder. A table entry no test
//!   exercises is how a `gateway-configs` "rollback" came to be a `PUT` that
//!   replaced the whole profile with `{"revision":3}`.
//! * [`receipt_never_carries_the_token_it_authenticated_with`] — asserted on
//!   the *rendered* JSON and table, so any field that starts echoing the
//!   bearer token fails, not just `credential_source`.
//! * [`a_refused_mutation_still_produces_a_receipt`] and
//!   [`an_ambiguous_failure_reports_the_outcome_as_unknown_not_as_refused`] —
//!   the receipt is the output contract of a mutating verb on the failing
//!   paths too, and "the server refused" is a different fact from "we never
//!   found out".
//! * [`a_gateway_timeout_is_unknown_not_an_authoritative_refusal`],
//!   [`a_throttled_mutation_agrees_with_the_exit_class_it_returns`] and
//!   [`the_outcome_a_status_permits_is_authority_not_success`] — an HTTP
//!   response is not the same thing as an authoritative answer. The first two
//!   are fixtures next to the `409` so the two readings are proven distinct;
//!   the third sweeps the whole status space, because the defect was a missing
//!   *distinction* and sampled fixtures only pin the statuses someone thought
//!   to write down.

use super::*;
use crate::action_identity::ClientActionIdentity;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::dispatch::build_request;
use crate::output::{render_output, OutputFormat};
use crate::registry_helpers::ResourceInput;
use crate::resource::ListParams;
use crate::transport::{PreparedRequest, RawResponse};
use crate::{register_resource_families, Registry};
use http::Method;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};
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
    status: u16,
    /// When set, the transport never obtains an answer at all: the connection
    /// dies (or the body cannot be read) after the request was handed over.
    /// This is the ambiguous case — the server may have committed.
    dead: Option<String>,
    /// When set, the response carries `x-ferrogate-time-token`.
    ///
    /// Without this the transport emitted only `x-request-id`/`x-trace-id`, so
    /// `ControlPlaneClient::harvest_time_token` early-returned on every fixture
    /// and no test could tell a token read *before* the call from one read
    /// *after* it — which is the ordering the whole `presented` variable exists
    /// to guarantee.
    time_token: Option<String>,
}

impl RecordingTransport {
    fn with_body(body: &str) -> RecordingTransport {
        RecordingTransport::with_status(201, body)
    }

    fn with_status(status: u16, body: &str) -> RecordingTransport {
        RecordingTransport {
            seen: Mutex::new(Vec::new()),
            body: body.as_bytes().to_vec(),
            status,
            dead: None,
            time_token: None,
        }
    }

    /// A transport that delivers the request and then loses the answer.
    fn dead(message: &str) -> RecordingTransport {
        RecordingTransport {
            seen: Mutex::new(Vec::new()),
            body: Vec::new(),
            status: 0,
            dead: Some(message.to_string()),
            time_token: None,
        }
    }

    /// The same transport, answering with a server time token.
    fn issuing_time_token(mut self, token: &str) -> RecordingTransport {
        self.time_token = Some(token.to_string());
        self
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
        let status = self.status;
        let dead = self.dead.clone();
        let time_token = self.time_token.clone();
        Box::pin(async move {
            if let Some(message) = dead {
                return Err(CliError::transport(message));
            }
            let mut headers = vec![
                ("x-request-id".to_string(), "fgadm-receipt-1".to_string()),
                ("x-trace-id".to_string(), "trace-receipt-1".to_string()),
            ];
            if let Some(token) = time_token {
                headers.push((crate::action_identity::TIME_TOKEN_HEADER.to_string(), token));
            }
            Ok(RawResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// Plan and run `group verb` against a transport that answers with `status` and
/// `body`. Returns the full [`MutationReport`], so a test can assert on the
/// receipt that a *failing* call produced — the thing a `CliResult` cannot
/// carry.
fn execute_against(
    group: &str,
    verb: &str,
    segments: &[String],
    status: u16,
    body: &str,
) -> MutationReport {
    run_plan(
        group,
        verb,
        segments,
        std::sync::Arc::new(RecordingTransport::with_status(status, body)),
    )
}

/// As [`execute_against`], but the transport never gets an authoritative
/// answer.
fn execute_with_no_answer(
    group: &str,
    verb: &str,
    segments: &[String],
    message: &str,
) -> MutationReport {
    run_plan(
        group,
        verb,
        segments,
        std::sync::Arc::new(RecordingTransport::dead(message)),
    )
}

fn run_plan(
    group: &str,
    verb: &str,
    segments: &[String],
    transport: std::sync::Arc<RecordingTransport>,
) -> MutationReport {
    let registry = full_registry();
    let descriptor = registry
        .resolve(group, verb)
        .unwrap_or_else(|error| panic!("'{group} {verb}' is registered: {error}"));
    let RenderGate::Receipt(renderer) = descriptor.render_gate() else {
        panic!("'{group} {verb}' must be gated to a receipt");
    };
    let input = ResourceInput::new()
        .with_segments(segments.to_vec())
        .with_body(serde_json::json!({"probe": true}));
    let spec = build_request(group, verb, &input).expect("the family builder accepts this shape");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        group,
        spec,
        segments,
        &context,
        &ClientActionIdentity::fixture(),
        false,
    )
    .expect("plan");
    let client = ControlPlaneClient::new(context, None, transport, ClientActionIdentity::fixture());
    block_on(plan.execute(&client))
}

fn full_registry() -> Registry {
    let mut registry = Registry::new();
    register_resource_families(&mut registry).expect("register every resource family");
    registry
}

#[derive(Debug)]
struct ProbeContract {
    path_segments: usize,
    required_query: Vec<String>,
}

/// Required request inputs keyed by OpenAPI operation id.
///
/// Path arity comes from the enforced contract's path template, not from what
/// a builder happens to accept. Required query values are also populated so a
/// probe represents a contract-valid request. A positional query value is an
/// explicit [`VerbDescriptor::positional_query_segments`] exception layered on
/// top of this contract (currently `asset-channels set`'s version).
fn probe_contracts() -> &'static BTreeMap<String, ProbeContract> {
    static CONTRACTS: OnceLock<BTreeMap<String, ProbeContract>> = OnceLock::new();
    CONTRACTS.get_or_init(|| {
        let document: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json"))
                .expect("the OpenAPI contract parses");
        let paths = document["paths"]
            .as_object()
            .expect("the OpenAPI contract has paths");
        let component_parameters = document["components"]["parameters"]
            .as_object()
            .expect("the OpenAPI contract has component parameters");
        let mut contracts = BTreeMap::new();
        for (path, path_item) in paths {
            for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
                let Some(operation) = path_item.get(method) else {
                    continue;
                };
                let Some(operation_id) = operation["operationId"].as_str() else {
                    continue;
                };
                let mut required_query = BTreeSet::new();
                for raw_parameter in path_item["parameters"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .chain(operation["parameters"].as_array().into_iter().flatten())
                {
                    let parameter = if let Some(reference) = raw_parameter["$ref"].as_str() {
                        let name = reference.rsplit('/').next().unwrap_or_default();
                        component_parameters.get(name).unwrap_or_else(|| {
                            panic!("{operation_id} references unknown parameter {reference}")
                        })
                    } else {
                        raw_parameter
                    };
                    if parameter["in"] == "query" && parameter["required"] == true {
                        required_query.insert(
                            parameter["name"]
                                .as_str()
                                .unwrap_or_else(|| {
                                    panic!("{operation_id} has an unnamed required query parameter")
                                })
                                .to_string(),
                        );
                    }
                }
                let replaced = contracts.insert(
                    operation_id.to_string(),
                    ProbeContract {
                        path_segments: path.matches('{').count(),
                        required_query: required_query.into_iter().collect(),
                    },
                );
                assert!(
                    replaced.is_none(),
                    "OpenAPI operation id '{operation_id}' is duplicated"
                );
            }
        }
        contracts
    })
}

fn registry_verb_count(registry: &Registry) -> usize {
    registry
        .groups()
        .iter()
        .map(|group| group.verbs.len())
        .sum()
}

fn registry_mutating_verb_count(registry: &Registry) -> usize {
    registry
        .groups()
        .iter()
        .flat_map(|group| &group.verbs)
        .filter(|verb| verb.is_mutating())
        .count()
}

fn probe_input(
    operation_id: &str,
    positional_query_segments: usize,
) -> Result<(ResourceInput, Vec<String>), String> {
    let contract = probe_contracts()
        .get(operation_id)
        .ok_or_else(|| format!("OpenAPI contract has no operation '{operation_id}'"))?;
    let arity = contract.path_segments + positional_query_segments;
    let segments: Vec<String> = (0..arity).map(|index| format!("probe-{index}")).collect();
    let list = contract
        .required_query
        .iter()
        .fold(ListParams::new(), |list, parameter| {
            list.with_filter(parameter, format!("probe-{parameter}"))
        });
    Ok((
        ResourceInput::new()
            .with_segments(segments.clone())
            .with_body(serde_json::json!({"probe": true}))
            .with_list(list),
        segments,
    ))
}

/// Build `group verb` at the exact positional arity its OpenAPI path and verb
/// metadata require. A permissive builder cannot move this probe onto a longer
/// shape, and an under-guarded builder cannot move it onto a shorter one.
fn try_probe_spec(group: &str, verb: &str) -> Result<(RequestSpec, Vec<String>), String> {
    let registry = full_registry();
    let descriptor = registry
        .resolve(group, verb)
        .map_err(|error| format!("registered verb '{group} {verb}' is unavailable: {error}"))?;
    let operation_id = descriptor
        .operation_id
        .as_deref()
        .ok_or_else(|| format!("registered verb '{group} {verb}' has no OpenAPI operation id"))?;
    let (input, segments) = probe_input(operation_id, descriptor.positional_query_segments())
        .map_err(|error| format!("registered verb '{group} {verb}' cannot be probed: {error}"))?;
    let spec = build_request(group, verb, &input).map_err(|error| {
        format!(
            "registered verb '{group} {verb}' rejects its contract-required {} positional \
             segment(s): {error}",
            segments.len()
        )
    })?;
    let contract = &probe_contracts()[operation_id];
    let missing_query: Vec<&str> = contract
        .required_query
        .iter()
        .map(String::as_str)
        .filter(|required| !spec.query.iter().any(|(name, _)| name == required))
        .collect();
    if !missing_query.is_empty() {
        return Err(format!(
            "registered verb '{group} {verb}' omits required OpenAPI query parameter(s): {}",
            missing_query.join(", ")
        ));
    }
    Ok((spec, segments))
}

/// [`try_probe_spec`], panicking with the verb's name.
///
/// Every call site takes this form on purpose. The sweeps used to write
/// `.expect("probe request")`, which reported the builder's usage string
/// (`verb 'set' requires <asset_type> …`) and left the reader to guess which of
/// the registry's 200-plus verbs owned it.
fn probe_spec(group: &str, verb: &str) -> (RequestSpec, Vec<String>) {
    try_probe_spec(group, verb).unwrap_or_else(|failure| panic!("{failure}"))
}

/// Every verb builds at exactly the arity declared by the OpenAPI path plus its
/// explicit positional-query metadata. Every addressed verb also rejects one
/// segment fewer, so an under-guarded live builder is named rather than trusted
/// as the source of its own requirement.
#[test]
fn every_registered_verb_is_constructable_by_the_prober() {
    let registry = full_registry();
    let mut unconstructable: Vec<String> = Vec::new();
    let mut probed = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            match try_probe_spec(&group.name, &verb.name) {
                Ok((_, segments)) => {
                    probed += 1;
                    if !segments.is_empty() {
                        let operation_id = verb.operation_id.as_deref().unwrap_or_else(|| {
                            panic!("'{} {}' has no OpenAPI operation id", group.name, verb.name)
                        });
                        let (short_input, _) =
                            probe_input(operation_id, verb.positional_query_segments())
                                .unwrap_or_else(|error| {
                                    panic!(
                                        "'{} {}' has no probe contract: {error}",
                                        group.name, verb.name
                                    )
                                });
                        let short_input = ResourceInput::new()
                            .with_segments(segments[..segments.len() - 1].to_vec())
                            .with_body(serde_json::json!({"probe": true}))
                            .with_list(short_input.list);
                        if build_request(&group.name, &verb.name, &short_input).is_ok() {
                            unconstructable.push(format!(
                                "registered verb '{} {}' accepts {} positional segment(s), one \
                                 fewer than its contract requires ({})",
                                group.name,
                                verb.name,
                                segments.len() - 1,
                                segments.len()
                            ));
                        }
                    }
                }
                Err(failure) => unconstructable.push(failure),
            }
        }
    }
    assert!(
        unconstructable.is_empty(),
        "{} registered verb(s) cannot be probed, so the whole-registry sweeps cannot check \
         them:\n{}",
        unconstructable.len(),
        unconstructable.join("\n\n")
    );
    assert_eq!(
        probed,
        registry_verb_count(&registry),
        "every registered verb must be probed exactly once"
    );
}

/// A verb the prober cannot construct fails **by name**.
///
/// This exercises the registry-resolution failure and the panicking wrapper.
/// Whole-registry call sites add the same identity to their own fallible steps,
/// so no first failure aborts a sweep as an unnamed `.expect`.
#[test]
fn a_verb_the_prober_cannot_construct_fails_by_name() {
    let failure = try_probe_spec("asset-channels", "promote-everything")
        .expect_err("an unregistered verb cannot be probed");
    assert!(
        failure.contains("asset-channels promote-everything"),
        "the failure must name the verb that could not be built, not just the builder's usage \
         string: {failure}"
    );

    let panicked = std::panic::catch_unwind(|| probe_spec("asset-channels", "promote-everything"));
    let payload = panicked.expect_err("probe_spec must panic rather than return");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<panic payload was neither String nor &str>");
    assert!(
        message.contains("asset-channels promote-everything"),
        "the panic every sweep would raise must name the verb: {message}"
    );
}

/// The prober uses the contract's required arity, not a constant and not a
/// longer shape a permissive builder happens to tolerate.
#[test]
fn prober_distinguishes_required_arity_from_tolerated_extra_segments() {
    for (group, verb, required) in [
        ("projects", "list", 0),
        ("projects", "get", 1),
        ("quota-policies", "get", 2),
        ("assets", "get", 3),
        ("asset-channels", "set", 4),
    ] {
        let (_, segments) = probe_spec(group, verb);
        assert_eq!(
            segments.len(),
            required,
            "'{group} {verb}' must be probed at its contract-required arity"
        );
    }

    // `projects get` currently accepts trailing segments, but that tolerance is
    // deliberately not asserted as a contract. Whether it is permissive or is
    // tightened later, the probe remains at the one segment OpenAPI requires.
    assert_eq!(
        probe_spec("projects", "get").1.len(),
        1,
        "builder tolerance must not redefine required arity"
    );
}

/// **The acceptance box.** Every verb in the registry — read and mutating,
/// every one of them — prepares `action_id`, the client fingerprint and the
/// client's own unverified clock reading for the production transport (issue
/// #548).
///
/// Pins: `headers.extend(identity.headers())` in `transport::prepare_request`.
///
/// Catches: deleting that line (every verb reds), and emitting the identity for
/// only some verbs — this enumerates the whole registry rather than a fixture,
/// so a family added tomorrow is covered the day it is registered.
///
/// It is necessary and **not sufficient**. The getter-only `PreparedRequest`
/// API and its crate-private fields prevent a consumer from constructing or
/// stripping headers before `Transport::execute`; this sweep proves each
/// registered verb uses that preparation path. Neither proves that an adapter
/// copies the prepared headers onto a socket. The production adapter's residual
/// runtime question is held by
/// `transport_test::reqwest_transport_writes_the_identity_onto_the_socket`.
///
/// The crate has had a dedicated workflow slice since #360, but the composing
/// workflow is release-published only. The receipt/effect sweeps were created
/// on 2026-07-27 after the four-segment asset verb and were therefore born red;
/// they were not a four-day regression, nor was their crate absent from the
/// workflow matrix. Evidence for the full claim is deliberately composite:
/// exact contract-shaped registry sweep, construction guard, and the
/// independent reqwest wire test.
#[test]
fn every_registered_verb_prepares_the_action_identity_for_transport() {
    let registry = full_registry();
    let expected = registry_verb_count(&registry);
    let context = test_context();
    let identity = ClientActionIdentity::fixture();
    let mut checked = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            let (spec, _) = probe_spec(&group.name, &verb.name);
            let prepared = crate::transport::prepare_request(&spec, &context, None, &identity)
                .unwrap_or_else(|error| {
                    panic!(
                        "'{} {}' failed while preparing the request: {error}",
                        group.name, verb.name
                    )
                });
            for header in [
                crate::action_identity::ACTION_ID_HEADER,
                crate::action_identity::CLIENT_FINGERPRINT_HEADER,
                crate::action_identity::CLIENT_CLOCK_HEADER,
            ] {
                assert!(
                    prepared
                        .header(header)
                        .is_some_and(|value| !value.is_empty()),
                    "'{} {}' would issue a request carrying no {header}; the audit identity is \
                     enforced at the transport chokepoint, so this can only mean the chokepoint \
                     was bypassed",
                    group.name,
                    verb.name
                );
            }
            assert_eq!(
                prepared.header(crate::action_identity::ACTION_ID_HEADER),
                Some(identity.action_id().as_str()),
                "'{} {}' must carry THIS invocation's action id, not one of its own",
                group.name,
                verb.name
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, expected,
        "every registered verb must reach request preparation exactly once"
    );
}

/// A dry run reports the action identity it *would* have used, and reports
/// `client_sent_at` as absent because **nothing was sent**.
///
/// Pins: the `(false, _)` arm of `MutationPlan::client_identity` — and only that
/// arm — plus `client_clock_unverified_unix` being filled from the identity.
///
/// Catches: reusing whatever token the identity happens to hold on a path that
/// issued no request (the `REQUEST_NOT_SENT` assertion reds), and dropping the
/// client's own reading (the last assertion reds).
///
/// **What it does not catch, corrected:** this test's doc header used to claim
/// it caught "filling `client_sent_at` from the local clock when no token is
/// held". It cannot — it takes the dry-run arm and asserts `REQUEST_NOT_SENT`,
/// a different arm and a different code from the one that mutation lives in.
/// That claim now belongs to
/// [`a_sent_receipt_with_no_token_refuses_to_stand_the_local_clock_in`],
/// which takes the arm that actually runs.
#[test]
fn a_receipt_reports_the_action_id_and_refuses_to_invent_a_client_sent_at() {
    let registry = full_registry();
    let verb = registry
        .resolve("projects", "create")
        .expect("projects create is registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("create must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("projects", "create");
    let identity = ClientActionIdentity::fixture();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &test_context(),
        &identity,
        true,
    )
    .expect("plan");
    let output = plan.dry_run();
    let receipt = output.receipt().expect("a mutating verb returns a receipt");

    assert_eq!(
        receipt.client_identity.action_id,
        identity.action_id().as_str(),
        "the receipt reports the action the transport would have sent, not a second one"
    );
    assert!(receipt.client_identity.client_sent_at.value.is_none());
    assert_eq!(
        receipt
            .client_identity
            .client_sent_at
            .absent_reason
            .as_ref()
            .map(|reason| reason.code.as_str()),
        Some(absence_codes::REQUEST_NOT_SENT),
        "a dry run presented no server instant, and the local clock must NOT stand in for one"
    );
    assert_eq!(
        receipt.client_identity.client_clock_unverified_unix,
        identity.client_clock().unverified_unix_seconds(),
        "the client's own reading is always present — it is the only evidence of clock skew"
    );
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
}

/// An executed mutation with a held token reports the SERVER's instant, and the
/// two instants stay in two fields.
///
/// Pins: the `(true, Some(time))` arm of `MutationPlan::client_identity`, and
/// `MutationPlan::send` reading the held token *before* the call
/// (`receipt.rs`'s `let presented = self.identity.server_issued_time();`).
///
/// Catches: moving that read to after `client.send(...)`. The fixture response
/// carries a **different, valid** time token for the same action, which
/// `harvest_time_token` accepts and stores, so a read taken afterwards reports
/// `RESPONSE_ISSUED_AT` — the instant that arrived *with the answer* — instead
/// of the one the request carried, and both the `presented` equality and the
/// inequality against the client's own reading red.
///
/// This is the assertion the test claimed and did not have: the old fixture's
/// response emitted only `x-request-id` and `x-trace-id`, so `harvest_time_token`
/// early-returned, the held token never changed across the call, and moving the
/// read produced an identical receipt. The production ordering was correct;
/// nothing held it.
#[test]
fn an_executed_mutation_reports_the_server_instant_it_presented() {
    /// The instant the *response* carries. Distinct from the presented one, so
    /// "before" and "after" the call are two different receipts.
    const RESPONSE_ISSUED_AT: u64 = 1_800_000_000;

    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("create must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("projects", "create");
    let identity = ClientActionIdentity::fixture();
    let presented = identity.client_clock().unverified_unix_seconds() - 5;
    identity
        .accept_server_time(&format!(
            "v1;issued_at={presented};ttl=300;action_id={};sig=abc",
            identity.action_id()
        ))
        .expect("the fixture token is bound to this action and inside its TTL");

    let transport = std::sync::Arc::new(
        RecordingTransport::with_body(r#"{"id":"proj_1"}"#).issuing_time_token(&format!(
            "v1;issued_at={RESPONSE_ISSUED_AT};ttl=300;action_id={};sig=zzz",
            identity.action_id()
        )),
    );
    assert_ne!(
        presented, RESPONSE_ISSUED_AT,
        "the two instants must differ, or the ordering assertion below proves nothing"
    );
    let client = ControlPlaneClient::new(
        test_context(),
        None,
        std::sync::Arc::clone(&transport),
        identity.clone(),
    );
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &test_context(),
        &identity,
        false,
    )
    .expect("plan");
    let report = block_on(plan.execute(&client));
    let receipt = report
        .output()
        .receipt()
        .expect("a mutating verb returns a receipt");

    let sent_at = receipt
        .client_identity
        .client_sent_at
        .value
        .as_ref()
        .expect("a held token is reported as the authoritative client_sent_at");
    assert_eq!(
        sent_at.issued_at_unix, presented,
        "the receipt reports the instant the REQUEST carried, not the one that arrived with the \
         answer to it"
    );
    // The response's token really was harvested — otherwise the assertion above
    // would hold for the trivial reason that nothing could ever have changed it,
    // which is exactly how this test used to be vacuous.
    assert_eq!(
        identity
            .server_issued_time()
            .expect("the response's token was harvested")
            .issued_at_unix(),
        RESPONSE_ISSUED_AT,
        "harvest_time_token must have replaced the held token during the call"
    );
    assert_eq!(sent_at.bound_action_id, receipt.client_identity.action_id);
    assert_eq!(
        sent_at.authority,
        crate::action_identity::SERVER_TIME_AUTHORITY,
        "the serialized record names its own authority instead of leaving it to be inferred"
    );
    assert_ne!(
        sent_at.issued_at_unix, receipt.client_identity.client_clock_unverified_unix,
        "the server-issued instant and the client's own reading are two authorities in two \
         fields; a fixture where they coincide would prove nothing"
    );
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
}

/// A sent receipt with no presented server time token reports
/// `client_sent_at: null` with [`absence_codes::NO_SERVER_TIME_TOKEN`] — and
/// the local clock does not stand in for it.
///
/// Pins: the `(true, None)` arm of `MutationPlan::client_identity`
/// (`receipt.rs`, `Attested::absent(absence_codes::NO_SERVER_TIME_TOKEN, …)`).
///
/// Catches: replacing that `Attested::absent(...)` with
/// ```text
/// Attested::present(ServerIssuedClientSentAt {
///     issued_at_unix: self.identity.client_clock().unverified_unix_seconds(),
///     ttl_seconds: 0,
///     bound_action_id: self.identity.action_id().to_string(),
///     authority: SERVER_TIME_AUTHORITY.to_string(),
/// })
/// ```
/// — the local clock wearing the server's authority, which is verbatim the one
/// thing this whole timestamp design exists to prevent. Nothing else in the
/// suite sees it:
///
/// * `a_receipt_reports_the_action_id_and_refuses_to_invent_a_client_sent_at`
///   takes the dry-run `(false, _)` arm and asserts a different code;
/// * `an_executed_mutation_reports_the_server_instant_it_presented` takes
///   `(true, Some)`;
/// * `MutationReceipt::validate` passes, because a forger fills
///   `bound_action_id` and `authority` too;
/// * the `SystemTime::now()` source guard passes, because the mutation adds no
///   clock read — it launders one the identity already took.
///
/// The transport now obtains an action-bound token with a safe preflight before
/// it sends a mutation, so this branch is an invariant guard rather than the
/// normal first-request path. Testing it through `ControlPlaneClient::send`
/// would be a lie: a compliant client refuses to send the effect request when
/// preflight cannot produce a token. The receipt projection is the branch that
/// needs pinning.
///
/// `absent_reason.code` is what is asserted, not just `value.is_none()`: the
/// mutation above produces a *plausible* instant, so only the code can tell
/// "the server issued none" from "nothing was sent" from a silently filled one.
#[test]
fn a_sent_receipt_with_no_token_refuses_to_stand_the_local_clock_in() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("create must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("projects", "create");
    let identity = ClientActionIdentity::fixture();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &test_context(),
        &identity,
        false,
    )
    .expect("plan");
    let response = ApiResponse {
        status: 201,
        request_id: Some("fgadm-receipt-1".to_string()),
        trace_id: Some("trace-receipt-1".to_string()),
        body: serde_json::json!({"id": "proj_1"}),
    };
    let receipt = plan.build_receipt(verb, Executed::Applied(&response), None);
    assert_eq!(receipt.outcome, MutationOutcome::Applied);

    assert_eq!(
        receipt.client_identity.client_sent_at.value, None,
        "no server issued an instant, so the receipt must carry none: {:?}",
        receipt.client_identity.client_sent_at
    );
    assert_eq!(
        receipt
            .client_identity
            .client_sent_at
            .absent_reason
            .as_ref()
            .map(|reason| reason.code.as_str()),
        Some(absence_codes::NO_SERVER_TIME_TOKEN),
        "the absence is a finding with a code of its own — NOT 'request not sent', which is a \
         different fact about a different arm"
    );
    // The client's own reading is present, and stayed on its own side of the
    // line. Rendering the receipt is what a sink would consume, so the check
    // that no other field carries that number is made against the JSON.
    let clock = receipt.client_identity.client_clock_unverified_unix;
    assert_eq!(clock, identity.client_clock().unverified_unix_seconds());
    let json = serde_json::to_string(&receipt).expect("receipt serializes");
    assert_eq!(
        json.matches(&clock.to_string()).count(),
        1,
        "the client's own reading appears exactly once, in the field named for it; a second \
         occurrence means it was copied into client_sent_at: {json}"
    );
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
}

/// The client identity survives the JSON rendering an audit pipeline consumes,
/// and the two instants stay distinguishable there.
///
/// Pins: the `client_identity` field of `MutationReceipt` and its serde names.
///
/// Catches: renaming `client_clock_unverified_unix` to `timestamp` — the
/// rename the issue explicitly forbids, because a downstream sink would then
/// read an attacker-controlled reading as the event time.
#[test]
fn the_rendered_receipt_keeps_the_two_instants_distinguishable() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("create must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("projects", "create");
    let identity = ClientActionIdentity::fixture();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &test_context(),
        &identity,
        true,
    )
    .expect("plan");
    let output = plan.dry_run();
    let json = render_output(OutputFormat::Json, &output, |_| unreachable!()).expect("json");
    let table = render_output(OutputFormat::Table, &output, |_| {
        panic!("a receipt must never route through the bare-body table projection")
    })
    .expect("table");

    assert!(json.contains("\"client_identity\""));
    assert!(json.contains("\"client_clock_unverified_unix\""));
    assert!(json.contains("\"client_sent_at\""));
    assert!(json.contains(identity.action_id().as_str()));
    assert!(
        !json.contains("\"timestamp\""),
        "a bare 'timestamp' is exactly the name issue #548 forbids: {json}"
    );
    assert!(
        table.contains("client.clock (unverified, client-asserted)"),
        "the human rendering must say which instant is which too: {table}"
    );
    assert!(table.contains("client.client_sent_at (server-issued)"));
    // The third authority label. It was listed in the receipt's own authority
    // table and rendered by `to_rows`, and nothing asserted it — so dropping
    // "(client-asserted)" from the row, and with it the one word telling an
    // operator that this address is the client's claim and not the server's
    // observation, reded nothing.
    assert!(
        table.contains("client.reported_ip (client-asserted)"),
        "the client-asserted address must say so in the human rendering, or a reader will take \
         it for the source IP the server observed: {table}"
    );
    assert!(
        !table.contains("client.reported_ip (server"),
        "there is exactly one authority for this row and it is not the server: {table}"
    );
}

/// The two fingerprints on a receipt cannot be confused for one another, and
/// `validate()` is what says so.
///
/// Pins: the `client_fingerprint` checks in [`MutationReceipt::validate`].
///
/// Catches: rendering the CLIENT fingerprint as `sha256:<64 hex>`. That is the
/// two-fingerprint confusion issue #548 explicitly warned about — `target.action_fingerprint`
/// digests the *call* and is mirrored byte-for-byte from `ferrogate-runtime`,
/// while `client_identity.client_fingerprint` describes the *client* and is not
/// a digest at all. `validate()` pinned the shape of the first and asserted
/// nothing whatsoever about the second, so a receipt carrying two `sha256:`
/// values validated clean and an audit consumer joining on digests would join
/// the wrong records.
#[test]
fn validate_refuses_a_client_fingerprint_dressed_up_as_an_action_fingerprint() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("create must be gated to a receipt");
    };
    let (spec, segments) = probe_spec("projects", "create");
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &test_context(),
        &ClientActionIdentity::fixture(),
        true,
    )
    .expect("plan");
    let receipt = plan
        .dry_run()
        .receipt()
        .expect("a mutating verb returns a receipt")
        .clone();
    assert!(
        receipt.validate().is_empty(),
        "the produced receipt is well formed to begin with: {:?}",
        receipt.validate()
    );

    let mut forged = receipt.clone();
    forged.client_identity.client_fingerprint = format!("sha256:{}", "a".repeat(64));
    let problems = forged.validate();
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("client_fingerprint")
                && problem.contains("not a digest")),
        "a client fingerprint rendered as a canonical action fingerprint must be named as the \
         confusion it is: {problems:?}"
    );

    let mut unmarked = receipt;
    unmarked.client_identity.client_fingerprint = "cli=1.0;os=linux".to_string();
    assert!(
        unmarked
            .validate()
            .iter()
            .any(|problem| problem.contains("schema marker")),
        "a fingerprint with no schema marker cannot be told apart from a future v2: {:?}",
        unmarked.validate()
    );
}

/// The local clock cannot reach [`ServerIssuedClientSentAt`] along any path this
/// crate takes, and this is the half of that claim a test can hold.
///
/// Pins: [`ServerIssuedClientSentAt::from_server_time`] being the **only**
/// struct literal of that type in the crate.
///
/// Catches: a second construction site anywhere in `ferrogate-control-plane-client` —
/// which is exactly the shape of the surviving mutation in
/// [`a_sent_receipt_with_no_token_refuses_to_stand_the_local_clock_in`],
/// and of any future "just fill it in from the clock, it is only a fallback".
///
/// It is a source scan and not a value assertion for the same reason the
/// `SystemTime::now()` guard is: a fabricated instant is a perfectly plausible
/// number, and the defect is the *existence of a path*, not any particular
/// value on it. Together with `ServerIssuedTime` having no constructor taking an
/// instant — only `parse`, over bytes a server sent — this is the whole chain.
///
/// Deliberately scoped: the struct's fields are `pub` and it derives
/// `Deserialize`, both load-bearing (the CLI's renderers read the fields, an
/// audit consumer must parse a receipt back). So the guarantee is about this
/// crate's own code and is stated that way, rather than dressed up as a
/// type-level impossibility it is not.
#[test]
fn the_only_way_to_mint_a_client_sent_at_is_from_a_parsed_server_token() {
    // Assembled at runtime so this file's own scan is not a hit. The
    // alternative — skipping `*_test.rs` — would exempt test code from a rule
    // that should bind it too: a fixture receipt built with a hand-written
    // instant is how the shape gets normalised before it reaches production.
    let needle = format!("{}{}", "ServerIssuedClientSentAt", " {");
    let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut literals: Vec<String> = Vec::new();
    let mut files_scanned = 0usize;
    for entry in std::fs::read_dir(&source_dir).expect("the crate's src/ is readable") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        files_scanned += 1;
        let source = std::fs::read_to_string(&path).expect("source file is UTF-8");
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let mut enclosing = String::from("<file scope>");
        for line in source.lines() {
            let trimmed = line.trim_start();
            // Prose quotes the literal on purpose — including the mutation this
            // test exists to catch, spelled out in a doc comment. A guard a
            // comment can trip is not a guard.
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("fn "))
                .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
            {
                enclosing = rest
                    .split(['(', '<'])
                    .next()
                    .unwrap_or("<unnamed>")
                    .to_string();
            }
            // The type's own declaration and its `impl` block spell the same
            // characters and construct nothing.
            let is_declaration = trimmed.starts_with("impl ")
                || trimmed.contains(&format!("struct {}", "ServerIssuedClientSentAt"));
            if trimmed.contains(&needle) && !is_declaration {
                literals.push(format!("{name}::{enclosing}"));
            }
        }
    }
    // A floor: an empty or mis-rooted scan would otherwise make the assertion
    // below vacuous by finding nothing at all.
    assert!(
        files_scanned > 20,
        "expected the whole crate's src/, scanned only {files_scanned} files"
    );
    assert_eq!(
        literals,
        vec!["receipt.rs::from_server_time".to_string()],
        "ServerIssuedClientSentAt is constructed in exactly one place, from a ServerIssuedTime \
         and from nothing else. A second construction site is how a local clock reaches the \
         audit instant while every value assertion in this suite stays green"
    );
}

/// Every registered verb's DECLARED effect agrees with the HTTP method its
/// family builder actually emits.
///
/// This is the anti-vacuity guard on the whole slice: the render gate is a
/// type-level barrier, but which side of the barrier a verb lands on is a
/// `VerbEffect` field an author types. Deriving the same fact from the request
/// builder — which is what really talks to the server — means a
/// misclassification cannot hide behind a green suite.
///
/// The method is only a **proxy** for the effect, though, and an earlier cut of
/// this test made the proxy authoritative with a bare
/// `assert_eq!(!method_is_safe, verb.is_mutating())`. That did not detect
/// misclassification of effect, it detected disagreement with the method — and
/// it pinned the one known-wrong classification in place, because correcting
/// `mcp-identity callback` (a GET that completes an OAuth flow and persists an
/// identity grant) to `mutating` *failed* it. `METHOD_EFFECT_EXCEPTIONS` is the
/// narrow, reasoned escape hatch, and
/// [`method_effect_exceptions_are_all_live_and_needed`] stops it becoming a
/// place to hide a real misclassification.
#[test]
fn declared_verb_effect_matches_the_method_the_builder_emits() {
    let registry = full_registry();
    let expected = registry_verb_count(&registry);
    let expected_mutating = registry_mutating_verb_count(&registry);
    let mut checked = 0usize;
    let mut mutating = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            let (spec, _) = probe_spec(&group.name, &verb.name);
            let method_is_safe =
                matches!(spec.method, Method::GET | Method::HEAD | Method::OPTIONS);
            checked += 1;
            if verb.is_mutating() {
                mutating += 1;
            }
            // The method is a PROXY for the effect, not the effect. Where the
            // two genuinely disagree the exception carries a stated reason and
            // the method it expects; everywhere else the method rules.
            let expected_mutating = match method_effect_exception(&group.name, &verb.name) {
                Some(exception) => {
                    assert_eq!(
                        exception.method,
                        spec.method.as_str(),
                        "the method/effect exception for '{} {}' claims the builder emits {} but \
                         it emits {}; the exception is stale and must be re-justified",
                        group.name,
                        verb.name,
                        exception.method,
                        spec.method
                    );
                    exception.effect.is_mutating()
                }
                None => !method_is_safe,
            };
            assert_eq!(
                expected_mutating,
                verb.is_mutating(),
                "'{} {}' is declared '{}' but its builder emits {}; fix the VerbDescriptor \
                 constructor, fix the builder, or add a justified entry to \
                 METHOD_EFFECT_EXCEPTIONS",
                group.name,
                verb.name,
                verb.effect.as_str(),
                spec.method
            );
        }
    }
    assert_eq!(
        checked, expected,
        "every registered verb must reach the method/effect assertion exactly once"
    );
    assert_eq!(
        mutating, expected_mutating,
        "every registered mutating verb must reach the method/effect assertion exactly once"
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
                    assert_eq!(
                        renderer.verb().name,
                        verb.name,
                        "'{} {}' receipt renderer points at another verb",
                        group.name,
                        verb.name
                    );
                }
                RenderGate::Bare(renderer) => {
                    assert!(
                        !verb.is_mutating(),
                        "'{} {}' is declared mutating but opened a BARE render gate: a mutating \
                         verb must be unable to render a raw body",
                        group.name,
                        verb.name
                    );
                    assert_eq!(
                        renderer.verb().name,
                        verb.name,
                        "'{} {}' bare renderer points at another verb",
                        group.name,
                        verb.name
                    );
                }
            }
        }
    }
}

/// Every mutating verb can actually produce a receipt end to end, and every
/// receipt it produces is well formed (no silent nulls, canonical fingerprint,
/// stated absence reasons).
///
/// Read verbs are excluded by their declared effect. The final equality is a
/// census of the same registry, not a slack floor, so no mutating verb can
/// disappear from the sweep without changing the result.
#[test]
fn every_mutating_verb_produces_a_well_formed_receipt() {
    let registry = full_registry();
    let expected = registry_mutating_verb_count(&registry);
    let context = test_context();
    let mut produced = 0usize;
    for group in registry.groups() {
        for verb in &group.verbs {
            if !verb.is_mutating() {
                continue;
            }
            let RenderGate::Receipt(renderer) = verb.render_gate() else {
                unreachable!(
                    "'{} {}' is mutating but did not produce a receipt render gate",
                    group.name, verb.name
                )
            };
            let (spec, segments) = probe_spec(&group.name, &verb.name);
            let plan = MutationPlan::new(
                renderer,
                group.name.clone(),
                spec,
                &segments,
                &context,
                &ClientActionIdentity::fixture(),
                true,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "'{} {}' failed while planning its receipt: {error}",
                    group.name, verb.name
                )
            });
            let output = plan.dry_run();
            let receipt = output.receipt().unwrap_or_else(|| {
                panic!(
                    "'{} {}' produced no mutation receipt",
                    group.name, verb.name
                )
            });
            let problems = receipt.validate();
            assert!(
                problems.is_empty(),
                "receipt for '{} {}' is malformed: {problems:?}",
                group.name,
                verb.name
            );
            assert!(
                receipt.dry_run,
                "'{} {}' must echo dry_run as true",
                group.name, verb.name
            );
            assert!(
                output.body().is_none(),
                "'{} {}' receipt output must never expose a bare body",
                group.name,
                verb.name
            );
            produced += 1;
        }
    }
    assert_eq!(
        produced, expected,
        "every registered mutating verb must produce one receipt"
    );
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
    let (spec, segments) = probe_spec("guardrail-policies", "create-revision");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        true,
    )
    .expect("plan");

    let transport = RecordingTransport::with_body(r#"{"object":"guardrail_policy_revision"}"#);
    let transport = std::sync::Arc::new(transport);
    let client = ControlPlaneClient::new(
        context,
        None,
        std::sync::Arc::clone(&transport),
        ClientActionIdentity::fixture(),
    );

    let output = block_on(plan.execute(&client))
        .into_result()
        .expect("dry run succeeds");

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
    let (spec, segments) = probe_spec("guardrail-policies", "create-revision");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        false,
    )
    .expect("plan");

    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_1","revision":4}}"#,
    ));
    let client = ControlPlaneClient::new(
        context,
        None,
        std::sync::Arc::clone(&transport),
        ClientActionIdentity::fixture(),
    );

    let output = block_on(plan.execute(&client))
        .into_result()
        .expect("mutation succeeds");
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
    let (spec, segments) = probe_spec("projects", "create");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"project","project":{"id":"proj_1","name":"n","status":"active"}}"#,
    ));
    let client = ControlPlaneClient::new(
        context,
        None,
        std::sync::Arc::clone(&transport),
        ClientActionIdentity::fixture(),
    );
    let output = block_on(plan.execute(&client))
        .into_result()
        .expect("mutation");
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
///
/// Asserted on the **cell**, not on the row label. The previous cut checked
/// `rendered.contains("audit_id")` / `"dry_run"` / `"target.action_fingerprint"`
/// — literal row labels the table emits unconditionally for any receipt — so
/// deleting the `null (<code>)` formatting in `cell()` and printing a bare
/// `null` left three of the four checks green. A coverage check that survives
/// the deletion of the thing it covers is not covering it.
#[test]
fn table_render_states_the_nulls() {
    let registry = full_registry();
    let verb = registry.resolve("projects", "delete").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("gated");
    };
    let (spec, segments) = probe_spec("projects", "delete");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        true,
    )
    .expect("plan");
    let output = plan.dry_run();
    let rendered = render_output(OutputFormat::Table, &output, |_| {
        panic!("a receipt must never route through the bare-body table projection")
    })
    .expect("render table");
    // Every absent field renders `null (<code>)`. Deleting the parenthesized
    // code — or the word `null` — reds this.
    for (label, code) in [
        ("audit_id", absence_codes::DRY_RUN_NOT_EXECUTED),
        ("approval_id", absence_codes::DRY_RUN_NOT_EXECUTED),
        (
            "actor.subject",
            absence_codes::SUBJECT_NOT_LOCALLY_RESOLVABLE,
        ),
        ("decision", absence_codes::NO_DECISION_IN_CONTRACT),
        ("rollback", absence_codes::RESOURCE_HAS_NO_REVISIONS),
        ("http_status", absence_codes::DRY_RUN_NOT_EXECUTED),
    ] {
        let expected = format!("null ({code})");
        let row = rendered
            .lines()
            .find(|line| line.starts_with(label))
            .unwrap_or_else(|| panic!("the table dropped the '{label}' row:\n{rendered}"));
        assert!(
            row.contains(&expected),
            "the '{label}' row must render '{expected}', got:\n{row}"
        );
    }
    // The non-null discriminators carry their values, not just their labels.
    assert!(
        rendered.contains("dry_run") && rendered.contains("true"),
        "{rendered}"
    );
    let fingerprint_row = rendered
        .lines()
        .find(|line| line.starts_with("target.action_fingerprint "))
        .expect("the fingerprint row");
    assert!(
        fingerprint_row.contains("sha256:"),
        "the fingerprint row must carry the digest, not just the label: {fingerprint_row}"
    );
    let outcome_row = rendered
        .lines()
        .find(|line| line.starts_with("outcome"))
        .expect("the outcome row");
    assert!(
        outcome_row.contains(MutationOutcome::NotSent.as_str()),
        "a dry run's table must say the change was not sent: {outcome_row}"
    );
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
    let (spec, segments) = probe_spec("guardrail-policies", "create-revision");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_42","revision":7,"status":"active"}}"#,
    ));
    let client = ControlPlaneClient::new(
        context,
        None,
        std::sync::Arc::clone(&transport),
        ClientActionIdentity::fixture(),
    );
    let output = block_on(plan.execute(&client))
        .into_result()
        .expect("mutation");
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
    let (spec, segments) = probe_spec("guardrail-policies", "create");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_new","revision":1}}"#,
    ));
    let client = ControlPlaneClient::new(
        context,
        None,
        std::sync::Arc::clone(&transport),
        ClientActionIdentity::fixture(),
    );
    let output = block_on(plan.execute(&client))
        .into_result()
        .expect("mutation");
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

/// The live Admin API response for `guardrail-policies activate` is the binding
/// document, not the immutable revision document:
/// `{"object":"guardrail_policy_binding","policy_id":...,"active_revision":...}`.
/// The receipt still owes a rollback pointer for the guardrail family, so
/// `active_revision` is a revision identifier for this response shape.
#[test]
fn guardrail_binding_response_yields_a_rollback_pointer() {
    let report = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        200,
        r#"{"object":"guardrail_policy_binding","policy_id":"gp_1","active_revision":2,"rollback":false,"reload":{"status":"applied"}}"#,
    );
    let receipt = report.output().receipt().expect("receipt");

    assert_eq!(receipt.target.object_version.value.as_deref(), Some("2"));
    let pointer = receipt
        .rollback
        .value
        .as_ref()
        .expect("active guardrail binding has a rollback pointer");
    assert_eq!(
        pointer.command,
        vec![
            "ctl".to_string(),
            "guardrail-policies".to_string(),
            "rollback".to_string(),
            "gp_1".to_string(),
            "--data".to_string(),
            "{\"revision\":1}".to_string(),
        ],
        "the pointer must be derived from policy_id + active_revision in the binding response"
    );
    assert_eq!(pointer.created_revision.value.as_deref(), Some("2"));
    assert_eq!(pointer.restores_revision.value.as_deref(), Some("1"));
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
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

/// The receipt's `decision` is a verdict on the CLI **call**, and no endpoint
/// returns one — so it is never populated from the resource's own state, even
/// when the response spells a field `decision` in exactly the runtime's
/// vocabulary.
///
/// This is the regression the previous cut shipped: `ctl tool-approvals deny
/// ta_9` succeeds with HTTP 200 and returns `decision: "deny"`, and a blind
/// scan rendered `decision.value.decision == "deny"` under a field documented
/// as a policy decision. An audit query selecting refused mutations picked up
/// every *successful* denial. The fixture that used to sit here
/// (`{"approval": {"decision": "approved"}}`) blessed the conflation instead of
/// catching it.
#[test]
fn decision_is_never_harvested_from_the_resources_own_state() {
    // The exact shape a successful `tool-approvals deny` returns.
    let denied = execute_against(
        "tool-approvals",
        "deny",
        &["ta_9".to_string()],
        200,
        r#"{"object":"tool_approval","approval":{"id":"ta_9","decision":"deny","decision_reason":"operator refused"}}"#,
    );
    let receipt = denied.output().receipt().expect("receipt");
    assert_eq!(
        receipt.outcome,
        MutationOutcome::Applied,
        "the denial itself succeeded"
    );
    assert!(
        receipt.decision.value.is_none(),
        "the approval's own verdict must not be reported as a verdict on the CLI call: {:?}",
        receipt.decision.value
    );
    assert_eq!(
        receipt.decision.absent_code(),
        Some(absence_codes::NO_DECISION_IN_CONTRACT)
    );

    // …and the same for the runtime's own spellings at the top level, so the
    // rule is "never harvested", not "not harvested from this nesting".
    for body in [
        r#"{"decision":"allow"}"#,
        r#"{"decision":"deny","decision_reason":"budget"}"#,
        r#"{"object":"payment_attempt","attempt":{"decision":"degrade"}}"#,
    ] {
        let receipt = execute_against(
            "guardrail-policies",
            "activate",
            &["gp_1".to_string()],
            200,
            body,
        );
        let receipt = receipt.output().receipt().expect("receipt").clone();
        assert_eq!(
            receipt.decision.absent_code(),
            Some(absence_codes::NO_DECISION_IN_CONTRACT),
            "a response spelling '{body}' must not populate the receipt's decision"
        );
    }
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
    let (spec, segments) = probe_spec("projects", "create");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        true,
    )
    .expect("plan");
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
    let (spec, segments) = probe_spec("guardrail-policies", "dry-run");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "guardrail-policies",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        false,
    )
    .expect("plan");
    let transport = std::sync::Arc::new(RecordingTransport::with_body(r#"{"object":"ok"}"#));
    let client = ControlPlaneClient::new(
        context,
        None,
        std::sync::Arc::clone(&transport),
        ClientActionIdentity::fixture(),
    );
    let output = block_on(plan.execute(&client))
        .into_result()
        .expect("mutation");
    assert_eq!(transport.request_count(), 1);
    assert!(
        !output.receipt().expect("receipt").dry_run,
        "the verb is named dry-run but the client executed it for real"
    );
}

// ---------------------------------------------------------------------------
// The rollback pointer: every family that gets one is pinned, individually.
// ---------------------------------------------------------------------------

/// Parse a [`RollbackPointer::command`] argv back into the pieces a dispatch
/// needs, so a test can hand it to the real request builder. Mirrors the clap
/// shape of `ferrogate ctl <group> <verb> [SEGMENT…] [--data JSON]`.
fn parse_rollback_argv(argv: &[String]) -> (String, String, Vec<String>, Option<Value>) {
    assert_eq!(
        argv.first().map(String::as_str),
        Some("ctl"),
        "a rollback command must be a `ctl` invocation: {argv:?}"
    );
    let group = argv[1].clone();
    let verb = argv[2].clone();
    let mut segments = Vec::new();
    let mut body = None;
    let mut index = 3;
    while index < argv.len() {
        if argv[index] == "--data" {
            let raw = argv
                .get(index + 1)
                .unwrap_or_else(|| panic!("--data with no value: {argv:?}"));
            body = Some(
                serde_json::from_str::<Value>(raw)
                    .unwrap_or_else(|error| panic!("--data '{raw}' is not JSON: {error}")),
            );
            index += 2;
            continue;
        }
        segments.push(argv[index].clone());
        index += 1;
    }
    (group, verb, segments, body)
}

/// **The pin that would have caught the destructive bug.** For every entry in
/// [`REVISIONED_FAMILIES`] — not just the one the E2E happens to exercise — the
/// argv the receipt emits is fed back through that family's *own* request
/// builder and must produce a request the family accepts.
///
/// [`RollbackPointer::command`] is documented as safe for a script to execute
/// verbatim, so this is the literal contract. The previous cut listed
/// `agent-schedules` and `gateway-configs` with `rollback_verb: "replace"` /
/// `archive_verb: "delete"`, which built
/// `PUT /admin/v1/gateway-configs/prod {"revision":3}` — replacing a whole
/// config profile with a one-field document — and
/// `DELETE /admin/v1/agent-schedules/<id>/1`, a path that does not exist. Both
/// are green under a test that only exercises `guardrail-policies`; neither
/// survives this one.
#[test]
fn rollback_pointer_argv_round_trips_through_every_familys_own_builder() {
    let registry = full_registry();
    let revisioned_groups = REVISIONED_FAMILIES
        .iter()
        .map(|family| family.group)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        revisioned_groups,
        BTreeSet::from(["guardrail-policies"]),
        "the guard must cover the complete reviewed revisioned-family set"
    );
    for family in REVISIONED_FAMILIES {
        // The verbs the pointer names must exist on the family it names.
        let group = registry
            .groups()
            .iter()
            .find(|group| group.name == family.group)
            .unwrap_or_else(|| panic!("'{}' is not a registered group", family.group));
        for verb in [family.rollback_verb, family.archive_verb] {
            let descriptor = group
                .verbs
                .iter()
                .find(|candidate| candidate.name == verb)
                .unwrap_or_else(|| panic!("'{} {verb}' is not a registered verb", family.group));
            assert!(
                descriptor.is_mutating(),
                "'{} {verb}' reverses a mutation, so it must itself be a mutating verb",
                family.group
            );
        }

        // Mid-chain: the pointer must be a rollback, and the argv must build.
        let mid = execute_against(
            family.group,
            family.rollback_verb,
            &["chain-1".to_string()],
            200,
            &format!(
                r#"{{"object":"revision","resource":{{"id":"chain-1","policy_id":"chain-1","{}":4}}}}"#,
                family.revision_keys[0]
            ),
        );
        let pointer = mid
            .output()
            .receipt()
            .expect("receipt")
            .rollback
            .value
            .clone()
            .unwrap_or_else(|| panic!("'{}' must emit a rollback pointer", family.group));
        assert_eq!(pointer.restores_revision.value.as_deref(), Some("3"));
        let (group_name, verb, segments, body) = parse_rollback_argv(&pointer.command);
        assert_eq!(group_name, family.group);
        assert_eq!(verb, family.rollback_verb);
        let mut input = ResourceInput::new().with_segments(segments);
        if let Some(body) = body {
            input = input.with_body(body);
        }
        let spec = build_request(&group_name, &verb, &input).unwrap_or_else(|error| {
            panic!(
                "the rollback command {:?} the receipt emits is not a request \
                 '{group_name}' accepts: {error}",
                pointer.command
            )
        });
        assert!(
            spec.path.contains("chain-1"),
            "the reversal must address the chain the mutation touched, got {}",
            spec.path
        );

        // First revision: the pointer must be an archive, and that argv must
        // build too. `ctl agent-schedules delete <id> 1` passed the first half
        // of this check and failed the second.
        let first = execute_against(
            family.group,
            family.rollback_verb,
            &["chain-2".to_string()],
            200,
            &format!(
                r#"{{"object":"revision","resource":{{"id":"chain-2","policy_id":"chain-2","{}":1}}}}"#,
                family.revision_keys[0]
            ),
        );
        let pointer = first
            .output()
            .receipt()
            .expect("receipt")
            .rollback
            .value
            .clone()
            .expect("a first-revision pointer");
        assert_eq!(
            pointer.restores_revision.absent_code(),
            Some(absence_codes::NO_PRIOR_REVISION)
        );
        let (group_name, verb, segments, body) = parse_rollback_argv(&pointer.command);
        assert_eq!(verb, family.archive_verb);
        let mut input = ResourceInput::new().with_segments(segments);
        if let Some(body) = body {
            input = input.with_body(body);
        }
        build_request(&group_name, &verb, &input).unwrap_or_else(|error| {
            panic!(
                "the archive command {:?} the receipt emits is not a request \
                 '{group_name}' accepts: {error}",
                pointer.command
            )
        });
    }
}

/// A family that merely carries a `revision` counter is **not** a revision
/// chain, and reports so instead of emitting a reversal command.
///
/// `agent-schedules` and `gateway-configs` both route through `build_crud`:
/// `revision` there is a concurrency token on one mutable row, and neither has
/// a verb that restores an earlier one. Naming them explicitly (rather than
/// asserting "everything not in the list") is the point — they are the two that
/// were wrong, so they are the two a future edit must trip over.
#[test]
fn a_revision_counter_without_a_chain_reports_no_rollback_pointer() {
    for (group, verb, segments) in [
        ("gateway-configs", "update", vec!["prod".to_string()]),
        ("agent-schedules", "update", vec!["sched_1".to_string()]),
    ] {
        assert!(
            revisioned_family(group).is_none(),
            "'{group}' has no reversal verb, so it must not be a revisioned family"
        );
        let report = execute_against(
            group,
            verb,
            &segments,
            200,
            r#"{"object":"config","config":{"id":"prod","revision":4}}"#,
        );
        let receipt = report.output().receipt().expect("receipt");
        assert!(
            receipt.rollback.value.is_none(),
            "'{group} {verb}' emitted a rollback command it has no verb for: {:?}",
            receipt.rollback.value
        );
        assert_eq!(
            receipt.rollback.absent_code(),
            Some(absence_codes::RESOURCE_HAS_NO_REVISIONS),
            "'{group} {verb}' must say WHY there is no pointer"
        );
        // The revision is still reported as the object's version - the counter
        // is real, it just is not a chain.
        assert_eq!(receipt.target.object_version.value.as_deref(), Some("4"));
    }
}

// ---------------------------------------------------------------------------
// Method/effect exceptions.
// ---------------------------------------------------------------------------

/// Every method/effect exception is live, accurate, and still needed.
///
/// Without this, [`METHOD_EFFECT_EXCEPTIONS`] is a place to silence the
/// classification guard: an entry naming a verb that no longer exists, or one
/// that agrees with the method anyway, would sit there indefinitely while
/// widening what the guard tolerates.
#[test]
fn method_effect_exceptions_are_all_live_and_needed() {
    let registry = full_registry();
    for exception in METHOD_EFFECT_EXCEPTIONS {
        let descriptor = registry
            .resolve(exception.group, exception.verb)
            .unwrap_or_else(|error| {
                panic!(
                    "the exception for '{} {}' names a verb that is not registered: {error}",
                    exception.group, exception.verb
                )
            });
        assert_eq!(
            descriptor.effect,
            exception.effect,
            "'{} {}' is declared '{}' but its exception claims '{}'",
            exception.group,
            exception.verb,
            descriptor.effect.as_str(),
            exception.effect.as_str()
        );
        let (spec, _) = probe_spec(exception.group, exception.verb);
        assert_eq!(
            spec.method.as_str(),
            exception.method,
            "the exception for '{} {}' is stale: the builder now emits {}",
            exception.group,
            exception.verb,
            spec.method
        );
        let method_is_safe = matches!(spec.method, Method::GET | Method::HEAD | Method::OPTIONS);
        assert_eq!(
            method_is_safe,
            exception.effect.is_mutating(),
            "the exception for '{} {}' agrees with its HTTP method, so it is not an exception \
             and must be deleted",
            exception.group,
            exception.verb
        );
        assert!(
            exception.why.len() > 40,
            "an exception without a stated reason is a silenced misclassification: '{} {}'",
            exception.group,
            exception.verb
        );
    }
}

/// `mcp-identity callback` completes an OAuth flow and persists an identity
/// grant, so it is gated to a receipt despite being a GET — and `--dry-run`
/// therefore applies to it, which is what an operator needs before completing
/// a grant.
#[test]
fn the_oauth_callback_is_a_mutating_verb_despite_being_a_get() {
    let registry = full_registry();
    let descriptor = registry
        .resolve("mcp-identity", "callback")
        .expect("registered");
    assert!(
        descriptor.is_mutating(),
        "completeMcpIdentityOauth persists an identity grant"
    );
    assert!(matches!(descriptor.render_gate(), RenderGate::Receipt(_)));
    let (spec, _) = probe_spec("mcp-identity", "callback");
    assert_eq!(
        spec.method,
        Method::GET,
        "the exception exists precisely because the method is a GET"
    );
}

// ---------------------------------------------------------------------------
// A receipt on the failing paths.
// ---------------------------------------------------------------------------

/// A refused mutation still produces a receipt on stdout — with the server's
/// status, error code, correlation ids and the target fingerprint — and still
/// propagates the failure so the process exits on its own class.
///
/// The previous cut returned `Err` before rendering, so under `--output json` a
/// non-2xx wrote prose to stderr and **nothing** to stdout: an audit pipeline
/// recorded no evidence at all for the mutation an operator most needs evidence
/// for.
#[test]
fn a_refused_mutation_still_produces_a_receipt() {
    let report = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        409,
        r#"{"error":{"code":"revision_conflict","message":"revision 2 is not the head"}}"#,
    );
    let failure = report
        .failure()
        .expect("a 409 must still be an error the caller propagates");
    assert!(
        matches!(failure, CliError::Api(api) if api.http_status == 409),
        "the failure keeps its class so the process exits on it: {failure}"
    );

    let receipt = report.output().receipt().expect("a receipt, not nothing");
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
    assert_eq!(receipt.outcome, MutationOutcome::Rejected);
    assert!(!receipt.dry_run, "the client did issue the call");
    assert_eq!(receipt.http_status.value, Some(409));
    let recorded = receipt.failure.value.as_ref().expect("the failure");
    assert_eq!(recorded.class, "api");
    assert_eq!(recorded.code, "revision_conflict");
    assert!(recorded.message.contains("not the head"));
    // Still joinable to gateway evidence, and still identifies the action.
    assert_eq!(
        receipt.correlation.request_id.value.as_deref(),
        Some("fgadm-receipt-1")
    );
    assert!(is_canonical_action_fingerprint(
        &receipt.target.action_fingerprint
    ));
    // Nothing landed, and every server-derived field says so with THAT reason
    // rather than borrowing the dry-run one.
    assert!(receipt.response.is_none());
    assert_eq!(
        receipt.rollback.absent_code(),
        Some(absence_codes::MUTATION_NOT_APPLIED)
    );
    assert_eq!(
        receipt.audit_id.absent_code(),
        Some(absence_codes::MUTATION_NOT_APPLIED)
    );
    assert_eq!(
        receipt.target.object_version.absent_code(),
        Some(absence_codes::MUTATION_NOT_APPLIED)
    );
}

/// The case the receipt exists for: a mutation whose outcome is **unknown**.
///
/// A 504 (or a dropped connection) after the server committed is not "it did
/// not happen". The receipt must not claim it did not, and must not claim it
/// did — `outcome: unknown` is the only honest answer, and it is a distinct
/// value from `rejected` so an operator can select exactly the calls that need
/// reconciling.
#[test]
fn an_ambiguous_failure_reports_the_outcome_as_unknown_not_as_refused() {
    let report = execute_with_no_answer(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        "connection closed before the response headers arrived",
    );
    assert!(report.failure().is_some());
    let receipt = report.output().receipt().expect("a receipt");
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
    assert_eq!(
        receipt.outcome,
        MutationOutcome::Unknown,
        "an answerless failure must not be reported as a refusal"
    );
    assert_eq!(
        receipt.http_status.absent_code(),
        Some(absence_codes::NO_HTTP_RESPONSE)
    );
    let recorded = receipt.failure.value.as_ref().expect("the failure");
    assert_eq!(recorded.class, "transport");
    assert_eq!(
        receipt.audit_id.absent_code(),
        Some(absence_codes::MUTATION_OUTCOME_UNKNOWN),
        "the audit id is missing because we do not know what happened, not because the \
         endpoint declares none"
    );
    // The target is still fully identified, so the operator can reconcile.
    assert_eq!(receipt.target.method, "POST");
    assert!(receipt.target.path.contains("gp_1"));
}

/// A `504` **is** an HTTP response, and the earlier cut folded every non-2xx
/// into "the server refused", so a gateway timeout after the write committed
/// produced a receipt reading `outcome: rejected` with *"the Control Plane API
/// refused this mutation, so no server-side artifact of the change exists"* on
/// `rollback`, `audit_id` and `object_version`. Every one of those is false for
/// a change that landed, on precisely the invocation an operator must
/// reconcile.
///
/// Sits next to [`a_refused_mutation_still_produces_a_receipt`] so the two are
/// proven **distinct**: same verb, same transport, same code path, one status
/// apart in meaning.
#[test]
fn a_gateway_timeout_is_unknown_not_an_authoritative_refusal() {
    let report = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        504,
        r#"{"error":{"code":"gateway_timeout","message":"upstream did not respond in time"}}"#,
    );
    assert!(
        report.failure().is_some(),
        "a 504 is still an error the caller propagates"
    );
    let receipt = report.output().receipt().expect("a receipt, not nothing");
    assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());

    assert_eq!(
        receipt.outcome,
        MutationOutcome::Unknown,
        "the server may have committed before the intermediary gave up; claiming a refusal is a \
         fabrication"
    );
    // The status IS reported — this is not the answerless case — and the
    // failure is still classed `api`, so the receipt does not pretend the
    // response never arrived either.
    assert_eq!(receipt.http_status.value, Some(504));
    let recorded = receipt.failure.value.as_ref().expect("the failure");
    assert_eq!(recorded.class, "api");
    assert_eq!(recorded.code, "gateway_timeout");

    // The three fields the wrong classification poisoned.
    for (field, absent) in [
        ("audit_id", receipt.audit_id.absent_code()),
        ("rollback", receipt.rollback.absent_code()),
        (
            "target.object_version",
            receipt.target.object_version.absent_code(),
        ),
    ] {
        assert_eq!(
            absent,
            Some(absence_codes::MUTATION_OUTCOME_UNKNOWN),
            "{field} must say the outcome is unknown, not that the mutation was not applied"
        );
    }
    // ...and the prose has to say it too, or the table render still tells the
    // operator nothing happened.
    let detail = receipt
        .audit_id
        .absent_reason
        .as_ref()
        .expect("a stated reason")
        .detail
        .clone();
    assert!(
        detail.contains("may or may not have been applied"),
        "the detail must leave both possibilities open: {detail}"
    );
    assert!(
        !detail.contains("refused"),
        "the detail must not claim a refusal: {detail}"
    );
    assert!(
        detail.contains("504"),
        "the ambiguous status is the thing to reconcile against, so name it: {detail}"
    );
}

/// The retryable-timeout statuses are the second half of the same defect, and
/// the one where the contradiction is visible inside a single invocation: this
/// crate already exits a `429` on [`ExitClass::Transport`], documented as *"the
/// request never produced an authoritative server answer"*. A receipt asserting
/// the server made an authoritative decision would put two fields of one
/// command in direct conflict — an edge throttle can reject a *retry* of a call
/// the origin already accepted.
#[test]
fn a_throttled_mutation_agrees_with_the_exit_class_it_returns() {
    for status in [408u16, 425, 429] {
        let report = execute_against(
            "guardrail-policies",
            "activate",
            &["gp_1".to_string()],
            status,
            r#"{"error":{"code":"rate_limited","message":"slow down"}}"#,
        );
        let failure = report.failure().expect("still an error");
        assert_eq!(
            failure.exit_class(),
            ExitClass::Transport,
            "HTTP {status} exits on the non-authoritative class"
        );
        let receipt = report.output().receipt().expect("a receipt");
        assert!(receipt.validate().is_empty(), "{:?}", receipt.validate());
        assert_eq!(
            receipt.outcome,
            MutationOutcome::Unknown,
            "HTTP {status} exits on the non-authoritative class, so the receipt may not report an \
             authoritative decision"
        );
        assert_eq!(
            receipt.audit_id.absent_code(),
            Some(absence_codes::MUTATION_OUTCOME_UNKNOWN)
        );
    }
}

/// The boundary itself, stated independently of the implementation: what a
/// status licenses the receipt to claim is **authority**, not success.
///
/// Swept over the whole status space rather than sampled, because the defect
/// was a missing distinction, and a fixture-only test would only pin the
/// statuses someone thought to write down.
#[test]
fn the_outcome_a_status_permits_is_authority_not_success() {
    // The boundary cases, spelled out so the ranges below cannot drift
    // silently.
    for status in [200u16, 201, 202, 204] {
        assert_eq!(
            MutationOutcome::from_http_status(status),
            MutationOutcome::Applied
        );
    }
    for status in [400u16, 401, 402, 403, 404, 405, 409, 410, 422, 451, 499] {
        assert_eq!(
            MutationOutcome::from_http_status(status),
            MutationOutcome::Rejected,
            "HTTP {status} is the server having looked at the request and refused it"
        );
    }
    for status in [408u16, 425, 429, 500, 502, 503, 504, 599] {
        assert_eq!(
            MutationOutcome::from_http_status(status),
            MutationOutcome::Unknown,
            "HTTP {status} says nothing about whether the write committed"
        );
    }

    let mut rejected = 0usize;
    let mut unknown = 0usize;
    for status in 100u16..600 {
        let outcome = MutationOutcome::from_http_status(status);
        let class = ExitClass::from_http_status(status);
        match outcome {
            MutationOutcome::Rejected => {
                rejected += 1;
                assert!(
                    (400..500).contains(&status),
                    "only a client error is an authoritative refusal, not HTTP {status}"
                );
                assert_ne!(
                    class,
                    ExitClass::Transport,
                    "HTTP {status} exits on the non-authoritative class; its receipt cannot \
                     claim the server decided"
                );
                assert_ne!(
                    class,
                    ExitClass::Server,
                    "HTTP {status} is the server failing after accepting the request"
                );
            }
            MutationOutcome::Unknown => {
                unknown += 1;
                assert!(
                    !matches!(
                        class,
                        ExitClass::Auth | ExitClass::NotFoundConflict | ExitClass::Validation
                    ),
                    "HTTP {status} exits on an authoritative class but reports unknown"
                );
            }
            MutationOutcome::Applied => assert_eq!(
                class,
                ExitClass::Success,
                "HTTP {status} is not a 2xx and must not report the change as applied"
            ),
            MutationOutcome::NotSent => {
                panic!("HTTP {status} means a request was sent")
            }
        }
        if (500..600).contains(&status) {
            assert_eq!(
                outcome,
                MutationOutcome::Unknown,
                "a 5xx may follow a committed write"
            );
        }
    }
    // Non-vacuity: both arms are populated, so neither assertion above is
    // holding over an empty set.
    assert!(rejected > 90, "expected the 4xx block, saw {rejected}");
    assert!(
        unknown > 100,
        "expected the 5xx block plus 408/425/429, saw {unknown}"
    );
}

/// The control: a 2xx reports `applied` and no failure, so the outcome field is
/// discriminating rather than a constant.
#[test]
fn an_applied_mutation_reports_no_failure() {
    let report = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        200,
        r#"{"object":"guardrail_policy_revision","policy":{"policy_id":"gp_1","revision":2}}"#,
    );
    assert!(report.failure().is_none());
    let receipt = report.output().receipt().expect("receipt");
    assert_eq!(receipt.outcome, MutationOutcome::Applied);
    assert_eq!(
        receipt.failure.absent_code(),
        Some(absence_codes::MUTATION_SUCCEEDED)
    );
    assert!(receipt.validate().is_empty());
}

// ---------------------------------------------------------------------------
// Harvesting: what the receipt reads out of the response, and what it will not.
// ---------------------------------------------------------------------------

/// A `create` harvests the id the server assigned, so an audit query keyed on
/// `target.resource_id` can say what was created.
///
/// It used to stay `null` with "the server assigns the id in the response" even
/// though the response had arrived carrying it — leaving the operator to parse
/// the nested raw body, which is the bare-body reading this receipt exists to
/// remove.
#[test]
fn a_create_harvests_the_server_assigned_id() {
    let report = execute_against(
        "projects",
        "create",
        &[],
        201,
        r#"{"object":"project","project":{"id":"proj_1","name":"n","status":"active"}}"#,
    );
    let receipt = report.output().receipt().expect("receipt");
    assert_eq!(
        receipt.target.resource_id.value.as_deref(),
        Some("proj_1"),
        "the created id is in the response; the receipt must name it"
    );

    // A flat (unwrapped) document works the same way.
    let flat = execute_against("projects", "create", &[], 201, r#"{"id":"proj_2"}"#);
    assert_eq!(
        flat.output()
            .receipt()
            .expect("receipt")
            .target
            .resource_id
            .value
            .as_deref(),
        Some("proj_2")
    );

    // The absence reason is reserved for a genuinely id-less response.
    let idless = execute_against("projects", "create", &[], 201, r#"{"object":"project"}"#);
    assert_eq!(
        idless
            .output()
            .receipt()
            .expect("receipt")
            .target
            .resource_id
            .absent_code(),
        Some(absence_codes::RESPONSE_NAMES_NO_RESOURCE_ID)
    );

    // An item-scoped verb still reports the id the operator addressed.
    let addressed = execute_against(
        "projects",
        "delete",
        &["proj_9".to_string()],
        200,
        r#"{"object":"project","project":{"id":"proj_9"}}"#,
    );
    assert_eq!(
        addressed
            .output()
            .receipt()
            .expect("receipt")
            .target
            .resource_id
            .value
            .as_deref(),
        Some("proj_9")
    );
}

/// The fourth arm: `collection_scoped_mutation` — a collection verb where NO
/// response document was obtained, so no id was ever assigned to name.
///
/// This is the arm that distinguishes "the server created something and the
/// document did not say what" (`response_names_no_resource_id`, above) from
/// "nothing was created". An audit query reading the first as the second, or
/// vice versa, draws the opposite conclusion about whether a write happened.
///
/// It had no assertion anywhere in the repo (issue #564 review, minor 6): the
/// five references that named it were the pre-#505 expectations on the create
/// legs, and those became wrong when the receipt started harvesting, so
/// correcting them left the code reachable and uncovered. Collapsing the
/// `None =>` arm into the `Some` one — one absence code for both — reddened
/// nothing.
#[test]
fn a_collection_verb_with_no_response_reports_no_id_was_ever_assigned() {
    // A dry run: the request never left the process.
    let registry = full_registry();
    let verb = registry
        .resolve("projects", "create")
        .expect("projects create is registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("projects create must be gated to a receipt");
    };
    // Explicitly NO id segments: this arm only exists for a collection verb, so
    // the shape is stated here rather than borrowed from `probe_spec`. (Since
    // #569 the prober returns the SHORTEST arity a builder accepts, which for
    // `projects create` is zero segments — but a builder that started
    // tolerating an id would move the prober onto the `Addressed` arm and this
    // test would quietly stop covering the arm it names.)
    let input = ResourceInput::new().with_body(serde_json::json!({"probe": true}));
    let spec = build_request("projects", "create", &input).expect("create takes no id segments");
    let context = test_context();
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &[],
        &context,
        &ClientActionIdentity::fixture(),
        true,
    )
    .expect("plan");
    let dry = plan.dry_run();
    let receipt = dry.receipt().expect("receipt");
    assert_eq!(
        receipt.target.resource_id.value, None,
        "a dry run creates nothing, so there is no id to name"
    );
    assert_eq!(
        receipt.target.resource_id.absent_code(),
        Some(absence_codes::COLLECTION_SCOPED_MUTATION),
        "the null must say NOTHING WAS CREATED, not that a response omitted the id"
    );

    // And the failure case the same arm covers: the call was made and no
    // authoritative answer came back.
    let dead = execute_with_no_answer("projects", "create", &[], "connection reset");
    assert_eq!(
        dead.output()
            .receipt()
            .expect("receipt")
            .target
            .resource_id
            .absent_code(),
        Some(absence_codes::COLLECTION_SCOPED_MUTATION),
        "no response document was obtained, so no id can be attested"
    );
}

/// `object_version` is the version of the **changed object**, so the harvest is
/// bounded to the response envelope and its key priority is fixed.
///
/// The previous cut was a depth-4 depth-first walk over the whole document with
/// alphabetical sibling order, so a nested rule's or plugin's own `version` —
/// `SkillPackage`, `AssetSummary`, `AdminPlugin`, `X402ConversionRule` all
/// declare one — could be attested as the changed object's version, and
/// reordering `OBJECT_VERSION_KEYS` or changing `depth > 4` to `depth > 3`
/// changed nothing in any fixture. Both mutations red here.
#[test]
fn object_version_is_scoped_to_the_envelope_and_prefers_the_most_specific_key() {
    // Priority: `revision` outranks `version` outranks `etag`.
    let ranked = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        200,
        r#"{"object":"r","policy":{"etag":"W/e","revision":7,"version":"v2"}}"#,
    );
    assert_eq!(
        ranked
            .output()
            .receipt()
            .expect("receipt")
            .target
            .object_version
            .value
            .as_deref(),
        Some("7"),
        "`revision` is the most specific name for the changed object's version"
    );
    let without_revision = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        200,
        r#"{"object":"r","policy":{"etag":"W/e","version":"v2"}}"#,
    );
    assert_eq!(
        without_revision
            .output()
            .receipt()
            .expect("receipt")
            .target
            .object_version
            .value
            .as_deref(),
        Some("v2")
    );

    // A version on a NESTED sub-document is not the changed object's version.
    let nested = execute_against(
        "guardrail-policies",
        "activate",
        &["gp_1".to_string()],
        200,
        r#"{"object":"r","policy":{"id":"gp_1","rule":{"version":"rule-9"}}}"#,
    );
    assert_eq!(
        nested
            .output()
            .receipt()
            .expect("receipt")
            .target
            .object_version
            .absent_code(),
        Some(absence_codes::NO_OBJECT_VERSION),
        "a nested rule's own version must not be attested as the changed object's"
    );

    // An envelope that wraps two candidate resources names no single subject,
    // so nothing is harvested rather than the alphabetically-first one.
    assert_eq!(
        envelope_scalar(
            &serde_json::json!({"object": "r", "left": {"revision": 1}, "right": {"revision": 2}}),
            OBJECT_VERSION_KEYS
        ),
        None,
        "an ambiguous envelope must yield nothing, not a coin flip on key spelling"
    );
}

/// The receipt never carries the credential it authenticated with.
///
/// `AuthSource::Inline { token }` holds a plaintext bearer token, and
/// `credential_source` is the only thing between it and stdout. Nothing pinned
/// its value before, so `AuthSource::Inline { token } => format!("inline:{token}")`
/// left every test, `resource_cmd_test.rs` and the E2E green while printing the
/// bearer token inside an artifact designed to be piped into an audit query.
/// Asserted on the **rendered** JSON and table, so any other field that starts
/// echoing the token fails too.
#[test]
fn receipt_never_carries_the_token_it_authenticated_with() {
    const TOKEN: &str = "fg_live_super_secret_bearer_value";
    let registry = full_registry();
    let verb = registry.resolve("projects", "create").expect("registered");
    let RenderGate::Receipt(renderer) = verb.render_gate() else {
        panic!("gated");
    };
    let (spec, segments) = probe_spec("projects", "create");
    let mut context = test_context();
    context.auth = crate::auth::AuthSource::Inline {
        token: TOKEN.to_string(),
    };
    let plan = MutationPlan::new(
        renderer,
        "projects",
        spec,
        &segments,
        &context,
        &ClientActionIdentity::fixture(),
        true,
    )
    .expect("plan");
    let output = plan.dry_run();
    let receipt = output.receipt().expect("receipt");

    assert_eq!(
        receipt.actor.credential_source, "inline",
        "the receipt records the SHAPE of the credential source, never the material"
    );
    for rendered in [
        render_output(OutputFormat::Json, &output, |_| panic!("not a body")).expect("json"),
        render_output(OutputFormat::Table, &output, |_| panic!("not a body")).expect("table"),
    ] {
        assert!(
            !rendered.contains(TOKEN),
            "the rendered receipt leaked the bearer token:\n{rendered}"
        );
        assert!(
            rendered.contains("inline"),
            "the credential source must still be stated:\n{rendered}"
        );
    }
}

/// Exactly the audited allowlist of mutating operations returns an audit
/// identifier; every other mutating operation returns none (issue #552, split
/// from #505 acceptance box 6).
///
/// This is now a **deliberate contract invariant**, not the old "nothing
/// returns one". The guardrail-policy activate and rollback operations are the
/// first mutating operations #552 wired to return the id of the audit row they
/// write, so a receipt's `audit_id` can follow it to that row (issue #505 E2E
/// box 5(a)); every other mutating operation still returns no `audit*` property,
/// so its receipt's `audit_id` stays null with `NO_AUDIT_ID_IN_CONTRACT`.
///
/// The claim is re-derived from `docs/openapi/admin-api.openapi.json` on every
/// run rather than asserted in the abstract: the day another operation starts
/// declaring an audit id without joining the allowlist this fails and forces the
/// receipt's absence reason, the E2E's branch, and the module doc to be
/// corrected together. The failure message carries the full enumeration, so the
/// list exists in the repository rather than in a comment.
#[test]
fn only_the_audited_allowlist_of_mutating_operations_returns_an_audit_id() {
    /// The mutating operations #552 deliberately wired to return an audit id.
    /// Every other mutating operation must return none. Kept sorted.
    const AUDITED_ALLOWLIST: &[&str] = &[
        "activateGuardrailPolicyRevision",
        "rollbackGuardrailPolicyRevision",
    ];

    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json"))
            .expect("the OpenAPI contract parses");
    let components = spec["components"]["schemas"].clone();

    /// Whether a schema (following `$ref` through the component map, bounded)
    /// declares any `audit*` property.
    fn declares_audit_property(
        schema: &serde_json::Value,
        components: &serde_json::Value,
        depth: usize,
    ) -> bool {
        if depth > 6 {
            return false;
        }
        if let Some(reference) = schema.get("$ref").and_then(|value| value.as_str()) {
            let name = reference.rsplit('/').next().unwrap_or_default();
            return declares_audit_property(&components[name], components, depth + 1);
        }
        if let Some(properties) = schema.get("properties").and_then(|value| value.as_object()) {
            if properties.keys().any(|key| key.starts_with("audit")) {
                return true;
            }
            if properties
                .values()
                .any(|value| declares_audit_property(value, components, depth + 1))
            {
                return true;
            }
        }
        for key in ["items", "allOf", "oneOf", "anyOf"] {
            match schema.get(key) {
                Some(serde_json::Value::Array(variants)) => {
                    if variants
                        .iter()
                        .any(|variant| declares_audit_property(variant, components, depth + 1))
                    {
                        return true;
                    }
                }
                Some(value) => {
                    if declares_audit_property(value, components, depth + 1) {
                        return true;
                    }
                }
                None => {}
            }
        }
        false
    }

    let mut mutating: Vec<String> = Vec::new();
    // Allowlisted mutating operations that DO resolve an `audit*` property in a
    // 2xx schema, keyed by operation id.
    let mut allowlisted_declaring: BTreeSet<String> = BTreeSet::new();
    // Mutating operations that declare an audit id but are NOT allowlisted —
    // the regression this invariant now guards against.
    let mut unexpected_declaring: Vec<String> = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("paths") {
        let Some(operations) = item.as_object() else {
            continue;
        };
        for (method, operation) in operations {
            if !matches!(method.as_str(), "post" | "put" | "patch" | "delete") {
                continue;
            }
            let operation_id = operation["operationId"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{method} {path}"));
            mutating.push(operation_id.clone());
            let Some(responses) = operation.get("responses").and_then(|r| r.as_object()) else {
                continue;
            };
            for (status, response) in responses {
                if !status.starts_with('2') {
                    continue;
                }
                let schema = &response["content"]["application/json"]["schema"];
                if declares_audit_property(schema, &components, 0) {
                    if AUDITED_ALLOWLIST.contains(&operation_id.as_str()) {
                        allowlisted_declaring.insert(operation_id.clone());
                    } else {
                        unexpected_declaring.push(format!("{operation_id} ({status})"));
                    }
                }
            }
        }
    }
    mutating.sort();
    assert!(
        mutating.len() > 100,
        "the structural scan found only {} mutating operations, which means it stopped scanning",
        mutating.len()
    );
    // Non-vacuity: the allowlist is a real, non-empty set, and it is meaningful
    // only if each of its operations exists as a mutating operation.
    assert!(
        !AUDITED_ALLOWLIST.is_empty(),
        "the audited allowlist must name at least one operation, or this test degenerates back \
         into 'nothing returns an audit id'"
    );
    for operation_id in AUDITED_ALLOWLIST {
        assert!(
            mutating.iter().any(|found| found == operation_id),
            "allowlisted audited operation '{operation_id}' is not a mutating operation in the \
             contract; the allowlist is stale"
        );
    }
    // The invariant's positive half: every allowlisted operation DOES resolve an
    // `audit*` property in a 2xx schema. Without this the test would pass even if
    // #552's schema change were reverted.
    let missing_allowlisted: Vec<&str> = AUDITED_ALLOWLIST
        .iter()
        .copied()
        .filter(|operation_id| !allowlisted_declaring.contains(*operation_id))
        .collect();
    assert!(
        missing_allowlisted.is_empty(),
        "these audited operations must return an audit identifier but do not: {missing_allowlisted:?} \
         — #552 wired guardrail-policy activate/rollback to return the id of the audit row they \
         write; a reverted schema or renamed property reds here"
    );
    // The invariant's negative half: no operation OUTSIDE the allowlist returns
    // an audit id, so every other receipt's `audit_id` stays null with
    // NO_AUDIT_ID_IN_CONTRACT.
    assert!(
        unexpected_declaring.is_empty(),
        "these NON-allowlisted mutating operations now return an audit identifier: \
         {unexpected_declaring:?} — either wire the receipt to follow it and add the operation to \
         AUDITED_ALLOWLIST, or drop the audit property.\n\nEnumeration of the {} mutating \
         operations:\n{}",
        mutating.len(),
        mutating.join("\n")
    );
}
