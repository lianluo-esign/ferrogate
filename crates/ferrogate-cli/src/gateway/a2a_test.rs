// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Tests for A2A (agent-to-agent) ingress deep governance (issue
// #278): message-envelope parsing into the guardrail model, a content guardrail
// firing on an A2A message body in both directions, and the A2A exchange landing
// in metering + usage aggregates attributable to the calling key/tenant.

use super::{
    a2a_input_envelope, a2a_message_count, a2a_output_envelope, declared_parent_action_fingerprint,
    A2A_ROUTE, PARENT_ACTION_FINGERPRINT_HEADER,
};
use crate::config::{Config, GuardrailStage};
use crate::state::{AppState, GuardrailEvaluationContext, SharedAppState};
use ferrogate_guardrails::{
    CheckBinding, DetectorDefinition, DetectorStage, GuardrailProtocol, PolicyAction,
    PolicyAggregation, PolicyExecution, PolicyMode, PolicyRevision, PolicyScopeSelector,
    PolicyStreamingMode,
};
use serde_json::json;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn tenant() -> ferrogate_core::TenantContext {
    ferrogate_core::TenantContext {
        organization_id: Some("org".into()),
        project_id: Some("project".into()),
        api_key_id: Some("key_dev".into()),
        ..ferrogate_core::TenantContext::default()
    }
}

/// A guardrail policy that blocks any content containing `keyword`, at both the
/// request and response stages, scoped to everything (default selector).
fn secret_guardrail_revision(keyword: &str) -> PolicyRevision {
    let check = |stage: DetectorStage| CheckBinding {
        id: format!("keyword-{stage:?}"),
        enabled: true,
        stage,
        sources: ferrogate_guardrails::all_content_sources(),
        detector: DetectorDefinition::local(vec![keyword.to_string()], Vec::new(), None),
        fallback_detector: None,
    };
    PolicyRevision {
        policy_id: "a2a-secret-policy".to_string(),
        revision: 1,
        name: "a2a secret policy".to_string(),
        description: None,
        enforced: true,
        scope: PolicyScopeSelector::default(),
        checks: vec![
            check(DetectorStage::Request),
            check(DetectorStage::Response),
        ],
        aggregation: PolicyAggregation::All,
        execution: PolicyExecution::Sequential,
        mode: PolicyMode::Enforce,
        streaming: PolicyStreamingMode::BufferAndEnforce,
        on_pass: vec![PolicyAction::allow()],
        on_fail: vec![PolicyAction::block(
            "a2a_guardrail_blocked",
            "blocked by a2a guardrail policy",
        )],
        on_error: vec![PolicyAction::block(
            "a2a_guardrail_unavailable",
            "a2a guardrail policy unavailable",
        )],
        deadline_ms: 2_000,
        created_at_unix: 1,
        created_by: "test-admin".to_string(),
    }
}

#[test]
fn a2a_input_envelope_extracts_message_parts() {
    // A2A message/send JSON-RPC shape: params.message.parts[].text.
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [
                    {"kind": "text", "text": "hello agent"},
                    {"kind": "text", "text": "sk-live-super-secret"}
                ]
            }
        }
    });
    let envelope = a2a_input_envelope("planner", &body);
    assert_eq!(envelope.protocol, GuardrailProtocol::A2a);
    let flattened = envelope.flattened_text();
    assert!(flattened.contains("hello agent"));
    assert!(flattened.contains("sk-live-super-secret"));
    // Two text parts collected as the metered message unit.
    assert_eq!(a2a_message_count(&body), 2);
}

#[test]
fn a2a_output_envelope_parses_unary_and_streamed_replies() {
    let unary = serde_json::to_vec(&json!({
        "result": {
            "status": {"state": "completed"},
            "artifacts": [
                {"parts": [{"kind": "text", "text": "leaked sk-live-super-secret"}]}
            ]
        }
    }))
    .unwrap();
    let envelope = a2a_output_envelope("planner", &unary, false);
    assert!(envelope.flattened_text().contains("sk-live-super-secret"));

    // SSE stream: two data frames each carrying a text part.
    let sse = b"data: {\"result\":{\"parts\":[{\"kind\":\"text\",\"text\":\"partial \"}]}}\n\n\
data: {\"result\":{\"parts\":[{\"kind\":\"text\",\"text\":\"sk-live-super-secret\"}]}}\n\n\
data: [DONE]\n\n";
    let streamed = a2a_output_envelope("planner", sse, true);
    let flattened = streamed.flattened_text();
    assert!(flattened.contains("partial"));
    assert!(flattened.contains("sk-live-super-secret"));
}

#[test]
fn a2a_guardrail_blocks_secret_in_request_and_response() {
    let shared = SharedAppState::with_source_path(Config::default(), None);
    shared
        .create_guardrail_policy_revision(secret_guardrail_revision("sk-live-super-secret"))
        .expect("create policy");
    shared
        .activate_guardrail_policy_revision("a2a-secret-policy", 1, "test-admin", 10, false)
        .expect("activate policy");
    let state = shared.current();
    let tenant = tenant();

    // Request-stage: a secret pattern in an inbound A2A message part is blocked.
    let request_body = json!({
        "params": {"message": {"parts": [{"kind": "text", "text": "sk-live-super-secret"}]}}
    });
    let input_envelope = a2a_input_envelope("planner", &request_body);
    let blocked = block_on(state.match_guardrail(
        GuardrailStage::Request,
        GuardrailEvaluationContext {
            request_id: "fg-a2a-1",
            trace_id: Some("trace-1"),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: tenant.api_key_id.as_deref(),
            tenant: &tenant,
            service_account_id: None,
            gateway_config_id: None,
            model: None,
            provider: Some("planner"),
            streaming: false,
            envelope: &input_envelope,
            managed_action: None,
            action_fingerprint: None,
        },
    ));
    assert!(blocked.is_some(), "secret in A2A request must be blocked");

    // Response-stage: a secret leaked in the agent's reply is also blocked.
    let reply = serde_json::to_vec(&json!({
        "result": {"parts": [{"kind": "text", "text": "here it is: sk-live-super-secret"}]}
    }))
    .unwrap();
    let output_envelope = a2a_output_envelope("planner", &reply, false);
    let blocked_response = block_on(state.match_guardrail(
        GuardrailStage::Response,
        GuardrailEvaluationContext {
            request_id: "fg-a2a-1",
            trace_id: Some("trace-1"),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: tenant.api_key_id.as_deref(),
            tenant: &tenant,
            service_account_id: None,
            gateway_config_id: None,
            model: None,
            provider: Some("planner"),
            streaming: false,
            envelope: &output_envelope,
            managed_action: None,
            action_fingerprint: None,
        },
    ));
    assert!(
        blocked_response.is_some(),
        "secret in A2A response must be blocked"
    );

    // A clean body passes governance untouched.
    let clean = json!({"params": {"message": {"parts": [{"kind": "text", "text": "hello"}]}}});
    let clean_envelope = a2a_input_envelope("planner", &clean);
    let allowed = block_on(state.match_guardrail(
        GuardrailStage::Request,
        GuardrailEvaluationContext {
            request_id: "fg-a2a-2",
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: tenant.api_key_id.as_deref(),
            tenant: &tenant,
            service_account_id: None,
            gateway_config_id: None,
            model: None,
            provider: Some("planner"),
            streaming: false,
            envelope: &clean_envelope,
            managed_action: None,
            action_fingerprint: None,
        },
    ));
    assert!(allowed.is_none(), "clean A2A content must pass");
}

#[test]
fn a2a_exchange_is_metered_into_usage_aggregates() {
    let state = AppState::new(Config::default());
    let parent = format!("sha256:{}", "ab".repeat(32));
    block_on(state.record_a2a_exchange_event(
        "fg-a2a-meter",
        Some("trace-a2a"),
        Some("agent-run-a2a"),
        Some(&parent),
        &tenant(),
        "planner",
        false,
        3,
        4_096,
        200,
        Some(42),
    ))
    .expect("record a2a metering event");

    let events = state.billing_events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.provider, "a2a");
    // #305: the declared agent-run context survives onto billing evidence.
    assert_eq!(event.agent_run_id.as_deref(), Some("agent-run-a2a"));
    assert_eq!(event.logical_model, "a2a:planner");
    assert_eq!(event.usage.total_tokens, 0, "a2a carries no token usage");
    assert_eq!(
        event.metadata.get("a2a_message_count").map(String::as_str),
        Some("3")
    );
    assert_eq!(
        event.metadata.get("a2a_bytes").map(String::as_str),
        Some("4096")
    );
    // #307: the declared parent action rides the billing evidence metadata.
    assert_eq!(
        event
            .metadata
            .get("a2a_parent_action_fingerprint")
            .map(String::as_str),
        Some(parent.as_str())
    );
    assert_eq!(event.latency_ms, Some(42));
    assert_eq!(
        event.cost_usd, None,
        "a2a is metered but unpriced by default"
    );

    // Usage aggregates attribute the exchange to the calling tenant/key.
    let aggregates = state.usage_aggregates(None);
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].organization_id.as_deref(), Some("org"));
    assert_eq!(aggregates[0].api_key_id.as_deref(), Some("key_dev"));
    assert_eq!(aggregates[0].provider, "a2a");
}

#[test]
fn a2a_route_label_is_stable() {
    // The request-log / policy route label the ingress stamps on A2A traffic.
    assert_eq!(A2A_ROUTE, "a2a.message");
}

/// #307: an A2A exchange WITHOUT a declared parent records no parent metadata
/// on its billing evidence — absence is explicit, never back-filled.
#[test]
fn a2a_exchange_without_parent_records_no_parent_metadata() {
    let state = AppState::new(Config::default());
    block_on(state.record_a2a_exchange_event(
        "fg-a2a-orphan",
        None,
        None,
        None,
        &tenant(),
        "planner",
        false,
        1,
        128,
        200,
        None,
    ))
    .expect("record a2a metering event");
    let events = state.billing_events();
    assert_eq!(events.len(), 1);
    assert!(
        !events[0]
            .metadata
            .contains_key("a2a_parent_action_fingerprint"),
        "absent parent must not appear in billing metadata: {:?}",
        events[0].metadata
    );
}

/// #307: validation of the declared-parent header. Absent/empty → Ok(None)
/// (explicit NULL, nothing fabricated); a well-formed canonical fingerprint →
/// Ok(Some); anything else → Err (the handler maps it to a 400).
#[test]
fn declared_parent_action_fingerprint_header_validation() {
    let parent = format!("sha256:{}", "ab".repeat(32));

    // Absent header → None.
    let headers = http::HeaderMap::new();
    assert_eq!(declared_parent_action_fingerprint(&headers), Ok(None));

    // Empty / whitespace-only header → None (treated as absent).
    let mut headers = http::HeaderMap::new();
    headers.insert(
        PARENT_ACTION_FINGERPRINT_HEADER,
        http::HeaderValue::from_static("   "),
    );
    assert_eq!(declared_parent_action_fingerprint(&headers), Ok(None));

    // A canonical fingerprint (with surrounding whitespace) is accepted.
    let mut headers = http::HeaderMap::new();
    headers.insert(
        PARENT_ACTION_FINGERPRINT_HEADER,
        http::HeaderValue::from_str(&format!(" {parent} ")).unwrap(),
    );
    assert_eq!(
        declared_parent_action_fingerprint(&headers),
        Ok(Some(parent.clone()))
    );

    // Malformed values are rejected with a caller-visible message.
    for invalid in [
        "not-a-fingerprint",
        "sha256:short",
        &format!("sha256:{}", "AB".repeat(32)), // uppercase hex
        &format!("sha256:{}ff", "ab".repeat(32)), // too long
        &format!("blake2b:{}", "ab".repeat(32)), // wrong scheme
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            PARENT_ACTION_FINGERPRINT_HEADER,
            http::HeaderValue::from_str(invalid).unwrap(),
        );
        let error = declared_parent_action_fingerprint(&headers)
            .expect_err(&format!("must reject {invalid:?}"));
        assert!(
            error.contains(PARENT_ACTION_FINGERPRINT_HEADER),
            "error names the offending header: {error}"
        );
        assert!(
            error.contains("64 lowercase hex"),
            "error explains the contract: {error}"
        );
    }

    // Non-ASCII header bytes are rejected, not lossily accepted.
    let mut headers = http::HeaderMap::new();
    headers.insert(
        PARENT_ACTION_FINGERPRINT_HEADER,
        http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );
    assert!(declared_parent_action_fingerprint(&headers).is_err());
}
