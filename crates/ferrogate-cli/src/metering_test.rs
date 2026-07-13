use ferrogate_billing::{BillingUsageSource, TokenUsage};

use super::*;

#[test]
fn openmeter_event_maps_billing_event_to_cloud_event() {
    let event = sample_billing_event();
    let payload = serde_json::to_value(openmeter_event(
        &event,
        "ai.tokens",
        "ferrogate",
        MeteringExportSubject::ApiKey,
    ))
    .unwrap();

    assert_eq!(payload["specversion"], "1.0");
    assert_eq!(
        payload["id"],
        "ferrogate:provider-attempt:req_123:provider-attempt:0"
    );
    assert_eq!(payload["source"], "ferrogate");
    assert_eq!(payload["type"], "ai.tokens");
    assert_eq!(payload["subject"], "client");
    assert_eq!(payload["data"]["logical_model"], "fast-chat");
    assert_eq!(payload["data"]["provider"], "openai");
    assert_eq!(payload["data"]["provider_model"], "gpt-4o-mini");
    assert_eq!(payload["data"]["prompt_tokens"], 3);
    assert_eq!(payload["data"]["completion_tokens"], 5);
    assert_eq!(payload["data"]["total_tokens"], 8);
    assert_eq!(payload["data"]["tenant"]["organization_id"], "org_demo");
}

#[test]
fn legacy_metering_adapter_encodes_provider_envelope() {
    let adapter = LegacyMeteringAdapter;
    let payload: serde_json::Value = serde_json::from_slice(
        &adapter
            .encode_event(&sample_billing_event())
            .expect("legacy payload"),
    )
    .expect("legacy json");

    assert_eq!(payload["object"], "token_metering_event");
    assert_eq!(
        payload["idempotency_key"],
        "ferrogate:provider-attempt:req_123:provider-attempt:0"
    );
    assert_eq!(payload["event"]["logical_model"], "fast-chat");
    assert_eq!(payload["event"]["provider"], "openai");
    assert_eq!(payload["event"]["usage"]["total_tokens"], 8);
}

#[test]
fn openmeter_adapter_encodes_cloud_event_payload() {
    let adapter = OpenMeteringAdapter {
        event_type: "ai.tokens".into(),
        source: "ferrogate-test".into(),
        subject: MeteringExportSubject::Project,
    };
    let payload: serde_json::Value = serde_json::from_slice(
        &adapter
            .encode_event(&sample_billing_event())
            .expect("openmeter payload"),
    )
    .expect("openmeter json");

    assert_eq!(payload["specversion"], "1.0");
    assert_eq!(payload["source"], "ferrogate-test");
    assert_eq!(payload["type"], "ai.tokens");
    assert_eq!(payload["subject"], "project_gateway");
    assert_eq!(payload["data"]["request_id"], "req_123");
    assert_eq!(payload["data"]["trace_id"], "trace_456");
    assert_eq!(
        payload["data"]["provider_attempt_id"],
        "req_123:provider-attempt:0"
    );
    assert_eq!(payload["data"]["provider_attempt_index"], 0);
    assert_eq!(payload["data"]["logical_model"], "fast-chat");
    assert_eq!(payload["data"]["provider_model"], "gpt-4o-mini");
    assert_eq!(payload["data"]["total_tokens"], 8);
    assert_eq!(payload["data"]["status_code"], 200);
}

#[test]
fn metering_subject_falls_back_to_available_tenant_identity() {
    let event = BillingEvent {
        request_id: "req_123".into(),
        trace_id: None,
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request("req_123", 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext {
            organization_id: Some("org_demo".into()),
            ..Default::default()
        },
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(0, 0, 0),
        usage_source: BillingUsageSource::GatewayEstimate,
        status_code: 200,
        occurred_at_unix: None,
        cost_usd: None,
        latency_ms: None,
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    };

    assert_eq!(
        metering_subject(&event, MeteringExportSubject::ApiKey),
        "org_demo"
    );
    assert_eq!(
        metering_idempotency_key(&event),
        "ferrogate:provider-attempt:req_123:provider-attempt:0"
    );
}

fn sample_billing_event() -> BillingEvent {
    BillingEvent {
        request_id: "req_123".into(),
        trace_id: Some("trace_456".into()),
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request("req_123", 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: Some("cluster-a".into()),
        node_id: Some("node-a".into()),
        tenant: ferrogate_core::TenantContext {
            workspace_id: None,
            organization_id: Some("org_demo".into()),
            team_id: None,
            project_id: Some("project_gateway".into()),
            user_id: None,
            api_key_id: Some("client".into()),
        },
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(3, 5, 8),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.0012),
        latency_ms: Some(430),
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}
