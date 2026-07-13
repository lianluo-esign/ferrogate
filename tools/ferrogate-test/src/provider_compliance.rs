// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Provider usage, fallback, error, and billing compliance contracts for issue #210.

use crate::{
    cli::LocalArgs,
    compliance::{assert_component_contract, ComponentContract},
    constants::{ADMIN_AUTH, BILLING_AUTH, CLIENT_AUTH, JSON_CONTENT},
    http::{http_request_addr, HttpResponse},
    local::{BillingHarness, LocalHarness},
};
use anyhow::{bail, Context, Result};
use ferrogate_providers::SUPPORTED_PROVIDER_ADAPTER_FAMILIES;
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
    thread,
    time::Duration,
};

const COST_SCALE: f64 = 1_000_000_000_000.0;
const COMPLIANCE_TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const COMPLIANCE_TRACEPARENT: &str =
    "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[derive(Clone, Copy, Debug)]
struct ProviderCase {
    adapter_family: &'static str,
    name: &'static str,
    logical_model: &'static str,
    content: &'static str,
    stream: bool,
    expected_status: u16,
    expected_error_code: Option<&'static str>,
    provider: &'static str,
    provider_model: &'static str,
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    expected_cost_picousd: u64,
    expected_response_marker: &'static str,
    expected_upstream_marker: &'static str,
}

const PROVIDER_CASES: [ProviderCase; 18] = [
    ProviderCase {
        adapter_family: "openai-compatible",
        name: "primary-success",
        logical_model: "fast-chat",
        content: "provider compliance primary success",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "openai",
        provider_model: "gpt-4o-mini",
        prompt_tokens: 1,
        completion_tokens: 1,
        total_tokens: 2,
        expected_cost_picousd: 3_000_000,
        expected_response_marker: "chatcmpl_ferrogate_test",
        expected_upstream_marker: r#""model":"gpt-4o-mini""#,
    },
    ProviderCase {
        adapter_family: "openai-compatible",
        name: "openai-stream-success",
        logical_model: "fast-chat",
        content: "provider compliance openai-compatible streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "openai",
        provider_model: "gpt-4o-mini",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_openai_stream",
        expected_upstream_marker: r#""model":"gpt-4o-mini""#,
    },
    ProviderCase {
        adapter_family: "openai-compatible",
        name: "gpt-5.5-success",
        logical_model: "gpt-5.5-chat",
        content: "provider compliance gpt-5.5 success",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "openai",
        provider_model: "gpt-5.5",
        prompt_tokens: 1,
        completion_tokens: 1,
        total_tokens: 2,
        expected_cost_picousd: 20_000_000,
        expected_response_marker: "chatcmpl_ferrogate_test",
        expected_upstream_marker: r#""model":"gpt-5.5""#,
    },
    ProviderCase {
        adapter_family: "openai-compatible",
        name: "terminal-error-with-usage",
        logical_model: "fast-chat",
        content: "provider upstream error with usage",
        stream: false,
        expected_status: 400,
        expected_error_code: Some("bad_provider_request"),
        provider: "openai",
        provider_model: "gpt-4o-mini",
        prompt_tokens: 3,
        completion_tokens: 2,
        total_tokens: 5,
        expected_cost_picousd: 7_000_000,
        expected_response_marker: "bad_provider_request",
        expected_upstream_marker: r#""model":"gpt-4o-mini""#,
    },
    ProviderCase {
        adapter_family: "openai-compatible",
        name: "terminal-stream-error-with-usage",
        logical_model: "fast-chat",
        content: "provider upstream error with usage streaming",
        stream: true,
        expected_status: 400,
        expected_error_code: Some("bad_provider_request"),
        provider: "openai",
        provider_model: "gpt-4o-mini",
        prompt_tokens: 3,
        completion_tokens: 2,
        total_tokens: 5,
        expected_cost_picousd: 7_000_000,
        expected_response_marker: "bad_provider_request",
        expected_upstream_marker: r#""model":"gpt-4o-mini""#,
    },
    ProviderCase {
        adapter_family: "anthropic",
        name: "anthropic-success",
        logical_model: "anthropic-chat",
        content: "provider compliance anthropic usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "anthropic",
        provider_model: "claude-3-5-sonnet-latest",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "msg_compliance_anthropic",
        expected_upstream_marker: r#""model":"claude-3-5-sonnet-latest""#,
    },
    ProviderCase {
        adapter_family: "anthropic",
        name: "anthropic-stream-success",
        logical_model: "anthropic-chat",
        content: "provider compliance anthropic streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "anthropic",
        provider_model: "claude-3-5-sonnet-latest",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "msg_compliance_anthropic_stream",
        expected_upstream_marker: r#""model":"claude-3-5-sonnet-latest""#,
    },
    ProviderCase {
        adapter_family: "gemini",
        name: "gemini-success",
        logical_model: "gemini-chat",
        content: "provider compliance gemini usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "gemini",
        provider_model: "gemini-2.5-flash",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "resp_compliance_gemini",
        expected_upstream_marker: "models/gemini-2.5-flash:generateContent",
    },
    ProviderCase {
        adapter_family: "gemini",
        name: "gemini-stream-success",
        logical_model: "gemini-chat",
        content: "provider compliance gemini streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "gemini",
        provider_model: "gemini-2.5-flash",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "resp_compliance_gemini_stream",
        expected_upstream_marker: "models/gemini-2.5-flash:streamGenerateContent",
    },
    ProviderCase {
        adapter_family: "grok",
        name: "grok-success",
        logical_model: "grok-chat",
        content: "provider compliance grok usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "xai",
        provider_model: "grok-4.20-fast",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_grok",
        expected_upstream_marker: r#""model":"grok-4.20-fast""#,
    },
    ProviderCase {
        adapter_family: "grok",
        name: "grok-stream-success",
        logical_model: "grok-chat",
        content: "provider compliance grok streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "xai",
        provider_model: "grok-4.20-fast",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_grok_stream",
        expected_upstream_marker: r#""model":"grok-4.20-fast""#,
    },
    ProviderCase {
        adapter_family: "openrouter",
        name: "openrouter-success",
        logical_model: "openrouter-chat",
        content: "provider compliance openrouter usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "openrouter",
        provider_model: "openai/gpt-4o-mini",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_openrouter",
        expected_upstream_marker: r#""model":"openai/gpt-4o-mini""#,
    },
    ProviderCase {
        adapter_family: "openrouter",
        name: "openrouter-stream-success",
        logical_model: "openrouter-chat",
        content: "provider compliance openrouter streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "openrouter",
        provider_model: "openai/gpt-4o-mini",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_openrouter_stream",
        expected_upstream_marker: r#""model":"openai/gpt-4o-mini""#,
    },
    ProviderCase {
        adapter_family: "azure-openai",
        name: "azure-openai-success",
        logical_model: "azure-openai-chat",
        content: "provider compliance azure-openai usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "azure-openai",
        provider_model: "azure-gpt-4o",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_azure",
        expected_upstream_marker: "/openai/deployments/azure-gpt-4o/chat/completions",
    },
    ProviderCase {
        adapter_family: "azure-openai",
        name: "azure-openai-stream-success",
        logical_model: "azure-openai-chat",
        content: "provider compliance azure-openai streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "azure-openai",
        provider_model: "azure-gpt-4o",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "chatcmpl_compliance_azure_stream",
        expected_upstream_marker: "/openai/deployments/azure-gpt-4o/chat/completions",
    },
    ProviderCase {
        adapter_family: "bedrock",
        name: "bedrock-success",
        logical_model: "bedrock-chat",
        content: "provider compliance bedrock usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "bedrock",
        provider_model: "anthropic.claude-3-5-sonnet-20241022-v2:0",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: r#""stopReason":"end_turn""#,
        expected_upstream_marker: "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse",
    },
    ProviderCase {
        adapter_family: "vertex",
        name: "vertex-success",
        logical_model: "vertex-chat",
        content: "provider compliance vertex usage",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "vertex",
        provider_model: "gemini-2.5-flash",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "resp_compliance_vertex",
        expected_upstream_marker: "/v1/projects/ferrogate-test/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
    },
    ProviderCase {
        adapter_family: "vertex",
        name: "vertex-stream-success",
        logical_model: "vertex-chat",
        content: "provider compliance vertex streaming usage",
        stream: true,
        expected_status: 200,
        expected_error_code: None,
        provider: "vertex",
        provider_model: "gemini-2.5-flash",
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
        expected_cost_picousd: 13_000_000,
        expected_response_marker: "resp_compliance_vertex_stream",
        expected_upstream_marker: "/v1/projects/ferrogate-test/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent",
    },
];

const MULTI_ATTEMPT_CONTENT: &str = "provider compliance multi attempt settlement";
const MULTI_ATTEMPT_AGENT_RUN_ID: &str = "provider-compliance-multi-attempt";

#[derive(Clone, Copy, Debug)]
struct ProviderNoSettlementCase {
    name: &'static str,
    content: &'static str,
    stream: bool,
    expected_upstream_model: &'static str,
}

const PROVIDER_NO_SETTLEMENT_CASES: [ProviderNoSettlementCase; 2] = [
    ProviderNoSettlementCase {
        name: "terminal-error-without-usage",
        content: "provider upstream error without usage",
        stream: false,
        expected_upstream_model: "gpt-4o-mini",
    },
    ProviderNoSettlementCase {
        name: "terminal-stream-error-without-usage",
        content: "provider upstream error without usage streaming",
        stream: true,
        expected_upstream_model: "gpt-4o-mini",
    },
];

#[derive(Clone, Debug, PartialEq)]
struct ProviderSettlementProjection {
    request_id: String,
    trace_id: String,
    provider_attempt_id: String,
    provider_attempt_index: u64,
    logical_model: String,
    provider: String,
    provider_model: String,
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    usage_source: String,
    status_code: u16,
    cost_picousd: u64,
    cost_source: String,
    currency: String,
    credits_positive: bool,
    organization_id: String,
    project_id: String,
}

#[derive(Debug)]
struct ProviderRuntimeEvidence {
    gateway_event: ProviderSettlementProjection,
    agent_run_id: String,
    latency_recorded: bool,
}

struct ProviderSettlementContract<'a> {
    billing: &'a BillingHarness,
    observations: RefCell<HashMap<&'static str, ProviderSettlementProjection>>,
}

impl<'a> ProviderSettlementContract<'a> {
    fn new(billing: &'a BillingHarness) -> Self {
        Self {
            billing,
            observations: RefCell::new(HashMap::new()),
        }
    }

    fn observation(&self, case: &ProviderCase) -> Result<ProviderSettlementProjection> {
        self.observations
            .borrow()
            .get(case.name)
            .cloned()
            .with_context(|| format!("provider case {} has not executed", case.name))
    }
}

impl ComponentContract for ProviderSettlementContract<'_> {
    type Case = ProviderCase;
    type Written = ProviderSettlementProjection;
    type Runtime = ProviderRuntimeEvidence;

    fn name(&self) -> &'static str {
        "provider-settlement"
    }

    fn cases(&self) -> Vec<Self::Case> {
        PROVIDER_CASES.to_vec()
    }

    fn write(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        let agent_run_id = format!("provider-compliance-{}", case.name);
        let agent_header = format!("x-ferrogate-agent-run-id: {agent_run_id}");
        let body = serde_json::json!({
            "model": case.logical_model,
            "messages": [{"role": "user", "content": case.content}],
            "stream": case.stream
        })
        .to_string();
        let response = http_request_addr(
            gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[
                CLIENT_AUTH,
                JSON_CONTENT,
                &agent_header,
                COMPLIANCE_TRACEPARENT,
            ],
            &body,
        )?;
        if response.status != case.expected_status {
            bail!(
                "provider case {} expected status {}, got {}; raw: {}",
                case.name,
                case.expected_status,
                response.status,
                response.raw
            );
        }
        if !response.body.contains(case.expected_response_marker) {
            bail!(
                "provider case {} response omitted fixture marker {}: {}",
                case.name,
                case.expected_response_marker,
                response.body
            );
        }
        let parsed = (!case.stream || case.expected_error_code.is_some())
            .then(|| {
                serde_json::from_str::<Value>(&response.body)
                    .with_context(|| format!("provider case {} returned invalid JSON", case.name))
            })
            .transpose()?;
        match (case.expected_error_code, parsed.as_ref()) {
            (Some(code), Some(parsed)) if parsed["error"]["code"] != code => {
                bail!(
                    "provider case {} returned the wrong error: {parsed}",
                    case.name
                )
            }
            _ => {}
        }

        let request_id = response_header(&response, "x-request-id")
            .with_context(|| format!("provider case {} omitted x-request-id", case.name))?;
        let projection = expected_projection(case, request_id);
        self.observations
            .borrow_mut()
            .insert(case.name, projection.clone());
        Ok(projection)
    }

    fn read(&self, _gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        let written = self.observation(case)?;
        let entry = self
            .billing
            .wait_for_ledger_entry(|entry| entry["request_id"] == written.request_id)?;
        ledger_projection(&entry)
    }

    fn exercise(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Runtime> {
        let written = self.observation(case)?;
        let event = wait_for_gateway_billing_event(gateway_addr, &written.request_id)?;
        Ok(ProviderRuntimeEvidence {
            gateway_event: billing_event_projection(&event)?,
            agent_run_id: event["agent_run_id"]
                .as_str()
                .context("gateway billing event omitted agent_run_id")?
                .to_string(),
            latency_recorded: event["latency_ms"].as_u64().is_some(),
        })
    }

    fn verify(
        &self,
        case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.cost_picousd != case.expected_cost_picousd {
            bail!(
                "provider case {} expected cost {} picodollars, got {}",
                case.name,
                case.expected_cost_picousd,
                written.cost_picousd
            );
        }
        if runtime.gateway_event != *written {
            bail!(
                "provider case {} gateway telemetry diverged: expected {written:?}, got {:?}",
                case.name,
                runtime.gateway_event
            );
        }
        if runtime.agent_run_id != format!("provider-compliance-{}", case.name) {
            bail!("provider case {} lost agent_run_id attribution", case.name);
        }
        if !runtime.latency_recorded {
            bail!("provider case {} omitted latency telemetry", case.name);
        }
        Ok(())
    }

    fn cleanup(&self, _gateway_addr: &str, case: &Self::Case) -> Result<()> {
        let written = self.observation(case)?;
        let entries = billing_ledger_entries(&self.billing.billing_addr)?;
        let count = entries
            .iter()
            .filter(|entry| entry["request_id"] == written.request_id)
            .count();
        if count != 1 {
            bail!(
                "provider case {} expected exactly one ledger entry, got {count}",
                case.name
            );
        }
        Ok(())
    }
}

pub(crate) fn run_provider_compliance(args: &LocalArgs) -> Result<()> {
    validate_provider_case_matrix(&PROVIDER_CASES)?;
    let billing = BillingHarness::start(&args.ferrogate_bin)?;
    assert_billing_auth(&billing.billing_addr)?;
    let expected_requests = expected_provider_requests();
    let mut gateway = LocalHarness::start_with_billing_service(
        &args.ferrogate_bin,
        expected_requests,
        &billing.billing_addr,
    )?;
    run_provider_compliance_at(&gateway.gateway_addr, &billing)?;
    let requests = gateway.take_provider_requests()?;
    assert_upstream_attempts(&requests)?;
    println!("provider-component-compliance scenario passed");
    Ok(())
}

pub(crate) fn expected_provider_requests() -> usize {
    PROVIDER_CASES.len() + PROVIDER_NO_SETTLEMENT_CASES.len() + 2
}

fn validate_provider_case_matrix(cases: &[ProviderCase]) -> Result<()> {
    let runtime = runtime_provider_adapter_families();
    validate_provider_case_matrix_against(cases, &runtime)
}

fn runtime_provider_adapter_families() -> BTreeSet<&'static str> {
    SUPPORTED_PROVIDER_ADAPTER_FAMILIES
        .iter()
        .map(|family| family.canonical_kind)
        .collect()
}

fn validate_provider_case_matrix_against(
    cases: &[ProviderCase],
    runtime: &BTreeSet<&str>,
) -> Result<()> {
    let compliance = cases
        .iter()
        .map(|case| case.adapter_family)
        .collect::<BTreeSet<_>>();
    let missing = runtime.difference(&compliance).copied().collect::<Vec<_>>();
    let unsupported = compliance.difference(runtime).copied().collect::<Vec<_>>();
    if !missing.is_empty() || !unsupported.is_empty() {
        bail!(
            "provider compliance matrix mismatch: missing compliance cases={missing:?}; unsupported adapter families={unsupported:?}"
        );
    }
    Ok(())
}

pub(crate) fn run_provider_compliance_at(
    gateway_addr: &str,
    billing: &BillingHarness,
) -> Result<()> {
    validate_provider_case_matrix(&PROVIDER_CASES)?;
    assert_billing_auth(&billing.billing_addr)?;
    // The multi-attempt case is deliberately last because its primary 503
    // opens the shared provider circuit.
    assert_no_settlement_cases(gateway_addr, billing)?;
    let contract = ProviderSettlementContract::new(billing);
    assert_component_contract(gateway_addr, &contract)?;
    assert_multi_attempt_settlement(gateway_addr, billing)
}

fn assert_multi_attempt_settlement(gateway_addr: &str, billing: &BillingHarness) -> Result<()> {
    let body = serde_json::json!({
        "model": "fallback-chat",
        "messages": [{"role": "user", "content": ""}],
        "user": MULTI_ATTEMPT_CONTENT,
        "max_tokens": 5,
        "stream": true
    })
    .to_string();
    let agent_header = format!("x-ferrogate-agent-run-id: {MULTI_ATTEMPT_AGENT_RUN_ID}");
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT, &agent_header],
        &body,
    )?;
    if response.status != 200 {
        bail!(
            "multi-attempt provider case expected status 200, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let request_id = response_header(&response, "x-request-id")
        .context("multi-attempt provider case omitted x-request-id")?;

    let mut gateway_events = wait_for_gateway_billing_events(gateway_addr, &request_id, 2)?;
    let mut ledger_entries = wait_for_billing_ledger_entries(billing, &request_id, 2)?;
    sort_by_provider_attempt(&mut gateway_events, "gateway event")?;
    sort_by_provider_attempt(&mut ledger_entries, "ledger entry")?;

    assert_multi_attempt_evidence(&gateway_events, false)?;
    assert_multi_attempt_evidence(&ledger_entries, true)?;

    let gateway_ids = provider_attempt_ids(&gateway_events)?;
    let ledger_ids = provider_attempt_ids(&ledger_entries)?;
    if gateway_ids != ledger_ids || gateway_ids[0] == gateway_ids[1] {
        bail!(
            "provider attempt identity diverged or collided: gateway={gateway_ids:?}, ledger={ledger_ids:?}"
        );
    }
    let ledger_charge_ids = ledger_entries
        .iter()
        .map(|entry| required_string(&entry["id"], "ledger.id"))
        .collect::<Result<Vec<_>>>()?;
    if ledger_charge_ids[0] == ledger_charge_ids[1] {
        bail!("multi-attempt ledger charge ids collided");
    }

    // Replay the exact same two attempt events. Billing must return success but
    // keep exactly two ledger rows because each attempt identity is its own
    // idempotency key.
    for event in &gateway_events {
        let replay = http_request_addr(
            &billing.billing_addr,
            "POST",
            "/v1/billing/charge",
            &[BILLING_AUTH, JSON_CONTENT],
            &serde_json::to_string(event)?,
        )?;
        if replay.status != 200 {
            bail!("provider attempt replay failed: {}", replay.raw);
        }
    }
    let mut collision = gateway_events[0].clone();
    collision["request_id"] = Value::String(format!("{request_id}-collision"));
    let rejected = http_request_addr(
        &billing.billing_addr,
        "POST",
        "/v1/billing/charge",
        &[BILLING_AUTH, JSON_CONTENT],
        &serde_json::to_string(&collision)?,
    )?;
    if rejected.status != 409 {
        bail!(
            "provider attempt payload collision was not rejected with 409: {}",
            rejected.raw
        );
    }
    let replayed = wait_for_billing_ledger_entries(billing, &request_id, 2)?;
    if replayed.len() != 2 {
        bail!(
            "provider attempt replay double-charged logical request {request_id}: {} rows",
            replayed.len()
        );
    }

    let total_tokens = ledger_entries.iter().try_fold(0_u64, |total, entry| {
        Ok::<_, anyhow::Error>(total.saturating_add(required_u64(
            &entry["usage"]["total_tokens"],
            "ledger.total_tokens",
        )?))
    })?;
    let total_cost_picousd = ledger_entries.iter().try_fold(0_u64, |total, entry| {
        Ok::<_, anyhow::Error>(total.saturating_add(cost_picousd(
            &entry["cost"]["total_cost"],
            "ledger.total_cost",
        )?))
    })?;
    if total_tokens != 13 || total_cost_picousd != 20_000_000 {
        bail!(
            "multi-attempt rollup mismatch: tokens={total_tokens}, cost_picousd={total_cost_picousd}"
        );
    }
    Ok(())
}

fn assert_multi_attempt_evidence(entries: &[Value], ledger: bool) -> Result<()> {
    let expected = [
        (
            0_u64,
            "openai",
            "gpt-4o-mini-failover-primary",
            503_u64,
            2_u64,
            1_u64,
            3_u64,
            4_000_000_u64,
            "provider_usage",
        ),
        (
            1_u64,
            "backup-openai",
            "gpt-4o-mini-fallback",
            200_u64,
            4_u64,
            6_u64,
            10_u64,
            16_000_000_u64,
            "provider_usage",
        ),
    ];
    for (entry, expected) in entries.iter().zip(expected) {
        let cost = if ledger {
            &entry["cost"]["total_cost"]
        } else {
            &entry["cost_usd"]
        };
        let actual = (
            required_u64(&entry["provider_attempt_index"], "provider_attempt_index")?,
            required_string(&entry["provider"], "provider")?,
            required_string(&entry["provider_model"], "provider_model")?,
            required_u64(&entry["status_code"], "status_code")?,
            required_u64(&entry["usage"]["prompt_tokens"], "prompt_tokens")?,
            required_u64(&entry["usage"]["completion_tokens"], "completion_tokens")?,
            required_u64(&entry["usage"]["total_tokens"], "total_tokens")?,
            cost_picousd(cost, "cost")?,
            required_string(&entry["usage_source"], "usage_source")?,
        );
        let expected = (
            expected.0,
            expected.1.to_string(),
            expected.2.to_string(),
            expected.3,
            expected.4,
            expected.5,
            expected.6,
            expected.7,
            expected.8.to_string(),
        );
        if actual != expected {
            bail!("multi-attempt evidence mismatch: expected {expected:?}, got {actual:?}");
        }
        if entry["agent_run_id"] != MULTI_ATTEMPT_AGENT_RUN_ID && !ledger {
            bail!("multi-attempt gateway evidence lost agent_run_id: {entry}");
        }
    }
    Ok(())
}

fn provider_attempt_ids(entries: &[Value]) -> Result<Vec<String>> {
    entries
        .iter()
        .map(|entry| required_string(&entry["provider_attempt_id"], "provider_attempt_id"))
        .collect()
}

fn sort_by_provider_attempt(entries: &mut [Value], kind: &str) -> Result<()> {
    for entry in entries.iter() {
        required_u64(&entry["provider_attempt_index"], kind)?;
    }
    entries.sort_by_key(|entry| entry["provider_attempt_index"].as_u64().unwrap_or(u64::MAX));
    Ok(())
}

fn expected_projection(case: &ProviderCase, request_id: String) -> ProviderSettlementProjection {
    ProviderSettlementProjection {
        provider_attempt_id: format!("{request_id}:provider-attempt:0"),
        provider_attempt_index: 0,
        request_id,
        trace_id: COMPLIANCE_TRACE_ID.to_string(),
        logical_model: case.logical_model.to_string(),
        provider: case.provider.to_string(),
        provider_model: case.provider_model.to_string(),
        prompt_tokens: case.prompt_tokens,
        completion_tokens: case.completion_tokens,
        total_tokens: case.total_tokens,
        usage_source: "provider_usage".to_string(),
        status_code: case.expected_status,
        cost_picousd: case.expected_cost_picousd,
        cost_source: "gateway_settled".to_string(),
        currency: "USD".to_string(),
        credits_positive: true,
        organization_id: "org_demo".to_string(),
        project_id: "project_gateway".to_string(),
    }
}

fn ledger_projection(entry: &Value) -> Result<ProviderSettlementProjection> {
    Ok(ProviderSettlementProjection {
        request_id: required_string(&entry["request_id"], "ledger.request_id")?,
        trace_id: required_string(&entry["trace_id"], "ledger.trace_id")?,
        provider_attempt_id: required_string(
            &entry["provider_attempt_id"],
            "ledger.provider_attempt_id",
        )?,
        provider_attempt_index: required_u64(
            &entry["provider_attempt_index"],
            "ledger.provider_attempt_index",
        )?,
        logical_model: required_string(&entry["logical_model"], "ledger.logical_model")?,
        provider: required_string(&entry["provider"], "ledger.provider")?,
        provider_model: required_string(&entry["provider_model"], "ledger.provider_model")?,
        prompt_tokens: required_u64(&entry["usage"]["prompt_tokens"], "ledger.prompt_tokens")?,
        completion_tokens: required_u64(
            &entry["usage"]["completion_tokens"],
            "ledger.completion_tokens",
        )?,
        total_tokens: required_u64(&entry["usage"]["total_tokens"], "ledger.total_tokens")?,
        usage_source: required_string(&entry["usage_source"], "ledger.usage_source")?,
        status_code: required_u64(&entry["status_code"], "ledger.status_code")? as u16,
        cost_picousd: cost_picousd(&entry["cost"]["total_cost"], "ledger.total_cost")?,
        cost_source: required_string(&entry["cost_source"], "ledger.cost_source")?,
        currency: required_string(&entry["cost"]["currency"], "ledger.currency")?,
        credits_positive: entry["credits"].as_f64().unwrap_or_default() > 0.0,
        organization_id: required_string(
            &entry["tenant"]["organization_id"],
            "ledger.organization_id",
        )?,
        project_id: required_string(&entry["tenant"]["project_id"], "ledger.project_id")?,
    })
}

fn billing_event_projection(event: &Value) -> Result<ProviderSettlementProjection> {
    Ok(ProviderSettlementProjection {
        request_id: required_string(&event["request_id"], "billing_event.request_id")?,
        trace_id: required_string(&event["trace_id"], "billing_event.trace_id")?,
        provider_attempt_id: required_string(
            &event["provider_attempt_id"],
            "billing_event.provider_attempt_id",
        )?,
        provider_attempt_index: required_u64(
            &event["provider_attempt_index"],
            "billing_event.provider_attempt_index",
        )?,
        logical_model: required_string(&event["logical_model"], "billing_event.logical_model")?,
        provider: required_string(&event["provider"], "billing_event.provider")?,
        provider_model: required_string(&event["provider_model"], "billing_event.provider_model")?,
        prompt_tokens: required_u64(
            &event["usage"]["prompt_tokens"],
            "billing_event.prompt_tokens",
        )?,
        completion_tokens: required_u64(
            &event["usage"]["completion_tokens"],
            "billing_event.completion_tokens",
        )?,
        total_tokens: required_u64(
            &event["usage"]["total_tokens"],
            "billing_event.total_tokens",
        )?,
        usage_source: required_string(&event["usage_source"], "billing_event.usage_source")?,
        status_code: required_u64(&event["status_code"], "billing_event.status_code")? as u16,
        cost_picousd: cost_picousd(&event["cost_usd"], "billing_event.cost_usd")?,
        cost_source: "gateway_settled".to_string(),
        currency: "USD".to_string(),
        credits_positive: event["cost_usd"].as_f64().unwrap_or_default() > 0.0,
        organization_id: required_string(
            &event["tenant"]["organization_id"],
            "billing_event.organization_id",
        )?,
        project_id: required_string(&event["tenant"]["project_id"], "billing_event.project_id")?,
    })
}

fn wait_for_gateway_billing_event(gateway_addr: &str, request_id: &str) -> Result<Value> {
    let mut last = String::new();
    for _ in 0..50 {
        let response = http_request_addr(
            gateway_addr,
            "GET",
            "/admin/v1/billing-events?limit=200",
            &[ADMIN_AUTH],
            "",
        )?;
        if response.status != 200 {
            bail!("billing event query failed: {}", response.raw);
        }
        let body: Value = serde_json::from_str(&response.body)?;
        if let Some(event) = body["data"].as_array().and_then(|events| {
            events
                .iter()
                .find(|event| event["request_id"] == request_id)
        }) {
            return Ok(event.clone());
        }
        last = response.body;
        thread::sleep(Duration::from_millis(100));
    }
    bail!("timed out waiting for gateway billing event {request_id}; last response: {last}")
}

fn wait_for_gateway_billing_events(
    gateway_addr: &str,
    request_id: &str,
    expected: usize,
) -> Result<Vec<Value>> {
    let mut last = String::new();
    for _ in 0..100 {
        let response = http_request_addr(
            gateway_addr,
            "GET",
            "/admin/v1/billing-events?limit=200",
            &[ADMIN_AUTH],
            "",
        )?;
        if response.status != 200 {
            bail!("billing event query failed: {}", response.raw);
        }
        let body: Value = serde_json::from_str(&response.body)?;
        let events = body["data"]
            .as_array()
            .context("gateway billing event response omitted data")?
            .iter()
            .filter(|event| event["request_id"] == request_id)
            .cloned()
            .collect::<Vec<_>>();
        if events.len() >= expected {
            return Ok(events);
        }
        last = response.body;
        thread::sleep(Duration::from_millis(100));
    }
    bail!(
        "timed out waiting for {expected} gateway billing events for {request_id}; last response: {last}"
    )
}

fn wait_for_billing_ledger_entries(
    billing: &BillingHarness,
    request_id: &str,
    expected: usize,
) -> Result<Vec<Value>> {
    let mut last = Vec::new();
    for _ in 0..100 {
        let entries = billing_ledger_entries(&billing.billing_addr)?
            .into_iter()
            .filter(|entry| entry["request_id"] == request_id)
            .collect::<Vec<_>>();
        if entries.len() >= expected {
            return Ok(entries);
        }
        last = entries;
        thread::sleep(Duration::from_millis(100));
    }
    bail!(
        "timed out waiting for {expected} billing ledger entries for {request_id}; last entries: {last:?}"
    )
}

fn billing_ledger_entries(billing_addr: &str) -> Result<Vec<Value>> {
    let response = http_request_addr(
        billing_addr,
        "GET",
        "/v1/billing/ledger?limit=200",
        &[BILLING_AUTH],
        "",
    )?;
    if response.status != 200 {
        bail!("billing ledger query failed: {}", response.raw);
    }
    let body: Value = serde_json::from_str(&response.body)?;
    body["entries"]
        .as_array()
        .cloned()
        .context("billing ledger response omitted entries")
}

fn assert_billing_auth(billing_addr: &str) -> Result<()> {
    let unauthenticated = http_request_addr(billing_addr, "GET", "/v1/billing/ledger", &[], "")?;
    if unauthenticated.status != 401 {
        bail!("unauthenticated billing ledger read was not rejected");
    }
    let authenticated = http_request_addr(
        billing_addr,
        "GET",
        "/v1/billing/ledger",
        &[BILLING_AUTH],
        "",
    )?;
    if authenticated.status != 200 {
        bail!(
            "authenticated billing ledger read failed: {}",
            authenticated.raw
        );
    }
    Ok(())
}

pub(crate) fn assert_upstream_attempts(requests: &[String]) -> Result<()> {
    for case in PROVIDER_CASES {
        let content_markers = [
            format!(r#""content":"{}""#, case.content),
            format!(r#""text":"{}""#, case.content),
        ];
        let matching = requests
            .iter()
            .filter(|request| {
                content_markers
                    .iter()
                    .any(|marker| request.contains(marker))
                    && request.contains(expected_provider_path(&case))
                    && request.contains(expected_provider_body_shape(&case))
                    && expected_provider_stream_usage_request_marker(&case)
                        .is_none_or(|marker| request.contains(marker))
                    && request.contains(case.expected_upstream_marker)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            bail!(
                "provider case {} expected one upstream attempt containing {}, got {}: {requests:#?}",
                case.name,
                case.expected_upstream_marker,
                matching.len()
            );
        }
        let request = matching[0].to_ascii_lowercase();
        if !request.contains(&COMPLIANCE_TRACEPARENT.to_ascii_lowercase()) {
            bail!("provider case {} lost W3C trace context", case.name);
        }
        if !request.contains("x-ferrogate-provider-attempt-index: 0")
            || !request.contains("x-ferrogate-provider-attempt-id:")
            || !request.contains(":provider-attempt:0")
        {
            bail!(
                "provider case {} lost provider-attempt identity: {}",
                case.name,
                matching[0]
            );
        }
    }
    for case in PROVIDER_NO_SETTLEMENT_CASES {
        let count = requests
            .iter()
            .filter(|request| {
                request.contains(&format!(r#""content":"{}""#, case.content))
                    && request.contains(&format!(r#""model":"{}""#, case.expected_upstream_model))
            })
            .count();
        if count != 1 {
            bail!(
                "provider case {} expected one upstream attempt for {}, got {count}: {requests:#?}",
                case.name,
                case.expected_upstream_model
            );
        }
    }
    for model in ["gpt-4o-mini-failover-primary", "gpt-4o-mini-fallback"] {
        let count = requests
            .iter()
            .filter(|request| {
                request.contains(MULTI_ATTEMPT_CONTENT)
                    && request.contains(&format!(r#""model":"{model}""#))
            })
            .count();
        if count != 1 {
            bail!(
                "multi-attempt provider case expected one upstream dispatch for {model}, got {count}: {requests:#?}"
            );
        }
    }
    Ok(())
}

fn expected_provider_path(case: &ProviderCase) -> &'static str {
    match case.adapter_family {
        "anthropic" => "POST /v1/messages ",
        "gemini" if case.stream => {
            "POST /v1/models/gemini-2.5-flash:streamGenerateContent?alt=sse "
        }
        "gemini" => "POST /v1/models/gemini-2.5-flash:generateContent ",
        "azure-openai" => "POST /openai/deployments/azure-gpt-4o/chat/completions?",
        "bedrock" => {
            "POST /model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse "
        }
        "vertex" if case.stream => {
            "POST /v1/projects/ferrogate-test/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse "
        }
        "vertex" => {
            "POST /v1/projects/ferrogate-test/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent "
        }
        _ => "POST /v1/chat/completions ",
    }
}

fn expected_provider_body_shape(case: &ProviderCase) -> &'static str {
    match case.adapter_family {
        "anthropic" => r#""max_tokens":1024,"messages""#,
        "gemini" | "vertex" => r#""contents":[{"parts""#,
        "bedrock" => r#""content":[{"text""#,
        _ => r#""messages":[{"content""#,
    }
}

fn expected_provider_stream_usage_request_marker(case: &ProviderCase) -> Option<&'static str> {
    if !case.stream {
        return None;
    }
    match case.adapter_family {
        "openai-compatible" | "grok" | "azure-openai" => {
            Some(r#""stream_options":{"include_usage":true}"#)
        }
        _ => None,
    }
}

fn assert_no_settlement_cases(gateway_addr: &str, billing: &BillingHarness) -> Result<()> {
    let mut request_ids = Vec::new();
    for case in PROVIDER_NO_SETTLEMENT_CASES {
        let body = serde_json::json!({
            "model": "fast-chat",
            "messages": [{"role": "user", "content": case.content}],
            "stream": case.stream
        })
        .to_string();
        let response = http_request_addr(
            gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[CLIENT_AUTH, JSON_CONTENT],
            &body,
        )?;
        if response.status != 400 {
            bail!(
                "provider case {} expected status 400, got {}; raw: {}",
                case.name,
                response.status,
                response.raw
            );
        }
        let parsed: Value = serde_json::from_str(&response.body)
            .with_context(|| format!("provider case {} returned invalid JSON", case.name))?;
        if parsed["error"]["code"] != "bad_provider_request" {
            bail!(
                "provider case {} returned the wrong error: {parsed}",
                case.name
            );
        }
        request_ids.push((
            case.name,
            response_header(&response, "x-request-id")
                .with_context(|| format!("provider case {} omitted x-request-id", case.name))?,
        ));
    }

    // Billing-event persistence is synchronous. Polling both surfaces also
    // gives the asynchronous outbox reporter enough time to expose an
    // accidental charge in the standalone ledger.
    for _ in 0..15 {
        let gateway_entries = gateway_billing_entries(gateway_addr)?;
        let ledger_entries = billing_ledger_entries(&billing.billing_addr)?;
        for (case, request_id) in &request_ids {
            if gateway_entries
                .iter()
                .any(|entry| entry["request_id"] == request_id.as_str())
            {
                bail!("provider case {case} created a gateway billing event");
            }
            if ledger_entries
                .iter()
                .any(|entry| entry["request_id"] == request_id.as_str())
            {
                bail!("provider case {case} created a standalone ledger entry");
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn gateway_billing_entries(gateway_addr: &str) -> Result<Vec<Value>> {
    let response = http_request_addr(
        gateway_addr,
        "GET",
        "/admin/v1/billing-events?limit=200",
        &[ADMIN_AUTH],
        "",
    )?;
    if response.status != 200 {
        bail!("billing event query failed: {}", response.raw);
    }
    let body: Value = serde_json::from_str(&response.body)?;
    body["data"]
        .as_array()
        .cloned()
        .context("gateway billing event response omitted data")
}

fn response_header(response: &HttpResponse, expected_name: &str) -> Option<String> {
    response.raw.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(expected_name)
            .then(|| value.trim().to_string())
    })
}

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("{field} must be a string, got {value}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .with_context(|| format!("{field} must be an unsigned integer, got {value}"))
}

fn cost_picousd(value: &Value, field: &str) -> Result<u64> {
    let value = value
        .as_f64()
        .with_context(|| format!("{field} must be a number, got {value}"))?;
    Ok((value * COST_SCALE).round() as u64)
}

#[cfg(test)]
#[path = "provider_compliance_test.rs"]
mod provider_compliance_test;
