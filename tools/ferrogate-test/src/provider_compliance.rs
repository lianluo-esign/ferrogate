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
use serde_json::Value;
use std::{cell::RefCell, collections::HashMap, thread, time::Duration};

const COST_SCALE: f64 = 1_000_000_000_000.0;

#[derive(Clone, Copy, Debug)]
struct ProviderCase {
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
    expected_upstream_models: &'static [&'static str],
}

const PROVIDER_CASES: [ProviderCase; 5] = [
    ProviderCase {
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
        expected_upstream_models: &["gpt-4o-mini"],
    },
    ProviderCase {
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
        expected_upstream_models: &["gpt-5.5"],
    },
    ProviderCase {
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
        expected_upstream_models: &["gpt-4o-mini"],
    },
    ProviderCase {
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
        expected_upstream_models: &["gpt-4o-mini"],
    },
    // Keep fallback last: its primary 503 deliberately opens the shared
    // provider circuit, which would prevent later cases from reaching the
    // upstream behavior they are intended to verify.
    ProviderCase {
        name: "fallback-success",
        logical_model: "fallback-chat",
        content: "provider compliance fallback success",
        stream: false,
        expected_status: 200,
        expected_error_code: None,
        provider: "backup-openai",
        provider_model: "gpt-4o-mini-fallback",
        prompt_tokens: 4,
        completion_tokens: 6,
        total_tokens: 10,
        expected_cost_picousd: 16_000_000,
        expected_upstream_models: &["gpt-4o-mini-failover-primary", "gpt-4o-mini-fallback"],
    },
];

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
            &[CLIENT_AUTH, JSON_CONTENT, &agent_header],
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
        let parsed: Value = serde_json::from_str(&response.body)
            .with_context(|| format!("provider case {} returned invalid JSON", case.name))?;
        match case.expected_error_code {
            Some(code) if parsed["error"]["code"] != code => {
                bail!(
                    "provider case {} returned the wrong error: {parsed}",
                    case.name
                )
            }
            None if parsed["object"] != "chat.completion" => {
                bail!(
                    "provider case {} did not return a chat completion: {parsed}",
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
    let billing = BillingHarness::start(&args.ferrogate_bin)?;
    assert_billing_auth(&billing.billing_addr)?;
    let expected_requests = PROVIDER_CASES
        .iter()
        .map(|case| case.expected_upstream_models.len())
        .sum::<usize>()
        + PROVIDER_NO_SETTLEMENT_CASES.len();
    let mut gateway = LocalHarness::start_with_billing_service(
        &args.ferrogate_bin,
        expected_requests,
        &billing.billing_addr,
    )?;
    // Run non-billable errors before the fallback case opens the shared
    // primary provider circuit.
    assert_no_settlement_cases(&gateway.gateway_addr, &billing)?;
    let contract = ProviderSettlementContract::new(&billing);
    assert_component_contract(&gateway.gateway_addr, &contract)?;
    let requests = gateway.take_provider_requests()?;
    assert_upstream_attempts(&requests)?;
    println!("provider-component-compliance scenario passed");
    Ok(())
}

fn expected_projection(case: &ProviderCase, request_id: String) -> ProviderSettlementProjection {
    ProviderSettlementProjection {
        request_id,
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

fn assert_upstream_attempts(requests: &[String]) -> Result<()> {
    for case in PROVIDER_CASES {
        for model in case.expected_upstream_models {
            let count = requests
                .iter()
                .filter(|request| {
                    request.contains(&format!(r#""content":"{}""#, case.content))
                        && request.contains(&format!(r#""model":"{model}""#))
                })
                .count();
            if count != 1 {
                bail!(
                    "provider case {} expected one upstream attempt for {model}, got {count}: {requests:#?}",
                    case.name
                );
            }
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
    Ok(())
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
