// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

pub(crate) fn http_request_body(request: &str) -> Result<&str> {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| anyhow!("HTTP request body separator not found"))
}

pub(crate) fn parse_jsonl(body: &str) -> Result<Vec<Value>> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .with_context(|| format!("failed to parse JSONL line: {line}"))
        })
        .collect()
}

pub(crate) fn agent_run_otlp_trace_is_reconstructable(
    body: &Value,
    agent_run_id: &str,
) -> Result<bool> {
    let spans = otlp_spans(body);
    let Some(root) = spans.iter().copied().find(|span| {
        span["name"] == "ferrogate.agent.run"
            && otlp_attribute(span, "agent_run_id").as_deref() == Some(agent_run_id)
    }) else {
        return Ok(false);
    };
    let root_span_id = root["spanId"]
        .as_str()
        .context("agent run OTLP root span is missing spanId")?;
    let trace_id = root["traceId"]
        .as_str()
        .context("agent run OTLP root span is missing traceId")?;

    let child_spans = spans
        .iter()
        .copied()
        .filter(|span| {
            span["traceId"].as_str() == Some(trace_id)
                && span["parentSpanId"].as_str() == Some(root_span_id)
                && otlp_attribute(span, "agent_run_id").as_deref() == Some(agent_run_id)
        })
        .collect::<Vec<_>>();

    let provider_step = child_spans.iter().copied().any(|span| {
        span["name"] == "ferrogate.agent.provider.step"
            && otlp_attribute(span, "route").as_deref() == Some("openai.chat.completions")
            && otlp_attribute(span, "logical_model").as_deref() == Some("fast-chat")
            && otlp_attribute(span, "provider").as_deref() == Some("openai")
            && otlp_attribute(span, "provider_model").as_deref() == Some("gpt-4o-mini")
    });
    let billing_write = child_spans.iter().copied().any(|span| {
        span["name"] == "ferrogate.billing.write"
            && otlp_attribute(span, "logical_model").as_deref() == Some("fast-chat")
            && otlp_attribute(span, "provider").as_deref() == Some("openai")
            && otlp_attribute(span, "provider_model").as_deref() == Some("gpt-4o-mini")
            && otlp_attribute(span, "total_tokens").as_deref() == Some("2")
    });

    Ok(provider_step && billing_write)
}

fn otlp_spans(body: &Value) -> Vec<&Value> {
    body["resourceSpans"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|resource| {
            resource["scopeSpans"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|scope| scope["spans"].as_array().into_iter().flatten())
        })
        .collect()
}

fn otlp_attribute(span: &Value, key: &str) -> Option<String> {
    span["attributes"].as_array()?.iter().find_map(|attribute| {
        (attribute["key"].as_str()? == key)
            .then(|| {
                attribute["value"]["stringValue"]
                    .as_str()
                    .map(str::to_string)
            })
            .flatten()
    })
}

pub(crate) fn list_contains(body: &Value, field: &str, expected: &str) -> bool {
    body.get("data")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item[field] == expected))
}

pub(crate) fn admin_list_item<'a>(
    body: &'a Value,
    field: &str,
    expected: &str,
) -> Option<&'a Value> {
    body.get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find(|item| item[field] == expected))
}

pub(crate) fn assert_mcp_tool_present(body: &Value, name: &str, description: &str) -> Result<()> {
    let tools = body["result"]["tools"]
        .as_array()
        .context("MCP tools/list result must contain a tools array")?;
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == name)
        .with_context(|| format!("MCP tool {name} missing from tools/list response: {body}"))?;
    assert_eq!(tool["description"], description);
    assert_eq!(tool["inputSchema"]["type"], "object");
    Ok(())
}

pub(crate) fn array_contains(
    body: &Value,
    array_field: &str,
    item_field: &str,
    expected: &str,
) -> bool {
    body.get(array_field)
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item[item_field] == expected))
}

pub(crate) fn assert_array_contains(array: &Value, expected: &str) -> Result<()> {
    let values = array
        .as_array()
        .with_context(|| format!("expected JSON array containing {expected}"))?;
    if values.iter().any(|value| value == expected) {
        return Ok(());
    }
    bail!("JSON array does not contain {expected}: {array}");
}

pub(crate) fn assert_secret_redacted(raw: &str) {
    for secret in [
        "admin-secret",
        "client-secret",
        "test-secret",
        "test-secret-2",
        "provider-secret",
        "Bearer",
    ] {
        assert!(!raw.contains(secret), "secret leaked in response: {secret}");
    }
}
