// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: A2A (agent-to-agent) ingress deep governance (issue #278):
// parse A2A message envelopes (streaming + non-streaming) into the guardrail
// content-envelope model so the same input/output detector chains, policy,
// metering, and request-log chokepoints the OpenAI/Anthropic/MCP ingresses use
// apply to agent-to-agent traffic. The heavy governance primitives
// (`match_guardrail`, `evaluate_policy`, `record_a2a_exchange_event`,
// `record_request_log`) are reused verbatim from the shared chokepoint; this
// module owns only the A2A-protocol-specific parsing and envelope construction.

use ferrogate_guardrails::{ContentSource, DetectorStage, GuardrailEnvelope, GuardrailProtocol};
use serde_json::Value;

/// Route label recorded on A2A request logs and policy contexts, mirroring the
/// `anthropic.messages` / `openai.chat.completions` route constants.
pub(super) const A2A_ROUTE: &str = "a2a.message";

/// Build the request-stage (`input`) guardrail envelope for an inbound A2A
/// message body (issue #278). A2A message parts (`{"kind":"text","text":...}`)
/// can appear at several JSON-RPC / task locations (`params.message.parts[]`,
/// top-level `message.parts[]`, `messages[].parts[]`, `parts[]`), so every text
/// part reachable in the body is collected and flattened into a single
/// `ContentSource::User` segment — the same fail-safe "scan all inbound content"
/// posture the chat ingress applies to prompt messages.
pub(super) fn a2a_input_envelope(agent_id: &str, body: &Value) -> GuardrailEnvelope {
    let text = collect_a2a_text_flattened(body);
    GuardrailEnvelope::from_text(
        GuardrailProtocol::A2a,
        DetectorStage::Request,
        ContentSource::User,
        format!("a2a:{agent_id}/message"),
        text,
    )
}

/// Build the response-stage (`output`) guardrail envelope for an A2A upstream
/// reply (issue #278). For a streamed reply the SSE `data:` frames are parsed
/// and their text parts accumulated; for a unary reply the JSON body is parsed
/// directly. Everything is flattened into a single `ContentSource::Assistant`
/// segment so output detectors (secret leakage, etc.) evaluate the agent's
/// reply in both directions, identical to the messages ingress buffering its
/// stream before the response-stage guardrail.
pub(super) fn a2a_output_envelope(agent_id: &str, body: &[u8], stream: bool) -> GuardrailEnvelope {
    let mut collected = Vec::new();
    if stream {
        for value in sse_data_values(body) {
            collect_a2a_text(&value, &mut collected);
        }
    } else if let Ok(value) = serde_json::from_slice::<Value>(body) {
        collect_a2a_text(&value, &mut collected);
    }
    let text = if collected.is_empty() {
        // Fall back to the raw body so a reply the parser did not recognise is
        // still scanned rather than silently skipped (fail-safe, matching the
        // `response.raw` fallback in the HTTP normalizer).
        String::from_utf8_lossy(body).into_owned()
    } else {
        collected.join("\n")
    };
    GuardrailEnvelope::from_text(
        GuardrailProtocol::A2a,
        DetectorStage::Response,
        ContentSource::Assistant,
        format!("a2a:{agent_id}/response"),
        text,
    )
}

/// Count the A2A message parts in a body, used as the metered message unit
/// (issue #278). Every `{"kind":"text","text":...}`-style part contributes one;
/// a body with no recognizable parts still counts as one exchange.
pub(super) fn a2a_message_count(body: &Value) -> u64 {
    let mut parts = Vec::new();
    collect_a2a_text(body, &mut parts);
    parts.len().max(1) as u64
}

fn collect_a2a_text_flattened(body: &Value) -> String {
    let mut collected = Vec::new();
    collect_a2a_text(body, &mut collected);
    collected.join("\n")
}

/// Recursively collect the `text` of every A2A text part in `value`. A2A parts
/// are objects carrying a string `text` field (the `kind:"text"` shape); we key
/// off the presence of a string `text` field so the walk is robust to the
/// protocol's several envelope shapes (message/send params, task status
/// messages, artifacts) and to minor upstream variations.
fn collect_a2a_text(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(text)) = map.get("text") {
                if !text.is_empty() {
                    out.push(text.clone());
                }
            }
            for (key, child) in map {
                // The `text` field itself is already captured above; recurse
                // into every other field to reach nested parts/artifacts.
                if key != "text" {
                    collect_a2a_text(child, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_a2a_text(item, out);
            }
        }
        _ => {}
    }
}

/// Parse the `data:` payloads of an SSE stream into JSON values, skipping
/// heartbeat / `[DONE]` frames. Mirrors the framing `extract_sse` in the
/// guardrails crate but returns the decoded values for the A2A part walk.
fn sse_data_values(body: &[u8]) -> Vec<Value> {
    let normalized = String::from_utf8_lossy(body).replace("\r\n", "\n");
    let mut values = Vec::new();
    for frame in normalized.split("\n\n") {
        let mut data = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("data:") {
                data.push(value.trim_start());
            }
        }
        let data = data.join("\n");
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&data) {
            values.push(value);
        }
    }
    values
}

#[cfg(test)]
#[path = "a2a_test.rs"]
mod a2a_test;
