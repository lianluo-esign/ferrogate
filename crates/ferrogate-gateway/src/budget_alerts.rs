// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Outbound webhook dispatch for proactive budget-threshold
// alerting (issue #170). Threshold-crossing detection and idempotency
// live in `AppState` (state.rs) / `ferrogate-storage`; this module is
// only the "POST a JSON payload to the configured webhook_url" transport,
// reusing `telemetry::dispatch_otlp_request`'s raw TCP/TLS client rather
// than duplicating it.

use std::time::Duration;

use anyhow::Result as AnyResult;
use ferrogate_observability::OtlpHttpRequest;
use ferrogate_storage::QuotaScopeKind;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HTTP header carrying the alert HMAC signature (`sha256=<hex>`), issue #228.
pub(crate) const WEBHOOK_SIGNATURE_HEADER: &str = "X-FerroGate-Signature";
/// HTTP header carrying the signed timestamp (the payload's `fired_at_unix`).
pub(crate) const WEBHOOK_TIMESTAMP_HEADER: &str = "X-FerroGate-Timestamp";

/// Compute the budget-alert signature over `"<timestamp>.<body>"` with
/// HMAC-SHA256, returned as `sha256=<lowercase hex>`. The timestamp is bound
/// into the signed material so a receiver can reject replays. Exposed for the
/// delivery path and its regression test.
pub(crate) fn budget_alert_signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("sha256={}", encode_hex(&mac.finalize().into_bytes()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Wire payload for a budget-threshold-crossing webhook (issue #170). Flat
/// and self-describing so a receiver needs no FerroGate-internal knowledge
/// to route it (e.g. to a per-tenant Slack channel) -- this is the
/// documented extension point the issue calls for pluggable email/Slack
/// targets to eventually sit behind.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BudgetAlertWebhookPayload<'a> {
    pub(crate) event: &'static str,
    pub(crate) scope_type: &'static str,
    pub(crate) scope_id: &'a str,
    pub(crate) period_month: &'a str,
    pub(crate) threshold_pct: u8,
    pub(crate) spent_usd: f64,
    pub(crate) budget_usd: f64,
    pub(crate) fired_at_unix: i64,
}

impl<'a> BudgetAlertWebhookPayload<'a> {
    pub(crate) fn new(
        scope_type: QuotaScopeKind,
        scope_id: &'a str,
        period_month: &'a str,
        threshold_pct: u8,
        spent_usd: f64,
        budget_usd: f64,
        fired_at_unix: i64,
    ) -> Self {
        Self {
            event: "budget_threshold_crossed",
            scope_type: scope_type.as_str(),
            scope_id,
            period_month,
            threshold_pct,
            spent_usd,
            budget_usd,
            fired_at_unix,
        }
    }
}

/// Best-effort delivery -- callers must not let a webhook failure block or
/// retry the request that triggered it. See [`crate::state::AppState`]'s
/// budget-threshold-alert dispatch for the idempotency handling that makes
/// a delivery failure here merely "this tier's alert didn't go out" rather
/// than a correctness problem for the gateway itself.
pub(crate) fn dispatch_budget_alert_webhook(
    webhook_url: &str,
    timeout: Duration,
    signing_secret: Option<&str>,
    payload: &BudgetAlertWebhookPayload<'_>,
) -> AnyResult<()> {
    let body = serde_json::to_vec(payload)?;
    // When a signing secret is configured, authenticate the alert with an
    // HMAC-SHA256 over "<fired_at_unix>.<body>" plus the timestamp header, so a
    // receiver can verify the alert originated from this gateway and reject
    // replays. Unsigned (secret None) preserves the legacy behavior.
    let headers = match signing_secret.filter(|secret| !secret.is_empty()) {
        Some(secret) => vec![
            (
                WEBHOOK_TIMESTAMP_HEADER.to_string(),
                payload.fired_at_unix.to_string(),
            ),
            (
                WEBHOOK_SIGNATURE_HEADER.to_string(),
                budget_alert_signature(secret, payload.fired_at_unix, &body),
            ),
        ],
        None => Vec::new(),
    };
    let request = OtlpHttpRequest {
        method: "POST",
        url: webhook_url.to_string(),
        content_type: "application/json",
        body,
        headers,
    };
    crate::telemetry::dispatch_otlp_request(&request, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn signature_is_deterministic_and_binds_timestamp_body_and_secret() {
        let body = br#"{"event":"budget_threshold_crossed"}"#;
        let base = budget_alert_signature("s3cr3t", 1_000, body);
        assert!(base.starts_with("sha256="));
        assert_eq!(base, budget_alert_signature("s3cr3t", 1_000, body));
        // Any input change must change the signature.
        assert_ne!(base, budget_alert_signature("other", 1_000, body));
        assert_ne!(base, budget_alert_signature("s3cr3t", 1_001, body));
        assert_ne!(base, budget_alert_signature("s3cr3t", 1_000, b"tampered"));
    }

    // Captures the full raw HTTP request (headers + body) for one connection.
    fn spawn_raw_capture_server() -> (String, Arc<Mutex<Option<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/budget-alerts", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(None));
        let server_captured = Arc::clone(&captured);
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let mut raw = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    let header_end = raw
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| position + 4);
                    if let Some(header_end) = header_end {
                        let content_length: usize = String::from_utf8_lossy(&raw[..header_end])
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .and_then(|value| value.trim().parse().ok())
                            .unwrap_or(0);
                        if raw.len() >= header_end + content_length {
                            break;
                        }
                    }
                }
                *server_captured.lock().unwrap() = Some(raw);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                );
            }
        });
        (endpoint, captured)
    }

    fn split_headers_body(raw: &[u8]) -> (String, Vec<u8>) {
        let end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("request must have a header terminator")
            + 4;
        (
            String::from_utf8_lossy(&raw[..end]).to_string(),
            raw[end..].to_vec(),
        )
    }

    fn sample_payload() -> BudgetAlertWebhookPayload<'static> {
        BudgetAlertWebhookPayload::new(
            QuotaScopeKind::Tenant,
            "tenant-x",
            "2026-07",
            90,
            9.0,
            10.0,
            1_700_000_000,
        )
    }

    #[test]
    fn signed_delivery_emits_a_verifiable_signature_header() {
        let (endpoint, captured) = spawn_raw_capture_server();
        dispatch_budget_alert_webhook(
            &endpoint,
            Duration::from_secs(2),
            Some("webhook-secret"),
            &sample_payload(),
        )
        .expect("signed dispatch");

        let raw = loop {
            if let Some(raw) = captured.lock().unwrap().take() {
                break raw;
            }
            std::thread::yield_now();
        };
        let (headers, body) = split_headers_body(&raw);
        assert!(
            headers.contains(&format!("{WEBHOOK_TIMESTAMP_HEADER}: 1700000000")),
            "missing/incorrect timestamp header: {headers}"
        );
        let expected = budget_alert_signature("webhook-secret", 1_700_000_000, &body);
        assert!(
            headers.contains(&format!("{WEBHOOK_SIGNATURE_HEADER}: {expected}")),
            "signature header must match HMAC over the delivered body: {headers}"
        );
        // A receiver using the wrong secret must not verify.
        assert_ne!(
            expected,
            budget_alert_signature("wrong-secret", 1_700_000_000, &body)
        );
    }

    #[test]
    fn unsigned_delivery_carries_no_signature_header() {
        let (endpoint, captured) = spawn_raw_capture_server();
        dispatch_budget_alert_webhook(&endpoint, Duration::from_secs(2), None, &sample_payload())
            .expect("unsigned dispatch");
        let raw = loop {
            if let Some(raw) = captured.lock().unwrap().take() {
                break raw;
            }
            std::thread::yield_now();
        };
        let (headers, _) = split_headers_body(&raw);
        assert!(
            !headers.contains(WEBHOOK_SIGNATURE_HEADER),
            "unsigned alerts must not carry a signature header: {headers}"
        );
    }
}
