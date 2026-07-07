// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Payment-provider adapter boundary for prepaid-credit wallet
// top-ups (issue #169), mirroring `ProviderAdapter` (`ferrogate-providers`)
// and `MeteringProviderAdapter` (`metering.rs`): a small trait so the
// wallet top-up path isn't hard-wired to one payment processor, with a
// `StripePaymentProviderAdapter` as the first (and, for now, only)
// implementation.
//
// Honest scope note: this targets Stripe's real, published API shape
// (`POST https://api.stripe.com/v1/customers`, `.../payment_methods/{id}/
// attach`, `.../payment_intents`) and is tested against a local mock HTTP
// server (asserting request shape: form-urlencoded body, Bearer auth,
// idempotency key), the same testing philosophy as every other adapter in
// this codebase -- none of them call a real upstream provider in tests
// either. No live Stripe test-mode credentials were available to verify
// end-to-end against the real Stripe API; that verification is documented
// as remaining follow-up work on issue #169.

use async_trait::async_trait;
use serde::Deserialize;

use super::dispatch::provider_http_client;

/// A payment-provider-side customer/payment-method/charge operation
/// boundary (issue #169). Implementations must never expose raw card
/// data through this trait -- only opaque provider-side ids.
#[async_trait]
pub(crate) trait PaymentProviderAdapter: Send + Sync {
    fn provider_name(&self) -> &'static str;

    /// Creates (or, for an idempotent provider like Stripe, reuses) a
    /// customer record for `tenant_id`, returning the provider-side
    /// customer id.
    async fn create_customer(&self, tenant_id: &str) -> anyhow::Result<String>;

    /// Attaches an existing provider-side payment-method token (e.g. a
    /// Stripe `pm_...` id collected client-side, never a raw card number)
    /// to `customer_id`.
    async fn attach_payment_method(
        &self,
        customer_id: &str,
        payment_method_token: &str,
    ) -> anyhow::Result<String>;

    /// Charges `amount_usd_cents` against `payment_method_id` for
    /// `customer_id`. `idempotency_key` must be stable across retries of
    /// the *same* logical charge (e.g. derived from the wallet top-up
    /// request id) so a network retry can never double-charge.
    async fn charge(
        &self,
        customer_id: &str,
        payment_method_id: &str,
        amount_usd_cents: u64,
        idempotency_key: &str,
    ) -> anyhow::Result<ChargeOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChargeOutcome {
    pub(crate) succeeded: bool,
    /// Provider-side charge/payment-intent id, present whether the charge
    /// succeeded or was declined (Stripe still assigns a PaymentIntent id
    /// to a declined attempt).
    pub(crate) provider_charge_id: String,
    /// Human-readable decline reason when `succeeded` is `false`.
    pub(crate) decline_reason: Option<String>,
}

/// Stripe implementation of [`PaymentProviderAdapter`] (issue #169).
/// Stripe's API is `application/x-www-form-urlencoded`, not JSON, and
/// authenticates via HTTP Basic auth with the secret key as the
/// username and an empty password -- both are easy to get wrong copying
/// from a JSON-API mental model, so this adapter is deliberately explicit
/// about both.
pub(crate) struct StripePaymentProviderAdapter {
    secret_key: String,
    /// Overridable for tests (a local mock server) -- defaults to
    /// Stripe's real API host in production.
    api_base: String,
}

impl StripePaymentProviderAdapter {
    pub(crate) const PROVIDER_NAME: &'static str = "stripe";

    pub(crate) fn new(secret_key: String) -> Self {
        Self {
            secret_key,
            api_base: "https://api.stripe.com".to_string(),
        }
    }

    #[cfg(test)]
    fn with_api_base(secret_key: String, api_base: String) -> Self {
        Self {
            secret_key,
            api_base,
        }
    }

    /// Hand-encodes the form body and Basic-auth header rather than using
    /// reqwest's `form`/`json`/`basic_auth` convenience methods: this
    /// crate's `reqwest` build only enables the `rustls-no-provider` and
    /// `stream` features (same constraint `dispatch.rs`'s AI-provider
    /// dispatch already works under, parsing JSON manually via
    /// `serde_json::from_slice` rather than `Response::json`), so adding
    /// those features crate-wide isn't warranted for one adapter.
    async fn post_form(
        &self,
        path: &str,
        form: &[(&str, String)],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        let client = provider_http_client()?;
        let encoded_body = form
            .iter()
            .map(|(key, value)| format!("{}={}", form_url_encode(key), form_url_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let basic_auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:", self.secret_key),
        );
        let mut request = client
            .post(format!("{}{path}", self.api_base))
            .header("Authorization", format!("Basic {basic_auth}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded_body);
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }
        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            let message = body
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("stripe request failed");
            anyhow::bail!("stripe API error (HTTP {status}): {message}");
        }
        Ok(body)
    }
}

/// `application/x-www-form-urlencoded` percent-encoding: every byte
/// outside the unreserved set is percent-encoded, and a literal space
/// encodes as `+` (form encoding's one difference from plain URI
/// percent-encoding, which the SigV4 encoder in `ferrogate-providers`
/// doesn't need since it never form-encodes a body).
fn form_url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else if ch == ' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct StripeIdResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct StripePaymentIntentResponse {
    id: String,
    status: String,
}

#[async_trait]
impl PaymentProviderAdapter for StripePaymentProviderAdapter {
    fn provider_name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    async fn create_customer(&self, tenant_id: &str) -> anyhow::Result<String> {
        let body = self
            .post_form(
                "/v1/customers",
                &[
                    ("description", format!("FerroGate tenant {tenant_id}")),
                    ("metadata[ferrogate_tenant_id]", tenant_id.to_string()),
                ],
                None,
            )
            .await?;
        let parsed: StripeIdResponse = serde_json::from_value(body)?;
        Ok(parsed.id)
    }

    async fn attach_payment_method(
        &self,
        customer_id: &str,
        payment_method_token: &str,
    ) -> anyhow::Result<String> {
        let body = self
            .post_form(
                &format!("/v1/payment_methods/{payment_method_token}/attach"),
                &[("customer", customer_id.to_string())],
                None,
            )
            .await?;
        let parsed: StripeIdResponse = serde_json::from_value(body)?;
        Ok(parsed.id)
    }

    async fn charge(
        &self,
        customer_id: &str,
        payment_method_id: &str,
        amount_usd_cents: u64,
        idempotency_key: &str,
    ) -> anyhow::Result<ChargeOutcome> {
        let body = self
            .post_form(
                "/v1/payment_intents",
                &[
                    ("amount", amount_usd_cents.to_string()),
                    ("currency", "usd".to_string()),
                    ("customer", customer_id.to_string()),
                    ("payment_method", payment_method_id.to_string()),
                    ("confirm", "true".to_string()),
                    ("off_session", "true".to_string()),
                ],
                Some(idempotency_key),
            )
            .await?;
        let parsed: StripePaymentIntentResponse = serde_json::from_value(body)?;
        let succeeded = parsed.status == "succeeded";
        Ok(ChargeOutcome {
            succeeded,
            provider_charge_id: parsed.id,
            decline_reason: (!succeeded).then_some(parsed.status),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Spawns a one-shot plain-HTTP mock Stripe API on `127.0.0.1` that
    /// records the request's path, headers, and form-decoded body, and
    /// replies with a fixed JSON body -- mirrors
    /// `state.rs::spawn_guardrail_provider_mock`'s pattern.
    fn spawn_stripe_mock(
        response_body: &'static str,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Option<CapturedRequest>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api_base = format!("http://{}", listener.local_addr().unwrap());
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let server_captured = std::sync::Arc::clone(&captured);

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                raw.extend_from_slice(&buffer[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
            let content_length: usize = head
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length: ")
                        .or(line.strip_prefix("Content-Length: "))
                })
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            while raw.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                raw.extend_from_slice(&buffer[..read]);
            }
            let body =
                String::from_utf8_lossy(&raw[header_end..header_end + content_length]).into_owned();
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let has_basic_auth = head.to_lowercase().contains("authorization: basic");
            let idempotency_key = head
                .lines()
                .find_map(|line| line.strip_prefix("idempotency-key: "))
                .map(ToOwned::to_owned);
            *server_captured.lock().unwrap() = Some(CapturedRequest {
                path,
                body,
                has_basic_auth,
                idempotency_key,
            });

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        (api_base, captured)
    }

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        path: String,
        body: String,
        has_basic_auth: bool,
        idempotency_key: Option<String>,
    }

    #[tokio::test]
    async fn create_customer_posts_form_encoded_request_with_basic_auth() {
        let (api_base, captured) = spawn_stripe_mock(r#"{"id":"cus_test123"}"#);
        let adapter = StripePaymentProviderAdapter::with_api_base("sk_test_dummy".into(), api_base);

        let customer_id = adapter.create_customer("tenant-1").await.unwrap();
        assert_eq!(customer_id, "cus_test123");

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.path, "/v1/customers");
        assert!(
            request.has_basic_auth,
            "must authenticate via HTTP Basic auth"
        );
        assert!(request
            .body
            .contains("metadata%5Bferrogate_tenant_id%5D=tenant-1"));
    }

    #[tokio::test]
    async fn attach_payment_method_posts_to_the_attach_endpoint() {
        let (api_base, captured) = spawn_stripe_mock(r#"{"id":"pm_test123"}"#);
        let adapter = StripePaymentProviderAdapter::with_api_base("sk_test_dummy".into(), api_base);

        let id = adapter
            .attach_payment_method("cus_test123", "pm_test123")
            .await
            .unwrap();
        assert_eq!(id, "pm_test123");

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.path, "/v1/payment_methods/pm_test123/attach");
        assert!(request.body.contains("customer=cus_test123"));
    }

    #[tokio::test]
    async fn charge_sends_idempotency_key_and_parses_success() {
        let (api_base, captured) = spawn_stripe_mock(r#"{"id":"pi_test123","status":"succeeded"}"#);
        let adapter = StripePaymentProviderAdapter::with_api_base("sk_test_dummy".into(), api_base);

        let outcome = adapter
            .charge("cus_test123", "pm_test123", 500, "idem-key-1")
            .await
            .unwrap();
        assert!(outcome.succeeded);
        assert_eq!(outcome.provider_charge_id, "pi_test123");
        assert!(outcome.decline_reason.is_none());

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.path, "/v1/payment_intents");
        assert_eq!(request.idempotency_key.as_deref(), Some("idem-key-1"));
        assert!(request.body.contains("amount=500"));
        assert!(request.body.contains("currency=usd"));
    }

    #[tokio::test]
    async fn charge_reports_decline_without_erroring() {
        let (api_base, _captured) =
            spawn_stripe_mock(r#"{"id":"pi_test456","status":"requires_payment_method"}"#);
        let adapter = StripePaymentProviderAdapter::with_api_base("sk_test_dummy".into(), api_base);

        let outcome = adapter
            .charge("cus_test123", "pm_test123", 500, "idem-key-2")
            .await
            .unwrap();
        assert!(!outcome.succeeded);
        assert_eq!(
            outcome.decline_reason.as_deref(),
            Some("requires_payment_method")
        );
    }
}
