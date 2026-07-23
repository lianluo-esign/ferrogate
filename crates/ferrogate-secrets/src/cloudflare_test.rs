// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Tests for the Cloudflare Secrets Store cf:// secret resolver (issue #417).

//! Tests for the `cf://` Secrets Store backend (issue #417).
//!
//! The Cloudflare REST API is mocked entirely through `ferrogate-cloudflare`'s
//! injectable [`HttpTransport`] seam — a scripted, URL-keyed fake transport —
//! so parse + resolve are exercised with **no live network**.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, CloudflareError, EnvTokenResolver, HttpRequest,
    HttpResponse, HttpTransport, RetryPolicy, TokioClock,
};

use crate::{
    CloudflareSecretResolver, SecretRef, SecretResolver, SecretResolverRegistry,
    CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES,
};

const BASE: &str = "https://api.test/client/v4/accounts/acct-123/secrets_store";

/// A scripted transport keyed on `"{METHOD} {url}"`. Returns the configured
/// envelope for a matching request; any unscripted request surfaces as a
/// distinctive error envelope so a mis-routed call fails loudly.
struct MockTransport {
    routes: HashMap<String, (u16, String)>,
}

#[async_trait]
impl HttpTransport for MockTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        let key = format!("{:?} {}", request.method, request.url);
        match self.routes.get(&key) {
            Some((status, body)) => Ok(HttpResponse {
                status: *status,
                retry_after: None,
                body: body.clone().into_bytes(),
            }),
            None => Ok(HttpResponse {
                status: 404,
                retry_after: None,
                body: format!(
                    "{{\"success\":false,\"errors\":[{{\"code\":0,\"message\":\"unscripted request {key}\"}}],\"result\":null}}"
                )
                .into_bytes(),
            }),
        }
    }
}

/// Wrap a `result` payload in a `success:true` Cloudflare envelope.
fn ok_envelope(result_json: &str) -> String {
    format!("{{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{result_json}}}")
}

/// Build a resolver whose client speaks to the scripted transport.
fn resolver_with(routes: HashMap<String, (u16, String)>) -> CloudflareSecretResolver {
    let mut config = CloudflareConfig::new("acct-123", "inline-token");
    config.api_base_url = "https://api.test/client/v4".to_string();
    let client = CloudflareClient::from_parts(
        config,
        Arc::new(EnvTokenResolver::default()),
        Arc::new(MockTransport { routes }),
        Arc::new(TokioClock),
        RetryPolicy {
            max_retries: 0,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
        },
    );
    CloudflareSecretResolver::from_client(client)
}

/// Routes for the happy read path: one store named `provider-keys` (id
/// `store-1`) holding one secret `openai-api-key` (id `sec-1`). `detail_result`
/// is spliced in as the `GET .../secrets/sec-1` body so a single helper covers
/// both the value-bearing and write-only-metadata cases.
fn read_routes(detail_result: &str) -> HashMap<String, (u16, String)> {
    let mut routes = HashMap::new();
    routes.insert(
        format!("Get {BASE}/stores"),
        (
            200,
            ok_envelope(r#"[{"id":"store-1","name":"provider-keys"}]"#),
        ),
    );
    routes.insert(
        format!("Get {BASE}/stores/store-1/secrets"),
        (
            200,
            ok_envelope(r#"[{"id":"sec-1","name":"openai-api-key"}]"#),
        ),
    );
    routes.insert(
        format!("Get {BASE}/stores/store-1/secrets/sec-1"),
        (200, ok_envelope(detail_result)),
    );
    routes
}

// --- parse -----------------------------------------------------------------

#[test]
fn parses_cf_reference() {
    let reference = SecretRef::parse("cf://provider-keys/openai-api-key").unwrap();
    assert_eq!(
        reference,
        SecretRef::CfSecret {
            store: "provider-keys".into(),
            name: "openai-api-key".into(),
        }
    );
}

#[test]
fn rejects_cf_reference_missing_name() {
    // No `/` separator at all.
    assert!(SecretRef::parse("cf://provider-keys").is_err());
    // Trailing slash → empty name.
    assert!(SecretRef::parse("cf://provider-keys/").is_err());
    // Empty store.
    assert!(SecretRef::parse("cf:///openai-api-key").is_err());
}

// --- resolve ---------------------------------------------------------------

#[test]
fn cf_resolver_reads_secret_value_via_rest() {
    let resolver = resolver_with(read_routes(
        r#"{"id":"sec-1","name":"openai-api-key","value":"sk-cf-secret"}"#,
    ));
    let reference = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "openai-api-key".into(),
    };
    assert_eq!(
        resolver.resolve(&reference).unwrap().as_deref(),
        Some("sk-cf-secret")
    );
}

#[test]
fn cf_resolver_accepts_store_by_id() {
    // The `store` segment of the ref may be the store id directly.
    let resolver = resolver_with(read_routes(
        r#"{"id":"sec-1","name":"openai-api-key","value":"sk-cf-secret"}"#,
    ));
    let reference = SecretRef::CfSecret {
        store: "store-1".into(),
        name: "openai-api-key".into(),
    };
    assert_eq!(
        resolver.resolve(&reference).unwrap().as_deref(),
        Some("sk-cf-secret")
    );
}

#[test]
fn cf_resolver_returns_none_for_missing_secret() {
    let mut routes = read_routes(r#"{"id":"sec-1","name":"openai-api-key"}"#);
    // Empty secret list → the requested name is not present.
    routes.insert(
        format!("Get {BASE}/stores/store-1/secrets"),
        (200, ok_envelope("[]")),
    );
    let resolver = resolver_with(routes);
    let reference = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "missing-secret".into(),
    };
    assert_eq!(resolver.resolve(&reference).unwrap(), None);
}

#[test]
fn cf_resolver_returns_none_for_missing_store() {
    let mut routes = HashMap::new();
    routes.insert(format!("Get {BASE}/stores"), (200, ok_envelope("[]")));
    let resolver = resolver_with(routes);
    let reference = SecretRef::CfSecret {
        store: "does-not-exist".into(),
        name: "openai-api-key".into(),
    };
    assert_eq!(resolver.resolve(&reference).unwrap(), None);
}

#[test]
fn cf_resolver_surfaces_write_only_value_as_precise_error() {
    // A real Secrets Store returns metadata with NO `value` field. The resolver
    // must NOT fabricate a value — it surfaces a precise error instead.
    let resolver = resolver_with(read_routes(
        r#"{"id":"sec-1","name":"openai-api-key","status":"active"}"#,
    ));
    let reference = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "openai-api-key".into(),
    };
    let error = resolver.resolve(&reference).unwrap_err().to_string();
    assert!(
        error.contains("write-only"),
        "error should explain the write-only value semantics: {error}"
    );
}

// --- registry wiring (proves cf:// flows like vault://) --------------------

#[test]
fn registry_errors_on_cf_reference_without_cloudflare_configured() {
    let registry = SecretResolverRegistry::new();
    let error = registry
        .resolve("cf://provider-keys/openai-api-key")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not configured"),
        "unconfigured cf:// must error clearly: {error}"
    );
}

#[test]
fn registry_routes_cf_reference_through_configured_resolver() {
    let resolver = resolver_with(read_routes(
        r#"{"id":"sec-1","name":"openai-api-key","value":"sk-cf-secret"}"#,
    ));
    let registry = SecretResolverRegistry::new().with_cloudflare(resolver);
    // A cf:// ref resolves through the registry exactly like a vault:// one —
    // this is the seam every provider/MCP secret_ref flows through.
    assert_eq!(
        registry
            .resolve("cf://provider-keys/openai-api-key")
            .unwrap()
            .as_deref(),
        Some("sk-cf-secret")
    );
}

// --- write path + beta caps ------------------------------------------------

#[test]
fn create_secret_rejects_value_exceeding_beta_cap() {
    // Short-circuits before any network call: no routes needed.
    let resolver = resolver_with(HashMap::new());
    let oversized = "x".repeat(CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES + 1);
    let error = resolver
        .create_secret("provider-keys", "big-secret", &oversized, None)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("beta cap"),
        "oversized value must surface the beta cap: {error}"
    );
}

#[test]
fn create_secret_writes_via_rest() {
    let mut routes = HashMap::new();
    routes.insert(
        format!("Get {BASE}/stores"),
        (
            200,
            ok_envelope(r#"[{"id":"store-1","name":"provider-keys"}]"#),
        ),
    );
    routes.insert(
        format!("Post {BASE}/stores/store-1/secrets"),
        (200, ok_envelope(r#"[{"id":"sec-new","name":"new-key"}]"#)),
    );
    let resolver = resolver_with(routes);
    let id = resolver
        .create_secret(
            "provider-keys",
            "new-key",
            "sk-value",
            Some("added by test"),
        )
        .unwrap();
    assert_eq!(id, "sec-new");
}
