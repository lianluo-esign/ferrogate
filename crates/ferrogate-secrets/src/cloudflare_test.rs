// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Tests for the Cloudflare Secrets Store cf:// secret backend —
// Worker-binding value resolution + write/manage REST plane (issues #417, #423).

//! Tests for the `cf://` Secrets Store backend (issues #417/#423).
//!
//! The Cloudflare REST API is mocked entirely through `ferrogate-cloudflare`'s
//! injectable [`HttpTransport`] seam — a scripted, URL-keyed fake transport —
//! so parse + manage-plane behavior are exercised with **no live network**.
//! Value resolution (decision #423) is exercised through the Worker-binding
//! context ([`CfSecretBindings`]) — the injected-map and environment-convention
//! paths — which by design never touches the network at all.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, CloudflareError, EnvTokenResolver, HttpRequest,
    HttpResponse, HttpTransport, RetryPolicy, TokioClock,
};

use crate::{
    cf_binding_env_var, cf_binding_name_is_unambiguous, CfSecretBindings, CfSecretsStoreConfig,
    CloudflareSecretResolver, SecretRef, SecretResolver, SecretResolverRegistry, CF_ACCOUNT_ID_ENV,
    CF_API_TOKEN_ENV, CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES,
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

/// Routes for the manage-plane read path: one store named `provider-keys` (id
/// `store-1`) holding one secret `openai-api-key` (id `sec-1`). Note there is
/// no secret-detail route: since #423 the resolver's REST path is an existence
/// check only (list stores → list secrets) and never fetches a detail body.
fn read_routes() -> HashMap<String, (u16, String)> {
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

// --- Worker-binding value resolution (decision #423, Option A) -------------

#[test]
fn binding_env_var_follows_documented_convention() {
    assert_eq!(
        cf_binding_env_var("openai-api-key"),
        "FERROGATE_CF_SECRET_OPENAI_API_KEY"
    );
    // The mapping itself is lossy — this is precisely the hazard the
    // canonical-name guard below exists to contain, not a supported lookup.
    assert_eq!(
        cf_binding_env_var("db.password/v2"),
        "FERROGATE_CF_SECRET_DB_PASSWORD_V2"
    );
}

// --- aliasing guard: a cf:// ref must never serve a different credential ----

#[test]
fn canonical_names_are_unambiguous_and_everything_else_is_not() {
    // Canonical shape `[a-z0-9-]+`: lowercase → A-Z, digits → digits, `-` → `_`
    // are three disjoint images, so the mapping is injective here.
    for name in ["openai-api-key", "gateway-token-2", "abc", "a-1-b"] {
        assert!(
            cf_binding_name_is_unambiguous(name),
            "{name} should be canonical"
        );
    }
    // Every non-canonical form collapses onto some other name's variable.
    for name in [
        "openai.api.key",
        "openai_api_key",
        "OpenAI-API-Key",
        "OPENAI-API-KEY",
        "db.password/v2",
        "openai api key",
        "openai\u{2013}api\u{2013}key",
        "",
    ] {
        assert!(
            !cf_binding_name_is_unambiguous(name),
            "{name} must not be treated as unambiguous"
        );
    }
}

#[test]
fn distinct_names_that_alias_onto_one_variable_error_instead_of_resolving() {
    // The exact collision the review named: four *distinct* Cloudflare secrets
    // all map to FERROGATE_CF_SECRET_ALIAS_HAZARD_KEY. Only the canonical
    // spelling may read it; the others must fail loudly rather than silently
    // hand back a credential the operator did not name.
    let aliases = [
        "alias.hazard.key",
        "alias_hazard_key",
        "Alias-Hazard-Key",
        "ALIAS-HAZARD-KEY",
    ];
    for name in aliases {
        assert_eq!(
            cf_binding_env_var(name),
            cf_binding_env_var("alias-hazard-key"),
            "test premise: {name} must collide with the canonical spelling"
        );
    }

    std::env::set_var("FERROGATE_CF_SECRET_ALIAS_HAZARD_KEY", "sk-canonical-owner");
    let bindings = CfSecretBindings::new();

    // The canonical owner resolves.
    assert_eq!(
        bindings.lookup("alias-hazard-key").unwrap().as_deref(),
        Some("sk-canonical-owner")
    );

    // Every aliasing spelling errors — and, critically, never yields the
    // canonical owner's value.
    for name in aliases {
        let result = bindings.lookup(name);
        let error = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| panic!("{name} must not resolve, got {result:?}"));
        assert!(
            !error.contains("sk-canonical-owner"),
            "the aliased value leaked into the error: {error}"
        );
        assert!(
            error.contains("FERROGATE_CF_SECRET_ALIAS_HAZARD_KEY"),
            "the error must name the shared variable: {error}"
        );
        assert!(
            error.contains("[a-z0-9-]+") && error.contains("from_map"),
            "the error must offer both remedies (rename / exact injection): {error}"
        );
    }
}

#[test]
fn injected_map_resolves_non_canonical_names_exactly() {
    // The lossless escape hatch: an exact-keyed binding works for any name
    // Cloudflare accepts, and two colliding names keep their own values.
    let mut bindings = CfSecretBindings::new();
    bindings.insert("Alias-Exact-Key", "sk-upper");
    bindings.insert("alias.exact.key", "sk-dotted");
    assert_eq!(
        bindings.lookup("Alias-Exact-Key").unwrap().as_deref(),
        Some("sk-upper")
    );
    assert_eq!(
        bindings.lookup("alias.exact.key").unwrap().as_deref(),
        Some("sk-dotted")
    );
    // A third colliding spelling was never injected → still refused, not
    // silently served one of the two above.
    assert!(bindings.lookup("alias_exact_key").is_err());
}

#[test]
fn registry_refuses_an_ambiguous_cf_reference_before_the_rest_backend() {
    // A REST resolver with no scripted routes: reaching it would surface the
    // loud "unscripted request" error, so its absence proves the binding
    // context refuses first.
    let registry = SecretResolverRegistry::new().with_cloudflare(resolver_with(HashMap::new()));
    let error = registry
        .resolve("cf://provider-keys/Registry_Ambiguous.Key")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not canonical"),
        "ambiguous cf:// must be refused with the aliasing reason: {error}"
    );
    assert!(
        !error.contains("unscripted request"),
        "the refusal must fire before any REST call: {error}"
    );
}

// --- secret material must never reach a Debug rendering (#489/#492) --------

#[test]
fn cf_bindings_debug_redacts_bound_values() {
    let mut bindings = CfSecretBindings::new();
    bindings.insert("openai-api-key", "sk-live-debug-leak-canary");
    bindings.insert("mcp-oauth-client-secret", "cs-live-debug-leak-canary");

    let rendered = format!("{bindings:?}");
    assert!(
        !rendered.contains("sk-live-debug-leak-canary"),
        "bound secret value leaked into CfSecretBindings Debug: {rendered}"
    );
    assert!(
        !rendered.contains("cs-live-debug-leak-canary"),
        "bound secret value leaked into CfSecretBindings Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // Names are not secret and must stay, or the redaction traded a leak for
    // an undiagnosable binding context (the #492 rule for VaultConfig).
    assert!(rendered.contains("CfSecretBindings"), "{rendered}");
    assert!(rendered.contains("openai-api-key"), "{rendered}");
    assert!(rendered.contains("mcp-oauth-client-secret"), "{rendered}");
}

#[test]
fn registry_debug_redacts_nested_binding_values() {
    // The path that actually shows up in logs: `SecretResolver` requires
    // `Debug`, and `SecretResolverRegistry` derives it over a
    // `CfSecretBindings` field — so a single `tracing::debug!(?registry)` three
    // levels up used to print every bound credential.
    let mut bindings = CfSecretBindings::new();
    bindings.insert("openai-api-key", "sk-registry-debug-canary");
    let registry = SecretResolverRegistry::new().with_cf_bindings(bindings);

    let rendered = format!("{registry:?}");
    assert!(
        !rendered.contains("sk-registry-debug-canary"),
        "bound secret value leaked through SecretResolverRegistry Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn cf_secrets_store_config_debug_redacts_an_inline_token() {
    let config = CfSecretsStoreConfig {
        account_id: "acct-123".into(),
        api_token_ref: "cf-live-api-token-canary".into(),
        api_base_url: Some("https://api.test/client/v4".into()),
    };
    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains("cf-live-api-token-canary"),
        "inline CF API token leaked into CfSecretsStoreConfig Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted"), "{rendered}");
    // Non-secret diagnostics survive.
    assert!(rendered.contains("acct-123"), "{rendered}");
    assert!(
        rendered.contains("https://api.test/client/v4"),
        "{rendered}"
    );
}

#[test]
fn cf_secrets_store_config_debug_keeps_an_env_reference_visible() {
    // `env://VAR` names a variable, not a credential: redacting it would hide
    // which variable the client reads without protecting anything.
    let config = CfSecretsStoreConfig {
        account_id: "acct-123".into(),
        api_token_ref: format!("env://{CF_API_TOKEN_ENV}"),
        api_base_url: None,
    };
    let rendered = format!("{config:?}");
    assert!(
        rendered.contains("env://CLOUDFLARE_API_TOKEN"),
        "the token reference should stay legible: {rendered}"
    );
}

#[test]
fn from_env_stores_a_token_reference_and_never_the_token_value() {
    std::env::set_var(CF_ACCOUNT_ID_ENV, "acct-from-env");
    std::env::set_var(CF_API_TOKEN_ENV, "cf-from-env-token-canary");

    let config = CfSecretsStoreConfig::from_env().expect("both variables are set");
    assert_eq!(config.account_id, "acct-from-env");
    assert_eq!(config.api_token_ref, "env://CLOUDFLARE_API_TOKEN");
    assert!(
        !config.api_token_ref.contains("cf-from-env-token-canary"),
        "from_env copied the token VALUE into the config"
    );

    // And the value must not survive into the client config either — which is
    // `Debug + Serialize`, so a token there is both printable and persistable.
    let resolver = CloudflareSecretResolver::new(config).expect("client builds offline");
    let client_config = resolver.client().config();
    assert_eq!(client_config.api_token, "env://CLOUDFLARE_API_TOKEN");
    assert!(
        !format!("{client_config:?}").contains("cf-from-env-token-canary"),
        "the CF API token reached CloudflareConfig's Debug"
    );
    assert!(
        !serde_json::to_string(client_config)
            .unwrap()
            .contains("cf-from-env-token-canary"),
        "the CF API token reached CloudflareConfig's Serialize output"
    );

    std::env::remove_var(CF_ACCOUNT_ID_ENV);
    std::env::remove_var(CF_API_TOKEN_ENV);
}

#[test]
fn cf_bindings_resolve_value_from_injected_map() {
    let mut bindings = CfSecretBindings::new();
    bindings.insert("openai-api-key", "sk-from-binding");
    let reference = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "openai-api-key".into(),
    };
    assert_eq!(
        bindings.resolve(&reference).unwrap().as_deref(),
        Some("sk-from-binding")
    );
    // A name absent from the map (and the environment) is simply unset.
    let missing = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "cf-binding-test-absent-key".into(),
    };
    assert_eq!(bindings.resolve(&missing).unwrap(), None);
}

#[test]
fn cf_bindings_resolve_value_from_env_convention() {
    // Unique secret name so no other (parallel) test touches this variable.
    std::env::set_var("FERROGATE_CF_SECRET_ENV_CONV_TEST_KEY", "sk-from-env");
    let bindings = CfSecretBindings::new();
    let reference = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "env-conv-test-key".into(),
    };
    assert_eq!(
        bindings.resolve(&reference).unwrap().as_deref(),
        Some("sk-from-env")
    );

    // Empty/whitespace values count as unset (mirrors env://).
    std::env::set_var("FERROGATE_CF_SECRET_ENV_CONV_EMPTY_KEY", "  ");
    let empty = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "env-conv-empty-key".into(),
    };
    assert_eq!(bindings.resolve(&empty).unwrap(), None);
}

#[test]
fn registry_resolves_cf_reference_from_env_binding_without_rest_backend() {
    // The Worker-binding env convention needs no CLOUDFLARE_* configuration —
    // exactly how a Worker-bound deployment resolves cf:// with no API token.
    std::env::set_var("FERROGATE_CF_SECRET_REGISTRY_ENV_BIND_KEY", "sk-bound");
    let registry = SecretResolverRegistry::new();
    assert_eq!(
        registry
            .resolve("cf://provider-keys/registry-env-bind-key")
            .unwrap()
            .as_deref(),
        Some("sk-bound")
    );
}

#[test]
fn registry_prefers_binding_value_over_rest_backend() {
    // A REST resolver with NO scripted routes: any network call would return
    // the loud "unscripted request" error — so a successful resolve proves the
    // binding context short-circuits before any REST traffic.
    let rest = resolver_with(HashMap::new());
    let mut bindings = CfSecretBindings::new();
    bindings.insert("openai-api-key", "sk-from-binding");
    let registry = SecretResolverRegistry::new()
        .with_cloudflare(rest)
        .with_cf_bindings(bindings);
    assert_eq!(
        registry
            .resolve("cf://provider-keys/openai-api-key")
            .unwrap()
            .as_deref(),
        Some("sk-from-binding")
    );
}

// --- REST backend: existence checks, write/manage-only scoping -------------

#[test]
fn cf_resolver_returns_none_for_missing_secret() {
    let mut routes = read_routes();
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
    // A real Secrets Store never returns a value over REST. The resolver must
    // NOT fabricate one — an existing secret surfaces a precise error pointing
    // at the supported Worker-binding path (decision #423).
    let resolver = resolver_with(read_routes());
    let reference = SecretRef::CfSecret {
        store: "provider-keys".into(),
        name: "openai-api-key".into(),
    };
    let error = resolver.resolve(&reference).unwrap_err().to_string();
    assert!(
        error.contains("write-only"),
        "error should explain the write-only value semantics: {error}"
    );
    assert!(
        error.contains("FERROGATE_CF_SECRET_OPENAI_API_KEY"),
        "error should point at the Worker-binding env convention: {error}"
    );
    assert!(
        error.contains("vault://"),
        "error should point at the readable-backend alternative: {error}"
    );
}

#[test]
fn cf_resolver_accepts_store_by_id() {
    // The `store` segment of the ref may be the store id directly; reaching
    // the write-only error (rather than Ok(None)) proves the store + secret
    // lookups both succeeded.
    let resolver = resolver_with(read_routes());
    let reference = SecretRef::CfSecret {
        store: "store-1".into(),
        name: "openai-api-key".into(),
    };
    let error = resolver.resolve(&reference).unwrap_err().to_string();
    assert!(error.contains("write-only"), "unexpected error: {error}");
}

// --- registry wiring (proves cf:// flows like vault://) --------------------

#[test]
fn registry_errors_on_cf_reference_without_cloudflare_configured() {
    let registry = SecretResolverRegistry::new();
    let error = registry
        .resolve("cf://provider-keys/unbound-unconfigured-key")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not configured"),
        "unconfigured cf:// must error clearly: {error}"
    );
    assert!(
        error.contains("FERROGATE_CF_SECRET_UNBOUND_UNCONFIGURED_KEY"),
        "the error must name the binding env var that was checked: {error}"
    );
}

#[test]
fn registry_routes_cf_reference_through_configured_rest_resolver() {
    // With no binding value present, a cf:// ref flows through the registry to
    // the REST backend exactly like a vault:// one — whose existence check
    // yields None for a missing secret.
    let mut routes = read_routes();
    routes.insert(
        format!("Get {BASE}/stores/store-1/secrets"),
        (200, ok_envelope("[]")),
    );
    let registry = SecretResolverRegistry::new().with_cloudflare(resolver_with(routes));
    assert_eq!(
        registry
            .resolve("cf://provider-keys/registry-rest-missing-key")
            .unwrap(),
        None
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

/// JSON array of `count` secret metadata items (`bulk-0` … `bulk-{count-1}`),
/// for scripting a store that already holds a given number of secrets.
fn secrets_listing_json(count: usize) -> String {
    let items: Vec<String> = (0..count)
        .map(|index| format!(r#"{{"id":"sec-{index}","name":"bulk-{index}"}}"#))
        .collect();
    format!("[{}]", items.join(","))
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
    // The #418 budget guardrail counts the store's secrets before writing.
    routes.insert(
        format!("Get {BASE}/stores/store-1/secrets"),
        (
            200,
            ok_envelope(r#"[{"id":"sec-1","name":"openai-api-key"}]"#),
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

#[test]
fn create_secret_rejects_new_secret_when_store_is_at_the_budget() {
    // 100 existing secrets = the full beta budget. Deliberately NO Post route:
    // the guardrail must fail before any create request, so a POST attempt
    // would surface as the loud "unscripted request" error instead.
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
        (200, ok_envelope(&secrets_listing_json(100))),
    );
    let resolver = resolver_with(routes);
    let error = resolver
        .create_secret("provider-keys", "one-too-many", "sk-value", None)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("100 secrets") && error.contains("budget"),
        "budget error must state usage vs budget: {error}"
    );
    assert!(
        !error.contains("unscripted request"),
        "the guardrail must fire before any create request: {error}"
    );
}

#[test]
fn create_secret_allows_overwrite_when_store_is_at_the_budget() {
    // Overwriting an existing name consumes no new slot, so it stays allowed
    // even with the budget fully consumed (the soft-cap warning is logged).
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
        (200, ok_envelope(&secrets_listing_json(100))),
    );
    routes.insert(
        format!("Post {BASE}/stores/store-1/secrets"),
        (200, ok_envelope(r#"[{"id":"sec-7","name":"bulk-7"}]"#)),
    );
    let resolver = resolver_with(routes);
    let id = resolver
        .create_secret("provider-keys", "bulk-7", "rotated-value", None)
        .unwrap();
    assert_eq!(id, "sec-7");
}
