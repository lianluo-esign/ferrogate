// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Unit tests for the inbound x402 operator config surface (#356):
// disabled-by-default, missing-section and cross-field refusals, the replay
// floor, secret-by-reference resolution, and a load of the SHIPPED deployment
// manifest so it cannot rot away from the schema.

use std::collections::HashMap;

use super::*;

const DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER: &str = "So11111111111111111111111111111111111111112";
const SECRET_ENV: &str = "FERROGATE_TEST_X402_INBOUND_SECRET";
const PREVIOUS_ENV: &str = "FERROGATE_TEST_X402_INBOUND_SECRET_PREVIOUS";
const SECRET: &str = "unit-test-sidecar-secret-0123456789abcdef";
const PREVIOUS_SECRET: &str = "unit-test-sidecar-secret-previous-0123456789";

fn endpoint() -> InboundX402Endpoint {
    InboundX402Endpoint {
        resource_url: "https://api.ferrogate.example/v1/priced/report".to_string(),
        resource_description: None,
        resource_mime_type: None,
        network_caip2: DEVNET.to_string(),
        mint: MINT.to_string(),
        recipient: RECIPIENT.to_string(),
        fee_payer: FEE_PAYER.to_string(),
        price_atomic_amount: 10_000,
        max_timeout_seconds: 120,
        memo: None,
        challenge_error: None,
    }
}

fn config() -> InboundX402Config {
    InboundX402Config {
        enabled: true,
        endpoint: Some(endpoint()),
        sidecar: Some(InboundX402SidecarConfig {
            credential_secret_env: SECRET_ENV.to_string(),
            rotating_out_secret_env: None,
            require_mutual_tls: false,
            pinned_client_subjects: Vec::new(),
        }),
        attribution: Some(InboundX402AttributionConfig {
            tenant_id: "tenant-public-paid-api".to_string(),
            project_id: Some("project-x402-inbound".to_string()),
            workspace_id: None,
        }),
        forward_claim_ttl_secs: Some(300),
        forward_claim_capacity: Some(1_024),
    }
}

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

// -------------------------------------------------------------------------
// Disabled by default
// -------------------------------------------------------------------------

#[test]
fn an_omitted_section_is_disabled_not_an_error() {
    let validated = load_inbound_x402_toml("").expect("an empty document is valid");
    assert!(
        validated.is_none(),
        "inbound monetization must never be on by accident"
    );
}

#[test]
fn an_explicitly_disabled_section_needs_no_other_field() {
    let validated = load_inbound_x402_toml("[x402_inbound]\nenabled = false\n")
        .expect("a disabled section is valid on its own");
    assert!(validated.is_none());
}

#[test]
fn the_default_config_is_disabled() {
    assert_eq!(InboundX402Config::disabled(), InboundX402Config::default());
    assert!(!InboundX402Config::disabled().enabled);
    assert_eq!(
        InboundX402Config::disabled()
            .validate_structure()
            .expect("valid"),
        None
    );
}

// -------------------------------------------------------------------------
// Required sections
// -------------------------------------------------------------------------

#[test]
fn enabling_without_an_endpoint_is_refused() {
    let mut config = config();
    config.endpoint = None;
    assert_eq!(
        config
            .validate_structure()
            .expect_err("endpoint is required"),
        InboundX402SectionError::MissingSection {
            section: "x402_inbound.endpoint",
        }
    );
}

#[test]
fn enabling_without_a_sidecar_section_is_refused() {
    let mut config = config();
    config.sidecar = None;
    assert_eq!(
        config
            .validate_structure()
            .expect_err("sidecar is required"),
        InboundX402SectionError::MissingSection {
            section: "x402_inbound.sidecar",
        }
    );
}

#[test]
fn enabling_without_attribution_is_refused() {
    let mut config = config();
    config.attribution = None;
    assert_eq!(
        config
            .validate_structure()
            .expect_err("a tenant must be declared, never inferred from the payer"),
        InboundX402SectionError::MissingSection {
            section: "x402_inbound.attribution",
        }
    );
}

#[test]
fn an_empty_tenant_id_is_refused() {
    let mut config = config();
    config.attribution = Some(InboundX402AttributionConfig {
        tenant_id: "   ".to_string(),
        project_id: None,
        workspace_id: None,
    });
    assert_eq!(
        config.validate_structure().expect_err("blank tenant"),
        InboundX402SectionError::EmptyField {
            field: "attribution.tenant_id",
        }
    );
}

#[test]
fn an_invalid_endpoint_surfaces_the_billing_crates_own_error() {
    let mut config = config();
    let mut endpoint = endpoint();
    endpoint.price_atomic_amount = 0;
    config.endpoint = Some(endpoint);
    assert!(matches!(
        config
            .validate_structure()
            .expect_err("a zero price is not a price"),
        InboundX402SectionError::Endpoint(_)
    ));
}

// -------------------------------------------------------------------------
// The replay floor
// -------------------------------------------------------------------------

#[test]
fn a_claim_ttl_below_the_payment_window_is_refused() {
    let mut config = config();
    config.forward_claim_ttl_secs = Some(119);
    assert_eq!(
        config
            .validate_structure()
            .expect_err("a claim must outlive the payment that created it"),
        InboundX402SectionError::ClaimTtlBelowPaymentWindow {
            ttl_secs: 119,
            max_timeout_seconds: 120,
        }
    );
}

#[test]
fn a_claim_ttl_equal_to_the_payment_window_is_accepted() {
    let mut config = config();
    config.forward_claim_ttl_secs = Some(120);
    let validated = config
        .validate_structure()
        .expect("the floor is inclusive")
        .expect("enabled");
    assert_eq!(validated.forward_claim_ttl_secs(), 120);
}

#[test]
fn an_absent_claim_ttl_defaults_to_the_payment_window() {
    let mut config = config();
    config.forward_claim_ttl_secs = None;
    let validated = config
        .validate_structure()
        .expect("valid")
        .expect("enabled");
    assert_eq!(validated.forward_claim_ttl_secs(), 120);
}

#[test]
fn an_absent_capacity_defaults_to_the_documented_constant() {
    let mut config = config();
    config.forward_claim_capacity = None;
    let validated = config
        .validate_structure()
        .expect("valid")
        .expect("enabled");
    assert_eq!(
        validated.forward_claim_capacity(),
        DEFAULT_FORWARD_CLAIM_CAPACITY
    );
}

#[test]
fn a_zero_capacity_is_refused_by_the_guards_own_constructor() {
    let mut config = config();
    config.forward_claim_capacity = Some(0);
    assert!(matches!(
        config
            .validate_structure()
            .expect_err("a zero capacity fails closed on every request"),
        InboundX402SectionError::ForwardClaim(_)
    ));
}

// -------------------------------------------------------------------------
// mTLS cross-field rules, pre-flighted through the billing crate's constructor
// -------------------------------------------------------------------------

#[test]
fn mtls_without_a_pinned_subject_is_refused_at_config_time() {
    let mut config = config();
    config.sidecar = Some(InboundX402SidecarConfig {
        credential_secret_env: SECRET_ENV.to_string(),
        rotating_out_secret_env: None,
        require_mutual_tls: true,
        pinned_client_subjects: Vec::new(),
    });
    assert!(matches!(
        config
            .validate_structure()
            .expect_err("mTLS with no pin accepts any chaining certificate"),
        InboundX402SectionError::SidecarPolicy(_)
    ));
}

#[test]
fn a_pinned_subject_without_mtls_is_refused_at_config_time() {
    let mut config = config();
    config.sidecar = Some(InboundX402SidecarConfig {
        credential_secret_env: SECRET_ENV.to_string(),
        rotating_out_secret_env: None,
        require_mutual_tls: false,
        pinned_client_subjects: vec!["CN=pay-sidecar".to_string()],
    });
    assert!(matches!(
        config
            .validate_structure()
            .expect_err("a pin that is never consulted is not protection"),
        InboundX402SectionError::SidecarPolicy(_)
    ));
}

// -------------------------------------------------------------------------
// Secrets: by reference only
// -------------------------------------------------------------------------

#[test]
fn a_secret_value_cannot_be_written_into_the_document() {
    // `deny_unknown_fields` plus the absence of any value-carrying field means an
    // operator who tries to inline a secret gets a parse error, not a config
    // that quietly works and leaks.
    let raw = r#"
[x402_inbound]
enabled = true
[x402_inbound.sidecar]
credential_secret_env = "X"
credential = "super-secret-value"
"#;
    let error = load_inbound_x402_toml(raw).expect_err("an inline secret must not parse");
    assert!(matches!(error, InboundX402TomlError::Parse { .. }));
}

#[test]
fn resolution_reads_the_referenced_variable() {
    let vars = env(&[(SECRET_ENV, SECRET)]);
    let resolved = config()
        .validate_structure()
        .expect("valid")
        .expect("enabled")
        .resolve_with(|key| vars.get(key).cloned())
        .expect("the secret is present");
    assert_eq!(resolved.endpoint.price_atomic_amount(), 10_000);
    assert!(!resolved.policy.require_mutual_tls());
    assert_eq!(
        resolved.policy.tenant().organization_id.as_deref(),
        Some("tenant-public-paid-api")
    );
    assert_eq!(resolved.claims.ttl_secs(), 300);
    assert_eq!(resolved.claims.capacity(), 1_024);
}

#[test]
fn an_unset_variable_fails_resolution_with_the_variable_name() {
    let vars = env(&[]);
    let error = config()
        .validate_structure()
        .expect("valid")
        .expect("enabled")
        .resolve_with(|key| vars.get(key).cloned())
        .expect_err("an unset secret must fail loudly");
    assert_eq!(
        error,
        InboundX402SectionError::SecretUnresolved {
            env: SECRET_ENV.to_string(),
        }
    );
}

#[test]
fn an_empty_variable_is_treated_as_unset() {
    let vars = env(&[(SECRET_ENV, "")]);
    let error = config()
        .validate_structure()
        .expect("valid")
        .expect("enabled")
        .resolve_with(|key| vars.get(key).cloned())
        .expect_err("an empty secret is not a secret");
    assert!(matches!(
        error,
        InboundX402SectionError::SecretUnresolved { .. }
    ));
}

#[test]
fn a_too_short_resolved_secret_is_refused() {
    let vars = env(&[(SECRET_ENV, "short")]);
    let error = config()
        .validate_structure()
        .expect("valid")
        .expect("enabled")
        .resolve_with(|key| vars.get(key).cloned())
        .expect_err("a guessable secret is refused at resolve time");
    assert!(matches!(error, InboundX402SectionError::Credential(_)));
}

#[test]
fn a_rotation_resolves_both_variables() {
    let mut config = config();
    config.sidecar = Some(InboundX402SidecarConfig {
        credential_secret_env: SECRET_ENV.to_string(),
        rotating_out_secret_env: Some(PREVIOUS_ENV.to_string()),
        require_mutual_tls: false,
        pinned_client_subjects: Vec::new(),
    });
    let vars = env(&[(SECRET_ENV, SECRET), (PREVIOUS_ENV, PREVIOUS_SECRET)]);
    let resolved = config
        .validate_structure()
        .expect("valid")
        .expect("enabled")
        .resolve_with(|key| vars.get(key).cloned())
        .expect("both secrets resolve");
    let _ = resolved;

    // The rotating-out variable being unset is a failure, not a silent skip:
    // a half-configured rotation would reject the very traffic it exists to keep
    // serving.
    let vars = env(&[(SECRET_ENV, SECRET)]);
    let mut config = self::config();
    config.sidecar = Some(InboundX402SidecarConfig {
        credential_secret_env: SECRET_ENV.to_string(),
        rotating_out_secret_env: Some(PREVIOUS_ENV.to_string()),
        require_mutual_tls: false,
        pinned_client_subjects: Vec::new(),
    });
    let error = config
        .validate_structure()
        .expect("valid")
        .expect("enabled")
        .resolve_with(|key| vars.get(key).cloned())
        .expect_err("a half-configured rotation must fail loudly");
    assert_eq!(
        error,
        InboundX402SectionError::SecretUnresolved {
            env: PREVIOUS_ENV.to_string(),
        }
    );
}

#[test]
fn both_secrets_reading_the_same_variable_is_refused() {
    let mut config = config();
    config.sidecar = Some(InboundX402SidecarConfig {
        credential_secret_env: SECRET_ENV.to_string(),
        rotating_out_secret_env: Some(SECRET_ENV.to_string()),
        require_mutual_tls: false,
        pinned_client_subjects: Vec::new(),
    });
    assert_eq!(
        config
            .validate_structure()
            .expect_err("a rotation between one variable and itself is a no-op"),
        InboundX402SectionError::DuplicateSecretEnv {
            env: SECRET_ENV.to_string(),
        }
    );
}

#[test]
fn an_empty_credential_env_name_is_refused() {
    let mut config = config();
    config.sidecar = Some(InboundX402SidecarConfig {
        credential_secret_env: "  ".to_string(),
        rotating_out_secret_env: None,
        require_mutual_tls: false,
        pinned_client_subjects: Vec::new(),
    });
    assert_eq!(
        config.validate_structure().expect_err("blank env name"),
        InboundX402SectionError::EmptyField {
            field: "sidecar.credential_secret_env",
        }
    );
}

// -------------------------------------------------------------------------
// The SHIPPED manifest — this is the test the previous slice was missing
// -------------------------------------------------------------------------

/// The example operator manifest under `deploy/x402-sidecar/` must parse,
/// structurally validate, and resolve. Without this, the shipped file is
/// documentation that nothing checks: the code review of the previous slice
/// wrote this test by hand, confirmed it passed, and deleted it — so the
/// manifest was correct and unguarded at the same time.
#[test]
fn the_shipped_deployment_manifest_loads_validates_and_resolves() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/x402-sidecar/ferrogate-x402-inbound.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    let validated = load_inbound_x402_toml(&raw)
        .expect("the shipped manifest must parse and validate")
        .expect("the shipped manifest enables the section");

    // The claims the manifest's own comments make, asserted rather than trusted.
    assert_eq!(
        validated.endpoint().network().caip2(),
        DEVNET,
        "the shipped sandbox manifest must default to devnet"
    );
    assert_eq!(validated.endpoint().price_atomic_amount(), 10_000);
    assert!(
        validated.forward_claim_ttl_secs() >= validated.endpoint().endpoint().max_timeout_seconds,
        "the shipped manifest must satisfy the replay floor"
    );

    let vars = env(&[("FERROGATE_X402_INBOUND_SIDECAR_SECRET", SECRET)]);
    let resolved = validated
        .resolve_with(|key| vars.get(key).cloned())
        .expect("the shipped manifest must resolve against its documented variable");
    assert_eq!(
        resolved.policy.tenant().organization_id.as_deref(),
        Some("tenant-public-paid-api")
    );
}

/// The shipped manifest and the shipped sidecar spec must quote the same price
/// and the same mint. A drift between them does not mispriced-bill — the
/// upstream re-verifies and fails closed — but it turns every paid call into a
/// refusal, which is a deployment that looks configured and serves nothing.
#[test]
fn the_shipped_manifest_and_sidecar_spec_agree_on_price_and_mint() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/x402-sidecar");
    let sidecar = std::fs::read_to_string(root.join("pay-server.yaml"))
        .expect("the sidecar spec ships alongside the manifest");
    assert!(
        sidecar.contains("\"10000\""),
        "pay-server.yaml must quote the manifest's price_atomic_amount"
    );
    assert!(
        sidecar.contains(MINT),
        "pay-server.yaml must quote the manifest's mint"
    );
    assert!(
        sidecar.contains("streaming: false"),
        "the monetized route must stay non-streaming"
    );
}
