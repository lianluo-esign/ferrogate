// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Component-compliance closure for the typed Solana x402 spend
// policy (issue #351): operator config -> Admin API effective policy -> runtime
// policy decision, proving allow / deny / approval-required against the SAME
// declaration the operator wrote. This is the #188 guard for the money path:
// an endpoint that answers 200 while the runtime evaluates something else is a
// failure, so the contract compares the declared config with what the gateway
// reports as effective before exercising a decision against it.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::{
    compliance::ComponentContract,
    constants::{ADMIN_AUTH, CLIENT_AUTH, JSON_CONTENT},
    http::http_request_addr,
};

// ---------------------------------------------------------------------------
// The operator-declared fixture (one source of truth for both config formats)
// ---------------------------------------------------------------------------

/// Devnet USDC mint. A canonical base58 mint address, never the `USDC` symbol.
pub(crate) const USDC_DEVNET_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
/// CAIP-2 id for Solana devnet. A mainnet pin would have to be explicit.
pub(crate) const CAIP2_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
/// The one allowlisted devnet merchant.
pub(crate) const MERCHANT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
/// An unrelated wallet used to prove a payee outside the allowlist denies.
const OTHER_MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";

const RESOURCE_ORIGIN: &str = "https://pay.example.com";
const RESOURCE_PATH_PREFIX: &str = "/weather";
pub(crate) const RESOURCE_URL: &str = "https://pay.example.com/weather";

pub(crate) const TENANT_ID: &str = "compliance-tenant";
const PROJECT_ID: &str = "compliance-project";
const WORKSPACE_ID: &str = "compliance-workspace";
const KEY_ID: &str = "compliance-key";
const RUN_ID: &str = "compliance-run";

/// Tenant-scope declaration: 1 credit per 1000 atomic units (round up), 1000
/// credits per payment, approval above 500 credits.
pub(crate) const TENANT_REVISION: u64 = 7;
const TENANT_MAX_CREDITS_PER_PAYMENT: u64 = 1_000;
const APPROVAL_THRESHOLD_CREDITS: u64 = 500;
/// Project-scope override at a deliberately tiny cap, so the SAME payment that
/// the tenant policy allows is denied once the project scope is named. That is
/// what proves precedence is real and not cosmetic.
const PROJECT_REVISION: u64 = 11;
const PROJECT_MAX_CREDITS_PER_PAYMENT: u64 = 2;
/// Narrower still. Each level gets its own revision and its own per-payment cap
/// so that naming one more level of the chain visibly changes BOTH which
/// declaration is in force and what it decides -- through the surface an
/// operator actually uses, not only in-process.
const WORKSPACE_REVISION: u64 = 13;
const WORKSPACE_MAX_CREDITS_PER_PAYMENT: u64 = 900;
const KEY_REVISION: u64 = 17;
const KEY_MAX_CREDITS_PER_PAYMENT: u64 = 800;
const RUN_REVISION: u64 = 19;
const RUN_MAX_CREDITS_PER_PAYMENT: u64 = 1;

/// The full declared chain, broadest first: `(scope_type, scope_id, revision,
/// max_credits_per_payment)`. One source of truth for the TOML fixture, the
/// YAML fixture, and the expected write-side projection.
const DECLARED_SCOPES: [(&str, &str, u64, u64); 5] = [
    (
        "tenant",
        TENANT_ID,
        TENANT_REVISION,
        TENANT_MAX_CREDITS_PER_PAYMENT,
    ),
    (
        "project",
        PROJECT_ID,
        PROJECT_REVISION,
        PROJECT_MAX_CREDITS_PER_PAYMENT,
    ),
    (
        "workspace",
        WORKSPACE_ID,
        WORKSPACE_REVISION,
        WORKSPACE_MAX_CREDITS_PER_PAYMENT,
    ),
    ("key", KEY_ID, KEY_REVISION, KEY_MAX_CREDITS_PER_PAYMENT),
    ("run", RUN_ID, RUN_REVISION, RUN_MAX_CREDITS_PER_PAYMENT),
];

const CONVERSION_NUMERATOR: u64 = 1;
const CONVERSION_DENOMINATOR: u64 = 1_000;
const CONVERSION_ROUNDING: &str = "up";
const CONVERSION_VERSION: &str = "usdc-devnet-v1";

const MAX_CREDITS_PER_RUN: u64 = 5_000;
const MAX_CREDITS_PER_WINDOW: u64 = 10_000;
const WINDOW_SECONDS: u64 = 3_600;
const MAX_ATOMIC_PER_PAYMENT: u64 = 2_000_000;
const MIN_ATOMIC_PER_PAYMENT: u64 = 10;

/// The body of the POST-bound case, and its SHA-256. Pins that an authorized
/// POST is a materially different intent from the authorized GET carrying the
/// same challenge. The hash is computed from the body so the two cannot drift.
const POST_BODY: &[u8] = br#"{"query":"weather"}"#;

fn empty_body_sha256_hex() -> String {
    sha256_hex(&[])
}

fn post_body_sha256_hex() -> String {
    sha256_hex(POST_BODY)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The `[[x402_spend_policies]]` section for a TOML gateway config.
///
/// Emitted from the same constants as [`x402_spend_policies_yaml`] and as the
/// expected write-side projection, so the operator input, the two config
/// formats, and the assertion can never drift apart.
///
/// Must be appended at the END of a TOML document: an array-of-tables section
/// swallows every following top-level key.
pub(crate) fn x402_spend_policies_toml() -> String {
    DECLARED_SCOPES
        .iter()
        .map(|(scope_type, scope_id, revision, max_credits)| {
            format!(
                r#"
[[x402_spend_policies]]
scope_type = "{scope_type}"
scope_id = "{scope_id}"

[x402_spend_policies.policy]
enabled = true
revision = {revision}
allowed_networks = ["{CAIP2_DEVNET}"]
allowed_recipients = ["{MERCHANT}"]
allow_insecure_local_resources = false

[[x402_spend_policies.policy.allowed_assets]]
network = "{CAIP2_DEVNET}"
mint = "{USDC_DEVNET_MINT}"

[[x402_spend_policies.policy.allowed_resources]]
origin = "{RESOURCE_ORIGIN}"
path_prefix = "{RESOURCE_PATH_PREFIX}"

[x402_spend_policies.policy.caps]
max_credits_per_payment = {max_credits}
max_credits_per_run = {MAX_CREDITS_PER_RUN}
max_credits_per_window = {MAX_CREDITS_PER_WINDOW}
window_seconds = {WINDOW_SECONDS}
max_atomic_per_payment = {MAX_ATOMIC_PER_PAYMENT}
min_atomic_per_payment = {MIN_ATOMIC_PER_PAYMENT}

[x402_spend_policies.policy.conversion]
numerator = {CONVERSION_NUMERATOR}
denominator = {CONVERSION_DENOMINATOR}
rounding = "{CONVERSION_ROUNDING}"
version = "{CONVERSION_VERSION}"

[x402_spend_policies.policy.approval]
threshold_credits = {APPROVAL_THRESHOLD_CREDITS}
"#
            )
        })
        .collect()
}

/// The same declarations for a YAML gateway config (the Supabase-live
/// compliance run authors YAML, the local run authors TOML; both must produce
/// the identical effective policy).
pub(crate) fn x402_spend_policies_yaml() -> String {
    let entries: String = DECLARED_SCOPES
        .iter()
        .map(|(scope_type, scope_id, revision, max_credits)| {
            format!(
                r#"  - scope_type: "{scope_type}"
    scope_id: "{scope_id}"
    policy:
      enabled: true
      revision: {revision}
      allowed_networks: ["{CAIP2_DEVNET}"]
      allowed_recipients: ["{MERCHANT}"]
      allow_insecure_local_resources: false
      allowed_assets:
        - network: "{CAIP2_DEVNET}"
          mint: "{USDC_DEVNET_MINT}"
      allowed_resources:
        - origin: "{RESOURCE_ORIGIN}"
          path_prefix: "{RESOURCE_PATH_PREFIX}"
      caps:
        max_credits_per_payment: {max_credits}
        max_credits_per_run: {MAX_CREDITS_PER_RUN}
        max_credits_per_window: {MAX_CREDITS_PER_WINDOW}
        window_seconds: {WINDOW_SECONDS}
        max_atomic_per_payment: {MAX_ATOMIC_PER_PAYMENT}
        min_atomic_per_payment: {MIN_ATOMIC_PER_PAYMENT}
      conversion:
        numerator: {CONVERSION_NUMERATOR}
        denominator: {CONVERSION_DENOMINATOR}
        rounding: "{CONVERSION_ROUNDING}"
        version: "{CONVERSION_VERSION}"
      approval:
        threshold_credits: {APPROVAL_THRESHOLD_CREDITS}
"#
            )
        })
        .collect();
    format!("x402_spend_policies:\n{entries}")
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/// Which scope chain a case is evaluated at, and what the policy in force must
/// decide for the case's challenge.
#[derive(Debug, Clone, Copy)]
pub(crate) struct X402Case {
    name: &'static str,
    /// How much of the tenancy chain the case names. Each additional level must
    /// pull in that level's declaration and its own per-payment cap.
    chain: X402ChainDepth,
    atomic_amount: u64,
    recipient: &'static str,
    /// The resource the merchant challenge claims to unlock. Differs from
    /// `authorized_resource` only in the payment-redirect case.
    challenge_resource: &'static str,
    authorized_resource: &'static str,
    run_spent_credits: u64,
    /// The already-authorized request the payment is bound to.
    authorized_method: &'static str,
    /// True when the case's authorized request carries [`POST_BODY`]; its hash
    /// is computed rather than transcribed.
    authorized_has_body: bool,
    expected_decision: &'static str,
    expected_reason_code: &'static str,
    /// Expected internal credits for the challenge amount, computed by the
    /// gateway's own conversion rule. `None` for cases denied before pricing.
    expected_credits: Option<u64>,
    expected_revision: u64,
}

/// How much of the `tenant -> project -> workspace -> key -> run` chain a case
/// names. The narrowest named level's declaration must win.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum X402ChainDepth {
    Tenant,
    Project,
    Workspace,
    Key,
    Run,
}

impl X402ChainDepth {
    /// The declared entry this depth must resolve to.
    fn declared(self) -> (&'static str, &'static str, u64, u64) {
        DECLARED_SCOPES[self as usize]
    }

    /// The `?tenant_id=…&project_id=…` suffix for the effective-policy read.
    fn query(self) -> String {
        let mut query = format!("tenant_id={TENANT_ID}");
        for (name, value) in self.narrower_levels() {
            query.push_str(&format!("&{name}={value}"));
        }
        query
    }

    /// The `scope` object for the evaluate call. Must name exactly the same
    /// levels as [`Self::query`] or the read and the decision are not comparable.
    fn scope_body(self) -> Value {
        let mut scope = json!({ "tenant_id": TENANT_ID });
        for (name, value) in self.narrower_levels() {
            scope[name] = json!(value);
        }
        scope
    }

    fn narrower_levels(self) -> Vec<(&'static str, &'static str)> {
        [
            ("project_id", PROJECT_ID),
            ("workspace_id", WORKSPACE_ID),
            ("key_id", KEY_ID),
            ("run_id", RUN_ID),
        ]
        .into_iter()
        .take(self as usize)
        .collect()
    }
}

/// The projection compared between "what the operator declared" and "what the
/// gateway reports as effective". Every field is one an operator would act on;
/// a drift in any of them is the #188 failure mode.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectivePolicyProjection {
    resolved_scope_type: String,
    resolved_scope_id: String,
    revision: u64,
    enabled: bool,
    networks: Vec<String>,
    assets: Vec<(String, String)>,
    recipients: Vec<String>,
    resources: Vec<(String, String)>,
    max_credits_per_payment: Option<u64>,
    max_credits_per_run: Option<u64>,
    max_credits_per_window: Option<u64>,
    max_atomic_per_payment: Option<u64>,
    min_atomic_per_payment: Option<u64>,
    /// Informational, but part of what the operator wrote: if the loader
    /// dropped it, the caps an operator reads back would describe a different
    /// window than the one they configured.
    window_seconds: Option<u64>,
    approval_threshold_credits: Option<u64>,
    conversion: (u64, u64, String, String),
    /// The ONE security-relevant boolean in the policy: the http-resource
    /// escape hatch. Outside the write/read closure it could be flipped or
    /// dropped between what the operator wrote and what the gateway holds and
    /// this contract would never see it.
    allow_insecure_local_resources: bool,
}

/// The runtime decision, as read off the diagnostics surface.
#[derive(Debug)]
pub(crate) struct X402RuntimeDecision {
    decision: String,
    reason_code: String,
    policy_revision: u64,
    atomic_amount: u64,
    computed_credits: Option<u64>,
    challenge_hash_hex: String,
    matched_resource: Option<(String, String)>,
    conversion_version: String,
    approval_threshold_credits: Option<u64>,
    /// The already-authorized request the decision is bound to.
    http_method: String,
    request_body_sha256_hex: String,
    intent_hash_hex: String,
    decision_hash_hex: String,
    /// Whether the caller's ledger figures were used, echoed back so an omitted
    /// `spent` cannot be mistaken for "the run has spent nothing".
    spent_supplied: bool,
}

pub(crate) struct X402SpendPolicyContract;

impl X402SpendPolicyContract {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl ComponentContract for X402SpendPolicyContract {
    type Case = X402Case;
    type Written = EffectivePolicyProjection;
    type Runtime = X402RuntimeDecision;

    fn name(&self) -> &'static str {
        "x402 spend policy"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![
            // 2500 atomic / 1000 = 3 credits: inside every tenant cap and below
            // the approval threshold.
            X402Case {
                name: "allow",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "allow",
                expected_reason_code: "x402_allowed",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // 600_000 atomic = 600 credits: above the 500-credit approval
            // threshold, still under the 1000-credit hard cap.
            X402Case {
                name: "approval_required",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 600_000,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "approval_required",
                expected_reason_code: "x402_approval_required",
                expected_credits: Some(600),
                expected_revision: TENANT_REVISION,
            },
            // 1_500_000 atomic = 1500 credits: over the per-payment cap.
            X402Case {
                name: "deny_over_cap",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 1_500_000,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "deny",
                expected_reason_code: "x402_over_per_payment_cap",
                expected_credits: Some(1_500),
                expected_revision: TENANT_REVISION,
            },
            // Same payment the tenant policy allows, denied once the project
            // override (2-credit cap) is the policy in force: precedence is
            // what the runtime actually reads, not just what the list shows.
            X402Case {
                name: "project_override_denies",
                chain: X402ChainDepth::Project,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "deny",
                expected_reason_code: "x402_over_per_payment_cap",
                expected_credits: Some(3),
                expected_revision: PROJECT_REVISION,
            },
            // A challenge cannot redirect payment to a resource the gateway
            // never authorized egress to.
            X402Case {
                name: "deny_payment_redirect",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: "https://evil.example.com/drain",
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "deny",
                expected_reason_code: "x402_resource_mismatch",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // A payee outside the allowlist denies, whatever the amount.
            X402Case {
                name: "deny_unknown_payee",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 2_500,
                recipient: OTHER_MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "deny",
                expected_reason_code: "x402_recipient_not_allowed",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // Committed run spend is accounted against the run cap: 4999 + 3
            // exceeds 5000.
            X402Case {
                name: "deny_over_run_cap",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 4_999,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "deny",
                expected_reason_code: "x402_over_run_cap",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // Each narrower level in turn: naming it must swap in that level's
            // declaration (revision) AND its cap, through the surface.
            X402Case {
                name: "workspace_override_is_in_force",
                chain: X402ChainDepth::Workspace,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "allow",
                expected_reason_code: "x402_allowed",
                expected_credits: Some(3),
                expected_revision: WORKSPACE_REVISION,
            },
            X402Case {
                name: "key_override_is_in_force",
                chain: X402ChainDepth::Key,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "allow",
                expected_reason_code: "x402_allowed",
                expected_credits: Some(3),
                expected_revision: KEY_REVISION,
            },
            // The narrowest scope wins outright: the same 3-credit payment that
            // every broader level allows is denied by the run's 1-credit cap.
            X402Case {
                name: "run_override_denies_what_every_broader_scope_allows",
                chain: X402ChainDepth::Run,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "GET",
                authorized_has_body: false,
                expected_decision: "deny",
                expected_reason_code: "x402_over_per_payment_cap",
                expected_credits: Some(3),
                expected_revision: RUN_REVISION,
            },
            // A POST with a body is a DIFFERENT authorized request than the GET
            // above, and the decision must say so rather than being byte-identical.
            X402Case {
                name: "allow_bound_to_a_post_body",
                chain: X402ChainDepth::Tenant,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                authorized_method: "POST",
                authorized_has_body: true,
                expected_decision: "allow",
                expected_reason_code: "x402_allowed",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
        ]
    }

    /// The operator's declared input. The harness authored the gateway config
    /// itself (see [`x402_spend_policies_toml`]/[`x402_spend_policies_yaml`]),
    /// so this is literally what was written, expressed from the same constants
    /// that generated the config text.
    fn write(&self, _gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        let (scope_type, scope_id, revision, max_credits_per_payment) = case.chain.declared();
        Ok(EffectivePolicyProjection {
            resolved_scope_type: scope_type.to_string(),
            resolved_scope_id: scope_id.to_string(),
            revision,
            enabled: true,
            networks: vec![CAIP2_DEVNET.to_string()],
            assets: vec![(CAIP2_DEVNET.to_string(), USDC_DEVNET_MINT.to_string())],
            recipients: vec![MERCHANT.to_string()],
            resources: vec![(
                RESOURCE_ORIGIN.to_string(),
                RESOURCE_PATH_PREFIX.to_string(),
            )],
            max_credits_per_payment: Some(max_credits_per_payment),
            max_credits_per_run: Some(MAX_CREDITS_PER_RUN),
            max_credits_per_window: Some(MAX_CREDITS_PER_WINDOW),
            max_atomic_per_payment: Some(MAX_ATOMIC_PER_PAYMENT),
            min_atomic_per_payment: Some(MIN_ATOMIC_PER_PAYMENT),
            window_seconds: Some(WINDOW_SECONDS),
            approval_threshold_credits: Some(APPROVAL_THRESHOLD_CREDITS),
            conversion: (
                CONVERSION_NUMERATOR,
                CONVERSION_DENOMINATOR,
                CONVERSION_ROUNDING.to_string(),
                CONVERSION_VERSION.to_string(),
            ),
            allow_insecure_local_resources: false,
        })
    }

    /// What the gateway reports as the effective policy for the case's scope
    /// chain. Equality with `write` is the write-path == read-path proof.
    fn read(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        let body = expect_json(
            gateway_addr,
            "GET",
            &effective_policy_path(case),
            &[ADMIN_AUTH],
            "",
            200,
        )?;
        assert_no_secret_fields(&body, "effective policy")?;

        if body["declared"] != Value::Bool(true) {
            bail!("effective policy is not backed by an operator declaration: {body}");
        }
        let resolved = &body["resolved_scope"];
        let policy = &body["policy"];
        let caps = &policy["caps"];
        let conversion = &policy["conversion"];
        Ok(EffectivePolicyProjection {
            resolved_scope_type: string_field(resolved, "scope_type")?,
            resolved_scope_id: string_field(resolved, "scope_id")?,
            revision: u64_field(&body["policy_revision"], "policy_revision")?,
            enabled: policy["enabled"]
                .as_bool()
                .context("policy.enabled must be a boolean")?,
            networks: string_array(&policy["allowed_networks"], "allowed_networks")?,
            assets: pair_array(&policy["allowed_assets"], "network", "mint")?,
            recipients: string_array(&policy["allowed_recipients"], "allowed_recipients")?,
            resources: pair_array(&policy["allowed_resources"], "origin", "path_prefix")?,
            max_credits_per_payment: optional_u64(&caps["max_credits_per_payment"])?,
            max_credits_per_run: optional_u64(&caps["max_credits_per_run"])?,
            max_credits_per_window: optional_u64(&caps["max_credits_per_window"])?,
            max_atomic_per_payment: optional_u64(&caps["max_atomic_per_payment"])?,
            min_atomic_per_payment: optional_u64(&caps["min_atomic_per_payment"])?,
            window_seconds: optional_u64(&caps["window_seconds"])?,
            approval_threshold_credits: optional_u64(&policy["approval"]["threshold_credits"])?,
            conversion: (
                u64_field(&conversion["numerator"], "conversion.numerator")?,
                u64_field(&conversion["denominator"], "conversion.denominator")?,
                string_field(conversion, "rounding")?,
                string_field(conversion, "version")?,
            ),
            allow_insecure_local_resources: policy["allow_insecure_local_resources"]
                .as_bool()
                .context("policy.allow_insecure_local_resources must be a boolean")?,
        })
    }

    /// Drive the runtime decision for a concrete, untrusted merchant challenge
    /// through the same policy function the payment path uses.
    fn exercise(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Runtime> {
        let request = json!({
            "scope": scope_body(case),
            "payment_required": challenge_header(
                case.atomic_amount,
                case.recipient,
                case.challenge_resource,
            ),
            "authorized_resource_url": case.authorized_resource,
            "authorized_method": case.authorized_method,
            "authorized_request_body_sha256_hex": case
                .authorized_has_body
                .then(post_body_sha256_hex),
            "spent": {
                "run_spent_credits": case.run_spent_credits,
                "window_spent_credits": 0
            }
        })
        .to_string();
        let body = expect_json(
            gateway_addr,
            "POST",
            "/admin/v1/x402-spend-policies/evaluate",
            &[ADMIN_AUTH, JSON_CONTENT],
            &request,
            200,
        )?;
        assert_no_secret_fields(&body, "policy evaluation")?;

        let decision = &body["decision"];
        Ok(X402RuntimeDecision {
            decision: string_field(decision, "decision")?,
            reason_code: string_field(decision, "reason_code")?,
            policy_revision: u64_field(&decision["policy_revision"], "policy_revision")?,
            atomic_amount: u64_field(&decision["atomic_amount"], "atomic_amount")?,
            computed_credits: optional_u64(&decision["computed_credits"])?,
            challenge_hash_hex: string_field(decision, "challenge_hash_hex")?,
            matched_resource: match &decision["matched_resource"] {
                Value::Null => None,
                rule => Some((
                    string_field(rule, "origin")?,
                    string_field(rule, "path_prefix")?,
                )),
            },
            conversion_version: string_field(&decision["conversion"], "version")?,
            approval_threshold_credits: optional_u64(&decision["approval_threshold_credits"])?,
            http_method: string_field(decision, "http_method")?,
            request_body_sha256_hex: string_field(decision, "request_body_sha256_hex")?,
            intent_hash_hex: string_field(decision, "intent_hash_hex")?,
            decision_hash_hex: string_field(decision, "decision_hash_hex")?,
            spent_supplied: body["spent"]["supplied"]
                .as_bool()
                .context("spent.supplied must be a boolean")?,
        })
    }

    fn verify(
        &self,
        case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if runtime.decision != case.expected_decision {
            bail!(
                "case {}: expected decision {}, got {} ({})",
                case.name,
                case.expected_decision,
                runtime.decision,
                runtime.reason_code
            );
        }
        if runtime.reason_code != case.expected_reason_code {
            bail!(
                "case {}: expected reason code {}, got {}",
                case.name,
                case.expected_reason_code,
                runtime.reason_code
            );
        }
        // The decision must be attributable to the exact declaration the
        // effective-policy read reported -- same revision, same conversion rule.
        if runtime.policy_revision != case.expected_revision
            || runtime.policy_revision != written.revision
        {
            bail!(
                "case {}: decision revision {} does not match the effective policy revision {} (expected {})",
                case.name,
                runtime.policy_revision,
                written.revision,
                case.expected_revision
            );
        }
        if runtime.conversion_version != written.conversion.3 {
            bail!(
                "case {}: decision used conversion version {}, effective policy declares {}",
                case.name,
                runtime.conversion_version,
                written.conversion.3
            );
        }
        // Original atomic units survive losslessly, and credits are the
        // gateway's own integer conversion of them.
        if runtime.atomic_amount != case.atomic_amount {
            bail!(
                "case {}: decision reports atomic amount {}, challenge carried {}",
                case.name,
                runtime.atomic_amount,
                case.atomic_amount
            );
        }
        if runtime.computed_credits != case.expected_credits {
            bail!(
                "case {}: expected {:?} internal credits, got {:?}",
                case.name,
                case.expected_credits,
                runtime.computed_credits
            );
        }
        // The challenge hash is the audit/idempotency key: 32 bytes of hex.
        if runtime.challenge_hash_hex.len() != 64
            || !runtime
                .challenge_hash_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!(
                "case {}: challenge hash {:?} is not 32 bytes of hex",
                case.name,
                runtime.challenge_hash_hex
            );
        }
        match case.expected_decision {
            "allow" | "approval_required" => {
                let expected = Some((
                    written.resources[0].0.clone(),
                    written.resources[0].1.clone(),
                ));
                if runtime.matched_resource != expected {
                    bail!(
                        "case {}: expected matched resource rule {:?}, got {:?}",
                        case.name,
                        expected,
                        runtime.matched_resource
                    );
                }
            }
            _ => {
                if runtime.matched_resource.is_some() {
                    bail!(
                        "case {}: a denied payment must not report a matched resource rule ({:?})",
                        case.name,
                        runtime.matched_resource
                    );
                }
            }
        }
        // The decision must name the exact request it authorized: method, body
        // hash, and a 32-byte seal over both. Without this, an authorization for
        // a GET and one for a POST of a different body to the same URL are
        // indistinguishable evidence.
        if runtime.http_method != case.authorized_method {
            bail!(
                "case {}: decision is bound to method {}, the authorized request was {}",
                case.name,
                runtime.http_method,
                case.authorized_method
            );
        }
        let expected_body_hash = if case.authorized_has_body {
            post_body_sha256_hex()
        } else {
            empty_body_sha256_hex()
        };
        if runtime.request_body_sha256_hex != expected_body_hash {
            bail!(
                "case {}: decision is bound to body hash {}, the authorized request hashed to {}",
                case.name,
                runtime.request_body_sha256_hex,
                expected_body_hash
            );
        }
        for (what, value) in [
            ("intent_hash_hex", &runtime.intent_hash_hex),
            ("decision_hash_hex", &runtime.decision_hash_hex),
        ] {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!(
                    "case {}: {what} {value:?} is not 32 bytes of hex",
                    case.name
                );
            }
        }
        // Every case supplies `spent` explicitly, so the surface must say so.
        if !runtime.spent_supplied {
            bail!(
                "case {}: the response must report that the ledger figures were supplied",
                case.name
            );
        }
        if case.expected_decision == "approval_required"
            && runtime.approval_threshold_credits != written.approval_threshold_credits
        {
            bail!(
                "case {}: approval decision reports threshold {:?}, policy declares {:?}",
                case.name,
                runtime.approval_threshold_credits,
                written.approval_threshold_credits
            );
        }
        Ok(())
    }

    /// Declarations are operator config, immutable at runtime: there is nothing
    /// this contract created to tear down.
    fn cleanup(&self, _gateway_addr: &str, _case: &Self::Case) -> Result<()> {
        Ok(())
    }
}

/// Checks that hold for the surface as a whole rather than per case: the
/// declarations are listed, an unconfigured tenant fails closed, and a garbage
/// challenge is rejected instead of being decided.
pub(crate) fn assert_x402_spend_policy_surface(gateway_addr: &str) -> Result<()> {
    let listed = expect_json(
        gateway_addr,
        "GET",
        "/admin/v1/x402-spend-policies",
        &[ADMIN_AUTH],
        "",
        200,
    )?;
    assert_no_secret_fields(&listed, "policy list")?;
    let declarations = listed["data"]
        .as_array()
        .context("x402 spend policy list must carry a data array")?;
    let scopes: Vec<(String, String)> = declarations
        .iter()
        .map(|entry| {
            Ok((
                string_field(entry, "scope_type")?,
                string_field(entry, "scope_id")?,
            ))
        })
        .collect::<Result<_>>()?;
    for (scope_type, scope_id, _, _) in DECLARED_SCOPES {
        let expected = (scope_type.to_string(), scope_id.to_string());
        if !scopes.contains(&expected) {
            bail!("declared x402 policy {expected:?} is missing from the admin list: {listed}");
        }
    }

    // Tenancy: a tenant-scoped `admin.read` caller (org_demo) must not be able
    // to read another tenant's spend caps, payee allowlist or policy revision
    // through this surface, and must not be able to name a run scope at all.
    // Every declaration above belongs to `compliance-tenant`, so org_demo sees
    // none of them.
    let scoped_list = expect_json(
        gateway_addr,
        "GET",
        "/admin/v1/x402-spend-policies",
        &[CLIENT_AUTH],
        "",
        200,
    )?;
    let scoped_scopes: Vec<String> = scoped_list["data"]
        .as_array()
        .context("x402 spend policy list must carry a data array")?
        .iter()
        .map(|entry| string_field(entry, "scope_id"))
        .collect::<Result<_>>()?;
    for (_, scope_id, _, _) in DECLARED_SCOPES {
        if scoped_scopes.iter().any(|seen| seen == scope_id) {
            bail!(
                "a tenant-scoped caller must not see another tenant's x402 declaration \
                 {scope_id}: {scoped_list}"
            );
        }
    }
    for (path, expected_code) in [
        (
            format!("/admin/v1/x402-spend-policies/effective?tenant_id={TENANT_ID}"),
            "tenant_scope_denied",
        ),
        (
            "/admin/v1/x402-spend-policies/effective?tenant_id=org_demo&run_id=some-run"
                .to_string(),
            "run_scope_requires_platform_operator",
        ),
    ] {
        let refused = expect_json(gateway_addr, "GET", &path, &[CLIENT_AUTH], "", 403)?;
        if refused["error"]["code"] != expected_code {
            bail!("GET {path} must be refused as {expected_code}: {refused}");
        }
    }

    // The SAME refusals on the decision side. `POST …/evaluate` returns the
    // policy revision, the resolved scope, the matched rule and the full
    // decision evidence for whatever scope it is handed, so a tenancy check on
    // the read side alone would leave another tenant's caps readable by
    // sweeping `atomic_amount` against this endpoint.
    for (scope, expected_code) in [
        (json!({"tenant_id": TENANT_ID}), "tenant_scope_denied"),
        (
            json!({"tenant_id": "org_demo", "run_id": "some-run"}),
            "run_scope_requires_platform_operator",
        ),
    ] {
        let refused = expect_json(
            gateway_addr,
            "POST",
            "/admin/v1/x402-spend-policies/evaluate",
            &[CLIENT_AUTH, JSON_CONTENT],
            &json!({
                "scope": scope,
                "payment_required": challenge_header(2_500, MERCHANT, RESOURCE_URL),
                "authorized_resource_url": RESOURCE_URL
            })
            .to_string(),
            403,
        )?;
        if refused["error"]["code"] != expected_code {
            bail!("POST evaluate at {scope} must be refused as {expected_code}: {refused}");
        }
        if refused.get("decision").is_some() {
            bail!("a refused evaluation must not carry decision evidence: {refused}");
        }
    }

    // An unconfigured tenant is not a 404 and not an absence of limits: it is
    // the disabled deny-all default at revision 0.
    let unconfigured = expect_json(
        gateway_addr,
        "GET",
        "/admin/v1/x402-spend-policies/effective?tenant_id=tenant-with-no-x402-policy",
        &[ADMIN_AUTH],
        "",
        200,
    )?;
    if unconfigured["declared"] != Value::Bool(false)
        || unconfigured["policy"]["enabled"] != Value::Bool(false)
        || unconfigured["policy_revision"] != 0
    {
        bail!("an unconfigured tenant must report the disabled deny-all default: {unconfigured}");
    }
    let denied = expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/x402-spend-policies/evaluate",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "scope": {"tenant_id": "tenant-with-no-x402-policy"},
            "payment_required": challenge_header(2_500, MERCHANT, RESOURCE_URL),
            "authorized_resource_url": RESOURCE_URL
        })
        .to_string(),
        200,
    )?;
    if denied["decision"]["decision"] != "deny"
        || denied["decision"]["reason_code"] != "x402_disabled"
    {
        bail!("an unconfigured tenant must deny every payment: {denied}");
    }

    // An unparseable merchant challenge is a client error, never a decision.
    let rejected = expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/x402-spend-policies/evaluate",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "scope": {"tenant_id": TENANT_ID},
            "payment_required": "not-a-valid-challenge",
            "authorized_resource_url": RESOURCE_URL
        })
        .to_string(),
        400,
    )?;
    if rejected["error"]["code"] != "invalid_x402_challenge" {
        bail!("a malformed challenge must be rejected as invalid_x402_challenge: {rejected}");
    }

    // The diagnostics surface is read-only: it never accepts a mutation.
    for (method, path) in [
        ("POST", "/admin/v1/x402-spend-policies"),
        ("PUT", "/admin/v1/x402-spend-policies/effective"),
        ("GET", "/admin/v1/x402-spend-policies/evaluate"),
    ] {
        let response = http_request_addr(gateway_addr, method, path, &[ADMIN_AUTH], "{}")?;
        if response.status != 405 {
            bail!(
                "{method} {path} must be rejected as method_not_allowed, got {}: {}",
                response.status,
                response.raw
            );
        }
    }

    // Unauthenticated access is refused on every operation.
    for (method, path) in [
        ("GET", "/admin/v1/x402-spend-policies"),
        (
            "GET",
            "/admin/v1/x402-spend-policies/effective?tenant_id=compliance-tenant",
        ),
        ("POST", "/admin/v1/x402-spend-policies/evaluate"),
    ] {
        let response = http_request_addr(gateway_addr, method, path, &[JSON_CONTENT], "{}")?;
        if response.status != 401 {
            bail!(
                "{method} {path} must require authentication, got {}: {}",
                response.status,
                response.raw
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn effective_policy_path(case: &X402Case) -> String {
    format!(
        "/admin/v1/x402-spend-policies/effective?{}",
        case.chain.query()
    )
}

fn scope_body(case: &X402Case) -> Value {
    case.chain.scope_body()
}

/// A base64 `PAYMENT-REQUIRED` header exactly as an x402 merchant would send it.
pub(crate) fn challenge_header(atomic_amount: u64, recipient: &str, resource: &str) -> String {
    let challenge = json!({
        "x402Version": 2,
        "resource": {"url": resource, "mimeType": "application/json"},
        "accepts": [{
            "scheme": "exact",
            "network": CAIP2_DEVNET,
            "amount": atomic_amount.to_string(),
            "asset": USDC_DEVNET_MINT,
            "payTo": recipient,
            "maxTimeoutSeconds": 120,
            "extra": {"feePayer": FEE_PAYER}
        }]
    });
    base64::engine::general_purpose::STANDARD.encode(challenge.to_string())
}

/// The diagnostics surface must expose decisions and revisions, never signer or
/// secret material. Scans every key in the response, at any depth.
fn assert_no_secret_fields(value: &Value, what: &str) -> Result<()> {
    let mut keys = Vec::new();
    collect_keys(value, &mut keys);
    for key in keys {
        let lowered = key.to_ascii_lowercase();
        for forbidden in ferrogate_core::SECRET_SHAPED_KEY_FRAGMENTS {
            if lowered.contains(forbidden) {
                bail!("{what} response exposes a {forbidden}-shaped field: {key}");
            }
        }
    }
    Ok(())
}

fn collect_keys(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                into.push(key.clone());
                collect_keys(nested, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_keys(item, into)),
        _ => {}
    }
}

fn string_field(value: &Value, field: &str) -> Result<String> {
    value[field]
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("{field} must be a string, got {}", value[field]))
}

fn u64_field(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .with_context(|| format!("{field} must be a non-negative integer, got {value}"))
}

fn optional_u64(value: &Value) -> Result<Option<u64>> {
    match value {
        Value::Null => Ok(None),
        other => other
            .as_u64()
            .map(Some)
            .with_context(|| format!("expected a non-negative integer or null, got {other}")),
    }
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .as_array()
        .with_context(|| format!("{field} must be an array, got {value}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("{field} entries must be strings, got {entry}"))
        })
        .collect()
}

fn pair_array(value: &Value, first: &str, second: &str) -> Result<Vec<(String, String)>> {
    value
        .as_array()
        .with_context(|| format!("expected an array, got {value}"))?
        .iter()
        .map(|entry| Ok((string_field(entry, first)?, string_field(entry, second)?)))
        .collect()
}

fn expect_json(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
) -> Result<Value> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    serde_json::from_str(&response.body)
        .with_context(|| format!("{method} {path} returned invalid JSON: {}", response.body))
}
