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
    constants::{ADMIN_AUTH, JSON_CONTENT},
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

const TENANT_ID: &str = "compliance-tenant";
const PROJECT_ID: &str = "compliance-project";

/// Tenant-scope declaration: 1 credit per 1000 atomic units (round up), 1000
/// credits per payment, approval above 500 credits.
const TENANT_REVISION: u64 = 7;
const TENANT_MAX_CREDITS_PER_PAYMENT: u64 = 1_000;
const APPROVAL_THRESHOLD_CREDITS: u64 = 500;
/// Project-scope override at a deliberately tiny cap, so the SAME payment that
/// the tenant policy allows is denied once the project scope is named. That is
/// what proves precedence is real and not cosmetic.
const PROJECT_REVISION: u64 = 11;
const PROJECT_MAX_CREDITS_PER_PAYMENT: u64 = 2;

const CONVERSION_NUMERATOR: u64 = 1;
const CONVERSION_DENOMINATOR: u64 = 1_000;
const CONVERSION_ROUNDING: &str = "up";
const CONVERSION_VERSION: &str = "usdc-devnet-v1";

const MAX_CREDITS_PER_RUN: u64 = 5_000;
const MAX_CREDITS_PER_WINDOW: u64 = 10_000;
const WINDOW_SECONDS: u64 = 3_600;
const MAX_ATOMIC_PER_PAYMENT: u64 = 2_000_000;
const MIN_ATOMIC_PER_PAYMENT: u64 = 10;

/// The `[[x402_spend_policies]]` section for a TOML gateway config.
///
/// Emitted from the same constants as [`x402_spend_policies_yaml`] and as the
/// expected write-side projection, so the operator input, the two config
/// formats, and the assertion can never drift apart.
///
/// Must be appended at the END of a TOML document: an array-of-tables section
/// swallows every following top-level key.
pub(crate) fn x402_spend_policies_toml() -> String {
    format!(
        r#"
[[x402_spend_policies]]
scope_type = "tenant"
scope_id = "{TENANT_ID}"

[x402_spend_policies.policy]
enabled = true
revision = {TENANT_REVISION}
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
max_credits_per_payment = {TENANT_MAX_CREDITS_PER_PAYMENT}
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

[[x402_spend_policies]]
scope_type = "project"
scope_id = "{PROJECT_ID}"

[x402_spend_policies.policy]
enabled = true
revision = {PROJECT_REVISION}
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
max_credits_per_payment = {PROJECT_MAX_CREDITS_PER_PAYMENT}
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
}

/// The same declarations for a YAML gateway config (the Supabase-live
/// compliance run authors YAML, the local run authors TOML; both must produce
/// the identical effective policy).
pub(crate) fn x402_spend_policies_yaml() -> String {
    format!(
        r#"x402_spend_policies:
  - scope_type: "tenant"
    scope_id: "{TENANT_ID}"
    policy:
      enabled: true
      revision: {TENANT_REVISION}
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
        max_credits_per_payment: {TENANT_MAX_CREDITS_PER_PAYMENT}
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
  - scope_type: "project"
    scope_id: "{PROJECT_ID}"
    policy:
      enabled: true
      revision: {PROJECT_REVISION}
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
        max_credits_per_payment: {PROJECT_MAX_CREDITS_PER_PAYMENT}
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
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/// Which scope chain a case is evaluated at, and what the policy in force must
/// decide for the case's challenge.
#[derive(Debug, Clone, Copy)]
pub(crate) struct X402Case {
    name: &'static str,
    /// `None` = tenant scope only; `Some` = name the project too, which must
    /// pull in the tighter project declaration.
    project: Option<&'static str>,
    atomic_amount: u64,
    recipient: &'static str,
    /// The resource the merchant challenge claims to unlock. Differs from
    /// `authorized_resource` only in the payment-redirect case.
    challenge_resource: &'static str,
    authorized_resource: &'static str,
    run_spent_credits: u64,
    expected_decision: &'static str,
    expected_reason_code: &'static str,
    /// Expected internal credits for the challenge amount, computed by the
    /// gateway's own conversion rule. `None` for cases denied before pricing.
    expected_credits: Option<u64>,
    expected_revision: u64,
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
    approval_threshold_credits: Option<u64>,
    conversion: (u64, u64, String, String),
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
                project: None,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                expected_decision: "allow",
                expected_reason_code: "x402_allowed",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // 600_000 atomic = 600 credits: above the 500-credit approval
            // threshold, still under the 1000-credit hard cap.
            X402Case {
                name: "approval_required",
                project: None,
                atomic_amount: 600_000,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                expected_decision: "approval_required",
                expected_reason_code: "x402_approval_required",
                expected_credits: Some(600),
                expected_revision: TENANT_REVISION,
            },
            // 1_500_000 atomic = 1500 credits: over the per-payment cap.
            X402Case {
                name: "deny_over_cap",
                project: None,
                atomic_amount: 1_500_000,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
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
                project: Some(PROJECT_ID),
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                expected_decision: "deny",
                expected_reason_code: "x402_over_per_payment_cap",
                expected_credits: Some(3),
                expected_revision: PROJECT_REVISION,
            },
            // A challenge cannot redirect payment to a resource the gateway
            // never authorized egress to.
            X402Case {
                name: "deny_payment_redirect",
                project: None,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: "https://evil.example.com/drain",
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                expected_decision: "deny",
                expected_reason_code: "x402_resource_mismatch",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // A payee outside the allowlist denies, whatever the amount.
            X402Case {
                name: "deny_unknown_payee",
                project: None,
                atomic_amount: 2_500,
                recipient: OTHER_MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 0,
                expected_decision: "deny",
                expected_reason_code: "x402_recipient_not_allowed",
                expected_credits: Some(3),
                expected_revision: TENANT_REVISION,
            },
            // Committed run spend is accounted against the run cap: 4999 + 3
            // exceeds 5000.
            X402Case {
                name: "deny_over_run_cap",
                project: None,
                atomic_amount: 2_500,
                recipient: MERCHANT,
                challenge_resource: RESOURCE_URL,
                authorized_resource: RESOURCE_URL,
                run_spent_credits: 4_999,
                expected_decision: "deny",
                expected_reason_code: "x402_over_run_cap",
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
        let (scope_type, scope_id, revision, max_credits_per_payment) = match case.project {
            Some(project) => (
                "project",
                project,
                PROJECT_REVISION,
                PROJECT_MAX_CREDITS_PER_PAYMENT,
            ),
            None => (
                "tenant",
                TENANT_ID,
                TENANT_REVISION,
                TENANT_MAX_CREDITS_PER_PAYMENT,
            ),
        };
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
            approval_threshold_credits: Some(APPROVAL_THRESHOLD_CREDITS),
            conversion: (
                CONVERSION_NUMERATOR,
                CONVERSION_DENOMINATOR,
                CONVERSION_ROUNDING.to_string(),
                CONVERSION_VERSION.to_string(),
            ),
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
            approval_threshold_credits: optional_u64(&policy["approval"]["threshold_credits"])?,
            conversion: (
                u64_field(&conversion["numerator"], "conversion.numerator")?,
                u64_field(&conversion["denominator"], "conversion.denominator")?,
                string_field(conversion, "rounding")?,
                string_field(conversion, "version")?,
            ),
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
    for expected in [
        ("tenant".to_string(), TENANT_ID.to_string()),
        ("project".to_string(), PROJECT_ID.to_string()),
    ] {
        if !scopes.contains(&expected) {
            bail!("declared x402 policy {expected:?} is missing from the admin list: {listed}");
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
    match case.project {
        Some(project) => format!(
            "/admin/v1/x402-spend-policies/effective?tenant_id={TENANT_ID}&project_id={project}"
        ),
        None => format!("/admin/v1/x402-spend-policies/effective?tenant_id={TENANT_ID}"),
    }
}

fn scope_body(case: &X402Case) -> Value {
    match case.project {
        Some(project) => json!({"tenant_id": TENANT_ID, "project_id": project}),
        None => json!({"tenant_id": TENANT_ID}),
    }
}

/// A base64 `PAYMENT-REQUIRED` header exactly as an x402 merchant would send it.
fn challenge_header(atomic_amount: u64, recipient: &str, resource: &str) -> String {
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
        for forbidden in [
            "secret",
            "signer",
            "signature",
            "private",
            "keypair",
            "mnemonic",
            "credential",
            "password",
        ] {
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
