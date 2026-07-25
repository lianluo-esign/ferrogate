// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Billing and usage command families (issue #364).
//!
//! Moves the money/usage control surface of the Control Plane API onto the
//! shared #360 `CommandGroup`/`Registry` + #361 `ResourceApi`/`build_crud`
//! foundation. As with the other families, each resource noun is a
//! [`CommandGroup`] declaring its verbs and the OpenAPI `operationId` each verb
//! invokes as compile-time metadata — the single source of truth the #365 parity
//! gate diffs against the contract — plus a `build` function mapping a resolved
//! verb and typed [`ResourceInput`] onto a [`RequestSpec`].
//!
//! ## Money and usage stay exact
//!
//! The contract represents money and usage as **integers** in fixed minor units
//! (`balance_credits`, `delta_credits`, `amount_usd_cents`) and ledger truth
//! lives server-side. This layer never parses, rounds, sums, or otherwise
//! recomputes those values: every mutation body is carried opaquely as a
//! complete operator-supplied `serde_json::Value` and every read is rendered
//! from the server's response verbatim. The CLI is therefore structurally
//! incapable of drifting from ledger truth — it transports the API's exact
//! representation and nothing else. If the operator supplies an idempotency key
//! or generation token in the request document, it passes through unmodified;
//! the admin billing contract does not currently define one on these operations.
//!
//! ## Irreversible actions are first-class, not generic CRUD
//!
//! `wallets adjust` (atomic credit adjustment) and `wallets charge` (charge a
//! payment method and credit a wallet) move real money and are modelled as their
//! own `POST .../{tenant_id}/adjust` and `.../charge` action verbs — exactly the
//! first-class-action shape #362 used for lifecycle operations — so the audit
//! trail records precise operator intent instead of an ambiguous `update`. The
//! `VerbDescriptor` metadata layer carries no confirm-intent field (and this
//! slice does not modify the #360 foundation), so the explicit-confirmation /
//! non-interactive-intent gate for these irreversible verbs is enforced at the
//! command-dispatch layer that consumes this metadata; the verbs' `about` text
//! marks them as the settlement-affecting operations that gate must guard.
//!
//! ## Excluded from this family (with reason)
//!
//! * `listPlans`/`getPlan`/`createPlan`/`replacePlan`/`updatePlan` — the plan
//!   catalog is already owned by the #361 `organization` family (`plans` group);
//!   re-declaring it here would duplicate coverage and collide on the group name.
//! * Plan **assignment** (`assignTenantPlan`) is owned by the #361 `organization`
//!   family's `tenant-accounts assign-plan` verb (it addresses a tenant, not a
//!   billing collection), so it is not re-declared here.
//!
//! ## Dead-letter replay landed (#388, wired via #443)
//!
//! The billing outbox dead-letter **replay** operation
//! (`replayBillingOutboxDeadLetter`) landed in the admin OpenAPI contract via
//! #388 and is now driven by the `billing-events replay` verb — a first-class
//! `POST .../{report_id}/replay` recovery action alongside the read-only
//! `dead-letters` listing.
//!
//! ## Per-agent cost-burn lives with usage, not with the agent family (#428)
//!
//! `listAdminAgentCostBurn` (`GET /admin/v1/agent-cost-burn`) is keyed by agent
//! but is a *spend* read: one durable, tenant-scoped `accumulated_usd` rollup per
//! `(tenant, agent_key, period)` billing window. It answers "what did each agent
//! cost me this month", which is the same question `usage aggregates` and
//! `usage reports` answer at other granularities, so it is declared as
//! `usage cost-burn` rather than under the #362 `agent-*` lifecycle groups (which
//! configure agents, not their spend). Like every other verb here it transports
//! the server's exact money representation and never recomputes it.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{build_crud, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/wallets` — tenant credit wallets, keyed by `tenant_id`.
pub const WALLETS: ResourceApi = ResourceApi::new("/admin/v1/wallets");
/// `/admin/v1/payment-methods` — stored payment methods.
pub const PAYMENT_METHODS: ResourceApi = ResourceApi::new("/admin/v1/payment-methods");
/// `/admin/v1/billing-events` — the emitted billing event stream (read view).
pub const BILLING_EVENTS: ResourceApi = ResourceApi::new("/admin/v1/billing-events");
/// `/admin/v1/billing-outbox-dead-letters` — billing outbox dead letters (read view).
pub const BILLING_DEAD_LETTERS: ResourceApi =
    ResourceApi::new("/admin/v1/billing-outbox-dead-letters");
/// `/admin/v1/usage-aggregates` — rolled-up usage aggregates (read view).
pub const USAGE_AGGREGATES: ResourceApi = ResourceApi::new("/admin/v1/usage-aggregates");
/// `/admin/v1/usage-reports` — generated usage reports (read view).
pub const USAGE_REPORTS: ResourceApi = ResourceApi::new("/admin/v1/usage-reports");
/// `/admin/v1/metering-events` — raw metering events (read view).
pub const METERING_EVENTS: ResourceApi = ResourceApi::new("/admin/v1/metering-events");
/// `/admin/v1/metering-export-status` — metering exporter status (read view).
pub const METERING_EXPORT_STATUS: ResourceApi =
    ResourceApi::new("/admin/v1/metering-export-status");
/// `/admin/v1/agent-cost-burn` — durable per-agent runtime cost-burn for a
/// billing period (read view, #428).
pub const AGENT_COST_BURN: ResourceApi = ResourceApi::new("/admin/v1/agent-cost-burn");

/// Tenant wallets: read/create/settings plus the two settlement-affecting
/// actions and the ledger read.
pub struct WalletsGroup;

impl CommandGroup for WalletsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "wallets",
            "Manage tenant credit wallets and settlement",
            vec![
                VerbDescriptor::api("list", "List wallets", "listWallets"),
                VerbDescriptor::api("get", "Show a tenant's wallet", "getWallet"),
                VerbDescriptor::api("create", "Create a tenant wallet", "createWallet"),
                VerbDescriptor::api(
                    "update",
                    "Update a wallet's recharge settings",
                    "updateWallet",
                ),
                VerbDescriptor::api(
                    "adjust",
                    "Atomically adjust wallet credits (irreversible; requires confirmation)",
                    "adjustWallet",
                ),
                VerbDescriptor::api(
                    "charge",
                    "Charge a payment method and credit a wallet (irreversible; requires confirmation)",
                    "chargeWallet",
                ),
                VerbDescriptor::api(
                    "ledger",
                    "List a wallet's ledger entries",
                    "listWalletLedger",
                ),
            ],
        )
    }
}

/// Build the request for a `wallets` verb. `adjust`/`charge` are settlement
/// actions on `.../{tenant_id}/{action}` carrying the operator's exact,
/// server-owned money document; `ledger` reads `.../{tenant_id}/ledger` with
/// pagination/filters preserved; everything else is CRUD keyed by `tenant_id`.
pub fn build_wallets(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "adjust" => WALLETS.action(
            &[first_segment(input, "wallet")?, "adjust"],
            Some(input.require_body(verb)?),
        ),
        "charge" => WALLETS.action(
            &[first_segment(input, "wallet")?, "charge"],
            Some(input.require_body(verb)?),
        ),
        "ledger" => WALLETS.read(&[first_segment(input, "wallet")?, "ledger"], &input.list),
        other => build_crud(&WALLETS, other, input),
    }
}

/// Stored payment methods (list/create/delete).
pub struct PaymentMethodsGroup;

impl CommandGroup for PaymentMethodsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "payment-methods",
            "Manage stored payment methods",
            vec![
                VerbDescriptor::api("list", "List payment methods", "listPaymentMethods"),
                VerbDescriptor::api("create", "Register a payment method", "createPaymentMethod"),
                VerbDescriptor::api("delete", "Delete a payment method", "deletePaymentMethod"),
            ],
        )
    }
}

/// Build the request for a `payment-methods` verb.
pub fn build_payment_methods(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&PAYMENT_METHODS, verb, input)
}

/// Billing event stream and outbox dead letters (read views).
pub struct BillingEventsGroup;

impl CommandGroup for BillingEventsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "billing-events",
            "Inspect billing events and outbox dead letters",
            vec![
                VerbDescriptor::api(
                    "list",
                    "List billing events",
                    "listAdminBillingEventsCompat",
                ),
                VerbDescriptor::api(
                    "dead-letters",
                    "List billing outbox dead letters",
                    "listBillingOutboxDeadLetters",
                ),
                VerbDescriptor::api(
                    "replay",
                    "Replay a dead-lettered billing outbox record",
                    "replayBillingOutboxDeadLetter",
                ),
            ],
        )
    }
}

/// Build the request for a `billing-events` verb. `dead-letters` reads the
/// dead-letter collection; `list` reads the billing event stream — both preserve
/// pagination/filters via `input.list`. `replay` is a first-class recovery
/// action that `POST`s `.../{report_id}/replay` to re-emit a single
/// dead-lettered outbox record (its own verb rather than a generic mutate so the
/// audit trail records the precise operator intent); the server owns idempotency,
/// so any operator-supplied document passes through unmodified.
pub fn build_billing_events(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "dead-letters" => BILLING_DEAD_LETTERS.read(&[], &input.list),
        "replay" => BILLING_DEAD_LETTERS.action(
            &[first_segment(input, "billing dead-letter")?, "replay"],
            input.body.clone(),
        ),
        other => build_crud(&BILLING_EVENTS, other, input),
    }
}

/// Usage and metering read surface: aggregates, generated reports, raw metering
/// events, metering exporter status, and per-agent runtime cost-burn.
pub struct UsageGroup;

impl CommandGroup for UsageGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "usage",
            "Inspect usage aggregates, reports, metering, and agent cost-burn",
            vec![
                VerbDescriptor::api(
                    "aggregates",
                    "List usage aggregates",
                    "listAdminUsageAggregates",
                ),
                VerbDescriptor::api("reports", "List usage reports", "listUsageReports"),
                VerbDescriptor::api(
                    "metering-events",
                    "List raw metering events",
                    "listAdminMeteringEvents",
                ),
                VerbDescriptor::api(
                    "metering-export-status",
                    "Show metering exporter status",
                    "listAdminMeteringExportStatus",
                ),
                VerbDescriptor::api(
                    "cost-burn",
                    "List per-agent runtime cost-burn for a billing period (--filter period=YYYY-MM)",
                    "listAdminAgentCostBurn",
                ),
            ],
        )
    }
}

/// Build the request for a `usage` verb. Each verb reads its own collection with
/// pagination/filters preserved; no verb recomputes any usage value client-side.
///
/// `cost-burn` reads the #428 durable per-agent runtime cost-burn rollup. The
/// operation declares exactly three query parameters — `period` (`YYYY-MM`, the
/// billing window; the server defaults to the current UTC month when omitted)
/// plus the shared `offset`/`limit` pagination — all of which ride the generic
/// `input.list` filter/page channel verbatim, so the CLI neither invents a
/// parameter nor rounds the server-owned `accumulated_usd` totals it returns.
pub fn build_usage(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "aggregates" => USAGE_AGGREGATES.read(&[], &input.list),
        "reports" => USAGE_REPORTS.read(&[], &input.list),
        "metering-events" => METERING_EVENTS.read(&[], &input.list),
        "metering-export-status" => METERING_EXPORT_STATUS.read(&[], &input.list),
        "cost-burn" => AGENT_COST_BURN.read(&[], &input.list),
        other => Err(crate::error::CliError::usage(format!(
            "verb '{other}' is not a usage verb"
        ))),
    }
}

/// Register every billing/usage command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&WalletsGroup)?;
    registry.register(&PaymentMethodsGroup)?;
    registry.register(&BillingEventsGroup)?;
    registry.register(&UsageGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "billing_test.rs"]
mod billing_test;
