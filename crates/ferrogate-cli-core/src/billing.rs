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
//! * Dead-letter **replay** and plan **assignment** operations named in the
//!   issue scope are **not present** in the shipped admin OpenAPI contract, so
//!   there is no `operationId` to map. Dead letters are exposed read-only here
//!   (`billing-events dead-letters`); a replay operation must first be added to
//!   the contract before the CLI can drive it.

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
            ],
        )
    }
}

/// Build the request for a `billing-events` verb. `dead-letters` reads the
/// dead-letter collection; `list` reads the billing event stream. Both preserve
/// pagination/filters via `input.list`.
pub fn build_billing_events(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "dead-letters" => BILLING_DEAD_LETTERS.read(&[], &input.list),
        other => build_crud(&BILLING_EVENTS, other, input),
    }
}

/// Usage and metering read surface: aggregates, generated reports, raw metering
/// events, and metering exporter status.
pub struct UsageGroup;

impl CommandGroup for UsageGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "usage",
            "Inspect usage aggregates, reports, and metering",
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
            ],
        )
    }
}

/// Build the request for a `usage` verb. Each verb reads its own collection with
/// pagination/filters preserved; no verb recomputes any usage value client-side.
pub fn build_usage(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "aggregates" => USAGE_AGGREGATES.read(&[], &input.list),
        "reports" => USAGE_REPORTS.read(&[], &input.list),
        "metering-events" => METERING_EVENTS.read(&[], &input.list),
        "metering-export-status" => METERING_EXPORT_STATUS.read(&[], &input.list),
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
