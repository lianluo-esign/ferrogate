// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the billing/usage command families (#364): registration
//! order, verb → operationId/method/path resolution, exact money pass-through,
//! irreversible-action shape, pagination/filter building against a fake
//! transport, and error → exit-class mapping. Pure logic plus a fake transport —
//! no live network.

use super::*;
use crate::auth::AuthSource;
use crate::command::CommandGroup;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::{CliResult, ExitClass};
use crate::output::OutputFormat;
use crate::registry_helpers::ResourceInput;
use crate::resource::ListParams;
use crate::transport::{
    ControlPlaneClient, PageRequest, PreparedRequest, RawResponse, RequestSpec, Transport,
};
use http::Method;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};

type Seen = Arc<Mutex<Option<PreparedRequest>>>;
type BuildFn = fn(&str, &ResourceInput) -> CliResult<RequestSpec>;

fn context() -> EffectiveContext {
    EffectiveContext {
        context_name: Some("test".to_string()),
        endpoint: "https://cp.example.com".to_string(),
        tenant: Some("acme".to_string()),
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: AuthSource::None,
        output: OutputFormat::Json,
        non_interactive: true,
    }
}

fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => continue,
        }
    }
}

struct FakeTransport {
    response: RawResponse,
    seen: Seen,
}

fn fake(status: u16, body: &[u8]) -> (FakeTransport, Seen) {
    let seen: Seen = Arc::new(Mutex::new(None));
    let transport = FakeTransport {
        response: RawResponse {
            status,
            headers: vec![],
            body: body.to_vec(),
        },
        seen: seen.clone(),
    };
    (transport, seen)
}

impl Transport for FakeTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        *self.seen.lock().unwrap() = Some(request);
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }
}

/// An input satisfying every declared verb across the families: a single id
/// segment (tenant/payment-method) plus a money body for the write verbs.
fn universal_input() -> ResourceInput {
    ResourceInput::new()
        .with_segments(["acme"])
        .with_body(serde_json::json!({"delta_credits": 500}))
}

#[test]
fn all_groups_register_in_order() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let names: Vec<&str> = registry.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["wallets", "payment-methods", "billing-events", "usage"]
    );
}

#[test]
fn every_declared_verb_builds_a_request() {
    let cases: Vec<(GroupDescriptor, BuildFn)> = vec![
        (WalletsGroup.descriptor(), build_wallets),
        (PaymentMethodsGroup.descriptor(), build_payment_methods),
        (BillingEventsGroup.descriptor(), build_billing_events),
        (UsageGroup.descriptor(), build_usage),
    ];
    let input = universal_input();
    for (descriptor, build) in cases {
        for verb in &descriptor.verbs {
            let built = build(&verb.name, &input);
            assert!(
                built.is_ok(),
                "group {} verb {} failed to build: {:?}",
                descriptor.name,
                verb.name,
                built.err()
            );
        }
    }
}

#[test]
fn coverage_manifest_has_exactly_the_declared_operation_ids() {
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    let manifest = registry.coverage_manifest();
    for op in [
        "listWallets",
        "getWallet",
        "createWallet",
        "updateWallet",
        "adjustWallet",
        "chargeWallet",
        "listWalletLedger",
        "listPaymentMethods",
        "createPaymentMethod",
        "deletePaymentMethod",
        "listAdminBillingEventsCompat",
        "listBillingOutboxDeadLetters",
        "replayBillingOutboxDeadLetter",
        "listAdminUsageAggregates",
        "listUsageReports",
        "listAdminMeteringEvents",
        "listAdminMeteringExportStatus",
        "listAdminAgentCostBurn",
    ] {
        assert!(manifest.contains(op), "missing operation id {op}");
    }
    // 7 (wallets) + 3 (payment-methods) + 3 (billing-events) + 5 (usage) = 18.
    assert_eq!(manifest.len(), 18);
}

#[test]
fn every_operation_id_exists_in_the_openapi_contract() {
    // The declared operationIds are what the #365 parity gate diffs against the
    // contract, so a typo here would silently break coverage. Assert each one is
    // a real operationId in the shipped OpenAPI document.
    let spec = include_str!("../../../docs/openapi/admin-api.openapi.json");
    let mut registry = Registry::new();
    register(&mut registry).unwrap();
    for op in registry.coverage_manifest() {
        let needle = format!("\"operationId\": \"{op}\"");
        assert!(
            spec.contains(&needle),
            "operationId {op} not found in admin-api.openapi.json"
        );
    }
}

#[test]
fn wallet_crud_and_ledger_map_to_the_tenant_key() {
    let key = ResourceInput::new().with_segments(["acme"]);

    let get = build_wallets("get", &key).unwrap();
    assert_eq!(get.method, Method::GET);
    assert_eq!(get.path, "/admin/v1/wallets/acme");

    let update = build_wallets(
        "update",
        &key.clone()
            .with_body(serde_json::json!({"auto_recharge_amount_credits": 1000})),
    )
    .unwrap();
    assert_eq!(update.method, Method::PATCH);
    assert_eq!(update.path, "/admin/v1/wallets/acme");

    let ledger = build_wallets("ledger", &key).unwrap();
    assert_eq!(ledger.method, Method::GET);
    assert_eq!(ledger.path, "/admin/v1/wallets/acme/ledger");

    let list = build_wallets("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/wallets");
}

#[test]
fn wallet_adjust_and_charge_are_first_class_post_actions() {
    let key = ResourceInput::new()
        .with_segments(["acme"])
        .with_body(serde_json::json!({"delta_credits": -250}));

    let adjust = build_wallets("adjust", &key).unwrap();
    assert_eq!(adjust.method, Method::POST);
    assert_eq!(adjust.path, "/admin/v1/wallets/acme/adjust");
    assert!(adjust.body.is_some());

    let charge = build_wallets(
        "charge",
        &ResourceInput::new()
            .with_segments(["acme"])
            .with_body(serde_json::json!({"amount_usd_cents": 2500})),
    )
    .unwrap();
    assert_eq!(charge.method, Method::POST);
    assert_eq!(charge.path, "/admin/v1/wallets/acme/charge");
}

#[test]
fn wallet_money_body_passes_through_exactly_unrounded() {
    // Money is an integer minor-unit representation the CLI must not touch. A
    // negative debit and a large cent amount survive verbatim onto the wire.
    let adjust = build_wallets(
        "adjust",
        &ResourceInput::new()
            .with_segments(["acme"])
            .with_body(serde_json::json!({"delta_credits": -123456789})),
    )
    .unwrap();
    assert_eq!(adjust.body.as_ref().unwrap()["delta_credits"], -123456789);

    let (transport, seen) = fake(200, br#"{"balance_credits": 999}"#);
    let client = ControlPlaneClient::new(context(), None, transport);
    block_on(client.send(&adjust)).unwrap();
    let seen = seen.lock().unwrap().clone().unwrap();
    let sent: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(sent["delta_credits"], -123456789);
}

#[test]
fn wallet_adjust_without_body_is_a_usage_error() {
    let error = build_wallets("adjust", &ResourceInput::new().with_segments(["acme"])).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error
        .to_string()
        .contains("requires a JSON request document"));
}

#[test]
fn wallet_adjust_without_tenant_is_a_usage_error() {
    let error = build_wallets(
        "adjust",
        &ResourceInput::new().with_body(serde_json::json!({"delta_credits": 1})),
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn payment_methods_crud_maps_to_the_collection() {
    let list = build_payment_methods("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/payment-methods");

    let delete =
        build_payment_methods("delete", &ResourceInput::new().with_segments(["pm_123"])).unwrap();
    assert_eq!(delete.method, Method::DELETE);
    assert_eq!(delete.path, "/admin/v1/payment-methods/pm_123");
}

#[test]
fn billing_events_and_dead_letters_map_to_their_collections() {
    let list = build_billing_events("list", &ResourceInput::new()).unwrap();
    assert_eq!(list.method, Method::GET);
    assert_eq!(list.path, "/admin/v1/billing-events");

    let dl = build_billing_events("dead-letters", &ResourceInput::new()).unwrap();
    assert_eq!(dl.method, Method::GET);
    assert_eq!(dl.path, "/admin/v1/billing-outbox-dead-letters");
}

#[test]
fn dead_letter_replay_is_a_first_class_post_action_on_the_report() {
    // replayBillingOutboxDeadLetter re-emits one dead-lettered record via
    // POST .../{report_id}/replay; the id rides the path, no body is required.
    let replay =
        build_billing_events("replay", &ResourceInput::new().with_segments(["rpt_42"])).unwrap();
    assert_eq!(replay.method, Method::POST);
    assert_eq!(
        replay.path,
        "/admin/v1/billing-outbox-dead-letters/rpt_42/replay"
    );
    assert!(replay.body.is_none());
}

#[test]
fn dead_letter_replay_without_report_id_is_a_usage_error() {
    let error = build_billing_events("replay", &ResourceInput::new()).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(error.to_string().contains("requires a target id"));
}

#[test]
fn usage_verbs_map_to_their_collections_and_preserve_filters() {
    let aggregates = build_usage("aggregates", &ResourceInput::new()).unwrap();
    assert_eq!(aggregates.path, "/admin/v1/usage-aggregates");

    let reports = build_usage("reports", &ResourceInput::new()).unwrap();
    assert_eq!(reports.path, "/admin/v1/usage-reports");

    let events = build_usage("metering-events", &ResourceInput::new()).unwrap();
    assert_eq!(events.path, "/admin/v1/metering-events");

    let status = build_usage("metering-export-status", &ResourceInput::new()).unwrap();
    assert_eq!(status.path, "/admin/v1/metering-export-status");

    let cost_burn = build_usage("cost-burn", &ResourceInput::new()).unwrap();
    assert_eq!(cost_burn.path, "/admin/v1/agent-cost-burn");

    // Pagination and a server-side filter are folded into the query verbatim.
    let filtered = build_usage(
        "aggregates",
        &ResourceInput::new().with_list(
            ListParams::new()
                .with_page(PageRequest::first(50))
                .with_filter("organization_id", "org-1"),
        ),
    )
    .unwrap();
    assert!(filtered
        .query
        .contains(&("organization_id".to_string(), "org-1".to_string())));
    assert!(filtered
        .query
        .contains(&("limit".to_string(), "50".to_string())));
}

#[test]
fn cost_burn_reads_the_period_rollup_and_preserves_filters() {
    // listAdminAgentCostBurn (#428) is a read-only GET on its own collection; the
    // only parameters it declares are `period` plus offset/limit pagination, and
    // all three must reach the wire exactly as the operator asked.
    let plain = build_usage("cost-burn", &ResourceInput::new()).unwrap();
    assert_eq!(plain.method, Method::GET);
    assert_eq!(plain.path, "/admin/v1/agent-cost-burn");
    // No period is invented client-side: omitting it lets the server apply its
    // documented default (the current UTC month).
    assert!(plain.query.iter().all(|(key, _)| key != "period"));

    let scoped = build_usage(
        "cost-burn",
        &ResourceInput::new().with_list(
            ListParams::new()
                .with_page(PageRequest {
                    offset: 20,
                    limit: Some(10),
                })
                .with_filter("period", "2026-06"),
        ),
    )
    .unwrap();
    assert_eq!(scoped.method, Method::GET);
    assert_eq!(scoped.path, "/admin/v1/agent-cost-burn");
    assert!(scoped
        .query
        .contains(&("period".to_string(), "2026-06".to_string())));
    assert!(scoped
        .query
        .contains(&("offset".to_string(), "20".to_string())));
    assert!(scoped
        .query
        .contains(&("limit".to_string(), "10".to_string())));
}

#[test]
fn insufficient_balance_on_charge_maps_to_validation_class() {
    let spec = build_wallets(
        "charge",
        &ResourceInput::new()
            .with_segments(["acme"])
            .with_body(serde_json::json!({"amount_usd_cents": 100})),
    )
    .unwrap();
    let (transport, _seen) = fake(
        422,
        br#"{"error":{"message":"insufficient balance","type":"ferrogate_error","code":"unprocessable_entity","request_id":"fgadm-bal"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Validation);
}

#[test]
fn duplicate_idempotency_key_on_adjust_maps_to_conflict_class() {
    let spec = build_wallets(
        "adjust",
        &ResourceInput::new()
            .with_segments(["acme"])
            .with_body(serde_json::json!({"delta_credits": 10, "idempotency_key": "k1"})),
    )
    .unwrap();
    // A replayed idempotency key surfaces as 409 conflict and must fail closed on
    // the not-found/conflict exit class rather than being mistaken for success.
    let (transport, _seen) = fake(
        409,
        br#"{"error":{"message":"duplicate idempotency key","type":"ferrogate_error","code":"conflict","request_id":"fgadm-idem"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
}

#[test]
fn wrong_tenant_scope_on_wallet_get_maps_to_auth_class() {
    let spec = build_wallets("get", &ResourceInput::new().with_segments(["other-tenant"])).unwrap();
    let (transport, _seen) = fake(
        403,
        br#"{"error":{"message":"wallet not in scope","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-scope"}}"#,
    );
    let client = ControlPlaneClient::new(context(), None, transport);
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}
