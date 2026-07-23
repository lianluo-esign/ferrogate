// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Operator-action command families (issue #364).
//!
//! Exposes the runtime-control surface of the Control Plane API: system
//! status/readiness/health, provider health, the general observability snapshot,
//! config validate/reload, graceful node drain, and gateway config profiles.
//! Each resource noun is a [`CommandGroup`] declaring its verbs and OpenAPI
//! `operationId`s as compile-time metadata (tracked by the #365 parity gate),
//! plus a `build` function mapping a resolved verb and typed [`ResourceInput`]
//! onto a [`RequestSpec`] via the shared [`ResourceApi`] REST builders.
//!
//! ## Irreversible / state-changing actions are first-class
//!
//! `config reload` (validate-and-apply a process-local config reload) and
//! `drain set` (enter/exit node drain for rolling maintenance) change live node
//! behavior and are modelled as their own action verbs — the same first-class
//! shape #362 used for lifecycle operations — so operator intent is explicit in
//! the audit trail rather than hidden inside a generic mutation. `config
//! validate` is the safe dry-run that pairs with `reload`. The `VerbDescriptor`
//! metadata layer carries no confirm-intent field (and this slice does not
//! modify the #360 foundation), so the explicit-confirmation / non-interactive
//! intent gate for `reload` and `drain set` is enforced at the command-dispatch
//! layer that consumes this metadata; the verbs' `about` text marks them as the
//! runtime-affecting operations that gate must guard. The reload response
//! carries the server's generation/commit outcome verbatim (never recomputed
//! here), and `classify` preserves the request/trace id for attribution.
//!
//! ## Excluded from this family (with reason)
//!
//! * `registerAdminSelfHostedWorker` (`POST /admin/v1/status`) — this shares the
//!   status path but is a worker-agent data-plane registration, already
//!   explicitly excluded by the #362 `worker` family; it is not an operator
//!   action driven from this surface. Only the `GET` status reads are mapped.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::{CliError, CliResult};
use crate::registry_helpers::{build_crud, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/healthz` — liveness probe.
pub const HEALTHZ: ResourceApi = ResourceApi::new("/healthz");
/// `/readyz` — readiness probe.
pub const READYZ: ResourceApi = ResourceApi::new("/readyz");
/// `/admin/v1/status` — admin system status.
pub const ADMIN_STATUS: ResourceApi = ResourceApi::new("/admin/v1/status");
/// `/admin/status` — admin system status (compat alias).
pub const ADMIN_STATUS_ALIAS: ResourceApi = ResourceApi::new("/admin/status");
/// `/admin/v1/observability` — general observability snapshot.
pub const OBSERVABILITY: ResourceApi = ResourceApi::new("/admin/v1/observability");
/// `/admin/v1/provider-health` — provider health (read view).
pub const PROVIDER_HEALTH: ResourceApi = ResourceApi::new("/admin/v1/provider-health");
/// `/admin/v1/config` — config validate/reload sub-surface.
pub const CONFIG: ResourceApi = ResourceApi::new("/admin/v1/config");
/// `/admin/v1/drain` — node drain mode.
pub const DRAIN: ResourceApi = ResourceApi::new("/admin/v1/drain");
/// `/admin/v1/gateway-configs` — gateway config profiles.
pub const GATEWAY_CONFIGS: ResourceApi = ResourceApi::new("/admin/v1/gateway-configs");

/// System status, readiness, liveness, and the observability snapshot.
pub struct SystemGroup;

impl CommandGroup for SystemGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "system",
            "Inspect system status, readiness, and observability",
            vec![
                VerbDescriptor::api("status", "Show admin system status", "getAdminStatus"),
                VerbDescriptor::api(
                    "status-alias",
                    "Show admin system status (compat alias)",
                    "getAdminStatusAlias",
                ),
                VerbDescriptor::api("ready", "Check readiness", "getReadyz"),
                VerbDescriptor::api("health", "Check liveness", "getHealthz"),
                VerbDescriptor::api(
                    "observability",
                    "Show the observability snapshot",
                    "listAdminObservability",
                ),
            ],
        )
    }
}

/// Build the request for a `system` verb. Every verb is a `GET` on its own
/// endpoint; pagination/filters (where the endpoint accepts them) ride
/// `input.list`.
pub fn build_system(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "status" => ADMIN_STATUS.read(&[], &input.list),
        "status-alias" => ADMIN_STATUS_ALIAS.read(&[], &input.list),
        "ready" => READYZ.read(&[], &input.list),
        "health" => HEALTHZ.read(&[], &input.list),
        "observability" => OBSERVABILITY.read(&[], &input.list),
        other => Err(CliError::usage(format!(
            "verb '{other}' is not a system verb"
        ))),
    }
}

/// Provider health (read-only list view).
pub struct ProviderHealthGroup;

impl CommandGroup for ProviderHealthGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "provider-health",
            "List provider health status",
            vec![VerbDescriptor::api(
                "list",
                "List provider health",
                "listAdminProviderHealth",
            )],
        )
    }
}

/// Build the request for a `provider-health` verb.
pub fn build_provider_health(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&PROVIDER_HEALTH, verb, input)
}

/// Config lifecycle: dry-run validate and validate-and-apply reload.
pub struct ConfigGroup;

impl CommandGroup for ConfigGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "config",
            "Validate and reload gateway configuration",
            vec![
                VerbDescriptor::api(
                    "validate",
                    "Validate a candidate config without committing",
                    "validateAdminConfig",
                ),
                VerbDescriptor::api(
                    "reload",
                    "Validate and apply a config reload (state-changing; requires confirmation)",
                    "reloadAdminConfig",
                ),
            ],
        )
    }
}

/// Build the request for a `config` verb. `validate` is a safe dry-run that must
/// carry the candidate config document; `reload` validates-and-applies and
/// carries an optional candidate (absent = reload from the on-disk source). Both
/// map to `POST /admin/v1/config/{action}`.
pub fn build_config(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "validate" => CONFIG.action(&["validate"], Some(input.require_body(verb)?)),
        "reload" => CONFIG.action(&["reload"], input.body.clone()),
        other => Err(CliError::usage(format!(
            "verb '{other}' is not a config verb"
        ))),
    }
}

/// Node drain: read current drain state and set/clear drain mode.
pub struct DrainGroup;

impl CommandGroup for DrainGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "drain",
            "Inspect and control node drain mode",
            vec![
                VerbDescriptor::api("get", "Show current drain state", "getAdminDrain"),
                VerbDescriptor::api(
                    "set",
                    "Set or clear node drain mode (state-changing; requires confirmation)",
                    "setAdminDrain",
                ),
            ],
        )
    }
}

/// Build the request for a `drain` verb. `get` reads the current state; `set`
/// posts the desired drain document to the drain endpoint.
pub fn build_drain(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "get" => DRAIN.read(&[], &input.list),
        "set" => DRAIN.action(&[], Some(input.require_body(verb)?)),
        other => Err(CliError::usage(format!(
            "verb '{other}' is not a drain verb"
        ))),
    }
}

/// Gateway config profiles (full CRUD).
pub struct GatewayConfigsGroup;

impl CommandGroup for GatewayConfigsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "gateway-configs",
            "Manage gateway config profiles",
            vec![
                VerbDescriptor::api(
                    "list",
                    "List gateway config profiles",
                    "listAdminGatewayConfigs",
                ),
                VerbDescriptor::api(
                    "get",
                    "Show a gateway config profile",
                    "getAdminGatewayConfig",
                ),
                VerbDescriptor::api(
                    "create",
                    "Create a gateway config profile",
                    "createAdminGatewayConfig",
                ),
                VerbDescriptor::api(
                    "replace",
                    "Replace a gateway config profile",
                    "putAdminGatewayConfig",
                ),
                VerbDescriptor::api(
                    "update",
                    "Update a gateway config profile",
                    "patchAdminGatewayConfig",
                ),
                VerbDescriptor::api(
                    "delete",
                    "Delete a gateway config profile",
                    "deleteAdminGatewayConfig",
                ),
            ],
        )
    }
}

/// Build the request for a `gateway-configs` verb.
pub fn build_gateway_configs(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&GATEWAY_CONFIGS, verb, input)
}

/// Register every operator-action command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&SystemGroup)?;
    registry.register(&ProviderHealthGroup)?;
    registry.register(&ConfigGroup)?;
    registry.register(&DrainGroup)?;
    registry.register(&GatewayConfigsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "ops_test.rs"]
mod ops_test;
