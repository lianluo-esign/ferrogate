// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Scoped control-plane overview API (issue #339):
// `GET /admin/v1/overview`. A single read-only request returns the dashboard's
// global-control-plane totals -- resource inventory counts, durable
// lifetime/current-month token totals, and a bounded critical-alert summary --
// backed by bounded repository aggregation (COUNT/SUM pushdown on Postgres, an
// in-process fold elsewhere), never by loading whole collections to count them
// in the gateway or the browser. Every section carries an explicit
// available/unavailable state so a storage failure is reported honestly and
// never fabricated as a zero, and tenant-scoped callers only ever see their own
// tenant's counts.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use http::StatusCode;
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Serialize;

use ferrogate_storage::{ControlPlaneOverviewAggregate, OverviewUsageTotals, QuotaPressureScope};

use crate::auth::authenticate;
use crate::responses::{write_json_error, write_json_response};
use crate::state::AppState;

use super::{FerroGateway, ProxyContext};

/// Upper bound on the number of alert entries returned. The alert summary is a
/// triage signal, not a full incident list -- it must stay bounded regardless
/// of how many providers/servers/runs are unhealthy.
const MAX_ALERTS: usize = 50;
/// Upper bound on evidence identifiers attached to any one alert entry.
const MAX_ALERT_EVIDENCE: usize = 20;

/// Which resources the authenticated admin context may see (issue #339,
/// "Define global = all resources visible to the authenticated admin
/// context"). A platform-operator key (`organization_id: None`) gets the
/// global control-plane view; a tenant-scoped key is confined to its own
/// tenant so no count crosses a scope boundary.
pub(crate) enum OverviewScope {
    Global,
    Tenant(String),
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverview {
    pub(crate) object: &'static str,
    pub(crate) generated_at_unix: u64,
    pub(crate) scope: AdminOverviewScope,
    /// Runtime/config-derived inventory. Always available -- it is read from the
    /// in-memory active configuration, so it never depends on the durable store.
    pub(crate) runtime: AdminOverviewSection<AdminOverviewRuntime>,
    /// Durable control-plane inventory counts. `unavailable` (never a zero) when
    /// the storage aggregation fails.
    pub(crate) control_plane: AdminOverviewSection<AdminOverviewControlPlane>,
    /// Durable token/cost totals, lifetime and current calendar month.
    pub(crate) usage: AdminOverviewSection<AdminOverviewUsage>,
    /// Bounded critical-alert summary with evidence identifiers.
    pub(crate) alerts: AdminOverviewSection<AdminOverviewAlerts>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewScope {
    /// `global` for a platform-operator key, `tenant` for a tenant-scoped key.
    pub(crate) kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tenant_id: Option<String>,
}

/// A section that is either fresh data or an explicit unavailable/error state.
/// `data` is `None` whenever `status != "ok"` -- a failed section is NEVER
/// reported as a fabricated zero (issue #339 acceptance).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewSection<T> {
    pub(crate) status: &'static str,
    pub(crate) source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) generated_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<T>,
}

impl<T> AdminOverviewSection<T> {
    fn ok(source: &'static str, generated_at_unix: u64, data: T) -> Self {
        Self {
            status: "ok",
            source,
            generated_at_unix: Some(generated_at_unix),
            error: None,
            data: Some(data),
        }
    }

    fn unavailable(source: &'static str, error: impl Into<String>) -> Self {
        Self {
            status: "unavailable",
            source,
            generated_at_unix: None,
            error: Some(error.into()),
            data: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub(crate) struct AdminOverviewEnabledCount {
    pub(crate) total: usize,
    pub(crate) enabled: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub(crate) struct AdminOverviewActiveCount {
    pub(crate) total: usize,
    pub(crate) active: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub(crate) struct AdminOverviewMcpServers {
    pub(crate) total: usize,
    pub(crate) connected: usize,
    pub(crate) disconnected: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewRuntime {
    pub(crate) providers: AdminOverviewEnabledCount,
    pub(crate) models: AdminOverviewEnabledCount,
    pub(crate) static_api_keys: usize,
    pub(crate) prompt_templates: usize,
    pub(crate) upstreams: AdminOverviewEnabledCount,
    pub(crate) routes: AdminOverviewEnabledCount,
    pub(crate) plugins: AdminOverviewActiveCount,
    pub(crate) tools: usize,
    pub(crate) mcp_servers: AdminOverviewMcpServers,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewControlPlane {
    pub(crate) tenants: u64,
    pub(crate) projects: u64,
    pub(crate) workspaces: u64,
    /// Virtual-key inventory split into total vs enabled (#458); the disabled
    /// count is `total - enabled`. A scope with only disabled keys reports a
    /// non-zero `total` with `enabled = 0` -- a real breakdown, never a fake
    /// zero for the whole count.
    pub(crate) virtual_keys: AdminOverviewEnabledCount,
    pub(crate) assets: AdminOverviewAssets,
    pub(crate) agent_runs: AdminOverviewCountByStatus,
    pub(crate) self_hosted_workers: AdminOverviewCountByStatus,
    /// Number of tool-approval records in scope awaiting a decision (#458),
    /// tenant-scoped by the approval's `organization_id`. A matching bounded
    /// `tool_approvals_pending` alert is raised when this is non-zero.
    pub(crate) pending_tool_approvals: u64,
    /// Bounded, nearest-to-cap-first list of tenant scopes at/over the quota
    /// pressure threshold for a budget or asset-storage cap (#458). Empty means
    /// "no scope under pressure", not "unknown" (a durable failure instead nulls
    /// this whole section). A matching `quota_pressure` alert summarizes it.
    pub(crate) quota_pressure: Vec<AdminOverviewQuotaPressure>,
    /// Global-only policy-governance inventory counts (#458). Present only for a
    /// platform-operator (global) key; serialized as `null` for a tenant-scoped
    /// key because guardrail revisions/bindings carry no tenant column and the
    /// quota/policy tables are not per-tenant attributable without a join. The
    /// `null` is an explicit "not applicable at tenant scope", never a fake
    /// zero, and the field is always returned (never omitted).
    pub(crate) policy_governance: Option<AdminOverviewPolicyGovernance>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewAssets {
    pub(crate) count: u64,
    /// Sum of stored asset `size_bytes` in scope.
    pub(crate) storage_bytes: u64,
    /// Count of asset versions currently pinned by a channel (#458); the
    /// unreferenced split is `count - referenced`. "Referenced" means some
    /// channel points at the exact `(tenant, type, name, version)`.
    pub(crate) referenced: u64,
    /// `count - referenced`: asset versions no channel pins (#458).
    pub(crate) unreferenced: u64,
    /// Applicable per-scope asset-storage quota in bytes (#458). Asset storage
    /// quota is a per-tenant admission-time override with NO single global
    /// number, so this is `null` for the platform-operator (global) view and
    /// for a tenant with no explicit override (it then falls back to its plan
    /// default, intentionally not folded in here). It is a per-scope value, never
    /// a fabricated global aggregate. Always returned (present as `null` when
    /// not applicable).
    pub(crate) storage_quota_bytes: Option<u64>,
}

/// One tenant scope at/over the quota-pressure threshold for one dimension
/// (#458), mirroring the storage aggregate's `QuotaPressureScope`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewQuotaPressure {
    pub(crate) scope_type: String,
    pub(crate) scope_id: String,
    /// `monthly_budget_usd` or `asset_storage_bytes`.
    pub(crate) dimension: String,
    /// `usd` or `bytes`.
    pub(crate) unit: String,
    pub(crate) used: f64,
    pub(crate) cap: f64,
    pub(crate) utilization_pct: f64,
}

/// Global-only policy-governance inventory counts (#458). See
/// [`AdminOverviewControlPlane::policy_governance`] for the scope rationale.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub(crate) struct AdminOverviewPolicyGovernance {
    pub(crate) guardrail_policy_revisions: u64,
    pub(crate) guardrail_policy_bindings: u64,
    pub(crate) quota_policies: u64,
    pub(crate) policy_rules: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewCountByStatus {
    pub(crate) total: u64,
    pub(crate) by_status: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewUsage {
    /// The `YYYY-MM` UTC month the `current_month` totals cover.
    pub(crate) current_period_month: String,
    pub(crate) lifetime: AdminOverviewTokens,
    pub(crate) current_month: AdminOverviewTokens,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewTokens {
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) total_tokens: u64,
    pub(crate) cost_usd: f64,
    pub(crate) request_count: u64,
    pub(crate) error_count: u64,
}

impl From<&OverviewUsageTotals> for AdminOverviewTokens {
    fn from(totals: &OverviewUsageTotals) -> Self {
        Self {
            prompt_tokens: totals.prompt_tokens,
            completion_tokens: totals.completion_tokens,
            total_tokens: totals.total_tokens,
            cost_usd: totals.cost_usd,
            request_count: totals.request_count,
            error_count: totals.error_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewAlerts {
    /// Number of alert entries returned (already bounded by [`MAX_ALERTS`]).
    pub(crate) total: usize,
    /// `true` when more alerts existed than [`MAX_ALERTS`] and were dropped.
    pub(crate) truncated: bool,
    /// Alert sources that could NOT be evaluated for this response (e.g. the
    /// control-plane store when the durable aggregate failed). A source listed
    /// here means "unknown", not "zero alerts".
    pub(crate) unavailable_sources: Vec<&'static str>,
    pub(crate) entries: Vec<AdminOverviewAlert>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewAlert {
    pub(crate) kind: &'static str,
    pub(crate) severity: &'static str,
    pub(crate) summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) count: Option<u64>,
    pub(crate) detected_at_unix: u64,
    pub(crate) evidence: Vec<AdminOverviewEvidence>,
    pub(crate) evidence_truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct AdminOverviewEvidence {
    pub(crate) id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) at_unix: Option<u64>,
    /// Admin API path an operator can follow for the full record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reference: Option<String>,
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// A run/worker status counts as a failure alert when its label looks like a
/// terminal error state. The status strings are free-form (they come from the
/// runtime's `AgentRunStatus`/worker lifecycle), so the overview matches on
/// substrings rather than hardcoding an enum that would silently miss a new
/// state -- and it always echoes the exact bucket label as evidence.
fn is_failure_status(status: &str) -> bool {
    let lower = status.to_ascii_lowercase();
    ["fail", "error", "timed_out", "timeout", "abort", "denied"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// A worker status that means the fleet is losing capacity: draining or stale
/// on top of the outright-failure states.
fn is_worker_pressure_status(status: &str) -> bool {
    let lower = status.to_ascii_lowercase();
    is_failure_status(status) || lower.contains("drain") || lower.contains("stale")
}

pub(crate) fn runtime_inventory(state: &AppState) -> AdminOverviewRuntime {
    let config = &state.config;
    let mcp = state.mcp_statuses();
    let connected = mcp.iter().filter(|status| status.connected).count();
    AdminOverviewRuntime {
        providers: AdminOverviewEnabledCount {
            total: config.providers.len(),
            enabled: config.providers.iter().filter(|p| p.enabled).count(),
        },
        models: AdminOverviewEnabledCount {
            total: config.models.len(),
            enabled: config.models.iter().filter(|m| m.enabled).count(),
        },
        static_api_keys: config.api_keys.len(),
        prompt_templates: config.prompt_templates.len(),
        upstreams: AdminOverviewEnabledCount {
            total: config.upstreams.len(),
            enabled: config.upstreams.iter().filter(|u| u.enabled).count(),
        },
        routes: AdminOverviewEnabledCount {
            total: config.routes.len(),
            enabled: config.routes.iter().filter(|r| r.enabled).count(),
        },
        plugins: AdminOverviewActiveCount {
            total: config.plugin_registrations().len(),
            active: state
                .extension_statuses()
                .iter()
                .filter(|extension| extension.active)
                .count(),
        },
        tools: state.all_tools().len(),
        mcp_servers: AdminOverviewMcpServers {
            total: mcp.len(),
            connected,
            disconnected: mcp.len().saturating_sub(connected),
        },
    }
}

/// Runtime-derived critical alerts: unhealthy providers and disconnected MCP
/// servers. These read only the in-memory runtime health state, so they are
/// available even when the durable store is not. Each carries evidence
/// identifiers + timestamps and a follow-up admin API reference.
pub(crate) fn runtime_alerts(state: &AppState, now_unix: u64) -> Vec<AdminOverviewAlert> {
    let mut alerts = Vec::new();

    let unhealthy_providers: Vec<_> = state
        .provider_health_checks()
        .into_iter()
        .filter(|check| check.enabled && (!check.reachable || check.circuit_open))
        .collect();
    if !unhealthy_providers.is_empty() {
        let (evidence, evidence_truncated) = bound_evidence(unhealthy_providers.iter().map(
            |check| AdminOverviewEvidence {
                id: check.name.clone(),
                detail: Some(if check.circuit_open {
                    format!("circuit_open; status={}", check.status)
                } else {
                    check
                        .error
                        .clone()
                        .unwrap_or_else(|| format!("unreachable; status={}", check.status))
                }),
                at_unix: check.checked_at_unix,
                reference: Some("/admin/v1/provider-health".to_string()),
            },
        ));
        alerts.push(AdminOverviewAlert {
            kind: "provider_unhealthy",
            severity: "critical",
            summary: format!(
                "{} enabled provider(s) unreachable or circuit-open",
                unhealthy_providers.len()
            ),
            count: Some(unhealthy_providers.len() as u64),
            detected_at_unix: now_unix,
            evidence,
            evidence_truncated,
        });
    }

    let disconnected_mcp: Vec<_> = state
        .mcp_statuses()
        .into_iter()
        .filter(|status| !status.connected)
        .collect();
    if !disconnected_mcp.is_empty() {
        let (evidence, evidence_truncated) =
            bound_evidence(disconnected_mcp.iter().map(|status| {
                AdminOverviewEvidence {
                    id: status.name.clone(),
                    detail: status
                        .last_error
                        .clone()
                        .or_else(|| Some(format!("health={}", status.health))),
                    at_unix: status.last_connected_at_unix,
                    reference: Some(format!("/admin/v1/mcp-servers/{}", status.name)),
                }
            }));
        alerts.push(AdminOverviewAlert {
            kind: "mcp_server_disconnected",
            severity: "warning",
            summary: format!("{} MCP server(s) disconnected", disconnected_mcp.len()),
            count: Some(disconnected_mcp.len() as u64),
            detected_at_unix: now_unix,
            evidence,
            evidence_truncated,
        });
    }

    alerts
}

fn bound_evidence(
    items: impl Iterator<Item = AdminOverviewEvidence>,
) -> (Vec<AdminOverviewEvidence>, bool) {
    let all: Vec<_> = items.collect();
    let truncated = all.len() > MAX_ALERT_EVIDENCE;
    let mut bounded = all;
    bounded.truncate(MAX_ALERT_EVIDENCE);
    (bounded, truncated)
}

/// Derive the durable-store-backed alerts (failed agent runs, worker capacity
/// pressure) from a status histogram, echoing the exact bucket labels as
/// evidence so an operator can pivot to the underlying list endpoint.
fn status_pressure_alert(
    kind: &'static str,
    severity: &'static str,
    summary_noun: &str,
    reference: &'static str,
    by_status: &BTreeMap<String, u64>,
    now_unix: u64,
    is_pressure: impl Fn(&str) -> bool,
) -> Option<AdminOverviewAlert> {
    let flagged: Vec<(&String, u64)> = by_status
        .iter()
        .filter(|(status, count)| **count > 0 && is_pressure(status))
        .map(|(status, count)| (status, *count))
        .collect();
    if flagged.is_empty() {
        return None;
    }
    let total: u64 = flagged.iter().map(|(_, count)| *count).sum();
    let (evidence, evidence_truncated) =
        bound_evidence(flagged.iter().map(|(status, count)| AdminOverviewEvidence {
            id: (*status).clone(),
            detail: Some(format!("{count} in status {status}")),
            at_unix: None,
            reference: Some(reference.to_string()),
        }));
    Some(AdminOverviewAlert {
        kind,
        severity,
        summary: format!("{total} {summary_noun} in a failure/pressure state"),
        count: Some(total),
        detected_at_unix: now_unix,
        evidence,
        evidence_truncated,
    })
}

/// Derive the bounded quota-pressure alert (#458) from the aggregate's
/// already-bounded, nearest-to-cap-first quota-pressure list. Each scope/
/// dimension becomes one evidence entry echoing its utilization and cap so an
/// operator can pivot to the quota-policy endpoint. An empty list is not an
/// alert (it is an honest "no scope under pressure"), and the durable aggregate
/// nulling out instead surfaces as an unavailable source, never a fake zero.
fn quota_pressure_alert(
    pressure: &[QuotaPressureScope],
    now_unix: u64,
) -> Option<AdminOverviewAlert> {
    if pressure.is_empty() {
        return None;
    }
    let (evidence, evidence_truncated) =
        bound_evidence(pressure.iter().map(|scope| AdminOverviewEvidence {
            id: format!("{}:{}", scope.scope_id, scope.dimension),
            detail: Some(format!(
                "{:.2}% of {} cap ({} / {} {})",
                scope.utilization_pct, scope.dimension, scope.used, scope.cap, scope.unit
            )),
            at_unix: None,
            reference: Some("/admin/v1/quota-policies".to_string()),
        }));
    Some(AdminOverviewAlert {
        kind: "quota_pressure",
        severity: "warning",
        summary: format!(
            "{} scope/quota-dimension(s) at or over the pressure threshold",
            pressure.len()
        ),
        count: Some(pressure.len() as u64),
        detected_at_unix: now_unix,
        evidence,
        evidence_truncated,
    })
}

/// Derive the pending-approval alert (#458) from the scoped pending count. The
/// count is authoritative; the single evidence entry references the list
/// endpoint (the aggregate carries the tally, not per-approval ids). A zero
/// count is no alert, and a durable failure instead nulls the section, so a
/// pending approval is never silently reported as zero.
fn pending_approvals_alert(pending: u64, now_unix: u64) -> Option<AdminOverviewAlert> {
    if pending == 0 {
        return None;
    }
    Some(AdminOverviewAlert {
        kind: "tool_approvals_pending",
        severity: "warning",
        summary: format!("{pending} tool approval(s) awaiting a decision"),
        count: Some(pending),
        detected_at_unix: now_unix,
        evidence: vec![AdminOverviewEvidence {
            id: "pending".to_string(),
            detail: Some(format!("{pending} pending tool approval(s)")),
            at_unix: None,
            reference: Some("/admin/v1/tool-approvals".to_string()),
        }],
        evidence_truncated: false,
    })
}

/// Pure envelope assembler (issue #339). Kept free of I/O so the
/// never-fake-a-zero and alert-bounding behavior is unit-testable: a failed
/// durable aggregate (`Err`) yields `unavailable` control-plane/usage sections
/// with `data: None`, while the runtime section and runtime-derived alerts stay
/// available.
pub(crate) fn build_overview(
    now_unix: u64,
    scope: OverviewScope,
    runtime: AdminOverviewRuntime,
    runtime_alerts: Vec<AdminOverviewAlert>,
    current_period_month: String,
    aggregate: Result<ControlPlaneOverviewAggregate, String>,
) -> AdminOverview {
    let scope = match scope {
        OverviewScope::Global => AdminOverviewScope {
            kind: "global",
            tenant_id: None,
        },
        OverviewScope::Tenant(tenant_id) => AdminOverviewScope {
            kind: "tenant",
            tenant_id: Some(tenant_id),
        },
    };

    let runtime_section = AdminOverviewSection::ok("runtime_config", now_unix, runtime);

    let (control_plane_section, usage_section, mut alerts, unavailable_sources) = match aggregate {
        Ok(aggregate) => {
            let control_plane = AdminOverviewControlPlane {
                tenants: aggregate.tenants,
                projects: aggregate.projects,
                workspaces: aggregate.workspaces,
                virtual_keys: AdminOverviewEnabledCount {
                    total: aggregate.virtual_keys as usize,
                    enabled: aggregate.virtual_keys_enabled as usize,
                },
                assets: AdminOverviewAssets {
                    count: aggregate.assets,
                    storage_bytes: aggregate.asset_storage_bytes,
                    referenced: aggregate.assets_referenced,
                    unreferenced: aggregate.assets.saturating_sub(aggregate.assets_referenced),
                    storage_quota_bytes: aggregate.asset_storage_quota_bytes,
                },
                agent_runs: AdminOverviewCountByStatus {
                    total: aggregate.agent_runs,
                    by_status: aggregate.agent_runs_by_status.clone(),
                },
                self_hosted_workers: AdminOverviewCountByStatus {
                    total: aggregate.self_hosted_workers,
                    by_status: aggregate.self_hosted_workers_by_status.clone(),
                },
                pending_tool_approvals: aggregate.pending_tool_approvals,
                quota_pressure: aggregate
                    .quota_pressure
                    .iter()
                    .map(|scope| AdminOverviewQuotaPressure {
                        scope_type: scope.scope_type.clone(),
                        scope_id: scope.scope_id.clone(),
                        dimension: scope.dimension.to_string(),
                        unit: scope.unit.to_string(),
                        used: scope.used,
                        cap: scope.cap,
                        utilization_pct: scope.utilization_pct,
                    })
                    .collect(),
                policy_governance: aggregate.policy_governance.as_ref().map(|counts| {
                    AdminOverviewPolicyGovernance {
                        guardrail_policy_revisions: counts.guardrail_policy_revisions,
                        guardrail_policy_bindings: counts.guardrail_policy_bindings,
                        quota_policies: counts.quota_policies,
                        policy_rules: counts.policy_rules,
                    }
                }),
            };
            let usage = AdminOverviewUsage {
                current_period_month: current_period_month.clone(),
                lifetime: AdminOverviewTokens::from(&aggregate.usage_lifetime),
                current_month: AdminOverviewTokens::from(&aggregate.usage_current_month),
            };
            let mut durable_alerts = Vec::new();
            if let Some(alert) = status_pressure_alert(
                "agent_runs_failed",
                "warning",
                "agent run(s)",
                "/admin/v1/agent-runs",
                &aggregate.agent_runs_by_status,
                now_unix,
                is_failure_status,
            ) {
                durable_alerts.push(alert);
            }
            if let Some(alert) = status_pressure_alert(
                "self_hosted_workers_unhealthy",
                "warning",
                "self-hosted worker(s)",
                "/admin/v1/self-hosted-worker-records",
                &aggregate.self_hosted_workers_by_status,
                now_unix,
                is_worker_pressure_status,
            ) {
                durable_alerts.push(alert);
            }
            if let Some(alert) = quota_pressure_alert(&aggregate.quota_pressure, now_unix) {
                durable_alerts.push(alert);
            }
            if let Some(alert) = pending_approvals_alert(aggregate.pending_tool_approvals, now_unix)
            {
                durable_alerts.push(alert);
            }
            (
                AdminOverviewSection::ok("control_plane_store", now_unix, control_plane),
                AdminOverviewSection::ok("control_plane_store", now_unix, usage),
                durable_alerts,
                Vec::new(),
            )
        }
        Err(error) => (
            AdminOverviewSection::unavailable("control_plane_store", error.clone()),
            AdminOverviewSection::unavailable("control_plane_store", error),
            Vec::new(),
            vec!["control_plane_store"],
        ),
    };

    // Runtime-derived alerts always apply; durable alerts only when the
    // aggregate succeeded. Bound the merged list so the summary stays a triage
    // signal, not an unbounded incident dump.
    let mut merged = runtime_alerts;
    merged.append(&mut alerts);
    let truncated = merged.len() > MAX_ALERTS;
    merged.truncate(MAX_ALERTS);
    let alerts_section = AdminOverviewSection::ok(
        "runtime+control_plane",
        now_unix,
        AdminOverviewAlerts {
            total: merged.len(),
            truncated,
            unavailable_sources,
            entries: merged,
        },
    );

    AdminOverview {
        object: "control_plane.overview",
        generated_at_unix: now_unix,
        scope,
        runtime: runtime_section,
        control_plane: control_plane_section,
        usage: usage_section,
        alerts: alerts_section,
    }
}

impl FerroGateway {
    /// `GET /admin/v1/overview` (issue #339): the dashboard's scoped
    /// control-plane overview. Authenticates `admin.read`, resolves the caller's
    /// visibility scope, and assembles inventory counts, durable
    /// lifetime/current-month token totals, and a bounded alert summary in one
    /// bounded response.
    pub(super) async fn handle_admin_overview(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let now_unix = now_unix_seconds();
        let current_period_month = ferrogate_storage::period_month_from_unix(now_unix as i64);
        // #515: a global (all-tenant) overview is for a declared platform
        // operator; anything else is pinned to its own tenant.
        let scope = match auth.caller_scope() {
            crate::auth::CallerScope::PlatformOperator => OverviewScope::Global,
            crate::auth::CallerScope::Tenant(tenant_id) => {
                OverviewScope::Tenant(tenant_id.to_string())
            }
        };

        // Runtime/config counts + runtime-health alerts: in-memory, always
        // available (never gated on the durable store).
        let runtime = runtime_inventory(&state);
        let runtime_alerts = runtime_alerts(&state, now_unix);

        // Durable inventory + usage aggregate, scoped to the caller's tenant so
        // a tenant-scoped console can never read another tenant's counts. A
        // failure surfaces as `unavailable`, never a fabricated zero.
        // The SAME classification the `scope` label above was built from. Read
        // off `organization_id` these two could disagree: an unclassified
        // credential got labelled `Tenant("")` while the aggregate below was
        // computed with `None`, i.e. over every tenant.
        let aggregate = state
            .control_plane_overview_aggregate(auth.tenant_filter(), &current_period_month)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "control-plane overview aggregate failed");
                format!("control-plane inventory/usage aggregate unavailable: {error}")
            });

        let overview = build_overview(
            now_unix,
            scope,
            runtime,
            runtime_alerts,
            current_period_month,
            aggregate,
        );
        write_json_response(session, StatusCode::OK, &overview, &ctx.request_id).await
    }
}

#[cfg(test)]
#[path = "admin_overview_test.rs"]
mod admin_overview_test;
