// Fixture builders for the Operations cockpit tests (#322). Each returns a
// contract-shaped object with sensible defaults, overridable per test.
import type { components } from "@/lib/api-types.generated";
import type {
  AdminOverviewSection,
  OverviewAlertsWire,
  OverviewControlPlaneWire,
  OverviewRuntimeWire,
  OverviewUsageWire,
} from "@/lib/overview";

type AdminSchema<K extends keyof components["schemas"]> = components["schemas"][K];

export function adminStatus(
  overrides: Partial<AdminSchema<"AdminStatus">> = {},
): AdminSchema<"AdminStatus"> {
  return {
    service: "ferrogate",
    version: "1.2.3",
    runtime: "pingora",
    snapshot: "snap-abc",
    providers: 4,
    enabled_providers: 3,
    models: 12,
    enabled_models: 10,
    api_keys: 7,
    prompt_templates: 2,
    upstreams: 5,
    enabled_upstreams: 4,
    routes: 9,
    enabled_routes: 8,
    plugins: 3,
    active_plugins: 2,
    extensions: 1,
    active_extensions: 1,
    tools: 6,
    platform_providers: 2,
    platform_models: 5,
    platform_offerings: 8,
    auth_required: true,
    storage: {
      provider: "postgres",
      durable: true,
      implemented: true,
      required: true,
      migration_mode: "auto",
      health: "ok",
      provider_order: ["postgres", "memory"],
      contract_version: 1,
      schema: {
        engine: "postgres",
        version: 42,
        name: "ferrogate",
        checksum: "sha",
        validated: true,
      },
    },
    analytics: {
      provider: "clickhouse",
      enabled: true,
      active: true,
      required: false,
      mode: "direct_warehouse",
      sink_configured: true,
      signals: ["request_log"],
      export_timeout_secs: 5,
      batch_max_events: 100,
      flush_interval_millis: 1000,
      queue_capacity: 1000,
      request_log_retention_records: 1000,
      audit_event_retention_records: 1000,
      billing_event_retention_records: 1000,
      health: "ok",
      last_success_at_unix: 1_752_000_000,
      last_export_error: null,
      contract_version: 1,
    },
    cluster: {
      enabled: true,
      cluster_id: "cluster-1",
      node_id: "node-a",
      node_region: "us-east",
      node_zone: "a",
      state_backend: "file",
      counter_backend: "redis",
      active_revision: "rev-9",
      last_sync_at_unix: 1_752_000_000,
      last_sync_error: null,
      stale: false,
      ready: true,
      readiness_reason: "state_loaded",
      draining: false,
      accepting_new_requests: true,
    },
    observability: [],
    acme: {
      enabled: true,
      domains: ["gateway.example.com"],
      cert_path: "/certs/cert.pem",
      key_path: "/certs/key.pem",
      certificate_expires_at_unix: 1_760_000_000,
      renewal_window_secs: 2_592_000,
      renewal_due: false,
      last_renewal_status: "ok",
      last_renewal_at_unix: 1_752_000_000,
      last_renewal_error: null,
      next_check_at_unix: 1_759_000_000,
      reload_required: false,
      reload_mode: "hot",
    },
    ...overrides,
  };
}

export function drainStatus(
  overrides: Partial<AdminSchema<"AdminDrainResponse">> = {},
): AdminSchema<"AdminDrainResponse"> {
  return {
    object: "drain_status",
    draining: false,
    accepting_new_requests: true,
    drain_reason: "not_draining",
    ...overrides,
  };
}

export function providerHealth(
  overrides: Partial<AdminSchema<"ProviderHealthCheck">> = {},
): AdminSchema<"ProviderHealthCheck"> {
  const routing: AdminSchema<"ProviderRoutingHealth"> = {} as AdminSchema<"ProviderRoutingHealth">;
  return {
    name: "openai",
    kind: "openai",
    base_url: "https://api.openai.com",
    enabled: true,
    status: "ok",
    reachable: true,
    circuit_open: false,
    consecutive_failures: 0,
    checked_at_unix: 1_752_000_000,
    error: null,
    routing,
    local_observations: routing,
    cluster_observations: null,
    ...overrides,
  };
}

// --- Control-plane overview (issue #343, contract #339) ---

/** An `ok` overview section wrapping a typed payload. */
export function overviewSectionOk<T>(
  data: T,
  source = "control_plane_store",
  generatedAtUnix = Math.floor(Date.now() / 1000),
): AdminOverviewSection {
  return {
    status: "ok",
    source,
    generated_at_unix: generatedAtUnix,
    data: data as Record<string, unknown>,
  };
}

/** An `unavailable` overview section — carries an error, never a zero payload. */
export function overviewSectionUnavailable(
  error: string,
  source = "control_plane_store",
): AdminOverviewSection {
  return { status: "unavailable", source, error };
}

export function overviewRuntimeData(
  overrides: Partial<OverviewRuntimeWire> = {},
): OverviewRuntimeWire {
  return {
    providers: { total: 4, enabled: 3 },
    models: { total: 12, enabled: 10 },
    static_api_keys: 7,
    prompt_templates: 2,
    upstreams: { total: 5, enabled: 4 },
    routes: { total: 9, enabled: 8 },
    plugins: { total: 3, active: 2 },
    tools: 6,
    mcp_servers: { total: 5, connected: 4, disconnected: 1 },
    ...overrides,
  };
}

// The control-plane payload mirrors `AdminOverviewControlPlane`
// (crates/ferrogate-cli/src/gateway/admin_overview.rs) AFTER #458, and the
// worker histogram uses the status labels the gateway really writes:
// `registered` at registration and the worker-reported `online` on heartbeat —
// never an `active` bucket, which no gateway code path produces.
export function overviewControlPlaneData(
  overrides: Partial<OverviewControlPlaneWire> = {},
): OverviewControlPlaneWire {
  return {
    tenants: 24,
    projects: 52,
    workspaces: 8,
    virtual_keys: { total: 15, enabled: 11 },
    assets: {
      count: 128,
      storage_bytes: 5_368_709_120,
      referenced: 96,
      unreferenced: 32,
      storage_quota_bytes: null,
    },
    agent_runs: { total: 340, by_status: { completed: 300, failed: 32, blocked: 8 } },
    self_hosted_workers: {
      total: 12,
      by_status: { online: 8, registered: 1, stale: 2, draining: 1 },
    },
    pending_tool_approvals: 4,
    quota_pressure: [
      {
        scope_type: "tenant",
        scope_id: "tenant-alpha",
        dimension: "monthly_budget_usd",
        unit: "usd",
        used: 912.5,
        cap: 1000,
        utilization_pct: 91.25,
      },
    ],
    policy_governance: {
      guardrail_policy_revisions: 7,
      guardrail_policy_bindings: 5,
      quota_policies: 3,
      policy_rules: 9,
    },
    ...overrides,
  };
}

export function overviewUsageData(
  overrides: Partial<OverviewUsageWire> = {},
): OverviewUsageWire {
  return {
    current_period_month: "2026-07",
    lifetime: {
      prompt_tokens: 8_000_000,
      completion_tokens: 4_000_000,
      total_tokens: 12_000_000,
      cost_usd: 4210.5,
      request_count: 1_200_000,
      error_count: 3400,
    },
    current_month: {
      prompt_tokens: 900_000,
      completion_tokens: 600_000,
      total_tokens: 1_500_000,
      cost_usd: 512.75,
      request_count: 86_000,
      error_count: 220,
    },
    ...overrides,
  };
}

// Mirrors the alert set `build_overview` derives from the control-plane payload
// above: runtime alerts first, then the durable ones (failed runs, worker
// pressure, quota pressure, pending approvals) — the last two landed in #458.
export function overviewAlertsData(
  overrides: Partial<OverviewAlertsWire> = {},
): OverviewAlertsWire {
  return {
    total: 5,
    truncated: false,
    unavailable_sources: [],
    entries: [
      {
        kind: "provider_unhealthy",
        severity: "critical",
        summary: "1 enabled provider(s) unreachable or circuit-open",
        count: 1,
        detected_at_unix: 1_752_000_000,
        evidence: [
          {
            id: "anthropic",
            detail: "circuit_open; status=error",
            at_unix: 1_752_000_000,
            reference: "/admin/v1/provider-health",
          },
        ],
        evidence_truncated: false,
      },
      {
        kind: "agent_runs_failed",
        severity: "warning",
        summary: "32 agent run(s) in a failure/pressure state",
        count: 32,
        detected_at_unix: 1_752_000_000,
        evidence: [
          { id: "failed", detail: "32 in status failed", reference: "/admin/v1/agent-runs" },
        ],
        evidence_truncated: false,
      },
      {
        kind: "self_hosted_workers_unhealthy",
        severity: "warning",
        summary: "3 self-hosted worker(s) in a failure/pressure state",
        count: 3,
        detected_at_unix: 1_752_000_000,
        evidence: [
          {
            id: "stale",
            detail: "2 in status stale",
            reference: "/admin/v1/self-hosted-worker-records",
          },
          { id: "draining", detail: "1 in status draining" },
        ],
        evidence_truncated: false,
      },
      {
        kind: "quota_pressure",
        severity: "warning",
        summary: "1 scope/quota-dimension(s) at or over the pressure threshold",
        count: 1,
        detected_at_unix: 1_752_000_000,
        evidence: [
          {
            id: "tenant-alpha:monthly_budget_usd",
            detail: "91.25% of monthly_budget_usd cap (912.5 / 1000 usd)",
            reference: "/admin/v1/quota-policies",
          },
        ],
        evidence_truncated: false,
      },
      {
        kind: "tool_approvals_pending",
        severity: "warning",
        summary: "4 tool approval(s) awaiting a decision",
        count: 4,
        detected_at_unix: 1_752_000_000,
        evidence: [
          {
            id: "pending",
            detail: "4 pending tool approval(s)",
            reference: "/admin/v1/tool-approvals",
          },
        ],
        evidence_truncated: false,
      },
    ],
    ...overrides,
  };
}

/** A full, fresh, global-scope control-plane overview. */
export function adminOverview(
  overrides: Partial<AdminSchema<"AdminOverview">> = {},
): AdminSchema<"AdminOverview"> {
  const now = Math.floor(Date.now() / 1000);
  return {
    object: "control_plane.overview",
    generated_at_unix: now,
    scope: { kind: "global" },
    runtime: overviewSectionOk(overviewRuntimeData(), "runtime_config", now),
    control_plane: overviewSectionOk(overviewControlPlaneData(), "control_plane_store", now),
    usage: overviewSectionOk(overviewUsageData(), "control_plane_store", now),
    alerts: overviewSectionOk(overviewAlertsData(), "runtime+control_plane", now),
    ...overrides,
  };
}

export function gatewayConfigProfile(
  overrides: Partial<AdminSchema<"AdminGatewayConfigProfile">> = {},
): AdminSchema<"AdminGatewayConfigProfile"> {
  return {
    id: "profile-1",
    name: "No-cache agent",
    revision: 1,
    enabled: true,
    api_key_ids: ["key_dev"],
    cache_enabled: false,
    ...overrides,
  };
}
