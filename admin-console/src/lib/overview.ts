// Typed consumer layer over GET /admin/v1/overview (issue #343, contract #339).
//
// The #339 contract types each overview SECTION's `data` as an OPEN object
// (`additionalProperties: true` -> `{ [key: string]: unknown }` in the generated
// client) because the four section payloads have different, evolving shapes. The
// interfaces here mirror the server structs (crates/ferrogate-cli/src/gateway/
// admin_overview.rs) so the cockpit reads them with real field types WITHOUT
// hand-fetching every resource list or counting paginated pages in the browser.
//
// This is a typed VIEW over the contract, not a second source of truth: a
// section that failed (or a field the contract does not yet expose — see the
// deferred #458 fields) is surfaced as UNAVAILABLE / not-available, never as a
// fabricated zero (issue #339/#343 acceptance).
//
// Types come straight from the generated contract (a pure type module) rather
// than the `gateway-client` transport layer, so importing this file — e.g. from
// the shared test fixtures reused by the Playwright suite — never drags the
// runtime config/transport graph into a type-only consumer.
import type { components } from "@/lib/api-types.generated";

export type AdminOverview = components["schemas"]["AdminOverview"];
export type AdminOverviewSection = components["schemas"]["AdminOverviewSection"];

/** A `{ enabled, total }` inventory counter (providers, models, upstreams, routes). */
export interface OverviewEnabledCount {
  total: number;
  enabled: number;
}

/** An `{ active, total }` inventory counter (plugins/extensions). */
export interface OverviewActiveCount {
  total: number;
  active: number;
}

export interface OverviewMcpServers {
  total: number;
  connected: number;
  disconnected: number;
}

/** `runtime` section payload: config-derived inventory (always available). */
export interface OverviewRuntimeData {
  providers: OverviewEnabledCount;
  models: OverviewEnabledCount;
  static_api_keys: number;
  prompt_templates: number;
  upstreams: OverviewEnabledCount;
  routes: OverviewEnabledCount;
  plugins: OverviewActiveCount;
  tools: number;
  mcp_servers: OverviewMcpServers;
}

export interface OverviewAssets {
  count: number;
  storage_bytes: number;
}

export interface OverviewCountByStatus {
  total: number;
  by_status: Record<string, number>;
}

/** `control_plane` section payload: durable tenancy/agents/assets/workers. */
export interface OverviewControlPlaneData {
  tenants: number;
  projects: number;
  workspaces: number;
  virtual_keys: number;
  assets: OverviewAssets;
  agent_runs: OverviewCountByStatus;
  self_hosted_workers: OverviewCountByStatus;
}

export interface OverviewTokens {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  request_count: number;
  error_count: number;
}

/** `usage` section payload: durable token/cost totals, lifetime + current month. */
export interface OverviewUsageData {
  current_period_month: string;
  lifetime: OverviewTokens;
  current_month: OverviewTokens;
}

export interface OverviewEvidence {
  id: string;
  detail?: string;
  at_unix?: number;
  reference?: string;
}

export interface OverviewAlert {
  kind: string;
  severity: string;
  summary: string;
  count?: number;
  detected_at_unix: number;
  evidence: OverviewEvidence[];
  evidence_truncated: boolean;
}

/** `alerts` section payload: bounded critical-alert summary with evidence. */
export interface OverviewAlertsData {
  total: number;
  truncated: boolean;
  unavailable_sources: string[];
  entries: OverviewAlert[];
}

/** A section narrowed to typed data OR an explicit unavailable state. */
export type SectionView<T> =
  | { status: "ok"; data: T; source: string; generatedAtUnix?: number }
  | { status: "unavailable"; source: string; error?: string };

/**
 * Narrow a raw overview section into a typed view. An `ok` section WITH a
 * payload becomes typed `data`; anything else (including the contract-illegal
 * `ok`-without-`data`) is reported as `unavailable` so the caller renders an
 * honest N/A instead of a zero.
 */
export function sectionView<T>(section: AdminOverviewSection): SectionView<T> {
  if (section.status === "ok" && section.data) {
    return {
      status: "ok",
      data: section.data as T,
      source: section.source,
      generatedAtUnix: section.generated_at_unix,
    };
  }
  return { status: "unavailable", source: section.source, error: section.error };
}

/** Severity ordering for the alerts region: critical first, then warning, then info. */
export function alertSeverityRank(severity: string): number {
  switch (severity) {
    case "critical":
      return 0;
    case "warning":
      return 1;
    default:
      return 2;
  }
}
