// Typed consumer layer over GET /admin/v1/overview (issue #343, contract #339).
//
// The #339 contract types each overview SECTION's `data` as an OPEN object
// (`additionalProperties: true` -> `{ [key: string]: unknown }` in the generated
// client) because the four section payloads have different, evolving shapes.
//
// Two type families live here, and the split is deliberate:
//
//   * `Overview*Wire` mirrors the server structs (crates/ferrogate-cli/src/
//     gateway/admin_overview.rs) EXACTLY, with every field required. It is what
//     the gateway promises to send and what the shared test fixtures must
//     produce, so a fixture can never drift into a shape the product never sees.
//   * `Overview*Data` is the PARSED view the cockpit renders: every field is
//     validated at runtime and independently optional. `undefined` means
//     "missing or unreadable", which the cockpit renders as N/A — never as a
//     fabricated zero and never as a `NaN`.
//
// Why runtime validation instead of a cast: this module used to hand the raw
// `data` object to the caller with an unchecked `as T`. That let the server's
// wire shape drift silently past `tsc` — #458 changed `virtual_keys` from a
// number to a `{total,enabled}` object and the console rendered
// `Intl.NumberFormat().format({...})` === "NaN" on screen. A cast cannot fail;
// a parser can, so every field the cockpit displays is now proven to be a
// number/string/object BEFORE it reaches a formatter.
//
// Types come straight from the generated contract (a pure type module) rather
// than the `gateway-client` transport layer, so importing this file — e.g. from
// the shared test fixtures reused by the Playwright suite — never drags the
// runtime config/transport graph into a type-only consumer.
import type { components } from "@/lib/api-types.generated";

export type AdminOverview = components["schemas"]["AdminOverview"];
export type AdminOverviewSection = components["schemas"]["AdminOverviewSection"];

// --- Wire shapes: a 1:1 mirror of the server structs -------------------------

/** A `{ enabled, total }` inventory counter (providers, models, virtual keys…). */
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
export interface OverviewRuntimeWire {
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
  /** Asset versions a channel currently pins (#458). */
  referenced: number;
  /** `count - referenced`: asset versions no channel pins (#458). */
  unreferenced: number;
  /**
   * Applicable per-scope asset-storage quota (#458). `null` for the global view
   * and for a tenant with no explicit override — an honest "not applicable",
   * never a fabricated global aggregate.
   */
  storage_quota_bytes: number | null;
}

export interface OverviewCountByStatus {
  total: number;
  by_status: Record<string, number>;
}

/** One scope at/over its quota-pressure threshold (#458). */
export interface OverviewQuotaPressure {
  scope_type: string;
  scope_id: string;
  dimension: string;
  unit: string;
  used: number;
  cap: number;
  utilization_pct: number;
}

/** Global-only policy-governance counts (#458); `null` at tenant scope. */
export interface OverviewPolicyGovernance {
  guardrail_policy_revisions: number;
  guardrail_policy_bindings: number;
  quota_policies: number;
  policy_rules: number;
}

/** `control_plane` section payload: durable tenancy/agents/assets/workers. */
export interface OverviewControlPlaneWire {
  tenants: number;
  projects: number;
  workspaces: number;
  virtual_keys: OverviewEnabledCount;
  assets: OverviewAssets;
  agent_runs: OverviewCountByStatus;
  self_hosted_workers: OverviewCountByStatus;
  pending_tool_approvals: number;
  quota_pressure: OverviewQuotaPressure[];
  policy_governance: OverviewPolicyGovernance | null;
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
export interface OverviewUsageWire {
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
export interface OverviewAlertsWire {
  total: number;
  truncated: boolean;
  unavailable_sources: string[];
  entries: OverviewAlert[];
}

// --- Parsed views: what the cockpit renders ---------------------------------
//
// Every field is optional because every field is validated: a field the server
// stopped sending, renamed, or changed the type of arrives as `undefined` and
// is rendered N/A, so a wire-shape drift degrades one cell instead of printing
// a wrong number.

export type OverviewRuntimeData = Partial<OverviewRuntimeWire>;
export type OverviewControlPlaneData = Partial<OverviewControlPlaneWire>;
export type OverviewUsageData = Partial<OverviewUsageWire>;
/** Alerts keep a concrete `entries` list plus a count of entries dropped as unreadable. */
export type OverviewAlertsData = Partial<Omit<OverviewAlertsWire, "entries">> & {
  entries: OverviewAlert[];
  malformed_entries: number;
};

// --- Field readers ----------------------------------------------------------

function readRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** A finite number, or `undefined`. `NaN`/`Infinity`/non-numbers never pass. */
function readNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

/** Read several numeric fields; `undefined` unless EVERY one is a finite number. */
function readNumbers<K extends string>(
  value: unknown,
  keys: readonly K[],
): Record<K, number> | undefined {
  const source = readRecord(value);
  if (!source) return undefined;
  const out = {} as Record<K, number>;
  for (const key of keys) {
    const parsed = readNumber(source[key]);
    if (parsed === undefined) return undefined;
    out[key] = parsed;
  }
  return out;
}

/** A `Record<string, number>` histogram; `undefined` if any bucket is not a number. */
function readCountMap(value: unknown): Record<string, number> | undefined {
  const source = readRecord(value);
  if (!source) return undefined;
  const out: Record<string, number> = {};
  for (const [key, raw] of Object.entries(source)) {
    const count = readNumber(raw);
    if (count === undefined) return undefined;
    out[key] = count;
  }
  return out;
}

function readEnabledCount(value: unknown): OverviewEnabledCount | undefined {
  return readNumbers(value, ["total", "enabled"] as const);
}

function readActiveCount(value: unknown): OverviewActiveCount | undefined {
  return readNumbers(value, ["total", "active"] as const);
}

function readMcpServers(value: unknown): OverviewMcpServers | undefined {
  return readNumbers(value, ["total", "connected", "disconnected"] as const);
}

function readCountByStatus(value: unknown): OverviewCountByStatus | undefined {
  const source = readRecord(value);
  if (!source) return undefined;
  const total = readNumber(source.total);
  const byStatus = readCountMap(source.by_status);
  return total !== undefined && byStatus !== undefined
    ? { total, by_status: byStatus }
    : undefined;
}

function readAssets(value: unknown): OverviewAssets | undefined {
  const source = readRecord(value);
  const counts = readNumbers(
    source,
    ["count", "storage_bytes", "referenced", "unreferenced"] as const,
  );
  if (!source || !counts) return undefined;
  // `storage_quota_bytes` is explicitly nullable on the wire: `null` means
  // "no applicable per-scope quota", which is NOT the same as a missing field.
  const quota = source.storage_quota_bytes;
  if (quota !== null && readNumber(quota) === undefined) return undefined;
  return { ...counts, storage_quota_bytes: quota === null ? null : (quota as number) };
}

function readTokens(value: unknown): OverviewTokens | undefined {
  return readNumbers(value, [
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cost_usd",
    "request_count",
    "error_count",
  ] as const);
}

function readQuotaPressure(value: unknown): OverviewQuotaPressure[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: OverviewQuotaPressure[] = [];
  for (const raw of value) {
    const source = readRecord(raw);
    const numbers = readNumbers(source, ["used", "cap", "utilization_pct"] as const);
    const scopeType = readString(source?.scope_type);
    const scopeId = readString(source?.scope_id);
    const dimension = readString(source?.dimension);
    const unit = readString(source?.unit);
    if (
      !numbers ||
      scopeType === undefined ||
      scopeId === undefined ||
      dimension === undefined ||
      unit === undefined
    ) {
      // One unreadable entry must not silently shrink the pressure list into a
      // smaller, wrong number: the whole field becomes unknown (N/A).
      return undefined;
    }
    out.push({ scope_type: scopeType, scope_id: scopeId, dimension, unit, ...numbers });
  }
  return out;
}

function readPolicyGovernance(value: unknown): OverviewPolicyGovernance | null | undefined {
  // `null` is the server's explicit "not applicable at tenant scope".
  if (value === null) return null;
  return readNumbers(value, [
    "guardrail_policy_revisions",
    "guardrail_policy_bindings",
    "quota_policies",
    "policy_rules",
  ] as const);
}

function readEvidence(value: unknown): OverviewEvidence[] {
  if (!Array.isArray(value)) return [];
  const out: OverviewEvidence[] = [];
  for (const raw of value) {
    const source = readRecord(raw);
    const id = readString(source?.id);
    if (id === undefined) continue;
    out.push({
      id,
      detail: readString(source?.detail),
      at_unix: readNumber(source?.at_unix),
      reference: readString(source?.reference),
    });
  }
  return out;
}

// --- Section parsers --------------------------------------------------------

export function parseRuntime(data: Record<string, unknown>): OverviewRuntimeData {
  return {
    providers: readEnabledCount(data.providers),
    models: readEnabledCount(data.models),
    static_api_keys: readNumber(data.static_api_keys),
    prompt_templates: readNumber(data.prompt_templates),
    upstreams: readEnabledCount(data.upstreams),
    routes: readEnabledCount(data.routes),
    plugins: readActiveCount(data.plugins),
    tools: readNumber(data.tools),
    mcp_servers: readMcpServers(data.mcp_servers),
  };
}

export function parseControlPlane(data: Record<string, unknown>): OverviewControlPlaneData {
  return {
    tenants: readNumber(data.tenants),
    projects: readNumber(data.projects),
    workspaces: readNumber(data.workspaces),
    virtual_keys: readEnabledCount(data.virtual_keys),
    assets: readAssets(data.assets),
    agent_runs: readCountByStatus(data.agent_runs),
    self_hosted_workers: readCountByStatus(data.self_hosted_workers),
    pending_tool_approvals: readNumber(data.pending_tool_approvals),
    quota_pressure: readQuotaPressure(data.quota_pressure),
    policy_governance: readPolicyGovernance(data.policy_governance),
  };
}

export function parseUsage(data: Record<string, unknown>): OverviewUsageData {
  return {
    current_period_month: readString(data.current_period_month),
    lifetime: readTokens(data.lifetime),
    current_month: readTokens(data.current_month),
  };
}

export function parseAlerts(data: Record<string, unknown>): OverviewAlertsData {
  const rawEntries = Array.isArray(data.entries) ? data.entries : [];
  const entries: OverviewAlert[] = [];
  let malformed = 0;
  for (const raw of rawEntries) {
    const source = readRecord(raw);
    const kind = readString(source?.kind);
    const severity = readString(source?.severity);
    const summary = readString(source?.summary);
    if (kind === undefined || severity === undefined || summary === undefined) {
      // An unreadable alert is COUNTED, never dropped in silence: a missing
      // alert must not read as "all clear".
      malformed += 1;
      continue;
    }
    entries.push({
      kind,
      severity,
      summary,
      count: readNumber(source?.count),
      detected_at_unix: readNumber(source?.detected_at_unix) ?? 0,
      evidence: readEvidence(source?.evidence),
      evidence_truncated: readBoolean(source?.evidence_truncated) ?? false,
    });
  }
  const sources = Array.isArray(data.unavailable_sources)
    ? data.unavailable_sources.filter((item): item is string => typeof item === "string")
    : undefined;
  return {
    total: readNumber(data.total),
    truncated: readBoolean(data.truncated),
    unavailable_sources: sources,
    entries,
    malformed_entries: malformed,
  };
}

/** A section narrowed to typed data OR an explicit unavailable state. */
export type SectionView<T> =
  | { status: "ok"; data: T; source: string; generatedAtUnix?: number }
  | { status: "unavailable"; source: string; error?: string };

/**
 * Narrow a raw overview section into a validated view. An `ok` section WITH an
 * object payload is handed to `parse`, which validates every field it claims;
 * anything else (including the contract-illegal `ok`-without-`data`) is reported
 * as `unavailable` so the caller renders an honest N/A instead of a zero.
 *
 * `parse` — not a cast — is what keeps a server-side shape change from reaching
 * a formatter as a wrong number.
 */
export function sectionView<T>(
  section: AdminOverviewSection,
  parse: (data: Record<string, unknown>) => T,
): SectionView<T> {
  if (section.status === "ok") {
    const data = readRecord(section.data);
    if (data) {
      return {
        status: "ok",
        data: parse(data),
        source: section.source,
        generatedAtUnix: section.generated_at_unix,
      };
    }
  }
  return { status: "unavailable", source: section.source, error: section.error };
}

// --- Self-hosted worker health ----------------------------------------------

/**
 * Worker status labels that mean "this worker is up and usable".
 *
 * These are the ONLY labels the gateway itself writes: registration stores
 * `registered` (crates/ferrogate-cli/src/state_agent_runtime.rs) and each
 * heartbeat overwrites it with the worker-reported label, canonically `online`
 * (crates/ferrogate-runtime/src/self_hosted_worker.rs). The aggregate stores
 * those strings verbatim — it never normalizes them.
 *
 * `active` is deliberately absent: no gateway code path produces it (the
 * gateway's own test uses it as the example of an unrecognized status), and
 * reading a non-existent `active` bucket is precisely the bug this replaces.
 * A new healthy label belongs here only once the fleet really reports it.
 */
const HEALTHY_WORKER_STATUSES = new Set(["registered", "online"]);

/**
 * Substrings that mark a status as known-unhealthy. Mirrors the gateway's own
 * `is_worker_pressure_status` (crates/ferrogate-gateway/src/server/
 * admin_overview.rs), which raises the `self_hosted_workers_unhealthy` alert.
 */
const WORKER_PRESSURE_NEEDLES = [
  "fail",
  "error",
  "timed_out",
  "timeout",
  "abort",
  "denied",
  "drain",
  "stale",
];

export type WorkerStatusClass = "healthy" | "pressure" | "unknown";

/** Classify one worker status label. Pressure wins over healthy on a compound label. */
export function classifyWorkerStatus(status: string): WorkerStatusClass {
  const lower = status.toLowerCase();
  if (WORKER_PRESSURE_NEEDLES.some((needle) => lower.includes(needle))) return "pressure";
  return HEALTHY_WORKER_STATUSES.has(lower) ? "healthy" : "unknown";
}

/**
 * Count the workers that are up, from the status histogram the gateway really
 * emits.
 *
 * Returns `undefined` — rendered N/A — when the histogram contains a label this
 * console cannot classify, because then "how many are healthy" is genuinely
 * unknown and any number would be a claim the console cannot make. An empty
 * histogram is a real zero (no workers in any state), not an unknown.
 */
export function healthyWorkerCount(
  byStatus: Record<string, number> | undefined,
): number | undefined {
  if (!byStatus) return undefined;
  let healthy = 0;
  for (const [status, count] of Object.entries(byStatus)) {
    if (count <= 0) continue;
    const classification = classifyWorkerStatus(status);
    if (classification === "unknown") return undefined;
    if (classification === "healthy") healthy += count;
  }
  return healthy;
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
