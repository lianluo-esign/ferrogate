/**
 * Placement registry for the generic control-plane document surface.
 *
 * This is deliberately a data table rather than a defaulting helper. A new
 * collection must choose a destination before the durable split store can
 * persist it; silently treating an unknown collection as control-global would
 * bypass the tenant-object boundary.
 */
export type ResourceKindPlacement = "tenant_private" | "platform_shared" | "derived";

export interface ControlPlaneResourceKind {
  readonly kind: string;
  readonly placement: ResourceKindPlacement;
}

const TENANT_PRIVATE_KINDS = [
  "tenant-accounts",
  "projects",
  "workspaces",
  "virtual-keys",
  "api-keys",
  "quota-policies",
  "agent-upstreams",
  "agent-workflows",
  "agent-schedules",
  "agent-schedule-fires",
  "agent-runs",
  "agent-run-events",
  "mcp-servers",
  "tool-approvals",
  "tool-sessions",
  "tool-session-events",
  "plugins",
  "plugin-tools",
  "skill-packages",
  "prompt-templates",
  "prompt-template-labels",
  "policies",
  "x402-spend-policies",
  "wallets",
  "wallet-ledger",
  "payment-methods",
  "payment-attempts",
  "site-domains",
  "site-domain-verifications",
  "semantic-cache-policies",
  "asset-reviews",
  "asset-deletions",
  "tenant-roles",
  "self-hosted-workers",
  "self-hosted-runs",
  "self-hosted-run-events",
  "self-hosted-run-dispatches",
  "self-hosted-worker-artifacts",
  "self-hosted-worker-checkpoints",
  "self-hosted-worker-events",
  "experiments",
  "investigations",
  "workflow-run-steps",
  "metering-events",
  "billing-outbox-dead-letters",
  "usage-reports",
  "cost-record-exports",
  "request-log-exports",
] as const;

const PLATFORM_SHARED_KINDS = [
  "plans",
  "permissions",
  "roles",
  "providers",
  "provider-models",
  "provider-health",
  "models",
  "gateway-configs",
  "framework-adapters",
  "extensions",
  "runtime-state",
  "d1_tenant_database",
  "guardrail-policies",
  "guardrail-policy-revisions",
] as const;

const DERIVED_KINDS = [
  "tenants",
  "request-logs",
  "audit-events",
  "guardrail-evaluations",
  "cost-records",
  "usage-aggregates",
  "agent-cost-burn",
  "managed-workers",
  "managed-worker-sessions",
  "self-hosted-worker-records",
  "spend-anomalies",
  "metering-export-status",
  "observed-agent-activity",
  "tools",
] as const;

export const CONTROL_PLANE_RESOURCE_KINDS: readonly ControlPlaneResourceKind[] = [
  ...TENANT_PRIVATE_KINDS.map((kind) => ({ kind, placement: "tenant_private" as const })),
  ...PLATFORM_SHARED_KINDS.map((kind) => ({ kind, placement: "platform_shared" as const })),
  ...DERIVED_KINDS.map((kind) => ({ kind, placement: "derived" as const })),
];

export const TENANT_RESOURCE_KINDS: readonly string[] = TENANT_PRIVATE_KINDS;
export const PLATFORM_RESOURCE_KINDS: readonly string[] = PLATFORM_SHARED_KINDS;
export const DERIVED_RESOURCE_KINDS: readonly string[] = DERIVED_KINDS;

/** The generic document table inside a TenantDataObject. */
export const CONTROL_RESOURCE_KIND_TABLE = "tenant_resources";

const PLACEMENTS = new Map(
  CONTROL_PLANE_RESOURCE_KINDS.map(({ kind, placement }) => [kind, placement]),
);

export function resourceKindPlacement(kind: string): ResourceKindPlacement {
  const placement = PLACEMENTS.get(kind);
  if (placement === undefined) {
    throw new Error(`unknown control-plane resource kind: ${kind}`);
  }
  return placement;
}
