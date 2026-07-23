// Shared building blocks for the Agent Ops pages (issue #317): evidence-chain
// badges for run/timeline rendering plus fingerprint truncation + copy.
//
// Timeline event "families" follow the stored `kind` conventions from
// crates/ferrogate-cli/src/gateway/agent_runs.rs: capability evidence rows are
// `capability.<outcome>`, guardrail evidence rows are `guardrail.*`, and the
// remaining lifecycle rows are `run_started` / `turn_started` /
// `tool_call_requested` / `tool_call_completed` / `run_completed` /
// `run_stopped`. Audit events come from the timeline's separate
// `audit_events` array and are rendered as the `audit` family.
import { Copy } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useI18n, type I18nContextValue } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";

export type TimelineEventFamily = "capability" | "guardrail" | "audit" | "lifecycle";

export function eventFamily(kind: string): TimelineEventFamily {
  if (kind === "audit" || kind.startsWith("audit.")) return "audit";
  if (kind.startsWith("capability")) return "capability";
  if (kind.startsWith("guardrail")) return "guardrail";
  return "lifecycle";
}

const FAMILY_CLASSES: Record<TimelineEventFamily, string> = {
  capability: "border-transparent bg-blue-100 text-blue-900 dark:bg-blue-950 dark:text-blue-200",
  guardrail: "border-transparent bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200",
  audit: "border-transparent bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200",
  lifecycle: "border-transparent bg-muted text-muted-foreground",
};

/** Colored family badge distinguishing capability/guardrail/audit/lifecycle rows. */
export function EventFamilyBadge({ family }: { family: TimelineEventFamily }) {
  return <Badge className={FAMILY_CLASSES[family]}>{family}</Badge>;
}

/** Issue #304 canonical governance decision class: allow | deny | ask | degrade. */
export function DecisionBadge({ decision }: { decision: string | null | undefined }) {
  if (!decision) return <span className="text-muted-foreground">—</span>;
  const classes =
    decision === "allow"
      ? "border-transparent bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200"
      : decision === "deny"
        ? "border-transparent bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-200"
        : "border-transparent bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200";
  return <Badge className={classes}>{decision}</Badge>;
}

export function runStatusBadgeVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "completed":
      return "secondary";
    case "blocked":
    case "failed":
      return "destructive";
    default:
      return "outline";
  }
}

export function fireOutcomeBadgeVariant(
  outcome: AdminSchema<"AdminAgentScheduleFire">["outcome"],
): "default" | "secondary" | "destructive" | "outline" {
  switch (outcome) {
    case "dispatched":
      return "secondary";
    case "error":
      return "destructive";
    default:
      return "outline";
  }
}

export function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "—";
  return new Date(unix * 1000).toISOString().replace("T", " ").replace(".000Z", "Z");
}

/** Compact tenant label from a TenantContext (first non-null scope id). */
export function tenantLabel(tenant: AdminSchema<"TenantContext"> | undefined): string {
  if (!tenant) return "—";
  return (
    tenant.organization_id ??
    tenant.project_id ??
    tenant.team_id ??
    tenant.user_id ??
    tenant.api_key_id ??
    "—"
  );
}

/** True when any TenantContext scope id contains the filter text. */
export function tenantMatches(
  tenant: AdminSchema<"TenantContext"> | undefined,
  filter: string,
): boolean {
  const needle = filter.trim().toLowerCase();
  if (!needle) return true;
  if (!tenant) return false;
  return [
    tenant.organization_id,
    tenant.team_id,
    tenant.project_id,
    tenant.user_id,
    tenant.api_key_id,
  ].some((id) => id?.toLowerCase().includes(needle));
}

async function copyToClipboard(value: string, label: string, t: I18nContextValue["t"]) {
  try {
    await navigator.clipboard.writeText(value);
    toast.success(t("common.copied", { label }));
  } catch {
    toast.error(t("common.copyFailed"));
  }
}

/**
 * Truncated monospace value (fingerprints, request/trace ids) with a
 * copy-full-value button. `sha256:<hex>` fingerprints keep the scheme prefix
 * plus the first hex chars so two fingerprints stay visually comparable.
 */
export function TruncatedCopyable({
  value,
  label,
  prefixLength = 18,
}: {
  value: string | null | undefined;
  label: string;
  prefixLength?: number;
}) {
  const { t } = useI18n();
  if (!value) return <span className="text-muted-foreground">—</span>;
  const shown = value.length > prefixLength ? `${value.slice(0, prefixLength)}…` : value;
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      <span className="font-mono text-xs" title={value}>
        {shown}
      </span>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="h-5 w-5"
        aria-label={t("common.copyLabel", { label })}
        onClick={() => void copyToClipboard(value, label, t)}
      >
        <Copy className="h-3 w-3" />
      </Button>
    </span>
  );
}
