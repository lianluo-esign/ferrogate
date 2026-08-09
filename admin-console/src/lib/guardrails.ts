// Shared types + formatters for the guardrails control-plane pages (#316).
//
// All row/response shapes are derived from the generated OpenAPI contract
// (src/lib/api-types.generated.ts): if docs/openapi/admin-api.openapi.json
// changes a guardrail schema, these pages stop type-checking.
import type { AdminSchema } from "@/lib/gateway-client";

export type GuardrailPolicyRevisionView = AdminSchema<"GuardrailPolicyRevisionView">;
export type GuardrailPolicyBindingResponse = AdminSchema<"GuardrailPolicyBindingResponse">;
export type GuardrailPolicyDryRunResponse = AdminSchema<"GuardrailPolicyDryRunResponse">;
export type GuardrailPolicyAction = AdminSchema<"GuardrailPolicyAction">;
export type GuardrailEvaluationView = AdminSchema<"GuardrailEvaluationView">;
export type GuardrailInvestigationTimeline = AdminSchema<"GuardrailInvestigationTimeline">;
export type InvestigationActionCorrelation = AdminSchema<"InvestigationActionCorrelation">;

/** Renders a unix-seconds timestamp as a compact UTC string ("—" when absent). */
export function formatUnix(ts: number | null | undefined): string {
  if (ts === null || ts === undefined) return "—";
  return `${new Date(ts * 1000).toISOString().slice(0, 19).replace("T", " ")}Z`;
}

/** Truncates a "sha256:<hex>" fingerprint for table cells ("—" when absent). */
export function shortFingerprint(fingerprint: string | null | undefined): string {
  if (!fingerprint) return "—";
  return fingerprint.length > 20 ? `${fingerprint.slice(0, 20)}…` : fingerprint;
}

/** "block (pii_detected), record" summary of a policy action list. */
export function describeActions(actions: GuardrailPolicyAction[]): string {
  if (actions.length === 0) return "—";
  return actions
    .map((action) => (action.code ? `${action.kind} (${action.code})` : action.kind))
    .join(", ");
}

/** Badge variant for a guardrail verdict / decision-ish value. */
export function verdictVariant(
  value: string | null | undefined,
): "default" | "secondary" | "destructive" | "outline" {
  switch (value) {
    case "pass":
    case "allow":
    case "succeeded":
      return "secondary";
    case "fail":
    case "deny":
    case "block":
    case "blocked":
    case "failed":
      return "destructive";
    case "error":
    case "degrade":
    case "ask":
      return "default";
    default:
      return "outline";
  }
}
