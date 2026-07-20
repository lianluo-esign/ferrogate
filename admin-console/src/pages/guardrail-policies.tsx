import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { adminGet } from "@/lib/gateway-client";
import { formatUnix, type GuardrailPolicyRevisionView } from "@/lib/guardrails";

interface PolicySummary {
  policyId: string;
  active: GuardrailPolicyRevisionView | null;
  latest: GuardrailPolicyRevisionView;
  revisionCount: number;
}

/**
 * Groups the flat revision list returned by GET /admin/v1/guardrail-policies
 * into one row per policy_id (active revision when bound, else the latest).
 */
function groupByPolicy(revisions: GuardrailPolicyRevisionView[]): PolicySummary[] {
  const byPolicy = new Map<string, GuardrailPolicyRevisionView[]>();
  for (const revision of revisions) {
    const policyId = revision.policy_id ?? "";
    const bucket = byPolicy.get(policyId);
    if (bucket) bucket.push(revision);
    else byPolicy.set(policyId, [revision]);
  }
  return [...byPolicy.entries()]
    .map(([policyId, group]) => {
      const sorted = [...group].sort((a, b) => b.revision - a.revision);
      return {
        policyId,
        active: sorted.find((revision) => revision.status === "active") ?? null,
        latest: sorted[0],
        revisionCount: sorted.length,
      };
    })
    .sort((a, b) => a.policyId.localeCompare(b.policyId));
}

export default function GuardrailPoliciesPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["guardrail-policies"],
    queryFn: () => adminGet(apiKey, "/admin/v1/guardrail-policies"),
  });

  const policies = useMemo(() => groupByPolicy(data?.data ?? []), [data]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Guardrail policies</h1>
        <p className="text-sm text-muted-foreground">
          Versioned guardrail policy revisions: drafts are created, then activated one at a
          time per policy. Open a policy to inspect its revision history, activate or roll
          back a revision, and dry-run the active binding.
        </p>
      </div>

      {error && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load guardrail policies: {error.message}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Policy</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Active revision</TableHead>
              <TableHead>Revisions</TableHead>
              <TableHead>Mode</TableHead>
              <TableHead>Enforced</TableHead>
              <TableHead>Checks</TableHead>
              <TableHead>Latest change</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : policies.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  No guardrail policies yet.
                </TableCell>
              </TableRow>
            ) : (
              policies.map(({ policyId, active, latest, revisionCount }) => {
                const shown = active ?? latest;
                return (
                  <TableRow key={policyId}>
                    <TableCell>
                      <Link
                        className="font-mono text-xs underline underline-offset-2"
                        to={`/app/guardrail-policies/${encodeURIComponent(policyId)}`}
                      >
                        {policyId}
                      </Link>
                    </TableCell>
                    <TableCell>{shown.name}</TableCell>
                    <TableCell>
                      {active ? (
                        <Badge variant="secondary">r{active.revision} active</Badge>
                      ) : (
                        <Badge variant="outline">none ({latest.status})</Badge>
                      )}
                    </TableCell>
                    <TableCell>{revisionCount}</TableCell>
                    <TableCell>{shown.mode}</TableCell>
                    <TableCell>{shown.enforced ? "Yes" : "No"}</TableCell>
                    <TableCell>{shown.checks.length}</TableCell>
                    <TableCell>{formatUnix(latest.created_at_unix)}</TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
