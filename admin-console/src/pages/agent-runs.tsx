// Agent runs list (issue #317): correlation-first view over
// GET /admin/v1/agent-runs. The contract only paginates (offset/limit — see
// listAdminAgentRuns in api-types.generated.ts), so the status and tenant
// filters below narrow the fetched page client-side.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  formatUnix,
  runStatusBadgeVariant,
  tenantLabel,
  tenantMatches,
} from "@/components/agent-ops/agent-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

export type AgentRunSummary = AdminSchema<"AgentRunSummary">;

const PAGE_SIZE = 50;

const STATUS_OPTIONS: { label: string; value: string }[] = [
  { label: "All statuses", value: "all" },
  { label: "Completed", value: "completed" },
  { label: "Blocked", value: "blocked" },
  { label: "Failed", value: "failed" },
];

export default function AgentRunsPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState("all");
  const [tenantFilter, setTenantFilter] = useState("");

  const { data, isLoading, error } = useQuery({
    queryKey: ["agent-runs", offset],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/agent-runs", {
        query: { offset, limit: PAGE_SIZE },
      }),
  });

  const rows = useMemo(() => {
    const all = data?.data ?? [];
    return all.filter(
      (run) =>
        (statusFilter === "all" || run.status === statusFilter) &&
        tenantMatches(run.tenant, tenantFilter),
    );
  }, [data, statusFilter, tenantFilter]);

  const total = data?.total ?? 0;
  const hasNext = offset + PAGE_SIZE < total;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Agent runs</h1>
        <p className="text-sm text-muted-foreground">
          Governed agent runs correlated across requests, billing, audit, and agent events. Open a
          run to see its full evidence-chain timeline (#304).
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div className="grid gap-2">
          <Label htmlFor="run-status-filter">Status</Label>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger id="run-status-filter" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="run-tenant-filter">Tenant</Label>
          <Input
            id="run-tenant-filter"
            className="w-64"
            placeholder="org / project / user / key id"
            value={tenantFilter}
            onChange={(event) => setTenantFilter(event.target.value)}
          />
        </div>
      </div>

      {error && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load agent runs: {error.message}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Run</TableHead>
              <TableHead>Tenant</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Requests</TableHead>
              <TableHead className="text-right">Billing</TableHead>
              <TableHead className="text-right">Audit</TableHead>
              <TableHead className="text-right">Agent events</TableHead>
              <TableHead>First seen</TableHead>
              <TableHead>Last seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  No agent runs match.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((run) => (
                <TableRow key={run.id}>
                  <TableCell>
                    <Link
                      to={`/app/agent-runs/${encodeURIComponent(run.id)}`}
                      className="font-mono text-xs underline underline-offset-2"
                    >
                      {run.id}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{tenantLabel(run.tenant)}</TableCell>
                  <TableCell>
                    <Badge variant={runStatusBadgeVariant(run.status)}>{run.status}</Badge>
                  </TableCell>
                  <TableCell className="text-right">{run.request_count}</TableCell>
                  <TableCell className="text-right">{run.billing_event_count}</TableCell>
                  <TableCell className="text-right">{run.audit_event_count}</TableCell>
                  <TableCell className="text-right">{run.agent_event_count}</TableCell>
                  <TableCell className="text-xs">{formatUnix(run.first_seen_unix)}</TableCell>
                  <TableCell className="text-xs">{formatUnix(run.last_seen_unix)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!hasNext}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </Button>
        <span className="text-xs text-muted-foreground">
          {total > 0 ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}` : ""}
        </span>
      </div>
    </div>
  );
}
