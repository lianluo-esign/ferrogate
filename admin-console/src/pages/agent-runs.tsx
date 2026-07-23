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
import { useI18n } from "@/i18n";
import type { TranslationKey } from "@/i18n";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

export type AgentRunSummary = AdminSchema<"AgentRunSummary">;

const PAGE_SIZE = 50;

// Option labels resolve through the catalog at render time; `value` is the raw
// contract status token matched against `run.status`.
const STATUS_OPTIONS: { labelKey: TranslationKey; value: string }[] = [
  { labelKey: "page.agentRuns.status.all", value: "all" },
  { labelKey: "page.agentRuns.status.completed", value: "completed" },
  { labelKey: "page.agentRuns.status.blocked", value: "blocked" },
  { labelKey: "page.agentRuns.status.failed", value: "failed" },
];

export default function AgentRunsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
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
        <h1 className="text-lg font-semibold">{t("page.agentRuns.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.agentRuns.description")}
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div className="grid gap-2">
          <Label htmlFor="run-status-filter">{t("common.status")}</Label>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger id="run-status-filter" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {t(option.labelKey)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="run-tenant-filter">{t("common.tenant")}</Label>
          <Input
            id="run-tenant-filter"
            className="w-64"
            placeholder={t("page.agentRuns.filter.tenantPlaceholder")}
            value={tenantFilter}
            onChange={(event) => setTenantFilter(event.target.value)}
          />
        </div>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.agentRuns.loadError", { message: error.message })}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.agentRuns.col.run")}</TableHead>
              <TableHead>{t("common.tenant")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
              <TableHead className="text-right">{t("page.agentRuns.col.requests")}</TableHead>
              <TableHead className="text-right">{t("page.agentRuns.col.billing")}</TableHead>
              <TableHead className="text-right">{t("page.agentRuns.col.audit")}</TableHead>
              <TableHead className="text-right">{t("page.agentRuns.col.agentEvents")}</TableHead>
              <TableHead>{t("page.agentRuns.col.firstSeen")}</TableHead>
              <TableHead>{t("page.agentRuns.col.lastSeen")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  {t("page.agentRuns.empty")}
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
          {t("resource.pagination.previous")}
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!hasNext}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          {t("resource.pagination.next")}
        </Button>
        <span className="text-xs text-muted-foreground">
          {total > 0
            ? t("page.agentRuns.pagination.range", {
                start: offset + 1,
                end: Math.min(offset + PAGE_SIZE, total),
                total,
              })
            : ""}
        </span>
      </div>
    </div>
  );
}
