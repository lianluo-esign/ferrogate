import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  DollarSign,
  Server,
  ShieldAlert,
} from "lucide-react";
import type { ReactNode } from "react";
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
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ProviderHealthCheck = AdminSchema<"ProviderHealthCheck">;
type RequestLog = AdminSchema<"RequestLog">;
type UsageReport = AdminSchema<"AdminUsageReportRow">;

const NUMBER_FORMAT = new Intl.NumberFormat();
const COST_FORMAT = new Intl.NumberFormat(undefined, {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 2,
  maximumFractionDigits: 4,
});
const TIME_FORMAT = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

function formatUpdatedAt(updatedAt: number): string {
  return updatedAt > 0 ? `Updated ${TIME_FORMAT.format(updatedAt)}` : "Waiting for data";
}

function formatUnix(timestamp?: number | null): string {
  return timestamp ? TIME_FORMAT.format(timestamp * 1000) : "-";
}

function providerIsHealthy(provider: ProviderHealthCheck): boolean {
  return (
    !provider.enabled ||
    (provider.reachable && !provider.circuit_open && provider.status.toLowerCase() === "ok")
  );
}

function selectUsageReport(rows: UsageReport[], tenantId?: string): UsageReport | undefined {
  const sorted = [...rows].sort((left, right) =>
    (right.period_month ?? "").localeCompare(left.period_month ?? ""),
  );
  return sorted.find((row) => row.scope_id === tenantId) ?? sorted[0];
}

function QueryState({
  error,
  isLoading,
  empty,
  loadingLabel,
  emptyLabel,
}: {
  error: unknown;
  isLoading: boolean;
  empty: boolean;
  loadingLabel: string;
  emptyLabel: string;
}) {
  if (error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        Unable to load: {(error as Error).message}
      </p>
    );
  }
  if (isLoading) return <p className="text-sm text-muted-foreground">{loadingLabel}</p>;
  if (empty) return <p className="text-sm text-muted-foreground">{emptyLabel}</p>;
  return null;
}

function Metric({
  icon,
  label,
  value,
  detail,
  tone = "default",
}: {
  icon: ReactNode;
  label: string;
  value: ReactNode;
  detail: string;
  tone?: "default" | "danger";
}) {
  return (
    <div className="min-w-0 bg-background px-3 py-3 sm:px-4">
      <dt className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
        {icon}
        {label}
      </dt>
      <dd
        className={`mt-2 text-xl font-semibold tabular-nums ${
          tone === "danger" ? "text-destructive" : "text-foreground"
        }`}
      >
        {value}
      </dd>
      <p className="mt-1 truncate text-xs text-muted-foreground" title={detail}>
        {detail}
      </p>
    </div>
  );
}

function SectionHeader({
  title,
  description,
  updatedAt,
  href,
  linkLabel,
}: {
  title: string;
  description: string;
  updatedAt: number;
  href: string;
  linkLabel: string;
}) {
  return (
    <div className="flex flex-col gap-2 border-b pb-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <div className="flex items-center justify-between gap-4 sm:justify-end">
        <span className="text-xs text-muted-foreground">{formatUpdatedAt(updatedAt)}</span>
        <Link
          to={href}
          className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
        >
          {linkLabel}
          <ArrowRight className="size-3.5" aria-hidden="true" />
        </Link>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const statusQuery = useQuery({
    queryKey: ["dashboard", "status"],
    queryFn: () => adminGet(apiKey, "/admin/v1/status"),
    refetchInterval: 10_000,
  });
  const providersQuery = useQuery({
    queryKey: ["dashboard", "provider-health"],
    queryFn: () => adminGet(apiKey, "/admin/v1/provider-health"),
    refetchInterval: 15_000,
  });
  const approvalsQuery = useQuery({
    queryKey: ["dashboard", "tool-approvals"],
    queryFn: () => adminGet(apiKey, "/admin/v1/tool-approvals"),
    refetchInterval: 15_000,
  });
  const requestsQuery = useQuery({
    queryKey: ["dashboard", "request-logs"],
    queryFn: () => adminGet(apiKey, "/admin/v1/request-logs"),
    refetchInterval: 15_000,
  });
  const usageQuery = useQuery({
    queryKey: ["dashboard", "usage-reports"],
    queryFn: () => adminGet(apiKey, "/admin/v1/usage-reports"),
    refetchInterval: 60_000,
  });

  const status = statusQuery.data;
  const clusterReady = Boolean(
    status?.cluster.ready &&
      status.cluster.accepting_new_requests &&
      !status.cluster.draining &&
      !status.cluster.stale,
  );
  const providers = providersQuery.data?.data ?? [];
  const enabledProviders = providers.filter((provider) => provider.enabled);
  const unhealthyProviders = enabledProviders.filter((provider) => !providerIsHealthy(provider));
  const pendingApprovals = (approvalsQuery.data?.data ?? []).filter(
    (approval) => approval.status === "pending",
  );
  const requests = [...(requestsQuery.data?.data ?? [])]
    .sort((left, right) => (right.started_at_unix ?? 0) - (left.started_at_unix ?? 0))
    .slice(0, 6);
  const failedRequests = requests.filter((request) => (request.status_code ?? 0) >= 400);
  const usage = selectUsageReport(usageQuery.data?.data ?? [], session?.tenant.id);

  const attentionItems = [
    statusQuery.error
      ? {
          key: "status-error",
          label: "Gateway readiness is unknown because the status check failed.",
          href: "/app/ops/status",
        }
      : status && !clusterReady
        ? {
            key: "cluster",
            label: `Gateway is not ready: ${status.cluster.readiness_reason}.`,
            href: "/app/ops/status",
          }
        : null,
    providersQuery.error
      ? {
          key: "providers-error",
          label: `Provider health is unavailable: ${(providersQuery.error as Error).message}.`,
          href: "/app/ops/provider-health",
        }
      : unhealthyProviders.length > 0
        ? {
            key: "providers",
            label: `${unhealthyProviders.length} provider${unhealthyProviders.length === 1 ? "" : "s"} need attention.`,
            href: "/app/ops/provider-health",
          }
        : null,
    approvalsQuery.error
      ? {
          key: "approvals-error",
          label: `Pending approvals could not be checked: ${(approvalsQuery.error as Error).message}.`,
          href: "/app/tool-approvals",
        }
      : pendingApprovals.length > 0
        ? {
            key: "approvals",
            label: `${pendingApprovals.length} tool approval${pendingApprovals.length === 1 ? "" : "s"} waiting for review.`,
            href: "/app/tool-approvals",
          }
        : null,
  ].filter((item): item is NonNullable<typeof item> => item !== null);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold">Operations overview</h1>
          <p className="text-sm text-muted-foreground">
            Live gateway posture and operator actions for {session?.tenant.name}.
          </p>
        </div>
        <Badge variant="outline" className="w-fit font-normal">
          {session?.tenant.role}
        </Badge>
      </header>

      <section aria-labelledby="gateway-posture-heading">
        <div className="flex items-center justify-between border-b pb-3">
          <div>
            <h2 id="gateway-posture-heading" className="text-sm font-semibold">
              Gateway posture
            </h2>
            <p className="text-xs text-muted-foreground">
              Independent live checks; unknown data is never treated as healthy.
            </p>
          </div>
          <span className="hidden text-xs text-muted-foreground sm:block">
            {formatUpdatedAt(Math.max(statusQuery.dataUpdatedAt, providersQuery.dataUpdatedAt))}
          </span>
        </div>
        <dl className="grid grid-cols-2 gap-px border-b sm:grid-cols-3 lg:grid-cols-5 [&>*:last-child]:col-span-2 lg:[&>*:last-child]:col-span-1">
          <Metric
            icon={clusterReady ? <CheckCircle2 className="size-4" /> : <AlertTriangle className="size-4" />}
            label="Gateway state"
            value={statusQuery.isLoading ? "Checking" : statusQuery.error ? "Unknown" : clusterReady ? "Ready" : "Attention"}
            detail={status ? `Snapshot ${status.snapshot}` : "Status endpoint"}
            tone={!statusQuery.isLoading && (!clusterReady || Boolean(statusQuery.error)) ? "danger" : "default"}
          />
          <Metric
            icon={<Server className="size-4" />}
            label="Provider health"
            value={providersQuery.isLoading ? "Checking" : providersQuery.error ? "Unknown" : `${enabledProviders.length - unhealthyProviders.length} / ${enabledProviders.length}`}
            detail="healthy / enabled"
            tone={providersQuery.error || unhealthyProviders.length > 0 ? "danger" : "default"}
          />
          <Metric
            icon={<ShieldAlert className="size-4" />}
            label="Pending approvals"
            value={approvalsQuery.isLoading ? "Checking" : approvalsQuery.error ? "Unknown" : NUMBER_FORMAT.format(pendingApprovals.length)}
            detail="human review required"
            tone={approvalsQuery.error || pendingApprovals.length > 0 ? "danger" : "default"}
          />
          <Metric
            icon={<Activity className="size-4" />}
            label="Recent requests"
            value={requestsQuery.isLoading ? "Checking" : requestsQuery.error ? "Unknown" : NUMBER_FORMAT.format(requestsQuery.data?.total ?? requests.length)}
            detail={requestsQuery.error ? "Request logs unavailable" : `${failedRequests.length} failures in latest ${requests.length}`}
            tone={requestsQuery.error || failedRequests.length > 0 ? "danger" : "default"}
          />
          <Metric
            icon={<DollarSign className="size-4" />}
            label="Latest cost"
            value={usageQuery.isLoading ? "Checking" : usageQuery.error ? "Unknown" : usage ? COST_FORMAT.format(usage.cost_usd) : "No data"}
            detail={usage?.period_month ?? "Usage report"}
            tone={usageQuery.error ? "danger" : "default"}
          />
        </dl>
      </section>

      <section aria-labelledby="attention-heading">
        <div className="mb-3 flex items-center justify-between">
          <h2 id="attention-heading" className="text-sm font-semibold">
            Needs attention
          </h2>
          <span className="text-xs tabular-nums text-muted-foreground">
            {attentionItems.length} active
          </span>
        </div>
        <div className="divide-y rounded-md border">
          {attentionItems.length === 0 ? (
            <div className="flex items-center gap-2 px-3 py-3 text-sm">
              <CheckCircle2 className="size-4 text-emerald-600" aria-hidden="true" />
              No active gateway, provider, or approval alerts.
            </div>
          ) : (
            attentionItems.map((item) => (
              <Link
                key={item.key}
                to={item.href}
                className="flex min-h-11 items-center justify-between gap-3 px-3 py-2 text-sm hover:bg-muted/50"
              >
                <span className="flex min-w-0 items-center gap-2">
                  <AlertTriangle className="size-4 shrink-0 text-destructive" aria-hidden="true" />
                  <span>{item.label}</span>
                </span>
                <ArrowRight className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              </Link>
            ))
          )}
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(18rem,1fr)]">
        <section aria-labelledby="recent-requests-heading" className="min-w-0">
          <SectionHeader
            title="Recent requests"
            description="Latest retained gateway traffic and failures."
            updatedAt={requestsQuery.dataUpdatedAt}
            href="/app/request-logs"
            linkLabel="View logs"
          />
          <div className="mt-3 overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Request</TableHead>
                  <TableHead>Provider / model</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Started</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {requestsQuery.error || requestsQuery.isLoading || requests.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="h-24 text-center">
                      <QueryState
                        error={requestsQuery.error}
                        isLoading={requestsQuery.isLoading}
                        empty={requests.length === 0}
                        loadingLabel="Loading recent requests..."
                        emptyLabel="No retained requests yet."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  requests.map((request: RequestLog, index) => (
                    <TableRow key={request.request_id ?? `request-${index}`}>
                      <TableCell>
                        <span className="block max-w-40 truncate font-mono text-xs" title={request.request_id}>
                          {request.request_id ?? "-"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="block text-sm">{request.provider ?? "-"}</span>
                        <span className="block max-w-44 truncate text-xs text-muted-foreground" title={request.logical_model ?? undefined}>
                          {request.logical_model ?? "unmapped model"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={(request.status_code ?? 0) >= 400 ? "destructive" : "secondary"}>
                          {request.status_code ?? "pending"}
                        </Badge>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {formatUnix(request.started_at_unix)}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </section>

        <section aria-labelledby="usage-heading">
          <SectionHeader
            title="Usage and cost"
            description="Latest tenant-preferred usage rollup."
            updatedAt={usageQuery.dataUpdatedAt}
            href="/app/usage-reports"
            linkLabel="View reports"
          />
          <div className="mt-3">
            <QueryState
              error={usageQuery.error}
              isLoading={usageQuery.isLoading}
              empty={!usage}
              loadingLabel="Loading usage report..."
              emptyLabel="No usage report is available yet."
            />
            {usage ? (
              <dl className="divide-y rounded-md border px-3">
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="flex items-center gap-2 text-sm text-muted-foreground">
                    <DollarSign className="size-4" aria-hidden="true" /> Cost
                  </dt>
                  <dd className="font-semibold tabular-nums">{COST_FORMAT.format(usage.cost_usd)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="text-sm text-muted-foreground">Requests</dt>
                  <dd className="tabular-nums">{NUMBER_FORMAT.format(usage.request_count)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="text-sm text-muted-foreground">Tokens</dt>
                  <dd className="tabular-nums">{NUMBER_FORMAT.format(usage.total_tokens)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="text-sm text-muted-foreground">Errors</dt>
                  <dd className="tabular-nums">{NUMBER_FORMAT.format(usage.error_count)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3 text-xs text-muted-foreground">
                  <dt className="flex items-center gap-2">
                    <Clock3 className="size-3.5" aria-hidden="true" /> Period
                  </dt>
                  <dd>{usage.period_month ?? "Latest"}</dd>
                </div>
              </dl>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}
