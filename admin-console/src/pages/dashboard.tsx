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
import { useI18n } from "@/i18n";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ProviderHealthCheck = AdminSchema<"ProviderHealthCheck">;
type RequestLog = AdminSchema<"RequestLog">;
type UsageReport = AdminSchema<"AdminUsageReportRow">;

// Compact absolute timestamp used for "Updated …" chrome and the request table.
const TIMESTAMP_OPTIONS: Intl.DateTimeFormatOptions = {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
};

// USD cost is displayed with up to four fraction digits so sub-cent rollups
// stay visible; localized via the shared currency formatter (#348).
const COST_OPTIONS: Intl.NumberFormatOptions = {
  minimumFractionDigits: 2,
  maximumFractionDigits: 4,
};

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
  errorLabel,
}: {
  error: unknown;
  isLoading: boolean;
  empty: boolean;
  loadingLabel: string;
  emptyLabel: string;
  errorLabel: string;
}) {
  if (error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {errorLabel}
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
      <dd className="mt-1 truncate text-xs text-muted-foreground" title={detail}>
        {detail}
      </dd>
    </div>
  );
}

function SectionHeader({
  title,
  description,
  updatedLabel,
  href,
  linkLabel,
}: {
  title: string;
  description: string;
  updatedLabel: string;
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
        <span className="text-xs text-muted-foreground">{updatedLabel}</span>
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
  const { t, format } = useI18n();
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const formatUnix = (timestamp?: number | null): string =>
    timestamp ? format.date(timestamp * 1000, TIMESTAMP_OPTIONS) : "-";

  const formatUpdatedAt = (updatedAt: number): string =>
    updatedAt > 0
      ? t("dashboard.updatedAt", { time: format.date(updatedAt, TIMESTAMP_OPTIONS) })
      : t("dashboard.waitingForData");

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
          label: t("dashboard.alert.statusError"),
          href: "/app/ops/status",
        }
      : status && !clusterReady
        ? {
            key: "cluster",
            label: t("dashboard.alert.clusterNotReady", {
              reason: status.cluster.readiness_reason,
            }),
            href: "/app/ops/status",
          }
        : null,
    providersQuery.error
      ? {
          key: "providers-error",
          label: t("dashboard.alert.providersError", {
            message: (providersQuery.error as Error).message,
          }),
          href: "/app/ops/provider-health",
        }
      : unhealthyProviders.length > 0
        ? {
            key: "providers",
            label: format.plural(unhealthyProviders.length, {
              one: t("dashboard.alert.providersUnhealthy.one", {
                count: unhealthyProviders.length,
              }),
              other: t("dashboard.alert.providersUnhealthy.other", {
                count: unhealthyProviders.length,
              }),
            }),
            href: "/app/ops/provider-health",
          }
        : null,
    approvalsQuery.error
      ? {
          key: "approvals-error",
          label: t("dashboard.alert.approvalsError", {
            message: (approvalsQuery.error as Error).message,
          }),
          href: "/app/tool-approvals",
        }
      : pendingApprovals.length > 0
        ? {
            key: "approvals",
            label: format.plural(pendingApprovals.length, {
              one: t("dashboard.alert.approvalsPending.one", {
                count: pendingApprovals.length,
              }),
              other: t("dashboard.alert.approvalsPending.other", {
                count: pendingApprovals.length,
              }),
            }),
            href: "/app/tool-approvals",
          }
        : null,
  ].filter((item): item is NonNullable<typeof item> => item !== null);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold">{t("dashboard.title")}</h1>
          <p className="text-sm text-muted-foreground">
            {t("dashboard.subtitle", { name: session?.tenant.name ?? "" })}
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
              {t("dashboard.posture.title")}
            </h2>
            <p className="text-xs text-muted-foreground">
              {t("dashboard.posture.description")}
            </p>
          </div>
          <span className="hidden text-xs text-muted-foreground sm:block">
            {formatUpdatedAt(Math.max(statusQuery.dataUpdatedAt, providersQuery.dataUpdatedAt))}
          </span>
        </div>
        <dl className="grid grid-cols-2 gap-px border-b sm:grid-cols-3 lg:grid-cols-5 [&>*:last-child]:col-span-2 lg:[&>*:last-child]:col-span-1">
          <Metric
            icon={clusterReady ? <CheckCircle2 className="size-4" /> : <AlertTriangle className="size-4" />}
            label={t("dashboard.metric.gatewayState")}
            value={statusQuery.isLoading ? t("common.checking") : statusQuery.error ? t("common.unknown") : clusterReady ? t("dashboard.state.ready") : t("dashboard.state.attention")}
            detail={status ? t("dashboard.metric.snapshot", { snapshot: status.snapshot }) : t("dashboard.metric.statusEndpoint")}
            tone={!statusQuery.isLoading && (!clusterReady || Boolean(statusQuery.error)) ? "danger" : "default"}
          />
          <Metric
            icon={<Server className="size-4" />}
            label={t("dashboard.metric.providerHealth")}
            value={providersQuery.isLoading ? t("common.checking") : providersQuery.error ? t("common.unknown") : `${format.number(enabledProviders.length - unhealthyProviders.length)} / ${format.number(enabledProviders.length)}`}
            detail={t("dashboard.metric.healthyEnabled")}
            tone={providersQuery.error || unhealthyProviders.length > 0 ? "danger" : "default"}
          />
          <Metric
            icon={<ShieldAlert className="size-4" />}
            label={t("dashboard.metric.pendingApprovals")}
            value={approvalsQuery.isLoading ? t("common.checking") : approvalsQuery.error ? t("common.unknown") : format.number(pendingApprovals.length)}
            detail={t("dashboard.metric.humanReview")}
            tone={approvalsQuery.error || pendingApprovals.length > 0 ? "danger" : "default"}
          />
          <Metric
            icon={<Activity className="size-4" />}
            label={t("dashboard.metric.recentRequests")}
            value={requestsQuery.isLoading ? t("common.checking") : requestsQuery.error ? t("common.unknown") : format.number(requestsQuery.data?.total ?? requests.length)}
            detail={requestsQuery.error ? t("dashboard.metric.requestsUnavailable") : t("dashboard.metric.failuresInLatest", { failures: failedRequests.length, count: requests.length })}
            tone={requestsQuery.error || failedRequests.length > 0 ? "danger" : "default"}
          />
          <Metric
            icon={<DollarSign className="size-4" />}
            label={t("dashboard.metric.latestCost")}
            value={usageQuery.isLoading ? t("common.checking") : usageQuery.error ? t("common.unknown") : usage ? format.currency(usage.cost_usd, "USD", COST_OPTIONS) : t("common.noData")}
            detail={usage?.period_month ?? t("dashboard.metric.usageReport")}
            tone={usageQuery.error ? "danger" : "default"}
          />
        </dl>
      </section>

      <section aria-labelledby="attention-heading">
        <div className="mb-3 flex items-center justify-between">
          <h2 id="attention-heading" className="text-sm font-semibold">
            {t("dashboard.attention.title")}
          </h2>
          <span className="text-xs tabular-nums text-muted-foreground">
            {t("dashboard.attention.active", { count: format.number(attentionItems.length) })}
          </span>
        </div>
        <div className="divide-y rounded-md border">
          {attentionItems.length === 0 ? (
            <div className="flex items-center gap-2 px-3 py-3 text-sm">
              <CheckCircle2 className="size-4 text-emerald-600" aria-hidden="true" />
              {t("dashboard.attention.empty")}
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
            title={t("dashboard.requests.title")}
            description={t("dashboard.requests.description")}
            updatedLabel={formatUpdatedAt(requestsQuery.dataUpdatedAt)}
            href="/app/request-logs"
            linkLabel={t("dashboard.requests.viewLogs")}
          />
          <div className="mt-3 overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("dashboard.requests.colRequest")}</TableHead>
                  <TableHead>{t("dashboard.requests.colProviderModel")}</TableHead>
                  <TableHead>{t("common.status")}</TableHead>
                  <TableHead>{t("dashboard.requests.colStarted")}</TableHead>
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
                        loadingLabel={t("dashboard.requests.loading")}
                        emptyLabel={t("dashboard.requests.empty")}
                        errorLabel={
                          requestsQuery.error
                            ? t("common.unableToLoad", {
                                message: (requestsQuery.error as Error).message,
                              })
                            : ""
                        }
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
                          {request.logical_model ?? t("dashboard.requests.unmappedModel")}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={(request.status_code ?? 0) >= 400 ? "destructive" : "secondary"}>
                          {request.status_code ?? t("common.pending")}
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
            title={t("dashboard.usage.title")}
            description={t("dashboard.usage.description")}
            updatedLabel={formatUpdatedAt(usageQuery.dataUpdatedAt)}
            href="/app/usage-reports"
            linkLabel={t("dashboard.usage.viewReports")}
          />
          <div className="mt-3">
            <QueryState
              error={usageQuery.error}
              isLoading={usageQuery.isLoading}
              empty={!usage}
              loadingLabel={t("dashboard.usage.loading")}
              emptyLabel={t("dashboard.usage.empty")}
              errorLabel={
                usageQuery.error
                  ? t("common.unableToLoad", {
                      message: (usageQuery.error as Error).message,
                    })
                  : ""
              }
            />
            {usage ? (
              <dl className="divide-y rounded-md border px-3">
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="flex items-center gap-2 text-sm text-muted-foreground">
                    <DollarSign className="size-4" aria-hidden="true" /> {t("dashboard.usage.cost")}
                  </dt>
                  <dd className="font-semibold tabular-nums">{format.currency(usage.cost_usd, "USD", COST_OPTIONS)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="text-sm text-muted-foreground">{t("dashboard.usage.requests")}</dt>
                  <dd className="tabular-nums">{format.number(usage.request_count)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="text-sm text-muted-foreground">{t("dashboard.usage.tokens")}</dt>
                  <dd className="tabular-nums">{format.tokens(usage.total_tokens)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3">
                  <dt className="text-sm text-muted-foreground">{t("dashboard.usage.errors")}</dt>
                  <dd className="tabular-nums">{format.number(usage.error_count)}</dd>
                </div>
                <div className="flex items-center justify-between gap-4 py-3 text-xs text-muted-foreground">
                  <dt className="flex items-center gap-2">
                    <Clock3 className="size-3.5" aria-hidden="true" /> {t("dashboard.usage.period")}
                  </dt>
                  <dd>{usage.period_month ?? t("dashboard.usage.latest")}</dd>
                </div>
              </dl>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}
