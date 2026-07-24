// Global control-plane cockpit (issue #343).
//
// The landing dashboard is the operator's resource + utilization overview. It
// consumes the SCOPED, single-request GET /admin/v1/overview contract (#339) —
// so it never fans out across every resource list or counts paginated pages in
// the browser — and lays the response out as three quiet, dense bands:
//   1. Traffic + cost + core runtime counts (first viewport), with an explicit
//      lifetime-vs-current-month period toggle preserved in the URL.
//   2. A prioritized alerts region (provider/MCP/run/worker + any unavailable
//      overview section), each with evidence + a link to its source page.
//   3. A resource inventory grouped by control-plane domain, each row linking to
//      its filtered management view.
//
// Honesty rules (from the contract): a failed SECTION stays visible as a partial
// error and never blanks the healthy sections; unavailable and not-applicable
// are rendered DISTINCT from a real zero; polling is bounded and pauses on a
// backgrounded tab.
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bot,
  Boxes,
  CheckCircle2,
  Coins,
  DollarSign,
  HardDrive,
  Network,
  Server,
} from "lucide-react";
import type { ComponentType, ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
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
import { useVisibilityPolling } from "@/hooks/use-visibility-polling";
import { useI18n } from "@/i18n";
import type { TranslationKey } from "@/i18n";
import { APP_ROUTES } from "@/lib/app-routes";
import { adminGet } from "@/lib/gateway-client";
import {
  alertSeverityRank,
  sectionView,
  type OverviewAlert,
  type OverviewControlPlaneData,
  type OverviewEvidence,
  type OverviewRuntimeData,
  type OverviewUsageData,
} from "@/lib/overview";

// Bounded polling cadence and the age past which the overview is flagged stale.
const POLL_INTERVAL_MS = 30_000;
const STALE_AFTER_SECONDS = 120;
const MAX_EVIDENCE_CHIPS = 3;

// USD with up to four fraction digits so sub-cent rollups stay visible.
const COST_OPTIONS: Intl.NumberFormatOptions = {
  minimumFractionDigits: 2,
  maximumFractionDigits: 4,
};

const RELATIVE_TIME: Intl.DateTimeFormatOptions = {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
};

type Period = "lifetime" | "month";

// Console routes an alert kind pivots to (filtered where the target supports it).
const ALERT_ROUTE: Record<string, string> = {
  provider_unhealthy: APP_ROUTES.operationsProviderHealth,
  mcp_server_disconnected: "/app/mcp-servers",
  agent_runs_failed: `${APP_ROUTES.agentRuns}?status=failed`,
  self_hosted_workers_unhealthy: APP_ROUTES.selfHostedWorkerOperations,
};

const ALERT_KIND_LABEL: Record<string, TranslationKey> = {
  provider_unhealthy: "dashboard.alert.kind.provider_unhealthy",
  mcp_server_disconnected: "dashboard.alert.kind.mcp_server_disconnected",
  agent_runs_failed: "dashboard.alert.kind.agent_runs_failed",
  self_hosted_workers_unhealthy: "dashboard.alert.kind.self_hosted_workers_unhealthy",
  section_unavailable: "dashboard.alert.kind.section_unavailable",
};

const SEVERITY_LABEL: Record<string, TranslationKey> = {
  critical: "dashboard.severity.critical",
  warning: "dashboard.severity.warning",
  info: "dashboard.severity.info",
};

/** A normalized alert row: server entries + synthesized section-failure alerts. */
interface DisplayAlert {
  key: string;
  kind: string;
  severity: string;
  summary: string;
  count?: number;
  evidence: OverviewEvidence[];
  evidenceTruncated: boolean;
  route?: string;
}

/** Explicit "unavailable" value: a failed section, styled distinct from zero. */
function Unavailable() {
  const { t } = useI18n();
  return (
    <span className="text-muted-foreground" title={t("dashboard.value.unavailableHint")}>
      {t("dashboard.value.unavailable")}
    </span>
  );
}

/** Explicit "not applicable" value: a field the contract does not (yet) expose. */
function NotAvailable() {
  const { t } = useI18n();
  return (
    <span className="text-muted-foreground" title={t("dashboard.value.notAvailableHint")}>
      {t("dashboard.value.notAvailable")}
    </span>
  );
}

function MetricTile({
  icon: Icon,
  label,
  value,
  detail,
  tone = "default",
  href,
  viewLabel,
}: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  value: ReactNode;
  detail: ReactNode;
  tone?: "default" | "danger";
  href?: string;
  viewLabel?: string;
}) {
  const body = (
    <div className="flex min-w-0 flex-col gap-1 bg-background px-3 py-3 sm:px-4">
      <span className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
        <Icon className="size-4 shrink-0" />
        <span className="truncate">{label}</span>
        {href ? <ArrowUpRight className="ml-auto size-3.5 shrink-0 opacity-60" aria-hidden="true" /> : null}
      </span>
      <span
        className={`text-xl font-semibold tabular-nums ${
          tone === "danger" ? "text-destructive" : "text-foreground"
        }`}
      >
        {value}
      </span>
      <span className="truncate text-xs text-muted-foreground">{detail}</span>
    </div>
  );
  if (!href) return body;
  return (
    <Link
      to={href}
      aria-label={viewLabel}
      className="block outline-none ring-inset focus-visible:ring-2 focus-visible:ring-ring hover:bg-muted/50"
    >
      {body}
    </Link>
  );
}

export default function DashboardPage() {
  const { t, format } = useI18n();
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const [searchParams, setSearchParams] = useSearchParams();
  const period: Period = searchParams.get("period") === "month" ? "month" : "lifetime";

  const setPeriod = (next: Period) => {
    const params = new URLSearchParams(searchParams);
    // Default (lifetime) is encoded as an ABSENT param so the pristine URL is clean.
    if (next === "lifetime") params.delete("period");
    else params.set("period", next);
    setSearchParams(params, { replace: true });
  };

  const overviewQuery = useQuery({
    queryKey: ["dashboard", "overview"],
    queryFn: () => adminGet(apiKey, "/admin/v1/overview"),
  });

  // Bounded polling that pauses on a backgrounded tab and tears down on unmount;
  // only runs once the first load has succeeded.
  useVisibilityPolling(
    () => {
      void overviewQuery.refetch();
    },
    POLL_INTERVAL_MS,
    overviewQuery.isSuccess,
  );

  const overview = overviewQuery.data;

  const runtime = overview ? sectionView<OverviewRuntimeData>(overview.runtime) : undefined;
  const controlPlane = overview
    ? sectionView<OverviewControlPlaneData>(overview.control_plane)
    : undefined;
  const usage = overview ? sectionView<OverviewUsageData>(overview.usage) : undefined;
  const alerts = overview
    ? sectionView<{
        total: number;
        truncated: boolean;
        unavailable_sources: string[];
        entries: OverviewAlert[];
      }>(overview.alerts)
    : undefined;

  const nowSeconds = Math.floor(Date.now() / 1000);
  const isStale =
    overview !== undefined && nowSeconds - overview.generated_at_unix > STALE_AFTER_SECONDS;

  // The period-scoped token/cost/request totals, or undefined when the usage
  // section failed (rendered as Unavailable, never zero).
  const tokens = usage?.status === "ok"
    ? period === "month"
      ? usage.data.current_month
      : usage.data.lifetime
    : undefined;
  const periodScope =
    usage?.status === "ok" && period === "month"
      ? t("dashboard.period.monthScope", { month: usage.data.current_period_month })
      : t("dashboard.period.lifetimeScope");

  // Prioritized alert list: synthesize a visible alert for any unavailable
  // section FIRST (so a partial failure is never silent), then the server's
  // bounded entries, then stable-sort by severity.
  const displayAlerts = useMemo<DisplayAlert[]>(() => {
    if (!overview) return [];
    const rows: DisplayAlert[] = [];
    const sectionFailure = (
      section: { status: "ok" } | { status: "unavailable"; error?: string } | undefined,
      sectionKey: TranslationKey,
      route: string | undefined,
    ) => {
      if (!section || section.status === "ok") return;
      rows.push({
        key: `section-${sectionKey}`,
        kind: "section_unavailable",
        severity: "warning",
        summary: t("dashboard.section.unavailableSummary", {
          section: t(sectionKey),
          error: section.error ?? t("dashboard.value.unavailable"),
        }),
        evidence: [],
        evidenceTruncated: false,
        route,
      });
    };
    sectionFailure(controlPlane, "dashboard.section.controlPlane", undefined);
    sectionFailure(usage, "dashboard.section.usage", "/app/usage-reports");
    sectionFailure(runtime, "dashboard.section.runtime", APP_ROUTES.operationsStatus);

    if (alerts?.status === "ok") {
      for (const [index, entry] of alerts.data.entries.entries()) {
        rows.push({
          key: `alert-${index}-${entry.kind}`,
          kind: entry.kind,
          severity: entry.severity,
          summary: entry.summary,
          count: entry.count,
          evidence: entry.evidence,
          evidenceTruncated: entry.evidence_truncated,
          route: ALERT_ROUTE[entry.kind],
        });
      }
    }
    return rows.sort((a, b) => alertSeverityRank(a.severity) - alertSeverityRank(b.severity));
  }, [overview, runtime, controlPlane, usage, alerts, t]);

  const unavailableSources =
    alerts?.status === "ok" ? alerts.data.unavailable_sources : [];
  const alertsTruncated = alerts?.status === "ok" ? alerts.data.truncated : false;

  const scopeLabel =
    overview?.scope.kind === "tenant"
      ? (session?.tenant.name ?? t("dashboard.scope.tenant"))
      : t("dashboard.scope.global");

  // --- Loading / hard-error states (no data at all) ---------------------------
  if (overviewQuery.isLoading) {
    return (
      <div className="flex flex-col gap-2">
        <h1 className="text-lg font-semibold">{t("dashboard.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("dashboard.loading")}</p>
      </div>
    );
  }
  if (overviewQuery.error || !overview) {
    return (
      <div className="flex flex-col gap-2">
        <h1 className="text-lg font-semibold">{t("dashboard.title")}</h1>
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("dashboard.loadError", {
            message: (overviewQuery.error as Error | null)?.message ?? "",
          })}
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">{t("dashboard.title")}</h1>
          <p className="text-sm text-muted-foreground">
            {t("dashboard.subtitle", { name: session?.tenant.name ?? "" })}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="font-normal">
            {scopeLabel}
          </Badge>
          <span className="text-xs text-muted-foreground">
            {t("dashboard.generatedAt", {
              time: format.date(overview.generated_at_unix * 1000, RELATIVE_TIME),
            })}
          </span>
          {isStale ? (
            <Badge variant="destructive" title={t("dashboard.freshness.staleHint")}>
              {t("dashboard.freshness.stale")}
            </Badge>
          ) : (
            <Badge variant="secondary">{t("dashboard.freshness.fresh")}</Badge>
          )}
        </div>
      </header>

      {/* --- Band 1: traffic, cost, and core counts (first viewport) --------- */}
      <section aria-labelledby="traffic-heading">
        <div className="flex flex-col gap-2 border-b pb-3 sm:flex-row sm:items-end sm:justify-between">
          <div className="min-w-0">
            <h2 id="traffic-heading" className="text-sm font-semibold">
              {t("dashboard.band.traffic.title")}
            </h2>
            <p className="text-xs text-muted-foreground">
              {t("dashboard.band.traffic.description")}
            </p>
          </div>
          <div
            role="group"
            aria-label={t("dashboard.period.label")}
            className="inline-flex shrink-0 rounded-md border p-0.5 text-xs"
          >
            {(["lifetime", "month"] as const).map((option) => (
              <button
                key={option}
                type="button"
                aria-pressed={period === option}
                onClick={() => setPeriod(option)}
                className={`rounded px-2 py-1 font-medium transition-colors ${
                  period === option
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {t(option === "lifetime" ? "dashboard.period.lifetime" : "dashboard.period.month")}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-px overflow-hidden rounded-md border bg-border sm:grid-cols-3 lg:grid-cols-4">
          <MetricTile
            icon={Coins}
            label={t("dashboard.metric.tokens")}
            value={tokens ? format.tokens(tokens.total_tokens) : <Unavailable />}
            detail={periodScope}
          />
          <MetricTile
            icon={Activity}
            label={t("dashboard.metric.requests")}
            value={tokens ? format.number(tokens.request_count) : <Unavailable />}
            detail={
              tokens ? t("dashboard.metric.requestsHint", { errors: format.number(tokens.error_count) }) : periodScope
            }
            tone={tokens && tokens.error_count > 0 ? "danger" : "default"}
          />
          <MetricTile
            icon={DollarSign}
            label={t("dashboard.metric.cost")}
            value={tokens ? format.currency(tokens.cost_usd, "USD", COST_OPTIONS) : <Unavailable />}
            detail={periodScope}
          />
          <MetricTile
            icon={Server}
            label={t("dashboard.metric.providers")}
            value={
              runtime?.status === "ok" ? (
                `${format.number(runtime.data.providers.enabled)} / ${format.number(runtime.data.providers.total)}`
              ) : (
                <Unavailable />
              )
            }
            detail={t("dashboard.metric.providersHint")}
          />
          <MetricTile
            icon={Network}
            label={t("dashboard.metric.mcpServers")}
            value={
              runtime?.status === "ok" ? (
                `${format.number(runtime.data.mcp_servers.connected)} / ${format.number(runtime.data.mcp_servers.total)}`
              ) : (
                <Unavailable />
              )
            }
            detail={t("dashboard.metric.mcpHint")}
            href="/app/mcp-servers"
            viewLabel={t("dashboard.action.viewResource", { resource: t("dashboard.res.mcpServers") })}
          />
          <MetricTile
            icon={HardDrive}
            label={t("dashboard.metric.assets")}
            value={
              controlPlane?.status === "ok" ? format.number(controlPlane.data.assets.count) : <Unavailable />
            }
            detail={
              controlPlane?.status === "ok" ? (
                t("dashboard.breakdown.storage", {
                  size: format.bytes(controlPlane.data.assets.storage_bytes),
                })
              ) : (
                <Unavailable />
              )
            }
            href={APP_ROUTES.assets}
            viewLabel={t("dashboard.action.viewResource", { resource: t("dashboard.res.assets") })}
          />
          <MetricTile
            icon={Bot}
            label={t("dashboard.metric.agentRuns")}
            value={
              controlPlane?.status === "ok" ? format.number(controlPlane.data.agent_runs.total) : <Unavailable />
            }
            detail={t("dashboard.metric.agentRunsHint")}
            href={APP_ROUTES.agentRuns}
            viewLabel={t("dashboard.action.viewResource", { resource: t("dashboard.res.agentRuns") })}
          />
          <MetricTile
            icon={Boxes}
            label={t("dashboard.metric.workers")}
            value={
              controlPlane?.status === "ok" ? (
                `${format.number(controlPlane.data.self_hosted_workers.by_status.active ?? 0)} / ${format.number(controlPlane.data.self_hosted_workers.total)}`
              ) : (
                <Unavailable />
              )
            }
            detail={t("dashboard.metric.workersHint")}
            href={APP_ROUTES.selfHostedWorkerOperations}
            viewLabel={t("dashboard.action.viewResource", { resource: t("dashboard.res.workers") })}
          />
        </div>
      </section>

      {/* --- Band 2: prioritized alerts ------------------------------------- */}
      <section aria-labelledby="alerts-heading">
        <div className="mb-3 flex items-center justify-between">
          <h2 id="alerts-heading" className="text-sm font-semibold">
            {t("dashboard.alerts.title")}
          </h2>
          <span className="text-xs tabular-nums text-muted-foreground">
            {t("dashboard.alerts.active", { count: format.number(displayAlerts.length) })}
          </span>
        </div>
        <div className="divide-y rounded-md border">
          {displayAlerts.length === 0 ? (
            <div className="flex items-center gap-2 px-3 py-3 text-sm">
              <CheckCircle2 className="size-4 shrink-0 text-emerald-600" aria-hidden="true" />
              <span>{t("dashboard.alerts.empty")}</span>
            </div>
          ) : (
            displayAlerts.map((alert) => (
              <div
                key={alert.key}
                className="flex flex-col gap-2 px-3 py-2.5 sm:flex-row sm:items-start sm:justify-between"
              >
                <div className="flex min-w-0 items-start gap-2">
                  <AlertTriangle
                    className={`mt-0.5 size-4 shrink-0 ${
                      alert.severity === "critical" ? "text-destructive" : "text-amber-600"
                    }`}
                    aria-hidden="true"
                  />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={alert.severity === "critical" ? "destructive" : "secondary"}>
                        {t(SEVERITY_LABEL[alert.severity] ?? "dashboard.severity.info")}
                      </Badge>
                      <span className="text-sm font-medium">
                        {t(ALERT_KIND_LABEL[alert.kind] ?? "dashboard.alert.kind.unknown")}
                      </span>
                      {alert.count !== undefined ? (
                        <span className="text-xs tabular-nums text-muted-foreground">
                          {format.number(alert.count)}
                        </span>
                      ) : null}
                    </div>
                    <p className="text-xs text-muted-foreground">{alert.summary}</p>
                    {alert.evidence.length > 0 ? (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {alert.evidence.slice(0, MAX_EVIDENCE_CHIPS).map((item) => (
                          <Badge
                            key={item.id}
                            variant="outline"
                            className="font-mono text-[11px] font-normal"
                            title={item.detail}
                          >
                            <span translate="no">{item.id}</span>
                          </Badge>
                        ))}
                        {alert.evidence.length > MAX_EVIDENCE_CHIPS || alert.evidenceTruncated ? (
                          <span className="text-[11px] text-muted-foreground">
                            {t("dashboard.alerts.evidenceMore", {
                              count: format.number(
                                Math.max(alert.evidence.length - MAX_EVIDENCE_CHIPS, 0),
                              ),
                            })}
                          </span>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                </div>
                {alert.route ? (
                  <Link
                    to={alert.route}
                    className="inline-flex shrink-0 items-center gap-1 self-start text-xs font-medium text-primary hover:underline"
                  >
                    {t("dashboard.alerts.investigate")}
                    <ArrowUpRight className="size-3.5" aria-hidden="true" />
                  </Link>
                ) : null}
              </div>
            ))
          )}
        </div>
        <div className="mt-2 flex flex-col gap-1 text-xs text-muted-foreground">
          {unavailableSources.length > 0 ? (
            <p role="status">
              {t("dashboard.alerts.unavailableSources", { sources: unavailableSources.join(", ") })}
            </p>
          ) : null}
          {alertsTruncated ? <p>{t("dashboard.alerts.truncated")}</p> : null}
          <p>{t("dashboard.alerts.deferred")}</p>
          {/* Deferred #458 signals: shown as explicit N/A, never a fabricated zero. */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="font-medium">{t("dashboard.deferred.title")}</span>
            <span className="inline-flex items-center gap-1">
              {t("dashboard.deferred.pendingApprovals")} <NotAvailable />
            </span>
            <span className="inline-flex items-center gap-1">
              {t("dashboard.deferred.quotaPressure")} <NotAvailable />
            </span>
          </div>
        </div>
      </section>

      {/* --- Band 3: resource inventory by domain --------------------------- */}
      <section aria-labelledby="inventory-heading">
        <div className="border-b pb-3">
          <h2 id="inventory-heading" className="text-sm font-semibold">
            {t("dashboard.inventory.title")}
          </h2>
          <p className="text-xs text-muted-foreground">{t("dashboard.inventory.description")}</p>
        </div>
        <div className="mt-3 grid gap-6 lg:grid-cols-2">
          <InventoryTable
            title={t("dashboard.inventory.runtime.title")}
            description={t("dashboard.inventory.runtime.description")}
            unavailableError={runtime?.status === "unavailable" ? runtime.error : undefined}
            rows={runtime?.status === "ok" ? runtimeRows(runtime.data) : []}
          />
          <InventoryTable
            title={t("dashboard.inventory.controlPlane.title")}
            description={t("dashboard.inventory.controlPlane.description")}
            unavailableError={controlPlane?.status === "unavailable" ? controlPlane.error : undefined}
            rows={controlPlane?.status === "ok" ? controlPlaneRows(controlPlane.data) : []}
          />
        </div>
      </section>
    </div>
  );
}

/** A single inventory row: a resource, its total, a breakdown, and its route. */
interface InventoryRow {
  labelKey: TranslationKey;
  total: number;
  breakdown?: (t: ReturnType<typeof useI18n>["t"], format: ReturnType<typeof useI18n>["format"]) => ReactNode;
  href?: string;
}

function runtimeRows(data: OverviewRuntimeData): InventoryRow[] {
  return [
    {
      labelKey: "dashboard.res.providers",
      total: data.providers.total,
      breakdown: (t) =>
        t("dashboard.breakdown.enabledOfTotal", {
          enabled: data.providers.enabled,
          total: data.providers.total,
        }),
      href: "/app/providers",
    },
    {
      labelKey: "dashboard.res.models",
      total: data.models.total,
      breakdown: (t) =>
        t("dashboard.breakdown.enabledOfTotal", {
          enabled: data.models.enabled,
          total: data.models.total,
        }),
      href: "/app/models",
    },
    {
      labelKey: "dashboard.res.upstreams",
      total: data.upstreams.total,
      breakdown: (t) =>
        t("dashboard.breakdown.enabledOfTotal", {
          enabled: data.upstreams.enabled,
          total: data.upstreams.total,
        }),
      href: "/app/agent-upstreams",
    },
    {
      labelKey: "dashboard.res.routes",
      total: data.routes.total,
      breakdown: (t) =>
        t("dashboard.breakdown.enabledOfTotal", {
          enabled: data.routes.enabled,
          total: data.routes.total,
        }),
    },
    {
      labelKey: "dashboard.res.plugins",
      total: data.plugins.total,
      breakdown: (t) =>
        t("dashboard.breakdown.activeOfTotal", {
          active: data.plugins.active,
          total: data.plugins.total,
        }),
      href: "/app/plugins",
    },
    { labelKey: "dashboard.res.tools", total: data.tools, href: APP_ROUTES.tools },
    { labelKey: "dashboard.res.promptTemplates", total: data.prompt_templates, href: "/app/prompt-templates" },
    { labelKey: "dashboard.res.staticApiKeys", total: data.static_api_keys },
    {
      labelKey: "dashboard.res.mcpServers",
      total: data.mcp_servers.total,
      breakdown: (t) =>
        t("dashboard.breakdown.connectedOfTotal", {
          connected: data.mcp_servers.connected,
          total: data.mcp_servers.total,
        }),
      href: "/app/mcp-servers",
    },
  ];
}

function controlPlaneRows(data: OverviewControlPlaneData): InventoryRow[] {
  const byStatus = (counts: Record<string, number>): InventoryRow["breakdown"] => {
    const entries = Object.entries(counts).filter(([, count]) => count > 0);
    if (entries.length === 0) return undefined;
    return (_t, format) => (
      <span className="flex flex-wrap gap-1">
        {entries.map(([status, count]) => (
          <Badge key={status} variant="outline" className="font-normal">
            <span translate="no">{status}</span>
            <span className="ml-1 tabular-nums">{format.number(count)}</span>
          </Badge>
        ))}
      </span>
    );
  };
  return [
    { labelKey: "dashboard.res.tenants", total: data.tenants, href: "/app/tenants" },
    { labelKey: "dashboard.res.projects", total: data.projects, href: "/app/projects" },
    { labelKey: "dashboard.res.workspaces", total: data.workspaces, href: "/app/workspaces" },
    { labelKey: "dashboard.res.virtualKeys", total: data.virtual_keys, href: APP_ROUTES.virtualKeys },
    {
      labelKey: "dashboard.res.assets",
      total: data.assets.count,
      breakdown: (t, format) =>
        t("dashboard.breakdown.storage", { size: format.bytes(data.assets.storage_bytes) }),
      href: APP_ROUTES.assets,
    },
    {
      labelKey: "dashboard.res.agentRuns",
      total: data.agent_runs.total,
      breakdown: byStatus(data.agent_runs.by_status),
      href: APP_ROUTES.agentRuns,
    },
    {
      labelKey: "dashboard.res.workers",
      total: data.self_hosted_workers.total,
      breakdown: byStatus(data.self_hosted_workers.by_status),
      href: APP_ROUTES.selfHostedWorkerOperations,
    },
  ];
}

function InventoryTable({
  title,
  description,
  unavailableError,
  rows,
}: {
  title: string;
  description: string;
  unavailableError?: string;
  rows: InventoryRow[];
}) {
  const { t, format } = useI18n();
  return (
    <div className="min-w-0">
      <div className="mb-2">
        <h3 className="text-sm font-medium">{title}</h3>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      {unavailableError !== undefined ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-muted-foreground"
        >
          {t("dashboard.inventory.unavailable", { error: unavailableError })}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("dashboard.inventory.col.resource")}</TableHead>
                <TableHead className="text-right">{t("dashboard.inventory.col.total")}</TableHead>
                <TableHead>{t("dashboard.inventory.col.breakdown")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => {
                const label = t(row.labelKey);
                return (
                  <TableRow key={row.labelKey}>
                    <TableCell className="whitespace-nowrap font-medium">
                      {row.href ? (
                        <Link
                          to={row.href}
                          aria-label={t("dashboard.action.viewResource", { resource: label })}
                          className="inline-flex items-center gap-1 hover:underline"
                        >
                          {label}
                          <ArrowUpRight className="size-3 opacity-60" aria-hidden="true" />
                        </Link>
                      ) : (
                        label
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{format.number(row.total)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {row.breakdown ? row.breakdown(t, format) : "—"}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
