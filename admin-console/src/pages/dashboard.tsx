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
  type OverviewControlPlaneData,
  type OverviewEvidence,
  type OverviewRuntimeData,
  alertSeverityRank,
  healthyWorkerCount,
  parseAlerts,
  parseControlPlane,
  parseRuntime,
  parseUsage,
  sectionView,
} from "@/lib/overview";
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
import type { ComponentType, ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

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

const QUOTA_POLICIES_ROUTE = "/app/quota-policies";

// Console routes an alert kind pivots to (filtered where the target supports it).
const ALERT_ROUTE: Record<string, string> = {
  provider_unhealthy: APP_ROUTES.operationsProviderHealth,
  mcp_server_disconnected: "/app/mcp-servers",
  agent_runs_failed: `${APP_ROUTES.agentRuns}?status=failed`,
  self_hosted_workers_unhealthy: APP_ROUTES.selfHostedWorkerOperations,
  // #458 alert kinds: both are raised by the live gateway, so both need a label
  // and a pivot target — an untitled "Alert" with no link is not triage.
  quota_pressure: QUOTA_POLICIES_ROUTE,
  tool_approvals_pending: APP_ROUTES.toolApprovals,
};

const ALERT_KIND_LABEL: Record<string, TranslationKey> = {
  provider_unhealthy: "dashboard.alert.kind.provider_unhealthy",
  mcp_server_disconnected: "dashboard.alert.kind.mcp_server_disconnected",
  agent_runs_failed: "dashboard.alert.kind.agent_runs_failed",
  self_hosted_workers_unhealthy: "dashboard.alert.kind.self_hosted_workers_unhealthy",
  quota_pressure: "dashboard.alert.kind.quota_pressure",
  tool_approvals_pending: "dashboard.alert.kind.tool_approvals_pending",
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

/**
 * Explicit "not available" value: a field the payload did not carry, one this
 * console could not read, or one that is not applicable at this scope. Distinct
 * from a real zero and from an unavailable section; `hint` says which.
 */
function NotAvailable({ hint }: { hint?: TranslationKey } = {}) {
  const { t } = useI18n();
  return (
    <span className="text-muted-foreground" title={t(hint ?? "dashboard.value.notAvailableHint")}>
      {t("dashboard.value.notAvailable")}
    </span>
  );
}

/** `x / y` where an unknown numerator stays N/A instead of collapsing to zero. */
function Ratio({
  value,
  total,
  unknownHint,
}: {
  value: number | undefined;
  total: number;
  unknownHint?: TranslationKey;
}) {
  const { format } = useI18n();
  return (
    <span>
      {value === undefined ? <NotAvailable hint={unknownHint} /> : format.number(value)}
      {" / "}
      {format.number(total)}
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
        {href ? (
          <ArrowUpRight className="ml-auto size-3.5 shrink-0 opacity-60" aria-hidden="true" />
        ) : null}
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
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

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

  // Every section is PARSED, not cast: a field the gateway renamed or retyped
  // arrives as `undefined` (rendered N/A) instead of reaching a formatter.
  const runtime = overview ? sectionView(overview.runtime, parseRuntime) : undefined;
  const controlPlane = overview
    ? sectionView(overview.control_plane, parseControlPlane)
    : undefined;
  const usage = overview ? sectionView(overview.usage, parseUsage) : undefined;
  const alerts = overview ? sectionView(overview.alerts, parseAlerts) : undefined;

  // A FAILED BACKGROUND REFRESH keeps the last good payload: TanStack Query
  // sets `error` while retaining `data`, and blanking a healthy cockpit over one
  // transient tick is exactly the "blanks healthy sections" failure mode. The
  // payload on screen is then, by definition, stale — say so.
  const refreshError = overview !== undefined ? (overviewQuery.error as Error | null) : null;

  const nowSeconds = Math.floor(Date.now() / 1000);
  const isStale =
    refreshError !== null ||
    (overview !== undefined && nowSeconds - overview.generated_at_unix > STALE_AFTER_SECONDS);

  // The period-scoped token/cost/request totals, or undefined when the usage
  // section failed (rendered as Unavailable, never zero).
  const tokens =
    usage?.status === "ok"
      ? period === "month"
        ? usage.data.current_month
        : usage.data.lifetime
      : undefined;
  const periodScope =
    usage?.status === "ok" && period === "month"
      ? t("dashboard.period.monthScope", {
          month: usage.data.current_period_month ?? t("dashboard.value.notAvailable"),
        })
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
    // An unavailable ALERTS section must never read as "all clear" — the worst
    // dishonest state a cockpit can reach.
    sectionFailure(alerts, "dashboard.section.alerts", undefined);

    if (alerts?.status === "ok") {
      if (alerts.data.malformed_entries > 0) {
        // Entries this console could not read are COUNTED, not silently dropped.
        rows.push({
          key: "alerts-malformed",
          kind: "alerts_unreadable",
          severity: "warning",
          summary: t("dashboard.alerts.malformed", { count: alerts.data.malformed_entries }),
          count: alerts.data.malformed_entries,
          evidence: [],
          evidenceTruncated: false,
        });
      }
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

  const unavailableSources = alerts?.status === "ok" ? (alerts.data.unavailable_sources ?? []) : [];
  const alertsTruncated = alerts?.status === "ok" ? (alerts.data.truncated ?? false) : false;

  // #458 governance signals, read from the live payload. Three distinct states:
  // an unavailable section (Unavailable), a field this console could not read
  // (N/A), and a real count.
  const controlPlaneData = controlPlane?.status === "ok" ? controlPlane.data : undefined;
  const signalValue = (value: number | undefined): ReactNode => {
    if (controlPlane?.status !== "ok") return <Unavailable />;
    if (value === undefined) return <NotAvailable />;
    return <span className="tabular-nums">{format.number(value)}</span>;
  };

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
  // Only a load with NO payload at all is a full-page error. See `refreshError`.
  if (!overview) {
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

      {/* A failed refresh degrades the cockpit to "stale", never to a blank page. */}
      {refreshError ? (
        <p
          // biome-ignore lint/a11y/useSemanticElements: ARIA live region for the refresh-error banner; keeping the block <p> preserves layout that <output>'s inline default would change
          role="status"
          className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-muted-foreground"
        >
          {t("dashboard.refreshError", {
            message: refreshError.message,
            time: format.date(overview.generated_at_unix * 1000, RELATIVE_TIME),
          })}
        </p>
      ) : null}

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
            // biome-ignore lint/a11y/useSemanticElements: a segmented period toggle grouped with role="group"; a native <fieldset> carries form-field semantics and default margins/border this inline toggle must not inherit
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
              tokens
                ? t("dashboard.metric.requestsHint", { errors: format.number(tokens.error_count) })
                : periodScope
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
              runtime?.status !== "ok" ? (
                <Unavailable />
              ) : runtime.data.providers === undefined ? (
                <NotAvailable />
              ) : (
                <Ratio
                  value={runtime.data.providers.enabled}
                  total={runtime.data.providers.total}
                />
              )
            }
            detail={t("dashboard.metric.providersHint")}
          />
          <MetricTile
            icon={Network}
            label={t("dashboard.metric.mcpServers")}
            value={
              runtime?.status !== "ok" ? (
                <Unavailable />
              ) : runtime.data.mcp_servers === undefined ? (
                <NotAvailable />
              ) : (
                <Ratio
                  value={runtime.data.mcp_servers.connected}
                  total={runtime.data.mcp_servers.total}
                />
              )
            }
            detail={t("dashboard.metric.mcpHint")}
            href="/app/mcp-servers"
            viewLabel={t("dashboard.action.viewResource", {
              resource: t("dashboard.res.mcpServers"),
            })}
          />
          <MetricTile
            icon={HardDrive}
            label={t("dashboard.metric.assets")}
            value={
              controlPlane?.status !== "ok" ? (
                <Unavailable />
              ) : controlPlaneData?.assets === undefined ? (
                <NotAvailable />
              ) : (
                format.number(controlPlaneData.assets.count)
              )
            }
            detail={
              controlPlane?.status !== "ok" ? (
                <Unavailable />
              ) : controlPlaneData?.assets === undefined ? (
                <NotAvailable />
              ) : (
                t("dashboard.breakdown.storage", {
                  size: format.bytes(controlPlaneData.assets.storage_bytes),
                })
              )
            }
            href={APP_ROUTES.assets}
            viewLabel={t("dashboard.action.viewResource", { resource: t("dashboard.res.assets") })}
          />
          <MetricTile
            icon={Bot}
            label={t("dashboard.metric.agentRuns")}
            value={
              controlPlane?.status !== "ok" ? (
                <Unavailable />
              ) : controlPlaneData?.agent_runs === undefined ? (
                <NotAvailable />
              ) : (
                format.number(controlPlaneData.agent_runs.total)
              )
            }
            detail={t("dashboard.metric.agentRunsHint")}
            href={APP_ROUTES.agentRuns}
            viewLabel={t("dashboard.action.viewResource", {
              resource: t("dashboard.res.agentRuns"),
            })}
          />
          {/*
            Healthy workers are DERIVED from the status labels the gateway
            actually writes (`registered` on registration, the worker-reported
            `online` on heartbeat). There is no `active` bucket to read, and a
            histogram this console cannot classify renders N/A — never a zero
            that would claim twelve healthy workers are down.
          */}
          <MetricTile
            icon={Boxes}
            label={t("dashboard.metric.workers")}
            value={
              controlPlane?.status !== "ok" ? (
                <Unavailable />
              ) : controlPlaneData?.self_hosted_workers === undefined ? (
                <NotAvailable />
              ) : (
                <Ratio
                  value={healthyWorkerCount(controlPlaneData.self_hosted_workers.by_status)}
                  total={controlPlaneData.self_hosted_workers.total}
                  unknownHint="dashboard.metric.workersUnknownHint"
                />
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
            <p
              // biome-ignore lint/a11y/useSemanticElements: ARIA live region for the unavailable-sources alert; keeping the block <p> preserves layout that <output>'s inline default would change
              role="status"
            >
              {t("dashboard.alerts.unavailableSources", { sources: unavailableSources.join(", ") })}
            </p>
          ) : null}
          {alertsTruncated ? <p>{t("dashboard.alerts.truncated")}</p> : null}
          {/*
            Live #458 governance signals. Each links to the page that resolves it
            and reports three distinct states: unavailable section, unreadable
            field (N/A), or a real count.
          */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="font-medium">{t("dashboard.signals.title")}</span>
            <span className="inline-flex items-center gap-1">
              <Link to={APP_ROUTES.toolApprovals} className="hover:underline">
                {t("dashboard.signals.pendingApprovals")}
              </Link>
              {signalValue(controlPlaneData?.pending_tool_approvals)}
            </span>
            <span className="inline-flex items-center gap-1">
              <Link to={QUOTA_POLICIES_ROUTE} className="hover:underline">
                {t("dashboard.signals.quotaPressure")}
              </Link>
              {signalValue(controlPlaneData?.quota_pressure?.length)}
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
            unavailableError={
              controlPlane?.status === "unavailable" ? controlPlane.error : undefined
            }
            rows={controlPlane?.status === "ok" ? controlPlaneRows(controlPlane.data) : []}
          />
        </div>
      </section>
    </div>
  );
}

/**
 * A single inventory row: a resource, its total, a breakdown, and its route.
 * `total: undefined` means the payload did not carry a readable count — the row
 * renders N/A (with `totalHint` explaining why), never a zero.
 */
interface InventoryRow {
  labelKey: TranslationKey;
  total: number | undefined;
  totalHint?: TranslationKey;
  breakdown?: (
    t: ReturnType<typeof useI18n>["t"],
    format: ReturnType<typeof useI18n>["format"],
  ) => ReactNode;
  href?: string;
}

/** An `{enabled,total}` row; the whole row degrades to N/A when the field is unreadable. */
function enabledRow(
  labelKey: TranslationKey,
  count: { total: number; enabled: number } | undefined,
  href?: string,
): InventoryRow {
  return {
    labelKey,
    total: count?.total,
    href,
    breakdown: count
      ? (t) =>
          t("dashboard.breakdown.enabledOfTotal", {
            enabled: count.enabled,
            total: count.total,
          })
      : undefined,
  };
}

function runtimeRows(data: OverviewRuntimeData): InventoryRow[] {
  const plugins = data.plugins;
  const mcp = data.mcp_servers;
  return [
    enabledRow("dashboard.res.providers", data.providers, "/app/providers"),
    enabledRow("dashboard.res.models", data.models, "/app/models"),
    enabledRow("dashboard.res.upstreams", data.upstreams, "/app/agent-upstreams"),
    enabledRow("dashboard.res.routes", data.routes),
    {
      labelKey: "dashboard.res.plugins",
      total: plugins?.total,
      breakdown: plugins
        ? (t) =>
            t("dashboard.breakdown.activeOfTotal", {
              active: plugins.active,
              total: plugins.total,
            })
        : undefined,
      href: "/app/plugins",
    },
    { labelKey: "dashboard.res.tools", total: data.tools, href: APP_ROUTES.tools },
    {
      labelKey: "dashboard.res.promptTemplates",
      total: data.prompt_templates,
      href: "/app/prompt-templates",
    },
    { labelKey: "dashboard.res.staticApiKeys", total: data.static_api_keys },
    {
      labelKey: "dashboard.res.mcpServers",
      total: mcp?.total,
      breakdown: mcp
        ? (t) =>
            t("dashboard.breakdown.connectedOfTotal", {
              connected: mcp.connected,
              total: mcp.total,
            })
        : undefined,
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
  const assets = data.assets;
  const runs = data.agent_runs;
  const workers = data.self_hosted_workers;
  // `policy_governance` is `null` — not zero — for a tenant-scoped key, because
  // guardrail/quota/policy tables are not per-tenant attributable (#458).
  const governance = data.policy_governance ?? undefined;
  const governanceHint: TranslationKey | undefined =
    data.policy_governance === null ? "dashboard.value.notApplicableScopeHint" : undefined;
  return [
    { labelKey: "dashboard.res.tenants", total: data.tenants, href: "/app/tenants" },
    { labelKey: "dashboard.res.projects", total: data.projects, href: "/app/projects" },
    { labelKey: "dashboard.res.workspaces", total: data.workspaces, href: "/app/workspaces" },
    enabledRow("dashboard.res.virtualKeys", data.virtual_keys, APP_ROUTES.virtualKeys),
    {
      labelKey: "dashboard.res.assets",
      total: assets?.count,
      breakdown: assets
        ? (t, format) => (
            <span className="flex flex-col">
              <span>
                {t("dashboard.breakdown.storage", { size: format.bytes(assets.storage_bytes) })}
                {assets.storage_quota_bytes !== null
                  ? t("dashboard.breakdown.storageQuota", {
                      quota: format.bytes(assets.storage_quota_bytes),
                    })
                  : null}
              </span>
              <span>
                {t("dashboard.breakdown.assetReferences", {
                  referenced: assets.referenced,
                  unreferenced: assets.unreferenced,
                })}
              </span>
            </span>
          )
        : undefined,
      href: APP_ROUTES.assets,
    },
    {
      labelKey: "dashboard.res.agentRuns",
      total: runs?.total,
      breakdown: runs ? byStatus(runs.by_status) : undefined,
      href: APP_ROUTES.agentRuns,
    },
    {
      labelKey: "dashboard.res.workers",
      total: workers?.total,
      breakdown: workers ? byStatus(workers.by_status) : undefined,
      href: APP_ROUTES.selfHostedWorkerOperations,
    },
    {
      labelKey: "dashboard.res.toolApprovals",
      total: data.pending_tool_approvals,
      href: APP_ROUTES.toolApprovals,
    },
    {
      labelKey: "dashboard.res.guardrailRevisions",
      total: governance?.guardrail_policy_revisions,
      totalHint: governanceHint,
      href: APP_ROUTES.guardrailPolicies,
    },
    {
      labelKey: "dashboard.res.guardrailBindings",
      total: governance?.guardrail_policy_bindings,
      totalHint: governanceHint,
      href: APP_ROUTES.guardrailPolicies,
    },
    {
      labelKey: "dashboard.res.quotaPolicies",
      total: governance?.quota_policies,
      totalHint: governanceHint,
      href: QUOTA_POLICIES_ROUTE,
    },
    {
      labelKey: "dashboard.res.policyRules",
      total: governance?.policy_rules,
      totalHint: governanceHint,
      href: "/app/policies",
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
                    <TableCell className="text-right tabular-nums">
                      {row.total === undefined ? (
                        <NotAvailable hint={row.totalHint} />
                      ) : (
                        format.number(row.total)
                      )}
                    </TableCell>
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
