import {
  formatUnix,
  runStatusBadgeVariant,
  tenantLabel,
  tenantMatches,
} from "@/components/agent-ops/agent-ops-primitives";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import type { TranslationKey } from "@/i18n";
import { type AdminSchema, adminGet } from "@/lib/gateway-client";
import { useQuery } from "@tanstack/react-query";
// Agent runs list (issue #317): correlation-first view over
// GET /admin/v1/agent-runs. The contract only paginates (offset/limit — see
// listAdminAgentRuns in api-types.generated.ts), so the status and tenant
// filters below narrow the fetched page client-side.
//
// UNATTRIBUTED VIEW (#464, epic #313 chain)
// -----------------------------------------
// The page carries a second tab over GET /admin/v1/observed-agent-activity
// (#357): traffic authenticated by a durable virtual API key that carries NO
// verified agent identity. It lives HERE rather than behind its own nav item
// because those rows are exactly the traffic with no agent run to link to —
// juxtaposing them with the real runs answers the operator's actual question
// ("what is running that I cannot account for?").
//
// The contract is deliberately non-committal and this view must not flatten it:
//   * `status=running` is DERIVED from a recency window
//     (`evidence.within_running_window` over `running_ttl_seconds`). Once the
//     window expires the row is inactive and there is NO stop event — the view
//     says so explicitly and never renders a fabricated "ended at".
//   * `evidence.usage_evidence_available=false` means unknown, NOT zero, so
//     token/cost cells render an explicit unavailable indicator (never `0`).
//   * `display_name` is the constant "Unknown" and `identity_status` is
//     `unattributed`: a CATEGORY of observed key activity, not a named agent
//     entity, and it never claims how many real agents share the key.
//   * the evidence behind the derived status is inspectable per row, so the
//     operator can always see WHY a row reads running.
import { Fragment, useCallback, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

export type AgentRunSummary = AdminSchema<"AgentRunSummary">;
export type ObservedAgentActivity = AdminSchema<"AdminObservedAgentActivity">;
/** #494: the list-level "could we even read presence?" qualifier. */
export type ObservedPresenceFeed = AdminSchema<"AdminObservedAgentPresenceFeed">;

type ObservedActivityState = "running" | "inactive" | "unknown";

const PAGE_SIZE = 50;

/** Tab ids; `runs` is the default and is encoded as an ABSENT `view` param. */
const RUNS_VIEW = "runs";
const UNATTRIBUTED_VIEW = "unattributed";

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
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

  const [offset, setOffset] = useState(0);
  // #342: the operational filters live in the URL query so a filtered view is
  // shareable and survives a reload (?status=&tenant=). Defaults (all statuses /
  // empty tenant) are encoded as ABSENT params so the pristine URL stays clean.
  // `status` writes a known contract token and DISPLAYS a localized human label
  // via the select. `tenant` stays a free-text substring (no silent exclusion):
  // an AgentRunSummary's tenant is a polymorphic TenantContext — any of
  // organization/team/project/user/key scope ids — with no single entity kind to
  // build a picker over (same rationale as the guardrail scope_id filter), so it
  // is a correlation box, not an entity reference.
  const [searchParams, setSearchParams] = useSearchParams();
  const statusFilter = searchParams.get("status") ?? "all";
  const tenantFilter = searchParams.get("tenant") ?? "";
  // Which tab is open also lives in the URL (?view=unattributed) so a triage
  // view is shareable, with the default (`runs`) encoded as an absent param.
  const view = searchParams.get("view") === UNATTRIBUTED_VIEW ? UNATTRIBUTED_VIEW : RUNS_VIEW;

  const setParam = useCallback(
    (key: string, value: string, defaultValue: string) => {
      const next = new URLSearchParams(searchParams);
      if (value === defaultValue || value === "") next.delete(key);
      else next.set(key, value);
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const setFilterParam = useCallback(
    (key: string, value: string, defaultValue: string) => {
      setParam(key, value, defaultValue);
      setOffset(0);
    },
    [setParam],
  );

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
        <p className="text-sm text-muted-foreground">{t("page.agentRuns.description")}</p>
      </div>

      <Tabs value={view} onValueChange={(next) => setParam("view", next, RUNS_VIEW)}>
        <TabsList>
          <TabsTrigger value={RUNS_VIEW}>{t("page.agentRuns.tab.runs")}</TabsTrigger>
          <TabsTrigger value={UNATTRIBUTED_VIEW}>
            {t("page.agentRuns.tab.unattributed")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value={RUNS_VIEW} className="flex flex-col gap-4">
          <div className="flex flex-wrap items-end gap-4">
            <div className="grid gap-2">
              <Label htmlFor="run-status-filter">{t("common.status")}</Label>
              <Select
                value={statusFilter}
                onValueChange={(value) => setFilterParam("status", value, "all")}
              >
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
                onChange={(event) => setFilterParam("tenant", event.target.value, "")}
              />
            </div>
          </div>

          {error && (
            <p
              role="alert"
              className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
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
                  <TableHead className="text-right">
                    {t("page.agentRuns.col.agentEvents")}
                  </TableHead>
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
        </TabsContent>

        {/* Radix unmounts inactive content, so the observed-activity read only
            fires once the operator opens the tab. */}
        <TabsContent value={UNATTRIBUTED_VIEW} className="flex flex-col gap-4">
          <UnattributedActivityView apiKey={apiKey} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** Localized cell for a usage figure the evidence does not carry (never `0`). */
function UsageUnavailable() {
  const { t } = useI18n();
  const label = t("page.agentRuns.unattributed.usageUnavailable");
  return (
    <span className="text-muted-foreground" aria-label={label} title={label}>
      {"—"}
    </span>
  );
}

/**
 * Unattributed ("Unknown" virtual-API-key) activity over
 * GET /admin/v1/observed-agent-activity. Pagination mirrors the runs list: the
 * contract exposes only offset/limit, so the page walks `total` in PAGE_SIZE
 * steps and the query key carries the offset.
 */
function UnattributedActivityView({ apiKey }: { apiKey: string }) {
  const { t, format } = useI18n();
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["observed-agent-activity", offset],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/observed-agent-activity", {
        query: { offset, limit: PAGE_SIZE },
      }),
  });

  const rows = data?.data ?? [];
  const total = data?.total ?? 0;
  const hasNext = offset + PAGE_SIZE < total;
  // #494: an empty table is itself an answer, and a failed presence read makes
  // that answer unsound. Say so above the table instead of letting "no rows"
  // read as "nothing is running".
  const presenceFeed = data?.presence_feed;
  const presenceDegraded =
    data !== undefined &&
    (presenceFeed === undefined || presenceFeed.rows_may_be_incomplete !== false);

  return (
    <>
      <p className="text-sm text-muted-foreground">
        {t("page.agentRuns.unattributed.description")}
      </p>

      {error && (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.agentRuns.unattributed.loadError", { message: error.message })}
        </p>
      )}

      {presenceDegraded && (
        <p
          // biome-ignore lint/a11y/useSemanticElements: ARIA live region for the presence-degraded banner; keeping the block <p> preserves layout that <output>'s inline default would change
          role="status"
          className="rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-sm"
        >
          {t("page.agentRuns.unattributed.presenceFeedDegraded", {
            reason:
              presenceFeed?.unavailable_reason ??
              t("page.agentRuns.unattributed.status.unknownReasonFallback"),
          })}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.agentRuns.unattributed.col.activity")}</TableHead>
              <TableHead>{t("common.tenant")}</TableHead>
              <TableHead>{t("page.agentRuns.unattributed.col.apiKey")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
              <TableHead className="text-right">{t("page.agentRuns.col.requests")}</TableHead>
              <TableHead className="text-right">
                {t("page.agentRuns.unattributed.col.tokens")}
              </TableHead>
              <TableHead className="text-right">
                {t("page.agentRuns.unattributed.col.cost")}
              </TableHead>
              <TableHead>{t("page.agentRuns.col.firstSeen")}</TableHead>
              <TableHead>{t("page.agentRuns.col.lastSeen")}</TableHead>
              <TableHead className="text-right">
                {t("page.agentRuns.unattributed.col.evidence")}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={10} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={10} className="h-24 text-center">
                  {t("page.agentRuns.unattributed.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => {
                const evidence = row.evidence;
                const activityState = observedActivityState(row);
                const usage = evidence.usage_evidence_available;
                const isExpanded = expanded === row.id;
                return (
                  <Fragment key={row.id}>
                    <TableRow>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <span className="font-mono text-xs">{row.id}</span>
                          <Badge
                            variant="outline"
                            title={t("page.agentRuns.unattributed.categoryHint")}
                          >
                            {t("page.agentRuns.unattributed.category")}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.tenant_id}</TableCell>
                      <TableCell className="font-mono text-xs">{row.api_key_id}</TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <Badge
                            variant={
                              activityState === "running"
                                ? "default"
                                : activityState === "unknown"
                                  ? "secondary"
                                  : "outline"
                            }
                          >
                            {activityState === "running"
                              ? t("page.agentRuns.unattributed.status.running")
                              : activityState === "inactive"
                                ? t("page.agentRuns.unattributed.status.inactive")
                                : t("page.agentRuns.unattributed.status.unknown")}
                          </Badge>
                          {/* The sub-label reads off the window itself, so the
                              badge and the justification can never disagree.
                              `within_running_window === null` is the undecided
                              case and gets its own sentence, not the
                              "no stop event" negative. */}
                          <span className="text-xs text-muted-foreground">
                            {evidence.within_running_window === null
                              ? t("page.agentRuns.unattributed.status.unknownBasis", {
                                  reason:
                                    evidence.presence_unavailable_reason ??
                                    t("page.agentRuns.unattributed.status.unknownReasonFallback"),
                                })
                              : evidence.within_running_window
                                ? t("page.agentRuns.unattributed.status.runningBasis", {
                                    ttl: evidence.running_ttl_seconds,
                                  })
                                : t("page.agentRuns.unattributed.status.noStopEvent")}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">{evidence.request_count}</TableCell>
                      <TableCell className="text-right">
                        {usage && evidence.total_tokens !== undefined ? (
                          format.tokens(evidence.total_tokens)
                        ) : (
                          <UsageUnavailable />
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        {usage && evidence.cost_usd !== undefined ? (
                          format.currency(evidence.cost_usd, "USD")
                        ) : (
                          <UsageUnavailable />
                        )}
                      </TableCell>
                      <TableCell className="text-xs">
                        {formatUnix(row.first_seen_at_unix)}
                      </TableCell>
                      <TableCell className="text-xs">{formatUnix(row.last_seen_at_unix)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="outline"
                          size="sm"
                          aria-expanded={isExpanded}
                          aria-label={t("page.agentRuns.unattributed.evidence.toggleLabel", {
                            id: row.id,
                          })}
                          onClick={() => setExpanded(isExpanded ? null : row.id)}
                        >
                          {isExpanded
                            ? t("page.agentRuns.unattributed.evidence.hide")
                            : t("page.agentRuns.unattributed.evidence.show")}
                        </Button>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow>
                        <TableCell colSpan={10} className="bg-muted/40">
                          <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.source")}
                              value={evidence.evidence_source}
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.statusBasis")}
                              value={row.status_basis}
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.requestCount")}
                              value={format.number(evidence.request_count)}
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.secondsSinceLastSeen")}
                              value={format.number(evidence.seconds_since_last_seen)}
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.runningTtl")}
                              value={format.number(evidence.running_ttl_seconds)}
                            />
                            {/* #494: `null` is "we could not tell". Rendering it
                                as "No" would be the same confident-negative
                                defect one layer down. */}
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.withinWindow")}
                              value={triState(t, evidence.within_running_window)}
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.durablePresence")}
                              value={triState(t, evidence.durable_presence_backed)}
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.presenceFeed")}
                              value={
                                evidence.presence_feed_status === "unavailable"
                                  ? t("page.agentRuns.unattributed.evidence.presenceFeedDown", {
                                      reason:
                                        evidence.presence_unavailable_reason ??
                                        t(
                                          "page.agentRuns.unattributed.status.unknownReasonFallback",
                                        ),
                                    })
                                  : t("page.agentRuns.unattributed.evidence.presenceFeedUp")
                              }
                            />
                            <EvidenceItem
                              label={t("page.agentRuns.unattributed.evidence.usageAvailable")}
                              value={
                                evidence.usage_evidence_available ? t("common.yes") : t("common.no")
                              }
                            />
                            <EvidenceItem
                              className="sm:col-span-2"
                              label={t("page.agentRuns.unattributed.evidence.reason")}
                              value={evidence.reason}
                            />
                          </dl>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })
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
    </>
  );
}

/**
 * Interpret the status token and its evidence together. Only the two coherent
 * positive/negative combinations are actionable; missing or contradictory
 * wire values stay unknown instead of becoming a confident negative.
 */
function observedActivityState(row: ObservedAgentActivity): ObservedActivityState {
  switch (row.status) {
    case "running":
      return row.evidence.within_running_window === true ? "running" : "unknown";
    case "inactive":
      return row.evidence.within_running_window === false ? "inactive" : "unknown";
    default:
      return "unknown";
  }
}

/**
 * Render a nullable boolean as Yes / No / Unknown (#494).
 *
 * `null` on these evidence fields means the gateway could not tell, so it must
 * NOT collapse into "No" — that is exactly the confident-negative defect the
 * backend change removed.
 */
function triState(t: (key: TranslationKey) => string, value: boolean | null | undefined): string {
  if (value === null || value === undefined) {
    return t("page.agentRuns.unattributed.evidence.unknownValue");
  }
  return value ? t("common.yes") : t("common.no");
}

/** One `<dt>/<dd>` pair inside the per-row evidence expander. */
function EvidenceItem({
  label,
  value,
  className,
}: {
  label: string;
  value: string;
  className?: string;
}) {
  return (
    <div className={className}>
      <dt className="inline text-muted-foreground">{label}</dt>{" "}
      <dd className="inline font-mono">{value}</dd>
    </div>
  );
}
