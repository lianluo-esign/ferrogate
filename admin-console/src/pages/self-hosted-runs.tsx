// Self-hosted run inspector (issue #320): looks up one customer-reported run
// timeline (GET /admin/v1/self-hosted-runs/{run_id}) and surfaces the
// correlation triple (request_id / trace_id / agent_run_id, #305) plus the
// parent action fingerprint (#307). Because a self-hosted run is
// customer-reported evidence, those ids are not structured contract columns —
// they are lifted out of each event's reported `event_json` document and
// aggregated for the run header. Individual reported lifecycle events are
// listed below with their per-event correlation.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatUnix, TruncatedCopyable } from "@/components/agent-ops/agent-ops-primitives";
import {
  aggregateReportedCorrelation,
  parseReportedCorrelation,
  ReportedTrustBadge,
} from "@/components/worker-ops/worker-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet } from "@/lib/gateway-client";

function CorrelationField({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | null;
  hint?: string;
}) {
  return (
    <div className="grid gap-1">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <div>
        <TruncatedCopyable value={value} label={label} prefixLength={28} />
      </div>
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

export default function SelfHostedRunsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const [runInput, setRunInput] = useState("");
  const [activeRunId, setActiveRunId] = useState("");

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ["self-hosted-run", activeRunId],
    enabled: activeRunId !== "",
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/self-hosted-runs/{run_id}", {
        params: { run_id: activeRunId },
      }),
  });

  const correlation = useMemo(
    () => aggregateReportedCorrelation((data?.events ?? []).map((e) => e.event_json)),
    [data],
  );

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.selfHostedRuns.title")}</h1>
        <div className="text-sm text-muted-foreground">
          {t("page.selfHostedRuns.description.before")}
          <ReportedTrustBadge />
          {t("page.selfHostedRuns.description.after")}
        </div>
      </div>

      <form
        className="flex items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setActiveRunId(runInput.trim());
        }}
      >
        <div className="grid flex-1 gap-1.5">
          <Label htmlFor="run-id">{t("page.selfHostedRuns.field.runId")}</Label>
          <Input
            id="run-id"
            value={runInput}
            onChange={(e) => setRunInput(e.target.value)}
            // eslint-disable-next-line ferrogate/no-untranslated-literal -- example run id format, not translatable copy
            placeholder="run-..."
          />
        </div>
        <Button type="submit" disabled={runInput.trim() === ""}>
          {t("page.selfHostedRuns.inspect")}
        </Button>
      </form>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.selfHostedRuns.error", { runId: activeRunId, message: error.message })}
        </p>
      ) : null}

      {activeRunId === "" ? (
        <p className="text-sm text-muted-foreground">
          {t("page.selfHostedRuns.prompt")}
        </p>
      ) : isLoading || isFetching ? (
        <p className="text-sm text-muted-foreground">
          {t("page.selfHostedRuns.loading", { runId: activeRunId })}
        </p>
      ) : data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t("page.selfHostedRuns.card.title", { runId: data.run_id })}
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <CorrelationField
                  label={t("page.selfHostedRuns.field.requestId")}
                  value={correlation.requestId}
                  hint={t("page.selfHostedRuns.hint.correlationTriple")}
                />
                <CorrelationField
                  label={t("page.selfHostedRuns.field.traceId")}
                  value={correlation.traceId}
                  hint={t("page.selfHostedRuns.hint.correlationTriple")}
                />
                <CorrelationField
                  label={t("page.selfHostedRuns.field.agentRunId")}
                  value={correlation.agentRunId}
                  hint={t("page.selfHostedRuns.hint.correlationTriple")}
                />
                <CorrelationField
                  label={t("page.selfHostedRuns.field.parentFingerprint")}
                  value={correlation.parentActionFingerprint}
                  hint={t("page.selfHostedRuns.hint.parentProvenance")}
                />
              </div>
              <div className="grid gap-3 text-sm sm:grid-cols-3">
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.selfHostedRuns.field.latestLifecycleState")}
                  </span>
                  <div>{data.latest_lifecycle_state ?? "—"}</div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.selfHostedRuns.field.reportedEvents")}
                  </span>
                  <div>
                    {t("page.selfHostedRuns.events.summary", {
                      reported: data.reported_event_count,
                      lifecycle: data.lifecycle_event_count,
                    })}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.selfHostedRuns.field.firstLastSeen")}
                  </span>
                  <div>
                    {formatUnix(data.first_seen_unix)} → {formatUnix(data.last_seen_unix)}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.selfHostedRuns.field.workerIds")}
                  </span>
                  <div className="break-all">
                    {data.worker_ids.length > 0 ? data.worker_ids.join(", ") : "—"}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.selfHostedRuns.field.sessionIds")}
                  </span>
                  <div className="break-all">
                    {data.session_ids.length > 0 ? data.session_ids.join(", ") : "—"}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("page.selfHostedRuns.col.kind")}</TableHead>
                  <TableHead>{t("page.selfHostedRuns.col.workerSession")}</TableHead>
                  <TableHead>{t("page.selfHostedRuns.col.requestTrace")}</TableHead>
                  <TableHead>{t("page.selfHostedRuns.col.parentFingerprint")}</TableHead>
                  <TableHead>{t("page.selfHostedRuns.col.occurred")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.events.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="h-24 text-center">
                      {t("page.selfHostedRuns.events.empty")}
                    </TableCell>
                  </TableRow>
                ) : (
                  data.events.map((event) => {
                    const c = parseReportedCorrelation(event.event_json);
                    return (
                      <TableRow key={event.id} data-testid={`run-event-${event.id}`}>
                        <TableCell>
                          <Badge variant="secondary">{event.kind}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">
                          <div>{t("page.selfHostedRuns.row.worker", { id: event.worker_id })}</div>
                          <div className="text-muted-foreground">
                            {t("page.selfHostedRuns.row.session", {
                              id: event.session_id ?? "—",
                            })}
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">
                          <div className="flex flex-col gap-1">
                            <TruncatedCopyable
                              value={c.requestId}
                              label={t("page.selfHostedRuns.field.requestId")}
                            />
                            <TruncatedCopyable
                              value={c.traceId}
                              label={t("page.selfHostedRuns.field.traceId")}
                            />
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">
                          <TruncatedCopyable
                            value={c.parentActionFingerprint}
                            label={t("page.selfHostedRuns.field.parentFingerprint")}
                          />
                        </TableCell>
                        <TableCell className="text-xs">
                          {formatUnix(event.occurred_at_unix)}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </>
      ) : null}
    </div>
  );
}
