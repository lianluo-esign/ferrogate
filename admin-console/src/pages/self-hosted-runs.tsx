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
        <h1 className="text-lg font-semibold">Self-hosted runs</h1>
        <p className="text-sm text-muted-foreground">
          Inspect a customer-reported run timeline (<ReportedTrustBadge />) by its
          run id. The correlation triple and parent action fingerprint are lifted from
          the worker's reported event documents.
        </p>
      </div>

      <form
        className="flex items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setActiveRunId(runInput.trim());
        }}
      >
        <div className="grid flex-1 gap-1.5">
          <Label htmlFor="run-id">Run id</Label>
          <Input
            id="run-id"
            value={runInput}
            onChange={(e) => setRunInput(e.target.value)}
            placeholder="run-..."
          />
        </div>
        <Button type="submit" disabled={runInput.trim() === ""}>
          Inspect
        </Button>
      </form>

      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load run {activeRunId}: {error.message}
        </p>
      ) : null}

      {activeRunId === "" ? (
        <p className="text-sm text-muted-foreground">
          Enter a run id reported by a self-hosted worker to inspect its timeline.
        </p>
      ) : isLoading || isFetching ? (
        <p className="text-sm text-muted-foreground">Loading run {activeRunId}...</p>
      ) : data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Run {data.run_id}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <CorrelationField
                  label="Request id"
                  value={correlation.requestId}
                  hint="#305 correlation triple"
                />
                <CorrelationField
                  label="Trace id"
                  value={correlation.traceId}
                  hint="#305 correlation triple"
                />
                <CorrelationField
                  label="Agent run id"
                  value={correlation.agentRunId}
                  hint="#305 correlation triple"
                />
                <CorrelationField
                  label="Parent action fingerprint"
                  value={correlation.parentActionFingerprint}
                  hint="#307 parent action provenance"
                />
              </div>
              <div className="grid gap-3 text-sm sm:grid-cols-3">
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    Latest lifecycle state
                  </span>
                  <div>{data.latest_lifecycle_state ?? "—"}</div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    Reported events
                  </span>
                  <div>
                    {data.reported_event_count} ({data.lifecycle_event_count} lifecycle)
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    First / last seen
                  </span>
                  <div>
                    {formatUnix(data.first_seen_unix)} → {formatUnix(data.last_seen_unix)}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    Worker ids
                  </span>
                  <div className="break-all">
                    {data.worker_ids.length > 0 ? data.worker_ids.join(", ") : "—"}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    Session ids
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
                  <TableHead>Kind</TableHead>
                  <TableHead>Worker / session</TableHead>
                  <TableHead>Request / trace</TableHead>
                  <TableHead>Parent fingerprint</TableHead>
                  <TableHead>Occurred</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.events.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="h-24 text-center">
                      No reported events for this run.
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
                          <div>worker {event.worker_id}</div>
                          <div className="text-muted-foreground">
                            session {event.session_id ?? "—"}
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">
                          <div className="flex flex-col gap-1">
                            <TruncatedCopyable value={c.requestId} label="Request id" />
                            <TruncatedCopyable value={c.traceId} label="Trace id" />
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">
                          <TruncatedCopyable
                            value={c.parentActionFingerprint}
                            label="Parent action fingerprint"
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
