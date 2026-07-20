// Agent run timeline (issue #317): renders GET /admin/v1/agent-runs/{run_id}
// as the #304 evidence chain — agent events (capability/guardrail/lifecycle
// kinds) merged with the run's audit events into one time-ordered timeline,
// with the structured governance columns (action_fingerprint, decision,
// decision_reason, output_disposition) and correlation ids
// (request_id/trace_id) on every row.
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DecisionBadge,
  EventFamilyBadge,
  eventFamily,
  formatUnix,
  runStatusBadgeVariant,
  tenantLabel,
  TruncatedCopyable,
  type TimelineEventFamily,
} from "@/components/agent-ops/agent-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

export type AgentRunTimeline = AdminSchema<"AgentRunTimeline">;

interface TimelineEntry {
  id: string;
  family: TimelineEventFamily;
  turn: number | null;
  kind: string;
  target: string;
  outcome: string;
  message: string | null;
  actionFingerprint: string | null;
  decision: string | null;
  decisionReason: string | null;
  outputDisposition: string | null;
  requestId: string;
  traceId: string | null;
  occurredAtUnix: number | null;
}

/**
 * Merges the timeline's agent events (kind-prefixed capability./guardrail.
 * evidence plus lifecycle rows) with its audit events into one list ordered
 * by occurred_at (stable within equal/missing timestamps: agent events keep
 * their stored order, audit events follow).
 */
export function mergeTimeline(timeline: AgentRunTimeline): TimelineEntry[] {
  const agentEntries: TimelineEntry[] = timeline.agent_events.map((event) => ({
    id: `agent-${event.id}`,
    family: eventFamily(event.kind),
    turn: event.turn,
    kind: event.kind,
    target: event.target,
    outcome: event.outcome,
    message: event.message ?? null,
    actionFingerprint: event.action_fingerprint ?? null,
    decision: event.decision ?? null,
    decisionReason: event.decision_reason ?? null,
    outputDisposition: event.output_disposition ?? null,
    requestId: event.request_id,
    traceId: event.trace_id ?? null,
    occurredAtUnix: event.occurred_at_unix ?? null,
  }));
  const auditEntries: TimelineEntry[] = timeline.audit_events.map((event) => ({
    id: `audit-${event.id}`,
    family: "audit",
    turn: null,
    kind: event.action,
    target: event.target,
    outcome: event.outcome,
    message: event.message,
    actionFingerprint: event.action_fingerprint ?? null,
    decision: event.decision ?? null,
    decisionReason: event.decision_reason ?? null,
    outputDisposition: event.output_disposition ?? null,
    requestId: event.request_id,
    traceId: event.trace_id ?? null,
    occurredAtUnix: event.occurred_at_unix ?? null,
  }));
  // Array.prototype.sort is stable, so ties keep agent-before-audit order.
  return [...agentEntries, ...auditEntries].sort(
    (a, b) =>
      (a.occurredAtUnix ?? Number.MAX_SAFE_INTEGER) -
      (b.occurredAtUnix ?? Number.MAX_SAFE_INTEGER),
  );
}

export default function AgentRunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["agent-run-timeline", runId],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/agent-runs/{run_id}", {
        params: { run_id: runId! },
      }),
    enabled: Boolean(runId),
  });

  const entries = useMemo(() => (data ? mergeTimeline(data) : []), [data]);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading run timeline...</p>;
  }
  if (error) {
    return (
      <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
        Failed to load agent run: {error.message}
      </p>
    );
  }
  if (!data) return null;

  const { summary, run } = data;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">
          Agent run <span className="font-mono text-base">{data.id}</span>
        </h1>
        <Badge variant={runStatusBadgeVariant(summary.status)}>{summary.status}</Badge>
        <Link
          to="/app/agent-runs"
          className="text-sm text-muted-foreground underline underline-offset-2"
        >
          Back to runs
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Run summary</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">Tenant</dt>
              <dd className="font-mono text-xs">{tenantLabel(summary.tenant)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Request ID</dt>
              <dd>
                {run ? (
                  <TruncatedCopyable value={run.request_id} label="request id" prefixLength={24} />
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Trace ID</dt>
              <dd>
                {run?.trace_id ? (
                  <TruncatedCopyable value={run.trace_id} label="trace id" prefixLength={24} />
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Provider / turns</dt>
              <dd>
                {run ? `${run.provider} / ${run.turns_executed} turns` : "—"}
                {run ? (run.output_recorded ? " (output recorded)" : " (no output)") : ""}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Correlated counts</dt>
              <dd>
                {summary.request_count} requests · {summary.billing_event_count} billing ·{" "}
                {summary.audit_event_count} audit · {summary.agent_event_count} agent events
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Window</dt>
              <dd className="text-xs">
                {formatUnix(summary.first_seen_unix)} → {formatUnix(summary.last_seen_unix)}
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Timeline</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Turn</TableHead>
                <TableHead>Family</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Outcome</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Output</TableHead>
                <TableHead>Fingerprint</TableHead>
                <TableHead>Correlation</TableHead>
                <TableHead>Message</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={12} className="h-24 text-center">
                    No timeline events recorded for this run.
                  </TableCell>
                </TableRow>
              ) : (
                entries.map((entry) => (
                  <TableRow key={entry.id} data-testid={`timeline-${entry.id}`}>
                    <TableCell className="whitespace-nowrap text-xs">
                      {formatUnix(entry.occurredAtUnix)}
                    </TableCell>
                    <TableCell>{entry.turn ?? "—"}</TableCell>
                    <TableCell>
                      <EventFamilyBadge family={entry.family} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{entry.kind}</TableCell>
                    <TableCell className="font-mono text-xs">{entry.target}</TableCell>
                    <TableCell className="text-xs">{entry.outcome}</TableCell>
                    <TableCell>
                      <DecisionBadge decision={entry.decision} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {entry.decisionReason ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs">{entry.outputDisposition ?? "—"}</TableCell>
                    <TableCell>
                      <TruncatedCopyable
                        value={entry.actionFingerprint}
                        label="action fingerprint"
                      />
                    </TableCell>
                    <TableCell className="text-xs">
                      <div className="flex flex-col gap-0.5">
                        <TruncatedCopyable
                          value={entry.requestId}
                          label="request id"
                          prefixLength={12}
                        />
                        <TruncatedCopyable
                          value={entry.traceId}
                          label="trace id"
                          prefixLength={12}
                        />
                      </div>
                    </TableCell>
                    <TableCell className="max-w-72 truncate text-xs" title={entry.message ?? ""}>
                      {entry.message ?? "—"}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Requests ({data.requests.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Request ID</TableHead>
                <TableHead>Route</TableHead>
                <TableHead>Model</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Started</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.requests.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-16 text-center">
                    No correlated requests.
                  </TableCell>
                </TableRow>
              ) : (
                data.requests.map((request, index) => (
                  <TableRow key={request.request_id ?? index}>
                    <TableCell>
                      <TruncatedCopyable
                        value={request.request_id}
                        label="request id"
                        prefixLength={24}
                      />
                    </TableCell>
                    <TableCell className="text-xs">{request.route ?? "—"}</TableCell>
                    <TableCell className="text-xs">{request.logical_model ?? "—"}</TableCell>
                    <TableCell className="text-xs">{request.provider ?? "—"}</TableCell>
                    <TableCell className="text-xs">{request.status_code ?? "—"}</TableCell>
                    <TableCell className="text-xs">{formatUnix(request.started_at_unix)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Billing events ({data.billing_events.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Request ID</TableHead>
                <TableHead>Model</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Tokens (p/c)</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Occurred</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.billing_events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-16 text-center">
                    No correlated billing events.
                  </TableCell>
                </TableRow>
              ) : (
                data.billing_events.map((event, index) => (
                  <TableRow key={`${event.request_id}-${index}`}>
                    <TableCell>
                      <TruncatedCopyable
                        value={event.request_id}
                        label="request id"
                        prefixLength={24}
                      />
                    </TableCell>
                    <TableCell className="text-xs">{event.logical_model}</TableCell>
                    <TableCell className="text-xs">{event.provider}</TableCell>
                    <TableCell className="text-xs">
                      {event.usage.prompt_tokens} / {event.usage.completion_tokens}
                    </TableCell>
                    <TableCell className="text-xs">{event.usage_source}</TableCell>
                    <TableCell className="text-xs">{formatUnix(event.occurred_at_unix)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
