// Async agent-job console (issue #474). The operator counterpart of the
// caller-facing long-running job protocol: submit a task, get a durable
// `run_id` back, watch the run advance as the runtime reports it, collect the
// result, and cancel.
//
// This is the ONE console surface for `/v1/agent-jobs`, so the #463 coverage
// gate's caller-facing check keys on the call sites below. It deliberately does
// NOT re-implement retrieval: `/v1/agent-jobs/{run_id}/result` is the single
// collect verb, and the artifacts it returns are the runtime's own work-product
// evidence.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatUnix, TruncatedCopyable } from "@/components/agent-ops/agent-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet, adminPost, gatewayPost, type AdminSchema } from "@/lib/gateway-client";

type AgentJobStatus = AdminSchema<"AgentJobStatus">;

/** Poll while the job is live; stop the moment it is terminal. */
const LIVE_POLL_INTERVAL_MS = 4_000;

function StatusBadge({ status, terminal }: { status: string; terminal: boolean }) {
  return <Badge variant={terminal ? "secondary" : "default"}>{status}</Badge>;
}

export default function AgentJobsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [input, setInput] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [runIdInput, setRunIdInput] = useState("");
  const [activeRunId, setActiveRunId] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [cancelError, setCancelError] = useState<string | null>(null);

  const status = useQuery<AgentJobStatus>({
    queryKey: ["agent-job", activeRunId],
    enabled: activeRunId !== "",
    refetchInterval: (query) => (query.state.data?.terminal ? false : LIVE_POLL_INTERVAL_MS),
    queryFn: () =>
      adminGet(apiKey, "/v1/agent-jobs/{run_id}", { params: { run_id: activeRunId } }),
  });

  const events = useQuery({
    queryKey: ["agent-job-events", activeRunId],
    enabled: activeRunId !== "",
    refetchInterval: status.data?.terminal ? false : LIVE_POLL_INTERVAL_MS,
    queryFn: () =>
      adminGet(apiKey, "/v1/agent-jobs/{run_id}/events", {
        params: { run_id: activeRunId },
      }),
  });

  // Collect is only meaningful once the runtime (or a cancel) settled the run;
  // before that the endpoint answers 409 by contract, so it is not requested.
  const result = useQuery({
    queryKey: ["agent-job-result", activeRunId],
    enabled: activeRunId !== "" && status.data?.terminal === true,
    queryFn: () =>
      adminGet(apiKey, "/v1/agent-jobs/{run_id}/result", {
        params: { run_id: activeRunId },
      }),
  });

  const submit = useMutation({
    mutationFn: () =>
      adminPost(apiKey, "/v1/agent-jobs", {
        input: input.trim(),
        idempotency_key: idempotencyKey.trim() === "" ? undefined : idempotencyKey.trim(),
      }),
    onSuccess: (job) => {
      setSubmitError(null);
      setActiveRunId(job.run_id);
      setRunIdInput(job.run_id);
    },
    onError: (error: Error) => setSubmitError(error.message),
  });

  const cancel = useMutation({
    mutationFn: () => gatewayPost(apiKey, `/v1/agent-jobs/${activeRunId}/cancel`),
    onSuccess: async () => {
      setCancelError(null);
      await queryClient.invalidateQueries({ queryKey: ["agent-job", activeRunId] });
      await queryClient.invalidateQueries({ queryKey: ["agent-job-events", activeRunId] });
    },
    onError: (error: Error) => setCancelError(error.message),
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.agentJobs.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.agentJobs.description")}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.agentJobs.submit.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              submit.mutate();
            }}
          >
            <div className="grid gap-1.5">
              <Label htmlFor="agent-job-input">{t("page.agentJobs.field.input")}</Label>
              <Textarea
                id="agent-job-input"
                value={input}
                rows={3}
                onChange={(e) => setInput(e.target.value)}
                placeholder={t("page.agentJobs.placeholder.input")}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="agent-job-key">{t("page.agentJobs.field.idempotencyKey")}</Label>
              <Input
                id="agent-job-key"
                value={idempotencyKey}
                onChange={(e) => setIdempotencyKey(e.target.value)}
                placeholder={t("page.agentJobs.placeholder.idempotencyKey")}
              />
              <p className="text-xs text-muted-foreground">
                {t("page.agentJobs.hint.idempotencyKey")}
              </p>
            </div>
            <div>
              <Button type="submit" disabled={input.trim() === "" || submit.isPending}>
                {t("page.agentJobs.submit.action")}
              </Button>
            </div>
          </form>
          {submitError ? (
            <p
              role="alert"
              className="mt-3 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              {t("page.agentJobs.submit.error", { message: submitError })}
            </p>
          ) : null}
          {submit.data ? (
            <p className="mt-3 text-sm text-muted-foreground">
              {submit.data.deduplicated
                ? t("page.agentJobs.submit.deduplicated", { runId: submit.data.run_id })
                : t("page.agentJobs.submit.accepted", { runId: submit.data.run_id })}
            </p>
          ) : null}
        </CardContent>
      </Card>

      <form
        className="flex items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setActiveRunId(runIdInput.trim());
        }}
      >
        <div className="grid flex-1 gap-1.5">
          <Label htmlFor="agent-job-run-id">{t("page.agentJobs.field.runId")}</Label>
          <Input
            id="agent-job-run-id"
            value={runIdInput}
            onChange={(e) => setRunIdInput(e.target.value)}
            // eslint-disable-next-line ferrogate/no-untranslated-literal -- job id format, not translatable copy
            placeholder="job-..."
          />
        </div>
        <Button type="submit" disabled={runIdInput.trim() === ""}>
          {t("page.agentJobs.track")}
        </Button>
      </form>

      {status.error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.agentJobs.error", { runId: activeRunId, message: status.error.message })}
        </p>
      ) : null}

      {activeRunId === "" ? (
        <p className="text-sm text-muted-foreground">{t("page.agentJobs.prompt")}</p>
      ) : status.isLoading ? (
        <p className="text-sm text-muted-foreground">
          {t("page.agentJobs.loading", { runId: activeRunId })}
        </p>
      ) : status.data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t("page.agentJobs.card.title", { runId: status.data.run_id })}
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <div className="grid gap-3 text-sm sm:grid-cols-3">
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.agentJobs.field.status")}
                  </span>
                  <div>
                    <StatusBadge status={status.data.status} terminal={status.data.terminal} />
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.agentJobs.field.runtimeReportedState")}
                  </span>
                  <div>{status.data.runtime_reported_state ?? "—"}</div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.agentJobs.field.turns")}
                  </span>
                  <div>{status.data.turns_executed}</div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.agentJobs.field.startedCompleted")}
                  </span>
                  <div>
                    {formatUnix(status.data.started_at_unix)} →{" "}
                    {formatUnix(status.data.completed_at_unix)}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.agentJobs.field.events")}
                  </span>
                  <div>{status.data.event_count}</div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.agentJobs.field.requestId")}
                  </span>
                  <div>
                    <TruncatedCopyable
                      value={status.data.request_id}
                      label={t("page.agentJobs.field.requestId")}
                    />
                  </div>
                </div>
              </div>
              <div>
                <Button
                  variant="destructive"
                  disabled={status.data.terminal || cancel.isPending}
                  onClick={() => cancel.mutate()}
                >
                  {t("page.agentJobs.cancel")}
                </Button>
              </div>
              {cancelError ? (
                <p role="alert" className="text-sm text-destructive">
                  {t("page.agentJobs.cancel.error", { message: cancelError })}
                </p>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("page.agentJobs.result.title")}</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 text-sm">
              {!status.data.terminal ? (
                <p className="text-muted-foreground">{t("page.agentJobs.result.pending")}</p>
              ) : result.data ? (
                <>
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">
                      {t("page.agentJobs.result.output")}
                    </span>
                    <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap rounded-md border bg-muted/40 p-2 text-xs">
                      {result.data.output ?? t("page.agentJobs.result.noOutput")}
                    </pre>
                  </div>
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">
                      {t("page.agentJobs.result.artifacts")}
                    </span>
                    <div>
                      {result.data.artifacts.length === 0
                        ? t("page.agentJobs.result.noArtifacts")
                        : result.data.artifacts.map((artifact) => artifact.id).join(", ")}
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-muted-foreground">{t("page.agentJobs.result.loading")}</p>
              )}
            </CardContent>
          </Card>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("page.agentJobs.col.kind")}</TableHead>
                  <TableHead>{t("page.agentJobs.col.outcome")}</TableHead>
                  <TableHead>{t("page.agentJobs.col.message")}</TableHead>
                  <TableHead>{t("page.agentJobs.col.occurred")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(events.data?.data ?? []).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="h-24 text-center">
                      {t("page.agentJobs.events.empty")}
                    </TableCell>
                  </TableRow>
                ) : (
                  (events.data?.data ?? []).map((event) => (
                    <TableRow key={event.id} data-testid={`agent-job-event-${event.id}`}>
                      <TableCell>
                        <Badge variant="secondary">{event.kind}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{event.outcome}</TableCell>
                      <TableCell className="max-w-md truncate text-xs">
                        {event.message ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs">{formatUnix(event.occurred_at_unix)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </>
      ) : null}
    </div>
  );
}
