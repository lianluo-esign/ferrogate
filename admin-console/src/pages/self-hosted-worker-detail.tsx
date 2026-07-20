// Self-hosted worker detail (issue #320): the evidence surface for one
// registered customer worker. Reads the storage-backed worker projection
// (GET /admin/v1/self-hosted-workers/{id}) for identity + heartbeat +
// checkpoint/artifact counts, and the reported telemetry stream
// (GET /admin/v1/self-hosted-workers/{id}/events) for the per-event timeline.
//
// Rotate (POST .../rotate, #249 mTLS) issues a new durable identity
// fingerprint that is shown ONCE, mirroring worker registration. Everything
// here is customer-reported evidence (trust_level:
// reported_by_self_hosted_worker), never managed-worker enforcement proof.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  formatUnix,
  tenantLabel,
  TruncatedCopyable,
} from "@/components/agent-ops/agent-ops-primitives";
import {
  CredentialRevealDialog,
  parseReportedCorrelation,
  ReportedTrustBadge,
  workerStatusVariant,
} from "@/components/worker-ops/worker-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";

function OverviewField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-0.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="break-all text-sm">{children}</span>
    </div>
  );
}

function CountCard({
  title,
  count,
  latestLabel,
  latestUnix,
  testId,
}: {
  title: string;
  count: number;
  latestLabel: string;
  latestUnix: number | null | undefined;
  testId: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold" data-testid={testId}>
          {count}
        </div>
        <div className="text-xs text-muted-foreground">
          {latestLabel} {formatUnix(latestUnix)}
        </div>
      </CardContent>
    </Card>
  );
}

export default function SelfHostedWorkerDetailPage() {
  const { workerId = "" } = useParams<{ workerId: string }>();
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [rotateOpen, setRotateOpen] = useState(false);
  const [rotateFingerprint, setRotateFingerprint] = useState("");
  const [rotateExpiry, setRotateExpiry] = useState("");
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);

  const workerQueryKey = ["self-hosted-worker", workerId];
  const {
    data: worker,
    isLoading: workerLoading,
    error: workerError,
  } = useQuery({
    queryKey: workerQueryKey,
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/self-hosted-workers/{id}", {
        params: { id: workerId },
      }),
  });

  const { data: eventStream, isLoading: eventsLoading } = useQuery({
    queryKey: ["self-hosted-worker-events", workerId],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/self-hosted-workers/{id}/events", {
        params: { id: workerId },
        query: { limit: 100 },
      }),
  });

  const events = useMemo(() => eventStream?.data ?? [], [eventStream]);

  const rotateMutation = useMutation({
    mutationFn: (body: AdminSchema<"AdminSelfHostedWorkerRotateRequest">) =>
      adminPost(apiKey, "/admin/v1/self-hosted-workers/{id}/rotate", body, {
        params: { id: workerId },
      }),
    onSuccess: (response) => {
      toast.success("Worker identity rotated");
      setRotateOpen(false);
      setRotateFingerprint("");
      setRotateExpiry("");
      setRotateError(null);
      setRevealed(response.worker.identity_fingerprint);
      queryClient.invalidateQueries({ queryKey: workerQueryKey });
    },
    onError: (err: Error) => {
      setRotateError(err.message);
      toast.error(err.message);
    },
  });

  function submitRotate() {
    setRotateError(null);
    if (!rotateFingerprint.trim()) {
      setRotateError("A new identity fingerprint is required.");
      return;
    }
    if (rotateExpiry.trim() && Number.isNaN(Number(rotateExpiry.trim()))) {
      setRotateError("Identity expiry must be a Unix timestamp (seconds).");
      return;
    }
    rotateMutation.mutate({
      identity_fingerprint: rotateFingerprint.trim(),
      identity_expires_at_unix: rotateExpiry.trim() ? Number(rotateExpiry.trim()) : null,
    });
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <Link
          to="/app/workers/self-hosted"
          className="text-sm text-muted-foreground hover:underline"
        >
          ← Self-hosted workers
        </Link>
      </div>

      {workerError ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load worker: {workerError.message}
        </p>
      ) : null}

      {workerLoading ? (
        <p className="text-sm text-muted-foreground">Loading worker...</p>
      ) : worker ? (
        <>
          <div className="flex items-start justify-between gap-4">
            <div>
              <h1 className="text-lg font-semibold">{worker.worker_name}</h1>
              <div className="mt-1 flex items-center gap-2">
                <Badge variant={workerStatusVariant(worker.status)}>
                  {worker.status}
                </Badge>
                {worker.stale ? (
                  <Badge variant="outline" className="text-destructive">
                    stale
                  </Badge>
                ) : null}
                <ReportedTrustBadge />
              </div>
            </div>
            <Button onClick={() => setRotateOpen(true)}>Rotate identity</Button>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <CountCard
              title="Telemetry events"
              testId="count-events"
              count={worker.telemetry_event_count}
              latestLabel="Latest"
              latestUnix={worker.latest_event_at_unix}
            />
            <CountCard
              title="Checkpoints"
              testId="count-checkpoints"
              count={worker.checkpoint_count}
              latestLabel="Latest"
              latestUnix={worker.latest_checkpoint_at_unix}
            />
            <CountCard
              title="Artifacts"
              testId="count-artifacts"
              count={worker.artifact_count}
              latestLabel="Latest"
              latestUnix={worker.latest_artifact_at_unix}
            />
          </div>

          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="events">
                Events{events.length > 0 ? ` (${events.length})` : ""}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="overview">
              <Card>
                <CardContent className="grid gap-4 pt-6 sm:grid-cols-2">
                  <OverviewField label="Worker id">
                    <TruncatedCopyable value={worker.id} label="Worker id" prefixLength={28} />
                  </OverviewField>
                  <OverviewField label="Workspace">{worker.workspace_id}</OverviewField>
                  <OverviewField label="Tenant">{tenantLabel(worker.tenant)}</OverviewField>
                  <OverviewField label="Orchestration">
                    {worker.orchestration_enabled ? "Enabled" : "Disabled"}
                  </OverviewField>
                  <OverviewField label="Identity fingerprint">
                    <TruncatedCopyable
                      value={worker.identity_fingerprint}
                      label="Identity fingerprint"
                      prefixLength={28}
                    />
                  </OverviewField>
                  <OverviewField label="Identity expires">
                    {formatUnix(worker.identity_expires_at_unix)}
                  </OverviewField>
                  <OverviewField label="Registered">
                    {formatUnix(worker.registered_at_unix)}
                  </OverviewField>
                  <OverviewField label="Last seen">
                    {formatUnix(worker.last_seen_at_unix)}
                  </OverviewField>
                  <OverviewField label="Stale after">
                    {formatUnix(worker.stale_after_unix)}
                  </OverviewField>
                  <OverviewField label="Latest heartbeat">
                    {worker.latest_heartbeat
                      ? `${worker.latest_heartbeat.status} @ ${formatUnix(
                          worker.latest_heartbeat.observed_at_unix ??
                            worker.latest_heartbeat.reported_at_unix,
                        )}`
                      : "— (no heartbeat observed)"}
                  </OverviewField>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="events">
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Kind</TableHead>
                      <TableHead>Run / session</TableHead>
                      <TableHead>Correlation</TableHead>
                      <TableHead>Occurred</TableHead>
                      <TableHead>Ingested</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {eventsLoading ? (
                      <TableRow>
                        <TableCell colSpan={5} className="h-24 text-center">
                          Loading events...
                        </TableCell>
                      </TableRow>
                    ) : events.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="h-24 text-center">
                          No reported telemetry events.
                        </TableCell>
                      </TableRow>
                    ) : (
                      events.map((event) => {
                        const correlation = parseReportedCorrelation(event.event_json);
                        return (
                          <TableRow key={event.id} data-testid={`worker-event-${event.id}`}>
                            <TableCell>
                              <Badge variant="secondary">{event.kind}</Badge>
                            </TableCell>
                            <TableCell className="text-xs">
                              <div>run {event.run_id ?? "—"}</div>
                              <div className="text-muted-foreground">
                                session {event.session_id ?? "—"}
                              </div>
                            </TableCell>
                            <TableCell className="text-xs">
                              <div className="flex flex-col gap-1">
                                <span>
                                  req{" "}
                                  <TruncatedCopyable
                                    value={correlation.requestId}
                                    label="Request id"
                                  />
                                </span>
                                <span>
                                  trace{" "}
                                  <TruncatedCopyable
                                    value={correlation.traceId}
                                    label="Trace id"
                                  />
                                </span>
                              </div>
                            </TableCell>
                            <TableCell className="text-xs">
                              {formatUnix(event.occurred_at_unix)}
                            </TableCell>
                            <TableCell className="text-xs">
                              {formatUnix(event.ingested_at_unix)}
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </div>
            </TabsContent>
          </Tabs>
        </>
      ) : null}

      <Dialog
        open={rotateOpen}
        onOpenChange={(open) => {
          setRotateOpen(open);
          if (!open) {
            setRotateFingerprint("");
            setRotateExpiry("");
            setRotateError(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Rotate worker identity</DialogTitle>
            <DialogDescription>
              Issue a replacement mTLS identity fingerprint. The previous identity is
              retired and the new one is shown once.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="rotate-fingerprint">New identity fingerprint</Label>
              <Input
                id="rotate-fingerprint"
                value={rotateFingerprint}
                onChange={(e) => setRotateFingerprint(e.target.value)}
                placeholder="sha256:..."
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="rotate-expiry">Identity expiry Unix seconds (optional)</Label>
              <Input
                id="rotate-expiry"
                value={rotateExpiry}
                onChange={(e) => setRotateExpiry(e.target.value)}
                placeholder="leave blank for no expiry"
              />
            </div>
            {rotateError ? (
              <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {rotateError}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setRotateOpen(false)}>
              Cancel
            </Button>
            <Button
              type="button"
              disabled={rotateMutation.isPending}
              onClick={submitRotate}
            >
              {rotateMutation.isPending ? "Rotating..." : "Rotate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CredentialRevealDialog
        open={revealed !== null}
        onClose={() => setRevealed(null)}
        title="Identity rotated"
        description="Store the new identity fingerprint now. The previous credential no longer authenticates the worker."
        credentialLabel="New identity fingerprint"
        credential={revealed}
      />
    </div>
  );
}
