// Managed worker sessions (issue #320): the runtime-session ledger for
// gateway-managed (isolated) agent workers, read from
// GET /admin/v1/managed-worker-sessions. Unlike the existing read-only
// /app/managed-workers runtime-contract page, this lists actual persisted
// sessions with their isolation backend, lifecycle status, and per-session
// lifecycle event trail (exec/attach → stop → cleanup). Selecting a row opens
// its lifecycle event detail.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatUnix, tenantLabel } from "@/components/agent-ops/agent-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ManagedWorkerSession = AdminSchema<"AdminManagedWorkerSession">;

const PAGE_SIZE = 50;

function sessionStatusVariant(
  status: ManagedWorkerSession["status"],
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "running":
      return "default";
    case "completed":
    case "cleaned_up":
      return "secondary";
    case "failed":
    case "cancelled":
      return "destructive";
    default:
      return "outline";
  }
}

export default function ManagedWorkerSessionsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const [detail, setDetail] = useState<ManagedWorkerSession | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["managed-worker-sessions"],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/managed-worker-sessions", {
        query: { offset: 0, limit: PAGE_SIZE },
      }),
  });

  const sessions = useMemo<ManagedWorkerSession[]>(() => data?.data ?? [], [data]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.managedWorkerSessions.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.managedWorkerSessions.description")}
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.managedWorkerSessions.error", { message: error.message })}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.managedWorkerSessions.col.session")}</TableHead>
              <TableHead>{t("page.managedWorkerSessions.col.run")}</TableHead>
              <TableHead>{t("common.tenant")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
              <TableHead>{t("page.managedWorkerSessions.col.isolation")}</TableHead>
              <TableHead>{t("page.managedWorkerSessions.col.started")}</TableHead>
              <TableHead>{t("page.managedWorkerSessions.col.lifecycleEvents")}</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : sessions.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("page.managedWorkerSessions.empty")}
                </TableCell>
              </TableRow>
            ) : (
              sessions.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <div className="font-medium">{row.id}</div>
                    <div className="text-xs text-muted-foreground">
                      {t("page.managedWorkerSessions.row.template", {
                        id: row.worker_template_id,
                      })}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{row.run_id}</TableCell>
                  <TableCell className="text-xs">{tenantLabel(row.tenant)}</TableCell>
                  <TableCell>
                    <Badge variant={sessionStatusVariant(row.status)}>{row.status}</Badge>
                  </TableCell>
                  <TableCell className="text-xs">{row.isolation_backend_kind}</TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(row.started_at_unix)}
                  </TableCell>
                  <TableCell className="text-xs">{row.lifecycle_events.length}</TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" onClick={() => setDetail(row)}>
                      {t("page.managedWorkerSessions.details")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog open={detail !== null} onOpenChange={(open) => !open && setDetail(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          {detail ? (
            <>
              <DialogHeader>
                <DialogTitle>
                  {t("page.managedWorkerSessions.dialog.title", { id: detail.id })}
                </DialogTitle>
                <DialogDescription>
                  {t("page.managedWorkerSessions.dialog.description", {
                    run: detail.run_id,
                    backend: detail.isolation_backend_kind,
                    vm: detail.microvm_id
                      ? t("page.managedWorkerSessions.dialog.microvm", {
                          id: detail.microvm_id,
                        })
                      : t("page.managedWorkerSessions.dialog.noMicrovm"),
                  })}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.managedWorkerSessions.field.capabilityEnvelope")}
                  </span>
                  <div className="break-all">{detail.capability_envelope_id}</div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.managedWorkerSessions.field.workerInstance")}
                  </span>
                  <div className="break-all">
                    {detail.agent_worker_instance_id ?? "—"}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.managedWorkerSessions.field.requestedStarted")}
                  </span>
                  <div>
                    {formatUnix(detail.requested_at_unix)} →{" "}
                    {formatUnix(detail.started_at_unix)}
                  </div>
                </div>
                <div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.managedWorkerSessions.field.completedCleanedUp")}
                  </span>
                  <div>
                    {formatUnix(detail.completed_at_unix)} →{" "}
                    {formatUnix(detail.cleanup_completed_at_unix)}
                  </div>
                </div>
              </div>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("page.managedWorkerSessions.events.col.action")}</TableHead>
                      <TableHead>{t("common.status")}</TableHead>
                      <TableHead>{t("page.managedWorkerSessions.events.col.outcome")}</TableHead>
                      <TableHead>{t("page.managedWorkerSessions.events.col.occurred")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detail.lifecycle_events.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="h-16 text-center">
                          {t("page.managedWorkerSessions.events.empty")}
                        </TableCell>
                      </TableRow>
                    ) : (
                      detail.lifecycle_events.map((event) => (
                        <TableRow
                          key={event.id}
                          data-testid={`lifecycle-event-${event.id}`}
                        >
                          <TableCell className="text-xs">{event.action}</TableCell>
                          <TableCell>
                            <Badge variant={sessionStatusVariant(event.status)}>
                              {event.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs">{event.outcome}</TableCell>
                          <TableCell className="text-xs">
                            {formatUnix(event.occurred_at_unix)}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setDetail(null)}>
                  {t("page.managedWorkerSessions.close")}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
