// Agent schedules (issues #251/#317): CRUD over /admin/v1/agent-schedules,
// per-schedule fire history (GET .../{id}/fires) and a confirmed manual
// "Run now" (POST .../{id}/run-now) that surfaces the recorded fire
// (outcome + dispatch/run ids) from the 202 response.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  fireOutcomeBadgeVariant,
  formatUnix,
} from "@/components/agent-ops/agent-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import {
  adminDelete,
  adminGet,
  adminPost,
  adminPut,
  type AdminSchema,
} from "@/lib/gateway-client";

export type AdminAgentSchedule = AdminSchema<"AdminAgentSchedule">;
export type AdminAgentScheduleFire = AdminSchema<"AdminAgentScheduleFire">;
type ScheduleMutation = AdminSchema<"AdminAgentScheduleMutation">;

interface ScheduleFormState {
  name: string;
  tenant_id: string;
  workspace_id: string;
  enabled: boolean;
  spec_kind: "cron" | "interval";
  cron_expr: string;
  timezone: string;
  interval_secs: string;
  target_kind: "self_hosted_dispatch" | "agent_run";
  target: string;
  overlap_policy: "skip" | "allow";
  catchup_policy: "skip_missed" | "fire_once";
  jitter_secs: string;
}

const EMPTY_FORM: ScheduleFormState = {
  name: "",
  tenant_id: "",
  workspace_id: "",
  enabled: true,
  spec_kind: "cron",
  cron_expr: "",
  timezone: "UTC",
  interval_secs: "",
  target_kind: "agent_run",
  target: "{}",
  overlap_policy: "skip",
  catchup_policy: "skip_missed",
  jitter_secs: "0",
};

function formFromSchedule(schedule: AdminAgentSchedule): ScheduleFormState {
  return {
    name: schedule.name,
    tenant_id: schedule.tenant_id,
    workspace_id: schedule.workspace_id,
    enabled: schedule.enabled,
    spec_kind: schedule.spec_kind,
    cron_expr: schedule.cron_expr ?? "",
    timezone: schedule.timezone,
    interval_secs: schedule.interval_secs != null ? String(schedule.interval_secs) : "",
    target_kind: schedule.target_kind,
    target: JSON.stringify(schedule.target ?? {}, null, 2),
    overlap_policy: schedule.overlap_policy,
    catchup_policy: schedule.catchup_policy,
    jitter_secs: String(schedule.jitter_secs),
  };
}

function mutationFromForm(form: ScheduleFormState): ScheduleMutation {
  let target: ScheduleMutation["target"];
  try {
    target = JSON.parse(form.target || "{}") as ScheduleMutation["target"];
  } catch {
    throw new Error("Target must be valid JSON");
  }
  const body: ScheduleMutation = {
    name: form.name.trim(),
    tenant_id: form.tenant_id.trim(),
    workspace_id: form.workspace_id.trim(),
    enabled: form.enabled,
    spec_kind: form.spec_kind,
    timezone: form.timezone.trim() || "UTC",
    target_kind: form.target_kind,
    target,
    overlap_policy: form.overlap_policy,
    catchup_policy: form.catchup_policy,
    jitter_secs: Number(form.jitter_secs || "0"),
  };
  if (form.spec_kind === "cron") {
    if (!form.cron_expr.trim()) throw new Error("Cron expression is required");
    body.cron_expr = form.cron_expr.trim();
  } else {
    if (!form.interval_secs.trim()) throw new Error("Interval seconds is required");
    body.interval_secs = Number(form.interval_secs);
  }
  return body;
}

const SPEC_KIND_OPTIONS = [
  { label: "Cron", value: "cron" },
  { label: "Interval", value: "interval" },
] as const;

const TARGET_KIND_OPTIONS = [
  { label: "Agent run", value: "agent_run" },
  { label: "Self-hosted dispatch", value: "self_hosted_dispatch" },
] as const;

function scheduleSpecLabel(schedule: AdminAgentSchedule): string {
  return schedule.spec_kind === "cron"
    ? `cron ${schedule.cron_expr ?? "?"} (${schedule.timezone})`
    : `every ${schedule.interval_secs ?? "?"}s`;
}

export default function AgentSchedulesPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const listQueryKey = ["agent-schedules"];

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<AdminAgentSchedule | null>(null);
  const [form, setForm] = useState<ScheduleFormState>(EMPTY_FORM);
  const [runNowTarget, setRunNowTarget] = useState<AdminAgentSchedule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AdminAgentSchedule | null>(null);
  const [firesFor, setFiresFor] = useState<AdminAgentSchedule | null>(null);
  const [lastFire, setLastFire] = useState<{
    scheduleName: string;
    fire: AdminAgentScheduleFire;
  } | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: listQueryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/agent-schedules"),
  });

  const firesQuery = useQuery({
    queryKey: ["agent-schedule-fires", firesFor?.id],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/agent-schedules/{id}/fires", {
        params: { id: firesFor!.id },
      }),
    enabled: Boolean(firesFor),
  });

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body = mutationFromForm(form);
      if (editing) {
        return adminPut(apiKey, "/admin/v1/agent-schedules/{id}", body, {
          params: { id: editing.id },
        });
      }
      return adminPost(apiKey, "/admin/v1/agent-schedules", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: listQueryKey });
      toast.success(editing ? "Schedule updated" : "Schedule created");
      setFormOpen(false);
      setEditing(null);
      setForm(EMPTY_FORM);
    },
    onError: (saveError: Error) => toast.error(saveError.message),
  });

  const runNowMutation = useMutation({
    mutationFn: (schedule: AdminAgentSchedule) =>
      adminPost(apiKey, "/admin/v1/agent-schedules/{id}/run-now", undefined, {
        params: { id: schedule.id },
      }),
    onSuccess: (response, schedule) => {
      setLastFire({ scheduleName: schedule.name, fire: response.fire });
      toast.success(`Manual fire recorded: ${response.fire.outcome}`);
      queryClient.invalidateQueries({ queryKey: listQueryKey });
      queryClient.invalidateQueries({ queryKey: ["agent-schedule-fires", schedule.id] });
    },
    onError: (runError: Error) => toast.error(runError.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (schedule: AdminAgentSchedule) =>
      adminDelete(apiKey, "/admin/v1/agent-schedules/{id}", {
        params: { id: schedule.id },
      }),
    onSuccess: (_response, schedule) => {
      queryClient.invalidateQueries({ queryKey: listQueryKey });
      if (firesFor?.id === schedule.id) setFiresFor(null);
      toast.success("Schedule deleted");
    },
    onError: (deleteError: Error) => toast.error(deleteError.message),
  });

  function openCreate() {
    setEditing(null);
    setForm(EMPTY_FORM);
    setFormOpen(true);
  }

  function openEdit(schedule: AdminAgentSchedule) {
    setEditing(schedule);
    setForm(formFromSchedule(schedule));
    setFormOpen(true);
  }

  const rows = data?.data ?? [];
  const fires = firesQuery.data?.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Agent schedules</h1>
          <p className="text-sm text-muted-foreground">
            Cron/interval schedules that fire agent runs or self-hosted dispatches (#251). Fires
            record the dispatch outcome; Run now fires a schedule immediately.
          </p>
        </div>
        <Button onClick={openCreate}>New schedule</Button>
      </div>

      {error && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load agent schedules: {error.message}
        </p>
      )}

      {lastFire && (
        <Card data-testid="last-manual-fire">
          <CardHeader>
            <CardTitle className="text-base">
              Last manual fire — {lastFire.scheduleName}
            </CardTitle>
            <CardDescription>Recorded by POST /run-now.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <Badge variant={fireOutcomeBadgeVariant(lastFire.fire.outcome)}>
              {lastFire.fire.outcome}
            </Badge>
            <span className="font-mono text-xs">fire {lastFire.fire.fire_id}</span>
            {lastFire.fire.dispatch_id && (
              <span className="font-mono text-xs">dispatch {lastFire.fire.dispatch_id}</span>
            )}
            {lastFire.fire.run_id && (
              <span className="font-mono text-xs">run {lastFire.fire.run_id}</span>
            )}
            <span className="text-xs text-muted-foreground">
              fired {formatUnix(lastFire.fire.fired_at_unix)}
            </span>
            {lastFire.fire.detail && (
              <span className="text-xs text-muted-foreground">{lastFire.fire.detail}</span>
            )}
          </CardContent>
        </Card>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Tenant / workspace</TableHead>
              <TableHead>Spec</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead>Next fire</TableHead>
              <TableHead>Last fire</TableHead>
              <TableHead className="w-72" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  No schedules yet.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((schedule) => (
                <TableRow key={schedule.id}>
                  <TableCell className="font-medium">{schedule.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {schedule.tenant_id} / {schedule.workspace_id}
                  </TableCell>
                  <TableCell className="text-xs">{scheduleSpecLabel(schedule)}</TableCell>
                  <TableCell className="text-xs">{schedule.target_kind}</TableCell>
                  <TableCell>
                    <Badge variant={schedule.enabled ? "secondary" : "outline"}>
                      {schedule.enabled ? "enabled" : "disabled"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(schedule.next_fire_at_unix)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(schedule.last_fire_at_unix)}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setRunNowTarget(schedule)}
                      >
                        Run now
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setFiresFor(schedule)}>
                        Fires
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => openEdit(schedule)}>
                        Edit
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setDeleteTarget(schedule)}
                      >
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {firesFor && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Fire history — {firesFor.name}</CardTitle>
            <CardDescription>
              Recorded fires for schedule <span className="font-mono">{firesFor.id}</span>.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {firesQuery.error ? (
              <p className="px-4 py-3 text-sm text-destructive">
                Failed to load fires: {firesQuery.error.message}
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Fire ID</TableHead>
                    <TableHead>Scheduled</TableHead>
                    <TableHead>Fired</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>Dispatch / run</TableHead>
                    <TableHead>Node</TableHead>
                    <TableHead>Detail</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {firesQuery.isLoading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="h-16 text-center">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : fires.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="h-16 text-center">
                        No fires recorded yet.
                      </TableCell>
                    </TableRow>
                  ) : (
                    fires.map((fire) => (
                      <TableRow key={fire.fire_id}>
                        <TableCell className="font-mono text-xs">{fire.fire_id}</TableCell>
                        <TableCell className="text-xs">
                          {formatUnix(fire.scheduled_fire_at_unix)}
                        </TableCell>
                        <TableCell className="text-xs">{formatUnix(fire.fired_at_unix)}</TableCell>
                        <TableCell>
                          <Badge variant={fireOutcomeBadgeVariant(fire.outcome)}>
                            {fire.outcome}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {fire.dispatch_id ?? fire.run_id ?? "—"}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{fire.node_id ?? "—"}</TableCell>
                        <TableCell className="text-xs">{fire.detail ?? "—"}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <Dialog
        open={formOpen}
        onOpenChange={(open) => {
          setFormOpen(open);
          if (!open) setEditing(null);
        }}
      >
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.name}` : "New schedule"}</DialogTitle>
          </DialogHeader>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              saveMutation.mutate();
            }}
          >
            <div className="grid gap-2">
              <Label htmlFor="schedule-name">Name</Label>
              <Input
                id="schedule-name"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
              />
            </div>
            <div className="flex items-center gap-2 pt-6">
              <Switch
                id="schedule-enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm({ ...form, enabled: checked })}
              />
              <Label htmlFor="schedule-enabled">Enabled</Label>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-tenant">Tenant ID</Label>
              <Input
                id="schedule-tenant"
                value={form.tenant_id}
                onChange={(event) => setForm({ ...form, tenant_id: event.target.value })}
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-workspace">Workspace ID</Label>
              <Input
                id="schedule-workspace"
                value={form.workspace_id}
                onChange={(event) => setForm({ ...form, workspace_id: event.target.value })}
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-spec-kind">Spec kind</Label>
              <Select
                value={form.spec_kind}
                onValueChange={(value) =>
                  setForm({ ...form, spec_kind: value as ScheduleFormState["spec_kind"] })
                }
              >
                <SelectTrigger id="schedule-spec-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SPEC_KIND_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {form.spec_kind === "cron" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-cron">Cron expression</Label>
                  <Input
                    id="schedule-cron"
                    value={form.cron_expr}
                    onChange={(event) => setForm({ ...form, cron_expr: event.target.value })}
                    placeholder="*/5 * * * *"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-timezone">Timezone</Label>
                  <Input
                    id="schedule-timezone"
                    value={form.timezone}
                    onChange={(event) => setForm({ ...form, timezone: event.target.value })}
                    placeholder="UTC"
                  />
                </div>
              </>
            ) : (
              <div className="grid gap-2">
                <Label htmlFor="schedule-interval">Interval (seconds)</Label>
                <Input
                  id="schedule-interval"
                  type="number"
                  min={1}
                  value={form.interval_secs}
                  onChange={(event) => setForm({ ...form, interval_secs: event.target.value })}
                />
              </div>
            )}
            <div className="grid gap-2">
              <Label htmlFor="schedule-target-kind">Target kind</Label>
              <Select
                value={form.target_kind}
                onValueChange={(value) =>
                  setForm({ ...form, target_kind: value as ScheduleFormState["target_kind"] })
                }
              >
                <SelectTrigger id="schedule-target-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TARGET_KIND_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-jitter">Jitter (seconds)</Label>
              <Input
                id="schedule-jitter"
                type="number"
                min={0}
                value={form.jitter_secs}
                onChange={(event) => setForm({ ...form, jitter_secs: event.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-overlap">Overlap policy</Label>
              <Select
                value={form.overlap_policy}
                onValueChange={(value) =>
                  setForm({
                    ...form,
                    overlap_policy: value as ScheduleFormState["overlap_policy"],
                  })
                }
              >
                <SelectTrigger id="schedule-overlap">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="skip">Skip overlapping fires</SelectItem>
                  <SelectItem value="allow">Allow overlapping fires</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-catchup">Catch-up policy</Label>
              <Select
                value={form.catchup_policy}
                onValueChange={(value) =>
                  setForm({
                    ...form,
                    catchup_policy: value as ScheduleFormState["catchup_policy"],
                  })
                }
              >
                <SelectTrigger id="schedule-catchup">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="skip_missed">Skip missed fires</SelectItem>
                  <SelectItem value="fire_once">Fire once for missed window</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="schedule-target">Target (JSON)</Label>
              <Textarea
                id="schedule-target"
                className="font-mono text-xs"
                rows={5}
                value={form.target}
                onChange={(event) => setForm({ ...form, target: event.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={saveMutation.isPending}>
                {saveMutation.isPending ? "Saving..." : editing ? "Save" : "Create"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={Boolean(runNowTarget)}
        onOpenChange={(open) => {
          if (!open) setRunNowTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Run schedule now?</AlertDialogTitle>
            <AlertDialogDescription>
              This immediately fires "{runNowTarget?.name}" (target:{" "}
              {runNowTarget?.target_kind}) outside its normal cadence and records the fire in its
              history.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (runNowTarget) runNowMutation.mutate(runNowTarget);
                setRunNowTarget(null);
              }}
            >
              Run now
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete schedule?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently deletes "{deleteTarget?.name}". Recorded fire history is kept but
              the schedule stops firing.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deleteTarget) deleteMutation.mutate(deleteTarget);
                setDeleteTarget(null);
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
