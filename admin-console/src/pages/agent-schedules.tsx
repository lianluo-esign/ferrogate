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
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { LocalizedError } from "@/lib/localized-error";
import { useOperatorError } from "@/hooks/use-operator-error";
import type { InterpolationValues, TranslationKey } from "@/i18n";
import {
  adminDelete,
  adminGet,
  adminPost,
  adminPut,
  type AdminSchema,
} from "@/lib/gateway-client";

/** Locale-bound translator threaded into module-scope helpers. */
type Translate = (key: TranslationKey, values?: InterpolationValues) => string;

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

function mutationFromForm(form: ScheduleFormState, t: Translate): ScheduleMutation {
  let target: ScheduleMutation["target"];
  try {
    target = JSON.parse(form.target || "{}") as ScheduleMutation["target"];
  } catch {
    throw new LocalizedError(t("page.agentSchedules.validation.targetJson"));
  }
  if (!form.tenant_id.trim()) {
    throw new LocalizedError(t("page.agentSchedules.validation.tenantRequired"));
  }
  if (!form.workspace_id.trim()) {
    throw new LocalizedError(t("page.agentSchedules.validation.workspaceRequired"));
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
    if (!form.cron_expr.trim()) {
      throw new LocalizedError(t("page.agentSchedules.validation.cronRequired"));
    }
    body.cron_expr = form.cron_expr.trim();
  } else {
    if (!form.interval_secs.trim()) {
      throw new LocalizedError(t("page.agentSchedules.validation.intervalRequired"));
    }
    body.interval_secs = Number(form.interval_secs);
  }
  return body;
}

// Select-option labels resolve through the catalog at render time; `value` is
// the raw contract discriminant submitted unchanged.
const SPEC_KIND_OPTIONS: { labelKey: TranslationKey; value: string }[] = [
  { labelKey: "page.agentSchedules.form.specKind.cron", value: "cron" },
  { labelKey: "page.agentSchedules.form.specKind.interval", value: "interval" },
];

const TARGET_KIND_OPTIONS: { labelKey: TranslationKey; value: string }[] = [
  { labelKey: "page.agentSchedules.form.targetKind.agentRun", value: "agent_run" },
  {
    labelKey: "page.agentSchedules.form.targetKind.selfHostedDispatch",
    value: "self_hosted_dispatch",
  },
];

function scheduleSpecLabel(schedule: AdminAgentSchedule, t: Translate): string {
  return schedule.spec_kind === "cron"
    ? t("page.agentSchedules.spec.cron", {
        expr: schedule.cron_expr ?? "?",
        tz: schedule.timezone,
      })
    : t("page.agentSchedules.spec.interval", { secs: schedule.interval_secs ?? "?" });
}

export default function AgentSchedulesPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const { toastError } = useOperatorError();
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
      const body = mutationFromForm(form, t);
      if (editing) {
        return adminPut(apiKey, "/admin/v1/agent-schedules/{id}", body, {
          params: { id: editing.id },
        });
      }
      return adminPost(apiKey, "/admin/v1/agent-schedules", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: listQueryKey });
      toast.success(
        editing
          ? t("page.agentSchedules.toast.updated")
          : t("page.agentSchedules.toast.created"),
      );
      setFormOpen(false);
      setEditing(null);
      setForm(EMPTY_FORM);
    },
    onError: (saveError: Error) => toastError(saveError),
  });

  const runNowMutation = useMutation({
    mutationFn: (schedule: AdminAgentSchedule) =>
      adminPost(apiKey, "/admin/v1/agent-schedules/{id}/run-now", undefined, {
        params: { id: schedule.id },
      }),
    onSuccess: (response, schedule) => {
      setLastFire({ scheduleName: schedule.name, fire: response.fire });
      toast.success(
        t("page.agentSchedules.toast.manualFire", { outcome: response.fire.outcome }),
      );
      queryClient.invalidateQueries({ queryKey: listQueryKey });
      queryClient.invalidateQueries({ queryKey: ["agent-schedule-fires", schedule.id] });
    },
    onError: (runError: Error) => toastError(runError),
  });

  const deleteMutation = useMutation({
    mutationFn: (schedule: AdminAgentSchedule) =>
      adminDelete(apiKey, "/admin/v1/agent-schedules/{id}", {
        params: { id: schedule.id },
      }),
    onSuccess: (_response, schedule) => {
      queryClient.invalidateQueries({ queryKey: listQueryKey });
      if (firesFor?.id === schedule.id) setFiresFor(null);
      toast.success(t("page.agentSchedules.toast.deleted"));
    },
    onError: (deleteError: Error) => toastError(deleteError),
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
          <h1 className="text-lg font-semibold">{t("page.agentSchedules.title")}</h1>
          <p className="text-sm text-muted-foreground">
            {t("page.agentSchedules.description")}
          </p>
        </div>
        <Button onClick={openCreate}>{t("page.agentSchedules.new")}</Button>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.agentSchedules.loadError", { message: error.message })}
        </p>
      )}

      {lastFire && (
        <Card data-testid="last-manual-fire">
          <CardHeader>
            <CardTitle className="text-base">
              {t("page.agentSchedules.lastFire.title", { name: lastFire.scheduleName })}
            </CardTitle>
            <CardDescription>{t("page.agentSchedules.lastFire.recordedBy")}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <Badge variant={fireOutcomeBadgeVariant(lastFire.fire.outcome)}>
              {lastFire.fire.outcome}
            </Badge>
            <span className="font-mono text-xs">
              {t("page.agentSchedules.lastFire.fire", { id: lastFire.fire.fire_id })}
            </span>
            {lastFire.fire.dispatch_id && (
              <span className="font-mono text-xs">
                {t("page.agentSchedules.lastFire.dispatch", { id: lastFire.fire.dispatch_id })}
              </span>
            )}
            {lastFire.fire.run_id && (
              <span className="font-mono text-xs">
                {t("page.agentSchedules.lastFire.run", { id: lastFire.fire.run_id })}
              </span>
            )}
            <span className="text-xs text-muted-foreground">
              {t("page.agentSchedules.lastFire.firedAt", {
                time: formatUnix(lastFire.fire.fired_at_unix),
              })}
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
              <TableHead>{t("page.agentSchedules.name")}</TableHead>
              <TableHead>{t("page.agentSchedules.col.tenantWorkspace")}</TableHead>
              <TableHead>{t("page.agentSchedules.col.spec")}</TableHead>
              <TableHead>{t("page.agentSchedules.col.target")}</TableHead>
              <TableHead>{t("common.enabled")}</TableHead>
              <TableHead>{t("page.agentSchedules.col.nextFire")}</TableHead>
              <TableHead>{t("page.agentSchedules.col.lastFire")}</TableHead>
              <TableHead className="w-72" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("page.agentSchedules.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((schedule) => (
                <TableRow key={schedule.id}>
                  <TableCell className="font-medium">{schedule.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {schedule.tenant_id} / {schedule.workspace_id}
                  </TableCell>
                  <TableCell className="text-xs">{scheduleSpecLabel(schedule, t)}</TableCell>
                  <TableCell className="text-xs">{schedule.target_kind}</TableCell>
                  <TableCell>
                    <Badge variant={schedule.enabled ? "secondary" : "outline"}>
                      {schedule.enabled ? t("common.enabled") : t("common.disabled")}
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
                        {t("page.agentSchedules.action.runNow")}
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setFiresFor(schedule)}>
                        {t("page.agentSchedules.action.fires")}
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => openEdit(schedule)}>
                        {t("resource.action.edit")}
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setDeleteTarget(schedule)}
                      >
                        {t("resource.action.delete")}
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
            <CardTitle className="text-base">
              {t("page.agentSchedules.fires.title", { name: firesFor.name })}
            </CardTitle>
            <CardDescription>
              {t("page.agentSchedules.fires.descriptionPrefix")}
              <span className="font-mono">{firesFor.id}</span>
              {t("page.agentSchedules.fires.descriptionSuffix")}
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {firesQuery.error ? (
              <p className="px-4 py-3 text-sm text-destructive">
                {t("page.agentSchedules.fires.loadError", {
                  message: firesQuery.error.message,
                })}
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("page.agentSchedules.fires.col.fireId")}</TableHead>
                    <TableHead>{t("page.agentSchedules.fires.col.scheduled")}</TableHead>
                    <TableHead>{t("page.agentSchedules.fires.col.fired")}</TableHead>
                    <TableHead>{t("page.agentSchedules.fires.col.outcome")}</TableHead>
                    <TableHead>{t("page.agentSchedules.fires.col.dispatchRun")}</TableHead>
                    <TableHead>{t("page.agentSchedules.fires.col.node")}</TableHead>
                    <TableHead>{t("page.agentSchedules.fires.col.detail")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {firesQuery.isLoading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="h-16 text-center">
                        {t("resource.table.loading")}
                      </TableCell>
                    </TableRow>
                  ) : fires.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="h-16 text-center">
                        {t("page.agentSchedules.fires.empty")}
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
            <DialogTitle>
              {editing
                ? t("page.agentSchedules.form.editTitle", { name: editing.name })
                : t("page.agentSchedules.new")}
            </DialogTitle>
          </DialogHeader>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              saveMutation.mutate();
            }}
          >
            <div className="grid gap-2">
              <Label htmlFor="schedule-name">{t("page.agentSchedules.name")}</Label>
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
              <Label htmlFor="schedule-enabled">{t("common.enabled")}</Label>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-tenant">{t("common.tenant")}</Label>
              {/* #342: pick the owning tenant account from the shared entity
                  registry; the schedule's tenant_id (canonical `id`) is
                  submitted unchanged. */}
              <EntityReferencePicker
                id="schedule-tenant"
                label={t("common.tenant")}
                reference={{
                  target: "tenant-accounts",
                  valueKey: "id",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["slug"],
                }}
                value={form.tenant_id}
                dependencyValues={{}}
                required
                placeholder={t("page.agentSchedules.form.tenantPlaceholder")}
                onChange={(value) =>
                  // Changing the tenant invalidates any workspace picked under the
                  // previous tenant, so clear it — the workspace picker below is
                  // scoped to the selected tenant and a stale cross-tenant id must
                  // not survive.
                  setForm({
                    ...form,
                    tenant_id: typeof value === "string" ? value : "",
                    workspace_id: "",
                  })
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-workspace">{t("common.workspace")}</Label>
              {/* #342: the workspace list honours a `tenant_id` filter
                  (listWorkspaces), so this picker DEPENDS on the selected tenant
                  and only lists that tenant's workspaces — a workspace from
                  another tenant is structurally excluded. Until a tenant is
                  chosen the picker is disabled with a "select tenant first"
                  explanation (the picker's missing-dependency affordance). The
                  workspace `id` is submitted unchanged. */}
              <EntityReferencePicker
                id="schedule-workspace"
                label={t("common.workspace")}
                reference={{
                  target: "workspaces",
                  valueKey: "id",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["slug", "project_id"],
                  dependencies: [
                    {
                      field: "tenant_id",
                      queryKey: "tenant_id",
                      label: t("common.tenant"),
                    },
                  ],
                }}
                value={form.workspace_id}
                dependencyValues={{ tenant_id: form.tenant_id }}
                required
                placeholder={t("page.agentSchedules.form.workspacePlaceholder")}
                onChange={(value) =>
                  setForm({ ...form, workspace_id: typeof value === "string" ? value : "" })
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-spec-kind">{t("page.agentSchedules.form.specKind")}</Label>
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
                      {t(option.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {form.spec_kind === "cron" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-cron">{t("page.agentSchedules.form.cronExpr")}</Label>
                  <Input
                    id="schedule-cron"
                    value={form.cron_expr}
                    onChange={(event) => setForm({ ...form, cron_expr: event.target.value })}
                    placeholder="*/5 * * * *"
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-timezone">{t("page.agentSchedules.form.timezone")}</Label>
                  <Input
                    id="schedule-timezone"
                    value={form.timezone}
                    onChange={(event) => setForm({ ...form, timezone: event.target.value })}
                    // eslint-disable-next-line ferrogate/no-untranslated-literal -- IANA timezone token, identical in every locale
                    placeholder="UTC"
                  />
                </div>
              </>
            ) : (
              <div className="grid gap-2">
                <Label htmlFor="schedule-interval">
                  {t("page.agentSchedules.form.intervalSecs")}
                </Label>
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
              <Label htmlFor="schedule-target-kind">
                {t("page.agentSchedules.form.targetKind")}
              </Label>
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
                      {t(option.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-jitter">{t("page.agentSchedules.form.jitterSecs")}</Label>
              <Input
                id="schedule-jitter"
                type="number"
                min={0}
                value={form.jitter_secs}
                onChange={(event) => setForm({ ...form, jitter_secs: event.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-overlap">
                {t("page.agentSchedules.form.overlapPolicy")}
              </Label>
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
                  <SelectItem value="skip">
                    {t("page.agentSchedules.form.overlap.skip")}
                  </SelectItem>
                  <SelectItem value="allow">
                    {t("page.agentSchedules.form.overlap.allow")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="schedule-catchup">
                {t("page.agentSchedules.form.catchupPolicy")}
              </Label>
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
                  <SelectItem value="skip_missed">
                    {t("page.agentSchedules.form.catchup.skipMissed")}
                  </SelectItem>
                  <SelectItem value="fire_once">
                    {t("page.agentSchedules.form.catchup.fireOnce")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            {/* #342 (justified, no silent exclusion): the schedule `target` is
                typed `unknown` on read and `Record<string, never>` on the
                mutation contract (AdminAgentScheduleMutation.target) — the OpenAPI
                schema publishes NO field shape for it, so there is no discoverable
                set of entity references to build a selector over. Inventing one
                would mean guessing keys the contract does not define, so this
                stays a raw JSON payload that round-trips verbatim. The entity
                scoping that IS modelled (tenant + tenant-scoped workspace) is
                already structured above. If the target schema later gains a
                concrete shape, a structured selector can replace this textarea. */}
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="schedule-target">{t("page.agentSchedules.form.target")}</Label>
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
                {saveMutation.isPending
                  ? t("resource.action.saving")
                  : editing
                    ? t("page.agentSchedules.form.save")
                    : t("resource.action.create")}
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
            <AlertDialogTitle>{t("page.agentSchedules.runNow.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.agentSchedules.runNow.description", {
                name: runNowTarget?.name ?? "",
                target: runNowTarget?.target_kind ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (runNowTarget) runNowMutation.mutate(runNowTarget);
                setRunNowTarget(null);
              }}
            >
              {t("page.agentSchedules.action.runNow")}
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
            <AlertDialogTitle>{t("page.agentSchedules.delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.agentSchedules.delete.description", {
                name: deleteTarget?.name ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deleteTarget) deleteMutation.mutate(deleteTarget);
                setDeleteTarget(null);
              }}
            >
              {t("resource.action.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
