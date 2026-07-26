// Self-hosted worker registry + lifecycle (issue #320). The existing
// read-only records page (src/resources/self-hosted-workers.ts) only lists;
// this richer page adds the CRUD lifecycle the console lacked: register a new
// worker identity (the mTLS identity fingerprint #249 is shown ONCE on
// success like a virtual key), then drill into a worker for its telemetry
// events / heartbeat / checkpoint / artifact evidence.
//
// Registry rows are read from /admin/v1/self-hosted-worker-records (the same
// storage-backed projection the read-only page uses) — registration POSTs to
// /admin/v1/self-hosted-workers. Both surface customer-reported evidence
// (trust_level: reported_by_self_hosted_worker), never managed-worker proof.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { ResourceTable } from "@/components/resource/resource-table";
import { toast } from "sonner";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { formatUnix, TruncatedCopyable } from "@/components/agent-ops/agent-ops-primitives";
import {
  CredentialRevealDialog,
  ReportedTrustBadge,
  workerStatusVariant,
} from "@/components/worker-ops/worker-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { useOperatorError } from "@/hooks/use-operator-error";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import type { ColumnConfig } from "@/lib/resource-config";

type SelfHostedWorkerRecord = AdminSchema<"AdminSelfHostedWorkerRecord">;

const PAGE_SIZE = 50;

interface RegisterForm {
  workerName: string;
  workspaceId: string;
  identityFingerprint: string;
  organizationId: string;
  projectId: string;
  identityExpiresAt: string;
  orchestrationEnabled: boolean;
}

const EMPTY_FORM: RegisterForm = {
  workerName: "",
  workspaceId: "",
  identityFingerprint: "",
  organizationId: "",
  projectId: "",
  identityExpiresAt: "",
  orchestrationEnabled: false,
};

function buildRegistrationBody(
  form: RegisterForm,
): AdminSchema<"AdminSelfHostedWorkerRegistrationRequest"> {
  const tenant: AdminSchema<"TenantContext"> = {};
  if (form.organizationId.trim()) tenant.organization_id = form.organizationId.trim();
  if (form.projectId.trim()) tenant.project_id = form.projectId.trim();
  const expiry = form.identityExpiresAt.trim();
  return {
    tenant,
    workspace_id: form.workspaceId.trim(),
    worker_name: form.workerName.trim(),
    identity_fingerprint: form.identityFingerprint.trim(),
    identity_expires_at_unix: expiry ? Number(expiry) : null,
    orchestration_enabled: form.orchestrationEnabled,
  };
}

export default function SelfHostedWorkersOpsPage() {
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["self-hosted-worker-records"];

  const [registerOpen, setRegisterOpen] = useState(false);
  const [form, setForm] = useState<RegisterForm>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ name: string; fingerprint: string } | null>(
    null,
  );

  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/self-hosted-worker-records", {
        query: { offset: 0, limit: PAGE_SIZE },
      }),
  });

  const workers = useMemo<SelfHostedWorkerRecord[]>(() => data?.data ?? [], [data]);
  const workerColumns: ColumnConfig<SelfHostedWorkerRecord>[] = [
    {
      key: "worker_name",
      header: t("page.selfHostedWorkersOps.col.worker"),
      priority: "primary",
      minWidth: 200,
      mobileVisibility: "always",
      render: (worker) => (
        <div>
          <div className="font-medium">{worker.worker_name}</div>
          <TruncatedCopyable
            value={worker.id}
            label={t("page.selfHostedWorkersOps.workerIdLabel")}
          />
        </div>
      ),
    },
    {
      key: "status",
      header: t("common.status"),
      priority: "secondary",
      minWidth: 130,
      mobileVisibility: "always",
      render: (worker) => (
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={workerStatusVariant(worker.status)}>{worker.status}</Badge>
          {worker.stale ? (
            <Badge variant="outline" className="text-destructive">
              {t("page.selfHostedWorkersOps.badge.stale")}
            </Badge>
          ) : null}
        </div>
      ),
    },
    {
      key: "identity_fingerprint",
      header: t("page.selfHostedWorkersOps.field.identityFingerprint"),
      priority: "detail",
      minWidth: 210,
      mobileVisibility: "details",
      copyable: true,
    },
    {
      key: "orchestration_enabled",
      header: t("page.selfHostedWorkersOps.col.orchestration"),
      priority: "secondary",
      minWidth: 130,
      mobileVisibility: "always",
      render: (worker) =>
        worker.orchestration_enabled ? t("common.enabled") : t("common.disabled"),
    },
    {
      key: "activity",
      header: t("page.selfHostedWorkersOps.col.activity"),
      priority: "secondary",
      minWidth: 190,
      mobileVisibility: "always",
      render: (worker) =>
        t("page.selfHostedWorkersOps.activity", {
          events: worker.telemetry_event_count,
          checkpoints: worker.checkpoint_count,
          artifacts: worker.artifact_count,
        }),
      compactRender: (worker) =>
        t("page.selfHostedWorkersOps.activityCompact", {
          events: worker.telemetry_event_count,
          checkpoints: worker.checkpoint_count,
          artifacts: worker.artifact_count,
        }),
    },
    {
      key: "last_seen_at_unix",
      header: t("page.selfHostedWorkersOps.col.lastSeen"),
      priority: "detail",
      minWidth: 170,
      mobileVisibility: "details",
      render: (worker) => formatUnix(worker.last_seen_at_unix),
    },
  ];

  const registerMutation = useMutation({
    mutationFn: (body: AdminSchema<"AdminSelfHostedWorkerRegistrationRequest">) =>
      adminPost(apiKey, "/admin/v1/self-hosted-workers", body),
    onSuccess: (response) => {
      toast.success(
        t("page.selfHostedWorkersOps.toast.registered", {
          name: response.worker.worker_name,
        }),
      );
      setRegisterOpen(false);
      setForm(EMPTY_FORM);
      setFormError(null);
      setRevealed({
        name: response.worker.worker_name,
        fingerprint: response.worker.identity_fingerprint,
      });
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => {
      setFormError(err.message);
      toastError(err);
    },
  });

  function submitRegister() {
    setFormError(null);
    if (!form.workerName.trim() || !form.workspaceId.trim() || !form.identityFingerprint.trim()) {
      setFormError(t("page.selfHostedWorkersOps.error.required"));
      return;
    }
    if (form.identityExpiresAt.trim() && Number.isNaN(Number(form.identityExpiresAt.trim()))) {
      setFormError(t("page.selfHostedWorkersOps.error.expiryInvalid"));
      return;
    }
    registerMutation.mutate(buildRegistrationBody(form));
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">
            {t("page.selfHostedWorkersOps.title")}
          </h1>
          <div className="text-sm text-muted-foreground">
            {t("page.selfHostedWorkersOps.subtitle.before")}
            <ReportedTrustBadge />
            {t("page.selfHostedWorkersOps.subtitle.after")}
          </div>
        </div>
        <Button onClick={() => setRegisterOpen(true)}>
          {t("page.selfHostedWorkersOps.register")}
        </Button>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.selfHostedWorkersOps.error", { message: error.message })}
        </p>
      ) : null}

      <ResourceTable
        columns={workerColumns}
        rows={workers}
        isLoading={isLoading}
        readOnly={false}
        emptyLabel={t("page.selfHostedWorkersOps.empty")}
        rowLabel={(worker) => worker.worker_name}
        renderActions={(worker) => (
          <Button asChild variant="outline" size="sm" className="min-h-11 lg:min-h-9">
            <Link to={`/app/workers/self-hosted/${worker.id}`}>
              {t("page.selfHostedWorkersOps.inspect")}
            </Link>
          </Button>
        )}
      />

      <Dialog
        open={registerOpen}
        onOpenChange={(open) => {
          setRegisterOpen(open);
          if (!open) {
            setForm(EMPTY_FORM);
            setFormError(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("page.selfHostedWorkersOps.dialog.title")}</DialogTitle>
            <DialogDescription>
              {t("page.selfHostedWorkersOps.dialog.description")}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="worker-name">
                {t("page.selfHostedWorkersOps.field.workerName")}
              </Label>
              <Input
                id="worker-name"
                value={form.workerName}
                onChange={(e) => setForm({ ...form, workerName: e.target.value })}
                placeholder={t("page.selfHostedWorkersOps.placeholder.workerName")}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="workspace-id">
                {t("page.selfHostedWorkersOps.field.workspaceId")}
              </Label>
              {/* #342: the worker's workspace scope is entity-backed — pick a
                  known workspace by name from the shared registry instead of
                  pasting its id. The workspace `id` is submitted unchanged. It is
                  an independent picker (not scoped to project/org) because the
                  registration's project is optional and the org id here is a
                  free-form scope token, not a modelled tenant row (see below). */}
              <EntityReferencePicker
                id="workspace-id"
                label={t("page.selfHostedWorkersOps.field.workspaceId")}
                reference={{
                  target: "workspaces",
                  valueKey: "id",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["slug", "project_id"],
                }}
                value={form.workspaceId}
                dependencyValues={{}}
                required
                placeholder={t("page.selfHostedWorkersOps.placeholder.workspaceId")}
                onChange={(value) =>
                  setForm({
                    ...form,
                    workspaceId: typeof value === "string" ? value : "",
                  })
                }
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="identity-fingerprint">
                {t("page.selfHostedWorkersOps.field.identityFingerprint")}
              </Label>
              <Input
                id="identity-fingerprint"
                value={form.identityFingerprint}
                onChange={(e) =>
                  setForm({ ...form, identityFingerprint: e.target.value })
                }
                placeholder={t(
                  "page.selfHostedWorkersOps.placeholder.identityFingerprint",
                )}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="organization-id">
                  {t("page.selfHostedWorkersOps.field.organizationId")}
                </Label>
                {/* #342 (justified, no silent exclusion): organization_id is a
                    free-form TenantContext scope token presented by the caller at
                    request time, NOT a modelled admin-console entity — there is no
                    organizations collection to pick from (mirrors the
                    agent-workflows.organization_ids decision). It stays a raw text
                    input. */}
                <Input
                  id="organization-id"
                  value={form.organizationId}
                  onChange={(e) =>
                    setForm({ ...form, organizationId: e.target.value })
                  }
                  placeholder={t(
                    "page.selfHostedWorkersOps.placeholder.organizationId",
                  )}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="project-id">
                  {t("page.selfHostedWorkersOps.field.projectId")}
                </Label>
                {/* #342: the worker's project scope is entity-backed — pick a
                    known project by name. Optional, so it is an independent picker
                    (no forced dependency). The project `id` is submitted
                    unchanged. */}
                <EntityReferencePicker
                  id="project-id"
                  label={t("page.selfHostedWorkersOps.field.projectId")}
                  reference={{
                    target: "projects",
                    valueKey: "id",
                    primaryLabelKey: "name",
                    secondaryLabelKeys: ["slug", "tenant_id"],
                  }}
                  value={form.projectId}
                  dependencyValues={{}}
                  placeholder={t("page.selfHostedWorkersOps.placeholder.projectId")}
                  onChange={(value) =>
                    setForm({
                      ...form,
                      projectId: typeof value === "string" ? value : "",
                    })
                  }
                />
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="identity-expires">
                {t("page.selfHostedWorkersOps.field.identityExpires")}
              </Label>
              <Input
                id="identity-expires"
                value={form.identityExpiresAt}
                onChange={(e) =>
                  setForm({ ...form, identityExpiresAt: e.target.value })
                }
                placeholder={t(
                  "page.selfHostedWorkersOps.placeholder.identityExpires",
                )}
              />
            </div>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor="orchestration-enabled" className="cursor-pointer">
                {t("page.selfHostedWorkersOps.field.orchestrationEnabled")}
              </Label>
              <Switch
                id="orchestration-enabled"
                checked={form.orchestrationEnabled}
                onCheckedChange={(checked) =>
                  setForm({ ...form, orchestrationEnabled: checked })
                }
              />
            </div>
            {formError ? (
              <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {formError}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setRegisterOpen(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button
              type="button"
              disabled={registerMutation.isPending}
              onClick={submitRegister}
            >
              {registerMutation.isPending
                ? t("page.selfHostedWorkersOps.submitting")
                : t("page.selfHostedWorkersOps.submit")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CredentialRevealDialog
        open={revealed !== null}
        onClose={() => setRevealed(null)}
        title={t("page.selfHostedWorkersOps.reveal.title")}
        description={t("page.selfHostedWorkersOps.reveal.description", {
          name:
            revealed?.name ?? t("page.selfHostedWorkersOps.reveal.fallbackName"),
        })}
        credentialLabel={t("page.selfHostedWorkersOps.field.identityFingerprint")}
        credential={revealed?.fingerprint ?? null}
      />
    </div>
  );
}
