// Tool-approvals action queue (issue #318): the human-in-the-loop UI over
// /admin/v1/tool-approvals (+ /approve /deny /expire).
//
// Fail-closed fingerprint contract (#62): every approve/deny POST carries the
// EXACT immutable invocation `fingerprint` from the record being actioned —
// never re-derived, never user-editable — so the gateway can reject a decision
// that raced a changed invocation. The target-level `action_fingerprint`
// (#306) and the run/workflow context (#305) are displayed for correlation
// but are never part of the decision payload.
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MoreHorizontal } from "lucide-react";
import { toast } from "sonner";
import { ResourceTable } from "@/components/resource/resource-table";
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
import { Label } from "@/components/ui/label";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import type { ColumnConfig } from "@/lib/resource-config";

type ToolApprovalRecord = AdminSchema<"ToolApprovalRecord">;
type ApprovalAction = "approve" | "deny" | "expire";

/** Localized `t` bound to a locale (see `useI18n`). */
type Translate = ReturnType<typeof useI18n>["t"];

interface ActionCopy {
  title: string;
  description: string;
  confirmLabel: string;
  success: string;
}

/** Per-action dialog copy resolved from the typed catalog for the active locale. */
function buildActionCopy(t: Translate): Record<ApprovalAction, ActionCopy> {
  return {
    approve: {
      title: t("page.toolApprovals.action.approve.title"),
      description: t("page.toolApprovals.action.approve.description"),
      confirmLabel: t("page.toolApprovals.action.approve.confirmLabel"),
      success: t("page.toolApprovals.action.approve.success"),
    },
    deny: {
      title: t("page.toolApprovals.action.deny.title"),
      description: t("page.toolApprovals.action.deny.description"),
      confirmLabel: t("page.toolApprovals.action.deny.confirmLabel"),
      success: t("page.toolApprovals.action.deny.success"),
    },
    expire: {
      title: t("page.toolApprovals.action.expire.title"),
      description: t("page.toolApprovals.action.expire.description"),
      confirmLabel: t("page.toolApprovals.action.expire.confirmLabel"),
      success: t("page.toolApprovals.action.expire.success"),
    },
  };
}

const QUEUE_REFETCH_INTERVAL_MS = 5_000;

function postDecision(
  apiKey: string,
  action: ApprovalAction,
  approvalId: string,
  body: AdminSchema<"ToolApprovalDecisionRequest">,
): Promise<ToolApprovalRecord> {
  const options = { params: { approval_id: approvalId } };
  switch (action) {
    case "approve":
      return adminPost(
        apiKey,
        "/admin/v1/tool-approvals/{approval_id}/approve",
        body,
        options,
      );
    case "deny":
      return adminPost(
        apiKey,
        "/admin/v1/tool-approvals/{approval_id}/deny",
        body,
        options,
      );
    case "expire":
      return adminPost(
        apiKey,
        "/admin/v1/tool-approvals/{approval_id}/expire",
        body,
        options,
      );
  }
}

function formatDuration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "-";
  return new Date(unix * 1000).toLocaleString();
}

/** Compact "who asked" line from the actor key + non-null tenant context ids. */
function actorSummary(record: ToolApprovalRecord): string {
  const parts: string[] = [];
  if (record.actor_api_key_id) parts.push(`key ${record.actor_api_key_id}`);
  const tenant = record.tenant;
  if (tenant.organization_id) parts.push(`org ${tenant.organization_id}`);
  if (tenant.project_id) parts.push(`project ${tenant.project_id}`);
  if (tenant.user_id) parts.push(`user ${tenant.user_id}`);
  return parts.length > 0 ? parts.join(" · ") : "-";
}

/** Compact agent-run / workflow context line (#305). */
function runContextSummary(record: ToolApprovalRecord): string {
  const parts: string[] = [];
  if (record.agent_run_id) parts.push(`run ${record.agent_run_id}`);
  if (record.workflow_id) parts.push(`workflow ${record.workflow_id}`);
  if (record.workflow_node_id) parts.push(`node ${record.workflow_node_id}`);
  return parts.length > 0 ? parts.join(" · ") : "-";
}

function toolLabel(record: ToolApprovalRecord): string {
  const server = record.server_name ? `${record.server_name}/` : "";
  return `${server}${record.tool_name}`;
}

function statusVariant(
  status: ToolApprovalRecord["status"],
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "approved":
      return "default";
    case "denied":
      return "destructive";
    case "expired":
      return "outline";
    default:
      return "secondary";
  }
}

async function copyToClipboard(
  value: string,
  successMessage: string,
  errorMessage: string,
): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    toast.success(successMessage);
  } catch {
    toast.error(errorMessage);
  }
}

function FingerprintRow({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | null | undefined;
  hint?: string;
}) {
  const { t } = useI18n();
  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium">{label}</span>
        {value ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-6 px-2 text-xs"
            onClick={() =>
              copyToClipboard(
                value,
                t("page.toolApprovals.copied", { label }),
                t("page.toolApprovals.copyFailed", { label }),
              )
            }
          >
            {t("page.toolApprovals.copy")}
          </Button>
        ) : null}
      </div>
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
      <code className="break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
        {value ?? "-"}
      </code>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="break-all text-sm">{value}</span>
    </div>
  );
}

function ApprovalDetailDialog({
  record,
  onClose,
}: {
  record: ToolApprovalRecord | null;
  onClose: () => void;
}) {
  const { t } = useI18n();
  return (
    <Dialog open={record !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        {record ? (
          <>
            <DialogHeader>
              <DialogTitle>
                {t("page.toolApprovals.detail.title", { id: record.id })}
              </DialogTitle>
              <DialogDescription>
                {t("page.toolApprovals.detail.description", { tool: toolLabel(record) })}
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4">
              <FingerprintRow
                label={t("page.toolApprovals.detail.invocationFingerprint")}
                value={record.fingerprint}
                hint={t("page.toolApprovals.detail.invocationFingerprintHint")}
              />
              <FingerprintRow
                label={t("page.toolApprovals.detail.actionFingerprint")}
                value={record.action_fingerprint}
                hint={t("page.toolApprovals.detail.actionFingerprintHint")}
              />
              <div className="grid gap-3 sm:grid-cols-2">
                <DetailField label={t("common.status")} value={record.status} />
                <DetailField
                  label={t("page.toolApprovals.detail.riskReason")}
                  value={record.risk_reason}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.tool")}
                  value={record.tool_name}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.server")}
                  value={record.server_name ?? "-"}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.route")}
                  value={record.route ?? "-"}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.approvalPolicy")}
                  value={t("page.toolApprovals.detail.approvalPolicyValue", {
                    policy: record.approval_policy,
                    timeout: record.approval_timeout_secs,
                  })}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.requestedBy")}
                  value={actorSummary(record)}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.runContext")}
                  value={runContextSummary(record)}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.requestId")}
                  value={record.request_id}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.traceId")}
                  value={record.trace_id ?? "-"}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.requestedAt")}
                  value={formatUnix(record.requested_at_unix)}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.expiresAt")}
                  value={formatUnix(record.expires_at_unix)}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.decision")}
                  value={record.decision ?? "-"}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.decisionReason")}
                  value={record.decision_reason ?? "-"}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.reviewer")}
                  value={record.reviewer_api_key_id ?? "-"}
                />
                <DetailField
                  label={t("page.toolApprovals.detail.decidedAt")}
                  value={formatUnix(record.decided_at_unix)}
                />
              </div>
              <div className="grid gap-0.5">
                <span className="text-xs font-medium text-muted-foreground">
                  {t("page.toolApprovals.detail.argumentsSummary")}
                </span>
                <code className="whitespace-pre-wrap break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
                  {record.arguments_summary}
                </code>
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                {t("page.toolApprovals.detail.close")}
              </Button>
            </DialogFooter>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

export default function ToolApprovalsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["tool-approvals"];

  const actionCopy = useMemo(() => buildActionCopy(t), [t]);

  const [detailRecord, setDetailRecord] = useState<ToolApprovalRecord | null>(null);
  const [pendingDecision, setPendingDecision] = useState<{
    record: ToolApprovalRecord;
    action: ApprovalAction;
  } | null>(null);
  const [reason, setReason] = useState("");
  const [decisionError, setDecisionError] = useState<string | null>(null);

  // Ticking clock for age / TTL countdowns on the pending queue.
  const [nowUnix, setNowUnix] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const timer = setInterval(
      () => setNowUnix(Math.floor(Date.now() / 1000)),
      1_000,
    );
    return () => clearInterval(timer);
  }, []);

  const { data, isLoading, error: listError } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/tool-approvals"),
    refetchInterval: QUEUE_REFETCH_INTERVAL_MS,
  });

  const records = useMemo(() => data?.data ?? [], [data]);
  const pending = useMemo(
    () =>
      records
        .filter((record) => record.status === "pending")
        .sort((a, b) => a.requested_at_unix - b.requested_at_unix),
    [records],
  );
  const history = useMemo(
    () =>
      records
        .filter((record) => record.status !== "pending")
        .sort(
          (a, b) =>
            (b.decided_at_unix ?? b.requested_at_unix) -
            (a.decided_at_unix ?? a.requested_at_unix),
        ),
    [records],
  );

  const decisionMutation = useMutation({
    mutationFn: ({
      record,
      action,
      comment,
    }: {
      record: ToolApprovalRecord;
      action: ApprovalAction;
      comment: string;
    }) =>
      postDecision(apiKey, action, record.id, {
        // Fail-closed #62 contract: bind approve/deny to the exact pending
        // fingerprint from the record. Expire is not fingerprint-bound.
        fingerprint: action === "expire" ? null : record.fingerprint,
        reason: comment.trim() === "" ? null : comment.trim(),
      }),
    onSuccess: (_updated, variables) => {
      toast.success(actionCopy[variables.action].success);
      setPendingDecision(null);
      setReason("");
      setDecisionError(null);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (error: Error) => {
      // Keep the dialog (and the queue row) in place: a fingerprint mismatch
      // or already-terminal rejection must stay visible, not silently vanish.
      setDecisionError(error.message);
      toast.error(error.message);
      queryClient.invalidateQueries({ queryKey });
    },
  });

  function openDecision(record: ToolApprovalRecord, action: ApprovalAction) {
    setReason("");
    setDecisionError(null);
    setPendingDecision({ record, action });
  }

  function closeDecision() {
    setPendingDecision(null);
    setReason("");
    setDecisionError(null);
  }

  const decisionCopy = pendingDecision ? actionCopy[pendingDecision.action] : null;

  const pendingColumns: ColumnConfig<ToolApprovalRecord>[] = [
    {
      key: "tool_name",
      header: t("page.toolApprovals.col.tool"),
      priority: "primary",
      minWidth: 180,
      mobileVisibility: "always",
      render: (record) => (
        <div>
          <div className="font-medium">{toolLabel(record)}</div>
          {record.route ? (
            <div className="text-xs text-muted-foreground">
              {t("page.toolApprovals.rowRoute", { route: record.route })}
            </div>
          ) : null}
        </div>
      ),
    },
    { key: "actor", header: t("page.toolApprovals.col.requestedBy"), priority: "secondary", minWidth: 220, mobileVisibility: "always", render: actorSummary },
    {
      key: "arguments_summary",
      header: t("page.toolApprovals.col.arguments"),
      priority: "detail",
      minWidth: 220,
      mobileVisibility: "details",
      render: (record) => <code className="line-clamp-2 break-all font-mono text-xs">{record.arguments_summary}</code>,
    },
    { key: "run_context", header: t("page.toolApprovals.col.runContext"), priority: "detail", minWidth: 220, mobileVisibility: "details", render: runContextSummary },
    { key: "age", header: t("page.toolApprovals.col.age"), priority: "secondary", minWidth: 90, mobileVisibility: "always", render: (record) => formatDuration(nowUnix - record.requested_at_unix) },
    {
      key: "expires",
      header: t("page.toolApprovals.col.expiresIn"),
      priority: "secondary",
      minWidth: 100,
      mobileVisibility: "always",
      render: (record) => {
        const remaining = record.expires_at_unix - nowUnix;
        return remaining > 0 ? (
          formatDuration(remaining)
        ) : (
          <span className="text-destructive">{t("page.toolApprovals.overdue")}</span>
        );
      },
    },
  ];

  const historyColumns: ColumnConfig<ToolApprovalRecord>[] = [
    { key: "tool_name", header: t("page.toolApprovals.col.tool"), priority: "primary", minWidth: 190, mobileVisibility: "always", render: toolLabel },
    { key: "status", header: t("common.status"), priority: "secondary", minWidth: 110, mobileVisibility: "always", render: (record) => <Badge variant={statusVariant(record.status)}>{record.status}</Badge> },
    { key: "decision", header: t("page.toolApprovals.col.decision"), priority: "secondary", minWidth: 100, mobileVisibility: "always", render: (record) => record.decision ?? "-" },
    { key: "decision_reason", header: t("page.toolApprovals.col.decisionReason"), priority: "detail", minWidth: 180, mobileVisibility: "details", render: (record) => record.decision_reason ?? "-" },
    { key: "reviewer_api_key_id", header: t("page.toolApprovals.col.reviewer"), priority: "detail", minWidth: 180, mobileVisibility: "details", copyable: true },
    { key: "decided_at_unix", header: t("page.toolApprovals.col.decidedAt"), priority: "secondary", minWidth: 170, mobileVisibility: "always", render: (record) => formatUnix(record.decided_at_unix) },
  ];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.toolApprovals.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.toolApprovals.description")}
        </p>
      </div>

      {listError ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.toolApprovals.loadError", { message: listError.message })}
        </p>
      ) : null}

      <Tabs defaultValue="pending">
        <TabsList>
          <TabsTrigger value="pending">
            {t("page.toolApprovals.tab.pending")}
            {pending.length > 0 ? ` (${pending.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="history">{t("page.toolApprovals.tab.history")}</TabsTrigger>
        </TabsList>

        <TabsContent value="pending">
          <ResourceTable
            columns={pendingColumns}
            rows={pending}
            isLoading={isLoading}
            readOnly={false}
            emptyLabel={t("page.toolApprovals.pending.empty")}
            rowLabel={(record) => toolLabel(record)}
            renderActions={(record) => (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="icon" className="size-11 lg:size-8" aria-label={t("resource.action.rowActions", { label: toolLabel(record) })}>
                    <MoreHorizontal className="size-4" aria-hidden="true" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setDetailRecord(record)}>
                    {t("page.toolApprovals.action.details")}
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => openDecision(record, "approve")}>
                    {actionCopy.approve.confirmLabel}
                  </DropdownMenuItem>
                  <DropdownMenuItem className="text-destructive" onSelect={() => openDecision(record, "deny")}>
                    {actionCopy.deny.confirmLabel}
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => openDecision(record, "expire")}>
                    {actionCopy.expire.confirmLabel}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          />
        </TabsContent>

        <TabsContent value="history">
          <ResourceTable
            columns={historyColumns}
            rows={history}
            isLoading={isLoading}
            readOnly={false}
            emptyLabel={t("page.toolApprovals.history.empty")}
            rowLabel={(record) => toolLabel(record)}
            renderActions={(record) => (
              <Button variant="outline" size="sm" className="min-h-11 lg:min-h-9" onClick={() => setDetailRecord(record)}>
                {t("page.toolApprovals.action.details")}
              </Button>
            )}
          />
        </TabsContent>
      </Tabs>

      <ApprovalDetailDialog
        record={detailRecord}
        onClose={() => setDetailRecord(null)}
      />

      <Dialog
        open={pendingDecision !== null}
        onOpenChange={(open) => !open && closeDecision()}
      >
        <DialogContent className="sm:max-w-lg">
          {pendingDecision && decisionCopy ? (
            <>
              <DialogHeader>
                <DialogTitle>{decisionCopy.title}</DialogTitle>
                <DialogDescription>{decisionCopy.description}</DialogDescription>
              </DialogHeader>
              <div className="grid gap-4">
                <DetailField
                  label={t("page.toolApprovals.detail.tool")}
                  value={toolLabel(pendingDecision.record)}
                />
                <div className="grid gap-0.5">
                  <span className="text-xs font-medium text-muted-foreground">
                    {t("page.toolApprovals.detail.argumentsSummary")}
                  </span>
                  <code className="break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
                    {pendingDecision.record.arguments_summary}
                  </code>
                </div>
                <FingerprintRow
                  label={t("page.toolApprovals.detail.invocationFingerprint")}
                  value={pendingDecision.record.fingerprint}
                />
                <div className="grid gap-2">
                  <Label htmlFor="decision-reason">
                    {t("page.toolApprovals.reviewerComment")}
                  </Label>
                  <Textarea
                    id="decision-reason"
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder={t("page.toolApprovals.reviewerCommentPlaceholder")}
                    rows={2}
                  />
                </div>
                {decisionError ? (
                  <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {decisionError}
                  </p>
                ) : null}
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={closeDecision}>
                  {t("resource.action.cancel")}
                </Button>
                <Button
                  type="button"
                  variant={
                    pendingDecision.action === "deny" ? "destructive" : "default"
                  }
                  disabled={decisionMutation.isPending}
                  onClick={() =>
                    decisionMutation.mutate({
                      record: pendingDecision.record,
                      action: pendingDecision.action,
                      comment: reason,
                    })
                  }
                >
                  {decisionMutation.isPending
                    ? t("page.toolApprovals.submitting")
                    : decisionCopy.confirmLabel}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
