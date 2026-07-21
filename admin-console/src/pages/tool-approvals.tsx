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
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import type { ColumnConfig } from "@/lib/resource-config";

type ToolApprovalRecord = AdminSchema<"ToolApprovalRecord">;
type ApprovalAction = "approve" | "deny" | "expire";

const QUEUE_REFETCH_INTERVAL_MS = 5_000;

const ACTION_COPY: Record<
  ApprovalAction,
  { title: string; description: string; confirmLabel: string; success: string }
> = {
  approve: {
    title: "Approve tool invocation",
    description:
      "The pending tool call will be released for execution. The decision is bound to the invocation fingerprint below; if the invocation changed, the gateway rejects it.",
    confirmLabel: "Approve",
    success: "Approval granted",
  },
  deny: {
    title: "Deny tool invocation",
    description:
      "The pending tool call will be rejected and the caller receives a denial. The decision is bound to the invocation fingerprint below.",
    confirmLabel: "Deny",
    success: "Approval denied",
  },
  expire: {
    title: "Expire approval request",
    description:
      "The pending request will be marked expired without an explicit approve/deny decision. The caller receives a timeout-style rejection.",
    confirmLabel: "Expire",
    success: "Approval expired",
  },
};

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

async function copyToClipboard(label: string, value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    toast.success(`${label} copied to clipboard`);
  } catch {
    toast.error(`Could not copy ${label.toLowerCase()}`);
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
            onClick={() => copyToClipboard(label, value)}
          >
            Copy
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
  return (
    <Dialog open={record !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        {record ? (
          <>
            <DialogHeader>
              <DialogTitle>Approval {record.id}</DialogTitle>
              <DialogDescription>
                Full record for the {toolLabel(record)} invocation, including the
                fail-closed invocation fingerprint the decision is bound to.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4">
              <FingerprintRow
                label="Invocation fingerprint"
                value={record.fingerprint}
                hint="Blake2b binding of the exact invocation (#62). Approve/deny decisions must carry this value; a mismatch is rejected fail-closed."
              />
              <FingerprintRow
                label="Action fingerprint"
                value={record.action_fingerprint}
                hint="Target-level canonical_target_sha256 (#306) shared with timeline/audit rows of the same action."
              />
              <div className="grid gap-3 sm:grid-cols-2">
                <DetailField label="Status" value={record.status} />
                <DetailField label="Risk reason" value={record.risk_reason} />
                <DetailField label="Tool" value={record.tool_name} />
                <DetailField label="Server" value={record.server_name ?? "-"} />
                <DetailField label="Route" value={record.route ?? "-"} />
                <DetailField
                  label="Approval policy"
                  value={`${record.approval_policy} (timeout ${record.approval_timeout_secs}s)`}
                />
                <DetailField label="Requested by" value={actorSummary(record)} />
                <DetailField label="Run context" value={runContextSummary(record)} />
                <DetailField label="Request id" value={record.request_id} />
                <DetailField label="Trace id" value={record.trace_id ?? "-"} />
                <DetailField
                  label="Requested at"
                  value={formatUnix(record.requested_at_unix)}
                />
                <DetailField
                  label="Expires at"
                  value={formatUnix(record.expires_at_unix)}
                />
                <DetailField label="Decision" value={record.decision ?? "-"} />
                <DetailField
                  label="Decision reason"
                  value={record.decision_reason ?? "-"}
                />
                <DetailField
                  label="Reviewer"
                  value={record.reviewer_api_key_id ?? "-"}
                />
                <DetailField
                  label="Decided at"
                  value={formatUnix(record.decided_at_unix)}
                />
              </div>
              <div className="grid gap-0.5">
                <span className="text-xs font-medium text-muted-foreground">
                  Arguments summary
                </span>
                <code className="whitespace-pre-wrap break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
                  {record.arguments_summary}
                </code>
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                Close
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
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["tool-approvals"];

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
      toast.success(ACTION_COPY[variables.action].success);
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

  const decisionCopy = pendingDecision ? ACTION_COPY[pendingDecision.action] : null;

  const pendingColumns: ColumnConfig<ToolApprovalRecord>[] = [
    {
      key: "tool_name",
      header: "Tool",
      priority: "primary",
      minWidth: 180,
      mobileVisibility: "always",
      render: (record) => (
        <div>
          <div className="font-medium">{toolLabel(record)}</div>
          {record.route ? <div className="text-xs text-muted-foreground">route {record.route}</div> : null}
        </div>
      ),
    },
    { key: "actor", header: "Requested by", priority: "secondary", minWidth: 220, mobileVisibility: "always", render: actorSummary },
    {
      key: "arguments_summary",
      header: "Arguments",
      priority: "detail",
      minWidth: 220,
      mobileVisibility: "details",
      render: (record) => <code className="line-clamp-2 break-all font-mono text-xs">{record.arguments_summary}</code>,
    },
    { key: "run_context", header: "Run context", priority: "detail", minWidth: 220, mobileVisibility: "details", render: runContextSummary },
    { key: "age", header: "Age", priority: "secondary", minWidth: 90, mobileVisibility: "always", render: (record) => formatDuration(nowUnix - record.requested_at_unix) },
    {
      key: "expires",
      header: "Expires in",
      priority: "secondary",
      minWidth: 100,
      mobileVisibility: "always",
      render: (record) => {
        const remaining = record.expires_at_unix - nowUnix;
        return remaining > 0 ? formatDuration(remaining) : <span className="text-destructive">overdue</span>;
      },
    },
  ];

  const historyColumns: ColumnConfig<ToolApprovalRecord>[] = [
    { key: "tool_name", header: "Tool", priority: "primary", minWidth: 190, mobileVisibility: "always", render: toolLabel },
    { key: "status", header: "Status", priority: "secondary", minWidth: 110, mobileVisibility: "always", render: (record) => <Badge variant={statusVariant(record.status)}>{record.status}</Badge> },
    { key: "decision", header: "Decision", priority: "secondary", minWidth: 100, mobileVisibility: "always", render: (record) => record.decision ?? "-" },
    { key: "decision_reason", header: "Decision reason", priority: "detail", minWidth: 180, mobileVisibility: "details", render: (record) => record.decision_reason ?? "-" },
    { key: "reviewer_api_key_id", header: "Reviewer", priority: "detail", minWidth: 180, mobileVisibility: "details", copyable: true },
    { key: "decided_at_unix", header: "Decided at", priority: "secondary", minWidth: 170, mobileVisibility: "always", render: (record) => formatUnix(record.decided_at_unix) },
  ];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Tool approvals</h1>
        <p className="text-sm text-muted-foreground">
          Human-in-the-loop queue for gated MCP tool invocations. Approve and deny
          decisions are bound to the invocation fingerprint (fail-closed): if the
          pending invocation no longer matches, the gateway rejects the decision.
        </p>
      </div>

      {listError ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load tool approvals: {listError.message}
        </p>
      ) : null}

      <Tabs defaultValue="pending">
        <TabsList>
          <TabsTrigger value="pending">
            Pending queue{pending.length > 0 ? ` (${pending.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="pending">
          <ResourceTable
            columns={pendingColumns}
            rows={pending}
            isLoading={isLoading}
            readOnly={false}
            emptyLabel="No pending approvals."
            rowLabel={(record) => toolLabel(record)}
            renderActions={(record) => (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="icon" className="size-11 lg:size-8" aria-label={`Actions for ${toolLabel(record)}`}>
                    <MoreHorizontal className="size-4" aria-hidden="true" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setDetailRecord(record)}>Details</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => openDecision(record, "approve")}>Approve</DropdownMenuItem>
                  <DropdownMenuItem className="text-destructive" onSelect={() => openDecision(record, "deny")}>Deny</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => openDecision(record, "expire")}>Expire</DropdownMenuItem>
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
            emptyLabel="No decided approvals yet."
            rowLabel={(record) => toolLabel(record)}
            renderActions={(record) => (
              <Button variant="outline" size="sm" className="min-h-11 lg:min-h-9" onClick={() => setDetailRecord(record)}>
                Details
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
                  label="Tool"
                  value={toolLabel(pendingDecision.record)}
                />
                <div className="grid gap-0.5">
                  <span className="text-xs font-medium text-muted-foreground">
                    Arguments summary
                  </span>
                  <code className="break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
                    {pendingDecision.record.arguments_summary}
                  </code>
                </div>
                <FingerprintRow
                  label="Invocation fingerprint"
                  value={pendingDecision.record.fingerprint}
                />
                <div className="grid gap-2">
                  <Label htmlFor="decision-reason">
                    Reviewer comment (optional)
                  </Label>
                  <Textarea
                    id="decision-reason"
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder="Why this decision was made"
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
                  Cancel
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
                    ? "Submitting…"
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
