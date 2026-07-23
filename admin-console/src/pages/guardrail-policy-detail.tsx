import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
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
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet, adminPost } from "@/lib/gateway-client";
import {
  describeActions,
  formatUnix,
  verdictVariant,
  type GuardrailPolicyDryRunResponse,
} from "@/lib/guardrails";

export default function GuardrailPolicyDetailPage() {
  const { policyId = "" } = useParams<{ policyId: string }>();
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const historyQueryKey = ["guardrail-policy-revisions", policyId];

  const { data, isLoading, error } = useQuery({
    queryKey: historyQueryKey,
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/guardrail-policies/{policy_id}/revisions", {
        params: { policy_id: policyId },
      }),
  });

  const revisions = [...(data?.data ?? [])].sort((a, b) => b.revision - a.revision);
  const active = revisions.find((revision) => revision.status === "active") ?? null;

  // Exact-revision inspector (GET .../revisions/{revision}).
  const [inspectedRevision, setInspectedRevision] = useState<number | null>(null);
  const revisionQuery = useQuery({
    queryKey: ["guardrail-policy-revision", policyId, inspectedRevision],
    enabled: inspectedRevision !== null,
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/guardrail-policies/{policy_id}/revisions/{revision}", {
        params: { policy_id: policyId, revision: inspectedRevision! },
      }),
  });

  // --- Activate (confirmation dialog -> POST .../activate) ---
  const [activateTarget, setActivateTarget] = useState<number | null>(null);
  const activateMutation = useMutation({
    mutationFn: (revision: number) =>
      adminPost(
        apiKey,
        "/admin/v1/guardrail-policies/{policy_id}/activate",
        { revision },
        { params: { policy_id: policyId } },
      ),
    onSuccess: (binding) => {
      queryClient.invalidateQueries({ queryKey: historyQueryKey });
      toast.success(
        t("page.guardrailPolicyDetail.toast.activated", {
          revision: binding.active_revision,
        }),
      );
    },
    onError: (activateError: Error) => toast.error(activateError.message),
  });

  // --- Rollback (confirmation dialog -> POST .../rollback) ---
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollbackRevision, setRollbackRevision] = useState("");
  const rollbackMutation = useMutation({
    mutationFn: (revision: number | null) =>
      adminPost(
        apiKey,
        "/admin/v1/guardrail-policies/{policy_id}/rollback",
        { revision },
        { params: { policy_id: policyId } },
      ),
    onSuccess: (binding) => {
      queryClient.invalidateQueries({ queryKey: historyQueryKey });
      toast.success(
        t("page.guardrailPolicyDetail.toast.rolledBack", {
          revision: binding.active_revision,
        }),
      );
    },
    onError: (rollbackError: Error) => toast.error(rollbackError.message),
  });

  // --- Dry-run panel (POST .../dry-run) ---
  const [dryRunStage, setDryRunStage] = useState<"request" | "response">("request");
  const [dryRunRevision, setDryRunRevision] = useState("");
  const [dryRunModel, setDryRunModel] = useState("");
  const [dryRunProvider, setDryRunProvider] = useState("");
  const [dryRunText, setDryRunText] = useState("");
  const [dryRunResult, setDryRunResult] = useState<GuardrailPolicyDryRunResponse | null>(
    null,
  );
  const dryRunMutation = useMutation({
    mutationFn: () =>
      adminPost(
        apiKey,
        "/admin/v1/guardrail-policies/{policy_id}/dry-run",
        {
          revision: dryRunRevision.trim() === "" ? null : Number(dryRunRevision),
          stage: dryRunStage,
          model: dryRunModel.trim() === "" ? null : dryRunModel.trim(),
          provider: dryRunProvider.trim() === "" ? null : dryRunProvider.trim(),
          text: dryRunText,
        },
        { params: { policy_id: policyId } },
      ),
    onSuccess: (result) => setDryRunResult(result),
    onError: (dryRunError: Error) => toast.error(dryRunError.message),
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-lg font-semibold">
            {t("page.guardrailPolicyDetail.title")}{" "}
            <span className="font-mono">{policyId}</span>
          </h1>
          <p className="text-sm text-muted-foreground">
            <Link className="underline underline-offset-2" to="/app/guardrail-policies">
              {t("page.guardrailPolicyDetail.allPolicies")}
            </Link>
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => setRollbackOpen(true)}
          disabled={rollbackMutation.isPending}
        >
          {t("page.guardrailPolicyDetail.rollbackOpen")}
        </Button>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.guardrailPolicyDetail.loadError", { message: error.message })}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t("page.guardrailPolicyDetail.active.title")}
          </CardTitle>
          <CardDescription>
            {t("page.guardrailPolicyDetail.active.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
          ) : active ? (
            <div className="grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.field.revision")}
                </span>{" "}
                <Badge variant="secondary">r{active.revision}</Badge>
              </div>
              <div>
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.field.name")}
                </span>{" "}
                {active.name}
              </div>
              <div>
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.field.mode")}
                </span>{" "}
                {t(
                  active.enforced
                    ? "page.guardrailPolicyDetail.field.modeEnforced"
                    : "page.guardrailPolicyDetail.field.modeNotEnforced",
                  { mode: active.mode },
                )}
              </div>
              <div>
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.field.execution")}
                </span>{" "}
                {t("page.guardrailPolicyDetail.field.executionValue", {
                  execution: active.execution,
                  streaming: active.streaming,
                  deadline: active.deadline_ms,
                })}
              </div>
              <div>
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.field.checks")}
                </span>{" "}
                {active.checks.map((check) => check.id).join(", ") || "—"}
              </div>
              <div>
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.field.onFail")}
                </span>{" "}
                {describeActions(active.on_fail)}
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("page.guardrailPolicyDetail.active.none")}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t("page.guardrailPolicyDetail.history.title")}
          </CardTitle>
          <CardDescription>
            {t("page.guardrailPolicyDetail.history.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("page.guardrailPolicyDetail.history.col.revision")}</TableHead>
                  <TableHead>{t("common.status")}</TableHead>
                  <TableHead>{t("page.guardrailPolicyDetail.history.col.name")}</TableHead>
                  <TableHead>{t("page.guardrailPolicyDetail.history.col.mode")}</TableHead>
                  <TableHead>{t("page.guardrailPolicyDetail.history.col.created")}</TableHead>
                  <TableHead>{t("page.guardrailPolicyDetail.history.col.createdBy")}</TableHead>
                  <TableHead className="w-40" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {revisions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-24 text-center">
                      {isLoading
                        ? t("resource.table.loading")
                        : t("page.guardrailPolicyDetail.history.empty")}
                    </TableCell>
                  </TableRow>
                ) : (
                  revisions.map((revision) => (
                    <TableRow key={revision.revision}>
                      <TableCell className="font-mono text-xs">r{revision.revision}</TableCell>
                      <TableCell>
                        <Badge
                          variant={revision.status === "active" ? "secondary" : "outline"}
                        >
                          {revision.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{revision.name}</TableCell>
                      <TableCell>{revision.mode}</TableCell>
                      <TableCell>{formatUnix(revision.created_at_unix)}</TableCell>
                      <TableCell>{revision.created_by}</TableCell>
                      <TableCell className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setInspectedRevision(revision.revision)}
                        >
                          {t("page.guardrailPolicyDetail.action.view")}
                        </Button>
                        {revision.status !== "active" && (
                          <Button
                            size="sm"
                            onClick={() => setActivateTarget(revision.revision)}
                            disabled={activateMutation.isPending}
                          >
                            {t("page.guardrailPolicyDetail.action.activate")}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {inspectedRevision !== null && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t("page.guardrailPolicyDetail.inspect.title", { revision: inspectedRevision })}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {revisionQuery.error ? (
              <p className="text-sm text-destructive">
                {t("page.guardrailPolicyDetail.inspect.loadError", {
                  message: revisionQuery.error.message,
                })}
              </p>
            ) : revisionQuery.data ? (
              <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
                {JSON.stringify(revisionQuery.data.policy, null, 2)}
              </pre>
            ) : (
              <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t("page.guardrailPolicyDetail.dryRun.title")}
          </CardTitle>
          <CardDescription>
            {t("page.guardrailPolicyDetail.dryRun.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              setDryRunResult(null);
              dryRunMutation.mutate();
            }}
          >
            <div className="grid gap-2">
              <Label htmlFor="dry-run-stage">
                {t("page.guardrailPolicyDetail.dryRun.stage")}
              </Label>
              <Select
                value={dryRunStage}
                onValueChange={(value) => setDryRunStage(value as "request" | "response")}
              >
                <SelectTrigger id="dry-run-stage">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="request">
                    {t("page.guardrailPolicyDetail.dryRun.stageRequest")}
                  </SelectItem>
                  <SelectItem value="response">
                    {t("page.guardrailPolicyDetail.dryRun.stageResponse")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="dry-run-revision">
                {t("page.guardrailPolicyDetail.dryRun.revision")}
              </Label>
              <Input
                id="dry-run-revision"
                type="number"
                value={dryRunRevision}
                onChange={(event) => setDryRunRevision(event.target.value)}
                placeholder={t("page.guardrailPolicyDetail.dryRun.revisionPlaceholder")}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="dry-run-model">
                {t("page.guardrailPolicyDetail.dryRun.model")}
              </Label>
              {/* #341: the dry-run target model reuses the shared reference
                  picker so operators plan against a real routing-catalog model
                  (searchable, human labels) instead of typing a raw name. An
                  existing value hydrates to its label; an unresolved one stays
                  visible with its badge. */}
              <EntityReferencePicker
                id="dry-run-model"
                label={t("page.guardrailPolicyDetail.dryRun.model")}
                reference={{
                  target: "models",
                  valueKey: "name",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["provider", "provider_model"],
                }}
                value={dryRunModel}
                dependencyValues={{}}
                onChange={(value) =>
                  setDryRunModel(typeof value === "string" ? value : (value[0] ?? ""))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="dry-run-provider">
                {t("page.guardrailPolicyDetail.dryRun.provider")}
              </Label>
              <EntityReferencePicker
                id="dry-run-provider"
                label={t("page.guardrailPolicyDetail.dryRun.provider")}
                reference={{
                  target: "providers",
                  valueKey: "name",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["kind", "base_url"],
                }}
                value={dryRunProvider}
                dependencyValues={{}}
                onChange={(value) =>
                  setDryRunProvider(typeof value === "string" ? value : (value[0] ?? ""))
                }
              />
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="dry-run-text">
                {t("page.guardrailPolicyDetail.dryRun.text")}
              </Label>
              <Textarea
                id="dry-run-text"
                value={dryRunText}
                onChange={(event) => setDryRunText(event.target.value)}
                placeholder={t("page.guardrailPolicyDetail.dryRun.textPlaceholder")}
                rows={5}
              />
            </div>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={dryRunMutation.isPending}>
                {dryRunMutation.isPending
                  ? t("page.guardrailPolicyDetail.dryRun.running")
                  : t("page.guardrailPolicyDetail.dryRun.submit")}
              </Button>
            </div>
          </form>

          {dryRunResult && (
            <div className="mt-4 flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="text-muted-foreground">
                  {t("page.guardrailPolicyDetail.dryRun.plannedAgainst")}
                </span>
                <Badge variant="outline" className="font-mono">
                  {dryRunResult.policy_revision}
                </Badge>
                <Badge variant={dryRunResult.selected ? "secondary" : "outline"}>
                  {dryRunResult.selected
                    ? t("page.guardrailPolicyDetail.dryRun.selected")
                    : t("page.guardrailPolicyDetail.dryRun.notSelected")}
                </Badge>
              </div>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("page.guardrailPolicyDetail.dryRun.col.check")}</TableHead>
                      <TableHead>{t("page.guardrailPolicyDetail.dryRun.col.detector")}</TableHead>
                      <TableHead>{t("page.guardrailPolicyDetail.dryRun.col.result")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {dryRunResult.checks.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={3} className="h-16 text-center">
                          {t("page.guardrailPolicyDetail.dryRun.noChecks")}
                        </TableCell>
                      </TableRow>
                    ) : (
                      dryRunResult.checks.map((check) => (
                        <TableRow key={check.id}>
                          <TableCell className="font-mono text-xs">{check.id}</TableCell>
                          <TableCell>{check.detector}</TableCell>
                          <TableCell>
                            <Badge variant={verdictVariant(check.result)}>
                              {check.result}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-1 text-sm">
                <p>
                  <span className="text-muted-foreground">
                    {t("page.guardrailPolicyDetail.field.onPass")}
                  </span>{" "}
                  {describeActions(dryRunResult.on_pass)}
                </p>
                <p>
                  <span className="text-muted-foreground">
                    {t("page.guardrailPolicyDetail.field.onFail")}
                  </span>{" "}
                  {describeActions(dryRunResult.on_fail)}
                </p>
                <p>
                  <span className="text-muted-foreground">
                    {t("page.guardrailPolicyDetail.field.onError")}
                  </span>{" "}
                  {describeActions(dryRunResult.on_error)}
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog
        open={activateTarget !== null}
        onOpenChange={(open) => {
          if (!open) setActivateTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("page.guardrailPolicyDetail.activateDialog.title", {
                revision: activateTarget ?? "",
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.guardrailPolicyDetail.activateDialog.description", {
                policyId,
                revision: activateTarget ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (activateTarget !== null) activateMutation.mutate(activateTarget);
                setActivateTarget(null);
              }}
            >
              {t("page.guardrailPolicyDetail.action.activate")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={rollbackOpen} onOpenChange={setRollbackOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("page.guardrailPolicyDetail.rollbackDialog.title", { policyId })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.guardrailPolicyDetail.rollbackDialog.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="rollback-revision">
              {t("page.guardrailPolicyDetail.rollbackDialog.targetLabel")}
            </Label>
            <Input
              id="rollback-revision"
              type="number"
              value={rollbackRevision}
              onChange={(event) => setRollbackRevision(event.target.value)}
              placeholder={t("page.guardrailPolicyDetail.rollbackDialog.targetPlaceholder")}
            />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                rollbackMutation.mutate(
                  rollbackRevision.trim() === "" ? null : Number(rollbackRevision),
                );
                setRollbackOpen(false);
                setRollbackRevision("");
              }}
            >
              {t("page.guardrailPolicyDetail.action.rollback")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
