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
      toast.success(`Revision ${binding.active_revision} activated`);
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
      toast.success(`Rolled back to revision ${binding.active_revision}`);
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
            Guardrail policy <span className="font-mono">{policyId}</span>
          </h1>
          <p className="text-sm text-muted-foreground">
            <Link className="underline underline-offset-2" to="/app/guardrail-policies">
              All guardrail policies
            </Link>
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => setRollbackOpen(true)}
          disabled={rollbackMutation.isPending}
        >
          Rollback...
        </Button>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load revisions: {error.message}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Active revision</CardTitle>
          <CardDescription>
            The revision currently bound to the guardrail runtime for this policy.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : active ? (
            <div className="grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <span className="text-muted-foreground">Revision:</span>{" "}
                <Badge variant="secondary">r{active.revision}</Badge>
              </div>
              <div>
                <span className="text-muted-foreground">Name:</span> {active.name}
              </div>
              <div>
                <span className="text-muted-foreground">Mode:</span> {active.mode}
                {active.enforced ? " (enforced)" : " (not enforced)"}
              </div>
              <div>
                <span className="text-muted-foreground">Execution:</span> {active.execution},
                streaming {active.streaming}, deadline {active.deadline_ms} ms
              </div>
              <div>
                <span className="text-muted-foreground">Checks:</span>{" "}
                {active.checks.map((check) => check.id).join(", ") || "—"}
              </div>
              <div>
                <span className="text-muted-foreground">On fail:</span>{" "}
                {describeActions(active.on_fail)}
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              No active revision — activate one from the history below.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Revision history</CardTitle>
          <CardDescription>
            Activating a revision archives the previously active one; a failed runtime
            reload restores the prior binding.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Revision</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Created by</TableHead>
                  <TableHead className="w-40" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {revisions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-24 text-center">
                      {isLoading ? "Loading…" : "No revisions."}
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
                          View
                        </Button>
                        {revision.status !== "active" && (
                          <Button
                            size="sm"
                            onClick={() => setActivateTarget(revision.revision)}
                            disabled={activateMutation.isPending}
                          >
                            Activate
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
              Revision r{inspectedRevision} definition
            </CardTitle>
          </CardHeader>
          <CardContent>
            {revisionQuery.error ? (
              <p className="text-sm text-destructive">
                Failed to load revision: {revisionQuery.error.message}
              </p>
            ) : revisionQuery.data ? (
              <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
                {JSON.stringify(revisionQuery.data.policy, null, 2)}
              </pre>
            ) : (
              <p className="text-sm text-muted-foreground">Loading…</p>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Dry-run</CardTitle>
          <CardDescription>
            Plans the policy against a sample payload without dispatching to any provider
            or external action. Sample text is used only by local deterministic checks and
            is never persisted.
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
              <Label htmlFor="dry-run-stage">Stage</Label>
              <Select
                value={dryRunStage}
                onValueChange={(value) => setDryRunStage(value as "request" | "response")}
              >
                <SelectTrigger id="dry-run-stage">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="request">request</SelectItem>
                  <SelectItem value="response">response</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="dry-run-revision">Revision (blank = active)</Label>
              <Input
                id="dry-run-revision"
                type="number"
                value={dryRunRevision}
                onChange={(event) => setDryRunRevision(event.target.value)}
                placeholder="active"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="dry-run-model">Model (optional)</Label>
              <Input
                id="dry-run-model"
                value={dryRunModel}
                onChange={(event) => setDryRunModel(event.target.value)}
                placeholder="gpt-4o"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="dry-run-provider">Provider (optional)</Label>
              <Input
                id="dry-run-provider"
                value={dryRunProvider}
                onChange={(event) => setDryRunProvider(event.target.value)}
                placeholder="openai"
              />
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="dry-run-text">Sample payload text</Label>
              <Textarea
                id="dry-run-text"
                value={dryRunText}
                onChange={(event) => setDryRunText(event.target.value)}
                placeholder="Paste a sample prompt/response to evaluate against local checks"
                rows={5}
              />
            </div>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={dryRunMutation.isPending}>
                {dryRunMutation.isPending ? "Running…" : "Run dry-run"}
              </Button>
            </div>
          </form>

          {dryRunResult && (
            <div className="mt-4 flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="text-muted-foreground">Planned against</span>
                <Badge variant="outline" className="font-mono">
                  {dryRunResult.policy_revision}
                </Badge>
                <Badge variant={dryRunResult.selected ? "secondary" : "outline"}>
                  {dryRunResult.selected ? "policy selected" : "policy not selected"}
                </Badge>
              </div>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Check</TableHead>
                      <TableHead>Detector</TableHead>
                      <TableHead>Result</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {dryRunResult.checks.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={3} className="h-16 text-center">
                          No checks planned.
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
                  <span className="text-muted-foreground">On pass:</span>{" "}
                  {describeActions(dryRunResult.on_pass)}
                </p>
                <p>
                  <span className="text-muted-foreground">On fail:</span>{" "}
                  {describeActions(dryRunResult.on_fail)}
                </p>
                <p>
                  <span className="text-muted-foreground">On error:</span>{" "}
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
            <AlertDialogTitle>Activate revision r{activateTarget}?</AlertDialogTitle>
            <AlertDialogDescription>
              The currently active revision of {policyId} will be archived and the
              guardrail runtime reloads with revision r{activateTarget}. A failed reload
              restores the prior binding.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (activateTarget !== null) activateMutation.mutate(activateTarget);
                setActivateTarget(null);
              }}
            >
              Activate
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={rollbackOpen} onOpenChange={setRollbackOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Roll back {policyId}?</AlertDialogTitle>
            <AlertDialogDescription>
              Re-activates an archived revision. Leave the revision blank to roll back to
              the highest archived revision.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="rollback-revision">Target revision (optional)</Label>
            <Input
              id="rollback-revision"
              type="number"
              value={rollbackRevision}
              onChange={(event) => setRollbackRevision(event.target.value)}
              placeholder="highest archived"
            />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                rollbackMutation.mutate(
                  rollbackRevision.trim() === "" ? null : Number(rollbackRevision),
                );
                setRollbackOpen(false);
                setRollbackRevision("");
              }}
            >
              Roll back
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
