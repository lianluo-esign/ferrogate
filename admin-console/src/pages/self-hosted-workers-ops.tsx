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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatUnix, TruncatedCopyable } from "@/components/agent-ops/agent-ops-primitives";
import {
  CredentialRevealDialog,
  ReportedTrustBadge,
  workerStatusVariant,
} from "@/components/worker-ops/worker-ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";

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

  const registerMutation = useMutation({
    mutationFn: (body: AdminSchema<"AdminSelfHostedWorkerRegistrationRequest">) =>
      adminPost(apiKey, "/admin/v1/self-hosted-workers", body),
    onSuccess: (response) => {
      toast.success(`Worker ${response.worker.worker_name} registered`);
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
      toast.error(err.message);
    },
  });

  function submitRegister() {
    setFormError(null);
    if (!form.workerName.trim() || !form.workspaceId.trim() || !form.identityFingerprint.trim()) {
      setFormError("Worker name, workspace id, and identity fingerprint are required.");
      return;
    }
    if (form.identityExpiresAt.trim() && Number.isNaN(Number(form.identityExpiresAt.trim()))) {
      setFormError("Identity expiry must be a Unix timestamp (seconds).");
      return;
    }
    registerMutation.mutate(buildRegistrationBody(form));
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Self-hosted worker lifecycle</h1>
          <p className="text-sm text-muted-foreground">
            Register, inspect, and rotate customer-infrastructure agent workers. All
            worker telemetry is customer-reported evidence (
            <ReportedTrustBadge />) — not managed-worker enforcement proof.
          </p>
        </div>
        <Button onClick={() => setRegisterOpen(true)}>Register worker</Button>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load self-hosted workers: {error.message}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Identity fingerprint</TableHead>
              <TableHead>Orchestration</TableHead>
              <TableHead>Events</TableHead>
              <TableHead>Checkpoints</TableHead>
              <TableHead>Artifacts</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : workers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  No self-hosted workers registered yet.
                </TableCell>
              </TableRow>
            ) : (
              workers.map((worker) => (
                <TableRow key={worker.id}>
                  <TableCell>
                    <div className="font-medium">{worker.worker_name}</div>
                    <div className="text-xs text-muted-foreground">{worker.id}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Badge variant={workerStatusVariant(worker.status)}>
                        {worker.status}
                      </Badge>
                      {worker.stale ? (
                        <Badge variant="outline" className="text-destructive">
                          stale
                        </Badge>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <TruncatedCopyable
                      value={worker.identity_fingerprint}
                      label="Identity fingerprint"
                    />
                  </TableCell>
                  <TableCell className="text-xs">
                    {worker.orchestration_enabled ? "Enabled" : "Disabled"}
                  </TableCell>
                  <TableCell className="text-xs">{worker.telemetry_event_count}</TableCell>
                  <TableCell className="text-xs">{worker.checkpoint_count}</TableCell>
                  <TableCell className="text-xs">{worker.artifact_count}</TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(worker.last_seen_at_unix)}
                  </TableCell>
                  <TableCell>
                    <Button asChild variant="outline" size="sm">
                      <Link to={`/app/workers/self-hosted/${worker.id}`}>Inspect</Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

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
            <DialogTitle>Register self-hosted worker</DialogTitle>
            <DialogDescription>
              Bind a customer-owned worker identity. The identity fingerprint is the
              durable mTLS credential and is shown once after registration.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="worker-name">Worker name</Label>
              <Input
                id="worker-name"
                value={form.workerName}
                onChange={(e) => setForm({ ...form, workerName: e.target.value })}
                placeholder="edge-runner-01"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="workspace-id">Workspace id</Label>
              <Input
                id="workspace-id"
                value={form.workspaceId}
                onChange={(e) => setForm({ ...form, workspaceId: e.target.value })}
                placeholder="ws-..."
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="identity-fingerprint">Identity fingerprint</Label>
              <Input
                id="identity-fingerprint"
                value={form.identityFingerprint}
                onChange={(e) =>
                  setForm({ ...form, identityFingerprint: e.target.value })
                }
                placeholder="sha256:..."
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="organization-id">Organization id (optional)</Label>
                <Input
                  id="organization-id"
                  value={form.organizationId}
                  onChange={(e) =>
                    setForm({ ...form, organizationId: e.target.value })
                  }
                  placeholder="org-..."
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="project-id">Project id (optional)</Label>
                <Input
                  id="project-id"
                  value={form.projectId}
                  onChange={(e) => setForm({ ...form, projectId: e.target.value })}
                  placeholder="proj-..."
                />
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="identity-expires">
                Identity expiry Unix seconds (optional)
              </Label>
              <Input
                id="identity-expires"
                value={form.identityExpiresAt}
                onChange={(e) =>
                  setForm({ ...form, identityExpiresAt: e.target.value })
                }
                placeholder="leave blank for no expiry"
              />
            </div>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor="orchestration-enabled" className="cursor-pointer">
                Orchestration enabled
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
              <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
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
              Cancel
            </Button>
            <Button
              type="button"
              disabled={registerMutation.isPending}
              onClick={submitRegister}
            >
              {registerMutation.isPending ? "Registering..." : "Register"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CredentialRevealDialog
        open={revealed !== null}
        onClose={() => setRevealed(null)}
        title="Worker identity registered"
        description={`Store the identity fingerprint for ${revealed?.name ?? "the worker"} now. It binds the worker's mTLS transport identity.`}
        credentialLabel="Identity fingerprint"
        credential={revealed?.fingerprint ?? null}
      />
    </div>
  );
}
