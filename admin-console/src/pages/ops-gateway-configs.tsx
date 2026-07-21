// Stored gateway config profiles (issue #322): CRUD over
// /admin/v1/gateway-configs (+ /{id}). These are reusable per-api-key config
// overlays (e.g. toggling exact-match response caching for an agent
// workflow); creating, replacing or deleting one applies through a
// process-local reload, so mutations are confirmed and the list refetches.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
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
import { BoolBadge } from "@/components/ops/ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import {
  adminDelete,
  adminGet,
  adminPost,
  adminPut,
  type AdminSchema,
} from "@/lib/gateway-client";

type GatewayConfigProfile = AdminSchema<"AdminGatewayConfigProfile">;

type CacheOverride = "inherit" | "on" | "off";

interface FormState {
  id: string;
  name: string;
  revision: number;
  enabled: boolean;
  apiKeyIds: string;
  cache: CacheOverride;
}

const EMPTY_FORM: FormState = {
  id: "",
  name: "",
  revision: 1,
  enabled: true,
  apiKeyIds: "",
  cache: "inherit",
};

function formFromProfile(profile: GatewayConfigProfile): FormState {
  return {
    id: profile.id,
    name: profile.name,
    revision: profile.revision,
    enabled: profile.enabled,
    apiKeyIds: profile.api_key_ids.join(", "),
    cache:
      profile.cache_enabled === null || profile.cache_enabled === undefined
        ? "inherit"
        : profile.cache_enabled
          ? "on"
          : "off",
  };
}

function mutationBody(form: FormState): AdminSchema<"AdminGatewayConfigMutation"> {
  return {
    id: form.id.trim(),
    name: form.name.trim(),
    revision: form.revision,
    enabled: form.enabled,
    api_key_ids: form.apiKeyIds
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
    cache_enabled: form.cache === "inherit" ? undefined : form.cache === "on",
  };
}

export default function OpsGatewayConfigsPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["ops-gateway-configs"];

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [deleteTarget, setDeleteTarget] = useState<GatewayConfigProfile | null>(
    null,
  );

  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/gateway-configs"),
  });

  const profiles = data?.data ?? [];

  const saveMutation = useMutation({
    mutationFn: (state: FormState) => {
      const body = mutationBody(state);
      return editingId
        ? adminPut(apiKey, "/admin/v1/gateway-configs/{id}", body, {
            params: { id: editingId },
          })
        : adminPost(apiKey, "/admin/v1/gateway-configs", body);
    },
    onSuccess: () => {
      toast.success(editingId ? "Config profile updated" : "Config profile created");
      setDialogOpen(false);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      adminDelete(apiKey, "/admin/v1/gateway-configs/{id}", {
        params: { id },
      }),
    onSuccess: () => {
      toast.success("Config profile deleted");
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  function openCreate() {
    setEditingId(null);
    setForm(EMPTY_FORM);
    setDialogOpen(true);
  }

  function openEdit(profile: GatewayConfigProfile) {
    setEditingId(profile.id);
    setForm(formFromProfile(profile));
    setDialogOpen(true);
  }

  const idInvalid = form.id.trim() === "";
  const nameInvalid = form.name.trim() === "";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Gateway config profiles</h1>
          <p className="text-sm text-muted-foreground">
            Reusable per-api-key config overlays. Changes apply through a
            process-local reload.
          </p>
        </div>
        <Button onClick={openCreate}>New profile</Button>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load gateway configs: {(error as Error).message}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Id</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Revision</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead>API keys</TableHead>
              <TableHead>Cache</TableHead>
              <TableHead className="w-40" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : profiles.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  No config profiles.
                </TableCell>
              </TableRow>
            ) : (
              profiles.map((profile) => (
                <TableRow key={profile.id}>
                  <TableCell className="font-mono text-xs">{profile.id}</TableCell>
                  <TableCell>{profile.name}</TableCell>
                  <TableCell className="tabular-nums">{profile.revision}</TableCell>
                  <TableCell>
                    <BoolBadge value={profile.enabled} />
                  </TableCell>
                  <TableCell className="text-xs">
                    {profile.api_key_ids.length > 0
                      ? profile.api_key_ids.join(", ")
                      : "-"}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {profile.cache_enabled === null ||
                      profile.cache_enabled === undefined
                        ? "inherit"
                        : profile.cache_enabled
                          ? "on"
                          : "off"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEdit(profile)}
                      >
                        Edit
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setDeleteTarget(profile)}
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

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingId ? "Edit config profile" : "New config profile"}
            </DialogTitle>
            <DialogDescription>
              Applied through a process-local reload on save.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="gc-id">Id</Label>
              <Input
                id="gc-id"
                value={form.id}
                disabled={editingId !== null}
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, id: event.target.value }))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="gc-name">Name</Label>
              <Input
                id="gc-name"
                value={form.name}
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, name: event.target.value }))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="gc-revision">Revision</Label>
              <Input
                id="gc-revision"
                type="number"
                min={1}
                value={form.revision}
                onChange={(event) =>
                  setForm((prev) => ({
                    ...prev,
                    revision: Math.max(1, Number(event.target.value) || 1),
                  }))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="gc-keys">API key ids (comma-separated)</Label>
              <Input
                id="gc-keys"
                value={form.apiKeyIds}
                placeholder="key_dev, key_prod"
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, apiKeyIds: event.target.value }))
                }
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="gc-enabled">Enabled</Label>
              <Switch
                id="gc-enabled"
                checked={form.enabled}
                onCheckedChange={(checked) =>
                  setForm((prev) => ({ ...prev, enabled: checked }))
                }
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="gc-cache">Cache override</Label>
              <div className="flex gap-1">
                {(["inherit", "on", "off"] as CacheOverride[]).map((value) => (
                  <Button
                    key={value}
                    type="button"
                    size="sm"
                    variant={form.cache === value ? "default" : "outline"}
                    onClick={() => setForm((prev) => ({ ...prev, cache: value }))}
                  >
                    {value}
                  </Button>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={saveMutation.isPending || idInvalid || nameInvalid}
              onClick={() => saveMutation.mutate(form)}
            >
              {saveMutation.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete config profile?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently deletes "{deleteTarget?.name}" ({deleteTarget?.id})
              and applies the change through a process-local reload.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deleteTarget) deleteMutation.mutate(deleteTarget.id);
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
