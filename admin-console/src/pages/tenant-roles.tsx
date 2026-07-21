// Tenant role bindings (#321 / #232): assign and remove RBAC roles for a
// tenant over `/admin/v1/tenant-roles/{tenant_id}` (+ POST body {role_id} and
// DELETE `.../{role_id}`). Bespoke because the resource path is parameterised
// by a chosen tenant. Tenant-scoping (#232): the tenant defaults to the signed-in
// tenant; a tenant-scoped caller who targets another tenant gets a 403 which is
// surfaced in the error banner rather than hidden.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { adminDelete, adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";

type AdminTenantRoleBinding = AdminSchema<"AdminTenantRoleBinding">;

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "-";
  return new Date(unix * 1000).toLocaleString();
}

export default function TenantRolesPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [tenantId, setTenantId] = useState(session!.tenant.id);
  const [roleId, setRoleId] = useState("");
  const [removing, setRemoving] = useState<AdminTenantRoleBinding | null>(null);

  const queryKey = ["tenant-roles", tenantId];
  const { data, isLoading, error: listError } = useQuery({
    queryKey,
    enabled: tenantId.trim() !== "",
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/tenant-roles/{tenant_id}", {
        params: { tenant_id: tenantId },
      }),
  });

  const bindings = (data?.data ?? []) as AdminTenantRoleBinding[];

  const assignMutation = useMutation({
    mutationFn: (nextRoleId: string) =>
      adminPost(
        apiKey,
        "/admin/v1/tenant-roles/{tenant_id}",
        { role_id: nextRoleId },
        { params: { tenant_id: tenantId } },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success("Role assigned to tenant");
      setRoleId("");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const removeMutation = useMutation({
    mutationFn: (binding: AdminTenantRoleBinding) =>
      adminDelete(apiKey, "/admin/v1/tenant-roles/{tenant_id}/{role_id}", {
        params: { tenant_id: tenantId, role_id: binding.role_id },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success("Role binding removed");
      setRemoving(null);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Tenant role bindings</h1>
        <p className="text-sm text-muted-foreground">
          Assign RBAC roles to a tenant. Role IDs come from the Roles page.
          Tenant-scoped callers can only manage their own tenant; targeting
          another tenant surfaces a 403 below.
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="grid gap-2">
          <Label htmlFor="tenant-id">Tenant ID</Label>
          <Input
            id="tenant-id"
            className="w-72"
            value={tenantId}
            onChange={(event) => setTenantId(event.target.value)}
            placeholder="tenant id"
          />
        </div>
      </div>

      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (roleId.trim() !== "") assignMutation.mutate(roleId.trim());
        }}
      >
        <div className="grid gap-2">
          <Label htmlFor="role-id">Role ID to assign</Label>
          <Input
            id="role-id"
            className="w-72"
            value={roleId}
            onChange={(event) => setRoleId(event.target.value)}
            placeholder="role id"
          />
        </div>
        <Button
          type="submit"
          disabled={roleId.trim() === "" || tenantId.trim() === "" || assignMutation.isPending}
        >
          <Plus className="mr-1 h-4 w-4" />
          Assign role
        </Button>
      </form>

      {listError ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load tenant roles: {(listError as Error).message}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Role ID</TableHead>
              <TableHead>Bound at</TableHead>
              <TableHead className="w-24 text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={3} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : bindings.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="h-24 text-center">
                  No roles bound to this tenant.
                </TableCell>
              </TableRow>
            ) : (
              bindings.map((binding) => (
                <TableRow key={binding.id}>
                  <TableCell className="font-mono text-xs">{binding.role_id}</TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(binding.created_at_unix)}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => setRemoving(binding)}
                      >
                        Remove
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <AlertDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove role binding?</AlertDialogTitle>
            <AlertDialogDescription>
              Role <span className="font-mono">{removing?.role_id}</span> will be
              unbound from tenant <span className="font-mono">{tenantId}</span>.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={removeMutation.isPending}
              onClick={(event) => {
                event.preventDefault();
                if (removing) removeMutation.mutate(removing);
              }}
            >
              {removeMutation.isPending ? "Removing…" : "Remove"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
