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
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { Button } from "@/components/ui/button";
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
import { useI18n } from "@/i18n";
import { adminDelete, adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";

type AdminTenantRoleBinding = AdminSchema<"AdminTenantRoleBinding">;

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "-";
  return new Date(unix * 1000).toLocaleString();
}

export default function TenantRolesPage() {
  const { session } = useAuth();
  const { t } = useI18n();
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
      toast.success(t("page.tenantRoles.toast.assigned"));
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
      toast.success(t("page.tenantRoles.toast.removed"));
      setRemoving(null);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.tenantRoles.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.tenantRoles.description")}
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="grid w-72 gap-2">
          {/* #340: pick the owning tenant account from the shared #337 registry
              instead of pasting a tenant id; the canonical `id` still drives the
              parameterised list/assign/remove paths. */}
          <Label htmlFor="tenant-id">{t("common.tenant")}</Label>
          <EntityReferencePicker
            id="tenant-id"
            label={t("common.tenant")}
            reference={{
              target: "tenant-accounts",
              valueKey: "id",
              primaryLabelKey: "name",
              secondaryLabelKeys: ["slug"],
            }}
            value={tenantId}
            dependencyValues={{}}
            placeholder={t("page.tenantRoles.placeholder.tenantId")}
            onChange={(value) => setTenantId(typeof value === "string" ? value : "")}
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
        <div className="grid w-72 gap-2">
          {/* #340: choose the RBAC role from the roles catalog; the binding still
              submits the role's canonical `id`. A deleted role selected earlier
              stays inspectable as an unresolved chip. */}
          <Label htmlFor="role-id">{t("page.tenantRoles.field.role")}</Label>
          <EntityReferencePicker
            id="role-id"
            label={t("page.tenantRoles.field.role")}
            reference={{
              target: "roles",
              valueKey: "id",
              primaryLabelKey: "name",
              secondaryLabelKeys: ["slug"],
            }}
            value={roleId}
            dependencyValues={{}}
            placeholder={t("page.tenantRoles.placeholder.roleId")}
            onChange={(value) => setRoleId(typeof value === "string" ? value : "")}
          />
        </div>
        <Button
          type="submit"
          disabled={roleId.trim() === "" || tenantId.trim() === "" || assignMutation.isPending}
        >
          <Plus className="mr-1 h-4 w-4" />
          {t("page.tenantRoles.assign")}
        </Button>
      </form>

      {listError ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.tenantRoles.loadError", { message: (listError as Error).message })}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.tenantRoles.col.roleId")}</TableHead>
              <TableHead>{t("page.tenantRoles.col.boundAt")}</TableHead>
              <TableHead className="w-24 text-right">
                {t("resource.table.actionsColumn")}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={3} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : bindings.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="h-24 text-center">
                  {t("page.tenantRoles.empty")}
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
                        {t("resource.action.remove")}
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
            <AlertDialogTitle>{t("page.tenantRoles.remove.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.tenantRoles.remove.description", {
                role: removing?.role_id ?? "",
                tenant: tenantId,
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={removeMutation.isPending}
              onClick={(event) => {
                event.preventDefault();
                if (removing) removeMutation.mutate(removing);
              }}
            >
              {removeMutation.isPending
                ? t("page.tenantRoles.removing")
                : t("resource.action.remove")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
