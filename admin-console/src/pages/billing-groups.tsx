import { CatalogScopeToggle } from "@/components/resource/catalog-scope-toggle";
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
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
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
import { useCatalogApiKey } from "@/hooks/use-catalog-api-key";
import { useCatalogScope } from "@/hooks/use-catalog-scope";
import { useOperatorError } from "@/hooks/use-operator-error";
import { useI18n } from "@/i18n";
import { adminDelete, adminGet, adminPatch, adminPost, adminPut } from "@/lib/gateway-client";
import type {
  AdminBillingGroup as BillingGroup,
  BillingGroupMutation,
} from "@/resources/billing-groups";
import type { AdminProvider } from "@/resources/providers";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";

// Platform billing-groups console surface (#946, epic #941): the operator UI over
// GET/POST /admin/v1/billing-groups, GET/PATCH/DELETE /admin/v1/billing-groups/{id}
// and PUT/DELETE /admin/v1/billing-groups/{id}/providers/{providerId} (S2/S3,
// #943/#944). A billing group carries one price MULTIPLIER and binds a set of
// platform provider channels many-to-many.
//
// This REUSES slice 2a's platform-scope machinery (`useCatalogApiKey()` +
// `<CatalogScopeToggle>`): the surface is platform-operator ONLY — a
// tenant-scoped caller is fenced with a leak-proof 404 — so the operator flips to
// platform scope to reach it, exactly as on the model-offerings page. The console
// never sends a `tenant_id`; scope is resolved purely from WHICH credential asked.
// The provider list backing the bind picker is fetched with the SAME scoped key so
// it lists the platform provider catalogue under platform scope.

interface GroupFormState {
  name: string;
  nameZh: string;
  multiplier: string;
  description: string;
  descriptionZh: string;
  enabled: boolean;
}

function emptyForm(): GroupFormState {
  return { name: "", nameZh: "", multiplier: "1", description: "", descriptionZh: "", enabled: true };
}

function formFromGroup(group: BillingGroup): GroupFormState {
  return {
    name: group.name,
    nameZh: group.name_zh ?? "",
    multiplier: String(group.multiplier),
    description: group.description ?? "",
    descriptionZh: group.description_zh ?? "",
    enabled: group.enabled,
  };
}

export default function BillingGroupsPage() {
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  // Slice 2a's scope machinery: the credential follows the active scope, and both
  // queries key on it so flipping the toggle refetches the platform surface.
  const apiKey = useCatalogApiKey();
  const { scope } = useCatalogScope();
  const queryClient = useQueryClient();
  const groupsKey = useMemo(() => ["billing-groups", scope], [scope]);
  const providersKey = useMemo(() => ["billing-groups", "providers", scope], [scope]);

  const [formOpen, setFormOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<GroupFormState>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<BillingGroup | null>(null);

  const {
    data: groupsData,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey: groupsKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/billing-groups"),
  });

  const groups = useMemo(() => groupsData?.data ?? [], [groupsData]);

  // The provider catalogue backing the bind picker. Only needed once the operator
  // opens an existing group's editor, so it is lazy (`enabled`) on the sheet.
  const { data: providersData } = useQuery({
    queryKey: providersKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/providers", { query: { offset: 0, limit: 200 } }),
    enabled: formOpen && editingId !== null,
  });

  const providers = useMemo<AdminProvider[]>(
    () => (providersData?.data ?? []) as AdminProvider[],
    [providersData],
  );

  // The editing group is derived from the FRESHEST query data by id, so a
  // bind/unbind that refetches the list immediately reflows the picker's ticks.
  const editing = useMemo(
    () => (editingId ? (groups.find((group) => group.id === editingId) ?? null) : null),
    [editingId, groups],
  );

  const boundProviderIds = useMemo(() => new Set(editing?.provider_ids ?? []), [editing]);

  function openCreate() {
    setEditingId(null);
    setForm(emptyForm());
    setFormError(null);
    setFormOpen(true);
  }

  function openEdit(group: BillingGroup) {
    setEditingId(group.id);
    setForm(formFromGroup(group));
    setFormError(null);
    setFormOpen(true);
  }

  const createMutation = useMutation({
    mutationFn: (body: BillingGroupMutation) => adminPost(apiKey, "/admin/v1/billing-groups", body),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: groupsKey });
      toast.success(t("page.billingGroups.toast.created"));
      // Keep the sheet open on the freshly-created group so its providers can be
      // bound straight away (create carries no provider_ids).
      const created = response.billing_group;
      if (created) {
        setEditingId(created.id);
        setForm(formFromGroup(created));
      } else {
        setFormOpen(false);
      }
    },
    onError: (error: Error) => {
      setFormError(error.message);
      toastError(error);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: BillingGroupMutation }) =>
      adminPatch(apiKey, "/admin/v1/billing-groups/{id}", body, { params: { id } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: groupsKey });
      toast.success(t("page.billingGroups.toast.updated"));
      setFormOpen(false);
      setEditingId(null);
    },
    onError: (error: Error) => {
      setFormError(error.message);
      toastError(error);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      adminDelete(apiKey, "/admin/v1/billing-groups/{id}", { params: { id } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: groupsKey });
      toast.success(t("page.billingGroups.toast.deleted"));
      setDeleting(null);
    },
    onError: (error: Error) => {
      toastError(error);
      setDeleting(null);
    },
  });

  const bindMutation = useMutation({
    mutationFn: ({ id, providerId, bind }: { id: string; providerId: string; bind: boolean }) =>
      bind
        ? adminPut(apiKey, "/admin/v1/billing-groups/{id}/providers/{providerId}", undefined, {
            params: { id, providerId },
          })
        : adminDelete(apiKey, "/admin/v1/billing-groups/{id}/providers/{providerId}", {
            params: { id, providerId },
          }),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: groupsKey });
      toast.success(
        variables.bind
          ? t("page.billingGroups.toast.providerBound")
          : t("page.billingGroups.toast.providerUnbound"),
      );
    },
    onError: (error: Error) => {
      toastError(error);
    },
  });

  function submitForm() {
    setFormError(null);
    const name = form.name.trim();
    if (name === "") {
      setFormError(t("page.billingGroups.validation.nameRequired"));
      return;
    }
    const multiplier = Number(form.multiplier.trim());
    if (!Number.isFinite(multiplier) || multiplier < 0) {
      setFormError(t("page.billingGroups.validation.multiplierInvalid"));
      return;
    }
    const description = form.description.trim();
    const nameZh = form.nameZh.trim();
    const descriptionZh = form.descriptionZh.trim();
    const body: BillingGroupMutation = {
      name,
      name_zh: nameZh === "" ? null : nameZh,
      multiplier,
      description: description === "" ? null : description,
      description_zh: descriptionZh === "" ? null : descriptionZh,
      enabled: form.enabled,
    };
    if (editing) {
      updateMutation.mutate({ id: editing.id, body });
    } else {
      createMutation.mutate(body);
    }
  }

  function toggleProvider(providerId: string, bind: boolean) {
    if (!editing) return;
    bindMutation.mutate({ id: editing.id, providerId, bind });
  }

  const submitting = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">{t("resource.billingGroups.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("resource.billingGroups.description")}</p>
          {scope === "platform" ? (
            <p className="mt-1 text-xs text-muted-foreground">{t("catalog.scope.hint")}</p>
          ) : (
            <p className="mt-1 text-xs text-muted-foreground">
              {t("page.billingGroups.platformHint")}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <CatalogScopeToggle />
          <Button onClick={openCreate}>{t("resource.action.new")}</Button>
        </div>
      </div>

      {listError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.billingGroups.loadError", { message: listError.message })}
        </p>
      ) : null}

      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("resource.billingGroups.col.name")}</TableHead>
              <TableHead>{t("resource.billingGroups.col.multiplier")}</TableHead>
              <TableHead>{t("resource.billingGroups.col.providers")}</TableHead>
              <TableHead>{t("resource.billingGroups.col.enabled")}</TableHead>
              <TableHead className="w-32">
                <span className="sr-only">{t("resource.table.actionsColumn")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : groups.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  {t("page.billingGroups.empty")}
                </TableCell>
              </TableRow>
            ) : (
              groups.map((group) => (
                <TableRow key={group.id} data-testid={`billing-group-${group.id}`}>
                  <TableCell className="font-medium">{group.name}</TableCell>
                  <TableCell>{group.multiplier}</TableCell>
                  <TableCell>{group.provider_ids.length}</TableCell>
                  <TableCell>{group.enabled ? t("common.yes") : t("common.no")}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(group)}>
                        {t("resource.action.edit")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => setDeleting(group)}
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

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {editing ? t("page.billingGroups.edit.title") : t("page.billingGroups.create.title")}
            </SheetTitle>
          </SheetHeader>
          <div className="grid gap-3 px-4 pb-4">
            <div className="grid gap-1.5">
              <Label htmlFor="name">{t("resource.billingGroups.field.name")} *</Label>
              <Input
                id="name"
                value={form.name}
                onChange={(event) => setForm((prev) => ({ ...prev, name: event.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                {t("page.billingGroups.field.name.hint")}
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="name_zh">{t("resource.billingGroups.field.nameZh")}</Label>
              <Input
                id="name_zh"
                value={form.nameZh}
                onChange={(event) => setForm((prev) => ({ ...prev, nameZh: event.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                {t("page.billingGroups.field.localized.hint")}
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="multiplier">{t("resource.billingGroups.field.multiplier")} *</Label>
              <Input
                id="multiplier"
                type="number"
                min={0}
                step="any"
                value={form.multiplier}
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, multiplier: event.target.value }))
                }
              />
              <p className="text-xs text-muted-foreground">
                {t("page.billingGroups.field.multiplier.hint")}
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="description">{t("resource.billingGroups.field.description")}</Label>
              <Textarea
                id="description"
                value={form.description}
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, description: event.target.value }))
                }
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="description_zh">
                {t("resource.billingGroups.field.descriptionZh")}
              </Label>
              <Textarea
                id="description_zh"
                value={form.descriptionZh}
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, descriptionZh: event.target.value }))
                }
              />
              <p className="text-xs text-muted-foreground">
                {t("page.billingGroups.field.localized.hint")}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((prev) => ({ ...prev, enabled: checked }))}
              />
              <Label htmlFor="enabled">{t("resource.billingGroups.field.enabled")}</Label>
            </div>

            {formError ? (
              <p
                role="alert"
                className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {formError}
              </p>
            ) : null}

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setFormOpen(false)}>
                {t("resource.action.cancel")}
              </Button>
              <Button onClick={submitForm} disabled={submitting}>
                {editing ? t("resource.action.saveChanges") : t("resource.action.create")}
              </Button>
            </div>

            {editing ? (
              <div className="mt-2 grid gap-2 border-t pt-4">
                <div>
                  <h2 className="text-sm font-semibold">
                    {t("page.billingGroups.providers.title")}
                  </h2>
                  <p className="text-xs text-muted-foreground">
                    {t("page.billingGroups.providers.description")}
                  </p>
                </div>
                {providers.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t("page.billingGroups.providers.empty")}
                  </p>
                ) : (
                  <ul className="grid gap-1">
                    {providers.map((provider) => {
                      const providerId = String(provider.id ?? "");
                      const bound = boundProviderIds.has(providerId);
                      return (
                        <li
                          key={providerId}
                          className="flex items-center justify-between gap-2 rounded-md border px-3 py-2"
                        >
                          <span className="text-sm">
                            {provider.name}
                            <span className="ml-2 font-mono text-xs text-muted-foreground">
                              {providerId}
                            </span>
                          </span>
                          <Switch
                            aria-label={t("page.billingGroups.providers.toggleLabel", {
                              provider: provider.name,
                            })}
                            checked={bound}
                            disabled={bindMutation.isPending || providerId === ""}
                            onCheckedChange={(checked) => toggleProvider(providerId, checked)}
                          />
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <AlertDialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("page.billingGroups.delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.billingGroups.delete.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                if (deleting) deleteMutation.mutate(deleting.id);
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
