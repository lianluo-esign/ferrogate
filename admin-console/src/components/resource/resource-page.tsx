import { useRef, useState } from "react";
import { AsyncStatus } from "@/components/ui/async-status";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Plus } from "lucide-react";
import { useSearchParams } from "react-router-dom";
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
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { CatalogScopeToggle } from "@/components/resource/catalog-scope-toggle";
import { ResourceForm } from "@/components/resource/resource-form";
import { ResourceTable } from "@/components/resource/resource-table";
import { useAuth } from "@/hooks/use-auth";
import { useCatalogApiKey } from "@/hooks/use-catalog-api-key";
import { useCatalogScope } from "@/hooks/use-catalog-scope";
import { useI18n } from "@/i18n";
import { useOperatorError } from "@/hooks/use-operator-error";
import {
  gatewayDelete,
  gatewayGet,
  gatewayPost,
  gatewayPut,
  type AdminPage,
} from "@/lib/gateway-client";
import {
  defaultFieldValues,
  resolveConfigText,
  resolveOptionalConfigText,
  type ResourceConfig,
} from "@/lib/resource-config";

export function ResourcePage<T extends Record<string, unknown>>({
  config,
}: {
  config: ResourceConfig<T>;
}) {
  const { session } = useAuth();
  // Platform-scopable catalog pages (#912) select their credential by the active
  // catalog scope — the platform-operator key under "platform", the tenant key
  // otherwise — so create/edit/delete AND the list all address one catalog. The
  // catalog hooks are called unconditionally to satisfy the rules of hooks;
  // non-scopable resources keep exactly their prior tenant-key behavior.
  const catalogApiKey = useCatalogApiKey();
  const { scope } = useCatalogScope();
  const apiKey = config.platformScopable ? catalogApiKey : session!.gatewayApiKey;
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  // Per-resource copy resolves the typed catalog key when present (migrated
  // resources) and falls back to the legacy inline literal otherwise (#348).
  const title = resolveConfigText(t, config.titleKey, config.title);
  const description = resolveOptionalConfigText(
    t,
    config.descriptionKey,
    config.description,
  );
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const paginationMode = config.pagination ?? (config.fetchList ? "none" : "offset");
  const requestedPage = Number.parseInt(searchParams.get("page") ?? "1", 10);
  const page = paginationMode === "offset" && requestedPage > 0 ? requestedPage : 1;
  const pageSize = 25;
  const offset = (page - 1) * pageSize;
  // A scopable resource keys its list on the active scope so flipping the toggle
  // refetches the OTHER catalog rather than serving stale rows; non-scopable
  // resources keep the prior key shape exactly.
  const queryKey = config.platformScopable
    ? ["resource", config.key, paginationMode === "offset" ? offset : 0, scope]
    : ["resource", config.key, paginationMode === "offset" ? offset : 0];

  const [formOpen, setFormOpen] = useState(false);
  const [editingRow, setEditingRow] = useState<T | null>(null);
  const [deletingRow, setDeletingRow] = useState<T | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const newButtonRef = useRef<HTMLButtonElement>(null);
  const formReturnFocusRef = useRef<HTMLElement | null>(null);
  const deleteReturnFocusRef = useRef<HTMLElement | null>(null);

  const {
    data,
    isLoading,
    isFetching,
    error: listError,
  } = useQuery({
    queryKey,
    queryFn: () =>
      config.fetchList
        ? config.fetchList(apiKey, { offset, limit: pageSize })
        : gatewayGet<AdminPage<T>>(apiKey, config.basePath, {
            query: { offset, limit: pageSize },
          }),
    placeholderData: (previous) => previous,
  });

  const createMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) =>
      gatewayPost<Record<string, unknown>>(apiKey, config.basePath, values),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t("resource.toast.created", { name: title }));
      setFormOpen(false);
      if (config.secretResponseKey) {
        const secret = response[config.secretResponseKey];
        if (typeof secret === "string") setRevealedSecret(secret);
      }
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, values }: { id: string; values: Record<string, unknown> }) =>
      gatewayPut(apiKey, `${config.basePath}/${id}`, values),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t("resource.toast.updated", { name: title }));
      setEditingRow(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => gatewayDelete(apiKey, `${config.basePath}/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t("resource.toast.deleted", { name: title }));
      setDeletingRow(null);
    },
    onError: (error: Error) => {
      toastError(error);
    },
  });

  const rows = data?.data ?? [];
  const total = data?.total ?? (paginationMode === "none" ? rows.length : undefined);
  const rangeStart = rows.length > 0 ? offset + 1 : 0;
  const rangeEnd = rows.length > 0 ? offset + rows.length : 0;
  const hasNext = total !== undefined ? rangeEnd < total : rows.length === pageSize;
  const canEdit = !config.readOnly && !config.noEditDelete && !config.noUpdate;
  const canDelete = !config.readOnly && !config.noEditDelete && !config.noDelete;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">{title}</h1>
          {description && (
            <p className="text-sm text-muted-foreground">{description}</p>
          )}
        </div>
        <div className="flex items-center gap-3">
          {config.platformScopable && <CatalogScopeToggle />}
          {!config.readOnly && (
            <Button
              ref={newButtonRef}
              onClick={() => {
                formReturnFocusRef.current = newButtonRef.current;
                setEditingRow(null);
                setFormOpen(true);
              }}
            >
              <Plus className="mr-1 h-4 w-4" />
              {t("resource.action.new")}
            </Button>
          )}
        </div>
      </div>

      {listError && (
        <AsyncStatus tone="error">
          {t("resource.list.loadError", {
            name: title.toLowerCase(),
            message: listError.message,
          })}
        </AsyncStatus>
      )}

      <ResourceTable
        columns={config.columns}
        rows={rows}
        isLoading={isLoading}
        readOnly={!canEdit && !canDelete}
        emptyLabel={
          listError ? t("resource.table.unavailable") : t("resource.table.empty")
        }
        rowLabel={config.rowLabel}
        rowHref={config.rowHref}
        onEdit={
          canEdit
            ? (row, trigger) => {
                formReturnFocusRef.current = trigger ?? null;
                setEditingRow(row);
                setFormOpen(true);
              }
            : undefined
        }
        onDelete={canDelete ? (row, trigger) => {
          deleteReturnFocusRef.current = trigger ?? null;
          setDeletingRow(row);
        } : undefined}
      />

      <nav className="flex flex-col gap-2 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between" aria-label={t("resource.pagination.label", { name: title })}>
        <span aria-live="polite">
          {total !== undefined
            ? t("resource.pagination.rangeOf", {
                start: rangeStart,
                end: rangeEnd,
                total,
              })
            : t("resource.pagination.range", { start: rangeStart, end: rangeEnd })}
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="min-h-11 flex-1 sm:min-h-9 sm:flex-none"
            disabled={page === 1 || isFetching}
            onClick={() => {
              const next = new URLSearchParams(searchParams);
              const previousPage = Math.max(1, page - 1);
              if (previousPage === 1) next.delete("page");
              else next.set("page", String(previousPage));
              setSearchParams(next);
            }}
          >
            <ChevronLeft className="size-4" aria-hidden="true" />
            {t("resource.pagination.previous")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="min-h-11 flex-1 sm:min-h-9 sm:flex-none"
            disabled={!hasNext || isFetching}
            onClick={() => {
              const next = new URLSearchParams(searchParams);
              next.set("page", String(page + 1));
              setSearchParams(next);
            }}
          >
            {t("resource.pagination.next")}
            <ChevronRight className="size-4" aria-hidden="true" />
          </Button>
        </div>
      </nav>

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent
          className="overflow-y-auto sm:max-w-lg"
          onCloseAutoFocus={(event) => {
            if (!formReturnFocusRef.current) return;
            event.preventDefault();
            formReturnFocusRef.current.focus();
          }}
        >
          <SheetHeader>
            <SheetTitle>
              {editingRow
                ? t("resource.dialog.editTitle", { name: title })
                : t("resource.dialog.createTitle", { name: title })}
            </SheetTitle>
          </SheetHeader>
          <div className="px-4 pb-4">
            <ResourceForm
              fields={config.fields}
              isEdit={Boolean(editingRow)}
              initialValues={
                editingRow
                  ? config.unwrapRow
                    ? config.unwrapRow(editingRow)
                    : (editingRow as Record<string, unknown>)
                  : defaultFieldValues(config.fields)
              }
              submitLabel={
                editingRow
                  ? t("resource.action.saveChanges")
                  : t("resource.action.create")
              }
              onCancel={() => setFormOpen(false)}
              onSubmit={async (values) => {
                if (editingRow) {
                  await updateMutation.mutateAsync({
                    id: config.resolveDetailPath
                      ? config.resolveDetailPath(editingRow)
                      : String(editingRow[config.idField]),
                    values,
                  });
                } else {
                  await createMutation.mutateAsync(values);
                }
              }}
            />
          </div>
        </SheetContent>
      </Sheet>

      <AlertDialog open={Boolean(deletingRow)} onOpenChange={(open) => !open && setDeletingRow(null)}>
        <AlertDialogContent
          onCloseAutoFocus={(event) => {
            if (!deleteReturnFocusRef.current) return;
            event.preventDefault();
            deleteReturnFocusRef.current.focus();
          }}
        >
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("resource.dialog.deleteTitle", {
                name: title.toLowerCase(),
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("resource.dialog.deleteDescription")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deletingRow) {
                  deleteMutation.mutate(
                    config.resolveDetailPath
                      ? config.resolveDetailPath(deletingRow)
                      : String(deletingRow[config.idField]),
                  );
                }
              }}
            >
              {t("resource.action.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={Boolean(revealedSecret)} onOpenChange={(open) => !open && setRevealedSecret(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("resource.secret.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("resource.secret.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <code className="block break-all rounded-md bg-muted p-3 text-sm">
            {revealedSecret}
          </code>
          <AlertDialogFooter>
            <AlertDialogAction
              onClick={() => {
                if (revealedSecret) {
                  navigator.clipboard.writeText(revealedSecret).catch(() => {
                    toast.error(t("resource.secret.copyError"));
                  });
                }
                setRevealedSecret(null);
              }}
            >
              {t("resource.secret.copyClose")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
