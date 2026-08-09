import { ResourceForm } from "@/components/resource/resource-form";
import { ResourceTable } from "@/components/resource/resource-table";
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useAuth } from "@/hooks/use-auth";
import { useOperatorError } from "@/hooks/use-operator-error";
import { useI18n } from "@/i18n";
import type { TranslationKey } from "@/i18n";
import { type AdminSchema, adminDelete, adminGet, adminPost } from "@/lib/gateway-client";
import { defaultFieldValues } from "@/lib/resource-config";
import { type AdminVirtualApiKey, virtualKeysConfig } from "@/resources/virtual-keys";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MoreHorizontal, Plus } from "lucide-react";
// Virtual-key lifecycle console (#321): list + create + delete plus the
// enable / disable / rotate / revoke ACTION endpoints
// (`/admin/v1/virtual-keys/{key_id}/{action}`). This is a bespoke page rather
// than a generic resource because those actions need per-action confirmation
// and rotate returns a fresh secret shown ONCE. Columns/fields are reused from
// the shared virtual-keys resource config so the create form and table stay in
// sync with the OpenAPI contract (#314).
import { useState } from "react";
import { toast } from "sonner";

type KeyAction = "enable" | "disable" | "rotate" | "revoke" | "delete";

// Per-action metadata drives the confirm dialog and success toast. Copy stays
// as typed catalog keys resolved with `t()` at render time so the lifecycle
// actions localize; `destructive` toggles the destructive dialog styling.
const ACTION_META: Record<
  KeyAction,
  {
    labelKey: TranslationKey;
    titleKey: TranslationKey;
    descriptionKey: TranslationKey;
    successKey: TranslationKey;
    destructive: boolean;
  }
> = {
  enable: {
    labelKey: "page.virtualKeys.action.enable.label",
    titleKey: "page.virtualKeys.action.enable.title",
    descriptionKey: "page.virtualKeys.action.enable.description",
    successKey: "page.virtualKeys.action.enable.success",
    destructive: false,
  },
  disable: {
    labelKey: "page.virtualKeys.action.disable.label",
    titleKey: "page.virtualKeys.action.disable.title",
    descriptionKey: "page.virtualKeys.action.disable.description",
    successKey: "page.virtualKeys.action.disable.success",
    destructive: false,
  },
  rotate: {
    labelKey: "page.virtualKeys.action.rotate.label",
    titleKey: "page.virtualKeys.action.rotate.title",
    descriptionKey: "page.virtualKeys.action.rotate.description",
    successKey: "page.virtualKeys.action.rotate.success",
    destructive: false,
  },
  revoke: {
    labelKey: "page.virtualKeys.action.revoke.label",
    titleKey: "page.virtualKeys.action.revoke.title",
    descriptionKey: "page.virtualKeys.action.revoke.description",
    successKey: "page.virtualKeys.action.revoke.success",
    destructive: true,
  },
  delete: {
    labelKey: "page.virtualKeys.action.delete.label",
    titleKey: "page.virtualKeys.action.delete.title",
    descriptionKey: "page.virtualKeys.action.delete.description",
    successKey: "page.virtualKeys.action.delete.success",
    destructive: true,
  },
};

/** Extracts the one-time secret from a create/rotate response envelope. */
function extractSecret(response: unknown): string | null {
  if (response && typeof response === "object") {
    const record = response as Record<string, unknown>;
    for (const key of ["secret", "key"]) {
      if (typeof record[key] === "string") return record[key] as string;
    }
  }
  return null;
}

function runAction(apiKey: string, action: KeyAction, keyId: string): Promise<unknown> {
  const options = { params: { key_id: keyId } };
  switch (action) {
    case "enable":
      return adminPost(apiKey, "/admin/v1/virtual-keys/{key_id}/enable", undefined, options);
    case "disable":
      return adminPost(apiKey, "/admin/v1/virtual-keys/{key_id}/disable", undefined, options);
    case "rotate":
      return adminPost(apiKey, "/admin/v1/virtual-keys/{key_id}/rotate", undefined, options);
    case "revoke":
      return adminPost(apiKey, "/admin/v1/virtual-keys/{key_id}/revoke", undefined, options);
    case "delete":
      return adminDelete(apiKey, "/admin/v1/virtual-keys/{key_id}", options);
  }
}

export default function VirtualKeysPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["resource", "virtual-keys"];

  const [formOpen, setFormOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<{
    row: AdminVirtualApiKey;
    action: KeyAction;
  } | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const {
    data,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/virtual-keys"),
  });

  const rows = (data?.data ?? []) as AdminVirtualApiKey[];

  const createMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) =>
      adminPost(
        apiKey,
        "/admin/v1/virtual-keys",
        values as AdminSchema<"AdminVirtualApiKeyCreateRequest">,
      ),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t("page.virtualKeys.toast.created"));
      setFormOpen(false);
      const secret = extractSecret(response);
      if (secret) setRevealedSecret(secret);
    },
    onError: (error: Error) => toastError(error),
  });

  const actionMutation = useMutation({
    mutationFn: ({ row, action }: { row: AdminVirtualApiKey; action: KeyAction }) =>
      runAction(apiKey, action, row.id),
    onSuccess: (response, variables) => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(t(ACTION_META[variables.action].successKey));
      setPendingAction(null);
      if (variables.action === "rotate") {
        const secret = extractSecret(response);
        if (secret) setRevealedSecret(secret);
      }
    },
    onError: (error: Error) => {
      // Keep the confirm dialog open so a 403 (e.g. tenant-scope denial, #232)
      // stays visible instead of silently closing.
      toastError(error);
    },
  });

  const actionMeta = pendingAction ? ACTION_META[pendingAction.action] : null;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{t("page.virtualKeys.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("page.virtualKeys.description")}</p>
        </div>
        <Button onClick={() => setFormOpen(true)}>
          <Plus className="mr-1 h-4 w-4" />
          {t("resource.action.new")}
        </Button>
      </div>

      {listError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.virtualKeys.loadError", { message: (listError as Error).message })}
        </p>
      ) : null}

      <ResourceTable
        columns={virtualKeysConfig.columns}
        rows={rows}
        isLoading={isLoading}
        readOnly={false}
        emptyLabel={t("page.virtualKeys.empty")}
        rowLabel={virtualKeysConfig.rowLabel}
        renderActions={(row) => {
          const revoked = row.revoked_at_unix != null;
          return (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  className="size-11 lg:size-8"
                  aria-label={t("resource.action.rowActions", { label: row.name })}
                >
                  <MoreHorizontal className="size-4" aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  disabled={revoked}
                  onSelect={() =>
                    setPendingAction({ row, action: row.enabled ? "disable" : "enable" })
                  }
                >
                  {row.enabled
                    ? t("page.virtualKeys.action.disable.label")
                    : t("page.virtualKeys.action.enable.label")}
                </DropdownMenuItem>
                <DropdownMenuItem
                  disabled={revoked}
                  onSelect={() => setPendingAction({ row, action: "rotate" })}
                >
                  {t("page.virtualKeys.action.rotate.label")}
                </DropdownMenuItem>
                <DropdownMenuItem
                  disabled={revoked}
                  onSelect={() => setPendingAction({ row, action: "revoke" })}
                >
                  {t("page.virtualKeys.action.revoke.label")}
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="text-destructive"
                  onSelect={() => setPendingAction({ row, action: "delete" })}
                >
                  {t("page.virtualKeys.action.delete.label")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          );
        }}
      />

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {t("resource.dialog.createTitle", { name: t("page.virtualKeys.title") })}
            </SheetTitle>
          </SheetHeader>
          <div className="px-4 pb-4">
            <ResourceForm
              fields={virtualKeysConfig.fields}
              initialValues={defaultFieldValues(virtualKeysConfig.fields)}
              submitLabel={t("resource.action.create")}
              onCancel={() => setFormOpen(false)}
              onSubmit={async (values) => {
                await createMutation.mutateAsync(values);
              }}
            />
          </div>
        </SheetContent>
      </Sheet>

      <AlertDialog
        open={pendingAction !== null}
        onOpenChange={(open) => !open && setPendingAction(null)}
      >
        <AlertDialogContent>
          {pendingAction && actionMeta ? (
            <>
              <AlertDialogHeader>
                <AlertDialogTitle>{t(actionMeta.titleKey)}</AlertDialogTitle>
                <AlertDialogDescription>
                  {t(actionMeta.descriptionKey)}
                  <br />
                  <span className="font-medium">{pendingAction.row.name}</span> (
                  {pendingAction.row.key_prefix}...{pendingAction.row.last4})
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
                <AlertDialogAction
                  className={
                    actionMeta.destructive
                      ? "bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      : undefined
                  }
                  disabled={actionMutation.isPending}
                  onClick={(event) => {
                    // Keep the dialog mounted through the async call; close on success.
                    event.preventDefault();
                    actionMutation.mutate(pendingAction);
                  }}
                >
                  {actionMutation.isPending ? t("common.working") : t(actionMeta.labelKey)}
                </AlertDialogAction>
              </AlertDialogFooter>
            </>
          ) : null}
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={Boolean(revealedSecret)}
        onOpenChange={(open) => !open && setRevealedSecret(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("resource.secret.title")}</AlertDialogTitle>
            <AlertDialogDescription>{t("resource.secret.description")}</AlertDialogDescription>
          </AlertDialogHeader>
          <code className="block break-all rounded-md bg-muted p-3 text-sm">{revealedSecret}</code>
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
