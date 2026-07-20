// Virtual-key lifecycle console (#321): list + create + delete plus the
// enable / disable / rotate / revoke ACTION endpoints
// (`/admin/v1/virtual-keys/{key_id}/{action}`). This is a bespoke page rather
// than a generic resource because those actions need per-action confirmation
// and rotate returns a fresh secret shown ONCE. Columns/fields are reused from
// the shared virtual-keys resource config so the create form and table stay in
// sync with the OpenAPI contract (#314).
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ResourceForm } from "@/components/resource/resource-form";
import { useAuth } from "@/hooks/use-auth";
import {
  adminDelete,
  adminGet,
  adminPost,
  type AdminSchema,
} from "@/lib/gateway-client";
import { defaultFieldValues } from "@/lib/resource-config";
import { virtualKeysConfig, type AdminVirtualApiKey } from "@/resources/virtual-keys";

type KeyAction = "enable" | "disable" | "rotate" | "revoke" | "delete";

const ACTION_COPY: Record<
  KeyAction,
  { title: string; description: string; confirmLabel: string; success: string; destructive: boolean }
> = {
  enable: {
    title: "Enable key",
    description: "Re-enable this virtual key so it can authenticate requests again.",
    confirmLabel: "Enable",
    success: "Virtual key enabled",
    destructive: false,
  },
  disable: {
    title: "Disable key",
    description:
      "Disable this virtual key. Requests using it are rejected until it is re-enabled.",
    confirmLabel: "Disable",
    success: "Virtual key disabled",
    destructive: false,
  },
  rotate: {
    title: "Rotate key",
    description:
      "Issue a fresh secret for this key and invalidate the previous one. The new secret is shown ONCE.",
    confirmLabel: "Rotate",
    success: "Virtual key rotated",
    destructive: false,
  },
  revoke: {
    title: "Revoke key",
    description:
      "Permanently revoke this virtual key. It can no longer be enabled and cannot authenticate.",
    confirmLabel: "Revoke",
    success: "Virtual key revoked",
    destructive: true,
  },
  delete: {
    title: "Delete key",
    description: "Delete this virtual key record entirely. This cannot be undone.",
    confirmLabel: "Delete",
    success: "Virtual key deleted",
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

function runAction(
  apiKey: string,
  action: KeyAction,
  keyId: string,
): Promise<unknown> {
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
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["resource", "virtual-keys"];

  const [formOpen, setFormOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<{
    row: AdminVirtualApiKey;
    action: KeyAction;
  } | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const { data, isLoading, error: listError } = useQuery({
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
      toast.success("Virtual key created");
      setFormOpen(false);
      const secret = extractSecret(response);
      if (secret) setRevealedSecret(secret);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const actionMutation = useMutation({
    mutationFn: ({ row, action }: { row: AdminVirtualApiKey; action: KeyAction }) =>
      runAction(apiKey, action, row.id),
    onSuccess: (response, variables) => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(ACTION_COPY[variables.action].success);
      setPendingAction(null);
      if (variables.action === "rotate") {
        const secret = extractSecret(response);
        if (secret) setRevealedSecret(secret);
      }
    },
    onError: (error: Error) => {
      // Keep the confirm dialog open so a 403 (e.g. tenant-scope denial, #232)
      // stays visible instead of silently closing.
      toast.error(error.message);
    },
  });

  const actionCopy = pendingAction ? ACTION_COPY[pendingAction.action] : null;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{virtualKeysConfig.title}</h1>
          <p className="text-sm text-muted-foreground">
            {virtualKeysConfig.description}
          </p>
        </div>
        <Button
          onClick={() => setFormOpen(true)}
        >
          <Plus className="mr-1 h-4 w-4" />
          New
        </Button>
      </div>

      {listError ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load virtual keys: {(listError as Error).message}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              {virtualKeysConfig.columns.map((column) => (
                <TableHead key={column.key}>{column.header}</TableHead>
              ))}
              <TableHead className="w-[360px] text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell
                  colSpan={virtualKeysConfig.columns.length + 1}
                  className="h-24 text-center"
                >
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={virtualKeysConfig.columns.length + 1}
                  className="h-24 text-center"
                >
                  No virtual keys yet.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => {
                const revoked = row.revoked_at_unix != null;
                return (
                  <TableRow key={row.id}>
                    {virtualKeysConfig.columns.map((column) => (
                      <TableCell key={column.key}>
                        {column.render
                          ? column.render(row)
                          : String(row[column.key] ?? "")}
                      </TableCell>
                    ))}
                    <TableCell>
                      <div className="flex flex-wrap justify-end gap-2">
                        {revoked ? (
                          <Badge variant="destructive">revoked</Badge>
                        ) : row.enabled ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setPendingAction({ row, action: "disable" })}
                          >
                            Disable
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setPendingAction({ row, action: "enable" })}
                          >
                            Enable
                          </Button>
                        )}
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={revoked}
                          onClick={() => setPendingAction({ row, action: "rotate" })}
                        >
                          Rotate
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={revoked}
                          onClick={() => setPendingAction({ row, action: "revoke" })}
                        >
                          Revoke
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive"
                          onClick={() => setPendingAction({ row, action: "delete" })}
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>New {virtualKeysConfig.title}</SheetTitle>
          </SheetHeader>
          <div className="px-4 pb-4">
            <ResourceForm
              fields={virtualKeysConfig.fields}
              initialValues={defaultFieldValues(virtualKeysConfig.fields)}
              submitLabel="Create"
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
          {pendingAction && actionCopy ? (
            <>
              <AlertDialogHeader>
                <AlertDialogTitle>{actionCopy.title}</AlertDialogTitle>
                <AlertDialogDescription>
                  {actionCopy.description}
                  <br />
                  <span className="font-medium">{pendingAction.row.name}</span> (
                  {pendingAction.row.key_prefix}...{pendingAction.row.last4})
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  className={
                    actionCopy.destructive
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
                  {actionMutation.isPending ? "Working..." : actionCopy.confirmLabel}
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
            <AlertDialogTitle>Save this secret now</AlertDialogTitle>
            <AlertDialogDescription>
              This value will not be shown again. Store it somewhere safe.
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
                    toast.error("Could not copy to clipboard; the secret is shown above.");
                  });
                }
                setRevealedSecret(null);
              }}
            >
              Copy &amp; close
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
