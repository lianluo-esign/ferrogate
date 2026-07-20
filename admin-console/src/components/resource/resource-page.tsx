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
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { ResourceForm } from "@/components/resource/resource-form";
import { ResourceTable } from "@/components/resource/resource-table";
import { useAuth } from "@/hooks/use-auth";
import {
  gatewayDelete,
  gatewayGet,
  gatewayPost,
  gatewayPut,
  type AdminPage,
} from "@/lib/gateway-client";
import { defaultFieldValues, type ResourceConfig } from "@/lib/resource-config";

export function ResourcePage<T extends Record<string, unknown>>({
  config,
}: {
  config: ResourceConfig<T>;
}) {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["resource", config.key];

  const [formOpen, setFormOpen] = useState(false);
  const [editingRow, setEditingRow] = useState<T | null>(null);
  const [deletingRow, setDeletingRow] = useState<T | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const {
    data,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey,
    queryFn: () =>
      config.fetchList
        ? config.fetchList(apiKey)
        : gatewayGet<AdminPage<T>>(apiKey, config.basePath, { query: { limit: 200 } }),
  });

  const createMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) =>
      gatewayPost<Record<string, unknown>>(apiKey, config.basePath, values),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(`${config.title} created`);
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
      toast.success(`${config.title} updated`);
      setEditingRow(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => gatewayDelete(apiKey, `${config.basePath}/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey });
      toast.success(`${config.title} deleted`);
      setDeletingRow(null);
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  const rows = data?.data ?? [];
  const canEdit = !config.readOnly && !config.noEditDelete;
  const canDelete = canEdit && !config.noDelete;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{config.title}</h1>
          {config.description && (
            <p className="text-sm text-muted-foreground">{config.description}</p>
          )}
        </div>
        {!config.readOnly && (
          <Button
            onClick={() => {
              setEditingRow(null);
              setFormOpen(true);
            }}
          >
            <Plus className="mr-1 h-4 w-4" />
            New
          </Button>
        )}
      </div>

      {listError && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load {config.title.toLowerCase()}: {listError.message}
        </p>
      )}

      <ResourceTable
        columns={config.columns}
        rows={rows}
        isLoading={isLoading}
        readOnly={!canEdit && !canDelete}
        onEdit={
          canEdit
            ? (row) => {
                setEditingRow(row);
                setFormOpen(true);
              }
            : undefined
        }
        onDelete={canDelete ? (row) => setDeletingRow(row) : undefined}
      />

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {editingRow ? `Edit ${config.title}` : `New ${config.title}`}
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
              submitLabel={editingRow ? "Save changes" : "Create"}
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
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {config.title.toLowerCase()}?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
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
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={Boolean(revealedSecret)} onOpenChange={(open) => !open && setRevealedSecret(null)}>
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
              Copy & close
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
