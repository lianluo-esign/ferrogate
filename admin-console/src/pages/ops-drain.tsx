// Graceful drain control (issue #322) over GET/POST /admin/v1/drain.
//
// Drain flips this node out of the load-balancer's healthy set: it stops
// accepting NEW AI requests while letting in-flight work finish. Both
// starting and stopping a drain sit behind a confirmation dialog with explicit
// consequence text, since either changes whether live traffic is served.
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
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { BoolBadge, DefinitionRow } from "@/components/ops/ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import { useState } from "react";

type DrainStatus = AdminSchema<"AdminDrainResponse">;

const DRAIN_REFETCH_INTERVAL_MS = 5_000;

export default function OpsDrainPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["ops-drain"];

  const [confirmDrain, setConfirmDrain] = useState<boolean | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/drain"),
    refetchInterval: DRAIN_REFETCH_INTERVAL_MS,
  });

  const mutation = useMutation({
    mutationFn: (drain: boolean) =>
      adminPost(apiKey, "/admin/v1/drain", { drain }),
    onSuccess: (result: DrainStatus) => {
      toast.success(
        result.draining
          ? t("page.opsDrain.toast.draining")
          : t("page.opsDrain.toast.serving"),
      );
      queryClient.setQueryData(queryKey, result);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => {
      toast.error(t("page.opsDrain.toast.failed", { message: err.message }));
    },
  });

  const draining = data?.draining ?? false;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.opsDrain.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.opsDrain.description")}
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.opsDrain.loadError", { message: (error as Error).message })}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            {t("page.opsDrain.status.title")}
            {data ? (
              <Badge variant={draining ? "destructive" : "default"}>
                {draining
                  ? t("page.opsDrain.status.draining")
                  : t("page.opsDrain.status.serving")}
              </Badge>
            ) : null}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading || !data ? (
            <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
          ) : (
            <div className="divide-y">
              <DefinitionRow
                label={t("page.opsDrain.field.draining")}
                value={
                  <BoolBadge
                    value={data.draining}
                    trueLabel={t("page.opsDrain.status.draining")}
                    falseLabel={t("page.opsDrain.status.serving")}
                    good="false"
                  />
                }
              />
              <DefinitionRow
                label={t("page.opsDrain.field.accepting")}
                value={
                  <BoolBadge
                    value={data.accepting_new_requests}
                    trueLabel={t("common.yes")}
                    falseLabel={t("common.no")}
                  />
                }
              />
              <DefinitionRow label={t("page.opsDrain.field.reason")} value={data.drain_reason} />
            </div>
          )}
          <div className="mt-4 flex gap-2">
            <Button
              variant="destructive"
              disabled={draining || mutation.isPending || !data}
              onClick={() => setConfirmDrain(true)}
            >
              {t("page.opsDrain.action.start")}
            </Button>
            <Button
              variant="outline"
              disabled={!draining || mutation.isPending || !data}
              onClick={() => setConfirmDrain(false)}
            >
              {t("page.opsDrain.action.resume")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <AlertDialog
        open={confirmDrain !== null}
        onOpenChange={(open) => {
          if (!open) setConfirmDrain(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirmDrain
                ? t("page.opsDrain.confirm.startTitle")
                : t("page.opsDrain.confirm.resumeTitle")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirmDrain
                ? t("page.opsDrain.confirm.startBody")
                : t("page.opsDrain.confirm.resumeBody")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (confirmDrain !== null) mutation.mutate(confirmDrain);
                setConfirmDrain(null);
              }}
            >
              {confirmDrain
                ? t("page.opsDrain.confirm.start")
                : t("page.opsDrain.confirm.resume")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
