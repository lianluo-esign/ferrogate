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
import { adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import { useState } from "react";

type DrainStatus = AdminSchema<"AdminDrainResponse">;

const DRAIN_REFETCH_INTERVAL_MS = 5_000;

export default function OpsDrainPage() {
  const { session } = useAuth();
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
        result.draining ? "Node is now draining" : "Node resumed serving",
      );
      queryClient.setQueryData(queryKey, result);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => {
      toast.error(`Drain change failed: ${err.message}`);
    },
  });

  const draining = data?.draining ?? false;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Graceful drain</h1>
        <p className="text-sm text-muted-foreground">
          Drain stops this node from accepting new AI requests while in-flight
          requests finish, so it can be rolled or removed from the pool safely.
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load drain status: {(error as Error).message}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            Drain status
            {data ? (
              <Badge variant={draining ? "destructive" : "default"}>
                {draining ? "draining" : "serving"}
              </Badge>
            ) : null}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading || !data ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <div className="divide-y">
              <DefinitionRow
                label="Draining"
                value={
                  <BoolBadge
                    value={data.draining}
                    trueLabel="draining"
                    falseLabel="serving"
                    good="false"
                  />
                }
              />
              <DefinitionRow
                label="Accepting new requests"
                value={<BoolBadge value={data.accepting_new_requests} />}
              />
              <DefinitionRow label="Reason" value={data.drain_reason} />
            </div>
          )}
          <div className="mt-4 flex gap-2">
            <Button
              variant="destructive"
              disabled={draining || mutation.isPending || !data}
              onClick={() => setConfirmDrain(true)}
            >
              Start drain
            </Button>
            <Button
              variant="outline"
              disabled={!draining || mutation.isPending || !data}
              onClick={() => setConfirmDrain(false)}
            >
              Resume serving
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
              {confirmDrain ? "Start draining this node?" : "Resume serving?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirmDrain
                ? "This node will stop accepting new AI requests and report unready to the load balancer. In-flight requests keep running until they finish. Use this before a rollout or shutdown."
                : "This node will resume accepting new AI requests and report ready again."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (confirmDrain !== null) mutation.mutate(confirmDrain);
                setConfirmDrain(null);
              }}
            >
              {confirmDrain ? "Confirm drain" : "Confirm resume"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
