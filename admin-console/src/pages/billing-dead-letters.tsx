// Billing outbox dead-letters browser (issue #319, over #143): usage reports
// that permanently failed delivery to the standalone billing service after the
// max retry attempts, surfaced so an operator can inspect (and remediate out of
// band) instead of them silently accumulating.
//
// The endpoint (/admin/v1/billing-outbox-dead-letters) is untyped in the
// contract (`object` w/ additionalProperties), so the runtime
// `{ object: "list", data: StoredBillingReportOutboxEntry[] }` envelope is
// modeled locally over the fields this view renders.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";
import { tenantLabel } from "@/components/agent-ops/agent-ops-primitives";

interface DeadLetterEvent {
  request_id: string;
  trace_id: string | null;
  tenant: AdminSchema<"TenantContext">;
  logical_model: string;
  provider: string;
  provider_model: string;
  status_code: number;
  cost_usd: number | null;
  occurred_at_unix: number | null;
}

interface DeadLetterEntry {
  id: string;
  event: DeadLetterEvent;
  attempts: number;
  next_attempt_unix: number;
  dead_lettered_at_unix: number | null;
}

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "—";
  return new Date(unix * 1000).toLocaleString();
}

export default function BillingDeadLettersPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const [filter, setFilter] = useState("");
  const [detail, setDetail] = useState<DeadLetterEntry | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["billing-dead-letters"],
    queryFn: async () => {
      const body = await adminGet(apiKey, "/admin/v1/billing-outbox-dead-letters");
      return (body as { data?: DeadLetterEntry[] }).data ?? [];
    },
  });

  const entries = useMemo(() => {
    const rows = data ?? [];
    const needle = filter.trim().toLowerCase();
    if (needle === "") return rows;
    return rows.filter(
      (row) =>
        row.id.toLowerCase().includes(needle) ||
        row.event.request_id.toLowerCase().includes(needle) ||
        tenantLabel(row.event.tenant).toLowerCase().includes(needle),
    );
  }, [data, filter]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Billing dead-letters</h1>
        <p className="text-sm text-muted-foreground">
          Usage reports that permanently failed delivery to the billing service
          after exhausting retries. Inspect the delivery context here and remediate
          out of band.
        </p>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load dead-letters: {(error as Error).message}
        </p>
      ) : null}

      <Input
        className="w-80"
        placeholder="Filter by id, request id, or tenant"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Ledger id</TableHead>
              <TableHead>Tenant</TableHead>
              <TableHead>Model</TableHead>
              <TableHead className="text-right">Attempts</TableHead>
              <TableHead>Dead-lettered</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  No dead-lettered billing reports.
                </TableCell>
              </TableRow>
            ) : (
              entries.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="font-mono text-xs">{entry.id}</TableCell>
                  <TableCell className="text-xs">
                    {tenantLabel(entry.event.tenant)}
                  </TableCell>
                  <TableCell className="text-xs">{entry.event.logical_model}</TableCell>
                  <TableCell className="text-right text-xs">{entry.attempts}</TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(entry.dead_lettered_at_unix)}
                  </TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" onClick={() => setDetail(entry)}>
                      Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog open={detail !== null} onOpenChange={(open) => !open && setDetail(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          {detail ? (
            <>
              <DialogHeader>
                <DialogTitle>Dead-letter {detail.id}</DialogTitle>
                <DialogDescription>
                  Delivery and error context for the failed usage report.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3 sm:grid-cols-2">
                <Detail label="Request id" value={detail.event.request_id} />
                <Detail label="Trace id" value={detail.event.trace_id ?? "—"} />
                <Detail label="Tenant" value={tenantLabel(detail.event.tenant)} />
                <Detail
                  label="Model"
                  value={`${detail.event.logical_model} (${detail.event.provider}/${detail.event.provider_model})`}
                />
                <Detail label="Status code" value={String(detail.event.status_code)} />
                <Detail
                  label="Cost (USD)"
                  value={detail.event.cost_usd != null ? `$${detail.event.cost_usd}` : "—"}
                />
                <Detail label="Delivery attempts" value={String(detail.attempts)} />
                <Detail
                  label="Next attempt"
                  value={formatUnix(detail.next_attempt_unix)}
                />
                <Detail
                  label="Occurred at"
                  value={formatUnix(detail.event.occurred_at_unix)}
                />
                <Detail
                  label="Dead-lettered at"
                  value={formatUnix(detail.dead_lettered_at_unix)}
                />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDetail(null)}>
                  Close
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="break-all text-sm">{value}</span>
    </div>
  );
}
