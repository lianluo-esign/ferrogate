import { tenantLabel } from "@/components/agent-ops/agent-ops-primitives";
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
import { useFormatUnix } from "@/hooks/use-format-unix";
import { type BoundFormatters, useI18n } from "@/i18n";
import { type AdminSchema, adminGet } from "@/lib/gateway-client";
import { useQuery } from "@tanstack/react-query";
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

// `cost_usd` is the API's exact USD amount; render it through the locale
// currency formatter without any local recomputation or rounding.
function formatCost(format: BoundFormatters, costUsd: number | null | undefined): string {
  if (costUsd === null || costUsd === undefined) return "—";
  return format.currency(costUsd, "USD");
}

export default function BillingDeadLettersPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const formatUnix = useFormatUnix("—");
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

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
        <h1 className="text-lg font-semibold">{t("page.billingDeadLetters.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.billingDeadLetters.description")}</p>
      </div>

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.billingDeadLetters.loadError", {
            message: (error as Error).message,
          })}
        </p>
      ) : null}

      <Input
        className="w-80"
        placeholder={t("page.billingDeadLetters.filterPlaceholder")}
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.billingDeadLetters.col.ledgerId")}</TableHead>
              <TableHead>{t("common.tenant")}</TableHead>
              <TableHead>{t("page.billingDeadLetters.col.model")}</TableHead>
              <TableHead className="text-right">
                {t("page.billingDeadLetters.col.attempts")}
              </TableHead>
              <TableHead>{t("page.billingDeadLetters.col.deadLettered")}</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("page.billingDeadLetters.empty")}
                </TableCell>
              </TableRow>
            ) : (
              entries.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="font-mono text-xs">{entry.id}</TableCell>
                  <TableCell className="text-xs">{tenantLabel(entry.event.tenant)}</TableCell>
                  <TableCell className="text-xs">{entry.event.logical_model}</TableCell>
                  <TableCell className="text-right text-xs">{entry.attempts}</TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(entry.dead_lettered_at_unix)}
                  </TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" onClick={() => setDetail(entry)}>
                      {t("page.billingDeadLetters.details")}
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
                <DialogTitle>
                  {t("page.billingDeadLetters.detail.title", { id: detail.id })}
                </DialogTitle>
                <DialogDescription>
                  {t("page.billingDeadLetters.detail.description")}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3 sm:grid-cols-2">
                <Detail
                  label={t("page.billingDeadLetters.detail.requestId")}
                  value={detail.event.request_id}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.traceId")}
                  value={detail.event.trace_id ?? "—"}
                />
                <Detail label={t("common.tenant")} value={tenantLabel(detail.event.tenant)} />
                <Detail
                  label={t("page.billingDeadLetters.col.model")}
                  value={`${detail.event.logical_model} (${detail.event.provider}/${detail.event.provider_model})`}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.statusCode")}
                  value={String(detail.event.status_code)}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.cost")}
                  value={formatCost(format, detail.event.cost_usd)}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.attempts")}
                  value={String(detail.attempts)}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.nextAttempt")}
                  value={formatUnix(detail.next_attempt_unix)}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.occurredAt")}
                  value={formatUnix(detail.event.occurred_at_unix)}
                />
                <Detail
                  label={t("page.billingDeadLetters.detail.deadLetteredAt")}
                  value={formatUnix(detail.dead_lettered_at_unix)}
                />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDetail(null)}>
                  {t("page.billingDeadLetters.detail.close")}
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
