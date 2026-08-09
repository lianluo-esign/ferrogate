import { tenantLabel } from "@/components/agent-ops/agent-ops-primitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/hooks/use-auth";
import { useFormatUnix } from "@/hooks/use-format-unix";
import { useI18n } from "@/i18n";
import { adminGet } from "@/lib/gateway-client";
import { useQuery } from "@tanstack/react-query";
// Metering & usage read-only views (issue #319): three operator-facing lenses
// over the metering pipeline —
//   • Metering events  (/admin/v1/metering-events)        paginated raw events
//   • Export status    (/admin/v1/metering-export-status) per-request export outcomes
//   • Usage aggregates (/admin/v1/usage-aggregates)       rolled-up token totals
// All read-only; every call goes through the typed client.
import { useState } from "react";

const PAGE_SIZE = 50;

function MeteringEventsTab() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const formatUnix = useFormatUnix("—");
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const [offset, setOffset] = useState(0);

  const { data, isLoading, error } = useQuery({
    queryKey: ["metering-events", offset],
    queryFn: () =>
      adminGet(apiKey, "/admin/v1/metering-events", {
        query: { offset, limit: PAGE_SIZE },
      }),
  });

  const events = data?.data ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.billingMetering.events.loadError", {
            message: (error as Error).message,
          })}
        </p>
      ) : null}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.billingMetering.col.when")}</TableHead>
              <TableHead>{t("common.tenant")}</TableHead>
              <TableHead>{t("page.billingMetering.col.model")}</TableHead>
              <TableHead className="text-right">{t("page.billingMetering.col.prompt")}</TableHead>
              <TableHead className="text-right">
                {t("page.billingMetering.col.completion")}
              </TableHead>
              <TableHead className="text-right">{t("page.billingMetering.col.total")}</TableHead>
              <TableHead>{t("page.billingMetering.col.source")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : events.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("page.billingMetering.events.empty")}
                </TableCell>
              </TableRow>
            ) : (
              events.map((event) => (
                <TableRow key={event.request_id}>
                  <TableCell className="text-xs">{formatUnix(event.occurred_at_unix)}</TableCell>
                  <TableCell className="text-xs">{tenantLabel(event.tenant)}</TableCell>
                  <TableCell className="text-xs font-medium">
                    {event.logical_model}
                    <div className="text-muted-foreground">
                      {event.provider}/{event.provider_model}
                    </div>
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {format.tokens(event.usage.prompt_tokens)}
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {format.tokens(event.usage.completion_tokens)}
                  </TableCell>
                  <TableCell className="text-right text-xs font-medium">
                    {format.tokens(event.usage.total_tokens)}
                  </TableCell>
                  <TableCell className="text-xs">{event.usage_source}</TableCell>
                  <TableCell className="text-xs">{event.status_code}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>
          {total > 0
            ? t("page.billingMetering.events.range", {
                start: offset + 1,
                end: Math.min(offset + PAGE_SIZE, total),
                total,
              })
            : t("page.billingMetering.events.noEvents")}
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0}
            onClick={() => setOffset((current) => Math.max(0, current - PAGE_SIZE))}
          >
            {t("resource.pagination.previous")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset((current) => current + PAGE_SIZE)}
          >
            {t("resource.pagination.next")}
          </Button>
        </div>
      </div>
    </div>
  );
}

function ExportStatusTab() {
  const { session } = useAuth();
  const { t } = useI18n();
  const formatUnix = useFormatUnix("—");
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["metering-export-status"],
    queryFn: () => adminGet(apiKey, "/admin/v1/metering-export-status"),
  });

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.billingMetering.export.loadError", {
            message: (error as Error).message,
          })}
        </p>
      ) : null}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.billingMetering.col.when")}</TableHead>
              <TableHead>{t("page.billingMetering.col.provider")}</TableHead>
              <TableHead>{t("page.billingMetering.col.endpoint")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
              <TableHead>{t("page.billingMetering.col.requestId")}</TableHead>
              <TableHead>{t("page.billingMetering.col.error")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("page.billingMetering.export.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.request_id}>
                  <TableCell className="text-xs">{formatUnix(row.occurred_at_unix)}</TableCell>
                  <TableCell className="text-xs">{row.provider}</TableCell>
                  <TableCell className="font-mono text-xs">{row.endpoint}</TableCell>
                  <TableCell>
                    <Badge variant={row.success ? "secondary" : "destructive"}>{row.status}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{row.request_id}</TableCell>
                  <TableCell className="text-xs text-destructive">{row.error ?? "—"}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function UsageAggregatesTab() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["usage-aggregates"],
    queryFn: () => adminGet(apiKey, "/admin/v1/usage-aggregates"),
  });

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.billingMetering.aggregates.loadError", {
            message: (error as Error).message,
          })}
        </p>
      ) : null}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.billingMetering.col.organization")}</TableHead>
              <TableHead>{t("page.billingMetering.col.project")}</TableHead>
              <TableHead>{t("page.billingMetering.col.apiKey")}</TableHead>
              <TableHead>{t("page.billingMetering.col.model")}</TableHead>
              <TableHead className="text-right">{t("page.billingMetering.col.prompt")}</TableHead>
              <TableHead className="text-right">
                {t("page.billingMetering.col.completion")}
              </TableHead>
              <TableHead className="text-right">{t("page.billingMetering.col.total")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("page.billingMetering.aggregates.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="text-xs">{row.organization_id ?? "—"}</TableCell>
                  <TableCell className="text-xs">{row.project_id ?? "—"}</TableCell>
                  <TableCell className="text-xs">{row.api_key_id ?? "—"}</TableCell>
                  <TableCell className="text-xs font-medium">
                    {row.logical_model}
                    <div className="text-muted-foreground">{row.provider}</div>
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {format.tokens(row.usage.prompt_tokens)}
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {format.tokens(row.usage.completion_tokens)}
                  </TableCell>
                  <TableCell className="text-right text-xs font-medium">
                    {format.tokens(row.usage.total_tokens)}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export default function BillingMeteringPage() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.billingMetering.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.billingMetering.description")}</p>
      </div>

      <Tabs defaultValue="events">
        <TabsList>
          <TabsTrigger value="events">{t("page.billingMetering.tab.events")}</TabsTrigger>
          <TabsTrigger value="export">{t("page.billingMetering.tab.export")}</TabsTrigger>
          <TabsTrigger value="aggregates">{t("page.billingMetering.tab.aggregates")}</TabsTrigger>
        </TabsList>
        <TabsContent value="events">
          <MeteringEventsTab />
        </TabsContent>
        <TabsContent value="export">
          <ExportStatusTab />
        </TabsContent>
        <TabsContent value="aggregates">
          <UsageAggregatesTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
