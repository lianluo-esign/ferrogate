// Metering & usage read-only views (issue #319): three operator-facing lenses
// over the metering pipeline —
//   • Metering events  (/admin/v1/metering-events)        paginated raw events
//   • Export status    (/admin/v1/metering-export-status) per-request export outcomes
//   • Usage aggregates (/admin/v1/usage-aggregates)       rolled-up token totals
// All read-only; every call goes through the typed client.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { adminGet } from "@/lib/gateway-client";
import { tenantLabel } from "@/components/agent-ops/agent-ops-primitives";

const PAGE_SIZE = 50;

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "—";
  return new Date(unix * 1000).toLocaleString();
}

function MeteringEventsTab() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
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
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load metering events: {(error as Error).message}
        </p>
      ) : null}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Tenant</TableHead>
              <TableHead>Model</TableHead>
              <TableHead className="text-right">Prompt</TableHead>
              <TableHead className="text-right">Completion</TableHead>
              <TableHead className="text-right">Total</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : events.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  No metering events.
                </TableCell>
              </TableRow>
            ) : (
              events.map((event) => (
                <TableRow key={event.request_id}>
                  <TableCell className="text-xs">
                    {formatUnix(event.occurred_at_unix)}
                  </TableCell>
                  <TableCell className="text-xs">{tenantLabel(event.tenant)}</TableCell>
                  <TableCell className="text-xs font-medium">
                    {event.logical_model}
                    <div className="text-muted-foreground">
                      {event.provider}/{event.provider_model}
                    </div>
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {event.usage.prompt_tokens.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {event.usage.completion_tokens.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right text-xs font-medium">
                    {event.usage.total_tokens.toLocaleString()}
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
            ? `Showing ${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}`
            : "No events"}
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0}
            onClick={() => setOffset((current) => Math.max(0, current - PAGE_SIZE))}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset((current) => current + PAGE_SIZE)}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}

function ExportStatusTab() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["metering-export-status"],
    queryFn: () => adminGet(apiKey, "/admin/v1/metering-export-status"),
  });

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load export status: {(error as Error).message}
        </p>
      ) : null}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Provider</TableHead>
              <TableHead>Endpoint</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Request id</TableHead>
              <TableHead>Error</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  No export status records.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.request_id}>
                  <TableCell className="text-xs">
                    {formatUnix(row.occurred_at_unix)}
                  </TableCell>
                  <TableCell className="text-xs">{row.provider}</TableCell>
                  <TableCell className="font-mono text-xs">{row.endpoint}</TableCell>
                  <TableCell>
                    <Badge variant={row.success ? "secondary" : "destructive"}>
                      {row.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{row.request_id}</TableCell>
                  <TableCell className="text-xs text-destructive">
                    {row.error ?? "—"}
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

function UsageAggregatesTab() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["usage-aggregates"],
    queryFn: () => adminGet(apiKey, "/admin/v1/usage-aggregates"),
  });

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load usage aggregates: {(error as Error).message}
        </p>
      ) : null}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Organization</TableHead>
              <TableHead>Project</TableHead>
              <TableHead>API key</TableHead>
              <TableHead>Model</TableHead>
              <TableHead className="text-right">Prompt</TableHead>
              <TableHead className="text-right">Completion</TableHead>
              <TableHead className="text-right">Total</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  No usage aggregates.
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
                    {row.usage.prompt_tokens.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right text-xs">
                    {row.usage.completion_tokens.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right text-xs font-medium">
                    {row.usage.total_tokens.toLocaleString()}
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
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Metering &amp; usage</h1>
        <p className="text-sm text-muted-foreground">
          Read-only lenses over the metering pipeline: raw metering events, per-request
          export outcomes, and rolled-up usage aggregates.
        </p>
      </div>

      <Tabs defaultValue="events">
        <TabsList>
          <TabsTrigger value="events">Metering events</TabsTrigger>
          <TabsTrigger value="export">Export status</TabsTrigger>
          <TabsTrigger value="aggregates">Usage aggregates</TabsTrigger>
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
