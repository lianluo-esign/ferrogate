// Observability & log exports (issue #322): read-only exporter status over
// GET /admin/v1/observability, plus a request-log export tool over
// GET /admin/v1/request-log-exports.
//
// The export endpoint streams newline-delimited JSON (application/x-ndjson),
// not the Admin API's JSON list envelope, so it can't go through the typed
// `adminGet` (whose success body is JSON). It's fetched directly with the
// gateway API key here, then previewed and offered as a file download.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  BoolBadge,
  DefinitionRow,
  formatUnix,
  HealthBadge,
} from "@/components/ops/ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { GATEWAY_ADMIN_BASE_URL } from "@/lib/config";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ObservabilityStatus = AdminSchema<"ObservabilityStatus">;

interface ExportFilters {
  model: string;
  provider: string;
  status: string;
  limit: string;
}

const EMPTY_FILTERS: ExportFilters = {
  model: "",
  provider: "",
  status: "",
  limit: "100",
};

interface ExportPreview {
  recordCount: number;
  body: string;
}

function buildExportUrl(filters: ExportFilters): string {
  const url = new URL("/admin/v1/request-log-exports", GATEWAY_ADMIN_BASE_URL);
  if (filters.model.trim()) url.searchParams.set("model", filters.model.trim());
  if (filters.provider.trim())
    url.searchParams.set("provider", filters.provider.trim());
  if (filters.status.trim()) url.searchParams.set("status", filters.status.trim());
  if (filters.limit.trim()) url.searchParams.set("limit", filters.limit.trim());
  return url.toString();
}

export default function OpsObservabilityPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-observability"],
    queryFn: () => adminGet(apiKey, "/admin/v1/observability"),
    refetchInterval: 15_000,
  });
  const exporters = data?.data ?? [];

  const [filters, setFilters] = useState<ExportFilters>(EMPTY_FILTERS);
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [exporting, setExporting] = useState(false);

  async function runExport() {
    setExporting(true);
    try {
      const response = await fetch(buildExportUrl(filters), {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (!response.ok) {
        throw new Error(`export failed (${response.status})`);
      }
      const body = await response.text();
      const recordCount = body
        .split("\n")
        .filter((line) => line.trim().length > 0).length;
      setPreview({ recordCount, body });
      toast.success(`Fetched ${recordCount} export records`);
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setExporting(false);
    }
  }

  function downloadExport() {
    if (!preview) return;
    const blob = new Blob([preview.body], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "request-log-export.jsonl";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Observability &amp; exports</h1>
        <p className="text-sm text-muted-foreground">
          Telemetry exporter status and on-demand request-log (JSONL) exports.
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load observability: {(error as Error).message}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Telemetry exporters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Health</TableHead>
                  <TableHead>Active</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Dropped</TableHead>
                  <TableHead>Last success</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="h-24 text-center">
                      Loading…
                    </TableCell>
                  </TableRow>
                ) : exporters.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="h-24 text-center">
                      No exporters configured.
                    </TableCell>
                  </TableRow>
                ) : (
                  exporters.map((row: ObservabilityStatus) => (
                    <TableRow key={row.provider}>
                      <TableCell>
                        <div className="font-medium">{row.provider}</div>
                        <div className="text-xs text-muted-foreground">
                          {row.signals.join(", ") || "-"}
                        </div>
                        {row.last_export_error ? (
                          <div className="text-xs text-destructive">
                            {row.last_export_error}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <HealthBadge health={row.health} />
                      </TableCell>
                      <TableCell>
                        <BoolBadge value={row.active} />
                      </TableCell>
                      <TableCell className="text-xs">{row.endpoint ?? "-"}</TableCell>
                      <TableCell className="tabular-nums">
                        {row.dropped_events}
                      </TableCell>
                      <TableCell className="text-xs">
                        {formatUnix(row.last_success_at_unix)}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Request-log export</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <div className="grid gap-2">
              <Label htmlFor="exp-model">Model</Label>
              <Input
                id="exp-model"
                value={filters.model}
                onChange={(event) =>
                  setFilters((prev) => ({ ...prev, model: event.target.value }))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="exp-provider">Provider</Label>
              <Input
                id="exp-provider"
                value={filters.provider}
                onChange={(event) =>
                  setFilters((prev) => ({ ...prev, provider: event.target.value }))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="exp-status">Status code</Label>
              <Input
                id="exp-status"
                type="number"
                value={filters.status}
                onChange={(event) =>
                  setFilters((prev) => ({ ...prev, status: event.target.value }))
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="exp-limit">Limit</Label>
              <Input
                id="exp-limit"
                type="number"
                min={1}
                max={1000}
                value={filters.limit}
                onChange={(event) =>
                  setFilters((prev) => ({ ...prev, limit: event.target.value }))
                }
              />
            </div>
          </div>
          <div className="flex gap-2">
            <Button onClick={runExport} disabled={exporting}>
              {exporting ? "Fetching…" : "Fetch export"}
            </Button>
            <Button
              variant="outline"
              onClick={downloadExport}
              disabled={preview === null}
            >
              Download JSONL
            </Button>
          </div>
          {preview ? (
            <div className="divide-y rounded-md border p-3">
              <DefinitionRow
                label="Records"
                value={<Badge variant="secondary">{preview.recordCount}</Badge>}
              />
              <div className="pt-2">
                <span className="text-xs text-muted-foreground">Preview</span>
                <pre className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
                  {preview.body.trim() || "(empty)"}
                </pre>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
