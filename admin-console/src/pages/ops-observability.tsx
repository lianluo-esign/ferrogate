// Observability & log exports (issue #322): read-only exporter status over
// GET /admin/v1/observability, plus a request-log export tool over
// GET /admin/v1/request-log-exports.
//
// The export endpoint streams newline-delimited JSON (application/x-ndjson),
// not the Admin API's JSON list envelope, so it can't go through the typed
// `adminGet` (whose success body is JSON). It's fetched directly with the
// gateway API key here, then previewed and offered as a file download.
import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
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
import { useI18n } from "@/i18n";
import { GATEWAY_ADMIN_BASE_URL } from "@/lib/config";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ObservabilityStatus = AdminSchema<"ObservabilityStatus">;

interface ExportFilters {
  model: string;
  provider: string;
  status: string;
  limit: string;
}

const DEFAULT_LIMIT = "100";

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
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-observability"],
    queryFn: () => adminGet(apiKey, "/admin/v1/observability"),
    refetchInterval: 15_000,
  });
  const exporters = data?.data ?? [];

  // #342: the export filters live in the URL query so a configured export is
  // shareable and survives a reload (?model=&provider=&status=&limit=). The
  // model/provider filters target the known models/providers catalogs, so they
  // WRITE the canonical name to the query while the picker DISPLAYS the human
  // label; `allowRawValue` still lets an operator export logs for a historical
  // model/provider no longer in the catalog (no silent exclusion). Defaults
  // (empty model/provider/status, limit 100) are encoded as ABSENT params.
  const [searchParams, setSearchParams] = useSearchParams();
  const filters: ExportFilters = {
    model: searchParams.get("model") ?? "",
    provider: searchParams.get("provider") ?? "",
    status: searchParams.get("status") ?? "",
    limit: searchParams.get("limit") ?? DEFAULT_LIMIT,
  };

  const setFilterParam = useCallback(
    (key: keyof ExportFilters, value: string, defaultValue: string) => {
      const next = new URLSearchParams(searchParams);
      if (value === defaultValue || value === "") next.delete(key);
      else next.set(key, value);
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [exporting, setExporting] = useState(false);

  async function runExport() {
    setExporting(true);
    try {
      const response = await fetch(buildExportUrl(filters), {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (!response.ok) {
        throw new Error(
          t("page.opsObservability.exportFailed", { status: response.status }),
        );
      }
      const body = await response.text();
      const recordCount = body
        .split("\n")
        .filter((line) => line.trim().length > 0).length;
      setPreview({ recordCount, body });
      toast.success(t("page.opsObservability.toast.fetched", { count: recordCount }));
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
        <h1 className="text-lg font-semibold">{t("page.opsObservability.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.opsObservability.description")}
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.opsObservability.loadError", { message: (error as Error).message })}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.opsObservability.exporters.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("page.opsObservability.col.provider")}</TableHead>
                  <TableHead>{t("page.opsObservability.col.health")}</TableHead>
                  <TableHead>{t("page.opsObservability.col.active")}</TableHead>
                  <TableHead>{t("page.opsObservability.col.endpoint")}</TableHead>
                  <TableHead>{t("page.opsObservability.col.dropped")}</TableHead>
                  <TableHead>{t("page.opsObservability.col.lastSuccess")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="h-24 text-center">
                      {t("resource.table.loading")}
                    </TableCell>
                  </TableRow>
                ) : exporters.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="h-24 text-center">
                      {t("page.opsObservability.exporters.empty")}
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
                        <BoolBadge
                          value={row.active}
                          trueLabel={t("common.yes")}
                          falseLabel={t("common.no")}
                        />
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
          <CardTitle className="text-base">{t("page.opsObservability.export.title")}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <div className="grid gap-2">
              <Label htmlFor="exp-model">{t("page.opsObservability.filter.model")}</Label>
              {/* #342: the model filter targets the known models catalog — pick
                  by name (human label) instead of typing a raw string; the
                  canonical model name is written to the query. `allowRawValue`
                  keeps historical models exportable. */}
              <EntityReferencePicker
                id="exp-model"
                label={t("page.opsObservability.filter.model")}
                reference={{
                  target: "models",
                  valueKey: "name",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["provider", "provider_model"],
                  allowRawValue: true,
                }}
                value={filters.model}
                dependencyValues={{}}
                onChange={(value) =>
                  setFilterParam("model", typeof value === "string" ? value : "", "")
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="exp-provider">{t("page.opsObservability.filter.provider")}</Label>
              {/* #342: the provider filter targets the known providers catalog. */}
              <EntityReferencePicker
                id="exp-provider"
                label={t("page.opsObservability.filter.provider")}
                reference={{
                  target: "providers",
                  valueKey: "name",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["kind"],
                  allowRawValue: true,
                }}
                value={filters.provider}
                dependencyValues={{}}
                onChange={(value) =>
                  setFilterParam("provider", typeof value === "string" ? value : "", "")
                }
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="exp-status">{t("page.opsObservability.filter.status")}</Label>
              <Input
                id="exp-status"
                type="number"
                value={filters.status}
                onChange={(event) => setFilterParam("status", event.target.value, "")}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="exp-limit">{t("page.opsObservability.filter.limit")}</Label>
              <Input
                id="exp-limit"
                type="number"
                min={1}
                max={1000}
                value={filters.limit}
                onChange={(event) => setFilterParam("limit", event.target.value, DEFAULT_LIMIT)}
              />
            </div>
          </div>
          <div className="flex gap-2">
            <Button onClick={runExport} disabled={exporting}>
              {exporting
                ? t("page.opsObservability.fetching")
                : t("page.opsObservability.fetch")}
            </Button>
            <Button
              variant="outline"
              onClick={downloadExport}
              disabled={preview === null}
            >
              {t("page.opsObservability.download")}
            </Button>
          </div>
          {preview ? (
            <div className="divide-y rounded-md border p-3">
              <DefinitionRow
                label={t("page.opsObservability.records")}
                value={<Badge variant="secondary">{preview.recordCount}</Badge>}
              />
              <div className="pt-2">
                <span className="text-xs text-muted-foreground">
                  {t("page.opsObservability.preview")}
                </span>
                <pre className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted px-2 py-1 font-mono text-xs">
                  {preview.body.trim() || t("page.opsObservability.empty")}
                </pre>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
