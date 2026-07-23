// Provider & runtime health board (issue #322): read-only status over
// /admin/v1/provider-health, /provider-models, /framework-adapters and
// /extensions. Each tab is an independent query so a slow/erroring upstream
// probe (e.g. provider-models fanning out to live provider catalogs) doesn't
// block the others.
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { BoolBadge, formatUnix, HealthBadge } from "@/components/ops/ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ProviderHealthCheck = AdminSchema<"ProviderHealthCheck">;
type ProviderModelCatalog = AdminSchema<"AdminProviderModelCatalog">;
type FrameworkAdapter = AdminSchema<"AdminFrameworkAdapterRuntime">;
type ExtensionPlugin = AdminSchema<"AdminPlugin">;

function ErrorLine({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      {(error as Error).message}
    </p>
  );
}

function ProviderHealthTab({ apiKey }: { apiKey: string }) {
  const { t } = useI18n();
  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-provider-health"],
    queryFn: () => adminGet(apiKey, "/admin/v1/provider-health"),
    refetchInterval: 15_000,
  });
  const rows = data?.data ?? [];
  return (
    <div className="flex flex-col gap-3">
      <ErrorLine error={error} />
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.opsProviderHealth.providers.col.provider")}</TableHead>
              <TableHead>{t("common.status")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.providers.col.reachable")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.providers.col.circuit")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.providers.col.failures")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.providers.col.checked")}</TableHead>
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
                  {t("page.opsProviderHealth.providers.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row: ProviderHealthCheck) => (
                <TableRow key={row.name}>
                  <TableCell>
                    <div className="font-medium">{row.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {row.kind} · {row.base_url}
                    </div>
                    {row.error ? (
                      <div className="text-xs text-destructive">{row.error}</div>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <HealthBadge health={row.status} />
                      {!row.enabled ? (
                        <Badge variant="outline">{t("common.disabled")}</Badge>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <BoolBadge
                      value={row.reachable}
                      trueLabel={t("common.yes")}
                      falseLabel={t("common.no")}
                    />
                  </TableCell>
                  <TableCell>
                    <BoolBadge
                      value={row.circuit_open}
                      trueLabel={t("page.opsProviderHealth.circuit.open")}
                      falseLabel={t("page.opsProviderHealth.circuit.closed")}
                      good="false"
                    />
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {row.consecutive_failures}
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatUnix(row.checked_at_unix)}
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

function ProviderModelsTab({ apiKey }: { apiKey: string }) {
  const { t } = useI18n();
  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-provider-models"],
    queryFn: () => adminGet(apiKey, "/admin/v1/provider-models"),
  });
  const catalogs = data?.data ?? [];
  return (
    <div className="flex flex-col gap-3">
      <ErrorLine error={error} />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
      ) : catalogs.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("page.opsProviderHealth.models.empty")}</p>
      ) : (
        catalogs.map((catalog: ProviderModelCatalog) => (
          <div key={catalog.provider} className="rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{catalog.provider}</span>
              <Badge variant="outline">{catalog.kind}</Badge>
              <HealthBadge health={catalog.status} />
              <span className="text-xs text-muted-foreground">
                {t("page.opsProviderHealth.models.count", {
                  count: catalog.models.length,
                })}
              </span>
            </div>
            {catalog.error ? (
              <p className="mt-1 text-xs text-destructive">{catalog.error}</p>
            ) : null}
            {catalog.models.length > 0 ? (
              <div className="mt-2 flex flex-wrap gap-1">
                {catalog.models.slice(0, 24).map((model) => (
                  <Badge key={model.id} variant="secondary" className="font-mono">
                    {model.id}
                  </Badge>
                ))}
                {catalog.models.length > 24 ? (
                  <span className="text-xs text-muted-foreground">
                    {t("page.opsProviderHealth.models.more", {
                      count: catalog.models.length - 24,
                    })}
                  </span>
                ) : null}
              </div>
            ) : null}
          </div>
        ))
      )}
    </div>
  );
}

function FrameworkAdaptersTab({ apiKey }: { apiKey: string }) {
  const { t } = useI18n();
  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-framework-adapters"],
    queryFn: () => adminGet(apiKey, "/admin/v1/framework-adapters"),
  });
  const rows = data?.data ?? [];
  return (
    <div className="flex flex-col gap-3">
      <ErrorLine error={error} />
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.opsProviderHealth.adapters.col.adapter")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.adapters.col.framework")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.adapters.col.integration")}</TableHead>
              <TableHead>{t("common.enabled")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.adapters.col.modes")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  {t("page.opsProviderHealth.adapters.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row: FrameworkAdapter) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <div className="font-medium">{row.adapter_name}</div>
                    <div className="text-xs text-muted-foreground">
                      v{row.adapter_version}
                    </div>
                  </TableCell>
                  <TableCell>{row.framework}</TableCell>
                  <TableCell>
                    <HealthBadge health={row.integration_status} />
                  </TableCell>
                  <TableCell>
                    <BoolBadge
                      value={row.enabled}
                      trueLabel={t("common.yes")}
                      falseLabel={t("common.no")}
                    />
                  </TableCell>
                  <TableCell className="text-xs">{row.modes.join(", ")}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function ExtensionsTab({ apiKey }: { apiKey: string }) {
  const { t } = useI18n();
  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-extensions"],
    queryFn: () => adminGet(apiKey, "/admin/v1/extensions"),
  });
  const rows = data?.data ?? [];
  return (
    <div className="flex flex-col gap-3">
      <ErrorLine error={error} />
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.opsProviderHealth.extensions.col.extension")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.extensions.col.kind")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.extensions.col.lifecycle")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.extensions.col.health")}</TableHead>
              <TableHead>{t("page.opsProviderHealth.extensions.col.active")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  {t("page.opsProviderHealth.extensions.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row: ExtensionPlugin) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <div className="font-medium">{row.id}</div>
                    <div className="text-xs text-muted-foreground">
                      v{row.version} · {row.source}
                    </div>
                    {row.last_error ? (
                      <div className="text-xs text-destructive">{row.last_error}</div>
                    ) : null}
                  </TableCell>
                  <TableCell>{row.kind}</TableCell>
                  <TableCell>
                    <HealthBadge health={row.lifecycle} />
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
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export default function OpsProviderHealthPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.opsProviderHealth.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.opsProviderHealth.description")}
        </p>
      </div>

      <Tabs defaultValue="providers">
        <TabsList>
          <TabsTrigger value="providers">{t("page.opsProviderHealth.tab.providers")}</TabsTrigger>
          <TabsTrigger value="models">{t("page.opsProviderHealth.tab.models")}</TabsTrigger>
          <TabsTrigger value="adapters">{t("page.opsProviderHealth.tab.adapters")}</TabsTrigger>
          <TabsTrigger value="extensions">{t("page.opsProviderHealth.tab.extensions")}</TabsTrigger>
        </TabsList>
        <TabsContent value="providers">
          <ProviderHealthTab apiKey={apiKey} />
        </TabsContent>
        <TabsContent value="models">
          <ProviderModelsTab apiKey={apiKey} />
        </TabsContent>
        <TabsContent value="adapters">
          <FrameworkAdaptersTab apiKey={apiKey} />
        </TabsContent>
        <TabsContent value="extensions">
          <ExtensionsTab apiKey={apiKey} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
