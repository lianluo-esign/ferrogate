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
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type ProviderHealthCheck = AdminSchema<"ProviderHealthCheck">;
type ProviderModelCatalog = AdminSchema<"AdminProviderModelCatalog">;
type FrameworkAdapter = AdminSchema<"AdminFrameworkAdapterRuntime">;
type ExtensionPlugin = AdminSchema<"AdminPlugin">;

function ErrorLine({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      {(error as Error).message}
    </p>
  );
}

function ProviderHealthTab({ apiKey }: { apiKey: string }) {
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
              <TableHead>Provider</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Reachable</TableHead>
              <TableHead>Circuit</TableHead>
              <TableHead>Failures</TableHead>
              <TableHead>Checked</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  No providers configured.
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
                        <Badge variant="outline">disabled</Badge>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <BoolBadge value={row.reachable} />
                  </TableCell>
                  <TableCell>
                    <BoolBadge
                      value={row.circuit_open}
                      trueLabel="open"
                      falseLabel="closed"
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
  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-provider-models"],
    queryFn: () => adminGet(apiKey, "/admin/v1/provider-models"),
  });
  const catalogs = data?.data ?? [];
  return (
    <div className="flex flex-col gap-3">
      <ErrorLine error={error} />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : catalogs.length === 0 ? (
        <p className="text-sm text-muted-foreground">No provider catalogs.</p>
      ) : (
        catalogs.map((catalog: ProviderModelCatalog) => (
          <div key={catalog.provider} className="rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{catalog.provider}</span>
              <Badge variant="outline">{catalog.kind}</Badge>
              <HealthBadge health={catalog.status} />
              <span className="text-xs text-muted-foreground">
                {catalog.models.length} models
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
                    +{catalog.models.length - 24} more
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
              <TableHead>Adapter</TableHead>
              <TableHead>Framework</TableHead>
              <TableHead>Integration</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead>Modes</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  No framework adapters.
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
                    <BoolBadge value={row.enabled} />
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
              <TableHead>Extension</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Lifecycle</TableHead>
              <TableHead>Health</TableHead>
              <TableHead>Active</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center">
                  No extensions.
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
                    <BoolBadge value={row.active} />
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
  const apiKey = session!.gatewayApiKey;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Provider &amp; runtime health</h1>
        <p className="text-sm text-muted-foreground">
          Upstream provider reachability, discovered model catalogs, framework
          adapter runtimes and loaded extensions.
        </p>
      </div>

      <Tabs defaultValue="providers">
        <TabsList>
          <TabsTrigger value="providers">Provider health</TabsTrigger>
          <TabsTrigger value="models">Provider models</TabsTrigger>
          <TabsTrigger value="adapters">Framework adapters</TabsTrigger>
          <TabsTrigger value="extensions">Extensions</TabsTrigger>
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
