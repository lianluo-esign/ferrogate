// Operations status dashboard (issue #322): the landing ops view over
// GET /admin/v1/status (AdminStatus). Surfaces the running snapshot, the
// enabled-vs-total counters, the ACME renewal + reload_required posture (#265),
// the cluster readiness/drain state and storage/analytics backend evidence in
// one scannable board.
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  BoolBadge,
  DefinitionRow,
  formatUnix,
  HealthBadge,
  StatTile,
} from "@/components/ops/ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { adminGet, type AdminSchema } from "@/lib/gateway-client";

type AdminStatus = AdminSchema<"AdminStatus">;
type AdminAcmeStatus = AdminSchema<"AdminAcmeStatus">;

const STATUS_REFETCH_INTERVAL_MS = 10_000;

function AcmeCard({ acme }: { acme: AdminAcmeStatus | null | undefined }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          TLS / ACME
          {acme?.reload_required ? (
            <Badge variant="destructive">reload required</Badge>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!acme || !acme.enabled ? (
          <p className="text-sm text-muted-foreground">
            ACME automatic certificate management is disabled.
          </p>
        ) : (
          <div className="divide-y">
            <DefinitionRow label="Domains" value={acme.domains.join(", ") || "-"} />
            <DefinitionRow
              label="Renewal due"
              value={
                <BoolBadge
                  value={acme.renewal_due}
                  trueLabel="due"
                  falseLabel="not due"
                  good="false"
                />
              }
            />
            <DefinitionRow
              label="Reload required"
              value={
                <BoolBadge
                  value={acme.reload_required}
                  trueLabel={`required (${acme.reload_mode})`}
                  falseLabel="up to date"
                  good="false"
                />
              }
            />
            <DefinitionRow
              label="Last renewal"
              value={
                <span className="flex items-center gap-2">
                  <HealthBadge health={acme.last_renewal_status} />
                  <span className="text-muted-foreground">
                    {formatUnix(acme.last_renewal_at_unix)}
                  </span>
                </span>
              }
            />
            <DefinitionRow
              label="Certificate expires"
              value={formatUnix(acme.certificate_expires_at_unix)}
            />
            <DefinitionRow
              label="Next check"
              value={formatUnix(acme.next_check_at_unix)}
            />
            {acme.last_renewal_error ? (
              <DefinitionRow
                label="Last error"
                value={
                  <span className="text-destructive">{acme.last_renewal_error}</span>
                }
              />
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ClusterCard({ cluster }: { cluster: AdminStatus["cluster"] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Cluster</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="divide-y">
          <DefinitionRow
            label="Enabled"
            value={<BoolBadge value={cluster.enabled} />}
          />
          <DefinitionRow
            label="Ready"
            value={
              <span className="flex items-center gap-2">
                <BoolBadge value={cluster.ready} />
                <span className="text-xs text-muted-foreground">
                  {cluster.readiness_reason}
                </span>
              </span>
            }
          />
          <DefinitionRow
            label="Draining"
            value={
              <BoolBadge
                value={cluster.draining}
                trueLabel="draining"
                falseLabel="serving"
                good="false"
              />
            }
          />
          <DefinitionRow
            label="Accepting requests"
            value={<BoolBadge value={cluster.accepting_new_requests} />}
          />
          <DefinitionRow label="Node" value={cluster.node_id || "-"} />
          <DefinitionRow label="Cluster id" value={cluster.cluster_id || "-"} />
          <DefinitionRow label="Active revision" value={cluster.active_revision || "-"} />
          <DefinitionRow
            label="State / counter backend"
            value={`${cluster.state_backend} / ${cluster.counter_backend}`}
          />
          <DefinitionRow
            label="Last sync"
            value={
              <span className="flex items-center gap-2">
                {formatUnix(cluster.last_sync_at_unix)}
                {cluster.stale ? <Badge variant="destructive">stale</Badge> : null}
              </span>
            }
          />
          {cluster.last_sync_error ? (
            <DefinitionRow
              label="Sync error"
              value={<span className="text-destructive">{cluster.last_sync_error}</span>}
            />
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

export default function OpsStatusPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-status"],
    queryFn: () => adminGet(apiKey, "/admin/v1/status"),
    refetchInterval: STATUS_REFETCH_INTERVAL_MS,
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Ops status</h1>
        <p className="text-sm text-muted-foreground">
          Live gateway status: running snapshot, enabled-vs-total counters, TLS
          renewal posture and cluster readiness.
        </p>
      </div>

      {error ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load status: {(error as Error).message}
        </p>
      ) : null}

      {isLoading || !data ? (
        <p className="text-sm text-muted-foreground">Loading status…</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">{data.service}</Badge>
            <Badge variant="secondary">v{data.version}</Badge>
            <Badge variant="outline">runtime {data.runtime}</Badge>
            <Badge variant="outline">snapshot {data.snapshot}</Badge>
            <BoolBadge
              value={data.auth_required}
              trueLabel="auth required"
              falseLabel="auth open"
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Providers"
              value={`${data.enabled_providers} / ${data.providers}`}
              hint="enabled / total"
            />
            <StatTile
              label="Models"
              value={`${data.enabled_models} / ${data.models}`}
              hint="enabled / total"
            />
            <StatTile
              label="Upstreams"
              value={`${data.enabled_upstreams} / ${data.upstreams}`}
              hint="enabled / total"
            />
            <StatTile
              label="Routes"
              value={`${data.enabled_routes} / ${data.routes}`}
              hint="enabled / total"
            />
            <StatTile label="API keys" value={data.api_keys} />
            <StatTile
              label="Plugins"
              value={`${data.active_plugins} / ${data.plugins}`}
              hint="active / total"
            />
            <StatTile
              label="Extensions"
              value={`${data.active_extensions} / ${data.extensions}`}
              hint="active / total"
            />
            <StatTile label="Tools" value={data.tools} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <AcmeCard acme={data.acme} />
            <ClusterCard cluster={data.cluster} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Storage backend</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="divide-y">
                  <DefinitionRow
                    label="Provider"
                    value={
                      <span className="flex items-center gap-2">
                        {data.storage.provider}
                        <HealthBadge health={data.storage.health} />
                      </span>
                    }
                  />
                  <DefinitionRow
                    label="Durable"
                    value={<BoolBadge value={data.storage.durable} />}
                  />
                  <DefinitionRow
                    label="Required"
                    value={<BoolBadge value={data.storage.required} />}
                  />
                  <DefinitionRow
                    label="Migration mode"
                    value={data.storage.migration_mode}
                  />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Analytics pipeline</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="divide-y">
                  <DefinitionRow
                    label="Provider"
                    value={
                      <span className="flex items-center gap-2">
                        {data.analytics.provider}
                        <HealthBadge health={data.analytics.health} />
                      </span>
                    }
                  />
                  <DefinitionRow label="Mode" value={data.analytics.mode} />
                  <DefinitionRow
                    label="Active"
                    value={<BoolBadge value={data.analytics.active} />}
                  />
                  <DefinitionRow
                    label="Last success"
                    value={formatUnix(data.analytics.last_success_at_unix)}
                  />
                  {data.analytics.last_export_error ? (
                    <DefinitionRow
                      label="Last error"
                      value={
                        <span className="text-destructive">
                          {data.analytics.last_export_error}
                        </span>
                      }
                    />
                  ) : null}
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
