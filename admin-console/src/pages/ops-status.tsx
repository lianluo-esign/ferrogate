import { BoolBadge, DefinitionRow, HealthBadge, StatTile } from "@/components/ops/ops-primitives";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/hooks/use-auth";
import { useFormatUnix } from "@/hooks/use-format-unix";
import { useI18n } from "@/i18n";
import { type AdminSchema, adminGet } from "@/lib/gateway-client";
// Operations status dashboard (issue #322): the landing ops view over
// GET /admin/v1/status (AdminStatus). Surfaces the running snapshot, the
// enabled-vs-total counters, the ACME renewal + reload_required posture (#265),
// the cluster readiness/drain state and storage/analytics backend evidence in
// one scannable board.
import { useQuery } from "@tanstack/react-query";

type AdminStatus = AdminSchema<"AdminStatus">;
type AdminAcmeStatus = AdminSchema<"AdminAcmeStatus">;

const STATUS_REFETCH_INTERVAL_MS = 10_000;

function AcmeCard({ acme }: { acme: AdminAcmeStatus | null | undefined }) {
  const { t } = useI18n();
  const formatUnix = useFormatUnix();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          {t("page.opsStatus.acme.title")}
          {acme?.reload_required ? (
            <Badge variant="destructive">{t("page.opsStatus.acme.reloadRequired")}</Badge>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!acme || !acme.enabled ? (
          <p className="text-sm text-muted-foreground">{t("page.opsStatus.acme.disabled")}</p>
        ) : (
          <div className="divide-y">
            <DefinitionRow
              label={t("page.opsStatus.acme.domains")}
              value={acme.domains.join(", ") || "-"}
            />
            <DefinitionRow
              label={t("page.opsStatus.acme.renewalDue")}
              value={
                <BoolBadge
                  value={acme.renewal_due}
                  trueLabel={t("page.opsStatus.acme.renewalDue.due")}
                  falseLabel={t("page.opsStatus.acme.renewalDue.notDue")}
                  good="false"
                />
              }
            />
            <DefinitionRow
              label={t("page.opsStatus.acme.reloadRow")}
              value={
                <BoolBadge
                  value={acme.reload_required}
                  trueLabel={t("page.opsStatus.acme.reload.required", {
                    mode: acme.reload_mode,
                  })}
                  falseLabel={t("page.opsStatus.acme.reload.upToDate")}
                  good="false"
                />
              }
            />
            <DefinitionRow
              label={t("page.opsStatus.acme.lastRenewal")}
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
              label={t("page.opsStatus.acme.certExpires")}
              value={formatUnix(acme.certificate_expires_at_unix)}
            />
            <DefinitionRow
              label={t("page.opsStatus.acme.nextCheck")}
              value={formatUnix(acme.next_check_at_unix)}
            />
            {acme.last_renewal_error ? (
              <DefinitionRow
                label={t("page.opsStatus.field.lastError")}
                value={<span className="text-destructive">{acme.last_renewal_error}</span>}
              />
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ClusterCard({ cluster }: { cluster: AdminStatus["cluster"] }) {
  const { t, format } = useI18n();
  const formatUnix = useFormatUnix();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("page.opsStatus.cluster.title")}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="divide-y">
          <DefinitionRow
            label={t("page.opsStatus.cluster.enabled")}
            value={
              <BoolBadge
                value={cluster.enabled}
                trueLabel={t("common.yes")}
                falseLabel={t("common.no")}
              />
            }
          />
          <DefinitionRow
            label={t("page.opsStatus.cluster.ready")}
            value={
              <span className="flex items-center gap-2">
                <BoolBadge
                  value={cluster.ready}
                  trueLabel={t("common.yes")}
                  falseLabel={t("common.no")}
                />
                <span className="text-xs text-muted-foreground">{cluster.readiness_reason}</span>
              </span>
            }
          />
          <DefinitionRow
            label={t("page.opsStatus.cluster.draining")}
            value={
              <BoolBadge
                value={cluster.draining}
                trueLabel={t("page.opsStatus.cluster.draining.draining")}
                falseLabel={t("page.opsStatus.cluster.draining.serving")}
                good="false"
              />
            }
          />
          <DefinitionRow
            label={t("page.opsStatus.cluster.accepting")}
            value={
              <BoolBadge
                value={cluster.accepting_new_requests}
                trueLabel={t("common.yes")}
                falseLabel={t("common.no")}
              />
            }
          />
          <DefinitionRow label={t("page.opsStatus.cluster.node")} value={cluster.node_id || "-"} />
          <DefinitionRow
            label={t("page.opsStatus.cluster.clusterId")}
            value={cluster.cluster_id || "-"}
          />
          <DefinitionRow
            label={t("page.opsStatus.cluster.activeRevision")}
            value={cluster.active_revision || "-"}
          />
          <DefinitionRow
            label={t("page.opsStatus.cluster.backends")}
            value={`${cluster.state_backend} / ${cluster.counter_backend}`}
          />
          <DefinitionRow
            label={t("page.opsStatus.cluster.lastSync")}
            value={
              <span className="flex items-center gap-2">
                {formatUnix(cluster.last_sync_at_unix)}
                {cluster.last_sync_at_unix ? (
                  // How long ago, in the operator's language ("3 minutes ago" /
                  // "3分钟前"). The absolute timestamp stays; this answers the
                  // staleness question the `stale` badge raises without making
                  // the operator subtract two clocks.
                  <span className="text-xs text-muted-foreground">
                    {format.relativeTime(cluster.last_sync_at_unix * 1000)}
                  </span>
                ) : null}
                {cluster.stale ? (
                  <Badge variant="destructive">{t("page.opsStatus.cluster.stale")}</Badge>
                ) : null}
              </span>
            }
          />
          {cluster.last_sync_error ? (
            <DefinitionRow
              label={t("page.opsStatus.cluster.syncError")}
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
  const { t } = useI18n();
  const formatUnix = useFormatUnix();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;

  const { data, isLoading, error } = useQuery({
    queryKey: ["ops-status"],
    queryFn: () => adminGet(apiKey, "/admin/v1/status"),
    refetchInterval: STATUS_REFETCH_INTERVAL_MS,
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.opsStatus.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.opsStatus.description")}</p>
      </div>

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.opsStatus.loadError", { message: (error as Error).message })}
        </p>
      ) : null}

      {isLoading || !data ? (
        <p className="text-sm text-muted-foreground">{t("page.opsStatus.loading")}</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">{data.service}</Badge>
            <Badge variant="secondary">v{data.version}</Badge>
            <Badge variant="outline">
              {t("page.opsStatus.badge.runtime", { value: data.runtime })}
            </Badge>
            <Badge variant="outline">
              {t("page.opsStatus.badge.snapshot", { value: data.snapshot })}
            </Badge>
            <BoolBadge
              value={data.auth_required}
              trueLabel={t("page.opsStatus.auth.required")}
              falseLabel={t("page.opsStatus.auth.open")}
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label={t("page.opsStatus.stat.providers")}
              value={`${data.enabled_providers} / ${data.providers}`}
              hint={t("page.opsStatus.hint.enabledTotal")}
            />
            <StatTile
              label={t("page.opsStatus.stat.models")}
              value={`${data.enabled_models} / ${data.models}`}
              hint={t("page.opsStatus.hint.enabledTotal")}
            />
            <StatTile
              label={t("page.opsStatus.stat.upstreams")}
              value={`${data.enabled_upstreams} / ${data.upstreams}`}
              hint={t("page.opsStatus.hint.enabledTotal")}
            />
            <StatTile
              label={t("page.opsStatus.stat.routes")}
              value={`${data.enabled_routes} / ${data.routes}`}
              hint={t("page.opsStatus.hint.enabledTotal")}
            />
            <StatTile label={t("page.opsStatus.stat.apiKeys")} value={data.api_keys} />
            <StatTile
              label={t("page.opsStatus.stat.plugins")}
              value={`${data.active_plugins} / ${data.plugins}`}
              hint={t("page.opsStatus.hint.activeTotal")}
            />
            <StatTile
              label={t("page.opsStatus.stat.extensions")}
              value={`${data.active_extensions} / ${data.extensions}`}
              hint={t("page.opsStatus.hint.activeTotal")}
            />
            <StatTile label={t("page.opsStatus.stat.tools")} value={data.tools} />
          </div>

          {/* Platform model catalog (#893): the FLEET catalog #889 introduced,
              counted distinctly from the tenant aggregates above — a platform
              channel is not a tenant provider. GET /admin/v1/status reports
              these unscoped, so this read-only view is visible to any admin
              without a platform-operator session (which the console cannot yet
              mint). Rendered only when the deployment reports them, so a gateway
              predating #902 shows no empty tiles. */}
          {data.platform_providers !== undefined ||
          data.platform_models !== undefined ||
          data.platform_offerings !== undefined ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t("page.opsStatus.platform.title")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  <StatTile
                    label={t("page.opsStatus.stat.platformProviders")}
                    value={data.platform_providers ?? 0}
                    hint={t("page.opsStatus.hint.platformCatalog")}
                  />
                  <StatTile
                    label={t("page.opsStatus.stat.platformModels")}
                    value={data.platform_models ?? 0}
                    hint={t("page.opsStatus.hint.platformCatalog")}
                  />
                  <StatTile
                    label={t("page.opsStatus.stat.platformOfferings")}
                    value={data.platform_offerings ?? 0}
                    hint={t("page.opsStatus.hint.platformCatalog")}
                  />
                </div>
              </CardContent>
            </Card>
          ) : null}

          <div className="grid gap-4 lg:grid-cols-2">
            <AcmeCard acme={data.acme} />
            <ClusterCard cluster={data.cluster} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t("page.opsStatus.storage.title")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="divide-y">
                  <DefinitionRow
                    label={t("page.opsStatus.field.provider")}
                    value={
                      <span className="flex items-center gap-2">
                        {data.storage.provider}
                        <HealthBadge health={data.storage.health} />
                      </span>
                    }
                  />
                  <DefinitionRow
                    label={t("page.opsStatus.storage.durable")}
                    value={
                      <BoolBadge
                        value={data.storage.durable}
                        trueLabel={t("common.yes")}
                        falseLabel={t("common.no")}
                      />
                    }
                  />
                  <DefinitionRow
                    label={t("page.opsStatus.storage.required")}
                    value={
                      <BoolBadge
                        value={data.storage.required}
                        trueLabel={t("common.yes")}
                        falseLabel={t("common.no")}
                      />
                    }
                  />
                  <DefinitionRow
                    label={t("page.opsStatus.storage.migrationMode")}
                    value={data.storage.migration_mode}
                  />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t("page.opsStatus.analytics.title")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="divide-y">
                  <DefinitionRow
                    label={t("page.opsStatus.field.provider")}
                    value={
                      <span className="flex items-center gap-2">
                        {data.analytics.provider}
                        <HealthBadge health={data.analytics.health} />
                      </span>
                    }
                  />
                  <DefinitionRow
                    label={t("page.opsStatus.analytics.mode")}
                    value={data.analytics.mode}
                  />
                  <DefinitionRow
                    label={t("page.opsStatus.analytics.active")}
                    value={
                      <BoolBadge
                        value={data.analytics.active}
                        trueLabel={t("common.yes")}
                        falseLabel={t("common.no")}
                      />
                    }
                  />
                  <DefinitionRow
                    label={t("page.opsStatus.analytics.lastSuccess")}
                    value={formatUnix(data.analytics.last_success_at_unix)}
                  />
                  {data.analytics.last_export_error ? (
                    <DefinitionRow
                      label={t("page.opsStatus.field.lastError")}
                      value={
                        <span className="text-destructive">{data.analytics.last_export_error}</span>
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
