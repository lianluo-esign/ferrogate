import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { gatewayGet } from "@/lib/gateway-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

interface ResolvedDefaults {
  tenant_id: string;
  plan_id: string;
  model_allowlist: string[] | null;
  rpm_limit: number | null;
  tpm_limit: number | null;
  monthly_budget_usd: number | null;
  mcp_enabled: boolean;
  extension_tools_enabled: boolean;
  self_hosted_workers_enabled: boolean;
  asset_hosting_enabled: boolean;
  default_asset_storage_quota_bytes: number | null;
}

export default function TenantResolvedDefaultsPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const [tenantIdInput, setTenantIdInput] = useState("");
  const [lookupTenantId, setLookupTenantId] = useState<string | null>(null);

  // Numeric limits and boolean feature flags render page-locally; a null limit
  // shows the localized "unlimited" copy and flags reuse the shared #385
  // enabled/disabled state keys.
  const formatLimit = (value: number | null): string =>
    value === null ? t("page.resolvedDefaults.value.unlimited") : format.number(value);
  const formatFlag = (value: boolean): string =>
    value ? t("common.enabled") : t("common.disabled");

  const { data, isFetching, error } = useQuery({
    queryKey: ["tenant-resolved-defaults", lookupTenantId],
    queryFn: () =>
      gatewayGet<ResolvedDefaults>(
        apiKey,
        `/admin/v1/tenant-accounts/${encodeURIComponent(lookupTenantId ?? "")}/resolved-defaults`,
      ),
    enabled: Boolean(lookupTenantId),
  });

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.resolvedDefaults.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.resolvedDefaults.description")}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.resolvedDefaults.lookup.title")}</CardTitle>
          <CardDescription>{t("page.resolvedDefaults.lookup.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              setLookupTenantId(tenantIdInput.trim() || null);
            }}
          >
            {/* #340 box 7: this lookup used to be a free-text tenant id
                (`placeholder="tenant-abc123"`), the last entity-backed field in
                the tenancy module still asking an operator to paste an id. It
                now uses the same shared #337 tenant-accounts picker as
                tenant-roles/payment-methods; the canonical `id` still drives
                `/admin/v1/tenant-accounts/{id}/resolved-defaults`. No
                `disabledWhen` here on purpose: box 5 forbids *newly selecting* a
                disabled target in a create/edit form, and inspecting a suspended
                tenant's effective entitlements is exactly what an operator needs
                during an incident -- marking it here would only lock the lookup. */}
            <div className="grid flex-1 gap-2">
              <Label htmlFor="tenant-id">{t("page.resolvedDefaults.field.tenantId")}</Label>
              <EntityReferencePicker
                id="tenant-id"
                label={t("page.resolvedDefaults.field.tenantId")}
                reference={{
                  target: "tenant-accounts",
                  valueKey: "id",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["slug", "status", "plan_id"],
                }}
                value={tenantIdInput}
                dependencyValues={{}}
                onChange={(value) => setTenantIdInput(typeof value === "string" ? value : "")}
              />
            </div>
            <Button type="submit" disabled={!tenantIdInput.trim()}>
              {t("page.resolvedDefaults.lookup.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>

      {isFetching && <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>}

      {error && (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {error.message}
        </p>
      )}

      {data && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{data.tenant_id}</CardTitle>
            <CardDescription>
              {t("page.resolvedDefaults.plan", { plan: data.plan_id })}
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div>
              <h3 className="mb-2 text-sm font-medium">
                {t("page.resolvedDefaults.section.features")}
              </h3>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.feature.mcp")}
                  </dt>
                  <dd>{formatFlag(data.mcp_enabled)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.feature.extension")}
                  </dt>
                  <dd>{formatFlag(data.extension_tools_enabled)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.feature.selfHostedWorkers")}
                  </dt>
                  <dd>{formatFlag(data.self_hosted_workers_enabled)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.feature.assetHosting")}
                  </dt>
                  <dd>{formatFlag(data.asset_hosting_enabled)}</dd>
                </div>
              </dl>
            </div>
            <div>
              <h3 className="mb-2 text-sm font-medium">
                {t("page.resolvedDefaults.section.quota")}
              </h3>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">{t("page.resolvedDefaults.quota.rpm")}</dt>
                  <dd>{formatLimit(data.rpm_limit)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">{t("page.resolvedDefaults.quota.tpm")}</dt>
                  <dd>{formatLimit(data.tpm_limit)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.quota.monthlyBudget")}
                  </dt>
                  <dd>
                    {data.monthly_budget_usd === null
                      ? t("page.resolvedDefaults.value.unlimited")
                      : format.currency(data.monthly_budget_usd, "USD")}
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.quota.assetStorage")}
                  </dt>
                  <dd>{formatLimit(data.default_asset_storage_quota_bytes)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">
                    {t("page.resolvedDefaults.quota.modelAllowlist")}
                  </dt>
                  <dd>
                    {data.model_allowlist && data.model_allowlist.length > 0
                      ? data.model_allowlist.join(", ")
                      : t("page.resolvedDefaults.value.allModels")}
                  </dd>
                </div>
              </dl>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
