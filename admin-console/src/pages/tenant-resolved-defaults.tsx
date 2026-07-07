import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import { gatewayGet } from "@/lib/gateway-client";

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

function formatLimit(value: number | null): string {
  return value === null ? "Unlimited" : value.toLocaleString();
}

function formatFlag(value: boolean): string {
  return value ? "Enabled" : "Disabled";
}

export default function TenantResolvedDefaultsPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const [tenantIdInput, setTenantIdInput] = useState("");
  const [lookupTenantId, setLookupTenantId] = useState<string | null>(null);

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
        <h1 className="text-lg font-semibold">Resolved tenant defaults</h1>
        <p className="text-sm text-muted-foreground">
          The merged, effective quota and feature entitlements a tenant's plan actually grants --
          resolved the same way the auth path resolves them at request time, not just the raw
          plan_id pointer. See the Plans page to change a plan's defaults, and Tenant accounts to
          reassign which plan a tenant is on.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Look up a tenant</CardTitle>
          <CardDescription>Enter a tenant account ID (not slug or name).</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              setLookupTenantId(tenantIdInput.trim() || null);
            }}
          >
            <div className="flex-1">
              <Label htmlFor="tenant-id">Tenant ID</Label>
              <Input
                id="tenant-id"
                value={tenantIdInput}
                onChange={(event) => setTenantIdInput(event.target.value)}
                placeholder="tenant-abc123"
              />
            </div>
            <Button type="submit" disabled={!tenantIdInput.trim()}>
              Look up
            </Button>
          </form>
        </CardContent>
      </Card>

      {isFetching && <p className="text-sm text-muted-foreground">Loading...</p>}

      {error && (
        <p className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error.message}
        </p>
      )}

      {data && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{data.tenant_id}</CardTitle>
            <CardDescription>Plan: {data.plan_id}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div>
              <h3 className="mb-2 text-sm font-medium">Feature entitlements</h3>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">MCP tool execution</dt>
                  <dd>{formatFlag(data.mcp_enabled)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Extension tool execution</dt>
                  <dd>{formatFlag(data.extension_tools_enabled)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Self-hosted workers</dt>
                  <dd>{formatFlag(data.self_hosted_workers_enabled)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Asset hosting</dt>
                  <dd>{formatFlag(data.asset_hosting_enabled)}</dd>
                </div>
              </dl>
            </div>
            <div>
              <h3 className="mb-2 text-sm font-medium">Resolved quota</h3>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">RPM limit</dt>
                  <dd>{formatLimit(data.rpm_limit)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">TPM limit</dt>
                  <dd>{formatLimit(data.tpm_limit)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Monthly budget (USD)</dt>
                  <dd>
                    {data.monthly_budget_usd === null
                      ? "Unlimited"
                      : `$${data.monthly_budget_usd.toLocaleString()}`}
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Asset storage quota (bytes)</dt>
                  <dd>{formatLimit(data.default_asset_storage_quota_bytes)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-muted-foreground">Model allowlist</dt>
                  <dd>
                    {data.model_allowlist && data.model_allowlist.length > 0
                      ? data.model_allowlist.join(", ")
                      : "All models"}
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
