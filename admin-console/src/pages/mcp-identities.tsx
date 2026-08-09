import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAuth } from "@/hooks/use-auth";
import { useFormatUnix } from "@/hooks/use-format-unix";
import { useOperatorError } from "@/hooks/use-operator-error";
import { useI18n } from "@/i18n";
import { type AdminSchema, adminDelete, adminGet, adminPost } from "@/lib/gateway-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
// MCP OAuth identities console (#202/#215, #323): per-server view of the
// subject-bound MCP identity over the runtime endpoints
//   GET    /v1/mcp/identity/{server}            → status (no token material)
//   POST   /v1/mcp/identity/{server}/authorize  → authorization URL + state
//   DELETE /v1/mcp/identity/{server}            → revoke locally
//
// These are RUNTIME (/v1/mcp/...) not /admin/v1/... paths, but they live in the
// same Admin API OpenAPI contract and the shared client routes them to the
// gateway data-plane origin with the same bearer auth — no separate client.
//
// OAuth redirect dance (out-of-band): "Connect" only INITIATES the flow and
// returns an authorization URL. The operator (or the bound subject) opens that
// URL and completes consent with the upstream provider, which redirects back to
// the gateway's GET /v1/mcp/identity/callback?code&state — a browser-to-gateway
// redirect the SPA cannot drive or observe. Once the gateway consumes the
// one-time state and persists the encrypted credential, "Refresh status" here
// reflects the now-connected identity. We surface the URL + state and explain
// the hand-off rather than pretending the SPA completes it.
import { useMemo, useState } from "react";
import { toast } from "sonner";

type AuthorizeResponse = AdminSchema<"McpOauthAuthorizeResponse">;

// Identity types that can complete an interactive OAuth authorization-code flow
// from this console; the rest surface status only (no Connect action).
const OAUTH_AUTH_TYPES = new Set(["oauth", "per_user_oauth"]);

function StatusField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="break-all text-sm">{children}</span>
    </div>
  );
}

export default function McpIdentitiesPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const formatUnix = useFormatUnix();
  const { toastError } = useOperatorError();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const queryClient = useQueryClient();

  const [serverInput, setServerInput] = useState("");
  const [server, setServer] = useState("");
  const [authorization, setAuthorization] = useState<AuthorizeResponse | null>(null);

  // Populate a picker from the configured MCP servers; manual entry still works.
  const { data: serversData } = useQuery({
    queryKey: ["mcp-servers"],
    queryFn: () => adminGet(apiKey, "/admin/v1/mcp-servers"),
  });
  const serverNames = useMemo(() => (serversData?.data ?? []).map((s) => s.name), [serversData]);

  const identityQueryKey = ["mcp-identity", server];
  const {
    data: status,
    isLoading,
    isFetching,
    error: statusError,
  } = useQuery({
    queryKey: identityQueryKey,
    queryFn: () => adminGet(apiKey, "/v1/mcp/identity/{server}", { params: { server } }),
    enabled: server !== "",
  });

  const authorizeMutation = useMutation({
    mutationFn: () =>
      adminPost(apiKey, "/v1/mcp/identity/{server}/authorize", undefined, {
        params: { server },
      }),
    onSuccess: (response) => {
      setAuthorization(response);
      toast.success(t("page.mcpIdentities.toast.authInitiated"));
    },
    onError: (err: Error) => toastError(err),
  });

  const revokeMutation = useMutation({
    mutationFn: () => adminDelete(apiKey, "/v1/mcp/identity/{server}", { params: { server } }),
    onSuccess: () => {
      toast.success(t("page.mcpIdentities.toast.disconnected", { server }));
      setAuthorization(null);
      queryClient.invalidateQueries({ queryKey: identityQueryKey });
    },
    onError: (err: Error) => toastError(err),
  });

  function loadServer(name: string) {
    const trimmed = name.trim();
    if (trimmed === "") return;
    setServer(trimmed);
    setAuthorization(null);
  }

  const canOauth = status ? OAUTH_AUTH_TYPES.has(status.auth_type) : false;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.mcpIdentities.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.mcpIdentities.description")}</p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            {t("page.mcpIdentities.select.title")}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          {serverNames.length > 0 ? (
            <div className="grid gap-1.5">
              <Label>{t("page.mcpIdentities.field.configuredServers")}</Label>
              <Select value={server || undefined} onValueChange={loadServer}>
                <SelectTrigger
                  className="w-56"
                  aria-label={t("page.mcpIdentities.field.configuredServers")}
                >
                  <SelectValue placeholder={t("page.mcpIdentities.field.pickServer")} />
                </SelectTrigger>
                <SelectContent>
                  {serverNames.map((name) => (
                    <SelectItem key={name} value={name}>
                      {name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : null}
          <div className="grid gap-1.5">
            <Label htmlFor="server-input">{t("page.mcpIdentities.field.serverName")}</Label>
            <Input
              id="server-input"
              value={serverInput}
              onChange={(e) => setServerInput(e.target.value)}
              // eslint-disable-next-line ferrogate/no-untranslated-literal -- example server name, not translatable copy
              placeholder="github-mcp"
              className="w-56"
            />
          </div>
          <Button type="button" variant="outline" onClick={() => loadServer(serverInput)}>
            {t("page.mcpIdentities.loadStatus")}
          </Button>
        </CardContent>
      </Card>

      {statusError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.mcpIdentities.loadError", { server, message: statusError.message })}
        </p>
      ) : null}

      {server === "" ? (
        <p className="text-sm text-muted-foreground">{t("page.mcpIdentities.prompt")}</p>
      ) : isLoading ? (
        <p className="text-sm text-muted-foreground">{t("page.mcpIdentities.loading")}</p>
      ) : status ? (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-3">
            <CardTitle className="text-sm font-medium">{status.server_name}</CardTitle>
            <div className="flex items-center gap-2">
              <Badge
                variant={status.connected ? "default" : "secondary"}
                data-testid="identity-connection"
              >
                {status.connected
                  ? t("page.mcpIdentities.connected")
                  : t("page.mcpIdentities.disconnected")}
              </Badge>
              <Badge variant="outline">{status.auth_type}</Badge>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <StatusField label={t("page.mcpIdentities.field.credentialSource")}>
                {status.credential_source}
              </StatusField>
              <StatusField label={t("page.mcpIdentities.field.subject")}>
                {status.subject ?? "-"}
              </StatusField>
              <StatusField label={t("page.mcpIdentities.field.expiresAt")}>
                {formatUnix(status.expires_at_unix)}
              </StatusField>
              <StatusField label={t("page.mcpIdentities.field.revokedAt")}>
                {formatUnix(status.revoked_at_unix)}
              </StatusField>
              <StatusField label={t("page.mcpIdentities.field.lastRefreshOutcome")}>
                {status.last_refresh_outcome ?? "-"}
              </StatusField>
              <StatusField label={t("page.mcpIdentities.field.lastRevocationOutcome")}>
                {status.last_revocation_outcome ?? "-"}
              </StatusField>
            </div>

            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => queryClient.invalidateQueries({ queryKey: identityQueryKey })}
                disabled={isFetching}
              >
                {isFetching
                  ? t("page.mcpIdentities.refreshing")
                  : t("page.mcpIdentities.refreshStatus")}
              </Button>
              {canOauth ? (
                <Button
                  type="button"
                  onClick={() => authorizeMutation.mutate()}
                  disabled={authorizeMutation.isPending}
                >
                  {authorizeMutation.isPending
                    ? t("page.mcpIdentities.initiating")
                    : status.connected
                      ? t("page.mcpIdentities.reconnect")
                      : t("page.mcpIdentities.connect")}
                </Button>
              ) : (
                <span className="self-center text-xs text-muted-foreground">
                  {t("page.mcpIdentities.notInteractive", { authType: status.auth_type })}
                </span>
              )}
              {status.connected ? (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => revokeMutation.mutate()}
                  disabled={revokeMutation.isPending}
                >
                  {revokeMutation.isPending
                    ? t("page.mcpIdentities.disconnecting")
                    : t("page.mcpIdentities.disconnect")}
                </Button>
              ) : null}
            </div>

            {authorization ? (
              <div
                className="grid gap-2 rounded-md border border-primary/40 bg-primary/5 px-3 py-3"
                data-testid="authorization-panel"
              >
                <p className="text-sm font-medium">{t("page.mcpIdentities.authPanel.title")}</p>
                <p className="text-xs text-muted-foreground">
                  {t("page.mcpIdentities.authPanel.description", {
                    expires: formatUnix(authorization.expires_at_unix),
                  })}
                </p>
                <a
                  href={authorization.authorize_url}
                  target="_blank"
                  rel="noreferrer"
                  className="break-all text-sm text-primary underline"
                >
                  {authorization.authorize_url}
                </a>
                <code className="break-all rounded bg-muted px-2 py-1 font-mono text-xs">
                  state: {authorization.state}
                </code>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
