// Site domains bind/unbind console (#265, #323): the admin surface over
// /admin/v1/site-domains (+ /{hostname}). Lists custom hostnames bound to
// hosted static sites and lets an operator bind a new hostname or unbind an
// existing one. Both bind and unbind are audited server-side.
//
// The bind form validates the hostname client-side with the same rules the
// gateway enforces (src/lib/hostname.ts mirrors validate_site_domain_hostname):
// FQDN with >=2 DNS labels, no wildcard, no IP literal, no port. The backend
// stays authoritative — this is fast feedback, not the gate. TLS for a freshly
// bound hostname rides the existing ACME issuance + graceful-upgrade reload;
// the bind response reports that ACME posture.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { adminDelete, adminGet, adminPost, type AdminSchema } from "@/lib/gateway-client";
import { validateSiteDomainHostname } from "@/lib/hostname";

type SiteDomain = AdminSchema<"AdminSiteDomain">;

function formatUnix(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "-";
  return new Date(unix * 1000).toLocaleString();
}

export default function SiteDomainsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["site-domains"];

  const [hostname, setHostname] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [site, setSite] = useState("");
  const [bindError, setBindError] = useState<string | null>(null);
  const [pendingUnbind, setPendingUnbind] = useState<SiteDomain | null>(null);

  const { data, isLoading, error: listError } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/site-domains"),
  });

  const domains = useMemo(() => data?.data ?? [], [data]);

  // Live client-side validation feedback (empty input shows no error yet).
  const hostnameCheck = hostname.trim() === "" ? null : validateSiteDomainHostname(hostname);
  const hostnameInvalid = hostnameCheck !== null && hostnameCheck.error !== null;

  const bindMutation = useMutation({
    mutationFn: (body: AdminSchema<"AdminSiteDomainMutation">) =>
      adminPost(apiKey, "/admin/v1/site-domains", body),
    onSuccess: (response) => {
      const bound = response.site_domain.hostname;
      const acme = response.acme;
      const acmeNote = acme.enabled
        ? acme.reload_triggered
          ? t("page.siteDomains.acme.reloadTriggered")
          : t("page.siteDomains.acme.enabledNoReload")
        : t("page.siteDomains.acme.disabled");
      toast.success(t("page.siteDomains.toast.bound", { hostname: bound, note: acmeNote }));
      setHostname("");
      setTenantId("");
      setSite("");
      setBindError(null);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => {
      setBindError(err.message);
      toast.error(err.message);
    },
  });

  const unbindMutation = useMutation({
    mutationFn: (target: SiteDomain) =>
      adminDelete(apiKey, "/admin/v1/site-domains/{hostname}", {
        params: { hostname: target.hostname },
      }),
    onSuccess: (_res, target) => {
      toast.success(t("page.siteDomains.toast.unbound", { hostname: target.hostname }));
      setPendingUnbind(null);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => {
      toast.error(err.message);
      setPendingUnbind(null);
    },
  });

  function submitBind() {
    setBindError(null);
    const check = validateSiteDomainHostname(hostname);
    if (check.error !== null) {
      setBindError(check.error);
      return;
    }
    if (tenantId.trim() === "") {
      setBindError(t("page.siteDomains.validation.tenantRequired"));
      return;
    }
    if (site.trim() === "") {
      setBindError(t("page.siteDomains.validation.siteRequired"));
      return;
    }
    bindMutation.mutate({
      hostname: check.hostname,
      tenant_id: tenantId.trim(),
      site: site.trim(),
    });
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.siteDomains.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.siteDomains.description")}
        </p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            {t("page.siteDomains.bind.title")}
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-3">
          <div className="grid gap-1.5">
            <Label htmlFor="bind-hostname">{t("page.siteDomains.field.hostname")}</Label>
            <Input
              id="bind-hostname"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              // eslint-disable-next-line ferrogate/no-untranslated-literal -- example FQDN, identical across locales
              placeholder="app.example.com"
              aria-invalid={hostnameInvalid}
            />
            {hostnameCheck?.error ? (
              <p className="text-xs text-destructive" role="alert">
                {hostnameCheck.error}
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                {t("page.siteDomains.field.hostname.hint")}
              </p>
            )}
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="bind-tenant">{t("page.siteDomains.field.tenant")}</Label>
            {/* #342: bind a hostname to a known tenant account via the shared
                entity picker; the underlying tenant_id (canonical `id`) is
                submitted unchanged. */}
            <EntityReferencePicker
              id="bind-tenant"
              label={t("page.siteDomains.field.tenant")}
              reference={{
                target: "tenant-accounts",
                valueKey: "id",
                primaryLabelKey: "name",
                secondaryLabelKeys: ["slug"],
              }}
              value={tenantId}
              dependencyValues={{}}
              placeholder={t("page.siteDomains.field.tenant.select")}
              onChange={(value) => setTenantId(typeof value === "string" ? value : "")}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="bind-site">{t("page.siteDomains.field.site")}</Label>
            {/* `site` names a published static-site slug within the tenant's
                hosting bundle, not an entity row the admin API lists/gets, so it
                stays free-text (no list/get endpoint exists to back a picker). */}
            <Input
              id="bind-site"
              value={site}
              onChange={(e) => setSite(e.target.value)}
              // eslint-disable-next-line ferrogate/no-untranslated-literal -- example site slug, identical across locales
              placeholder="marketing"
            />
          </div>
          {bindError ? (
            <p className="sm:col-span-3 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {bindError}
            </p>
          ) : null}
          <div className="sm:col-span-3">
            <Button
              type="button"
              onClick={submitBind}
              disabled={bindMutation.isPending || hostnameInvalid}
            >
              {bindMutation.isPending
                ? t("page.siteDomains.bind.submitting")
                : t("page.siteDomains.bind.submit")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {listError ? (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.siteDomains.loadError", { message: listError.message })}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.siteDomains.col.hostname")}</TableHead>
              <TableHead>{t("page.siteDomains.field.tenant")}</TableHead>
              <TableHead>{t("page.siteDomains.field.site")}</TableHead>
              <TableHead>{t("page.siteDomains.col.servePath")}</TableHead>
              <TableHead>{t("page.siteDomains.col.bound")}</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : domains.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  {t("page.siteDomains.empty")}
                </TableCell>
              </TableRow>
            ) : (
              domains.map((domain) => (
                <TableRow key={domain.hostname} data-testid={`site-domain-${domain.hostname}`}>
                  <TableCell className="font-medium">{domain.hostname}</TableCell>
                  <TableCell className="text-xs">{domain.tenant_id}</TableCell>
                  <TableCell className="text-xs">
                    <Badge variant="secondary">{domain.site}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{domain.serve_path}</TableCell>
                  <TableCell className="text-xs">{formatUnix(domain.created_at_unix)}</TableCell>
                  <TableCell>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => setPendingUnbind(domain)}
                    >
                      {t("page.siteDomains.unbind")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <AlertDialog
        open={pendingUnbind !== null}
        onOpenChange={(open) => !open && setPendingUnbind(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("page.siteDomains.unbind.title", { hostname: pendingUnbind?.hostname ?? "" })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.siteDomains.unbind.description", {
                target: `${pendingUnbind?.tenant_id ?? ""}/${pendingUnbind?.site ?? ""}`,
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                if (pendingUnbind) unbindMutation.mutate(pendingUnbind);
              }}
            >
              {t("page.siteDomains.unbind")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
