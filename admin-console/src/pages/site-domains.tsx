import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import {
  SiteDomainChallenge,
  SiteDomainLiveness,
  bindAcmeNoteKey,
} from "@/components/site-domain-liveness";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { useFormatUnix } from "@/hooks/use-format-unix";
import { useOperatorError } from "@/hooks/use-operator-error";
import { useI18n } from "@/i18n";
import { type AdminSchema, adminDelete, adminGet, adminPost } from "@/lib/gateway-client";
import { validateSiteDomainHostname } from "@/lib/hostname";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
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
//
// A bind RECORDS a binding; it does not make the hostname live. Post-#488 the
// gateway serves a bound hostname only while its DNS-TXT ownership proof
// resolves, and it reports that verdict on every listed binding (`serving` +
// `verification_state`). Those are rendered per row — see
// components/site-domain-liveness.tsx — because a bound timestamp on its own
// makes a hostname whose requests are REFUSED look identical to a live one.
import { useMemo, useRef, useState } from "react";
import { toast } from "sonner";

type SiteDomain = AdminSchema<"AdminSiteDomain">;

export default function SiteDomainsPage() {
  const { session } = useAuth();
  const { t } = useI18n();
  const formatUnix = useFormatUnix();
  const { toastError } = useOperatorError();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const queryClient = useQueryClient();
  const queryKey = ["site-domains"];

  const [hostname, setHostname] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [site, setSite] = useState("");
  const [bindError, setBindError] = useState<string | null>(null);
  const [pendingUnbind, setPendingUnbind] = useState<SiteDomain | null>(null);
  // The unbind confirm is ONE controlled AlertDialog shared by every row, so
  // Radix has no `AlertDialogTrigger` to restore focus to on close. Remember
  // the row button that opened it and hand focus back ourselves — otherwise a
  // keyboard operator dismissing the dialog is dropped onto <body>.
  const unbindTriggerRef = useRef<HTMLElement | null>(null);

  const {
    data,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/site-domains"),
  });

  const domains = useMemo(() => data?.data ?? [], [data]);

  // A binding is RECORDED on bind but only SERVES once its #488 DNS ownership
  // proof resolves, and the listing already carries that verdict per row
  // (`serving` + `verification_state`, bulk-joined server-side — no N+1). The
  // one thing the listing cannot carry is the challenge TXT record itself, so
  // exactly the pending rows get a detail read to fetch it; nothing else does.
  const pendingHostnames = useMemo(
    () =>
      domains
        .filter((domain) => domain.verification_state === "pending_verification")
        .map((domain) => domain.hostname),
    [domains],
  );
  const challengeQueries = useQueries({
    queries: pendingHostnames.map((hostname) => ({
      queryKey: ["site-domain-detail", hostname] as const,
      queryFn: () =>
        adminGet(apiKey, "/admin/v1/site-domains/{hostname}", {
          params: { hostname },
        }),
    })),
  });
  const challenges = challengeQueries.flatMap((query) => {
    const verification = query.data?.verification;
    return verification && verification.state === "pending_verification" ? [verification] : [];
  });

  // The session tenant's PUBLISHED static-site slugs, from the same `/v1/assets`
  // enumeration the Static sites page derives its list from. Only read while the
  // bind form targets the session tenant (see the field comment below).
  const sessionTenantId = (session as NonNullable<typeof session>).tenant.id;
  const bindsSessionTenant = tenantId.trim() === sessionTenantId;
  const { data: assetData } = useQuery({
    queryKey: ["assets"],
    enabled: bindsSessionTenant,
    queryFn: () => adminGet(apiKey, "/v1/assets"),
  });
  const publishedSites = useMemo(() => {
    if (!bindsSessionTenant) return [];
    const names = new Set<string>();
    for (const row of assetData?.data ?? []) {
      // The reserved marker/per-file rows share the site's `name`, so the
      // distinct names are exactly the published site slugs.
      if (row.asset_type === "static_site") names.add(row.name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [assetData, bindsSessionTenant]);

  // Live client-side validation feedback (empty input shows no error yet).
  const hostnameCheck = hostname.trim() === "" ? null : validateSiteDomainHostname(hostname);
  const hostnameInvalid = hostnameCheck !== null && hostnameCheck.error !== null;

  const bindMutation = useMutation({
    mutationFn: (body: AdminSchema<"AdminSiteDomainMutation">) =>
      adminPost(apiKey, "/admin/v1/site-domains", body),
    onSuccess: (response) => {
      const bound = response.site_domain.hostname;
      // The ACME claim is qualified by whether THIS hostname was enrolled, not
      // by the gateway-wide flag: an unproven binding (the gateway's 202) is
      // deliberately kept out of the order set. See bindAcmeNoteKey.
      const acmeNote = t(bindAcmeNoteKey(response));
      toast.success(t("page.siteDomains.toast.bound", { hostname: bound, note: acmeNote }));
      setHostname("");
      setTenantId("");
      setSite("");
      setBindError(null);
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => {
      setBindError(err.message);
      toastError(err);
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
      toastError(err);
      setPendingUnbind(null);
    },
  });

  function submitBind() {
    setBindError(null);
    const check = validateSiteDomainHostname(hostname);
    if (check.error !== null) {
      setBindError(t(check.error.key, check.error.values));
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
        <p className="text-sm text-muted-foreground">{t("page.siteDomains.description")}</p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">{t("page.siteDomains.bind.title")}</CardTitle>
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
                {t(hostnameCheck.error.key, hostnameCheck.error.values)}
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
            {/* `site` names a PUBLISHED static-site slug; a bind against a slug
                that is not published is 404'd server-side. The slugs are
                enumerable — they are the distinct `name`s of the tenant's
                `static_site` asset rows — so the input is backed by that
                enumeration instead of being blind free text.
                The suggestions are offered ONLY while the selected tenant is
                the session tenant: `GET /v1/assets` is scoped to the caller's
                own tenant, so listing them under a different selected tenant
                would assert an inventory we have not read. A platform-operator
                key binding for another tenant still types the slug. */}
            <Input
              id="bind-site"
              list="bind-site-options"
              value={site}
              onChange={(e) => setSite(e.target.value)}
              // eslint-disable-next-line ferrogate/no-untranslated-literal -- example site slug, identical across locales
              placeholder="marketing"
            />
            <datalist id="bind-site-options">
              {publishedSites.map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
            <p className="text-xs text-muted-foreground">{t("page.siteDomains.field.site.hint")}</p>
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
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
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
              <TableHead>{t("page.siteDomains.col.status")}</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : domains.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
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
                  {/* Is this hostname live? A bound timestamp does not answer
                      that: the gateway refuses requests on a hostname whose
                      ownership proof is missing, pending or expired. Rendered
                      from the fields the listing itself reports; `Unknown` when
                      it reports none, never a guess. */}
                  <TableCell>
                    <SiteDomainLiveness
                      serving={domain.serving}
                      verificationState={domain.verification_state}
                    />
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={(event) => {
                        unbindTriggerRef.current = event.currentTarget;
                        setPendingUnbind(domain);
                      }}
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

      {/* The remedy for every "Pending DNS verification" row above: the exact
          TXT record to publish, straight from the gateway. */}
      {challenges.map((verification) => (
        <SiteDomainChallenge key={verification.hostname} verification={verification} />
      ))}

      <AlertDialog
        open={pendingUnbind !== null}
        onOpenChange={(open) => !open && setPendingUnbind(null)}
      >
        <AlertDialogContent
          onCloseAutoFocus={(event) => {
            // Restore focus to the opening row button (still-connected check:
            // after a confirmed unbind the row is gone, and Radix's default —
            // body — is then the honest fallback).
            const trigger = unbindTriggerRef.current;
            unbindTriggerRef.current = null;
            if (trigger?.isConnected) {
              event.preventDefault();
              trigger.focus();
            }
          }}
        >
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
