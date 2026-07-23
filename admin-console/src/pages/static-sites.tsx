// Static-site management surface (issue #345, parent #295). Static sites are
// published as `static_site`-typed ZIP bundles (PUT /v1/assets/static_site/
// {site}/{version}) that the gateway unpacks into per-file objects plus a
// stored site manifest, then serves under `/sites/{tenant}/{site}/…` (#258).
// Custom domains are bound on the separate Site Domains page (#265/#323).
//
// This module gives operators one coherent view over that machinery instead of
// forcing them to know the ZIP convention and type `x-site-*` headers by hand:
//   - a LIST of logical sites (bundle version, public/private, SPA fallback,
//     cache policy, file count/bytes, publish time, serve URL, bound domains),
//     joined from the tenant asset listing, each site's manifest, and the
//     site-domains registry; and
//   - a PUBLISH/republish flow that uploads a ZIP bundle with explicit tenant/
//     project/site selection, a bundle version, public/private + SPA-fallback
//     toggles, and a Cache-Control override, validating the archive CLIENT-SIDE
//     for fast feedback while the gateway stays authoritative — scan / zip-bomb
//     / quota rejections are surfaced VERBATIM and accessibly.
//
// The manifest JSON (public/spa_fallback/cache_control/bundle_version/files) is
// read back from the reserved `__site_manifest__` version the gateway writes at
// publish time; it is the authoritative source for a site's serving policy.
import { useMemo, useRef, useState } from "react";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EntityReferencePicker } from "@/components/resource/entity-reference-picker";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { APP_ROUTES } from "@/lib/app-routes";
import {
  adminGet,
  type AdminSchema,
  gatewayGet,
  gatewayPutBinary,
} from "@/lib/gateway-client";

type SiteDomain = AdminSchema<"AdminSiteDomain">;

/** Reserved manifest `version` the gateway writes per site (mirrors
 * SITE_MANIFEST_VERSION in the gateway's sites.rs). A real bundle file path
 * never collides with it. */
const SITE_MANIFEST_VERSION = "__site_manifest__";
const STATIC_SITE_TYPE = "static_site";

/** Client-side fast-feedback ceiling on the compressed upload. The gateway's
 * MAX_ASSET_BYTES (and the 64 MiB unpacked zip-bomb guard) remain the real,
 * authoritative limits; this only spares an operator a doomed multi-megabyte
 * round trip. */
const MAX_BUNDLE_BYTES = 32 * 1024 * 1024;

/** One file in a published site manifest (mirrors the gateway SiteFileEntry). */
interface SiteFileEntry {
  path: string;
  content_type: string;
  content_hash: string;
  size_bytes: number;
}

/** A published site's serving policy + file tree, read from the manifest row
 * (mirrors the gateway SiteManifest serialized as the manifest asset body). */
interface SiteManifest {
  site: string;
  bundle_version: string;
  public: boolean;
  spa_fallback: boolean;
  cache_control: string | null;
  files: SiteFileEntry[];
  created_at_unix: number;
  updated_at_unix: number;
}

/** Publish response body the gateway returns for a `static_site` ZIP push. */
interface StaticSitePublishResponse {
  object: "static_site";
  tenant: string;
  site: string;
  bundle_version: string;
  public: boolean;
  spa_fallback: boolean;
  file_count: number;
  size_bytes: number;
  files: string[];
}

const ASSETS_QUERY_KEY = ["assets"] as const;
const SITE_DOMAINS_QUERY_KEY = ["site-domains"] as const;

function manifestPath(site: string): string {
  return `/v1/assets/${STATIC_SITE_TYPE}/${encodeURIComponent(site)}/${encodeURIComponent(SITE_MANIFEST_VERSION)}`;
}

// The gateway serves the reserved manifest version as its stored JSON body; a
// plain JSON GET parses it regardless of the stored content type.
async function fetchSiteManifest(apiKey: string, site: string): Promise<SiteManifest> {
  return gatewayGet<SiteManifest>(apiKey, manifestPath(site));
}

/** Total stored bytes across a manifest's files. */
function manifestBytes(manifest: SiteManifest): number {
  return manifest.files.reduce((sum, file) => sum + file.size_bytes, 0);
}

/** `.zip` by extension or a zip-ish MIME type. The gateway re-checks the ZIP
 * magic bytes on the raw upload, so this is fast feedback, not the gate. */
function looksLikeZip(file: File): boolean {
  if (file.name.toLowerCase().endsWith(".zip")) return true;
  return (
    file.type === "application/zip" ||
    file.type === "application/x-zip-compressed" ||
    file.type === "application/x-zip"
  );
}

export default function StaticSitesPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const tenantId = session!.tenant.id;
  const queryClient = useQueryClient();

  // Publish form state.
  const [formTenant, setFormTenant] = useState(tenantId);
  const [formProject, setFormProject] = useState("");
  const [site, setSite] = useState("");
  const [version, setVersion] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [spaFallback, setSpaFallback] = useState(false);
  const [cacheControl, setCacheControl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [publishError, setPublishError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const {
    data: assetData,
    isLoading: assetsLoading,
    error: assetsError,
  } = useQuery({
    queryKey: ASSETS_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets"),
  });

  const { data: domainData } = useQuery({
    queryKey: SITE_DOMAINS_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/admin/v1/site-domains"),
  });

  // Distinct site slugs = distinct `name` of the tenant's static_site assets.
  const siteNames = useMemo(() => {
    const rows = assetData?.data ?? [];
    const names = new Set<string>();
    for (const row of rows) {
      if (row.asset_type === STATIC_SITE_TYPE) names.add(row.name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [assetData]);

  // One parallel manifest read per site (no waterfall): each carries the
  // authoritative serving policy the flat asset listing cannot express.
  const manifestQueries = useQueries({
    queries: siteNames.map((name) => ({
      queryKey: ["static-site-manifest", name] as const,
      queryFn: () => fetchSiteManifest(apiKey, name),
    })),
  });

  // Bound custom hostnames grouped by site slug.
  const domainsBySite = useMemo(() => {
    const map = new Map<string, SiteDomain[]>();
    for (const domain of domainData?.data ?? []) {
      const bucket = map.get(domain.site);
      if (bucket) bucket.push(domain);
      else map.set(domain.site, [domain]);
    }
    return map;
  }, [domainData]);

  const rows = useMemo(
    () =>
      siteNames.map((name, index) => {
        const query = manifestQueries[index];
        const domains = domainsBySite.get(name) ?? [];
        // Canonical serve URL: a bound hostname's serve_path when one exists,
        // else the tenant-scoped /sites/{tenant}/{site}/ browse path.
        const serveUrl =
          domains[0]?.serve_path ?? `/sites/${tenantId}/${name}/`;
        return {
          name,
          manifest: query.data,
          manifestLoading: query.isLoading,
          manifestError: query.error as Error | undefined,
          domains,
          serveUrl,
        };
      }),
    // manifestQueries identity changes each render; depend on its data/status
    // via a derived signature to avoid needless row rebuilds.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [siteNames, domainsBySite, tenantId, manifestQueries.map((q) => q.status).join(",")],
  );

  function resetForm() {
    setSite("");
    setVersion("");
    setIsPublic(false);
    setSpaFallback(false);
    setCacheControl("");
    setFile(null);
    setArchiveError(null);
    setPublishError(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function onFileChange(next: File | null) {
    setFile(next);
    setPublishError(null);
    if (!next) {
      setArchiveError(null);
      return;
    }
    if (!looksLikeZip(next)) {
      setArchiveError(t("page.staticSites.validation.notZip"));
      return;
    }
    if (next.size > MAX_BUNDLE_BYTES) {
      setArchiveError(
        t("page.staticSites.validation.tooLarge", {
          max: format.bytes(MAX_BUNDLE_BYTES),
        }),
      );
      return;
    }
    setArchiveError(null);
  }

  const publishMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error(t("page.staticSites.validation.bundleRequired"));
      const path = `/v1/assets/${STATIC_SITE_TYPE}/${encodeURIComponent(site.trim())}/${encodeURIComponent(version.trim())}`;
      return gatewayPutBinary<StaticSitePublishResponse>(
        apiKey,
        path,
        file,
        file.type || "application/zip",
        {
          "x-site-public": isPublic ? "true" : undefined,
          "x-site-spa-fallback": spaFallback ? "true" : undefined,
          "x-site-cache-control": cacheControl.trim() || undefined,
          "x-asset-visibility": isPublic ? "public" : undefined,
        },
      );
    },
    onSuccess: (response) => {
      toast.success(
        t("page.staticSites.toast.published", {
          site: response.site,
          files: response.file_count,
          bytes: format.bytes(response.size_bytes),
        }),
      );
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: SITE_DOMAINS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: ["static-site-manifest", response.site] });
      resetForm();
    },
    // Surface the gateway verdict VERBATIM (scan / zip-bomb / quota / immutable).
    onError: (error: Error) => {
      setPublishError(error.message);
      toast.error(error.message);
    },
  });

  function submitPublish() {
    setPublishError(null);
    if (site.trim() === "") {
      setPublishError(t("page.siteDomains.validation.siteRequired"));
      return;
    }
    if (version.trim() === "") {
      setPublishError(t("page.staticSites.validation.versionRequired"));
      return;
    }
    if (!file) {
      setPublishError(t("page.staticSites.validation.bundleRequired"));
      return;
    }
    if (archiveError) {
      setPublishError(archiveError);
      return;
    }
    publishMutation.mutate();
  }

  const serveUrlPreview = `/sites/${formTenant || tenantId}/${site.trim() || "{site}"}/`;
  const publishDisabled = publishMutation.isPending || archiveError !== null;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.staticSites.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.staticSites.description")}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.staticSites.publish.title")}</CardTitle>
          <CardDescription>{t("page.staticSites.publish.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              submitPublish();
            }}
          >
            <div className="grid gap-1.5">
              <Label htmlFor="site-tenant">{t("page.siteDomains.field.tenant")}</Label>
              <EntityReferencePicker
                id="site-tenant"
                label={t("page.siteDomains.field.tenant")}
                reference={{
                  target: "tenant-accounts",
                  valueKey: "id",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["slug"],
                }}
                value={formTenant}
                dependencyValues={{}}
                placeholder={t("page.siteDomains.field.tenant.select")}
                onChange={(value) => setFormTenant(typeof value === "string" ? value : "")}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-project">{t("page.staticSites.field.project")}</Label>
              <EntityReferencePicker
                id="site-project"
                label={t("page.staticSites.field.project")}
                reference={{
                  target: "projects",
                  valueKey: "id",
                  primaryLabelKey: "name",
                  secondaryLabelKeys: ["slug", "tenant_id"],
                }}
                value={formProject}
                dependencyValues={{}}
                placeholder={t("page.staticSites.field.project.select")}
                onChange={(value) => setFormProject(typeof value === "string" ? value : "")}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-slug">{t("page.siteDomains.field.site")}</Label>
              <Input
                id="site-slug"
                value={site}
                onChange={(event) => setSite(event.target.value)}
                // eslint-disable-next-line ferrogate/no-untranslated-literal -- example site slug, identical across locales
                placeholder="marketing"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-version">{t("page.assets.field.version")}</Label>
              <Input
                id="site-version"
                value={version}
                onChange={(event) => setVersion(event.target.value)}
                placeholder="1.0.0"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-cache">{t("page.staticSites.field.cacheControl")}</Label>
              <Input
                id="site-cache"
                value={cacheControl}
                onChange={(event) => setCacheControl(event.target.value)}
                // eslint-disable-next-line ferrogate/no-untranslated-literal -- example Cache-Control value, identical across locales
                placeholder="public, max-age=300"
              />
              <p className="text-xs text-muted-foreground">
                {t("page.staticSites.field.cacheControl.hint")}
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-bundle">{t("page.staticSites.field.bundle")}</Label>
              <Input
                id="site-bundle"
                type="file"
                accept=".zip,application/zip"
                ref={fileInputRef}
                onChange={(event) => onFileChange(event.target.files?.[0] ?? null)}
                aria-invalid={archiveError !== null}
                aria-describedby="site-bundle-hint"
              />
              {archiveError ? (
                <p id="site-bundle-hint" role="alert" className="text-xs text-destructive">
                  {archiveError}
                </p>
              ) : (
                <p id="site-bundle-hint" className="text-xs text-muted-foreground">
                  {t("page.staticSites.field.bundle.hint")}
                </p>
              )}
            </div>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor="site-public" className="cursor-pointer">
                {t("page.staticSites.field.public")}
              </Label>
              <Switch id="site-public" checked={isPublic} onCheckedChange={setIsPublic} />
            </div>
            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <Label htmlFor="site-spa" className="cursor-pointer">
                {t("page.staticSites.field.spa")}
              </Label>
              <Switch id="site-spa" checked={spaFallback} onCheckedChange={setSpaFallback} />
            </div>

            <p className="text-xs text-muted-foreground sm:col-span-2">
              {t("page.staticSites.serveUrlPreview")}{" "}
              <span className="font-mono">{serveUrlPreview}</span>
            </p>

            {publishError ? (
              <p
                role="alert"
                className="sm:col-span-2 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {publishError}
              </p>
            ) : null}

            {publishMutation.isPending ? (
              <p
                role="status"
                aria-live="polite"
                className="sm:col-span-2 flex items-center gap-2 text-sm text-muted-foreground"
              >
                <span
                  aria-hidden="true"
                  className="h-2 w-24 overflow-hidden rounded-full bg-muted"
                >
                  <span className="block h-full w-1/3 animate-pulse rounded-full bg-primary" />
                </span>
                {t("page.staticSites.publish.uploading")}
              </p>
            ) : null}

            <div className="sm:col-span-2">
              <Button type="submit" disabled={publishDisabled}>
                {publishMutation.isPending
                  ? t("page.staticSites.publish.submitting")
                  : t("page.staticSites.publish.submit")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {assetsError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.staticSites.loadError", { message: assetsError.message })}
        </p>
      ) : null}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.staticSites.col.site")}</TableHead>
              <TableHead>{t("page.assets.col.version")}</TableHead>
              <TableHead>{t("page.staticSites.col.access")}</TableHead>
              <TableHead>{t("page.staticSites.col.cache")}</TableHead>
              <TableHead>{t("page.staticSites.col.files")}</TableHead>
              <TableHead>{t("page.assets.col.size")}</TableHead>
              <TableHead>{t("page.staticSites.col.published")}</TableHead>
              <TableHead>{t("page.staticSites.col.serveUrl")}</TableHead>
              <TableHead>{t("page.staticSites.col.domains")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assetsLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="h-24 text-center">
                  {t("page.staticSites.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.name} data-testid={`static-site-${row.name}`}>
                  <TableCell className="font-medium">{row.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {row.manifest?.bundle_version || t("common.unknown")}
                  </TableCell>
                  <TableCell>
                    {row.manifest ? (
                      <div className="flex flex-wrap gap-1">
                        <Badge variant={row.manifest.public ? "default" : "secondary"}>
                          {row.manifest.public
                            ? t("page.staticSites.access.public")
                            : t("page.staticSites.access.private")}
                        </Badge>
                        {row.manifest.spa_fallback ? (
                          <Badge variant="outline">{t("page.staticSites.access.spa")}</Badge>
                        ) : null}
                      </div>
                    ) : row.manifestError ? (
                      <span className="text-xs text-destructive">
                        {t("page.staticSites.manifestError")}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        {t("resource.table.loading")}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {row.manifest?.cache_control ?? t("page.staticSites.cache.default")}
                  </TableCell>
                  <TableCell>{row.manifest ? row.manifest.files.length : "—"}</TableCell>
                  <TableCell>
                    {row.manifest ? format.bytes(manifestBytes(row.manifest)) : "—"}
                  </TableCell>
                  <TableCell className="text-xs">
                    {row.manifest
                      ? format.date(row.manifest.updated_at_unix * 1000, {
                          dateStyle: "medium",
                          timeStyle: "short",
                        })
                      : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs break-all">{row.serveUrl}</TableCell>
                  <TableCell>
                    {row.domains.length === 0 ? (
                      <Button asChild variant="link" size="sm" className="h-auto p-0">
                        <Link to={APP_ROUTES.siteDomains}>
                          {t("page.staticSites.domains.bind")}
                        </Link>
                      </Button>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {row.domains.map((domain) => (
                          <Badge key={domain.hostname} variant="secondary" className="text-xs">
                            {domain.hostname}
                          </Badge>
                        ))}
                      </div>
                    )}
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
