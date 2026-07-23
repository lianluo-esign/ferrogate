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
//     site-domains registry;
//   - a PUBLISH/republish flow that uploads a ZIP bundle with explicit tenant/
//     project/site selection, a bundle version, public/private + SPA-fallback
//     toggles, and a Cache-Control override, validating the archive CLIENT-SIDE
//     for fast feedback while the gateway stays authoritative — scan / zip-bomb
//     / quota rejections are surfaced VERBATIM and accessibly — and reporting
//     REAL byte-level upload progress via XHR `upload.onprogress` (fetch has no
//     upload-progress event) into a determinate `role="progressbar"`;
//   - a per-site DETAIL drawer that inspects the published bundle's file tree
//     (paths, content types, hashes, sizes) straight from the manifest; and
//   - an UNPUBLISH flow that permanently removes a site (every per-file object
//     plus the reserved manifest row) behind a name-typed destructive confirm,
//     each underlying delete recorded in the gateway audit log.
//
// The manifest JSON (public/spa_fallback/cache_control/bundle_version/files) is
// read back from the reserved `__site_manifest__` version the gateway writes at
// publish time; it is the authoritative source for a site's serving policy and
// its file tree.
//
// This slice (#345) adds the remaining deferred affordances that the runtime
// actually backs: (a) per-file DOWNLOAD of any published file (a plain asset GET
// of that file's path-keyed object), and (b) an outbound OPEN-SERVE-URL link.
//
// NOTE — per-bundle version HISTORY + channel-move ROLLBACK were also requested
// but are intentionally NOT built here, because the static-site runtime does not
// back them (verified against gateway `sites.rs`, not assumed from the generic
// asset model): publishing a bundle overwrites each file object in place under a
// PATH-keyed `version` and rewrites the single `__site_manifest__` row, so NO
// prior bundle is retained to roll back to; and serve-mode resolves purely
// through that manifest — it never consults an asset CHANNEL. A channel-move on
// a static_site would therefore return 200 yet change nothing that is served
// (the #188 "write succeeds, runtime ignores it" failure mode). Real history/
// rollback needs gateway support (retain prior bundles + make serve resolve
// through a pointer); tracked as a follow-up rather than faked in the UI.
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
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
import { GATEWAY_ADMIN_BASE_URL } from "@/lib/config";
import {
  adminDelete,
  adminGet,
  type AdminSchema,
  gatewayGet,
  gatewayGetBinary,
} from "@/lib/gateway-client";
import { ApiError, type ApiErrorBody } from "@/types/auth";

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

/** One published site's fully-joined row (list + manifest + bound domains). */
interface SiteRow {
  name: string;
  manifest: SiteManifest | undefined;
  manifestLoading: boolean;
  manifestError: Error | undefined;
  domains: SiteDomain[];
  serveUrl: string;
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

/** First 12 hex chars of a content hash, ellipsized (mirrors the Assets page). */
function shortHash(hash: string): string {
  return `${hash.slice(0, 12)}…`;
}

/** Asset-object path for ONE published file. Each file's `version` key IS its
 * bundle path (the same convention publish writes and unpublish deletes), so a
 * plain asset GET streams that individual file back. Kept as a manual encoded
 * string (not the typed `params` client) so it lines up byte-for-byte with the
 * publish/unpublish addressing in this module. */
function siteFilePath(site: string, filePath: string): string {
  return `/v1/assets/${STATIC_SITE_TYPE}/${encodeURIComponent(site)}/${encodeURIComponent(filePath)}`;
}

/** Absolute, browser-openable serve URL for a site's stored relative serve path
 * (`/sites/{tenant}/{site}/…`). The gateway serves the browse surface on the
 * same origin the admin client already talks to, so we resolve the relative
 * path against that base; a malformed base degrades to the raw path. */
function serveHref(servePath: string): string {
  try {
    return new URL(servePath, GATEWAY_ADMIN_BASE_URL).toString();
  } catch {
    return servePath;
  }
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

/**
 * PUTs the bundle bytes via XHR so the publish reports REAL byte-level upload
 * progress: `fetch` exposes no upload-progress event, so this mirrors
 * `gatewayPutBinary`'s auth + `x-site-*` headers and verbatim `ApiError`
 * surfacing while streaming `xhr.upload.onprogress` byte counts to
 * `onProgress`. Kept local to this lazy page so the entry chunk stays lean.
 */
function putBundleWithProgress<T>(
  apiKey: string,
  path: string,
  body: Blob,
  contentType: string,
  extraHeaders: Record<string, string | undefined>,
  onProgress: (loaded: number, total: number) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", new URL(path, GATEWAY_ADMIN_BASE_URL).toString());
    xhr.responseType = "text";
    xhr.setRequestHeader("Authorization", `Bearer ${apiKey}`);
    xhr.setRequestHeader("Content-Type", contentType || "application/octet-stream");
    for (const [key, value] of Object.entries(extraHeaders)) {
      if (value !== undefined && value !== "") xhr.setRequestHeader(key, value);
    }
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded, event.total);
    };
    xhr.onload = () => {
      let parsed: unknown = null;
      try {
        parsed = xhr.responseText ? JSON.parse(xhr.responseText) : null;
      } catch {
        parsed = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(parsed as T);
        return;
      }
      const errorBody = parsed as ApiErrorBody | null;
      reject(
        new ApiError(
          xhr.status,
          errorBody?.error?.code ?? "unknown_error",
          errorBody?.error?.message ?? xhr.statusText,
        ),
      );
    };
    xhr.onerror = () =>
      reject(new ApiError(0, "network_error", "network request failed"));
    xhr.send(body);
  });
}

/**
 * Per-site detail drawer: the published bundle's file tree straight from the
 * manifest (path, content type, content hash, size), plus the destructive
 * Unpublish trigger. The manifest is already loaded by the list's parallel
 * reads, so opening the drawer is a pure render — no extra round trip.
 */
function SiteDetailSheet({
  row,
  apiKey,
  onClose,
  onUnpublish,
}: {
  row: SiteRow | null;
  apiKey: string;
  onClose: () => void;
  onUnpublish: () => void;
}) {
  const { t, format } = useI18n();
  const manifest = row?.manifest;
  const files = useMemo(
    () =>
      manifest
        ? [...manifest.files].sort((a, b) => a.path.localeCompare(b.path))
        : [],
    [manifest],
  );

  // Which file's asset GET is in flight, so exactly that row's button shows a
  // busy state (concurrent downloads of different files stay independent).
  const [downloadingPath, setDownloadingPath] = useState<string | null>(null);

  async function handleFileDownload(entry: SiteFileEntry) {
    if (!row) return;
    setDownloadingPath(entry.path);
    try {
      const blob = await gatewayGetBinary(apiKey, siteFilePath(row.name, entry.path));
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      // Save under the file's leaf name, not the full bundle path.
      link.download = entry.path.split("/").pop() || entry.path;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      // Surface the gateway/network verdict verbatim, keyed to the exact file.
      toast.error(
        t("page.staticSites.download.failed", {
          file: entry.path,
          message: error instanceof Error ? error.message : String(error),
        }),
      );
    } finally {
      setDownloadingPath(null);
    }
  }

  return (
    <Sheet open={row !== null} onOpenChange={(next) => !next && onClose()}>
      <SheetContent className="flex w-full flex-col gap-4 overflow-y-auto sm:max-w-2xl">
        {row ? (
          <>
            <SheetHeader>
              <SheetTitle className="font-mono text-base">{row.name}</SheetTitle>
              {manifest ? (
                <SheetDescription>
                  {t("page.staticSites.detail.description", {
                    version: manifest.bundle_version,
                    files: manifest.files.length,
                    bytes: format.bytes(manifestBytes(manifest)),
                  })}
                </SheetDescription>
              ) : null}
            </SheetHeader>

            {/* Outbound affordance: open the live serve surface in a new tab.
              rel=noopener keeps the opened site from reaching back via
              window.opener; the sr-only hint announces the new-tab behavior. */}
            <div>
              <Button asChild variant="outline" size="sm">
                <a
                  href={serveHref(row.serveUrl)}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {t("page.staticSites.serveUrl.open")}
                  <span className="sr-only">
                    {" "}
                    {t("page.staticSites.serveUrl.newTabHint")}
                  </span>
                </a>
              </Button>
            </div>

            {row.manifestError ? (
              <p
                role="alert"
                className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {t("page.staticSites.manifestError")}
              </p>
            ) : !manifest ? (
              <p className="text-sm text-muted-foreground">
                {t("resource.table.loading")}
              </p>
            ) : (
              <section className="flex flex-col gap-2">
                <h3 className="text-sm font-semibold">
                  {t("page.staticSites.detail.files")}
                </h3>
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t("page.staticSites.col.path")}</TableHead>
                        <TableHead>{t("page.assets.col.contentType")}</TableHead>
                        <TableHead>{t("page.assets.col.contentHash")}</TableHead>
                        <TableHead>{t("page.assets.col.size")}</TableHead>
                        <TableHead className="w-28">
                          {t("resource.table.actionsColumn")}
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {files.length === 0 ? (
                        <TableRow>
                          <TableCell
                            colSpan={5}
                            className="h-16 text-center text-sm text-muted-foreground"
                          >
                            {t("resource.table.empty")}
                          </TableCell>
                        </TableRow>
                      ) : (
                        files.map((entry) => (
                          <TableRow key={entry.path}>
                            <TableCell className="font-mono text-xs break-all">
                              {entry.path}
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {entry.content_type}
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {shortHash(entry.content_hash)}
                            </TableCell>
                            <TableCell>{format.bytes(entry.size_bytes)}</TableCell>
                            <TableCell>
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                disabled={downloadingPath === entry.path}
                                onClick={() => handleFileDownload(entry)}
                              >
                                {downloadingPath === entry.path
                                  ? t("page.staticSites.detail.downloading")
                                  : t("page.staticSites.detail.download")}
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </div>
              </section>
            )}

            <SheetFooter className="mt-auto">
              <Button
                type="button"
                variant="destructive"
                onClick={onUnpublish}
                disabled={!manifest}
              >
                {t("page.staticSites.unpublish.action")}
              </Button>
              <Button type="button" variant="outline" onClick={onClose}>
                {t("common.close")}
              </Button>
            </SheetFooter>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
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
  // Real byte-level upload progress, fed by xhr.upload.onprogress.
  const [uploadProgress, setUploadProgress] = useState<{
    loaded: number;
    total: number;
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Detail drawer + unpublish, both keyed by site slug so they survive row
  // rebuilds (the joined rows re-derive on every manifest status change).
  const [detailSite, setDetailSite] = useState<string | null>(null);
  const [unpublishSite, setUnpublishSite] = useState<string | null>(null);
  const [unpublishConfirm, setUnpublishConfirm] = useState("");

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

  const rows = useMemo<SiteRow[]>(
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

  const detailRow = detailSite
    ? (rows.find((row) => row.name === detailSite) ?? null)
    : null;
  const unpublishRow = unpublishSite
    ? (rows.find((row) => row.name === unpublishSite) ?? null)
    : null;

  function resetForm() {
    setSite("");
    setVersion("");
    setIsPublic(false);
    setSpaFallback(false);
    setCacheControl("");
    setFile(null);
    setArchiveError(null);
    setPublishError(null);
    setUploadProgress(null);
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
      return putBundleWithProgress<StaticSitePublishResponse>(
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
        (loaded, total) => setUploadProgress({ loaded, total }),
      );
    },
    onMutate: () => {
      setPublishError(null);
      setUploadProgress({ loaded: 0, total: file?.size ?? 0 });
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
      setUploadProgress(null);
      setPublishError(error.message);
      toast.error(error.message);
    },
  });

  // Unpublish = purge every per-file object PLUS the reserved manifest row.
  // The gateway offers no single "delete site" endpoint, so this deletes each
  // asset version (each file's `version` key IS its path) and finally the
  // manifest; every DELETE is audit-logged by the assets registry.
  const unpublishMutation = useMutation({
    mutationFn: async ({
      name,
      manifest,
    }: {
      name: string;
      manifest: SiteManifest;
    }) => {
      await Promise.all(
        manifest.files.map((entry) =>
          adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/{version}", {
            params: {
              asset_type: STATIC_SITE_TYPE,
              name,
              version: entry.path,
            },
          }),
        ),
      );
      // Remove the manifest LAST so a partial file failure leaves the site
      // describable rather than orphaning file objects behind a gone manifest.
      await adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/{version}", {
        params: {
          asset_type: STATIC_SITE_TYPE,
          name,
          version: SITE_MANIFEST_VERSION,
        },
      });
    },
    onSuccess: (_result, variables) => {
      toast.success(
        t("page.staticSites.unpublish.success", { site: variables.name }),
      );
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: SITE_DOMAINS_QUERY_KEY });
      queryClient.invalidateQueries({
        queryKey: ["static-site-manifest", variables.name],
      });
      setUnpublishSite(null);
      setUnpublishConfirm("");
      setDetailSite(null);
    },
    onError: (error: Error) => toast.error(error.message),
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

  const progressFraction =
    uploadProgress && uploadProgress.total > 0
      ? uploadProgress.loaded / uploadProgress.total
      : 0;
  const progressPercent = Math.round(progressFraction * 100);

  // Exact site slug the operator must retype to arm the destructive unpublish.
  const unpublishArmed =
    unpublishSite !== null && unpublishConfirm === unpublishSite;

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
              <div className="sm:col-span-2 flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-sm text-muted-foreground">
                  <span id="site-upload-label">
                    {t("page.staticSites.publish.uploading")}
                  </span>
                  <span className="font-mono text-xs">
                    {format.percent(progressFraction)}
                  </span>
                </div>
                <div
                  role="progressbar"
                  aria-labelledby="site-upload-label"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={progressPercent}
                  aria-valuetext={format.percent(progressFraction)}
                  className="h-2 w-full overflow-hidden rounded-full bg-secondary"
                >
                  <div
                    className="h-full bg-primary transition-all"
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
              </div>
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
              <TableHead className="w-24">{t("resource.table.actionsColumn")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assetsLoading ? (
              <TableRow>
                <TableCell colSpan={10} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={10} className="h-24 text-center">
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
                  <TableCell className="font-mono text-xs break-all">
                    <a
                      href={serveHref(row.serveUrl)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      {row.serveUrl}
                      <span className="sr-only">
                        {" "}
                        {t("page.staticSites.serveUrl.newTabHint")}
                      </span>
                    </a>
                  </TableCell>
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
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!row.manifest}
                      onClick={() => setDetailSite(row.name)}
                    >
                      {t("resource.table.moreDetails")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <SiteDetailSheet
        row={detailRow}
        apiKey={apiKey}
        onClose={() => setDetailSite(null)}
        onUnpublish={() => {
          if (!detailRow) return;
          setUnpublishConfirm("");
          setUnpublishSite(detailRow.name);
        }}
      />

      {/*
        Unpublish — a name-typed destructive confirmation. Unlike a republish
        (which overwrites the bundle in place), this permanently removes every
        file object and the manifest, so the site stops serving. The confirm
        button stays disarmed until the operator retypes the exact site slug.
      */}
      <Dialog
        open={unpublishSite !== null}
        onOpenChange={(next) => {
          if (!next) {
            setUnpublishSite(null);
            setUnpublishConfirm("");
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          {unpublishSite ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (unpublishArmed && unpublishRow?.manifest)
                  unpublishMutation.mutate({
                    name: unpublishSite,
                    manifest: unpublishRow.manifest,
                  });
              }}
            >
              <DialogHeader>
                <DialogTitle>
                  {t("page.staticSites.unpublish.title", { site: unpublishSite })}
                </DialogTitle>
                <DialogDescription>
                  {t("page.staticSites.unpublish.body", { site: unpublishSite })}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-2 py-4">
                <Label htmlFor="site-unpublish-confirm">
                  {t("page.staticSites.unpublish.confirmLabel", {
                    site: unpublishSite,
                  })}
                </Label>
                <Input
                  id="site-unpublish-confirm"
                  value={unpublishConfirm}
                  onChange={(event) => setUnpublishConfirm(event.target.value)}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  aria-invalid={unpublishConfirm !== "" && !unpublishArmed}
                />
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setUnpublishSite(null);
                    setUnpublishConfirm("");
                  }}
                >
                  {t("common.cancel")}
                </Button>
                <Button
                  type="submit"
                  variant="destructive"
                  disabled={!unpublishArmed || unpublishMutation.isPending}
                >
                  {t("page.staticSites.unpublish.action")}
                </Button>
              </DialogFooter>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
