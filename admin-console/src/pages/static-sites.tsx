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
//     site selection, a bundle version, public/private + SPA-fallback
//     toggles, and a Cache-Control override, validating the archive CLIENT-SIDE
//     for fast feedback while the gateway stays authoritative — scan / zip-bomb
//     / quota rejections are surfaced VERBATIM and accessibly — and reporting
//     REAL byte-level upload progress via XHR `upload.onprogress` (fetch has no
//     upload-progress event) into a determinate `role="progressbar"`;
//   - a per-site DETAIL drawer that inspects the served bundle's file tree
//     (paths, content types, hashes, sizes) straight from that bundle's
//     manifest; and
//   - an UNPUBLISH flow that permanently removes a site (the `serving` channel
//     FIRST, then every retained bundle-manifest row and every per-file object,
//     then the reserved marker — the one order the gateway accepts) behind a
//     name-typed destructive confirm, each delete recorded in the audit log.
//
// The drawer's domain table reports each bound hostname's LIVENESS, not just
// that it is bound: post-#488 the gateway refuses requests on a hostname whose
// DNS ownership proof is missing, pending or expired, and it says so on every
// `AdminSiteDomain` it serializes (`serving`, `verification_state`). Rendering
// only the bound timestamp + ACME flag showed a refused hostname as if it were
// live; see components/site-domain-liveness.tsx.
//
// EVERY displayed policy/file field describes the bundle the gateway ACTUALLY
// SERVES, resolved exactly the way `Gateway::resolve_active_site_bundle` does
// (sites.rs): read the asset registry manifest, take the version the `serving`
// channel points at, and read THAT bundle's immutable manifest row
// (`/v1/assets/static_site/{site}/{servingVersion}`). Only a legacy site with no
// `serving` channel (published before #397) falls back to the MUTABLE
// `__site_manifest__` marker, which is exactly the gateway's own fallback.
// Reading the marker unconditionally would be a lie after a rollback: a rollback
// is a channel move only and never rewrites the marker, so the marker keeps
// describing the last-PUBLISHED bundle while a different one is served — the
// drawer would badge one version "Active" while its header named another, and
// the file tree's hashes would not match the bytes a per-file download returns
// (the gateway remaps a bare per-file path onto the ACTIVE bundle).
//
// This slice (#345) adds the remaining static-site affordances the runtime now
// actually backs: (a) per-file DOWNLOAD of any published file (a plain asset GET
// of that file's path-keyed object), (b) an outbound OPEN-SERVE-URL link, and
// (c) per-bundle version HISTORY + a truthful channel-move ROLLBACK.
//
// History/rollback are real (not inert) as of gateway #397: a publish now
// RETAINS each bundle under its immutable `{bundle_version}` and serve-mode
// resolves the ACTIVE bundle through the well-known `serving` asset channel
// (SITE_SERVE_CHANNEL) — the same channel a publish moves via the
// `move_asset_channel_if_resolvable` CAS. So moving `serving` to a prior
// retained version genuinely re-points what `/sites/{tenant}/{site}/…` serves
// (write-path == read-path, the #188 guard). The drawer lists retained bundle
// versions from the asset registry manifest, marks the one the `serving`
// channel currently points at (the served version), and rolls back by PUT-ing
// that channel to a selected prior version behind a consequence-named confirm.
// Under #397 each bundle's files are keyed `__site_file__:{version}:{path}` and
// the bundle manifest at the bare `{version}`, so a bare version is a real
// rollback target only when it has companion `__site_file__:{version}:…` rows —
// that structural check keeps legacy path-keyed file rows (pre-#397, whose
// `version` IS a bare file path) out of the history list.
import { useCallback, useMemo, useRef, useState } from "react";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
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
import {
  bindAcmeNoteKey,
  SiteDomainChallenge,
  SiteDomainLiveness,
} from "@/components/site-domain-liveness";
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
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import { APP_ROUTES } from "@/lib/app-routes";
import { GATEWAY_ADMIN_BASE_URL } from "@/lib/config";
import {
  adminDelete,
  adminGet,
  adminPost,
  type AdminSchema,
  gatewayGet,
  gatewayGetBinary,
  gatewayPut,
  type HeaderParamsFor,
  type OpFor,
  type PathParamsFor,
  resolveAdminPath,
} from "@/lib/gateway-client";
import { validateSiteDomainHostname } from "@/lib/hostname";
import { readsAsZipArchive } from "@/lib/zip-archive";
import { ApiError, type ApiErrorBody } from "@/types/auth";

type SiteDomain = AdminSchema<"AdminSiteDomain">;
type AssetSummary = AdminSchema<"AssetSummary">;
type AssetManifest = AdminSchema<"AssetManifest">;
type AssetChannelMutationResponse = AdminSchema<"AssetChannelMutationResponse">;

/** Reserved manifest `version` the gateway writes per site (mirrors
 * SITE_MANIFEST_VERSION in the gateway's sites.rs). A real bundle file path
 * never collides with it. */
const SITE_MANIFEST_VERSION = "__site_manifest__";
const STATIC_SITE_TYPE = "static_site";

/** Page size asked of the withheld listing when explaining an uncommitted
 * publish. `storage.admin_list_max_limit` defaults to 1000 (config/types.rs:
 * `default_admin_list_max_limit`) and clamps anything larger, so this is the
 * most a single read can return; whether it was ENOUGH is decided by comparing
 * the returned rows against the response's `total`, never assumed. */
const WITHHELD_LOOKUP_LIMIT = 1000;

/** `version`-key prefix under which gateway #397 stores each per-file object of
 * a RETAINED bundle: `__site_file__:{bundle_version}:{path}`. A bare version is
 * a genuine rollback target only when it has companion rows under this prefix,
 * which is how we tell a real bundle version from a legacy path-keyed file row.
 * Mirrors SITE_FILE_VERSION_PREFIX in the gateway's sites.rs. */
const SITE_FILE_VERSION_PREFIX = "__site_file__";

/** Well-known asset channel whose target is the ACTIVE (served) bundle version
 * (gateway #397 `SITE_SERVE_CHANNEL`). Serve-mode resolves the bundle through
 * this channel, so PUT-ing it to a prior retained version genuinely re-points
 * what is served — the truthful rollback (write-path == read-path, #188). */
const SITE_SERVE_CHANNEL = "serving";

/** True for the reserved `version` keys the gateway writes for a static site
 * (the mutable manifest marker and the per-file bundle objects), so history
 * lists only real bundle versions. */
function isReservedSiteVersion(version: string): boolean {
  return (
    version === SITE_MANIFEST_VERSION ||
    version.startsWith(`${SITE_FILE_VERSION_PREFIX}:`)
  );
}

/** The set of bundle versions that have retained per-file objects, extracted
 * from the registry's `__site_file__:{version}:{path}` rows. Only these bare
 * versions are real #397 rollback targets; a legacy pre-#397 file row (whose
 * `version` IS a bare file path like `index.html`) has no such companion and is
 * therefore excluded. */
function retainedBundleVersions(manifest: AssetManifest): Set<string> {
  const bundles = new Set<string>();
  const prefix = `${SITE_FILE_VERSION_PREFIX}:`;
  for (const entry of manifest.versions) {
    if (!entry.version.startsWith(prefix)) continue;
    // `__site_file__:{version}:{path}` — the version ends at the first colon
    // after the prefix (bundle versions carry no colon, same as the gateway).
    const rest = entry.version.slice(prefix.length);
    const boundary = rest.indexOf(":");
    if (boundary > 0) bundles.add(rest.slice(0, boundary));
  }
  return bundles;
}

/** One retained bundle version, joined for the history table. */
interface BundleVersionRow {
  version: string;
  yanked: boolean;
  /** Publish time (unix seconds) of the bundle manifest row, when the asset
   * listing carries it; `undefined` if the row has not loaded yet. */
  publishedAtUnix: number | undefined;
  /** True when the `serving` channel currently points at this version. */
  active: boolean;
}

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

/** Publish response body the gateway returns for a `static_site` ZIP push.
 * Sourced from the generated OpenAPI contract (#446) rather than hand-declared,
 * so it stays pinned to the gateway's actual response shape. */
type StaticSitePublishResponse = AdminSchema<"StaticSitePublishResponse">;

/** The OTHER 200 the same publish PUT can answer: the ordinary single-blob
 * asset push envelope. See `PublishEnvelope`. */
type AssetMutationResponse = AdminSchema<"AssetMutationResponse">;

/** One withheld (pending_scan / quarantined) asset row, used to explain WHY a
 * publish fell through to the blob store instead of committing a bundle. */
type WithheldAssetSummary = AdminSchema<"WithheldAssetSummary">;

/**
 * THE PUBLISH PUT HAS TWO DIFFERENT 200 ENVELOPES, AND ONLY ONE OF THEM IS A
 * PUBLISH. The gateway takes the site-bundle path only when ALL THREE of
 * `asset_type == "static_site"`, `is_zip_archive(body)` and
 * `screening.is_visible()` hold (assets.rs:653); otherwise the request falls
 * THROUGH to the ordinary opaque-blob asset store, which answers **200** with
 * `AssetMutationResponse` — a completely different shape that carries no
 * `site`, `file_count` or `size_bytes`.
 *
 * Both fallthroughs are reachable from this form:
 *   1. a body that is not a real ZIP (a corrupt or wrong file the operator
 *      named `.zip`), and
 *   2. a bundle whose supply-chain screening came back pending/quarantined,
 *      which #366 DELIBERATELY stores withheld rather than rejecting, so the
 *      site is never served before it is proven clean.
 *
 * In both cases nothing was deployed and the site keeps serving its previous
 * bundle — so treating any 2xx as a publish printed
 * `Published undefined (undefined files, NaN)` over a deployment that never
 * happened. `object` is the `@constant` discriminator the contract gives us for
 * exactly this, so the publish is narrowed on it and anything else is routed to
 * the failure path (#345 box 3: the UI states the ACTUAL outcome).
 */
type PublishEnvelope = StaticSitePublishResponse | AssetMutationResponse;

/** True only for the envelope that means a site bundle was actually committed.
 * Written defensively against `unknown` because the transport hands back
 * whatever the gateway serialized (including `null` for an unparseable body),
 * not a value TypeScript has checked. */
function isBundleCommit(body: unknown): body is StaticSitePublishResponse {
  return (
    typeof body === "object" &&
    body !== null &&
    (body as { object?: unknown }).object === "static_site"
  );
}

/** The generated `putAsset` operation the gateway routes static-site publishes
 * through: a `static_site` `asset_type` whose body is a ZIP archive branches
 * into the bundle-publish path (there is no separate gateway route). The publish
 * call below derives its URL, path params, and `x-site-*`/visibility header
 * NAMES from this typed operation instead of hand-encoding them (#446, #338). */
const PUBLISH_PATH = "/v1/assets/{asset_type}/{name}/{version}" as const;
type PublishOp = OpFor<typeof PUBLISH_PATH, "put">;
type PublishHeaders = HeaderParamsFor<PublishOp>;

/** The bundle a site ACTUALLY serves right now, plus the registry manifest the
 * resolution went through (so the version history and the unpublish purge work
 * off the same single read). */
interface ActiveSiteBundle {
  /** Asset registry manifest: channels + every retained version row. */
  registry: AssetManifest;
  /** Version the `serving` channel points at. `undefined` for a legacy site
   * (published before #397) that has no `serving` channel — such a site serves
   * from the mutable marker, which is then also what we display. */
  servingVersion: string | undefined;
  /** Manifest of the SERVED bundle (policy + file tree); `undefined` when that
   * row could not be read — see `manifestError`. */
  manifest: SiteManifest | undefined;
  /** Why the served bundle's manifest could not be read, if it could not. The
   * REGISTRY read is what fails the query outright; a manifest failure is
   * carried instead of thrown so the row still knows its stored versions, and
   * so an operator can still open the drawer and purge a site whose manifest
   * row is gone or corrupt. */
  manifestError: Error | undefined;
}

/** One published site's fully-joined row (list + served bundle + domains). */
interface SiteRow {
  name: string;
  /** Manifest of the bundle currently SERVED (never the stale marker for a
   * #397 site) — see the module header. */
  manifest: SiteManifest | undefined;
  /** Version the `serving` channel resolves to; `undefined` for a legacy site
   * or while the read is in flight. */
  servingVersion: string | undefined;
  /** Registry manifest (channels + retained versions) behind that resolution. */
  registry: AssetManifest | undefined;
  manifestLoading: boolean;
  manifestError: Error | undefined;
  domains: SiteDomain[];
  serveUrl: string;
  /** Every `static_site` asset row for this site from the tenant listing, used
   * to date each retained bundle version in the history table. */
  assetVersions: AssetSummary[];
}

const ASSETS_QUERY_KEY = ["assets"] as const;
const SITE_DOMAINS_QUERY_KEY = ["site-domains"] as const;

/** React-query key for one site's active-bundle resolution. Shared by the list
 * and the drawer so both render the same served bundle from one read. */
function siteBundleQueryKey(site: string) {
  return ["static-site-active-bundle", site] as const;
}

/** Asset-object path for ONE stored row of a site: a bundle-version manifest,
 * the reserved `__site_manifest__` marker, or an individual published file
 * (whose bare `{path}` the gateway remaps onto the ACTIVE bundle). Kept as a
 * manually-encoded string (not the typed `params` client) so it lines up
 * byte-for-byte with the publish/unpublish addressing in this module. */
function siteObjectPath(site: string, versionOrPath: string): string {
  return `/v1/assets/${STATIC_SITE_TYPE}/${encodeURIComponent(site)}/${encodeURIComponent(versionOrPath)}`;
}

/**
 * Resolves the bundle a site actually serves, mirroring the gateway's
 * `resolve_active_site_bundle` (sites.rs) step for step so the console reads
 * exactly what serve-mode reads (write-path == read-path, #188):
 *   1. read the asset REGISTRY manifest (channels + retained versions);
 *   2. take the version the well-known `serving` channel points at;
 *   3. read THAT bundle's immutable manifest row.
 * A site with no `serving` channel is a legacy (pre-#397) site whose serve path
 * falls back to the mutable `__site_manifest__` marker — so we read the marker
 * too, and only then. The two reads are inherently dependent (step 3 needs the
 * channel target), but sites resolve in parallel with each other.
 *
 * The gateway serves a manifest row as its stored JSON body, so a plain JSON GET
 * parses it regardless of the stored content type.
 */
async function fetchActiveSiteBundle(
  apiKey: string,
  site: string,
): Promise<ActiveSiteBundle> {
  const registry = await adminGet(
    apiKey,
    "/v1/assets/{asset_type}/{name}/manifest",
    { params: { asset_type: STATIC_SITE_TYPE, name: site } },
  );
  const servingVersion = registry.channels.find(
    (channel) => channel.channel === SITE_SERVE_CHANNEL,
  )?.version;
  try {
    const manifest = await gatewayGet<SiteManifest>(
      apiKey,
      siteObjectPath(site, servingVersion ?? SITE_MANIFEST_VERSION),
    );
    return { registry, servingVersion, manifest, manifestError: undefined };
  } catch (error) {
    return {
      registry,
      servingVersion,
      manifest: undefined,
      manifestError: error instanceof Error ? error : new Error(String(error)),
    };
  }
}

/**
 * Runs one stage of the unpublish purge concurrently and REPORTS which deletes
 * failed, instead of `Promise.all`'s abandon-at-first-rejection: with `all`, one
 * 409 both hides which siblings actually ran and skips every stage after it, so
 * the caller can neither describe nor finish the purge. Returns one
 * `"{row}: {verdict}"` line per failure, empty when the stage fully applied.
 */
async function settleDeletes(
  deletes: { label: string; run: () => Promise<unknown> }[],
): Promise<string[]> {
  const results = await Promise.allSettled(deletes.map((entry) => entry.run()));
  return results.flatMap((result, index) => {
    if (result.status !== "rejected") return [];
    const reason: unknown = result.reason;
    const message = reason instanceof Error ? reason.message : String(reason);
    return [`${deletes[index].label}: ${message}`];
  });
}

/** Total stored bytes across a manifest's files. */
function manifestBytes(manifest: SiteManifest): number {
  return manifest.files.reduce((sum, file) => sum + file.size_bytes, 0);
}

/** First 12 hex chars of a content hash, ellipsized (mirrors the Assets page). */
function shortHash(hash: string): string {
  return `${hash.slice(0, 12)}…`;
}

/** PUT target that moves the `serving` channel of `site` to `version`. Kept as a
 * manually-encoded string (not the typed `params` client) so it lines up with
 * the asset-object addressing the rest of this module uses, and mirrors the
 * channel-move URL the Assets page issues (`.../channels/{channel}?version=`).
 * Moving this channel is the truthful rollback: serve-mode resolves the active
 * bundle through it, so the served bytes actually change (#397 / #188). */
function serveChannelPath(site: string, version: string): string {
  return `/v1/assets/${STATIC_SITE_TYPE}/${encodeURIComponent(site)}/channels/${encodeURIComponent(SITE_SERVE_CHANNEL)}?version=${encodeURIComponent(version)}`;
}

/** Maps a rollback (channel-move) failure to a clear localized message. The
 * gateway rejects an unresolvable target — a version that was yanked or removed
 * out from under the move — with 404 (gone) or 409/400 (the CAS could not
 * resolve it); those get specific, version-named copy so the operator knows the
 * served bundle is unchanged. Anything else is surfaced verbatim. */
function rollbackErrorMessage(
  t: ReturnType<typeof useI18n>["t"],
  error: unknown,
  version: string,
): string {
  if (error instanceof ApiError) {
    if (error.status === 404)
      return t("page.staticSites.rollback.notFound", { version });
    if (error.status === 409 || error.status === 400)
      return t("page.staticSites.rollback.unresolvable", { version });
  }
  const message = error instanceof Error ? error.message : String(error);
  return t("page.staticSites.rollback.failed", { message });
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

// The client-side archive check (`readsAsZipArchive`, the gateway's own
// `PK\x03\x04` predicate) lives in lib/zip-archive.ts so tests other than this
// page's can run it — notably lib/zip-archive.test.ts, which runs it over the
// byte fixtures e2e/static-sites.spec.ts uploads. Tightening this gate is what
// silently invalidated those fixtures once; a shared predicate is what lets a
// unit test catch the next one.

/**
 * Explains a publish PUT that answered 200 WITHOUT committing a site bundle,
 * for the operator-facing failure message. Never guesses: the reason is read
 * back from the gateway, and when it cannot be read the message says so.
 *
 * The gateway's fallthrough condition is `!is_zip_archive(body) ||
 * !screening.is_visible()` (assets.rs:653), and a withheld verdict is DURABLE
 * on the stored row — so the operator-only withheld listing (#379) is the
 * authoritative answer to "was it withheld, or was it simply not a ZIP?". A row
 * for this exact `{name}/{version}` means screening withheld it and names the
 * state; its absence means the screening passed and the body was therefore not a
 * ZIP archive. If that read fails we report the outcome we DID observe (nothing
 * was published) and surface the unread reason verbatim, rather than picking one.
 *
 * ABSENCE ONLY MEANS ANYTHING IF WE SAW THE WHOLE ANSWER. Any non-empty query
 * puts this listing on the paginated branch (admin_list_query.rs:21-36) at
 * `admin_list_default_limit = 100`, and it is sorted by `(name, version)` —
 * alphabetically, NOT by recency (ferrogate-storage/src/lib.rs:4415-4440). So a
 * tenant with more withheld `static_site` rows than the page holds could have
 * this bundle's row sort past the cut, and reading absence as "not a ZIP" would
 * be exactly the guess the message claims never to make. Hence: narrow the query
 * with `search` (matched against id/name/version/asset_type/visibility) and ask
 * for the maximum page, then CHECK `total` against what came back and, if rows
 * were left behind, say the reason could not be determined instead of asserting
 * one.
 */
async function explainUncommittedPublish(
  t: ReturnType<typeof useI18n>["t"],
  apiKey: string,
  site: string,
  version: string,
): Promise<string> {
  let withheld: WithheldAssetSummary | undefined;
  let truncated = false;
  try {
    const listing = await adminGet(apiKey, "/v1/assets/withheld", {
      query: {
        asset_type: STATIC_SITE_TYPE,
        search: version,
        limit: WITHHELD_LOOKUP_LIMIT,
      },
    });
    withheld = listing.data.find(
      (row) => row.name === site && row.version === version,
    );
    // `total` is the pre-pagination count; the gateway clamps `limit` to
    // `storage.admin_list_max_limit`, so asking for the max is not a promise of
    // getting it. Fewer rows than `total` means rows we never saw.
    truncated = listing.total !== undefined && listing.data.length < listing.total;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return t("page.staticSites.notPublished.unknown", { site, version, message });
  }
  if (withheld) {
    return t("page.staticSites.notPublished.withheld", {
      site,
      version,
      state: t(
        withheld.visibility === "quarantined"
          ? "page.withheldAssets.visibility.quarantined"
          : "page.withheldAssets.visibility.pendingScan",
      ),
    });
  }
  if (truncated) {
    return t("page.staticSites.notPublished.inconclusive", { site, version });
  }
  return t("page.staticSites.notPublished.notArchive", { site, version });
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
 * Per-site detail drawer: the SERVED bundle's file tree (path, content type,
 * content hash, size), the retained bundle VERSION HISTORY (with a truthful
 * channel-move rollback), the site's bound custom domains with their live ACME
 * posture, plus the destructive Unpublish trigger.
 *
 * Everything here is derived from the ONE active-bundle resolution the list
 * already performed for this row (`fetchActiveSiteBundle`) — the served
 * bundle's manifest AND the registry manifest behind it. Sharing that single
 * read is what keeps the header ("Bundle X") and the history's Active badge
 * from contradicting each other: both name the version the `serving` channel
 * points at.
 */
function SiteDetailSheet({
  row,
  apiKey,
  tenantId,
  onClose,
  onUnpublish,
}: {
  row: SiteRow | null;
  apiKey: string;
  /** Session tenant that OWNS every listed site. A domain bind issued from this
   * drawer uses it verbatim, so a bind cannot target another tenant. */
  tenantId: string;
  onClose: () => void;
  onUnpublish: () => void;
}) {
  const { t, format } = useI18n();
  const queryClient = useQueryClient();
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
  // The prior version the operator has selected to roll back to, awaiting its
  // consequence-named confirmation; null when no rollback is armed.
  const [rollbackVersion, setRollbackVersion] = useState<string | null>(null);

  // Asset REGISTRY manifest (channels + versions) + the version the `serving`
  // channel points at: both come from the row's single active-bundle read, so
  // the history's Active badge and the header's bundle version cannot disagree.
  const registry = row?.registry;
  const registryLoading = row?.manifestLoading ?? false;
  // The history is unavailable only when the REGISTRY itself could not be read;
  // a failed served-bundle manifest leaves the retained versions perfectly
  // knowable (and is what lets an operator still purge such a site).
  const registryError =
    row !== null && row.registry === undefined ? row.manifestError : undefined;
  const servingVersion = row?.servingVersion;

  // Publish time per bundle version, from the tenant asset listing rows.
  const publishedAtByVersion = useMemo(() => {
    const map = new Map<string, number>();
    for (const asset of row?.assetVersions ?? []) {
      map.set(asset.version, asset.created_at_unix);
    }
    return map;
  }, [row?.assetVersions]);

  // Retained bundle versions, newest first, each marked active/yanked/dated.
  const bundleRows = useMemo<BundleVersionRow[]>(() => {
    if (!registry) return [];
    const retained = retainedBundleVersions(registry);
    return registry.versions
      .filter(
        (entry) =>
          !isReservedSiteVersion(entry.version) && retained.has(entry.version),
      )
      .map((entry) => ({
        version: entry.version,
        yanked: entry.yanked,
        publishedAtUnix: publishedAtByVersion.get(entry.version),
        active: entry.version === servingVersion,
      }))
      .sort((a, b) => {
        // Newest publish first; fall back to a stable version comparison when a
        // listing row has not dated a version yet.
        if (a.publishedAtUnix !== undefined && b.publishedAtUnix !== undefined)
          return b.publishedAtUnix - a.publishedAtUnix;
        if (a.publishedAtUnix !== undefined) return -1;
        if (b.publishedAtUnix !== undefined) return 1;
        return b.version.localeCompare(a.version);
      });
  }, [registry, publishedAtByVersion, servingVersion]);

  const rollbackMutation = useMutation({
    // Rollback IS a channel move: PUT the `serving` channel to the chosen prior
    // version. Serve-mode resolves the active bundle through that channel, so
    // this genuinely re-points the served bytes (#397 / #188), not an inert ack.
    mutationFn: (version: string) =>
      gatewayPut<AssetChannelMutationResponse>(
        apiKey,
        serveChannelPath(row!.name, version),
      ),
    onSuccess: (_result, version) => {
      toast.success(
        t("page.staticSites.rollback.success", { site: row!.name, version }),
      );
      setRollbackVersion(null);
      // The served version changed: re-resolve the active bundle (channel
      // pointer AND the served bundle's manifest, which is now a DIFFERENT row)
      // plus the tenant asset listing, so the list and drawer both re-derive.
      queryClient.invalidateQueries({ queryKey: siteBundleQueryKey(row!.name) });
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
    },
    onError: (error: unknown, version) =>
      toast.error(rollbackErrorMessage(t, error, version)),
  });

  // Custom-domain binding, integrated into THIS site's context (#345/#265).
  // The bind's tenant_id + site are taken from the site context — the session
  // tenant that owns the listing and this row's slug — so a bind from here can
  // never target another tenant or an unpublished site; the hostname is the only
  // free input, validated client-side for fast feedback while the gateway stays
  // authoritative and its ACME/reload posture is surfaced on success.
  const [bindHostname, setBindHostname] = useState("");
  const [bindError, setBindError] = useState<string | null>(null);
  const [bindAcmeNote, setBindAcmeNote] = useState<string | null>(null);
  const [pendingUnbind, setPendingUnbind] = useState<SiteDomain | null>(null);

  // Per-binding detail read for EVERY bound hostname, not just one bound in this
  // session. The list endpoint (`GET /admin/v1/site-domains`) carries no ACME
  // field and no `verification` block, so both come from each binding's own
  // detail read (`GET /admin/v1/site-domains/{hostname}` -> `acme` +
  // `verification`, site_domains.rs). Read in parallel while the drawer is open;
  // a read that has not landed or that failed prints "Unknown" rather than
  // asserting a posture we do not know.
  const domainDetailQueries = useQueries({
    queries: (row?.domains ?? []).map((domain) => ({
      queryKey: ["site-domain-detail", domain.hostname] as const,
      queryFn: () =>
        adminGet(apiKey, "/admin/v1/site-domains/{hostname}", {
          params: { hostname: domain.hostname },
        }),
    })),
  });
  const detailByHostname = new Map(
    (row?.domains ?? []).map((domain, index) => [
      domain.hostname,
      domainDetailQueries[index]?.data,
    ]),
  );
  /**
   * The gateway reports a binding's LIVENESS on every `AdminSiteDomain` it
   * serializes — the listing row we already hold AND the detail read — so both
   * are consulted, freshest first. `serving` answers "is this hostname live?";
   * `verification_state` says why. Consuming only `acme.enabled` (what this used
   * to do) renders a hostname the gateway REFUSES exactly like a live one.
   */
  function livenessOf(domain: SiteDomain) {
    const detail = detailByHostname.get(domain.hostname);
    return {
      acme: detail?.acme.enabled,
      serving: detail?.site_domain.serving ?? domain.serving,
      verificationState:
        detail?.site_domain.verification_state ?? domain.verification_state,
    };
  }
  // The TXT records still to be published. Only a pending binding has one to
  // act on, and only the detail read carries it.
  const pendingChallenges = (row?.domains ?? []).flatMap((domain) => {
    const detail = detailByHostname.get(domain.hostname);
    const verification = detail?.verification;
    if (!verification || verification.state !== "pending_verification") return [];
    return [verification];
  });

  const hostnameCheck =
    bindHostname.trim() === "" ? null : validateSiteDomainHostname(bindHostname);
  const hostnameInvalid = hostnameCheck !== null && hostnameCheck.error !== null;

  const bindMutation = useMutation({
    mutationFn: (hostname: string) =>
      adminPost(apiKey, "/admin/v1/site-domains", {
        hostname,
        tenant_id: tenantId,
        site: row!.name,
      }),
    onSuccess: (response) => {
      // Qualified by THIS hostname's enrolment, not by the gateway-wide ACME
      // flag: a binding the gateway answered 202 for is recorded but unproven,
      // and it is deliberately excluded from the certificate order set.
      const acmeNote = t(bindAcmeNoteKey(response));
      // Keep the ACME posture visible in the drawer (not just a transient toast).
      setBindAcmeNote(acmeNote);
      setBindHostname("");
      setBindError(null);
      toast.success(
        t("page.siteDomains.toast.bound", {
          hostname: response.site_domain.hostname,
          note: acmeNote,
        }),
      );
      queryClient.invalidateQueries({ queryKey: SITE_DOMAINS_QUERY_KEY });
    },
    // Surface the gateway verdict verbatim (e.g. hostname already bound, or a
    // bind targeting a site the tenant does not own).
    onError: (error: Error) => {
      setBindError(error.message);
      toast.error(error.message);
    },
  });

  const unbindMutation = useMutation({
    mutationFn: (target: SiteDomain) =>
      adminDelete(apiKey, "/admin/v1/site-domains/{hostname}", {
        params: { hostname: target.hostname },
      }),
    onSuccess: (_result, target) => {
      toast.success(
        t("page.siteDomains.toast.unbound", { hostname: target.hostname }),
      );
      setPendingUnbind(null);
      queryClient.invalidateQueries({ queryKey: SITE_DOMAINS_QUERY_KEY });
    },
    onError: (error: Error) => {
      toast.error(error.message);
      setPendingUnbind(null);
    },
  });

  function submitBind() {
    setBindError(null);
    const check = validateSiteDomainHostname(bindHostname);
    if (check.error !== null) {
      setBindError(check.error);
      return;
    }
    bindMutation.mutate(check.hostname);
  }

  async function handleFileDownload(entry: SiteFileEntry) {
    if (!row) return;
    setDownloadingPath(entry.path);
    try {
      // Address the file by its BARE bundle path: the gateway remaps that onto
      // the ACTIVE bundle (sites.rs `resolve_site_asset_version`). Because the
      // tree above is now the active bundle's own manifest, the bytes that come
      // back are the ones whose hash/size sit beside the button.
      const blob = await gatewayGetBinary(apiKey, siteObjectPath(row.name, entry.path));
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

            {/* Version history + truthful channel-move rollback. The `serving`
              channel resolves what serve-mode returns, so rolling it back to a
              retained prior version actually changes the served bytes (#397). */}
            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-semibold">
                {t("page.staticSites.history.title")}
              </h3>
              <p className="text-xs text-muted-foreground">
                {t("page.staticSites.history.description")}
              </p>
              {registryError ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {t("page.staticSites.history.unavailable")}
                </p>
              ) : registryLoading || !registry ? (
                <p className="text-sm text-muted-foreground">
                  {t("resource.table.loading")}
                </p>
              ) : bundleRows.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t("page.staticSites.history.empty")}
                </p>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t("page.assets.col.version")}</TableHead>
                        <TableHead>{t("page.staticSites.col.published")}</TableHead>
                        <TableHead>{t("page.staticSites.col.access")}</TableHead>
                        <TableHead className="w-32">
                          {t("resource.table.actionsColumn")}
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {bundleRows.map((bundle) => (
                        <TableRow
                          key={bundle.version}
                          data-testid={`static-site-version-${bundle.version}`}
                        >
                          <TableCell className="font-mono text-xs break-all">
                            {bundle.version}
                          </TableCell>
                          <TableCell className="text-xs">
                            {bundle.publishedAtUnix !== undefined
                              ? format.date(bundle.publishedAtUnix * 1000, {
                                  dateStyle: "medium",
                                  timeStyle: "short",
                                })
                              : "—"}
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {bundle.active ? (
                                <Badge variant="default">
                                  {t("page.staticSites.history.active")}
                                </Badge>
                              ) : null}
                              {bundle.yanked ? (
                                <Badge variant="destructive">
                                  {t("page.staticSites.history.yanked")}
                                </Badge>
                              ) : null}
                            </div>
                          </TableCell>
                          <TableCell>
                            {bundle.active ? (
                              <span className="text-xs text-muted-foreground">
                                {t("page.staticSites.history.servedNow")}
                              </span>
                            ) : (
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                // A yanked target is unresolvable, so the gateway
                                // would reject the move; disarm it up front.
                                disabled={bundle.yanked || rollbackMutation.isPending}
                                onClick={() => setRollbackVersion(bundle.version)}
                              >
                                {t("page.staticSites.rollback.action")}
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </section>

            {/* Custom domains, bound in THIS site's context. tenant_id + site
              are fixed from the drawer's row, so the bind cannot cross tenants
              or target an unpublished site; the ACME + reload posture returned
              by the gateway stays visible after a successful bind. */}
            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-semibold">
                {t("page.staticSites.domains.title")}
              </h3>
              <p className="text-xs text-muted-foreground">
                {t("page.staticSites.domains.description", { site: row.name })}
              </p>

              {row.domains.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t("page.staticSites.domains.empty")}
                </p>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t("page.siteDomains.col.hostname")}</TableHead>
                        <TableHead>{t("page.siteDomains.col.servePath")}</TableHead>
                        <TableHead>{t("page.siteDomains.col.bound")}</TableHead>
                        <TableHead>{t("page.siteDomains.col.status")}</TableHead>
                        <TableHead>{t("page.staticSites.domains.acme")}</TableHead>
                        <TableHead className="w-24">
                          {t("resource.table.actionsColumn")}
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {row.domains.map((domain) => {
                        const liveness = livenessOf(domain);
                        return (
                        <TableRow
                          key={domain.hostname}
                          data-testid={`static-site-domain-${domain.hostname}`}
                        >
                          <TableCell className="font-medium">
                            {domain.hostname}
                          </TableCell>
                          <TableCell className="font-mono text-xs break-all">
                            {domain.serve_path}
                          </TableCell>
                          <TableCell className="text-xs">
                            {format.date(domain.created_at_unix * 1000, {
                              dateStyle: "medium",
                              timeStyle: "short",
                            })}
                          </TableCell>
                          {/* Does this hostname actually SERVE, and if not, why?
                            A bound timestamp alone says nothing: post-#488 a
                            binding is refused until its DNS ownership proof
                            resolves, so omitting this rendered an unhealthy
                            state as implicitly healthy. */}
                          <TableCell>
                            <SiteDomainLiveness
                              serving={liveness.serving}
                              verificationState={liveness.verificationState}
                            />
                          </TableCell>
                          {/* Live ACME posture for THIS binding, however long
                            ago it was bound. Unknown until its detail read
                            lands (or if it failed) — never a guessed posture. */}
                          <TableCell className="text-xs">
                            {liveness.acme === undefined
                              ? t("common.unknown")
                              : liveness.acme
                                ? t("page.staticSites.acme.enabled")
                                : t("page.staticSites.acme.disabled")}
                          </TableCell>
                          <TableCell>
                            <Button
                              type="button"
                              variant="destructive"
                              size="sm"
                              onClick={() => setPendingUnbind(domain)}
                            >
                              {t("page.siteDomains.unbind")}
                            </Button>
                          </TableCell>
                        </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}

              {/* A pending binding has exactly one thing the operator must do:
                publish the challenge TXT record the gateway issued. Reporting
                "not serving" while withholding the remedy would be half an
                answer. */}
              {pendingChallenges.map((verification) => (
                <SiteDomainChallenge
                  key={verification.hostname}
                  verification={verification}
                />
              ))}

              {/* ACME posture from the last successful bind, kept visible in the
                drawer (an aria-live status, not just a transient toast). */}
              {bindAcmeNote ? (
                <p
                  role="status"
                  className="rounded-md border border-primary/40 bg-primary/5 px-3 py-2 text-xs text-muted-foreground"
                >
                  {bindAcmeNote}
                </p>
              ) : null}

              <form
                className="flex flex-col gap-1.5"
                onSubmit={(event) => {
                  event.preventDefault();
                  submitBind();
                }}
              >
                <Label htmlFor="site-domain-hostname">
                  {t("page.siteDomains.field.hostname")}
                </Label>
                <div className="flex flex-wrap items-start gap-2">
                  <Input
                    id="site-domain-hostname"
                    value={bindHostname}
                    onChange={(event) => {
                      setBindHostname(event.target.value);
                      setBindError(null);
                    }}
                    // eslint-disable-next-line ferrogate/no-untranslated-literal -- example FQDN, identical across locales
                    placeholder="app.example.com"
                    aria-invalid={hostnameInvalid}
                    aria-describedby="site-domain-hostname-hint"
                    className="max-w-xs"
                  />
                  <Button
                    type="submit"
                    disabled={
                      bindMutation.isPending ||
                      hostnameInvalid ||
                      bindHostname.trim() === ""
                    }
                  >
                    {bindMutation.isPending
                      ? t("page.siteDomains.bind.submitting")
                      : t("page.siteDomains.bind.submit")}
                  </Button>
                </div>
                {hostnameCheck?.error ? (
                  <p
                    id="site-domain-hostname-hint"
                    role="alert"
                    className="text-xs text-destructive"
                  >
                    {hostnameCheck.error}
                  </p>
                ) : bindError ? (
                  <p
                    id="site-domain-hostname-hint"
                    role="alert"
                    className="text-xs text-destructive"
                  >
                    {bindError}
                  </p>
                ) : (
                  <p
                    id="site-domain-hostname-hint"
                    className="text-xs text-muted-foreground"
                  >
                    {t("page.siteDomains.field.hostname.hint")}
                  </p>
                )}
              </form>
            </section>

            {/* Unbind confirmation for a domain bound to THIS site. */}
            <AlertDialog
              open={pendingUnbind !== null}
              onOpenChange={(open) => !open && setPendingUnbind(null)}
            >
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    {t("page.siteDomains.unbind.title", {
                      hostname: pendingUnbind?.hostname ?? "",
                    })}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {t("page.siteDomains.unbind.description", {
                      target: `${pendingUnbind?.tenant_id ?? ""}/${pendingUnbind?.site ?? ""}`,
                    })}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>
                    {t("resource.action.cancel")}
                  </AlertDialogCancel>
                  <AlertDialogAction
                    onClick={(event) => {
                      event.preventDefault();
                      if (pendingUnbind) unbindMutation.mutate(pendingUnbind);
                    }}
                  >
                    {t("page.siteDomains.unbind")}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>

            <SheetFooter className="mt-auto">
              <Button
                type="button"
                variant="destructive"
                onClick={onUnpublish}
                // Gated on the REGISTRY, not the served manifest: a site whose
                // manifest row is gone or corrupt is exactly the one an
                // operator most needs to be able to purge.
                disabled={registry === undefined}
              >
                {t("page.staticSites.unpublish.action")}
              </Button>
              <Button type="button" variant="outline" onClick={onClose}>
                {t("common.close")}
              </Button>
            </SheetFooter>

            {/* Rollback confirmation — names the exact target version and spells
              out the consequence (the served bundle changes at once) before it
              moves the `serving` channel. */}
            <Dialog
              open={rollbackVersion !== null}
              onOpenChange={(next) => {
                if (!next) setRollbackVersion(null);
              }}
            >
              <DialogContent className="sm:max-w-lg">
                {rollbackVersion !== null ? (
                  <>
                    <DialogHeader>
                      <DialogTitle>
                        {t("page.staticSites.rollback.title", {
                          version: rollbackVersion,
                        })}
                      </DialogTitle>
                      <DialogDescription>
                        {t("page.staticSites.rollback.body", {
                          site: row.name,
                          version: rollbackVersion,
                        })}
                      </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setRollbackVersion(null)}
                      >
                        {t("common.cancel")}
                      </Button>
                      <Button
                        type="button"
                        onClick={() => rollbackMutation.mutate(rollbackVersion)}
                        disabled={rollbackMutation.isPending}
                      >
                        {t("page.staticSites.rollback.confirm")}
                      </Button>
                    </DialogFooter>
                  </>
                ) : null}
              </DialogContent>
            </Dialog>
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
  // Label for the read-only publish-target tenant: the session tenant is the
  // ONLY tenant a publish from this console can land in (the publish path
  // carries no tenant; the gateway takes it from the API key).
  const tenantName = session!.tenant.name || tenantId;
  const queryClient = useQueryClient();

  // The site/version selection and the open site are mirrored to the URL
  // (#345) so a selection is a shareable DIRECT LINK: a deep link seeds these on
  // mount, and edits write through. Local state stays the immediate source for
  // snappy text input; `updateParam` writes the change back with `replace` so it
  // never spams history. Volatile publish inputs (the file, the policy toggles,
  // the Cache-Control override) stay local — they are not linkable selections.
  const [searchParams, setSearchParams] = useSearchParams();
  const updateParam = useCallback(
    (key: string, value: string | null) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (value === null || value === "") next.delete(key);
          else next.set(key, value);
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  // Publish form state (site/version seeded from + mirrored to the URL).
  const [site, setSiteState] = useState(() => searchParams.get("site") ?? "");
  const [version, setVersionState] = useState(
    () => searchParams.get("version") ?? "",
  );
  const [isPublic, setIsPublic] = useState(false);
  const [spaFallback, setSpaFallback] = useState(false);
  const [cacheControl, setCacheControl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  // True while the picked bundle's magic bytes are being read. Publishing is
  // held during it so the operator cannot beat the check to the button and
  // upload a bundle we have not yet formed a verdict on.
  const [archiveChecking, setArchiveChecking] = useState(false);
  // Reading the archive magic is async, so a fast second pick could otherwise
  // let the FIRST file's verdict land after it and describe the wrong file.
  // Each selection takes a ticket and only the current one may write state.
  const archiveCheckRef = useRef(0);
  const [publishError, setPublishError] = useState<string | null>(null);
  // Real byte-level upload progress, fed by xhr.upload.onprogress.
  const [uploadProgress, setUploadProgress] = useState<{
    loaded: number;
    total: number;
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const setSite = useCallback(
    (value: string) => {
      setSiteState(value);
      updateParam("site", value);
    },
    [updateParam],
  );
  const setVersion = useCallback(
    (value: string) => {
      setVersionState(value);
      updateParam("version", value);
    },
    [updateParam],
  );

  // Detail drawer + unpublish, both keyed by site slug so they survive row
  // rebuilds (the joined rows re-derive on every manifest status change). The
  // open site is mirrored to the URL too, so a drawer is a direct link.
  const [detailSite, setDetailSiteState] = useState<string | null>(
    () => searchParams.get("detail"),
  );
  const setDetailSite = useCallback(
    (value: string | null) => {
      setDetailSiteState(value);
      updateParam("detail", value);
    },
    [updateParam],
  );
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

  // The tenant's static_site asset rows grouped by site slug. The keys are the
  // distinct site names; the values date each retained bundle version for the
  // detail drawer's version history (the flat listing carries created_at, which
  // the registry manifest does not).
  const assetVersionsBySite = useMemo(() => {
    const map = new Map<string, AssetSummary[]>();
    for (const row of assetData?.data ?? []) {
      if (row.asset_type !== STATIC_SITE_TYPE) continue;
      const bucket = map.get(row.name);
      if (bucket) bucket.push(row);
      else map.set(row.name, [row]);
    }
    return map;
  }, [assetData]);

  // Distinct site slugs = distinct `name` of the tenant's static_site assets.
  const siteNames = useMemo(
    () => [...assetVersionsBySite.keys()].sort((a, b) => a.localeCompare(b)),
    [assetVersionsBySite],
  );

  // One ACTIVE-BUNDLE resolution per site, all in parallel (no waterfall
  // BETWEEN sites). Each resolves the bundle the gateway actually serves the
  // same way serve-mode does — registry manifest -> `serving` channel -> that
  // bundle's manifest row — so the policy, file count, bytes and publish time in
  // this table describe the SERVED bundle, not whatever was published last.
  const bundleQueries = useQueries({
    queries: siteNames.map((name) => ({
      queryKey: siteBundleQueryKey(name),
      queryFn: () => fetchActiveSiteBundle(apiKey, name),
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

  // bundleQueries identity changes each render; depend on a derived signature
  // (status + resolved serving version) so rows only rebuild when a resolution
  // actually transitions or the served version moves.
  const bundleStatusSignature = bundleQueries
    .map((q) => `${q.status}:${q.data?.servingVersion ?? ""}`)
    .join(",");

  const rows = useMemo<SiteRow[]>(
    () =>
      siteNames.map((name, index) => {
        const query = bundleQueries[index];
        const domains = domainsBySite.get(name) ?? [];
        // Canonical serve URL: ALWAYS the tenant-scoped browse path. This used
        // to prefer `domains[0]?.serve_path`, which silently picked one of
        // several bound hostnames — and picked nothing useful anyway, since the
        // gateway computes `serve_path` as exactly this tenant path
        // (site_domains.rs `admin_site_domain`). Worse, a custom hostname is
        // NOT interchangeable with it: post-#488 the hostname only serves once
        // its DNS ownership proof resolves, so presenting one as "the canonical
        // URL" would advertise a link that may be refused. Bound hostnames and
        // their liveness are shown in the detail drawer's domain table instead.
        const serveUrl = `/sites/${tenantId}/${name}/`;
        return {
          name,
          manifest: query.data?.manifest,
          servingVersion: query.data?.servingVersion,
          registry: query.data?.registry,
          manifestLoading: query.isLoading,
          // A registry failure fails the whole resolution; a manifest-row
          // failure is carried on the result so the row keeps its registry.
          manifestError:
            (query.error as Error | undefined) ?? query.data?.manifestError,
          domains,
          serveUrl,
          assetVersions: assetVersionsBySite.get(name) ?? [],
        };
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      siteNames,
      domainsBySite,
      assetVersionsBySite,
      tenantId,
      bundleStatusSignature,
    ],
  );

  const detailRow = detailSite
    ? (rows.find((row) => row.name === detailSite) ?? null)
    : null;
  const unpublishRow = unpublishSite
    ? (rows.find((row) => row.name === unpublishSite) ?? null)
    : null;

  function resetForm() {
    setSiteState("");
    setVersionState("");
    setIsPublic(false);
    setSpaFallback(false);
    setCacheControl("");
    setFile(null);
    setArchiveError(null);
    // Invalidate any archive check still in flight so its verdict cannot land
    // on the cleared form and re-raise an error about a file that is gone.
    archiveCheckRef.current += 1;
    setArchiveChecking(false);
    setPublishError(null);
    setUploadProgress(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
    // Drop the mirrored site/version from the URL in a single navigation (the
    // tenant selection is kept so a subsequent publish stays in context).
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("site");
        next.delete("version");
        return next;
      },
      { replace: true },
    );
  }

  async function onFileChange(next: File | null) {
    const ticket = ++archiveCheckRef.current;
    setFile(next);
    setPublishError(null);
    if (!next) {
      setArchiveError(null);
      setArchiveChecking(false);
      return;
    }
    // Size is known synchronously; check it before reading any bytes.
    if (next.size > MAX_BUNDLE_BYTES) {
      setArchiveError(
        t("page.staticSites.validation.tooLarge", {
          max: format.bytes(MAX_BUNDLE_BYTES),
        }),
      );
      setArchiveChecking(false);
      return;
    }
    setArchiveError(null);
    setArchiveChecking(true);
    let isZip: boolean;
    try {
      isZip = await readsAsZipArchive(next);
    } catch {
      // The bytes could not be read at all, so we know nothing about them.
      // Let the upload proceed and let the gateway be the judge, exactly as
      // before this check existed — never block on an unproven suspicion.
      isZip = true;
    }
    if (ticket !== archiveCheckRef.current) return;
    setArchiveChecking(false);
    setArchiveError(isZip ? null : t("page.staticSites.validation.notZip"));
  }

  const publishMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error(t("page.staticSites.validation.bundleRequired"));
      // Derive the target URL + header NAMES from the generated `putAsset`
      // operation (the enforced OpenAPI client, #446) instead of hand-encoding
      // them: `resolveAdminPath` substitutes the typed path params (the same
      // encodeURIComponent the typed `admin*` helpers use), and the `x-site-*` /
      // visibility keys are checked against the operation's header parameters.
      // The XHR transport itself is retained ONLY for byte-level upload progress
      // (`fetch` exposes no upload-progress event) — see putBundleWithProgress.
      const path = resolveAdminPath(PUBLISH_PATH, {
        asset_type: STATIC_SITE_TYPE,
        name: site.trim(),
        version: version.trim(),
      } satisfies PathParamsFor<PublishOp>);
      const publishHeaders: Record<string, string | undefined> = {
        "x-site-public": isPublic ? "true" : undefined,
        "x-site-spa-fallback": spaFallback ? "true" : undefined,
        "x-site-cache-control": cacheControl.trim() || undefined,
        "x-asset-visibility": isPublic ? "public" : undefined,
      } satisfies Partial<Record<keyof PublishHeaders, string | undefined>>;
      const envelope = await putBundleWithProgress<PublishEnvelope | null>(
        apiKey,
        path,
        file,
        file.type || "application/zip",
        publishHeaders,
        (loaded, total) => setUploadProgress({ loaded, total }),
      );
      // A 2xx is NOT a publish. The gateway answers this same PUT with the
      // opaque-blob `AssetMutationResponse` envelope — still 200 — whenever the
      // body is not a real ZIP or screening withheld it, having committed no
      // manifest and no files; the site keeps serving its previous bundle. Only
      // the `static_site` envelope means a bundle was committed, so anything
      // else becomes a FAILURE carrying the gateway's own reason. Throwing here
      // routes it through the one `onError` path the verbatim gateway verdicts
      // already use, so the alert, the toast and the untouched form behave
      // identically to an outright rejection.
      if (!isBundleCommit(envelope)) {
        throw new Error(
          await explainUncommittedPublish(t, apiKey, site.trim(), version.trim()),
        );
      }
      return envelope;
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
      // A publish moves the `serving` channel to the new bundle, so re-resolve.
      queryClient.invalidateQueries({
        queryKey: siteBundleQueryKey(response.site),
      });
      resetForm();
    },
    // Surface the gateway verdict VERBATIM (scan / zip-bomb / quota / immutable).
    onError: (error: Error) => {
      setUploadProgress(null);
      setPublishError(error.message);
      toast.error(error.message);
    },
  });

  // Unpublish = purge EVERY stored row of the site, driven off the asset
  // registry manifest (the complete, authoritative row list for this
  // `(asset_type, name)`) rather than off the served bundle's file list.
  //
  // Deleting only the ACTIVE bundle's files plus the marker — what this used to
  // do — leaves a site that #397 retains: every prior bundle's
  // `__site_file__:{version}:{path}` objects, every bare `{bundle_version}`
  // bundle-manifest row, and the `serving` channel all survive. The site then
  // keeps appearing in `GET /v1/assets` forever (listed as "Manifest
  // unavailable") and its retained bytes keep counting against the tenant's
  // asset-storage quota — so the "Site unpublished" toast would be a lie.
  //
  // ORDER IS LOAD-BEARING: CHANNELS FIRST, then the version rows, then the
  // reserved marker. The gateway REFUSES the other order —
  // `delete_asset_variant_if_unreferenced` returns `BlockedByChannel` for the
  // last resolvable variant of a channel-referenced version, which
  // `handle_asset_delete` turns into 409 `asset_version_referenced` whose
  // message is literally "move or delete the channel first". Deleting versions
  // up front therefore 409s on exactly the served bundle, and (under a bare
  // `Promise.all`) abandons the channel + marker deletes mid-flight, leaving a
  // site that still lists, still bills, and now serves a manifest whose file
  // objects are gone. The marker goes LAST for the same reason it always did: a
  // partial failure must leave the site describable, not orphan objects behind
  // a manifest that is already gone.
  //
  // Every version row is addressed by its EXACT registry key, which the
  // gateway's bare-path remap (`resolve_site_asset_version`) passes through
  // untouched. Every DELETE is audit-logged by the assets registry.
  //
  // Each stage is `allSettled`, not `all`: one failed DELETE must not silently
  // decide which of its siblings ran. A stage that reports failures stops the
  // purge and surfaces an explicit PARTIAL state naming what failed, and the
  // registry is refetched so pressing Unpublish again re-drives the purge over
  // exactly the rows that are still there.
  const unpublishMutation = useMutation({
    mutationFn: async ({
      name,
      registry,
    }: {
      name: string;
      registry: AssetManifest;
    }) => {
      const deleteVersion = (version: string) =>
        adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/{version}", {
          params: { asset_type: STATIC_SITE_TYPE, name, version },
        });
      const deleteChannel = (channel: string) =>
        adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/channels/{channel}", {
          params: { asset_type: STATIC_SITE_TYPE, name, channel },
        });
      const versions = registry.versions
        .map((entry) => entry.version)
        .filter((version) => version !== SITE_MANIFEST_VERSION);
      const total = registry.channels.length + versions.length + 1;
      const halt = (failures: string[]): never => {
        throw new Error(
          t("page.staticSites.unpublish.partial", {
            site: name,
            failed: failures.length,
            total,
            message: failures.join("; "),
          }),
        );
      };

      // 1. The channels. `serving` is a separate stored pointer: leaving it
      //    would keep resolving (to a now-missing target) and would be
      //    re-adopted by a later publish of the same slug — and, until it is
      //    gone, the gateway will not let its target version be deleted.
      const channelFailures = await settleDeletes(
        registry.channels.map((channel) => ({
          label: channel.channel,
          run: () => deleteChannel(channel.channel),
        })),
      );
      if (channelFailures.length > 0) halt(channelFailures);

      // 2. Every version row — now unreferenced, so none of them 409.
      const versionFailures = await settleDeletes(
        versions.map((version) => ({
          label: version,
          run: () => deleteVersion(version),
        })),
      );
      if (versionFailures.length > 0) halt(versionFailures);

      // 3. The reserved marker, last.
      const markerFailures = await settleDeletes([
        {
          label: SITE_MANIFEST_VERSION,
          run: () => deleteVersion(SITE_MANIFEST_VERSION),
        },
      ]);
      if (markerFailures.length > 0) halt(markerFailures);
    },
    onSuccess: (_result, variables) => {
      toast.success(
        t("page.staticSites.unpublish.success", { site: variables.name }),
      );
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: SITE_DOMAINS_QUERY_KEY });
      queryClient.invalidateQueries({
        queryKey: siteBundleQueryKey(variables.name),
      });
      setUnpublishSite(null);
      setUnpublishConfirm("");
      setDetailSite(null);
    },
    // A partially-applied purge is the normal failure here, so refresh the row
    // list the retry walks (the already-deleted rows are gone from it) and keep
    // the confirm dialog open so the operator can immediately re-drive it.
    onError: (error: Error) => {
      toast.error(error.message);
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      if (unpublishSite)
        queryClient.invalidateQueries({
          queryKey: siteBundleQueryKey(unpublishSite),
        });
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
    // The bundle's own verdict is not in yet; publishing now would upload bytes
    // we have not checked. The button is disabled during the read, so this only
    // catches a programmatic submit.
    if (archiveChecking) return;
    publishMutation.mutate();
  }

  // The canonical serve path the bundle WILL be reachable at — always under the
  // session tenant, because that is where the gateway files the publish.
  const serveUrlPreview = `/sites/${tenantId}/${site.trim() || "{site}"}/`;
  const publishDisabled =
    publishMutation.isPending || archiveChecking || archiveError !== null;

  const progressFraction =
    uploadProgress && uploadProgress.total > 0
      ? uploadProgress.loaded / uploadProgress.total
      : 0;
  const progressPercent = Math.round(progressFraction * 100);

  // Exact site slug the operator must retype to arm the destructive unpublish.
  const unpublishNameMatches =
    unpublishSite !== null && unpublishConfirm === unpublishSite;
  // …and the registry row list the purge walks must have loaded, so the action
  // can never fire a partial delete set.
  const unpublishArmed =
    unpublishNameMatches && unpublishRow?.registry !== undefined;

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
            {/* Publish target tenant — READ-ONLY on purpose. The publish path
              is /v1/assets/{asset_type}/{name}/{version}: it carries no tenant,
              and the gateway takes the owning tenant from the API key
              (`auth.organization_id`, assets.rs). A tenant PICKER here would be
              inert — worse, it would drive the serve-URL preview below into
              naming a tenant the bundle does not publish to (the inert-control
              pattern #395 rejected for the project field). So we state the
              tenant the bundle will actually land in and let it be. */}
            <div className="grid gap-1.5">
              <Label htmlFor="site-tenant">{t("page.siteDomains.field.tenant")}</Label>
              <p
                id="site-tenant"
                className="rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm"
              >
                {tenantName}
              </p>
              <p className="text-xs text-muted-foreground">
                {t("page.staticSites.field.tenant.hint")}
              </p>
            </div>
            {/* Published-site selection, backed by the tenant's OWN published
              sites (the same `/v1/assets` enumeration this page's list is built
              from) rather than blind free text. It stays an input because a
              first publish must be able to name a slug that does not exist yet;
              the datalist turns the existing slugs into real, selectable
              suggestions for the republish case. */}
            <div className="grid gap-1.5">
              <Label htmlFor="site-slug">{t("page.siteDomains.field.site")}</Label>
              <Input
                id="site-slug"
                list="site-slug-options"
                value={site}
                onChange={(event) => setSite(event.target.value)}
                // eslint-disable-next-line ferrogate/no-untranslated-literal -- example site slug, identical across locales
                placeholder="marketing"
              />
              <datalist id="site-slug-options">
                {siteNames.map((name) => (
                  <option key={name} value={name} />
                ))}
              </datalist>
              <p className="text-xs text-muted-foreground">
                {t("page.staticSites.field.site.hint")}
              </p>
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
                  {/* `default` is a REAL policy claim (the gateway's built-in
                    Cache-Control when the manifest sets none), so it may only be
                    printed once a manifest has actually been read. While the
                    read is in flight or after it failed we know nothing about
                    the policy, and say so with the same em dash the sibling
                    cells use — asserting "default" there would be a lie
                    (#458/#464/#473). */}
                  <TableCell className="font-mono text-xs">
                    {row.manifest
                      ? (row.manifest.cache_control ??
                        t("page.staticSites.cache.default"))
                      : "—"}
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
                    {/* Openable as soon as the site's stored versions are
                      known — a site whose served manifest failed to read must
                      still be inspectable and unpublishable, not stranded. */}
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!row.registry}
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
        tenantId={tenantId}
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
                // The registry manifest is the row list the purge walks, so the
                // action is unavailable until it has actually loaded.
                if (unpublishArmed && unpublishRow?.registry)
                  unpublishMutation.mutate({
                    name: unpublishSite,
                    registry: unpublishRow.registry,
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
                  aria-invalid={unpublishConfirm !== "" && !unpublishNameMatches}
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
