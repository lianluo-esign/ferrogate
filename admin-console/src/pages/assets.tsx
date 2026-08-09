import { TruncatedCopyable } from "@/components/agent-ops/agent-ops-primitives";
import { ResourceTable } from "@/components/resource/resource-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { useOperatorError } from "@/hooks/use-operator-error";
import { type TranslationKey, useI18n } from "@/i18n";
import {
  type AdminSchema,
  PresignedUploadRejectedError,
  adminDelete,
  adminGet,
  adminPost,
  gatewayDelete,
  gatewayGetBinary,
  gatewayPost,
  gatewayPut,
  gatewayPutBinary,
  putPresignedObject,
} from "@/lib/gateway-client";
import { LocalizedError } from "@/lib/localized-error";
import type { ColumnConfig } from "@/lib/resource-config";
import { ApiError } from "@/types/auth";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
// Static-resource registry (issue #344). Rebuilds the former thin push/list/
// download/delete screen into a REGISTRY: a type/search/filter list of logical
// resources (an asset_type + name package, collapsed from the per-version
// GET /v1/assets rows) that opens a DETAIL dialog over the registry manifest —
// every version, platform variant, SHA-256, storage backend, and channel
// pointer (GET /v1/assets/{type}/{name}/manifest). From the detail the operator
// runs lifecycle actions that the thin page could not: yank / unyank a version
// (POST|DELETE .../{version}/yank), create / move / delete a channel pointer
// (PUT|DELETE .../channels/{channel}), download or copy a pull reference for a
// concrete variant, and permanently purge a version. Each destructive action
// names the exact resource, spells out its consequence, and — where the
// gateway's lifecycle invariants can block it (#367) — names the blocker BEFORE
// it fires, because a yank changes what every consumer resolves and a channel
// delete breaks pinned clients.
//
// Browse state (type filter, search, open resource, focused version) lives in
// the URL query (?type=&q=&rtype=&rname=&rver=) so a filtered view, an open
// detail panel, or a link to one version is shareable and survives a reload.
//
// Honesty rules this page holds to (#458/#464/#473):
//   * nothing renders a fabricated value for missing data — an unknown asset
//     type renders its raw identifier, an unmapped content type contributes no
//     file extension, and a quota that the summary did not return renders as
//     loading or as an alert rather than as a zero;
//   * no failure reads as success — a cancelled or failed presigned upload
//     never claims a publish, a partially-purged version reports exactly how
//     many variant rows were removed, and every mutation's error surfaces in
//     the dialog that fired it instead of a toast that vanishes.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";

type AssetSummary = AdminSchema<"AssetSummary">;
type AssetManifestVersion = AdminSchema<"AssetManifestVersion">;
type AssetManifestVariant = AssetManifestVersion["variants"][number];
type AssetChannelSummary = AdminSchema<"AssetChannelSummary">;

// Asset-type option values map to their catalog label key; labels resolve
// through `t()` at render so the picker localizes with the console.
const ASSET_TYPES: { value: string; labelKey: TranslationKey }[] = [
  { value: "cli_tool", labelKey: "page.assets.type.cliTool" },
  { value: "mcp_manifest", labelKey: "page.assets.type.mcpManifest" },
  { value: "skill_bundle", labelKey: "page.assets.type.skillBundle" },
  { value: "static_site", labelKey: "page.assets.type.staticSite" },
  { value: "config_file", labelKey: "page.assets.type.configFile" },
];
const ALL_TYPES = "__all__";
const ASSETS_QUERY_KEY = ["assets"] as const;
const ASSET_STORAGE_SUMMARY_QUERY_KEY = ["asset-storage-summary"] as const;
/** Fraction of the quota above which the storage card raises quota pressure. */
const QUOTA_PRESSURE_RATIO = 0.9;

type Translate = ReturnType<typeof useI18n>["t"];

/**
 * Localized label for a built-in asset type, or the raw identifier for a type
 * the console does not know. The gateway's `asset_type` is an open string
 * (custom families are allowed), so inventing a prettified label for one would
 * fabricate a name the API never used — the raw identifier is the honest
 * rendering, and the catalog covers the five built-ins.
 */
function assetTypeLabel(t: Translate, assetType: string): string {
  const option = ASSET_TYPES.find((entry) => entry.value === assetType);
  return option ? t(option.labelKey) : assetType;
}

/** A logical registry package: one row per (asset_type, name), all versions. */
type LogicalResource = {
  key: string;
  assetType: string;
  name: string;
  versionCount: number;
  latestVersion: string;
  createdAtUnix: number;
  updatedAtUnix: number;
  storageBacked: boolean;
};

/**
 * Composite map key for an (asset_type, name) pair.
 *
 * A JSON-encoded array, NOT a delimiter character. Asset types and names are
 * free-form tenant strings, so any single separator can appear inside one of
 * them and collide two distinct resources into one registry row. The previous
 * key used a literal NUL byte for exactly that reason — which made this file
 * binary to git, so no diff of the page was reviewable and every repo-wide
 * grep silently skipped it (#487). `JSON.stringify` is injective over string
 * tuples (it escapes the quotes and backslashes that could forge a boundary),
 * so it is collision-free AND leaves the file text.
 */
function compositeKey(...parts: string[]): string {
  return JSON.stringify(parts);
}

function assetPath(assetType: string, name: string, version: string): string {
  return `/v1/assets/${encodeURIComponent(assetType)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

function shortHash(hash: string): string {
  return `${hash.slice(0, 12)}…`;
}

/**
 * File extension for a stored content type, or "" when the mapping is unknown.
 *
 * Only content types the gateway actually records for assets are mapped. An
 * unknown type contributes NO extension rather than a guessed one: naming a
 * download `foo.bin` when the bytes are a tarball is a fabricated fact about
 * the payload, and the operator can always rename a file the console left
 * unsuffixed.
 */
const EXTENSION_BY_CONTENT_TYPE: Readonly<Record<string, string>> = {
  "application/gzip": ".tar.gz",
  "application/x-gzip": ".tar.gz",
  "application/x-tar": ".tar",
  "application/zip": ".zip",
  "application/json": ".json",
  "application/yaml": ".yaml",
  "application/x-yaml": ".yaml",
  "text/yaml": ".yaml",
  "text/plain": ".txt",
  "text/markdown": ".md",
  "application/wasm": ".wasm",
};

function downloadExtension(contentType: string): string {
  const base = contentType.split(";")[0].trim().toLowerCase();
  return EXTENSION_BY_CONTENT_TYPE[base] ?? "";
}

/**
 * The `ferrogate assets pull` invocation that fetches this exact artifact.
 *
 * Mirrors the real CLI surface (crates/ferrogate-cli/src/cli.rs
 * `AssetsIdentityArgs`): `--type`, `--name`, `--version` (an exact version, a
 * channel, or a semver range) and the optional `--platform` variant selector.
 * `--version` therefore accepts a channel name verbatim, which is what makes
 * the channel rows' reference correct as well.
 */
function pullReference(
  assetType: string,
  name: string,
  versionOrChannel: string,
  variant = "",
): string {
  const platform = variant === "" ? "" : ` --platform ${variant}`;
  return `ferrogate assets pull --type ${assetType} --name ${name} --version ${versionOrChannel}${platform}`;
}

/** Lowercase hex SHA-256 of the bytes, computed client-side via WebCrypto. */
async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Presigned-upload phases, in the order the flow drives them. */
type UploadPhase = "idle" | "hashing" | "registering" | "uploading" | "committing";

const UPLOAD_PHASE_PROGRESS: Record<UploadPhase, number> = {
  idle: 0,
  hashing: 15,
  registering: 35,
  uploading: 65,
  committing: 90,
};

const UPLOAD_PHASE_KEY: Record<Exclude<UploadPhase, "idle">, TranslationKey> = {
  hashing: "page.assets.presign.phaseHashing",
  registering: "page.assets.presign.phaseRegistering",
  uploading: "page.assets.presign.phaseUploading",
  committing: "page.assets.presign.phaseCommitting",
};

/**
 * True for the `AbortError` `fetch` rejects with once its signal aborts.
 *
 * Tested structurally, not with `instanceof Error`: the rejection is a
 * `DOMException`, which does not extend `Error` in every realm the console runs
 * in (it does not under jsdom). Getting that wrong makes a cancellation render
 * as "Upload failed", i.e. reports an operator's own deliberate action as a
 * system failure.
 */
function isAbortError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { name?: unknown }).name === "AbortError"
  );
}

/** Collapses the flat per-version list into logical (type, name) packages. */
function groupResources(rows: AssetSummary[]): LogicalResource[] {
  const buckets = new Map<string, AssetSummary[]>();
  for (const row of rows) {
    const key = compositeKey(row.asset_type, row.name);
    const bucket = buckets.get(key);
    if (bucket) bucket.push(row);
    else buckets.set(key, [row]);
  }
  const resources: LogicalResource[] = [];
  for (const [key, versions] of buckets) {
    let latest = versions[0];
    let createdAtUnix = versions[0].created_at_unix;
    let storageBacked = false;
    for (const row of versions) {
      if (row.updated_at_unix > latest.updated_at_unix) latest = row;
      if (row.created_at_unix < createdAtUnix) createdAtUnix = row.created_at_unix;
      if (row.storage_backed) storageBacked = true;
    }
    resources.push({
      key,
      assetType: latest.asset_type,
      name: latest.name,
      versionCount: versions.length,
      latestVersion: latest.version,
      createdAtUnix,
      updatedAtUnix: latest.updated_at_unix,
      storageBacked,
    });
  }
  resources.sort((a, b) =>
    a.assetType === b.assetType
      ? a.name.localeCompare(b.name)
      : a.assetType.localeCompare(b.assetType),
  );
  return resources;
}

/**
 * The message an operator must read for a failed mutation, VERBATIM from the
 * gateway, with the machine-readable error code kept alongside it. The code is
 * what the lifecycle docs key their remedies on (`asset_version_referenced` →
 * move the channel first), so dropping it would make the alert less actionable
 * than the raw API response.
 */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError) return `${error.code}: ${error.message}`;
  return error instanceof Error ? error.message : String(error);
}

/** A lifecycle action awaiting explicit, consequence-aware confirmation. */
type PendingAction =
  | { kind: "yank" | "unyank"; version: string }
  | { kind: "channelDelete"; channel: string };

/**
 * Per-variant purge outcome. The gateway's DELETE removes ONE variant row
 * (`?platform=`, default variant when omitted) — see `deleteAsset` in the
 * generated contract and docs/assets/channel-version-lifecycle.md, where a
 * whole-version delete is defined as deleting each variant row in turn. So a
 * "delete this version" button that fires a single unqualified DELETE silently
 * no-ops (404) on any version whose only variant is platform-specific.
 */
class VersionPurgeError extends Error {
  readonly deletedVariants: number;
  readonly totalVariants: number;

  constructor(message: string, deletedVariants: number, totalVariants: number) {
    super(message);
    this.name = "VersionPurgeError";
    this.deletedVariants = deletedVariants;
    this.totalVariants = totalVariants;
  }
}

/** Whether a variant's bytes are worth offering as an inline text preview. */
const PREVIEWABLE_CONTENT_TYPES = new Set([
  "application/json",
  "application/yaml",
  "application/x-yaml",
  "text/yaml",
  "text/plain",
  "text/markdown",
]);
/** Cap on preview fetches; larger config files are a download, not a preview. */
const PREVIEW_MAX_BYTES = 256 * 1024;

function isPreviewable(assetType: string, variant: AssetManifestVariant): boolean {
  if (variant.size_bytes > PREVIEW_MAX_BYTES) return false;
  const base = variant.content_type.split(";")[0].trim().toLowerCase();
  if (PREVIEWABLE_CONTENT_TYPES.has(base) || base.startsWith("text/")) return true;
  // config_file / mcp_manifest are text families by definition; the gateway
  // records whatever Content-Type the pusher declared, which is frequently the
  // generic octet-stream, so the family is the better signal for them.
  return assetType === "config_file" || assetType === "mcp_manifest";
}

function AssetDetailDialog({
  resource,
  apiKey,
  selectedVersion,
  onSelectVersion,
  onClose,
}: {
  resource: LogicalResource | null;
  apiKey: string;
  selectedVersion: string | null;
  onSelectVersion: (version: string | null) => void;
  onClose: () => void;
}) {
  const { t, format } = useI18n();
  const { toastError } = useOperatorError();
  const queryClient = useQueryClient();
  const open = resource !== null;

  const [pending, setPending] = useState<PendingAction | null>(null);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [channelForm, setChannelForm] = useState<{
    channel: string;
    version: string;
  } | null>(null);
  const [channelError, setChannelError] = useState<string | null>(null);
  // Permanent deletion is kept DISTINCT from yank: it needs a name-typed
  // destructive confirmation, so it gets its own state + dialog rather than
  // riding the shared consequence-confirm above.
  const [deleteVersion, setDeleteVersion] = useState<string | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [deleteError, setDeleteError] = useState<string | null>(null);
  // config_file / mcp_manifest affordance: read a small text payload without
  // round-tripping it through the filesystem.
  const [preview, setPreview] = useState<{
    version: string;
    variant: string;
    body: string | null;
    error: string | null;
  } | null>(null);

  const manifestQueryKey = useMemo(
    () => ["asset-manifest", resource?.assetType, resource?.name] as const,
    [resource?.assetType, resource?.name],
  );

  const {
    data: manifest,
    isLoading,
    error: manifestError,
  } = useQuery({
    queryKey: manifestQueryKey,
    enabled: open,
    queryFn: () =>
      adminGet(apiKey, "/v1/assets/{asset_type}/{name}/manifest", {
        params: {
          asset_type: (resource as NonNullable<typeof resource>).assetType,
          name: (resource as NonNullable<typeof resource>).name,
        },
      }),
  });

  function refresh() {
    queryClient.invalidateQueries({ queryKey: manifestQueryKey });
    queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
  }

  const yankMutation = useMutation({
    mutationFn: ({ version, yank }: { version: string; yank: boolean }) => {
      const path = `${assetPath((resource as NonNullable<typeof resource>).assetType, (resource as NonNullable<typeof resource>).name, version)}/yank`;
      return yank
        ? gatewayPost<AdminSchema<"AssetYankMutationResponse">>(apiKey, path)
        : gatewayDelete<AdminSchema<"AssetYankMutationResponse">>(apiKey, path);
    },
    onMutate: () => setPendingError(null),
    onSuccess: (_result, variables) => {
      toast.success(
        variables.yank ? t("page.assets.yank.success") : t("page.assets.unyank.success"),
      );
      setPending(null);
      refresh();
    },
    // The confirmation dialog STAYS OPEN carrying the verbatim gateway verdict.
    // A yank blocked by a live channel answers 409 asset_version_referenced
    // (docs/assets/channel-version-lifecycle.md); a toast that fades takes the
    // one instruction the operator needs — "move the channel first" — with it.
    onError: (error: unknown) => setPendingError(apiErrorText(error)),
  });

  const setChannelMutation = useMutation({
    mutationFn: ({ channel, version }: { channel: string; version: string }) => {
      const path = `/v1/assets/${encodeURIComponent((resource as NonNullable<typeof resource>).assetType)}/${encodeURIComponent((resource as NonNullable<typeof resource>).name)}/channels/${encodeURIComponent(channel)}?version=${encodeURIComponent(version)}`;
      return gatewayPut<AdminSchema<"AssetChannelMutationResponse">>(apiKey, path);
    },
    onMutate: () => setChannelError(null),
    onSuccess: () => {
      toast.success(t("page.assets.channel.success"));
      setChannelForm(null);
      refresh();
    },
    onError: (error: unknown) => setChannelError(apiErrorText(error)),
  });

  /**
   * Permanent purge of a whole logical version — every variant row of it.
   *
   * The gateway deletes ONE variant per call, so this walks the manifest's
   * variants and issues one DELETE each, passing `?platform=` for the
   * non-default ones. Platform-specific variants are purged BEFORE the default
   * one because #367 blocks only the delete that would remove the LAST
   * resolvable variant of a channel-referenced version; ordering that call last
   * means a blocked purge reports the block instead of stranding the operator
   * mid-sequence with no explanation.
   *
   * A partial purge is reported AS a partial purge: the error carries how many
   * of how many variant rows were removed, because a "delete failed" message
   * after three of four rows are already gone is a false statement about the
   * registry's state.
   */
  const deleteVersionMutation = useMutation({
    mutationFn: async (version: string) => {
      const target = manifest?.versions.find((entry) => entry.version === version);
      const variants = (target?.variants ?? []).map((entry) => entry.variant);
      // No manifest variant rows (a manifest that raced the delete) still means
      // one call against the default variant — never zero calls reported as a
      // successful purge.
      const ordered = (variants.length > 0 ? variants : [""])
        .slice()
        .sort((a, b) => (a === "" ? 1 : 0) - (b === "" ? 1 : 0));
      let deleted = 0;
      for (const variant of ordered) {
        try {
          await adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/{version}", {
            params: {
              asset_type: (resource as NonNullable<typeof resource>).assetType,
              name: (resource as NonNullable<typeof resource>).name,
              version,
            },
            query: variant === "" ? undefined : { platform: variant },
          });
          deleted += 1;
        } catch (error) {
          throw new VersionPurgeError(apiErrorText(error), deleted, ordered.length);
        }
      }
      return deleted;
    },
    onMutate: () => setDeleteError(null),
    onSuccess: () => {
      toast.success(t("page.assets.delete.success"));
      setDeleteVersion(null);
      setDeleteConfirmText("");
      refresh();
    },
    onError: (error: unknown) => {
      if (error instanceof VersionPurgeError && error.deletedVariants > 0) {
        setDeleteError(
          t("page.assets.delete.partial", {
            deleted: String(error.deletedVariants),
            total: String(error.totalVariants),
            message: error.message,
          }),
        );
      } else {
        setDeleteError(apiErrorText(error));
      }
      // A failed or partial purge changed the registry (or proved the manifest
      // stale), so refresh rather than leave a view the gateway disagrees with.
      refresh();
    },
  });

  const deleteChannelMutation = useMutation({
    mutationFn: (channel: string) => {
      const path = `/v1/assets/${encodeURIComponent((resource as NonNullable<typeof resource>).assetType)}/${encodeURIComponent((resource as NonNullable<typeof resource>).name)}/channels/${encodeURIComponent(channel)}`;
      return gatewayDelete<AdminSchema<"DeleteResponse">>(apiKey, path);
    },
    onMutate: () => setPendingError(null),
    onSuccess: () => {
      toast.success(t("page.assets.channel.deleteSuccess"));
      setPending(null);
      refresh();
    },
    onError: (error: unknown) => setPendingError(apiErrorText(error)),
  });

  async function handleDownload(version: string, variant: AssetManifestVariant) {
    if (!resource) return;
    try {
      // `platform` selects the variant; the contract documents it as required
      // when resolution is otherwise ambiguous, and a multi-variant version is
      // exactly that case.
      const query =
        variant.variant === "" ? "" : `?platform=${encodeURIComponent(variant.variant)}`;
      const blob = await gatewayGetBinary(
        apiKey,
        `${assetPath(resource.assetType, resource.name, version)}${query}`,
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const variantSuffix = variant.variant === "" ? "" : `-${variant.variant}`;
      link.download = `${resource.name}-${version}${variantSuffix}${downloadExtension(variant.content_type)}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      // Localized headline + the verbatim gateway/network detail (#348). A
      // non-Error throwable falls back to the generic localized headline
      // (`error.unknown`) rather than to a raw English sentence.
      toastError(error);
    }
  }

  async function handlePreview(version: string, variant: AssetManifestVariant) {
    if (!resource) return;
    setPreview({ version, variant: variant.variant, body: null, error: null });
    try {
      const query =
        variant.variant === "" ? "" : `?platform=${encodeURIComponent(variant.variant)}`;
      const blob = await gatewayGetBinary(
        apiKey,
        `${assetPath(resource.assetType, resource.name, version)}${query}`,
      );
      const body = await blob.text();
      setPreview({ version, variant: variant.variant, body, error: null });
    } catch (error) {
      setPreview({
        version,
        variant: variant.variant,
        body: null,
        error: apiErrorText(error),
      });
    }
  }

  const resourceLabel = resource ? `${resource.assetType}/${resource.name}` : "";
  const versions = useMemo(() => manifest?.versions ?? [], [manifest]);
  const channels = useMemo(() => manifest?.channels ?? [], [manifest]);
  const nonYankedVersions = versions.filter((version) => !version.yanked);

  /**
   * Channels still pointing at `version` — the gateway's own blocker for both
   * yank and permanent delete (#367: `ReferencedByChannel` / `BlockedByChannel`
   * → 409 `asset_version_referenced`). Reported from the manifest ALREADY in
   * scope, so the operator sees the blocker before firing rather than as a
   * conflict afterwards.
   */
  const channelsReferencing = useCallback(
    (version: string): AssetChannelSummary[] =>
      channels.filter((channel) => channel.version === version),
    [channels],
  );

  // Exact identifier the operator must retype to arm the permanent delete.
  const deleteToken = resource && deleteVersion ? `${resource.name}@${deleteVersion}` : "";
  const deleteArmed = deleteToken !== "" && deleteConfirmText === deleteToken;
  const deleteBlockers = deleteVersion ? channelsReferencing(deleteVersion) : [];
  const deleteIsLastVersion = deleteVersion !== null && versions.length === 1;
  const pendingBlockers =
    pending && pending.kind === "yank" ? channelsReferencing(pending.version) : [];

  function confirmLabel(action: PendingAction): string {
    if (action.kind === "channelDelete") return action.channel;
    return `${resourceLabel}@${action.version}`;
  }

  function closeDeleteDialog() {
    setDeleteVersion(null);
    setDeleteConfirmText("");
    setDeleteError(null);
  }

  return (
    <>
      <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
          {resource ? (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono text-base">{resourceLabel}</DialogTitle>
                <DialogDescription>
                  {t("page.assets.detail.description", {
                    created: format.date(resource.createdAtUnix * 1000, {
                      dateStyle: "medium",
                    }),
                    updated: format.date(resource.updatedAtUnix * 1000, {
                      dateStyle: "medium",
                    }),
                  })}
                </DialogDescription>
              </DialogHeader>

              {manifestError ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {t("page.assets.detail.error", { message: manifestError.message })}
                </p>
              ) : isLoading || !manifest ? (
                <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
              ) : (
                <div className="flex flex-col gap-6">
                  <section className="flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold">{t("page.assets.detail.channels")}</h3>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          setChannelError(null);
                          setChannelForm({ channel: "", version: "" });
                        }}
                      >
                        {t("page.assets.action.setChannel")}
                      </Button>
                    </div>
                    <div className="overflow-x-auto rounded-md border">
                      <Table>
                        <TableHeader>
                          {/* Responsive contract (#336/#344): below lg the
                              dialog is viewport-wide, so the identity columns
                              and the lifecycle ACTIONS must fit without a
                              horizontal scroll; the density columns (pull
                              reference, timestamps) are >=lg only. */}
                          <TableRow>
                            <TableHead>{t("page.assets.col.channel")}</TableHead>
                            <TableHead>{t("page.assets.col.version")}</TableHead>
                            <TableHead className="hidden lg:table-cell">
                              {t("page.assets.col.reference")}
                            </TableHead>
                            <TableHead className="hidden lg:table-cell">
                              {t("page.assets.col.updated")}
                            </TableHead>
                            <TableHead className="lg:w-24" />
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {channels.length === 0 ? (
                            <TableRow>
                              <TableCell
                                colSpan={5}
                                className="h-16 text-center text-sm text-muted-foreground"
                              >
                                {t("resource.table.empty")}
                              </TableCell>
                            </TableRow>
                          ) : (
                            channels.map((channel: AssetChannelSummary) => (
                              <TableRow key={channel.channel}>
                                <TableCell className="font-mono text-xs">
                                  {channel.channel}
                                </TableCell>
                                <TableCell className="font-mono text-xs">
                                  {channel.version}
                                </TableCell>
                                <TableCell className="hidden lg:table-cell">
                                  <TruncatedCopyable
                                    prefixLength={28}
                                    label={t("page.assets.reference.pullLabel", {
                                      asset: `${resourceLabel}@${channel.channel}`,
                                    })}
                                    value={pullReference(
                                      resource.assetType,
                                      resource.name,
                                      channel.channel,
                                    )}
                                  />
                                </TableCell>
                                <TableCell className="hidden text-xs lg:table-cell">
                                  {format.date(channel.updated_at_unix * 1000, {
                                    dateStyle: "medium",
                                    timeStyle: "short",
                                  })}
                                </TableCell>
                                <TableCell>
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    onClick={() => {
                                      setPendingError(null);
                                      setPending({
                                        kind: "channelDelete",
                                        channel: channel.channel,
                                      });
                                    }}
                                  >
                                    {t("resource.action.delete")}
                                  </Button>
                                </TableCell>
                              </TableRow>
                            ))
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </section>

                  <section className="flex flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-sm font-semibold">{t("page.assets.detail.versions")}</h3>
                      {selectedVersion !== null ? (
                        <Button size="sm" variant="ghost" onClick={() => onSelectVersion(null)}>
                          {t("page.assets.action.clearVersion")}
                        </Button>
                      ) : null}
                    </div>
                    <div className="overflow-x-auto rounded-md border">
                      <Table>
                        <TableHeader>
                          {/* Same responsive contract as the channels table:
                              version/state/variant identify the row and the
                              actions column carries the lifecycle operations
                              (download/yank/delete), so those must sit within
                              a mobile viewport; hash/size/storage/reference
                              density is >=lg only. */}
                          <TableRow>
                            <TableHead>{t("page.assets.col.version")}</TableHead>
                            <TableHead>{t("page.assets.col.state")}</TableHead>
                            <TableHead>{t("page.assets.col.variant")}</TableHead>
                            <TableHead className="hidden lg:table-cell">
                              {t("page.assets.col.contentHash")}
                            </TableHead>
                            <TableHead className="hidden lg:table-cell">
                              {t("page.assets.col.size")}
                            </TableHead>
                            <TableHead className="hidden lg:table-cell">
                              {t("page.assets.col.storage")}
                            </TableHead>
                            <TableHead className="hidden lg:table-cell">
                              {t("page.assets.col.reference")}
                            </TableHead>
                            <TableHead className="lg:w-56" />
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {versions.length === 0 ? (
                            <TableRow>
                              <TableCell
                                colSpan={8}
                                className="h-16 text-center text-sm text-muted-foreground"
                              >
                                {t("resource.table.empty")}
                              </TableCell>
                            </TableRow>
                          ) : (
                            versions.map((version: AssetManifestVersion) =>
                              version.variants.map((variant, variantIndex) => (
                                <TableRow
                                  key={compositeKey(version.version, variant.variant)}
                                  aria-current={
                                    version.version === selectedVersion ? "true" : undefined
                                  }
                                  className={
                                    version.version === selectedVersion ? "bg-muted/60" : undefined
                                  }
                                >
                                  <TableCell className="font-mono text-xs">
                                    {variantIndex === 0 ? (
                                      <button
                                        type="button"
                                        className="underline-offset-2 hover:underline"
                                        aria-label={t("page.assets.action.focusVersion", {
                                          version: version.version,
                                        })}
                                        onClick={() =>
                                          onSelectVersion(
                                            version.version === selectedVersion
                                              ? null
                                              : version.version,
                                          )
                                        }
                                      >
                                        {version.version}
                                      </button>
                                    ) : null}
                                  </TableCell>
                                  <TableCell>
                                    {variantIndex === 0 ? (
                                      version.yanked ? (
                                        <Badge variant="destructive">
                                          {t("page.assets.state.yanked")}
                                        </Badge>
                                      ) : (
                                        <Badge variant="secondary">
                                          {t("page.assets.state.active")}
                                        </Badge>
                                      )
                                    ) : null}
                                  </TableCell>
                                  <TableCell className="font-mono text-xs">
                                    {variant.variant === ""
                                      ? t("page.assets.variant.default")
                                      : variant.variant}
                                  </TableCell>
                                  <TableCell className="hidden font-mono text-xs lg:table-cell">
                                    {shortHash(variant.content_hash)}
                                  </TableCell>
                                  <TableCell className="hidden lg:table-cell">
                                    {format.bytes(variant.size_bytes)}
                                  </TableCell>
                                  <TableCell className="hidden lg:table-cell">
                                    {variant.storage_backed
                                      ? t("page.assets.storage.bucket")
                                      : t("page.assets.storage.inline")}
                                  </TableCell>
                                  <TableCell className="hidden lg:table-cell">
                                    <TruncatedCopyable
                                      prefixLength={28}
                                      label={t("page.assets.reference.pullLabel", {
                                        asset: `${resourceLabel}@${version.version}`,
                                      })}
                                      value={pullReference(
                                        resource.assetType,
                                        resource.name,
                                        version.version,
                                        variant.variant,
                                      )}
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <div className="flex flex-wrap gap-2">
                                      {/* Per-VARIANT: a version's linux-arm64
                                          build is a distinct object and was
                                          previously unreachable from here. */}
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() => handleDownload(version.version, variant)}
                                      >
                                        {t("page.assets.action.download")}
                                      </Button>
                                      {isPreviewable(resource.assetType, variant) ? (
                                        <Button
                                          size="sm"
                                          variant="ghost"
                                          onClick={() => handlePreview(version.version, variant)}
                                        >
                                          {t("page.assets.action.preview")}
                                        </Button>
                                      ) : null}
                                      {variantIndex === 0 ? (
                                        <>
                                          {version.yanked ? (
                                            <Button
                                              size="sm"
                                              variant="outline"
                                              onClick={() => {
                                                setPendingError(null);
                                                setPending({
                                                  kind: "unyank",
                                                  version: version.version,
                                                });
                                              }}
                                            >
                                              {t("page.assets.action.unyank")}
                                            </Button>
                                          ) : (
                                            <Button
                                              size="sm"
                                              variant="destructive"
                                              onClick={() => {
                                                setPendingError(null);
                                                setPending({
                                                  kind: "yank",
                                                  version: version.version,
                                                });
                                              }}
                                            >
                                              {t("page.assets.action.yank")}
                                            </Button>
                                          )}
                                          <Button
                                            size="sm"
                                            variant="ghost"
                                            className="text-destructive hover:text-destructive"
                                            onClick={() => {
                                              setDeleteConfirmText("");
                                              setDeleteError(null);
                                              setDeleteVersion(version.version);
                                            }}
                                          >
                                            {t("page.assets.delete.action")}
                                          </Button>
                                        </>
                                      ) : null}
                                    </div>
                                  </TableCell>
                                </TableRow>
                              )),
                            )
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </section>
                </div>
              )}

              <DialogFooter>
                <Button type="button" variant="outline" onClick={onClose}>
                  {t("common.close")}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Consequence-aware destructive confirmation, naming the exact resource
          AND the gateway-side blocker that would reject it. */}
      <Dialog
        open={pending !== null}
        onOpenChange={(next) => {
          if (!next) {
            setPending(null);
            setPendingError(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          {pending ? (
            <>
              <DialogHeader>
                <DialogTitle>
                  {pending.kind === "yank"
                    ? t("page.assets.yank.title", { asset: confirmLabel(pending) })
                    : pending.kind === "unyank"
                      ? t("page.assets.unyank.title", { asset: confirmLabel(pending) })
                      : t("page.assets.channel.deleteTitle", {
                          channel: confirmLabel(pending),
                        })}
                </DialogTitle>
                <DialogDescription>
                  {pending.kind === "yank"
                    ? t("page.assets.yank.body", { asset: confirmLabel(pending) })
                    : pending.kind === "unyank"
                      ? t("page.assets.unyank.body", { asset: confirmLabel(pending) })
                      : t("page.assets.channel.deleteBody", {
                          channel: confirmLabel(pending),
                          name: resourceLabel,
                        })}
                </DialogDescription>
              </DialogHeader>
              {pendingBlockers.length > 0 ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {t("page.assets.yank.blocked", {
                    channels: pendingBlockers.map((channel) => channel.channel).join(", "),
                  })}
                </p>
              ) : null}
              {pendingError ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  <span className="font-medium">{t("page.assets.action.errorHeading")}</span>{" "}
                  <span className="break-all font-mono text-xs">{pendingError}</span>
                </p>
              ) : null}
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setPending(null);
                    setPendingError(null);
                  }}
                >
                  {t("common.cancel")}
                </Button>
                <Button
                  type="button"
                  variant={pending.kind === "unyank" ? "default" : "destructive"}
                  disabled={yankMutation.isPending || deleteChannelMutation.isPending}
                  onClick={() => {
                    if (pending.kind === "channelDelete")
                      deleteChannelMutation.mutate(pending.channel);
                    else
                      yankMutation.mutate({
                        version: pending.version,
                        yank: pending.kind === "yank",
                      });
                  }}
                >
                  {pending.kind === "yank"
                    ? t("page.assets.action.yank")
                    : pending.kind === "unyank"
                      ? t("page.assets.action.unyank")
                      : t("resource.action.delete")}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Create / move a channel pointer onto a non-yanked version. */}
      <Dialog
        open={channelForm !== null}
        onOpenChange={(next) => {
          if (!next) {
            setChannelForm(null);
            setChannelError(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          {channelForm ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (channelForm.channel.trim() === "" || channelForm.version === "") return;
                setChannelMutation.mutate({
                  channel: channelForm.channel.trim(),
                  version: channelForm.version,
                });
              }}
            >
              <DialogHeader>
                <DialogTitle>{t("page.assets.channel.title")}</DialogTitle>
                <DialogDescription>
                  {t("page.assets.channel.body", { name: resourceLabel })}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid gap-2">
                  <Label htmlFor="asset-channel-name">{t("page.assets.col.channel")}</Label>
                  <Input
                    id="asset-channel-name"
                    value={channelForm.channel}
                    onChange={(event) =>
                      setChannelForm((current) =>
                        current ? { ...current, channel: event.target.value } : current,
                      )
                    }
                    placeholder={t("page.assets.channel.placeholder")}
                    required
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="asset-channel-version">{t("page.assets.col.version")}</Label>
                  <Select
                    value={channelForm.version}
                    onValueChange={(value) =>
                      setChannelForm((current) =>
                        current ? { ...current, version: value } : current,
                      )
                    }
                  >
                    <SelectTrigger id="asset-channel-version">
                      <SelectValue placeholder={t("resource.form.selectPlaceholder")} />
                    </SelectTrigger>
                    <SelectContent>
                      {nonYankedVersions.map((version) => (
                        <SelectItem key={version.version} value={version.version}>
                          {version.version}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {channelError ? (
                  <p
                    role="alert"
                    className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                  >
                    <span className="font-medium">{t("page.assets.action.errorHeading")}</span>{" "}
                    <span className="break-all font-mono text-xs">{channelError}</span>
                  </p>
                ) : null}
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setChannelForm(null);
                    setChannelError(null);
                  }}
                >
                  {t("common.cancel")}
                </Button>
                <Button type="submit" disabled={setChannelMutation.isPending}>
                  {t("page.assets.action.setChannel")}
                </Button>
              </DialogFooter>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>

      {/*
        Permanent version deletion — DISTINCT from yank. Yank is reversible and
        keeps the bytes; this purges every variant row of the version and its
        stored bytes for good, so the delete button stays disarmed until the
        operator retypes the exact name@version identifier. Before it fires the
        dialog names the BLOCKERS the gateway will enforce (a channel still
        pointing at the version -> 409 asset_version_referenced, and the "this
        is the only version" case); after a failure the verdict stays on screen.
      */}
      <Dialog
        open={deleteVersion !== null}
        onOpenChange={(next) => {
          if (!next) closeDeleteDialog();
        }}
      >
        <DialogContent className="sm:max-w-lg">
          {deleteVersion ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (deleteArmed) deleteVersionMutation.mutate(deleteVersion);
              }}
            >
              <DialogHeader>
                <DialogTitle>{t("page.assets.delete.title", { asset: deleteToken })}</DialogTitle>
                <DialogDescription>
                  {t("page.assets.delete.body", { asset: deleteToken })}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-2 py-4">
                {deleteBlockers.length > 0 ? (
                  <p
                    role="alert"
                    className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                  >
                    {t("page.assets.delete.blocked", {
                      asset: deleteToken,
                      channels: deleteBlockers.map((channel) => channel.channel).join(", "),
                    })}
                  </p>
                ) : null}
                {deleteIsLastVersion ? (
                  <p
                    // biome-ignore lint/a11y/useSemanticElements: ARIA live region for the last-version delete warning; keeping the block <p> preserves layout that <output>'s inline default would change
                    role="status"
                    className="rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-sm"
                  >
                    {t("page.assets.delete.lastVersion", { name: resourceLabel })}
                  </p>
                ) : null}
                <Label htmlFor="asset-delete-confirm">
                  {t("page.assets.delete.confirmLabel", { asset: deleteToken })}
                </Label>
                <Input
                  id="asset-delete-confirm"
                  value={deleteConfirmText}
                  onChange={(event) => setDeleteConfirmText(event.target.value)}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  aria-invalid={deleteConfirmText !== "" && !deleteArmed}
                />
                {deleteError ? (
                  <p
                    role="alert"
                    className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                  >
                    <span className="font-medium">{t("page.assets.delete.errorHeading")}</span>{" "}
                    <span className="break-all font-mono text-xs">{deleteError}</span>
                  </p>
                ) : null}
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={closeDeleteDialog}>
                  {t("common.cancel")}
                </Button>
                <Button
                  type="submit"
                  variant="destructive"
                  disabled={!deleteArmed || deleteVersionMutation.isPending}
                >
                  {t("page.assets.delete.action")}
                </Button>
              </DialogFooter>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* config_file / mcp_manifest affordance: read a small text payload in
          place. Bytes come from the same variant-addressed GET the download
          uses, so what is shown is exactly what a pull would fetch. */}
      <Dialog open={preview !== null} onOpenChange={(next) => !next && setPreview(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
          {preview ? (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono text-base">
                  {t("page.assets.preview.title", {
                    asset: `${resourceLabel}@${preview.version}`,
                  })}
                </DialogTitle>
                <DialogDescription>{t("page.assets.preview.description")}</DialogDescription>
              </DialogHeader>
              {preview.error ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {preview.error}
                </p>
              ) : preview.body === null ? (
                <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
              ) : (
                <pre className="max-h-[50vh] overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
                  {preview.body}
                </pre>
              )}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setPreview(null)}>
                  {t("common.close")}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}

/**
 * Large-object upload (#344/#338/#259). Bundles above the inline push limit
 * never touch the gateway body: the console hashes the bytes, asks the gateway
 * for a presigned intent (register-intent), PUTs the bytes DIRECTLY to storage,
 * then commits so the gateway can verify size + SHA-256 before registering the
 * version. Lives in its own dialog so its asset-type picker doesn't collide
 * with the inline push form / registry filter, and so the flow is a deliberate
 * operator action. Commit/intent errors surface verbatim in a role="alert".
 *
 * The flow is CANCELLABLE at every leg: one AbortController is threaded through
 * the intent POST, the direct bucket PUT and the commit POST, so "Cancel" stops
 * the transfer instead of merely greying itself out. A cancelled upload is
 * reported as cancelled — never as a publish — and still releases the intent it
 * registered, because an abandoned intent holds staging capacity.
 */
function PresignedUploadCard({
  apiKey,
  storageSummary,
  isLoading,
  onCommitted,
}: {
  apiKey: string;
  storageSummary: AdminSchema<"AssetStorageSummary"> | undefined;
  isLoading: boolean;
  onCommitted: () => void;
}) {
  const { t, format } = useI18n();
  const [open, setOpen] = useState(false);
  const [assetType, setAssetType] = useState("cli_tool");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [phase, setPhase] = useState<UploadPhase>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  // Cancellation outcome, kept DISTINCT from the failure alert: a cancel is not
  // an error and must never read as one, and neither may read as a publish.
  // The staging disposition is reported as one of three OBSERVED states, never
  // assumed: no intent was ever registered, the intent was released, or the
  // release could not be confirmed.
  const [cancelled, setCancelled] = useState<null | "no-intent" | "released" | "unconfirmed">(null);
  const abortRef = useRef<AbortController | null>(null);
  // Set inside the run so the error handler can say what actually happened to
  // the intent, instead of asserting a cleanup it never observed.
  const stagingRef = useRef<"no-intent" | "released" | "unconfirmed">("no-intent");

  const presign = storageSummary?.presigned_upload;
  const maxObjectBytes = presign?.max_object_bytes ?? null;
  const inlineMaxBytes = storageSummary?.inline_upload_max_bytes ?? null;
  const running = phase !== "idle";

  // A component unmounted mid-upload must not leave the transfer running.
  useEffect(() => () => abortRef.current?.abort(), []);

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error(t("page.assets.error.chooseFile"));
      if (file.size < 1) throw new Error(t("page.assets.error.chooseFile"));
      if (!name.trim() || !version.trim())
        throw new Error(t("page.assets.error.nameVersionRequired"));
      if (maxObjectBytes !== null && file.size > maxObjectBytes)
        throw new Error(
          t("page.assets.presign.tooLarge", {
            size: format.bytes(file.size),
            max: format.bytes(maxObjectBytes),
          }),
        );

      const controller = new AbortController();
      abortRef.current = controller;
      stagingRef.current = "no-intent";
      const signal = controller.signal;

      const params = {
        asset_type: assetType,
        name: name.trim(),
        version: version.trim(),
      };

      // 1) Hash client-side — both the intent and the commit are keyed on it.
      setPhase("hashing");
      const sha256 = await sha256Hex(await file.arrayBuffer());
      // WebCrypto has no signal; honour a cancel that landed while it ran
      // rather than pressing on to register an intent nobody wants.
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");

      // 2) Register the intent; the gateway returns a short-lived PUT URL.
      setPhase("registering");
      const intent = await adminPost(
        apiKey,
        "/v1/assets/presign/upload/{asset_type}/{name}/{version}",
        { size_bytes: file.size, sha256 },
        { params, signal },
      );

      // Once an intent exists it holds staging capacity, so every path out of
      // here that is not a successful commit releases it — INCLUDING a cancel.
      // #368's own integrator contract (docs/assets/private-bucket-migration.md)
      // tells clients to abort an intent they will not commit; the first-party
      // console has to follow the contract it publishes, or a failed or
      // cancelled upload leaks the tenant's quota to the lifecycle GC.
      try {
        // 3) PUT the bytes straight to storage, bypassing the gateway body.
        //    #368: required_headers are SigV4 SignedHeaders of upload_url —
        //    the bucket 403s a PUT that omits them, so they are forwarded
        //    verbatim.
        setPhase("uploading");
        await putPresignedObject(
          intent.upload_url,
          file,
          file.type,
          intent.required_headers,
          signal,
        );

        // 4) Commit; the gateway re-verifies size + SHA-256 (and scans/quota).
        setPhase("committing");
        await adminPost(
          apiKey,
          "/v1/assets/presign/commit/{asset_type}/{name}/{version}",
          {
            upload_id: intent.upload_id,
            size_bytes: file.size,
            sha256,
            content_type: file.type !== "" ? file.type : null,
          },
          { params, signal },
        );
      } catch (error: unknown) {
        // `bucket_rejected` is only claimed when the bucket itself answered
        // the PUT with a non-2xx. Anything else — a local length refusal, a
        // commit rejection, an operator cancel — is a plain abandonment: that
        // class is caller-asserted, and over-claiming it would put a fabricated
        // bucket rejection into the gateway's audit trail and counter.
        //
        // The release deliberately carries NO signal: it is the cleanup for an
        // aborted run, so sharing the aborted signal would cancel the very call
        // that frees the staging capacity.
        await adminPost(
          apiKey,
          "/v1/assets/presign/abort/{asset_type}/{name}/{version}",
          {
            upload_id: intent.upload_id,
            size_bytes: file.size,
            sha256,
            reason:
              error instanceof PresignedUploadRejectedError
                ? ("bucket_rejected" as const)
                : ("abandoned" as const),
          },
          { params },
        ).then(
          () => {
            stagingRef.current = "released";
          },
          () => {
            // The abort is cleanup. Its own failure must never replace the
            // verdict the operator needs to read, so it is swallowed — but it
            // is also NOT reported as a release that never happened; the
            // lifecycle GC stays the backstop.
            stagingRef.current = "unconfirmed";
          },
        );
        throw error;
      }
    },
    onMutate: () => {
      setErrorMessage(null);
      setCancelled(null);
    },
    onSuccess: () => {
      toast.success(t("page.assets.presign.success"));
      setName("");
      setVersion("");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
      setPhase("idle");
      abortRef.current = null;
      setOpen(false);
      onCommitted();
    },
    onError: (error: unknown) => {
      setPhase("idle");
      abortRef.current = null;
      if (isAbortError(error)) {
        // A cancel is NOT a failure and is NOT a publish. Nothing was
        // registered in the registry, and the dialog says exactly that —
        // qualified by the OBSERVED disposition of the staged intent.
        setCancelled(stagingRef.current);
        return;
      }
      // Surfaced VERBATIM — a size/sha mismatch, scan reject, or quota denial
      // from the commit step must reach the operator exactly as the gateway
      // phrased it, not paraphrased.
      setErrorMessage(error instanceof Error ? error.message : String(error));
    },
  });

  function closeDialog() {
    // Closing mid-flight ABORTS the transfer rather than leaving an orphan
    // request racing a dialog the operator already dismissed.
    abortRef.current?.abort();
    setOpen(false);
    setErrorMessage(null);
    setCancelled(null);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("page.assets.presign.title")}</CardTitle>
        <CardDescription>{t("page.assets.presign.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading || !storageSummary ? (
          <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
        ) : !presign?.enabled ? (
          <p className="text-sm text-muted-foreground">{t("page.assets.presign.disabled")}</p>
        ) : (
          <div className="flex flex-col gap-2">
            {maxObjectBytes !== null ? (
              <p className="text-sm text-muted-foreground">
                {t("page.assets.presign.maxHint", {
                  max: format.bytes(maxObjectBytes),
                })}
              </p>
            ) : null}
            <div>
              <Button type="button" onClick={() => setOpen(true)}>
                {t("page.assets.presign.submit")}
              </Button>
            </div>
          </div>
        )}
      </CardContent>

      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) closeDialog();
          else setOpen(true);
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <form
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              uploadMutation.mutate();
            }}
          >
            <DialogHeader>
              <DialogTitle>{t("page.assets.presign.title")}</DialogTitle>
              <DialogDescription>{t("page.assets.presign.description")}</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="presign-asset-type">{t("page.assets.field.assetType")}</Label>
                <Select value={assetType} onValueChange={setAssetType}>
                  <SelectTrigger id="presign-asset-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ASSET_TYPES.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {t(option.labelKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="presign-asset-name">{t("page.assets.field.name")}</Label>
                <Input
                  id="presign-asset-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  // eslint-disable-next-line ferrogate/no-untranslated-literal -- example asset name, not translatable copy
                  placeholder="my-tool"
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="presign-asset-version">{t("page.assets.field.version")}</Label>
                <Input
                  id="presign-asset-version"
                  value={version}
                  onChange={(event) => setVersion(event.target.value)}
                  placeholder="1.0.0"
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="presign-asset-file">{t("page.assets.field.file")}</Label>
                <Input
                  id="presign-asset-file"
                  type="file"
                  ref={fileInputRef}
                  onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                  required
                />
              </div>

              {/* Backend-capability routing (#344 scope): the authoritative
                  summary's inline ceiling is what decides which of the two
                  forms a file belongs in, so it is stated here instead of
                  leaving the operator to guess. */}
              {file && inlineMaxBytes !== null && file.size <= inlineMaxBytes ? (
                <p
                  // biome-ignore lint/a11y/useSemanticElements: ARIA live region hinting inline upload; keeping <p> preserves the surrounding text flow that <output>'s inline-block box model would alter
                  role="status"
                  className="text-sm text-muted-foreground"
                >
                  {t("page.assets.presign.inlineWouldDo", {
                    size: format.bytes(file.size),
                    max: format.bytes(inlineMaxBytes),
                  })}
                </p>
              ) : null}

              {running ? (
                <div className="grid gap-2" aria-live="polite">
                  <p
                    // biome-ignore lint/a11y/useSemanticElements: ARIA live region for the upload phase label; keeping <p> preserves the grid layout that <output>'s inline default would change
                    role="status"
                    className="text-sm text-muted-foreground"
                  >
                    {t(UPLOAD_PHASE_KEY[phase as Exclude<UploadPhase, "idle">])}
                  </p>
                  {/* biome-ignore lint/a11y/useFocusableInteractive: a progressbar is a non-interactive status indicator, not a tab stop */}
                  <div
                    className="h-2 w-full overflow-hidden rounded-full bg-secondary"
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={UPLOAD_PHASE_PROGRESS[phase]}
                  >
                    <div
                      className="h-full bg-primary transition-all"
                      style={{ width: `${UPLOAD_PHASE_PROGRESS[phase]}%` }}
                    />
                  </div>
                </div>
              ) : null}

              {cancelled ? (
                <p
                  role="alert"
                  className="rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-sm"
                >
                  {cancelled === "released"
                    ? t("page.assets.presign.cancelledReleased")
                    : cancelled === "unconfirmed"
                      ? t("page.assets.presign.cancelledUnreleased")
                      : t("page.assets.presign.cancelledNoIntent")}
                </p>
              ) : null}

              {errorMessage ? (
                <p
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  <span className="font-medium">{t("page.assets.presign.errorHeading")}</span>{" "}
                  <span className="break-all font-mono text-xs">{errorMessage}</span>
                </p>
              ) : null}
            </div>
            <DialogFooter>
              {/* Cancellation is a real action, not a disabled button: while a
                  transfer runs this aborts the in-flight leg (intent / bucket
                  PUT / commit) and releases the staged intent. */}
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  if (running) abortRef.current?.abort();
                  else closeDialog();
                }}
              >
                {running ? t("page.assets.presign.cancelUpload") : t("common.cancel")}
              </Button>
              <Button type="submit" disabled={running}>
                {running
                  ? t(UPLOAD_PHASE_KEY[phase as Exclude<UploadPhase, "idle">])
                  : t("page.assets.presign.submit")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

export default function AssetsPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const { toastError } = useOperatorError();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const queryClient = useQueryClient();

  const [assetType, setAssetType] = useState("cli_tool");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Browse state lives in the URL query so a filtered view, an open detail
  // panel, or a link to one version is shareable and reload-safe. `type`/`q`
  // hold the type filter and the free-text search; `rtype`+`rname` name the
  // open resource (the manifest is keyed on asset_type + name, so we round-trip
  // both rather than a delimited pair that could collide with a slash in the
  // asset name); `rver` focuses one version inside the open resource. Defaults
  // (all types / empty search / no selection) are encoded as ABSENT params,
  // keeping the canonical URL of a pristine registry clean.
  const [searchParams, setSearchParams] = useSearchParams();
  const filterType = searchParams.get("type") ?? ALL_TYPES;
  const search = searchParams.get("q") ?? "";
  const selectedType = searchParams.get("rtype");
  const selectedName = searchParams.get("rname");
  const selectedVersion = searchParams.get("rver");

  // Transient filter/search edits REPLACE the history entry (typing shouldn't
  // spam the back stack); opening/closing a resource PUSHes, so Back closes the
  // detail panel. Both prune params at their default so the URL stays minimal.
  const setBrowseParam = useCallback(
    (key: string, value: string | null) => {
      const next = new URLSearchParams(searchParams);
      if (value === null || value === "") next.delete(key);
      else next.set(key, value);
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const {
    data,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey: ASSETS_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets"),
  });

  const {
    data: storageSummary,
    isLoading: isStorageSummaryLoading,
    error: storageSummaryError,
  } = useQuery({
    queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets/storage/summary"),
  });

  const inlineMaxBytes = storageSummary?.inline_upload_max_bytes ?? null;
  const inlineTooLarge = file !== null && inlineMaxBytes !== null && file.size > inlineMaxBytes;

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new LocalizedError(t("page.assets.error.chooseFile"));
      if (!name.trim() || !version.trim())
        throw new LocalizedError(t("page.assets.error.nameVersionRequired"));
      // Backend-capability routing: the gateway buffers at most
      // inline_upload_max_bytes on this path and rejects the rest, so refuse
      // locally with the actionable instruction instead of burning the upload.
      if (inlineMaxBytes !== null && file.size > inlineMaxBytes)
        throw new LocalizedError(
          t("page.assets.push.tooLargeForInline", {
            size: format.bytes(file.size),
            max: format.bytes(inlineMaxBytes),
          }),
        );
      return gatewayPutBinary(
        apiKey,
        assetPath(assetType, name.trim(), version.trim()),
        file,
        file.type,
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY });
      toast.success(t("page.assets.toast.pushed"));
      setName("");
      setVersion("");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    onError: (uploadError: Error) => toastError(uploadError),
  });

  // Group ONCE, then filter the logical packages. Grouping is keyed on
  // (asset_type, name) and both filters are per-resource, so this is equivalent
  // to the old filter-then-group but also lets the URL-selected resource resolve
  // against the FULL registry — a type/search filter that hides a row must not
  // close a detail panel opened by a shared ?rtype=&rname= link.
  //
  // Known limit (contract-bound, NOT a client bug): `GET /v1/assets` declares no
  // query parameters in the generated contract, so there is no server-side
  // search or pagination to call. The whole tenant's version rows load per view
  // and are grouped here. Fixing that needs a paginated/filterable list
  // endpoint on the gateway first; the console cannot paper over its absence
  // without lying about totals.
  const allResources = useMemo(() => groupResources(data?.data ?? []), [data]);

  const resources = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return allResources.filter(
      (resource) =>
        (filterType === ALL_TYPES || resource.assetType === filterType) &&
        (needle === "" || resource.name.toLowerCase().includes(needle)),
    );
  }, [allResources, filterType, search]);

  const selected = useMemo<LogicalResource | null>(() => {
    if (!selectedType || !selectedName) return null;
    return (
      allResources.find(
        (resource) => resource.assetType === selectedType && resource.name === selectedName,
      ) ?? null
    );
  }, [allResources, selectedType, selectedName]);

  const selectResource = useCallback(
    (resource: LogicalResource | null) => {
      const next = new URLSearchParams(searchParams);
      if (resource) {
        next.set("rtype", resource.assetType);
        next.set("rname", resource.name);
      } else {
        next.delete("rtype");
        next.delete("rname");
      }
      // A focused version belongs to the resource that was open; carrying it
      // onto a different one would point at a version that resource may not
      // have.
      next.delete("rver");
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

  const selectVersion = useCallback(
    (nextVersion: string | null) => setBrowseParam("rver", nextVersion),
    [setBrowseParam],
  );

  // Registry columns reuse the shared responsive data surface (#336): a table
  // on desktop, `data-compact-records` cards below it, with 44px touch targets.
  const columns = useMemo<ColumnConfig<LogicalResource>[]>(
    () => [
      {
        key: "assetType",
        headerKey: "page.assets.col.type",
        mobileVisibility: "always",
        minWidth: 140,
        // Localized like the filter directly above the table; an asset type the
        // console has no catalog entry for renders as its raw identifier.
        render: (row, translate) => assetTypeLabel(translate, row.assetType),
      },
      {
        key: "name",
        headerKey: "page.assets.col.name",
        priority: "primary",
        mobileVisibility: "always",
        minWidth: 200,
      },
      {
        key: "versionCount",
        headerKey: "page.assets.col.versions",
        mobileVisibility: "always",
        minWidth: 100,
      },
      {
        key: "latestVersion",
        headerKey: "page.assets.col.latest",
        mobileVisibility: "always",
        minWidth: 140,
      },
      {
        key: "storageBacked",
        headerKey: "page.assets.col.storage",
        mobileVisibility: "always",
        minWidth: 120,
        render: (row, translate) =>
          row.storageBacked
            ? translate("page.assets.storage.bucket")
            : translate("page.assets.storage.inline"),
      },
    ],
    [],
  );

  const usedBytes = storageSummary?.used_bytes ?? null;
  const quotaBytes = storageSummary?.quota_bytes ?? null;
  const remainingBytes = storageSummary?.remaining_bytes ?? null;
  // Quota pressure is only meaningful against a configured quota; with none,
  // there is no denominator and the card says so rather than inventing 100%.
  const usedRatio =
    usedBytes !== null && quotaBytes !== null && quotaBytes > 0
      ? Math.min(usedBytes / quotaBytes, 1)
      : null;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.assets.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("page.assets.description")}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.assets.storage.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          {storageSummaryError ? (
            <p role="alert" className="text-sm text-destructive">
              {t("page.assets.storage.error", { message: storageSummaryError.message })}
            </p>
          ) : isStorageSummaryLoading || !storageSummary ? (
            <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
          ) : (
            <div className="flex flex-col gap-2">
              <p className="text-sm">
                {quotaBytes !== null
                  ? t("page.assets.storage.usageWithQuota", {
                      used: format.bytes(storageSummary.used_bytes),
                      quota: format.bytes(quotaBytes),
                    })
                  : t("page.assets.storage.usageNoQuota", {
                      used: format.bytes(storageSummary.used_bytes),
                    })}
              </p>
              {usedRatio !== null ? (
                // biome-ignore lint/a11y/useFocusableInteractive: a progressbar is a non-interactive status indicator, not a tab stop
                <div
                  className="h-2 w-full overflow-hidden rounded-full bg-secondary"
                  role="progressbar"
                  aria-label={t("page.assets.storage.title")}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(usedRatio * 100)}
                >
                  <div
                    className={
                      usedRatio >= QUOTA_PRESSURE_RATIO
                        ? "h-full bg-destructive transition-all"
                        : "h-full bg-primary transition-all"
                    }
                    style={{ width: `${Math.round(usedRatio * 100)}%` }}
                  />
                </div>
              ) : null}
              {/* remaining_bytes is the authoritative headroom (#338) — it is
                  the gateway's saturating quota-minus-usage, not a subtraction
                  this page performs, and it is null exactly when storage is
                  unlimited. */}
              {remainingBytes !== null ? (
                <p className="text-sm text-muted-foreground">
                  {t("page.assets.storage.remaining", {
                    remaining: format.bytes(remainingBytes),
                    percent: format.percent(usedRatio ?? 0, 0),
                  })}
                </p>
              ) : null}
              {usedRatio !== null && usedRatio >= QUOTA_PRESSURE_RATIO ? (
                <p role="alert" className="text-sm font-medium text-destructive">
                  {t("page.assets.storage.pressure", {
                    percent: format.percent(usedRatio, 0),
                  })}
                </p>
              ) : null}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.assets.push.title")}</CardTitle>
          <CardDescription>{t("page.assets.push.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              uploadMutation.mutate();
            }}
          >
            <div className="grid gap-2">
              <Label htmlFor="asset-type">{t("page.assets.field.assetType")}</Label>
              <Select value={assetType} onValueChange={setAssetType}>
                <SelectTrigger id="asset-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ASSET_TYPES.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {t(option.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-name">{t("page.assets.field.name")}</Label>
              <Input
                id="asset-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                // eslint-disable-next-line ferrogate/no-untranslated-literal -- example asset name, not translatable copy
                placeholder="my-tool"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-version">{t("page.assets.field.version")}</Label>
              <Input
                id="asset-version"
                value={version}
                onChange={(event) => setVersion(event.target.value)}
                placeholder="1.0.0"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-file">{t("page.assets.field.file")}</Label>
              <Input
                id="asset-file"
                type="file"
                ref={fileInputRef}
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                required
              />
              {/* Inline vs presigned selection is driven by the authoritative
                  ceiling, not by the operator guessing between two forms. The
                  hint only renders once the summary has actually supplied one. */}
              {inlineMaxBytes !== null ? (
                <p className="text-xs text-muted-foreground">
                  {t("page.assets.push.inlineLimit", {
                    max: format.bytes(inlineMaxBytes),
                  })}
                </p>
              ) : null}
            </div>
            {inlineTooLarge && inlineMaxBytes !== null && file ? (
              <p
                role="alert"
                className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive sm:col-span-2"
              >
                {t("page.assets.push.tooLargeForInline", {
                  size: format.bytes(file.size),
                  max: format.bytes(inlineMaxBytes),
                })}
              </p>
            ) : null}
            <div className="sm:col-span-2">
              <Button type="submit" disabled={uploadMutation.isPending || inlineTooLarge}>
                {uploadMutation.isPending
                  ? t("page.assets.push.submitting")
                  : t("page.assets.push.submit")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <PresignedUploadCard
        apiKey={apiKey}
        storageSummary={storageSummary}
        isLoading={isStorageSummaryLoading}
        onCommitted={() => {
          queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
          queryClient.invalidateQueries({
            queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY,
          });
        }}
      />

      <div className="flex flex-wrap items-end gap-4">
        <div className="grid gap-2">
          <Label htmlFor="asset-filter-type">{t("page.assets.field.assetType")}</Label>
          <Select
            value={filterType}
            onValueChange={(value) => setBrowseParam("type", value === ALL_TYPES ? null : value)}
          >
            <SelectTrigger id="asset-filter-type" className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_TYPES}>{t("page.withheldAssets.filter.allTypes")}</SelectItem>
              {ASSET_TYPES.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {t(option.labelKey)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="asset-search">{t("page.withheldAssets.filter.search")}</Label>
          <Input
            id="asset-search"
            className="w-64"
            value={search}
            onChange={(event) => setBrowseParam("q", event.target.value)}
          />
        </div>
      </div>

      {listError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.assets.list.error", { message: listError.message })}
        </p>
      ) : null}

      <ResourceTable
        columns={columns}
        rows={resources}
        isLoading={isLoading}
        emptyLabel={t("page.assets.empty")}
        rowLabel={(row) => `${row.assetType}/${row.name}`}
        renderActions={(row) => (
          <Button
            variant="outline"
            size="sm"
            className="min-h-11 lg:min-h-0"
            onClick={() => selectResource(row)}
          >
            {t("resource.table.moreDetails")}
          </Button>
        )}
      />

      <AssetDetailDialog
        resource={selected}
        apiKey={apiKey}
        selectedVersion={selectedVersion}
        onSelectVersion={selectVersion}
        onClose={() => selectResource(null)}
      />
    </div>
  );
}
