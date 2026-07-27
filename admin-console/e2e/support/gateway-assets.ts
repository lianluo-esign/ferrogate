// Bespoke browser-contract mocks for the assets registry GATEWAY surface
// (issue #344). The assets page (src/pages/assets.tsx) does NOT talk to the
// Admin API (`/admin/v1/*`) that installAuthenticatedAdminApi covers — it
// fetches the tenant gateway paths `/v1/assets`, `/v1/assets/storage/summary`,
// `/v1/assets/{type}/{name}/manifest`, the presign upload/commit endpoints, and
// the channel/yank/delete mutation endpoints, all against GATEWAY_ADMIN_BASE_URL
// (`http://localhost:8080` in tests). #348 flagged that the shared admin mock
// leaves those unmocked, so this module supplies faithful, STATEFUL mocks whose
// shapes match the generated OpenAPI contract (AssetSummary / AssetManifest /
// AssetStorageSummary / AssetPresignUploadIntentResponse / ...).
//
// State is rebuilt fresh per install() call so each test is isolated. Mutations
// (yank/unyank, channel move/delete, permanent delete, presign commit) mutate
// the in-memory manifest so a subsequent manifest/list refetch — which the page
// triggers via invalidateQueries — reflects the change (a yanked badge appears,
// a moved channel repoints, a deleted version disappears). That lets the spec
// assert real post-conditions, not just fire-and-forget request sends.
import type { Page, Route } from "@playwright/test";
import type { components } from "../../src/lib/api-types.generated";

type AssetSummary = components["schemas"]["AssetSummary"];
type AssetManifest = components["schemas"]["AssetManifest"];
type AssetManifestVersion = components["schemas"]["AssetManifestVersion"];
type AssetChannelSummary = components["schemas"]["AssetChannelSummary"];
type AssetStorageSummary = components["schemas"]["AssetStorageSummary"];

export interface GatewayAssetsOptions {
  /**
   * Exact gateway pathnames to answer with a 503 partial failure (an isolated
   * SECTION error, e.g. the storage-summary card, so the page's partial-error
   * surface can be exercised without blanking the healthy registry list).
   */
  failPaths?: string[];
  /**
   * Hold the direct-to-bucket PUT open this many ms so the presigned upload's
   * "Uploading to storage…" phase + progress bar are observable by a web-first
   * assertion. Zero (default) resolves the PUT immediately.
   */
  uploadHoldMs?: number;
}

const GATEWAY_ORIGIN = "http://localhost:8080";
const BUCKET_PREFIX = "/e2e-bucket/";

const HASH_A = "1".repeat(64);
const HASH_B = "2".repeat(64);
const HASH_C = "3".repeat(64);
const HASH_D = "4".repeat(64);
const HASH_E = "5".repeat(64);
const HASH_F = "6".repeat(64);

interface AssetsState {
  /** Flat per-version summary rows backing GET /v1/assets (the registry list). */
  summaries: AssetSummary[];
  /** Registry manifests keyed by `${asset_type}/${name}`. */
  manifests: Map<string, AssetManifest>;
  uploadCounter: number;
  /**
   * #368: the SHA-256 each intent signed, keyed by upload_id. The bucket route
   * compares the PUT's `x-amz-content-sha256` against it, because a real
   * S3-compatible bucket verifies the *value* in the signature, not the mere
   * presence of the header — a console sending a constant or stale digest
   * would 403 in production while a presence-only mock stayed green.
   */
  declaredSha256ByUpload: Map<string, string>;
  /** #368: upload_ids whose direct PUT the bucket route actually accepted. */
  stagedUploads: Set<string>;
}

function manifestKey(assetType: string, name: string): string {
  return `${assetType}/${name}`;
}

/**
 * Fresh fixture per test: a multi-version, multi-variant, multi-channel registry
 * with a YANKED target (deploy-cli@1.0.0) plus a second logical resource so the
 * list is non-trivial. deploy-cli@2.0.0 is the latest, bucket-backed, and has a
 * second platform variant; deploy-cli@1.5.0 is inline. Channels: stable->1.5.0,
 * canary->2.0.0.
 */
function buildState(): AssetsState {
  const deployCliVersions: AssetManifestVersion[] = [
    {
      version: "2.0.0",
      yanked: false,
      variants: [
        {
          variant: "",
          content_type: "application/gzip",
          content_hash: HASH_A,
          size_bytes: 734_003_200,
          storage_backed: true,
        },
        {
          variant: "linux-arm64",
          content_type: "application/gzip",
          content_hash: HASH_B,
          size_bytes: 712_003_584,
          storage_backed: true,
        },
      ],
    },
    {
      version: "1.5.0",
      yanked: false,
      variants: [
        {
          variant: "",
          content_type: "application/gzip",
          content_hash: HASH_C,
          size_bytes: 1_048_576,
          storage_backed: false,
        },
      ],
    },
    // Active and referenced by NO channel: the target for the yank and the
    // permanent-delete cases, which the gateway only permits on an
    // unreferenced version (#367).
    {
      version: "1.2.0",
      yanked: false,
      variants: [
        {
          variant: "",
          content_type: "application/gzip",
          content_hash: HASH_F,
          size_bytes: 2_097_152,
          storage_backed: false,
        },
      ],
    },
    {
      version: "1.0.0",
      yanked: true,
      variants: [
        {
          variant: "",
          content_type: "application/gzip",
          content_hash: HASH_D,
          size_bytes: 524_288,
          storage_backed: false,
        },
      ],
    },
  ];

  const deployCliManifest: AssetManifest = {
    object: "asset_manifest",
    asset_type: "cli_tool",
    name: "deploy-cli",
    channels: [
      { channel: "stable", version: "1.5.0", updated_at_unix: 1_752_000_500 },
      { channel: "canary", version: "2.0.0", updated_at_unix: 1_752_000_900 },
    ],
    versions: deployCliVersions,
  };

  const incidentToolsManifest: AssetManifest = {
    object: "asset_manifest",
    asset_type: "mcp_manifest",
    name: "incident-tools",
    channels: [],
    versions: [
      {
        version: "0.9.0",
        yanked: false,
        variants: [
          {
            variant: "",
            content_type: "application/json",
            content_hash: HASH_E,
            size_bytes: 4_096,
            storage_backed: false,
          },
        ],
      },
    ],
  };

  // #528: every row here is `visible` -- GET /v1/assets withholds the
  // pending_scan/quarantined ones (#366), so a listed row cannot be anything
  // else.
  const summaries: AssetSummary[] = [
    {
      id: "asset_deploy_cli_200",
      asset_type: "cli_tool",
      name: "deploy-cli",
      version: "2.0.0",
      content_type: "application/gzip",
      content_hash: HASH_A,
      size_bytes: 734_003_200,
      storage_backed: true,
      visibility: "visible",
      created_at_unix: 1_752_000_000,
      updated_at_unix: 1_752_000_900,
    },
    {
      id: "asset_deploy_cli_150",
      asset_type: "cli_tool",
      name: "deploy-cli",
      version: "1.5.0",
      content_type: "application/gzip",
      content_hash: HASH_C,
      size_bytes: 1_048_576,
      storage_backed: false,
      visibility: "visible",
      created_at_unix: 1_751_900_000,
      updated_at_unix: 1_752_000_500,
    },
    {
      id: "asset_deploy_cli_120",
      asset_type: "cli_tool",
      name: "deploy-cli",
      version: "1.2.0",
      content_type: "application/gzip",
      content_hash: HASH_F,
      size_bytes: 2_097_152,
      storage_backed: false,
      visibility: "visible",
      created_at_unix: 1_751_850_000,
      updated_at_unix: 1_751_860_000,
    },
    {
      id: "asset_deploy_cli_100",
      asset_type: "cli_tool",
      name: "deploy-cli",
      version: "1.0.0",
      content_type: "application/gzip",
      content_hash: HASH_D,
      size_bytes: 524_288,
      storage_backed: false,
      visibility: "visible",
      created_at_unix: 1_751_800_000,
      updated_at_unix: 1_751_850_000,
    },
    {
      id: "asset_incident_tools_090",
      asset_type: "mcp_manifest",
      name: "incident-tools",
      version: "0.9.0",
      content_type: "application/json",
      content_hash: HASH_E,
      size_bytes: 4_096,
      storage_backed: false,
      visibility: "visible",
      created_at_unix: 1_751_700_000,
      updated_at_unix: 1_751_760_000,
    },
  ];

  const manifests = new Map<string, AssetManifest>([
    [manifestKey("cli_tool", "deploy-cli"), deployCliManifest],
    [manifestKey("mcp_manifest", "incident-tools"), incidentToolsManifest],
  ]);

  return {
    summaries,
    manifests,
    uploadCounter: 0,
    declaredSha256ByUpload: new Map<string, string>(),
    stagedUploads: new Set<string>(),
  };
}

function storageSummary(): AssetStorageSummary {
  return {
    object: "asset_storage_summary",
    used_bytes: 1_572_864_000,
    quota_bytes: 5_368_709_120,
    remaining_bytes: 3_795_845_120,
    inline_upload_max_bytes: 5_242_880,
    presigned_upload: {
      enabled: true,
      max_object_bytes: 5_368_709_120,
      url_ttl_seconds: 900,
    },
  };
}

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function fail503(route: Route): Promise<void> {
  await fulfillJson(route, 503, {
    error: {
      code: "e2e_forced_failure",
      message: "forced browser-contract failure (assets gateway)",
    },
  });
}

async function notMocked(route: Route, method: string, pathname: string): Promise<void> {
  await fulfillJson(route, 501, {
    error: {
      code: "unmocked_e2e_route",
      message: `${method} ${pathname} is not mocked by the assets gateway contract`,
    },
  });
}

/** Summary rows for one logical version (there may be several across variants). */
function summariesForVersion(
  state: AssetsState,
  assetType: string,
  name: string,
  version: string,
): AssetSummary[] {
  return state.summaries.filter(
    (row) => row.asset_type === assetType && row.name === name && row.version === version,
  );
}

async function handleAssetsRequest(
  route: Route,
  state: AssetsState,
  options: GatewayAssetsOptions,
): Promise<void> {
  const request = route.request();
  const method = request.method();
  const url = new URL(request.url());
  const pathname = url.pathname;

  if (options.failPaths?.includes(pathname)) {
    await fail503(route);
    return;
  }

  // GET /v1/assets — the flat registry list. The contract declares NO query
  // params here (type/search filtering is client-side over the grouped rows),
  // so there is nothing to honor; the page never paginates this endpoint.
  if (method === "GET" && pathname === "/v1/assets") {
    await fulfillJson(route, 200, { object: "list", data: state.summaries });
    return;
  }

  // GET /v1/assets/storage/summary — authoritative quota + presign constraints.
  if (method === "GET" && pathname === "/v1/assets/storage/summary") {
    await fulfillJson(route, 200, storageSummary());
    return;
  }

  const segments = pathname
    .slice("/v1/assets".length)
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => decodeURIComponent(segment));

  // POST /v1/assets/presign/upload/{asset_type}/{name}/{version}
  if (
    method === "POST" &&
    segments.length === 5 &&
    segments[0] === "presign" &&
    segments[1] === "upload"
  ) {
    const [, , assetType, name, version] = segments;
    const body = (request.postDataJSON() ?? {}) as {
      size_bytes?: number;
      sha256?: string;
    };
    state.uploadCounter += 1;
    const uploadId = `upload_${state.uploadCounter}`;
    state.declaredSha256ByUpload.set(uploadId, body.sha256 ?? "");
    await fulfillJson(route, 200, {
      object: "asset_upload_intent",
      key: `${assetType}/${name}/${version}`,
      upload_id: uploadId,
      upload_url: `${GATEWAY_ORIGIN}${BUCKET_PREFIX}staging/${uploadId}`,
      method: "PUT",
      expires_in_seconds: 900,
      size_bytes: body.size_bytes ?? 0,
      sha256: body.sha256 ?? "",
      // #368: the real intent returns the SigV4 SignedHeaders the direct PUT
      // must carry. Omitting them here is what let a broken console pass:
      // the bucket route below now enforces them.
      required_headers: {
        "content-length": String(body.size_bytes ?? 0),
        "x-amz-content-sha256": body.sha256 ?? "",
      },
      max_object_bytes: 5 * 1024 * 1024 * 1024,
      upload_protocol: "single_put",
    });
    return;
  }

  // POST /v1/assets/presign/abort/{asset_type}/{name}/{version}
  //
  // #368: the console releases an intent it will not commit, so the mock must
  // answer it. `staging_reclamation` is reported as the tri-state the real
  // gateway returns — it is set from the DELETE's own result there, never from
  // the preceding HEAD.
  if (
    method === "POST" &&
    segments.length === 5 &&
    segments[0] === "presign" &&
    segments[1] === "abort"
  ) {
    const body = (request.postDataJSON() ?? {}) as {
      upload_id?: string;
      reason?: string;
    };
    const uploadId = body.upload_id ?? "";
    const staged = state.stagedUploads.delete(uploadId);
    await fulfillJson(route, 200, {
      object: "asset_upload_abort",
      upload_id: uploadId,
      staging_object_removed: staged,
      staging_reclamation: staged ? "removed" : "not_staged",
      outcome:
        body.reason === "bucket_rejected" && !staged ? "rejected_bucket" : "aborted",
    });
    return;
  }

  // POST /v1/assets/presign/commit/{asset_type}/{name}/{version}
  if (
    method === "POST" &&
    segments.length === 5 &&
    segments[0] === "presign" &&
    segments[1] === "commit"
  ) {
    const [, , assetType, name, version] = segments;
    const body = (request.postDataJSON() ?? {}) as {
      size_bytes?: number;
      sha256?: string;
      content_type?: string | null;
    };
    const asset: AssetSummary = {
      id: `asset_${assetType}_${name}_${version}`.replace(/[^a-z0-9_]/gi, "_"),
      asset_type: assetType,
      name,
      version,
      content_type: body.content_type ?? "application/octet-stream",
      content_hash: body.sha256 ?? HASH_A,
      size_bytes: body.size_bytes ?? 0,
      storage_backed: true,
      // #528: this fixture models the CLEAN commit (answered 200 below). A
      // withheld commit answers 202 with visibility pending_scan/quarantined.
      visibility: "visible",
      created_at_unix: 1_752_100_000,
      updated_at_unix: 1_752_100_000,
    };
    // Register the committed version so a subsequent list refetch reflects it.
    state.summaries = [asset, ...state.summaries];
    await fulfillJson(route, 200, { object: "asset", asset });
    return;
  }

  // GET /v1/assets/{asset_type}/{name}/manifest
  if (method === "GET" && segments.length === 3 && segments[2] === "manifest") {
    const [assetType, name] = segments;
    const manifest = state.manifests.get(manifestKey(assetType, name));
    if (!manifest) {
      await fulfillJson(route, 404, {
        error: { code: "asset_not_found", message: "manifest not found" },
      });
      return;
    }
    await fulfillJson(route, 200, manifest);
    return;
  }

  // PUT|DELETE /v1/assets/{asset_type}/{name}/channels/{channel}
  if (segments.length === 4 && segments[2] === "channels") {
    const [assetType, name, , channel] = segments;
    const manifest = state.manifests.get(manifestKey(assetType, name));
    if (!manifest) {
      await fulfillJson(route, 404, {
        error: { code: "asset_not_found", message: "asset not found" },
      });
      return;
    }
    if (method === "PUT") {
      const version = url.searchParams.get("version") ?? "";
      const next: AssetChannelSummary = {
        channel,
        version,
        updated_at_unix: 1_752_200_000,
      };
      const existing = manifest.channels.find((entry) => entry.channel === channel);
      if (existing) existing.version = version;
      else manifest.channels.push(next);
      manifest.channels.sort((a, b) => a.channel.localeCompare(b.channel));
      await fulfillJson(route, 200, {
        object: "asset_channel",
        asset_type: assetType,
        name,
        channel: next,
      });
      return;
    }
    if (method === "DELETE") {
      manifest.channels = manifest.channels.filter((entry) => entry.channel !== channel);
      await fulfillJson(route, 200, {
        object: "asset_channel",
        id: `${assetType}/${name}/channels/${channel}`,
        deleted: true,
      });
      return;
    }
  }

  // POST|DELETE /v1/assets/{asset_type}/{name}/{version}/yank
  if (segments.length === 4 && segments[3] === "yank") {
    const [assetType, name, version] = segments;
    const manifest = state.manifests.get(manifestKey(assetType, name));
    const target = manifest?.versions.find((entry) => entry.version === version);
    if (!manifest || !target) {
      await fulfillJson(route, 404, {
        error: { code: "asset_not_found", message: "version not found" },
      });
      return;
    }
    // #367: a yank is REJECTED while a channel still references the version
    // (VersionYankOutcome::ReferencedByChannel -> 409). Modelling that is the
    // point: a mock that yanks anything keeps a console green that would 409
    // against every real gateway. Unyank never coordinates.
    if (
      method === "POST" &&
      manifest.channels.some((entry) => entry.version === version)
    ) {
      await fulfillJson(route, 409, {
        error: {
          code: "asset_version_referenced",
          message: `${assetType}/${name}/${version} is still referenced by a channel; move the channel off this version before yanking`,
        },
      });
      return;
    }
    if (method === "POST" || method === "DELETE") {
      target.yanked = method === "POST";
      await fulfillJson(route, 200, {
        object: "list",
        data: summariesForVersion(state, assetType, name, version),
      });
      return;
    }
  }

  // /v1/assets/{asset_type}/{name}/{version} — GET download, DELETE purge.
  if (
    segments.length === 3 &&
    segments[2] !== "manifest" &&
    segments[2] !== "channels"
  ) {
    const [assetType, name, version] = segments;

    // Both verbs are VARIANT-addressed: `platform` selects the row, and an
    // omitted `platform` means the default ("") variant, exactly as `getAsset`
    // and `deleteAsset` document it.
    const platform = url.searchParams.get("platform") ?? "";

    if (method === "GET") {
      // The download action: the page issues this GET, wraps the bytes in an
      // object URL, and clicks a synthetic <a download>. Any body suffices; the
      // spec asserts the request/action, not the saved file.
      await route.fulfill({
        status: 200,
        contentType: "application/gzip",
        body: Buffer.from(
          `e2e-asset-bytes:${assetType}/${name}/${version}/${platform}`,
        ),
      });
      return;
    }

    if (method === "DELETE") {
      const manifest = state.manifests.get(manifestKey(assetType, name));
      const target = manifest?.versions.find((entry) => entry.version === version);
      const variantRow = target?.variants.find((entry) => entry.variant === platform);
      if (!manifest || !target || !variantRow) {
        await fulfillJson(route, 404, {
          error: {
            code: "asset_not_found",
            message: `no asset at ${assetType}/${name}/${version}${platform === "" ? "" : ` (${platform})`}`,
          },
        });
        return;
      }
      // #367 `delete_asset_variant_if_unreferenced`: removing the LAST
      // resolvable variant of a channel-referenced version is rejected, so a
      // live channel can never be stranded on an absent version. A mock that
      // returned 200 for every DELETE is precisely what let the previous round
      // ship a purge that neither warned about the blocker nor reported it.
      const isLastResolvable =
        target.variants.filter((entry) => entry.variant !== platform).length === 0;
      if (
        isLastResolvable &&
        manifest.channels.some((entry) => entry.version === version)
      ) {
        await fulfillJson(route, 409, {
          error: {
            code: "asset_version_referenced",
            message: `${assetType}/${name}/${version} is the last resolvable variant of a channel-referenced version; move or delete the channel first`,
          },
        });
        return;
      }
      target.variants = target.variants.filter((entry) => entry.variant !== platform);
      if (target.variants.length === 0) {
        manifest.versions = manifest.versions.filter(
          (entry) => entry.version !== version,
        );
        state.summaries = state.summaries.filter(
          (row) =>
            !(row.asset_type === assetType && row.name === name && row.version === version),
        );
      }
      await fulfillJson(route, 200, {
        object: "asset",
        id: `${assetType}/${name}/${version}`,
        deleted: true,
      });
      return;
    }
  }

  await notMocked(route, method, pathname);
}

/**
 * Installs the assets gateway mocks. Pair with installAuthenticatedAdminApi
 * (which seeds the session + Admin API shell). Registers two routes: the
 * `/v1/assets*` gateway surface, and the presigned direct-to-bucket PUT target
 * the intent hands back (kept off the gateway `/v1/assets` namespace, exactly
 * as the real flow bypasses the gateway body).
 */
export async function installGatewayAssets(
  page: Page,
  options: GatewayAssetsOptions = {},
): Promise<void> {
  const state = buildState();

  await page.route(
    (url) => url.pathname === "/v1/assets" || url.pathname.startsWith("/v1/assets/"),
    (route) => handleAssetsRequest(route, state, options),
  );

  // The presigned bucket PUT (putPresignedObject): direct-to-storage, no gateway
  // Authorization header. Succeed after the optional hold so the "uploading"
  // progress phase is observable.
  //
  // #368: this stands in for an S3-compatible bucket verifying the SigV4
  // SignedHeaders set, so it MUST fail closed the way a real bucket does. The
  // previous unconditional 200 is exactly what hid a console that never sent
  // `x-amz-content-sha256`: the suite stayed green while the real upload path
  // was dead. The header's VALUE is compared against the digest the intent
  // signed, not merely its presence — the signature binds the value, so a
  // console forwarding a constant or a stale hash 403s against every real
  // bucket while a presence-only assertion keeps passing. `content-length` is
  // signed too, but the browser supplies it from the body and Playwright's
  // `headers()` does not reliably surface network-stack-added headers, so
  // asserting it here would test the harness rather than the console.
  await page.route(
    (url) => url.pathname.startsWith(BUCKET_PREFIX),
    async (route) => {
      if (options.uploadHoldMs && options.uploadHoldMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, options.uploadHoldMs));
      }
      const uploadId = new URL(route.request().url()).pathname
        .slice(BUCKET_PREFIX.length)
        .replace(/^staging\//, "");
      const signed = state.declaredSha256ByUpload.get(uploadId);
      const payloadHash = route.request().headers()["x-amz-content-sha256"] ?? "";
      if (payloadHash === "" || (signed !== undefined && payloadHash !== signed)) {
        await route.fulfill({
          status: 403,
          contentType: "application/xml",
          body: `<Error><Code>SignatureDoesNotMatch</Code><Message>x-amz-content-sha256 is a signed header: expected ${signed ?? "(unknown intent)"}, got ${payloadHash === "" ? "(absent)" : payloadHash}</Message></Error>`,
        });
        return;
      }
      state.stagedUploads.add(uploadId);
      await route.fulfill({ status: 200, contentType: "text/plain", body: "" });
    },
  );
}
