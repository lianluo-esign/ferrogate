import {
  PLATFORM_CATALOG_REVISION_SQL,
  PLATFORM_CATALOG_ROWS_SQL,
  PLATFORM_CATALOG_SNAPSHOT_KEY,
  type PlatformCatalogSnapshot,
} from "../../../gateway/src/inference/platform-catalog.js";
import type { CatalogJoinRow } from "../../../gateway/src/inference/tenant-catalog.js";

export type PlatformConfigCachePublishResult =
  | { readonly status: "unconfigured" }
  | {
      readonly status: "published";
      readonly revision: number;
      readonly rows: number;
    };

/** Publish one complete, versioned routing snapshot after the D1 commit. */
export async function publishPlatformCatalogCache(options: {
  readonly db: D1Database;
  readonly kv?: KVNamespace;
  readonly nowUnix?: number;
}): Promise<PlatformConfigCachePublishResult> {
  if (options.kv === undefined) return { status: "unconfigured" };

  const results = await options.db.batch([
    options.db.prepare(PLATFORM_CATALOG_REVISION_SQL),
    options.db.prepare(PLATFORM_CATALOG_ROWS_SQL),
  ]);
  const revisionResult = results[0] as D1Result<{ revision: number | string | null }> | undefined;
  const rows = results[1] as D1Result<CatalogJoinRow> | undefined;
  if (revisionResult === undefined || rows === undefined) {
    throw new Error("platform catalog snapshot batch returned an incomplete result");
  }
  const revision = Number(revisionResult.results[0]?.revision ?? 0);
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("platform catalog revision is invalid");
  }

  const snapshot: PlatformCatalogSnapshot = {
    schema_version: 2,
    revision,
    published_at_unix: options.nowUnix ?? Math.floor(Date.now() / 1000),
    rows: rows.results,
  };
  await options.kv.put(PLATFORM_CATALOG_SNAPSHOT_KEY, JSON.stringify(snapshot));
  return { status: "published", revision, rows: rows.results.length };
}
