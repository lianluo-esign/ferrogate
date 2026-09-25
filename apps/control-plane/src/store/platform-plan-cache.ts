import {
  PLATFORM_PLAN_SNAPSHOT_KEY,
  platformPlanSnapshotSchema,
} from "../../../gateway/src/ratelimit/plan-source.js";
import { rowToStoredPlan } from "../../../gateway/src/ratelimit/quota.js";
import { publishSnapshotIfChanged } from "./cache-publish.js";

export type PlatformPlanCachePublishResult =
  | { status: "unconfigured" }
  | { status: "published" | "unchanged"; plans: number; tenants: number };

/** The platform's definitions and assignments come from one atomic DB snapshot. */
export async function publishPlatformPlanCache(options: {
  db: D1Database;
  kv?: KVNamespace;
  nowMs?: number;
}): Promise<PlatformPlanCachePublishResult> {
  if (options.kv === undefined) return { status: "unconfigured" };
  const publishedAt = options.nowMs ?? Date.now();
  const results = await options.db.batch([
    options.db.prepare("SELECT * FROM plans ORDER BY id"),
    options.db.prepare("SELECT id, plan_id FROM tenants ORDER BY id"),
  ]);
  if (
    results.length !== 2 ||
    !results.every((result) => result.success && Array.isArray(result.results))
  ) {
    throw new Error("incomplete platform plan snapshot");
  }
  const snapshot = platformPlanSnapshotSchema.parse({
    schema_version: 1,
    published_at_ms: publishedAt,
    plans: (results[0]?.results ?? []).map((row) =>
      rowToStoredPlan(row as Record<string, unknown>),
    ),
    tenants: results[1]?.results,
  });
  const published = await publishSnapshotIfChanged(
    options.kv,
    PLATFORM_PLAN_SNAPSHOT_KEY,
    { ...snapshot },
    "published_at_ms",
    30_000,
  );
  return {
    status: published ? "published" : "unchanged",
    plans: snapshot.plans.length,
    tenants: snapshot.tenants.length,
  };
}

/** DB commit is authoritative. The scheduled publisher repairs failed KV writes. */
export async function refreshPlatformPlanCache(db: D1Database, kv?: KVNamespace): Promise<void> {
  try {
    await publishPlatformPlanCache({ db, kv });
  } catch {
    console.warn("control-plane: platform quota-plan cache publish failed");
  }
}
