import type { StoredPlan } from "@ferrogate/policy";
import { z } from "zod";

export const PLATFORM_PLAN_SNAPSHOT_KEY = "platform-config:quota-plans:v1";
// A missed mutation publish must not pin an old, more permissive plan indefinitely.
export const PLATFORM_PLAN_MAX_AGE_MS = 60_000;
const optionalLimit = z.number().finite().nonnegative().optional();
export const storedPlanSchema = z.object({
  id: z.string().min(1),
  name: z.string(),
  slug: z.string(),
  mcpEnabled: z.boolean(),
  selfHostedWorkersEnabled: z.boolean(),
  adminConsoleSeats: optionalLimit,
  defaultModelAllowlist: z.array(z.string()),
  defaultRpmLimit: optionalLimit,
  defaultTpmLimit: optionalLimit,
  defaultMonthlyBudgetUsd: optionalLimit,
  createdAtUnix: z.number().finite(),
  updatedAtUnix: z.number().finite(),
  assetHostingEnabled: z.boolean(),
  defaultAssetStorageQuotaBytes: optionalLimit,
  defaultAssetMaxObjectBytes: optionalLimit,
  defaultAgentCostBudgetUsd: optionalLimit,
  defaultMonthlyEgressBytesBudget: optionalLimit,
  defaultDownloadRpmLimit: optionalLimit,
  extensionToolsEnabled: z.boolean(),
});
export const platformPlanSnapshotSchema = z.object({
  schema_version: z.literal(1),
  published_at_ms: z.number().int().nonnegative(),
  plans: z.array(storedPlanSchema),
  tenants: z.array(z.object({ id: z.string().min(1), plan_id: z.string() })),
});
export type PlatformPlanSnapshot = z.infer<typeof platformPlanSnapshotSchema>;
export type CachedPlan = { plan: StoredPlan | undefined; expiresAtMs: number };
type SnapshotEntry = {
  publishedAt: number;
  expiresAt: number;
  plans: Map<string, StoredPlan>;
  tenants: Map<string, string>;
};
const snapshots = new WeakMap<object, SnapshotEntry>();

/** Only completed, validated data is shared; request I/O and promises are never retained. */
export async function platformPlanFromKv(
  kv: KVNamespace | undefined,
  tenantId: string,
  now: () => number = Date.now,
): Promise<CachedPlan | undefined> {
  if (kv === undefined) return undefined;
  const startedAt = now();
  let cached = snapshots.get(kv);
  if (cached === undefined || cached.expiresAt <= startedAt) {
    try {
      const raw = await kv.get(PLATFORM_PLAN_SNAPSHOT_KEY, { cacheTtl: 30 });
      if (raw === null) return undefined;
      const parsed = platformPlanSnapshotSchema.safeParse(JSON.parse(raw));
      if (!parsed.success) return undefined;
      const value = parsed.data;
      const expiresAt = value.published_at_ms + PLATFORM_PLAN_MAX_AGE_MS;
      if (value.published_at_ms > now() || expiresAt <= now()) return undefined;
      const plans = new Map(value.plans.map((plan) => [plan.id, plan]));
      const tenants = new Map(value.tenants.map((tenant) => [tenant.id, tenant.plan_id]));
      if (plans.size !== value.plans.length || tenants.size !== value.tenants.length)
        return undefined;
      // Recheck after I/O: a slower request must not overwrite a newer snapshot.
      const latest = snapshots.get(kv);
      cached =
        latest !== undefined &&
        latest.publishedAt > value.published_at_ms &&
        latest.expiresAt > now()
          ? latest
          : {
              publishedAt: value.published_at_ms,
              expiresAt: Math.min(startedAt + 5_000, expiresAt),
              plans,
              tenants,
            };
      snapshots.set(kv, cached);
    } catch {
      return undefined; // A failure or invalid value always falls back to the authority.
    }
  }
  if (!cached.tenants.has(tenantId)) return undefined;
  const planId = cached.tenants.get(tenantId) as string;
  // Dangling assignments need an authoritative join, not a guessed unlimited plan.
  if (planId !== "" && !cached.plans.has(planId)) return undefined;
  return {
    plan: cached.plans.get(planId),
    expiresAtMs: Math.min(cached.expiresAt, cached.publishedAt + PLATFORM_PLAN_MAX_AGE_MS),
  };
}
