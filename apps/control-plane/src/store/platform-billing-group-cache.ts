import {
  PLATFORM_BILLING_GROUP_SNAPSHOT_KEY,
  type PlatformBillingGroupSnapshot,
} from "../../../gateway/src/inference/billing-group-source.js";
import { PlatformBillingGroupStore } from "./platform-billing-group.js";

export type PlatformBillingGroupCachePublishResult =
  | { readonly status: "unconfigured" }
  | {
      readonly status: "published";
      readonly revision: number;
      readonly groups: number;
    };

/**
 * Publish one complete, versioned billing-group snapshot to `PLATFORM_CONFIG`
 * after the D1 commit (#961) — the account-global config the gateway money path
 * reads KV-first. This REPLACES the per-tenant Durable Object fan-out: one
 * atomic KV overwrite, not a serial RPC per tenant.
 *
 * Only the money-path fields travel (id, multiplier, enabled, provider_ids); the
 * `revision` lets a reader ignore a stale write that lost a KV race. A missing
 * registry (0028 not applied) yields an EMPTY snapshot at revision `0`, never a
 * throw — the gateway reads that as "no group has a multiplier" and every
 * request bills at the official price, the same fail-open direction the whole
 * multiplier path takes.
 *
 * Mirrors `platform-config-cache.ts::publishPlatformCatalogCache`.
 */
export async function publishPlatformBillingGroupsCache(options: {
  readonly db: D1Database;
  readonly kv?: KVNamespace;
  readonly nowUnix?: number;
}): Promise<PlatformBillingGroupCachePublishResult> {
  if (options.kv === undefined) return { status: "unconfigured" };

  const store = new PlatformBillingGroupStore({ db: options.db });
  const [groups, revision] = await Promise.all([store.listGroups(), store.revision()]);
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("platform billing-group revision is invalid");
  }

  const snapshot: PlatformBillingGroupSnapshot = {
    schema_version: 1,
    revision,
    published_at_unix: options.nowUnix ?? Math.floor(Date.now() / 1000),
    groups: groups.map((group) => ({
      id: group.id,
      multiplier: group.multiplier,
      enabled: group.enabled,
      provider_ids: group.provider_ids,
    })),
  };
  await options.kv.put(PLATFORM_BILLING_GROUP_SNAPSHOT_KEY, JSON.stringify(snapshot));
  return { status: "published", revision, groups: groups.length };
}
