/**
 * Contract group `retention_policy` (2 operations).
 *
 * `retention_policies` lives in the tenant database because it is consumed by
 * the tenant-local asset sweeper. The API keeps the resource type fixed to
 * `asset` and uses `{asset_type}` as the policy scope; `*` is the default rule.
 */
import {
  D1RetentionPolicyStore,
  RETENTION_RESOURCE_ASSET,
  type StoredRetentionPolicy,
  retentionPolicyId,
} from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import {
  type GroupModule,
  type Handler,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const RETENTION_POLICY_OBJECT = "retention_policy";

const retentionPolicyMutationSchema = z
  .object({
    keep_last_n: z.number().int().min(0).nullish(),
    max_age_secs: z.number().int().min(0).nullish(),
    min_age_secs: z.number().int().min(0).default(0),
  })
  .strict();

function tenantIdOf(c: Parameters<Handler>[0]): string {
  const tenantId = pathParam(c, "tenant_id");
  const scope = scopeOf(c);
  if (scope.kind === "platform_operator") return tenantId;
  if (scope.kind === "tenant" && scope.tenantId === tenantId) return tenantId;
  throw new HttpError(
    403,
    "tenant_scope_denied",
    `retention policy access is limited to tenant ${scope.kind === "tenant" ? scope.tenantId : "this credential"}`,
  );
}

async function storeOf(
  c: Parameters<Handler>[0],
  tenantId: string,
): Promise<D1RetentionPolicyStore> {
  const deps = depsOf(c);
  const handle = await tenantDatabaseFor(deps.tenantStorage ?? deps.tenantDatabases, tenantId);
  if (handle === null) {
    throw new HttpError(
      503,
      "tenant_database_unavailable",
      `tenant ${tenantId} has no reachable tenant database for retention policy storage`,
    );
  }
  return new D1RetentionPolicyStore(handle);
}

function wirePolicy(policy: StoredRetentionPolicy): Record<string, unknown> {
  return {
    id: policy.id,
    tenant_id: policy.tenantId,
    resource_type: policy.resourceType,
    scope: policy.scope,
    asset_type: policy.scope,
    keep_last_n: policy.keepLastN ?? null,
    max_age_secs: policy.maxAgeSecs ?? null,
    min_age_secs: policy.minAgeSecs,
    created_at_unix: policy.createdAtUnix,
    updated_at_unix: policy.updatedAtUnix,
  };
}

function assetTypeOf(c: Parameters<Handler>[0]): string {
  return pathParam(c, "asset_type");
}

const getAssetRetentionPolicy: Handler = async (c) => {
  const tenantId = tenantIdOf(c);
  const assetType = assetTypeOf(c);
  const policy = await (await storeOf(c, tenantId)).getRetentionPolicy(
    tenantId,
    RETENTION_RESOURCE_ASSET,
    assetType,
  );
  if (policy === undefined) {
    throw new HttpError(
      404,
      "not_found",
      `asset retention policy ${tenantId}:${assetType} not found`,
    );
  }
  return json(c, 200, { object: RETENTION_POLICY_OBJECT, retention_policy: wirePolicy(policy) });
};

const putAssetRetentionPolicy: Handler = async (c) => {
  const tenantId = tenantIdOf(c);
  const assetType = assetTypeOf(c);
  const body = await readJson(c, retentionPolicyMutationSchema);
  const store = await storeOf(c, tenantId);
  const nowUnix = Math.floor(Date.now() / 1000);
  const existing = await store.getRetentionPolicy(tenantId, RETENTION_RESOURCE_ASSET, assetType);
  const policy: StoredRetentionPolicy = {
    id: retentionPolicyId(tenantId, RETENTION_RESOURCE_ASSET, assetType),
    tenantId,
    resourceType: RETENTION_RESOURCE_ASSET,
    scope: assetType,
    keepLastN: body.keep_last_n ?? undefined,
    maxAgeSecs: body.max_age_secs ?? undefined,
    minAgeSecs: body.min_age_secs,
    createdAtUnix: existing?.createdAtUnix ?? nowUnix,
    updatedAtUnix: nowUnix,
  };
  await store.setRetentionPolicy(policy);
  return json(c, 200, { object: RETENTION_POLICY_OBJECT, retention_policy: wirePolicy(policy) });
};

export const retentionPolicyRoutes: GroupModule = {
  group: "retention_policy",
  build(operations) {
    const handlers = new Map<string, Handler>();
    const table: Record<string, Handler> = {
      getAssetRetentionPolicy,
      putAssetRetentionPolicy,
    };
    for (const operation of operations) {
      const handler = table[operation.operationId];
      if (handler === undefined) {
        throw new Error(
          `control-plane group retention_policy: operation ${operation.operationId} ` +
            `(${operation.method} ${operation.path}) has no handler`,
        );
      }
      handlers.set(operation.operationId, handler);
    }
    return handlers;
  },
};
