/**
 * Contract group `admin_provider_credential` (3 operations) — the tenant-facing
 * registration surface for per-tenant BYOK (issue #682).
 *
 * ```
 *   GET     /admin/v1/provider-credentials            list (REDACTED)
 *   PUT     /admin/v1/provider-credentials/{alias}    register OR rotate
 *   DELETE  /admin/v1/provider-credentials/{alias}    revoke
 * ```
 *
 * Read `packages/secrets/src/byok.ts` for the design; this module is only the
 * HTTP end of it. Three properties are the reason it is hand-written rather than
 * a `crudGroup` over `control_plane_resources` documents:
 *
 *  1. **The document store cannot hold this.** A generic admin document is
 *     readable back verbatim, and the whole point of the row is that the
 *     credential is NOT. Writes go to the typed
 *     `tenant_provider_credentials` table through
 *     `D1TenantProviderCredentialStore`, sealed by
 *     `sealTenantCredential` before they ever reach storage.
 *  2. **Register and rotate are ONE operation.** `PUT` on an alias is
 *     idempotent-by-key: first call registers, every later call rotates. That is
 *     what makes "rotate without a deploy" a single request, and it is why
 *     there is no `POST` — a create/update split would let a client rotate by
 *     accident or fail to rotate because it guessed wrong.
 *  3. **The tenant is the CALLER's.** It is never a body field and never a path
 *     segment, so there is nothing for a request to forge. A platform-operator
 *     credential is REFUSED here (403) rather than defaulting to some tenant:
 *     "which tenant is root registering this key for?" has no safe answer, and
 *     inventing one would put a credential in a partition nobody asked for.
 *
 * ## What a response may contain
 *
 * `last4` and metadata. Never the credential, never the ciphertext, never the
 * IV — the listing goes through `TenantProviderCredentialSummary`, a type with
 * no such fields, so a future edit to this file cannot leak what it was never
 * handed. `PUT` echoes the same summary shape rather than the request body,
 * because echoing the body would put the plaintext key in a response, in an
 * access log, and in every HTTP client's history.
 */
import {
  BYOK_ALIAS_PATTERN,
  byokKeyringFromEnvAsync,
  sealTenantCredential,
} from "@ferrogate/secrets";
import {
  backfillTenantConfigurationPolicy,
  credentialLast4,
  type D1TenantProviderCredentialStore,
  tenantProviderCredentialStoreFor,
} from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneEnv } from "../ports.js";
import type { Context } from "hono";
import {
  type GroupModule,
  type Handler,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

/** The request body of `PUT /admin/v1/provider-credentials/{alias}`. */
const putBodySchema = z
  .object({
    /**
     * `[[providers]].name` this credential authenticates against. Required,
     * with no default: a credential whose provider was guessed could be
     * presented to an upstream the tenant never negotiated with.
     */
    provider: z.string().trim().min(1),
    /** The provider API key. Sealed immediately; never stored or echoed. */
    value: z.string().min(1),
  })
  .strict();

/**
 * The tenant this request writes for. A platform operator has no tenant, so it
 * is refused rather than silently attributed — see the module docs.
 */
function tenantOf(c: Context<ControlPlaneEnv>): string {
  const scope = scopeOf(c);
  if (scope.kind !== "tenant") {
    throw new HttpError(
      403,
      "forbidden",
      "a BYOK provider credential belongs to a tenant; this credential is scoped to the " +
        "platform, not to a tenant, so there is no scope to register it in",
    );
  }
  return scope.tenantId;
}

/** The control database, or a precise 503 rather than a silent no-op. */
async function storeOf(
  c: Context<ControlPlaneEnv>,
  tenantId: string,
): Promise<D1TenantProviderCredentialStore> {
  const deps = depsOf(c);
  const control = deps.controlDatabase;
  if (control === null) {
    throw new HttpError(
      503,
      "storage_unavailable",
      "per-tenant BYOK needs the CONTROL_DB and TENANT_DATA bindings, which are not configured on this " +
        "deployment",
    );
  }
  await backfillTenantConfigurationPolicy(control, deps.tenantDatabases, tenantId);
  const handle = await deps.tenantDatabases.forTenant(tenantId);
  return tenantProviderCredentialStoreFor(handle);
}

/**
 * The fleet keyring. Async because the master key may be a Secrets Store
 * binding; a missing or malformed key is a 503 naming the BINDING, never the
 * value.
 */
async function keyringOf(c: Context<ControlPlaneEnv>): Promise<
  Awaited<ReturnType<typeof byokKeyringFromEnvAsync>>
> {
  try {
    return await byokKeyringFromEnvAsync(
      c.env as unknown as Parameters<typeof byokKeyringFromEnvAsync>[0],
    );
  } catch (error) {
    throw new HttpError(
      503,
      "byok_not_configured",
      `per-tenant BYOK is not enabled on this deployment: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/** Path `{alias}`, held to the same grammar the `byok://` parser enforces. */
function aliasOf(c: Context<ControlPlaneEnv>): string {
  const alias = pathParam(c, "alias");
  if (!BYOK_ALIAS_PATTERN.test(alias)) {
    throw new HttpError(
      400,
      "invalid_request_body",
      `alias must match ${BYOK_ALIAS_PATTERN.source} (lowercase alphanumerics plus . _ -, ` +
        "no path separators, 1-64 chars)",
    );
  }
  return alias;
}

const listProviderCredentials: Handler = async (c) => {
  // AUTHORIZATION BEFORE INFRASTRUCTURE, in every handler here. A caller with no
  // tenant scope must get its 403 without first learning whether this
  // deployment has a control database or a master key bound — a 503 answered
  // ahead of the scope check is a (small) configuration oracle for an
  // unauthorized caller, and it costs nothing to order it the other way.
  const tenantId = tenantOf(c);
  const rows = await (await storeOf(c, tenantId)).list(tenantId);
  // `object`/`data` is the admin list envelope this app uses elsewhere; the
  // rows are the REDACTED summary type, which has no credential field at all.
  return json(c, 200, { object: "list", data: rows });
};

const putProviderCredential: Handler = async (c) => {
  const tenantId = tenantOf(c);
  const alias = aliasOf(c);
  const body = await readJson(c, putBodySchema);
  const store = await storeOf(c, tenantId);
  const keyring = await keyringOf(c);

  // `last4` is derived BEFORE sealing, from the plaintext, because it is the
  // only part of the credential any surface will ever show and deriving it
  // later would mean handing the plaintext to a second module.
  const last4 = credentialLast4(body.value);
  const sealed = await sealTenantCredential(keyring, {
    tenantId,
    alias,
    provider: body.provider,
    value: body.value,
  });

  await store.upsert(
    {
      tenantId,
      alias,
      provider: sealed.provider,
      keyVersion: sealed.keyVersion,
      iv: sealed.iv,
      ciphertext: sealed.ciphertext,
      last4,
    },
    Math.floor(Date.now() / 1000),
  );

  // Read back rather than echoing the request: the response then carries the
  // stored metadata (including `created_at_unix`, which a rotation preserves)
  // and structurally cannot carry the key the caller just sent.
  const stored = await store.lookup(tenantId, alias);
  return json(c, 200, {
    object: "provider_credential",
    alias,
    provider: sealed.provider,
    last4,
    key_version: sealed.keyVersion,
    created_at_unix: stored?.createdAtUnix ?? null,
    rotated_at_unix: stored?.rotatedAtUnix ?? null,
  });
};

const revokeProviderCredential: Handler = async (c) => {
  const tenantId = tenantOf(c);
  const alias = aliasOf(c);
  const revoked = await (await storeOf(c, tenantId)).revoke(
    tenantId,
    alias,
    Math.floor(Date.now() / 1000),
  );
  if (!revoked) {
    // 404 for "this tenant has no live alias by that name" — the same answer
    // another tenant's alias produces, so this is not an oracle.
    throw new HttpError(404, "not_found", `no BYOK credential registered under ${alias}`);
  }
  return json(c, 200, { object: "provider_credential", alias, deleted: true });
};

export const adminProviderCredentialRoutes: GroupModule = {
  group: "admin_provider_credential",
  build(operations) {
    const handlers = new Map<string, Handler>();
    const table: Record<string, Handler> = {
      listProviderCredentials,
      putProviderCredential,
      revokeProviderCredential,
    };
    for (const operation of operations) {
      const handler = table[operation.operationId];
      if (handler === undefined) {
        // The same fail-loud rule `crudGroup` applies: a contract operation with
        // no handler must break the build, not 404 in production.
        throw new Error(
          `control-plane group admin_provider_credential: operation ${operation.operationId} ` +
            `(${operation.method} ${operation.path}) has no handler`,
        );
      }
      handlers.set(operation.operationId, handler);
    }
    return handlers;
  },
};
