/**
 * Contract group `admin_api_key` (6 operations) — CRUD over
 * `/admin/v1/api-keys`, the operator-facing view of the gateway's own keys.
 *
 * ```
 *   GET/POST              /admin/v1/api-keys
 *   GET/PUT/PATCH/DELETE  /admin/v1/api-keys/{id}
 * ```
 *
 * Distinct from `admin_virtual_key` (`/admin/v1/virtual-keys`), which is the
 * tenant-minted credential family with its own enable/disable/revoke/rotate
 * lifecycle. Both exist in the Rust tree and both are ported; conflating them
 * would lose the lifecycle actions. The two are also NOT interchangeable at the
 * storage layer: `static_api_keys` carries `platform_operator`, which a
 * durable/virtual key can never declare (#515).
 *
 * The secret itself is never echoed: Rust stores `sha256:`/`blake2b:` hashes
 * plus a 16-char `key_prefix` and `last4`, and the admin views return only
 * those. The schema therefore refuses a client-supplied plaintext `secret`
 * rather than storing one — and `createAdminApiKey` MINTS one, returning the
 * plaintext exactly once.
 *
 * ## Why three write legs are overridden rather than declared on the spec
 *
 * `CollectionSpec.project` receives `(db, record, now)` and no caller, but every
 * write here needs the CALLER: `clampMintedScopes` is the rule that a minted key
 * never outranks its minter, and it is applied to the DOCUMENT so the admin
 * surface reports the authority the credential actually has. `PUT` additionally
 * has to carry the minted `key_hash`/`key_prefix`/`last4` forward — a whole-body
 * replace would otherwise drop the digest from the document while the
 * `static_api_keys` row kept authenticating, which is this family's own defect
 * class one field down.
 *
 * `DELETE` keeps the generic handler and the spec's `unproject` hook, which
 * removes the credential row BEFORE the document: a residual grant is the one
 * residue that is not survivable. See `store/static_keys.ts`.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { type AuthContext, StoreConflictError, type StoreRecord } from "../ports.js";
import { hashApiKeySecret } from "../store/api_keys.js";
import {
  clampMintedScopes,
  mintApiKeySecret,
  projectStaticApiKey,
  staticKeyProjectable,
  unprojectStaticApiKey,
} from "../store/static_keys.js";
import {
  type CollectionSpec,
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const API_KEYS = "api-keys";

export const adminApiKeySchema = adminRecordSchema
  .extend({
    enabled: z.boolean().optional(),
    scopes: z.array(z.string()).optional(),
    organization_id: z.string().trim().min(1).nullish(),
    expires_at: z.number().int().optional(),
  })
  .refine((body) => !("secret" in body) && !("key" in body), {
    message: "an API key secret is never accepted or echoed on the admin surface",
  });

const API_KEY_SPEC: CollectionSpec = {
  segment: API_KEYS,
  object: "api_key",
  body: adminApiKeySchema,
  unproject: (db, id) => unprojectStaticApiKey(db, id),
};

/** The server-owned triple. Minted at create, never client-supplied, never re-minted. */
const MINTED_FIELDS = ["key_hash", "key_prefix", "last4"] as const;

/**
 * Write the credential row for a committed document.
 *
 * Skipped entirely when no control database is bound — that is `store: "memory"`
 * or a deployment with no `DB`, where there is no table for the row to live in
 * and the document store is not durable either.
 */
async function projectCredential(c: Parameters<Handler>[0], record: StoreRecord): Promise<void> {
  const db = depsOf(c).controlDatabase;
  if (db === null) return;
  if (!staticKeyProjectable(record)) return;
  await projectStaticApiKey(db, record, Math.floor(Date.now() / 1000));
}

/** The caller's `AuthContext`, which `clampMintedScopes` measures the mint against. */
function authOf(c: Parameters<Handler>[0]): AuthContext {
  const auth = c.get("auth");
  if (auth === null || auth === undefined) {
    // Unreachable behind `contractAuth`; fail closed rather than mint unclamped.
    throw new HttpError(401, "invalid_api_key", "invalid API key");
  }
  return auth;
}

export const adminApiKeyRoutes: GroupModule = crudGroup("admin_api_key", [API_KEY_SPEC], {
  /** The ONE response that carries the plaintext secret. */
  createAdminApiKey: async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const body = (await readJson(c, adminApiKeySchema)) as Record<string, unknown>;
    const id =
      typeof body.id === "string" && body.id.trim() !== "" ? body.id.trim() : crypto.randomUUID();

    const secret = mintApiKeySecret();
    const record: StoreRecord = {
      ...clampMintedScopes(body, authOf(c)),
      id,
      key_hash: await hashApiKeySecret(secret),
      key_prefix: secret.slice(0, 16),
      last4: secret.slice(-4),
    };

    try {
      const stored = await deps.store.create(API_KEYS, scope, record);
      // Document first, then the GRANT: a crash between them leaves a
      // credential the operator can see that does not yet authenticate.
      await projectCredential(c, stored);
      return json(c, 201, {
        object: "api_key",
        api_key: stored,
        // Shown once, never persisted, never returned again.
        secret,
      });
    } catch (error) {
      if (error instanceof StoreConflictError) {
        throw new HttpError(409, "conflict", `api_key ${id} already exists`);
      }
      throw error;
    }
  },

  putAdminApiKey: async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const id = pathParam(c, "id");
    const body = (await readJson(c, adminApiKeySchema)) as Record<string, unknown>;

    const existing = await deps.store.get(API_KEYS, scope, id);
    if (existing === null) throw new HttpError(404, "not_found", `api_key ${id} not found`);

    // Carry the minted triple across the replace. Without this a `PUT` would
    // blank the digest from the document while the credential row kept
    // authenticating — the operator would be looking at a key they can no
    // longer identify, and the projection below would silently skip.
    const minted: Record<string, unknown> = {};
    for (const field of MINTED_FIELDS) minted[field] = existing[field];

    const stored = await deps.store.replace(API_KEYS, scope, id, {
      ...clampMintedScopes(body, authOf(c)),
      ...minted,
    });
    if (stored === null) throw new HttpError(404, "not_found", `api_key ${id} not found`);
    await projectCredential(c, stored);
    return json(c, 200, { object: "api_key", api_key: stored });
  },

  patchAdminApiKey: async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const id = pathParam(c, "id");
    const body = (await readJson(c, adminApiKeySchema)) as Record<string, unknown>;

    // The minted triple is server-owned on a PATCH too: a client that names
    // `key_hash` is trying to re-point an existing credential id at a secret of
    // its own choosing, which is credential injection rather than an edit.
    const patch = { ...clampMintedScopes(body, authOf(c)) };
    for (const field of MINTED_FIELDS) delete patch[field];

    const stored = await deps.store.merge(API_KEYS, scope, id, patch);
    if (stored === null) throw new HttpError(404, "not_found", `api_key ${id} not found`);
    await projectCredential(c, stored);
    return json(c, 200, { object: "api_key", api_key: stored });
  },
});
