/**
 * Contract group `admin_virtual_key` (8 operations) — the tenant-minted
 * credential family and its full lifecycle.
 *
 * ```
 *   GET/POST  /admin/v1/virtual-keys
 *   GET       /admin/v1/virtual-keys/{key_id}
 *   DELETE    /admin/v1/virtual-keys/{key_id}            revokeVirtualKey
 *   POST      /admin/v1/virtual-keys/{key_id}/enable
 *   POST      /admin/v1/virtual-keys/{key_id}/disable
 *   POST      /admin/v1/virtual-keys/{key_id}/revoke     revokeVirtualKeyAction
 *   POST      /admin/v1/virtual-keys/{key_id}/rotate
 * ```
 *
 * **`disable`/`revoke` are exactly the states that make a presented key answer
 * `401 invalid_api_key`, not 403.** `StorageApiKeyAuthenticator` checks
 * `enabled && !revoked && !expired` and returns `None` otherwise, so the
 * request falls through to the same `invalid_api_key` an unknown key gets. The
 * lifecycle written here is therefore the *cause* of the 401-vs-403 invariant
 * the auth middleware preserves — the two must stay consistent.
 *
 * **The plaintext secret is returned exactly once**, from `create` and
 * `rotate`, and never stored: Rust keeps `sha256:`/`blake2b:` hash +
 * `key_prefix` (16 chars) + `last4`. Every read path returns only those, so a
 * compromised admin *read* credential cannot harvest live keys.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { StoreConflictError, type StoreRecord } from "../ports.js";
import { adminItem } from "../responses.js";
import {
  type CollectionSpec,
  type GroupModule,
  actionHandler,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const VIRTUAL_KEYS = "virtual-keys";

export const virtualKeySchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  scopes: z.array(z.string()).optional(),
  allowed_models: z.array(z.string()).optional(),
  allowed_providers: z.array(z.string()).optional(),
  monthly_token_budget: z.number().int().min(0).nullish(),
  request_limit_per_minute: z.number().int().min(0).nullish(),
  expires_at: z.number().int().min(0).nullish(),
});

const VIRTUAL_KEY_SPEC: CollectionSpec = {
  segment: VIRTUAL_KEYS,
  object: "virtual_key",
  body: virtualKeySchema,
};

/** Rust `api_key.rs`: `fg_<hex>`, stored as hash + 16-char prefix + last4. */
export const VIRTUAL_KEY_PREFIX = "fg_";

function mintSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${VIRTUAL_KEY_PREFIX}${hex}`;
}

/** SHA-256 of the secret, hex, tagged the way Rust tags it. */
async function hashSecret(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

/** The non-secret projection every read path returns. */
async function materialize(
  record: Record<string, unknown>,
  secret: string,
): Promise<Record<string, unknown>> {
  return {
    ...record,
    key_hash: await hashSecret(secret),
    key_prefix: secret.slice(0, 16),
    last4: secret.slice(-4),
    enabled: true,
    revoked: false,
  };
}

export const adminVirtualKeyRoutes: GroupModule = crudGroup(
  "admin_virtual_key",
  [VIRTUAL_KEY_SPEC],
  {
    /** The ONE response that carries the plaintext secret. */
    createVirtualKey: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const body = await readJson(c, virtualKeySchema);
      const id =
        typeof body.id === "string" && body.id.trim() !== "" ? body.id.trim() : crypto.randomUUID();
      const secret = mintSecret();
      const record = (await materialize({ ...body, id }, secret)) as StoreRecord;
      try {
        const stored = await deps.store.create(VIRTUAL_KEYS, scope, record);
        return json(c, 201, {
          object: "virtual_key",
          virtual_key: stored,
          // Shown once, never persisted, never returned again.
          secret,
        });
      } catch (error) {
        if (error instanceof StoreConflictError) {
          throw new HttpError(409, "conflict", `virtual key ${id} already exists`);
        }
        throw error;
      }
    },

    enableVirtualKey: actionHandler({
      spec: VIRTUAL_KEY_SPEC,
      param: "key_id",
      apply: (_record, _body, now) => ({ enabled: true, revoked: false, enabled_at: now }),
    }),

    disableVirtualKey: actionHandler({
      spec: VIRTUAL_KEY_SPEC,
      param: "key_id",
      // `enabled: false` is what makes a presented key answer 401, not 403.
      apply: (_record, _body, now) => ({ enabled: false, disabled_at: now }),
    }),

    revokeVirtualKeyAction: actionHandler({
      spec: VIRTUAL_KEY_SPEC,
      param: "key_id",
      apply: (_record, _body, now) => ({ enabled: false, revoked: true, revoked_at: now }),
    }),

    /**
     * `DELETE /admin/v1/virtual-keys/{key_id}` — Rust names this
     * `revokeVirtualKey`, and it is a REVOCATION, not a row deletion. The
     * distinction is real: audit, billing and request-log rows reference the
     * key id, and deleting the row would orphan them.
     */
    revokeVirtualKey: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const keyId = pathParam(c, "key_id");
      const stored = await deps.store.merge(VIRTUAL_KEYS, scope, keyId, {
        enabled: false,
        revoked: true,
        revoked_at: Math.floor(Date.now() / 1000),
      });
      if (stored === null) throw new HttpError(404, "not_found", `virtual key ${keyId} not found`);
      return json(c, 200, adminItem("virtual_key", stored));
    },

    /** Mints a NEW secret and invalidates the old one atomically. */
    rotateVirtualKey: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const keyId = pathParam(c, "key_id");
      const existing = await deps.store.get(VIRTUAL_KEYS, scope, keyId);
      if (existing === null) {
        throw new HttpError(404, "not_found", `virtual key ${keyId} not found`);
      }
      const secret = mintSecret();
      const stored = await deps.store.merge(VIRTUAL_KEYS, scope, keyId, {
        key_hash: await hashSecret(secret),
        key_prefix: secret.slice(0, 16),
        last4: secret.slice(-4),
        enabled: true,
        revoked: false,
        rotated_at: Math.floor(Date.now() / 1000),
      });
      return json(c, 200, { object: "virtual_key", virtual_key: stored, secret });
    },
  },
);
