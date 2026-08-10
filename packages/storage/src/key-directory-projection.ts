/**
 * Zero-D1 S6 (#882): a per-colo KV PROJECTION of the CONTROL `api_key_directory`,
 * so the gateway auth hot path can serve HOP 1 (`credential → tenant`) from a KV
 * read on a cold-isolate / cross-region miss instead of an RPC to the single
 * singleton {@link ControlDataObject}.
 *
 * ## What this is, and — more importantly — what it is NOT
 *
 * It is a CACHE of the ROUTING hop only. A KV row carries exactly the columns
 * {@link ApiKeyDirectoryRow} does: the owning tenant/project/workspace and the
 * three fail-closed lifecycle bits. It does NOT carry scopes, budgets or
 * allow-lists, because those are the TENANT's authoritative data read in HOP 2,
 * and a KV hit still goes through HOP 2 and every lifecycle check. This layer can
 * therefore make authentication FASTER, never LOOSER: the worst a stale or
 * corrupt KV entry can do is send a request to HOP 2, which then denies it.
 *
 * ## The fail-closed properties, stated as code
 *
 *  - **POSITIVE ONLY.** Only a directory row the control object actually holds is
 *    ever written (the write-through in `virtual_keys.ts::directoryLeg`, and the
 *    read-ahead populate on an RPC that returned a row). An unknown credential —
 *    no directory row — is NEVER written, so a key-spray cannot seed the cache and
 *    a miss can never be mistaken for a hit.
 *  - **A CORRUPT ENTRY IS A MISS.** {@link read} returns `null` for absent,
 *    unparseable OR shape-invalid bytes, so a garbled value forces the
 *    authoritative RPC rather than resolving something. There is no path from bad
 *    cache bytes to an authenticated request.
 *  - **DELETE-ON-REVOKE.** The write-through DELETEs the KV entry when a key is
 *    revoked/disabled/rotated, before the authoritative directory write, so a
 *    revoked key stops resolving from KV promptly rather than waiting out the TTL.
 *  - **A TTL BACKSTOP.** Every positive write carries an `expirationTtl`, so an
 *    entry a delete somehow missed still self-expires. HOP 2 already denies a
 *    revoked key inside that window; the TTL only bounds how long a stale ROUTING
 *    row can linger, and a stale routing row authenticates nothing on its own.
 *
 * ## Why the TTL is clamped to 60s even though the key cache is 30s
 *
 * The intended alignment is {@link DEFAULT_KEY_DIRECTORY_PROJECTION_TTL_SECONDS}
 * (30s — the gateway's `DEFAULT_API_KEY_CACHE_TTL_SECONDS`). Cloudflare KV
 * refuses an `expirationTtl` below {@link KV_MIN_EXPIRATION_TTL_SECONDS} (60s), so
 * the write clamps up to that floor. This does not weaken revocation: the primary
 * mechanism is delete-on-revoke (immediate) and HOP 2 re-authorization (immediate,
 * even if the delete failed and a stale routing row survives). The TTL is only the
 * backstop for a routing row that was never deleted, and a routing row alone can
 * authenticate nothing — HOP 2 owns that.
 */
import type { ApiKeyDirectoryRow } from "./api-key-directory.js";

/**
 * The default projection TTL, mirroring the gateway's
 * `DEFAULT_API_KEY_CACHE_TTL_SECONDS`. Kept as a constant here (rather than
 * imported from `apps/gateway`) so this package stays app-independent; both the
 * writer (control-plane) and the reader-populate (gateway) default to it.
 */
export const DEFAULT_KEY_DIRECTORY_PROJECTION_TTL_SECONDS = 30;

/** Cloudflare KV's minimum `expirationTtl`. A positive write clamps up to this. */
export const KV_MIN_EXPIRATION_TTL_SECONDS = 60;

/** The KV key prefix — namespaced + versioned so the byte format can evolve. */
export const KEY_DIRECTORY_PROJECTION_PREFIX = "akd:v1:";

/** The KV key a directory row is stored under, derived only from its `key_hash`. */
export function keyDirectoryProjectionKey(keyHash: string): string {
  return `${KEY_DIRECTORY_PROJECTION_PREFIX}${keyHash}`;
}

/**
 * The seam the gateway's HOP 1 read-ahead and the control-plane write-through both
 * depend on. Injected so both sides are testable without a real KV binding, and so
 * the `D1TwoHopApiKeyDirectory` stays inject-free (no projection ⇒ pure RPC).
 */
export interface ApiKeyDirectoryProjection {
  /** A cached routing row, or `null` for absent / unparseable / shape-invalid bytes. */
  read(keyHash: string): Promise<ApiKeyDirectoryRow | null>;
  /** Upsert a POSITIVE routing row under `row`'s `key_hash`, with the TTL backstop. */
  write(keyHash: string, row: ApiKeyDirectoryRow): Promise<void>;
  /** Drop the routing row for `keyHash` (revoke/disable/rotate). */
  delete(keyHash: string): Promise<void>;
}

/**
 * The KV surface this module needs — narrower than `KVNamespace` on purpose, so a
 * test double is a three-method object and this module reaches no method a
 * projection has no business calling.
 */
export interface KeyDirectoryKv {
  get(key: string, type: "text"): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface KvApiKeyDirectoryProjectionOptions {
  /** TTL in seconds; clamped up to {@link KV_MIN_EXPIRATION_TTL_SECONDS} for KV. */
  readonly ttlSeconds?: number;
}

/**
 * Turn arbitrary decoded JSON into an {@link ApiKeyDirectoryRow}, or `null`.
 *
 * A missing or wrong-typed field yields `null` — a corrupt cache entry is a MISS,
 * never a partially-trusted row. This is the read side's whole fail-closed
 * guarantee, so it is deliberately strict about every column.
 */
function toDirectoryRow(value: unknown): ApiKeyDirectoryRow | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (
    typeof v.id !== "string" ||
    typeof v.tenant_id !== "string" ||
    typeof v.project_id !== "string" ||
    typeof v.workspace_id !== "string" ||
    typeof v.enabled !== "number"
  ) {
    return null;
  }
  const expires = v.expires_at_unix;
  const revoked = v.revoked_at_unix;
  if (!(expires === null || typeof expires === "number")) return null;
  if (!(revoked === null || typeof revoked === "number")) return null;
  return {
    id: v.id,
    tenant_id: v.tenant_id,
    project_id: v.project_id,
    workspace_id: v.workspace_id,
    enabled: v.enabled,
    expires_at_unix: expires,
    revoked_at_unix: revoked,
  };
}

/** The stored value — exactly the {@link ApiKeyDirectoryRow} columns, nothing wider. */
function serialize(row: ApiKeyDirectoryRow): string {
  return JSON.stringify({
    id: row.id,
    tenant_id: row.tenant_id,
    project_id: row.project_id,
    workspace_id: row.workspace_id,
    enabled: row.enabled,
    expires_at_unix: row.expires_at_unix,
    revoked_at_unix: row.revoked_at_unix,
  });
}

/** {@link ApiKeyDirectoryProjection} over a real KV namespace. */
export class KvApiKeyDirectoryProjection implements ApiKeyDirectoryProjection {
  readonly #kv: KeyDirectoryKv;
  readonly #expirationTtl: number;

  constructor(kv: KeyDirectoryKv, options: KvApiKeyDirectoryProjectionOptions = {}) {
    this.#kv = kv;
    const ttl = options.ttlSeconds ?? DEFAULT_KEY_DIRECTORY_PROJECTION_TTL_SECONDS;
    const floored = Number.isFinite(ttl)
      ? Math.floor(ttl)
      : DEFAULT_KEY_DIRECTORY_PROJECTION_TTL_SECONDS;
    this.#expirationTtl = Math.max(floored, KV_MIN_EXPIRATION_TTL_SECONDS);
  }

  async read(keyHash: string): Promise<ApiKeyDirectoryRow | null> {
    const raw = await this.#kv.get(keyDirectoryProjectionKey(keyHash), "text");
    if (raw === null) return null;
    let decoded: unknown;
    try {
      decoded = JSON.parse(raw);
    } catch {
      return null;
    }
    return toDirectoryRow(decoded);
  }

  async write(keyHash: string, row: ApiKeyDirectoryRow): Promise<void> {
    await this.#kv.put(keyDirectoryProjectionKey(keyHash), serialize(row), {
      expirationTtl: this.#expirationTtl,
    });
  }

  async delete(keyHash: string): Promise<void> {
    await this.#kv.delete(keyDirectoryProjectionKey(keyHash));
  }
}
