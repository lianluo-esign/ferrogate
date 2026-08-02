/**
 * JWKS fetching + caching, keyed by `jwks_uri`.
 *
 * ## Cache policy, and why
 *
 * **Positive TTL: 300 s (`JWKS_CACHE_TTL_SECONDS`).** An IdP's signing keys
 * change on the order of weeks, so the TTL is not about freshness of the happy
 * path — it is the bound on how long a WITHDRAWN key can still be honoured
 * here. Five minutes matches the window Okta/Entra/Auth0 all document for
 * propagating a key retirement, and matches the clock skew this package already
 * allows on `exp`, so a key can never outlive the tokens it signed by more than
 * one skew window. Longer would mean a compromised-and-rotated key keeps
 * verifying; shorter would put a network round trip in front of a meaningful
 * share of logins.
 *
 * **Unknown-`kid` forced refresh, rate-limited to one per 30 s
 * (`JWKS_FORCED_REFRESH_COOLDOWN_SECONDS`).** A rotation is announced by a
 * token arriving with a `kid` that is not in the cached document. Waiting out
 * the TTL would fail every login for up to five minutes, so an unknown `kid`
 * triggers ONE immediate refetch. Without the cooldown that same path is an
 * unauthenticated request amplifier: the caller controls the `kid`, so a
 * stream of forged tokens would become a stream of outbound fetches at the
 * IdP. With it, a flood of unknown `kid`s costs at most two fetches per minute.
 *
 * A failed fetch NEVER extends the life of a cached document and never yields
 * a key: `findKey` answers `null`, and `null` means "refuse the login".
 */
import type { FetchLike, IdentityClock } from "../ports.js";

/** How long a fetched JWKS document is served before it must be refetched. */
export const JWKS_CACHE_TTL_SECONDS = 300;

/** The minimum gap between two unknown-`kid`-triggered refetches of one URI. */
export const JWKS_FORCED_REFRESH_COOLDOWN_SECONDS = 30;

interface CacheEntry {
  keys: JsonWebKey[];
  fetchedAtUnix: number;
  lastForcedRefreshAtUnix: number;
}

export interface JwksCacheOptions {
  fetch: FetchLike;
  clock: IdentityClock;
  ttlSeconds?: number;
  forcedRefreshCooldownSeconds?: number;
}

/** True when a JWKS entry may be used to VERIFY a signature. */
function isVerificationKey(value: unknown): value is JsonWebKey & { kid: string } {
  if (typeof value !== "object" || value === null) return false;
  const jwk = value as JsonWebKey & { kid?: unknown };
  if (typeof jwk.kid !== "string" || jwk.kid.length === 0) return false;
  // `use` is optional, but when the IdP states it, an encryption key must not
  // be pressed into signature verification.
  if (typeof jwk.use === "string" && jwk.use !== "sig") return false;
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes("verify")) return false;
  return jwk.kty === "RSA" || jwk.kty === "EC";
}

export class JwksCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly fetchImpl: FetchLike;
  private readonly clock: IdentityClock;
  private readonly ttlSeconds: number;
  private readonly cooldownSeconds: number;

  constructor(options: JwksCacheOptions) {
    this.fetchImpl = options.fetch;
    this.clock = options.clock;
    this.ttlSeconds = options.ttlSeconds ?? JWKS_CACHE_TTL_SECONDS;
    this.cooldownSeconds =
      options.forcedRefreshCooldownSeconds ?? JWKS_FORCED_REFRESH_COOLDOWN_SECONDS;
  }

  /**
   * The verification key published at `jwksUri` under `kid`, or `null`.
   *
   * `null` is the ONLY failure signal — an unreachable IdP, a malformed
   * document and a genuinely unknown `kid` are indistinguishable to the
   * caller, and all three must refuse the login.
   */
  async findKey(jwksUri: string, kid: string): Promise<JsonWebKey | null> {
    const now = this.clock.nowUnix();
    let entry = this.entries.get(jwksUri);
    let loadedInThisCall = false;

    if (!entry || now - entry.fetchedAtUnix >= this.ttlSeconds) {
      const keys = await this.load(jwksUri);
      if (!keys) {
        // Do NOT serve the expired document: a stale key past its TTL is the
        // rotated-away key this cache exists to stop honouring.
        this.entries.delete(jwksUri);
        return null;
      }
      entry = { keys, fetchedAtUnix: now, lastForcedRefreshAtUnix: 0 };
      this.entries.set(jwksUri, entry);
      loadedInThisCall = true;
    }

    const hit = entry.keys.find((key) => (key as { kid?: string }).kid === kid);
    if (hit) return hit;

    // A miss against a document we fetched microseconds ago is a REAL miss —
    // refetching it again would be two round trips for one answer, and is how
    // a TTL expiry silently costs double at the IdP.
    if (loadedInThisCall) return null;

    // Unknown `kid` against a CACHED document — the shape a fresh rotation
    // takes. Refetch once, then sit on the cooldown so a forged `kid` cannot
    // drive unbounded egress.
    if (now - entry.lastForcedRefreshAtUnix < this.cooldownSeconds) return null;
    entry.lastForcedRefreshAtUnix = now;
    const refreshed = await this.load(jwksUri);
    if (!refreshed) return null;
    entry.keys = refreshed;
    entry.fetchedAtUnix = now;
    return refreshed.find((key) => (key as { kid?: string }).kid === kid) ?? null;
  }

  /** Fetches and validates a JWKS document. `null` on any failure. */
  private async load(jwksUri: string): Promise<JsonWebKey[] | null> {
    let response: Response;
    try {
      response = await this.fetchImpl(jwksUri, {
        method: "GET",
        headers: { accept: "application/json" },
      });
    } catch {
      return null;
    }
    if (!response.ok) return null;
    let document: unknown;
    try {
      document = await response.json();
    } catch {
      return null;
    }
    if (typeof document !== "object" || document === null) return null;
    const keys = (document as { keys?: unknown }).keys;
    if (!Array.isArray(keys)) return null;
    return keys.filter(isVerificationKey);
  }
}
