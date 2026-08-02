/**
 * Revocation — the control that makes a delegation take-back-able (#691).
 *
 * ## The requirement, restated so the implementation can be checked against it
 *
 * Revoking a link must break EVERY chain that passes through it, and it must
 * take effect without waiting for expiry. A revocation that only applies when
 * the next link is minted is not a revocation: the compromised agent already
 * holds a valid link and will simply keep using it until `exp`.
 *
 * Both halves fall out of one decision: the verifier checks the revocation
 * state of **every link in the chain on every request**, not just the leaf and
 * not just at issue time. Revoking link 2 of a 4-link chain therefore refuses
 * links 3 and 4 as well, because they can only be presented together with the
 * link that was revoked — that is what "breaks every chain through it" means
 * structurally, and it is why the check is a walk rather than a lookup.
 *
 * ## Two things can be revoked, under one table
 *
 *  - a **link**, by its `jti` — surgical: this specific grant is dead;
 *  - a **principal**, by its `{kind}:{id}` — blast radius: this agent is
 *    compromised, kill everything it was given AND everything it granted.
 *
 * They share a table and a lookup because they answer the same question of the
 * same walk, and two tables would mean two chances to forget one of them in the
 * verifier. The `subject` column holds either form; a `jti` cannot collide with
 * a principal because a principal always contains a `:` after a known kind and
 * a `jti` is mint-generated.
 *
 * ## Fail CLOSED, with one carefully bounded exception
 *
 * A revocation list that cannot be read is unknown state, and admitting on
 * unknown state makes "flap the control plane" a revocation bypass — the same
 * argument `apps/gateway/src/ports.ts` makes for `LifecycleGateError::
 * Unavailable` and `attribution/source.ts` makes for its 503. So a read failure
 * is `{ ok: false }` and the gateway answers 503.
 *
 * The exception is a schema that PREDATES this table: a database with no
 * `delegation_revocations` table is physically incapable of holding a
 * revocation, so "nothing is revoked" is a complete reading of a known state
 * rather than a guess about an unknown one. Without this, deploying the Worker
 * before applying the migration would 503 every delegated request. This is the
 * same exception, for the same reason and matched the same way, as
 * `attribution/source.ts::schemaPredatesAttribution`.
 */

/**
 * The outcome of asking "which of these are revoked?".
 *
 * `revoked` is EVERY subject found revoked, not the first one. That is not
 * tidiness: {@link cachedDelegationRevocationSource} caches one entry per
 * subject asked about, so a source that reported only the first hit would have
 * it record every other revoked subject in the same batch as NOT revoked — a
 * cache-poisoning bug in which revoking two links makes one of them work again
 * for a TTL. The port returns the whole answer so the memo can store the whole
 * answer.
 */
export type DelegationRevocationResolution =
  | { readonly ok: true; readonly revoked: readonly string[] }
  | { readonly ok: false; readonly detail: string };

export interface DelegationRevocationSource {
  /**
   * Are any of `subjects` (link `jti`s and/or principals) revoked for `tenant`?
   *
   * Batched deliberately: a depth-8 chain asks about at most 8 jtis plus at
   * most 9 principals in ONE round trip, so the revocation check costs one
   * database read per request rather than seventeen.
   */
  revoked(tenant: string, subjects: readonly string[]): Promise<DelegationRevocationResolution>;
}

/** The posture of a deployment that has revoked nothing. */
export const NO_DELEGATION_REVOCATIONS: DelegationRevocationSource = {
  async revoked(): Promise<DelegationRevocationResolution> {
    return { ok: true, revoked: [] };
  },
};

/** The table this module reads, and `sql/d1-ts/control/0008_delegation_chain.sql` creates. */
export const DELEGATION_REVOCATION_TABLE = "delegation_revocations";

/** The `D1Database` subset this module needs; a live binding fits. */
export interface DelegationRevocationDatabase {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
    };
  };
}

/**
 * Does this failure mean "the schema predates #691" rather than "the database
 * is unavailable"? See the header comment on why the distinction is not a
 * fail-open hole.
 */
function schemaPredatesDelegation(detail: string): boolean {
  return new RegExp(`no such table:\\s*${DELEGATION_REVOCATION_TABLE}`, "i").test(detail);
}

/**
 * The durable source — one indexed read against the CONTROL database.
 *
 * `tenant = ?` is a bound equality and it is the fence: without it, tenant A
 * could revoke a `jti` and break tenant B's chain (a cross-tenant denial of
 * service), and — worse in the other direction — a lookup that ignored the
 * tenant would let a revocation row written for one tenant be read as authority
 * over another's audit trail.
 *
 * The `IN` list is built from a bound placeholder PER SUBJECT, never
 * interpolated, and its length is bounded by {@link MAX_DELEGATION_DEPTH} two
 * links up the call chain — so the statement text takes one of a handful of
 * shapes and D1's prepared-statement cache is not defeated by unbounded arity.
 */
export function d1DelegationRevocationSource(
  db: DelegationRevocationDatabase,
): DelegationRevocationSource {
  return {
    async revoked(
      tenant: string,
      subjects: readonly string[],
    ): Promise<DelegationRevocationResolution> {
      if (subjects.length === 0) return { ok: true, revoked: [] };
      const placeholders = subjects.map(() => "?").join(", ");
      try {
        const result = await db
          .prepare(
            `SELECT subject FROM ${DELEGATION_REVOCATION_TABLE} ` +
              `WHERE tenant = ? AND subject IN (${placeholders})`,
          )
          .bind(tenant, ...subjects)
          .all<{ subject?: unknown }>();
        const revoked = result.results
          .map((row) => row.subject)
          .filter((subject): subject is string => typeof subject === "string");
        return { ok: true, revoked };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (schemaPredatesDelegation(detail)) return { ok: true, revoked: [] };
        return { ok: false, detail };
      }
    },
  };
}

/**
 * How long a revocation ANSWER is trusted inside one isolate, in milliseconds.
 *
 * **This number is the maximum time between an operator revoking and the whole
 * fleet obeying**, so it is chosen against that sentence and not against
 * database load. Five seconds means a compromised agent gets at most five more
 * seconds of traffic on a warm isolate; it also means a busy isolate does at
 * most one read per five seconds per distinct chain, which is what keeps the
 * check affordable enough to run on every request instead of "at renewal".
 *
 * Longer would be cheaper and would start to turn this back into renewal-time
 * revocation. Zero would be strictly correct and would put a D1 read in front of
 * every delegated inference call, including retries.
 */
export const DELEGATION_REVOCATION_TTL_MS = 5_000;

/**
 * A per-isolate memo in front of any source, keyed per `(tenant, subject)`.
 *
 * ## The key is the fence, again
 *
 * Keying on the tenant AND the subject is what stops one tenant's cached
 * "revoked" from refusing another tenant's identically-named subject, and one
 * tenant's cached "not revoked" from admitting another's revoked one. A memo
 * keyed on the subject alone would be a cross-tenant control leak the moment
 * two tenants share a warm isolate — which on Workers is the normal case.
 *
 * ## Outages are never cached
 *
 * Caching `{ ok: false }` would extend a one-request blip into a TTL-long
 * refusal window. Only definite answers are stored.
 */
export function cachedDelegationRevocationSource(
  inner: DelegationRevocationSource,
  options: { readonly ttlMs?: number; readonly now?: () => number } = {},
): DelegationRevocationSource {
  const ttlMs = options.ttlMs ?? DELEGATION_REVOCATION_TTL_MS;
  const now = options.now ?? ((): number => Date.now());
  const entries = new Map<string, { revoked: boolean; expiresAtMs: number }>();

  return {
    async revoked(
      tenant: string,
      subjects: readonly string[],
    ): Promise<DelegationRevocationResolution> {
      const unknown: string[] = [];
      const cachedHits: string[] = [];
      for (const subject of subjects) {
        const hit = entries.get(`${tenant} ${subject}`);
        if (hit === undefined || hit.expiresAtMs <= now()) {
          unknown.push(subject);
          continue;
        }
        if (hit.revoked) cachedHits.push(subject);
      }
      if (unknown.length === 0) return { ok: true, revoked: cachedHits };

      const resolved = await inner.revoked(tenant, unknown);
      // An outage is returned, never cached: caching it would extend a
      // one-request blip into a TTL-long refusal window for this tenant.
      if (!resolved.ok) return resolved;

      // Every subject ASKED about gets an entry, including the ones that came
      // back clean. Recording only the hits would make the next request re-read
      // the whole chain, which is the cost this memo exists to remove.
      const found = new Set(resolved.revoked);
      const expiresAtMs = now() + ttlMs;
      for (const subject of unknown) {
        entries.set(`${tenant} ${subject}`, { revoked: found.has(subject), expiresAtMs });
      }
      return { ok: true, revoked: [...cachedHits, ...resolved.revoked] };
    },
  };
}
