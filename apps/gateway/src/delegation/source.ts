/**
 * Where the delegation verifier gets its key and its revocation list (#691).
 *
 * ## The key
 *
 * `DELEGATION_SIGNING_KEY`, one secret, resolved from the **Cloudflare Secrets
 * Store** — the owner directive is that credentials belong there once the fleet
 * is fully on Cloudflare, and a Secrets Store binding is resolved at DEPLOY
 * time rather than per request. On a Worker that is what a plain `env` string
 * looks like at the point of use, which is why nothing here knows the
 * difference between the Secrets Store binding and the `.dev.vars` value a
 * developer runs with: the binding shape is identical, and the deploy config is
 * the only place the distinction lives.
 *
 * The same secret verifies and signs, because the signer is our own Worker (see
 * `packages/identity/src/delegation/link.ts` on why symmetric, and what it
 * costs). The day a third party mints links, the `alg` table gains an
 * asymmetric entry and this resolver gains a public-key source; the chain
 * semantics do not change.
 *
 * ## What "not configured" means
 *
 * `unconfigured`, and the middleware turns that into a **503 for a request that
 * PRESENTS a chain** and into nothing at all for a request that does not. Those
 * two behaviours together are the whole posture: adopting delegation is opt-in,
 * and a deployment that cannot verify must never serve a delegated request with
 * the header quietly ignored — that would make "forget the binding" a bypass of
 * every rule in the verifier.
 *
 * ## Memoized per `env` object
 *
 * Importing an HMAC key is cheap but not free, and `envScopedDeps`, the model
 * registry, the guardrail engine and the attribution policy source all key on
 * the same identity: Workers hands the same `env` object to every request an
 * isolate serves. A `WeakMap` on it is an isolate-lifetime cache with no
 * module-global for a test to have to reset.
 */
import {
  type DelegationRevocationSource,
  NO_DELEGATION_REVOCATIONS,
  cachedDelegationRevocationSource,
  d1DelegationRevocationSource,
  importDelegationKey,
} from "@ferrogate/identity";

/** The Worker vars/bindings this slice reads. */
export interface DelegationBindings {
  /**
   * The HMAC secret the mint signs with and this Worker verifies with. A
   * SECRET (Cloudflare Secrets Store / `wrangler secret put`), never a
   * committed var.
   */
  readonly DELEGATION_SIGNING_KEY?: string | undefined;
  /** The CONTROL database that owns `delegation_revocations`. */
  readonly CONTROL_DB?: D1Database | undefined;
  /** The alias the metering/quota/attribution readers already accept. */
  readonly BILLING_DB?: D1Database | undefined;
}

/**
 * The three states of the verifier, kept apart.
 *
 * `unconfigured` and `misconfigured` are NOT the same answer and are not
 * collapsed: the first is a deployment that never opted in, the second is an
 * operator who did opt in and got it wrong (a secret too short to be safe).
 * Reporting the second as the first would silently downgrade a security control
 * to "off" at exactly the moment someone was trying to switch it on.
 */
export type DelegationVerifier =
  | {
      readonly state: "ready";
      readonly key: CryptoKey;
      readonly revocations: DelegationRevocationSource;
    }
  | { readonly state: "unconfigured" }
  | { readonly state: "misconfigured"; readonly detail: string };

const VERIFIERS = new WeakMap<object, Promise<DelegationVerifier>>();

/** Build (once per `env`) the verifier this Worker will use. */
export function delegationVerifierFromEnv(env: DelegationBindings): Promise<DelegationVerifier> {
  const cacheKey = env as unknown as object;
  const memoized = VERIFIERS.get(cacheKey);
  if (memoized !== undefined) return memoized;

  const resolving = resolveVerifier(env);
  VERIFIERS.set(cacheKey, resolving);
  return resolving;
}

async function resolveVerifier(env: DelegationBindings): Promise<DelegationVerifier> {
  const secret = env.DELEGATION_SIGNING_KEY;
  if (secret === undefined || secret.trim() === "") return { state: "unconfigured" };

  const imported = await importDelegationKey(secret);
  if (!imported.ok) return { state: "misconfigured", detail: imported.detail };

  const db = env.CONTROL_DB ?? env.BILLING_DB;
  // A deployment with no control database has nowhere to hold a revocation, so
  // "nothing is revoked" is a complete reading of a known state rather than a
  // guess — the same argument `attribution/source.ts` makes for a schema that
  // predates its columns. It is NOT the same as a database that is bound and
  // unreadable, which is a 503.
  const revocations =
    db === undefined
      ? NO_DELEGATION_REVOCATIONS
      : cachedDelegationRevocationSource(d1DelegationRevocationSource(db));

  return { state: "ready", key: imported.key, revocations };
}
