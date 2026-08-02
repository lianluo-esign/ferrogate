/**
 * The prepaid-wallet NO-OVERSELL guard on this Worker's admission path.
 *
 * ## Nothing here re-implements the guard
 *
 * `@ferrogate/storage` ships `D1WalletStore.reserveWalletCredits` — the
 * three-statement atomic `batch()` whose predicate lives INSIDE the writing
 * statement, so N parallel reserves against a balance that affords K admit
 * exactly K. It is mutation-tested in `packages/storage/test/d1/wallet-d1.test.ts`
 * ("replace the in-statement guard with a naive read-then-write → 20 parallel
 * reserves against a balance affording 7 admitted all 20"). This module
 * constructs it against the request's tenant and CALLS it. The only new code is
 * the seam: which database, which tenant, how much to hold, when to let go.
 *
 * ## Why the balance READ in `./quota.ts` is kept as well
 *
 * The read (`SpendSource.walletBalanceCredits`, `finalize_auth` step 3) bounds
 * CUMULATIVE spend: a tenant whose balance is gone is refused before anything
 * is dispatched. It cannot bound a RACE — two concurrent requests read the same
 * funded balance and both proceed. The guard here bounds concurrent overdraft,
 * because its decision is inside the INSERT. Neither substitutes for the other,
 * so both run, in Rust's order.
 *
 * ## Hold, not debit
 *
 * Rust took a `WalletCreditReservation` in `finalize_auth` and released it on
 * `Drop`; the real DEBIT happened later, at settlement. That split is kept:
 *
 *  - admission takes a hold of {@link DEFAULT_WALLET_HOLD_CREDITS};
 *  - the hold is RELEASED in the middleware's `finally` once the handler chain
 *    returns — the TS stand-in for `Drop`;
 *  - `expires_at_unix` is a SECOND, independent release, for the one case a
 *    `finally` cannot cover: an isolate that dies mid-request. Both the
 *    available-balance query and the guard's own subquery filter on
 *    `expires_at_unix > ?`, so a stranded hold frees itself within one TTL.
 *
 * ## Why the hold is a flat credit amount
 *
 * A hold must be sized before the job body is priced, and this Worker has no
 * pre-dispatch pricing for an agent run (the run's cost accrues as the run
 * executes). A flat floor is a WEAKER bound than a priced estimate, and it is
 * weaker in a KNOWN direction: it under-holds an expensive run rather than
 * over-holding a cheap one, so it can admit a run the true price would have
 * refused. It cannot do the reverse. When agent-run pre-pricing lands, the only
 * change is passing that number here instead of the floor.
 */
import {
  D1WalletStore,
  type TenantDatabaseHandle,
  type WalletReservationResult,
} from "@ferrogate/storage";

/**
 * Credits held per admitted request when nothing sizes the hold.
 *
 * One credit is 1e-6 USD, i.e. the smallest hold the storage guard accepts (it
 * rejects a non-positive amount outright). At this size a wallet funded with K
 * credits admits K genuinely-concurrent requests and refuses the K+1st, which
 * IS the no-oversell property; it is deliberately not a claim about the money
 * those K runs go on to spend.
 */
export const DEFAULT_WALLET_HOLD_CREDITS = 1;

/**
 * How long an admission hold survives without an explicit release.
 *
 * The release runs in a `finally`, so this only matters when the isolate dies
 * mid-request. 60s comfortably exceeds a Worker's wall-clock budget for one
 * request, so a live request can never have its own hold swept out from under
 * it, and a dead one frees its credits within a minute.
 */
export const WALLET_HOLD_TTL_SECONDS = 60;

/** Bindings this module reads. */
export interface WalletAdmissionBindings {
  /** The TENANT database, holding `wallets` and `wallet_reservations`. */
  readonly DB?: D1Database | undefined;
}

/** An admission hold that must be let go, whatever happens. */
export interface WalletHold {
  readonly id: string;
  readonly amountCredits: number;
  /** Idempotent; never throws (a release failure must not fail the response). */
  release(): Promise<void>;
}

/**
 * What the guard decided.
 *
 * `not_applicable` and `insufficient` are deliberately distinct: the prepaid
 * wallet is OPT-IN per tenant, so a tenant with no `wallets` row must never be
 * denied. Collapsing them would refuse every tenant that has not adopted
 * prepaid billing.
 */
export type WalletAdmissionOutcome =
  | { readonly kind: "admitted"; readonly hold: WalletHold }
  | {
      readonly kind: "insufficient";
      readonly availableCredits: number;
      readonly requestedCredits: number;
    }
  /** No wallet row, or no wallet database bound. Never a denial. */
  | { readonly kind: "not_applicable" }
  | { readonly kind: "unavailable"; readonly detail: string };

/** The seam the admission ladder codes against. */
export interface WalletAdmission {
  /**
   * Take a hold for one request, or report why not.
   *
   * `holdId` is the IDEMPOTENCY key: the storage guard probes for an existing
   * hold under that id first and returns it verbatim, so a retried admission of
   * the same request cannot take a second hold against the same balance.
   */
  reserve(
    tenantId: string,
    holdId: string,
    nowUnixSeconds: number,
  ): Promise<WalletAdmissionOutcome>;
}

/** A guard for a deployment with no tenant database bound. Never denies. */
export const NO_WALLET_ADMISSION: WalletAdmission = {
  async reserve(): Promise<WalletAdmissionOutcome> {
    return { kind: "not_applicable" };
  },
};

/** Tunables for {@link d1WalletAdmission}. */
export interface WalletAdmissionOptions {
  readonly holdCredits?: number | undefined;
  readonly ttlSeconds?: number | undefined;
}

/**
 * The tenant-database handle for this deployment's `DB` binding.
 *
 * `source: "shared_development"` is the honest label: this app declares ONE
 * tenant database, so every tenant's wallet lives in it today.
 * `supportsAtomicBatch` is `true` because a NATIVE D1 binding really does run
 * `batch()` as one transaction and really does return `RETURNING` rows — the
 * only property `requireAtomicBatch` gates on, and the only one the guard's
 * correctness depends on.
 *
 * The `tenantId` on the handle is load-bearing, not decorative:
 * `D1WalletStore.assertTenant` refuses any write whose `tenant_id` disagrees
 * with it, so a routing bug can never write one tenant's hold against another's
 * balance. Building the handle PER REQUEST from the authenticated tenant is
 * what arms that tripwire.
 */
export function agentRuntimeTenantHandle(db: D1Database, tenantId: string): TenantDatabaseHandle {
  return { tenantId, db, source: "shared_development", supportsAtomicBatch: true };
}

/** `env.DB`, but only when it is really a D1 binding (a `[vars]` `DB` is a string). */
function walletDatabase(env: WalletAdmissionBindings): D1Database | undefined {
  const candidate = env.DB;
  return candidate !== undefined && typeof candidate.prepare === "function" ? candidate : undefined;
}

/**
 * The durable guard: `@ferrogate/storage`'s `D1WalletStore`, per request, on
 * the tenant database.
 *
 * The store is constructed per call because the handle carries the tenant
 * identity `assertTenant` checks. It holds no state of its own, so this costs
 * an object allocation, not a round trip.
 */
export function d1WalletAdmission(
  db: D1Database,
  options: WalletAdmissionOptions = {},
): WalletAdmission {
  const amountCredits = options.holdCredits ?? DEFAULT_WALLET_HOLD_CREDITS;
  const ttlSeconds = options.ttlSeconds ?? WALLET_HOLD_TTL_SECONDS;

  return {
    async reserve(
      tenantId: string,
      holdId: string,
      nowUnixSeconds: number,
    ): Promise<WalletAdmissionOutcome> {
      const store = new D1WalletStore(agentRuntimeTenantHandle(db, tenantId));
      let result: WalletReservationResult;
      try {
        result = await store.reserveWalletCredits(
          holdId,
          tenantId,
          amountCredits,
          nowUnixSeconds + ttlSeconds,
          nowUnixSeconds,
        );
      } catch (error) {
        // A storage outage has NOT proven the caller is overdrawn, so it is
        // reported `unavailable` (→ 503) and never `insufficient` (→ 429).
        return {
          kind: "unavailable",
          detail: error instanceof Error ? error.message : String(error),
        };
      }

      if (result.kind === "no_wallet") return { kind: "not_applicable" };
      if (result.kind === "insufficient") {
        return {
          kind: "insufficient",
          availableCredits: result.availableCredits,
          requestedCredits: result.requestedCredits,
        };
      }
      return {
        kind: "admitted",
        hold: {
          id: result.reservation.id,
          amountCredits: result.reservation.amountCredits,
          async release(): Promise<void> {
            try {
              await store.releaseWalletReservation(holdId, Math.floor(Date.now() / 1000));
            } catch {
              // The hold expires on its own, so a failed release costs at most
              // one TTL of stranded credits. It must never surface: by the time
              // this runs the response is already the client's.
            }
          },
        },
      };
    },
  };
}

/**
 * The guard the request path gets: the durable D1 one whenever the tenant
 * database is bound, {@link NO_WALLET_ADMISSION} otherwise.
 *
 * Binding `DB` can therefore only ever TIGHTEN admission, never loosen it.
 */
export function walletAdmissionFromEnv(env: WalletAdmissionBindings): WalletAdmission {
  const db = walletDatabase(env);
  return db === undefined ? NO_WALLET_ADMISSION : d1WalletAdmission(db);
}

/** The hold id for a request. Stable, so a retried admission is idempotent. */
export function walletHoldId(requestId: string): string {
  return `ar_hold_${requestId}`;
}
