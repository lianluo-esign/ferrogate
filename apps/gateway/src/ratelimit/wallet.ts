/**
 * The prepaid-wallet NO-OVERSELL guard, mounted on the admission path.
 *
 * ## What was wrong before this file existed
 *
 * `@ferrogate/storage` ships `D1WalletStore.reserveWalletCredits` — the
 * three-statement atomic `batch()` whose guard lives INSIDE the writing
 * statement, so N parallel reserves against a balance that affords K admit
 * exactly K. It is mutation-tested in `packages/storage/test/d1/wallet-d1.test.ts`
 * (the README records "replace the in-statement guard with a naive
 * read-then-write → 20 parallel reserves against a balance affording 7 admitted
 * all 20"). And it had **zero callers**: `docs/rewrite/parity-audit-storage.md`
 * §4.1 names it as this repo's recurring defect in its purest form — "the wallet
 * no-oversell guard is not guarding any money".
 *
 * `rateLimit()` step 3 read `wallets.balance_credits` minus live holds and
 * refused at `<= 0` (`quota.ts::d1SpendSource`). That is a READ, not a guard:
 * two concurrent requests both read the same funded balance, both are admitted,
 * and both spend it. The read cannot be fixed by reading more carefully — the
 * decision has to move INTO the writing statement, which is exactly what the
 * storage guard already does.
 *
 * So this module does not re-implement anything. It constructs `D1WalletStore`
 * against the request's tenant and calls it. The only new code is the seam:
 * which database, which tenant, how much to hold, and when to let it go.
 *
 * ## Hold, not debit
 *
 * Rust took a `WalletCreditReservation` in `finalize_auth` and released it on
 * `Drop`, so a cancelled or errored request freed its hold. The real DEBIT
 * happened later, at settlement, from the metering path. This port keeps that
 * split exactly:
 *
 *  - admission takes a hold sized {@link WalletAdmissionOptions.holdCredits};
 *  - the hold is RELEASED in a `finally` once the handler chain returns, which
 *    is the TS stand-in for `Drop` (see `ports.ts::withReservation`);
 *  - `expiresAtUnix` is a second, independent release: an isolate that dies
 *    between the reserve and the release strands the credits only until the
 *    hold expires, because `WALLET_HELD_SQL` and the guard's own subquery both
 *    filter on `expires_at_unix > ?`.
 *
 * The consequence, stated plainly so nobody mistakes the scope: this guard
 * bounds CONCURRENT overdraft, which is the race Postgres closed with
 * `SELECT … FOR UPDATE` and D1 cannot. Cumulative spend across sequential
 * requests is bounded by `balance_credits` itself, which the metering
 * settlement moves — the two gates compose, and neither substitutes for the
 * other. That is why step 3's balance read is KEPT rather than replaced.
 *
 * ## Why the hold is a flat credit amount
 *
 * A hold has to be sized before the request body is parsed — the admission
 * check runs in middleware, ahead of model resolution, exactly as Rust's did.
 * Rust passed `estimated_credits`, which its data plane priced from the route's
 * rate card before dispatch; this port has no pre-dispatch pricing yet (see the
 * `settledCostUsd` marker in `../metering/sink.ts`), so the hold is a configured
 * per-request floor, `GATEWAY_WALLET_HOLD_CREDITS`, defaulting to
 * {@link DEFAULT_WALLET_HOLD_CREDITS}.
 *
 * A flat floor is a WEAKER bound than a priced estimate, and it is weaker in a
 * known direction: it under-holds an expensive request rather than over-holding
 * a cheap one, so it can admit a request that the true price would have
 * refused. It cannot do the reverse. When pre-dispatch pricing lands, the only
 * change is passing that number here instead of the floor.
 */
import {
  D1WalletStore,
  type TenantDatabaseHandle,
  type WalletReservationResult,
} from "@ferrogate/storage";

/**
 * Credits held per admitted request when the operator configures none.
 *
 * One credit is 1e-6 USD (`../metering/credits.ts`), i.e. the smallest hold the
 * storage guard accepts — it rejects a non-positive amount outright. At this
 * size a wallet funded with K credits admits K genuinely-concurrent requests
 * and refuses the K+1st, which is the no-oversell property; it is deliberately
 * NOT a claim about the money those K requests go on to spend.
 */
export const DEFAULT_WALLET_HOLD_CREDITS = 1;

/**
 * How long an admission hold survives without an explicit release.
 *
 * The release runs in a `finally`, so this only matters when the isolate dies
 * mid-request. 60s comfortably exceeds a Worker's wall-clock budget for a
 * single request, so a live request can never have its own hold swept out from
 * under it, and a dead one frees its credits within a minute.
 */
export const WALLET_HOLD_TTL_SECONDS = 60;

/** Bindings this module reads. */
export interface WalletAdmissionBindings {
  /**
   * The TENANT database (`sql/d1-ts/tenant/`), holding `wallets` and
   * `wallet_reservations`. Already declared in `apps/gateway/wrangler.toml`,
   * which is why this guard needs no composition-root edit to go live.
   */
  readonly DB?: D1Database | undefined;
  /**
   * Credits to hold per admitted request. Absent/unparseable ⇒
   * {@link DEFAULT_WALLET_HOLD_CREDITS}; a value that is not a positive integer
   * is IGNORED rather than applied, because the storage guard throws on a
   * non-positive amount and a throw on the admission path would be a 500 for
   * every wallet tenant.
   */
  readonly GATEWAY_WALLET_HOLD_CREDITS?: string | undefined;
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
 * prepaid billing — the failure `WalletBalanceReading`'s `null` exists to
 * prevent, one layer down.
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

/**
 * The seam `rateLimit()` codes against.
 *
 * A port rather than a direct `D1WalletStore` reference so the middleware stays
 * testable without a database, and so a deployment that routes tenants to
 * separate databases can swap the handle resolution without touching admission.
 */
export interface WalletAdmission {
  /**
   * Take a hold for one request, or report why not.
   *
   * `holdId` is the IDEMPOTENCY key: the storage guard probes for an existing
   * hold under that id first and returns it verbatim, so a retried admission of
   * the same request cannot take a second hold against the same balance.
   */
  reserve(tenantId: string, holdId: string, nowUnixSeconds: number): Promise<WalletAdmissionOutcome>;
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
 * `source: "shared_development"` is the honest label: `apps/gateway/wrangler.toml`
 * declares ONE `[[d1_databases]] binding = "DB"`, so every tenant's wallet lives
 * in that database today. `supportsAtomicBatch` is `true` because a NATIVE D1
 * binding really does run `batch()` as one transaction and really does return
 * `RETURNING` rows — which is the only thing `requireAtomicBatch` gates on, and
 * the only property the guard's correctness depends on.
 *
 * The `tenantId` on the handle is load-bearing, not decorative:
 * `D1WalletStore.assertTenant` refuses any write whose `tenant_id` disagrees
 * with it, so a routing bug can never write one tenant's hold against another's
 * balance. Building the handle PER REQUEST from the authenticated tenant is
 * what arms that tripwire.
 */
export function gatewayTenantHandle(db: D1Database, tenantId: string): TenantDatabaseHandle {
  return { tenantId, db, source: "shared_development", supportsAtomicBatch: true };
}

/** Parse `GATEWAY_WALLET_HOLD_CREDITS`; anything not a positive integer is ignored. */
export function walletHoldCreditsFromEnv(env: WalletAdmissionBindings): number {
  const raw = env.GATEWAY_WALLET_HOLD_CREDITS;
  if (raw === undefined || raw.trim() === "") return DEFAULT_WALLET_HOLD_CREDITS;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) return DEFAULT_WALLET_HOLD_CREDITS;
  return parsed;
}

/** `env.DB`, but only when it is really a D1 binding (a `[vars]` `DB` is a string). */
function walletDatabase(env: WalletAdmissionBindings): D1Database | undefined {
  const candidate = env.DB;
  return candidate !== undefined && typeof candidate.prepare === "function" ? candidate : undefined;
}

/**
 * The durable guard: `@ferrogate/storage`'s `D1WalletStore`, per request, on the
 * tenant database.
 *
 * The store is constructed per call because the handle carries the tenant
 * identity that `assertTenant` checks. It holds no state of its own, so this
 * costs an object allocation, not a round trip.
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
      const store = new D1WalletStore(gatewayTenantHandle(db, tenantId));
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
        // reported as `unavailable` (→ 503) and never as `insufficient`
        // (→ 429). Same split `SpendSource` takes one layer up.
        const detail = error instanceof Error ? error.message : String(error);
        return { kind: "unavailable", detail };
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
              // The hold expires on its own (`WALLET_HOLD_TTL_SECONDS`), so a
              // failed release costs at most one TTL of stranded credits. It
              // must never surface: by the time this runs the response is
              // already the client's.
            }
          },
        },
      };
    },
  };
}

/**
 * The guard the composition root gets: the durable D1 one whenever the tenant
 * database is bound, {@link NO_WALLET_ADMISSION} otherwise.
 *
 * Binding `DB` can therefore only ever TIGHTEN admission, never loosen it —
 * the same property `spendSourceFromEnv` has.
 */
export function walletAdmissionFromEnv(env: WalletAdmissionBindings): WalletAdmission {
  const db = walletDatabase(env);
  if (db === undefined) return NO_WALLET_ADMISSION;
  return d1WalletAdmission(db, { holdCredits: walletHoldCreditsFromEnv(env) });
}

/** The hold id for a request. Stable, so a retried admission is idempotent. */
export function walletHoldId(requestId: string): string {
  return `gw_hold_${requestId}`;
}
