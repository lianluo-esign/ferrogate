/**
 * `D1WalletStore` — the wallet family against a REAL D1 database
 * (inventory §1.5.1 / §1.5.2, issues #169/#281).
 *
 * This is the durable twin of `MemoryWalletStore` in `../wallet.ts`. The
 * in-memory store gets its no-oversell guarantee for free from JS's single
 * serialization point; here the guarantee has to be *constructed*, and how it
 * is constructed is the entire content of this module.
 *
 * ## Why the guard is shaped the way it is
 *
 * Postgres reserved credits as `SELECT balance_credits ... FOR UPDATE`, sum the
 * live holds, then insert — the row lock making the read-decide-write sequence
 * indivisible. **D1/SQLite has no row lock and no `FOR UPDATE`.** So the
 * decision cannot be made in the application and then written: between the read
 * and the write, another isolate commits, and the second reserve spends money
 * that is already spoken for.
 *
 * The fix is to stop making the decision in the application at all. The guard
 * becomes part of the *writing statement* — a conditional
 * `INSERT ... SELECT ... WHERE <amount fits in available balance>` — so SQLite
 * evaluates the predicate and performs the insert inside one statement, against
 * one committed snapshot. `batch()` wraps the three statements in one implicit
 * transaction, and SQLite serializes writers per database. Therefore N parallel
 * reserves against a balance that affords N−1 admit **exactly** N−1.
 *
 * The `RETURNING` clause is what makes this observable: an empty result set is
 * the guard's "not admitted" signal. Without `RETURNING` the caller could not
 * distinguish "inserted" from "predicate was false". `requireAtomicBatch`
 * refuses any future handle that cannot preserve this contract.
 *
 * ## Divergence from the Rust D1 backend (deliberate, and an improvement)
 *
 * The Rust backend reached D1 over the HTTP proxy, which binds every parameter
 * as **TEXT**. It therefore had to write `CAST(? AS INTEGER)` around every
 * numeric parameter and `NULLIF(?, '')` around every nullable one, or SQLite's
 * type affinity would compare a string to an integer and the guard would
 * quietly stop matching. Running natively inside a Worker, `.bind(n)` sends a
 * real number, so those wrappers are **dropped**. The comparisons are identical;
 * only the marshalling changed. (This is called out because a reader diffing
 * against `crates/ferrogate-storage/src/control_plane_store_d1/wallet.rs` will
 * notice the missing CASTs and should know they are not an oversight.)
 */
import { bindCredits, creditsFromText } from "../credits.js";
import { StorageError } from "../errors.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import {
  type StoredWallet,
  type StoredWalletReservation,
  type StoredWalletSettlement,
  WALLET_RESERVATION_ACTIVE,
  WALLET_RESERVATION_RELEASED,
  WALLET_RESERVATION_SETTLED,
  type WalletReservationResult,
  type WalletReservationSettlement,
  type WalletSettlementOutcome,
} from "../wallet.js";
import {
  bindOptional,
  boolFromSqlite,
  boolToSqlite,
  d1Error,
  optionalNumber,
  optionalText,
} from "./rows.js";

/** Projection shared by every `wallet_reservations` read (order matters to the decoder). */
const RESERVATION_COLUMNS =
  "id, tenant_id, amount_credits, status, expires_at_unix, settlement_id, " +
  "created_at_unix, updated_at_unix";

const SETTLEMENT_COLUMNS = "id, tenant_id, delta_credits, balance_after_credits, created_at_unix";

const WALLET_COLUMNS =
  "id, tenant_id, balance_credits, auto_recharge_threshold_credits, " +
  "auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix";

interface WalletRow {
  id: string;
  tenant_id: string;
  balance_credits: number;
  auto_recharge_threshold_credits: number | null;
  auto_recharge_amount_credits: number | null;
  dunning: number;
  created_at_unix: number;
  updated_at_unix: number;
}

interface ReservationRow {
  id: string;
  tenant_id: string;
  amount_credits: number;
  status: string;
  expires_at_unix: number;
  settlement_id: string | null;
  created_at_unix: number;
  updated_at_unix: number;
}

interface SettlementRow {
  id: string;
  tenant_id: string;
  delta_credits: number;
  balance_after_credits: number | null;
  created_at_unix: number;
}

/**
 * Normalise a credit amount to `bigint`, refusing anything a double has already
 * damaged.
 *
 * A `number` past `Number.MAX_SAFE_INTEGER` arrived here having lost digits, and
 * a fractional one is not an amount of money this schema can hold
 * (`balance_credits INTEGER`). Both would otherwise be laundered into an
 * exact-looking `bigint` by `BigInt(Math.round(x))`.
 */
function exactCredits(value: number | bigint, operation: string): bigint {
  if (typeof value === "bigint") return value;
  if (!Number.isSafeInteger(value)) {
    throw StorageError.conflict(
      `${operation}: ${value} is not an exact integer number of credits (safe-integer range)`,
    );
  }
  return BigInt(value);
}

function walletFromRow(row: WalletRow): StoredWallet {
  const threshold = optionalNumber(row.auto_recharge_threshold_credits);
  const amount = optionalNumber(row.auto_recharge_amount_credits);
  return {
    id: row.id,
    tenantId: row.tenant_id,
    balanceCredits: row.balance_credits,
    ...(threshold === undefined ? {} : { autoRechargeThresholdCredits: threshold }),
    ...(amount === undefined ? {} : { autoRechargeAmountCredits: amount }),
    dunning: boolFromSqlite(row.dunning),
    createdAtUnix: row.created_at_unix,
    updatedAtUnix: row.updated_at_unix,
  };
}

function reservationFromRow(row: ReservationRow): StoredWalletReservation {
  const settlementId = optionalText(row.settlement_id);
  return {
    id: row.id,
    tenantId: row.tenant_id,
    amountCredits: row.amount_credits,
    status: row.status as StoredWalletReservation["status"],
    expiresAtUnix: row.expires_at_unix,
    ...(settlementId === undefined ? {} : { settlementId }),
    createdAtUnix: row.created_at_unix,
    updatedAtUnix: row.updated_at_unix,
  };
}

function settlementFromRow(row: SettlementRow): StoredWalletSettlement {
  const balanceAfter = optionalNumber(row.balance_after_credits);
  return {
    id: row.id,
    tenantId: row.tenant_id,
    deltaCredits: row.delta_credits,
    ...(balanceAfter === undefined ? {} : { balanceAfterCredits: balanceAfter }),
    createdAtUnix: row.created_at_unix,
  };
}

/**
 * Wallets, holds and settlements on one tenant's D1 database.
 *
 * Constructed with an already-routed {@link TenantDatabaseHandle} rather than a
 * router, so the routing decision is made once by the caller and cannot be
 * silently re-made (differently) per statement.
 */
export class D1WalletStore {
  private readonly db: D1Database;

  constructor(private readonly handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  // --- Wallet configuration ------------------------------------------------

  /** Idempotent upsert of a tenant's wallet configuration (id == tenantId). */
  async upsertWallet(wallet: StoredWallet): Promise<void> {
    this.assertTenant(wallet.tenantId, "upsert_wallet");
    try {
      await this.db
        .prepare(
          "INSERT INTO wallets " +
            "(id, tenant_id, balance_credits, auto_recharge_threshold_credits, " +
            " auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (id) DO UPDATE SET " +
            "balance_credits = excluded.balance_credits, " +
            "auto_recharge_threshold_credits = excluded.auto_recharge_threshold_credits, " +
            "auto_recharge_amount_credits = excluded.auto_recharge_amount_credits, " +
            "dunning = excluded.dunning, " +
            "updated_at_unix = excluded.updated_at_unix",
        )
        .bind(
          wallet.id,
          wallet.tenantId,
          wallet.balanceCredits,
          bindOptional(wallet.autoRechargeThresholdCredits),
          bindOptional(wallet.autoRechargeAmountCredits),
          boolToSqlite(wallet.dunning),
          wallet.createdAtUnix,
          wallet.updatedAtUnix,
        )
        .run();
    } catch (error) {
      throw d1Error("upsert_wallet", error);
    }
  }

  async getWallet(tenantId: string): Promise<StoredWallet | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${WALLET_COLUMNS} FROM wallets WHERE tenant_id = ?`)
        .bind(tenantId)
        .first<WalletRow>();
      return row ? walletFromRow(row) : undefined;
    } catch (error) {
      throw d1Error("get_wallet", error);
    }
  }

  /**
   * Create the tenant's wallet row if — and only if — it does not already
   * exist, at `openingCredits` (default zero). Returns whether a row was
   * created, so a caller can tell "adopted just now" from "already had one".
   *
   * Distinct from {@link upsertWallet}, which OVERWRITES `balance_credits` with
   * whatever the caller passed. That is right for configuring a wallet and
   * catastrophic for adopting one: a caller that "made sure the wallet exists"
   * with `upsertWallet({balanceCredits: 0, …})` would silently zero a funded
   * customer.
   *
   * This exists because {@link settleWalletBalance} moves a balance with an
   * `UPDATE`, and an `UPDATE` against a missing row matches nothing while the
   * settlement id is still claimed — so a top-up for a tenant that has not yet
   * adopted prepaid billing would be swallowed AND become unrepeatable. The
   * settlement guards against that itself (see its docblock); this is how a
   * caller makes the guard pass on purpose.
   */
  async ensureWallet(tenantId: string, nowUnix: number, openingCredits = 0n): Promise<boolean> {
    this.assertTenant(tenantId, "ensure_wallet");
    try {
      const result = await this.db
        .prepare(
          "INSERT INTO wallets " +
            "(id, tenant_id, balance_credits, auto_recharge_threshold_credits, " +
            " auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, NULL, NULL, 0, ?, ?) " +
            "ON CONFLICT (id) DO NOTHING RETURNING id",
        )
        .bind(tenantId, tenantId, bindCredits(openingCredits), nowUnix, nowUnix)
        .all<{ id: string }>();
      return result.results.length > 0;
    } catch (error) {
      throw d1Error("ensure_wallet", error);
    }
  }

  /**
   * `wallets.balance_credits`, read EXACTLY.
   *
   * {@link getWallet} decodes the column through D1's default JS mapping, which
   * is a `number` and therefore lossy past 2^53 — fine for a display balance,
   * wrong as the input to any arithmetic. This selects `CAST(… AS TEXT)` and
   * decodes with `BigInt`, so a balance anywhere in the int64 range comes back
   * intact. `undefined` means NO wallet row, which is not the same fact as a
   * balance of zero (see `SpendSource.walletBalanceCredits` in the gateway:
   * "no wallet" must never deny).
   */
  async balanceCreditsExact(tenantId: string): Promise<bigint | undefined> {
    try {
      const row = await this.db
        .prepare("SELECT CAST(balance_credits AS TEXT) AS credits FROM wallets WHERE tenant_id = ?")
        .bind(tenantId)
        .first<{ credits: string }>();
      return row === null ? undefined : creditsFromText(row.credits);
    } catch (error) {
      throw d1Error("balance_credits_exact", error);
    }
  }

  // --- The keystone: no-oversell reserve -----------------------------------

  /**
   * Reserve `amountCredits` against available balance = `balance_credits` −
   * Σ(live holds), as ONE atomic 3-statement batch.
   *
   * | # | statement | why it is in the batch |
   * |---|---|---|
   * | S0 | idempotency probe by hold id | a replay must return the FIRST outcome; probing outside the batch would race a concurrent first insert |
   * | S1 | guarded conditional INSERT ... RETURNING id | the guard and the write are one statement, so no window exists between deciding and writing |
   * | S2 | wallet balance + outstanding read | splits `no_wallet` from `insufficient` when S1 admitted nothing, from the SAME snapshot S1 saw |
   *
   * `ON CONFLICT (id) DO NOTHING` keeps a racing replay from raising a
   * constraint error, so idempotency holds even when S0 and the concurrent
   * insert interleave.
   *
   * Note the SELECT in S1 carries a WHERE clause. That is required, not
   * incidental: SQLite's upsert grammar is ambiguous for
   * `INSERT ... SELECT ... ON CONFLICT` unless the SELECT has a WHERE
   * (sqlite.org/lang_UPSERT.html, "Parsing Ambiguity"). The guard predicate
   * doubles as that WHERE.
   */
  async reserveWalletCredits(
    reservationId: string,
    tenantId: string,
    amountCredits: number,
    expiresAtUnix: number,
    nowUnix: number,
  ): Promise<WalletReservationResult> {
    requireAtomicBatch(this.handle, "reserve_wallet_credits");
    this.assertTenant(tenantId, "reserve_wallet_credits");
    if (amountCredits <= 0) {
      // Mirrors the in-memory store: a non-positive hold is a caller bug, not a
      // balance outcome. Rejected before any I/O so it can never be recorded.
      throw StorageError.conflict(`wallet reservation ${reservationId} amount must be positive`);
    }

    let results: D1Result[];
    try {
      results = await this.db.batch([
        // S0 — idempotency probe.
        this.db
          .prepare(`SELECT ${RESERVATION_COLUMNS} FROM wallet_reservations WHERE id = ?`)
          .bind(reservationId),
        // S1 — THE GUARD. Inserts iff a wallet row exists AND the request fits
        // inside available balance. Empty RETURNING == not admitted.
        this.db
          .prepare(
            "INSERT INTO wallet_reservations " +
              "(id, tenant_id, amount_credits, status, expires_at_unix, settlement_id, " +
              " created_at_unix, updated_at_unix) " +
              "SELECT ?, ?, ?, 'active', ?, NULL, ?, ? " +
              "FROM wallets w " +
              "WHERE w.tenant_id = ? " +
              "  AND ? <= w.balance_credits - COALESCE(( " +
              "      SELECT SUM(r.amount_credits) FROM wallet_reservations r " +
              "      WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ? " +
              "  ), 0) " +
              "ON CONFLICT (id) DO NOTHING " +
              "RETURNING id",
          )
          .bind(
            reservationId,
            tenantId,
            amountCredits,
            expiresAtUnix,
            nowUnix,
            nowUnix,
            tenantId,
            amountCredits,
            tenantId,
            nowUnix,
          ),
        // S2 — wallet state for the no_wallet vs insufficient decision.
        this.db
          .prepare(
            "SELECT w.balance_credits AS balance_credits, " +
              "COALESCE(( " +
              "  SELECT SUM(r.amount_credits) FROM wallet_reservations r " +
              "  WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ? " +
              "), 0) AS outstanding_credits " +
              "FROM wallets w WHERE w.tenant_id = ?",
          )
          .bind(tenantId, nowUnix, tenantId),
      ]);
    } catch (error) {
      throw d1Error("reserve_wallet_credits", error);
    }

    if (results.length < 3) {
      throw StorageError.runtime(
        "cloudflare d1: reserve batch returned fewer than 3 per-statement results",
      );
    }

    // S0: an existing hold for this id is an idempotent replay.
    const priorRows = (results[0]?.results ?? []) as ReservationRow[];
    const prior = priorRows[0];
    if (prior !== undefined) {
      const existing = reservationFromRow(prior);
      if (existing.tenantId !== tenantId || existing.amountCredits !== amountCredits) {
        throw StorageError.conflict(
          `wallet reservation ${reservationId} replay changed tenant or amount`,
        );
      }
      return { kind: "reserved", reservation: existing };
    }

    // S1: a RETURNING row means the guard admitted the hold.
    const admitted = (results[1]?.results ?? []) as { id: string }[];
    if (admitted.length > 0) {
      return {
        kind: "reserved",
        reservation: {
          id: reservationId,
          tenantId,
          amountCredits,
          status: WALLET_RESERVATION_ACTIVE,
          expiresAtUnix,
          createdAtUnix: nowUnix,
          updatedAtUnix: nowUnix,
        },
      };
    }

    // Not admitted and no prior hold: S2 says whether a wallet even exists.
    const stateRows = (results[2]?.results ?? []) as {
      balance_credits: number;
      outstanding_credits: number;
    }[];
    const state = stateRows[0];
    if (state === undefined) return { kind: "no_wallet" };
    return {
      kind: "insufficient",
      availableCredits: state.balance_credits - state.outstanding_credits,
      requestedCredits: amountCredits,
    };
  }

  // --- Capture / cancel ----------------------------------------------------

  /**
   * Capture an active hold into a real, idempotent wallet debit whose ledger row
   * references the hold (#281).
   *
   * The capture is one 3-statement batch, and every statement is guarded on the
   * hold still being `'active'`:
   *   S0 debit the wallet;
   *   S1 write the settlement row (`balance_after_credits` reads the balance
   *      AFTER S0, because batch statements run in order in one transaction);
   *   S2 flip `active → settled` — the CAS that decides a concurrent race.
   *
   * All three share the guard, so two concurrent settles of the same hold cannot
   * both debit: the loser's S0/S1/S2 all see a non-active hold and no-op, and
   * `wallet_settlements`' primary key makes S1 idempotent regardless.
   */
  async settleWalletReservation(
    reservationId: string,
    nowUnix: number,
  ): Promise<WalletReservationSettlement> {
    requireAtomicBatch(this.handle, "settle_wallet_reservation");
    const reservation = await this.getReservation(reservationId);
    if (!reservation) {
      throw StorageError.notFound(`wallet reservation ${reservationId} does not exist`);
    }

    if (reservation.status === WALLET_RESERVATION_SETTLED) {
      const settlement = await this.getSettlement(reservationId);
      if (!settlement) {
        throw StorageError.runtime(
          `wallet reservation ${reservationId} is settled but its settlement is missing`,
        );
      }
      return { reservation, settlement, newlyApplied: false };
    }
    if (reservation.status === WALLET_RESERVATION_RELEASED) {
      throw StorageError.conflict(
        `wallet reservation ${reservationId} was released; cannot settle`,
      );
    }
    if (reservation.expiresAtUnix <= nowUnix) {
      // Expired before capture: release it in-line and refuse, so a settle that
      // races the sweeper still fails closed rather than debiting late.
      await this.releaseReservationCas(reservationId, nowUnix);
      throw StorageError.conflict(`wallet reservation ${reservationId} expired; cannot settle`);
    }

    const deltaCredits = -reservation.amountCredits;
    let results: D1Result[];
    try {
      results = await this.db.batch([
        this.db
          .prepare(
            "UPDATE wallets SET balance_credits = balance_credits + ?, updated_at_unix = ? " +
              "WHERE tenant_id = ? " +
              "  AND EXISTS(SELECT 1 FROM wallet_reservations WHERE id = ? AND status = 'active')",
          )
          .bind(deltaCredits, nowUnix, reservation.tenantId, reservationId),
        this.db
          .prepare(
            `INSERT INTO wallet_settlements
               (id, tenant_id, delta_credits, balance_after_credits, created_at_unix)
             SELECT ?, ?, ?, (SELECT balance_credits FROM wallets WHERE tenant_id = ?), ?
             WHERE EXISTS(SELECT 1 FROM wallet_reservations WHERE id = ? AND status = 'active')
             ON CONFLICT (id) DO NOTHING
             RETURNING ${SETTLEMENT_COLUMNS}`,
          )
          .bind(
            reservationId,
            reservation.tenantId,
            deltaCredits,
            reservation.tenantId,
            nowUnix,
            reservationId,
          ),
        this.db
          .prepare(
            `UPDATE wallet_reservations SET status = 'settled', settlement_id = ?,
               updated_at_unix = ? WHERE id = ? AND status = 'active'
             RETURNING ${RESERVATION_COLUMNS}`,
          )
          .bind(reservationId, nowUnix, reservationId),
      ]);
    } catch (error) {
      throw d1Error("settle_wallet_reservation", error);
    }

    const flipped = ((results[2]?.results ?? []) as ReservationRow[])[0];
    if (flipped === undefined) {
      // The CAS missed: a concurrent settle/release moved the hold between our
      // read and this batch. Re-read and report the terminal state faithfully
      // instead of inventing one.
      const reloaded = await this.getReservation(reservationId);
      if (reloaded?.status === WALLET_RESERVATION_SETTLED) {
        const settlement = await this.getSettlement(reservationId);
        if (!settlement) {
          throw StorageError.runtime(
            `wallet reservation ${reservationId} is settled but its settlement is missing`,
          );
        }
        return { reservation: reloaded, settlement, newlyApplied: false };
      }
      throw StorageError.conflict(
        `wallet reservation ${reservationId} was concurrently released; cannot settle`,
      );
    }

    const settlementRow = ((results[1]?.results ?? []) as SettlementRow[])[0];
    const settlement =
      settlementRow !== undefined
        ? settlementFromRow(settlementRow)
        : ((await this.getSettlement(reservationId)) ??
          (() => {
            throw StorageError.runtime(
              `wallet reservation ${reservationId} settled but its settlement is missing`,
            );
          })());

    return { reservation: reservationFromRow(flipped), settlement, newlyApplied: true };
  }

  /**
   * Cancel an active hold, restoring its credits to available balance (#281).
   * Idempotent on an already-released hold; refuses a settled one.
   */
  async releaseWalletReservation(
    reservationId: string,
    nowUnix: number,
  ): Promise<StoredWalletReservation> {
    requireAtomicBatch(this.handle, "release_wallet_reservation");
    const reservation = await this.getReservation(reservationId);
    if (!reservation) {
      throw StorageError.notFound(`wallet reservation ${reservationId} does not exist`);
    }
    if (reservation.status === WALLET_RESERVATION_SETTLED) {
      throw StorageError.conflict(
        `wallet reservation ${reservationId} was settled; cannot release`,
      );
    }
    if (reservation.status === WALLET_RESERVATION_RELEASED) return reservation;

    const released = await this.releaseReservationCas(reservationId, nowUnix);
    if (released) return released;

    // Guard missed — a concurrent transition won. Report its real terminal state.
    const reloaded = await this.getReservation(reservationId);
    if (!reloaded) {
      throw StorageError.notFound(`wallet reservation ${reservationId} does not exist`);
    }
    if (reloaded.status === WALLET_RESERVATION_SETTLED) {
      throw StorageError.conflict(
        `wallet reservation ${reservationId} was settled; cannot release`,
      );
    }
    return reloaded;
  }

  /**
   * Release every expired, active hold; returns the swept ids sorted.
   *
   * A single guarded `UPDATE ... RETURNING`, so the sweep is itself atomic and a
   * hold cannot be swept twice.
   *
   * PORT-TODO(D: inventory-data-billing §4 "x402"): the Postgres sweep carried a
   * `NOT EXISTS (SELECT 1 FROM payment_attempts ...)` guard so a hold owned by
   * an in-flight payment attempt (whose stablecoin transfer may already be
   * on-chain) is never released (#396/#352). `payment_attempts` is not created
   * by `sql/d1-ts/tenant/0001_init_tenant.sql` — x402 is deprioritized by
   * standing directive — so that clause cannot be written yet. Until it can,
   * callers MUST keep using `MemoryWalletStore.protectHoldId`'s equivalent at
   * the application layer; this method sweeps unconditionally.
   */
  async sweepExpiredWalletReservations(nowUnix: number): Promise<string[]> {
    requireAtomicBatch(this.handle, "sweep_expired_wallet_reservations");
    try {
      const result = await this.db
        .prepare(
          "UPDATE wallet_reservations SET status = 'released', updated_at_unix = ? " +
            "WHERE status = 'active' AND expires_at_unix <= ? RETURNING id",
        )
        .bind(nowUnix, nowUnix)
        .all<{ id: string }>();
      return result.results.map((r) => r.id).sort();
    } catch (error) {
      throw d1Error("sweep_expired_wallet_reservations", error);
    }
  }

  /**
   * Idempotent, no-double-apply balance settlement by `settlementId` (ports
   * `settle_wallet_balance`), used for top-ups and out-of-band adjustments that
   * are not backed by a hold.
   *
   * Three statements in one batch, using `balance_after_credits IS NULL` as the
   * claim token:
   *   S0 insert the settlement with a NULL `balance_after_credits`
   *      (`ON CONFLICT DO NOTHING`, so a replay claims nothing);
   *   S1 move the balance, guarded on that row existing AND still being NULL —
   *      i.e. on S0 having just created it;
   *   S2 stamp `balance_after_credits`, clearing the claim token.
   *
   * Because all three commit together, the token is never observable in a
   * NULL state by another transaction. A replay (or a concurrent duplicate that
   * loses the primary-key race) sees a non-NULL token, moves nothing, and
   * reports `newlyApplied: false`. Guarding on the id ALONE would be wrong: the
   * id exists as soon as S0 runs, including on the replay path, so the balance
   * would move twice.
   *
   * ## The amount is `bigint`-exact end to end
   *
   * `deltaCredits` accepts a `bigint` (and a safe-integer `number`, which the
   * older callers pass) and never touches a double after that. It reaches
   * SQLite as a decimal STRING, because D1 rejects a `bigint` parameter outright
   * and a `number` parameter would already have rounded — `100_000_000_000_001`
   * cents is 1_000_000_000_000_010_000 credits, and the nearest double is
   * sixteen credits short. `src/credits.ts` carries the whole argument. The
   * replay-conflict comparison reads the stored amount back as TEXT for the same
   * reason: comparing against the lossy decode would let a replay whose amount
   * differs only past the 53rd bit through as "the same movement".
   *
   * ## A settlement for a tenant with NO wallet row is refused, not swallowed
   *
   * S1 is an `UPDATE`, so with no `wallets` row it matches nothing — while S0
   * has already claimed the settlement id. The credit would vanish AND the id
   * would be permanently spent, so the retry that should have repaired it
   * reports `newlyApplied: false` and moves nothing either. That is the worst
   * shape a money bug can have, so S0 carries `WHERE EXISTS (SELECT 1 FROM
   * wallets …)`: with no wallet nothing is claimed, nothing is written, and the
   * call raises `not_found`. Callers that mean to adopt the wallet call
   * {@link ensureWallet} first.
   */
  async settleWalletBalance(
    settlementId: string,
    tenantId: string,
    deltaCredits: number | bigint,
    nowUnix: number,
  ): Promise<WalletSettlementOutcome> {
    requireAtomicBatch(this.handle, "settle_wallet_balance");
    this.assertTenant(tenantId, "settle_wallet_balance");
    const delta = exactCredits(deltaCredits, "settle_wallet_balance");
    const claimed0 = await this.settlementClaim(settlementId);
    if (claimed0 !== undefined) {
      if (claimed0.tenantId !== tenantId || claimed0.deltaCredits !== delta) {
        throw StorageError.conflict(
          `wallet settlement ${settlementId} replay changed tenant or amount`,
        );
      }
      const existing = await this.getSettlement(settlementId);
      if (existing === undefined) {
        throw StorageError.runtime(`wallet settlement ${settlementId} did not materialize`);
      }
      return { settlement: existing, newlyApplied: false };
    }

    const bound = bindCredits(delta);
    let results: D1Result[];
    try {
      results = await this.db.batch([
        this.db
          .prepare(
            "INSERT INTO wallet_settlements " +
              "(id, tenant_id, delta_credits, balance_after_credits, created_at_unix) " +
              "SELECT ?, ?, ?, NULL, ? " +
              "  WHERE EXISTS (SELECT 1 FROM wallets WHERE tenant_id = ?) " +
              "ON CONFLICT (id) DO NOTHING RETURNING id",
          )
          .bind(settlementId, tenantId, bound, nowUnix, tenantId),
        this.db
          .prepare(
            "UPDATE wallets SET balance_credits = balance_credits + ?, updated_at_unix = ? " +
              "WHERE tenant_id = ? " +
              "  AND EXISTS(SELECT 1 FROM wallet_settlements " +
              "             WHERE id = ? AND balance_after_credits IS NULL) " +
              "RETURNING balance_credits",
          )
          .bind(bound, nowUnix, tenantId, settlementId),
        this.db
          .prepare(
            `UPDATE wallet_settlements SET balance_after_credits =
               (SELECT balance_credits FROM wallets WHERE tenant_id = ?)
             WHERE id = ? AND balance_after_credits IS NULL RETURNING ${SETTLEMENT_COLUMNS}`,
          )
          .bind(tenantId, settlementId),
      ]);
    } catch (error) {
      throw d1Error("settle_wallet_balance", error);
    }

    const claimed = ((results[0]?.results ?? []) as { id: string }[]).length > 0;
    const row = ((results[2]?.results ?? []) as SettlementRow[])[0];
    if (row !== undefined) {
      return { settlement: settlementFromRow(row), newlyApplied: claimed };
    }
    // S2 stamped nothing: either a concurrent duplicate won the primary-key
    // race, or the tenant has no wallet row at all. The durable row is
    // authoritative — read it back rather than synthesizing one.
    const stored = await this.getSettlement(settlementId);
    if (!stored) {
      // Nothing was claimed and nothing was written, because S0's `WHERE EXISTS`
      // found no wallet. Saying so is the whole point: the alternative is a
      // top-up that reports success, moves nothing, and burns its own
      // idempotency key so the retry is a no-op too.
      throw StorageError.notFound(
        `tenant ${tenantId} has no wallet row; settlement ${settlementId} was not applied`,
      );
    }
    return { settlement: stored, newlyApplied: claimed };
  }

  /**
   * The settlement's tenant and EXACT amount, or `undefined` when the id is
   * unclaimed. Used only by {@link settleWalletBalance}'s replay guard — see
   * that method's docblock for why the amount must not come back through
   * {@link getSettlement}'s lossy `number` decode.
   */
  private async settlementClaim(
    settlementId: string,
  ): Promise<{ tenantId: string; deltaCredits: bigint } | undefined> {
    try {
      const row = await this.db
        .prepare(
          "SELECT tenant_id, CAST(delta_credits AS TEXT) AS delta FROM wallet_settlements WHERE id = ?",
        )
        .bind(settlementId)
        .first<{ tenant_id: string; delta: string }>();
      if (row === null) return undefined;
      return { tenantId: row.tenant_id, deltaCredits: creditsFromText(row.delta) ?? 0n };
    } catch (error) {
      throw d1Error("get_wallet_settlement", error);
    }
  }

  // --- Reads ---------------------------------------------------------------

  async getReservation(reservationId: string): Promise<StoredWalletReservation | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${RESERVATION_COLUMNS} FROM wallet_reservations WHERE id = ?`)
        .bind(reservationId)
        .first<ReservationRow>();
      return row ? reservationFromRow(row) : undefined;
    } catch (error) {
      throw d1Error("get_wallet_reservation", error);
    }
  }

  async getSettlement(settlementId: string): Promise<StoredWalletSettlement | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${SETTLEMENT_COLUMNS} FROM wallet_settlements WHERE id = ?`)
        .bind(settlementId)
        .first<SettlementRow>();
      return row ? settlementFromRow(row) : undefined;
    } catch (error) {
      throw d1Error("get_wallet_settlement", error);
    }
  }

  async listWalletReservations(tenantId: string): Promise<StoredWalletReservation[]> {
    try {
      const result = await this.db
        .prepare(
          `SELECT ${RESERVATION_COLUMNS} FROM wallet_reservations WHERE tenant_id = ?
           ORDER BY created_at_unix DESC, id ASC`,
        )
        .bind(tenantId)
        .all<ReservationRow>();
      return result.results.map(reservationFromRow);
    } catch (error) {
      throw d1Error("list_wallet_reservations", error);
    }
  }

  /**
   * Available balance = `balance_credits` − Σ(active, unexpired holds). Exposed
   * for pre-flight display ONLY — never as the input to a decision, because the
   * value is stale the moment it is returned. Decisions go through
   * {@link reserveWalletCredits}, where the arithmetic is inside the guard.
   */
  async availableCredits(tenantId: string, nowUnix: number): Promise<number | undefined> {
    try {
      const row = await this.db
        .prepare(
          "SELECT w.balance_credits - COALESCE((" +
            "  SELECT SUM(r.amount_credits) FROM wallet_reservations r " +
            "  WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ?" +
            "), 0) AS available FROM wallets w WHERE w.tenant_id = ?",
        )
        .bind(tenantId, nowUnix, tenantId)
        .first<{ available: number }>();
      return row ? row.available : undefined;
    } catch (error) {
      throw d1Error("available_credits", error);
    }
  }

  // --- Internals -----------------------------------------------------------

  /** The single guarded release CAS. `undefined` when the guard missed. */
  private async releaseReservationCas(
    reservationId: string,
    nowUnix: number,
  ): Promise<StoredWalletReservation | undefined> {
    try {
      const row = await this.db
        .prepare(
          `UPDATE wallet_reservations SET status = 'released', updated_at_unix = ?
           WHERE id = ? AND status = 'active' RETURNING ${RESERVATION_COLUMNS}`,
        )
        .bind(nowUnix, reservationId)
        .first<ReservationRow>();
      return row ? reservationFromRow(row) : undefined;
    } catch (error) {
      throw d1Error("release_wallet_reservation", error);
    }
  }

  /**
   * The mis-routing tripwire described in the tenant migration header: a write
   * whose `tenant_id` disagrees with the database it was routed to means the
   * router handed back the wrong tenant's database. Refuse rather than write
   * one tenant's money into another's ledger.
   */
  private assertTenant(tenantId: string, operation: string): void {
    if (tenantId !== this.handle.tenantId) {
      throw StorageError.runtime(
        `${operation}: tenant ${tenantId} routed to the database of tenant ` +
          `${this.handle.tenantId}; refusing to cross tenant isolation`,
      );
    }
  }
}
