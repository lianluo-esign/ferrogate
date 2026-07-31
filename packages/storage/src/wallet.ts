/**
 * Prepaid wallets, holds/reservations, and settlements
 * (ports `ferrogate-storage::wallet`, issues #169/#281).
 *
 * The load-bearing correctness proof (inventory §1.5.1/§1.5.2): reserving credits
 * is **no-oversell** — N parallel reserves against a balance affording N−1 admit
 * exactly N−1. On Postgres this is a `SELECT … FOR UPDATE` + conditional insert;
 * on D1 a 3-statement atomic batch. The reference in-memory backend (this module)
 * gets the same guarantee from a single serialization point: every mutation runs
 * to completion before the next, so a hold only lands when the just-read available
 * balance still covers it. Balances are integer credits (no float drift).
 */
import { StorageError } from "./errors.js";

/** A reservation whose hold is live and still counts against available balance. */
export const WALLET_RESERVATION_ACTIVE = "active";
/** A reservation captured into a real wallet debit. */
export const WALLET_RESERVATION_SETTLED = "settled";
/** A reservation cancelled or TTL-swept — never settleable. */
export const WALLET_RESERVATION_RELEASED = "released";

export type WalletReservationStatus = "active" | "settled" | "released";

export interface StoredWallet {
  /** Deterministic — equal to `tenantId` (a tenant has at most one wallet). */
  id: string;
  tenantId: string;
  balanceCredits: number;
  autoRechargeThresholdCredits?: number;
  autoRechargeAmountCredits?: number;
  dunning: boolean;
  createdAtUnix: number;
  updatedAtUnix: number;
}

export interface StoredPaymentMethod {
  id: string;
  tenantId: string;
  provider: string;
  providerCustomerId: string;
  providerPaymentMethodId: string;
  isDefault: boolean;
  createdAtUnix: number;
}

export interface StoredWalletSettlement {
  id: string;
  tenantId: string;
  deltaCredits: number;
  balanceAfterCredits?: number;
  createdAtUnix: number;
}

export interface WalletSettlementOutcome {
  settlement: StoredWalletSettlement;
  newlyApplied: boolean;
}

export interface StoredWalletReservation {
  /** Caller-supplied idempotency key; the settlement on capture reuses this id. */
  id: string;
  tenantId: string;
  amountCredits: number;
  status: WalletReservationStatus;
  expiresAtUnix: number;
  /** The `wallet_settlements.id` produced on capture (== id); undefined otherwise. */
  settlementId?: string;
  createdAtUnix: number;
  updatedAtUnix: number;
}

/** Outcome of {@link MemoryWalletStore.reserveWalletCredits}. */
export type WalletReservationResult =
  | { kind: "reserved"; reservation: StoredWalletReservation }
  | { kind: "insufficient"; availableCredits: number; requestedCredits: number }
  | { kind: "no_wallet" };

/** Outcome of capturing a hold via {@link MemoryWalletStore.settleWalletReservation}. */
export interface WalletReservationSettlement {
  reservation: StoredWalletReservation;
  settlement: StoredWalletSettlement;
  /** `false` on an idempotent replay of an already-captured hold. */
  newlyApplied: boolean;
}

/**
 * Reference in-memory wallet backend — the read-modify-write baseline the durable
 * backends mirror. Every method is synchronous and runs atomically from the
 * caller's view (single-threaded JS), giving the same no-oversell / idempotent
 * guarantees the Postgres row lock and D1 atomic batch provide.
 */
export class MemoryWalletStore {
  private readonly wallets = new Map<string, StoredWallet>();
  private readonly reservations = new Map<string, StoredWalletReservation>();
  private readonly settlements = new Map<string, StoredWalletSettlement>();
  private readonly paymentMethods = new Map<string, StoredPaymentMethod>();
  /** Hold ids owned by a payment attempt — never swept (money-safety, #396/#352). */
  private readonly protectedHoldIds = new Set<string>();

  upsertWallet(wallet: StoredWallet): void {
    this.wallets.set(wallet.id, { ...wallet });
  }

  getWallet(tenantId: string): StoredWallet | undefined {
    const w = this.wallets.get(tenantId);
    return w ? { ...w } : undefined;
  }

  listWallets(): StoredWallet[] {
    return [...this.wallets.values()].map((w) => ({ ...w }));
  }

  /** Applies a signed delta to a wallet balance; returns the updated wallet or undefined. */
  adjustWalletBalance(
    tenantId: string,
    deltaCredits: number,
    nowUnix: number,
  ): StoredWallet | undefined {
    const wallet = this.wallets.get(tenantId);
    if (!wallet) return undefined;
    wallet.balanceCredits += deltaCredits;
    wallet.updatedAtUnix = nowUnix;
    return { ...wallet };
  }

  setWalletDunning(tenantId: string, dunning: boolean, nowUnix: number): void {
    const wallet = this.wallets.get(tenantId);
    if (!wallet) return;
    wallet.dunning = dunning;
    wallet.updatedAtUnix = nowUnix;
  }

  /**
   * Idempotent, no-oversell balance settlement by `settlementId` (ports
   * `settle_wallet_balance`). A replay with a changed tenant or amount is a
   * conflict; a fresh id applies the delta and records the durable settlement.
   */
  settleWalletBalance(
    settlementId: string,
    tenantId: string,
    deltaCredits: number,
    nowUnix: number,
  ): WalletSettlementOutcome {
    const existing = this.settlements.get(settlementId);
    if (existing) {
      if (existing.tenantId !== tenantId || existing.deltaCredits !== deltaCredits) {
        throw StorageError.conflict(
          `wallet settlement ${settlementId} replay changed tenant or amount`,
        );
      }
      return { settlement: { ...existing }, newlyApplied: false };
    }
    const balanceAfter = this.adjustWalletBalance(tenantId, deltaCredits, nowUnix)?.balanceCredits;
    const settlement: StoredWalletSettlement = {
      id: settlementId,
      tenantId,
      deltaCredits,
      balanceAfterCredits: balanceAfter,
      createdAtUnix: nowUnix,
    };
    this.settlements.set(settlement.id, settlement);
    return { settlement: { ...settlement }, newlyApplied: true };
  }

  /**
   * Reserve `amountCredits` against available balance = balance − Σ(live holds).
   * No-oversell: N concurrent reserves against a balance affording N−1 admit
   * exactly N−1. Re-reserving the same id is a no-op that returns the existing
   * hold; a replay with a changed tenant/amount is a conflict; a tenant with no
   * wallet returns `no_wallet` (wallets are opt-in).
   */
  reserveWalletCredits(
    reservationId: string,
    tenantId: string,
    amountCredits: number,
    expiresAtUnix: number,
    nowUnix: number,
  ): WalletReservationResult {
    if (amountCredits <= 0) {
      throw StorageError.conflict(`wallet reservation ${reservationId} amount must be positive`);
    }
    const existing = this.reservations.get(reservationId);
    if (existing) {
      if (existing.tenantId !== tenantId || existing.amountCredits !== amountCredits) {
        throw StorageError.conflict(
          `wallet reservation ${reservationId} replay changed tenant or amount`,
        );
      }
      return { kind: "reserved", reservation: { ...existing } };
    }
    const wallet = this.wallets.get(tenantId);
    if (!wallet) return { kind: "no_wallet" };

    let outstanding = 0;
    for (const r of this.reservations.values()) {
      if (
        r.tenantId === tenantId &&
        r.status === WALLET_RESERVATION_ACTIVE &&
        r.expiresAtUnix > nowUnix
      ) {
        outstanding += r.amountCredits;
      }
    }
    const availableCredits = wallet.balanceCredits - outstanding;
    if (amountCredits > availableCredits) {
      return { kind: "insufficient", availableCredits, requestedCredits: amountCredits };
    }
    const reservation: StoredWalletReservation = {
      id: reservationId,
      tenantId,
      amountCredits,
      status: WALLET_RESERVATION_ACTIVE,
      expiresAtUnix,
      settlementId: undefined,
      createdAtUnix: nowUnix,
      updatedAtUnix: nowUnix,
    };
    this.reservations.set(reservation.id, reservation);
    return { kind: "reserved", reservation: { ...reservation } };
  }

  /**
   * Capture an active hold into a real debit (ports `settle_wallet_reservation`).
   * Idempotent on an already-settled hold; conflicts on a released one; expiring
   * an as-yet-unsettled hold releases it and refuses. On success debits
   * `-amountCredits`, writes the settlement (id == hold id), flips `active→settled`.
   */
  settleWalletReservation(reservationId: string, nowUnix: number): WalletReservationSettlement {
    const reservation = this.reservations.get(reservationId);
    if (!reservation) {
      throw StorageError.notFound(`wallet reservation ${reservationId} does not exist`);
    }
    if (reservation.status === WALLET_RESERVATION_SETTLED) {
      const settlement = this.settlements.get(reservationId);
      if (!settlement) {
        throw StorageError.runtime(
          `wallet reservation ${reservationId} is settled but its settlement is missing`,
        );
      }
      return { reservation: { ...reservation }, settlement: { ...settlement }, newlyApplied: false };
    }
    if (reservation.status === WALLET_RESERVATION_RELEASED) {
      throw StorageError.conflict(`wallet reservation ${reservationId} was released; cannot settle`);
    }
    if (reservation.expiresAtUnix <= nowUnix) {
      reservation.status = WALLET_RESERVATION_RELEASED;
      reservation.updatedAtUnix = nowUnix;
      throw StorageError.conflict(`wallet reservation ${reservationId} expired; cannot settle`);
    }
    const deltaCredits = -reservation.amountCredits;
    const balanceAfter = this.adjustWalletBalance(
      reservation.tenantId,
      deltaCredits,
      nowUnix,
    )?.balanceCredits;
    const settlement: StoredWalletSettlement = {
      id: reservationId,
      tenantId: reservation.tenantId,
      deltaCredits,
      balanceAfterCredits: balanceAfter,
      createdAtUnix: nowUnix,
    };
    this.settlements.set(settlement.id, settlement);
    reservation.status = WALLET_RESERVATION_SETTLED;
    reservation.settlementId = reservationId;
    reservation.updatedAtUnix = nowUnix;
    return { reservation: { ...reservation }, settlement: { ...settlement }, newlyApplied: true };
  }

  /**
   * Release (cancel) an active hold (ports `release_wallet_reservation`). A
   * settled hold cannot be released (conflict); an already-released one is a no-op.
   */
  releaseWalletReservation(reservationId: string, nowUnix: number): StoredWalletReservation {
    const reservation = this.reservations.get(reservationId);
    if (!reservation) {
      throw StorageError.notFound(`wallet reservation ${reservationId} does not exist`);
    }
    if (reservation.status === WALLET_RESERVATION_SETTLED) {
      throw StorageError.conflict(
        `wallet reservation ${reservationId} was settled; cannot release`,
      );
    }
    if (reservation.status === WALLET_RESERVATION_ACTIVE) {
      reservation.status = WALLET_RESERVATION_RELEASED;
      reservation.updatedAtUnix = nowUnix;
    }
    return { ...reservation };
  }

  /**
   * Mark a hold id as owned by a payment attempt, so
   * {@link sweepExpiredWalletReservations} never releases it (money-safety guard).
   */
  protectHoldId(holdId: string): void {
    this.protectedHoldIds.add(holdId);
  }

  /**
   * Release every expired, active, UNOWNED hold; returns the swept ids sorted.
   * A hold any payment attempt owns is retained (post-submission stablecoin may
   * be on-chain) — mirrors the Postgres `NOT EXISTS` guard.
   */
  sweepExpiredWalletReservations(nowUnix: number): string[] {
    const ids: string[] = [];
    for (const r of this.reservations.values()) {
      if (
        r.status === WALLET_RESERVATION_ACTIVE &&
        r.expiresAtUnix <= nowUnix &&
        !this.protectedHoldIds.has(r.id)
      ) {
        r.status = WALLET_RESERVATION_RELEASED;
        r.updatedAtUnix = nowUnix;
        ids.push(r.id);
      }
    }
    ids.sort();
    return ids;
  }

  listWalletReservations(tenantId: string): StoredWalletReservation[] {
    const out = [...this.reservations.values()]
      .filter((r) => r.tenantId === tenantId)
      .map((r) => ({ ...r }));
    out.sort((a, b) => b.createdAtUnix - a.createdAtUnix || a.id.localeCompare(b.id));
    return out;
  }

  upsertPaymentMethod(pm: StoredPaymentMethod): void {
    this.paymentMethods.set(pm.id, { ...pm });
  }

  getPaymentMethod(id: string): StoredPaymentMethod | undefined {
    const pm = this.paymentMethods.get(id);
    return pm ? { ...pm } : undefined;
  }

  listPaymentMethods(tenantId: string): StoredPaymentMethod[] {
    return [...this.paymentMethods.values()]
      .filter((pm) => pm.tenantId === tenantId)
      .map((pm) => ({ ...pm }));
  }

  deletePaymentMethod(id: string): boolean {
    return this.paymentMethods.delete(id);
  }
}
