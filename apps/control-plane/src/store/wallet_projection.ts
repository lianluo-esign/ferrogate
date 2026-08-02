/**
 * The WRITE half of the `wallets` group — the prepaid money the data plane
 * actually spends, in the TENANT database.
 *
 * ## What this closes
 *
 * `POST /admin/v1/wallets/{tenant_id}/adjust` wrote `balance_cents` onto a
 * `control_plane_resources` document in the CONTROL database and answered
 * `200`. Admission reads a different column, in a different database, in a
 * different unit: `apps/gateway/src/ratelimit/quota.ts` selects
 * `balance_credits FROM wallets` in the tenant database and subtracts the live
 * `wallet_reservations` holds, and `apps/gateway/src/ratelimit/wallet.ts` takes
 * the no-oversell hold through `@ferrogate/storage`'s
 * `D1WalletStore.reserveWalletCredits` against the same table.
 *
 * **Nothing connected the two.** An operator could top a customer up, watch the
 * admin API answer 200, and the customer was still refused with
 * `wallet_balance_exhausted` on the very next request. Same defect class as the
 * virtual-key credential (`store/virtual_keys.ts`), the RBAC grant and the
 * quota chain — reader mounted, writer absent, both sides green against their
 * own fixtures — except that this one is money.
 *
 * ## Which balance is the truth
 *
 * The TENANT `wallets.balance_credits` row is authoritative, and the control
 * document's `balance_cents` is a MIRROR of it. That is not a preference; it is
 * forced. The gateway's metering settlement debits `balance_credits` on every
 * settled request and never touches the control document, so the document
 * begins diverging the moment the customer spends anything. A movement computed
 * from the DOCUMENT's running total would therefore re-add money the customer
 * had already spent — and a `charge` decided on it could drive real money
 * negative. So every movement here re-bases on the tenant balance, applies a
 * DELTA to it, and writes the result back into the document.
 *
 * When a deployment has NO tenant database for the tenant
 * (`tenantDatabaseFor` → `null`: the document-only posture every
 * `wrangler dev --local` starts in), the arithmetic falls back to the document
 * exactly as before, so that deployment's behaviour is unchanged.
 *
 * ## Units: cents in, credits stored, ONE conversion
 *
 * The admin surface speaks cents; the tables hold integer credits (1 credit ==
 * 1 micro-USD). The conversion is `@ferrogate/storage`'s `centsToCredits`, is
 * `bigint`, and is the only place it happens. `100_000_000_000_001` cents is
 * `1_000_000_000_000_010_000` credits, and the `number` product is sixteen
 * credits short of that — while printing as the right answer, because
 * `toString` emits the shortest round-tripping decimal. See
 * `packages/storage/src/credits.ts`.
 *
 * ## There is NO transaction across the two databases
 *
 * D1 has no cross-database `BEGIN` and no two-phase commit (and the REST query
 * API cannot do interactive transactions at all), so this is an
 * **idempotent outbox**, not an atomic write, and the report says so plainly:
 *
 *  - the CONTROL leg (ledger entry + document balance) is ONE `store.atomic`,
 *    i.e. one real D1 `batch()`;
 *  - the TENANT leg is ONE `D1WalletStore.settleWalletBalance`, i.e. one real
 *    D1 `batch()` whose idempotency is the `wallet_settlements` PRIMARY KEY;
 *  - the two are ORDERED so the residue of a crash between them fails in the
 *    safe direction, and a replay drives the outstanding leg forward instead of
 *    refusing.
 *
 * | movement | order | crash residue |
 * |---|---|---|
 * | credit (`delta > 0`, LOOSEN) | control ledger claim first, tenant money second | a ledger entry for money the customer does not have — they are under-funded, never over-funded |
 * | debit (`delta < 0`, TIGHTEN) | tenant money first, control ledger second | the money is already gone; the entry that explains it is missing |
 *
 * Both residues are repaired by re-submitting the movement with the same
 * `reference`: the ledger id is derived from it, the settlement id IS the
 * ledger id, and both legs are idempotent on their own id. The failure window
 * is therefore "one leg outstanding until the operator retries", not "money
 * created or destroyed".
 */
import {
  D1WalletStore,
  type TenantDatabaseHandle,
  bindCredits,
  centsToCredits,
  creditsToCents,
} from "@ferrogate/storage";

/**
 * The `wallet_settlements.id` a movement claims — equal to the CONTROL ledger
 * entry's id.
 *
 * Sharing one identifier across the two databases is what makes the pair
 * repairable: the control row is the claim, the tenant settlement is the
 * effect, and a replay can tell whether each has happened by looking for that
 * one id. A second, independently generated id would leave no way to ask.
 */
export function walletMovementSettlementId(ledgerEntryId: string): string {
  return ledgerEntryId;
}

/**
 * The ledger entry / settlement id for a movement.
 *
 * With a `reference` the id is DETERMINISTIC, which is what makes a
 * double-submission apply once: the second POST claims the same control row and
 * the same `wallet_settlements` primary key, and both refuse to move anything
 * twice. The tenant prefix keeps two tenants' references from colliding on the
 * account-global document table.
 *
 * WITHOUT a reference the id is random, and two identical POSTs are two
 * distinct movements. That is the truthful reading — with no idempotency key
 * there is nothing to distinguish an operator crediting a customer twice on
 * purpose from a retry — and collapsing them would silently swallow a real
 * second credit.
 */
export function walletLedgerEntryId(tenantId: string, reference: unknown): string {
  if (typeof reference === "string" && reference.trim() !== "") {
    return `wl_${tenantId}_${reference.trim()}`;
  }
  return crypto.randomUUID();
}

/** What the tenant leg did. */
export interface WalletMovementOutcome {
  /** The tenant balance AFTER the movement, exact. */
  readonly balanceCredits: bigint;
  /** `false` on an idempotent replay of a settlement that had already applied. */
  readonly newlyApplied: boolean;
}

/**
 * The tenant balance a movement must be decided against, adopting the wallet at
 * `openingCredits` if the tenant has never had one.
 *
 * The adoption is why `openingCredits` exists. `POST /admin/v1/wallets` stores a
 * document that may declare an opening `balance_cents`, and it deliberately does
 * NOT create the tenant row — creating one would flip that tenant from
 * "prepaid billing not adopted" (which the gateway must never deny) to
 * "adopted, balance zero" (which denies everything) on what is only a
 * bookkeeping act. The row is created the first time money actually moves, and
 * it carries the declared opening balance forward so the operator's `$10` does
 * not evaporate.
 */
export async function walletBalanceForMovement(
  handle: TenantDatabaseHandle,
  tenantId: string,
  openingCredits: bigint,
  nowUnix: number,
): Promise<bigint> {
  const store = new D1WalletStore(handle);
  await store.ensureWallet(tenantId, nowUnix, openingCredits);
  // `ensureWallet` guarantees the row, so `undefined` here would mean the row
  // vanished between two statements — read it rather than assuming zero, which
  // would re-mint the whole balance on the next movement.
  return (await store.balanceCreditsExact(tenantId)) ?? 0n;
}

/**
 * Apply the movement to the tenant's spendable balance.
 *
 * Idempotent on `settlementId`: `wallet_settlements` claims the id and moves the
 * balance in ONE D1 `batch()`, so a replay reports `newlyApplied: false` and
 * moves nothing. That is the property a double-submitted credit relies on.
 */
export async function projectWalletMovement(
  handle: TenantDatabaseHandle,
  options: {
    readonly settlementId: string;
    readonly tenantId: string;
    readonly deltaCredits: bigint;
    readonly nowUnix: number;
  },
): Promise<WalletMovementOutcome> {
  const store = new D1WalletStore(handle);
  const outcome = await store.settleWalletBalance(
    options.settlementId,
    options.tenantId,
    options.deltaCredits,
    options.nowUnix,
  );
  const balance = await store.balanceCreditsExact(options.tenantId);
  return { balanceCredits: balance ?? 0n, newlyApplied: outcome.newlyApplied };
}

/** The `wallets` document fields a movement writes back. See the module docblock. */
export function walletMirrorFields(
  balanceCredits: bigint,
  nowUnix: number,
): Record<string, unknown> {
  return {
    /**
     * DISPLAY only, and floored — see `creditsToCents`. A balance the gateway
     * has been spending against is rarely a whole number of cents, and this
     * must never report more money than exists. It is also a JS `number`, so it
     * is only exact below 2^53; `balance_credits` beside it is the exact value.
     */
    balance_cents: Number(creditsToCents(balanceCredits)),
    /** The authoritative amount, as a decimal string so no double is involved. */
    balance_credits: bindCredits(balanceCredits),
    updated_at: nowUnix,
  };
}

/** The credits an opening `balance_cents` on the wallet document declares. */
export function openingCreditsOf(balanceCents: unknown): bigint {
  return typeof balanceCents === "number" ? centsToCredits(balanceCents) : 0n;
}

// ---------------------------------------------------------------------------
// Payment methods
// ---------------------------------------------------------------------------

/**
 * Whether a `payment-methods` document can become a tenant row.
 *
 * `provider` and `provider_payment_method_id` are `NOT NULL` and carry the
 * `UNIQUE (tenant_id, provider, provider_payment_method_id)` constraint, so a
 * document missing either would either fail the insert or collide with the next
 * such document on the empty string. The admin schema does not require them
 * (it is a passthrough), so this is checked rather than assumed.
 */
export function paymentMethodProjectable(record: Record<string, unknown>): boolean {
  return (
    typeof record.provider === "string" &&
    record.provider.trim() !== "" &&
    typeof record.provider_payment_method_id === "string" &&
    record.provider_payment_method_id.trim() !== ""
  );
}

/**
 * Write the tenant `payment_methods` row a document describes.
 *
 * `is_default` is written as SQLite's 0/1, and the upsert is on `id` so a
 * retried create or a later edit converges instead of colliding.
 */
export async function projectPaymentMethod(
  handle: TenantDatabaseHandle,
  record: Record<string, unknown>,
  nowUnix: number,
): Promise<void> {
  await handle.db
    .prepare(
      `INSERT INTO payment_methods
         (id, tenant_id, provider, provider_customer_id, provider_payment_method_id,
          is_default, created_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         provider = excluded.provider,
         provider_customer_id = excluded.provider_customer_id,
         provider_payment_method_id = excluded.provider_payment_method_id,
         is_default = excluded.is_default`,
    )
    .bind(
      String(record.id),
      handle.tenantId,
      String(record.provider),
      typeof record.provider_customer_id === "string" ? record.provider_customer_id : "",
      String(record.provider_payment_method_id),
      record.is_default === true ? 1 : 0,
      nowUnix,
    )
    .run();
}

/**
 * Remove the tenant row, BEFORE the document goes.
 *
 * A payment method is an instrument the recharge path may charge, so a residual
 * row is money that can still be taken from a customer who was told the card
 * was removed. That is the residue that is not survivable, so it goes first —
 * the same rule `store/static_keys.ts` states for a grant.
 */
export async function unprojectPaymentMethod(
  handle: TenantDatabaseHandle,
  id: string,
): Promise<void> {
  await handle.db.prepare("DELETE FROM payment_methods WHERE id = ?").bind(id).run();
}
