/**
 * Contract group `wallets` (10 operations) — prepaid balances, their ledger,
 * and the payment methods that top them up.
 *
 * ```
 *   GET/POST    /admin/v1/wallets
 *   GET/PATCH   /admin/v1/wallets/{tenant_id}
 *   POST        /admin/v1/wallets/{tenant_id}/adjust      operator credit/debit
 *   POST        /admin/v1/wallets/{tenant_id}/charge      consume balance
 *   GET         /admin/v1/wallets/{tenant_id}/ledger
 *   GET/POST    /admin/v1/payment-methods
 *   DELETE      /admin/v1/payment-methods/{payment_method_id}
 * ```
 *
 * Three shapes here are deliberate and easy to get wrong:
 *
 *  - **A wallet is keyed by `{tenant_id}`, not a wallet id.** One wallet per
 *    tenant; the path parameter IS the tenancy. A tenant-scoped caller may
 *    therefore only ever address its own wallet, which is checked explicitly
 *    (the tenant is a path parameter, not a row attribute the store can filter
 *    on) — Rust `authorize_tenant_scope`.
 *  - **There is no wallet DELETE.** A balance with a ledger behind it is not
 *    deletable; that would destroy the audit trail for money.
 *  - **`adjust` and `charge` both write a LEDGER ENTRY, then move the
 *    balance.** The ledger is the source of truth and the balance is its
 *    running total, which is why neither is a plain PATCH of `balance_cents`:
 *    a balance moved without an entry is an unexplained one.
 *
 * `charge` refuses to overdraw. Rust's wallet hold/settle path treats an
 * insufficient balance as a `409`, not a silent negative balance.
 *
 * PORT-TODO(inventory-data-billing §wallets): the balance update and its ledger
 * insert must become one atomic D1 `batch()` when `@ferrogate/storage` lands —
 * on the in-memory store they are two sequential writes in a single-threaded
 * isolate, which is atomic in practice but not by construction.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminItem, listResponse, parseListQuery } from "../responses.js";
import {
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const WALLETS = "wallets";
const LEDGER = "wallet-ledger";

export const walletSchema = adminRecordSchema.extend({
  tenant_id: z.string().trim().min(1).optional(),
  balance_cents: z.number().int().optional(),
  currency: z.string().trim().min(1).optional(),
});

/** `adjust`: a signed operator movement with a mandatory reason. */
export const walletAdjustSchema = z
  .object({
    amount_cents: z.number().int(),
    reason: z.string().trim().min(1),
    reference: z.string().trim().min(1).optional(),
  })
  .strict();

/** `charge`: a positive consumption. */
export const walletChargeSchema = z
  .object({
    amount_cents: z.number().int().positive(),
    reason: z.string().trim().min(1).optional(),
    reference: z.string().trim().min(1).optional(),
  })
  .strict();

export const paymentMethodSchema = adminRecordSchema
  .extend({
    kind: z.string().trim().min(1).optional(),
    last4: z.string().trim().length(4).optional(),
    tenant_id: z.string().trim().min(1).optional(),
  })
  // A payment instrument's raw number/token never crosses the admin boundary.
  .refine((body) => !("card_number" in body) && !("pan" in body), {
    message: "raw payment instrument data is never accepted on the admin surface",
  });

/** Rust `authorize_tenant_scope` — the tenant is named in the path here. */
function authorizeWalletTenant(scope: CallerScope, tenantId: string): void {
  if (scope.kind === "platform_operator") return;
  if (scope.tenantId === tenantId) return;
  throw new HttpError(
    403,
    "tenant_scope_denied",
    "API key is not authorized to access this tenant's resources",
  );
}

function balanceOf(record: StoreRecord): number {
  return typeof record.balance_cents === "number" ? record.balance_cents : 0;
}

/**
 * The shared movement path: authorize the tenant, load the wallet, append a
 * ledger entry, then move the balance to match it.
 */
function movement(options: {
  readonly entryKind: "adjustment" | "charge";
  readonly schema: z.ZodTypeAny;
  readonly delta: (body: Record<string, unknown>) => number;
}): Handler {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const tenantId = pathParam(c, "tenant_id");
    authorizeWalletTenant(scope, tenantId);

    const wallet = await deps.store.get(WALLETS, scope, tenantId);
    if (wallet === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);

    const body = (await readJson(c, options.schema)) as Record<string, unknown>;
    const delta = options.delta(body);
    const next = balanceOf(wallet) + delta;
    if (next < 0) {
      throw new HttpError(
        409,
        "conflict",
        `wallet ${tenantId} has insufficient balance for this ${options.entryKind}`,
      );
    }

    const now = Math.floor(Date.now() / 1000);
    await deps.store.create(LEDGER, scope, {
      id: crypto.randomUUID(),
      wallet_id: tenantId,
      tenant_id: tenantId,
      kind: options.entryKind,
      amount_cents: delta,
      balance_after_cents: next,
      reason: typeof body.reason === "string" ? body.reason : null,
      reference: typeof body.reference === "string" ? body.reference : null,
      recorded_at: now,
    });
    const stored = await deps.store.merge(WALLETS, scope, tenantId, {
      balance_cents: next,
      updated_at: now,
    });
    return json(c, 200, adminItem("wallet", stored));
  };
}

export const walletsRoutes: GroupModule = crudGroup(
  "wallets",
  [
    { segment: WALLETS, object: "wallet", idField: "tenant_id", body: walletSchema },
    { segment: "payment-methods", object: "payment_method", body: paymentMethodSchema },
  ],
  {
    getWallet: async (c) => {
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      authorizeWalletTenant(scope, tenantId);
      const record = await c.get("deps").store.get(WALLETS, scope, tenantId);
      if (record === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);
      return json(c, 200, adminItem("wallet", record));
    },

    updateWallet: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      authorizeWalletTenant(scope, tenantId);
      const body = await readJson(c, walletSchema);
      // A balance only ever moves through `adjust`/`charge`, which write the
      // ledger entry that explains the movement.
      const { balance_cents: _rejected, ...fields } = body;
      const stored = await deps.store.merge(WALLETS, scope, tenantId, fields);
      if (stored === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);
      return json(c, 200, adminItem("wallet", stored));
    },

    adjustWallet: movement({
      entryKind: "adjustment",
      schema: walletAdjustSchema,
      delta: (body) => (typeof body.amount_cents === "number" ? body.amount_cents : 0),
    }),

    chargeWallet: movement({
      entryKind: "charge",
      schema: walletChargeSchema,
      // A charge always DEBITS, whatever sign the body used.
      delta: (body) => -Math.abs(typeof body.amount_cents === "number" ? body.amount_cents : 0),
    }),

    listWalletLedger: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      authorizeWalletTenant(scope, tenantId);
      if ((await deps.store.get(WALLETS, scope, tenantId)) === null) {
        throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);
      }
      const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
      const scoped = { ...query, filters: { ...query.filters, wallet_id: tenantId } };
      const page = await deps.store.list(LEDGER, scope, scoped);
      return json(c, 200, listResponse(page, scoped));
    },
  },
);
