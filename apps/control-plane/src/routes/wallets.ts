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
 * ## 0. Reading a balance is one authority; MOVING it is another (#790)
 *
 * The reads and the two movements do NOT share a fence.
 * {@link authorizeWalletTenant} asks "is this wallet MINE?" — the right question
 * for `GET /wallets/{tenant_id}` and the ledger, and on a movement the
 * escalation itself, because `walletAdjustSchema.amount_cents` is SIGNED: a
 * tenant-scoped `admin.write` key adjusted its own wallet by `+10_000_000` and
 * got a `200`. `adjust` and `charge` therefore run
 * {@link authorizeWalletMovement} — **operator only, both directions** — which
 * states why a negative self-adjustment is refused too rather than waved
 * through as self-harm.
 *
 * Three more shapes here are deliberate and easy to get wrong:
 *
 *  - **A wallet is keyed by `{tenant_id}`, not a wallet id.** One wallet per
 *    tenant; the path parameter IS the tenancy. A tenant-scoped caller may
 *    therefore only ever READ its own wallet, which is checked explicitly (the
 *    tenant is a path parameter, not a row attribute the store can filter on) —
 *    Rust `authorize_tenant_scope`.
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
 * The ledger entry and the balance it explains are written as ONE unit through
 * {@link ControlPlaneStore.atomic}, which on the durable store is a single D1
 * `batch()` — a real SQLite transaction — with both statements guarded on the
 * wallet revision the balance was computed from. That closes two holes the
 * previous sequential pair had: a failure between the two writes could leave a
 * ledger entry with no balance movement (money the operator is told about but
 * was never charged), and a concurrent movement could compute both new balances
 * from the same old one and lose a charge entirely.
 */
import {
  D1WalletStore,
  type TenantDatabaseHandle,
  bindCredits,
  centsToCredits,
  creditsToCents,
} from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { type CallerScope, StoreConflictError, type StoreRecord } from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";
import { tenantDatabaseFor, tenantOf } from "../store/tenancy.js";
import {
  openingCreditsOf,
  paymentMethodProjectable,
  projectPaymentMethod,
  projectWalletMovement,
  unprojectPaymentMethod,
  walletBalanceForMovement,
  walletLedgerEntryId,
  walletMirrorFields,
} from "../store/wallet_projection.js";
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
const PAYMENT_METHODS = "payment-methods";

/**
 * MARKER CLOSED — the `inventory-data-billing §2.5 wallets` PORT-TODO that
 * stood here read: "the balance this group moves is NOT the balance the data
 * plane spends against … `adjust`/`charge` write `balance_cents` onto a
 * `control_plane_resources` document in the CONTROL database [while]
 * `apps/gateway/src/ratelimit/quota.ts` admits a request against `SELECT
 * balance_credits FROM wallets WHERE tenant_id = ?` in the TENANT database …
 * so crediting a prepaid wallet through the admin API does not let the tenant
 * spend, and charging it does not stop them."
 *
 * Both halves are now connected through `store/wallet_projection.ts`, which
 * carries the whole argument: which balance is authoritative (the tenant one),
 * where the single cents→credits conversion lives (`@ferrogate/storage`'s
 * `centsToCredits`, in `bigint`), the ordering that makes a crash between the
 * two databases repairable, and the fact that this is an idempotent OUTBOX and
 * not a cross-database transaction, because D1 has neither.
 *
 * The marker's own closing instruction named
 * `apps/gateway/src/metering/credits.ts` as the home of the conversion. It is
 * not: that module converts USD→credits for the metering settlement and lives
 * in an app `apps/control-plane` cannot import. The cents→credits conversion
 * did not exist anywhere, so it was written once, in the package BOTH apps
 * already depend on.
 */

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

/**
 * Rust `authorize_tenant_scope` — the tenant is named in the path here.
 *
 * The fence for the READ legs ONLY (`GET /wallets/{tenant_id}` and the ledger).
 * It asks "is this wallet MINE?", which is the right question for a read and,
 * on a money movement, is the escalation itself — see
 * {@link authorizeWalletMovement} and decision 0 in the module header.
 */
function authorizeWalletTenant(scope: CallerScope, tenantId: string): void {
  if (scope.kind === "platform_operator") return;
  if (scope.tenantId === tenantId) return;
  throw new HttpError(
    403,
    "tenant_scope_denied",
    "API key is not authorized to access this tenant's resources",
  );
}

/**
 * The fence for a money MOVEMENT — `adjust` and `charge`: **operator only**
 * (#790).
 *
 * `authorizeWalletTenant` used to be the only fence on both movements, and
 * `walletAdjustSchema.amount_cents` is SIGNED and is handed straight to the
 * movement as its delta. So a tenant-scoped `admin.write` key `POST`ing
 * `/admin/v1/wallets/{its own id}/adjust` with `+10_000_000` answered `200` and
 * took `balance_cents` 500 → 10_000_500, projecting the `balance_credits`
 * `apps/gateway`'s admission actually spends. The tenant minted its own prepaid
 * money, with a ledger entry to explain it.
 *
 * Both verbs, both directions, decided rather than defaulted:
 *
 *  - **Crediting is the whole defect**, and it is the one place on this surface
 *    where a tenant-scoped credential can create value out of nothing. There is
 *    no argument for it.
 *  - **A DEBIT is refused too**, and that is the judgement call — spending your
 *    own credit is not an escalation, so the sign alone does not settle it.
 *    Three things do. (1) `adjust` is the OPERATOR's verb by construction: its
 *    rows land in the ledger as `kind: "adjustment"` with a mandatory `reason`,
 *    which in this system means "an operator moved this money, and here is
 *    why". A tenant-authored adjustment is indistinguishable from an operator's
 *    on every read and every export, so admitting it does not just move money —
 *    it makes the operator's reconciliation of credits and write-offs untrue.
 *    (2) The ledger entry id is DERIVED from the caller-chosen `reference`
 *    (`walletLedgerEntryId`), and the replay check below compares only the
 *    AMOUNT — not the kind, not the author. A tenant that may write any
 *    movement can therefore SQUAT a reference the operator is about to use:
 *    reproduced on the pre-fix tree, a tenant `adjust` of `-1` at reference
 *    `promo-2026-08` made the operator's real `+5_000` credit under that same
 *    reference answer `409 conflict`, permanently. At the SAME amount it is
 *    worse and quieter — the operator's movement is taken for a replay and
 *    skips the control leg entirely. A self-harming debit is therefore not
 *    confined to the tenant's own money; it is a claim on the operator's
 *    idempotency namespace. (3) A tenant that wants to spend already has a way
 *    to: the data plane. The gateway debits `wallets.balance_credits` directly
 *    through `@ferrogate/storage`, never through this route, so refusing the
 *    verb here costs the product nothing.
 *  - **`charge` is refused as well**, even though it always debits. Reasons (1)
 *    and (2) apply to it unchanged — it writes into the same ledger and the
 *    same `wl_{tenant}_{reference}` id space — and this is what the product
 *    already tells its users: the console's own copy says "Adjust and charge
 *    are platform-operator-only (#229/#232); a non-operator caller sees a 403"
 *    (`admin-console/src/i18n/locales/en/rest.ts`), and the legacy scope for
 *    that screen (#319) called them "operator adjust/charge flows". The
 *    implementation had drifted from its own stated contract; this restores it.
 *  - **The READ stays open**, unchanged. A customer that cannot see its prepaid
 *    balance and its ledger cannot tell an exhausted wallet from an outage, and
 *    cannot reconcile what it was charged.
 *
 * Refusing BEFORE the wallet is resolved and BEFORE the body is parsed is
 * deliberate, exactly as in `quota_policy.ts`: a fence after the lookup would
 * answer `404` for a tenant with no wallet document and `403` for one that has
 * a wallet, which makes the write leg an oracle for who has adopted prepaid
 * billing; and a caller this verb will never admit is not told which fields its
 * request was missing. One refusal, one code, no probe — which is also why a
 * non-operator naming ANOTHER tenant's wallet gets this code here rather than
 * `tenant_scope_denied`.
 */
function authorizeWalletMovement(scope: CallerScope, verb: string): void {
  if (scope.kind === "platform_operator") return;
  throw new HttpError(
    403,
    "wallet_movement_operator_only",
    `${verb} a wallet is an operator action: this credential is scoped to tenant ${scope.tenantId}, which may read its own wallet and its ledger but may not move the balance it is billed against`,
  );
}

function balanceOf(record: StoreRecord): number {
  return typeof record.balance_cents === "number" ? record.balance_cents : 0;
}

/**
 * The shared movement path: authorize the tenant, decide the movement against
 * the money that ACTUALLY exists, then write the two legs in the order that
 * makes a crash between them repairable.
 *
 * The CONTROL leg — the ledger entry and the balance it explains — is still ONE
 * `store.atomic` unit, i.e. one D1 `batch()` guarded on the revision the read
 * saw, so a concurrent movement makes the guard fail and the store re-decides
 * against the state that writer left. The TENANT leg is one `batch()` of its
 * own inside `settleWalletBalance`. There is deliberately no claim that the two
 * are one transaction; `store/wallet_projection.ts` states the window.
 */
function movement(options: {
  readonly entryKind: "adjustment" | "charge";
  /** Gerund naming the verb in the refusal — "adjusting", "charging". */
  readonly verb: string;
  readonly schema: z.ZodTypeAny;
  readonly delta: (body: Record<string, unknown>) => number;
}): Handler {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const tenantId = pathParam(c, "tenant_id");
    /**
     * FIRST — before the wallet is resolved and before the body is read (#790).
     *
     * This is the whole fence for a movement: `authorizeWalletTenant` is NOT
     * called here, and its absence is deliberate rather than an omission. Only
     * a platform operator gets past this line, and an operator passes the
     * tenant check unconditionally, so running both would be one live fence and
     * one dead one — and a dead fence reads like protection.
     */
    authorizeWalletMovement(scope, options.verb);

    const wallet = await deps.store.get(WALLETS, scope, tenantId);
    if (wallet === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);

    const body = (await readJson(c, options.schema)) as Record<string, unknown>;
    const deltaCents = options.delta(body);
    // The ONE conversion. `bigint` from here down — see `store/wallet_projection.ts`.
    const deltaCredits = centsToCredits(deltaCents);
    const now = Math.floor(Date.now() / 1000);

    // Throws 503 for a tenant that HAS a provisioned database this deployment
    // cannot reach; `null` means document-only, which is the posture this
    // surface has always had and keeps exactly.
    const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantId);

    /**
     * The balance the movement is decided against.
     *
     * With a tenant database this is `wallets.balance_credits` — the money the
     * gateway spends — NOT the document's running total, which the metering
     * settlement has been silently debiting past. Without one it is the
     * document, unchanged.
     */
    const baseCredits =
      handle === null
        ? centsToCredits(balanceOf(wallet))
        : await walletBalanceForMovement(
            handle,
            tenantId,
            openingCreditsOf(wallet.balance_cents),
            now,
          );

    // A `reference` makes the ids deterministic, which is what makes a
    // double-submission apply once. See `walletLedgerEntryId`.
    const entryId = walletLedgerEntryId(tenantId, body.reference);
    const prior =
      typeof body.reference === "string" && body.reference.trim() !== ""
        ? await deps.store.get(LEDGER, scope, entryId)
        : null;
    if (prior !== null && prior.amount_cents !== deltaCents) {
      // The same idempotency key for a DIFFERENT amount is an operator error,
      // and applying it would be the double-charge the key exists to prevent.
      throw new HttpError(
        409,
        "conflict",
        `wallet ${tenantId} already has a movement for reference ` +
          `${String(body.reference)} of a different amount`,
      );
    }

    const nextCredits = prior === null ? baseCredits + deltaCredits : baseCredits;
    if (nextCredits < 0n) {
      throw new HttpError(
        409,
        "conflict",
        `wallet ${tenantId} has insufficient balance for this ${options.entryKind}`,
      );
    }

    /**
     * The CONTROL leg. Skipped on a replay — the entry is already there — so a
     * retry drives the OTHER leg forward instead of 409-ing and leaving a
     * half-applied movement stuck forever.
     */
    const controlLeg = async (): Promise<StoreRecord> => {
      if (prior !== null) {
        const current = await deps.store.get(WALLETS, scope, tenantId);
        if (current === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);
        return current;
      }
      const applied = await deps.store.atomic(scope, [
        {
          kind: "create",
          collection: LEDGER,
          record: {
            id: entryId,
            wallet_id: tenantId,
            tenant_id: tenantId,
            kind: options.entryKind,
            amount_cents: deltaCents,
            amount_credits: bindCredits(deltaCredits),
            balance_after_cents: Number(creditsToCents(nextCredits)),
            balance_after_credits: bindCredits(nextCredits),
            reason: typeof body.reason === "string" ? body.reason : null,
            reference: typeof body.reference === "string" ? body.reference : null,
            recorded_at: now,
          },
        },
        {
          kind: "merge",
          collection: WALLETS,
          id: tenantId,
          patch: walletMirrorFields(nextCredits, now),
        },
      ]);
      // `null` means the wallet went away between the read and the write. It is
      // the same 404 the read would have produced, and — the point of the unit
      // — no ledger entry was written for a movement that did not happen.
      if (applied === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);
      return applied[1] as StoreRecord;
    };

    /** The TENANT leg: the money the data plane can actually spend. */
    const tenantLeg = async (h: TenantDatabaseHandle): Promise<void> => {
      await projectWalletMovement(h, {
        settlementId: entryId,
        tenantId,
        deltaCredits,
        nowUnix: now,
      });
    };

    if (handle === null) return json(c, 200, adminItem("wallet", await controlLeg()));

    // ORDER. A DEBIT tightens, so the enforced row goes first and a crash
    // leaves money already taken with its entry outstanding. A CREDIT loosens,
    // so the ledger claim goes first and a crash leaves the customer
    // under-funded rather than funded with nothing to explain it. Both residues
    // are repaired by re-submitting with the same `reference`.
    if (deltaCredits < 0n) {
      await tenantLeg(handle);
      return json(c, 200, adminItem("wallet", await controlLeg()));
    }
    const stored = await controlLeg();
    await tenantLeg(handle);
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
    /**
     * `POST /admin/v1/wallets` — a wallet is keyed by `tenant_id`, so that field is REQUIRED here
     * even though the schema leaves it optional for the merge legs (#965).
     *
     * The generic `createHandler` mints `crypto.randomUUID()` when the id field is absent, which is
     * right where the id is a surrogate and wrong here: this collection's id is a FOREIGN identity.
     * A generated one produces a wallet belonging to a tenant that does not exist — and, because
     * this module deliberately has no wallet DELETE (a balance with a ledger behind it is not
     * disposable), that row is permanently orphaned. An empty `POST {}` therefore used to answer
     * `201` and leave unreachable state behind; it now answers `400` and leaves nothing.
     */
    createWallet: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const body = await readJson(c, walletSchema);
      const tenantId = body.tenant_id?.trim();
      if (tenantId === undefined || tenantId === "") {
        throw new HttpError(
          400,
          "invalid_request_body",
          "request body is invalid: tenant_id: Required",
        );
      }
      authorizeWalletTenant(scope, tenantId);
      const record: StoreRecord = { ...body, tenant_id: tenantId, id: tenantId };
      const stored = await deps.store.create(WALLETS, scope, record);
      return json(c, 201, adminItem("wallet", stored));
    },

    getWallet: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      authorizeWalletTenant(scope, tenantId);
      const record = await deps.store.get(WALLETS, scope, tenantId);
      if (record === null) throw new HttpError(404, "not_found", `wallet ${tenantId} not found`);
      const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantId);
      if (handle === null) return json(c, 200, adminItem("wallet", record));

      const balanceCredits = await new D1WalletStore(handle).balanceCreditsExact(tenantId);
      const current =
        balanceCredits === undefined
          ? record
          : {
              ...record,
              balance_cents: Number(creditsToCents(balanceCredits)),
              balance_credits: bindCredits(balanceCredits),
            };
      return json(c, 200, adminItem("wallet", current));
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
      verb: "adjusting",
      schema: walletAdjustSchema,
      delta: (body) => (typeof body.amount_cents === "number" ? body.amount_cents : 0),
    }),

    chargeWallet: movement({
      entryKind: "charge",
      verb: "charging",
      schema: walletChargeSchema,
      // A charge always DEBITS, whatever sign the body used.
      delta: (body) => -Math.abs(typeof body.amount_cents === "number" ? body.amount_cents : 0),
    }),

    /**
     * `POST /admin/v1/payment-methods` — the document PLUS the tenant
     * `payment_methods` row.
     *
     * The generic `CollectionSpec.project` hook cannot serve this: it is handed
     * the CONTROL database, and this table lives in the tenant's OWN one. The
     * create semantics below are the generic handler's, unchanged — an explicit
     * `id` wins, otherwise a UUID; a duplicate id is a 409.
     */
    createPaymentMethod: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const body = (await readJson(c, paymentMethodSchema)) as Record<string, unknown>;
      const declared = body.id;
      const id =
        typeof declared === "string" && declared.trim() !== ""
          ? declared.trim()
          : crypto.randomUUID();
      let stored: StoreRecord;
      try {
        stored = await deps.store.create(PAYMENT_METHODS, scope, { ...body, id });
      } catch (error) {
        if (error instanceof StoreConflictError) {
          throw new HttpError(409, "conflict", `payment_method ${id} already exists`);
        }
        throw error;
      }
      // LOOSEN: the document first, so a crash in between leaves an instrument
      // the operator can see that the recharge path cannot yet charge.
      const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantOf(stored));
      if (handle !== null && paymentMethodProjectable(stored)) {
        await projectPaymentMethod(handle, stored, Math.floor(Date.now() / 1000));
      }
      return json(c, 201, adminItem("payment_method", stored));
    },

    /**
     * `DELETE /admin/v1/payment-methods/{id}` — the tenant row FIRST.
     *
     * A residual row is an instrument that can still be charged after the
     * operator was told it was removed, which is the one residue that is not
     * survivable here. Resolving the document for THIS caller's scope first is
     * what keeps "delete the tenant row before the document" from being an
     * unfenced cross-tenant write.
     */
    deletePaymentMethod: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const id = pathParam(c, "payment_method_id");
      const visible = await deps.store.get(PAYMENT_METHODS, scope, id);
      if (visible === null) {
        throw new HttpError(404, "not_found", `payment_method ${id} not found`);
      }
      const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantOf(visible));
      if (handle !== null) await unprojectPaymentMethod(handle, id);
      await deps.store.remove(PAYMENT_METHODS, scope, id);
      return json(c, 200, adminDeleted("payment_method", id));
    },

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
