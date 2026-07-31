/**
 * Contract group `payment_attempt` (2 operations) — read-only, both
 * `admin.read`.
 *
 * ```
 *   GET /admin/v1/payment-attempts
 *   GET /admin/v1/payment-attempts/{id}    getPaymentAttemptLinks
 * ```
 *
 * The item read is `getPaymentAttemptLinks`: it returns the attempt together
 * with what it links to (wallet, invoice, billing event), which is how a
 * settlement is reconciled. There is deliberately no write path — a payment
 * attempt is a record of something that happened, and an admin-writable attempt
 * would be a ledger forgery primitive.
 */
import { crudGroup, readOnlyCollection, type GroupModule } from "./resource.js";

export const paymentAttemptRoutes: GroupModule = crudGroup("payment_attempt", [
  readOnlyCollection("payment-attempts", "payment_attempt"),
]);
