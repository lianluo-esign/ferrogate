/**
 * Contract group `plans` (5 operations).
 *
 * ```
 *   GET/POST          /admin/v1/plans
 *   GET/PUT/PATCH     /admin/v1/plans/{plan_id}
 * ```
 *
 * **A plan has no DELETE**, by contract. Tenants reference a plan
 * (`tenant_accounts.plan_id`, assigned via
 * `PUT /admin/v1/tenant-accounts/{tenant_id}/plan`), and deleting a plan out
 * from under them would leave those tenants billed against nothing. Retiring a
 * plan is a PATCH that disables it, which keeps historical billing rows
 * resolvable. `crudGroup` registers only what the contract declares, so
 * `DELETE /admin/v1/plans/{id}` answers 405 rather than silently succeeding.
 */
import { z } from "zod";
import { adminRecordSchema, crudGroup, type GroupModule } from "./resource.js";

export const planSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  enabled: z.boolean().optional(),
  monthly_token_budget: z.number().int().min(0).nullish(),
  rpm_limit: z.number().int().min(0).nullish(),
  price_cents: z.number().int().min(0).nullish(),
});

export const plansRoutes: GroupModule = crudGroup("plans", [
  { segment: "plans", object: "plan", idField: "id", body: planSchema },
]);
