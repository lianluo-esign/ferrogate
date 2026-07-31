/**
 * Contract group `admin_policy` (6 operations) — CRUD over
 * `/admin/v1/policies`, keyed by `{name}`.
 *
 * These are the routing/governance policies `@ferrogate/policy` evaluates, not
 * the immutable guardrail policy revisions (`guardrail_policy`, which has its
 * own revision/activate/rollback lifecycle and its own RBAC actions).
 */
import { z } from "zod";
import { adminRecordSchema, crudGroup, type GroupModule } from "./resource.js";

export const adminPolicySchema = adminRecordSchema.extend({
  name: z.string().trim().min(1),
  enabled: z.boolean().optional(),
  rules: z.array(z.record(z.unknown())).optional(),
});

export const adminPolicyRoutes: GroupModule = crudGroup("admin_policy", [
  { segment: "policies", object: "policy", idField: "name", body: adminPolicySchema },
]);
