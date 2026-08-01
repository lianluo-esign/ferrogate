/**
 * Contract group `admin_policy` (6 operations) — CRUD over
 * `/admin/v1/policies`, keyed by `{name}`.
 *
 * These are the routing/governance policies `@ferrogate/policy` evaluates, not
 * the immutable guardrail policy revisions (`guardrail_policy`, which has its
 * own revision/activate/rollback lifecycle and its own RBAC actions).
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

/**
 * PORT-TODO(P: cert2-controlplane §CLASS-A admin_policy) — CLASS A REGRESSION.
 * Rated `L` ("the Rust was also thin config CRUD") by the wave-15 pass; the
 * Rust says otherwise on both halves.
 *
 * READ: `local.rs::handle_admin_policies` (8865) projects `state.config.policies`
 * through `config_catalog_scope(&state, &auth).visible_policy(...)` — the #535
 * field-level redaction — and makes an out-of-scope name and an absent name the
 * SAME answer so the list cannot be recovered one probe at a time.
 * WRITE: `state.rs::upsert_policy` (1223) persists via
 * `repositories.upsert_control_plane_policy`, revalidates the whole candidate
 * config, `reload_process_local`s it and `publish_shared_control_plane`s it.
 *
 * Here the six operations are generic document CRUD over
 * `control_plane_resources` kind `policies`, and no module in `apps/*\/src` or
 * `packages/*\/src` reads that collection: `@ferrogate/policy` is driven from
 * the gateway's own config, never from these rows. So an operator can create,
 * PUT, PATCH and DELETE a routing/governance policy, receive 200/201 every time,
 * and change nothing the data plane evaluates.
 *
 * Two things to carry when closing it: the #535 scope redaction above (this
 * route's `passthrough()` store echoes whatever the document holds), and the
 * "absent and out-of-scope are indistinguishable" rule for `GET /policies/{name}`.
 */
export const adminPolicySchema = adminRecordSchema.extend({
  name: z.string().trim().min(1),
  enabled: z.boolean().optional(),
  rules: z.array(z.record(z.unknown())).optional(),
});

export const adminPolicyRoutes: GroupModule = crudGroup("admin_policy", [
  { segment: "policies", object: "policy", idField: "name", body: adminPolicySchema },
]);
