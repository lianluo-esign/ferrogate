/**
 * Contract group `skill` (6 operations) — CRUD over `/admin/v1/skill-packages`,
 * the admin side of the `/v1/skills/**` data-plane surface `apps/gateway` owns.
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

/**
 * PORT-TODO(P: cert2-controlplane §CLASS-A skill) — CLASS A REGRESSION. The
 * wave-15 pass verdicted this group from its consumer graph (none) and rated it
 * `L` on the assumption that the Rust surface was also inert. It was not.
 *
 * `local.rs::handle_admin_skill_packages` (1696) lists `state.config.skill_packages`
 * through `scope.visible_skill_package(...)` (#535 re-sweep: `api_key_ids` is a
 * cross-tenant selector and the admin read used to leak it), and
 * `handle_admin_skill_package_upsert` (1844) calls `state.upsert_skill_package`
 * (`state.rs:1334`) — persist to `repositories.upsert_control_plane_skill_package`,
 * rebuild the candidate config, `validate()`, `reload_process_local`, and then
 * RE-READ the committed config to confirm the package is visible, answering
 * `409 skill_package_reload_rejected` when it is not. That is a full
 * write→enforce round trip, not a stub.
 *
 * Here the six operations are document CRUD over `control_plane_resources` kind
 * `skill-packages`. The data plane's skills come from the deploy-time
 * `GATEWAY_SKILL_PACKAGES` var — `apps/gateway/src/routes/skills.ts` and
 * `apps/gateway/src/inference/workflow.ts:611` — which this Worker never writes.
 * So publishing a skill package needs a `wrangler.toml` edit and a redeploy, and
 * DELETE does not withdraw one. Note the second-order blast radius: a skill
 * package OWNS workflows, so this also gates what `workflow.ts` will execute.
 */
export const skillPackageSchema = adminRecordSchema.extend({
  version: z.string().trim().min(1).optional(),
  enabled: z.boolean().optional(),
});

export const skillRoutes: GroupModule = crudGroup("skill", [
  { segment: "skill-packages", object: "skill_package", body: skillPackageSchema },
]);
