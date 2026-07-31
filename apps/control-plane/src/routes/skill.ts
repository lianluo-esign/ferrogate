/**
 * Contract group `skill` (6 operations) — CRUD over `/admin/v1/skill-packages`,
 * the admin side of the `/v1/skills/**` data-plane surface `apps/gateway` owns.
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

export const skillPackageSchema = adminRecordSchema.extend({
  version: z.string().trim().min(1).optional(),
  enabled: z.boolean().optional(),
});

export const skillRoutes: GroupModule = crudGroup("skill", [
  { segment: "skill-packages", object: "skill_package", body: skillPackageSchema },
]);
