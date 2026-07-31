/**
 * Contract group `prompt` (6 operations) — CRUD over
 * `/admin/v1/prompt-templates`.
 *
 * Note the DELETE operation is `archiveAdminPromptTemplate`: Rust archives
 * rather than hard-deletes a template, because rendered requests reference the
 * template version they used. The generic delete handler removes the row from
 * the in-memory store today.
 *
 * PORT-TODO(inventory-policy-core §prompts): make DELETE a soft archive
 * (`archived_at` stamp + excluded from the default listing) once the D1 store
 * lands; the wire response (`{object, id, deleted: true}`) is unchanged either
 * way.
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

export const promptTemplateSchema = adminRecordSchema.extend({
  template: z.string().optional(),
  version: z.number().int().min(0).optional(),
});

export const promptRoutes: GroupModule = crudGroup("prompt", [
  { segment: "prompt-templates", object: "prompt_template", body: promptTemplateSchema },
]);
