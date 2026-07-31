/**
 * Contract group `admin_plugin` (7 operations).
 *
 * ```
 *   GET    /admin/v1/extensions              the active extension statuses
 *   GET    /admin/v1/plugins                 registered plugins
 *   POST   /admin/v1/plugins
 *   GET    /admin/v1/plugins/{plugin_id}
 *   PATCH  /admin/v1/plugins/{plugin_id}     (no PUT — the contract has none)
 *   DELETE /admin/v1/plugins/{plugin_id}
 *   GET    /admin/v1/plugins/{plugin_id}/tools
 * ```
 *
 * The absent `PUT` is not an oversight to "fix": a plugin registration is
 * patched, never wholesale replaced, because the runtime holds live state keyed
 * by the registration. `crudGroup` only derives the shapes the contract
 * declares, so no `PUT` route is registered and `PUT /admin/v1/plugins/{id}`
 * correctly answers 405 with `Allow: GET, PATCH, DELETE`.
 */
import { z } from "zod";
import {
  type CollectionSpec,
  type GroupModule,
  adminRecordSchema,
  crudGroup,
  readOnlyCollection,
  subListHandler,
} from "./resource.js";

export const pluginSchema = adminRecordSchema.extend({
  version: z.string().trim().min(1).optional(),
  enabled: z.boolean().optional(),
  active: z.boolean().optional(),
});

const PLUGIN_SPEC: CollectionSpec = {
  segment: "plugins",
  object: "plugin",
  body: pluginSchema,
};

export const adminPluginRoutes: GroupModule = crudGroup(
  "admin_plugin",
  [PLUGIN_SPEC, readOnlyCollection("extensions", "extension")],
  {
    listAdminPluginTools: subListHandler({
      parent: PLUGIN_SPEC,
      parentParam: "plugin_id",
      collection: "plugin-tools",
      parentField: "plugin_id",
    }),
  },
);
