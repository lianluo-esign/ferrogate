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

/**
 * PORT-TODO(P: cert2-controlplane §CLASS-A admin_plugin) — CLASS A REGRESSION, not
 * "the Rust was thin config CRUD". The wave-15 certification rated this group
 * `L` on that assumption; reading the Rust shows the assumption is wrong.
 *
 * `local.rs::handle_admin_plugins` (7470) answers `GET /extensions` and
 * `GET /plugins` from `state.extension_statuses()` and
 * `GET /plugins/{id}/tools` from `state.plugin_tools(id)`
 * (`state_tools.rs:13,17,24` → the live `extension_registry`), and the WRITE
 * half is `state.upsert_plugin_registration` (`state.rs:674`), which persists
 * through `repositories.upsert_control_plane_plugin_registration`, rebuilds the
 * config candidate, `validate()`s it and `reload_process_local`s it — a
 * COMMITTED hot reload with a `sync_control_plane_storage_from_config` rollback
 * on failure, plus `publish_shared_control_plane` for the cluster. Registering a
 * plugin through the admin API took effect on the next request, with no restart.
 *
 * Here all seven operations read and write `control_plane_resources` documents
 * of kind `plugins` / `extensions` / `plugin-tools`, and
 * `grep -rn '"plugins"' apps/*\/src packages/*\/src` finds no reader outside this
 * Worker. So `GET /admin/v1/extensions` is empty on every deployment, a
 * registration takes effect nowhere, and `adapters.ts::StoreRuntimeStatus.status()`
 * reports `plugins: 0` off the same collection.
 *
 * Closing it is the same cross-app decision named on `routes/admin_agent_upstream.ts`
 * and already made twice (`apps/mcp/src/catalog.ts`,
 * `apps/gateway/src/inference/workflow.ts`): the data plane reads
 * `control_plane_resources` directly, so the admin write IS the source.
 */
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
