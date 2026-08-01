/**
 * Contract group `admin_model` (1 operation) — `GET /admin/v1/models`.
 *
 * The admin listing of configured logical models. Rust filters it by the
 * caller's tenant (`can_tenant_use_model`) so a tenant key cannot enumerate
 * another tenant's private logical names and their upstream provider mapping;
 * here that filtering is the store's tenant scoping, applied for every
 * collection rather than remembered per handler.
 */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";

/**
 * PORT-TODO(P: inventory-edge-control §4 admin model listing) — same gap as
 * `admin_provider.ts`: Rust `handle_admin_models` (`local.rs:8227`) projects
 * `state.config.models` through `config_catalog_scope(...).visible_model(...)`
 * (the #535 field-level redaction of `visible_organization_ids` /
 * `visible_project_ids`); this lists a `models` document collection that no
 * contract operation writes, so it is empty on every deployment. The gateway's
 * own catalog comes from the `GATEWAY_MODELS` var
 * (`apps/gateway/src/inference/catalog.ts`), which this Worker never reads.
 *
 * The tenant fence IS correct here (the store applies it uniformly); the missing
 * piece is the SOURCE, plus the field-level redaction, which the store's
 * document passthrough does not perform — if a `models` document ever did carry
 * `visible_organization_ids`, this route would echo it, which is exactly the
 * #535 leak.
 */
export const adminModelRoutes: GroupModule = crudGroup("admin_model", [
  readOnlyCollection("models", "model"),
]);
