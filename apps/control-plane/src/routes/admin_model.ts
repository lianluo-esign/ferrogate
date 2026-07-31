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

export const adminModelRoutes: GroupModule = crudGroup("admin_model", [
  readOnlyCollection("models", "model"),
]);
