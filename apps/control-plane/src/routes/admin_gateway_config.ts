/**
 * Contract group `admin_gateway_config` (6 operations) — CRUD over
 * `/admin/v1/gateway-configs`, the named config snapshots a deployment can
 * hold alongside the running one.
 *
 * Applying a snapshot is `POST /admin/v1/config/reload` in `admin_config_ops`,
 * not a write here: storing a config and activating it are deliberately two
 * operations in the Rust tree.
 */
import { adminRecordSchema, crudGroup, type GroupModule } from "./resource.js";

export const adminGatewayConfigRoutes: GroupModule = crudGroup("admin_gateway_config", [
  { segment: "gateway-configs", object: "gateway_config", body: adminRecordSchema },
]);
