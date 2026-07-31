/**
 * Contract group `admin_api_key` (6 operations) — CRUD over
 * `/admin/v1/api-keys`, the operator-facing view of the gateway's own keys.
 *
 * Distinct from `admin_virtual_key` (`/admin/v1/virtual-keys`), which is the
 * tenant-minted credential family with its own enable/disable/revoke/rotate
 * lifecycle. Both exist in the Rust tree and both are ported; conflating them
 * would lose the lifecycle actions.
 *
 * The secret itself is never echoed: Rust stores `sha256:`/`blake2b:` hashes
 * plus a 16-char `key_prefix` and `last4`, and the admin views return only
 * those. The schema therefore refuses a client-supplied plaintext `secret`
 * rather than storing one.
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

export const adminApiKeySchema = adminRecordSchema
  .extend({
    enabled: z.boolean().optional(),
    scopes: z.array(z.string()).optional(),
    organization_id: z.string().trim().min(1).nullish(),
    expires_at: z.number().int().optional(),
  })
  .refine((body) => !("secret" in body) && !("key" in body), {
    message: "an API key secret is never accepted or echoed on the admin surface",
  });

export const adminApiKeyRoutes: GroupModule = crudGroup("admin_api_key", [
  { segment: "api-keys", object: "api_key", body: adminApiKeySchema },
]);
