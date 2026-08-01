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

/**
 * PORT-TODO(P: inventory-edge-control §5.2) — an api key created here authenticates
 * nothing, and the group cannot mint one.
 *
 * Two halves are missing, and they compound:
 *
 *  1. **No projection.** These six operations write only a
 *     `control_plane_resources` document. The operator-key authenticator
 *     (`store/api_keys.ts::D1ApiKeyAuthenticator`) reads the typed
 *     `static_api_keys` table, which has no writer anywhere in `apps/<app>/src`. So
 *     `POST /admin/v1/api-keys` produces a row the admin surface lists and the
 *     auth ladder never consults; `DELETE` likewise revokes nothing. Rust
 *     `handle_admin_api_key_upsert` mutated the config the authenticator reads,
 *     so the two could not diverge.
 *  2. **No secret.** The schema above deliberately REFUSES a client-supplied
 *     `secret`/`key`, but nothing mints one either — unlike
 *     `routes/admin_virtual_key.ts`, which mints, hashes, returns the plaintext
 *     exactly once and dual-writes `api_key_directory` + the tenant `api_keys`
 *     row. Refusing a supplied secret is right; not issuing one leaves the
 *     collection with no path to a working credential.
 *
 * The virtual-key module is the template for both halves. Note the two families
 * are NOT interchangeable: `static_api_keys` carries `platform_operator`, which
 * a durable/virtual key can never declare (#515).
 */
export const adminApiKeyRoutes: GroupModule = crudGroup("admin_api_key", [
  { segment: "api-keys", object: "api_key", body: adminApiKeySchema },
]);
