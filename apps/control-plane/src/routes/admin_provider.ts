/**
 * Contract group `admin_provider` (3 operations) — read-only provider views:
 * the configured providers, their live health, and the provider→model map.
 *
 * All three are `admin.read`. Rust's `AdminProvider` projection deliberately
 * exposes `has_api_key: bool` rather than the credential itself; the store rows
 * seeded into this app follow the same rule.
 */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";

/**
 * PORT-TODO(P: inventory-edge-control §4 admin provider views) — these three read
 * the store, and Rust reads the RUNNING CONFIGURATION.
 *
 *   - `handle_admin_providers` (`local.rs:5019`) projects
 *     `state.config.providers` into `AdminProvider { name, kind, compatibility,
 *     base_url, has_api_key, enabled }`.
 *   - `handle_admin_provider_health` (`local.rs:7445`) reports live health.
 *   - `handle_admin_provider_models` (`local.rs:5062`) actually DISPATCHES a
 *     catalog request per enabled provider and renders `disabled` /
 *     `error` states per provider.
 *
 * No contract operation POSTs to `/admin/v1/providers`, so the `providers`,
 * `provider-health` and `provider-models` document collections have no writer
 * and every deployment answers an empty `AdminList` — including
 * `adapters.ts::StoreRuntimeStatus.status()`, whose `providers` count is
 * `#count("providers")` and is therefore pinned at 0 on
 * `GET /admin/v1/status`.
 *
 * The TS equivalent of "the running configuration" on this platform is the
 * gateway's `GATEWAY_PROVIDERS`/`GATEWAY_MODELS` vars (or the `gateway_providers`
 * control table, which also has no writer). Closing this means naming ONE of
 * those as the source and projecting it here, not seeding documents.
 */
export const adminProviderRoutes: GroupModule = crudGroup("admin_provider", [
  readOnlyCollection("providers", "provider"),
  readOnlyCollection("provider-health", "provider_health"),
  readOnlyCollection("provider-models", "provider_model"),
]);
