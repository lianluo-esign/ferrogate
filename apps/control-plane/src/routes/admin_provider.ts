/**
 * Contract group `admin_provider` (3 operations) — read-only provider views:
 * the configured providers, their live health, and the provider→model map.
 *
 * All three are `admin.read`. Rust's `AdminProvider` projection deliberately
 * exposes `has_api_key: bool` rather than the credential itself; the store rows
 * seeded into this app follow the same rule.
 */
import { crudGroup, readOnlyCollection, type GroupModule } from "./resource.js";

export const adminProviderRoutes: GroupModule = crudGroup("admin_provider", [
  readOnlyCollection("providers", "provider"),
  readOnlyCollection("provider-health", "provider_health"),
  readOnlyCollection("provider-models", "provider_model"),
]);
