import { providerCatalogOverrides } from "./admin_model_catalog.js";
/** Provider channel CRUD and the existing provider read-only projections. */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";

export const adminProviderRoutes: GroupModule = crudGroup(
  "admin_provider",
  [
    readOnlyCollection("providers", "provider"),
    readOnlyCollection("provider-health", "provider_health"),
    readOnlyCollection("provider-models", "provider_model"),
  ],
  providerCatalogOverrides(),
);
