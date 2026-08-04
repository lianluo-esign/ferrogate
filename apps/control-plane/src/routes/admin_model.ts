/** Tenant-owned logical model and offering CRUD. */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";
import { modelCatalogOverrides } from "./admin_model_catalog.js";

export const adminModelRoutes: GroupModule = crudGroup(
  "admin_model",
  [readOnlyCollection("models", "model")],
  modelCatalogOverrides(),
);
