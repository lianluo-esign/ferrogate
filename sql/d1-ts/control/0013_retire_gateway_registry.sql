-- ===========================================================================
-- Retire the unused env-var model registry tables (#811)
--
-- `gateway_providers` and `gateway_models` were created by the initial schema
-- as a possible D1 home for the registry. They have no reader or writer in any
-- Worker, control-plane route, migration, or package. The live registry is
-- still the env-var path until the tenant catalog loader (#812); the destination
-- schema is tenant-local `provider_channels` / `catalog_models` /
-- `catalog_model_offerings` from tenant migration 0009. Keeping two empty
-- control tables would suggest a second source of truth and let a future writer
-- accidentally bypass tenant isolation.
--
-- Models are dropped before providers because the former has a foreign key to
-- the latter. Both statements are idempotent for fresh and already migrated
-- control databases.
-- ===========================================================================

DROP TABLE IF EXISTS gateway_models;
DROP TABLE IF EXISTS gateway_providers;
