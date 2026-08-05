-- M9 Step 5 / issue #863
--
-- Preserve the pre-object rows for the idempotent tenant-scoped backfill while
-- removing the old table names from the active CONTROL authority surface.
-- Readers must use the tenant object; these names are migration input only.

ALTER TABLE tenant_provider_credentials RENAME TO tenant_provider_credentials_legacy;
ALTER TABLE sso_provider_configs RENAME TO sso_provider_configs_legacy;
ALTER TABLE tenant_role_bindings RENAME TO tenant_role_bindings_legacy;
ALTER TABLE semantic_cache_policies RENAME TO semantic_cache_policies_legacy;
ALTER TABLE delegation_revocations RENAME TO delegation_revocations_legacy;
ALTER TABLE control_plane_replay_floors RENAME TO control_plane_replay_floors_legacy;
ALTER TABLE budget_alert_notifications RENAME TO budget_alert_notifications_legacy;
