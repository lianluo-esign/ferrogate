-- ===========================================================================
-- Shared tenant-D1 write fence for the #824 backfill.
--
-- The control registry and the shared tenant database are different SQLite
-- databases, so a control-plane state change alone cannot stop a late gateway
-- write. This local fence is the source-side enforcement point. The migration
-- driver inserts one `frozen` row before its first source scan and removes it
-- only after rollback or after the source retention window has expired.
--
-- Tables without a direct tenant_id are deliberately not covered by a generic
-- trigger: their ownership is derived by the copier's explicit table query and
-- an un-attributable row is a verification failure, never a guessed tenant.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS tenant_write_fences (
    tenant_id TEXT PRIMARY KEY,
    migration_epoch INTEGER NOT NULL CHECK (migration_epoch >= 0),
    mode TEXT NOT NULL CHECK (mode IN ('frozen', 'open')),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_tenant_write_fences_mode
    ON tenant_write_fences(mode, tenant_id);

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_projects_insert
BEFORE INSERT ON projects
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_projects_update
BEFORE UPDATE ON projects
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_projects_delete
BEFORE DELETE ON projects
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workspaces_insert
BEFORE INSERT ON workspaces
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workspaces_update
BEFORE UPDATE ON workspaces
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workspaces_delete
BEFORE DELETE ON workspaces
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_api_keys_insert
BEFORE INSERT ON api_keys
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_api_keys_update
BEFORE UPDATE ON api_keys
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_api_keys_delete
BEFORE DELETE ON api_keys
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallets_insert
BEFORE INSERT ON wallets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallets_update
BEFORE UPDATE ON wallets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallets_delete
BEFORE DELETE ON wallets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_reservations_insert
BEFORE INSERT ON wallet_reservations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_reservations_update
BEFORE UPDATE ON wallet_reservations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_reservations_delete
BEFORE DELETE ON wallet_reservations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_settlements_insert
BEFORE INSERT ON wallet_settlements
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_settlements_update
BEFORE UPDATE ON wallet_settlements
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_settlements_delete
BEFORE DELETE ON wallet_settlements
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_payment_methods_insert
BEFORE INSERT ON payment_methods
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_payment_methods_update
BEFORE UPDATE ON payment_methods
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_payment_methods_delete
BEFORE DELETE ON payment_methods
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_stored_assets_insert
BEFORE INSERT ON stored_assets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_stored_assets_update
BEFORE UPDATE ON stored_assets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_stored_assets_delete
BEFORE DELETE ON stored_assets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_channels_insert
BEFORE INSERT ON asset_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_channels_update
BEFORE UPDATE ON asset_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_channels_delete
BEFORE DELETE ON asset_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_retention_policies_insert
BEFORE INSERT ON retention_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_retention_policies_update
BEFORE UPDATE ON retention_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_retention_policies_delete
BEFORE DELETE ON retention_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workflow_run_budgets_insert
BEFORE INSERT ON workflow_run_budgets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workflow_run_budgets_update
BEFORE UPDATE ON workflow_run_budgets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workflow_run_budgets_delete
BEFORE DELETE ON workflow_run_budgets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedules_insert
BEFORE INSERT ON agent_schedules
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedules_update
BEFORE UPDATE ON agent_schedules
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedules_delete
BEFORE DELETE ON agent_schedules
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_observed_agent_presence_insert
BEFORE INSERT ON observed_agent_presence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_observed_agent_presence_update
BEFORE UPDATE ON observed_agent_presence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_observed_agent_presence_delete
BEFORE DELETE ON observed_agent_presence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_cost_burn_insert
BEFORE INSERT ON agent_cost_burn
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_cost_burn_update
BEFORE UPDATE ON agent_cost_burn
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_cost_burn_delete
BEFORE DELETE ON agent_cost_burn
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_bundle_files_insert
BEFORE INSERT ON asset_bundle_files
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = NEW.tenant_id AND mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN stored_assets a ON a.id = NEW.asset_id
  WHERE f.tenant_id = a.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_bundle_files_update
BEFORE UPDATE ON asset_bundle_files
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = OLD.tenant_id AND mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = NEW.tenant_id AND mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN stored_assets a ON a.id = OLD.asset_id
  WHERE f.tenant_id = a.tenant_id AND f.mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN stored_assets a ON a.id = NEW.asset_id
  WHERE f.tenant_id = a.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_bundle_files_delete
BEFORE DELETE ON asset_bundle_files
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = OLD.tenant_id AND mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN stored_assets a ON a.id = OLD.asset_id
  WHERE f.tenant_id = a.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_responses_conversations_insert
BEFORE INSERT ON responses_conversations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_responses_conversations_update
BEFORE UPDATE ON responses_conversations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_responses_conversations_delete
BEFORE DELETE ON responses_conversations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_provider_channels_insert
BEFORE INSERT ON provider_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_provider_channels_update
BEFORE UPDATE ON provider_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_provider_channels_delete
BEFORE DELETE ON provider_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_models_insert
BEFORE INSERT ON catalog_models
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_models_update
BEFORE UPDATE ON catalog_models
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_models_delete
BEFORE DELETE ON catalog_models
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_model_offerings_insert
BEFORE INSERT ON catalog_model_offerings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_model_offerings_update
BEFORE UPDATE ON catalog_model_offerings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_model_offerings_delete
BEFORE DELETE ON catalog_model_offerings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_provider_credentials_insert
BEFORE INSERT ON tenant_provider_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_provider_credentials_update
BEFORE UPDATE ON tenant_provider_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_provider_credentials_delete
BEFORE DELETE ON tenant_provider_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_bindings_insert
BEFORE INSERT ON tenant_role_bindings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_bindings_update
BEFORE UPDATE ON tenant_role_bindings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_bindings_delete
BEFORE DELETE ON tenant_role_bindings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_control_plane_replay_floors_insert
BEFORE INSERT ON control_plane_replay_floors
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_control_plane_replay_floors_update
BEFORE UPDATE ON control_plane_replay_floors
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_control_plane_replay_floors_delete
BEFORE DELETE ON control_plane_replay_floors
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_budget_alert_notifications_insert
BEFORE INSERT ON budget_alert_notifications
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_budget_alert_notifications_update
BEFORE UPDATE ON budget_alert_notifications
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_budget_alert_notifications_delete
BEFORE DELETE ON budget_alert_notifications
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_identities_insert
BEFORE INSERT ON self_hosted_worker_identities
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_identities_update
BEFORE UPDATE ON self_hosted_worker_identities
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_identities_delete
BEFORE DELETE ON self_hosted_worker_identities
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_projection_retries_insert
BEFORE INSERT ON usage_projection_retries
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_projection_retries_update
BEFORE UPDATE ON usage_projection_retries
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_projection_retries_delete
BEFORE DELETE ON usage_projection_retries
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_ledger_insert
BEFORE INSERT ON billing_ledger
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_ledger_update
BEFORE UPDATE ON billing_ledger
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_ledger_delete
BEFORE DELETE ON billing_ledger
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_report_outbox_insert
BEFORE INSERT ON billing_report_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_report_outbox_update
BEFORE UPDATE ON billing_report_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_report_outbox_delete
BEFORE DELETE ON billing_report_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_events_insert
BEFORE INSERT ON billing_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_events_update
BEFORE UPDATE ON billing_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_events_delete
BEFORE DELETE ON billing_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

-- UPDATE must protect the incoming owner as well as the old owner. Without
-- this second trigger, a row from another tenant could be reassigned into a
-- frozen tenant while the old-owner trigger still passes.
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_projects_update_new
BEFORE UPDATE ON projects
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workspaces_update_new
BEFORE UPDATE ON workspaces
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_api_keys_update_new
BEFORE UPDATE ON api_keys
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallets_update_new
BEFORE UPDATE ON wallets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_reservations_update_new
BEFORE UPDATE ON wallet_reservations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_wallet_settlements_update_new
BEFORE UPDATE ON wallet_settlements
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_payment_methods_update_new
BEFORE UPDATE ON payment_methods
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_stored_assets_update_new
BEFORE UPDATE ON stored_assets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_channels_update_new
BEFORE UPDATE ON asset_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_retention_policies_update_new
BEFORE UPDATE ON retention_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_workflow_run_budgets_update_new
BEFORE UPDATE ON workflow_run_budgets
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedules_update_new
BEFORE UPDATE ON agent_schedules
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_observed_agent_presence_update_new
BEFORE UPDATE ON observed_agent_presence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_cost_burn_update_new
BEFORE UPDATE ON agent_cost_burn
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_responses_conversations_update_new
BEFORE UPDATE ON responses_conversations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_provider_channels_update_new
BEFORE UPDATE ON provider_channels
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_models_update_new
BEFORE UPDATE ON catalog_models
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_model_offerings_update_new
BEFORE UPDATE ON catalog_model_offerings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_provider_credentials_update_new
BEFORE UPDATE ON tenant_provider_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_bindings_update_new
BEFORE UPDATE ON tenant_role_bindings
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_control_plane_replay_floors_update_new
BEFORE UPDATE ON control_plane_replay_floors
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_budget_alert_notifications_update_new
BEFORE UPDATE ON budget_alert_notifications
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_identities_update_new
BEFORE UPDATE ON self_hosted_worker_identities
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_projection_retries_update_new
BEFORE UPDATE ON usage_projection_retries
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_ledger_update_new
BEFORE UPDATE ON billing_ledger
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_report_outbox_update_new
BEFORE UPDATE ON billing_report_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_billing_events_update_new
BEFORE UPDATE ON billing_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_asset_bundle_files_update_new
BEFORE UPDATE ON asset_bundle_files
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN stored_assets a ON a.id = NEW.asset_id
  WHERE f.tenant_id = a.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

-- Directly attributed tables introduced after the original 22-table tenant
-- snapshot. They need the same fence as the legacy tables above.
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_database_identity_insert
BEFORE INSERT ON tenant_database_identity
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_database_identity_update
BEFORE UPDATE ON tenant_database_identity
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_database_identity_delete
BEFORE DELETE ON tenant_database_identity
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_revisions_insert
BEFORE INSERT ON catalog_revisions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_revisions_update
BEFORE UPDATE ON catalog_revisions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_revisions_delete
BEFORE DELETE ON catalog_revisions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_audit_outbox_insert
BEFORE INSERT ON catalog_audit_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_audit_outbox_update
BEFORE UPDATE ON catalog_audit_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_catalog_audit_outbox_delete
BEFORE DELETE ON catalog_audit_outbox
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_request_logs_insert
BEFORE INSERT ON request_logs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_request_logs_update
BEFORE UPDATE ON request_logs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_request_logs_delete
BEFORE DELETE ON request_logs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_runs_insert
BEFORE INSERT ON agent_runs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_runs_update
BEFORE UPDATE ON agent_runs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_runs_delete
BEFORE DELETE ON agent_runs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_run_events_insert
BEFORE INSERT ON agent_run_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_run_events_update
BEFORE UPDATE ON agent_run_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_run_events_delete
BEFORE DELETE ON agent_run_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_guardrail_evaluations_insert
BEFORE INSERT ON guardrail_evaluations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_guardrail_evaluations_update
BEFORE UPDATE ON guardrail_evaluations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_guardrail_evaluations_delete
BEFORE DELETE ON guardrail_evaluations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_guardrail_check_evaluations_insert
BEFORE INSERT ON guardrail_check_evaluations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_guardrail_check_evaluations_update
BEFORE UPDATE ON guardrail_check_evaluations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_guardrail_check_evaluations_delete
BEFORE DELETE ON guardrail_check_evaluations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_servers_insert
BEFORE INSERT ON mcp_servers
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_servers_update
BEFORE UPDATE ON mcp_servers
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_servers_delete
BEFORE DELETE ON mcp_servers
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_oauth_credentials_insert
BEFORE INSERT ON mcp_oauth_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_oauth_credentials_update
BEFORE UPDATE ON mcp_oauth_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_oauth_credentials_delete
BEFORE DELETE ON mcp_oauth_credentials
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_identity_generations_insert
BEFORE INSERT ON mcp_identity_generations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_identity_generations_update
BEFORE UPDATE ON mcp_identity_generations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_mcp_identity_generations_delete
BEFORE DELETE ON mcp_identity_generations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_sso_provider_configs_insert
BEFORE INSERT ON sso_provider_configs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_sso_provider_configs_update
BEFORE UPDATE ON sso_provider_configs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant_id OR tenant_id = NEW.tenant_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_sso_provider_configs_delete
BEFORE DELETE ON sso_provider_configs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_delegation_revocations_insert
BEFORE INSERT ON delegation_revocations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_delegation_revocations_update
BEFORE UPDATE ON delegation_revocations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_delegation_revocations_delete
BEFORE DELETE ON delegation_revocations
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_online_eval_scores_insert
BEFORE INSERT ON online_eval_scores
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_online_eval_scores_update
BEFORE UPDATE ON online_eval_scores
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_online_eval_scores_delete
BEFORE DELETE ON online_eval_scores
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_online_eval_regressions_insert
BEFORE INSERT ON online_eval_regressions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_online_eval_regressions_update
BEFORE UPDATE ON online_eval_regressions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_online_eval_regressions_delete
BEFORE DELETE ON online_eval_regressions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_experiment_shadow_legs_insert
BEFORE INSERT ON experiment_shadow_legs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_experiment_shadow_legs_update
BEFORE UPDATE ON experiment_shadow_legs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_experiment_shadow_legs_delete
BEFORE DELETE ON experiment_shadow_legs
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_audit_events_insert
BEFORE INSERT ON audit_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_audit_events_update
BEFORE UPDATE ON audit_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.tenant OR tenant_id = NEW.tenant) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_audit_events_delete
BEFORE DELETE ON audit_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.tenant AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

-- Derived ownership tables use the same relationships as the copier manifest.
-- They cannot use a generic tenant_id trigger because doing so would either
-- miss writes or freeze unrelated tenants.
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_contexts_insert
BEFORE INSERT ON tenant_contexts
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = NEW.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = NEW.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = NEW.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = NEW.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_contexts_update
BEFORE UPDATE ON tenant_contexts
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = OLD.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = OLD.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = OLD.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = OLD.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = NEW.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = NEW.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = NEW.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = NEW.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_contexts_delete
BEFORE DELETE ON tenant_contexts
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = OLD.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = OLD.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = OLD.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = OLD.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_aggregate_rollups_insert
BEFORE INSERT ON usage_aggregate_rollups
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN tenant_contexts c ON c.id = NEW.tenant_context_id
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = c.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = c.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = c.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = c.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_aggregate_rollups_update
BEFORE UPDATE ON usage_aggregate_rollups
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN tenant_contexts c ON c.id = OLD.tenant_context_id
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = c.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = c.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = c.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = c.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN tenant_contexts c ON c.id = NEW.tenant_context_id
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = c.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = c.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = c.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = c.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_aggregate_rollups_delete
BEFORE DELETE ON usage_aggregate_rollups
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN tenant_contexts c ON c.id = OLD.tenant_context_id
  WHERE f.mode = 'frozen' AND (
    f.tenant_id = c.organization_id
    OR EXISTS (SELECT 1 FROM projects p WHERE p.id = c.project_id AND p.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = c.workspace_id AND w.tenant_id = f.tenant_id)
    OR EXISTS (SELECT 1 FROM api_keys k WHERE k.id = c.api_key_id AND k.tenant_id = f.tenant_id)
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_monthly_rollups_insert
BEFORE INSERT ON usage_monthly_rollups
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    (NEW.scope_type = 'tenant' AND f.tenant_id = NEW.scope_id)
    OR (NEW.scope_type = 'project' AND EXISTS (SELECT 1 FROM projects p WHERE p.id = NEW.scope_id AND p.tenant_id = f.tenant_id))
    OR (NEW.scope_type = 'workspace' AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = NEW.scope_id AND w.tenant_id = f.tenant_id))
    OR (NEW.scope_type = 'key' AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id = NEW.scope_id AND k.tenant_id = f.tenant_id))
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_monthly_rollups_update
BEFORE UPDATE ON usage_monthly_rollups
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    (OLD.scope_type = 'tenant' AND f.tenant_id = OLD.scope_id)
    OR (OLD.scope_type = 'project' AND EXISTS (SELECT 1 FROM projects p WHERE p.id = OLD.scope_id AND p.tenant_id = f.tenant_id))
    OR (OLD.scope_type = 'workspace' AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = OLD.scope_id AND w.tenant_id = f.tenant_id))
    OR (OLD.scope_type = 'key' AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id = OLD.scope_id AND k.tenant_id = f.tenant_id))
  )
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    (NEW.scope_type = 'tenant' AND f.tenant_id = NEW.scope_id)
    OR (NEW.scope_type = 'project' AND EXISTS (SELECT 1 FROM projects p WHERE p.id = NEW.scope_id AND p.tenant_id = f.tenant_id))
    OR (NEW.scope_type = 'workspace' AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = NEW.scope_id AND w.tenant_id = f.tenant_id))
    OR (NEW.scope_type = 'key' AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id = NEW.scope_id AND k.tenant_id = f.tenant_id))
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_monthly_rollups_delete
BEFORE DELETE ON usage_monthly_rollups
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  WHERE f.mode = 'frozen' AND (
    (OLD.scope_type = 'tenant' AND f.tenant_id = OLD.scope_id)
    OR (OLD.scope_type = 'project' AND EXISTS (SELECT 1 FROM projects p WHERE p.id = OLD.scope_id AND p.tenant_id = f.tenant_id))
    OR (OLD.scope_type = 'workspace' AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = OLD.scope_id AND w.tenant_id = f.tenant_id))
    OR (OLD.scope_type = 'key' AND EXISTS (SELECT 1 FROM api_keys k WHERE k.id = OLD.scope_id AND k.tenant_id = f.tenant_id))
  )
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_metadata_rollups_insert
BEFORE INSERT ON usage_metadata_rollups
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = NEW.organization_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_metadata_rollups_update
BEFORE UPDATE ON usage_metadata_rollups
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE (tenant_id = OLD.organization_id OR tenant_id = NEW.organization_id) AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_metadata_rollups_delete
BEFORE DELETE ON usage_metadata_rollups
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE tenant_id = OLD.organization_id AND mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedule_fires_insert
BEFORE INSERT ON agent_schedule_fires
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN agent_schedules s ON s.schedule_id = NEW.schedule_id
  WHERE f.tenant_id = s.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedule_fires_update
BEFORE UPDATE ON agent_schedule_fires
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN agent_schedules s ON s.schedule_id = OLD.schedule_id
  WHERE f.tenant_id = s.tenant_id AND f.mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN agent_schedules s ON s.schedule_id = NEW.schedule_id
  WHERE f.tenant_id = s.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_schedule_fires_delete
BEFORE DELETE ON agent_schedule_fires
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN agent_schedules s ON s.schedule_id = OLD.schedule_id
  WHERE f.tenant_id = s.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_resources_insert
BEFORE INSERT ON tenant_resources
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = json_extract(NEW.document_json, '$.tenant_id') AND mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_resources_update
BEFORE UPDATE ON tenant_resources
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = json_extract(OLD.document_json, '$.tenant_id')
    AND mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = json_extract(NEW.document_json, '$.tenant_id')
    AND mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_resources_delete
BEFORE DELETE ON tenant_resources
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = json_extract(OLD.document_json, '$.tenant_id') AND mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_heartbeats_insert
BEFORE INSERT ON self_hosted_worker_heartbeats
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_heartbeats_update
BEFORE UPDATE ON self_hosted_worker_heartbeats
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_heartbeats_delete
BEFORE DELETE ON self_hosted_worker_heartbeats
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_artifacts_insert
BEFORE INSERT ON self_hosted_worker_artifacts
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_artifacts_update
BEFORE UPDATE ON self_hosted_worker_artifacts
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_artifacts_delete
BEFORE DELETE ON self_hosted_worker_artifacts
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_checkpoints_insert
BEFORE INSERT ON self_hosted_worker_checkpoints
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_checkpoints_update
BEFORE UPDATE ON self_hosted_worker_checkpoints
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_checkpoints_delete
BEFORE DELETE ON self_hosted_worker_checkpoints
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_telemetry_events_insert
BEFORE INSERT ON self_hosted_worker_telemetry_events
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_telemetry_events_update
BEFORE UPDATE ON self_hosted_worker_telemetry_events
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = NEW.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_worker_telemetry_events_delete
BEFORE DELETE ON self_hosted_worker_telemetry_events
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences f
  JOIN self_hosted_worker_identities w ON w.worker_id = OLD.worker_id
  WHERE f.tenant_id = w.tenant_id AND f.mode = 'frozen'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_spend_anomaly_episodes_insert
BEFORE INSERT ON spend_anomaly_episodes
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = NEW.scope_id AND mode = 'frozen' AND NEW.scope_type = 'tenant'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_spend_anomaly_episodes_update
BEFORE UPDATE ON spend_anomaly_episodes
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = OLD.scope_id AND mode = 'frozen' AND OLD.scope_type = 'tenant'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = NEW.scope_id AND mode = 'frozen' AND NEW.scope_type = 'tenant'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_spend_anomaly_episodes_delete
BEFORE DELETE ON spend_anomaly_episodes
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = OLD.scope_id AND mode = 'frozen' AND OLD.scope_type = 'tenant'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_semantic_cache_policies_insert
BEFORE INSERT ON semantic_cache_policies
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = NEW.scope_id AND mode = 'frozen' AND NEW.scope_type = 'tenant'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_semantic_cache_policies_update
BEFORE UPDATE ON semantic_cache_policies
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = OLD.scope_id AND mode = 'frozen' AND OLD.scope_type = 'tenant'
)
OR EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = NEW.scope_id AND mode = 'frozen' AND NEW.scope_type = 'tenant'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_semantic_cache_policies_delete
BEFORE DELETE ON semantic_cache_policies
WHEN EXISTS (
  SELECT 1 FROM tenant_write_fences
  WHERE tenant_id = OLD.scope_id AND mode = 'frozen' AND OLD.scope_type = 'tenant'
)
BEGIN SELECT RAISE(ABORT, 'tenant data writes are frozen for backfill'); END;

-- These tables have no safe tenant ownership key. A non-empty row set already
-- makes the copier fail closed; while any tenant is frozen, reject writes too
-- so a new global row cannot appear after the empty-set check.
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_catalog_insert
BEFORE INSERT ON tenant_role_catalog
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_catalog_update
BEFORE UPDATE ON tenant_role_catalog
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_tenant_role_catalog_delete
BEFORE DELETE ON tenant_role_catalog
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_templates_insert
BEFORE INSERT ON managed_worker_templates
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_templates_update
BEFORE UPDATE ON managed_worker_templates
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_templates_delete
BEFORE DELETE ON managed_worker_templates
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_worker_instances_insert
BEFORE INSERT ON agent_worker_instances
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_worker_instances_update
BEFORE UPDATE ON agent_worker_instances
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_agent_worker_instances_delete
BEFORE DELETE ON agent_worker_instances
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_sessions_insert
BEFORE INSERT ON managed_worker_sessions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_sessions_update
BEFORE UPDATE ON managed_worker_sessions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_sessions_delete
BEFORE DELETE ON managed_worker_sessions
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_lifecycle_events_insert
BEFORE INSERT ON managed_worker_lifecycle_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_lifecycle_events_update
BEFORE UPDATE ON managed_worker_lifecycle_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_lifecycle_events_delete
BEFORE DELETE ON managed_worker_lifecycle_events
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_selections_insert
BEFORE INSERT ON managed_worker_isolation_selections
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_selections_update
BEFORE UPDATE ON managed_worker_isolation_selections
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_selections_delete
BEFORE DELETE ON managed_worker_isolation_selections
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_policies_insert
BEFORE INSERT ON managed_worker_isolation_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_policies_update
BEFORE UPDATE ON managed_worker_isolation_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_policies_delete
BEFORE DELETE ON managed_worker_isolation_policies
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_run_dispatches_insert
BEFORE INSERT ON self_hosted_run_dispatches
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_run_dispatches_update
BEFORE UPDATE ON self_hosted_run_dispatches
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_self_hosted_run_dispatches_delete
BEFORE DELETE ON self_hosted_run_dispatches
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_evidence_insert
BEFORE INSERT ON managed_worker_isolation_evidence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_evidence_update
BEFORE UPDATE ON managed_worker_isolation_evidence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_managed_worker_isolation_evidence_delete
BEFORE DELETE ON managed_worker_isolation_evidence
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;

CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_event_claims_insert
BEFORE INSERT ON usage_event_claims
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_event_claims_update
BEFORE UPDATE ON usage_event_claims
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
CREATE TRIGGER IF NOT EXISTS tenant_backfill_fence_usage_event_claims_delete
BEFORE DELETE ON usage_event_claims
WHEN EXISTS (SELECT 1 FROM tenant_write_fences WHERE mode = 'frozen')
BEGIN SELECT RAISE(ABORT, 'unowned tenant data writes are frozen for backfill'); END;
