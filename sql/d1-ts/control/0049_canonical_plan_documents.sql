-- Single authority: the admin document; typed SQL readers use an indexed view.
-- Merge the former runtime authority into existing documents before dropping it.
INSERT INTO control_plane_resources (resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
SELECT 'plans',id,json_object('id', id, 'name', name, 'slug', slug, 'mcp_enabled', json(CASE WHEN COALESCE(mcp_enabled,0)=1 THEN 'true' ELSE 'false' END), 'self_hosted_workers_enabled', json(CASE WHEN COALESCE(self_hosted_workers_enabled,0)=1 THEN 'true' ELSE 'false' END), 'admin_console_seats', admin_console_seats, 'default_model_allowlist', json(CASE WHEN json_valid(default_model_allowlist_json) THEN default_model_allowlist_json ELSE '[]' END), 'default_rpm_limit', default_rpm_limit, 'default_tpm_limit', default_tpm_limit, 'default_monthly_budget_usd', default_monthly_budget_usd, 'created_at', created_at_unix, 'updated_at', updated_at_unix, 'asset_hosting_enabled', json(CASE WHEN COALESCE(asset_hosting_enabled,0)=1 THEN 'true' ELSE 'false' END), 'default_asset_storage_quota_bytes', default_asset_storage_quota_bytes, 'extension_tools_enabled', json(CASE WHEN COALESCE(extension_tools_enabled,0)=1 THEN 'true' ELSE 'false' END), 'default_monthly_egress_bytes_budget', default_monthly_egress_bytes_budget, 'default_download_rpm_limit', default_download_rpm_limit, 'default_asset_max_object_bytes', default_asset_max_object_bytes, 'default_agent_cost_budget_usd', default_agent_cost_budget_usd),1,created_at_unix,updated_at_unix FROM plans WHERE true
ON CONFLICT (resource_kind,resource_id) DO UPDATE SET
 document_json=json_patch(control_plane_resources.document_json,excluded.document_json);
DROP TABLE plans;
CREATE VIEW plans AS SELECT
resource_id AS id,
COALESCE(json_extract(document_json,'$.name'),resource_id) AS name,
COALESCE(json_extract(document_json,'$.slug'),resource_id) AS slug,
CASE WHEN json_type(document_json,'$.mcp_enabled')='true' THEN 1 WHEN json_type(document_json,'$.mcp_enabled')='false' THEN 0 ELSE 0 END AS mcp_enabled,
CASE WHEN json_type(document_json,'$.self_hosted_workers_enabled')='true' THEN 1 WHEN json_type(document_json,'$.self_hosted_workers_enabled')='false' THEN 0 ELSE 0 END AS self_hosted_workers_enabled,
CASE WHEN json_type(document_json,'$.admin_console_seats') IN ('integer','real') THEN json_extract(document_json,'$.admin_console_seats') ELSE NULL END AS admin_console_seats,
COALESCE(json_extract(document_json,'$.default_model_allowlist'),'[]') AS default_model_allowlist_json,
CASE WHEN json_type(document_json,'$.default_rpm_limit') IN ('integer','real') THEN json_extract(document_json,'$.default_rpm_limit') ELSE NULL END AS default_rpm_limit,
CASE WHEN json_type(document_json,'$.default_tpm_limit') IN ('integer','real') THEN json_extract(document_json,'$.default_tpm_limit') ELSE NULL END AS default_tpm_limit,
CASE WHEN json_type(document_json,'$.default_monthly_budget_usd') IN ('integer','real') THEN json_extract(document_json,'$.default_monthly_budget_usd') ELSE NULL END AS default_monthly_budget_usd,
CASE WHEN json_type(document_json,'$.created_at') IN ('integer','real') THEN json_extract(document_json,'$.created_at') ELSE created_at_unix END AS created_at_unix,
CASE WHEN json_type(document_json,'$.updated_at') IN ('integer','real') THEN json_extract(document_json,'$.updated_at') ELSE updated_at_unix END AS updated_at_unix,
CASE WHEN json_type(document_json,'$.asset_hosting_enabled')='true' THEN 1 WHEN json_type(document_json,'$.asset_hosting_enabled')='false' THEN 0 ELSE 0 END AS asset_hosting_enabled,
CASE WHEN json_type(document_json,'$.default_asset_storage_quota_bytes') IN ('integer','real') THEN json_extract(document_json,'$.default_asset_storage_quota_bytes') ELSE NULL END AS default_asset_storage_quota_bytes,
CASE WHEN json_type(document_json,'$.extension_tools_enabled')='true' THEN 1 WHEN json_type(document_json,'$.extension_tools_enabled')='false' THEN 0 ELSE 0 END AS extension_tools_enabled,
CASE WHEN json_type(document_json,'$.default_monthly_egress_bytes_budget') IN ('integer','real') THEN json_extract(document_json,'$.default_monthly_egress_bytes_budget') ELSE NULL END AS default_monthly_egress_bytes_budget,
CASE WHEN json_type(document_json,'$.default_download_rpm_limit') IN ('integer','real') THEN json_extract(document_json,'$.default_download_rpm_limit') ELSE NULL END AS default_download_rpm_limit,
CASE WHEN json_type(document_json,'$.default_asset_max_object_bytes') IN ('integer','real') THEN json_extract(document_json,'$.default_asset_max_object_bytes') ELSE NULL END AS default_asset_max_object_bytes,
CASE WHEN json_type(document_json,'$.default_agent_cost_budget_usd') IN ('integer','real') THEN json_extract(document_json,'$.default_agent_cost_budget_usd') ELSE NULL END AS default_agent_cost_budget_usd
FROM control_plane_resources WHERE resource_kind='plans';
CREATE TRIGGER plans_document_insert INSTEAD OF INSERT ON plans
BEGIN
 INSERT INTO control_plane_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
 VALUES('plans',NEW.id,json_object('id', NEW.id, 'name', NEW.name, 'slug', NEW.slug, 'mcp_enabled', json(CASE WHEN COALESCE(NEW.mcp_enabled,0)=1 THEN 'true' ELSE 'false' END), 'self_hosted_workers_enabled', json(CASE WHEN COALESCE(NEW.self_hosted_workers_enabled,0)=1 THEN 'true' ELSE 'false' END), 'admin_console_seats', NEW.admin_console_seats, 'default_model_allowlist', json(CASE WHEN json_valid(NEW.default_model_allowlist_json) THEN NEW.default_model_allowlist_json ELSE '[]' END), 'default_rpm_limit', NEW.default_rpm_limit, 'default_tpm_limit', NEW.default_tpm_limit, 'default_monthly_budget_usd', NEW.default_monthly_budget_usd, 'created_at', NEW.created_at_unix, 'updated_at', NEW.updated_at_unix, 'asset_hosting_enabled', json(CASE WHEN COALESCE(NEW.asset_hosting_enabled,0)=1 THEN 'true' ELSE 'false' END), 'default_asset_storage_quota_bytes', NEW.default_asset_storage_quota_bytes, 'extension_tools_enabled', json(CASE WHEN COALESCE(NEW.extension_tools_enabled,0)=1 THEN 'true' ELSE 'false' END), 'default_monthly_egress_bytes_budget', NEW.default_monthly_egress_bytes_budget, 'default_download_rpm_limit', NEW.default_download_rpm_limit, 'default_asset_max_object_bytes', NEW.default_asset_max_object_bytes, 'default_agent_cost_budget_usd', NEW.default_agent_cost_budget_usd),1,COALESCE(NEW.created_at_unix,unixepoch()),COALESCE(NEW.updated_at_unix,unixepoch()));
END;
CREATE TRIGGER plans_document_update INSTEAD OF UPDATE ON plans
BEGIN
 UPDATE control_plane_resources SET document_json=json_patch(document_json,json_object('id', NEW.id, 'name', NEW.name, 'slug', NEW.slug, 'mcp_enabled', json(CASE WHEN COALESCE(NEW.mcp_enabled,0)=1 THEN 'true' ELSE 'false' END), 'self_hosted_workers_enabled', json(CASE WHEN COALESCE(NEW.self_hosted_workers_enabled,0)=1 THEN 'true' ELSE 'false' END), 'admin_console_seats', NEW.admin_console_seats, 'default_model_allowlist', json(CASE WHEN json_valid(NEW.default_model_allowlist_json) THEN NEW.default_model_allowlist_json ELSE '[]' END), 'default_rpm_limit', NEW.default_rpm_limit, 'default_tpm_limit', NEW.default_tpm_limit, 'default_monthly_budget_usd', NEW.default_monthly_budget_usd, 'created_at', NEW.created_at_unix, 'updated_at', NEW.updated_at_unix, 'asset_hosting_enabled', json(CASE WHEN COALESCE(NEW.asset_hosting_enabled,0)=1 THEN 'true' ELSE 'false' END), 'default_asset_storage_quota_bytes', NEW.default_asset_storage_quota_bytes, 'extension_tools_enabled', json(CASE WHEN COALESCE(NEW.extension_tools_enabled,0)=1 THEN 'true' ELSE 'false' END), 'default_monthly_egress_bytes_budget', NEW.default_monthly_egress_bytes_budget, 'default_download_rpm_limit', NEW.default_download_rpm_limit, 'default_asset_max_object_bytes', NEW.default_asset_max_object_bytes, 'default_agent_cost_budget_usd', NEW.default_agent_cost_budget_usd)),revision=revision+1,updated_at_unix=COALESCE(NEW.updated_at_unix,unixepoch()) WHERE resource_kind='plans' AND resource_id=OLD.id;
END;
CREATE TRIGGER plans_document_delete INSTEAD OF DELETE ON plans
BEGIN
 DELETE FROM control_plane_resources WHERE resource_kind='plans' AND resource_id=OLD.id;
END;
CREATE UNIQUE INDEX idx_plans_document_slug ON control_plane_resources(COALESCE(json_extract(document_json,'$.slug'),resource_id)) WHERE resource_kind='plans';
