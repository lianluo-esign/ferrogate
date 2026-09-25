-- Single authority: the admin document; typed SQL readers use an indexed view.
-- Merge the former runtime authority into existing documents before dropping it.
INSERT INTO tenant_resources (resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
SELECT 'virtual-keys',id,json_object('id', id, 'workspace_id', workspace_id, 'tenant_id', tenant_id, 'project_id', project_id, 'name', name, 'key_prefix', key_prefix, 'key_hash', key_hash, 'last4', last4, 'enabled', json(CASE WHEN COALESCE(enabled,1)=1 THEN 'true' ELSE 'false' END), 'scopes', json(CASE WHEN json_valid(scopes_json) THEN scopes_json ELSE '[]' END), 'allowed_models', json(CASE WHEN json_valid(allowed_models_json) THEN allowed_models_json ELSE '[]' END), 'allowed_providers', json(CASE WHEN json_valid(allowed_providers_json) THEN allowed_providers_json ELSE '[]' END), 'monthly_token_budget', monthly_token_budget, 'request_limit_per_minute', request_limit_per_minute, 'created_at', created_at_unix, 'updated_at', updated_at_unix, 'rotated_at', rotated_at_unix, 'expires_at', expires_at_unix, 'revoked_at', revoked_at_unix, 'attribution_tags', json(CASE WHEN json_valid(attribution_tags_json) THEN attribution_tags_json ELSE '{}' END), 'billing_group_id', billing_group_id, 'revoked', json(CASE WHEN revoked_at_unix IS NULL THEN 'false' ELSE 'true' END)),1,created_at_unix,updated_at_unix FROM api_keys WHERE true
ON CONFLICT (resource_kind,resource_id) DO UPDATE SET
 document_json=json_patch(tenant_resources.document_json,excluded.document_json);
DROP TABLE api_keys;
CREATE VIEW api_keys AS SELECT
resource_id AS id,
COALESCE(json_extract(document_json,'$.workspace_id'),'') AS workspace_id,
COALESCE(json_extract(document_json,'$.tenant_id'),'') AS tenant_id,
COALESCE(json_extract(document_json,'$.project_id'),'') AS project_id,
COALESCE(json_extract(document_json,'$.name'),resource_id) AS name,
COALESCE(json_extract(document_json,'$.key_prefix'),'') AS key_prefix,
COALESCE(json_extract(document_json,'$.key_hash'),'') AS key_hash,
COALESCE(json_extract(document_json,'$.last4'),'') AS last4,
CASE WHEN json_type(document_json,'$.enabled')='true' THEN 1 WHEN json_type(document_json,'$.enabled')='false' THEN 0 ELSE 1 END AS enabled,
COALESCE(json_extract(document_json,'$.scopes'),'[]') AS scopes_json,
COALESCE(json_extract(document_json,'$.allowed_models'),'[]') AS allowed_models_json,
COALESCE(json_extract(document_json,'$.allowed_providers'),'[]') AS allowed_providers_json,
CASE WHEN json_type(document_json,'$.monthly_token_budget') IN ('integer','real') THEN json_extract(document_json,'$.monthly_token_budget') ELSE NULL END AS monthly_token_budget,
CASE WHEN json_type(document_json,'$.request_limit_per_minute') IN ('integer','real') THEN json_extract(document_json,'$.request_limit_per_minute') ELSE NULL END AS request_limit_per_minute,
CASE WHEN json_type(document_json,'$.created_at') IN ('integer','real') THEN json_extract(document_json,'$.created_at') ELSE created_at_unix END AS created_at_unix,
CASE WHEN json_type(document_json,'$.updated_at') IN ('integer','real') THEN json_extract(document_json,'$.updated_at') ELSE updated_at_unix END AS updated_at_unix,
CASE WHEN json_type(document_json,'$.rotated_at') IN ('integer','real') THEN json_extract(document_json,'$.rotated_at') ELSE NULL END AS rotated_at_unix,
CASE WHEN json_type(document_json,'$.expires_at') IN ('integer','real') THEN json_extract(document_json,'$.expires_at') ELSE json_extract(document_json,'$.expires_at_unix') END AS expires_at_unix,
CASE WHEN json_type(document_json,'$.revoked')='true' THEN COALESCE(json_extract(document_json,'$.revoked_at'),updated_at_unix) ELSE NULL END AS revoked_at_unix,
COALESCE(json_extract(document_json,'$.attribution_tags'),'{}') AS attribution_tags_json,
COALESCE(json_extract(document_json,'$.billing_group_id'),NULL) AS billing_group_id
FROM tenant_resources WHERE resource_kind='virtual-keys';
CREATE TRIGGER api_keys_document_insert INSTEAD OF INSERT ON api_keys
BEGIN
 INSERT INTO tenant_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
 VALUES('virtual-keys',NEW.id,json_object('id', NEW.id, 'workspace_id', NEW.workspace_id, 'tenant_id', NEW.tenant_id, 'project_id', NEW.project_id, 'name', NEW.name, 'key_prefix', NEW.key_prefix, 'key_hash', NEW.key_hash, 'last4', NEW.last4, 'enabled', json(CASE WHEN COALESCE(NEW.enabled,1)=1 THEN 'true' ELSE 'false' END), 'scopes', json(CASE WHEN json_valid(NEW.scopes_json) THEN NEW.scopes_json ELSE '[]' END), 'allowed_models', json(CASE WHEN json_valid(NEW.allowed_models_json) THEN NEW.allowed_models_json ELSE '[]' END), 'allowed_providers', json(CASE WHEN json_valid(NEW.allowed_providers_json) THEN NEW.allowed_providers_json ELSE '[]' END), 'monthly_token_budget', NEW.monthly_token_budget, 'request_limit_per_minute', NEW.request_limit_per_minute, 'created_at', NEW.created_at_unix, 'updated_at', NEW.updated_at_unix, 'rotated_at', NEW.rotated_at_unix, 'expires_at', NEW.expires_at_unix, 'revoked_at', NEW.revoked_at_unix, 'attribution_tags', json(CASE WHEN json_valid(NEW.attribution_tags_json) THEN NEW.attribution_tags_json ELSE '{}' END), 'billing_group_id', NEW.billing_group_id, 'revoked', json(CASE WHEN NEW.revoked_at_unix IS NULL THEN 'false' ELSE 'true' END)),1,COALESCE(NEW.created_at_unix,unixepoch()),COALESCE(NEW.updated_at_unix,unixepoch()));
END;
CREATE TRIGGER api_keys_document_update INSTEAD OF UPDATE ON api_keys
BEGIN
 UPDATE tenant_resources SET document_json=json_patch(document_json,json_object('id', NEW.id, 'workspace_id', NEW.workspace_id, 'tenant_id', NEW.tenant_id, 'project_id', NEW.project_id, 'name', NEW.name, 'key_prefix', NEW.key_prefix, 'key_hash', NEW.key_hash, 'last4', NEW.last4, 'enabled', json(CASE WHEN COALESCE(NEW.enabled,1)=1 THEN 'true' ELSE 'false' END), 'scopes', json(CASE WHEN json_valid(NEW.scopes_json) THEN NEW.scopes_json ELSE '[]' END), 'allowed_models', json(CASE WHEN json_valid(NEW.allowed_models_json) THEN NEW.allowed_models_json ELSE '[]' END), 'allowed_providers', json(CASE WHEN json_valid(NEW.allowed_providers_json) THEN NEW.allowed_providers_json ELSE '[]' END), 'monthly_token_budget', NEW.monthly_token_budget, 'request_limit_per_minute', NEW.request_limit_per_minute, 'created_at', NEW.created_at_unix, 'updated_at', NEW.updated_at_unix, 'rotated_at', NEW.rotated_at_unix, 'expires_at', NEW.expires_at_unix, 'revoked_at', NEW.revoked_at_unix, 'attribution_tags', json(CASE WHEN json_valid(NEW.attribution_tags_json) THEN NEW.attribution_tags_json ELSE '{}' END), 'billing_group_id', NEW.billing_group_id, 'revoked', json(CASE WHEN NEW.revoked_at_unix IS NULL THEN 'false' ELSE 'true' END))),revision=revision+1,updated_at_unix=COALESCE(NEW.updated_at_unix,unixepoch()) WHERE resource_kind='virtual-keys' AND resource_id=OLD.id;
END;
CREATE TRIGGER api_keys_document_delete INSTEAD OF DELETE ON api_keys
BEGIN
 DELETE FROM tenant_resources WHERE resource_kind='virtual-keys' AND resource_id=OLD.id;
END;
CREATE UNIQUE INDEX idx_api_keys_document_hash ON tenant_resources(COALESCE(json_extract(document_json,'$.key_hash'),'')) WHERE resource_kind='virtual-keys';
CREATE INDEX idx_api_keys_document_prefix ON tenant_resources(COALESCE(json_extract(document_json,'$.key_prefix'),'')) WHERE resource_kind='virtual-keys';
CREATE INDEX idx_api_keys_document_workspace ON tenant_resources(COALESCE(json_extract(document_json,'$.workspace_id'),'')) WHERE resource_kind='virtual-keys';
CREATE INDEX idx_api_keys_document_tenant ON tenant_resources(COALESCE(json_extract(document_json,'$.tenant_id'),'')) WHERE resource_kind='virtual-keys';
