-- MCP configuration is stored once in tenant_resources. SQL compatibility
-- readers address a view, while runtime validates the original document.
INSERT INTO tenant_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
SELECT 'mcp-servers',COALESCE((SELECT resource_id FROM tenant_resources r WHERE r.resource_kind='mcp-servers' AND COALESCE(json_extract(r.document_json,'$.name'),r.resource_id)=mcp_servers.name LIMIT 1),name),json_object('id',name,'tenant_id',tenant_id,'name',name,'transport',transport,'url',url,'auth_type',auth_type,'tools_to_execute',CASE WHEN json_valid(tools_to_execute) THEN json(tools_to_execute) ELSE tools_to_execute END,'tools_to_auto_execute',CASE WHEN json_valid(tools_to_auto_execute) THEN json(tools_to_auto_execute) ELSE tools_to_auto_execute END,'tools_to_exclude',CASE WHEN json_valid(tools_to_exclude) THEN json(tools_to_exclude) ELSE tools_to_exclude END,'headers',CASE WHEN json_valid(headers) THEN json(headers) ELSE headers END,'oauth',CASE WHEN json_valid(oauth) THEN json(oauth) ELSE oauth END,'signed_jwt_audience',signed_jwt_audience,'timeout_ms',timeout_ms),1,unixepoch(),unixepoch() FROM mcp_servers WHERE true
ON CONFLICT(resource_kind,resource_id) DO UPDATE SET document_json=json_set(json_patch(tenant_resources.document_json,excluded.document_json),'$.id',tenant_resources.resource_id);
DROP TABLE mcp_servers;
CREATE VIEW mcp_servers AS SELECT
json_extract(document_json,'$.tenant_id') AS tenant_id,
trim(COALESCE(json_extract(document_json,'$.name'),resource_id)) AS name,
CASE json_extract(document_json,'$.transport') WHEN 'http' THEN 'streamable_http' ELSE json_extract(document_json,'$.transport') END AS transport,
json_extract(document_json,'$.url') AS url,
CASE COALESCE(json_extract(document_json,'$.auth_type'),json_extract(document_json,'$.authType')) WHEN 'headers' THEN 'shared_headers' ELSE COALESCE(COALESCE(json_extract(document_json,'$.auth_type'),json_extract(document_json,'$.authType')),'none') END AS auth_type,
COALESCE(COALESCE(json_extract(document_json,'$.tools_to_execute'),json_extract(document_json,'$.toolsToExecute')),'[]') AS tools_to_execute,
COALESCE(COALESCE(json_extract(document_json,'$.tools_to_auto_execute'),json_extract(document_json,'$.toolsToAutoExecute')),'[]') AS tools_to_auto_execute,
COALESCE(json_extract(document_json,'$.tools_to_exclude'),json_extract(document_json,'$.toolsToExclude')) AS tools_to_exclude,
json_extract(document_json,'$.headers') AS headers,
json_extract(document_json,'$.oauth') AS oauth,
COALESCE(json_extract(document_json,'$.signed_jwt_audience'),json_extract(document_json,'$.signedJwtAudience')) AS signed_jwt_audience,
COALESCE(COALESCE(json_extract(document_json,'$.timeout_ms'),json_extract(document_json,'$.timeoutMs')),30000) AS timeout_ms
FROM tenant_resources WHERE resource_kind='mcp-servers' AND COALESCE(json_type(document_json,'$.enabled'),'true') <> 'false';
CREATE TRIGGER mcp_servers_document_insert INSTEAD OF INSERT ON mcp_servers
BEGIN
 INSERT INTO tenant_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
 VALUES('mcp-servers',NEW.name,json_object('id',NEW.name,'tenant_id',NEW.tenant_id,'name',NEW.name,'transport',NEW.transport,'url',NEW.url,'auth_type',NEW.auth_type,'tools_to_execute',CASE WHEN json_valid(NEW.tools_to_execute) THEN json(NEW.tools_to_execute) ELSE NEW.tools_to_execute END,'tools_to_auto_execute',CASE WHEN json_valid(NEW.tools_to_auto_execute) THEN json(NEW.tools_to_auto_execute) ELSE NEW.tools_to_auto_execute END,'tools_to_exclude',CASE WHEN json_valid(NEW.tools_to_exclude) THEN json(NEW.tools_to_exclude) ELSE NEW.tools_to_exclude END,'headers',CASE WHEN json_valid(NEW.headers) THEN json(NEW.headers) ELSE NEW.headers END,'oauth',CASE WHEN json_valid(NEW.oauth) THEN json(NEW.oauth) ELSE NEW.oauth END,'signed_jwt_audience',NEW.signed_jwt_audience,'timeout_ms',NEW.timeout_ms),1,unixepoch(),unixepoch());
END;
CREATE TRIGGER mcp_servers_document_update INSTEAD OF UPDATE ON mcp_servers
BEGIN
 UPDATE tenant_resources SET document_json=json_patch(document_json,json_object('id',NEW.name,'tenant_id',NEW.tenant_id,'name',NEW.name,'transport',NEW.transport,'url',NEW.url,'auth_type',NEW.auth_type,'tools_to_execute',CASE WHEN json_valid(NEW.tools_to_execute) THEN json(NEW.tools_to_execute) ELSE NEW.tools_to_execute END,'tools_to_auto_execute',CASE WHEN json_valid(NEW.tools_to_auto_execute) THEN json(NEW.tools_to_auto_execute) ELSE NEW.tools_to_auto_execute END,'tools_to_exclude',CASE WHEN json_valid(NEW.tools_to_exclude) THEN json(NEW.tools_to_exclude) ELSE NEW.tools_to_exclude END,'headers',CASE WHEN json_valid(NEW.headers) THEN json(NEW.headers) ELSE NEW.headers END,'oauth',CASE WHEN json_valid(NEW.oauth) THEN json(NEW.oauth) ELSE NEW.oauth END,'signed_jwt_audience',NEW.signed_jwt_audience,'timeout_ms',NEW.timeout_ms)),revision=revision+1,updated_at_unix=unixepoch()
 WHERE resource_kind='mcp-servers' AND trim(COALESCE(json_extract(document_json,'$.name'),resource_id))=OLD.name;
END;
CREATE TRIGGER mcp_servers_document_delete INSTEAD OF DELETE ON mcp_servers
BEGIN
 DELETE FROM tenant_resources WHERE resource_kind='mcp-servers' AND trim(COALESCE(json_extract(document_json,'$.name'),resource_id))=OLD.name;
END;
CREATE UNIQUE INDEX idx_mcp_document_name ON tenant_resources(trim(COALESCE(json_extract(document_json,'$.name'),resource_id))) WHERE resource_kind='mcp-servers';
