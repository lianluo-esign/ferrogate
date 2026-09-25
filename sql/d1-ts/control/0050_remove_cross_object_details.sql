-- Deployment precondition: historical full control records must already have
-- been moved to their tenant authority. Do not guess that a control row is a
-- redundant copy: reject the migration if unique legacy data could be lost.
CREATE TABLE cross_object_cleanup_guard (remaining INTEGER CHECK(remaining=0));
INSERT INTO cross_object_cleanup_guard SELECT COUNT(*) FROM control_plane_resources
WHERE resource_kind='mcp-servers' AND json_extract(document_json,'$.tenant_id') IS NOT NULL
 AND EXISTS(SELECT 1 FROM json_each(document_json) WHERE key NOT IN ('id','tenant_id'));
INSERT INTO cross_object_cleanup_guard SELECT COUNT(*) FROM self_hosted_worker_registrations
WHERE EXISTS(SELECT 1 FROM json_each(registration_json) WHERE key NOT IN ('worker_id','tenant_id','workspace_id'));
INSERT INTO cross_object_cleanup_guard SELECT COUNT(*) FROM site_domain_verifications
WHERE challenge_token <> '';
DROP TABLE cross_object_cleanup_guard;
-- Current runtime writes only directories / serving state. Never allow an old
-- writer to recreate a full MCP configuration or transport credential mirror.
UPDATE control_plane_resources SET document_json=json_object('id',resource_id,'tenant_id',json_extract(document_json,'$.tenant_id'))
WHERE resource_kind='mcp-servers' AND json_extract(document_json,'$.tenant_id') IS NOT NULL;
UPDATE self_hosted_worker_registrations SET registration_json=json_object(
 'worker_id',id,'tenant_id',json_extract(registration_json,'$.tenant_id'),
 'workspace_id',json_extract(registration_json,'$.workspace_id'));
CREATE TRIGGER reject_mcp_document_mirror_insert BEFORE INSERT ON control_plane_resources
WHEN NEW.resource_kind='mcp-servers' AND json_extract(NEW.document_json,'$.tenant_id') IS NOT NULL
 AND EXISTS(SELECT 1 FROM json_each(NEW.document_json) WHERE key NOT IN ('id','tenant_id'))
BEGIN
 SELECT RAISE(ABORT,'MCP configuration belongs only in its tenant object');
END;
CREATE TRIGGER reject_mcp_document_mirror_update BEFORE UPDATE ON control_plane_resources
WHEN NEW.resource_kind='mcp-servers' AND json_extract(NEW.document_json,'$.tenant_id') IS NOT NULL
 AND EXISTS(SELECT 1 FROM json_each(NEW.document_json) WHERE key NOT IN ('id','tenant_id'))
BEGIN
 SELECT RAISE(ABORT,'MCP configuration belongs only in its tenant object');
END;
CREATE TRIGGER reject_worker_identity_mirror_insert BEFORE INSERT ON self_hosted_worker_registrations
WHEN EXISTS(SELECT 1 FROM json_each(NEW.registration_json) WHERE key NOT IN ('worker_id','tenant_id','workspace_id'))
BEGIN
 SELECT RAISE(ABORT,'Worker credentials belong only in their tenant object');
END;
CREATE TRIGGER reject_worker_identity_mirror_update BEFORE UPDATE ON self_hosted_worker_registrations
WHEN EXISTS(SELECT 1 FROM json_each(NEW.registration_json) WHERE key NOT IN ('worker_id','tenant_id','workspace_id'))
BEGIN
 SELECT RAISE(ABORT,'Worker credentials belong only in their tenant object');
END;
ALTER TABLE site_domain_verifications DROP COLUMN site;
ALTER TABLE site_domain_verifications DROP COLUMN challenge_token;
ALTER TABLE site_domain_verifications DROP COLUMN issued_at_unix;
ALTER TABLE site_domain_verifications DROP COLUMN verified_at_unix;
ALTER TABLE site_domain_verifications DROP COLUMN last_checked_at_unix;
ALTER TABLE site_domain_verifications DROP COLUMN last_failure_reason;
ALTER TABLE site_domain_verifications DROP COLUMN attempt_count;
ALTER TABLE site_domain_verifications DROP COLUMN updated_at_unix;
