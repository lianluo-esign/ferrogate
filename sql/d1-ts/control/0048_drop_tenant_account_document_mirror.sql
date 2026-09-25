-- Full tenant account documents live only in their TenantDataObject.
-- Deploy the control-plane writer/reader removal before the gateway DO migration.
-- Keep the narrow tenant registry used for routing, lifecycle and plan joins.
ALTER TABLE tenants DROP COLUMN document_json;
