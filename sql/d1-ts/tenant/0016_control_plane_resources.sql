-- ===========================================================================
-- Generic control-plane documents that are private to this tenant (#861)
--
-- `control_plane_resources` remains the platform database's named document
-- table. Tenant-discriminated kinds move here so the database boundary, rather
-- than a JSON predicate, is the isolation boundary.
--
-- `tenant_id` is deliberately retained inside `document_json`. It is a
-- mis-routing tripwire: the object-local store stamps the object identity and
-- refuses a document that names another tenant. It is not a filter in this
-- table; object-local reads never append `tenantScopeSql`.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS tenant_resources (
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_resources_kind
    ON tenant_resources(resource_kind, resource_id);
