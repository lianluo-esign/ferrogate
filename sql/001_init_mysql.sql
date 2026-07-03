-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-06-11
-- description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

CREATE TABLE IF NOT EXISTS control_plane_resources (
    resource_kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    document_json JSON NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (resource_kind, resource_id),
    INDEX idx_control_plane_resources_kind (resource_kind, resource_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Multi-tenant hierarchy: Tenant -> Project -> Workspace.
-- Virtual API keys bind to a workspace and resolve upward to project_id and
-- tenant_id for routing, quota, metering, and audit.
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    created_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (id),
    UNIQUE KEY uq_tenants_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    created_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (id),
    UNIQUE KEY uq_projects_tenant_slug (tenant_id, slug),
    KEY idx_projects_tenant (tenant_id),
    CONSTRAINT fk_projects_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS workspaces (
    id VARCHAR(255) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    environment VARCHAR(64) NOT NULL DEFAULT 'default',
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    created_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    PRIMARY KEY (id),
    UNIQUE KEY uq_workspaces_project_slug (project_id, slug),
    KEY idx_workspaces_project (project_id),
    KEY idx_workspaces_tenant (tenant_id),
    CONSTRAINT fk_workspaces_project FOREIGN KEY (project_id)
        REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT fk_workspaces_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(255) NOT NULL,
    workspace_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(64) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    last4 VARCHAR(16) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    scopes_json JSON NOT NULL,
    created_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    rotated_at_unix BIGINT NULL,
    expires_at_unix BIGINT NULL,
    revoked_at_unix BIGINT NULL,
    PRIMARY KEY (id),
    KEY idx_api_keys_workspace (workspace_id),
    KEY idx_api_keys_tenant_project (tenant_id, project_id),
    KEY idx_api_keys_prefix (key_prefix),
    CONSTRAINT fk_api_keys_workspace FOREIGN KEY (workspace_id)
        REFERENCES workspaces(id) ON DELETE CASCADE,
    CONSTRAINT fk_api_keys_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_api_keys_project FOREIGN KEY (project_id)
        REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version BIGINT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at_unix BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP())
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_mysql')
ON DUPLICATE KEY UPDATE name = name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (9, '009_multi_tenant_hierarchy')
ON DUPLICATE KEY UPDATE name = name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (10, '010_virtual_api_keys')
ON DUPLICATE KEY UPDATE name = name;
