-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-06-11
-- description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

CREATE TABLE IF NOT EXISTS control_plane_resources (
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_control_plane_resources_kind
    ON control_plane_resources(resource_kind, resource_id);

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

INSERT INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_postgres')
ON CONFLICT (version) DO NOTHING;
