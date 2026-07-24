// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: generic kind-keyed config-document store (control database).

//! D1 backend: generic kind-keyed config-document store (control database).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    pub(super) async fn upsert_config_document_async(
        &self,
        kind: &str,
        id: String,
        document_json: String,
    ) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.put_document(&database_id, kind, &id, &document_json)
            .await
    }

    pub(super) async fn delete_config_document_async(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<bool, StorageError> {
        let database_id = self.control_database_id()?;
        let result = self
            .execute(
                &database_id,
                "DELETE FROM control_plane_resources \
                 WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.to_string(), id.to_string()],
            )
            .await?;
        Ok(result.changes() > 0)
    }

    pub(super) async fn get_config_document_async(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        let database_id = self.control_database_id()?;
        let row: Option<DocumentRow> = self
            .fetch_optional_row(
                &database_id,
                "SELECT document_json FROM control_plane_resources \
                 WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.to_string(), id.to_string()],
            )
            .await?;
        Ok(row.map(|row| row.document_json))
    }

    pub(super) async fn list_config_resource_documents_async(
        &self,
        kind: &str,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let database_id = self.control_database_id()?;
        let rows: Vec<ResourceDocumentRow> = self
            .fetch_rows(
                &database_id,
                "SELECT resource_id, document_json FROM control_plane_resources \
                 WHERE resource_kind = ? ORDER BY resource_id ASC",
                vec![kind.to_string()],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.resource_id, row.document_json))
            .collect())
    }

    pub(super) async fn replace_config_kind_async(
        &self,
        kind: &str,
        documents: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(
            &database_id,
            "DELETE FROM control_plane_resources WHERE resource_kind = ?",
            vec![kind.to_string()],
        )
        .await?;
        for (id, document_json) in documents {
            self.put_document(&database_id, kind, &id, &document_json)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn config_documents_async(
        &self,
    ) -> Result<ControlPlaneDocuments, StorageError> {
        Ok(ControlPlaneDocuments {
            api_keys: self.list_config_resource_documents_async("api_key").await?,
            tenants: self.list_config_resource_documents_async("tenant").await?,
            policies: self.list_config_resource_documents_async("policy").await?,
            gateway_configs: self
                .list_config_resource_documents_async("gateway_config")
                .await?,
            agent_workflows: self
                .list_config_resource_documents_async("agent_workflow")
                .await?,
            skill_packages: self
                .list_config_resource_documents_async("skill_package")
                .await?,
            prompt_templates: self
                .list_config_resource_documents_async("prompt_template")
                .await?,
            plugin_registrations: self
                .list_config_resource_documents_async("plugin_registration")
                .await?,
            mcp_servers: self
                .list_config_resource_documents_async("mcp_server")
                .await?,
            agent_upstreams: self
                .list_config_resource_documents_async("agent_upstream")
                .await?,
        })
    }
}
