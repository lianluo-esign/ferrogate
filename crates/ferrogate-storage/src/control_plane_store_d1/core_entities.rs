// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: API keys, tenant accounts, projects, workspaces (issue #420 core CRUD).

//! D1 backend: API keys, tenant accounts, projects, workspaces (issue #420 core CRUD).
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use super::rows::*;
use super::*;

const API_KEY_RECORD_ID_CLAIM_KIND: &str = "api_key_record_id_claim";
const PROJECT_ID_CLAIM_KIND: &str = "project_id_claim";
const WORKSPACE_ID_CLAIM_KIND: &str = "workspace_id_claim";

impl D1ControlPlaneStore {
    async fn claim_core_entity_id(
        &self,
        kind: &str,
        id: &str,
        tenant_id: &str,
    ) -> Result<bool, StorageError> {
        let database_id = self.control_database_id()?;
        let document_json =
            serialize_storage_document(&serde_json::json!({ "tenant_id": tenant_id }))?;
        self.execute(
            &database_id,
            "INSERT INTO control_plane_resources \
             (resource_kind, resource_id, document_json, revision, created_at_unix, \
              updated_at_unix) \
             VALUES (?, ?, ?, 1, unixepoch(), unixepoch()) \
             ON CONFLICT (resource_kind, resource_id) DO NOTHING",
            vec![kind.to_string(), id.to_string(), document_json],
        )
        .await
        .map(|result| result.changes() > 0)
    }

    async fn release_core_entity_id_claim(&self, kind: &str, id: &str) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(
            &database_id,
            "DELETE FROM control_plane_resources \
             WHERE resource_kind = ? AND resource_id = ?",
            vec![kind.to_string(), id.to_string()],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn upsert_api_key_record_async(
        &self,
        api_key: StoredApiKey,
    ) -> Result<(), StorageError> {
        let database_id = self.database_for_tenant(&api_key.tenant_id)?;
        let params = vec![
            api_key.id.clone(),
            api_key.workspace_id.clone(),
            api_key.tenant_id.clone(),
            api_key.project_id.clone(),
            api_key.name.clone(),
            api_key.key_prefix.clone(),
            api_key.key_hash.clone(),
            api_key.last4.clone(),
            if api_key.enabled { "1" } else { "0" }.to_string(),
            serialize_storage_document(&api_key.scopes)?,
            serialize_storage_document(&api_key.allowed_models)?,
            serialize_storage_document(&api_key.allowed_providers)?,
            optional_number_param(api_key.monthly_token_budget),
            optional_number_param(api_key.request_limit_per_minute),
            api_key.created_at_unix.to_string(),
            api_key.updated_at_unix.to_string(),
            optional_number_param(api_key.rotated_at_unix),
            optional_number_param(api_key.expires_at_unix),
            optional_number_param(api_key.revoked_at_unix),
        ];
        self.execute(
            &database_id,
            "INSERT INTO api_keys \
             (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, \
              enabled, scopes_json, allowed_models_json, allowed_providers_json, \
              monthly_token_budget, request_limit_per_minute, created_at_unix, \
              updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, \
              NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, '')) \
             ON CONFLICT (id) DO UPDATE SET \
             workspace_id = excluded.workspace_id, tenant_id = excluded.tenant_id, \
             project_id = excluded.project_id, name = excluded.name, \
             key_prefix = excluded.key_prefix, key_hash = excluded.key_hash, \
             last4 = excluded.last4, enabled = excluded.enabled, \
             scopes_json = excluded.scopes_json, \
             allowed_models_json = excluded.allowed_models_json, \
             allowed_providers_json = excluded.allowed_providers_json, \
             monthly_token_budget = excluded.monthly_token_budget, \
             request_limit_per_minute = excluded.request_limit_per_minute, \
             updated_at_unix = excluded.updated_at_unix, \
             rotated_at_unix = excluded.rotated_at_unix, \
             expires_at_unix = excluded.expires_at_unix, \
             revoked_at_unix = excluded.revoked_at_unix",
            params,
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn create_api_key_record_if_absent_async(
        &self,
        api_key: StoredApiKey,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        let id = api_key.id.clone();
        let tenant_id = api_key.tenant_id.clone();
        let database_id = self.database_for_tenant(&tenant_id)?;
        let params = vec![
            api_key.id.clone(),
            api_key.workspace_id.clone(),
            api_key.tenant_id.clone(),
            api_key.project_id.clone(),
            api_key.name.clone(),
            api_key.key_prefix.clone(),
            api_key.key_hash.clone(),
            api_key.last4.clone(),
            if api_key.enabled { "1" } else { "0" }.to_string(),
            serialize_storage_document(&api_key.scopes)?,
            serialize_storage_document(&api_key.allowed_models)?,
            serialize_storage_document(&api_key.allowed_providers)?,
            optional_number_param(api_key.monthly_token_budget),
            optional_number_param(api_key.request_limit_per_minute),
            api_key.created_at_unix.to_string(),
            api_key.updated_at_unix.to_string(),
            optional_number_param(api_key.rotated_at_unix),
            optional_number_param(api_key.expires_at_unix),
            optional_number_param(api_key.revoked_at_unix),
        ];
        if self.get_api_key_record_async(&id).await?.is_some() {
            return Ok(CreateIfAbsentOutcome::AlreadyExists);
        }
        if !self
            .claim_core_entity_id(API_KEY_RECORD_ID_CLAIM_KIND, &id, &tenant_id)
            .await?
        {
            return Ok(CreateIfAbsentOutcome::AlreadyExists);
        }
        let inserted = match self
            .execute(
                &database_id,
                "INSERT INTO api_keys \
                 (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, \
                  enabled, scopes_json, allowed_models_json, allowed_providers_json, \
                  monthly_token_budget, request_limit_per_minute, created_at_unix, \
                  updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, \
                  NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, '')) \
                 ON CONFLICT (id) DO NOTHING",
                params,
            )
            .await
        {
            Ok(result) => result.changes(),
            Err(error) => {
                let _ = self
                    .release_core_entity_id_claim(API_KEY_RECORD_ID_CLAIM_KIND, &id)
                    .await;
                return Err(error);
            }
        };
        Ok(if inserted > 0 {
            CreateIfAbsentOutcome::Created
        } else {
            CreateIfAbsentOutcome::AlreadyExists
        })
    }

    pub(super) async fn get_api_key_record_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredApiKey>, StorageError> {
        let sql = format!("{SELECT_API_KEY_COLUMNS} WHERE id = ?");
        for database_id in self.fan_out_database_ids()? {
            let row: Option<ApiKeyRow> = self
                .fetch_optional_row(&database_id, &sql, vec![id.to_string()])
                .await?;
            if let Some(row) = row {
                return Ok(Some(row.into_stored()?));
            }
        }
        Ok(None)
    }

    pub(super) async fn list_api_key_records_async(
        &self,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        let sql = format!("{SELECT_API_KEY_COLUMNS} ORDER BY id ASC");
        let mut api_keys = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<ApiKeyRow> = self.fetch_rows(&database_id, &sql, Vec::new()).await?;
            for row in rows {
                api_keys.push(row.into_stored()?);
            }
        }
        Ok(api_keys)
    }

    pub(super) async fn find_api_key_records_by_prefix_async(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<StoredApiKey>, StorageError> {
        let sql = format!("{SELECT_API_KEY_COLUMNS} WHERE key_prefix = ? ORDER BY id ASC");
        let mut api_keys = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<ApiKeyRow> = self
                .fetch_rows(&database_id, &sql, vec![key_prefix.to_string()])
                .await?;
            for row in rows {
                api_keys.push(row.into_stored()?);
            }
        }
        Ok(api_keys)
    }

    pub(super) async fn upsert_tenant_account_async(
        &self,
        account: StoredTenantAccount,
    ) -> Result<(), StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(
            &database_id,
            "INSERT INTO tenants \
             (id, name, slug, status, plan_id, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             name = excluded.name, slug = excluded.slug, status = excluded.status, \
             plan_id = excluded.plan_id, updated_at_unix = excluded.updated_at_unix",
            vec![
                account.id,
                account.name,
                account.slug,
                account.status,
                account.plan_id,
                account.created_at_unix.to_string(),
                account.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn get_tenant_account_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredTenantAccount>, StorageError> {
        let database_id = self.control_database_id()?;
        let row: Option<TenantAccountRow> = self
            .fetch_optional_row(
                &database_id,
                &format!("{SELECT_TENANT_COLUMNS} WHERE id = ?"),
                vec![id.to_string()],
            )
            .await?;
        Ok(row.map(StoredTenantAccount::from))
    }

    pub(super) async fn list_tenant_accounts_async(
        &self,
    ) -> Result<Vec<StoredTenantAccount>, StorageError> {
        let database_id = self.control_database_id()?;
        let rows: Vec<TenantAccountRow> = self
            .fetch_rows(
                &database_id,
                &format!("{SELECT_TENANT_COLUMNS} ORDER BY id ASC"),
                Vec::new(),
            )
            .await?;
        Ok(rows.into_iter().map(StoredTenantAccount::from).collect())
    }

    pub(super) async fn upsert_project_async(
        &self,
        project: StoredProject,
    ) -> Result<(), StorageError> {
        let database_id = self.database_for_tenant(&project.tenant_id)?;
        self.execute(
            &database_id,
            "INSERT INTO projects \
             (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             tenant_id = excluded.tenant_id, name = excluded.name, slug = excluded.slug, \
             status = excluded.status, updated_at_unix = excluded.updated_at_unix",
            vec![
                project.id,
                project.tenant_id,
                project.name,
                project.slug,
                project.status,
                project.created_at_unix.to_string(),
                project.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn create_project_if_absent_async(
        &self,
        project: StoredProject,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        let id = project.id.clone();
        let tenant_id = project.tenant_id.clone();
        let database_id = self.database_for_tenant(&tenant_id)?;
        if self.get_project_async(&id).await?.is_some() {
            return Ok(CreateIfAbsentOutcome::AlreadyExists);
        }
        if !self
            .claim_core_entity_id(PROJECT_ID_CLAIM_KIND, &id, &tenant_id)
            .await?
        {
            return Ok(CreateIfAbsentOutcome::AlreadyExists);
        }
        let inserted = match self
            .execute(
                &database_id,
                "INSERT INTO projects \
                 (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    project.id.clone(),
                    project.tenant_id.clone(),
                    project.name,
                    project.slug,
                    project.status,
                    project.created_at_unix.to_string(),
                    project.updated_at_unix.to_string(),
                ],
            )
            .await
        {
            Ok(result) => result.changes(),
            Err(error) => {
                let _ = self
                    .release_core_entity_id_claim(PROJECT_ID_CLAIM_KIND, &id)
                    .await;
                return Err(error);
            }
        };
        Ok(if inserted > 0 {
            CreateIfAbsentOutcome::Created
        } else {
            CreateIfAbsentOutcome::AlreadyExists
        })
    }

    pub(super) async fn get_project_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredProject>, StorageError> {
        let sql = format!("{SELECT_PROJECT_COLUMNS} WHERE id = ?");
        for database_id in self.fan_out_database_ids()? {
            let row: Option<ProjectRow> = self
                .fetch_optional_row(&database_id, &sql, vec![id.to_string()])
                .await?;
            if let Some(row) = row {
                return Ok(Some(row.into()));
            }
        }
        Ok(None)
    }

    pub(super) async fn list_projects_async(&self) -> Result<Vec<StoredProject>, StorageError> {
        let sql = format!("{SELECT_PROJECT_COLUMNS} ORDER BY id ASC");
        let mut projects = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<ProjectRow> = self.fetch_rows(&database_id, &sql, Vec::new()).await?;
            projects.extend(rows.into_iter().map(StoredProject::from));
        }
        Ok(projects)
    }

    pub(super) async fn delete_project_async(&self, id: &str) -> Result<bool, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let result = self
                .execute(
                    &database_id,
                    "DELETE FROM projects WHERE id = ?",
                    vec![id.to_string()],
                )
                .await?;
            if result.changes() > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) async fn delete_project_if_unreferenced_async(
        &self,
        id: &str,
    ) -> Result<DeleteProjectOutcome, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            // The guarded DELETE is a single statement, so the
            // reject-if-referenced check is atomic within this database.
            let deleted = self
                .execute(
                    &database_id,
                    "DELETE FROM projects WHERE id = ? \
                     AND NOT EXISTS (SELECT 1 FROM workspaces WHERE project_id = ?) \
                     AND NOT EXISTS (SELECT 1 FROM api_keys WHERE project_id = ?)",
                    vec![id.to_string(), id.to_string(), id.to_string()],
                )
                .await?;
            if deleted.changes() > 0 {
                return Ok(DeleteProjectOutcome::Deleted);
            }
            let counts: Option<ProjectReferenceCountRow> = self
                .fetch_optional_row(
                    &database_id,
                    "SELECT (SELECT COUNT(*) FROM projects WHERE id = ?) AS present, \
                     (SELECT COUNT(*) FROM workspaces WHERE project_id = ?) AS workspaces, \
                     (SELECT COUNT(*) FROM api_keys WHERE project_id = ?) AS virtual_keys",
                    vec![id.to_string(), id.to_string(), id.to_string()],
                )
                .await?;
            if let Some(counts) = counts {
                if counts.present > 0 {
                    return Ok(DeleteProjectOutcome::Referenced {
                        workspaces: counts.workspaces.max(0) as usize,
                        virtual_keys: counts.virtual_keys.max(0) as usize,
                    });
                }
            }
        }
        Ok(DeleteProjectOutcome::NotFound)
    }

    pub(super) async fn upsert_workspace_async(
        &self,
        workspace: StoredWorkspace,
    ) -> Result<(), StorageError> {
        let database_id = self.database_for_tenant(&workspace.tenant_id)?;
        self.execute(
            &database_id,
            "INSERT INTO workspaces \
             (id, project_id, tenant_id, name, slug, environment, status, created_at_unix, \
              updated_at_unix) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             project_id = excluded.project_id, tenant_id = excluded.tenant_id, \
             name = excluded.name, slug = excluded.slug, environment = excluded.environment, \
             status = excluded.status, updated_at_unix = excluded.updated_at_unix",
            vec![
                workspace.id,
                workspace.project_id,
                workspace.tenant_id,
                workspace.name,
                workspace.slug,
                workspace.environment,
                workspace.status,
                workspace.created_at_unix.to_string(),
                workspace.updated_at_unix.to_string(),
            ],
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn create_workspace_if_absent_async(
        &self,
        workspace: StoredWorkspace,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        let id = workspace.id.clone();
        let tenant_id = workspace.tenant_id.clone();
        let database_id = self.database_for_tenant(&tenant_id)?;
        if self.get_workspace_async(&id).await?.is_some() {
            return Ok(CreateIfAbsentOutcome::AlreadyExists);
        }
        if !self
            .claim_core_entity_id(WORKSPACE_ID_CLAIM_KIND, &id, &tenant_id)
            .await?
        {
            return Ok(CreateIfAbsentOutcome::AlreadyExists);
        }
        let inserted = match self
            .execute(
                &database_id,
                "INSERT INTO workspaces \
                 (id, project_id, tenant_id, name, slug, environment, status, created_at_unix, \
                  updated_at_unix) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (id) DO NOTHING",
                vec![
                    workspace.id.clone(),
                    workspace.project_id,
                    workspace.tenant_id.clone(),
                    workspace.name,
                    workspace.slug,
                    workspace.environment,
                    workspace.status,
                    workspace.created_at_unix.to_string(),
                    workspace.updated_at_unix.to_string(),
                ],
            )
            .await
        {
            Ok(result) => result.changes(),
            Err(error) => {
                let _ = self
                    .release_core_entity_id_claim(WORKSPACE_ID_CLAIM_KIND, &id)
                    .await;
                return Err(error);
            }
        };
        Ok(if inserted > 0 {
            CreateIfAbsentOutcome::Created
        } else {
            CreateIfAbsentOutcome::AlreadyExists
        })
    }

    pub(super) async fn get_workspace_async(
        &self,
        id: &str,
    ) -> Result<Option<StoredWorkspace>, StorageError> {
        let sql = format!("{SELECT_WORKSPACE_COLUMNS} WHERE id = ?");
        for database_id in self.fan_out_database_ids()? {
            let row: Option<WorkspaceRow> = self
                .fetch_optional_row(&database_id, &sql, vec![id.to_string()])
                .await?;
            if let Some(row) = row {
                return Ok(Some(row.into()));
            }
        }
        Ok(None)
    }

    pub(super) async fn list_workspaces_async(&self) -> Result<Vec<StoredWorkspace>, StorageError> {
        let sql = format!("{SELECT_WORKSPACE_COLUMNS} ORDER BY id ASC");
        let mut workspaces = Vec::new();
        for database_id in self.fan_out_database_ids()? {
            let rows: Vec<WorkspaceRow> = self.fetch_rows(&database_id, &sql, Vec::new()).await?;
            workspaces.extend(rows.into_iter().map(StoredWorkspace::from));
        }
        Ok(workspaces)
    }

    pub(super) async fn delete_workspace_async(&self, id: &str) -> Result<bool, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let result = self
                .execute(
                    &database_id,
                    "DELETE FROM workspaces WHERE id = ?",
                    vec![id.to_string()],
                )
                .await?;
            if result.changes() > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) async fn delete_workspace_if_unreferenced_async(
        &self,
        id: &str,
    ) -> Result<DeleteWorkspaceOutcome, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let deleted = self
                .execute(
                    &database_id,
                    "DELETE FROM workspaces WHERE id = ? \
                     AND NOT EXISTS (SELECT 1 FROM api_keys WHERE workspace_id = ?)",
                    vec![id.to_string(), id.to_string()],
                )
                .await?;
            if deleted.changes() > 0 {
                return Ok(DeleteWorkspaceOutcome::Deleted);
            }
            let counts: Option<WorkspaceReferenceCountRow> = self
                .fetch_optional_row(
                    &database_id,
                    "SELECT (SELECT COUNT(*) FROM workspaces WHERE id = ?) AS present, \
                     (SELECT COUNT(*) FROM api_keys WHERE workspace_id = ?) AS virtual_keys",
                    vec![id.to_string(), id.to_string()],
                )
                .await?;
            if let Some(counts) = counts {
                if counts.present > 0 {
                    return Ok(DeleteWorkspaceOutcome::Referenced {
                        virtual_keys: counts.virtual_keys.max(0) as usize,
                    });
                }
            }
        }
        Ok(DeleteWorkspaceOutcome::NotFound)
    }

    pub(super) async fn resolve_workspace_scope_async(
        &self,
        workspace_id: &str,
    ) -> Result<Option<WorkspaceScope>, StorageError> {
        for database_id in self.fan_out_database_ids()? {
            let row: Option<WorkspaceScopeRow> = self
                .fetch_optional_row(
                    &database_id,
                    "SELECT tenant_id, project_id, id FROM workspaces WHERE id = ?",
                    vec![workspace_id.to_string()],
                )
                .await?;
            if let Some(row) = row {
                return Ok(Some(WorkspaceScope::new(
                    row.tenant_id,
                    row.project_id,
                    row.id,
                )));
            }
        }
        Ok(None)
    }
}
