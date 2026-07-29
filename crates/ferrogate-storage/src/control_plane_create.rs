// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Atomic create-if-absent storage contracts for control-plane
// hierarchy rows and durable API-key records (issue #512).

//! Atomic create-if-absent storage contracts for issue #512.
//!
//! Collection `POST` handlers must not implement duplicate protection as a
//! handler-side read followed by an unconditional upsert. The backend owns the
//! single guarded mutation and reports whether it inserted or found a durable
//! winner.

use super::*;

/// Outcome of a repository-level create-if-absent write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateIfAbsentOutcome {
    /// The row did not exist and was inserted.
    Created,
    /// The id was already present; the existing row was left untouched.
    AlreadyExists,
}

fn create_outcome(affected_rows: u64) -> CreateIfAbsentOutcome {
    if affected_rows > 0 {
        CreateIfAbsentOutcome::Created
    } else {
        CreateIfAbsentOutcome::AlreadyExists
    }
}

impl PostgresControlPlaneStore {
    fn create_if_absent_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn create_api_key_record_if_absent(
        &self,
        api_key: &StoredApiKey,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        let scopes_json = serialize_storage_document(&api_key.scopes)?;
        let allowed_models_json = serialize_storage_document(&api_key.allowed_models)?;
        let allowed_providers_json = serialize_storage_document(&api_key.allowed_providers)?;
        let monthly_token_budget = api_key.monthly_token_budget.map(saturating_i64);
        let request_limit_per_minute = api_key.request_limit_per_minute.map(saturating_i64);
        let created_at_unix = saturating_i64(api_key.created_at_unix);
        let updated_at_unix = saturating_i64(api_key.updated_at_unix);
        let rotated_at_unix = api_key.rotated_at_unix.map(saturating_i64);
        let expires_at_unix = api_key.expires_at_unix.map(saturating_i64);
        let revoked_at_unix = api_key.revoked_at_unix.map(saturating_i64);
        let operation = self.create_if_absent_operation("create api key record if absent");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO api_keys \
                 (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4, \
                  enabled, scopes_json, allowed_models_json, allowed_providers_json, \
                  monthly_token_budget, request_limit_per_minute, created_at_unix, \
                  updated_at_unix, rotated_at_unix, expires_at_unix, revoked_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::jsonb, $11::text::jsonb, \
                 $12::text::jsonb, $13, $14, $15, $16, $17, $18, $19) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &api_key.id,
                    &api_key.workspace_id,
                    &api_key.tenant_id,
                    &api_key.project_id,
                    &api_key.name,
                    &api_key.key_prefix,
                    &api_key.key_hash,
                    &api_key.last4,
                    &api_key.enabled,
                    &scopes_json,
                    &allowed_models_json,
                    &allowed_providers_json,
                    &monthly_token_budget,
                    &request_limit_per_minute,
                    &created_at_unix,
                    &updated_at_unix,
                    &rotated_at_unix,
                    &expires_at_unix,
                    &revoked_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(create_outcome(inserted))
    }

    pub(super) async fn create_project_if_absent(
        &self,
        project: &StoredProject,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        let operation = self.create_if_absent_operation("create project if absent");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO projects \
                 (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &project.id,
                    &project.tenant_id,
                    &project.name,
                    &project.slug,
                    &project.status,
                    &project.created_at_unix,
                    &project.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(create_outcome(inserted))
    }

    pub(super) async fn create_workspace_if_absent(
        &self,
        workspace: &StoredWorkspace,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        let operation = self.create_if_absent_operation("create workspace if absent");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO workspaces \
                 (id, project_id, tenant_id, name, slug, environment, status, \
                  created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &workspace.id,
                    &workspace.project_id,
                    &workspace.tenant_id,
                    &workspace.name,
                    &workspace.slug,
                    &workspace.environment,
                    &workspace.status,
                    &workspace.created_at_unix,
                    &workspace.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(create_outcome(inserted))
    }
}

impl RuntimeControlPlaneState {
    pub(super) fn create_project_if_absent(
        &mut self,
        project: StoredProject,
    ) -> CreateIfAbsentOutcome {
        if self.projects.get(&project.id).is_some() {
            return CreateIfAbsentOutcome::AlreadyExists;
        }
        self.projects.insert(project.id.clone(), project);
        CreateIfAbsentOutcome::Created
    }

    pub(super) fn create_workspace_if_absent(
        &mut self,
        workspace: StoredWorkspace,
    ) -> CreateIfAbsentOutcome {
        if self.workspaces.get(&workspace.id).is_some() {
            return CreateIfAbsentOutcome::AlreadyExists;
        }
        self.workspaces.insert(workspace.id.clone(), workspace);
        CreateIfAbsentOutcome::Created
    }

    pub(super) fn create_api_key_record_if_absent(
        &mut self,
        api_key: StoredApiKey,
    ) -> CreateIfAbsentOutcome {
        if self.api_key_records.get(&api_key.id).is_some() {
            return CreateIfAbsentOutcome::AlreadyExists;
        }
        self.api_key_records.insert(api_key.id.clone(), api_key);
        CreateIfAbsentOutcome::Created
    }
}

impl RuntimeStorageRepositories {
    pub async fn create_api_key_record_if_absent(
        &self,
        api_key: StoredApiKey,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        self.control_plane
            .store()
            .create_api_key_record_if_absent(api_key)
            .await
    }

    pub async fn create_project_if_absent(
        &self,
        project: StoredProject,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        self.control_plane
            .store()
            .create_project_if_absent(project)
            .await
    }

    pub async fn create_workspace_if_absent(
        &self,
        workspace: StoredWorkspace,
    ) -> Result<CreateIfAbsentOutcome, StorageError> {
        self.control_plane
            .store()
            .create_workspace_if_absent(workspace)
            .await
    }
}
