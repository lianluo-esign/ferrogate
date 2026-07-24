// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: control/tenant database provisioning lifecycle + registry persistence.

//! D1 backend: control/tenant database provisioning lifecycle + registry persistence.
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use ferrogate_cloudflare::d1::{D1CreateDatabaseRequest, D1Database};

use super::*;

impl D1ControlPlaneStore {
    /// Build the backend from a D1 endpoint client and a (possibly empty)
    /// registry — load a persisted registry with
    /// [`D1TenantDatabaseRegistry::from_document_json`] first when resuming
    /// an existing deployment.
    pub fn new(client: D1Client, registry: D1TenantDatabaseRegistry) -> Self {
        Self {
            client,
            registry: Mutex::new(registry),
            usage_aggregates_mirror: Mutex::new(InMemoryRepository::new()),
        }
    }

    /// A snapshot of the current tenant->database registry.
    pub fn registry_snapshot(&self) -> Result<D1TenantDatabaseRegistry, StorageError> {
        self.registry
            .lock()
            .map(|registry| registry.clone())
            .map_err(|_| poisoned_registry_lock())
    }

    // --- Provisioning lifecycle (inherent, admin path) ---

    /// Provision the CONTROL database (tenants + config documents + registry
    /// document) if the registry does not name one yet. Idempotent; returns
    /// the control database uuid.
    pub async fn provision_control_database(&self) -> Result<String, StorageError> {
        {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            if !registry.control_database_id.is_empty() {
                return Ok(registry.control_database_id.clone());
            }
        }
        let database_id = self
            .create_database_with_schema("ferrogate-control")
            .await?;
        {
            let mut registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry.control_database_id = database_id.clone();
        }
        self.persist_registry().await?;
        Ok(database_id)
    }

    /// Provision a tenant's D1 database: create it, apply the SQLite core
    /// schema (`sql/d1/001_init_d1.sql`), record it in the registry, and
    /// persist the registry document. Idempotent per tenant; returns the
    /// database uuid.
    pub async fn provision_tenant_database(&self, tenant_id: &str) -> Result<String, StorageError> {
        validate_tenant_id(tenant_id)?;
        {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            if let Some(existing) = registry.tenant_databases.get(tenant_id) {
                return Ok(existing.clone());
            }
        }
        let name = format!("ferrogate-tenant-{}", tenant_id.to_ascii_lowercase());
        let database_id = self.create_database_with_schema(&name).await?;
        {
            let mut registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry
                .tenant_databases
                .insert(tenant_id.to_string(), database_id.clone());
        }
        self.persist_registry().await?;
        Ok(database_id)
    }

    /// Delete a tenant's D1 database (and ALL its data) and drop it from the
    /// registry. Returns `false` when the tenant had no registered database.
    pub async fn deprovision_tenant_database(&self, tenant_id: &str) -> Result<bool, StorageError> {
        let database_id = {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry.tenant_databases.get(tenant_id).cloned()
        };
        let Some(database_id) = database_id else {
            return Ok(false);
        };
        self.client
            .delete_database(&database_id)
            .await
            .map_err(d1_error)?;
        {
            let mut registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            registry.tenant_databases.remove(tenant_id);
        }
        self.persist_registry().await?;
        Ok(true)
    }

    /// List the account's D1 databases (admin visibility across control +
    /// tenant databases and any unregistered leftovers).
    pub async fn list_provisioned_databases(&self) -> Result<Vec<D1Database>, StorageError> {
        self.client.list_databases().await.map_err(d1_error)
    }

    pub(super) async fn create_database_with_schema(
        &self,
        name: &str,
    ) -> Result<String, StorageError> {
        let created = self
            .client
            .create_database(&D1CreateDatabaseRequest::named(name))
            .await
            .map_err(d1_error)?;
        let database_id = created.uuid.ok_or_else(|| {
            StorageError::Runtime(format!(
                "cloudflare d1: create database {name} returned no uuid"
            ))
        })?;
        self.execute(&database_id, &schema_batch_sql(), Vec::new())
            .await?;
        Ok(database_id)
    }

    pub(super) async fn persist_registry(&self) -> Result<(), StorageError> {
        let (control_database_id, document_json) = {
            let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
            (
                registry.control_database_id.clone(),
                registry.to_document_json()?,
            )
        };
        if control_database_id.is_empty() {
            return Err(StorageError::Runtime(
                "cloudflare d1: cannot persist tenant database registry without a control \
                 database (call provision_control_database first)"
                    .to_string(),
            ));
        }
        self.put_document(
            &control_database_id,
            D1_TENANT_DATABASE_REGISTRY_KIND,
            D1_TENANT_DATABASE_REGISTRY_ID,
            &document_json,
        )
        .await
    }
}
