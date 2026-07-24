// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: low-level query plumbing + tenant/control-database routing.

//! D1 backend: low-level query plumbing + tenant/control-database routing.
//!
//! Split out of `control_plane_store_d1.rs` in issue #451; see `mod.rs`.

use ferrogate_cloudflare::d1::D1QueryResult;

use super::rows::*;
use super::*;

impl D1ControlPlaneStore {
    // --- Routing ---

    pub(super) fn control_database_id(&self) -> Result<String, StorageError> {
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        if registry.control_database_id.is_empty() {
            return Err(StorageError::Runtime(
                "cloudflare d1: no control database configured (call \
                 provision_control_database or seed the registry)"
                    .to_string(),
            ));
        }
        Ok(registry.control_database_id.clone())
    }

    /// The database an entity write routes to: the tenant's database, or the
    /// control database for an EMPTY tenant id (pre-multi-tenant records).
    pub(super) fn database_for_tenant(&self, tenant_id: &str) -> Result<String, StorageError> {
        if tenant_id.is_empty() {
            return self.control_database_id();
        }
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        registry
            .tenant_databases
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "no provisioned D1 database for tenant {tenant_id} \
                     (call provision_tenant_database first)"
                ))
            })
    }

    /// The proxy-Worker binding NAME for a tenant's own D1 database when the
    /// tenant is PROVISIONED (present in the registry, so a binding was added +
    /// redeployed for it), else `None`. Validates the tenant id first. Used by
    /// opt-in reads (`get_wallet`, `list_wallet_reservations`) that answer
    /// empty for an unprovisioned tenant rather than erroring.
    pub(super) fn tenant_proxy_binding_optional(
        &self,
        tenant_id: &str,
    ) -> Result<Option<String>, StorageError> {
        validate_tenant_id(tenant_id)?;
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        Ok(registry
            .tenant_databases
            .contains_key(tenant_id)
            .then(|| tenant_database_binding(tenant_id)))
    }

    /// The proxy-Worker binding NAME for a tenant's own D1 database (issue #455
    /// tenant-scoped atomic routing), REQUIRING the tenant to be provisioned. A
    /// tenant with no provisioned database is a typed `NotFound`, mirroring
    /// [`database_for_tenant`](Self::database_for_tenant).
    pub(super) fn tenant_proxy_binding(&self, tenant_id: &str) -> Result<String, StorageError> {
        self.tenant_proxy_binding_optional(tenant_id)?
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "no provisioned D1 database for tenant {tenant_id} \
                     (call provision_tenant_database first)"
                ))
            })
    }

    /// Every provisioned tenant's `(tenant_id, proxy binding name)` in registry
    /// order — the fan-out set for a tenant-scoped op whose trait signature
    /// carries only an entity id (e.g. `settle`/`release` by reservation id),
    /// which must locate which tenant database holds the row.
    pub(super) fn provisioned_tenant_bindings(
        &self,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        Ok(registry
            .tenant_databases
            .keys()
            .map(|tenant_id| (tenant_id.clone(), tenant_database_binding(tenant_id)))
            .collect())
    }

    /// Control database first, then every tenant database in registry order —
    /// the fan-out set for id-only reads and unfiltered lists.
    pub(super) fn fan_out_database_ids(&self) -> Result<Vec<String>, StorageError> {
        let control = self.control_database_id()?;
        let registry = self.registry.lock().map_err(|_| poisoned_registry_lock())?;
        let mut databases = vec![control];
        for database_id in registry.tenant_databases.values() {
            if !databases.contains(database_id) {
                databases.push(database_id.clone());
            }
        }
        Ok(databases)
    }

    // --- Query plumbing ---

    /// Run one statement and return its result, surfacing per-statement
    /// failure as a typed error.
    pub(super) async fn execute(
        &self,
        database_id: &str,
        sql: &str,
        params: Vec<String>,
    ) -> Result<D1QueryResult, StorageError> {
        let mut results = self
            .client
            .query(database_id, sql, &params)
            .await
            .map_err(d1_error)?;
        if let Some(failed) = results
            .iter()
            .position(|result| result.success == Some(false))
        {
            return Err(StorageError::Runtime(format!(
                "cloudflare d1: statement {failed} of batch reported failure"
            )));
        }
        results.pop().ok_or_else(|| {
            StorageError::Runtime("cloudflare d1: query returned no result".to_string())
        })
    }

    pub(super) async fn fetch_rows<T: serde::de::DeserializeOwned>(
        &self,
        database_id: &str,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Vec<T>, StorageError> {
        let result = self.execute(database_id, sql, params).await?;
        result
            .results
            .into_iter()
            .map(|row| {
                serde_json::from_value(row)
                    .map_err(|error| StorageError::Serialization(error.to_string()))
            })
            .collect()
    }

    pub(super) async fn fetch_optional_row<T: serde::de::DeserializeOwned>(
        &self,
        database_id: &str,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Option<T>, StorageError> {
        Ok(self
            .fetch_rows(database_id, sql, params)
            .await?
            .into_iter()
            .next())
    }

    // --- Generic config documents (control database) ---

    pub(super) async fn put_document(
        &self,
        database_id: &str,
        kind: &str,
        id: &str,
        document_json: &str,
    ) -> Result<(), StorageError> {
        self.execute(
            database_id,
            "INSERT INTO control_plane_resources \
             (resource_kind, resource_id, document_json, revision, created_at_unix, \
              updated_at_unix) \
             VALUES (?, ?, ?, 1, unixepoch(), unixepoch()) \
             ON CONFLICT (resource_kind, resource_id) DO UPDATE SET \
             document_json = excluded.document_json, \
             revision = control_plane_resources.revision + 1, \
             updated_at_unix = unixepoch()",
            vec![kind.to_string(), id.to_string(), document_json.to_string()],
        )
        .await
        .map(|_| ())
    }

    // --- Account-global entities: read a single control-database row ---
    //
    // Admin identity, SSO, quota policies, and plans are account-scoped
    // control-plane configuration (issue #440); every one routes to the
    // control database, so these thin helpers factor out the shared
    // `control_database_id()` lookup.

    pub(super) async fn fetch_control_optional<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Option<T>, StorageError> {
        let database_id = self.control_database_id()?;
        self.fetch_optional_row(&database_id, sql, params).await
    }

    pub(super) async fn fetch_control_rows<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Vec<T>, StorageError> {
        let database_id = self.control_database_id()?;
        self.fetch_rows(&database_id, sql, params).await
    }

    pub(super) async fn execute_control(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<D1QueryResult, StorageError> {
        let database_id = self.control_database_id()?;
        self.execute(&database_id, sql, params).await
    }

    // --- Observability append/analytics families (issue #447, control DB) ---
    //
    // Agent runs/events + request/audit logs mirror the Postgres single-table
    // JSON-document pattern: each write stores the FULL record as a `*_json`
    // document plus the projection columns the read SQL filters/orders on; each
    // read selects that document and deserializes it. Every one routes to the
    // CONTROL database (routing rationale in the module docs + sql/d1 header):
    // the analytics reads are cross-tenant whole-table scans (time-ordered,
    // `count(*)`-paginated, UNION-seeded) and the `tenant` column is a
    // composite storage key, not a routing tenant id, so per-tenant fan-out
    // would only add a lossy merge-sort over the faithful single-query mirror.

    /// Deserialize a batch of records selected as a `document_json` column, in
    /// the order the query returned them.
    pub(super) async fn fetch_control_documents<T: for<'de> Deserialize<'de>>(
        &self,
        sql: &str,
        params: Vec<String>,
    ) -> Result<Vec<T>, StorageError> {
        let rows: Vec<DocumentRow> = self.fetch_control_rows(sql, params).await?;
        rows.iter()
            .map(|row| deserialize_storage_document(row.document_json.as_str()))
            .collect()
    }

    /// A paginated page of records: every row carries a `count(*) OVER()` total
    /// alongside its `document_json`, matching the Postgres window-count page.
    pub(super) async fn fetch_control_document_page<T: for<'de> Deserialize<'de>>(
        &self,
        sql: &str,
        offset: usize,
        limit: usize,
    ) -> Result<StoragePage<T>, StorageError> {
        let rows: Vec<PagedDocumentRow> = self.fetch_control_rows(sql, Vec::new()).await?;
        let total = rows.first().map(|row| row.total).unwrap_or(0);
        let data = rows
            .iter()
            .map(|row| deserialize_storage_document(row.document_json.as_str()))
            .collect::<Result<Vec<T>, StorageError>>()?;
        Ok(StoragePage {
            data,
            total: usize::try_from(total).unwrap_or(usize::MAX),
            offset,
            limit,
        })
    }
}
