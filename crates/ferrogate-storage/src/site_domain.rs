// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Custom-domain bindings for hosted static sites (#265, asset
// hosting epic #175). A `StoredSiteDomain` maps one exact hostname to the
// `{tenant}/{site}` that `Host: <hostname>` requests should serve through the
// #258 static-site resolution. The hostname is the natural key (one hostname
// -> one site; a site may have many hostnames). Split into its own file per
// the "one business entity per file" convention (mirrors `agent_schedule.rs`).

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneState,
    RuntimeStorageRepositories, StorageError, StorageOperation,
};

/// One hostname -> static-site binding. `hostname` is stored normalized
/// (lowercase, no port); callers normalize before writing or looking up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSiteDomain {
    pub hostname: String,
    pub tenant_id: String,
    pub site: String,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

fn site_domain_from_row(row: &PostgresRow) -> StoredSiteDomain {
    StoredSiteDomain {
        hostname: row.get::<_, String>(0),
        tenant_id: row.get::<_, String>(1),
        site: row.get::<_, String>(2),
        created_at_unix: row.get::<_, i64>(3),
        updated_at_unix: row.get::<_, i64>(4),
    }
}

const SITE_DOMAIN_COLUMNS: &str = "hostname, tenant_id, site, created_at_unix, updated_at_unix";

impl PostgresControlPlaneStore {
    fn site_domain_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn upsert_site_domain(
        &self,
        domain: &StoredSiteDomain,
    ) -> Result<(), StorageError> {
        let operation = self.site_domain_operation("upsert site domain");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves `site_domains` in the configured schema,
        // not the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO site_domains \
                 (hostname, tenant_id, site, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (hostname) DO UPDATE SET \
                     tenant_id = EXCLUDED.tenant_id, \
                     site = EXCLUDED.site, \
                     updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &domain.hostname,
                    &domain.tenant_id,
                    &domain.site,
                    &domain.created_at_unix,
                    &domain.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError> {
        let operation = self.site_domain_operation("get site domain");
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
        let row = transaction
            .query_opt(
                &format!("SELECT {SITE_DOMAIN_COLUMNS} FROM site_domains WHERE hostname = $1"),
                &[&hostname],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(site_domain_from_row))
    }

    pub(super) async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError> {
        let operation = self.site_domain_operation("list site domains");
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
        let rows = match tenant_id {
            Some(tenant_id) => transaction
                .query(
                    &format!(
                        "SELECT {SITE_DOMAIN_COLUMNS} FROM site_domains \
                         WHERE tenant_id = $1 ORDER BY hostname ASC"
                    ),
                    &[&tenant_id],
                )
                .await
                .map_err(postgres_error)?,
            None => transaction
                .query(
                    &format!(
                        "SELECT {SITE_DOMAIN_COLUMNS} FROM site_domains ORDER BY hostname ASC"
                    ),
                    &[],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(site_domain_from_row).collect())
    }

    pub(super) async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError> {
        let operation = self.site_domain_operation("delete site domain");
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
        let affected = transaction
            .execute("DELETE FROM site_domains WHERE hostname = $1", &[&hostname])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }
}

impl RuntimeControlPlaneState {
    pub(super) fn upsert_site_domain(&mut self, domain: StoredSiteDomain) {
        self.site_domains.insert(domain.hostname.clone(), domain);
    }

    pub(super) fn get_site_domain(&self, hostname: &str) -> Option<StoredSiteDomain> {
        self.site_domains.get(hostname)
    }

    pub(super) fn list_site_domains(&self, tenant_id: Option<&str>) -> Vec<StoredSiteDomain> {
        let mut domains: Vec<_> = self
            .site_domains
            .list()
            .into_iter()
            .filter(|domain| tenant_id.is_none_or(|tenant| domain.tenant_id == tenant))
            .collect();
        domains.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        domains
    }

    pub(super) fn delete_site_domain(&mut self, hostname: &str) -> bool {
        self.site_domains.remove(hostname).is_some()
    }
}

impl RuntimeStorageRepositories {
    pub async fn upsert_site_domain(&self, domain: StoredSiteDomain) -> Result<(), StorageError> {
        self.control_plane.store().upsert_site_domain(domain).await
    }

    pub async fn get_site_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomain>, StorageError> {
        self.control_plane.store().get_site_domain(hostname).await
    }

    /// Lists bindings, optionally narrowed to one tenant. `None` is the
    /// platform-operator view across all tenants (also used at startup to
    /// merge every bound hostname into the ACME certificate domain set).
    pub async fn list_site_domains(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomain>, StorageError> {
        self.control_plane
            .store()
            .list_site_domains(tenant_id)
            .await
    }

    pub async fn delete_site_domain(&self, hostname: &str) -> Result<bool, StorageError> {
        self.control_plane
            .store()
            .delete_site_domain(hostname)
            .await
    }
}
