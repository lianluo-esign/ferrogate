// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare D1 REST endpoint wrapper (database lifecycle + HTTP query API) for issue #420.

//! Cloudflare D1 REST endpoints (issue #420).
//!
//! A self-contained wrapper over the shared [`CloudflareClient`] (issue #405)
//! for the D1 database lifecycle and HTTP query endpoints:
//!
//! - `POST   /accounts/{account_id}/d1/database` — provision a database.
//! - `GET    /accounts/{account_id}/d1/database` — list databases.
//! - `GET    /accounts/{account_id}/d1/database/{uuid}` — fetch one database.
//! - `DELETE /accounts/{account_id}/d1/database/{uuid}` — delete a database.
//! - `POST   /accounts/{account_id}/d1/database/{uuid}/query` — run SQL.
//!
//! Auth, `{account_id}` templating, envelope decoding, typed error mapping,
//! and retry/backoff all come from the shared client, so this module is pure
//! endpoint shape: request/response DTOs plus thin methods.
//!
//! ## Rate-limit strategy (documented split, issue #420)
//!
//! The public REST API is limited to ~1,200 requests / 5 min / user, so this
//! raw-HTTP surface is the **admin / low-volume** path (provisioning, schema
//! migration, control-plane CRUD). Hot-path query traffic should go through a
//! **proxy Worker holding a D1 binding** (see
//! `docs/cloudflare-deploy-topology.md` §bindings and
//! `docs/cloudflare-integration.md` §6); that Worker is out of scope here.
//!
//! ## Parameter typing
//!
//! The documented REST schema types `params` as an array of **strings**.
//! SQLite column type affinity converts numeric-looking strings on insert
//! into `INTEGER`/`REAL` columns, and `NULL` is expressed in SQL (e.g.
//! `NULLIF(?, '')`) rather than as a JSON `null` param, so callers stay
//! inside the documented contract.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::client::{CloudflareClient, HttpMethod};
use crate::error::CloudflareError;

/// Request body for `POST /accounts/{account_id}/d1/database`.
#[derive(Debug, Clone, Serialize)]
pub struct D1CreateDatabaseRequest {
    /// D1 database name (unique per account).
    pub name: String,
    /// Placement hint (`wnam`/`enam`/`weur`/`eeur`/`apac`/`oc`). Ignored when
    /// `jurisdiction` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_location_hint: Option<String>,
    /// Jurisdictional restriction (`eu`/`fedramp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}

impl D1CreateDatabaseRequest {
    /// A plain create request with no placement/jurisdiction constraints.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            primary_location_hint: None,
            jurisdiction: None,
        }
    }
}

/// A D1 database descriptor as returned by the lifecycle endpoints. All
/// fields are optional in Cloudflare's schema; `uuid` is the identifier the
/// query endpoint routes on.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct D1Database {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub num_tables: Option<u64>,
}

/// The `meta` object attached to each query result: row accounting and the
/// write cursor (`last_row_id`), all optional in Cloudflare's schema.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct D1QueryMeta {
    #[serde(default)]
    pub changed_db: Option<bool>,
    #[serde(default)]
    pub changes: Option<u64>,
    #[serde(default)]
    pub duration: Option<f64>,
    #[serde(default)]
    pub last_row_id: Option<i64>,
    #[serde(default)]
    pub rows_read: Option<u64>,
    #[serde(default)]
    pub rows_written: Option<u64>,
    #[serde(default)]
    pub size_after: Option<u64>,
    #[serde(default)]
    pub served_by_region: Option<String>,
}

/// One statement's outcome from the query endpoint. `results` holds the rows
/// as JSON objects keyed by column name; a multi-statement batch yields one
/// [`D1QueryResult`] per statement.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct D1QueryResult {
    #[serde(default)]
    pub results: Vec<serde_json::Value>,
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub meta: Option<D1QueryMeta>,
}

impl D1QueryResult {
    /// `meta.changes` collapsed to a plain count (0 when absent).
    pub fn changes(&self) -> u64 {
        self.meta
            .as_ref()
            .and_then(|meta| meta.changes)
            .unwrap_or_default()
    }
}

#[derive(Serialize)]
struct D1QueryRequest<'a> {
    sql: &'a str,
    params: &'a [String],
}

/// Thin D1 endpoint client over the shared [`CloudflareClient`].
#[derive(Clone)]
pub struct D1Client {
    client: Arc<CloudflareClient>,
}

impl D1Client {
    pub fn new(client: Arc<CloudflareClient>) -> Self {
        Self { client }
    }

    /// The shared client this wrapper routes through.
    pub fn client(&self) -> &Arc<CloudflareClient> {
        &self.client
    }

    /// Provision a new D1 database. Returns the descriptor whose `uuid` the
    /// query endpoint routes on.
    pub async fn create_database(
        &self,
        request: &D1CreateDatabaseRequest,
    ) -> Result<D1Database, CloudflareError> {
        let body = serde_json::to_vec(request).map_err(|error| {
            CloudflareError::Config(format!("failed to encode D1 create request: {error}"))
        })?;
        self.client
            .request_json(
                HttpMethod::Post,
                "accounts/{account_id}/d1/database",
                Some(body),
                None,
            )
            .await
    }

    /// List the account's D1 databases. Requests the maximum page size
    /// (1,000); pagination beyond the first page is intentionally not
    /// followed in this admin-path slice.
    pub async fn list_databases(&self) -> Result<Vec<D1Database>, CloudflareError> {
        self.client
            .get_json("accounts/{account_id}/d1/database?per_page=1000", None)
            .await
    }

    /// Fetch one database descriptor by uuid.
    pub async fn get_database(&self, database_id: &str) -> Result<D1Database, CloudflareError> {
        let path = database_path(database_id, "")?;
        self.client.get_json(&path, None).await
    }

    /// Delete a database (and all of its data). The endpoint returns a null
    /// `result`, so this is an ack-style call.
    pub async fn delete_database(&self, database_id: &str) -> Result<(), CloudflareError> {
        let path = database_path(database_id, "")?;
        self.client
            .request_ack(HttpMethod::Delete, &path, None, None)
            .await
    }

    /// Run SQL against a database over the HTTP query endpoint.
    ///
    /// `sql` may contain multiple statements joined by semicolons (executed
    /// as a batch, one [`D1QueryResult`] per statement). `params` bind `?`
    /// placeholders positionally and are strings per the documented schema
    /// (see the module docs on affinity/NULL handling). Limits: statement
    /// <= 100 KB, <= 100 params, 30 s runtime, single-threaded per database.
    pub async fn query(
        &self,
        database_id: &str,
        sql: &str,
        params: &[String],
    ) -> Result<Vec<D1QueryResult>, CloudflareError> {
        let path = database_path(database_id, "/query")?;
        let body = serde_json::to_vec(&D1QueryRequest { sql, params }).map_err(|error| {
            CloudflareError::Config(format!("failed to encode D1 query request: {error}"))
        })?;
        self.client
            .request_json(HttpMethod::Post, &path, Some(body), None)
            .await
    }
}

/// Build the `d1/database/{uuid}{suffix}` path, rejecting ids that could
/// escape the path segment. Cloudflare ids are hex uuids; anything else is a
/// caller bug surfaced as a config error before any request is sent.
fn database_path(database_id: &str, suffix: &str) -> Result<String, CloudflareError> {
    if database_id.is_empty()
        || !database_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(CloudflareError::Config(format!(
            "invalid D1 database id {database_id:?}: expected a Cloudflare uuid"
        )));
    }
    Ok(format!(
        "accounts/{{account_id}}/d1/database/{database_id}{suffix}"
    ))
}
