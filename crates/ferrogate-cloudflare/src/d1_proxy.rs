// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Cloudflare D1 proxy-Worker client (native-binding atomic hot path) for issue #450.

//! Cloudflare D1 **proxy-Worker** client (issue #450).
//!
//! The landed D1 REST wrapper ([`crate::d1::D1Client`]) speaks the public HTTP
//! query API, which has **no multi-statement-with-params transaction and no
//! `RETURNING`**. That blocks every atomic-transition control-plane family
//! (wallets/payments/workflow-budgets, `append_billing_event_with_outbox_enqueue`,
//! guardrail CAS). The fix is a small Worker (`workers/d1-proxy/`) that holds a
//! NATIVE D1 binding and can run `prepare().bind()` / `batch()` (atomic) /
//! `RETURNING`, exposed as a bearer-authenticated HTTP API. This module is the
//! Rust half: a thin, self-contained client that speaks that API over the SAME
//! [`HttpTransport`] seam the REST client uses.
//!
//! ## Transport + envelope reuse
//!
//! This is deliberately NOT built on [`crate::CloudflareClient`]: that client
//! templates `{account_id}` and targets the Cloudflare REST base URL with the
//! account API token, whereas the proxy Worker lives at its own deployed URL and
//! authenticates with its OWN bearer secret. Instead this reuses the lower-level
//! seams directly — [`HttpTransport`] (Bearer request/response, injectable +
//! mockable), [`TokenResolver`] (the `env://`/inline/`cf://` credential seam),
//! and [`CloudflareEnvelope`] (the `{ success, errors, result }` wire shape). The
//! Worker emits that same envelope and, per statement, the same
//! `{ results, success, meta }` shape the REST endpoint returns — so both
//! transports decode into one [`D1QueryResult`] type.
//!
//! ## Routing split (documented, see `docs/cloudflare-d1-backend.md`)
//!
//! REST stays the transport for the non-atomic/admin surface (provisioning,
//! schema migration, CRUD, config documents). This proxy client is used ONLY for
//! the atomic hot path. The Worker's `env.DB` binding is fixed at deploy time to
//! the FerroGate CONTROL database, which is where the wired atomic family
//! (billing metering + report outbox) lives; per-tenant atomic families are an
//! enumerated follow-up needing per-database bindings.
//!
//! ## Parameter typing
//!
//! Params are bound as **strings**, identical to the REST client's contract:
//! SQLite column affinity converts numeric strings on insert, booleans bind as
//! `"1"`/`"0"`, and SQL `NULL` is expressed in SQL (`NULLIF(?, '')`) with an
//! empty-string bind rather than a JSON `null`.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::client::{HttpMethod, HttpRequest, HttpTransport};
use crate::d1::D1QueryResult;
use crate::envelope::CloudflareEnvelope;
use crate::error::CloudflareError;
use crate::resolver::TokenResolver;

/// One statement to run through the proxy Worker: SQL with positional `?`
/// placeholders plus the string params that bind them (see the module docs on
/// parameter typing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct D1ProxyStatement {
    /// SQL text (single statement). `RETURNING` is supported by the binding.
    pub sql: String,
    /// Positional binds for the statement's `?` placeholders, as strings.
    pub params: Vec<String>,
}

impl D1ProxyStatement {
    /// A statement with no bound params.
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
        }
    }

    /// A statement with its positional string binds.
    pub fn with_params(sql: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            sql: sql.into(),
            params,
        }
    }
}

/// Request body for `POST /d1/batch`.
///
/// `database` names the target D1 binding (issue #455). It is
/// `skip_serializing_if = "Option::is_none"`, so a control-database batch (the
/// #450 default) serializes to the unchanged `{ statements: [...] }` shape and a
/// tenant-scoped batch adds `"database": "<binding>"`.
#[derive(Serialize)]
struct BatchRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<&'a str>,
    statements: &'a [D1ProxyStatement],
}

/// Request body for `POST /d1/query`: the single statement flattened to the
/// top level (`sql` + `params`) plus the optional `database` binding selector
/// (issue #455). With `database == None` the flattened body is byte-for-byte the
/// pre-#455 `{ sql, params }` shape.
#[derive(Serialize)]
struct QueryRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<&'a str>,
    #[serde(flatten)]
    statement: &'a D1ProxyStatement,
}

/// Thin client over the d1-proxy Worker's HTTP API.
///
/// Holds the shared [`HttpTransport`] seam (so it is mockable with the same
/// scripted transport the REST client's tests use), the [`TokenResolver`] seam
/// for the Worker's bearer secret, the Worker's base URL, and the token
/// reference to resolve per request (cheap for `env://`/inline; picks up
/// rotation without a rebuild).
#[derive(Clone)]
pub struct D1ProxyClient {
    transport: Arc<dyn HttpTransport>,
    resolver: Arc<dyn TokenResolver>,
    base_url: String,
    token_reference: String,
}

impl std::fmt::Debug for D1ProxyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("D1ProxyClient")
            .field("base_url", &self.base_url)
            .field("token_reference", &"<redacted>")
            .finish()
    }
}

impl D1ProxyClient {
    /// Assemble a proxy client from its parts.
    ///
    /// `base_url` is the Worker's deployed origin (e.g.
    /// `https://ferrogate-d1-proxy.<subdomain>.workers.dev`); the `/d1/*` paths
    /// are appended. `token_reference` is resolved through `resolver` (an
    /// `env://VAR` or an inline plaintext token; `cf://` is rejected — see
    /// [`crate::resolver`]).
    pub fn new(
        base_url: impl Into<String>,
        transport: Arc<dyn HttpTransport>,
        resolver: Arc<dyn TokenResolver>,
        token_reference: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            resolver,
            base_url: base_url.into(),
            token_reference: token_reference.into(),
        }
    }

    /// The Worker origin this client targets.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Run an **atomic** multi-statement batch against the CONTROL database
    /// (`env.DB.batch([...])`) — the #450 default target.
    ///
    /// Every statement commits together or the whole batch rolls back — the
    /// guarantee the REST query API cannot give. Returns one [`D1QueryResult`]
    /// per statement, in order, each carrying its `RETURNING` rows in `results`.
    pub async fn batch(
        &self,
        statements: &[D1ProxyStatement],
    ) -> Result<Vec<D1QueryResult>, CloudflareError> {
        self.batch_on(None, statements).await
    }

    /// Run an **atomic** batch against a SELECTED D1 binding (issue #455).
    ///
    /// `database` is the Worker binding name of the target database
    /// (`Some("TENANT_DB_ACME")` for a tenant's own database, `None` for the
    /// control database). The Worker runs the whole batch as one atomic unit on
    /// that database; there is no runtime select-by-id, so the binding must exist
    /// in the Worker's wrangler config (an unknown binding fails closed at the
    /// Worker with a 400 the client maps to a typed API error).
    pub async fn batch_on(
        &self,
        database: Option<&str>,
        statements: &[D1ProxyStatement],
    ) -> Result<Vec<D1QueryResult>, CloudflareError> {
        let body = serde_json::to_vec(&BatchRequest {
            database,
            statements,
        })
        .map_err(|error| {
            CloudflareError::Config(format!("failed to encode D1 proxy batch request: {error}"))
        })?;
        self.post_enveloped("d1/batch", body).await
    }

    /// Run one `prepare().bind(...).all()` statement against the CONTROL database,
    /// `RETURNING` included — the single-statement companion to
    /// [`batch`](Self::batch) for CAS ops expressible as one `UPDATE ...
    /// RETURNING` / `INSERT ... RETURNING`.
    pub async fn query(
        &self,
        statement: &D1ProxyStatement,
    ) -> Result<D1QueryResult, CloudflareError> {
        self.query_on(None, statement).await
    }

    /// Run one statement against a SELECTED D1 binding (issue #455). `database`
    /// is the target binding name (`None` = control database); see
    /// [`batch_on`](Self::batch_on) for the binding-resolution contract.
    pub async fn query_on(
        &self,
        database: Option<&str>,
        statement: &D1ProxyStatement,
    ) -> Result<D1QueryResult, CloudflareError> {
        let body = serde_json::to_vec(&QueryRequest {
            database,
            statement,
        })
        .map_err(|error| {
            CloudflareError::Config(format!("failed to encode D1 proxy query request: {error}"))
        })?;
        self.post_enveloped("d1/query", body).await
    }

    /// Resolve the bearer, POST `body` to `path`, and decode the Cloudflare-style
    /// envelope the Worker returns into `T`.
    async fn post_enveloped<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<T, CloudflareError> {
        let token = self.resolver.resolve(&self.token_reference)?;
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: self.build_url(path),
            bearer_token: token.expose().to_string(),
            body: Some(body),
            content_type: None,
        };
        let response = self.transport.execute(request).await?;
        let envelope: CloudflareEnvelope<T> =
            serde_json::from_slice(&response.body).map_err(|error| {
                CloudflareError::Decode(format!("failed to decode D1 proxy envelope: {error}"))
            })?;
        envelope.into_result(response.status, response.retry_after)
    }

    /// Join the Worker origin with a `/d1/*` path.
    fn build_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}
