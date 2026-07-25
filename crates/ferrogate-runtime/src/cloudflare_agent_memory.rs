// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Typed memory verbs over the agent-gateway Worker's /memory/* routes
//   (issue #427): state get/set, SQL query, chat-history get/prune, plus the default-off
//   Vectorize semantic-memory pilot, with the tenant-isolating instance naming scheme.

//! FerroGate access to a Cloudflare agent's **per-instance memory** (issue
//! #427).
//!
//! Cloudflare agents keep all memory inside ONE Durable Object per named
//! instance (isolated SQLite + state, single-writer) and expose **no
//! first-party memory REST API**. Every memory operation FerroGate performs is
//! therefore a governed call to the agent-gateway Worker's authenticated
//! `/memory/*` routes (the tethered principle: memory access is a FerroGate
//! operation, never a direct agent-to-store call). Three composable layers:
//!
//! 1. **Synced JSON state** — whole-object replace, server-side validated
//!    (`state_get` / `state_set`).
//! 2. **Embedded per-agent SQLite** — arbitrary tables, 10 GB/DO, 2 MB
//!    row/value limit (`sql_query`). On `SQLITE_FULL` writes fail but reads
//!    and `DELETE` still succeed — the prune path relies on that
//!    ([`AgentMemoryClient::sql_query_with_prune_on_full`]).
//! 3. **Chat history** — the SDK's persisted message table with a retention
//!    cap (`chat_history_get` / `chat_history_prune`).
//!
//! Optional: **semantic memory** over Vectorize + Workers AI embeddings —
//! open **beta**, piloted behind a default-off flag on BOTH sides (the
//! Worker's `MEMORY_SEMANTIC_ENABLED` var and this client's
//! [`AgentMemoryClient::with_semantic_enabled`]).
//!
//! ## Instance naming — memory isolation IS tenant isolation
//!
//! The Durable Object instance **name** is the isolation unit: same name →
//! same instance (and its memory); different name → disjoint memory. FerroGate
//! therefore mints names from its own identity triple:
//!
//! ```text
//! fg.{tenant_id}.{session_id}.{run_id}
//! ```
//!
//! Components are validated against `[A-Za-z0-9_-]{1,64}` — the separator
//! `.` is **excluded** from components, which makes the mapping injective:
//! no two distinct (tenant, session, run) triples can collide on one name, so
//! two tenants can never address the same instance. Validation is strict
//! (reject, never sanitize): lossy sanitizing could fold two tenants onto one
//! name and silently break isolation.
//!
//! HTTP reuses the synchronous [`GatewayControlTransport`] seam from the #413
//! control surface, so every verb is unit-tested against a scripted mock with
//! no network — matching how #414 tested its lifecycle verbs.

use serde::Deserialize;
use serde_json::json;
use std::{error::Error, fmt};

use crate::cloudflare_gateway_control::GatewayControlTransport;
use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};

/// Leading tag of every FerroGate-minted agent instance name.
pub const AGENT_INSTANCE_NAME_PREFIX: &str = "fg";
/// Separator between name components; excluded from component charsets so the
/// identity → name mapping stays injective.
pub const AGENT_INSTANCE_NAME_SEPARATOR: char = '.';
/// Maximum length of one identity component.
pub const AGENT_INSTANCE_COMPONENT_MAX_LEN: usize = 64;

/// The FerroGate identity triple an agent instance name is minted from.
///
/// `tenant_id` leads the name, so per-instance Durable Object isolation is
/// per-tenant isolation by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInstanceIdentity {
    pub tenant_id: String,
    pub session_id: String,
    pub run_id: String,
}

impl AgentInstanceIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            session_id: session_id.into(),
            run_id: run_id.into(),
        }
    }

    /// Mint the agent instance name: `fg.{tenant}.{session}.{run}`.
    ///
    /// Fails (never sanitizes) when a component is empty, exceeds
    /// [`AGENT_INSTANCE_COMPONENT_MAX_LEN`], or contains a character outside
    /// `[A-Za-z0-9_-]` — in particular the separator itself.
    pub fn instance_name(&self) -> Result<String, AgentMemoryError> {
        validate_component("tenant_id", &self.tenant_id)?;
        validate_component("session_id", &self.session_id)?;
        validate_component("run_id", &self.run_id)?;
        Ok(format!(
            "{prefix}{sep}{tenant}{sep}{session}{sep}{run}",
            prefix = AGENT_INSTANCE_NAME_PREFIX,
            sep = AGENT_INSTANCE_NAME_SEPARATOR,
            tenant = self.tenant_id,
            session = self.session_id,
            run = self.run_id,
        ))
    }
}

fn validate_component(label: &str, value: &str) -> Result<(), AgentMemoryError> {
    if value.is_empty() {
        return Err(AgentMemoryError::InvalidIdentity(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > AGENT_INSTANCE_COMPONENT_MAX_LEN {
        return Err(AgentMemoryError::InvalidIdentity(format!(
            "{label} exceeds {AGENT_INSTANCE_COMPONENT_MAX_LEN} characters"
        )));
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
    {
        return Err(AgentMemoryError::InvalidIdentity(format!(
            "{label} contains {bad:?}; allowed: [A-Za-z0-9_-] (the separator {AGENT_INSTANCE_NAME_SEPARATOR:?} is reserved)"
        )));
    }
    Ok(())
}

/// Failure surfaced by an agent-memory verb.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentMemoryError {
    /// The identity triple cannot be turned into a safe instance name.
    InvalidIdentity(String),
    /// The Worker rejected the bearer credential (HTTP 401/403).
    Denied(String),
    /// The instance's embedded SQLite hit its 10 GB limit (`SQLITE_FULL`,
    /// HTTP 507). Reads and DELETEs still work — run the prune path.
    SqliteFull(String),
    /// Semantic memory is a default-off beta pilot; it is disabled here or on
    /// the Worker (HTTP 501).
    SemanticDisabled(String),
    /// Any other non-2xx from a memory route.
    RequestFailed {
        verb: &'static str,
        status: u16,
        body: String,
    },
    /// Connect/decoding failure talking to the Worker.
    Transport(String),
}

impl fmt::Display for AgentMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(m) => write!(f, "invalid agent instance identity: {m}"),
            Self::Denied(m) => write!(f, "agent memory access denied: {m}"),
            Self::SqliteFull(m) => write!(f, "agent sqlite storage full: {m}"),
            Self::SemanticDisabled(m) => write!(f, "semantic memory pilot disabled: {m}"),
            Self::RequestFailed { verb, status, body } => {
                write!(f, "agent memory {verb} failed: HTTP {status}: {body}")
            }
            Self::Transport(m) => write!(f, "agent memory transport failed: {m}"),
        }
    }
}

impl Error for AgentMemoryError {}

/// Layer-1 snapshot: the instance's synced JSON state.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentStateSnapshot {
    pub instance: String,
    pub state: serde_json::Value,
}

/// Layer-2 outcome of one SQL statement.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSqlOutcome {
    pub instance: String,
    pub columns: Vec<String>,
    pub rows: Vec<serde_json::Value>,
    pub row_count: u64,
}

/// One persisted chat message (layer 3).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentChatMessage {
    pub id: String,
    pub message: serde_json::Value,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Layer-3 history read, oldest-first.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentChatHistory {
    pub instance: String,
    pub messages: Vec<AgentChatMessage>,
    pub count: u64,
}

/// Layer-3 eviction outcome (`maxPersistedMessages` cap enforcement).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentChatPruneOutcome {
    pub instance: String,
    pub cap: u64,
    pub pruned: u64,
    pub remaining: u64,
}

/// One semantic-memory match (Vectorize pilot, beta).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentSemanticMatch {
    pub id: String,
    pub score: f64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Semantic-memory query result (Vectorize pilot, beta).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentSemanticMatches {
    pub instance: String,
    pub matches: Vec<AgentSemanticMatch>,
}

#[derive(Debug, Deserialize)]
struct MemoryErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// Typed client for the gateway Worker's `/memory/*` routes.
///
/// Reuses the synchronous [`GatewayControlTransport`] seam (and its production
/// block-on bridge) from the #413 control surface, and presents the same DIY
/// bearer credential — memory access rides the exact governed channel the
/// lifecycle verbs do.
pub struct AgentMemoryClient<T: GatewayControlTransport> {
    base_url: String,
    control_token: String,
    /// Default-off client-side gate for the semantic-memory beta pilot.
    semantic_enabled: bool,
    transport: T,
}

impl<T: GatewayControlTransport> AgentMemoryClient<T> {
    /// Build a memory client for a Worker at `base_url` presenting
    /// `control_token`. The semantic pilot starts DISABLED.
    pub fn new(
        base_url: impl Into<String>,
        control_token: impl Into<String>,
        transport: T,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            control_token: control_token.into(),
            semantic_enabled: false,
            transport,
        }
    }

    /// Opt in to the semantic-memory pilot (beta; also requires the Worker's
    /// `MEMORY_SEMANTIC_ENABLED` var + Vectorize/AI bindings).
    pub fn with_semantic_enabled(mut self, enabled: bool) -> Self {
        self.semantic_enabled = enabled;
        self
    }

    /// Borrow the underlying transport (tests inspect the mock through this).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn post(&self, path: &str, body: serde_json::Value) -> Result<HttpResponse, AgentMemoryError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| AgentMemoryError::Transport(format!("failed to encode body: {e}")))?;
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        self.transport
            .send(HttpRequest {
                method: HttpMethod::Post,
                url,
                bearer_token: self.control_token.clone(),
                body: Some(bytes),
                content_type: None,
            })
            .map_err(|e| AgentMemoryError::Transport(e.to_string()))
    }

    fn call<R: for<'de> Deserialize<'de>>(
        &self,
        verb: &'static str,
        path: &str,
        body: serde_json::Value,
    ) -> Result<R, AgentMemoryError> {
        let response = self.post(path, body)?;
        if !(200..300).contains(&response.status) {
            return Err(map_error(verb, &response));
        }
        serde_json::from_slice(&response.body)
            .map_err(|e| AgentMemoryError::Transport(format!("failed to decode {verb}: {e}")))
    }

    /// Layer 1: read the instance's synced JSON state.
    pub fn state_get(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<AgentStateSnapshot, AgentMemoryError> {
        let instance = identity.instance_name()?;
        self.call(
            "state_get",
            "memory/state/get",
            json!({ "instance": instance }),
        )
    }

    /// Layer 1: whole-object state replace. The Worker validates server-side;
    /// a validation failure aborts the write (HTTP 422 → `RequestFailed`).
    pub fn state_set(
        &self,
        identity: &AgentInstanceIdentity,
        state: serde_json::Value,
    ) -> Result<AgentStateSnapshot, AgentMemoryError> {
        let instance = identity.instance_name()?;
        self.call(
            "state_set",
            "memory/state/set",
            json!({ "instance": instance, "state": state }),
        )
    }

    /// Layer 2: run one SQL statement against the instance's embedded SQLite.
    /// `SQLITE_FULL` surfaces as [`AgentMemoryError::SqliteFull`].
    pub fn sql_query(
        &self,
        identity: &AgentInstanceIdentity,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<AgentSqlOutcome, AgentMemoryError> {
        let instance = identity.instance_name()?;
        self.call(
            "sql_query",
            "memory/sql/query",
            json!({ "instance": instance, "sql": sql, "params": params }),
        )
    }

    /// Layer 2 + eviction: like [`Self::sql_query`], but on `SQLITE_FULL` run
    /// the chat-history prune path (DELETE still works on a full database)
    /// and retry the statement once.
    pub fn sql_query_with_prune_on_full(
        &self,
        identity: &AgentInstanceIdentity,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<AgentSqlOutcome, AgentMemoryError> {
        match self.sql_query(identity, sql, params) {
            Err(AgentMemoryError::SqliteFull(_)) => {
                self.chat_history_prune(identity, None)?;
                self.sql_query(identity, sql, params)
            }
            other => other,
        }
    }

    /// Layer 3: read up to `limit` newest persisted chat messages
    /// (oldest-first in the result).
    pub fn chat_history_get(
        &self,
        identity: &AgentInstanceIdentity,
        limit: Option<u32>,
    ) -> Result<AgentChatHistory, AgentMemoryError> {
        let instance = identity.instance_name()?;
        let mut body = json!({ "instance": instance });
        if let Some(limit) = limit {
            body["limit"] = json!(limit);
        }
        self.call("chat_history_get", "memory/chat/get", body)
    }

    /// Layer 3: evict oldest chat messages beyond the retention cap. Passing
    /// `None` prunes to the deployment's `maxPersistedMessages`; a `Some`
    /// value can only tighten it.
    pub fn chat_history_prune(
        &self,
        identity: &AgentInstanceIdentity,
        max_messages: Option<u32>,
    ) -> Result<AgentChatPruneOutcome, AgentMemoryError> {
        let instance = identity.instance_name()?;
        let mut body = json!({ "instance": instance });
        if let Some(max) = max_messages {
            body["maxMessages"] = json!(max);
        }
        self.call("chat_history_prune", "memory/chat/prune", body)
    }

    /// Semantic-memory pilot (Vectorize + Workers AI embeddings) — **beta**,
    /// default OFF. When the client-side flag is off this sends **no HTTP**
    /// and returns [`AgentMemoryError::SemanticDisabled`].
    pub fn semantic_query(
        &self,
        identity: &AgentInstanceIdentity,
        query: &str,
        top_k: Option<u32>,
    ) -> Result<AgentSemanticMatches, AgentMemoryError> {
        if !self.semantic_enabled {
            return Err(AgentMemoryError::SemanticDisabled(
                "enable with AgentMemoryClient::with_semantic_enabled(true) (beta pilot)".into(),
            ));
        }
        let instance = identity.instance_name()?;
        let mut body = json!({ "instance": instance, "query": query });
        if let Some(top_k) = top_k {
            body["topK"] = json!(top_k);
        }
        self.call("semantic_query", "memory/semantic/query", body)
    }
}

/// Map a non-2xx memory-route response onto the typed error vocabulary.
fn map_error(verb: &'static str, response: &HttpResponse) -> AgentMemoryError {
    let body_text = String::from_utf8_lossy(&response.body).into_owned();
    let parsed: MemoryErrorBody =
        serde_json::from_slice(&response.body).unwrap_or(MemoryErrorBody {
            error: String::new(),
            message: String::new(),
        });
    let detail = if parsed.message.is_empty() {
        body_text.clone()
    } else {
        parsed.message
    };
    match (response.status, parsed.error.as_str()) {
        (401 | 403, _) => {
            AgentMemoryError::Denied(format!("HTTP {}: {body_text}", response.status))
        }
        (507, _) | (_, "sqlite_full") => AgentMemoryError::SqliteFull(detail),
        (501, _) | (_, "semantic_memory_disabled" | "semantic_memory_unbound") => {
            AgentMemoryError::SemanticDisabled(detail)
        }
        (status, _) => AgentMemoryError::RequestFailed {
            verb,
            status,
            body: body_text,
        },
    }
}

#[cfg(test)]
#[path = "cloudflare_agent_memory_test.rs"]
mod tests;
