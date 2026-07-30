// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: AgentMemoryClient verb tests (issue #427) — assert each memory verb hits the
//   right /memory/* route with the bearer token and instance name, that the naming scheme is
//   strict/injective, and that SQLITE_FULL triggers the prune-and-retry path. NO network.

use std::collections::VecDeque;
use std::sync::Mutex;

use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};
use serde_json::json;

use super::{
    vectorize_namespace, AgentChatMessageInput, AgentInstanceIdentity, AgentMemoryClient,
    AgentMemoryError, AGENT_INSTANCE_COMPONENT_MAX_LEN, VECTORIZE_NAMESPACE_MAX_BYTES,
};
use crate::cloudflare_gateway_control::GatewayControlTransport;
use crate::cloudflare_worker::CloudflareControlSurfaceError;

/// A synchronous scripted transport: records requests, replays responses.
struct MockMemoryTransport {
    responses: Mutex<VecDeque<HttpResponse>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockMemoryTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn last(&self) -> HttpRequest {
        self.captured.lock().unwrap().last().cloned().unwrap()
    }

    fn captured_urls(&self) -> Vec<String> {
        self.captured
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.url.clone())
            .collect()
    }

    fn captured_len(&self) -> usize {
        self.captured.lock().unwrap().len()
    }
}

impl GatewayControlTransport for MockMemoryTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.captured.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock memory transport ran out of responses"))
    }
}

fn ok(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn status(code: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status: code,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn client(responses: Vec<HttpResponse>) -> AgentMemoryClient<MockMemoryTransport> {
    AgentMemoryClient::new(
        "https://ferrogate-agent-gateway.example.workers.dev",
        "control-secret",
        MockMemoryTransport::new(responses),
    )
}

fn identity() -> AgentInstanceIdentity {
    AgentInstanceIdentity::new("tenant-a", "sess-1", "run-9")
}

fn body_json(req: &HttpRequest) -> serde_json::Value {
    serde_json::from_slice(req.body.as_ref().unwrap()).unwrap()
}

// ---- Naming scheme: memory isolation == tenant isolation --------------------

#[test]
fn instance_name_is_tenant_prefixed_and_dot_separated() {
    assert_eq!(
        identity().instance_name().unwrap(),
        "fg.tenant-a.sess-1.run-9"
    );
}

#[test]
fn instance_name_rejects_the_separator_inside_components() {
    // If '.' were allowed inside a component, ("a.b", "c") and ("a", "b.c")
    // would mint the same name — a cross-tenant memory collision. Strict
    // rejection (never sanitizing) keeps the mapping injective.
    let err = AgentInstanceIdentity::new("tenant.a", "s", "r")
        .instance_name()
        .unwrap_err();
    assert!(
        matches!(err, AgentMemoryError::InvalidIdentity(_)),
        "got {err:?}"
    );
}

#[test]
fn instance_name_rejects_empty_overlong_and_invalid_components() {
    for identity in [
        AgentInstanceIdentity::new("", "s", "r"),
        AgentInstanceIdentity::new("t", "s".repeat(65), "r".to_string()),
        AgentInstanceIdentity::new("t", "s", "r/../evil"),
        AgentInstanceIdentity::new("t", "s p a c e", "r"),
    ] {
        let err = identity.instance_name().unwrap_err();
        assert!(
            matches!(err, AgentMemoryError::InvalidIdentity(_)),
            "got {err:?}"
        );
    }
}

#[test]
fn distinct_tenants_never_share_an_instance_name() {
    let a = AgentInstanceIdentity::new("tenant-a", "s", "r")
        .instance_name()
        .unwrap();
    let b = AgentInstanceIdentity::new("tenant-b", "s", "r")
        .instance_name()
        .unwrap();
    assert_ne!(a, b);
}

// ---- Layer 1: synced JSON state ---------------------------------------------

#[test]
fn state_get_posts_instance_to_memory_state_get() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "state": { "status": "running" } }"#,
    )]);
    let snapshot = c.state_get(&identity()).unwrap();
    assert_eq!(snapshot.instance, "fg.tenant-a.sess-1.run-9");
    assert_eq!(snapshot.state["status"], "running");

    let req = c.transport().last();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/state/get"
    );
    assert_eq!(req.bearer_token, "control-secret");
    assert_eq!(body_json(&req)["instance"], "fg.tenant-a.sess-1.run-9");
}

#[test]
fn state_set_posts_the_whole_replacement_state() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "state": { "status": "stopped" } }"#,
    )]);
    let state = json!({ "status": "stopped", "updatedAt": 1 });
    let snapshot = c.state_set(&identity(), state.clone()).unwrap();
    assert_eq!(snapshot.state["status"], "stopped");

    let body = body_json(&c.transport().last());
    assert_eq!(body["state"], state);
    assert_eq!(
        c.transport().last().url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/state/set"
    );
}

#[test]
fn state_set_validation_abort_maps_to_request_failed_422() {
    let c = client(vec![status(
        422,
        r#"{ "error": "invalid_state", "message": "state.updatedAt must be a number" }"#,
    )]);
    let err = c
        .state_set(&identity(), json!({ "bogus": true }))
        .unwrap_err();
    match err {
        AgentMemoryError::RequestFailed { verb, status, .. } => {
            assert_eq!(verb, "state_set");
            assert_eq!(status, 422);
        }
        other => panic!("expected RequestFailed, got {other:?}"),
    }
}

// ---- Layer 2: embedded per-agent SQLite -------------------------------------

#[test]
fn sql_query_posts_sql_and_params_and_maps_rows() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9",
             "columns": ["id", "note"],
             "rows": [{ "id": 1, "note": "remember" }],
             "rowCount": 1 }"#,
    )]);
    let outcome = c
        .sql_query(
            &identity(),
            "select id, note from fg_notes where id = ?",
            &[json!(1)],
        )
        .unwrap();
    assert_eq!(outcome.columns, vec!["id", "note"]);
    assert_eq!(outcome.row_count, 1);
    assert_eq!(outcome.rows[0]["note"], "remember");

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/sql/query"
    );
    let body = body_json(&req);
    assert_eq!(body["sql"], "select id, note from fg_notes where id = ?");
    assert_eq!(body["params"][0], 1);
}

#[test]
fn sqlite_full_507_maps_to_the_typed_error() {
    let c = client(vec![status(
        507,
        r#"{ "error": "sqlite_full", "message": "SQLITE_FULL: database or disk is full" }"#,
    )]);
    let err = c
        .sql_query(
            &identity(),
            "insert into fg_notes values (?)",
            &[json!("x")],
        )
        .unwrap_err();
    assert!(
        matches!(err, AgentMemoryError::SqliteFull(_)),
        "got {err:?}"
    );
}

#[test]
fn sql_query_with_prune_on_full_prunes_then_retries_once() {
    // SQLITE_FULL prune path: write fails 507 → prune (DELETE succeeds on a
    // full database) → retry succeeds. Exactly three requests, in order.
    let c = client(vec![
        status(
            507,
            r#"{ "error": "sqlite_full", "message": "SQLITE_FULL" }"#,
        ),
        ok(
            r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "cap": 200, "pruned": 40, "remaining": 200 }"#,
        ),
        ok(
            r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "columns": [], "rows": [], "rowCount": 0 }"#,
        ),
    ]);
    let outcome = c
        .sql_query_with_prune_on_full(
            &identity(),
            "insert into fg_notes values (?)",
            &[json!("x")],
        )
        .unwrap();
    assert_eq!(outcome.row_count, 0);

    let urls = c.transport().captured_urls();
    assert_eq!(urls.len(), 3);
    assert!(urls[0].ends_with("/memory/sql/query"));
    assert!(urls[1].ends_with("/memory/chat/prune"));
    assert!(urls[2].ends_with("/memory/sql/query"));
}

// ---- Layer 3: chat history --------------------------------------------------

#[test]
fn chat_history_get_passes_limit_and_maps_messages() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9",
             "messages": [
               { "id": "m1", "message": { "role": "user", "content": "hi" }, "createdAt": "2026-07-24" }
             ],
             "count": 1 }"#,
    )]);
    let history = c.chat_history_get(&identity(), Some(50)).unwrap();
    assert_eq!(history.count, 1);
    assert_eq!(history.messages[0].id, "m1");
    assert_eq!(history.messages[0].message["role"], "user");

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/chat/get"
    );
    assert_eq!(body_json(&req)["limit"], 50);
}

#[test]
fn chat_history_prune_posts_the_cap_and_maps_the_eviction_outcome() {
    // The maxPersistedMessages cap: the caller may tighten (never widen) the
    // deployment cap; the Worker reports what it evicted.
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "cap": 100, "pruned": 23, "remaining": 100 }"#,
    )]);
    let outcome = c.chat_history_prune(&identity(), Some(100)).unwrap();
    assert_eq!(outcome.cap, 100);
    assert_eq!(outcome.pruned, 23);
    assert_eq!(outcome.remaining, 100);

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/chat/prune"
    );
    assert_eq!(body_json(&req)["maxMessages"], 100);
}

#[test]
fn chat_history_prune_without_cap_defers_to_the_deployment_cap() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "cap": 200, "pruned": 0, "remaining": 12 }"#,
    )]);
    c.chat_history_prune(&identity(), None).unwrap();
    let body = body_json(&c.transport().last());
    assert!(
        body.get("maxMessages").is_none(),
        "cap must be omitted: {body}"
    );
}

#[test]
fn chat_history_append_posts_the_batch_and_maps_the_outcome() {
    let c = client(vec![ok(
        r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "appended": 2, "cap": 200, "pruned": 0, "remaining": 2 }"#,
    )]);
    let outcome = c
        .chat_history_append(
            &identity(),
            &[
                AgentChatMessageInput {
                    id: "m1".into(),
                    message: json!({ "role": "user", "content": "one" }),
                },
                AgentChatMessageInput {
                    id: "m2".into(),
                    message: json!({ "role": "assistant", "content": "two" }),
                },
            ],
        )
        .unwrap();
    assert_eq!(outcome.appended, 2);
    assert_eq!(outcome.remaining, 2);

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/chat/append"
    );
    assert_eq!(req.bearer_token, "control-secret");
    let body = body_json(&req);
    assert_eq!(body["instance"], "fg.tenant-a.sess-1.run-9");
    assert_eq!(body["messages"][0]["id"], "m1");
    assert_eq!(body["messages"][1]["message"]["content"], "two");
}

// ---- The SQL governance guard ----------------------------------------------

#[test]
fn refused_statement_maps_to_sql_forbidden_not_denied() {
    // The Worker refuses a statement naming an SDK control table with 403.
    // Reporting that as a credential denial would send an operator hunting a
    // token problem that does not exist.
    let c = client(vec![status(
        403,
        r#"{ "error": "sql_forbidden", "message": "statement references the reserved Agents SDK control table 'cf_agents_state'" }"#,
    )]);
    let err = c
        .sql_query(&identity(), "select * from cf_agents_state", &[])
        .unwrap_err();
    match err {
        AgentMemoryError::SqlForbidden(detail) => assert!(detail.contains("cf_agents_state")),
        other => panic!("expected SqlForbidden, got {other:?}"),
    }
}

// ---- Vectorize namespace ----------------------------------------------------

#[test]
fn short_instance_names_are_their_own_vectorize_namespace() {
    assert_eq!(vectorize_namespace("fg.t.s.r"), "fg.t.s.r");
}

#[test]
fn overlong_instance_names_collapse_into_the_64_byte_namespace_cap() {
    // A realistic UUID triple is ~110 bytes against Vectorize's 64-byte cap;
    // the worst case the naming scheme can mint is 197.
    let component = "a".repeat(AGENT_INSTANCE_COMPONENT_MAX_LEN);
    let instance = format!("fg.{component}.{component}.{component}");
    assert_eq!(instance.len(), 197);

    let namespace = vectorize_namespace(&instance);
    assert_eq!(namespace.len(), VECTORIZE_NAMESPACE_MAX_BYTES);
    assert!(namespace.starts_with("fgh_"));
    assert!(namespace[4..].chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn vectorize_namespace_is_deterministic_and_separates_tenants() {
    let a = format!("fg.{}.sess.run", "t".repeat(64));
    let b = format!("fg.{}.sess.run", "u".repeat(64));
    assert_eq!(vectorize_namespace(&a), vectorize_namespace(&a));
    assert_ne!(vectorize_namespace(&a), vectorize_namespace(&b));
}

#[test]
fn vectorize_namespace_matches_the_worker_recipe() {
    // Pins the exact digest the Worker's `vectorizeNamespace` produces for the
    // same input. The two sides derive the namespace independently, so a
    // divergence would partition writes from reads instead of failing loudly —
    // this value is what makes that divergence a test failure.
    let component = "a".repeat(AGENT_INSTANCE_COMPONENT_MAX_LEN);
    let instance = format!("fg.{component}.{component}.{component}");
    assert_eq!(
        vectorize_namespace(&instance),
        "fgh_73e51c31d07ae87dda7fb74b74bbd972d68250ef373c80be85f86d88c090"
    );
}

// ---- Auth + semantic pilot --------------------------------------------------

#[test]
fn denied_bearer_maps_to_denied() {
    let c = client(vec![status(403, r#"{ "error": "invalid bearer token" }"#)]);
    let err = c.state_get(&identity()).unwrap_err();
    assert!(matches!(err, AgentMemoryError::Denied(_)), "got {err:?}");
}

#[test]
fn semantic_query_is_default_off_and_sends_no_http() {
    let c = client(vec![]);
    let err = c
        .semantic_query(&identity(), "what did we decide?", None)
        .unwrap_err();
    assert!(
        matches!(err, AgentMemoryError::SemanticDisabled(_)),
        "got {err:?}"
    );
    assert_eq!(
        c.transport().captured_len(),
        0,
        "disabled pilot must send no HTTP"
    );
}

#[test]
fn semantic_query_when_enabled_posts_and_maps_matches() {
    let c = AgentMemoryClient::new(
        "https://ferrogate-agent-gateway.example.workers.dev",
        "control-secret",
        MockMemoryTransport::new(vec![ok(
            r#"{ "ok": true, "instance": "fg.tenant-a.sess-1.run-9", "beta": true,
                 "matches": [{ "id": "v1", "score": 0.87, "metadata": { "note": "decision" } }] }"#,
        )]),
    )
    .with_semantic_enabled(true);

    let matches = c
        .semantic_query(&identity(), "what did we decide?", Some(3))
        .unwrap();
    assert_eq!(matches.matches.len(), 1);
    assert_eq!(matches.matches[0].id, "v1");

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/memory/semantic/query"
    );
    let body = body_json(&req);
    assert_eq!(body["query"], "what did we decide?");
    assert_eq!(body["topK"], 3);
}

#[test]
fn worker_side_disabled_pilot_501_maps_to_semantic_disabled() {
    let c = client(vec![status(
        501,
        r#"{ "error": "semantic_memory_disabled", "beta": true }"#,
    )])
    .with_semantic_enabled(true);
    let err = c.semantic_query(&identity(), "q", None).unwrap_err();
    assert!(
        matches!(err, AgentMemoryError::SemanticDisabled(_)),
        "got {err:?}"
    );
}
