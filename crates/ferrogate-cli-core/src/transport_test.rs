// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for request building, response classification, and pagination
//! (#360). Pure logic only — no live network.

use super::*;
use crate::auth::Credential;
use crate::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use crate::error::ExitClass;
use crate::output::OutputFormat;
use std::sync::Mutex;
use std::task::{Context as TaskContext, Poll, Waker};

fn context_with_endpoint(endpoint: &str, tenant: Option<&str>) -> EffectiveContext {
    EffectiveContext {
        context_name: Some("test".to_string()),
        endpoint: endpoint.to_string(),
        tenant: tenant.map(str::to_string),
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: crate::auth::AuthSource::None,
        output: OutputFormat::Json,
        non_interactive: true,
    }
}

/// Minimal single-poll executor: the fake transport's future is always ready,
/// so a spin-poll with a no-op waker completes it without pulling in a runtime.
fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = TaskContext::from_waker(waker);
    // Safety: the future is owned locally and never moved after pinning.
    let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => continue,
        }
    }
}

#[test]
fn prepare_request_builds_url_headers_and_body() {
    let context = context_with_endpoint("https://prod.example.com", Some("acme"));
    let credential = Credential::new("secret-token").unwrap();
    let spec = RequestSpec::new(Method::POST, "/admin/v1/tenants")
        .with_json_body(serde_json::json!({"name": "new-tenant"}))
        .with_query("dry_run", "true");
    let prepared = prepare_request(&spec, &context, Some(&credential)).unwrap();

    assert_eq!(prepared.method, Method::POST);
    assert_eq!(
        prepared.url,
        "https://prod.example.com/admin/v1/tenants?dry_run=true"
    );
    assert_eq!(
        prepared.header("authorization"),
        Some("Bearer secret-token")
    );
    assert_eq!(prepared.header("accept"), Some("application/json"));
    assert_eq!(prepared.header("content-type"), Some("application/json"));
    // Sent — but see `tenant_scope_is_not_yet_an_openapi_parameter`: nothing
    // server-side reads this header today, which is why the CLI says so on
    // stderr rather than letting this assertion imply a working capability.
    assert_eq!(prepared.header(TENANT_HEADER_UNDER_TEST), Some("acme"));
    assert!(prepared.header("user-agent").unwrap().contains("ferrogate"));
    assert_eq!(prepared.body, br#"{"name":"new-tenant"}"#.to_vec());
}

#[test]
fn prepare_request_without_credential_omits_authorization() {
    let context = context_with_endpoint("http://127.0.0.1:8080", None);
    let spec = RequestSpec::get("/admin/v1/status");
    let prepared = prepare_request(&spec, &context, None).unwrap();
    assert_eq!(prepared.header("authorization"), None);
    assert_eq!(prepared.header("x-ferrogate-tenant"), None);
    assert!(prepared.body.is_empty());
    assert_eq!(prepared.url, "http://127.0.0.1:8080/admin/v1/status");
}

#[test]
fn prepare_request_preserves_endpoint_base_path() {
    let context = context_with_endpoint("https://host.example.com/gw/", None);
    let spec = RequestSpec::get("/admin/v1/status");
    let prepared = prepare_request(&spec, &context, None).unwrap();
    assert_eq!(prepared.url, "https://host.example.com/gw/admin/v1/status");
}

#[test]
fn prepare_request_percent_encodes_query() {
    let context = context_with_endpoint("http://localhost:8080", None);
    let spec = RequestSpec::get("/admin/v1/search").with_query("q", "a b&c");
    let prepared = prepare_request(&spec, &context, None).unwrap();
    assert!(prepared.url.contains("q=a+b%26c") || prepared.url.contains("q=a%20b%26c"));
}

#[test]
fn classify_success_extracts_body_and_correlation_ids() {
    let raw = RawResponse {
        status: 200,
        headers: vec![
            ("x-request-id".to_string(), "fgadm-01".to_string()),
            ("x-trace-id".to_string(), "trace-99".to_string()),
        ],
        body: br#"{"items":[{"id":"t1"}]}"#.to_vec(),
    };
    let response = classify(&raw).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.request_id.as_deref(), Some("fgadm-01"));
    assert_eq!(response.trace_id.as_deref(), Some("trace-99"));
    assert_eq!(response.body["items"][0]["id"], "t1");
}

#[test]
fn classify_empty_success_body_is_null() {
    let raw = RawResponse {
        status: 204,
        headers: vec![],
        body: vec![],
    };
    let response = classify(&raw).unwrap();
    assert_eq!(response.body, serde_json::Value::Null);
}

#[test]
fn classify_decodes_ferrogate_error_envelope() {
    let raw = RawResponse {
        status: 404,
        headers: vec![("x-trace-id".to_string(), "trace-77".to_string())],
        body: br#"{"error":{"message":"no such tenant","type":"ferrogate_error","code":"tenant_not_found","request_id":"fgadm-77","hint":"check the id"}}"#.to_vec(),
    };
    let error = classify(&raw).unwrap_err();
    assert_eq!(error.http_status, 404);
    assert_eq!(error.code, "tenant_not_found");
    assert_eq!(error.message, "no such tenant");
    assert_eq!(error.request_id.as_deref(), Some("fgadm-77"));
    assert_eq!(error.trace_id.as_deref(), Some("trace-77"));
    assert_eq!(error.exit_class(), ExitClass::NotFoundConflict);
    // Unknown extra fields are preserved as details, not dropped.
    assert_eq!(error.details.unwrap()["hint"], "check the id");
}

#[test]
fn classify_extracts_retry_after_hint() {
    let raw = RawResponse {
        status: 429,
        headers: vec![("retry-after".to_string(), "12".to_string())],
        body: br#"{"error":{"message":"slow down","type":"ferrogate_error","code":"rate_limited","request_id":null}}"#.to_vec(),
    };
    let error = classify(&raw).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Transport);
    assert_eq!(error.retry_after_secs, Some(12));
}

#[test]
fn classify_synthesizes_error_for_nonjson_body() {
    let raw = RawResponse {
        status: 502,
        headers: vec![],
        body: b"upstream unreachable".to_vec(),
    };
    let error = classify(&raw).unwrap_err();
    assert_eq!(error.http_status, 502);
    assert_eq!(error.code, "server_error");
    assert_eq!(error.message, "upstream unreachable");
    assert_eq!(error.exit_class(), ExitClass::Server);
}

#[test]
fn page_request_query_params() {
    let page = PageRequest::first(50);
    assert_eq!(
        page.query_params(),
        vec![
            ("offset".to_string(), "0".to_string()),
            ("limit".to_string(), "50".to_string())
        ]
    );
    let no_limit = PageRequest {
        offset: 100,
        limit: None,
    };
    assert_eq!(
        no_limit.query_params(),
        vec![("offset".to_string(), "100".to_string())]
    );
}

#[test]
fn next_page_stops_on_known_total() {
    let first = PageRequest::first(50);
    let next = next_page(&first, 50, Some(120)).unwrap();
    assert_eq!(next.offset, 50);
    let third = next_page(&next, 50, Some(120)).unwrap();
    assert_eq!(third.offset, 100);
    // 100 + 20 returned reaches the total of 120: done.
    assert_eq!(next_page(&third, 20, Some(120)), None);
}

#[test]
fn next_page_stops_on_short_page_when_total_unknown() {
    let first = PageRequest::first(50);
    // A full page implies more may follow.
    assert!(next_page(&first, 50, None).is_some());
    // A short page is the last page.
    assert_eq!(next_page(&first, 30, None), None);
    // An empty page always ends iteration.
    assert_eq!(next_page(&first, 0, None), None);
}

#[test]
fn plan_all_pages_covers_every_item_without_truncation() {
    assert_eq!(plan_all_pages(0, 50), vec![]);
    let pages = plan_all_pages(120, 50);
    assert_eq!(pages.len(), 3);
    assert_eq!(pages[0].offset, 0);
    assert_eq!(pages[1].offset, 50);
    assert_eq!(pages[2].offset, 100);
    // A zero limit is clamped so the plan is finite.
    assert_eq!(plan_all_pages(3, 0).len(), 3);
}

/// Fake transport recording the last prepared request and returning a scripted
/// response, so the client orchestration is proven without a network.
struct FakeTransport {
    response: RawResponse,
    seen: Mutex<Option<PreparedRequest>>,
}

impl Transport for FakeTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        *self.seen.lock().unwrap() = Some(request);
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }
}

#[test]
fn client_sends_prepared_request_and_classifies_success() {
    let context = context_with_endpoint("https://prod.example.com", Some("acme"));
    let credential = Credential::new("secret").unwrap();
    let transport = FakeTransport {
        response: RawResponse {
            status: 200,
            headers: vec![("x-request-id".to_string(), "fgadm-abc".to_string())],
            body: br#"{"status":"ok"}"#.to_vec(),
        },
        seen: Mutex::new(None),
    };
    let client = ControlPlaneClient::new(context, Some(credential), transport);
    let spec = RequestSpec::get("/admin/v1/status");
    let response = block_on(client.send(&spec)).unwrap();
    assert_eq!(response.request_id.as_deref(), Some("fgadm-abc"));
    assert_eq!(response.body["status"], "ok");
}

#[test]
fn client_maps_error_envelope_to_cli_error() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = FakeTransport {
        response: RawResponse {
            status: 403,
            headers: vec![],
            body: br#"{"error":{"message":"wrong scope","type":"ferrogate_error","code":"forbidden","request_id":"fgadm-x"}}"#.to_vec(),
        },
        seen: Mutex::new(None),
    };
    let client = ControlPlaneClient::new(context, None, transport);
    let spec = RequestSpec::get("/admin/v1/tenants");
    let error = block_on(client.send(&spec)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}

// ----- list-page recognition and the all-pages walk ---------------------------

#[test]
fn page_envelope_recognizes_the_list_shapes() {
    let bare = serde_json::json!([{"id": "a"}, {"id": "b"}]);
    let envelope = page_envelope(&bare).unwrap();
    assert_eq!(envelope.items_key, None);
    assert_eq!(envelope.items.len(), 2);
    assert_eq!(envelope.total, None);

    // The real Control Plane API list envelope, verbatim from the contract:
    // `{"object":"list","data":[…],"total":N,"offset":O,"limit":L}`.
    let wrapped = serde_json::json!({
        "object": "list",
        "data": [{"id": "a"}],
        "total": 7,
        "offset": 0,
        "limit": 1,
    });
    let envelope = page_envelope(&wrapped).unwrap();
    assert_eq!(envelope.items_key, Some("data"));
    assert_eq!(envelope.items.len(), 1);
    assert_eq!(envelope.total, Some(7));
    assert_eq!(envelope.limit, Some(1));
    assert_eq!(envelope.offset, Some(0));
    assert!(!envelope.cursor);
    assert!(envelope.echoes_page_window());

    // An envelope that says nothing about the window it served: the shape 43 of
    // the contract's 65 `list*` operations return, and the one the walk must
    // refuse to advance through.
    let windowless = serde_json::json!({"object": "list", "data": [{"id": "a"}]});
    let envelope = page_envelope(&windowless).unwrap();
    assert_eq!(envelope.items.len(), 1);
    assert!(
        !envelope.echoes_page_window(),
        "no offset, limit, or total means no evidence of an offset window"
    );
    // Any ONE of the three is enough evidence to keep walking.
    for marker in ["total", "limit", "offset"] {
        let body = serde_json::json!({"object": "list", "data": [{"id": "a"}], marker: 1});
        assert!(
            page_envelope(&body).unwrap().echoes_page_window(),
            "'{marker}' alone is a page-window echo"
        );
    }

    // Spellings the contract does NOT use are not list envelopes. Accepting
    // them would let the pagination surface be "proven" against a payload no
    // endpoint emits.
    assert!(page_envelope(&serde_json::json!({"items": [{"id": "a"}], "total": 1})).is_none());
    assert!(page_envelope(&serde_json::json!({"results": [], "total_count": 0})).is_none());
    assert!(page_envelope(&serde_json::json!({"records": []})).is_none());

    // A per-page `count` is not a collection total: reading one as the total
    // would stop a walk after page one.
    let counted = serde_json::json!({"data": [{"id": "a"}], "count": 1});
    assert_eq!(page_envelope(&counted).unwrap().total, None);

    // A single object, a scalar, or null is not a list page.
    assert!(page_envelope(&serde_json::json!({"id": "a"})).is_none());
    assert!(page_envelope(&serde_json::json!("hello")).is_none());
    assert!(page_envelope(&serde_json::Value::Null).is_none());
}

/// The envelope keys the walker and the renderer recognize are re-derived from
/// the enforced OpenAPI contract, not asserted from memory.
///
/// This is the test that makes the shape claim falsifiable in the direction it
/// actually failed: previously `PAGE_ITEM_KEYS` carried three spellings the API
/// never emits, so deleting the one real key (`data`) left every pagination
/// test green while the feature died on 100% of endpoints. Here, a contract
/// that grows a page property this client cannot read fails the suite.
#[test]
fn page_item_keys_match_the_openapi_contract() {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json"))
            .expect("the OpenAPI contract parses");
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("component schemas");

    // A list envelope: an object schema with an array-typed property AND at
    // least one pagination marker. Collected structurally rather than by
    // grepping for "items", which in an OpenAPI document is overwhelmingly
    // JSON Schema's own array keyword.
    let markers = ["total", "limit", "offset", "has_more", "after_event_id"];
    let mut array_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for schema in schemas.values() {
        let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) else {
            continue;
        };
        if !markers
            .iter()
            .any(|marker| properties.contains_key(*marker))
        {
            continue;
        }
        for (name, property) in properties {
            if property.get("type").and_then(|t| t.as_str()) == Some("array") {
                array_keys.insert(name.clone());
            }
        }
    }

    let declared: std::collections::BTreeSet<String> =
        PAGE_ITEM_KEYS.iter().map(|key| key.to_string()).collect();
    // Asserted as an equality, in both directions at once, because each
    // direction catches a different regression and neither catches the other:
    // a contract that grows a page array the CLI cannot read (left side), and a
    // speculative alias re-added to PAGE_ITEM_KEYS that no endpoint emits
    // (right side — the failure this whole surface was reworked for). A
    // one-directional containment check stayed green when `items` was put back.
    assert_eq!(
        array_keys, declared,
        "the page-array spellings in the contract and PAGE_ITEM_KEYS must match exactly: \
         contract has {array_keys:?}, the CLI declares {declared:?}"
    );
}

/// Every object schema in the contract that the CLI would recognize as a list
/// page: one carrying an array-typed property under a [`PAGE_ITEM_KEYS`]
/// spelling. Walked recursively so an envelope declared **inline** on a
/// response (several are) counts exactly like a named component schema —
/// scanning only `components/schemas`, as the item-key test does, would let an
/// inline cursor envelope slip through.
fn list_envelope_properties(
    spec: &serde_json::Value,
) -> Vec<&serde_json::Map<String, serde_json::Value>> {
    fn walk<'a>(
        node: &'a serde_json::Value,
        found: &mut Vec<&'a serde_json::Map<String, serde_json::Value>>,
    ) {
        match node {
            serde_json::Value::Object(map) => {
                if let Some(properties) = map.get("properties").and_then(|p| p.as_object()) {
                    let is_page = PAGE_ITEM_KEYS.iter().any(|key| {
                        properties
                            .get(*key)
                            .and_then(|property| property.get("type"))
                            .and_then(|kind| kind.as_str())
                            == Some("array")
                    });
                    if is_page {
                        found.push(properties);
                    }
                }
                for value in map.values() {
                    walk(value, found);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(spec, &mut found);
    found
}

/// Whether a schema property may be absent/`null`. The contract spells that two
/// ways — `"type": ["string", "null"]` and `"nullable": true` — and a
/// derivation that understood only one would miss half the cursor envelopes.
fn property_is_nullable(property: &serde_json::Value) -> bool {
    if property.get("nullable").and_then(|n| n.as_bool()) == Some(true) {
        return true;
    }
    property
        .get("type")
        .and_then(|kind| kind.as_array())
        .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("null")))
}

fn property_has_type(property: &serde_json::Value, wanted: &str) -> bool {
    match property.get("type") {
        Some(serde_json::Value::String(kind)) => kind == wanted,
        Some(serde_json::Value::Array(kinds)) => {
            kinds.iter().any(|kind| kind.as_str() == Some(wanted))
        }
        _ => false,
    }
}

/// The cursor markers the walk refuses on are re-derived from the enforced
/// OpenAPI contract, exactly as [`page_item_keys_match_the_openapi_contract`]
/// re-derives the item keys — and for a sharper reason.
///
/// `PAGE_CURSOR_KEYS` was hand-maintained and documented as spec-derived. It
/// was accurate when written and became wrong without a single test going red:
/// `AdminPaymentAttemptList` added the admin contract's first `next_cursor`
/// envelope (#352), the constant did not grow the key, so `page_envelope`
/// reported `cursor = false` and `--all-pages` walked a cursor endpoint with
/// `offset`/`limit` the server ignores — up to `MAX_PAGES` requests that each
/// returned, and merged, page one. The item-key test could not catch it: it
/// only re-derives `PAGE_ITEM_KEYS`, and every cursor envelope spells its array
/// `data` like everyone else.
///
/// **The derivation.** Inside a list envelope, a cursor marker is a property
/// that is either
/// 1. **boolean-typed** — a "more pages exist" / "your cursor was reset" flag,
///    or
/// 2. **nullable-string-typed** — a resume token, which must be able to say
///    "there is no next page" and therefore must admit `null`.
///
/// Everything else in these envelopes is one of the offset-window integers
/// (`offset`/`limit`/`total`, nullable or not) or non-nullable endpoint context
/// (`object`, `run_id`, `worker_id`, `request_id`, `trust_level`) — none of
/// which can be a cursor. A name-shaped second rule backstops a hypothetical
/// cursor spelled as a **non**-nullable string, minus the offset vocabulary the
/// client already classifies elsewhere, so the union can only ever demand MORE
/// keys than rule 1 — and an extra key here merely *refuses* a walk, which is
/// the safe direction.
///
/// The consequence for the next envelope: add `{"data": [...],
/// "next_page_token": nullable string}` to the contract and this test fails
/// naming the key, instead of `--all-pages` quietly storming the admin plane.
#[test]
fn page_cursor_keys_match_the_openapi_contract() {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json"))
            .expect("the OpenAPI contract parses");
    let envelopes = list_envelope_properties(&spec);
    assert!(
        envelopes.len() > 10,
        "the derivation found only {} list envelopes, so it is not seeing the contract; \
         a vacuous scan would make this whole test pass by finding nothing",
        envelopes.len()
    );

    // Keys the client already classifies as OFFSET pagination. Excluded from
    // the name-shaped rule so a future `next_offset` — the one offset-shaped
    // name that would collide with it — is not mistaken for a cursor.
    let offset_vocabulary: std::collections::BTreeSet<&str> = PAGE_WINDOW_KEYS
        .iter()
        .chain(PAGE_TOTAL_KEYS.iter())
        .copied()
        .chain(["next_offset"])
        .collect();

    let mut markers: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for properties in &envelopes {
        for (name, property) in properties.iter() {
            if offset_vocabulary.contains(name.as_str()) {
                continue;
            }
            let by_shape = property_has_type(property, "boolean")
                || (property_is_nullable(property) && property_has_type(property, "string"));
            let by_name = name.contains("cursor")
                || name.contains("after")
                || name.starts_with("next_")
                || name == "has_more";
            if by_shape || by_name {
                markers.insert(name.clone());
            }
        }
    }

    let declared: std::collections::BTreeSet<String> =
        PAGE_CURSOR_KEYS.iter().map(|key| key.to_string()).collect();
    // Equality, in both directions, for the same reason the item-key test uses
    // one: the left side catches a contract that grew a cursor marker the walk
    // would not recognize (the #352 regression), the right side catches a
    // speculative alias re-added here that no endpoint emits (the #360 one).
    assert_eq!(
        markers, declared,
        "the cursor markers in the contract and PAGE_CURSOR_KEYS must match exactly: \
         contract has {markers:?}, the CLI declares {declared:?}"
    );
}

/// The regression the constant above exists for, expressed as behavior rather
/// than as a string list: the payment-attempt envelope **verbatim from the
/// contract** must be recognized as cursor-paginated, and `--all-pages` must
/// refuse it on the FIRST page instead of walking it by offset.
///
/// Without this, `ferrogate ctl payment-attempts list --all-pages` against a
/// tenant with more than one page of attempts issued `MAX_PAGES` requests that
/// each returned page one — a self-inflicted request storm on the admin plane,
/// reachable from a documented flag, on a money-audit surface.
#[test]
fn all_pages_refuses_the_payment_attempt_cursor_envelope() {
    // `AdminPaymentAttemptList` as the handler emits it: a full page, a
    // server-applied `limit`, no `total`, and a cursor to resume from. Every
    // one of those is what made the offset walk look legitimate.
    let page = serde_json::json!({
        "object": "list",
        "data": [{"id": "att-2"}, {"id": "att-1"}],
        "limit": 2,
        "next_cursor": "1753500000:att-1",
    });
    let envelope = page_envelope(&page).unwrap();
    assert!(
        envelope.cursor,
        "an envelope carrying next_cursor is cursor-paginated: {page}"
    );
    assert!(
        envelope.echoes_page_window(),
        "it echoes a limit, which is exactly why the windowless guard cannot catch it"
    );
    assert_eq!(
        next_page(&PageRequest::first(2), 2, None),
        Some(PageRequest {
            offset: 2,
            limit: Some(2)
        }),
        "the offset arithmetic itself is willing to advance — the refusal must come first"
    );

    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = FakeTransport {
        response: RawResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&page).unwrap(),
        },
        seen: Mutex::new(None),
    };
    let client = ControlPlaneClient::new(context, None, transport);
    let error = block_on(client.send_all_pages(&RequestSpec::get("/admin/v1/payment-attempts"), 2))
        .unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(
        error.to_string().contains("cursor-paginated"),
        "the refusal must name the reason: {error}"
    );
}

/// A cursor page reports its own continuation, and the reader must not confuse
/// the cursor the caller *used* with the one to use *next*.
#[test]
fn page_cursor_state_reads_the_continuation_not_the_echo() {
    // Not a cursor page at all.
    assert_eq!(
        page_cursor_state(&serde_json::json!({"object": "list", "data": [], "total": 0})),
        None
    );
    assert_eq!(page_cursor_state(&serde_json::json!([{"id": "a"}])), None);

    assert_eq!(
        page_cursor_state(&serde_json::json!({
            "data": [{"id": "att-1"}],
            "limit": 1,
            "next_cursor": "1753500000:att-1",
        })),
        Some(PageCursorState::Resume {
            key: "next_cursor",
            value: "1753500000:att-1".to_string(),
        })
    );
    // Null cursor: the definitive end, which is what keeps a full last page
    // from being announced as truncated.
    assert_eq!(
        page_cursor_state(&serde_json::json!({"data": [], "next_cursor": serde_json::Value::Null})),
        Some(PageCursorState::Exhausted)
    );
    // `after_event_id` is the cursor the caller ALREADY used. Resuming from it
    // would re-fetch the page in hand forever, so it is never a continuation.
    assert_eq!(
        page_cursor_state(&serde_json::json!({
            "data": [{"id": "e1"}],
            "after_event_id": "e0",
            "next_after_event_id": serde_json::Value::Null,
            "has_more": false,
        })),
        Some(PageCursorState::Exhausted)
    );
    assert_eq!(
        page_cursor_state(&serde_json::json!({
            "data": [{"id": "e1"}],
            "after_event_id": "e0",
            "next_after_event_id": "e1",
            "has_more": true,
        })),
        Some(PageCursorState::Resume {
            key: "next_after_event_id",
            value: "e1".to_string(),
        })
    );
    // An explicit `has_more: false` outranks a token the server echoed back on
    // its last page: the strongest statement available wins.
    assert_eq!(
        page_cursor_state(&serde_json::json!({
            "data": [],
            "next_after_event_id": "e1",
            "has_more": false,
        })),
        Some(PageCursorState::Exhausted)
    );
    // Cursor-paginated but silent about continuation.
    assert_eq!(
        page_cursor_state(&serde_json::json!({"data": [{"id": "e1"}], "has_more": true})),
        Some(PageCursorState::Unknown)
    );
}

/// `--sort` is documented as unhonored, and this pins that claim to the
/// contract instead of to a comment. When the server does implement sorting,
/// this test fails and forces the flag help, `docs/cli-reference.md`, and the
/// stderr note in `resource_cmd.rs` to be corrected together.
#[test]
fn sort_is_not_yet_an_openapi_query_parameter() {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json"))
            .expect("the OpenAPI contract parses");
    let mut declaring: Vec<String> = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("paths") {
        let Some(operations) = item.as_object() else {
            continue;
        };
        for (method, operation) in operations {
            let Some(parameters) = operation.get("parameters").and_then(|p| p.as_array()) else {
                continue;
            };
            if parameters
                .iter()
                .any(|parameter| parameter.get("name").and_then(|n| n.as_str()) == Some("sort"))
            {
                declaring.push(format!("{method} {path}"));
            }
        }
    }
    assert!(
        declaring.is_empty(),
        "the API now declares a `sort` query parameter on {declaring:?} — update the --sort flag \
         help, docs/cli-reference.md, and drop the 'not honored' stderr note in resource_cmd.rs"
    );
}

/// The tenant selection this client sends is documented as unhonored, and this
/// pins that claim to the contract rather than to a comment.
///
/// `prepare_request` turns a resolved tenant into an `x-ferrogate-tenant`
/// header. No operation and no component parameter in the contract declares it,
/// so the server has nothing to read it with — which is why `--tenant` exits 0
/// while returning whatever the bearer token's scope is. Three existing tests
/// assert only that the header is *sent*, and would pass just as happily if the
/// capability were entirely fictional; this one is the direction that matters.
/// The day the API declares the header, this fails and forces the flag help,
/// `docs/cli-reference.md`, and the stderr note to be corrected together.
#[test]
fn tenant_scope_is_not_yet_an_openapi_parameter() {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi/admin-api.openapi.json"))
            .expect("the OpenAPI contract parses");

    let mut declared: Vec<String> = Vec::new();
    let mut collect = |where_: String, parameters: &serde_json::Value| {
        let Some(parameters) = parameters.as_array() else {
            return;
        };
        for parameter in parameters {
            if parameter.get("name").and_then(|name| name.as_str())
                == Some(TENANT_HEADER_UNDER_TEST)
            {
                declared.push(where_.clone());
            }
        }
    };
    for (path, item) in spec["paths"].as_object().expect("paths") {
        let Some(operations) = item.as_object() else {
            continue;
        };
        for (method, operation) in operations {
            if let Some(parameters) = operation.get("parameters") {
                collect(format!("{method} {path}"), parameters);
            }
        }
    }
    if let Some(components) = spec["components"]
        .get("parameters")
        .and_then(|p| p.as_object())
    {
        for (name, parameter) in components {
            if parameter.get("name").and_then(|value| value.as_str())
                == Some(TENANT_HEADER_UNDER_TEST)
            {
                declared.push(format!("components.parameters.{name}"));
            }
        }
    }

    assert!(
        declared.is_empty(),
        "the API now declares the '{TENANT_HEADER_UNDER_TEST}' parameter on {declared:?} — honor \
         it: drop the 'not honored' wording from the --tenant flag help, regenerate \
         docs/cli-reference.md, and remove the stderr note from \
         context::unhonored_scope_notice"
    );
}

/// The header `prepare_request` emits for a resolved tenant. Named once so the
/// test above and the assertion in `prepare_request_builds_url_headers_and_body`
/// cannot drift apart from the producer at `transport.rs`.
const TENANT_HEADER_UNDER_TEST: &str = "x-ferrogate-tenant";

/// Fake transport that replies with a scripted sequence of responses and
/// records every request it saw, so a multi-page walk is provable without a
/// network.
struct ScriptedTransport {
    responses: Mutex<std::collections::VecDeque<RawResponse>>,
    seen: Mutex<Vec<PreparedRequest>>,
}

impl ScriptedTransport {
    fn new(bodies: Vec<&str>) -> ScriptedTransport {
        ScriptedTransport {
            responses: Mutex::new(
                bodies
                    .into_iter()
                    .map(|body| RawResponse {
                        status: 200,
                        headers: vec![("x-request-id".to_string(), "rid-page".to_string())],
                        body: body.as_bytes().to_vec(),
                    })
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn urls(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.url.clone())
            .collect()
    }
}

impl Transport for ScriptedTransport {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        self.seen.lock().unwrap().push(request);
        let next = self.responses.lock().unwrap().pop_front();
        Box::pin(async move {
            next.ok_or_else(|| CliError::transport("scripted transport ran out of responses"))
        })
    }
}

/// The client takes its transport by value; sharing it through an `Arc` lets
/// the test still inspect the recorded requests afterwards, without adding a
/// test-only accessor to the production client.
impl Transport for std::sync::Arc<ScriptedTransport> {
    fn execute<'a>(
        &'a self,
        request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        ScriptedTransport::execute(self.as_ref(), request)
    }
}

/// The walk visits every page and loses no row. This is the caller `next_page`
/// and `plan_all_pages` previously lacked: the arithmetic is now executed, not
/// merely described.
#[test]
fn send_all_pages_walks_every_page_and_loses_no_rows() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"a"},{"id":"b"}],"total":5,"offset":0,"limit":2}"#,
        r#"{"object":"list","data":[{"id":"c"},{"id":"d"}],"total":5,"offset":2,"limit":2}"#,
        r#"{"object":"list","data":[{"id":"e"}],"total":5,"offset":4,"limit":2}"#,
    ]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/tenant-accounts");
    let response = block_on(client.send_all_pages(&spec, 2)).unwrap();

    let items = response.body["data"].as_array().unwrap();
    let ids: Vec<&str> = items
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["a", "b", "c", "d", "e"]);
    // The server-reported total survives so the operator can cross-check.
    assert_eq!(response.body["total"], 5);
    // Per-page cursor keys would misdescribe the merged whole, so they go.
    assert!(response.body.get("offset").is_none());
    assert!(response.body.get("limit").is_none());
    // The first page's correlation metadata identifies the operator's request.
    assert_eq!(response.request_id.as_deref(), Some("rid-page"));

    let urls = transport.urls();
    assert_eq!(urls.len(), 3, "expected three page requests: {urls:?}");
    assert!(urls[0].contains("offset=0") && urls[0].contains("limit=2"));
    assert!(urls[1].contains("offset=2"));
    assert!(urls[2].contains("offset=4"));
}

/// Without a server-reported total the walk still terminates on the first
/// short page — and still returns every row it fetched.
///
/// The endpoint echoes its `offset`/`limit` window (so the walk has evidence it
/// is offset-paginated) but no `total`, which is a shape the contract really
/// produces; the walk must lean on the short page alone to stop.
#[test]
fn send_all_pages_stops_on_a_short_page_when_total_is_unknown() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"a"},{"id":"b"}],"offset":0,"limit":2}"#,
        r#"{"object":"list","data":[{"id":"c"}],"offset":2,"limit":2}"#,
        // A third response is scripted but must never be requested; asking for
        // it would exhaust nothing, so the assertion below is the real guard.
        r#"{"object":"list","data":[{"id":"never"}],"offset":4,"limit":2}"#,
    ]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/tenant-accounts");
    let response = block_on(client.send_all_pages(&spec, 2)).unwrap();

    let ids: Vec<&str> = response.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["a", "b", "c"]);
    assert_eq!(transport.urls().len(), 2);
}

/// `--all-pages` against a verb that does not return a list is an explicit
/// usage error, never a quietly single-page answer.
#[test]
fn send_all_pages_rejects_a_non_list_response() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = ScriptedTransport::new(vec![r#"{"service":"ferrogate"}"#]);
    let client = ControlPlaneClient::new(context, None, transport);
    let spec = RequestSpec::get("/admin/v1/status");
    let error = block_on(client.send_all_pages(&spec, 50)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(
        error.to_string().contains("--all-pages"),
        "message must name the flag: {error}"
    );
}

/// **The blocker this rework exists for.** An empty page in the middle of a
/// collection the server says holds 5 rows ends iteration — and the walk must
/// then FAIL, not hand back 2 rows with a success exit.
///
/// This is reachable in production, not a contrived shape: a concurrent delete,
/// or a server that applies a post-paging filter, produces exactly this. Before
/// the completeness check, `next_page`'s `returned == 0` arm returned `None`
/// before consulting the known total and the CLI printed 2 of 5 rows, exit 0,
/// no diagnostic — the silent truncation the Scope bullet forbids, inside the
/// code written to prevent it.
#[test]
fn send_all_pages_fails_on_an_empty_page_inside_a_known_total() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"a"},{"id":"b"}],"total":5,"offset":0,"limit":2}"#,
        r#"{"object":"list","data":[],"total":5,"offset":2,"limit":2}"#,
    ]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/tenant-accounts");
    let error = block_on(client.send_all_pages(&spec, 2)).unwrap_err();

    assert_ne!(
        error.exit_class(),
        ExitClass::Success,
        "a short walk must not be a success"
    );
    let message = error.to_string();
    assert!(
        message.contains("fetched 2 of the 5 rows"),
        "the operator must be told how many rows were missed: {message}"
    );
    assert_eq!(
        transport.urls().len(),
        2,
        "the walk still stops at the empty page rather than spinning"
    );
}

/// A short *final* page against a known total is still a completed walk: the
/// completeness check must not turn every legitimate walk into an error. The
/// negative twin of the test above.
#[test]
fn send_all_pages_accepts_a_walk_that_reaches_the_reported_total() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"a"},{"id":"b"}],"total":3,"offset":0,"limit":2}"#,
        r#"{"object":"list","data":[{"id":"c"}],"total":3,"offset":2,"limit":2}"#,
    ]);
    let client = ControlPlaneClient::new(context, None, transport);
    let spec = RequestSpec::get("/admin/v1/tenant-accounts");
    let response = block_on(client.send_all_pages(&spec, 2)).unwrap();
    assert_eq!(response.body["data"].as_array().unwrap().len(), 3);
}

/// A collection that legitimately shrank mid-walk is judged against the total
/// the server most recently reported, not a stale one — otherwise a concurrent
/// delete would make an honest, complete walk fail.
#[test]
fn send_all_pages_honors_the_freshest_reported_total() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"a"},{"id":"b"}],"total":5,"offset":0,"limit":2}"#,
        // Two rows were deleted between pages; the server now says 3.
        r#"{"object":"list","data":[{"id":"c"}],"total":3,"offset":2,"limit":2}"#,
    ]);
    let client = ControlPlaneClient::new(context, None, transport);
    let spec = RequestSpec::get("/admin/v1/tenant-accounts");
    let response = block_on(client.send_all_pages(&spec, 2)).unwrap();
    assert_eq!(response.body["data"].as_array().unwrap().len(), 3);
}

/// `--all-pages` on a mutating verb is rejected **before** a byte is sent.
///
/// The flag is augmented onto every verb, so `ctl projects delete p-1
/// --all-pages` used to issue the DELETE, have the server delete the project,
/// and only then report "usage error" — telling the operator the invocation was
/// malformed after the destructive change had already committed. The scripted
/// transport records every request it saw, so "nothing was sent" is asserted,
/// not assumed.
#[test]
fn send_all_pages_rejects_a_mutating_verb_before_sending_it() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![r#"{"deleted":true}"#]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::new(http::Method::DELETE, "/admin/v1/projects/proj-1");

    let error = block_on(client.send_all_pages(&spec, 50)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(
        error.to_string().contains("DELETE"),
        "the message must name the method that was refused: {error}"
    );
    assert!(
        transport.urls().is_empty(),
        "the mutation must NOT have been sent: {:?}",
        transport.urls()
    );
}

/// A cursor-paginated endpoint is refused after one page instead of becoming a
/// 10 000-request storm.
///
/// The walk speaks `offset`/`limit`; the event-stream endpoints paginate by
/// `after_event_id`/`has_more` and ignore both. Every iteration therefore
/// re-fetched page one: never a short page, never a total, so the loop ran to
/// `MAX_PAGES` and buffered 10 000 pages of duplicated rows before erroring.
/// Detection is on the response envelope, not on a hard-coded list of resource
/// nouns, so a future cursor endpoint is covered by the same rule.
#[test]
fn send_all_pages_refuses_a_cursor_paginated_endpoint() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"e1"}],"limit":1,"has_more":true,"next_after_event_id":"e1"}"#,
    ]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/agent-jobs/job-1/events");

    let error = block_on(client.send_all_pages(&spec, 1)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(
        error.to_string().contains("cursor-paginated"),
        "the message must state the rule: {error}"
    );
    assert_eq!(
        transport.urls().len(),
        1,
        "exactly one page is fetched before refusing, not MAX_PAGES"
    );
}

/// **The storm, in its broad form.** An endpoint that supports *neither*
/// pagination style carries no cursor marker, so the cursor rule never fires;
/// it ignores `offset`/`limit` and returns the whole collection on every
/// request. Full page + no `total` ⇒ `next_page` advances ⇒ the identical rows
/// come back ⇒ 10 000 requests.
///
/// This shape is the majority of the contract, not a curiosity: a structural
/// parse puts 43 of the 65 `list*` operations here (no `limit`/`offset` query
/// parameter declared, no `total`/`limit`/`offset` echoed) — `listVirtualKeys`
/// and `listAssets` among them. The walk must refuse after the first page.
#[test]
fn send_all_pages_refuses_an_endpoint_that_echoes_no_page_window() {
    let context = context_with_endpoint("https://prod.example.com", None);
    // The same full page every time — the server ignored offset entirely.
    let page = r#"{"object":"list","data":[{"id":"vk-1"},{"id":"vk-2"}]}"#;
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![page, page, page]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/virtual-keys");

    let error = block_on(client.send_all_pages(&spec, 2)).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Usage);
    assert!(
        error
            .to_string()
            .contains("echoes no offset, limit, or total"),
        "the message must name the missing signal, not just fail: {error}"
    );
    assert_eq!(
        transport.urls().len(),
        1,
        "exactly one page may be fetched before refusing, not MAX_PAGES"
    );
}

/// The negative twin: a windowless endpoint whose single page is *short* has
/// already returned everything, so the walk completes rather than failing.
/// Without this the guard could be a blanket refusal of every windowless
/// endpoint and still look correct.
#[test]
fn send_all_pages_completes_when_a_windowless_endpoint_returns_a_short_page() {
    let context = context_with_endpoint("https://prod.example.com", None);
    let transport = std::sync::Arc::new(ScriptedTransport::new(vec![
        r#"{"object":"list","data":[{"id":"vk-1"}]}"#,
    ]));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/virtual-keys");

    let response = block_on(client.send_all_pages(&spec, 2)).unwrap();
    assert_eq!(response.body["data"].as_array().unwrap().len(), 1);
    assert_eq!(transport.urls().len(), 1);
}

/// A transport that answers every request with the same body, forever, and
/// counts what it served. Distinct from [`ScriptedTransport`], which runs out:
/// a walk that never terminates cannot be modeled by a finite script.
struct EndlessTransport {
    body: String,
    served: Mutex<u32>,
}

impl EndlessTransport {
    fn new(body: &str) -> EndlessTransport {
        EndlessTransport {
            body: body.to_string(),
            served: Mutex::new(0),
        }
    }

    fn served(&self) -> u32 {
        *self.served.lock().unwrap()
    }
}

impl Transport for std::sync::Arc<EndlessTransport> {
    fn execute<'a>(
        &'a self,
        _request: PreparedRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CliResult<RawResponse>> + Send + 'a>>
    {
        *self.served.lock().unwrap() += 1;
        let body = self.body.as_bytes().to_vec();
        Box::pin(async move {
            Ok(RawResponse {
                status: 200,
                headers: vec![("x-request-id".to_string(), "rid-endless".to_string())],
                body,
            })
        })
    }
}

/// `MAX_PAGES` is load-bearing, and this is what proves it.
///
/// The window check (above) refuses an endpoint that admits it is not
/// offset-paginating. What it cannot catch is a server that *echoes* `offset`
/// and `limit` — so it looks like a well-behaved offset endpoint — and then
/// ignores them, handing back the same full page while reporting no `total`.
/// Every stop condition is defeated: never short, never empty, no total to
/// reach. Only the page cap ends it.
///
/// Delete `MAX_PAGES` (turn the bounded `for` into a `loop`) and this test does
/// not pass more quietly — it never terminates. Before this fixture existed the
/// constant could be removed with the whole suite staying green, which is the
/// definition of an untested guard.
#[test]
fn send_all_pages_gives_up_at_the_page_cap_when_the_server_never_advances() {
    let context = context_with_endpoint("https://prod.example.com", None);
    // Echoes a page window, so it is not refused as windowless — and then
    // serves the identical row no matter what offset was asked for.
    let transport = std::sync::Arc::new(EndlessTransport::new(
        r#"{"object":"list","data":[{"id":"stuck"}],"offset":0,"limit":1}"#,
    ));
    let client = ControlPlaneClient::new(context, None, std::sync::Arc::clone(&transport));
    let spec = RequestSpec::get("/admin/v1/tenant-accounts");

    let error = block_on(client.send_all_pages(&spec, 1)).unwrap_err();
    assert_eq!(
        error.exit_class(),
        ExitClass::Transport,
        "a server that never finishes paging is a transport-class failure, not the \
         operator's usage error: {error}"
    );
    assert!(
        error.to_string().contains("gave up after"),
        "the operator must be told the walk hit the cap: {error}"
    );
    assert_eq!(
        transport.served(),
        MAX_PAGES,
        "the cap is what stopped the walk"
    );
}

/// Merging must not leave per-page cursor keys describing the merged whole: a
/// `has_more`/`next_offset` copied off page one is false about the union.
#[test]
fn merged_pages_drop_every_per_page_cursor_key() {
    let merged = merge_pages(
        serde_json::json!({
            "object": "list",
            "data": [],
            "total": 2,
            "offset": 0,
            "limit": 1,
            "next_offset": 1,
            "has_more": true,
            "next_after_event_id": "e1",
        }),
        Some("data"),
        vec![
            serde_json::json!({"id": "a"}),
            serde_json::json!({"id": "b"}),
        ],
    );
    assert_eq!(merged["data"].as_array().unwrap().len(), 2);
    // The collection-wide count survives so the operator can cross-check.
    assert_eq!(merged["total"], 2);
    assert_eq!(merged["object"], "list");
    for stale in [
        "offset",
        "limit",
        "next_offset",
        "has_more",
        "next_after_event_id",
    ] {
        assert!(
            merged.get(stale).is_none(),
            "'{stale}' describes one page and must not survive the merge: {merged}"
        );
    }
}
