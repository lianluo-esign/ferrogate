// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Genuine create -> read -> update -> delete round trips for the
// #361 tenant/project/workspace and policy/quota command families, driven
// through the REAL `ferrogate` binary against a scripted loopback mock.
//
// Why this file exists (issue #361 review, finding 2). #361's acceptance clause
// asks for CRUD *round trips*. What existed was:
//
//   * `control_cli_resource_e2e.rs` - a real-binary round trip, but only for the
//     secret-bearing virtual-key family (and only single legs elsewhere).
//   * `organization_test.rs` / `iam_test.rs` - a single `create` against a fake
//     transport for tenant/project/workspace, plus path-string assertions for
//     policy/quota with NO transport-level coverage at all.
//   * `every_declared_verb_builds_a_request` - proof that each verb *builds* a
//     request, which is not a round trip: it never sends one, never sees a
//     response, and never renders anything.
//
// So "CRUD round trips are proved" was, for five of the six named families,
// held up by nothing. This file closes that at the same level as the approved
// secret-bearing test: the shipped binary, a loopback socket, a tempdir CLI
// home; no gateway, database, or network egress.
//
// Every leg is pinned on BOTH sides, because a round trip that only checks the
// final read is satisfied by a CLI that sent the wrong method to the wrong path
// with a mangled body and got lucky:
//
//   * what the mock RECEIVED - method, exact path (including the composite
//     `scope_type/scope_id` quota key), and the verbatim request document; and
//   * what the CLI RENDERED - for a read, the server's bare document; for a
//     mutation, the #505 `MutationReceipt` envelope, whose `response` field
//     carries the server document and whose attested fields must agree with the
//     leg that was actually issued (operation id, method, path, resource id,
//     HTTP status, correlation id).
//
// The mock is SCRIPTED: replies are consumed in order and an unscripted request
// is answered with a loud 500, so a CLI that issues an extra request - or skips
// one - fails rather than silently reusing a stale reply.

#[allow(dead_code)]
mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ferrogate_control_plane_client::action_identity::{
    ACTION_ID_HEADER, CLIENT_CLOCK_HEADER, TIME_TOKEN_HEADER,
};
use serde_json::{json, Value};

// ----- process helpers -------------------------------------------------------

/// Run the real binary with a pristine environment: no ambient endpoint,
/// context, tenant, or timeout can leak in from the developer's shell.
fn base_cmd(home: &Path) -> Command {
    let mut command = support::ferrogate_command();
    for var in [
        "FERROGATE_ENDPOINT",
        "FERROGATE_CONTEXT",
        "FERROGATE_TENANT",
        "FERROGATE_TIMEOUT_MILLIS",
    ] {
        command.env_remove(var);
    }
    command.env("FERROGATE_CLI_HOME", home);
    command
}

/// One `ferrogate ctl <args...> --endpoint <mock> --output json` invocation.
fn run_ctl(home: &Path, endpoint: &str, args: &[&str]) -> Output {
    base_cmd(home)
        .arg("ctl")
        .args(args)
        .args(["--endpoint", endpoint, "--output", "json"])
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exited via signal")
}

/// stdout parsed as JSON. stdout is data-only on success, so this must succeed.
fn json_stdout(output: &Output) -> Value {
    serde_json::from_str(stdout(output).trim()).unwrap_or_else(|error| {
        panic!(
            "stdout must be JSON ({error}): stdout={:?} stderr={:?}",
            stdout(output),
            stderr(output)
        )
    })
}

/// Assert a leg exited 0, surfacing stderr when it did not.
fn assert_ok(output: &Output, leg: &str) {
    assert_eq!(
        code(output),
        0,
        "{leg} must succeed; stderr: {}",
        stderr(output)
    );
}

// ----- scripted, body-capturing HTTP mock ------------------------------------

/// One request the mock actually received. The request *document* is captured,
/// not just the request line: a PATCH that reached the right URL with the wrong
/// body is exactly the defect an unpinned round trip hides.
#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl RecordedRequest {
    /// `METHOD /path?query`, for a single exact assertion per leg.
    fn line(&self) -> String {
        format!("{} {}", self.method, self.path)
    }

    /// The request document the CLI put on the wire.
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|error| panic!("request body must be JSON ({error}): {}", self.body))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockServer {
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// The nth request the mock saw, in arrival order.
    fn nth(&self, index: usize) -> RecordedRequest {
        let requests = self.requests.lock().unwrap();
        requests.get(index).cloned().unwrap_or_else(|| {
            panic!(
                "expected at least {} requests, saw {}: {:?}",
                index + 1,
                requests.len(),
                requests
                    .iter()
                    .map(RecordedRequest::line)
                    .collect::<Vec<_>>()
            )
        })
    }
}

/// A scripted reply: HTTP status, reason phrase, correlation id, and document.
fn reply(status: u16, reason: &str, request_id: &str, body: &Value) -> String {
    reply_with_headers(status, reason, request_id, &[], body)
}

fn reply_with_headers(
    status: u16,
    reason: &str,
    request_id: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> String {
    let body = body.to_string();
    let mut rendered_headers = String::new();
    for (name, value) in headers {
        rendered_headers.push_str(name);
        rendered_headers.push_str(": ");
        rendered_headers.push_str(value);
        rendered_headers.push_str("\r\n");
    }
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         content-type: application/json\r\n\
         x-request-id: {request_id}\r\n\
         {rendered_headers}\
         \r\n\
         {body}",
        body.len()
    )
}

fn time_token_reply(request: &RecordedRequest) -> String {
    let action_id = request.header(ACTION_ID_HEADER).unwrap_or_else(|| {
        panic!("time-token challenge carried no {ACTION_ID_HEADER}: {request:?}")
    });
    let issued_at = request.header(CLIENT_CLOCK_HEADER).unwrap_or("1800000000");
    let token = format!("v1;issued_at={issued_at};ttl=300;action_id={action_id};sig=test");
    reply_with_headers(
        200,
        "OK",
        "rid-time-token",
        &[(TIME_TOKEN_HEADER, token)],
        &json!({"status": "ok"}),
    )
}

/// The reply an *unscripted* request gets. Loud on purpose: a round trip that
/// issues one request too many (or reorders its legs) must fail, not silently
/// reuse the previous leg's document.
fn unscripted_reply() -> String {
    reply(
        500,
        "Internal Server Error",
        "rid-unscripted",
        &json!({"error": {"code": "unscripted_request", "message": "the scripted mock ran out of replies"}}),
    )
}

/// A loopback server that records every request (method, path, body) and
/// answers `script` in order.
fn spawn_mock(script: Vec<String>) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&requests);
    thread::spawn(move || {
        let mut script = script.into_iter();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let response = if let Some(request) = read_request(&mut stream) {
                if request.method == "GET" && request.path == "/healthz" {
                    time_token_reply(&request)
                } else {
                    sink.lock().unwrap().push(request);
                    script.next().unwrap_or_else(unscripted_reply)
                }
            } else {
                unscripted_reply()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    MockServer {
        base_url: format!("http://127.0.0.1:{port}"),
        requests,
    }
}

/// Read one whole HTTP request: the request line plus `Content-Length` bytes of
/// body. Reading only the first line (as the single-leg fixtures do) would make
/// the request document unassertable.
fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_millis(2_000)))
        .ok();
    let mut raw: Vec<u8> = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        raw.extend_from_slice(&buffer[..read]);
        let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
        let length = content_length(&head);
        let body_start = header_end + 4;
        if raw.len() - body_start < length {
            continue;
        }
        let body = String::from_utf8_lossy(&raw[body_start..body_start + length]).into_owned();
        let mut parts = head.lines().next()?.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let headers = head
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect();
        return Some(RecordedRequest {
            method,
            path,
            headers,
            body,
        });
    }
    None
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

// ----- leg assertions --------------------------------------------------------

/// What `target.resource_id` must say for one leg.
///
/// The three arms are the three outcomes `ReceiptRenderer::attested_resource_id`
/// can produce for a leg that got an answer, and the split between the last two
/// is #505's box 5: a create used to leave this null with
/// `collection_scoped_mutation` — "the server assigns the id in the response" —
/// *after* the response carrying that id had already arrived, so an audit query
/// keyed on `target.resource_id` could not say what had been created. The
/// harvest is now the contract, and `response_names_no_resource_id` is reserved
/// for a document that genuinely names none.
#[derive(Clone, Copy)]
enum ExpectResourceId<'a> {
    /// An item-scoped verb: the receipt echoes the id the OPERATOR addressed,
    /// which is in the request path.
    Addressed(&'a str),
    /// A collection-scoped create: the verb addressed no id, so the receipt
    /// must have harvested the one the SERVER assigned out of the response
    /// document. The leg also asserts the id is absent from the request path,
    /// which is what distinguishes this from [`Self::Addressed`] — otherwise
    /// a renderer that only ever echoed the path would satisfy both.
    HarvestedFromResponse(&'a str),
    /// A collection-scoped create whose response document names no id at all,
    /// so the honest answer is the stated reason. The leg also asserts the
    /// response really carries no `id`/`policy_id`, so this arm cannot quietly
    /// become the place a failed harvest hides.
    NoIdInResponse,
}

/// What a mutating leg's #505 receipt must say about the call it just made.
struct ReceiptExpect<'a> {
    group: &'a str,
    verb: &'a str,
    /// The OpenAPI operation the verb declares. Asserting it here is what ties
    /// the registry's parity metadata to the request that was really issued.
    operation_id: &'a str,
    method: &'a str,
    path: &'a str,
    resource_id: ExpectResourceId<'a>,
    status: u16,
    request_id: &'a str,
}

/// Whether a mutation response document names an id anywhere the receipt's
/// harvest looks: the envelope's own keys, and the single resource object it
/// wraps. Written here rather than imported so this test states the shape it
/// expects instead of agreeing with the code under test by construction.
fn document_names_an_id(response: &Value) -> bool {
    let names_id = |object: &Value| {
        ["id", "policy_id"]
            .iter()
            .any(|key| object.get(key).is_some_and(|value| !value.is_null()))
    };
    if names_id(response) {
        return true;
    }
    response
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, value)| key.as_str() != "object" && value.is_object())
        .any(|(_, value)| names_id(value))
}

/// Assert a mutating verb rendered a well-formed `MutationReceipt` describing
/// *this* leg, with the server's document nested under `response`.
///
/// #505 replaced the bare response body of a mutating verb with this envelope,
/// so every assertion here would be wrong if written against the pre-#505
/// shape - `stdout["id"]` is now `stdout["response"]["…"]["id"]`.
fn assert_receipt(rendered: &Value, expect: ReceiptExpect<'_>, response: &Value) {
    let leg = format!("{} {}", expect.group, expect.verb);
    assert_eq!(
        rendered["object"], "mutation_receipt",
        "{leg}: a mutating verb renders a receipt envelope: {rendered}"
    );
    assert_eq!(rendered["receipt_version"], 1, "{leg}: {rendered}");
    assert_eq!(rendered["group"], expect.group, "{leg}: {rendered}");
    assert_eq!(rendered["verb"], expect.verb, "{leg}: {rendered}");
    assert_eq!(
        rendered["operation_id"]["value"], expect.operation_id,
        "{leg}: the receipt names the declared operation: {rendered}"
    );
    assert_eq!(
        rendered["dry_run"], false,
        "{leg}: this leg really executed: {rendered}"
    );
    assert_eq!(
        rendered["target"]["method"], expect.method,
        "{leg}: {rendered}"
    );
    assert_eq!(rendered["target"]["path"], expect.path, "{leg}: {rendered}");
    match expect.resource_id {
        ExpectResourceId::Addressed(id) => assert_eq!(
            rendered["target"]["resource_id"]["value"], id,
            "{leg}: the receipt names the addressed item: {rendered}"
        ),
        ExpectResourceId::HarvestedFromResponse(id) => {
            assert!(
                !expect.path.contains(id),
                "{leg}: this leg is only evidence of a HARVEST if the id is absent \
                 from the request path {:?}",
                expect.path
            );
            assert_eq!(
                rendered["target"]["resource_id"]["value"], id,
                "{leg}: a create must name the id the server assigned, not a null \
                 with a reason (#505 box 5): {rendered}"
            );
        }
        ExpectResourceId::NoIdInResponse => {
            assert!(
                !document_names_an_id(response),
                "{leg}: this arm claims the response document names no id, but it \
                 does: {response}"
            );
            assert_eq!(
                rendered["target"]["resource_id"]["absent_reason"]["code"],
                "response_names_no_resource_id",
                "{leg}: a create whose document names no id says so with a code: {rendered}"
            );
        }
    }
    assert_eq!(
        rendered["http_status"]["value"], expect.status,
        "{leg}: {rendered}"
    );
    assert_eq!(
        rendered["correlation"]["request_id"]["value"], expect.request_id,
        "{leg}: the receipt carries this leg's correlation id: {rendered}"
    );
    assert_eq!(
        &rendered["response"], response,
        "{leg}: the server document is nested verbatim under `response`: {rendered}"
    );
    // The gap #505 exists to record: no Control Plane API mutation returns an
    // audit id, so the receipt must say so with a code rather than omit it.
    assert!(rendered["audit_id"]["value"].is_null(), "{leg}: {rendered}");
    assert_eq!(
        rendered["audit_id"]["absent_reason"]["code"], "endpoint_returns_no_audit_id",
        "{leg}: {rendered}"
    );
    // None of these families is a revision chain, so the reversal pointer is a
    // stated absence, not a missing key.
    assert_eq!(
        rendered["rollback"]["absent_reason"]["code"], "resource_has_no_revisions",
        "{leg}: {rendered}"
    );
    assert_eq!(
        rendered["target"]["action_fingerprint_contract"], "canonical_target_sha256",
        "{leg}: {rendered}"
    );
    let fingerprint = rendered["target"]["action_fingerprint"]
        .as_str()
        .unwrap_or_default();
    assert!(
        fingerprint
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64
                && hex
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())),
        "{leg}: action fingerprint is sha256:<64 lowercase hex>, got {fingerprint:?}"
    );
}

/// Assert a READ leg rendered the server's bare document, not a receipt. This
/// is the other half of the #505 contract: a read must NOT be wrapped, so an
/// operator piping `ctl … get` still gets the resource.
fn assert_bare_document(rendered: &Value, leg: &str) {
    assert_ne!(
        rendered["object"], "mutation_receipt",
        "{leg}: a read renders the server document bare: {rendered}"
    );
    assert!(
        rendered.get("receipt_version").is_none(),
        "{leg}: a read carries no receipt envelope: {rendered}"
    );
}

/// A read leg carries no request document at all.
fn assert_no_request_body(request: &RecordedRequest, leg: &str) {
    assert!(
        request.body.is_empty(),
        "{leg}: a read must not put a document on the wire, got {:?}",
        request.body
    );
}

// ----- tenant accounts: create -> read -> update -> replace -------------------

/// The tenant leg of the acceptance clause.
///
/// The `D` of CRUD is proved ABSENT rather than skipped: the contract declares
/// no `DELETE /admin/v1/tenant-accounts/{tenant_id}` (only GET/PUT/PATCH on the
/// item, plus `/plan` and `/resolved-defaults`), so `TenantAccountsGroup`
/// declares no `delete` verb. The last leg asserts the binary refuses it and
/// sends nothing — which is a stronger statement than a missing test, because a
/// future `delete` verb added without a contract operation breaks it.
#[test]
fn tenant_account_crud_round_trip_pins_every_leg() {
    let home = tempfile::tempdir().unwrap();
    let created = json!({
        "object": "tenant_account",
        "tenant": {
            "id": "tn-1", "name": "Acme", "slug": "acme", "status": "active",
            "plan_id": "free", "created_at_unix": 1000, "updated_at_unix": 1000
        }
    });
    let read_back = created.clone();
    let updated = json!({
        "object": "tenant_account",
        "tenant": {
            "id": "tn-1", "name": "Acme Rebrand", "slug": "acme", "status": "active",
            "plan_id": "free", "created_at_unix": 1000, "updated_at_unix": 1100
        }
    });
    let replaced = json!({
        "object": "tenant_account",
        "tenant": {
            "id": "tn-1", "name": "Acme Rebrand", "slug": "acme", "status": "suspended",
            "plan_id": "pro", "created_at_unix": 1000, "updated_at_unix": 1200
        }
    });
    let mock = spawn_mock(vec![
        reply(201, "Created", "rid-tn-create", &created),
        reply(200, "OK", "rid-tn-get", &read_back),
        reply(200, "OK", "rid-tn-update", &updated),
        reply(200, "OK", "rid-tn-replace", &replaced),
        reply(200, "OK", "rid-tn-reread", &replaced),
    ]);

    // C - POST the collection.
    let create_doc = json!({"id": "tn-1", "name": "Acme", "slug": "acme", "plan_id": "free"});
    let create = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "tenant-accounts",
            "create",
            "--data",
            &create_doc.to_string(),
        ],
    );
    assert_ok(&create, "tenant create");
    assert_eq!(
        mock.nth(0).line(),
        "POST /admin/v1/tenant-accounts",
        "create posts the collection"
    );
    assert_eq!(
        mock.nth(0).json(),
        create_doc,
        "the operator's document reaches the wire verbatim"
    );
    assert_receipt(
        &json_stdout(&create),
        ReceiptExpect {
            group: "tenant-accounts",
            verb: "create",
            operation_id: "createTenantAccount",
            method: "POST",
            path: "/admin/v1/tenant-accounts",
            resource_id: ExpectResourceId::HarvestedFromResponse("tn-1"),
            status: 201,
            request_id: "rid-tn-create",
        },
        &created,
    );

    // R - GET the item the create returned.
    let get = run_ctl(
        home.path(),
        &mock.base_url,
        &["tenant-accounts", "get", "tn-1"],
    );
    assert_ok(&get, "tenant get");
    assert_eq!(mock.nth(1).line(), "GET /admin/v1/tenant-accounts/tn-1");
    assert_no_request_body(&mock.nth(1), "tenant get");
    let read = json_stdout(&get);
    assert_bare_document(&read, "tenant get");
    assert_eq!(
        read["tenant"]["id"], "tn-1",
        "the created tenant reads back"
    );
    assert_eq!(read["tenant"]["name"], "Acme");

    // U - PATCH the item.
    let update_doc = json!({"name": "Acme Rebrand"});
    let update = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "tenant-accounts",
            "update",
            "tn-1",
            "--data",
            &update_doc.to_string(),
        ],
    );
    assert_ok(&update, "tenant update");
    assert_eq!(mock.nth(2).line(), "PATCH /admin/v1/tenant-accounts/tn-1");
    assert_eq!(mock.nth(2).json(), update_doc);
    let update_receipt = json_stdout(&update);
    assert_receipt(
        &update_receipt,
        ReceiptExpect {
            group: "tenant-accounts",
            verb: "update",
            operation_id: "updateTenantAccount",
            method: "PATCH",
            path: "/admin/v1/tenant-accounts/tn-1",
            resource_id: ExpectResourceId::Addressed("tn-1"),
            status: 200,
            request_id: "rid-tn-update",
        },
        &updated,
    );
    // The receipt harvests the changed object's version from the response, so
    // an operator can tell the mutation moved the object forward.
    assert_eq!(
        update_receipt["target"]["object_version"]["value"], "1100",
        "the receipt reports the version the update produced: {update_receipt}"
    );

    // U (full replacement) - PUT the item.
    let replace_doc = json!({
        "id": "tn-1", "name": "Acme Rebrand", "slug": "acme",
        "status": "suspended", "plan_id": "pro"
    });
    let replace = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "tenant-accounts",
            "replace",
            "tn-1",
            "--data",
            &replace_doc.to_string(),
        ],
    );
    assert_ok(&replace, "tenant replace");
    assert_eq!(mock.nth(3).line(), "PUT /admin/v1/tenant-accounts/tn-1");
    assert_eq!(mock.nth(3).json(), replace_doc);
    assert_receipt(
        &json_stdout(&replace),
        ReceiptExpect {
            group: "tenant-accounts",
            verb: "replace",
            operation_id: "replaceTenantAccount",
            method: "PUT",
            path: "/admin/v1/tenant-accounts/tn-1",
            resource_id: ExpectResourceId::Addressed("tn-1"),
            status: 200,
            request_id: "rid-tn-replace",
        },
        &replaced,
    );

    // R again - the mutations are visible on a fresh read.
    let reread = run_ctl(
        home.path(),
        &mock.base_url,
        &["tenant-accounts", "get", "tn-1"],
    );
    assert_ok(&reread, "tenant re-read");
    assert_eq!(mock.nth(4).line(), "GET /admin/v1/tenant-accounts/tn-1");
    let final_read = json_stdout(&reread);
    assert_bare_document(&final_read, "tenant re-read");
    assert_eq!(final_read["tenant"]["status"], "suspended");
    assert_eq!(final_read["tenant"]["plan_id"], "pro");

    // D - not in the contract, so not a verb, so not a request.
    let delete = run_ctl(
        home.path(),
        &mock.base_url,
        &["tenant-accounts", "delete", "tn-1"],
    );
    assert_eq!(
        code(&delete),
        2,
        "tenant-accounts declares no delete verb (the contract has no \
         DELETE /admin/v1/tenant-accounts/{{tenant_id}}): {}",
        stderr(&delete)
    );
    assert_eq!(
        mock.count(),
        5,
        "an unwired verb must not reach the wire at all"
    );
}

// ----- projects: create -> read -> update -> delete ---------------------------

#[test]
fn project_crud_round_trip_pins_every_leg() {
    let home = tempfile::tempdir().unwrap();
    let created = json!({
        "object": "project",
        "project": {
            "id": "prj-1", "tenant_id": "tn-1", "name": "Payments", "slug": "payments",
            "status": "active", "created_at_unix": 2000, "updated_at_unix": 2000
        }
    });
    let updated = json!({
        "object": "project",
        "project": {
            "id": "prj-1", "tenant_id": "tn-1", "name": "Payments Core", "slug": "payments",
            "status": "active", "created_at_unix": 2000, "updated_at_unix": 2100
        }
    });
    let deleted = json!({"object": "project", "id": "prj-1", "deleted": true});
    let gone = json!({"error": {
        "message": "no such project", "type": "ferrogate_error",
        "code": "not_found", "request_id": "rid-prj-gone"
    }});
    let mock = spawn_mock(vec![
        reply(201, "Created", "rid-prj-create", &created),
        reply(200, "OK", "rid-prj-get", &created),
        reply(200, "OK", "rid-prj-update", &updated),
        reply(200, "OK", "rid-prj-delete", &deleted),
        reply(404, "Not Found", "rid-prj-gone", &gone),
    ]);

    // C
    let create_doc = json!({"tenant_id": "tn-1", "name": "Payments", "slug": "payments"});
    let create = run_ctl(
        home.path(),
        &mock.base_url,
        &["projects", "create", "--data", &create_doc.to_string()],
    );
    assert_ok(&create, "project create");
    assert_eq!(mock.nth(0).line(), "POST /admin/v1/projects");
    assert_eq!(mock.nth(0).json(), create_doc);
    assert_receipt(
        &json_stdout(&create),
        ReceiptExpect {
            group: "projects",
            verb: "create",
            operation_id: "createProject",
            method: "POST",
            path: "/admin/v1/projects",
            resource_id: ExpectResourceId::HarvestedFromResponse("prj-1"),
            status: 201,
            request_id: "rid-prj-create",
        },
        &created,
    );

    // R
    let get = run_ctl(home.path(), &mock.base_url, &["projects", "get", "prj-1"]);
    assert_ok(&get, "project get");
    assert_eq!(mock.nth(1).line(), "GET /admin/v1/projects/prj-1");
    assert_no_request_body(&mock.nth(1), "project get");
    let read = json_stdout(&get);
    assert_bare_document(&read, "project get");
    assert_eq!(read["project"]["id"], "prj-1");
    assert_eq!(read["project"]["name"], "Payments");
    // A read is NOT redacted for this family (it holds no one-time secret), and
    // stdout stays data-only with the correlation id on stderr.
    assert!(
        stderr(&get).contains("request-id: rid-prj-get"),
        "correlation id on stderr: {}",
        stderr(&get)
    );
    assert!(
        !stdout(&get).contains("request-id"),
        "stdout stays data-only: {}",
        stdout(&get)
    );

    // U
    let update_doc = json!({"name": "Payments Core"});
    let update = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "projects",
            "update",
            "prj-1",
            "--data",
            &update_doc.to_string(),
        ],
    );
    assert_ok(&update, "project update");
    assert_eq!(mock.nth(2).line(), "PATCH /admin/v1/projects/prj-1");
    assert_eq!(mock.nth(2).json(), update_doc);
    assert_receipt(
        &json_stdout(&update),
        ReceiptExpect {
            group: "projects",
            verb: "update",
            operation_id: "updateProject",
            method: "PATCH",
            path: "/admin/v1/projects/prj-1",
            resource_id: ExpectResourceId::Addressed("prj-1"),
            status: 200,
            request_id: "rid-prj-update",
        },
        &updated,
    );

    // D
    let delete = run_ctl(
        home.path(),
        &mock.base_url,
        &["projects", "delete", "prj-1"],
    );
    assert_ok(&delete, "project delete");
    assert_eq!(mock.nth(3).line(), "DELETE /admin/v1/projects/prj-1");
    assert_no_request_body(&mock.nth(3), "project delete");
    let delete_receipt = json_stdout(&delete);
    assert_receipt(
        &delete_receipt,
        ReceiptExpect {
            group: "projects",
            verb: "delete",
            operation_id: "deleteProject",
            method: "DELETE",
            path: "/admin/v1/projects/prj-1",
            resource_id: ExpectResourceId::Addressed("prj-1"),
            status: 200,
            request_id: "rid-prj-delete",
        },
        &deleted,
    );
    // A delete response names no revision/version, so the receipt reports the
    // absence with its code instead of a bare null.
    assert_eq!(
        delete_receipt["target"]["object_version"]["absent_reason"]["code"],
        "response_carries_no_object_version",
        "delete receipt: {delete_receipt}"
    );

    // R after D - the object is gone, and the CLI maps that to the stable
    // not-found exit class with nothing on stdout.
    let after = run_ctl(home.path(), &mock.base_url, &["projects", "get", "prj-1"]);
    assert_eq!(
        code(&after),
        4,
        "reading a deleted project -> NotFoundConflict (exit 4): {}",
        stderr(&after)
    );
    assert_eq!(mock.nth(4).line(), "GET /admin/v1/projects/prj-1");
    assert!(
        stdout(&after).trim().is_empty(),
        "no data on stdout for a failed read: {}",
        stdout(&after)
    );
    assert!(
        stderr(&after).contains("no such project"),
        "server message surfaced: {}",
        stderr(&after)
    );
}

// ----- workspaces: create -> read -> replace -> update -> delete --------------

#[test]
fn workspace_crud_round_trip_pins_every_leg() {
    let home = tempfile::tempdir().unwrap();
    let created = json!({
        "object": "workspace",
        "workspace": {
            "id": "ws-1", "project_id": "prj-1", "tenant_id": "tn-1", "name": "Staging",
            "slug": "staging", "environment": "staging", "status": "active",
            "created_at_unix": 3000, "updated_at_unix": 3000
        }
    });
    let replaced = json!({
        "object": "workspace",
        "workspace": {
            "id": "ws-1", "project_id": "prj-1", "tenant_id": "tn-1", "name": "Production",
            "slug": "production", "environment": "production", "status": "active",
            "created_at_unix": 3000, "updated_at_unix": 3100
        }
    });
    let updated = json!({
        "object": "workspace",
        "workspace": {
            "id": "ws-1", "project_id": "prj-1", "tenant_id": "tn-1", "name": "Production",
            "slug": "production", "environment": "production", "status": "archived",
            "created_at_unix": 3000, "updated_at_unix": 3200
        }
    });
    let deleted = json!({"object": "workspace", "id": "ws-1", "deleted": true});
    let mock = spawn_mock(vec![
        reply(201, "Created", "rid-ws-create", &created),
        reply(200, "OK", "rid-ws-get", &created),
        reply(200, "OK", "rid-ws-replace", &replaced),
        reply(200, "OK", "rid-ws-update", &updated),
        reply(200, "OK", "rid-ws-delete", &deleted),
    ]);

    // C
    let create_doc = json!({
        "project_id": "prj-1", "tenant_id": "tn-1", "name": "Staging",
        "slug": "staging", "environment": "staging"
    });
    let create = run_ctl(
        home.path(),
        &mock.base_url,
        &["workspaces", "create", "--data", &create_doc.to_string()],
    );
    assert_ok(&create, "workspace create");
    assert_eq!(mock.nth(0).line(), "POST /admin/v1/workspaces");
    assert_eq!(mock.nth(0).json(), create_doc);
    assert_receipt(
        &json_stdout(&create),
        ReceiptExpect {
            group: "workspaces",
            verb: "create",
            operation_id: "createWorkspace",
            method: "POST",
            path: "/admin/v1/workspaces",
            resource_id: ExpectResourceId::HarvestedFromResponse("ws-1"),
            status: 201,
            request_id: "rid-ws-create",
        },
        &created,
    );

    // R
    let get = run_ctl(home.path(), &mock.base_url, &["workspaces", "get", "ws-1"]);
    assert_ok(&get, "workspace get");
    assert_eq!(mock.nth(1).line(), "GET /admin/v1/workspaces/ws-1");
    assert_no_request_body(&mock.nth(1), "workspace get");
    let read = json_stdout(&get);
    assert_bare_document(&read, "workspace get");
    assert_eq!(read["workspace"]["environment"], "staging");

    // U (full replacement)
    let replace_doc = json!({
        "id": "ws-1", "project_id": "prj-1", "tenant_id": "tn-1", "name": "Production",
        "slug": "production", "environment": "production", "status": "active"
    });
    let replace = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "workspaces",
            "replace",
            "ws-1",
            "--data",
            &replace_doc.to_string(),
        ],
    );
    assert_ok(&replace, "workspace replace");
    assert_eq!(mock.nth(2).line(), "PUT /admin/v1/workspaces/ws-1");
    assert_eq!(mock.nth(2).json(), replace_doc);
    assert_receipt(
        &json_stdout(&replace),
        ReceiptExpect {
            group: "workspaces",
            verb: "replace",
            operation_id: "replaceWorkspace",
            method: "PUT",
            path: "/admin/v1/workspaces/ws-1",
            resource_id: ExpectResourceId::Addressed("ws-1"),
            status: 200,
            request_id: "rid-ws-replace",
        },
        &replaced,
    );

    // U (partial)
    let update_doc = json!({"status": "archived"});
    let update = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "workspaces",
            "update",
            "ws-1",
            "--data",
            &update_doc.to_string(),
        ],
    );
    assert_ok(&update, "workspace update");
    assert_eq!(mock.nth(3).line(), "PATCH /admin/v1/workspaces/ws-1");
    assert_eq!(mock.nth(3).json(), update_doc);
    assert_receipt(
        &json_stdout(&update),
        ReceiptExpect {
            group: "workspaces",
            verb: "update",
            operation_id: "updateWorkspace",
            method: "PATCH",
            path: "/admin/v1/workspaces/ws-1",
            resource_id: ExpectResourceId::Addressed("ws-1"),
            status: 200,
            request_id: "rid-ws-update",
        },
        &updated,
    );

    // D
    let delete = run_ctl(
        home.path(),
        &mock.base_url,
        &["workspaces", "delete", "ws-1"],
    );
    assert_ok(&delete, "workspace delete");
    assert_eq!(mock.nth(4).line(), "DELETE /admin/v1/workspaces/ws-1");
    assert_no_request_body(&mock.nth(4), "workspace delete");
    assert_receipt(
        &json_stdout(&delete),
        ReceiptExpect {
            group: "workspaces",
            verb: "delete",
            operation_id: "deleteWorkspace",
            method: "DELETE",
            path: "/admin/v1/workspaces/ws-1",
            resource_id: ExpectResourceId::Addressed("ws-1"),
            status: 200,
            request_id: "rid-ws-delete",
        },
        &deleted,
    );
    assert_eq!(mock.count(), 5, "exactly five legs reached the wire");
}

// ----- access policies: create -> read -> update -> delete --------------------

/// The `policy` half of the "policy/quota" sub-clause, which previously had
/// ZERO transport-level coverage: `iam_test.rs` asserted only that the builder
/// produced the string `/admin/v1/policies/...`.
///
/// An access policy is addressed by NAME, not by a generated id, so the id
/// segment is operator-supplied on every item leg - which is exactly the shape
/// that made review finding 1 (an omitted id silently addressing the whole
/// collection) dangerous here.
#[test]
fn access_policy_crud_round_trip_pins_every_leg() {
    let home = tempfile::tempdir().unwrap();
    let created = json!({
        "object": "policy",
        "policy": {
            "name": "billing-readonly", "effect": "deny", "organization_ids": ["tn-1"],
            "project_ids": [], "api_key_ids": [], "models": ["gpt-4o"], "providers": [],
            "code": "billing_denied", "message": "billing models are read-only", "enabled": true
        }
    });
    let updated = json!({
        "object": "policy",
        "policy": {
            "name": "billing-readonly", "effect": "deny", "organization_ids": ["tn-1"],
            "project_ids": [], "api_key_ids": [], "models": ["gpt-4o", "o3"], "providers": [],
            "code": "billing_denied", "message": "billing models are read-only", "enabled": false
        }
    });
    let deleted = json!({"object": "policy", "id": "billing-readonly", "deleted": true});
    let mock = spawn_mock(vec![
        reply(201, "Created", "rid-pol-create", &created),
        reply(200, "OK", "rid-pol-get", &created),
        reply(200, "OK", "rid-pol-update", &updated),
        reply(200, "OK", "rid-pol-delete", &deleted),
    ]);

    // C
    let create_doc = json!({
        "name": "billing-readonly", "effect": "deny", "organization_ids": ["tn-1"],
        "models": ["gpt-4o"], "code": "billing_denied",
        "message": "billing models are read-only", "enabled": true
    });
    let create = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "access-policies",
            "create",
            "--data",
            &create_doc.to_string(),
        ],
    );
    assert_ok(&create, "policy create");
    assert_eq!(mock.nth(0).line(), "POST /admin/v1/policies");
    assert_eq!(mock.nth(0).json(), create_doc);
    assert_receipt(
        &json_stdout(&create),
        ReceiptExpect {
            group: "access-policies",
            verb: "create",
            operation_id: "createAdminPolicy",
            method: "POST",
            path: "/admin/v1/policies",
            // The one family here whose create really CANNOT be harvested: an
            // access policy's identity is its `name`, and the contract's
            // `PolicyRule` declares no `id` at all (the item legs below address
            // `billing-readonly`, which is that name). So the honest receipt is
            // a null with `response_names_no_resource_id`, and this leg is what
            // separates "the harvest found nothing" from "the harvest was never
            // attempted".
            resource_id: ExpectResourceId::NoIdInResponse,
            status: 201,
            request_id: "rid-pol-create",
        },
        &created,
    );

    // R - by name.
    let get = run_ctl(
        home.path(),
        &mock.base_url,
        &["access-policies", "get", "billing-readonly"],
    );
    assert_ok(&get, "policy get");
    assert_eq!(
        mock.nth(1).line(),
        "GET /admin/v1/policies/billing-readonly"
    );
    assert_no_request_body(&mock.nth(1), "policy get");
    let read = json_stdout(&get);
    assert_bare_document(&read, "policy get");
    assert_eq!(read["policy"]["effect"], "deny");
    assert_eq!(read["policy"]["enabled"], true);

    // U
    let update_doc = json!({"enabled": false, "models": ["gpt-4o", "o3"]});
    let update = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "access-policies",
            "update",
            "billing-readonly",
            "--data",
            &update_doc.to_string(),
        ],
    );
    assert_ok(&update, "policy update");
    assert_eq!(
        mock.nth(2).line(),
        "PATCH /admin/v1/policies/billing-readonly"
    );
    assert_eq!(mock.nth(2).json(), update_doc);
    assert_receipt(
        &json_stdout(&update),
        ReceiptExpect {
            group: "access-policies",
            verb: "update",
            operation_id: "patchAdminPolicy",
            method: "PATCH",
            path: "/admin/v1/policies/billing-readonly",
            resource_id: ExpectResourceId::Addressed("billing-readonly"),
            status: 200,
            request_id: "rid-pol-update",
        },
        &updated,
    );

    // D
    let delete = run_ctl(
        home.path(),
        &mock.base_url,
        &["access-policies", "delete", "billing-readonly"],
    );
    assert_ok(&delete, "policy delete");
    assert_eq!(
        mock.nth(3).line(),
        "DELETE /admin/v1/policies/billing-readonly"
    );
    assert_no_request_body(&mock.nth(3), "policy delete");
    assert_receipt(
        &json_stdout(&delete),
        ReceiptExpect {
            group: "access-policies",
            verb: "delete",
            operation_id: "deleteAdminPolicy",
            method: "DELETE",
            path: "/admin/v1/policies/billing-readonly",
            resource_id: ExpectResourceId::Addressed("billing-readonly"),
            status: 200,
            request_id: "rid-pol-delete",
        },
        &deleted,
    );
    assert_eq!(mock.count(), 4, "exactly four legs reached the wire");
}

// ----- quota policies: composite-key create -> read -> update -> delete -------

/// The `quota` half of the sub-clause, also previously transport-uncovered.
///
/// A quota policy's item key is the COMPOSITE `scope_type/scope_id` pair, so
/// every item leg carries two positional segments. That is the one CRUD family
/// where a single-segment assumption would build a wrong URL and still look
/// plausible, which is why each leg pins the full two-segment path and the
/// receipt's joined `resource_id`.
#[test]
fn quota_policy_crud_round_trip_pins_the_composite_key() {
    let home = tempfile::tempdir().unwrap();
    let created = json!({
        "object": "quota_policy",
        "policy": {
            "id": "qp-1", "scope_type": "tenant", "scope_id": "tn-1",
            "model_allowlist": ["gpt-4o"], "rpm_limit": 600, "tpm_limit": 120000,
            "monthly_budget_usd": 250.0, "updated_at_unix": 4000
        }
    });
    let replaced = json!({
        "object": "quota_policy",
        "policy": {
            "id": "qp-1", "scope_type": "tenant", "scope_id": "tn-1",
            "model_allowlist": ["gpt-4o", "o3"], "rpm_limit": 1200, "tpm_limit": 240000,
            "monthly_budget_usd": 500.0, "updated_at_unix": 4100
        }
    });
    let updated = json!({
        "object": "quota_policy",
        "policy": {
            "id": "qp-1", "scope_type": "tenant", "scope_id": "tn-1",
            "model_allowlist": ["gpt-4o", "o3"], "rpm_limit": 1200, "tpm_limit": 240000,
            "monthly_budget_usd": 750.0, "updated_at_unix": 4200
        }
    });
    let deleted = json!({"object": "quota_policy", "id": "qp-1", "deleted": true});
    let mock = spawn_mock(vec![
        reply(201, "Created", "rid-qp-create", &created),
        reply(200, "OK", "rid-qp-get", &created),
        reply(200, "OK", "rid-qp-replace", &replaced),
        reply(200, "OK", "rid-qp-update", &updated),
        reply(200, "OK", "rid-qp-delete", &deleted),
    ]);

    // C - the scope pair rides in the document, not the path.
    let create_doc = json!({
        "scope_type": "tenant", "scope_id": "tn-1", "model_allowlist": ["gpt-4o"],
        "rpm_limit": 600, "tpm_limit": 120000, "monthly_budget_usd": 250.0
    });
    let create = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "quota-policies",
            "create",
            "--data",
            &create_doc.to_string(),
        ],
    );
    assert_ok(&create, "quota create");
    assert_eq!(mock.nth(0).line(), "POST /admin/v1/quota-policies");
    assert_eq!(mock.nth(0).json(), create_doc);
    assert_receipt(
        &json_stdout(&create),
        ReceiptExpect {
            group: "quota-policies",
            verb: "create",
            operation_id: "createQuotaPolicy",
            method: "POST",
            path: "/admin/v1/quota-policies",
            // The ITEM legs below address the composite `tenant/tn-1` scope
            // key, but the create addresses the collection and the server
            // answers with the policy row's own id -- so the harvest names
            // `qp-1`, not the scope pair. That difference is the point: the
            // receipt reports what the SERVER assigned.
            resource_id: ExpectResourceId::HarvestedFromResponse("qp-1"),
            status: 201,
            request_id: "rid-qp-create",
        },
        &created,
    );

    // R - the composite key becomes two path segments.
    let get = run_ctl(
        home.path(),
        &mock.base_url,
        &["quota-policies", "get", "tenant", "tn-1"],
    );
    assert_ok(&get, "quota get");
    assert_eq!(
        mock.nth(1).line(),
        "GET /admin/v1/quota-policies/tenant/tn-1",
        "the scope_type/scope_id pair is a two-segment item key"
    );
    assert_no_request_body(&mock.nth(1), "quota get");
    let read = json_stdout(&get);
    assert_bare_document(&read, "quota get");
    assert_eq!(read["policy"]["rpm_limit"], 600);

    // U (full replacement)
    let replace_doc = json!({
        "scope_type": "tenant", "scope_id": "tn-1", "model_allowlist": ["gpt-4o", "o3"],
        "rpm_limit": 1200, "tpm_limit": 240000, "monthly_budget_usd": 500.0
    });
    let replace = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "quota-policies",
            "replace",
            "tenant",
            "tn-1",
            "--data",
            &replace_doc.to_string(),
        ],
    );
    assert_ok(&replace, "quota replace");
    assert_eq!(
        mock.nth(2).line(),
        "PUT /admin/v1/quota-policies/tenant/tn-1"
    );
    assert_eq!(mock.nth(2).json(), replace_doc);
    assert_receipt(
        &json_stdout(&replace),
        ReceiptExpect {
            group: "quota-policies",
            verb: "replace",
            operation_id: "replaceQuotaPolicy",
            method: "PUT",
            path: "/admin/v1/quota-policies/tenant/tn-1",
            resource_id: ExpectResourceId::Addressed("tenant/tn-1"),
            status: 200,
            request_id: "rid-qp-replace",
        },
        &replaced,
    );

    // U (partial)
    let update_doc = json!({"monthly_budget_usd": 750.0});
    let update = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "quota-policies",
            "update",
            "tenant",
            "tn-1",
            "--data",
            &update_doc.to_string(),
        ],
    );
    assert_ok(&update, "quota update");
    assert_eq!(
        mock.nth(3).line(),
        "PATCH /admin/v1/quota-policies/tenant/tn-1"
    );
    assert_eq!(mock.nth(3).json(), update_doc);
    assert_receipt(
        &json_stdout(&update),
        ReceiptExpect {
            group: "quota-policies",
            verb: "update",
            operation_id: "updateQuotaPolicy",
            method: "PATCH",
            path: "/admin/v1/quota-policies/tenant/tn-1",
            resource_id: ExpectResourceId::Addressed("tenant/tn-1"),
            status: 200,
            request_id: "rid-qp-update",
        },
        &updated,
    );

    // D
    let delete = run_ctl(
        home.path(),
        &mock.base_url,
        &["quota-policies", "delete", "tenant", "tn-1"],
    );
    assert_ok(&delete, "quota delete");
    assert_eq!(
        mock.nth(4).line(),
        "DELETE /admin/v1/quota-policies/tenant/tn-1"
    );
    assert_no_request_body(&mock.nth(4), "quota delete");
    assert_receipt(
        &json_stdout(&delete),
        ReceiptExpect {
            group: "quota-policies",
            verb: "delete",
            operation_id: "deleteQuotaPolicy",
            method: "DELETE",
            path: "/admin/v1/quota-policies/tenant/tn-1",
            resource_id: ExpectResourceId::Addressed("tenant/tn-1"),
            status: 200,
            request_id: "rid-qp-delete",
        },
        &deleted,
    );
    assert_eq!(mock.count(), 5, "exactly five legs reached the wire");
}

// ----- provider/model: the read-only families the clause cannot round-trip ----

/// The provider/model sub-clause of #361's acceptance box asks for a CRUD round
/// trip that the contract makes impossible: `docs/openapi/admin-api.openapi.json`
/// declares exactly three provider/model admin operations - `listAdminProviders`
/// (GET /admin/v1/providers), `listAdminModels` (GET /admin/v1/models), and
/// `listAdminProviderModels` (GET /admin/v1/provider-models) - and no POST, PUT,
/// PATCH, or DELETE anywhere under those paths. There is no create leg to start
/// a round trip with, so the CLI cannot be at fault for not having one.
///
/// This test covers what IS achievable for a read-only family, and covers it
/// properly rather than asserting a path string: each list is a real round trip
/// through the binary with its contract-declared query parameters (`limit`,
/// `offset`, `search`, `provider`) actually exercised on the wire, the envelope
/// rendered, and the truncation notice raised. The final leg pins the
/// impossibility itself: no mutating verb exists on the catalog group, so an
/// attempted create is refused before any request is issued.
#[test]
fn provider_and_model_catalogs_are_read_only_and_page_on_the_wire() {
    let home = tempfile::tempdir().unwrap();
    let providers = json!({
        "object": "list",
        "data": [
            {"id": "openai", "name": "OpenAI", "enabled": true},
            {"id": "anthropic", "name": "Anthropic", "enabled": true}
        ],
        "total": 9, "offset": 4, "limit": 2
    });
    let models = json!({
        "object": "list",
        "data": [{"id": "gpt-4o", "provider": "openai"}],
        "total": 1, "offset": 0, "limit": 1
    });
    let provider_models = json!({
        "object": "list",
        "data": [{"provider": "openai", "model": "gpt-4o", "available": true}],
        "total": 1
    });
    let mock = spawn_mock(vec![
        reply(200, "OK", "rid-cat-providers", &providers),
        reply(200, "OK", "rid-cat-models", &models),
        reply(200, "OK", "rid-cat-provider-models", &provider_models),
    ]);

    // listAdminProviders with its declared offset/limit/search parameters.
    let list = run_ctl(
        home.path(),
        &mock.base_url,
        &[
            "catalog",
            "providers",
            "--offset",
            "4",
            "--limit",
            "2",
            "--filter",
            "search=open",
        ],
    );
    assert_ok(&list, "catalog providers");
    let request = mock.nth(0);
    assert_eq!(request.method, "GET");
    assert!(
        request.path.starts_with("/admin/v1/providers?"),
        "pagination lands in the query string: {}",
        request.path
    );
    for parameter in ["offset=4", "limit=2", "search=open"] {
        assert!(
            request.path.contains(parameter),
            "contract-declared parameter {parameter} reached the wire: {}",
            request.path
        );
    }
    let body = json_stdout(&list);
    assert_bare_document(&body, "catalog providers");
    assert_eq!(body["data"][0]["id"], "openai");
    assert_eq!(body["data"][1]["id"], "anthropic");
    // A partial page must announce itself: 2 of 9 from offset 4 is truncated.
    assert!(
        stderr(&list).contains("showing 2 of 9 rows"),
        "a truncated page is announced on stderr: {}",
        stderr(&list)
    );

    // listAdminModels.
    let model_list = run_ctl(
        home.path(),
        &mock.base_url,
        &["catalog", "models", "--limit", "1"],
    );
    assert_ok(&model_list, "catalog models");
    assert!(
        mock.nth(1).path.starts_with("/admin/v1/models?"),
        "models list: {}",
        mock.nth(1).path
    );
    assert!(mock.nth(1).path.contains("limit=1"));
    assert_eq!(json_stdout(&model_list)["data"][0]["id"], "gpt-4o");

    // listAdminProviderModels, whose only declared parameter is `provider`.
    let provider_model_list = run_ctl(
        home.path(),
        &mock.base_url,
        &["catalog", "provider-models", "--filter", "provider=openai"],
    );
    assert_ok(&provider_model_list, "catalog provider-models");
    assert_eq!(
        mock.nth(2).line(),
        "GET /admin/v1/provider-models?provider=openai"
    );
    assert_eq!(
        json_stdout(&provider_model_list)["data"][0]["model"],
        "gpt-4o"
    );

    // The impossibility, pinned: there is no mutating provider/model verb to
    // open a round trip with, and asking for one never reaches the wire.
    for verb in ["create", "update", "delete"] {
        let refused = run_ctl(
            home.path(),
            &mock.base_url,
            &["catalog", verb, "--data", "{}"],
        );
        assert_eq!(
            code(&refused),
            2,
            "the catalog group declares no '{verb}' verb - the contract has no \
             mutating provider/model operation: {}",
            stderr(&refused)
        );
    }
    assert_eq!(mock.count(), 3, "only the three read legs reached the wire");
}
