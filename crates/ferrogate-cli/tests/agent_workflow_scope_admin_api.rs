// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: End-to-end regression coverage for issue #546 -- the eighth
// carrier of the #518/#535 selector family, split out of
// tests/config_catalog_scope_admin_api.rs because its rows also join runtime
// counters.
//
// `GET /admin/v1/agent-workflows` and `GET /admin/v1/agent-workflows/{id}`
// authenticated and then DISCARDED the resulting AuthContext (`Ok(_) => { let
// data = state.config.agent_workflows.iter().map(..) }`), so any tenant-scoped
// `admin.read` key -- the shape `provision_gateway_api_key` mints on every
// admin-console login -- read every other tenant's organization ids, project
// ids and api-key ids out of `AgentWorkflowPolicy`. Writes were already
// `require_platform_operator`-gated, so this was pure disclosure. The DATA
// PLANE was never affected: `can_use_workflow` (`server/chat.rs`, twinned in
// `server/agent_runs.rs`) has always applied exactly this narrowing at request
// time, which is why the fix is an application of `ConfigCatalogScope` and not
// a new rule -- see `ConfigCatalogScope::visible_agent_workflow` in
// gateway/rbac.rs.
//
// WHAT EACH TEST PINS (issue #500's standing bar: name the line, name the
// mutation, and let the assertion -- not the test name -- carry the claim).
// Two handler branches changed; each is pinned by exactly one test, and no two
// tests read the same route+arm, so reverting one branch reds one test:
//
//   local.rs, GET /admin/v1/agent-workflows      (list arm)
//       -> tenant_scoped_key_lists_only_agent_workflows_it_could_invoke
//       pins:     `.filter_map(|workflow| scope.visible_agent_workflow(workflow))`
//       mutation: delete the `filter_map` (i.e. restore `Ok(_) => ...`) and
//                 tenant A's id set gains wf-key-b / wf-project-b / wf-tenant-b
//                 and its selector-value set gains tenant-wf-b, project-wf-b
//                 and key-b-data -- both asserted as EXACT SETS below.
//       mutation: change `ConfigCatalogScope::narrow`'s tail from
//                 `(!kept.is_empty()).then_some(kept)` to `Some(kept)` -- the
//                 emptied-selector-reads-as-wildcard bug the helper exists to
//                 prevent -- and `wf-key-b` appears in tenant A's id set with
//                 an empty `api_key_ids`, i.e. rendered as runnable by anyone.
//       mutation: drop the `..workflow.clone()` narrowing of one field (say
//                 leave `api_key_ids` verbatim) and the exact selector-value
//                 set gains `key-b-data` from `wf-both-keys`.
//
//   local.rs, GET /admin/v1/agent-workflows/{id} (by-id arm)
//       -> tenant_scoped_key_cannot_fetch_an_out_of_scope_agent_workflow_by_id
//       pins:     `if visible.is_none() && !scope.is_full() { .. denied }`
//       mutation: delete the whole guard and tenant A gets 200 + tenant B's
//                 ids for `wf-tenant-b`.
//       mutation: delete ONLY `&& !scope.is_full()` and every scope assertion
//                 in that test still passes while the platform operator's
//                 request for an absent id turns 404 into 403 -- which is the
//                 clause #518 was bounced for leaving unpinned, so it is
//                 asserted separately, at the end of that test, on the
//                 OPERATOR credential.
//
// Every assertion is on the rows (and the ids inside them) a caller actually
// receives, never on handler source text. Runs against a real gateway process
// with in-memory storage -- no Postgres, no Docker.
//
// NOT RUN. Under speed mode this file was written and compiled but never
// executed, and no mutation above was performed; each is a design claim about
// the assertion below it, not an observation.

mod support;

use std::collections::BTreeSet;

use support::{http_request, start_ready_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];
const TENANT_A: [&str; 2] = [
    "Authorization: Bearer tenant-a-secret",
    "Content-Type: application/json",
];
const TENANT_B: [&str; 2] = [
    "Authorization: Bearer tenant-b-secret",
    "Content-Type: application/json",
];

/// Static config carrying the selector shapes `visible_agent_workflow` has to
/// tell apart -- the same six shapes the `PolicyRule` fixture in
/// `config_catalog_scope_admin_api.rs` uses, because the two structs carry the
/// same three lists and the runtime reads them the same way:
///
/// * `wf-shared` -- no selectors at all: genuinely platform-wide, returned to
///   everyone verbatim;
/// * `wf-tenant-a` / `wf-tenant-b` -- single-organization workflows;
/// * `wf-both-tenants` -- names A *and* B: A must see it (A can invoke it)
///   with B's id stripped;
/// * `wf-key-b` -- EMPTY `organization_ids` but a non-empty `api_key_ids`
///   naming only B's key. This is the shape that separates "empty selector =
///   wildcard" from "narrowed to nothing": it must be HIDDEN from A, never
///   rendered with an emptied `api_key_ids`, which would read as "any key may
///   run this";
/// * `wf-both-keys` -- names A's and B's key: visible to A with only A's;
/// * `wf-project-b` -- a project selector naming a project A does not own.
///
/// Load-time invariants (`validate_agent_workflows`,
/// `ferrogate-config/src/config/validate.rs:2010`, the crate this moved to in
/// #553 stage 3a): a workflow needs a non-empty `id` and `name`, a `version`
/// greater than zero (defaulted to 1), at least one node, and every id in
/// `api_key_ids` must name a declared `[[api_keys]]` entry. A node whose
/// `model` is set must name a declared `[[models]]` entry, and a `model`-kind
/// node may not declare a `tool`. `organization_ids` and `project_ids` are
/// NOT cross-checked against anything, which is why `project-wf-b` may be
/// named without a matching key.
fn write_config(path: &std::path::Path, gateway_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
# Declared out loud rather than inherited from
# `TenancyConfig::implicit_platform_operator` (#515 stage 1): the explicit form
# is accepted under BOTH settings, so the operator half of both tests below --
# including the 404-not-403 assertion -- keeps meaning the same thing when that
# default is flipped off. Without it this key would authenticate as
# `tenant_identity_required` and every operator assertion would fail for a
# reason that has nothing to do with #546.
platform_operator = true

[[api_keys]]
id = "tenant-a-console"
name = "Tenant A admin-console session key"
key = "tenant-a-secret"
scopes = ["admin.read"]
organization_id = "tenant-wf-a"

[[api_keys]]
id = "tenant-b-console"
name = "Tenant B admin-console session key"
key = "tenant-b-secret"
scopes = ["admin.read"]
organization_id = "tenant-wf-b"

[[api_keys]]
id = "key-a-data"
name = "Tenant A data key"
key = "key-a-secret"
organization_id = "tenant-wf-a"
project_id = "project-wf-a"

[[api_keys]]
id = "key-b-data"
name = "Tenant B data key"
key = "key-b-secret"
organization_id = "tenant-wf-b"
project_id = "project-wf-b"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:65535/v1"

[[models]]
name = "model-shared"
provider = "openai"
provider_model = "gpt-4o-mini"

[[agent_workflows]]
id = "wf-shared"
name = "Shared workflow"

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"

[[agent_workflows]]
id = "wf-tenant-a"
name = "Tenant A workflow"
organization_ids = ["tenant-wf-a"]

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"

[[agent_workflows]]
id = "wf-tenant-b"
name = "Tenant B workflow"
organization_ids = ["tenant-wf-b"]

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"

[[agent_workflows]]
id = "wf-both-tenants"
name = "Shared-by-organization workflow"
organization_ids = ["tenant-wf-a", "tenant-wf-b"]

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"

[[agent_workflows]]
id = "wf-key-b"
name = "Tenant B key workflow"
api_key_ids = ["key-b-data"]

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"

[[agent_workflows]]
id = "wf-both-keys"
name = "Shared-by-key workflow"
api_key_ids = ["key-a-data", "key-b-data"]

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"

[[agent_workflows]]
id = "wf-project-b"
name = "Tenant B project workflow"
project_ids = ["project-wf-b"]

[[agent_workflows.nodes]]
id = "answer"
kind = "model"
model = "model-shared"
"#
        ),
    )
    .unwrap();
}

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn rows(body: &serde_json::Value) -> &[serde_json::Value] {
    body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("list response has no data array: {body}"))
        .as_slice()
}

/// The workflow ids in a list response, sorted.
///
/// Sorted, not verbatim: `agent_workflows` is a control-plane collection, so
/// `AppState::try_new` seeds the store from the file and reads the catalog
/// back out keyed by `workflow_resource_id`, i.e. the handler sees the rows in
/// key order and not in the order the fixture declares them. Sorting keeps the
/// expectations below about WHICH rows a caller receives, which is the whole
/// of #546.
fn listed_workflow_ids(body: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = rows(body)
        .iter()
        .map(|row| {
            row["workflow"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("row has no workflow.id: {row}"))
                .to_string()
        })
        .collect();
    ids.sort();
    ids
}

fn string_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, got {value}"))
        .iter()
        .map(|entry| entry.as_str().unwrap_or_default().to_string())
        .collect()
}

fn workflow_named<'a>(body: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    let row = rows(body)
        .iter()
        .find(|row| row["workflow"]["id"] == id)
        .unwrap_or_else(|| panic!("workflow {id} is missing from {body}"));
    &row["workflow"]
}

/// EVERY id that appears in ANY of the three selector lists, across every row
/// of a list response, as a set.
///
/// This is the by-identity cross-tenant assertion, and it is deliberately not
/// `!response.contains("tenant-wf-b")`: a substring check passes vacuously the
/// moment a field is renamed, a value is truncated or an id happens to be a
/// prefix of another, and it cannot distinguish "B's id is absent" from "the
/// whole selector is absent". Comparing this set to an exact expectation fails
/// in BOTH directions -- an id of B's that leaks in, and an id of A's that the
/// narrowing wrongly dropped.
fn selector_values(body: &serde_json::Value) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for row in rows(body) {
        let workflow = &row["workflow"];
        for field in ["organization_ids", "project_ids", "api_key_ids"] {
            values.extend(string_list(&workflow[field]));
        }
    }
    values
}

/// Boots a gateway on the fixture above. `start_ready_gateway` rather than
/// `start_gateway` + `wait_for_gateway`: it watches for an early child exit, so
/// a config the gateway REFUSES fails in the time the process takes to die
/// instead of parking on the harness's 300s readiness window.
fn start(dir: &tempfile::TempDir) -> (std::process::Child, String) {
    let config_path = dir.path().join("ferrogate.toml");
    start_ready_gateway(&config_path, |addr| write_config(&config_path, addr))
}

/// Site 1 -- `GET /admin/v1/agent-workflows`. Before the fix this returned
/// EVERY `AgentWorkflowPolicy` verbatim to a tenant-scoped key.
#[test]
fn tenant_scoped_key_lists_only_agent_workflows_it_could_invoke() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/agent-workflows", &TENANT_A, "");
    let body = response_json(raw);

    // (a) WHICH ROWS. Exactly the workflows tenant A could actually invoke.
    // `wf-key-b` is absent rather than present-with-an-emptied-selector: that
    // is the `narrow -> None` rule, and returning `Some(vec![])` instead puts
    // `wf-key-b` in this vector.
    assert_eq!(
        listed_workflow_ids(&body),
        vec![
            "wf-both-keys".to_string(),
            "wf-both-tenants".to_string(),
            "wf-shared".to_string(),
            "wf-tenant-a".to_string(),
        ],
        "tenant A must see exactly the workflows tenant A could invoke"
    );

    // (b) WHICH IDS, BY IDENTITY. Every id in every selector of every returned
    // row, compared as a set: tenant B's `tenant-wf-b`, `project-wf-b` and
    // `key-b-data` are absent because they are not in this set, not because
    // they failed to match a substring.
    assert_eq!(
        selector_values(&body),
        BTreeSet::from([
            "tenant-wf-a".to_string(), // wf-tenant-a and wf-both-tenants
            "key-a-data".to_string(),  // wf-both-keys
        ]),
        "tenant A's workflow list carries an id that is not tenant A's"
    );

    // (c) NARROWED, NOT HIDDEN. A workflow naming both organizations stays
    // visible -- A can invoke it -- rendered with only A's id...
    assert_eq!(
        string_list(&workflow_named(&body, "wf-both-tenants")["organization_ids"]),
        vec!["tenant-wf-a".to_string()],
        "the shared workflow still names another tenant"
    );
    // ...and one naming both keys keeps only A's key id.
    assert_eq!(
        string_list(&workflow_named(&body, "wf-both-keys")["api_key_ids"]),
        vec!["key-a-data".to_string()],
        "the shared workflow still names another tenant's api key"
    );

    // (d) WILDCARDS SURVIVE. An empty selector is "runnable by anyone" and is
    // not something to narrow away; a mutation that narrowed empty selectors
    // against the caller would hide `wf-shared` from everyone.
    let shared = workflow_named(&body, "wf-shared");
    assert!(
        string_list(&shared["organization_ids"]).is_empty()
            && string_list(&shared["project_ids"]).is_empty()
            && string_list(&shared["api_key_ids"]).is_empty(),
        "the platform-wide workflow gained a selector: {shared}"
    );

    // (e) THE COUNTER JOIN SURVIVES THE NARROWING. `admin_agent_workflow` now
    // receives an owned, narrowed `AgentWorkflowPolicy` rather than a borrow
    // of `state.config`; this pins that the row is still the {workflow,
    // counters} pair the console renders and not a bare policy. It does NOT
    // claim the counters are tenant-scoped -- they are platform-wide
    // aggregates for the workflow id/version, which #546 deliberately leaves
    // alone (see `visible_agent_workflow`'s doc comment).
    let counters = &rows(&body)[0]["counters"];
    for field in [
        "request_count",
        "error_count",
        "billing_event_count",
        "audit_event_count",
        "estimated_tokens",
    ] {
        assert!(
            counters[field].is_u64(),
            "row lost its {field} counter: {counters}"
        );
    }

    // (f) KEYED ON THE CALLER. B's view is B's, not a copy of A's.
    let tenant_b = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/agent-workflows",
        &TENANT_B,
        "",
    ));
    assert_eq!(
        listed_workflow_ids(&tenant_b),
        vec![
            "wf-both-keys".to_string(),
            "wf-both-tenants".to_string(),
            "wf-key-b".to_string(),
            "wf-project-b".to_string(),
            "wf-shared".to_string(),
            "wf-tenant-b".to_string(),
        ],
        "tenant B must see exactly the workflows tenant B could invoke"
    );
    assert_eq!(
        selector_values(&tenant_b),
        BTreeSet::from([
            "tenant-wf-b".to_string(),
            "project-wf-b".to_string(),
            "key-b-data".to_string(),
        ]),
        "tenant B's workflow list carries an id that is not tenant B's"
    );

    // (g) NOT A BLANKET DENY. The platform operator still receives the whole
    // catalog, un-narrowed.
    let operator = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/agent-workflows",
        &ADMIN,
        "",
    ));
    assert_eq!(
        listed_workflow_ids(&operator),
        vec![
            "wf-both-keys".to_string(),
            "wf-both-tenants".to_string(),
            "wf-key-b".to_string(),
            "wf-project-b".to_string(),
            "wf-shared".to_string(),
            "wf-tenant-a".to_string(),
            "wf-tenant-b".to_string(),
        ],
        "platform operator lost workflows from the full catalog"
    );
    assert_eq!(
        string_list(&workflow_named(&operator, "wf-both-tenants")["organization_ids"]),
        vec!["tenant-wf-a".to_string(), "tenant-wf-b".to_string()],
        "platform operator received a narrowed workflow"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 2 -- `GET /admin/v1/agent-workflows/{id}`. Ids came free from the list,
/// so the by-id read was the second half of an enumeration primitive: it must
/// answer identically for out-of-scope and for nonexistent.
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_agent_workflow_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    // Its own workflow still reads back, with counters.
    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/agent-workflows/wf-tenant-a",
        &TENANT_A,
        "",
    ));
    assert_eq!(own["agent_workflow"]["workflow"]["id"], "wf-tenant-a");
    assert_eq!(
        string_list(&own["agent_workflow"]["workflow"]["organization_ids"]),
        vec!["tenant-wf-a".to_string()]
    );
    assert!(
        own["agent_workflow"]["counters"]["request_count"].is_u64(),
        "the by-id read lost its counters: {own}"
    );

    // The by-id read narrows exactly like the list does -- by identity, on the
    // three selector lists of the single returned workflow.
    let shared = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/agent-workflows/wf-both-tenants",
        &TENANT_A,
        "",
    ));
    let shared_workflow = &shared["agent_workflow"]["workflow"];
    let mut shared_ids: BTreeSet<String> = BTreeSet::new();
    for field in ["organization_ids", "project_ids", "api_key_ids"] {
        shared_ids.extend(string_list(&shared_workflow[field]));
    }
    assert_eq!(
        shared_ids,
        BTreeSet::from(["tenant-wf-a".to_string()]),
        "the by-id read returned an id that is not tenant A's: {shared}"
    );

    // Out-of-scope and absent are the SAME answer, so the endpoint is not an
    // existence oracle for the ids the list no longer discloses.
    for id in [
        "wf-tenant-b",
        "wf-key-b",
        "wf-project-b",
        "workflow-that-does-not-exist",
    ] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/agent-workflows/{id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused agent workflow {id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for agent workflow {id}: {response}"
        );
        // The refusal body must not carry the ids the refusal exists to hide.
        // (Substring here is the right shape: the claim is about the whole
        // response text, which for an error body has no id fields to walk.)
        assert!(
            !response.contains("tenant-wf-b")
                && !response.contains("key-b-data")
                && !response.contains("project-wf-b"),
            "the refusal for {id} leaked tenant B's ids: {response}"
        );
    }

    // The platform operator still reads any workflow by id, un-narrowed...
    let operator = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/agent-workflows/wf-both-tenants",
        &ADMIN,
        "",
    ));
    assert_eq!(
        string_list(&operator["agent_workflow"]["workflow"]["organization_ids"]),
        vec!["tenant-wf-a".to_string(), "tenant-wf-b".to_string()],
        "platform operator received a narrowed workflow by id"
    );

    // ...and still gets 404, NOT 403, for an id that genuinely does not exist.
    // This assertion, and only this one, pins `&& !scope.is_full()` on this
    // handler: delete that clause and every scope assertion above still
    // passes while the operator's 404 becomes `tenant_scope_denied`. #518 was
    // bounced for leaving exactly this unpinned, so it is asserted here on the
    // OPERATOR credential rather than inferred from the tenant loop above.
    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/agent-workflows/workflow-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent workflow, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("agent_workflow_not_found"),
        "operator 404 must name agent_workflow_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
