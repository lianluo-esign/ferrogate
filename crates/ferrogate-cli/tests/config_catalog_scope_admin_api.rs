// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: End-to-end regression coverage for issue #535 -- the siblings
// of #518. Seven admin read surfaces authenticated and then DISCARDED the
// resulting AuthContext (`Ok(_) => { let body = AdminList::new(
// state.config.policies.clone()) }`), so any tenant-scoped `admin.read` key --
// the shape `provision_gateway_api_key` mints on every admin-console login --
// read every other tenant's organization ids, project ids and api-key ids out
// of platform-global static config:
//
//   /admin/v1/policies[/{name}]         PolicyRule.{organization,project,api_key}_ids
//   /admin/v1/gateway-configs[/{id}]    GatewayConfigProfile.api_key_ids
//   /admin/v1/skill-packages[/{id}]     SkillPackage.api_key_ids
//   /admin/v1/agent-upstreams[/{id}]    AgentUpstreamConfig.tenant_ids
//   /admin/v1/models                    Model.visible_{organization,project}_ids
//
// (`/admin/v1/agent-workflows` is the eighth carrier of the same selector
// family; it was split out as #546 and is covered by the sibling file
// tests/agent_workflow_scope_admin_api.rs, because its rows also join runtime
// counters. `/admin/v1/api-keys` is operator-gated and
// `GuardrailRule` has no read surface at all -- see the derivation table on
// `ConfigCatalogScope` in gateway/rbac.rs.)
//
// Every assertion below is on the ROWS (and the ids inside them) a scoped
// caller actually receives, never on handler source text: revert any one of
// the handlers to `Ok(_) => ...` and the matching assertion sees the
// out-of-scope rows come back and fails. Runs against a real gateway process
// with in-memory storage -- no Postgres, no Docker.
//
// BRANCH SPECIFICITY (issue #500's standing bar). Nine handler branches call
// `config_catalog_scope`, and each is pinned by exactly one test -- reverting
// that one branch to `Ok(_) => ...` reds that test and no other, because no
// two tests read the same route+arm:
//
//   local.rs:8756  GET /admin/v1/policies              -> tenant_scoped_key_lists_only_policies_that_can_act_on_it
//   local.rs:8798  GET /admin/v1/policies/{name}       -> tenant_scoped_key_cannot_fetch_an_out_of_scope_policy_by_name
//   local.rs:891   GET /admin/v1/gateway-configs       -> tenant_scoped_key_lists_only_gateway_profiles_its_keys_may_select
//   local.rs:934   GET /admin/v1/gateway-configs/{id}  -> tenant_scoped_key_cannot_fetch_an_out_of_scope_gateway_profile_by_id
//   local.rs:8115  GET /admin/v1/models                -> tenant_scoped_key_lists_only_models_visible_to_it
//   local.rs:1686  GET /admin/v1/skill-packages        -> tenant_scoped_key_lists_only_skill_packages_its_keys_may_load
//   local.rs:1729  GET /admin/v1/skill-packages/{id}   -> (same test, list half vs by-id half)
//   local.rs:9283  GET /admin/v1/agent-upstreams       -> tenant_scoped_key_lists_only_agent_upstreams_its_keys_may_reach
//   local.rs:9316  GET /admin/v1/agent-upstreams/{id}  -> (same test, list half vs by-id half)
//
// The four by-id branches additionally carry `&& !scope.is_full()`; deleting
// it turns the OPERATOR's 404 for an absent id into a 403, which is asserted
// once per by-id branch, so that clause is pinned four times over and never
// by implication from a sibling route.
//
// The eighth test pins a different axis -- the two durable listings that feed
// the scope itself -- and is the one place the matrix is not one-to-one: it
// reads through the policy and agent-upstream lists, so those two handler
// mutations red it as well as their own test. That is intrinsic (a scope-
// SOURCE test has to observe through some scoped surface) and it does not
// make either test redundant, because the containment runs one way only.
// Deleting `api_key_ids.extend(list_virtual_api_keys(..))` (rbac.rs:1431) or
// `project_ids.extend(list_projects(..))` (:1439) reds ONLY the eighth test:
// it is the only test in this file that creates a project or a virtual key,
// so in the other seven both listings come back empty and neither mutation
// can change a byte of their responses.
//
// The CONVERSE does not hold, and an earlier revision of this header asserted
// that it did. Deleting the static `own_static_keys()` seeding
// (rbac.rs:1427-1428) reds the other seven AND the eighth: tenant A's scope
// collapses to `api_key_ids = {<durable key a>}`, so `narrow` returns `None`
// for every row selected by a *static* key id, and `deny-both-keys`,
// `upstream-a` and `upstream-both` drop out of the eighth test's exact
// expectations too. That is a consequence of asserting exact sorted sets
// rather than `contains()` -- the stronger assertion, and worth the loss --
// but the claim is corrected here rather than left standing, because this
// matrix is what a reviewer checks branch specificity against and a wrong
// audit is worse than no audit.

mod support;

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

/// Static config carrying the multi-tenant selector shapes the scope helper
/// has to tell apart:
///
/// * `global-deny` -- no selectors at all: genuinely platform-wide, so every
///   caller sees it verbatim;
/// * `deny-tenant-a` / `deny-tenant-b` -- single-tenant rules;
/// * `deny-both-tenants` -- names A *and* B: A must see it (it is denied by
///   it) with B's id stripped out;
/// * `deny-key-b` -- an EMPTY `organization_ids` but a non-empty
///   `api_key_ids` naming only B's key. This is the case that separates
///   "empty selector = wildcard" from "narrowed to nothing": it must be
///   hidden from A, not rendered as a global rule;
/// * `deny-both-keys` -- names A's and B's key: visible to A with only A's;
/// * `deny-project-b` -- project selector naming a project A does not own.
///
/// Gateway profiles, skill packages, agent upstreams and models mirror the
/// same shapes (unrestricted / A's / B's / both). Note the upstream fixtures
/// name API KEY ids in `tenant_ids`, because that is what
/// `agent_upstream_visible_to_auth` matches the field against at request
/// time -- the field name is a misnomer, and copying it into an
/// organization-shaped narrowing would hide every upstream from everyone.
///
/// # Load-time invariants this fixture has to satisfy
///
/// The first cut of this file declared `[[skill_packages]]` and
/// `[[agent_upstreams]]` with only their identity fields, so
/// `Config::validate` refused the file and the gateway exited before binding
/// -- every test in the suite then spent the harness's 300s readiness window
/// waiting for a process that was already dead. The three non-obvious
/// constraints, read off `ferrogate-config/src/config/validate.rs` (the crate
/// this module moved to in #553 stage 3a) rather than guessed:
///
/// * `validate_skill_packages` (`validate.rs:2295`) rejects a package with an
///   empty `capabilities` list, so each `[[skill_packages]]` entry carries a
///   `[[skill_packages.capabilities]]` sub-table. A capability is a *table*
///   (`SkillPackageCapability { kind, id }`), never a bare string.
/// * a `kind = "plugin"` capability id must name a registered plugin
///   (`validate.rs:2337`; the id set is `plugins` + `extensions` + resources
///   embedded in packages), which is what the single `[[plugins]]` entry
///   below is for. `tool.echo` is one of the builtin ids
///   `validate_builtin_plugin_shape` accepts, and it must be declared
///   `kind = "tool_provider"`.
/// * `validate_agent_upstreams` (`validate.rs:2959`) rejects an empty
///   `capabilities` list too; there a capability is a plain enum string.
///
/// Those three were derived from the error the suite actually produced, which
/// bounds the validator PREFIX and not the suffix: `Config::validate`
/// (`validate.rs:89`) runs its checks in sequence and aborts on the first, so
/// everything after `validate_agent_upstreams` -- `validate_guardrails`,
/// `validate_tls`, `validate_storage` and the rest -- has still never run on
/// this fixture. Nothing here is expected to trip them (the fixture declares
/// no guardrail, tls, storage or cluster block, and the sibling
/// `rbac_catalog_scope_admin_api` boots a strictly smaller config through all
/// of them on defaults), but "the error came from validator N" is evidence
/// about `1..=N` only, and this file is not entitled to more than it proved.
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

[[api_keys]]
id = "tenant-a-console"
name = "Tenant A admin-console session key"
key = "tenant-a-secret"
scopes = ["admin.read"]
organization_id = "tenant-pol-a"

[[api_keys]]
id = "tenant-b-console"
name = "Tenant B admin-console session key"
key = "tenant-b-secret"
scopes = ["admin.read"]
organization_id = "tenant-pol-b"

[[api_keys]]
id = "key-a-data"
name = "Tenant A data key"
key = "key-a-secret"
organization_id = "tenant-pol-a"
project_id = "project-pol-a"

[[api_keys]]
id = "key-b-data"
name = "Tenant B data key"
key = "key-b-secret"
organization_id = "tenant-pol-b"
project_id = "project-pol-b"

[[policies]]
name = "global-deny"
effect = "deny"
code = "global_denied"
message = "denied everywhere"

[[policies]]
name = "deny-tenant-a"
effect = "deny"
organization_ids = ["tenant-pol-a"]

[[policies]]
name = "deny-tenant-b"
effect = "deny"
organization_ids = ["tenant-pol-b"]

[[policies]]
name = "deny-both-tenants"
effect = "deny"
organization_ids = ["tenant-pol-a", "tenant-pol-b"]

[[policies]]
name = "deny-key-b"
effect = "deny"
api_key_ids = ["key-b-data"]

[[policies]]
name = "deny-both-keys"
effect = "deny"
api_key_ids = ["key-a-data", "key-b-data"]

[[policies]]
name = "deny-project-b"
effect = "deny"
project_ids = ["project-pol-b"]

[[gateway_configs]]
id = "profile-shared"
name = "Shared profile"
revision = 1
cache_enabled = true

[[gateway_configs]]
id = "profile-a"
name = "Tenant A profile"
revision = 1
cache_enabled = true
api_key_ids = ["key-a-data"]

[[gateway_configs]]
id = "profile-b"
name = "Tenant B profile"
revision = 1
cache_enabled = false
api_key_ids = ["key-b-data"]

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://127.0.0.1:65535/v1"

[[models]]
name = "model-shared"
provider = "openai"
provider_model = "gpt-4o-mini"

[[models]]
name = "model-a"
provider = "openai"
provider_model = "gpt-4o"
visible_organization_ids = ["tenant-pol-a"]

[[models]]
name = "model-b"
provider = "openai"
provider_model = "gpt-4.1"
visible_organization_ids = ["tenant-pol-b"]

[[models]]
name = "model-both"
provider = "openai"
provider_model = "gpt-4.1-mini"
visible_organization_ids = ["tenant-pol-a", "tenant-pol-b"]

[[models]]
name = "model-project-b"
provider = "openai"
provider_model = "o4-mini"
visible_project_ids = ["project-pol-b"]

[[plugins]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[plugins.permissions]
tools = ["tool.echo"]

[[skill_packages]]
id = "skill-shared"
name = "Shared skill package"
version = "1.0.0"

[[skill_packages.capabilities]]
kind = "plugin"
id = "tool.echo"

[[skill_packages]]
id = "skill-a"
name = "Tenant A skill package"
version = "1.0.0"
api_key_ids = ["key-a-data"]

[[skill_packages.capabilities]]
kind = "plugin"
id = "tool.echo"

[[skill_packages]]
id = "skill-b"
name = "Tenant B skill package"
version = "1.0.0"
api_key_ids = ["key-b-data"]

[[skill_packages.capabilities]]
kind = "plugin"
id = "tool.echo"

[[skill_packages]]
id = "skill-both"
name = "Shared-by-key skill package"
version = "1.0.0"
api_key_ids = ["key-a-data", "key-b-data"]

[[skill_packages.capabilities]]
kind = "plugin"
id = "tool.echo"

[[agent_upstreams]]
id = "upstream-shared"
name = "Shared upstream"
protocol = "a2a"
endpoint = "http://127.0.0.1:65535/a2a"
capabilities = ["invoke", "read"]

[[agent_upstreams]]
id = "upstream-a"
name = "Tenant A upstream"
protocol = "a2a"
endpoint = "http://127.0.0.1:65535/a2a"
tenant_ids = ["key-a-data"]
capabilities = ["invoke", "read"]

[[agent_upstreams]]
id = "upstream-b"
name = "Tenant B upstream"
protocol = "a2a"
endpoint = "http://127.0.0.1:65535/a2a"
tenant_ids = ["key-b-data"]
capabilities = ["invoke", "read"]

[[agent_upstreams]]
id = "upstream-both"
name = "Shared-by-key upstream"
protocol = "a2a"
endpoint = "http://127.0.0.1:65535/a2a"
tenant_ids = ["key-a-data", "key-b-data"]
capabilities = ["invoke", "read"]
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

/// The `data` array of a list response as a SORTED `Vec<String>` of one field
/// -- the assertions below compare ROW SETS by identity, never counts and
/// never arrival order.
///
/// Sorted, not verbatim, and not by taste: `AppState::try_new` seeds the
/// control-plane store from the file and then reads the catalog straight back
/// out of it (`apply_control_plane_snapshot_to_config_from_repositories`), and
/// `sorted_control_plane_documents` keys that store by resource id. So
/// `config.policies` / `gateway_configs` / `skill_packages` /
/// `agent_upstreams` reach a handler in LEXICOGRAPHIC id order, not in the
/// order the fixture below declares them -- while `models`, which is not a
/// control-plane collection, does keep file order. Comparing sorted sets makes
/// every expectation here read the same way regardless of which side of that
/// line a collection falls on, and keeps the assertion about *which rows a
/// caller receives*, which is the whole of #535.
fn listed_field(response: String, field: &str) -> Vec<String> {
    let body = response_json(response);
    let mut values: Vec<String> = body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("list response has no data array: {body}"))
        .iter()
        .map(|row| {
            row[field]
                .as_str()
                .unwrap_or_else(|| panic!("row is missing {field}: {row}"))
                .to_string()
        })
        .collect();
    values.sort();
    values
}

fn string_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, got {value}"))
        .iter()
        .map(|entry| entry.as_str().unwrap_or_default().to_string())
        .collect()
}

fn row_named<'a>(body: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("list response has no data array: {body}"))
        .iter()
        .find(|row| row["name"] == name || row["id"] == name)
        .unwrap_or_else(|| panic!("row {name} is missing from {body}"))
}

/// Boots a gateway on the fixture above.
///
/// `start_ready_gateway` rather than `start_gateway` + `wait_for_gateway`
/// deliberately: it watches for an early child exit, so a config the gateway
/// *refuses* fails this helper in the time it takes the process to die
/// instead of parking each test on the harness's 300s readiness window. That
/// is precisely the failure mode that hid this suite's broken fixture behind
/// a five-minute timeout, and it closes the `free_addr()` bind race too.
fn start(dir: &tempfile::TempDir) -> (std::process::Child, String) {
    let config_path = dir.path().join("ferrogate.toml");
    start_ready_gateway(&config_path, |addr| write_config(&config_path, addr))
}

/// Site 1 -- `GET /admin/v1/policies` (local.rs:8589 in the issue). Before the
/// fix this returned EVERY `PolicyRule` verbatim to a tenant-scoped key.
#[test]
fn tenant_scoped_key_lists_only_policies_that_can_act_on_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/policies", &TENANT_A, "");
    // The blunt cross-tenant assertion first: tenant B's ids must not appear
    // ANYWHERE in the payload, in any field, in any rule.
    assert!(
        !raw.contains("tenant-pol-b"),
        "tenant A's policy list leaked tenant B's organization id: {raw}"
    );
    assert!(
        !raw.contains("key-b-data"),
        "tenant A's policy list leaked tenant B's api key id: {raw}"
    );
    assert!(
        !raw.contains("project-pol-b"),
        "tenant A's policy list leaked tenant B's project id: {raw}"
    );

    let names = listed_field(raw.clone(), "name");
    assert_eq!(
        names,
        vec![
            "deny-both-keys".to_string(),
            "deny-both-tenants".to_string(),
            "deny-tenant-a".to_string(),
            "global-deny".to_string(),
        ],
        "tenant A must see exactly the rules that can act on tenant A"
    );

    let body = response_json(raw);
    // A rule naming both tenants stays visible -- A is denied by it -- but is
    // rendered with only A's id.
    assert_eq!(
        string_list(&row_named(&body, "deny-both-tenants")["organization_ids"]),
        vec!["tenant-pol-a".to_string()],
        "the shared rule still names another tenant"
    );
    // ...and a rule naming both keys keeps only A's key id.
    assert_eq!(
        string_list(&row_named(&body, "deny-both-keys")["api_key_ids"]),
        vec!["key-a-data".to_string()],
        "the shared rule still names another tenant's api key"
    );
    // The genuinely global rule is unchanged: empty selectors are a wildcard,
    // not something to narrow away.
    assert!(
        string_list(&row_named(&body, "global-deny")["organization_ids"]).is_empty(),
        "the global rule gained a selector"
    );
    assert_eq!(row_named(&body, "global-deny")["code"], "global_denied");

    // The symmetric half: B's view is B's, not a copy of A's, so the filter is
    // keyed on the CALLER.
    let tenant_b = http_request(&addr, "GET", "/admin/v1/policies", &TENANT_B, "");
    assert!(
        !tenant_b.contains("tenant-pol-a") && !tenant_b.contains("key-a-data"),
        "tenant B's policy list leaked tenant A's ids: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "name"),
        vec![
            "deny-both-keys".to_string(),
            "deny-both-tenants".to_string(),
            "deny-key-b".to_string(),
            "deny-project-b".to_string(),
            "deny-tenant-b".to_string(),
            "global-deny".to_string(),
        ],
        "tenant B must see exactly the rules that can act on tenant B"
    );

    // And the platform operator still gets every rule verbatim, so the fix is
    // a scoping of the view and not a blanket deny.
    let operator = http_request(&addr, "GET", "/admin/v1/policies", &ADMIN, "");
    let operator_body = response_json(operator.clone());
    assert_eq!(
        listed_field(operator, "name"),
        vec![
            "deny-both-keys".to_string(),
            "deny-both-tenants".to_string(),
            "deny-key-b".to_string(),
            "deny-project-b".to_string(),
            "deny-tenant-a".to_string(),
            "deny-tenant-b".to_string(),
            "global-deny".to_string(),
        ],
        "platform operator lost rules from the full catalog"
    );
    assert_eq!(
        string_list(&row_named(&operator_body, "deny-both-tenants")["organization_ids"]),
        vec!["tenant-pol-a".to_string(), "tenant-pol-b".to_string()],
        "platform operator received a narrowed rule"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 2 -- `GET /admin/v1/policies/{name}`. Names came free from the list,
/// so the by-id read was the second half of an enumeration primitive; it must
/// answer identically for out-of-scope and nonexistent.
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_policy_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/policies/deny-tenant-a",
        &TENANT_A,
        "",
    ));
    assert_eq!(own["policy"]["name"], "deny-tenant-a");
    assert_eq!(
        string_list(&own["policy"]["organization_ids"]),
        vec!["tenant-pol-a".to_string()]
    );

    // The by-id read narrows exactly like the list does.
    let shared = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/policies/deny-both-tenants",
        &TENANT_A,
        "",
    ));
    assert_eq!(
        string_list(&shared["policy"]["organization_ids"]),
        vec!["tenant-pol-a".to_string()],
        "the by-id read returned another tenant's id"
    );

    for name in [
        "deny-tenant-b",
        "deny-key-b",
        "deny-project-b",
        "policy-that-does-not-exist",
    ] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused policy {name}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for policy {name}: {response}"
        );
        assert!(
            !response.contains("tenant-pol-b") && !response.contains("key-b-data"),
            "the refusal for {name} still leaked tenant B's ids: {response}"
        );
    }

    // The platform operator still reads any rule by name...
    let operator = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/policies/deny-tenant-b",
        &ADMIN,
        "",
    ));
    assert_eq!(
        string_list(&operator["policy"]["organization_ids"]),
        vec!["tenant-pol-b".to_string()]
    );

    // ...and still gets 404, NOT 403, for a name that genuinely does not
    // exist. This is what pins the `&& !scope.is_full()` clause on this
    // handler: delete it and the operator gets `tenant_scope_denied` here
    // while every scope assertion above still passes, which is exactly how
    // #518's reviewer found the same clause unpinned.
    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/policies/policy-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent policy, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("policy_not_found"),
        "operator 404 must name policy_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 3 -- `GET /admin/v1/gateway-configs` (leak 2: per-profile
/// `api_key_ids` across tenants).
#[test]
fn tenant_scoped_key_lists_only_gateway_profiles_its_keys_may_select() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/gateway-configs", &TENANT_A, "");
    assert!(
        !raw.contains("key-b-data"),
        "tenant A's gateway-config list leaked tenant B's api key id: {raw}"
    );
    assert_eq!(
        listed_field(raw.clone(), "id"),
        vec!["profile-a".to_string(), "profile-shared".to_string()],
        "tenant A must see only the profiles one of its own keys may select"
    );
    let body = response_json(raw);
    assert_eq!(
        string_list(&row_named(&body, "profile-a")["api_key_ids"]),
        vec!["key-a-data".to_string()]
    );
    assert!(
        string_list(&row_named(&body, "profile-shared")["api_key_ids"]).is_empty(),
        "the unrestricted profile gained a key selector"
    );

    let tenant_b = http_request(&addr, "GET", "/admin/v1/gateway-configs", &TENANT_B, "");
    assert!(
        !tenant_b.contains("key-a-data"),
        "tenant B's gateway-config list leaked tenant A's api key id: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "id"),
        vec!["profile-b".to_string(), "profile-shared".to_string()]
    );

    let operator = http_request(&addr, "GET", "/admin/v1/gateway-configs", &ADMIN, "");
    assert_eq!(
        listed_field(operator, "id"),
        vec![
            "profile-a".to_string(),
            "profile-b".to_string(),
            "profile-shared".to_string(),
        ],
        "platform operator lost profiles from the full catalog"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 4 -- `GET /admin/v1/gateway-configs/{id}`.
#[test]
fn tenant_scoped_key_cannot_fetch_an_out_of_scope_gateway_profile_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/gateway-configs/profile-a",
        &TENANT_A,
        "",
    ));
    assert_eq!(own["gateway_config"]["id"], "profile-a");
    assert_eq!(
        string_list(&own["gateway_config"]["api_key_ids"]),
        vec!["key-a-data".to_string()]
    );

    for id in ["profile-b", "profile-that-does-not-exist"] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused gateway profile {id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for gateway profile {id}: {response}"
        );
        assert!(
            !response.contains("key-b-data"),
            "the refusal for {id} still leaked tenant B's api key id: {response}"
        );
    }

    let operator = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/gateway-configs/profile-b",
        &ADMIN,
        "",
    ));
    assert_eq!(
        string_list(&operator["gateway_config"]["api_key_ids"]),
        vec!["key-b-data".to_string()]
    );

    // Sibling of the policy assertion: the operator still gets 404, NOT 403,
    // for an absent id -- this pins `&& !scope.is_full()` on this handler.
    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/gateway-configs/profile-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent gateway profile, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("gateway_config_not_found"),
        "operator 404 must name gateway_config_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 5 -- `GET /admin/v1/models`. Found by the re-derived sweep, and the
/// one the first sweep classified as "not tenant-bearing", which was false:
/// `.cloned()` returned the whole `Model`, and `Model` carries
/// `visible_organization_ids`/`visible_project_ids` (both in the admin
/// response schema). `GET /v1/models` has filtered on exactly these since
/// #515 via `can_tenant_use_model`; the admin listing did not.
#[test]
fn tenant_scoped_key_lists_only_models_visible_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/models", &TENANT_A, "");
    assert!(
        !raw.contains("tenant-pol-b"),
        "tenant A's model list leaked tenant B's organization id: {raw}"
    );
    assert!(
        !raw.contains("project-pol-b"),
        "tenant A's model list leaked tenant B's project id: {raw}"
    );
    assert_eq!(
        listed_field(raw.clone(), "name"),
        vec![
            "model-a".to_string(),
            "model-both".to_string(),
            "model-shared".to_string(),
        ],
        "tenant A must see exactly the models its tenant may call"
    );

    let body = response_json(raw);
    // The AND semantics of `ModelVisibility::allows` make the both-tenants
    // model visible to A -- and it must render with only A's id.
    assert_eq!(
        string_list(&row_named(&body, "model-both")["visible_organization_ids"]),
        vec!["tenant-pol-a".to_string()],
        "the shared model still names another tenant"
    );
    // An empty visibility list is a wildcard, not something to narrow away.
    assert!(
        string_list(&row_named(&body, "model-shared")["visible_organization_ids"]).is_empty(),
        "the unrestricted model gained an organization selector"
    );

    let tenant_b = http_request(&addr, "GET", "/admin/v1/models", &TENANT_B, "");
    assert!(
        !tenant_b.contains("tenant-pol-a"),
        "tenant B's model list leaked tenant A's organization id: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "name"),
        vec![
            "model-b".to_string(),
            "model-both".to_string(),
            "model-project-b".to_string(),
            "model-shared".to_string(),
        ],
        "tenant B must see exactly the models its tenant may call"
    );

    let operator = http_request(&addr, "GET", "/admin/v1/models", &ADMIN, "");
    let operator_body = response_json(operator.clone());
    assert_eq!(
        listed_field(operator, "name"),
        vec![
            "model-a".to_string(),
            "model-b".to_string(),
            "model-both".to_string(),
            "model-project-b".to_string(),
            "model-shared".to_string(),
        ],
        "platform operator lost models from the full catalog"
    );
    assert_eq!(
        string_list(&row_named(&operator_body, "model-both")["visible_organization_ids"]),
        vec!["tenant-pol-a".to_string(), "tenant-pol-b".to_string()],
        "platform operator received a narrowed model"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 6 -- `GET /admin/v1/skill-packages[/{id}]`. The same `api_key_ids`
/// selector `GatewayConfigProfile` carries, on a route the first sweep did
/// not mention in either direction.
#[test]
fn tenant_scoped_key_lists_only_skill_packages_its_keys_may_load() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/skill-packages", &TENANT_A, "");
    assert!(
        !raw.contains("key-b-data"),
        "tenant A's skill-package list leaked tenant B's api key id: {raw}"
    );
    assert_eq!(
        listed_field(raw.clone(), "id"),
        vec![
            "skill-a".to_string(),
            "skill-both".to_string(),
            "skill-shared".to_string(),
        ],
        "tenant A must see only the packages one of its own keys may load"
    );
    let body = response_json(raw);
    assert_eq!(
        string_list(&row_named(&body, "skill-both")["api_key_ids"]),
        vec!["key-a-data".to_string()],
        "the shared package still names another tenant's api key"
    );
    assert!(
        string_list(&row_named(&body, "skill-shared")["api_key_ids"]).is_empty(),
        "the unrestricted package gained a key selector"
    );

    let tenant_b = http_request(&addr, "GET", "/admin/v1/skill-packages", &TENANT_B, "");
    assert!(
        !tenant_b.contains("key-a-data"),
        "tenant B's skill-package list leaked tenant A's api key id: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "id"),
        vec![
            "skill-b".to_string(),
            "skill-both".to_string(),
            "skill-shared".to_string(),
        ]
    );

    let operator = http_request(&addr, "GET", "/admin/v1/skill-packages", &ADMIN, "");
    assert_eq!(
        listed_field(operator, "id"),
        vec![
            "skill-a".to_string(),
            "skill-b".to_string(),
            "skill-both".to_string(),
            "skill-shared".to_string(),
        ],
        "platform operator lost packages from the full catalog"
    );

    // The by-id walk that would otherwise re-enumerate what the list hides.
    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/skill-packages/skill-both",
        &TENANT_A,
        "",
    ));
    assert_eq!(
        string_list(&own["skill_package"]["api_key_ids"]),
        vec!["key-a-data".to_string()],
        "the by-id read returned another tenant's api key id"
    );
    for id in ["skill-b", "skill-that-does-not-exist"] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/skill-packages/{id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused skill package {id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for skill package {id}: {response}"
        );
        assert!(
            !response.contains("key-b-data"),
            "the refusal for {id} still leaked tenant B's api key id: {response}"
        );
    }

    // The operator's 404 for a genuinely absent id is what pins
    // `&& !scope.is_full()` on THIS handler -- it is not implied by the
    // policy/gateway-config assertions on the other four.
    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/skill-packages/skill-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent skill package, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("skill_package_not_found"),
        "operator 404 must name skill_package_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Site 7 -- `GET /admin/v1/agent-upstreams[/{id}]`. The clearest instance of
/// the "primitive exists, this call site never calls it" shape:
/// `agent_upstream_visible_to_auth` already gated `/v1/agents` and the agent
/// invoke path, and the admin read simply did not call it.
///
/// Note `AgentUpstreamConfig::tenant_ids` is matched by that predicate
/// against the caller's API KEY id, not its organization id, so the fixture
/// names key ids -- narrowing this field against the tenant id instead would
/// hide every upstream from every tenant, and the operator row below is what
/// separates "correctly narrowed" from "accidentally emptied".
#[test]
fn tenant_scoped_key_lists_only_agent_upstreams_its_keys_may_reach() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    let raw = http_request(&addr, "GET", "/admin/v1/agent-upstreams", &TENANT_A, "");
    assert!(
        !raw.contains("key-b-data"),
        "tenant A's agent-upstream list leaked tenant B's api key id: {raw}"
    );
    assert_eq!(
        listed_field(raw.clone(), "id"),
        vec![
            "upstream-a".to_string(),
            "upstream-both".to_string(),
            "upstream-shared".to_string(),
        ],
        "tenant A must see only the upstreams one of its own keys may reach"
    );
    let body = response_json(raw);
    assert_eq!(
        string_list(&row_named(&body, "upstream-both")["tenant_ids"]),
        vec!["key-a-data".to_string()],
        "the shared upstream still names another tenant's api key"
    );
    assert!(
        string_list(&row_named(&body, "upstream-shared")["tenant_ids"]).is_empty(),
        "the unrestricted upstream gained a selector"
    );

    let tenant_b = http_request(&addr, "GET", "/admin/v1/agent-upstreams", &TENANT_B, "");
    assert!(
        !tenant_b.contains("key-a-data"),
        "tenant B's agent-upstream list leaked tenant A's api key id: {tenant_b}"
    );
    assert_eq!(
        listed_field(tenant_b, "id"),
        vec![
            "upstream-b".to_string(),
            "upstream-both".to_string(),
            "upstream-shared".to_string(),
        ]
    );

    let operator = http_request(&addr, "GET", "/admin/v1/agent-upstreams", &ADMIN, "");
    let operator_body = response_json(operator.clone());
    assert_eq!(
        listed_field(operator, "id"),
        vec![
            "upstream-a".to_string(),
            "upstream-b".to_string(),
            "upstream-both".to_string(),
            "upstream-shared".to_string(),
        ],
        "platform operator lost upstreams from the full catalog"
    );
    assert_eq!(
        string_list(&row_named(&operator_body, "upstream-both")["tenant_ids"]),
        vec!["key-a-data".to_string(), "key-b-data".to_string()],
        "platform operator received a narrowed upstream"
    );

    let own = response_json(http_request(
        &addr,
        "GET",
        "/admin/v1/agent-upstreams/upstream-both",
        &TENANT_A,
        "",
    ));
    assert_eq!(
        string_list(&own["agent_upstream"]["tenant_ids"]),
        vec!["key-a-data".to_string()],
        "the by-id read returned another tenant's api key id"
    );
    for id in ["upstream-b", "upstream-that-does-not-exist"] {
        let response = http_request(
            &addr,
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &TENANT_A,
            "",
        );
        assert!(
            status_line(&response).contains("403"),
            "tenant A was not refused agent upstream {id}: {response}"
        );
        assert!(
            response.contains("tenant_scope_denied"),
            "unexpected refusal code for agent upstream {id}: {response}"
        );
        assert!(
            !response.contains("key-b-data"),
            "the refusal for {id} still leaked tenant B's api key id: {response}"
        );
    }

    let missing = http_request(
        &addr,
        "GET",
        "/admin/v1/agent-upstreams/upstream-that-does-not-exist",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&missing).contains("404"),
        "operator must get 404 for an absent agent upstream, not a scope refusal: {missing}"
    );
    assert!(
        missing.contains("agent_upstream_not_found"),
        "operator 404 must name agent_upstream_not_found: {missing}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn post_as_operator(addr: &str, path: &str, body: &str) -> serde_json::Value {
    let response = http_request(addr, "POST", path, &ADMIN, body);
    assert!(
        status_line(&response).contains("200") || status_line(&response).contains("201"),
        "POST {path} failed: {response}"
    );
    response_json(response)
}

/// The DURABLE half of `config_catalog_scope`. Every test above seeds
/// ownership from static `[[api_keys]]`, so deleting both
/// `api_key_ids.extend(list_virtual_api_keys(..))` and
/// `project_ids.extend(list_projects(..))` leaves them all green -- while in
/// production a tenant's ownership set comes almost entirely from those two
/// listings, because the console key `provision_gateway_api_key` mints is a
/// durable/virtual key.
///
/// So: create a real project and a real virtual key for each tenant through
/// the admin API, then create catalog entries selected ONLY by those runtime
/// ids. Tenant A must see its own two and neither of B's. Delete either
/// `extend` and A's own entry stops being visible; keep the `extend` but drop
/// its `tenant_id` filter and B's entry becomes visible to A.
///
/// The two halves have to ride on DIFFERENT selectors, and not by taste:
///
/// * the project half is a `[[policies]]` rule carrying only `project_ids`,
///   because `PolicyRule` is the one catalog type with a project selector and
///   `validate_policies` does not cross-check `project_ids` against anything;
/// * the virtual-key half is an `[[agent_upstreams]]` entry carrying only
///   `tenant_ids`. It CANNOT be a policy: every admin write re-runs
///   `Config::validate` on the candidate, and `validate_policies`
///   (`validate.rs:1945`) rejects any `api_key_ids` entry that is not a
///   static `[[api_keys]]` id -- a durable virtual key lives in the
///   `api_key_records` store and never enters `config.api_keys`, so such a
///   rule can never be committed. `validate_agent_upstreams` takes its api-key
///   set as `_api_key_ids` and never consults it, and
///   `ConfigCatalogScope::visible_agent_upstream` narrows `tenant_ids`
///   against exactly the `api_key_ids` set `list_virtual_api_keys` feeds --
///   so this is the one surface on which a durable key id can be both stored
///   and scoped.
#[test]
fn config_catalog_scope_resolves_durable_virtual_keys_and_projects() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gateway, addr) = start(&dir);

    for tenant in ["tenant-pol-a", "tenant-pol-b"] {
        post_as_operator(
            &addr,
            "/admin/v1/tenant-accounts",
            &format!(r#"{{"id":"{tenant}","name":"{tenant}","slug":"{tenant}"}}"#),
        );
    }

    let mut virtual_key_ids = std::collections::BTreeMap::new();
    for (tenant, suffix) in [("tenant-pol-a", "a"), ("tenant-pol-b", "b")] {
        post_as_operator(
            &addr,
            "/admin/v1/projects",
            &format!(
                r#"{{"id":"project-durable-{suffix}","tenant_id":"{tenant}","name":"Durable {suffix}","slug":"project-durable-{suffix}"}}"#
            ),
        );
        post_as_operator(
            &addr,
            "/admin/v1/workspaces",
            &format!(
                r#"{{"id":"workspace-durable-{suffix}","project_id":"project-durable-{suffix}","name":"Durable {suffix}","slug":"workspace-durable-{suffix}"}}"#
            ),
        );
        let created = post_as_operator(
            &addr,
            "/admin/v1/virtual-keys",
            &format!(
                r#"{{"name":"Durable {suffix} key","workspace_id":"workspace-durable-{suffix}","scopes":["chat.completions"]}}"#
            ),
        );
        virtual_key_ids.insert(
            suffix,
            created["key"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("created virtual key has no id: {created}"))
                .to_string(),
        );
    }

    // Catalog entries whose ONLY selector is a runtime-created id -- each one
    // invisible to a scope that resolves ownership from static config alone.
    for suffix in ["a", "b"] {
        let virtual_key_id = &virtual_key_ids[suffix];
        post_as_operator(
            &addr,
            "/admin/v1/policies",
            &format!(
                r#"{{"name":"deny-durable-project-{suffix}","effect":"deny","project_ids":["project-durable-{suffix}"]}}"#
            ),
        );
        post_as_operator(
            &addr,
            "/admin/v1/agent-upstreams",
            &format!(
                r#"{{"id":"upstream-durable-{suffix}","name":"Durable {suffix} upstream","protocol":"a2a","endpoint":"http://127.0.0.1:65535/a2a","tenant_ids":["{virtual_key_id}"]}}"#
            ),
        );
    }

    // --- `project_ids.extend(list_projects(..))`, read through the policy
    // list. Delete that `extend` and `deny-durable-project-a` disappears from
    // tenant A's view; keep it but drop the `tenant_id` filter and
    // `deny-durable-project-b` appears in it.
    let raw = http_request(&addr, "GET", "/admin/v1/policies", &TENANT_A, "");
    assert_eq!(
        listed_field(raw.clone(), "name"),
        vec![
            "deny-both-keys".to_string(),
            "deny-both-tenants".to_string(),
            "deny-durable-project-a".to_string(),
            "deny-tenant-a".to_string(),
            "global-deny".to_string(),
        ],
        "tenant A's policy view must gain exactly its own durable-project rule"
    );
    assert!(
        !raw.contains("project-durable-b"),
        "tenant A's policy list leaked tenant B's durable project id: {raw}"
    );
    // The id is rendered, not merely used for the visibility decision.
    assert_eq!(
        string_list(&row_named(&response_json(raw), "deny-durable-project-a")["project_ids"]),
        vec!["project-durable-a".to_string()]
    );

    // --- `api_key_ids.extend(list_virtual_api_keys(..))`, read through the
    // agent-upstream list, the one catalog surface whose selector may name a
    // durable key id at all.
    let upstreams = http_request(&addr, "GET", "/admin/v1/agent-upstreams", &TENANT_A, "");
    assert_eq!(
        listed_field(upstreams.clone(), "id"),
        vec![
            "upstream-a".to_string(),
            "upstream-both".to_string(),
            "upstream-durable-a".to_string(),
            "upstream-shared".to_string(),
        ],
        "the durable virtual key tenant A owns did not reach the scope -- \
         list_virtual_api_keys is not feeding it"
    );
    assert!(
        !upstreams.contains(&virtual_key_ids["b"]),
        "tenant A's agent-upstream list leaked tenant B's durable key id: {upstreams}"
    );
    assert_eq!(
        string_list(&row_named(&response_json(upstreams), "upstream-durable-a")["tenant_ids"]),
        vec![virtual_key_ids["a"].clone()]
    );

    // Symmetric control on both halves: B sees B's, so the two listings are
    // filtered on the CALLER's tenant id and not merely appended.
    let tenant_b_policies = http_request(&addr, "GET", "/admin/v1/policies", &TENANT_B, "");
    assert_eq!(
        listed_field(tenant_b_policies.clone(), "name"),
        vec![
            "deny-both-keys".to_string(),
            "deny-both-tenants".to_string(),
            "deny-durable-project-b".to_string(),
            "deny-key-b".to_string(),
            "deny-project-b".to_string(),
            "deny-tenant-b".to_string(),
            "global-deny".to_string(),
        ],
        "tenant B lost its own durable-project rule, or gained tenant A's"
    );
    assert!(
        !tenant_b_policies.contains("project-durable-a"),
        "tenant B's policy list leaked tenant A's durable project id: {tenant_b_policies}"
    );

    let tenant_b_upstreams = http_request(&addr, "GET", "/admin/v1/agent-upstreams", &TENANT_B, "");
    assert_eq!(
        listed_field(tenant_b_upstreams.clone(), "id"),
        vec![
            "upstream-b".to_string(),
            "upstream-both".to_string(),
            "upstream-durable-b".to_string(),
            "upstream-shared".to_string(),
        ],
        "tenant B lost its own durable-key upstream, or gained tenant A's"
    );
    assert!(
        !tenant_b_upstreams.contains(&virtual_key_ids["a"]),
        "tenant B's agent-upstream list leaked tenant A's durable key id: {tenant_b_upstreams}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
