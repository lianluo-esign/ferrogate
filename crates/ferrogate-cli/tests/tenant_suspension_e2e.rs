// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Live regression for issue #514 -- "suspension enforces nothing".
// This is the test-gate audit's own probe, turned into a test. Before the fix,
// against a real gateway process, after suspending the tenant (200 OK):
//   * a pre-existing virtual key still returned 200 from GET /v1/models;
//   * the same key still PASSED auth on POST /v1/chat/completions;
//   * a brand-new virtual key could still be minted under the suspended chain
//     (201 + live secret);
//   * POST /admin/v1/projects under the suspended tenant returned 201.
// Every one of those is asserted here, in both directions (before suspension it
// works, after suspension it is refused, after un-suspension it works again) so
// the assertions cannot pass vacuously against a gateway that refuses
// everything.

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

fn write_config(path: &std::path::Path, gateway_addr: &str, provider_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
platform_operator = true

# A credential that names ONLY a project -- the shape the first #514 landing
# could not see. `organization_id` is optional on a native api-key, so this key
# never names `tenant-susp` at all; the gate has to WALK from the project row to
# its tenant to find the suspension. Before the chain walk this key kept serving
# `/v1/models` with its tenant fully suspended.
#
# #540: it declares `platform_operator` rather than an `organization_id`,
# because naming the tenant here would hand the gate the answer it is supposed
# to have to walk for. That is exactly what this key was before #540 (root by
# omission), only now written down -- and `platform_operator` does not shorten
# the chain: the walk reads the ids the key DECLARES, and this one still
# declares only `project_id`.
[[api_keys]]
id = "project-only"
name = "Project-scoped key"
key = "project-only-secret"
project_id = "proj-susp"
scopes = ["models.read"]
platform_operator = true

# The admin-console session credential `a_tenant_can_re_enable_the_project_it
# _disabled` needs: TENANT-scoped (so `authorize_tenant_scope` lets it edit its
# own project) and chained to the project it will turn off (so the request-time
# gate reaches it). It cannot be a VIRTUAL key -- since the empty-scope
# escalation fix a virtual key is refused any privileged `admin.*` scope, so the
# console-session shape is a static/durable credential, not a minted one. The
# rows it names are created by that test through the admin API.
[[api_keys]]
id = "console-off"
name = "Console session"
key = "console-off-secret"
organization_id = "tenant-off"
project_id = "proj-off"
workspace_id = "ws-off"
scopes = ["admin.read", "admin.write", "models.read"]
"#
        ),
    )
    .unwrap();
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn body_json(response: &str) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn admin(gateway_addr: &str, method: &str, path: &str, body: &str) -> String {
    http_request(gateway_addr, method, path, &ADMIN, body)
}

fn as_key(gateway_addr: &str, secret: &str, method: &str, path: &str, body: &str) -> String {
    http_request(
        gateway_addr,
        method,
        path,
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        body,
    )
}

fn set_tenant_status(gateway_addr: &str, status: &str) {
    let response = admin(
        gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-susp",
        &format!(r#"{{"name":"Suspendable","slug":"tenant-susp","status":"{status}"}}"#),
    );
    assert!(
        status_line(&response).contains("200"),
        "setting tenant status to {status} failed: {response}"
    );
}

/// The error body a refused request must carry: a typed 403 with a
/// distinguishable code -- never a panic, never a generic 500, never a silent
/// 200.
fn assert_suspended_rejection(response: &str, expected_code: &str) {
    assert!(
        status_line(response).contains("403"),
        "expected a 403-shaped rejection, got: {response}"
    );
    let body = body_json(response);
    let code = body["error"]["code"]
        .as_str()
        .or_else(|| body["code"].as_str())
        .unwrap_or_else(|| panic!("rejection body carries no error code: {body}"));
    assert_eq!(code, expected_code, "unexpected rejection code in {body}");
}

#[test]
fn suspending_a_tenant_stops_its_keys_and_blocks_new_credentials() {
    let gateway_addr = free_addr();
    // Two upstream responses: one for the pre-suspension baseline, one for the
    // post-reactivation control. If suspension leaked a single request through,
    // the upstream would be over-consumed and the control call would fail --
    // the counter is part of the proof.
    let (provider_addr, _provider) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_susp","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // --- Bootstrap tenant -> project -> workspace -> virtual key ------------
    let tenant = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-susp","name":"Suspendable","slug":"tenant-susp"}"#,
    );
    assert!(
        status_line(&tenant).contains("200") || status_line(&tenant).contains("201"),
        "tenant setup: {tenant}"
    );
    let project = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"proj-susp","tenant_id":"tenant-susp","name":"Proj","slug":"proj-susp"}"#,
    );
    assert!(
        status_line(&project).contains("200") || status_line(&project).contains("201"),
        "project setup: {project}"
    );
    let workspace = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"ws-susp","project_id":"proj-susp","name":"Ws","slug":"ws-susp"}"#,
    );
    assert!(
        status_line(&workspace).contains("200") || status_line(&workspace).contains("201"),
        "workspace setup: {workspace}"
    );
    let created = body_json(&admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"name":"Pre-existing key","workspace_id":"ws-susp","scopes":["chat.completions","models.read"]}"#,
    ));
    let secret = created["secret"]
        .as_str()
        .expect("create must return the plaintext secret")
        .to_string();

    // --- Baseline: everything works while the tenant is active -------------
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert!(
        status_line(&models).contains("200"),
        "baseline GET /v1/models must succeed while active: {models}"
    );
    let chat = as_key(
        &gateway_addr,
        &secret,
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&chat).contains("200"),
        "baseline chat completion must succeed while active: {chat}"
    );
    // Baseline for the project-only credential, so its post-suspension refusal
    // below cannot pass vacuously (e.g. because the key was simply invalid).
    let project_only = as_key(
        &gateway_addr,
        "project-only-secret",
        "GET",
        "/v1/models",
        "",
    );
    assert!(
        status_line(&project_only).contains("200"),
        "baseline GET /v1/models with a project-only key must succeed: {project_only}"
    );

    // --- Suspend the tenant ------------------------------------------------
    set_tenant_status(&gateway_addr, "suspended");

    // 1. Request-time seam: the PRE-EXISTING key stops working. This is the
    //    one that matters for billing -- before #514 this returned 200.
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert_suspended_rejection(&models, "tenancy_suspended");

    // 2. Same key, the spend-generating route. Before #514 this reached model
    //    resolution (400 model_not_found), i.e. it had PASSED authentication.
    let chat = as_key(
        &gateway_addr,
        &secret,
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert_suspended_rejection(&chat, "tenancy_suspended");

    // 3. Attach-time seam: no fresh virtual key under the suspended chain.
    //    Before #514 this returned 201 with a live secret.
    let minted = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"name":"Minted while suspended","workspace_id":"ws-susp","scopes":["chat.completions"]}"#,
    );
    assert_suspended_rejection(&minted, "inactive_tenancy_reference");
    assert!(
        !body_json(&minted).to_string().contains("fg_"),
        "a refused mint must not leak a secret: {minted}"
    );

    // 4. Attach-time seam: no new project under the suspended tenant.
    let new_project = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"proj-susp-2","tenant_id":"tenant-susp","name":"Proj2","slug":"proj-susp-2"}"#,
    );
    assert_suspended_rejection(&new_project, "inactive_tenancy_reference");

    // 5. Attach-time seam: no new workspace under the suspended tenant's
    //    (still nominally active) project -- the chain is checked whole.
    let new_workspace = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"ws-susp-2","project_id":"proj-susp","name":"Ws2","slug":"ws-susp-2"}"#,
    );
    assert_suspended_rejection(&new_workspace, "inactive_tenancy_reference");

    // 6. Attach-time seam: no native api-key scoped to the suspended chain.
    //    Note the payload names ONLY `project_id`: nothing here mentions
    //    `tenant-susp`, so this 403 is only reachable if the gate walks from
    //    the project row up to its tenant.
    let new_api_key = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/api-keys",
        r#"{"id":"ak-susp","name":"AK","key":"ak-secret-value","project_id":"proj-susp"}"#,
    );
    assert_suspended_rejection(&new_api_key, "inactive_tenancy_reference");

    // 7. Request-time seam, same hole: a live credential that declares only
    //    `project_id` must stop serving too. This is the issue's headline
    //    symptom -- the first landing resolved the chain from the ids the
    //    CALLER named, so this key's chain was `[proj-susp(active)]` and the
    //    suspended tenant above it was never read.
    let project_only = as_key(
        &gateway_addr,
        "project-only-secret",
        "GET",
        "/v1/models",
        "",
    );
    assert_suspended_rejection(&project_only, "tenancy_suspended");

    // 8. Rotation is a mint: it issues fresh secret material against the same
    //    chain, so "suspend the tenant" must not be undoable by rotating an
    //    existing key instead of creating one.
    let rotated = admin(
        &gateway_addr,
        "POST",
        &format!(
            "/admin/v1/virtual-keys/{}/rotate",
            created["key"]["id"].as_str().expect("created key id")
        ),
        "",
    );
    assert_suspended_rejection(&rotated, "inactive_tenancy_reference");
    assert!(
        !body_json(&rotated).to_string().contains("fg_"),
        "a refused rotation must not leak a secret: {rotated}"
    );

    // --- Reactivate: suspension is reversible, and un-suspending is itself
    // --- never blocked (the operator key carries no organization_id).
    set_tenant_status(&gateway_addr, "active");
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert!(
        status_line(&models).contains("200"),
        "the same key must work again once the tenant is reactivated: {models}"
    );
    let chat = as_key(
        &gateway_addr,
        &secret,
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&chat).contains("200"),
        "spend must resume after reactivation: {chat}"
    );
    let project_only = as_key(
        &gateway_addr,
        "project-only-secret",
        "GET",
        "/v1/models",
        "",
    );
    assert!(
        status_line(&project_only).contains("200"),
        "a project-only key must work again once its tenant is reactivated: {project_only}"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Finding 3: an unrecognized `status` token must be REFUSED at the write, not
/// accepted with a 200 that silently means "active".
///
/// The read side deliberately fails open so legacy rows keep working; paired
/// with an unvalidated write that produced the very failure #514 exists to
/// kill -- `{"status":"suspend"}` answered 200, the console rendered
/// `suspend`, and the tenant kept serving. Both halves are asserted: the typo
/// is a 400 AND the tenant is verifiably still serving afterwards (so the test
/// cannot pass by refusing everything), and the correctly-spelled token still
/// works.
#[test]
fn an_unrecognized_status_token_is_refused_rather_than_silently_ignored() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider) = spawn_provider_upstream(1, r#"{"id":"unused"}"#);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-typo","name":"Typo","slug":"tenant-typo"}"#,
    );
    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"proj-typo","tenant_id":"tenant-typo","name":"P","slug":"proj-typo"}"#,
    );
    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"ws-typo","project_id":"proj-typo","name":"W","slug":"ws-typo"}"#,
    );

    for (path, body) in [
        (
            "/admin/v1/tenant-accounts/tenant-typo",
            r#"{"name":"Typo","slug":"tenant-typo","status":"suspend"}"#,
        ),
        (
            "/admin/v1/projects/proj-typo",
            r#"{"tenant_id":"tenant-typo","name":"P","slug":"proj-typo","status":"suspend"}"#,
        ),
        (
            "/admin/v1/workspaces/ws-typo",
            r#"{"project_id":"proj-typo","name":"W","slug":"ws-typo","status":"suspend"}"#,
        ),
    ] {
        let response = admin(&gateway_addr, "PUT", path, body);
        assert!(
            status_line(&response).contains("400"),
            "PUT {path} with status=suspend must be refused, got: {response}"
        );
    }

    // The rows are untouched, so a key under them still authenticates: the 400s
    // above are a refusal to write, not a refusal to serve.
    let created = body_json(&admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"name":"Typo key","workspace_id":"ws-typo","scopes":["models.read"]}"#,
    ));
    let secret = created["secret"].as_str().expect("secret").to_string();
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert!(
        status_line(&models).contains("200"),
        "a rejected status write must leave the tenancy usable: {models}"
    );

    // The correctly-spelled token is accepted and DOES take effect -- the guard
    // against a validator that simply rejects everything.
    let accepted = admin(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-typo",
        r#"{"name":"Typo","slug":"tenant-typo","status":"SUSPENDED"}"#,
    );
    assert!(
        status_line(&accepted).contains("200"),
        "a canonical status token must still be accepted: {accepted}"
    );
    assert_suspended_rejection(
        &as_key(&gateway_addr, &secret, "GET", "/v1/models", ""),
        "tenancy_suspended",
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Finding 5: `disabled` must not be a one-way door.
///
/// `disabled` is documented as the TENANT's own "turn this project off" switch,
/// but the request-time gate runs inside `authenticate()`, before any handler
/// body, and a tenant-scoped console key is scoped to the project it just
/// disabled -- so gating the reversal route on it would leave the tenant unable
/// to undo its own self-service action without platform-operator help. The
/// lifecycle PUT/PATCH routes therefore authenticate against the Recovery seam.
#[test]
fn a_tenant_can_re_enable_the_project_it_disabled() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider) = spawn_provider_upstream(1, r#"{"id":"unused"}"#);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-off","name":"Off","slug":"tenant-off"}"#,
    );
    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"proj-off","tenant_id":"tenant-off","name":"P","slug":"proj-off"}"#,
    );
    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"ws-off","project_id":"proj-off","name":"W","slug":"ws-off"}"#,
    );
    // A TENANT-scoped admin key chained to the project it is about to disable
    // -- exactly the shape an admin-console login carries, and what makes the
    // lock-out reachable at all. A platform-operator key carries no tenancy
    // chain and was never gated.
    //
    // It is declared in the config rather than minted here: a VIRTUAL key is
    // refused every privileged `admin.*` scope (the empty-scope escalation fix
    // makes that a 400 `invalid_virtual_key`), so a console session that can
    // PUT a project is a static or durable credential. Minting one was this
    // test's original premise and it was never true.
    let console = "console-off-secret";
    let console_key = body_json(&admin(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/console-off",
        "",
    ));
    assert_eq!(
        console_key["key"]["organization_id"], "tenant-off",
        "the session key must be tenant-scoped, not platform root: {console_key}"
    );
    assert_eq!(
        console_key["key"]["project_id"], "proj-off",
        "...and chained to the project it disables: {console_key}"
    );

    let disabled = as_key(
        &gateway_addr,
        &console,
        "PUT",
        "/admin/v1/projects/proj-off",
        r#"{"tenant_id":"tenant-off","name":"P","slug":"proj-off","status":"disabled"}"#,
    );
    assert!(
        status_line(&disabled).contains("200"),
        "a tenant must be able to disable its own project: {disabled}"
    );

    // The switch is real: ordinary traffic under the disabled project stops.
    assert_suspended_rejection(
        &as_key(&gateway_addr, &console, "GET", "/v1/models", ""),
        "tenancy_disabled",
    );

    // ...and it is reversible with the same key, which is the whole point.
    let re_enabled = as_key(
        &gateway_addr,
        &console,
        "PUT",
        "/admin/v1/projects/proj-off",
        r#"{"tenant_id":"tenant-off","name":"P","slug":"proj-off","status":"active"}"#,
    );
    assert!(
        status_line(&re_enabled).contains("200"),
        "the tenant must be able to re-enable its own project: {re_enabled}"
    );
    assert!(
        status_line(&as_key(&gateway_addr, &console, "GET", "/v1/models", "")).contains("200"),
        "traffic must resume once the project is re-enabled"
    );

    // The carve-out is scoped to `disabled` only: a SUSPENDED chain (a platform
    // billing action) still refuses the same reversal route, so suspension does
    // not become self-serviceable.
    let suspend = admin(
        &gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-off",
        r#"{"name":"Off","slug":"tenant-off","status":"suspended"}"#,
    );
    assert!(
        status_line(&suspend).contains("200"),
        "operator suspension must succeed: {suspend}"
    );
    assert_suspended_rejection(
        &as_key(
            &gateway_addr,
            &console,
            "PUT",
            "/admin/v1/projects/proj-off",
            r#"{"tenant_id":"tenant-off","name":"P","slug":"proj-off","status":"active"}"#,
        ),
        "tenancy_suspended",
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Suspension at the project level alone must hold too: an operator who
/// suspends one business line must not be silently ignored because the tenant
/// above it is healthy. Also pins the dangerous default -- a SIBLING project
/// created before any status was ever written keeps serving.
#[test]
fn suspending_one_project_stops_only_that_projects_keys() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_leaf","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-leaf","name":"Leaf","slug":"tenant-leaf"}"#,
    );
    for (project, workspace) in [("proj-a", "ws-a"), ("proj-b", "ws-b")] {
        admin(
            &gateway_addr,
            "POST",
            "/admin/v1/projects",
            &format!(
                r#"{{"id":"{project}","tenant_id":"tenant-leaf","name":"{project}","slug":"{project}"}}"#
            ),
        );
        admin(
            &gateway_addr,
            "POST",
            "/admin/v1/workspaces",
            &format!(
                r#"{{"id":"{workspace}","project_id":"{project}","name":"{workspace}","slug":"{workspace}"}}"#
            ),
        );
    }
    let mut secrets = Vec::new();
    for workspace in ["ws-a", "ws-b"] {
        let created = body_json(&admin(
            &gateway_addr,
            "POST",
            "/admin/v1/virtual-keys",
            &format!(
                r#"{{"name":"{workspace} key","workspace_id":"{workspace}","scopes":["chat.completions","models.read"]}}"#
            ),
        ));
        secrets.push(
            created["secret"]
                .as_str()
                .expect("create must return the plaintext secret")
                .to_string(),
        );
    }

    let suspend = admin(
        &gateway_addr,
        "PUT",
        "/admin/v1/projects/proj-a",
        r#"{"tenant_id":"tenant-leaf","name":"proj-a","slug":"proj-a","status":"suspended"}"#,
    );
    assert!(
        status_line(&suspend).contains("200"),
        "suspending proj-a failed: {suspend}"
    );

    let blocked = as_key(&gateway_addr, &secrets[0], "GET", "/v1/models", "");
    assert_suspended_rejection(&blocked, "tenancy_suspended");

    // The sibling project was never touched: it must be completely unaffected.
    // This is the guard against an over-broad fix that denies everything.
    let unaffected = as_key(&gateway_addr, &secrets[1], "GET", "/v1/models", "");
    assert!(
        status_line(&unaffected).contains("200"),
        "an untouched sibling project's key must keep working: {unaffected}"
    );
    let unaffected_chat = as_key(
        &gateway_addr,
        &secrets[1],
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&unaffected_chat).contains("200"),
        "an untouched sibling project's key must keep spending: {unaffected_chat}"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}
