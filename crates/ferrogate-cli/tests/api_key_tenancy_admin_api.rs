// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Live regression for issue #340 acceptance box 4 -- "cross-tenant
// combinations are blocked client-side AND rejected authoritatively by the
// API". Before this landed, `api_key_from_mutation` copied `project_id` and
// `workspace_id` verbatim and the POST/PUT handler ran no existence, parenting,
// or tenant check: the exact request in
// `cross_project_workspace_pair_is_rejected_on_update` returned 200 and
// persisted project A paired with a workspace owned by project B (a different
// tenant). Runs against a real gateway process with in-memory storage, matching
// tests/tenant_isolation_admin_api.rs's convention.

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

fn write_config(path: &std::path::Path, gateway_addr: &str) {
    write_config_with(path, gateway_addr, "", "");
}

/// `tenancy` is an optional `[tenancy]` block and `extra_keys` optional extra
/// `[[api_keys]]` entries, so the #515 cases below can start a gateway whose
/// `require_registered_tenant` / `implicit_platform_operator` answers differ
/// from the defaults without duplicating the whole fixture.
///
/// The `admin` key declares `platform_operator = true` since #540: it drives
/// every cross-tenant admin call here, and a key that declared neither identity
/// no longer loads under the default `[tenancy]`.
fn write_config_with(path: &std::path::Path, gateway_addr: &str, tenancy: &str, extra_keys: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"
{tenancy}

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true
{extra_keys}
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

fn post(gateway_addr: &str, path: &str, body: &str) -> String {
    http_request(gateway_addr, "POST", path, &ADMIN, body)
}

fn seed_two_tenant_hierarchies(gateway_addr: &str) {
    for tenant in ["tenant-key-a", "tenant-key-b"] {
        let response = post(
            gateway_addr,
            "/admin/v1/tenant-accounts",
            &format!(r#"{{"id":"{tenant}","name":"{tenant}","slug":"{tenant}"}}"#),
        );
        assert!(
            status_line(&response).contains("200") || status_line(&response).contains("201"),
            "tenant {tenant} setup failed: {response}"
        );
    }
    for (project, tenant) in [
        ("project-key-a", "tenant-key-a"),
        ("project-key-b", "tenant-key-b"),
    ] {
        let response = post(
            gateway_addr,
            "/admin/v1/projects",
            &format!(
                r#"{{"id":"{project}","tenant_id":"{tenant}","name":"{project}","slug":"{project}"}}"#
            ),
        );
        assert!(
            status_line(&response).contains("201"),
            "project {project} setup failed: {response}"
        );
    }
    for (workspace, project) in [
        ("workspace-key-a", "project-key-a"),
        ("workspace-key-b", "project-key-b"),
    ] {
        let response = post(
            gateway_addr,
            "/admin/v1/workspaces",
            &format!(
                r#"{{"id":"{workspace}","project_id":"{project}","name":"{workspace}","slug":"{workspace}"}}"#
            ),
        );
        assert!(
            status_line(&response).contains("201"),
            "workspace {workspace} setup failed: {response}"
        );
    }
}

/// The reviewer's reproduction, verbatim: create a key that is legally scoped to
/// project A + workspace A, then PUT project A paired with project B's
/// workspace. That update must be refused and must not overwrite the stored
/// pair.
#[test]
fn cross_project_workspace_pair_is_rejected_on_update() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    seed_two_tenant_hierarchies(&gateway_addr);

    let created = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k1","name":"Scoped key","key":"k1-secret","organization_id":"tenant-key-a","project_id":"project-key-a","workspace_id":"workspace-key-a"}"#,
    );
    assert!(
        status_line(&created).contains("201"),
        "a consistent project+workspace pair must be accepted: {created}"
    );

    // The secret is repeated so the pre-existing "key_env, key, or key_hash is
    // required" rejection cannot stand in for the tenancy one: without the #340
    // check this exact request returns 200 and persists the cross-project pair.
    // #540-undeclared-on-purpose: this invalid replacement deliberately states
    // only project/workspace ids so their cross-project pairing is the refusal.
    let rejected = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/api-keys/k1",
        &ADMIN,
        r#"{"id":"k1","name":"Scoped key","key":"k1-secret","project_id":"project-key-a","workspace_id":"workspace-key-b"}"#,
    );
    assert!(
        status_line(&rejected).contains("400"),
        "project A + project B's workspace must be rejected: {rejected}"
    );
    let error = body_json(&rejected);
    assert_eq!(error["error"]["code"], "invalid_api_key");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("workspace-key-b"),
        "rejection must name the offending workspace: {rejected}"
    );

    // The stored key still carries the original, valid pair -- the refused
    // update never reached the runtime snapshot.
    let stored = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/k1",
        &ADMIN,
        "",
    ));
    assert_eq!(stored["key"]["project_id"], "project-key-a");
    assert_eq!(stored["key"]["workspace_id"], "workspace-key-a");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// The remaining rejection edge on the create path -- a project owned by a
/// different tenant than the key's `organization_id` -- plus the deliberate
/// non-rejections: a reference that names no control-plane row, and a key with
/// no hierarchy reference at all.
#[test]
fn create_rejects_cross_tenant_pairs_but_tolerates_dangling_references() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    seed_two_tenant_hierarchies(&gateway_addr);

    let cross_tenant = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-cross","name":"Cross tenant","key":"s","organization_id":"tenant-key-a","project_id":"project-key-b"}"#,
    );
    assert!(
        status_line(&cross_tenant).contains("400"),
        "a project owned by another tenant must be rejected: {cross_tenant}"
    );
    assert_eq!(
        body_json(&cross_tenant)["error"]["code"],
        "invalid_api_key",
        "{cross_tenant}"
    );

    // The rejected key never reached the runtime snapshot.
    let lookup = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/k-cross",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&lookup).contains("404"),
        "the rejected key must not have been persisted: {lookup}"
    );

    // A reference that names no control-plane row is NOT a cross-tenant
    // combination: the same key is declarable in ferrogate.toml, where
    // `Config::validate` performs no storage lookup, so refusing it here would
    // make the admin API stricter than the config path. It is accepted and
    // reported (audit event + operator warning) instead.
    //
    // #540: the payload names its tenant, which it did not have to before. That
    // is a separate rule (a key must declare a tenant identity) and keeping the
    // two apart is the point -- the DANGLING reference under test is still the
    // project, and it is still accepted.
    let dangling = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-ghost","name":"Dangling project","key":"s","organization_id":"tenant-key-a","project_id":"project-ghost"}"#,
    );
    assert!(
        status_line(&dangling).contains("201"),
        "an unresolvable project reference must not be refused: {dangling}"
    );
    let audit = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &ADMIN,
        "",
    ));
    let warned = audit["data"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["target"] == "k-ghost"
                    && event["outcome"] == "warning"
                    && event["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("project-ghost")
            })
        })
        .unwrap_or(false);
    assert!(
        warned,
        "an unresolvable reference must leave audit evidence: {audit}"
    );

    // A key that references no project/workspace at all stays legal: this
    // validation constrains the combination, it does not make the control-plane
    // hierarchy mandatory for native keys.
    let unscoped = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-unscoped","name":"Unscoped","key":"s","organization_id":"tenant-key-a"}"#,
    );
    assert!(
        status_line(&unscoped).contains("201"),
        "a key without hierarchy references must still be accepted: {unscoped}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

// --- issue #515: tenant identity on the api-key write path ---

/// Finding 1, the operator hazard. `PUT /admin/v1/api-keys/{id}` is a full
/// replace with no merge, so the GET document is what an operator (or a
/// generated SDK) reads, edits and writes back. While the response rendered
/// `platform_operator` as a plain `bool`, a legacy bootstrap key -- one that
/// declares no tenant and no `platform_operator`, i.e. root under the default
/// config -- read back as `platform_operator: false`. Writing that document
/// back unchanged persisted an explicit `false`, which
/// `resolve_platform_operator` honours over the `[tenancy]` default, leaving the
/// key with neither a tenant nor root: `finalize_auth` then answers
/// `403 tenant_identity_required` to EVERY subsequent request with it. Reading a
/// key and saving it locked the admin API out.
///
/// This drives that exact sequence over HTTP: GET, add the secret back (the
/// only field the response redacts), PUT verbatim, and then keep using the key.
///
/// #540: the undeclared-key premise now needs the legacy opt-in, because the
/// default refuses such a key at load. That is not a weakening -- the opt-in is
/// exactly the population still exposed to this hazard, and it is the one an
/// upgrading operator turns on before annotating anything.
#[test]
fn reading_an_operator_key_and_writing_it_back_does_not_lock_the_admin_api_out() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config_with(
        &config_path,
        &gateway_addr,
        "\n[tenancy]\nimplicit_platform_operator = true\n",
        r#"
[[api_keys]]
id = "legacy-admin"
name = "Undeclared legacy admin"
key = "legacy-admin-secret"
scopes = ["admin.read", "admin.write"]
"#,
    );
    let legacy_admin: [&str; 2] = [
        "Authorization: Bearer legacy-admin-secret",
        "Content-Type: application/json",
    ];

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let fetched = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/legacy-admin",
        &ADMIN,
        "",
    ));
    // Declared: nothing was written down, and the response says so rather than
    // flattening the third state into `false`.
    assert_eq!(
        fetched["key"]["platform_operator"],
        serde_json::Value::Null,
        "a key that declared nothing must not be reported as having declared false: {fetched}"
    );
    // Effective: under this config's `[tenancy] implicit_platform_operator` the
    // key IS root right now, which is the question an operator is asking.
    assert_eq!(
        fetched["key"]["effective_platform_operator"], true,
        "the legacy opt-in makes this key platform root; the surface added to make root visible \
         must say so: {fetched}"
    );

    // The canonical read-modify-write: every field exactly as returned, plus the
    // secret the response redacts. `effective_platform_operator` is sent back
    // too and must be ignored rather than 400'd or persisted as a declaration.
    let mut round_trip = fetched["key"].clone();
    round_trip["key"] = serde_json::Value::String("legacy-admin-secret".into());
    let replaced = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/api-keys/legacy-admin",
        &ADMIN,
        &round_trip.to_string(),
    );
    assert!(
        status_line(&replaced).contains("200"),
        "writing back the document we just read must be accepted: {replaced}"
    );

    // The lockout assertion: the very same credential still authenticates --
    // driven with ITS OWN bearer token, not the declared-root admin one, or the
    // self-lockout this test exists for would be invisible.
    let after = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys",
        &legacy_admin,
        "",
    );
    assert!(
        status_line(&after).contains("200"),
        "the legacy admin key must still work after a read-modify-write of its own document; a \
         403 here is the self-lockout (tenant_identity_required): {after}"
    );

    // ...and it is still reported with the same identity, so the round-trip is
    // genuinely lossless rather than merely non-fatal.
    let reread = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/legacy-admin",
        &ADMIN,
        "",
    ));
    assert_eq!(
        reread["key"]["platform_operator"],
        serde_json::Value::Null,
        "the round-trip must not have invented a declaration: {reread}"
    );
    assert_eq!(
        reread["key"]["effective_platform_operator"], true,
        "{reread}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Finding 1's second half: `platform_operator` (declared) and
/// `effective_platform_operator` (resolved) are different questions, and the
/// resolved one has to actually consult `[tenancy]` rather than echo the
/// declaration.
///
/// #540 moved which config can hold the four shapes. An undeclared static key
/// is refused at load under the default now, so this runs under the legacy
/// opt-in -- which sharpens the pin rather than weakening it: `legacy` and
/// `tenant-scoped` have the SAME declaration (`null`) and OPPOSITE effective
/// answers in one response, so an `effective_platform_operator` that echoed the
/// declaration, or that hardcoded either answer, cannot produce this listing.
#[test]
fn the_api_key_response_reports_declared_and_effective_platform_root_separately() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config_with(
        &config_path,
        &gateway_addr,
        "\n[tenancy]\nimplicit_platform_operator = true\n",
        r#"
[[api_keys]]
id = "legacy"
name = "Undeclared legacy key"
key = "legacy-secret"
scopes = ["admin.read"]

[[api_keys]]
id = "refuses-root"
name = "Explicitly not root"
key = "refuses-secret"
scopes = ["admin.read"]
platform_operator = false

[[api_keys]]
id = "tenant-scoped"
name = "Tenant key"
key = "tenant-secret"
scopes = ["admin.read"]
organization_id = "tenant-key-a"
"#,
    );

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let listed = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys",
        &ADMIN,
        "",
    ));
    let key_of = |id: &str| -> serde_json::Value {
        listed["data"]
            .as_array()
            .unwrap_or_else(|| panic!("api-key listing: {listed}"))
            .iter()
            .find(|key| key["id"] == id)
            .unwrap_or_else(|| panic!("api key {id} missing from {listed}"))
            .clone()
    };

    let admin = key_of("admin");
    assert_eq!(admin["platform_operator"], true, "{admin}");
    assert_eq!(admin["effective_platform_operator"], true, "{admin}");

    // The whole point of the pair: this key and `tenant-scoped` below declare
    // the same thing (`null`) and get opposite effective answers, because the
    // resolver reads `[tenancy]` and the tenant, not the declaration.
    let legacy = key_of("legacy");
    assert_eq!(
        legacy["platform_operator"],
        serde_json::Value::Null,
        "{legacy}"
    );
    assert_eq!(
        legacy["effective_platform_operator"], true,
        "the legacy opt-in is on, so this undeclared key IS root right now -- which is the whole \
         reason the surface reports it: {legacy}"
    );

    let refuses_root = key_of("refuses-root");
    assert_eq!(refuses_root["platform_operator"], false, "{refuses_root}");
    assert_eq!(
        refuses_root["effective_platform_operator"], false,
        "{refuses_root}"
    );

    let tenant_scoped = key_of("tenant-scoped");
    assert_eq!(
        tenant_scoped["platform_operator"],
        serde_json::Value::Null,
        "declaring a tenant is not declaring `platform_operator = false`: {tenant_scoped}"
    );
    assert_eq!(
        tenant_scoped["effective_platform_operator"], false,
        "a key that names a tenant is that tenant, never root: {tenant_scoped}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Finding 4: nothing proved the POST/PUT handler actually calls
/// `check_api_key_tenancy` with the config flag and the resolved tenant row.
/// `check_api_key_tenancy` was only ever exercised directly, so hardcoding
/// `require_registered_tenant`, or making the `get_tenant_account` lookup always
/// yield `None`, or deleting the `tenant` argument entirely, all stayed green.
///
/// Driving the handler with the flag ON pins both directions at once: a
/// registered tenant must be ACCEPTED (so the lookup has to really resolve) and
/// an unregistered one REFUSED (so the flag has to really be read).
#[test]
fn the_write_path_enforces_require_registered_tenant_against_a_real_lookup() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config_with(
        &config_path,
        &gateway_addr,
        "\n[tenancy]\nrequire_registered_tenant = true\n",
        "",
    );

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    seed_two_tenant_hierarchies(&gateway_addr);

    // A registered tenant is accepted. If the handler stopped plumbing the
    // `tenant` argument (or the lookup always returned `None`) this would be a
    // 400 `UnknownTenant` instead, because the flag is on.
    let registered = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-registered","name":"Registered tenant","key":"s","organization_id":"tenant-key-a"}"#,
    );
    assert!(
        status_line(&registered).contains("201"),
        "a key naming a registered tenant must be accepted even with require_registered_tenant \
         on: {registered}"
    );

    // An unregistered one is refused. If `require_registered_tenant` were
    // hardcoded to `false` this would be a 201 with a `warning` audit event.
    let unregistered = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-ghost-tenant","name":"Ghost tenant","key":"s","organization_id":"tenant-ghost"}"#,
    );
    assert!(
        status_line(&unregistered).contains("400"),
        "organization_id is a foreign key to tenants.id; with require_registered_tenant on a \
         dangling one must be refused: {unregistered}"
    );
    let error = body_json(&unregistered);
    assert_eq!(error["error"]["code"], "invalid_api_key", "{unregistered}");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("tenant-ghost"),
        "the rejection must name the tenant that does not exist: {unregistered}"
    );
    assert!(
        status_line(&http_request(
            &gateway_addr,
            "GET",
            "/admin/v1/api-keys/k-ghost-tenant",
            &ADMIN,
            "",
        ))
        .contains("404"),
        "the refused key must never have reached the runtime snapshot"
    );

    // The contradiction check on the same path: root and a tenant at once is a
    // 400, matching what `Config::validate` refuses at load.
    let contradiction = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-both","name":"Root and tenant","key":"s","organization_id":"tenant-key-a","platform_operator":true}"#,
    );
    assert!(
        status_line(&contradiction).contains("400"),
        "platform_operator = true with an organization_id must be refused: {contradiction}"
    );
    assert!(
        body_json(&contradiction)["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("platform_operator"),
        "{contradiction}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// The other half of finding 4's flag assertion: with `require_registered_tenant`
/// left at its default the SAME dangling `organization_id` is accepted and
/// merely reported, because the admin API must not be stricter than the
/// storage-free config path until a deployment opts in. Hardcoding the flag to
/// `true` turns this 201 into a 400; skipping the tenant lookup removes the
/// audit evidence.
#[test]
fn a_dangling_tenant_reference_is_tolerated_until_the_deployment_opts_in() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let tolerated = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"k-ghost-tenant","name":"Ghost tenant","key":"s","organization_id":"tenant-ghost"}"#,
    );
    assert!(
        status_line(&tolerated).contains("201"),
        "on the default the dangling tenant is reported, not refused: {tolerated}"
    );

    let audit = body_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &ADMIN,
        "",
    ));
    let warned = audit["data"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["target"] == "k-ghost-tenant"
                    && event["outcome"] == "warning"
                    && event["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("tenant-ghost")
            })
        })
        .unwrap_or(false);
    assert!(
        warned,
        "the unresolved tenant reference must still leave audit evidence -- this is what proves \
         the tenant lookup ran at all on the default path: {audit}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// #540 acceptance, #515's original probe driven end to end: `GET
/// /admin/v1/tenant-roles/{other-tenant}` no longer answers 200 to a key with
/// no declared tenant identity -- because that key can no longer be brought
/// into existence.
///
/// Both doors are checked in one run, on a config that writes no `[tenancy]`
/// section at all (so the DEFAULT is what is under test):
///
/// 1. the admin API refuses to mint one. `upsert_api_key` runs the candidate
///    through `Config::validate`, so `ensure_every_key_declares_tenant_identity`
///    applies to a runtime mutation exactly as it does to a config file, and the
///    handler returns `400 invalid_api_key` carrying the message. The static
///    half -- the same key written into `ferrogate.toml` -- is pinned in
///    `check_command.rs`; the authentication half in `auth_admission_test.rs`.
/// 2. the probe itself, from the tenant-scoped key that the refusal tells you to
///    create instead: still not 200, now via `authorize_tenant_scope`.
///
/// The two controls are load-bearing, not decoration. Without the 201 in
/// between, a handler that 400'd every api-key POST would pass step 1; without
/// the final 200, a 404 route or a gateway refusing all admin calls would pass
/// step 2 while proving nothing about tenant isolation. Flip
/// `TenancyConfig::default()` back to `true` and step 1 turns into a 201.
#[test]
fn an_unscoped_key_can_no_longer_read_another_tenants_roles() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    seed_two_tenant_hierarchies(&gateway_addr);

    // Neither organization_id nor platform_operator: the pre-#515 shape that
    // used to be silently minted as a platform-root credential.
    let refused = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"unscoped","name":"Unscoped","key":"unscoped-secret","scopes":["admin.read"]}"#,
    );
    assert!(
        status_line(&refused).contains("400"),
        "#540: the admin API must not mint a credential with no tenant identity: {refused}"
    );
    assert!(
        refused.contains("platform_operator") && refused.contains("organization_id"),
        "and must say which of the two to add: {refused}"
    );

    let never_created = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-roles/tenant-key-b",
        &["Authorization: Bearer unscoped-secret"],
        "",
    );
    assert!(
        status_line(&never_created).contains("401"),
        "#515's probe: the secret from the refused mint must not authenticate at all: \
         {never_created}"
    );

    // Control: the SAME payload with a tenant named is accepted, so the 400
    // above is about the missing identity and not about this endpoint.
    let scoped = post(
        &gateway_addr,
        "/admin/v1/api-keys",
        r#"{"id":"scoped","name":"Scoped","key":"scoped-secret","scopes":["admin.read"],"organization_id":"tenant-key-a"}"#,
    );
    assert!(
        status_line(&scoped).contains("201"),
        "declaring the tenant is the fix the refusal names, so it must work: {scoped}"
    );

    // The probe, from the key an operator is now steered towards: tenant A's
    // key reading tenant B's roles.
    let probe = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-roles/tenant-key-b",
        &["Authorization: Bearer scoped-secret"],
        "",
    );
    assert!(
        !status_line(&probe).contains("200"),
        "a tenant-scoped key must not read another tenant's roles: {probe}"
    );
    assert!(
        status_line(&probe).contains("403"),
        "and it fails closed rather than 404-ing its way to a pass: {probe}"
    );

    // Control: the declared platform operator still administers every tenant,
    // so the route exists and tenant-key-b is really there.
    let operator = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-roles/tenant-key-b",
        &ADMIN,
        "",
    );
    assert!(
        status_line(&operator).contains("200"),
        "a declared platform operator must still administer every tenant: {operator}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
