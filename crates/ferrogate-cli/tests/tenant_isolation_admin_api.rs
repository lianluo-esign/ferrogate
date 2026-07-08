// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end regression coverage for issues #185 and #186 --
// critical, live-verified cross-tenant IDOR spanning most of the
// /admin/v1/* admin API surface. Before the fix, `authenticate()` only
// ever checked *scope* (`admin.read`/`admin.write`), never whether the
// caller's own tenant matched the tenant the request actually targeted;
// any tenant-scoped admin.read+admin.write key (exactly the shape the
// admin-console auto-provisions on every login via
// `provision_gateway_api_key`) could read AND financially mutate every
// *other* tenant's wallets, virtual keys, quota policies, RBAC bindings,
// self-hosted workers, and tenant roster -- and, worse, could mint itself
// a brand-new platform-operator credential via the static api-keys
// endpoint. This reproduces the exact manually-curl-verified scenario from
// #185 (tenant-A-scoped key reads then adjusts tenant B's wallet balance)
// plus the same class of gap across the other admin surfaces fixed
// alongside it, against a real running gateway process -- no Postgres
// required (in-memory storage, matching tests/wallet_e2e.rs's
// convention).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

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
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-iso-a"

[[api_keys]]
id = "tenant-b-console"
name = "Tenant B admin-console session key"
key = "tenant-b-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "tenant-iso-b"
"#
        ),
    )
    .unwrap();
}

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

fn register_tenant(gateway_addr: &str, tenant_id: &str) {
    let register = http_request(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        &format!(r#"{{"id":"{tenant_id}","name":"{tenant_id}","slug":"{tenant_id}"}}"#),
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed for {tenant_id}: {register}"
    );
}

/// The primary regression: the exact scenario manually verified with curl
/// before this fix landed. Tenant A's own admin-console session key could
/// read, and then financially adjust, tenant B's wallet balance.
#[test]
fn cross_tenant_admin_key_cannot_read_or_mutate_another_tenants_wallet() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    register_tenant(&gateway_addr, "tenant-iso-a");
    register_tenant(&gateway_addr, "tenant-iso-b");

    let created_wallet = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets",
        &ADMIN,
        r#"{"tenant_id":"tenant-iso-a"}"#,
    ));
    assert_eq!(created_wallet["wallet"]["balance_credits"], 0);
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-iso-a/adjust",
        &ADMIN,
        r#"{"delta_credits":500000}"#,
    ));

    // Tenant A reading its own wallet is fine.
    let own_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &TENANT_A,
        "",
    );
    assert!(
        own_read.contains("HTTP/1.1 200"),
        "tenant A must be able to read its own wallet: {own_read}"
    );

    // Tenant B reading tenant A's wallet must be denied -- this is the
    // exact cross-tenant read confirmed live before the fix.
    let stolen_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_read).contains("403"),
        "tenant B must not be able to read tenant A's wallet: {stolen_read}"
    );
    assert!(stolen_read.contains("tenant_scope_denied"));

    // Tenant B financially adjusting tenant A's wallet must be denied --
    // the worst-case exploit path called out in the issue.
    let stolen_adjust = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/wallets/tenant-iso-a/adjust",
        &TENANT_B,
        r#"{"delta_credits":999999999}"#,
    );
    assert!(
        status_line(&stolen_adjust).contains("403"),
        "tenant B must not be able to adjust tenant A's wallet balance: {stolen_adjust}"
    );

    // The balance must be completely unaffected by tenant B's attempt.
    let balance_after = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &ADMIN,
        "",
    ));
    assert_eq!(
        balance_after["wallet"]["balance_credits"], 500000,
        "tenant B's denied adjust must not have changed tenant A's balance: {balance_after}"
    );

    // Tenant B's own bulk wallet list must not include tenant A's wallet.
    let tenant_b_list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets",
        &TENANT_B,
        "",
    ));
    let listed_tenants: Vec<&str> = tenant_b_list["data"]
        .as_array()
        .expect("wallets list must have a data array")
        .iter()
        .map(|wallet| wallet["tenant_id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !listed_tenants.contains(&"tenant-iso-a"),
        "tenant A's wallet must not appear in tenant B's list: {tenant_b_list}"
    );

    // The platform operator is completely unaffected by this fix -- it
    // must retain full cross-tenant access.
    let operator_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/wallets/tenant-iso-a",
        &ADMIN,
        "",
    );
    assert!(
        operator_read.contains("HTTP/1.1 200"),
        "the platform-operator key must retain unrestricted cross-tenant access: {operator_read}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// The same class of gap, across the other admin surfaces fixed alongside
/// wallets: tenant-accounts, projects, virtual-keys, and quota-policies.
#[test]
fn cross_tenant_admin_key_is_denied_across_identity_and_quota_surfaces() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    register_tenant(&gateway_addr, "tenant-iso-a");
    register_tenant(&gateway_addr, "tenant-iso-b");

    // Tenant B cannot read tenant A's tenant-account record.
    let stolen_tenant = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_tenant).contains("403"),
        "tenant B must not be able to read tenant A's account: {stolen_tenant}"
    );

    // Tenant A creates a project + workspace + virtual key under its own
    // tenant.
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &ADMIN,
        r#"{"id":"project-iso-a","tenant_id":"tenant-iso-a","name":"Project A","slug":"project-iso-a"}"#,
    ));
    response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &ADMIN,
        r#"{"id":"workspace-iso-a","project_id":"project-iso-a","name":"Workspace A","slug":"workspace-iso-a"}"#,
    ));
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &ADMIN,
        r#"{"name":"Tenant A virtual key","workspace_id":"workspace-iso-a","scopes":["chat.completions"]}"#,
    ));
    let virtual_key_id = created_key["key"]["id"]
        .as_str()
        .expect("created virtual key must have an id")
        .to_string();

    // Tenant B cannot read tenant A's virtual key by id.
    let stolen_key = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/virtual-keys/{virtual_key_id}"),
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_key).contains("403"),
        "tenant B must not be able to read tenant A's virtual key: {stolen_key}"
    );

    // Tenant B cannot revoke tenant A's virtual key either.
    let stolen_revoke = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/virtual-keys/{virtual_key_id}/revoke"),
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_revoke).contains("403"),
        "tenant B must not be able to revoke tenant A's virtual key: {stolen_revoke}"
    );

    // Tenant B's own project/workspace/virtual-key lists must not leak
    // tenant A's rows.
    let tenant_b_projects = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/projects",
        &TENANT_B,
        "",
    ));
    let project_ids: Vec<&str> = tenant_b_projects["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|project| project["id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !project_ids.contains(&"project-iso-a"),
        "tenant A's project must not appear in tenant B's list: {tenant_b_projects}"
    );

    // Tenant B cannot read or write a quota policy scoped to tenant A.
    let stolen_quota_read = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies/tenant/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_quota_read).contains("403"),
        "tenant B must not be able to read a quota policy scoped to tenant A -- the tenant-scope \
         check must run before the not-found check: {stolen_quota_read}"
    );
    let stolen_quota_write = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-iso-a",
        &TENANT_B,
        r#"{"rpm_limit":1}"#,
    );
    assert!(
        status_line(&stolen_quota_write).contains("403"),
        "tenant B must not be able to write a quota policy scoped to tenant A: {stolen_quota_write}"
    );
    // Project-scoped quota policy, resolved indirectly via the project's
    // owning tenant rather than a bare tenant_id.
    let stolen_quota_project = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/project/project-iso-a",
        &TENANT_B,
        r#"{"rpm_limit":1}"#,
    );
    assert!(
        status_line(&stolen_quota_project).contains("403"),
        "tenant B must not be able to write a quota policy scoped to tenant A's project: {stolen_quota_project}"
    );

    // Tenant A can still manage its own quota policy.
    let own_quota_write = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-iso-a",
        &TENANT_A,
        r#"{"rpm_limit":100}"#,
    );
    assert!(
        own_quota_write.contains("HTTP/1.1 200"),
        "tenant A must still be able to manage its own quota policy: {own_quota_write}"
    );

    // Tenant B cannot bind or list RBAC roles on tenant A.
    let role = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/roles",
        &ADMIN,
        r#"{"name":"Isolation Test Role","slug":"iso-test-role","permission_keys":[]}"#,
    ));
    let role_id = role["role"]["id"].as_str().unwrap().to_string();
    let stolen_bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/tenant-iso-a",
        &TENANT_B,
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(
        status_line(&stolen_bind).contains("403"),
        "tenant B must not be able to bind a role onto tenant A: {stolen_bind}"
    );
    let stolen_role_list = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-roles/tenant-iso-a",
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_role_list).contains("403"),
        "tenant B must not be able to list tenant A's role bindings: {stolen_role_list}"
    );

    // Sanity: the platform operator can still do all of the above.
    let operator_bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-roles/tenant-iso-a",
        &ADMIN,
        &format!(r#"{{"role_id":"{role_id}"}}"#),
    );
    assert!(
        operator_bind.contains("HTTP/1.1 200"),
        "the platform operator must retain unrestricted cross-tenant RBAC access: {operator_bind}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #186's most severe finding: `/admin/v1/api-keys*` let a
/// tenant-scoped `admin.write` key mint a brand-new STATIC key with
/// `organization_id: null` and `scopes: ["admin.read","admin.write"]` --
/// i.e. escalate itself to a full platform-operator credential that
/// bypasses every tenant-scope check in the system, not merely read/write
/// one other tenant's resource.
#[test]
fn tenant_scoped_admin_key_cannot_mint_a_platform_operator_credential() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let escalation_attempt = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/api-keys",
        &TENANT_A,
        r#"{"id":"pwn","name":"pwn","key":"pwn-secret","scopes":["admin.read","admin.write"],"organization_id":null}"#,
    );
    assert!(
        status_line(&escalation_attempt).contains("403"),
        "a tenant-scoped key must not be able to mint a platform-operator credential: {escalation_attempt}"
    );

    // The forged secret must never have taken effect.
    let forged_key_rejected = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys",
        &["Authorization: Bearer pwn-secret"],
        "",
    );
    assert!(
        status_line(&forged_key_rejected).contains("401"),
        "the forged key must never have been created: {forged_key_rejected}"
    );

    // Every other verb on this surface is denied to a tenant-scoped key too.
    let list_denied = http_request(&gateway_addr, "GET", "/admin/v1/api-keys", &TENANT_A, "");
    assert!(
        status_line(&list_denied).contains("403"),
        "tenant-scoped key must not list static api keys: {list_denied}"
    );
    let get_denied = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/api-keys/admin",
        &TENANT_A,
        "",
    );
    assert!(
        status_line(&get_denied).contains("403"),
        "tenant-scoped key must not read a static api key by id: {get_denied}"
    );
    let delete_denied = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/api-keys/tenant-a-console",
        &TENANT_A,
        "",
    );
    assert!(
        status_line(&delete_denied).contains("403"),
        "tenant-scoped key must not delete a static api key: {delete_denied}"
    );

    // The platform operator is unaffected.
    let operator_list = http_request(&gateway_addr, "GET", "/admin/v1/api-keys", &ADMIN, "");
    assert!(
        operator_list.contains("HTTP/1.1 200"),
        "the platform operator must retain full access to static api keys: {operator_list}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #186: every self-hosted-worker admin handler resolved the target
/// worker by bare `worker_id` with no tenant check, letting a tenant-scoped
/// key read, register-as-another-tenant, rotate (a takeover primitive),
/// heartbeat, or attach telemetry/artifacts/checkpoints to another
/// tenant's self-hosted worker, and see every tenant's workers in the bulk
/// list.
#[test]
fn cross_tenant_admin_key_is_denied_across_self_hosted_workers() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // Tenant B cannot register a worker attributed to tenant A.
    let impersonated_register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &TENANT_B,
        r#"{"tenant":{"organization_id":"tenant-iso-a"},"workspace_id":"ws-a","worker_name":"worker-a","identity_fingerprint":"sha256:worker-a"}"#,
    );
    assert!(
        status_line(&impersonated_register).contains("403"),
        "tenant B must not be able to register a worker attributed to tenant A: {impersonated_register}"
    );

    // Tenant A registers its own worker for real.
    let registered = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &TENANT_A,
        r#"{"tenant":{"organization_id":"tenant-iso-a"},"workspace_id":"ws-a","worker_name":"worker-a","identity_fingerprint":"sha256:worker-a"}"#,
    ));
    assert_eq!(registered["object"], "self_hosted_worker");
    let worker_id = registered["worker"]["id"]
        .as_str()
        .expect("registered worker must have an id")
        .to_string();

    // Tenant A can read its own worker.
    let own_read = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/self-hosted-workers/{worker_id}"),
        &TENANT_A,
        "",
    );
    assert!(
        own_read.contains("HTTP/1.1 200"),
        "tenant A must be able to read its own worker: {own_read}"
    );

    // Tenant B cannot read tenant A's worker.
    let stolen_read = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/self-hosted-workers/{worker_id}"),
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_read).contains("403"),
        "tenant B must not be able to read tenant A's worker: {stolen_read}"
    );

    // Tenant B cannot rotate tenant A's worker identity -- a takeover
    // primitive if it succeeded.
    let stolen_rotate = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/rotate"),
        &TENANT_B,
        r#"{"identity_fingerprint":"sha256:stolen"}"#,
    );
    assert!(
        status_line(&stolen_rotate).contains("403"),
        "tenant B must not be able to rotate tenant A's worker identity: {stolen_rotate}"
    );

    // Tenant B cannot post a heartbeat onto tenant A's worker.
    let stolen_heartbeat = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/heartbeat"),
        &TENANT_B,
        r#"{"status":"online"}"#,
    );
    assert!(
        status_line(&stolen_heartbeat).contains("403"),
        "tenant B must not be able to heartbeat tenant A's worker: {stolen_heartbeat}"
    );

    // Tenant B cannot attach a telemetry event to tenant A's worker.
    let stolen_event = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/events"),
        &TENANT_B,
        r#"{"session_id":"session-1","run_id":"run-1","kind":"log"}"#,
    );
    assert!(
        status_line(&stolen_event).contains("403"),
        "tenant B must not be able to attach a telemetry event to tenant A's worker: {stolen_event}"
    );

    // Tenant B cannot read tenant A's telemetry event stream either.
    let stolen_event_stream = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/events"),
        &TENANT_B,
        "",
    );
    assert!(
        status_line(&stolen_event_stream).contains("403"),
        "tenant B must not be able to read tenant A's telemetry event stream: {stolen_event_stream}"
    );

    // Tenant B cannot attach an artifact to tenant A's worker.
    let stolen_artifact = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/artifacts"),
        &TENANT_B,
        r#"{"artifact_id":"artifact-1","session_id":"session-1","run_id":"run-1","artifact_name":"stdout.log","size_bytes":10}"#,
    );
    assert!(
        status_line(&stolen_artifact).contains("403"),
        "tenant B must not be able to attach an artifact to tenant A's worker: {stolen_artifact}"
    );

    // Tenant B cannot attach a checkpoint to tenant A's worker.
    let stolen_checkpoint = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/checkpoints"),
        &TENANT_B,
        r#"{"checkpoint_id":"checkpoint-1","session_id":"session-1","run_id":"run-1","checkpoint_name":"state","size_bytes":10}"#,
    );
    assert!(
        status_line(&stolen_checkpoint).contains("403"),
        "tenant B must not be able to attach a checkpoint to tenant A's worker: {stolen_checkpoint}"
    );

    // Tenant B's bulk worker list does not include tenant A's worker.
    let tenant_b_list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/self-hosted-worker-records",
        &TENANT_B,
        "",
    ));
    let listed_ids: Vec<&str> = tenant_b_list["data"]
        .as_array()
        .expect("worker records list must have a data array")
        .iter()
        .map(|record| record["id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !listed_ids.contains(&worker_id.as_str()),
        "tenant A's worker must not appear in tenant B's list: {tenant_b_list}"
    );

    // Tenant A's own heartbeat still works.
    let own_heartbeat = http_request(
        &gateway_addr,
        "POST",
        &format!("/admin/v1/self-hosted-workers/{worker_id}/heartbeat"),
        &TENANT_A,
        r#"{"status":"online"}"#,
    );
    assert!(
        own_heartbeat.contains("HTTP/1.1 201"),
        "tenant A must still be able to heartbeat its own worker: {own_heartbeat}"
    );

    // The platform operator retains full cross-tenant access.
    let operator_read = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/self-hosted-workers/{worker_id}"),
        &ADMIN,
        "",
    );
    assert!(
        operator_read.contains("HTTP/1.1 200"),
        "the platform operator must retain unrestricted cross-tenant access: {operator_read}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Issue #186: `/admin/v1/tenants` (the legacy tenant-ref roster derived
/// from configured static api keys) returned every tenant on the platform
/// to any `admin.read` key, including a tenant-scoped one.
#[test]
fn tenant_roster_is_filtered_to_the_callers_own_tenant() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let tenant_b_roster = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenants",
        &TENANT_B,
        "",
    ));
    let listed_tenants: Vec<&str> = tenant_b_roster["data"]
        .as_array()
        .expect("tenant roster must have a data array")
        .iter()
        .map(|tenant_ref| tenant_ref["organization_id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        listed_tenants.contains(&"tenant-iso-b"),
        "tenant B must see its own entry in the roster: {tenant_b_roster}"
    );
    assert!(
        !listed_tenants.contains(&"tenant-iso-a"),
        "tenant A must not appear in tenant B's roster view: {tenant_b_roster}"
    );

    let operator_roster = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenants",
        &ADMIN,
        "",
    ));
    let operator_listed: Vec<&str> = operator_roster["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tenant_ref| tenant_ref["organization_id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        operator_listed.contains(&"tenant-iso-a") && operator_listed.contains(&"tenant-iso-b"),
        "the platform operator must see every tenant unfiltered: {operator_roster}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
