// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Live fixed-API contract enforcement coverage for issue #203.

use crate::{
    cli::LocalArgs,
    constants::{ADMIN_AUTH, JSON_CONTENT},
    local::LocalHarness,
};
use anyhow::Result;

pub(crate) fn run_api_contract(args: &LocalArgs) -> Result<()> {
    let case = LocalHarness::start(&args.ferrogate_bin, 1)?;

    case.expect_json("GET", "/healthz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ok");
        Ok(())
    })?;
    case.expect_json("POST", "/healthz", &[], "", 405, |body| {
        assert_eq!(body["error"]["code"], "method_not_allowed");
        Ok(())
    })?;
    case.expect_json(
        "PUT",
        "/admin/v1/projects",
        &[ADMIN_AUTH],
        "{}",
        405,
        |body| {
            assert_eq!(body["error"]["code"], "method_not_allowed");
            Ok(())
        },
    )?;
    assert_duplicate_create_conflicts(&case)?;
    case.expect_json("GET", "/v1/prompts/foo/custom", &[], "", 200, |body| {
        assert_eq!(body["id"], "chatcmpl_ferrogate_test");
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/v1/assets/skill/example/1.0.0/undeclared",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "not_found");
            Ok(())
        },
    )?;

    let wrong_asset_methods = [
        ("POST", "/v1/assets/storage/summary"),
        ("POST", "/v1/assets/skill/example/manifest"),
        ("POST", "/v1/assets/skill/example/channels"),
        ("PATCH", "/v1/assets/skill/example/channels/stable"),
        ("PUT", "/v1/assets/skill/example/1.0.0/yank"),
        ("GET", "/v1/assets/presign/upload/skill/example/1.0.0"),
        ("GET", "/v1/assets/presign/commit/skill/example/1.0.0"),
        ("GET", "/v1/assets/presign/abort/skill/example/1.0.0"),
        ("POST", "/v1/assets/presign/download/skill/example/1.0.0"),
    ];
    for (method, path) in wrong_asset_methods {
        case.expect_json(method, path, &[], "", 405, |body| {
            assert_eq!(body["error"]["type"], "ferrogate_error");
            assert_eq!(body["error"]["code"], "method_not_allowed");
            assert!(body["error"]["message"].is_string());
            assert!(body["error"]["request_id"].is_string());
            Ok(())
        })?;
    }

    let authenticated_asset_methods = [
        ("GET", "/v1/assets/skill/example/manifest", ""),
        ("GET", "/v1/assets/skill/example/channels", ""),
        (
            "PUT",
            "/v1/assets/skill/example/channels/stable?version=1.0.0",
            "",
        ),
        ("DELETE", "/v1/assets/skill/example/channels/stable", ""),
        ("POST", "/v1/assets/skill/example/1.0.0/yank", ""),
        ("DELETE", "/v1/assets/skill/example/1.0.0/yank", ""),
        (
            "POST",
            "/v1/assets/presign/upload/skill/example/1.0.0",
            r#"{"size_bytes":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        ),
        (
            "POST",
            "/v1/assets/presign/commit/skill/example/1.0.0",
            r#"{"size_bytes":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        ),
        (
            "POST",
            "/v1/assets/presign/abort/skill/example/1.0.0",
            r#"{"upload_id":"upl_00000000000000000000000000000000","size_bytes":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        ),
        ("GET", "/v1/assets/presign/download/skill/example/1.0.0", ""),
        ("GET", "/v1/assets/storage/summary", ""),
    ];
    for (method, path, body) in authenticated_asset_methods {
        case.expect_json(method, path, &[], body, 401, |response| {
            assert_eq!(response["error"]["type"], "ferrogate_error");
            assert_eq!(response["error"]["code"], "missing_api_key");
            assert!(response["error"]["message"].is_string());
            assert!(response["error"]["request_id"].is_string());
            Ok(())
        })?;
    }

    Ok(())
}

/// #577 API-contract coverage: collection POST creates are insert-only for the
/// tenant-account and agent-schedule surfaces. Removing either existence check
/// makes the duplicate request return 201/overwrite instead of the typed 409,
/// and the read-back equality assertions below go red if the old row mutates.
fn assert_duplicate_create_conflicts(case: &LocalHarness) -> Result<()> {
    case.expect_json(
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"contract-dup-tenant","name":"Contract duplicate tenant","slug":"contract-dup-tenant"}"#,
        201,
        |body| {
            assert_eq!(body["tenant"]["id"], "contract-dup-tenant");
            Ok(())
        },
    )?;
    let mut original_tenant = serde_json::Value::Null;
    case.expect_json(
        "GET",
        "/admin/v1/tenant-accounts/contract-dup-tenant",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            original_tenant = body["tenant"].clone();
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"contract-dup-tenant","name":"Replacement tenant","slug":"replacement-tenant","status":"suspended","plan_id":"free"}"#,
        409,
        |body| {
            assert_eq!(body["error"]["code"], "tenant_account_already_exists");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/tenant-accounts/contract-dup-tenant",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["tenant"], original_tenant);
            Ok(())
        },
    )?;

    case.expect_json(
        "POST",
        "/admin/v1/projects",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"contract-dup-project","tenant_id":"contract-dup-tenant","name":"Contract duplicate project","slug":"contract-dup-project"}"#,
        201,
        |_| Ok(()),
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/workspaces",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"contract-dup-workspace","project_id":"contract-dup-project","name":"Contract duplicate workspace","slug":"contract-dup-workspace"}"#,
        201,
        |_| Ok(()),
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-schedules",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"contract-dup-schedule","tenant_id":"contract-dup-tenant","workspace_id":"contract-dup-workspace","name":"Contract duplicate schedule","spec_kind":"interval","interval_secs":3600,"target_kind":"self_hosted_dispatch","target":{"required_capabilities":["shell"],"workload_ref":"contract-original-workload"}}"#,
        201,
        |body| {
            assert_eq!(body["agent_schedule"]["id"], "contract-dup-schedule");
            Ok(())
        },
    )?;
    let mut original_schedule = serde_json::Value::Null;
    case.expect_json(
        "GET",
        "/admin/v1/agent-schedules/contract-dup-schedule",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            original_schedule = body["agent_schedule"].clone();
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-schedules",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"contract-dup-schedule","tenant_id":"contract-dup-tenant","workspace_id":"contract-dup-workspace","name":"Replacement schedule","spec_kind":"interval","interval_secs":60,"target_kind":"self_hosted_dispatch","target":{"required_capabilities":["shell"],"workload_ref":"contract-replacement-workload"}}"#,
        409,
        |body| {
            assert_eq!(body["error"]["code"], "agent_schedule_already_exists");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-schedules/contract-dup-schedule",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["agent_schedule"], original_schedule);
            Ok(())
        },
    )
}
