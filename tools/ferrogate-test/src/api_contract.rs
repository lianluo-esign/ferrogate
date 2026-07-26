// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Live fixed-API contract enforcement coverage for issue #203.

use crate::{cli::LocalArgs, constants::ADMIN_AUTH, local::LocalHarness};
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
