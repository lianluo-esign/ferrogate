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

    Ok(())
}
