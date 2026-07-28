// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Real-process E2E coverage for cf:// provider secrets resolved from a Worker binding.

//! #417: prove the operator-facing `cf://` provider path through a real
//! FerroGate process without a Cloudflare REST backend or external resource.

use crate::{
    cli::LocalArgs,
    constants::{CLIENT_AUTH, JSON_CONTENT},
    local::LocalHarness,
};
use anyhow::{ensure, Result};

const SECRET_REF: &str = "cf://provider-keys/openai-api-key";
const BINDING_ENV: &str = "FERROGATE_CF_SECRET_OPENAI_API_KEY";
const BINDING_CANARY: &str = "cf-worker-binding-e2e-canary";

pub(crate) fn run_cloudflare_secret_api(args: &LocalArgs) -> Result<()> {
    let mut gateway = LocalHarness::start_with_provider_secret_binding(
        &args.ferrogate_bin,
        1,
        SECRET_REF,
        BINDING_ENV,
        BINDING_CANARY,
    )?;

    gateway.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"cloudflare worker binding e2e"}]}"#,
        200,
        |body| {
            ensure!(
                body["object"] == "chat.completion",
                "cf:// provider request returned the wrong response object: {body}"
            );
            Ok(())
        },
    )?;

    let requests = gateway.take_provider_requests()?;
    ensure!(
        requests.len() == 1,
        "cf:// scenario expected exactly one provider request, got {}",
        requests.len()
    );
    let request = &requests[0];
    ensure!(
        request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"),
        "cf:// scenario did not reach the OpenAI-compatible chat endpoint"
    );
    ensure!(
        request.contains("cloudflare worker binding e2e"),
        "cf:// scenario provider request lost its body marker"
    );

    let authorization: Vec<&str> = request
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .collect();
    let expected = format!("Bearer {BINDING_CANARY}");
    ensure!(
        authorization.len() == 1 && authorization[0] == expected.as_str(),
        "cf:// provider Authorization must come exactly from the Worker binding; expected one {expected:?}, got {authorization:?}"
    );
    ensure!(
        !request.contains("provider-secret"),
        "cf:// provider request used the ordinary api_key_env fixture instead of the Worker binding"
    );

    println!("cloudflare-secret-api scenario passed");
    Ok(())
}
