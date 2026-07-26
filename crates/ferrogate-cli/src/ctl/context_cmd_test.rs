// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for the `context` verb helpers (issue #360): the credential
//! flags collapse to the right secret-free [`AuthSource`], and the only
//! credential-rendering path never emits a token value.

use super::*;
use crate::cli::ContextCreateArgs;

fn base_args() -> ContextCreateArgs {
    ContextCreateArgs {
        name: "x".to_string(),
        endpoint: "https://control.example.com".to_string(),
        tenant: None,
        project: None,
        workspace: None,
        token_env: None,
        token_stdin: false,
        ca_bundle: None,
        insecure_skip_tls_verify: false,
        use_now: false,
        overwrite: false,
    }
}

#[test]
fn token_env_flag_maps_to_env_source() {
    let mut args = base_args();
    args.token_env = Some("MY_TOKEN".to_string());
    assert_eq!(
        auth_source(&args),
        AuthSource::Env {
            var: "MY_TOKEN".to_string()
        }
    );
}

#[test]
fn token_stdin_flag_maps_to_stdin_source() {
    let mut args = base_args();
    args.token_stdin = true;
    assert_eq!(auth_source(&args), AuthSource::Stdin);
}

#[test]
fn no_credential_flag_is_anonymous() {
    assert_eq!(auth_source(&base_args()), AuthSource::None);
}

#[test]
fn credential_rendering_is_secret_free() {
    // `list` and `show` render a credential ONLY through `describe`, which
    // reports the source, never a value or a Bearer header.
    let described = AuthSource::Env {
        var: "SECRET_ENV".to_string(),
    }
    .describe();
    assert_eq!(described, "env:SECRET_ENV");
    assert!(!described.contains("Bearer"));
}
