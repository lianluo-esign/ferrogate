// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the Clap global flags and their fold into overrides (#360).

use super::*;
use clap::Parser;

/// A minimal parser embedding the shared global flags, mirroring how the real
/// CLI root will flatten them.
#[derive(Debug, Parser)]
struct TestCli {
    #[command(flatten)]
    globals: GlobalArgs,
}

fn parse(args: &[&str]) -> GlobalArgs {
    TestCli::parse_from(std::iter::once("ferrogate").chain(args.iter().copied())).globals
}

#[test]
fn empty_args_produce_empty_overrides() {
    let overrides = parse(&[]).to_overrides().unwrap();
    assert_eq!(overrides, GlobalOverrides::default());
}

#[test]
fn flags_map_into_overrides() {
    let overrides = parse(&[
        "--context",
        "production",
        "--endpoint",
        "https://prod",
        "--tenant",
        "acme",
        "--timeout-millis",
        "1500",
        "--output",
        "json",
        "--non-interactive",
    ])
    .to_overrides()
    .unwrap();
    assert_eq!(overrides.context.as_deref(), Some("production"));
    assert_eq!(overrides.endpoint.as_deref(), Some("https://prod"));
    assert_eq!(overrides.tenant.as_deref(), Some("acme"));
    assert_eq!(overrides.timeout_millis, Some(1500));
    assert_eq!(overrides.output, Some(OutputFormat::Json));
    assert!(overrides.non_interactive);
}

#[test]
fn token_env_flag_selects_env_auth_source() {
    let overrides = parse(&["--token-env", "MY_TOKEN"]).to_overrides().unwrap();
    assert_eq!(
        overrides.auth,
        Some(AuthSource::Env {
            var: "MY_TOKEN".to_string()
        })
    );
}

#[test]
fn token_stdin_flag_selects_stdin_source() {
    let overrides = parse(&["--token-stdin"]).to_overrides().unwrap();
    assert_eq!(overrides.auth, Some(AuthSource::Stdin));
}

#[test]
fn token_env_and_token_stdin_conflict() {
    let result = TestCli::try_parse_from(["ferrogate", "--token-env", "X", "--token-stdin"]);
    assert!(result.is_err());
}

#[test]
fn invalid_output_format_is_usage_error() {
    let error = parse(&["--output", "xml"]).to_overrides().unwrap_err();
    assert_eq!(error.exit_class(), crate::error::ExitClass::Usage);
}
