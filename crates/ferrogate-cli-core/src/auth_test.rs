// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for credential source selection and redaction (#360).

use super::*;
use crate::error::ExitClass;
use std::collections::HashMap;

/// Test resolver with a fixed environment and a fixed stdin payload.
struct FakeResolver {
    env: HashMap<String, String>,
    stdin: Option<String>,
}

impl FakeResolver {
    fn new() -> Self {
        FakeResolver {
            env: HashMap::new(),
            stdin: None,
        }
    }
    fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_string(), value.to_string());
        self
    }
    fn with_stdin(mut self, value: &str) -> Self {
        self.stdin = Some(value.to_string());
        self
    }
}

impl SecretResolver for FakeResolver {
    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }
    fn read_stdin(&self) -> CliResult<String> {
        self.stdin
            .clone()
            .ok_or_else(|| CliError::auth("no stdin available"))
    }
}

#[test]
fn none_source_resolves_to_no_credential() {
    let resolver = FakeResolver::new();
    let credential = resolve_credential(&AuthSource::None, &resolver).unwrap();
    assert!(credential.is_none());
    assert!(AuthSource::None.is_anonymous());
}

#[test]
fn env_source_reads_named_variable() {
    let resolver = FakeResolver::new().with_env("PROD_TOKEN", "secret-token-value");
    let source = AuthSource::Env {
        var: "PROD_TOKEN".to_string(),
    };
    let credential = resolve_credential(&source, &resolver).unwrap().unwrap();
    assert_eq!(credential.expose(), "secret-token-value");
    assert_eq!(
        credential.authorization_header(),
        "Bearer secret-token-value"
    );
}

#[test]
fn env_source_missing_variable_is_auth_error() {
    let resolver = FakeResolver::new();
    let source = AuthSource::Env {
        var: "PROD_TOKEN".to_string(),
    };
    let error = resolve_credential(&source, &resolver).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}

#[test]
fn env_source_empty_variable_is_auth_error() {
    let resolver = FakeResolver::new().with_env("PROD_TOKEN", "   ");
    let source = AuthSource::Env {
        var: "PROD_TOKEN".to_string(),
    };
    let error = resolve_credential(&source, &resolver).unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Auth);
}

#[test]
fn stdin_source_trims_trailing_newline() {
    let resolver = FakeResolver::new().with_stdin("piped-token\n");
    let credential = resolve_credential(&AuthSource::Stdin, &resolver)
        .unwrap()
        .unwrap();
    assert_eq!(credential.expose(), "piped-token");
}

#[test]
fn inline_source_yields_token() {
    let source = AuthSource::Inline {
        token: "inline-token".to_string(),
    };
    let resolver = FakeResolver::new();
    let credential = resolve_credential(&source, &resolver).unwrap().unwrap();
    assert_eq!(credential.expose(), "inline-token");
}

#[test]
fn credential_debug_and_display_redact_the_secret() {
    let credential = Credential::new("very-secret").unwrap();
    let debug = format!("{credential:?}");
    let display = format!("{credential}");
    assert!(!debug.contains("very-secret"));
    assert!(!display.contains("very-secret"));
    assert!(debug.contains("redacted"));
}

#[test]
fn auth_source_describe_is_secret_free() {
    let inline = AuthSource::Inline {
        token: "should-not-appear".to_string(),
    };
    assert!(!inline.describe().contains("should-not-appear"));
    assert_eq!(
        AuthSource::Env {
            var: "FERROGATE_TOKEN".to_string()
        }
        .describe(),
        "env:FERROGATE_TOKEN"
    );
    assert_eq!(AuthSource::None.describe(), "none (anonymous)");
}

#[test]
fn env_auth_source_roundtrips_through_serde_without_a_token() {
    let source = AuthSource::Env {
        var: "FERROGATE_TOKEN".to_string(),
    };
    let json = serde_json::to_string(&source).unwrap();
    let parsed: AuthSource = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, source);
    assert!(json.contains("\"kind\":\"env\""));
}
