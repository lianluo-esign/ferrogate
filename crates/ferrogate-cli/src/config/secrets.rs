// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Result as AnyResult};

pub(crate) fn resolve_env_placeholders(value: &str) -> AnyResult<String> {
    let mut resolved = String::new();
    let mut rest = value;

    while let Some(start) = rest.find("{env.") {
        resolved.push_str(&rest[..start]);
        let after_start = &rest[start + 5..];
        let Some(end) = after_start.find('}') else {
            bail!("unterminated environment variable placeholder");
        };
        let name = &after_start[..end];
        if !valid_env_name(name) {
            bail!("invalid environment variable placeholder name `{name}`");
        }
        let env_value = std::env::var(name)
            .map_err(|_| anyhow::anyhow!("environment variable `{name}` is not set"))?;
        resolved.push_str(&env_value);
        rest = &after_start[end + 1..];
    }

    resolved.push_str(rest);
    Ok(resolved)
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_environment_placeholders() {
        std::env::set_var("FERROGATE_TEST_SECRET", "secret-value");

        let resolved = resolve_env_placeholders("Bearer {env.FERROGATE_TEST_SECRET}").unwrap();

        assert_eq!(resolved, "Bearer secret-value");
    }

    #[test]
    fn reports_missing_environment_variable_by_name_only() {
        std::env::remove_var("FERROGATE_MISSING_SECRET");

        let error = resolve_env_placeholders("{env.FERROGATE_MISSING_SECRET}")
            .unwrap_err()
            .to_string();

        assert!(error.contains("FERROGATE_MISSING_SECRET"));
        assert!(!error.contains("secret-value"));
    }
}
