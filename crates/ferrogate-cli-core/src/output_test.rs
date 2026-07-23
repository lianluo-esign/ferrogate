// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for output format parsing and rendering (#360).

use super::*;

#[test]
fn output_format_parse_accepts_known_spellings() {
    assert_eq!(OutputFormat::parse("table").unwrap(), OutputFormat::Table);
    assert_eq!(OutputFormat::parse("TEXT").unwrap(), OutputFormat::Table);
    assert_eq!(OutputFormat::parse(" json ").unwrap(), OutputFormat::Json);
}

#[test]
fn output_format_parse_rejects_unknown() {
    let error = OutputFormat::parse("yaml").unwrap_err();
    assert_eq!(error.exit_class(), crate::error::ExitClass::Usage);
}

#[test]
fn output_format_default_is_table() {
    assert_eq!(OutputFormat::default(), OutputFormat::Table);
    assert_eq!(OutputFormat::Json.as_str(), "json");
}

#[test]
fn table_render_aligns_columns() {
    let table = Table::new(
        vec!["NAME".to_string(), "ENDPOINT".to_string()],
        vec![
            vec!["production".to_string(), "https://prod".to_string()],
            vec!["dev".to_string(), "http://localhost:8080".to_string()],
        ],
    )
    .unwrap();
    let rendered = table.render();
    let lines: Vec<&str> = rendered.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("NAME"));
    // NAME column padded to the width of "production".
    assert!(lines[1].starts_with("production  https://prod"));
    assert!(lines[2].starts_with("dev "));
    // No trailing whitespace on any line.
    for line in &lines {
        assert_eq!(*line, line.trim_end());
    }
}

#[test]
fn ragged_table_is_a_usage_error() {
    let error = Table::new(
        vec!["A".to_string(), "B".to_string()],
        vec![vec!["only-one".to_string()]],
    )
    .unwrap_err();
    assert_eq!(error.exit_class(), crate::error::ExitClass::Usage);
}

#[test]
fn json_render_is_stable_and_pretty() {
    #[derive(serde::Serialize)]
    struct Row {
        name: String,
        count: u32,
    }
    let rendered = render_json(&Row {
        name: "acme".to_string(),
        count: 3,
    })
    .unwrap();
    assert_eq!(rendered, "{\n  \"name\": \"acme\",\n  \"count\": 3\n}");
}
