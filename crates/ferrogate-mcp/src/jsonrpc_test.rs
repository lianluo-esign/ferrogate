// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use serde_json::json;

#[test]
fn parses_tools_list_with_rmcp_model() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{
                "name": "search",
                "description": "Search repos",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}
            }]
        }
    });

    let tools = parse_tools_list(&response).unwrap();

    assert_eq!(tools[0].name, "search");
    assert_eq!(tools[0].description.as_deref(), Some("Search repos"));
    assert_eq!(tools[0].input_schema["type"], "object");
}
