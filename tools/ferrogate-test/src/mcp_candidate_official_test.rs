// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Focused checks for official MCP opponent provenance and wire evidence.

use super::*;
use serde_json::json;

fn modern_request(gateway_instance: usize, method: &str, name: Option<&str>) -> Value {
    let mut headers = json!({
        "authorization": "<redacted>",
        "content-type": "application/json",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": method,
    });
    if let Some(name) = name {
        headers["mcp-name"] = json!(name);
    }
    let mut params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "ferrogate-official-modern",
                "version": "1.0.0"
            }
        }
    });
    if let Some(name) = name {
        params["name"] = json!(name);
        params["arguments"] = json!({"query": "official"});
    }
    let response = match method {
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resultType": "complete", "tools": [], "ttlMs": 5_000, "cacheScope": "private"}
        }),
        _ => json!({"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}}),
    };
    json!({
        "gatewayInstance": gateway_instance,
        "httpMethod": "POST",
        "headers": headers,
        "body": {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        "response": response
    })
}

fn valid_evidence() -> OpponentEvidence {
    serde_json::from_value(json!({
        "opponent": {
            "package": "@modelcontextprotocol/client",
            "version": "2.0.0",
            "commit": "cc4b41617ce3601b1290d67216ea0b194a3cd9ac",
            "protocolArtifactCommit": "5f5440bb26a62e2cf3440b92da5a667efa03b267",
            "protocolArtifactStatus": "final"
        },
        "specVersion": "2026-07-28",
        "modern": {
            "era": "modern",
            "protocolVersion": "2026-07-28",
            "tools": ["http-search"],
            "call": {"content": [{"type": "text", "text": "ferrogate-result"}], "isError": false},
            "wire": [
                modern_request(0, "server/discover", None),
                modern_request(1, "tools/list", None),
                modern_request(0, "tools/call", Some("http-search"))
            ]
        },
        "legacy": {
            "era": "legacy",
            "protocolVersion": "2025-11-25",
            "tools": ["http-search"],
            "call": {"content": [{"type": "text", "text": "ferrogate-result"}], "isError": false},
            "wire": [
                {
                    "gatewayInstance": 0,
                    "httpMethod": "POST",
                    "headers": {"authorization": "<redacted>", "content-type": "application/json"},
                    "body": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}
                },
                {
                    "gatewayInstance": 0,
                    "httpMethod": "POST",
                    "headers": {"authorization": "<redacted>", "content-type": "application/json"},
                    "body": {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
                },
                {
                    "gatewayInstance": 0,
                    "httpMethod": "POST",
                    "headers": {"authorization": "<redacted>", "content-type": "application/json", "mcp-protocol-version": "2025-11-25"},
                    "body": {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
                },
                {
                    "gatewayInstance": 0,
                    "httpMethod": "POST",
                    "headers": {"authorization": "<redacted>", "content-type": "application/json", "mcp-protocol-version": "2025-11-25"},
                    "body": {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "http-search", "arguments": {}}}
                }
            ]
        }
    }))
    .unwrap()
}

#[test]
fn committed_opponent_provenance_and_lockfile_hold_the_exact_pins() {
    let root = repository_root().unwrap();
    verify_provenance(&root.join(FIXTURE_DIRECTORY)).unwrap();
}

#[test]
fn official_evidence_requires_the_full_modern_and_legacy_wire_contract() {
    validate_evidence(&valid_evidence()).unwrap();

    let mut session = valid_evidence();
    session.modern.wire[1]
        .headers
        .insert("mcp-session-id".into(), "forbidden".into());
    assert!(validate_evidence(&session)
        .unwrap_err()
        .to_string()
        .contains("Mcp-Session-Id"));

    let mut single_instance = valid_evidence();
    for request in &mut single_instance.modern.wire {
        request.gateway_instance = 0;
    }
    assert!(validate_evidence(&single_instance)
        .unwrap_err()
        .to_string()
        .contains("alternate across two FerroGate instances"));

    let mut missing_metadata = valid_evidence();
    missing_metadata.modern.wire[2].body.as_mut().unwrap()["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .remove("io.modelcontextprotocol/clientCapabilities");
    assert!(validate_evidence(&missing_metadata)
        .unwrap_err()
        .to_string()
        .contains("clientCapabilities"));

    let mut malformed_client_info = valid_evidence();
    malformed_client_info.modern.wire[0].body.as_mut().unwrap()["params"]["_meta"]
        ["io.modelcontextprotocol/clientInfo"] = json!({"name": "ferrogate-official-modern"});
    assert!(validate_evidence(&malformed_client_info)
        .unwrap_err()
        .to_string()
        .contains("clientInfo"));

    let mut wrong_probe = valid_evidence();
    wrong_probe.modern.wire[0].body.as_mut().unwrap()["method"] = json!("initialize");
    assert!(validate_evidence(&wrong_probe)
        .unwrap_err()
        .to_string()
        .contains("wire sequence"));

    let mut missing_ttl = valid_evidence();
    missing_ttl.modern.wire[1].response.as_mut().unwrap()["result"]
        .as_object_mut()
        .unwrap()
        .remove("ttlMs");
    assert!(validate_evidence(&missing_ttl)
        .unwrap_err()
        .to_string()
        .contains("ttlMs"));

    let mut missing_scope = valid_evidence();
    missing_scope.modern.wire[1].response.as_mut().unwrap()["result"]
        .as_object_mut()
        .unwrap()
        .remove("cacheScope");
    assert!(validate_evidence(&missing_scope)
        .unwrap_err()
        .to_string()
        .contains("cacheScope"));

    let mut public_scope = valid_evidence();
    public_scope.modern.wire[1].response.as_mut().unwrap()["result"]["cacheScope"] =
        json!("public");
    assert!(validate_evidence(&public_scope)
        .unwrap_err()
        .to_string()
        .contains("cacheScope"));
}
