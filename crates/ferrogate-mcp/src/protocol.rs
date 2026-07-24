// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP protocol revisions, version negotiation, and the 2026-07-28
//! `Mcp-Method` / `Mcp-Name` Streamable-HTTP routing headers (issue #277).

/// MCP protocol revision FerroGate prefers to negotiate: 2026-07-28, the
/// gateway-friendly "stateless core" revision that adds the `Mcp-Method` /
/// `Mcp-Name` Streamable-HTTP routing headers (issue #277).
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
/// Previous stable revision FerroGate falls back to when a peer does not speak
/// 2026-07-28.
pub const MCP_PROTOCOL_VERSION_FALLBACK: &str = "2025-06-18";
/// Protocol versions FerroGate can speak, newest first.
pub const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] =
    &[MCP_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION_FALLBACK];

/// Streamable-HTTP routing header carrying the JSON-RPC method (2026-07-28).
/// Lets gateways/load-balancers route, scope-gate, rate-limit, and meter per
/// operation without parsing the request body.
pub const MCP_METHOD_HEADER: &str = "mcp-method";
/// Streamable-HTTP routing header carrying the operation target name — for
/// `tools/call` this is the tool name.
pub const MCP_NAME_HEADER: &str = "mcp-name";

/// Returns true when `version` is a protocol revision FerroGate can speak.
pub fn is_supported_protocol_version(version: &str) -> bool {
    SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&version)
}

/// Server-side version negotiation for the `/v1/mcp` ingress: given the
/// `protocolVersion` a client requested in `initialize`, pick the version
/// FerroGate will actually speak. An exactly-supported request is honoured;
/// anything else (omitted, unknown, or newer) negotiates down to the newest
/// version FerroGate speaks so an unrecognised client still gets a usable
/// protocol rather than a hard failure.
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) if version == MCP_PROTOCOL_VERSION_FALLBACK => MCP_PROTOCOL_VERSION_FALLBACK,
        _ => MCP_PROTOCOL_VERSION,
    }
}

/// Client-side: resolve the version to use after an upstream `initialize`
/// echoes its chosen `protocolVersion`. The server's choice is honoured when
/// supported; if it is omitted or unknown FerroGate falls back to the previous
/// stable revision so tool calls still proceed.
pub fn resolve_negotiated_version(server_version: Option<&str>) -> &'static str {
    match server_version {
        Some(version) if version == MCP_PROTOCOL_VERSION => MCP_PROTOCOL_VERSION,
        _ => MCP_PROTOCOL_VERSION_FALLBACK,
    }
}

/// Mismatch between a Streamable-HTTP routing header and the JSON-RPC body it
/// claims to describe. The ingress fails such a request closed (issue #277) so
/// a caller cannot be scope-gated / rate-limited / metered as one operation
/// while the body executes another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingHeaderMismatch {
    pub header: &'static str,
    pub header_value: String,
    pub body_value: String,
}

impl std::fmt::Display for RoutingHeaderMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} header {:?} does not match request body value {:?}",
            self.header, self.header_value, self.body_value
        )
    }
}

/// Verify the optional `Mcp-Method` / `Mcp-Name` routing headers against the
/// parsed JSON-RPC body. The headers are optional — a pre-2026-07-28 client
/// omits them — but when present they MUST agree with the body, else the
/// request is rejected. `body_name` is the `tools/call` target name (`None`
/// for methods that carry no name).
pub fn verify_routing_headers(
    header_method: Option<&str>,
    header_name: Option<&str>,
    body_method: &str,
    body_name: Option<&str>,
) -> Result<(), RoutingHeaderMismatch> {
    if let Some(header_method) = header_method {
        if header_method != body_method {
            return Err(RoutingHeaderMismatch {
                header: "Mcp-Method",
                header_value: header_method.to_string(),
                body_value: body_method.to_string(),
            });
        }
    }
    if let Some(header_name) = header_name {
        let body_name = body_name.unwrap_or_default();
        if header_name != body_name {
            return Err(RoutingHeaderMismatch {
                header: "Mcp-Name",
                header_value: header_name.to_string(),
                body_value: body_name.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "protocol_test.rs"]
mod tests;
