// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP protocol revisions, version negotiation, and Streamable-HTTP routing
//! headers.
//!
//! The modern ingress contract is pinned to official modelcontextprotocol
//! commit `71e306956a4959c9655e5036be215d41986596e6`, rather than the obsolete
//! 2026-07-28-RC tag. The final release is not published, so this is a candidate
//! contract under validation rather than a final-conformance claim.

/// Modern MCP candidate revision accepted by FerroGate's stateless ingress.
/// This revision adds the `Mcp-Method` / `Mcp-Name` Streamable-HTTP routing
/// headers (issues #277/#570); it is never negotiated through `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
/// Direct legacy predecessor. This is the newest revision an `initialize`
/// handshake may negotiate; modern 2026-07-28 is not initialize-based.
pub const MCP_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
/// Older stable revision retained for existing FerroGate clients.
pub const MCP_PROTOCOL_VERSION_FALLBACK: &str = "2025-06-18";
/// Protocol versions FerroGate can speak, newest first.
pub const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &[
    MCP_PROTOCOL_VERSION,
    MCP_LEGACY_PROTOCOL_VERSION,
    MCP_PROTOCOL_VERSION_FALLBACK,
];

/// Streamable-HTTP header carrying the per-request protocol revision.
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

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

/// Legacy server-side negotiation for an `initialize` request.
///
/// `2026-07-28` removed the initialize handshake, so it must never be echoed by
/// this function. Exact supported legacy revisions are honoured; omitted,
/// unknown, or modern values choose the direct legacy predecessor.
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) if version == MCP_LEGACY_PROTOCOL_VERSION => MCP_LEGACY_PROTOCOL_VERSION,
        Some(version) if version == MCP_PROTOCOL_VERSION_FALLBACK => MCP_PROTOCOL_VERSION_FALLBACK,
        _ => MCP_LEGACY_PROTOCOL_VERSION,
    }
}

/// Client-side: resolve the version to use after an upstream `initialize`
/// echoes its chosen `protocolVersion`. The server's choice is honoured when
/// supported; if it is omitted or unknown FerroGate falls back to the previous
/// stable revision so tool calls still proceed.
pub fn resolve_negotiated_version(server_version: Option<&str>) -> &'static str {
    match server_version {
        Some(version) if version == MCP_PROTOCOL_VERSION => MCP_PROTOCOL_VERSION,
        Some(version) if version == MCP_LEGACY_PROTOCOL_VERSION => MCP_LEGACY_PROTOCOL_VERSION,
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
/// parsed JSON-RPC body. This low-level verifier accepts absent headers for
/// legacy callers; the modern ingress layer requires them. When present they
/// MUST agree with the body. `body_name` is the tool/prompt name or resource
/// URI (`None` for methods that carry no name).
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
