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

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Serialize;
use serde_json::{json, Map, Value};

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

const MODERN_ERROR_HEADER_MISMATCH: i64 = -32020;
const MODERN_ERROR_MISSING_CLIENT_CAPABILITY: i64 = -32021;
const MODERN_ERROR_UNSUPPORTED_VERSION: i64 = -32022;
const JSONRPC_ERROR_METHOD_NOT_FOUND: i64 = -32601;

/// The MCP protocol era selected for one upstream process or HTTP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProtocolMode {
    Modern,
    Legacy,
}

/// Bounded evidence explaining why a modern probe entered legacy mode.
///
/// Never put an upstream response body or error message here. Admin status is
/// operator evidence, not a place to copy untrusted or high-cardinality text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProtocolDowngradeReason {
    Http400UnrecognizedResponse,
    Http404UnrecognizedResponse,
    Http405UnrecognizedResponse,
    StdioMethodNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct McpNegotiatedProtocol {
    pub(crate) mode: McpProtocolMode,
    pub(crate) version: &'static str,
    pub(crate) downgrade_reason: Option<McpProtocolDowngradeReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum McpClientNegotiation {
    #[default]
    Pending,
    Negotiated(McpNegotiatedProtocol),
}

impl McpClientNegotiation {
    pub(crate) fn modern() -> Self {
        Self::Negotiated(McpNegotiatedProtocol {
            mode: McpProtocolMode::Modern,
            version: MCP_PROTOCOL_VERSION,
            downgrade_reason: None,
        })
    }

    pub(crate) fn legacy(
        version: &'static str,
        downgrade_reason: Option<McpProtocolDowngradeReason>,
    ) -> Self {
        Self::Negotiated(McpNegotiatedProtocol {
            mode: McpProtocolMode::Legacy,
            version,
            downgrade_reason,
        })
    }

    pub(crate) fn negotiated(self) -> Option<McpNegotiatedProtocol> {
        match self {
            Self::Pending => None,
            Self::Negotiated(protocol) => Some(protocol),
        }
    }

    pub(crate) fn is_modern(self) -> bool {
        self.negotiated()
            .is_some_and(|protocol| protocol.mode == McpProtocolMode::Modern)
    }
}

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

/// Strictly adopt a legacy revision returned by an upstream `initialize`.
/// Modern, omitted, and unknown versions are not valid initialize results.
pub fn resolve_legacy_protocol_version(server_version: Option<&str>) -> Option<&'static str> {
    match server_version {
        Some(version) if version == MCP_LEGACY_PROTOCOL_VERSION => {
            Some(MCP_LEGACY_PROTOCOL_VERSION)
        }
        Some(version) if version == MCP_PROTOCOL_VERSION_FALLBACK => {
            Some(MCP_PROTOCOL_VERSION_FALLBACK)
        }
        _ => None,
    }
}

/// Client-side: resolve the version to use after an upstream `initialize`
/// echoes its chosen `protocolVersion`. Kept for API compatibility; new client
/// code uses [`resolve_legacy_protocol_version`] and fails closed when the
/// server omits or returns an invalid legacy revision.
pub fn resolve_negotiated_version(server_version: Option<&str>) -> &'static str {
    match server_version {
        Some(version) if version == MCP_PROTOCOL_VERSION => MCP_PROTOCOL_VERSION,
        Some(version) if version == MCP_LEGACY_PROTOCOL_VERSION => MCP_LEGACY_PROTOCOL_VERSION,
        _ => MCP_PROTOCOL_VERSION_FALLBACK,
    }
}

pub(crate) fn modern_request_params(params: Value) -> Result<Value, &'static str> {
    let Value::Object(mut params) = params else {
        return Err("modern MCP request params must be an object");
    };
    params.insert("_meta".into(), modern_request_meta());
    Ok(Value::Object(params))
}

fn modern_request_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "ferrogate",
            "version": env!("CARGO_PKG_VERSION")
        },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

pub(crate) fn modern_discover_params() -> Value {
    let mut params = Map::new();
    params.insert("_meta".into(), modern_request_meta());
    Value::Object(params)
}

pub(crate) fn discover_supports_current_version(response: &Value) -> bool {
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !matches!(
            response.get("id"),
            Some(Value::String(_) | Value::Number(_))
        )
    {
        return false;
    }
    let Some(result) = response.get("result").and_then(Value::as_object) else {
        return false;
    };
    result.get("resultType").and_then(Value::as_str) == Some("complete")
        && result.get("capabilities").is_some_and(Value::is_object)
        && result
            .get("supportedVersions")
            .and_then(Value::as_array)
            .is_some_and(|versions| {
                versions
                    .iter()
                    .any(|version| version.as_str() == Some(MCP_PROTOCOL_VERSION))
            })
}

pub(crate) fn jsonrpc_error_code(response: &Value) -> Option<i64> {
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let error = response.get("error").and_then(Value::as_object)?;
    error.get("message").and_then(Value::as_str)?;
    error.get("code").and_then(Value::as_i64)
}

pub(crate) fn is_recognized_modern_error(response: &Value) -> bool {
    matches!(
        jsonrpc_error_code(response),
        Some(
            MODERN_ERROR_HEADER_MISMATCH
                | MODERN_ERROR_MISSING_CLIENT_CAPABILITY
                | MODERN_ERROR_UNSUPPORTED_VERSION
                | JSONRPC_ERROR_METHOD_NOT_FOUND
        )
    )
}

pub(crate) fn is_stdio_legacy_signal(response: &Value) -> bool {
    jsonrpc_error_code(response) == Some(JSONRPC_ERROR_METHOD_NOT_FOUND)
}

pub(crate) fn http_legacy_downgrade_reason(
    status: u16,
    response: Option<&Value>,
) -> Option<McpProtocolDowngradeReason> {
    if response.is_some_and(is_recognized_modern_error) {
        return None;
    }
    match status {
        400 => Some(McpProtocolDowngradeReason::Http400UnrecognizedResponse),
        404 => Some(McpProtocolDowngradeReason::Http404UnrecognizedResponse),
        405 => Some(McpProtocolDowngradeReason::Http405UnrecognizedResponse),
        _ => None,
    }
}

/// Encode an outbound mirrored header value using the candidate's sentinel
/// rules. Values that are not unambiguous, trimmed, visible ASCII are Base64.
pub(crate) fn encode_mcp_header_value(value: &str) -> String {
    let ambiguous = value.starts_with("=?base64?") && value.ends_with("?=");
    let has_unsafe_byte = value
        .as_bytes()
        .iter()
        .any(|byte| !matches!(byte, b'\t' | 0x20..=0x7e));
    let has_edge_whitespace = value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        || value.as_bytes().last().is_some_and(u8::is_ascii_whitespace);
    if ambiguous || has_unsafe_byte || has_edge_whitespace {
        format!("=?base64?{}?=", BASE64_STANDARD.encode(value.as_bytes()))
    } else {
        value.to_string()
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
