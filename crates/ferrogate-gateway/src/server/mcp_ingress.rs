// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Dual-era MCP ingress metadata validation for the pinned 2026-07-28 candidate.

//! Stateless modern MCP request classification and Streamable-HTTP validation.
//!
//! Protocol truth is pinned to official modelcontextprotocol commit
//! `71e306956a4959c9655e5036be215d41986596e6`. Legacy requests remain
//! initialize-based; modern requests carry all identity and capability metadata
//! on the request being validated. Nothing here caches client metadata.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use http::HeaderMap;
use serde_json::{json, Value};

use super::mcp_rpc::McpJsonRpcRequest;

const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO_META: &str = "io.modelcontextprotocol/clientInfo";
const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
const BASE64_SENTINEL_SUFFIX: &str = "?=";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum McpIngressMode {
    Legacy,
    Modern,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidatedMcpIngress {
    pub(super) mode: McpIngressMode,
    pub(super) metric_method: String,
    pub(super) metric_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum McpIngressValidationError {
    HeaderMismatch(String),
    UnsupportedVersion { requested: String },
}

impl McpIngressValidationError {
    pub(super) fn code(&self) -> i64 {
        match self {
            Self::HeaderMismatch(_) => -32020,
            Self::UnsupportedVersion { .. } => -32022,
        }
    }

    pub(super) fn message(&self) -> String {
        match self {
            Self::HeaderMismatch(message) => format!("Header mismatch: {message}"),
            Self::UnsupportedVersion { .. } => "Unsupported protocol version".to_string(),
        }
    }

    pub(super) fn data(&self) -> Option<Value> {
        match self {
            Self::HeaderMismatch(_) => None,
            Self::UnsupportedVersion { requested } => Some(json!({
                "requested": requested,
                "supported": ferrogate_mcp::SUPPORTED_MCP_PROTOCOL_VERSIONS,
            })),
        }
    }
}

impl std::fmt::Display for McpIngressValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderMismatch(_) => formatter.write_str(&self.message()),
            Self::UnsupportedVersion { requested } => {
                write!(
                    formatter,
                    "Unsupported protocol version requested: {requested}"
                )
            }
        }
    }
}

/// Select the protocol era from this request alone. The modern contract is
/// stateless, so no previous initialize/discover request participates.
pub(super) fn ingress_mode(headers: &HeaderMap, rpc: &McpJsonRpcRequest) -> McpIngressMode {
    if rpc.method == "initialize" {
        return McpIngressMode::Legacy;
    }
    if rpc.method == "server/discover" || body_uses_modern_metadata(rpc) {
        return McpIngressMode::Modern;
    }
    let Some(protocol_header) = headers.get(ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER) else {
        return McpIngressMode::Legacy;
    };
    match protocol_header.to_str() {
        Ok(version)
            if version == ferrogate_mcp::MCP_LEGACY_PROTOCOL_VERSION
                || version == ferrogate_mcp::MCP_PROTOCOL_VERSION_FALLBACK =>
        {
            McpIngressMode::Legacy
        }
        _ => McpIngressMode::Modern,
    }
}

pub(super) fn validate_ingress(
    headers: &HeaderMap,
    rpc: &McpJsonRpcRequest,
) -> Result<ValidatedMcpIngress, McpIngressValidationError> {
    let mode = ingress_mode(headers, rpc);
    let header_method = optional_header(headers, ferrogate_mcp::MCP_METHOD_HEADER)?;
    let header_name = optional_header(headers, ferrogate_mcp::MCP_NAME_HEADER)?
        .map(decode_mcp_name)
        .transpose()?;
    let body_name = body_name(rpc);

    if mode == McpIngressMode::Modern {
        let header_protocol = required_header(
            headers,
            ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
            "MCP-Protocol-Version",
        )?;
        let metadata = rpc
            .params
            .get("_meta")
            .and_then(Value::as_object)
            .ok_or_else(|| mismatch("required params._meta object is missing or malformed"))?;
        let body_protocol = metadata
            .get(PROTOCOL_VERSION_META)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                mismatch(format!(
                    "required params._meta[{PROTOCOL_VERSION_META:?}] string is missing or malformed"
                ))
            })?;
        if header_protocol != body_protocol {
            return Err(mismatch(format!(
                "MCP-Protocol-Version header value {header_protocol:?} does not match body value {body_protocol:?}"
            )));
        }
        if body_protocol != ferrogate_mcp::MCP_PROTOCOL_VERSION {
            return Err(McpIngressValidationError::UnsupportedVersion {
                requested: body_protocol.to_string(),
            });
        }
        if !metadata
            .get(CLIENT_CAPABILITIES_META)
            .is_some_and(Value::is_object)
        {
            return Err(mismatch(format!(
                "required params._meta[{CLIENT_CAPABILITIES_META:?}] object is missing or malformed"
            )));
        }
        if metadata
            .get(CLIENT_INFO_META)
            .is_some_and(|client_info| !client_info.is_object())
        {
            return Err(mismatch(format!(
                "optional params._meta[{CLIENT_INFO_META:?}] must be an object when present"
            )));
        }
        let header_method = header_method
            .ok_or_else(|| mismatch("required Mcp-Method header is missing or malformed"))?;
        if method_requires_name(&rpc.method) && header_name.is_none() {
            return Err(mismatch(format!(
                "required Mcp-Name header for {} is missing or malformed",
                rpc.method
            )));
        }
        ferrogate_mcp::verify_routing_headers(
            Some(header_method),
            header_name.as_deref(),
            &rpc.method,
            body_name,
        )
        .map_err(|error| mismatch(error.to_string()))?;
    } else {
        // Preserve the pre-#570 compatibility contract: routing headers are
        // optional for legacy requests, but an intermediary/body split-brain
        // is still rejected when either header is present.
        ferrogate_mcp::verify_routing_headers(
            header_method,
            header_name.as_deref(),
            &rpc.method,
            body_name,
        )
        .map_err(|error| mismatch(error.to_string()))?;
    }

    Ok(ValidatedMcpIngress {
        mode,
        metric_method: header_method.unwrap_or(&rpc.method).to_string(),
        metric_name: header_name
            .or_else(|| body_name.map(str::to_string))
            .unwrap_or_default(),
    })
}

pub(super) fn is_supported_modern_method(method: &str) -> bool {
    matches!(
        method,
        "server/discover"
            | "ping"
            | "resources/list"
            | "resources/read"
            | "tools/list"
            | "tools/call"
    )
}

fn body_uses_modern_metadata(rpc: &McpJsonRpcRequest) -> bool {
    rpc.params
        .get("_meta")
        .and_then(Value::as_object)
        .is_some_and(|metadata| {
            metadata.contains_key(PROTOCOL_VERSION_META)
                || metadata.contains_key(CLIENT_CAPABILITIES_META)
                || metadata.contains_key(CLIENT_INFO_META)
        })
}

fn body_name(rpc: &McpJsonRpcRequest) -> Option<&str> {
    match rpc.method.as_str() {
        "tools/call" | "prompts/get" => rpc.params.get("name").and_then(Value::as_str),
        "resources/read" => rpc.params.get("uri").and_then(Value::as_str),
        _ => None,
    }
}

fn method_requires_name(method: &str) -> bool {
    matches!(method, "tools/call" | "resources/read" | "prompts/get")
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    display_name: &'static str,
) -> Result<&'a str, McpIngressValidationError> {
    optional_header(headers, name)?.ok_or_else(|| {
        mismatch(format!(
            "required {display_name} header is missing or malformed"
        ))
    })
}

fn optional_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, McpIngressValidationError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(mismatch(format!(
            "{name} header occurs more than once and is ambiguous"
        )));
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| mismatch(format!("{name} header is not valid visible ASCII")))
}

fn decode_mcp_name(value: &str) -> Result<String, McpIngressValidationError> {
    let Some(encoded) = value
        .strip_prefix(BASE64_SENTINEL_PREFIX)
        .and_then(|value| value.strip_suffix(BASE64_SENTINEL_SUFFIX))
    else {
        return Ok(value.to_string());
    };
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| mismatch("Mcp-Name header has malformed Base64 sentinel encoding"))?;
    String::from_utf8(bytes)
        .map_err(|_| mismatch("Mcp-Name header Base64 payload is not valid UTF-8"))
}

fn mismatch(message: impl Into<String>) -> McpIngressValidationError {
    McpIngressValidationError::HeaderMismatch(message.into())
}

#[cfg(test)]
#[path = "mcp_ingress_test.rs"]
mod tests;
