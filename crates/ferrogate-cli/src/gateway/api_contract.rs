// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Structured fixed-route contract shared by runtime dispatch and OpenAPI validation.

use std::{collections::HashMap, sync::LazyLock};

use http::Method;
use matchit::Router;
use serde::Deserialize;

use super::route_groups::RouteGroup;

const CONTRACT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/openapi/runtime-api-contract.json"
));

#[derive(Debug, Deserialize)]
struct ApiContract {
    version: u32,
    route_patterns: Vec<RoutePattern>,
    operations: Vec<ApiOperation>,
}

#[derive(Debug, Deserialize)]
struct RoutePattern {
    pattern: String,
    group: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ApiOperation {
    pub(super) path: String,
    pub(super) method: String,
    pub(super) operation_id: String,
    pub(super) visibility: String,
    pub(super) auth: ApiOperationAuth,
    pub(super) rbac_action: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ApiOperationAuth {
    pub(super) kind: String,
    pub(super) scope: Option<String>,
    pub(super) scope_discriminator: Option<ApiScopeDiscriminator>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ApiScopeDiscriminator {
    pub(super) field: String,
    pub(super) map: HashMap<String, String>,
}

struct ParsedContract {
    route_groups: Router<RouteGroup>,
    operations: Router<HashMap<String, ApiOperation>>,
}

static CONTRACT: LazyLock<ParsedContract> = LazyLock::new(|| {
    parse_contract(CONTRACT_JSON)
        .unwrap_or_else(|error| panic!("invalid embedded runtime API contract: {error}"))
});

pub(super) fn match_route_group(path: &str) -> Option<RouteGroup> {
    CONTRACT
        .route_groups
        .at(path)
        .ok()
        .map(|matched| *matched.value)
}

pub(super) fn operation(method: &Method, path: &str) -> Option<&'static ApiOperation> {
    CONTRACT
        .operations
        .at(path)
        .ok()
        .and_then(|matched| matched.value.get(method.as_str()))
}

pub(super) fn path_is_documented(path: &str) -> bool {
    CONTRACT.operations.at(path).is_ok()
}

pub(super) fn method_dependent_scope(
    method: &Method,
    path: &str,
    discriminator_value: &str,
) -> Option<&'static str> {
    operation(method, path)?
        .auth
        .scope_discriminator
        .as_ref()?
        .map
        .get(discriminator_value)
        .map(String::as_str)
}

fn parse_contract(document: &str) -> Result<ParsedContract, String> {
    let contract: ApiContract =
        serde_json::from_str(document).map_err(|error| format!("invalid JSON: {error}"))?;
    if contract.version != 1 {
        return Err(format!(
            "unsupported contract version {}; expected 1",
            contract.version
        ));
    }

    let mut route_groups = Router::new();
    for route in contract.route_patterns {
        let group = RouteGroup::from_contract_name(&route.group).ok_or_else(|| {
            format!(
                "route pattern {} references unknown group {}",
                route.pattern, route.group
            )
        })?;
        route_groups
            .insert(route.pattern.as_str(), group)
            .map_err(|error| format!("invalid route pattern {}: {error}", route.pattern))?;
    }

    let mut by_path: HashMap<String, HashMap<String, ApiOperation>> = HashMap::new();
    let mut operation_ids = std::collections::HashSet::new();
    for operation in contract.operations {
        if route_groups.at(&operation.path).is_err() {
            return Err(format!(
                "operation {} path {} does not belong to a fixed route group",
                operation.operation_id, operation.path
            ));
        }
        let method = operation.method.to_ascii_uppercase();
        if Method::from_bytes(method.as_bytes()).is_err() {
            return Err(format!(
                "operation {} has invalid method {}",
                operation.operation_id, operation.method
            ));
        }
        if !matches!(
            operation.visibility.as_str(),
            "public" | "admin" | "internal"
        ) {
            return Err(format!(
                "operation {} has invalid visibility {}",
                operation.operation_id, operation.visibility
            ));
        }
        if !matches!(
            operation.auth.kind.as_str(),
            "anonymous" | "bearer" | "method_dependent" | "internal"
        ) {
            return Err(format!(
                "operation {} has invalid auth kind {}",
                operation.operation_id, operation.auth.kind
            ));
        }
        if operation.auth.kind == "bearer"
            && operation.auth.scope.as_deref().is_none_or(str::is_empty)
        {
            return Err(format!(
                "operation {} uses bearer auth without a scope",
                operation.operation_id
            ));
        }
        if operation.auth.kind == "method_dependent" {
            let Some(discriminator) = operation.auth.scope_discriminator.as_ref() else {
                return Err(format!(
                    "operation {} uses method_dependent auth without a scope discriminator",
                    operation.operation_id
                ));
            };
            if operation.auth.scope.is_some()
                || discriminator.field.is_empty()
                || discriminator.map.is_empty()
                || discriminator
                    .map
                    .iter()
                    .any(|(value, scope)| value.is_empty() || scope.is_empty())
            {
                return Err(format!(
                    "operation {} has an invalid scope discriminator",
                    operation.operation_id
                ));
            }
        }
        if !operation_ids.insert(operation.operation_id.clone()) {
            return Err(format!("duplicate operation_id {}", operation.operation_id));
        }
        let path = operation.path.clone();
        if by_path
            .entry(path.clone())
            .or_default()
            .insert(method.clone(), operation)
            .is_some()
        {
            return Err(format!("duplicate operation {method} {path}"));
        }
    }

    let mut operations = Router::new();
    for (path, methods) in by_path {
        operations
            .insert(path.as_str(), methods)
            .map_err(|error| format!("invalid operation path {path}: {error}"))?;
    }

    Ok(ParsedContract {
        route_groups,
        operations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_contract_builds_and_exposes_operation_metadata() {
        let operation = operation(&Method::GET, "/healthz").expect("health operation");
        assert_eq!(operation.operation_id, "getHealthz");
        assert_eq!(operation.visibility, "public");
        assert_eq!(operation.auth.kind, "anonymous");
        assert!(operation.rbac_action.is_none());
    }

    #[test]
    fn mcp_contract_maps_supported_json_rpc_methods_to_scopes() {
        let operation = operation(&Method::POST, "/v1/mcp").expect("MCP operation");
        let discriminator = operation
            .auth
            .scope_discriminator
            .as_ref()
            .expect("method-dependent scope discriminator");
        assert_eq!(discriminator.field, "method");
        assert_eq!(
            discriminator.map.get("initialize").map(String::as_str),
            Some("tools.read")
        );
        assert_eq!(
            discriminator
                .map
                .get("notifications/initialized")
                .map(String::as_str),
            Some("tools.read")
        );
        assert_eq!(
            discriminator.map.get("ping").map(String::as_str),
            Some("tools.read")
        );
        assert_eq!(
            discriminator.map.get("tools/list").map(String::as_str),
            Some("tools.read")
        );
        assert_eq!(
            discriminator.map.get("tools/call").map(String::as_str),
            Some("tools.execute")
        );
    }

    #[test]
    fn duplicate_operation_identity_is_rejected() {
        let error = parse_contract(
            r#"{
              "version": 1,
              "route_patterns": [{"pattern":"/a","group":"inference"}],
              "operations": [
                {"path":"/a","method":"get","operation_id":"same","visibility":"public","auth":{"kind":"anonymous","scope":null},"rbac_action":null},
                {"path":"/a","method":"post","operation_id":"same","visibility":"public","auth":{"kind":"anonymous","scope":null},"rbac_action":null}
              ]
            }"#,
        )
        .err()
        .expect("duplicate operation id must fail");
        assert!(error.contains("duplicate operation_id same"));
    }

    #[test]
    fn bearer_operation_requires_an_explicit_scope() {
        let error = parse_contract(
            r#"{
              "version": 1,
              "route_patterns": [{"pattern":"/a","group":"inference"}],
              "operations": [
                {"path":"/a","method":"get","operation_id":"getA","visibility":"public","auth":{"kind":"bearer","scope":null},"rbac_action":null}
              ]
            }"#,
        )
        .err()
        .expect("missing bearer scope must fail");
        assert!(error.contains("without a scope"));
    }

    #[test]
    fn method_dependent_operation_requires_a_scope_discriminator() {
        let error = parse_contract(
            r#"{
              "version": 1,
              "route_patterns": [{"pattern":"/a","group":"inference"}],
              "operations": [
                {"path":"/a","method":"post","operation_id":"postA","visibility":"public","auth":{"kind":"method_dependent","scope":null},"rbac_action":null}
              ]
            }"#,
        )
        .err()
        .expect("missing discriminator must fail");
        assert!(error.contains("without a scope discriminator"));
    }
}
