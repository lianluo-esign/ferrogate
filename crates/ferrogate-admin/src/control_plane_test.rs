// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Contract tests for the promoted public FerroGate Control Plane API surface.
//!
//! These pin the typed promotion registry against the enforced OpenAPI document
//! (`docs/openapi/admin-api.openapi.json`, the source of truth), and prove the
//! backward-compatibility guarantee of issue #359: promoted routes resolve, the
//! existing `/admin/v1` admin routes are unchanged, and the stability contract
//! is internally consistent.

use super::{
    canonicalize_alias_path, is_promoted, promoted_operations, public_surface, HttpMethod,
    PublicOperation, Stability, ADMIN_API_LEGACY_TITLE, ALIAS_PATH_PREFIX, CONTROL_PLANE_API_TITLE,
    DEPRECATED_ALIAS, PROMOTED_OPERATIONS, PROMOTED_RESOURCES, PUBLIC_API_MAJOR,
    STABLE_PATH_PREFIX,
};

use serde_json::Value;

const OPENAPI_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/openapi/admin-api.openapi.json"
));

fn openapi() -> Value {
    serde_json::from_str(OPENAPI_JSON).expect("admin-api.openapi.json must parse")
}

fn operation<'a>(document: &'a Value, path: &str, method: HttpMethod) -> Option<&'a Value> {
    document
        .get("paths")?
        .get(path)?
        .get(method.as_openapi_key())
}

// ---------------------------------------------------------------------------
// 1. Promoted public routes resolve in the enforced contract.
// ---------------------------------------------------------------------------

#[test]
fn promoted_operations_resolve_in_openapi() {
    let document = openapi();
    for op in promoted_operations() {
        let entry = operation(&document, op.path, op.method).unwrap_or_else(|| {
            panic!(
                "promoted operation {} {} is missing from the OpenAPI document",
                op.method.as_str(),
                op.path
            )
        });
        let operation_id = entry
            .get("operationId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{} {} has no operationId", op.method.as_str(), op.path));
        assert_eq!(
            operation_id,
            op.operation_id,
            "operationId drift for {} {}",
            op.method.as_str(),
            op.path
        );
        let stability = entry
            .get("x-ferrogate-stability")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "promoted operation {} is missing x-ferrogate-stability",
                    op.operation_id
                )
            });
        assert_eq!(
            stability,
            Stability::Stable.as_str(),
            "{} must be marked stable in the OpenAPI document",
            op.operation_id
        );
    }
}

#[test]
fn openapi_stable_markers_match_registry_exactly() {
    // The registry is the *exact* public-stable set: every operation the
    // OpenAPI document marks `x-ferrogate-stability: "stable"` must be in the
    // registry, and vice versa. This is the bidirectional drift guard.
    let document = openapi();
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths object");

    let mut marked_stable: Vec<(String, String, String)> = Vec::new();
    for (path, item) in paths {
        let Some(methods) = item.as_object() else {
            continue;
        };
        for (method, op) in methods {
            let Some(op) = op.as_object() else { continue };
            if op.get("x-ferrogate-stability").and_then(Value::as_str) == Some("stable") {
                let operation_id = op
                    .get("operationId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                marked_stable.push((path.clone(), method.to_ascii_uppercase(), operation_id));
            }
        }
    }
    marked_stable.sort();

    let mut registry: Vec<(String, String, String)> = PROMOTED_OPERATIONS
        .iter()
        .map(|op| {
            (
                op.path.to_string(),
                op.method.as_str().to_string(),
                op.operation_id.to_string(),
            )
        })
        .collect();
    registry.sort();

    assert_eq!(
        marked_stable, registry,
        "OpenAPI x-ferrogate-stability=stable markers must match PROMOTED_OPERATIONS exactly"
    );
}

// ---------------------------------------------------------------------------
// 2. Existing admin routes still resolve, unchanged (no break).
// ---------------------------------------------------------------------------

#[test]
fn existing_admin_routes_still_resolve_unchanged() {
    let document = openapi();

    // A representative slice of the pre-existing admin surface that the console
    // and CLI already depend on: it must still be present with its visibility
    // and auth scope untouched by this promotion.
    let anchors: &[(&str, HttpMethod, &str, &str, &str)] = &[
        (
            "/admin/v1/status",
            HttpMethod::Get,
            "getAdminStatus",
            "admin",
            "admin.read",
        ),
        (
            "/admin/v1/api-keys",
            HttpMethod::Get,
            "listAdminApiKeys",
            "admin",
            "admin.read",
        ),
        (
            "/admin/v1/providers",
            HttpMethod::Get,
            "listAdminProviders",
            "admin",
            "admin.read",
        ),
    ];
    for (path, method, operation_id, visibility, scope) in anchors {
        let entry = operation(&document, path, *method)
            .unwrap_or_else(|| panic!("existing admin route {path} disappeared"));
        assert_eq!(
            entry.get("operationId").and_then(Value::as_str),
            Some(*operation_id),
            "operationId for {path} must be stable",
        );
        let contract = entry
            .get("x-ferrogate-contract")
            .unwrap_or_else(|| panic!("{path} lost its x-ferrogate-contract"));
        assert_eq!(
            contract.get("visibility").and_then(Value::as_str),
            Some(*visibility),
            "{path} visibility must be unchanged",
        );
        assert_eq!(
            contract
                .get("auth")
                .and_then(|auth| auth.get("scope"))
                .and_then(Value::as_str),
            Some(*scope),
            "{path} auth scope must be unchanged",
        );
    }

    // A public data-plane route must also still resolve unchanged.
    let healthz = operation(&document, "/healthz", HttpMethod::Get).expect("/healthz present");
    assert_eq!(
        healthz.get("operationId").and_then(Value::as_str),
        Some("getHealthz"),
    );
}

#[test]
fn promotion_is_additive_runtime_auth_unchanged() {
    // Promotion is a *stability* guarantee expressed over existing routes. It
    // must NOT relax runtime enforcement: promoted operations keep their
    // `admin` visibility and their admin.read/admin.write scope, so existing
    // admin clients behave identically.
    let document = openapi();
    for op in promoted_operations() {
        let entry = operation(&document, op.path, op.method)
            .unwrap_or_else(|| panic!("{} missing", op.operation_id));
        let contract = entry
            .get("x-ferrogate-contract")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{} missing x-ferrogate-contract", op.operation_id));
        assert_eq!(
            contract.get("visibility").and_then(Value::as_str),
            Some("admin"),
            "{} must keep admin visibility (auth is not relaxed by promotion)",
            op.operation_id
        );
        let scope = contract
            .get("auth")
            .and_then(|auth| auth.get("scope"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{} must retain an auth scope", op.operation_id));
        assert!(
            scope == "admin.read" || scope == "admin.write",
            "{} scope {scope} must remain an admin scope",
            op.operation_id
        );
    }
}

// ---------------------------------------------------------------------------
// 3. The version / stability contract is internally consistent.
// ---------------------------------------------------------------------------

#[test]
fn openapi_artifact_carries_control_plane_identity() {
    let document = openapi();
    let title = document
        .get("info")
        .and_then(|info| info.get("title"))
        .and_then(Value::as_str);
    assert_eq!(
        title,
        Some(CONTROL_PLANE_API_TITLE),
        "the published OpenAPI artifact must be titled as the Control Plane API"
    );
    assert_ne!(
        CONTROL_PLANE_API_TITLE, ADMIN_API_LEGACY_TITLE,
        "canonical and legacy alias names must differ"
    );
    // The published surface still advertises the compatibility alias so tooling
    // keyed on the old name can discover the rename.
    let control_plane = document
        .get("x-ferrogate-control-plane")
        .and_then(Value::as_object)
        .expect("top-level x-ferrogate-control-plane block must be published");
    assert_eq!(
        control_plane
            .get("deprecated_alias")
            .and_then(Value::as_str),
        Some(DEPRECATED_ALIAS),
    );
    assert_eq!(
        control_plane.get("public_major").and_then(Value::as_str),
        Some(PUBLIC_API_MAJOR),
    );
}

#[test]
fn stability_contract_is_self_consistent() {
    assert_eq!(PUBLIC_API_MAJOR, "v1");
    assert_eq!(STABLE_PATH_PREFIX, "/admin/v1");
    // The first slice promotes the full guardrail-policies lifecycle (10 ops).
    assert_eq!(PROMOTED_OPERATIONS.len(), 10);
    assert_eq!(PROMOTED_RESOURCES, &["guardrail-policies"]);

    // No duplicate operationIds and no duplicate (path, method) keys.
    let mut ids: Vec<&str> = PROMOTED_OPERATIONS.iter().map(|o| o.operation_id).collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "duplicate operationId in the registry");

    let mut keys: Vec<(&str, &str)> = PROMOTED_OPERATIONS
        .iter()
        .map(|o| (o.path, o.method.as_str()))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(
        keys.len(),
        count,
        "duplicate (path, method) in the registry"
    );

    for op in PROMOTED_OPERATIONS {
        assert_eq!(
            op.stability,
            Stability::Stable,
            "everything in the registry is stable by construction: {}",
            op.operation_id
        );
        assert!(
            op.path.starts_with(STABLE_PATH_PREFIX),
            "{} must live under the stable prefix",
            op.operation_id
        );
        assert!(
            PROMOTED_RESOURCES.contains(&op.resource),
            "{} resource {} must be a declared promoted resource",
            op.operation_id,
            op.resource
        );
        assert!(is_promoted(op.operation_id));
    }
    assert!(!is_promoted("getHealthz"));
    assert!(!is_promoted("listAdminProviders"));
}

#[test]
fn public_surface_snapshot_serializes() {
    let surface = public_surface();
    assert_eq!(surface.title, CONTROL_PLANE_API_TITLE);
    assert_eq!(surface.promoted_operations.len(), PROMOTED_OPERATIONS.len());
    let json = serde_json::to_value(&surface).expect("surface serializes");
    assert_eq!(
        json.get("title").and_then(Value::as_str),
        Some(CONTROL_PLANE_API_TITLE)
    );
    assert_eq!(
        json.pointer("/promoted_operations/0/method")
            .and_then(Value::as_str),
        Some("GET"),
    );
    assert_eq!(
        json.pointer("/promoted_operations/0/stability")
            .and_then(Value::as_str),
        Some("stable"),
    );
}

// ---------------------------------------------------------------------------
// 4. The /control/v1 URI alias folds onto /admin/v1 from one contract (#453).
// ---------------------------------------------------------------------------

#[test]
fn alias_prefix_is_distinct_from_and_parallel_to_the_stable_prefix() {
    assert_eq!(ALIAS_PATH_PREFIX, "/control/v1");
    assert_eq!(STABLE_PATH_PREFIX, "/admin/v1");
    assert_ne!(
        ALIAS_PATH_PREFIX, STABLE_PATH_PREFIX,
        "the alias and the stable prefix must be different URIs"
    );
    // Both carry the same public major, so the alias is a spelling of the same
    // surface rather than a new version.
    assert!(ALIAS_PATH_PREFIX.ends_with(PUBLIC_API_MAJOR));
    assert!(STABLE_PATH_PREFIX.ends_with(PUBLIC_API_MAJOR));

    // The surface snapshot advertises the alias next to the stable prefix.
    let surface = public_surface();
    assert_eq!(surface.stable_path_prefix, STABLE_PATH_PREFIX);
    assert_eq!(surface.alias_path_prefix, ALIAS_PATH_PREFIX);
}

#[test]
fn alias_normalization_maps_control_prefix_onto_admin_prefix() {
    // Every promoted stable operation must resolve identically under the alias:
    // its alias path normalizes to exactly the operation's canonical path.
    for op in promoted_operations() {
        let alias = op
            .path
            .strip_prefix(STABLE_PATH_PREFIX)
            .map(|rest| format!("{ALIAS_PATH_PREFIX}{rest}"))
            .expect("promoted op lives under the stable prefix");
        assert_eq!(
            canonicalize_alias_path(&alias).as_deref(),
            Some(op.path),
            "alias {alias} must normalize onto {}",
            op.path
        );
    }

    // A representative slice across the admin surface, plus the bare prefix.
    let cases = [
        ("/control/v1", "/admin/v1"),
        ("/control/v1/status", "/admin/v1/status"),
        ("/control/v1/providers", "/admin/v1/providers"),
        ("/control/v1/config/reload", "/admin/v1/config/reload"),
        (
            "/control/v1/guardrail-policies/p_1/revisions/2",
            "/admin/v1/guardrail-policies/p_1/revisions/2",
        ),
    ];
    for (alias, canonical) in cases {
        assert_eq!(
            canonicalize_alias_path(alias).as_deref(),
            Some(canonical),
            "{alias} must normalize onto {canonical}"
        );
    }
}

#[test]
fn alias_normalization_ignores_non_alias_and_partial_segments() {
    // Already-canonical admin paths are not the alias: the ingress layer leaves
    // them untouched (the stable prefix stays stable, no double-rewrite).
    assert_eq!(canonicalize_alias_path("/admin/v1/providers"), None);
    assert_eq!(canonicalize_alias_path("/admin/v1"), None);

    // A path that merely shares the textual prefix is a DIFFERENT resource and
    // must never be captured by the alias.
    assert_eq!(canonicalize_alias_path("/control/v1x"), None);
    assert_eq!(canonicalize_alias_path("/control/v1x/y"), None);
    assert_eq!(canonicalize_alias_path("/control"), None);
    assert_eq!(canonicalize_alias_path("/controlled/v1"), None);

    // Unrelated data-plane and root paths are untouched.
    assert_eq!(canonicalize_alias_path("/v1/chat/completions"), None);
    assert_eq!(canonicalize_alias_path("/healthz"), None);
    assert_eq!(canonicalize_alias_path("/"), None);
}

#[test]
fn openapi_publishes_the_control_alias_from_the_same_contract() {
    // The published OpenAPI artifact documents the alias so external consumers
    // and the compatibility gate can discover it (issue #453). The alias lives
    // on the top-level control-plane block, keyed to the same stable prefix.
    let document = openapi();
    let control_plane = document
        .get("x-ferrogate-control-plane")
        .and_then(Value::as_object)
        .expect("top-level x-ferrogate-control-plane block must be published");
    assert_eq!(
        control_plane
            .get("stable_path_prefix")
            .and_then(Value::as_str),
        Some(STABLE_PATH_PREFIX),
    );
    assert_eq!(
        control_plane
            .get("alias_path_prefix")
            .and_then(Value::as_str),
        Some(ALIAS_PATH_PREFIX),
        "OpenAPI must advertise the /control/v1 alias prefix",
    );
    let aliases = control_plane
        .get("uri_aliases")
        .and_then(Value::as_array)
        .expect("uri_aliases must document the alias mapping");
    assert!(
        aliases.iter().any(|entry| {
            entry.get("alias_prefix").and_then(Value::as_str) == Some(ALIAS_PATH_PREFIX)
                && entry.get("canonical_prefix").and_then(Value::as_str) == Some(STABLE_PATH_PREFIX)
        }),
        "uri_aliases must map {ALIAS_PATH_PREFIX} onto {STABLE_PATH_PREFIX}",
    );
}

#[test]
fn method_wire_forms_are_stable() {
    assert_eq!(HttpMethod::Get.as_str(), "GET");
    assert_eq!(HttpMethod::Delete.as_openapi_key(), "delete");
    let sample = PublicOperation {
        operation_id: "x",
        method: HttpMethod::Patch,
        path: "/admin/v1/x",
        resource: "x",
        stability: Stability::Internal,
    };
    assert_eq!(sample.method.as_openapi_key(), "patch");
    assert_eq!(sample.stability.as_str(), "internal");
}
