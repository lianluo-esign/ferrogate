// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Issue #543 -- the storage-FAILURE branch of `rbac_catalog_scope`,
// the third property of #518 and the only one nothing held. The five #518
// tests in ferrogate-cli/tests/rbac_catalog_scope_admin_api.rs all stay green
// while the resolver degrades a failed control-plane read to
// `RbacCatalogScope::Full`, which hands every tenant-scoped `admin.read` key
// the entire platform RBAC catalog -- the exact disclosure #518 closed,
// reached through the error path instead of the happy path.

use super::*;
use crate::tenant_scope_reads::fault::{
    block_on, platform_operator_auth, tenant_auth, FaultyTenantScopeReads, TenantScopeRead,
};

/// A store that would resolve to a genuinely NARROW tenant scope if every read
/// succeeded: tenant-a holds `role-a` only, and the catalog also carries
/// `role-b` (bound to nobody here) with a permission tenant-a must never see.
///
/// Every failure test below starts from this store and arms one read, so a
/// resolver that degrades to `Full` is distinguishable from one that resolves
/// correctly -- the two answers differ on `role-b`/`billing.admin`.
fn catalog() -> FaultyTenantScopeReads {
    FaultyTenantScopeReads::healthy()
        .with_role("role-a", &["chat.read"])
        .with_role("role-b", &["billing.admin"])
        .with_binding("tenant-a", "role-a")
        .with_binding("tenant-b", "role-b")
}

/// Baseline, and the guard that makes every failure case below non-vacuous:
/// with healthy storage this resolver returns a NARROW tenant scope, so a
/// later `assert!(is_err())` is testing the failure branch rather than a store
/// that cannot answer anything.
///
/// Pins: the `role_ids.contains(&role.id)` filter and the
/// `CallerScope::Tenant` branch of `rbac_catalog_scope`.
/// Catches: dropping the role filter (tenant-a would gain `billing.admin`),
/// and returning `Full` for a tenant-scoped caller (`is_full()` would flip).
#[test]
fn healthy_storage_resolves_a_narrow_tenant_scope() {
    let store = catalog();
    let scope = block_on(rbac_catalog_scope(&store, &tenant_auth("tenant-a")))
        .expect("healthy storage must resolve a scope");

    assert!(
        !scope.is_full(),
        "a tenant-scoped caller must never resolve to the unfiltered catalog"
    );
    match &scope {
        RbacCatalogScope::Tenant {
            role_ids,
            permission_keys,
        } => {
            assert!(
                role_ids.contains("role-a"),
                "own bound role must be visible"
            );
            assert!(
                !role_ids.contains("role-b"),
                "another tenant's role must not be visible: {role_ids:?}"
            );
            assert!(permission_keys.contains("chat.read"));
            assert!(
                !permission_keys.contains("billing.admin"),
                "permission keys must be limited to the caller's own roles: \
                 {permission_keys:?}"
            );
        }
        RbacCatalogScope::Full => unreachable!("checked by is_full above"),
    }
    assert_eq!(
        store.reads(),
        vec![
            TenantScopeRead::ListTenantRoleBindings,
            TenantScopeRead::ListRoles
        ],
        "the resolver must read the bindings and the role catalog, in that order"
    );
}

/// THE #543 property, read one: a failed `list_tenant_role_bindings` must
/// propagate.
///
/// Pins: `state.list_tenant_role_bindings(tenant_id).await?` in
/// `rbac_catalog_scope`.
/// Catches: the mutation the test gate demonstrated on #518 --
/// `let Ok(bindings) = state.list_tenant_role_bindings(tenant_id).await else {
/// return Ok(RbacCatalogScope::Full) };` -- and equally
/// `.unwrap_or_default()`, which degrades to an empty (silently
/// everything-denied) scope. Both turn the `Err` this asserts into an `Ok`.
#[test]
fn failed_binding_read_propagates_and_never_degrades_to_a_scope() {
    let store = catalog().failing(TenantScopeRead::ListTenantRoleBindings);

    let resolved = block_on(rbac_catalog_scope(&store, &tenant_auth("tenant-a")));

    match resolved {
        Err(_) => {}
        Ok(RbacCatalogScope::Full) => panic!(
            "a failed control-plane read degraded to the UNFILTERED catalog: every \
             tenant-scoped admin.read key would receive the whole platform RBAC \
             catalog through the error path (#518 reopened via #543)"
        ),
        Ok(RbacCatalogScope::Tenant { role_ids, .. }) => panic!(
            "a failed control-plane read degraded to a fabricated tenant scope \
             ({role_ids:?}); an unavailable control plane is not an answer about \
             what this tenant may see"
        ),
    }
    assert!(
        store
            .reads()
            .contains(&TenantScopeRead::ListTenantRoleBindings),
        "the failure must come from the binding read actually being attempted"
    );
}

/// THE #543 property, read two: the SECOND storage read has the same
/// obligation as the first. It is a separate `?` on a separate line, so it is
/// a separate assertion.
///
/// Pins: `state.list_roles().await?` in `rbac_catalog_scope`.
/// Catches: `.unwrap_or_default()` on the role list, which resolves the caller
/// to a scope holding its role ids but NO permission keys -- and, worse, any
/// `else { return Ok(RbacCatalogScope::Full) }` on this read.
#[test]
fn failed_role_catalog_read_propagates_and_never_degrades_to_a_scope() {
    let store = catalog().failing(TenantScopeRead::ListRoles);

    let resolved = block_on(rbac_catalog_scope(&store, &tenant_auth("tenant-a")));

    match resolved {
        Err(_) => {}
        Ok(RbacCatalogScope::Full) => {
            panic!("a failed role-catalog read degraded to the UNFILTERED catalog")
        }
        Ok(RbacCatalogScope::Tenant {
            permission_keys, ..
        }) => panic!(
            "a failed role-catalog read degraded to a scope with permission keys \
             {permission_keys:?} rather than refusing to answer"
        ),
    }
    assert!(
        store.reads().contains(&TenantScopeRead::ListRoles),
        "the failure must come from the role-catalog read actually being attempted"
    );
}

/// The other half of "propagate": propagation is only safe if the CALLER turns
/// the refusal into a refusal. All four `/admin/v1/permissions*` /
/// `/admin/v1/roles*` GETs map a failed `rbac_catalog_scope` through this one
/// function.
///
/// Pins: `rbac_scope_storage_error`, and through it the four `Err(error) =>`
/// arms that now call it.
/// Catches: any remapping of the failure onto a success-shaped or permissive
/// response (a 200 with an empty list, or a 403), and any drift of the error
/// code the admin console keys off.
#[test]
fn a_failed_scope_becomes_503_storage_unavailable() {
    let store = catalog().failing(TenantScopeRead::ListTenantRoleBindings);
    let error = block_on(rbac_catalog_scope(&store, &tenant_auth("tenant-a")))
        .err()
        .expect("a failed control-plane read must not resolve to a scope");

    let (status, code, message) = rbac_scope_storage_error(&error);

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code, "storage_unavailable");
    assert!(
        !message.is_empty(),
        "the refusal must carry the underlying storage error"
    );
}

/// The platform-operator short-circuit is NOT collateral damage of the
/// fail-closed rule: a declared platform operator resolves to `Full` without
/// reading storage at all, so a control-plane blip cannot 503 the operator
/// surface that is used to diagnose it.
///
/// Pins: `let CallerScope::Tenant(tenant_id) = auth.caller_scope() else {
/// return Ok(RbacCatalogScope::Full) };`.
/// Catches: routing platform operators through the tenant path (the reads are
/// armed to fail, so the resolver would return `Err` instead of `Full`), and
/// any added storage read before the classification (the `reads()` assertion).
#[test]
fn platform_operator_resolves_full_without_touching_storage() {
    let store = catalog()
        .failing(TenantScopeRead::ListTenantRoleBindings)
        .failing(TenantScopeRead::ListRoles);

    let scope = block_on(rbac_catalog_scope(&store, &platform_operator_auth()))
        .expect("a declared platform operator must not depend on a storage read");

    assert!(scope.is_full());
    assert!(
        store.reads().is_empty(),
        "the platform-operator answer must be decided from the credential alone, \
         not from storage: {:?}",
        store.reads()
    );
}
