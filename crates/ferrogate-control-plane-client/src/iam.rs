// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! IAM resource command families (issue #361).
//!
//! Covers virtual keys and their lifecycle actions, gateway admin API keys,
//! roles, permissions, access policies, and tenant-role bindings. As with the
//! organization families, each resource noun is a [`CommandGroup`] declaring its
//! verbs and OpenAPI `operationId`s as compile-time metadata, plus a `build`
//! function mapping a resolved verb onto a [`RequestSpec`].
//!
//! Two IAM concerns beyond plain CRUD are modelled here:
//!
//! * **Lifecycle actions are first-class, not generic CRUD.** `rotate`,
//!   `enable`, `disable`, and both revoke forms of a virtual key map to their
//!   own operations, so an operator's intent (and the audit trail) is precise.
//! * **Secret material is redactable.** A virtual key's `create`/`rotate`
//!   returns one-time `key`/`secret` fields; [`VIRTUAL_KEY_SECRET_FIELDS`] and
//!   [`API_KEY_SECRET_FIELDS`] name those fields so the command layer can blank
//!   them from any later `list`/`get` read via
//!   [`crate::resource::redact_secret_fields`].

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{
    build_crud, build_item_action, build_item_delete, first_segment, require_target_segments,
    ResourceInput,
};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/virtual-keys` — tenant-facing virtual API keys.
pub const VIRTUAL_KEYS: ResourceApi = ResourceApi::new("/admin/v1/virtual-keys");
/// `/admin/v1/api-keys` — gateway admin API keys.
pub const API_KEYS: ResourceApi = ResourceApi::new("/admin/v1/api-keys");
/// `/admin/v1/roles` — RBAC roles.
pub const ROLES: ResourceApi = ResourceApi::new("/admin/v1/roles");
/// `/admin/v1/permissions` — RBAC permissions.
pub const PERMISSIONS: ResourceApi = ResourceApi::new("/admin/v1/permissions");
/// `/admin/v1/policies` — named access policies.
pub const ACCESS_POLICIES: ResourceApi = ResourceApi::new("/admin/v1/policies");
/// `/admin/v1/tenant-roles` — tenant ↔ role bindings.
pub const TENANT_ROLES: ResourceApi = ResourceApi::new("/admin/v1/tenant-roles");

/// One-time secret fields returned by virtual-key create/rotate; these must be
/// redacted from any list/get rendering.
pub const VIRTUAL_KEY_SECRET_FIELDS: &[&str] = &["key", "secret"];
/// One-time secret field returned by admin-api-key create/rotate.
pub const API_KEY_SECRET_FIELDS: &[&str] = &["key", "secret"];

/// Virtual keys, including rotate/revoke/enable/disable lifecycle actions.
pub struct VirtualKeysGroup;

impl CommandGroup for VirtualKeysGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "virtual-keys",
            "Manage virtual API keys and their lifecycle",
            vec![
                VerbDescriptor::read("list", "List virtual keys", "listVirtualKeys"),
                VerbDescriptor::read("get", "Show a virtual key", "getVirtualKey"),
                VerbDescriptor::mutating("create", "Create a virtual key", "createVirtualKey"),
                VerbDescriptor::mutating(
                    "revoke",
                    "Revoke (delete) a virtual key",
                    "revokeVirtualKey",
                )
                .without_request_body(),
                VerbDescriptor::mutating(
                    "rotate",
                    "Rotate a virtual key's secret",
                    "rotateVirtualKey",
                ),
                VerbDescriptor::mutating("enable", "Enable a virtual key", "enableVirtualKey"),
                VerbDescriptor::mutating("disable", "Disable a virtual key", "disableVirtualKey"),
                VerbDescriptor::mutating(
                    "revoke-action",
                    "Revoke a virtual key via the revoke action",
                    "revokeVirtualKeyAction",
                ),
            ],
        )
    }
}

/// Build the request for a virtual-keys verb. Lifecycle actions map to their
/// own operations; everything else falls through to CRUD.
pub fn build_virtual_keys(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "revoke" => build_item_delete(&VIRTUAL_KEYS, "virtual-key", input),
        "rotate" => build_item_action(&VIRTUAL_KEYS, "virtual-key", "rotate", input),
        "enable" => build_item_action(&VIRTUAL_KEYS, "virtual-key", "enable", input),
        "disable" => build_item_action(&VIRTUAL_KEYS, "virtual-key", "disable", input),
        "revoke-action" => build_item_action(&VIRTUAL_KEYS, "virtual-key", "revoke", input),
        other => build_crud(&VIRTUAL_KEYS, other, input),
    }
}

/// Gateway admin API keys (full CRUD; secret returned once at create).
pub struct ApiKeysGroup;

impl CommandGroup for ApiKeysGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "api-keys",
            "Manage gateway admin API keys",
            vec![
                VerbDescriptor::read("list", "List admin API keys", "listAdminApiKeys"),
                VerbDescriptor::read("get", "Show an admin API key", "getAdminApiKey"),
                VerbDescriptor::mutating("create", "Create an admin API key", "createAdminApiKey"),
                VerbDescriptor::mutating("replace", "Replace an admin API key", "putAdminApiKey")
                    .replacing_whole_document(),
                VerbDescriptor::mutating("update", "Update an admin API key", "patchAdminApiKey"),
                VerbDescriptor::mutating("delete", "Delete an admin API key", "deleteAdminApiKey")
                    .without_request_body(),
            ],
        )
    }
}

/// Build the request for an api-keys verb.
pub fn build_api_keys(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&API_KEYS, verb, input)
}

/// RBAC roles (list/get/create/delete).
pub struct RolesGroup;

impl CommandGroup for RolesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "roles",
            "Manage RBAC roles",
            vec![
                VerbDescriptor::read("list", "List roles", "listRoles"),
                VerbDescriptor::read("get", "Show a role", "getRole"),
                VerbDescriptor::mutating("create", "Create a role", "createRole"),
                VerbDescriptor::mutating("delete", "Delete a role", "deleteRole")
                    .without_request_body(),
            ],
        )
    }
}

/// Build the request for a roles verb.
pub fn build_roles(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&ROLES, verb, input)
}

/// RBAC permissions (list/get/create/delete).
pub struct PermissionsGroup;

impl CommandGroup for PermissionsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "permissions",
            "Manage RBAC permissions",
            vec![
                VerbDescriptor::read("list", "List permissions", "listPermissions"),
                VerbDescriptor::read("get", "Show a permission", "getPermission"),
                VerbDescriptor::mutating("create", "Create a permission", "createPermission"),
                VerbDescriptor::mutating("delete", "Delete a permission", "deletePermission")
                    .without_request_body(),
            ],
        )
    }
}

/// Build the request for a permissions verb.
pub fn build_permissions(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&PERMISSIONS, verb, input)
}

/// Named access policies (full CRUD; addressed by name).
pub struct AccessPoliciesGroup;

impl CommandGroup for AccessPoliciesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "access-policies",
            "Manage named access policies",
            vec![
                VerbDescriptor::read("list", "List access policies", "listAdminPolicies"),
                VerbDescriptor::read("get", "Show an access policy", "getAdminPolicy"),
                VerbDescriptor::mutating("create", "Create an access policy", "createAdminPolicy"),
                VerbDescriptor::mutating("replace", "Replace an access policy", "putAdminPolicy")
                    .replacing_whole_document(),
                VerbDescriptor::mutating("update", "Update an access policy", "patchAdminPolicy"),
                VerbDescriptor::mutating("delete", "Delete an access policy", "deleteAdminPolicy")
                    .without_request_body(),
            ],
        )
    }
}

/// Build the request for an access-policies verb.
pub fn build_access_policies(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&ACCESS_POLICIES, verb, input)
}

/// Tenant ↔ role bindings.
pub struct TenantRolesGroup;

impl CommandGroup for TenantRolesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tenant-roles",
            "Manage tenant role bindings",
            vec![
                VerbDescriptor::read("list", "List a tenant's role bindings", "listTenantRoles"),
                VerbDescriptor::mutating("bind", "Bind a role to a tenant", "bindTenantRole"),
                VerbDescriptor::mutating(
                    "unbind",
                    "Unbind a role from a tenant",
                    "unbindTenantRole",
                )
                .without_request_body(),
            ],
        )
    }
}

/// Build the request for a tenant-roles verb.
///
/// `list`/`bind` address a single tenant (`segments = [tenant_id]`); `unbind`
/// addresses the tenant/role pair (`segments = [tenant_id, role_id]`).
pub fn build_tenant_roles(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    let segments = input.segment_refs();
    match verb {
        "list" => {
            // A tenant id is required — refuse to list every tenant's bindings
            // by accident.
            first_segment(input, "tenant-role")?;
            TENANT_ROLES.read(&segments, &input.list)
        }
        "bind" => TENANT_ROLES.action(
            require_target_segments(&TENANT_ROLES, verb, &segments, 1)?,
            Some(input.require_body(verb)?),
        ),
        "unbind" => {
            TENANT_ROLES.delete(require_target_segments(&TENANT_ROLES, verb, &segments, 2)?)
        }
        other => build_crud(&TENANT_ROLES, other, input),
    }
}

/// Register every IAM command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&VirtualKeysGroup)?;
    registry.register(&ApiKeysGroup)?;
    registry.register(&RolesGroup)?;
    registry.register(&PermissionsGroup)?;
    registry.register(&AccessPoliciesGroup)?;
    registry.register(&TenantRolesGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "iam_test.rs"]
mod iam_test;
