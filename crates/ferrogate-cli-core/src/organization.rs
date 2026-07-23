// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Organization resource command families (issue #361).
//!
//! Covers the declarative tenancy surface of the Control Plane API: tenant
//! accounts and their resolved defaults, the lightweight admin tenant listing,
//! projects, workspaces, plans, and quota policies. Each resource noun is one
//! [`CommandGroup`] with uniform verbs whose OpenAPI `operationId`s are declared
//! as compile-time metadata (so the #365 parity gate tracks coverage), and a
//! `build` function that maps a resolved verb plus typed [`ResourceInput`] onto
//! a [`RequestSpec`] via the shared [`ResourceApi`] REST builders. No request
//! body schema is hard-coded: mutations carry a complete operator-supplied JSON
//! document, matching the transport's contract-friendly (not contract-hardwired)
//! design.

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{build_crud, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/tenant-accounts` — tenant accounts.
pub const TENANT_ACCOUNTS: ResourceApi = ResourceApi::new("/admin/v1/tenant-accounts");
/// `/admin/v1/tenants` — lightweight admin tenant listing.
pub const TENANTS: ResourceApi = ResourceApi::new("/admin/v1/tenants");
/// `/admin/v1/projects` — projects.
pub const PROJECTS: ResourceApi = ResourceApi::new("/admin/v1/projects");
/// `/admin/v1/workspaces` — workspaces.
pub const WORKSPACES: ResourceApi = ResourceApi::new("/admin/v1/workspaces");
/// `/admin/v1/plans` — plans.
pub const PLANS: ResourceApi = ResourceApi::new("/admin/v1/plans");
/// `/admin/v1/quota-policies` — quota policies, keyed by `scope_type/scope_id`.
pub const QUOTA_POLICIES: ResourceApi = ResourceApi::new("/admin/v1/quota-policies");

/// Tenant accounts, plus the resolved-defaults read.
pub struct TenantAccountsGroup;

impl CommandGroup for TenantAccountsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tenant-accounts",
            "Manage tenant accounts",
            vec![
                VerbDescriptor::api("list", "List tenant accounts", "listTenantAccounts"),
                VerbDescriptor::api("get", "Show a tenant account", "getTenantAccount"),
                VerbDescriptor::api("create", "Create a tenant account", "createTenantAccount"),
                VerbDescriptor::api(
                    "replace",
                    "Replace a tenant account",
                    "replaceTenantAccount",
                ),
                VerbDescriptor::api("update", "Update a tenant account", "updateTenantAccount"),
                VerbDescriptor::api(
                    "resolved-defaults",
                    "Show a tenant's resolved defaults",
                    "getTenantResolvedDefaults",
                ),
            ],
        )
    }
}

/// Build the request for a tenant-accounts verb.
pub fn build_tenant_accounts(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "resolved-defaults" => TENANT_ACCOUNTS.get(&[
            first_segment(input, "tenant-accounts")?,
            "resolved-defaults",
        ]),
        other => build_crud(&TENANT_ACCOUNTS, other, input),
    }
}

/// The admin tenant listing (list-only).
pub struct TenantsGroup;

impl CommandGroup for TenantsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tenants",
            "List gateway tenants (admin view)",
            vec![VerbDescriptor::api(
                "list",
                "List tenants",
                "listAdminTenants",
            )],
        )
    }
}

/// Build the request for a tenants verb.
pub fn build_tenants(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&TENANTS, verb, input)
}

/// Projects (full CRUD).
pub struct ProjectsGroup;

impl CommandGroup for ProjectsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "projects",
            "Manage projects",
            crud_verbs("project", "Project", "listProjects"),
        )
    }
}

/// Build the request for a projects verb.
pub fn build_projects(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&PROJECTS, verb, input)
}

/// Workspaces (full CRUD).
pub struct WorkspacesGroup;

impl CommandGroup for WorkspacesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "workspaces",
            "Manage workspaces",
            crud_verbs("workspace", "Workspace", "listWorkspaces"),
        )
    }
}

/// Build the request for a workspaces verb.
pub fn build_workspaces(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&WORKSPACES, verb, input)
}

/// Plans (CRUD without delete — plans are archived, not deleted).
pub struct PlansGroup;

impl CommandGroup for PlansGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "plans",
            "Manage plans",
            vec![
                VerbDescriptor::api("list", "List plans", "listPlans"),
                VerbDescriptor::api("get", "Show a plan", "getPlan"),
                VerbDescriptor::api("create", "Create a plan", "createPlan"),
                VerbDescriptor::api("replace", "Replace a plan", "replacePlan"),
                VerbDescriptor::api("update", "Update a plan", "updatePlan"),
            ],
        )
    }
}

/// Build the request for a plans verb.
pub fn build_plans(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&PLANS, verb, input)
}

/// Quota policies (full CRUD; item is addressed by `scope_type/scope_id`).
pub struct QuotaPoliciesGroup;

impl CommandGroup for QuotaPoliciesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "quota-policies",
            "Manage quota policies",
            vec![
                VerbDescriptor::api("list", "List quota policies", "listQuotaPolicies"),
                VerbDescriptor::api("get", "Show a quota policy", "getQuotaPolicy"),
                VerbDescriptor::api("create", "Create a quota policy", "createQuotaPolicy"),
                VerbDescriptor::api("replace", "Replace a quota policy", "replaceQuotaPolicy"),
                VerbDescriptor::api("update", "Update a quota policy", "updateQuotaPolicy"),
                VerbDescriptor::api("delete", "Delete a quota policy", "deleteQuotaPolicy"),
            ],
        )
    }
}

/// Build the request for a quota-policies verb. `get`/`replace`/`update`/
/// `delete` address the two-segment `scope_type/scope_id` key carried in
/// `input.segments`.
pub fn build_quota_policies(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&QUOTA_POLICIES, verb, input)
}

/// Standard list/get/create/replace/update/delete verb metadata for a resource
/// whose operation ids follow the `<Verb><Noun>` convention.
fn crud_verbs(noun_lower: &str, noun_pascal: &str, list_op: &str) -> Vec<VerbDescriptor> {
    vec![
        VerbDescriptor::api("list", format!("List {noun_lower}s"), list_op),
        VerbDescriptor::api(
            "get",
            format!("Show a {noun_lower}"),
            format!("get{noun_pascal}"),
        ),
        VerbDescriptor::api(
            "create",
            format!("Create a {noun_lower}"),
            format!("create{noun_pascal}"),
        ),
        VerbDescriptor::api(
            "replace",
            format!("Replace a {noun_lower}"),
            format!("replace{noun_pascal}"),
        ),
        VerbDescriptor::api(
            "update",
            format!("Update a {noun_lower}"),
            format!("update{noun_pascal}"),
        ),
        VerbDescriptor::api(
            "delete",
            format!("Delete a {noun_lower}"),
            format!("delete{noun_pascal}"),
        ),
    ]
}

/// Register every organization command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&TenantAccountsGroup)?;
    registry.register(&TenantsGroup)?;
    registry.register(&ProjectsGroup)?;
    registry.register(&WorkspacesGroup)?;
    registry.register(&PlansGroup)?;
    registry.register(&QuotaPoliciesGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "organization_test.rs"]
mod organization_test;
