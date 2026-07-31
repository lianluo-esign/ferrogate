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
use crate::registry_helpers::{
    build_crud, build_crud_with_item_segments, first_segment, ResourceInput,
};
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
                VerbDescriptor::read("list", "List tenant accounts", "listTenantAccounts"),
                VerbDescriptor::read("get", "Show a tenant account", "getTenantAccount"),
                VerbDescriptor::mutating(
                    "create",
                    "Create a tenant account",
                    "createTenantAccount",
                ),
                VerbDescriptor::mutating(
                    "replace",
                    "Replace a tenant account",
                    "replaceTenantAccount",
                )
                .replacing_whole_document(),
                VerbDescriptor::mutating(
                    "update",
                    "Update a tenant account",
                    "updateTenantAccount",
                ),
                VerbDescriptor::read(
                    "resolved-defaults",
                    "Show a tenant's resolved defaults",
                    "getTenantResolvedDefaults",
                ),
                VerbDescriptor::mutating(
                    "assign-plan",
                    "Assign a subscription plan to a tenant",
                    "assignTenantPlan",
                )
                .replacing_whole_document(),
            ],
        )
    }
}

/// Build the request for a tenant-accounts verb. `resolved-defaults` reads the
/// nested defaults view; `assign-plan` is a first-class subscription action that
/// `PUT`s the operator's plan-assignment document onto `.../{tenant_id}/plan`
/// (its own verb rather than a generic `update` so the audit trail records the
/// precise operator intent); everything else is CRUD keyed by `tenant_id`.
pub fn build_tenant_accounts(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "resolved-defaults" => TENANT_ACCOUNTS.get(&[
            first_segment(input, "tenant-accounts")?,
            "resolved-defaults",
        ]),
        "assign-plan" => TENANT_ACCOUNTS.replace(
            &[first_segment(input, "tenant-accounts")?, "plan"],
            input.require_body(verb)?,
        ),
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
            vec![VerbDescriptor::read(
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
                VerbDescriptor::read("list", "List plans", "listPlans"),
                VerbDescriptor::read("get", "Show a plan", "getPlan"),
                VerbDescriptor::mutating("create", "Create a plan", "createPlan"),
                VerbDescriptor::mutating("replace", "Replace a plan", "replacePlan")
                    .replacing_whole_document(),
                VerbDescriptor::mutating("update", "Update a plan", "updatePlan"),
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
                VerbDescriptor::read("list", "List quota policies", "listQuotaPolicies"),
                VerbDescriptor::read("get", "Show a quota policy", "getQuotaPolicy"),
                VerbDescriptor::mutating("create", "Create a quota policy", "createQuotaPolicy"),
                VerbDescriptor::mutating("replace", "Replace a quota policy", "replaceQuotaPolicy")
                    .replacing_whole_document(),
                VerbDescriptor::mutating("update", "Update a quota policy", "updateQuotaPolicy"),
                VerbDescriptor::mutating("delete", "Delete a quota policy", "deleteQuotaPolicy")
                    .without_request_body(),
            ],
        )
    }
}

/// Build the request for a quota-policies verb. `get`/`replace`/`update`/
/// `delete` address the two-segment `scope_type/scope_id` key carried in
/// `input.segments`.
pub fn build_quota_policies(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud_with_item_segments(&QUOTA_POLICIES, verb, input, 2)
}

/// Standard list/get/create/replace/update/delete verb metadata for a resource
/// whose operation ids follow the `<Verb><Noun>` convention.
fn crud_verbs(noun_lower: &str, noun_pascal: &str, list_op: &str) -> Vec<VerbDescriptor> {
    vec![
        VerbDescriptor::read("list", format!("List {noun_lower}s"), list_op),
        VerbDescriptor::read(
            "get",
            format!("Show a {noun_lower}"),
            format!("get{noun_pascal}"),
        ),
        VerbDescriptor::mutating(
            "create",
            format!("Create a {noun_lower}"),
            format!("create{noun_pascal}"),
        ),
        VerbDescriptor::mutating(
            "replace",
            format!("Replace a {noun_lower}"),
            format!("replace{noun_pascal}"),
        )
        .replacing_whole_document(),
        VerbDescriptor::mutating(
            "update",
            format!("Update a {noun_lower}"),
            format!("update{noun_pascal}"),
        ),
        VerbDescriptor::mutating(
            "delete",
            format!("Delete a {noun_lower}"),
            format!("delete{noun_pascal}"),
        )
        .without_request_body(),
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
