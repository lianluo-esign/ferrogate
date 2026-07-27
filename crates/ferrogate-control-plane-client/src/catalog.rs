// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Catalog command families: prompt templates, skill packages, plugins, the
//! read-only model/provider/extension/adapter catalogs, and the admin dashboard
//! aggregate reads (issue #363).
//!
//! These are the remaining catalog surfaces the #365 parity manifest attributed
//! to #363 once the asset families landed. Each resource noun is a
//! [`CommandGroup`] declaring its verbs and the OpenAPI `operationId` each verb
//! invokes as compile-time metadata — the single source of truth the #365 parity
//! gate diffs against the contract — and a `build` function mapping a resolved
//! verb plus a typed [`ResourceInput`] onto a [`RequestSpec`] via the shared #361
//! `ResourceApi`/`build_crud` helpers. No request body schema is hard-coded:
//! mutations carry a complete operator-supplied `serde_json::Value` document.
//!
//! Five families are declared:
//!
//! * **prompt-templates** — the admin prompt-template catalog. Full CRUD plus
//!   two non-CRUD verbs: `archive` retires a template (`DELETE .../{id}`, whose
//!   operation is `archiveAdminPromptTemplate` — archive semantics, not a hard
//!   delete) and `render` exercises a template through the public render path
//!   `POST /v1/prompts/{id}/render`, which lives under a different base than the
//!   admin management collection.
//! * **skill-packages** — the admin skill-package catalog, a uniform CRUD
//!   resource (`list`/`get`/`create`/`replace`/`update`/`delete`).
//! * **plugins** — the admin plugin catalog: `list`/`get`/`create`/`update`
//!   (`PATCH`)/`delete`. There is no full-replace (`PUT`) operation, so no
//!   `replace` verb is declared. Listing a plugin's tools is *not* here — that
//!   nested read (`listAdminPluginTools`) is already owned by the `tools` family
//!   in [`crate::mcp`], so binding it again would be a duplicate mapping the
//!   parity gate rejects.
//! * **catalog** — read-only reference catalogs the operator inspects but does
//!   not mutate through these verbs: models, providers, provider-models,
//!   extensions, and framework adapters. Each verb is a single collection `list`.
//! * **dashboard** — the admin dashboard aggregate read. The contract exposes it
//!   at three alias paths (`/admin`, `/admin/dashboard`, `/admin/`), each with a
//!   distinct `operationId`; every one is bound to its own verb so coverage is
//!   exact rather than collapsing three contract operations into one.

use http::Method;

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::{CliError, CliResult};
use crate::registry_helpers::{build_crud, first_segment, ResourceInput};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/prompt-templates` — the admin prompt-template catalog collection.
pub const PROMPT_TEMPLATES: ResourceApi = ResourceApi::new("/admin/v1/prompt-templates");
/// `/v1/prompts` — the public prompt render surface (`.../{id}/render`).
pub const PROMPTS: ResourceApi = ResourceApi::new("/v1/prompts");
/// `/admin/v1/skill-packages` — the admin skill-package catalog collection.
pub const SKILL_PACKAGES: ResourceApi = ResourceApi::new("/admin/v1/skill-packages");
/// `/admin/v1/plugins` — the admin plugin catalog collection.
pub const PLUGINS: ResourceApi = ResourceApi::new("/admin/v1/plugins");
/// `/admin/v1/models` — the resolved model catalog (read-only).
pub const MODELS: ResourceApi = ResourceApi::new("/admin/v1/models");
/// `/admin/v1/providers` — the provider catalog (read-only).
pub const PROVIDERS: ResourceApi = ResourceApi::new("/admin/v1/providers");
/// `/admin/v1/provider-models` — the provider-model catalog (read-only).
pub const PROVIDER_MODELS: ResourceApi = ResourceApi::new("/admin/v1/provider-models");
/// `/admin/v1/extensions` — the extension catalog (read-only).
pub const EXTENSIONS: ResourceApi = ResourceApi::new("/admin/v1/extensions");
/// `/admin/v1/framework-adapters` — the framework-adapter catalog (read-only).
pub const FRAMEWORK_ADAPTERS: ResourceApi = ResourceApi::new("/admin/v1/framework-adapters");

/// The admin prompt-template catalog: CRUD plus archive and render.
pub struct PromptTemplatesGroup;

impl CommandGroup for PromptTemplatesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "prompt-templates",
            "Manage the prompt-template catalog",
            vec![
                VerbDescriptor::read("list", "List prompt templates", "listAdminPromptTemplates"),
                VerbDescriptor::read("get", "Show one prompt template", "getAdminPromptTemplate"),
                VerbDescriptor::mutating(
                    "create",
                    "Create a prompt template",
                    "createAdminPromptTemplate",
                ),
                VerbDescriptor::mutating(
                    "replace",
                    "Replace a prompt template",
                    "putAdminPromptTemplate",
                ),
                VerbDescriptor::mutating(
                    "update",
                    "Patch a prompt template",
                    "patchAdminPromptTemplate",
                ),
                VerbDescriptor::mutating(
                    "archive",
                    "Archive a prompt template",
                    "archiveAdminPromptTemplate",
                ),
                VerbDescriptor::mutating(
                    "render",
                    "Render a prompt template with inputs",
                    "renderPromptTemplate",
                ),
            ],
        )
    }
}

/// Build the request for a `prompt-templates` verb. `archive` is a `DELETE` on
/// the item (retirement, not the standard CRUD `delete` name); `render` posts a
/// render document to the public `/v1/prompts/{id}/render` action path.
pub fn build_prompt_templates(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "archive" => PROMPT_TEMPLATES.delete(&[first_segment(input, "prompt-template")?]),
        "render" => PROMPTS.action(
            &[first_segment(input, "prompt-template")?, "render"],
            Some(input.require_body(verb)?),
        ),
        other => build_crud(&PROMPT_TEMPLATES, other, input),
    }
}

/// The admin skill-package catalog: a uniform CRUD resource.
pub struct SkillPackagesGroup;

impl CommandGroup for SkillPackagesGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "skill-packages",
            "Manage the skill-package catalog",
            vec![
                VerbDescriptor::read("list", "List skill packages", "listAdminSkillPackages"),
                VerbDescriptor::read("get", "Show one skill package", "getAdminSkillPackage"),
                VerbDescriptor::mutating(
                    "create",
                    "Create a skill package",
                    "createAdminSkillPackage",
                ),
                VerbDescriptor::mutating(
                    "replace",
                    "Replace a skill package",
                    "putAdminSkillPackage",
                ),
                VerbDescriptor::mutating(
                    "update",
                    "Patch a skill package",
                    "patchAdminSkillPackage",
                ),
                VerbDescriptor::mutating(
                    "delete",
                    "Delete a skill package",
                    "deleteAdminSkillPackage",
                ),
            ],
        )
    }
}

/// Build the request for a `skill-packages` verb — uniform CRUD.
pub fn build_skill_packages(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&SKILL_PACKAGES, verb, input)
}

/// The admin plugin catalog: list/get/create/update/delete (no full replace).
pub struct PluginsGroup;

impl CommandGroup for PluginsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "plugins",
            "Manage the plugin catalog",
            vec![
                VerbDescriptor::read("list", "List plugins", "listAdminPlugins"),
                VerbDescriptor::read("get", "Show one plugin", "getAdminPlugin"),
                VerbDescriptor::mutating("create", "Register a plugin", "createAdminPlugin"),
                VerbDescriptor::mutating("update", "Patch a plugin", "updateAdminPlugin"),
                VerbDescriptor::mutating("delete", "Delete a plugin", "deleteAdminPlugin"),
            ],
        )
    }
}

/// Build the request for a `plugins` verb — CRUD without `replace`.
pub fn build_plugins(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&PLUGINS, verb, input)
}

/// The read-only reference catalogs: models, providers, provider-models,
/// extensions, framework adapters. Each verb is a single collection list.
pub struct CatalogGroup;

impl CommandGroup for CatalogGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "catalog",
            "Inspect read-only model/provider/extension catalogs",
            vec![
                VerbDescriptor::read("models", "List resolved models", "listAdminModels"),
                VerbDescriptor::read("providers", "List providers", "listAdminProviders"),
                VerbDescriptor::read(
                    "provider-models",
                    "List provider models",
                    "listAdminProviderModels",
                ),
                VerbDescriptor::read("extensions", "List extensions", "listAdminExtensions"),
                VerbDescriptor::read(
                    "framework-adapters",
                    "List framework adapters",
                    "listAdminFrameworkAdapters",
                ),
            ],
        )
    }
}

/// Build the request for a `catalog` verb — each maps to a distinct read-only
/// collection list.
pub fn build_catalog(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    let api = match verb {
        "models" => &MODELS,
        "providers" => &PROVIDERS,
        "provider-models" => &PROVIDER_MODELS,
        "extensions" => &EXTENSIONS,
        "framework-adapters" => &FRAMEWORK_ADAPTERS,
        other => {
            return Err(CliError::usage(format!(
                "verb '{other}' is not a catalog verb"
            )))
        }
    };
    api.read(&[], &input.list)
}

/// The admin dashboard aggregate read, exposed at three alias paths.
pub struct DashboardGroup;

impl CommandGroup for DashboardGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "dashboard",
            "Read the admin dashboard aggregate summary",
            vec![
                VerbDescriptor::read("show", "Show the admin dashboard", "getAdminDashboard"),
                VerbDescriptor::read(
                    "alias",
                    "Show the admin dashboard (/admin/dashboard alias)",
                    "getAdminDashboardAlias",
                ),
                VerbDescriptor::read(
                    "root",
                    "Show the admin dashboard (/admin/ alias)",
                    "getAdminDashboardSlash",
                ),
            ],
        )
    }
}

/// Build the request for a `dashboard` verb. The three verbs address the three
/// contract alias paths of the same aggregate read; each is bound explicitly so
/// coverage stays exact.
pub fn build_dashboard(verb: &str, _input: &ResourceInput) -> CliResult<RequestSpec> {
    let path = match verb {
        "show" => "/admin",
        "alias" => "/admin/dashboard",
        "root" => "/admin/",
        other => {
            return Err(CliError::usage(format!(
                "verb '{other}' is not a dashboard verb"
            )))
        }
    };
    Ok(RequestSpec::new(Method::GET, path))
}

/// Register every catalog command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&PromptTemplatesGroup)?;
    registry.register(&SkillPackagesGroup)?;
    registry.register(&PluginsGroup)?;
    registry.register(&CatalogGroup)?;
    registry.register(&DashboardGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "catalog_test.rs"]
mod catalog_test;
