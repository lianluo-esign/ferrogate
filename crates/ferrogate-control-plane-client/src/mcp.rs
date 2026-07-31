// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP (Model Context Protocol) command families (issue #362).
//!
//! Covers the MCP governance surface of the Control Plane API: MCP server
//! registrations (declarative CRUD, addressed by name), per-server MCP identity
//! lifecycle (authorize / read / revoke, plus the OAuth callback completion),
//! tool-session event streams, and the tool catalog (global and per-plugin).
//! Each resource noun is a [`CommandGroup`] declaring its verbs and OpenAPI
//! `operationId`s as compile-time metadata, plus a `build` function mapping a
//! resolved verb onto a [`RequestSpec`] via the shared [`ResourceApi`] builders.
//!
//! MCP identity is modelled as first-class lifecycle, not generic CRUD:
//!
//! * `authorize` starts an authorization via `POST /v1/mcp/identity/{server}/authorize`,
//!   `get` reads the current grant, and `revoke` deletes it — so the audit trail
//!   distinguishes issuance from revocation for each server binding.
//!
//! Explicitly excluded (data-plane invocation surfaces a management CLI does not
//! drive): `mcpJsonRpc` (`POST /v1/mcp`), `executeMcpTool` (`POST /v1/mcp/tool/execute`),
//! `listTools`/`executeTool` (`/v1/tools*` runtime catalog + execution).

use crate::command::{CommandGroup, GroupDescriptor, VerbDescriptor};
use crate::error::CliResult;
use crate::registry_helpers::{
    build_crud, build_item_action, build_item_delete, first_segment, ResourceInput,
};
use crate::resource::ResourceApi;
use crate::transport::RequestSpec;
use crate::Registry;

/// `/admin/v1/mcp-servers` — registered MCP servers (keyed by name).
pub const MCP_SERVERS: ResourceApi = ResourceApi::new("/admin/v1/mcp-servers");
/// `/v1/mcp/identity` — per-server MCP identity grants (keyed by server).
pub const MCP_IDENTITY: ResourceApi = ResourceApi::new("/v1/mcp/identity");
/// `/admin/v1/tool-sessions` — tool session event streams (keyed by session id).
pub const TOOL_SESSIONS: ResourceApi = ResourceApi::new("/admin/v1/tool-sessions");
/// `/admin/v1/tools` — the admin tool catalog.
pub const TOOLS: ResourceApi = ResourceApi::new("/admin/v1/tools");
/// `/admin/v1/plugins` — plugins, whose `/tools` sub-collection lists their tools.
pub const PLUGINS: ResourceApi = ResourceApi::new("/admin/v1/plugins");

/// MCP servers (full CRUD, addressed by server name).
pub struct McpServersGroup;

impl CommandGroup for McpServersGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "mcp-servers",
            "Manage registered MCP servers",
            vec![
                VerbDescriptor::read("list", "List MCP servers", "listAdminMcpServers"),
                VerbDescriptor::read("get", "Show an MCP server", "getAdminMcpServer"),
                VerbDescriptor::mutating(
                    "create",
                    "Register an MCP server",
                    "createAdminMcpServer",
                ),
                VerbDescriptor::mutating("replace", "Replace an MCP server", "putAdminMcpServer"),
                VerbDescriptor::mutating("update", "Update an MCP server", "patchAdminMcpServer"),
                VerbDescriptor::mutating(
                    "delete",
                    "Deregister an MCP server",
                    "deleteAdminMcpServer",
                ),
            ],
        )
    }
}

/// Build the request for an mcp-servers verb.
pub fn build_mcp_servers(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    build_crud(&MCP_SERVERS, verb, input)
}

/// MCP identity lifecycle for a server binding.
pub struct McpIdentityGroup;

impl CommandGroup for McpIdentityGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "mcp-identity",
            "Manage per-server MCP identity grants",
            vec![
                VerbDescriptor::mutating(
                    "authorize",
                    "Authorize an MCP identity for a server",
                    "authorizeMcpIdentity",
                ),
                VerbDescriptor::read("get", "Show an MCP identity grant", "getMcpIdentity"),
                VerbDescriptor::mutating(
                    "revoke",
                    "Revoke an MCP identity grant",
                    "revokeMcpIdentity",
                ),
                // A GET that MUTATES. `completeMcpIdentityOauth` is a GET only
                // because it is the OAuth redirect target the authorization
                // server sends a browser to; completing the flow exchanges the
                // authorization code and persists an identity grant. The
                // method is therefore not the witness to its effect, and this
                // is the one registered verb where the two disagree - see
                // `receipt::METHOD_EFFECT_EXCEPTIONS`, which carries the
                // reason and is checked by the classification guard.
                VerbDescriptor::mutating(
                    "callback",
                    "Complete an MCP identity OAuth callback",
                    "completeMcpIdentityOauth",
                ),
            ],
        )
    }
}

/// Build the request for an mcp-identity verb.
///
/// `authorize`/`get`/`revoke` address a single `{server}` binding; `callback`
/// hits the fixed `.../callback` completion path.
pub fn build_mcp_identity(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "authorize" => build_item_action(&MCP_IDENTITY, "mcp-identity", "authorize", input),
        "get" => MCP_IDENTITY.read(&[first_segment(input, "mcp-identity")?], &input.list),
        "revoke" => build_item_delete(&MCP_IDENTITY, "mcp-identity", input),
        "callback" => MCP_IDENTITY.read(&["callback"], &input.list),
        other => build_crud(&MCP_IDENTITY, other, input),
    }
}

/// Tool session event streams (read-only, keyed by session id).
pub struct ToolSessionsGroup;

impl CommandGroup for ToolSessionsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tool-sessions",
            "Inspect tool session event streams",
            vec![VerbDescriptor::read(
                "events",
                "List a tool session's events",
                "listAdminToolSessionEvents",
            )],
        )
    }
}

/// Build the request for a tool-sessions verb.
pub fn build_tool_sessions(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "events" => TOOL_SESSIONS.read(&[first_segment(input, "tool-session")?], &input.list),
        other => build_crud(&TOOL_SESSIONS, other, input),
    }
}

/// The tool catalog: the global admin list plus a per-plugin sub-list.
pub struct ToolsGroup;

impl CommandGroup for ToolsGroup {
    fn descriptor(&self) -> GroupDescriptor {
        GroupDescriptor::new(
            "tools",
            "Inspect the admin tool catalog",
            vec![
                VerbDescriptor::read("list", "List all tools", "listAdminTools"),
                VerbDescriptor::read(
                    "plugin-tools",
                    "List a plugin's tools",
                    "listAdminPluginTools",
                ),
            ],
        )
    }
}

/// Build the request for a tools verb. `plugin-tools` reads the nested
/// `/plugins/{plugin_id}/tools` sub-collection.
pub fn build_tools(verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    match verb {
        "plugin-tools" => PLUGINS.read(&[first_segment(input, "plugin")?, "tools"], &input.list),
        other => build_crud(&TOOLS, other, input),
    }
}

/// Register every MCP command group with the registry.
pub fn register(registry: &mut Registry) -> CliResult<()> {
    registry.register(&McpServersGroup)?;
    registry.register(&McpIdentityGroup)?;
    registry.register(&ToolSessionsGroup)?;
    registry.register(&ToolsGroup)?;
    Ok(())
}

#[cfg(test)]
#[path = "mcp_test.rs"]
mod mcp_test;
