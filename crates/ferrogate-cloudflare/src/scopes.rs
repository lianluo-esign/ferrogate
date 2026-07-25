// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Machine-adjacent list of the Cloudflare token permission groups FerroGate needs.

//! Required Cloudflare API-token permission groups (issue #405).
//!
//! This is the machine-adjacent source of truth referenced by
//! [`crate::CloudflareClient::preflight`] when a token authenticates but is
//! under-scoped. The operator-facing prose doc is a sibling sub-issue (#421);
//! this table is what the code names in error messages so the two never drift.
//!
//! An API token is scoped by attaching **permission groups** at the account
//! (or zone) level. FerroGate's Cloudflare integrations collectively require
//! the groups below. A given deployment that only uses a subset of the
//! Cloudflare features can grant the corresponding subset — but the preflight
//! check reports the full foundational set so an operator can provision once.

/// One required token permission group and why FerroGate needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenPermissionGroup {
    /// Cloudflare's dashboard name for the permission group.
    pub name: &'static str,
    /// Read / Edit (Cloudflare's Read vs. Edit access level).
    pub access: &'static str,
    /// Which FerroGate Cloudflare sub-system consumes it.
    pub used_by: &'static str,
}

/// The full set of permission groups the FerroGate Cloudflare integrations
/// depend on. Kept in issue-declared order.
pub const REQUIRED_TOKEN_PERMISSION_GROUPS: &[TokenPermissionGroup] = &[
    TokenPermissionGroup {
        name: "AI Gateway",
        access: "Read, Edit",
        used_by: "AI Gateway management + inference proxying",
    },
    TokenPermissionGroup {
        name: "Secrets Store",
        access: "Read, Write",
        used_by: "cf:// secret backend (#417)",
    },
    TokenPermissionGroup {
        name: "D1",
        access: "Read, Edit",
        used_by: "D1-backed state",
    },
    TokenPermissionGroup {
        name: "Workers Scripts",
        access: "Edit",
        used_by: "Worker deployment",
    },
    TokenPermissionGroup {
        name: "Workers R2 Storage",
        access: "Read, Edit",
        used_by: "R2 object storage",
    },
    TokenPermissionGroup {
        name: "API Tokens",
        access: "Write",
        used_by: "minting/revoking bucket-scoped R2 API tokens (#462)",
    },
    TokenPermissionGroup {
        name: "Cloudflare Pages",
        access: "Edit",
        used_by: "Pages deployment",
    },
    TokenPermissionGroup {
        name: "Workflows (Workers Scripts)",
        access: "Write, Edit",
        used_by: "Workflows orchestration",
    },
];

/// The permission-group names, for embedding in a [`crate::CloudflareError`]
/// message. Allocation-free view over [`REQUIRED_TOKEN_PERMISSION_GROUPS`].
pub fn required_group_names() -> Vec<&'static str> {
    REQUIRED_TOKEN_PERMISSION_GROUPS
        .iter()
        .map(|g| g.name)
        .collect()
}
