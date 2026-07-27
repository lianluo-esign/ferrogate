// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Named contexts and deterministic value resolution (issue #360).
//!
//! A [`Context`] is a saved server profile: an endpoint, default
//! tenant/project/workspace, TLS/CA settings, and a *reference* to a
//! credential source. Bearer tokens are never stored in a context — only how
//! to obtain one (see [`crate::auth`]).
//!
//! The resolution rule is the load-bearing product contract here: for every
//! effective value the precedence is
//!
//! ```text
//! explicit global flag  >  environment variable  >  selected context  >  built-in default
//! ```
//!
//! This module implements that precedence as pure functions so it can be
//! exhaustively unit-tested without a filesystem or network (an acceptance
//! criterion of #360). Persistence format and the `context` verbs live with
//! the command layer; this module owns the in-memory model and resolution.

use serde::{Deserialize, Serialize};

use crate::auth::AuthSource;
use crate::error::{CliError, CliResult};

/// Default Control Plane API endpoint, matching the OpenAPI `servers[0]`
/// entry (`http://127.0.0.1:8080`).
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8080";

/// Default per-request timeout in milliseconds when neither a flag, env var,
/// nor context overrides it.
pub const DEFAULT_TIMEOUT_MILLIS: u64 = 30_000;

/// A saved server profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// Unique context name (e.g. `production`).
    pub name: String,
    /// Base URL of the Control Plane API for this context.
    pub endpoint: String,
    /// Default tenant applied to commands that accept one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Default project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Default workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// Optional path to a CA bundle used to verify the endpoint's TLS cert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_path: Option<String>,
    /// Whether TLS verification may be skipped (opt-in, never the default).
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    /// How the bearer token is obtained. Never the token itself.
    #[serde(default)]
    pub auth: AuthSource,
}

impl Context {
    /// Construct a context with only the required fields; optional defaults
    /// stay unset.
    pub fn new(name: impl Into<String>, endpoint: impl Into<String>) -> Context {
        Context {
            name: name.into(),
            endpoint: endpoint.into(),
            tenant: None,
            project: None,
            workspace: None,
            ca_bundle_path: None,
            tls_insecure_skip_verify: false,
            auth: AuthSource::default(),
        }
    }
}

/// The in-memory collection of contexts plus the currently selected one.
///
/// This is the deserialized form of the on-disk config; the command layer
/// owns where it lives on disk. `current` names the context used when no
/// `--context`/env override is given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextStore {
    #[serde(default)]
    pub contexts: Vec<Context>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
}

impl ContextStore {
    /// Look up a context by name.
    pub fn get(&self, name: &str) -> Option<&Context> {
        self.contexts.iter().find(|context| context.name == name)
    }

    /// Insert or replace a context, keeping names unique.
    pub fn upsert(&mut self, context: Context) {
        match self
            .contexts
            .iter_mut()
            .find(|existing| existing.name == context.name)
        {
            Some(existing) => *existing = context,
            None => self.contexts.push(context),
        }
    }

    /// Remove a context by name, returning whether it existed. Clears
    /// `current` if it pointed at the removed context.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.contexts.len();
        self.contexts.retain(|context| context.name != name);
        if self.current.as_deref() == Some(name) {
            self.current = None;
        }
        self.contexts.len() != before
    }

    /// Select the default context. Fails if it does not exist so `use`
    /// never leaves a dangling pointer.
    pub fn set_current(&mut self, name: &str) -> CliResult<()> {
        if self.get(name).is_none() {
            return Err(CliError::usage(format!(
                "no such context '{name}'; run `context list` to see defined contexts"
            )));
        }
        self.current = Some(name.to_string());
        Ok(())
    }
}

/// Explicit command-line overrides. Every field is optional; a set field wins
/// over the environment and the selected context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalOverrides {
    /// Force a specific context by name instead of the store's `current`.
    pub context: Option<String>,
    /// Override the endpoint entirely.
    pub endpoint: Option<String>,
    /// Override the tenant.
    pub tenant: Option<String>,
    /// Override the credential source.
    pub auth: Option<AuthSource>,
    /// Override the per-request timeout (milliseconds).
    pub timeout_millis: Option<u64>,
    /// Override the output format.
    pub output: Option<crate::output::OutputFormat>,
    /// Run without interactive prompts (e.g. destructive-action confirmation).
    pub non_interactive: bool,
}

/// Values sourced from the process environment. Kept as an explicit struct so
/// tests inject a fixed environment instead of mutating real `std::env`
/// (which is process-global and racy under a parallel test runner).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvOverrides {
    pub context: Option<String>,
    pub endpoint: Option<String>,
    pub tenant: Option<String>,
    pub timeout_millis: Option<u64>,
}

impl EnvOverrides {
    /// Canonical environment variable names for the client.
    pub const CONTEXT_VAR: &'static str = "FERROGATE_CONTEXT";
    pub const ENDPOINT_VAR: &'static str = "FERROGATE_ENDPOINT";
    pub const TENANT_VAR: &'static str = "FERROGATE_TENANT";
    pub const TIMEOUT_VAR: &'static str = "FERROGATE_TIMEOUT_MILLIS";

    /// Read the canonical variables from a lookup function. A function is
    /// taken (rather than reading `std::env` directly) so callers control the
    /// source and tests stay hermetic.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> CliResult<EnvOverrides> {
        let timeout_millis = match lookup(Self::TIMEOUT_VAR) {
            Some(raw) => Some(raw.trim().parse::<u64>().map_err(|_| {
                CliError::usage(format!(
                    "{} must be a positive integer number of milliseconds, got '{raw}'",
                    Self::TIMEOUT_VAR
                ))
            })?),
            None => None,
        };
        Ok(EnvOverrides {
            context: non_empty(lookup(Self::CONTEXT_VAR)),
            endpoint: non_empty(lookup(Self::ENDPOINT_VAR)),
            tenant: non_empty(lookup(Self::TENANT_VAR)),
            timeout_millis,
        })
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

/// The fully resolved connection parameters a command actually uses. Produced
/// by [`resolve`] after applying precedence; commands read this and never
/// re-derive precedence themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveContext {
    /// Name of the context these values were resolved from, if any.
    pub context_name: Option<String>,
    pub endpoint: String,
    pub tenant: Option<String>,
    pub project: Option<String>,
    pub workspace: Option<String>,
    pub ca_bundle_path: Option<String>,
    pub tls_insecure_skip_verify: bool,
    pub timeout_millis: u64,
    pub auth: AuthSource,
    pub output: crate::output::OutputFormat,
    pub non_interactive: bool,
}

/// Apply the precedence rule and produce the effective connection parameters.
///
/// Precedence, highest first: explicit global flag, environment variable,
/// selected context field, built-in default. The selected context is chosen
/// by (flag context name) then (env context name) then the store's `current`.
/// A named context that does not exist is a usage error rather than a silent
/// fallback to defaults.
pub fn resolve(
    store: &ContextStore,
    env: &EnvOverrides,
    overrides: &GlobalOverrides,
) -> CliResult<EffectiveContext> {
    let selected_name = overrides
        .context
        .as_deref()
        .or(env.context.as_deref())
        .or(store.current.as_deref());

    let context = match selected_name {
        Some(name) => Some(store.get(name).ok_or_else(|| {
            CliError::usage(format!(
                "selected context '{name}' is not defined; run `context list`"
            ))
        })?),
        None => None,
    };

    let endpoint = overrides
        .endpoint
        .clone()
        .or_else(|| env.endpoint.clone())
        .or_else(|| context.map(|context| context.endpoint.clone()))
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    let tenant = overrides
        .tenant
        .clone()
        .or_else(|| env.tenant.clone())
        .or_else(|| context.and_then(|context| context.tenant.clone()));

    let timeout_millis = overrides
        .timeout_millis
        .or(env.timeout_millis)
        .unwrap_or(DEFAULT_TIMEOUT_MILLIS);

    let auth = overrides
        .auth
        .clone()
        .or_else(|| context.map(|context| context.auth.clone()))
        .unwrap_or_default();

    Ok(EffectiveContext {
        context_name: context.map(|context| context.name.clone()),
        endpoint,
        tenant,
        project: context.and_then(|context| context.project.clone()),
        workspace: context.and_then(|context| context.workspace.clone()),
        ca_bundle_path: context.and_then(|context| context.ca_bundle_path.clone()),
        tls_insecure_skip_verify: context
            .map(|context| context.tls_insecure_skip_verify)
            .unwrap_or(false),
        timeout_millis,
        auth,
        output: overrides.output.unwrap_or_default(),
        non_interactive: overrides.non_interactive,
    })
}

/// The operator-facing note that a resolved scope field is **not** applied to
/// the request, or `None` when every set field is honored.
///
/// Why this exists rather than the fields being made to work: `--tenant`
/// (and `FERROGATE_TENANT`, and a context's `tenant`) becomes the
/// `x-ferrogate-tenant` request header, and that header appears **nowhere** in
/// `docs/openapi/admin-api.openapi.json` — no operation declares it, so no
/// server-side reader exists. Admin requests are scoped by the bearer token.
/// `project` and `workspace` are worse: persisted, shown by `context show`,
/// resolved here, and never placed in a request in any form.
///
/// The failure that motivates it: `ferrogate ctl virtual-keys list --tenant
/// acme` with an admin token exits 0 and returns whatever the token's scope is
/// — a wrong-tenant read presented as a scoped one, with no diagnostic. That is
/// the #188 ignored-field anti-pattern, and it is worse here than in a dropped
/// `ca_bundle_path`, because the operator's mental model of *which tenant's
/// data they are looking at* is what is wrong.
///
/// Honoring them client-side is not available: the client must not invent a
/// tenancy parameter ~200 operations do not accept. So they get the treatment
/// `--sort` got — stated in the flag help, in the generated reference, and on
/// stderr at every use — and `tenant_scope_is_not_yet_an_openapi_parameter`
/// pins the claim to the contract so it cannot go stale silently.
///
/// Pure, so the wording is unit-testable without capturing process stderr.
pub fn unhonored_scope_notice(effective: &EffectiveContext) -> Option<String> {
    let mut unsent: Vec<&str> = Vec::new();
    if effective.project.is_some() {
        unsent.push("project");
    }
    if effective.workspace.is_some() {
        unsent.push("workspace");
    }

    let mut notice = String::new();
    if effective.tenant.is_some() {
        notice.push_str(
            "note: the selected tenant is sent as the 'x-ferrogate-tenant' header, which no \
             Control Plane API operation declares — admin requests are scoped by the bearer \
             token, so this does not narrow or redirect the result. Where an operation does \
             accept tenant selection it is a 'tenant' query parameter: pass it as \
             `--filter tenant=<id>`",
        );
    }
    if !unsent.is_empty() {
        if !notice.is_empty() {
            notice.push('\n');
        }
        notice.push_str(&format!(
            "note: the selected context's {} {} recorded locally and {} not sent with any \
             request; scope the call with an id segment or `--filter` instead",
            unsent.join(" and "),
            if unsent.len() == 1 { "is" } else { "are" },
            if unsent.len() == 1 { "is" } else { "are" },
        ));
    }

    if notice.is_empty() {
        None
    } else {
        Some(notice)
    }
}

#[cfg(test)]
#[path = "context_test.rs"]
mod context_test;
