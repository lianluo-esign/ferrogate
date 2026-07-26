// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Scoped x402 spend-policy declarations and their deterministic
// precedence/inheritance resolution (issue #351). Pure config semantics: which
// declared policy a tenant/project/workspace/key/agent-run chain resolves to,
// with no I/O and no runtime state. The typed policy itself and its validation
// stay in `ferrogate-policy`; this module only says *which* policy applies.

//! Scope precedence for typed x402 spend policies (issue #351).
//!
//! An operator declares zero or more [`X402ScopedSpendPolicy`] entries, each
//! pinned to one scope in the tenancy chain
//! `tenant -> project -> workspace -> key -> run`. At decision time the runtime
//! resolves the request's scope chain against those declarations with a single,
//! deterministic rule:
//!
//! > **The most specific declared scope wins; if nothing is declared anywhere in
//! > the chain, the effective policy is the disabled default, which denies every
//! > payment.**
//!
//! There is deliberately no merge/inherit-field-by-field semantics. Merging two
//! money policies would make the effective caps of a payment depend on a
//! non-obvious field-level union, and a narrower parent cap could be silently
//! widened by a child that only meant to change a mint. One declaration is
//! either in force or it is not, and the resolution result names exactly which
//! one it was so a decision can always be traced back to a single config entry.
//!
//! Resolution is total: [`resolve_effective_x402_spend_policy`] always returns
//! an [`EffectiveX402SpendPolicy`], falling back to
//! [`X402SpendPolicy::disabled`] rather than an `Option`, so a caller can never
//! forget to handle "unconfigured" and accidentally treat it as "allowed".
//!
//! # Scope-id normalization
//!
//! Every scope id — declared and requested — passes through
//! [`normalize_x402_scope_id`], which is the ONE definition of "the same scope".
//! Before this existed, declaration validation trimmed while resolution matched
//! raw, so `scope_id = " acme "` loaded clean, listed on the admin surface, and
//! could never be resolved by any request: a money policy that is permanently
//! inert while looking live. Normalizing in a single place also makes the
//! read-side (`GET …/effective`, whose query parser trims) and the decision-side
//! (`POST …/evaluate`, which read the body verbatim) agree by construction,
//! which is the entire point of a "what you read back is what the runtime
//! decides" surface.

use serde::{Deserialize, Serialize};

use crate::x402::X402SpendPolicyConfig;
use ferrogate_policy::{ValidatedX402SpendPolicy, X402PolicyConfigError, X402SpendPolicy};

/// The single normalization applied to every x402 scope id, on both the
/// declaration side and the request side.
///
/// Surrounding whitespace is the only difference that is folded away: scope ids
/// are opaque tenant/project/workspace/key/run identifiers, so case folding or
/// unicode normalization would risk collapsing two genuinely distinct ids into
/// one, which on a money surface is strictly worse than rejecting the odd one.
///
/// A normalized id that is empty is not a scope at all; declaration validation
/// rejects it and [`X402ScopeChain::levels`] omits it.
pub fn normalize_x402_scope_id(scope_id: &str) -> &str {
    scope_id.trim()
}

/// One level of the tenancy chain an x402 spend policy may be declared at.
///
/// Ordered from broadest to narrowest; the ordinal is the precedence rank used
/// by [`resolve_effective_x402_spend_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum X402PolicyScopeKind {
    /// The tenant (organization) account.
    Tenant,
    /// A project inside the tenant.
    Project,
    /// A workspace inside the project.
    Workspace,
    /// A virtual API key inside the workspace.
    Key,
    /// A single agent run — the narrowest scope, used to pin one run's budget.
    Run,
}

impl X402PolicyScopeKind {
    /// Every scope kind, broadest first. The canonical inheritance order.
    pub const ALL: [Self; 5] = [
        Self::Tenant,
        Self::Project,
        Self::Workspace,
        Self::Key,
        Self::Run,
    ];

    /// Stable wire/config name for this scope kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Project => "project",
            Self::Workspace => "workspace",
            Self::Key => "key",
            Self::Run => "run",
        }
    }

    /// Parse a wire/config scope name. Unknown names are rejected rather than
    /// mapped to a default, so a typo can never silently widen a policy.
    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "tenant" => Some(Self::Tenant),
            "project" => Some(Self::Project),
            "workspace" => Some(Self::Workspace),
            "key" => Some(Self::Key),
            "run" => Some(Self::Run),
            _ => None,
        }
    }
}

/// One operator-declared policy, pinned to a scope.
///
/// The policy body is the transparent [`X402SpendPolicyConfig`] newtype, so a
/// declaration is just `scope_type` + `scope_id` + the policy's own fields under
/// `policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402ScopedSpendPolicy {
    /// Which level of the tenancy chain this declaration applies to.
    pub scope_type: X402PolicyScopeKind,
    /// The id at that level (tenant id, project id, workspace id, key id, or
    /// agent-run id).
    pub scope_id: String,
    /// The declared policy. Disabled by default when the section is omitted.
    #[serde(default)]
    pub policy: X402SpendPolicyConfig,
}

impl X402ScopedSpendPolicy {
    /// This declaration's scope id under [`normalize_x402_scope_id`]. Every
    /// comparison, projection, and tenancy check must use this rather than the
    /// raw field, or a padded declaration becomes unreachable.
    pub fn normalized_scope_id(&self) -> &str {
        normalize_x402_scope_id(&self.scope_id)
    }

    /// Does this declaration apply to `(kind, scope_id)`? `scope_id` is
    /// normalized here too, so callers cannot accidentally compare a raw
    /// request id against a normalized declaration id.
    pub fn matches_scope(&self, kind: X402PolicyScopeKind, scope_id: &str) -> bool {
        self.scope_type == kind && self.normalized_scope_id() == normalize_x402_scope_id(scope_id)
    }
}

/// The scope chain a payment is evaluated at. `tenant_id` is mandatory; the
/// narrower levels are optional and simply absent from resolution when `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct X402ScopeChain<'a> {
    pub tenant_id: &'a str,
    pub project_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    pub key_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
}

impl<'a> X402ScopeChain<'a> {
    /// A chain with only the tenant level populated.
    pub fn tenant(tenant_id: &'a str) -> Self {
        Self {
            tenant_id,
            ..Self::default()
        }
    }

    /// The chain as `(kind, id)` pairs, broadest first, skipping absent levels.
    ///
    /// Every id is normalized here — this is the request-side entry point that
    /// resolution, inheritance evidence, and the admin tenancy check all funnel
    /// through, so `" acme "` and `"acme"` are one scope everywhere downstream.
    /// A narrower level whose id normalizes to empty is treated as absent
    /// rather than as an empty-id scope that can match nothing.
    pub fn levels(&self) -> Vec<(X402PolicyScopeKind, &'a str)> {
        let mut levels = Vec::with_capacity(X402PolicyScopeKind::ALL.len());
        levels.push((
            X402PolicyScopeKind::Tenant,
            normalize_x402_scope_id(self.tenant_id),
        ));
        for (kind, id) in [
            (X402PolicyScopeKind::Project, self.project_id),
            (X402PolicyScopeKind::Workspace, self.workspace_id),
            (X402PolicyScopeKind::Key, self.key_id),
            (X402PolicyScopeKind::Run, self.run_id),
        ] {
            if let Some(id) = id.map(normalize_x402_scope_id).filter(|id| !id.is_empty()) {
                levels.push((kind, id));
            }
        }
        levels
    }
}

/// The resolved effective policy for one scope chain: the policy itself plus the
/// evidence of where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveX402SpendPolicy {
    /// The scope whose declaration won, or `None` when nothing was declared
    /// anywhere in the chain (in which case `policy` is the disabled default).
    pub source: Option<X402PolicyScopeRef>,
    /// The effective policy body.
    pub policy: X402SpendPolicy,
}

impl EffectiveX402SpendPolicy {
    /// The revision of the effective policy. The disabled default is revision 0.
    pub fn revision(&self) -> u64 {
        self.policy.revision
    }

    /// True iff an operator declaration was found for this chain.
    pub fn is_declared(&self) -> bool {
        self.source.is_some()
    }

    /// Validate the effective policy into the type the pure decision function
    /// accepts. Delegates to the policy crate so config-time and decision-time
    /// validity cannot drift.
    pub fn validate(&self) -> Result<ValidatedX402SpendPolicy, X402PolicyConfigError> {
        self.policy.clone().validate()
    }
}

/// A reference to the scope a declaration was made at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402PolicyScopeRef {
    pub scope_type: X402PolicyScopeKind,
    pub scope_id: String,
}

/// Resolve the effective x402 spend policy for `chain` out of `declared`.
///
/// Deterministic and total:
///
/// - the narrowest scope in the chain that has a declaration wins;
/// - ties within one scope level (a duplicate `(scope_type, scope_id)`, which
///   [`validate_scoped_x402_spend_policies`] rejects at load) resolve to the
///   FIRST declaration, so behaviour is still defined for a config that somehow
///   bypassed validation;
/// - no declaration anywhere yields the disabled default, which denies every
///   payment.
pub fn resolve_effective_x402_spend_policy(
    declared: &[X402ScopedSpendPolicy],
    chain: &X402ScopeChain<'_>,
) -> EffectiveX402SpendPolicy {
    for (kind, id) in chain.levels().into_iter().rev() {
        if let Some(entry) = declared.iter().find(|entry| entry.matches_scope(kind, id)) {
            return EffectiveX402SpendPolicy {
                source: Some(X402PolicyScopeRef {
                    scope_type: kind,
                    scope_id: id.to_string(),
                }),
                policy: entry.policy.policy().clone(),
            };
        }
    }
    EffectiveX402SpendPolicy {
        source: None,
        policy: X402SpendPolicy::disabled(),
    }
}

/// A rejected scoped-policy declaration set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X402ScopedPolicyError {
    /// Two declarations target the same `(scope_type, scope_id)`. Rejected
    /// rather than silently resolved, because which one is "the" policy for that
    /// scope would otherwise depend on config file order.
    DuplicateScope {
        scope_type: X402PolicyScopeKind,
        scope_id: String,
    },
    /// A declaration has an empty `scope_id`, which can never match a real
    /// tenant/project/workspace/key/run.
    EmptyScopeId { scope_type: X402PolicyScopeKind },
    /// A declared policy failed the policy crate's own structural validation.
    Invalid {
        scope_type: X402PolicyScopeKind,
        scope_id: String,
        error: X402PolicyConfigError,
    },
}

impl std::fmt::Display for X402ScopedPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateScope {
                scope_type,
                scope_id,
            } => write!(
                f,
                "duplicate x402 spend policy for {} {scope_id}",
                scope_type.as_str()
            ),
            Self::EmptyScopeId { scope_type } => write!(
                f,
                "x402 spend policy at scope {} has an empty scope_id",
                scope_type.as_str()
            ),
            Self::Invalid {
                scope_type,
                scope_id,
                error,
            } => write!(
                f,
                "invalid x402 spend policy for {} {scope_id}: {error}",
                scope_type.as_str()
            ),
        }
    }
}

impl std::error::Error for X402ScopedPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Validate a whole declaration set at config-load time: every declared policy
/// must pass the policy crate's structural validation, every `scope_id` must be
/// non-empty, and no two declarations may target the same scope.
///
/// Runs before the gateway serves traffic so an operator learns about a broken
/// money policy at startup, not at the first payment.
pub fn validate_scoped_x402_spend_policies(
    declared: &[X402ScopedSpendPolicy],
) -> Result<(), X402ScopedPolicyError> {
    let mut seen: Vec<(X402PolicyScopeKind, &str)> = Vec::with_capacity(declared.len());
    for entry in declared {
        // The SAME normalization resolution uses, so a declaration that loads
        // clean is by construction a declaration a request can reach.
        let scope_id = entry.normalized_scope_id();
        if scope_id.is_empty() {
            return Err(X402ScopedPolicyError::EmptyScopeId {
                scope_type: entry.scope_type,
            });
        }
        if seen.contains(&(entry.scope_type, scope_id)) {
            return Err(X402ScopedPolicyError::DuplicateScope {
                scope_type: entry.scope_type,
                scope_id: scope_id.to_string(),
            });
        }
        seen.push((entry.scope_type, scope_id));
        entry
            .policy
            .clone()
            .validate()
            .map_err(|error| X402ScopedPolicyError::Invalid {
                scope_type: entry.scope_type,
                scope_id: scope_id.to_string(),
                error,
            })?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "x402_scope_test.rs"]
mod x402_scope_test;
