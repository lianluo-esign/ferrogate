// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Configuration parsing, validation and typed adapter boundaries.
//!
//! # What this crate is for
//!
//! The gateway's configuration -- the `Config` an operator writes, the loader
//! that reads it and the validation that refuses a bad one -- lived in
//! `ferrogate-cli` until #553 stage 3a, while this crate held only the
//! Caddyfile compatibility layer. The name was attached to the smaller half.
//! Stage 3a moved `ferrogate-cli/src/config/` here, so the crate called
//! `ferrogate-config` is now where configuration actually is.
//!
//! The Caddyfile support remains a deliberately small compatibility contract.
//! It accepts the initial FerroGate subset, maps it to a typed gateway model,
//! and returns clear diagnostics for unsupported directives. Both halves now
//! sit in one crate, which is what lets `Config::from_gateway_config` (the
//! Caddyfile -> `Config` mapping in `config/loader.rs`) be an ordinary
//! same-crate call; #550 retires that path.
//!
//! # The public surface, and why it is a list and not a glob
//!
//! `mod config` below is PRIVATE. Everything inside it is `pub` only in the
//! sense that a private module's contents can be re-exported; nothing in it
//! reaches a caller except through the `pub use` list at the bottom of this
//! file, and every name in that list was added because a compile error in
//! `ferrogate-cli` named it. That list, not the module tree, is this crate's
//! contract.
//!
//! This matters because the alternative was to re-export the ~717 items that
//! carried `pub(crate)` inside `ferrogate-cli`. `pub(crate)` there meant
//! "anything in a 150k-line crate may touch this", which is not a decision;
//! copying it across the boundary would have published that non-decision as an
//! API. A name that leaves the list is a name no consumer needs -- deleting
//! one is a legitimate follow-up, and the list is short enough to audit.

mod caddyfile;
mod config;
mod diagnostic;
mod loader;
mod types;
mod x402;
mod x402_scope;

pub use caddyfile::parse_caddyfile;
/// `asset_bucket.endpoint` decomposition, shared by the load-time R2 guards
/// here and the runtime SigV4 signer in `ferrogate-cli` -- one decomposition,
/// which is the invariant #485 bought.
pub use config::asset_endpoint::{
    endpoint_targets_r2, parse_endpoint, parse_r2_endpoint, EndpointParts, R2Endpoint,
    R2_ENDPOINT_SUFFIX, R2_REGION,
};
/// The `[network_access]` section's enforcement primitives. `IpCidr::parse` is
/// what makes `ip_allowlist` a load-time error rather than a runtime surprise;
/// the client-IP resolution and the unauthenticated rate limiter travelled with
/// it because they share the module and its tests (see the crate note in the
/// #553 stage 3a commit -- they belong with the data plane, not here).
///
/// **Open, and named so #560 does not inherit it silently:** this is
/// `ferrogate-config` -- a crate everything else depends on -- exporting
/// *data-plane rate-limiting* primitives as `pub`. `pub` is currently the
/// minimum: each of these three has a cross-crate reader, so the visibility is
/// mechanically forced, not chosen. But the placement is not forced, and the
/// #553 stage-3a note conceded as much. `resolve_client_ip` and
/// `UnauthenticatedIpRateLimiter` decide things about live traffic; the crate
/// they sit in is supposed to decide only what a config file means. Whoever
/// takes #560's decomposition should move them out with the data plane rather
/// than treat their presence here as settled by precedent.
///
/// The same is true of `build_target_uri` and `normalize_host` below -- see
/// the note there. Both lists are one finding, and #560 inherits five names,
/// not three.
pub use config::network_access::{resolve_client_ip, IpCidr, UnauthenticatedIpRateLimiter};
/// Upstream-endpoint parsing and route-rule path rewriting: the inherent impls
/// on [`Config`]'s own `RouteRule`, so they cannot live anywhere else.
///
/// **`build_target_uri` and `normalize_host` are the other half of the
/// data-plane leak noted above, and the clearer half.** `parse_upstream_endpoint`
/// and `UpstreamEndpoint` genuinely belong here -- an `upstream` that will not
/// parse is a config error and this crate is where config errors are decided.
/// The other two are not consulted anywhere in the load or validate path: the
/// only caller of `build_target_uri` inside this crate is `#[cfg(test)]`, and
/// every production reader of both is in `ferrogate-gateway`'s
/// `server::handlers` and `server::site_domains`, i.e. on the per-request path.
/// They are here because `RouteRule` is here, which is a fact about where the
/// *type* lives, not an argument that per-request URI construction belongs in
/// the configuration crate. #560 should move them with the data plane.
pub use config::routing::{
    build_target_uri, normalize_host, parse_upstream_endpoint, UpstreamEndpoint,
};
/// Ed25519 signing/verification of a cluster config snapshot: the five items
/// `ferrogate-cli`'s control-plane state actually publishes and ingests. The
/// module holds 45 `pub` items after the move; exporting the module itself
/// would have published all of them.
pub use config::signed_snapshot::{
    build_snapshot_crypto, SignedSnapshotEnvelope, SignedSnapshotPayload, SnapshotCrypto,
    SnapshotSigner,
};
pub use config::{
    config_snapshot_id, resolve_env_placeholders, x402_hold_ttl_floor_secs, AccessLogMode,
    AgentRuntimeConfig, AgentRuntimeExternalConfig, AgentRuntimeManagedWorkerConfig,
    AgentRuntimeProvider, AgentUpstreamAuth, AgentUpstreamCapability, AgentUpstreamConfig,
    AgentUpstreamProtocol, AgentWorkflowEdge, AgentWorkflowNode, AgentWorkflowNodeKind,
    AgentWorkflowPolicy, AnalyticsConfig, AnalyticsProvider, ApiKey, AssetBucketBackend,
    AssetBucketConfig, AssetLifecycleConfig, AuthServiceConfig, BillingAlertsConfig,
    BillingServiceConfig, CacheMode, CanaryRoute, CloudflareConfig, ClusterSnapshotKey, Config,
    ExtensionConfig, ExtensionKind, ExtensionPermissions, GatewayConfigProfile, GuardrailEffect,
    GuardrailProviderErrorMode, GuardrailProviderKind, GuardrailProviderRuntimeConfig,
    GuardrailRule, GuardrailStage, HeaderMatcher, HeaderMutation, LimitsConfig,
    ManagedWorkerCapabilityActionConfig, ManagedWorkerCapabilityTargetGrantConfig, McpServerConfig,
    MeteringConfig, MeteringExportProvider, MeteringExportSubject, Model, ModelFallback,
    ObservabilityProvider, PluginCompatibility, PluginConfig, PluginManifest, PolicyRule,
    PromptTemplate, PromptTemplateMessage, PromptTemplateStatus, PromptTemplateTarget,
    PromptTemplateVariable, PromptTemplateVersion, PromptTemplateVersionStatus, Provider,
    ProviderCloudflareAiGatewayConfig, ProviderCloudflareAiGatewayMode, ReliabilityConfig,
    RouteRule, ShadowRoute, SkillPackage, SkillPackageCapability, SkillPackageCapabilityKind,
    SkillPackageCompatibility, SkillPackageResources, StorageConfig, StorageMigrationMode,
    TelemetryConfig, TenancyConfig, TlsAcmeConfig, TlsConfig, Upstream, X402ReconcilerConfig,
    X402SweeperConfig, ASSET_PRESIGN_MAX_TTL_SECS, ASSET_PRESIGN_MIN_TTL_SECS,
    ASSET_PRESIGN_SINGLE_PUT_MAX_OBJECT_BYTES,
};
pub use diagnostic::CaddyfileDiagnostic;
pub use ferrogate_providers::ModelCapability;
pub use loader::{is_caddyfile_path, load_caddyfile};
pub use types::{
    GatewayApiKey, GatewayConfig, GatewayHeader, GatewayLog, GatewayModel, GatewayProvider,
    GatewayRoute, GatewayTlsAcmeConfig, GatewayTlsConfig, GatewayUpstream, StaticResponse,
};
pub use x402::{
    default_x402_spend_policy, load_x402_spend_policy_toml, AllowedAsset, ApprovalPolicy,
    ConversionRule, PolicyNetwork, ResourceRule, Rounding, ValidatedX402SpendPolicy,
    X402ConfigError, X402PolicyConfigError, X402SpendCaps, X402SpendPolicy, X402SpendPolicyConfig,
};
pub use x402_scope::{
    normalize_x402_scope_id, resolve_effective_x402_spend_policy,
    validate_scoped_x402_spend_policies, EffectiveX402SpendPolicy, X402PolicyScopeKind,
    X402PolicyScopeRef, X402ScopeChain, X402ScopedPolicyError, X402ScopedSpendPolicy,
};
