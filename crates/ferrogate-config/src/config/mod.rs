// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The gateway's own configuration: the operator-facing model, its loader and
//! its validation (#553 stage 3a).
//!
//! This tree used to be `ferrogate-cli/src/config/`. It is the larger and more
//! central half of what this crate is named after; the Caddyfile compatibility
//! layer next door is the smaller half. Nothing in it changed in the move --
//! see the crate docs for how its public surface is decided.

pub mod asset_endpoint;
mod loader;
pub mod network_access;
mod provider;
pub mod routing;
#[cfg(test)]
mod routing_tests;
mod secrets;
#[cfg(test)]
mod serde_tests;
pub mod signed_snapshot;
mod snapshot;
#[cfg(test)]
mod tests;
mod types;
mod upstream;
mod validate;
#[cfg(test)]
mod validation_tests;

#[allow(unused_imports)]
pub use self::secrets::resolve_env_placeholders;
#[allow(unused_imports)]
pub use self::snapshot::config_snapshot_id;
/// The one x402 hold-TTL money-safety floor (issues #400/#401), shared by the
/// config-load validation and the runtime clamp in `X402SettlementLoop::open`.
#[allow(unused_imports)]
pub use self::types::x402_hold_ttl_floor_secs;
#[allow(unused_imports)]
pub use self::types::{
    AccessLogMode, AdminApiConfig, AdminConfig, AgentRuntimeConfig, AgentRuntimeExternalConfig,
    AgentRuntimeManagedWorkerConfig, AgentRuntimeProvider, AgentUpstreamAuth,
    AgentUpstreamCapability, AgentUpstreamConfig, AgentUpstreamProtocol, AgentWorkflowEdge,
    AgentWorkflowNode, AgentWorkflowNodeKind, AgentWorkflowPolicy, AnalyticsConfig,
    AnalyticsProvider, ApiKey, AssetBucketBackend, AssetBucketConfig, AssetLifecycleConfig,
    AuthConfig, AuthServiceConfig, BillingAlertsConfig, BillingServiceConfig, CacheConfig,
    CacheMode, CanaryRoute, CloudflareConfig, ClusterConfig, ClusterSnapshotKey, Config,
    ExtensionConfig, ExtensionKind, ExtensionPermissions, GatewayConfigProfile, GuardrailEffect,
    GuardrailProviderErrorMode, GuardrailProviderKind, GuardrailProviderRuntimeConfig,
    GuardrailRule, GuardrailStage, HeaderMatcher, HeaderMutation, LimitsConfig,
    ManagedWorkerCapabilityActionConfig, ManagedWorkerCapabilityTargetGrantConfig, McpAuthType,
    McpHeaderConfig, McpOauthConfig, McpServerConfig, McpTlsConfig, McpTransport, MeteringConfig,
    MeteringExportProvider, MeteringExportSubject, Model, ModelFallback, NetworkAccessConfig,
    ObservabilityConfig, ObservabilityProvider, PluginCompatibility, PluginConfig, PluginManifest,
    PolicyRule, PromptTemplate, PromptTemplateMessage, PromptTemplateStatus, PromptTemplateTarget,
    PromptTemplateVariable, PromptTemplateVersion, PromptTemplateVersionStatus, Provider,
    ProviderCloudflareAiGatewayConfig, ProviderCloudflareAiGatewayMode, ReliabilityConfig,
    RouteRule, SchedulerConfig, ShadowRoute, SkillPackage, SkillPackageCapability,
    SkillPackageCapabilityKind, SkillPackageCompatibility, SkillPackageResources, StaticSitePublishBackend,
    StaticSitePublishConfig, StorageConfig, StorageMigrationMode, TelemetryConfig, TenancyConfig,
    TlsAcmeConfig, TlsConfig, Upstream, X402ReconcilerConfig, X402SweeperConfig,
};
