// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod loader;
mod provider;
mod secrets;
#[cfg(test)]
mod serde_tests;
pub(crate) mod signed_snapshot;
mod snapshot;
#[cfg(test)]
mod tests;
mod types;
mod upstream;
mod validate;
#[cfg(test)]
mod validation_tests;

#[allow(unused_imports)]
pub(crate) use self::secrets::resolve_env_placeholders;
#[allow(unused_imports)]
pub(crate) use self::snapshot::config_snapshot_id;
/// The one x402 hold-TTL money-safety floor (issues #400/#401), shared by the
/// config-load validation and the runtime clamp in `X402SettlementLoop::open`.
#[allow(unused_imports)]
pub(crate) use self::types::x402_hold_ttl_floor_secs;
#[allow(unused_imports)]
pub(crate) use self::types::{
    AccessLogMode, AdminApiConfig, AdminConfig, AgentRuntimeConfig, AgentRuntimeExternalConfig,
    AgentRuntimeManagedWorkerConfig, AgentRuntimeProvider, AgentUpstreamAuth,
    AgentUpstreamCapability, AgentUpstreamConfig, AgentUpstreamProtocol, AgentWorkflowEdge,
    AgentWorkflowNode, AgentWorkflowNodeKind, AgentWorkflowPolicy, AnalyticsConfig,
    AnalyticsProvider, ApiKey, AssetBucketBackend, AssetBucketConfig, AssetLifecycleConfig,
    AuthConfig, AuthServiceConfig, BillingAlertsConfig, BillingServiceConfig, CacheConfig, CacheMode,
    CanaryRoute, CloudflareConfig, ClusterConfig, ClusterSnapshotKey, Config, ExtensionConfig,
    ExtensionKind, ExtensionPermissions, GatewayConfigProfile, GuardrailEffect,
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
    SkillPackageCapabilityKind, SkillPackageCompatibility, SkillPackageResources, StorageConfig,
    StorageMigrationMode, TelemetryConfig, TenancyConfig, TlsAcmeConfig, TlsConfig, Upstream,
    X402ReconcilerConfig, X402SweeperConfig,
};
