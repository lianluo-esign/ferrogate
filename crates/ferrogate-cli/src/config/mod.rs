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
#[allow(unused_imports)]
pub(crate) use self::types::{
    AccessLogMode, AdminConfig, AgentRuntimeConfig, AgentRuntimeExternalConfig,
    AgentRuntimeManagedWorkerConfig, AgentRuntimeProvider, AgentUpstreamAuth,
    AgentUpstreamCapability, AgentUpstreamConfig, AgentUpstreamProtocol, AgentWorkflowEdge,
    AgentWorkflowNode, AgentWorkflowNodeKind, AgentWorkflowPolicy, AnalyticsConfig,
    AnalyticsProvider, ApiKey, AssetBucketConfig, AssetLifecycleConfig, AuthServiceConfig,
    BillingAlertsConfig, BillingServiceConfig, CacheConfig, CacheMode, CanaryRoute, ClusterConfig,
    ClusterSnapshotKey, Config, ExtensionConfig, ExtensionKind, ExtensionPermissions,
    GatewayConfigProfile, GuardrailEffect, GuardrailProviderErrorMode, GuardrailProviderKind,
    GuardrailProviderRuntimeConfig, GuardrailRule, GuardrailStage, HeaderMatcher, HeaderMutation,
    LimitsConfig, ManagedWorkerCapabilityActionConfig, ManagedWorkerCapabilityTargetGrantConfig,
    McpAuthType, McpHeaderConfig, McpOauthConfig, McpServerConfig, McpTlsConfig, McpTransport,
    MeteringConfig, MeteringExportProvider, MeteringExportSubject, Model, ModelFallback,
    NetworkAccessConfig, ObservabilityConfig, ObservabilityProvider, PluginCompatibility,
    PluginConfig, PluginManifest, PolicyRule, PromptTemplate, PromptTemplateMessage,
    PromptTemplateStatus, PromptTemplateTarget, PromptTemplateVariable, PromptTemplateVersion,
    PromptTemplateVersionStatus, Provider, ReliabilityConfig, RouteRule, SchedulerConfig,
    ShadowRoute, SkillPackage, SkillPackageCapability, SkillPackageCapabilityKind,
    SkillPackageCompatibility, SkillPackageResources, StorageConfig, StorageMigrationMode,
    TelemetryConfig, TlsAcmeConfig, TlsConfig, Upstream,
};
