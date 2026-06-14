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
    AccessLogMode, AdminConfig, ApiKey, CacheConfig, CacheMode, ClusterConfig, Config,
    ExtensionConfig, ExtensionKind, ExtensionPermissions, GatewayConfigProfile, GuardrailEffect,
    GuardrailRule, GuardrailStage, HeaderMatcher, HeaderMutation, McpAuthType, McpHeaderConfig,
    McpServerConfig, McpTlsConfig, McpTransport, MeteringConfig, MeteringExportProvider,
    MeteringExportSubject, Model, ModelFallback, ObservabilityConfig, ObservabilityProvider,
    PolicyRule, PromptTemplate, PromptTemplateMessage, PromptTemplateStatus, PromptTemplateTarget,
    PromptTemplateVariable, PromptTemplateVersion, PromptTemplateVersionStatus, Provider,
    ReliabilityConfig, RouteRule, StorageConfig, TelemetryConfig, TlsAcmeConfig, TlsConfig,
    Upstream,
};
