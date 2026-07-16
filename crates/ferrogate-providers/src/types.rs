// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use ferrogate_core::{ToolCall, ToolDef, ToolResult};
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub openrouter_http_referer: Option<String>,
    pub openrouter_x_title: Option<String>,
    /// AWS SigV4 credentials for the `bedrock` adapter (issue #172) --
    /// unused by every other adapter, which authenticate via `api_key`
    /// instead. `None` for a Bedrock provider means the adapter fails
    /// closed at request-preparation time rather than silently sending an
    /// unsigned (and therefore rejected) request.
    pub aws_credentials: Option<AwsProviderCredentials>,
    /// GCP OAuth2 access token plus project/location for the `vertex`
    /// adapter (issue #172). `None` for a Vertex provider means the
    /// adapter fails closed the same way a missing `aws_credentials` does
    /// for Bedrock.
    pub gcp_credentials: Option<GcpProviderCredentials>,
}

/// AWS access-key credentials plus the region a Bedrock provider targets
/// (issue #172). `session_token` is present only for temporary/STS
/// credentials; long-lived IAM user access keys omit it. The secret
/// fields use [`SecretValue`] so an accidental `{:?}` of a
/// [`ProviderConfig`] (or anything embedding it) can never leak them,
/// mirroring how [`ProviderHeader`] already protects header values.
#[derive(Clone, PartialEq, Eq)]
pub struct AwsProviderCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretValue,
    pub session_token: Option<SecretValue>,
    pub region: String,
}

impl fmt::Debug for AwsProviderCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsProviderCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &self.secret_access_key)
            .field("session_token", &self.session_token)
            .field("region", &self.region)
            .finish()
    }
}

/// A pre-minted GCP OAuth2 access token (scope
/// `https://www.googleapis.com/auth/cloud-platform`) plus the project and
/// location a Vertex AI provider targets (issue #172). Deliberately does
/// NOT implement the service-account JWT-bearer token-minting flow
/// in-crate: `ProviderAdapter::prepare_chat_completions` is a synchronous
/// method (see `types.rs`), and minting a token requires a real network
/// round trip to `oauth2.googleapis.com`, which can't be done there
/// without blocking a pingora worker thread. Operators supply an
/// already-valid access token instead (refreshed by an external process,
/// e.g. `gcloud auth application-default print-access-token` on a cron,
/// or a sidecar that implements the full ADC flow) -- the same
/// externally-resolved-credential shape `aws_credentials` already uses,
/// just for a bearer token instead of a signing key.
#[derive(Clone, PartialEq, Eq)]
pub struct GcpProviderCredentials {
    pub access_token: SecretValue,
    pub project_id: String,
    pub location: String,
}

impl fmt::Debug for GcpProviderCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpProviderCredentials")
            .field("access_token", &self.access_token)
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatCompletionPlan {
    pub logical_model: String,
    pub provider_model: String,
    pub stream: bool,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponsesPlan {
    pub logical_model: String,
    pub provider_model: String,
    pub stream: bool,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingsPlan {
    pub logical_model: String,
    pub provider_model: String,
    pub body: Value,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHeader {
    pub name: String,
    pub value: SecretValue,
}

#[derive(Clone, PartialEq)]
pub struct ProviderHttpRequest {
    pub provider: String,
    pub endpoint: String,
    pub body: Value,
    pub stream: bool,
    pub headers: Vec<ProviderHeader>,
}

impl fmt::Debug for ProviderHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpRequest")
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("body", &self.body)
            .field("stream", &self.stream)
            .field("headers", &self.headers)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct ProviderCatalogRequest {
    pub provider: String,
    pub endpoint: String,
    pub headers: Vec<ProviderHeader>,
}

impl fmt::Debug for ProviderCatalogRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCatalogRequest")
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("headers", &self.headers)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    UnsupportedProviderKind { kind: String },
    InvalidRequest { message: String },
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProviderKind { kind } => {
                write!(formatter, "unsupported provider kind {kind}")
            }
            Self::InvalidRequest { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AdapterError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProviderAdapterFamily {
    OpenAiCompatible,
    Anthropic,
    Gemini,
    Grok,
    OpenRouter,
    AzureOpenAi,
    Bedrock,
    Vertex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderAdapterFamilyDescriptor {
    pub family: ProviderAdapterFamily,
    pub canonical_kind: &'static str,
    pub aliases: &'static [&'static str],
}

pub const SUPPORTED_PROVIDER_ADAPTER_FAMILIES: &[ProviderAdapterFamilyDescriptor] = &[
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::OpenAiCompatible,
        canonical_kind: "openai-compatible",
        aliases: &[
            "openai",
            "deepseek",
            "newapi",
            "sub2api",
            "cliproxyapi",
            "cli-proxy-api",
            "vllm",
            "llama.cpp",
            "llama-cpp",
            "llamacpp",
            "tgi",
            "ollama",
            "ollama-compatible",
        ],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::Anthropic,
        canonical_kind: "anthropic",
        aliases: &[],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::Gemini,
        canonical_kind: "gemini",
        aliases: &[],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::Grok,
        canonical_kind: "grok",
        aliases: &["xai"],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::OpenRouter,
        canonical_kind: "openrouter",
        aliases: &[],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::AzureOpenAi,
        canonical_kind: "azure-openai",
        aliases: &["azure"],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::Bedrock,
        canonical_kind: "bedrock",
        aliases: &["aws-bedrock"],
    },
    ProviderAdapterFamilyDescriptor {
        family: ProviderAdapterFamily::Vertex,
        canonical_kind: "vertex",
        aliases: &["vertex-ai"],
    },
];

pub fn canonical_provider_adapter_family(kind: &str) -> Option<ProviderAdapterFamily> {
    let kind = kind.trim();
    SUPPORTED_PROVIDER_ADAPTER_FAMILIES
        .iter()
        .find(|descriptor| {
            descriptor.canonical_kind.eq_ignore_ascii_case(kind)
                || descriptor
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(kind))
        })
        .map(|descriptor| descriptor.family)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderErrorResponse {
    pub status: u16,
    pub body: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderCatalogModel {
    pub id: String,
    pub owned_by: Option<String>,
    pub created: Option<u64>,
    pub context_window: Option<u64>,
    pub capabilities: Vec<String>,
}

pub fn is_openai_compatible_provider_kind(kind: &str) -> bool {
    canonical_provider_adapter_family(kind) == Some(ProviderAdapterFamily::OpenAiCompatible)
}

pub fn provider_compatibility_kind(kind: &str) -> &'static str {
    if is_openai_compatible_provider_kind(kind) {
        "openai-compatible"
    } else {
        "dedicated"
    }
}

pub trait ProviderAdapter: Send + Sync {
    fn kind(&self) -> &'static str;

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError>;

    fn prepare_responses(
        &self,
        _provider: ProviderConfig,
        _request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn prepare_embeddings(
        &self,
        _provider: ProviderConfig,
        _request: EmbeddingsPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn prepare_model_catalog(
        &self,
        _provider: ProviderConfig,
    ) -> Result<ProviderCatalogRequest, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn parse_model_catalog(&self, _body: &[u8]) -> Result<Vec<ProviderCatalogModel>, AdapterError> {
        Err(AdapterError::UnsupportedProviderKind {
            kind: self.kind().to_string(),
        })
    }

    fn normalize_error_response(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> ProviderErrorResponse;

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage>;

    fn inject_tools(&self, body: Value, _tools: &[ToolDef]) -> Result<Value, AdapterError> {
        Ok(body)
    }

    fn extract_tool_calls(&self, _body: &[u8]) -> Result<Vec<ToolCall>, AdapterError> {
        Ok(Vec::new())
    }

    fn append_tool_results(
        &self,
        body: Value,
        _results: &[ToolResult],
    ) -> Result<Value, AdapterError> {
        Ok(body)
    }

    fn is_retryable_status(&self, status: u16) -> bool {
        status == 429 || (500..=599).contains(&status)
    }
}
