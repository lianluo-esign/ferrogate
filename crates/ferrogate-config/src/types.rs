use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub listen: String,
    pub admin: Option<String>,
    pub upstreams: Vec<GatewayUpstream>,
    pub routes: Vec<GatewayRoute>,
    pub providers: Vec<GatewayProvider>,
    pub models: Vec<GatewayModel>,
    pub logs: Vec<GatewayLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayUpstream {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRoute {
    pub name: String,
    pub upstream: Option<String>,
    pub hosts: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub strip_prefix: Option<String>,
    pub request_headers: Vec<GatewayHeader>,
    pub response_headers: Vec<GatewayHeader>,
    pub static_response: Option<StaticResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticResponse {
    pub body: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayProvider {
    pub name: String,
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayModel {
    pub name: String,
    pub provider: String,
    pub provider_model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayLog {
    pub route: Option<String>,
}
