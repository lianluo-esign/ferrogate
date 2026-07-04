// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::mocks::{MockBillingServer, MockOtlpServer};
use std::path::Path;

pub(crate) struct LocalGatewayConfig<'a> {
    pub(crate) gateway_addr: &'a str,
    pub(crate) provider_addr: &'a str,
    pub(crate) mcp_addr: &'a str,
    pub(crate) agent_addr: &'a str,
    pub(crate) stdio_mcp_path: &'a Path,
    pub(crate) billing: Option<&'a MockBillingServer>,
    pub(crate) observability: Option<&'a MockOtlpServer>,
    pub(crate) auth_addr: Option<&'a str>,
    /// Address of a running `ferrogate billing serve` process. When set, the
    /// gateway reports settled usage to it over REST (issue #131).
    pub(crate) billing_service_addr: Option<&'a str>,
}

pub(crate) fn local_gateway_config(config: LocalGatewayConfig<'_>) -> String {
    let metering = config
        .billing
        .map(|billing| {
            format!(
                r#"
[metering]
export_enabled = true
export_provider = "openmeter"
export_endpoint = "http://{}/api/v1/events"
export_token = "test-metering-token"
export_timeout_secs = 3
export_event_type = "ai.tokens"
export_source = "ferrogate-test"
export_subject = "api_key_id"
"#,
                billing.addr
            )
        })
        .unwrap_or_default();
    let observability = config
        .observability
        .map(|observability| {
            format!(
                r#"
[observability]
enabled = true
provider = "vector"
otlp_endpoint = "http://{}"
prometheus_metrics_path = "/metrics"
export_timeout_secs = 3
"#,
                observability.addr
            )
        })
        .unwrap_or_default();
    let auth_service = config
        .auth_addr
        .map(|auth_addr| {
            format!(
                r#"
[auth_service]
enabled = true
endpoint = "http://{auth_addr}"
timeout_millis = 1000
"#
            )
        })
        .unwrap_or_default();
    let billing_service = config
        .billing_service_addr
        .map(|billing_addr| {
            format!(
                r#"
[billing_service]
enabled = true
endpoint = "http://{billing_addr}"
timeout_millis = 2000
"#
            )
        })
        .unwrap_or_default();
    let gateway_addr = config.gateway_addr;
    let provider_addr = config.provider_addr;
    let mcp_addr = config.mcp_addr;
    let agent_addr = config.agent_addr;
    format!(
        r#"
listen = "{gateway_addr}"

[cluster]
enabled = true
cluster_id = "ferrogate-test-cluster"
node_id = "ferrogate-test-node"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"
{metering}
{observability}
{auth_service}
{billing_service}

[telemetry]
service_name = "ferrogate-test"
log_bodies = true

[reliability]
provider_circuit_breaker_failure_threshold = 1
provider_circuit_breaker_cooldown_secs = 60
provider_dispatch_timeout_secs = 3
provider_dispatch_max_retries = 0
mcp_dispatch_timeout_secs = 1
mcp_dispatch_max_concurrency = 4

[agent_runtime]
enabled = true
provider = "external"
max_turns = 3
timeout_millis = 5000

[agent_runtime.external]
command = "sh"
args = ["-c", "payload=$(cat); if printf '%s' \"$payload\" | grep -q '\"tool_result_count\":0'; then printf 'tool\tmock-tool-call\ttool.echo\t{{\"message\":\"from ferrogate-test\"}}\n'; else printf 'finish\t%s\n' \"$(printf '%s' \"$payload\" | sed -n 's/.*\"input\":\"\\([^\"]*\\)\".*/\\1/p')\"; fi"]
timeout_millis = 1000

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["tool.echo"]
network = []
filesystem = false
shell = false
tenant_scope = true

[extensions.config]
tenant_allowlist = ["org_demo"]

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[providers]]
name = "backup-openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[providers]]
name = "anthropic"
kind = "anthropic"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[mcp_servers]]
name = "http"
transport = "streamable_http"
url = "http://{mcp_addr}/mcp"
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
approval_policy = "never"
timeout_ms = 3000

[[mcp_servers]]
name = "stdio"
transport = "stdio"
command = "python3"
args = [{stdio_mcp_path}]
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
approval_policy = "never"
timeout_ms = 3000

[[agent_upstreams]]
id = "agent.echo"
name = "Agent Echo"
description = "Harness agent upstream"
enabled = true
protocol = "a2a"
endpoint = "http://{agent_addr}/a2a"
tenant_ids = ["client"]
capabilities = ["invoke", "read", "stream", "discover"]

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[models]]
name = "fallback-chat"
provider = "openai"
provider_model = "gpt-4o-mini-failover-primary"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[models.fallbacks]]
provider = "backup-openai"
provider_model = "gpt-4o-mini-fallback"
input_price_per_1m = 1.0
output_price_per_1m = 2.0
priority = 0
weight = 1

[[models]]
name = "blocked-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[models]]
name = "gpt-5.5-chat"
provider = "openai"
provider_model = "gpt-5.5"
capabilities = ["chat", "streaming"]
input_price_per_1m = 5.0
output_price_per_1m = 15.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions", "responses.create", "agent.runs.create", "admin.read", "agents.read", "agents.invoke", "tools.read", "tools.execute", "functions.execute"]
allowed_models = ["fast-chat", "fallback-chat", "gpt-5.5-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

[[api_keys]]
id = "observer"
name = "Observer"
key = "observer-secret"
scopes = ["tools.read", "tools.execute"]
organization_id = "org_observer"
project_id = "project_observer"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[gateway_configs]]
id = "static-profile"
name = "Static profile"
revision = 1
enabled = true
api_key_ids = ["client"]
cache_enabled = false
"#,
        stdio_mcp_path = toml_basic_string(&config.stdio_mcp_path.to_string_lossy())
    )
}

pub(crate) fn toml_basic_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub(crate) fn blocking_stdio_mcp_script() -> &'static str {
    r#"import json
import sys
import time

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "initialize":
        response["result"] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "blocking-stdio", "version": "1.0.0"},
        }
    elif method == "tools/list":
        response["result"] = {
            "tools": [
                {
                    "name": "search",
                    "description": "Blocking stdio search",
                    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                }
            ]
        }
    elif method == "tools/call":
        time.sleep(60)
        continue
    elif method == "ping":
        response["result"] = {}
    else:
        response["error"] = {"code": -32601, "message": "unsupported method"}
    print(json.dumps(response), flush=True)
"#
}

pub(crate) fn auth_service_config() -> String {
    r#"
tenants:
  - id: tenant-example
    name: Example tenant
    enabled: true
    context:
      organization_id: org-example
      team_id: team-example
      project_id: project-example
      user_id: null
      api_key_id: null
api_keys:
  - id: key-example
    name: Example gateway key
    secret: dev-secret
    enabled: true
    tenant:
      organization_id: org-example
      team_id: team-example
      project_id: project-example
      user_id: null
      api_key_id: key-example
    scopes:
      - models.read
      - chat.completions
  - id: client
    name: Gateway client key
    secret: client-secret
    enabled: true
    tenant:
      organization_id: org_demo
      team_id: null
      project_id: project_gateway
      user_id: null
      api_key_id: client
    scopes:
      - models.read
      - chat.completions
      - responses.create
roles:
  - id: role-chat-caller
    name: Chat caller
    permissions:
      - action: chat.completions
        resource: model:fast-chat
      - action: models.read
        resource: "*"
bindings:
  - id: binding-key-example-chat
    role_id: role-chat-caller
    tenant:
      organization_id: org-example
      team_id: team-example
      project_id: project-example
      user_id: null
      api_key_id: key-example
    subject:
      type: api_key
      api_key_id: key-example
  - id: binding-client-chat
    role_id: role-chat-caller
    tenant:
      organization_id: org_demo
      team_id: null
      project_id: project_gateway
      user_id: null
      api_key_id: client
    subject:
      type: api_key
      api_key_id: client
"#
    .to_string()
}

pub(crate) fn gateway_config(
    node_id: &str,
    state_backend: &str,
    file_state_path: Option<&str>,
) -> String {
    let file_state_path = file_state_path
        .map(|path| format!("file_state_path = \"{path}\"\n"))
        .unwrap_or_default();
    format!(
        r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "{node_id}"
node_region = "local"
node_zone = "local-a"
state_backend = "{state_backend}"
{file_state_path}counter_backend = "local"
heartbeat_interval_secs = 10
config_poll_interval_secs = 5

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    )
}

pub(crate) fn guardrail_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[guardrails]]
id = "block-secret"
name = "Block secret"
stage = "request"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
keywords = ["secret"]
effect = "deny"
code = "guardrail_blocked"
message = "blocked by guardrail"
enabled = true
"#
    .to_string()
}

pub(crate) fn guardrail_response_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[telemetry]
log_bodies = true

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[guardrails]]
id = "redact-provider-output"
name = "Redact provider output"
stage = "response"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
keywords = ["secret"]
effect = "redact"
code = "guardrail_redacted"
message = "response redacted by guardrail"
enabled = true
"#
    .to_string()
}

pub(crate) fn guardrail_complete_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[telemetry]
log_bodies = true

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[guardrails]]
id = "block-ticket-regex"
name = "Block ticket regex"
stage = "request"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
regex = ["ABC-[0-9]+"]
effect = "deny"
code = "guardrail_regex_blocked"
message = "blocked by regex guardrail"
enabled = true

[[guardrails]]
id = "limit-request-size"
name = "Limit request size"
stage = "request"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
max_input_bytes = 120
effect = "deny"
code = "guardrail_input_too_large"
message = "input is too large"
enabled = true

[[guardrails]]
id = "block-provider-output"
name = "Block provider output"
stage = "response"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
keywords = ["deny-output"]
effect = "deny"
code = "guardrail_response_blocked"
message = "response blocked by guardrail"
enabled = true

[[guardrails]]
id = "redact-stream-output"
name = "Redact stream output"
stage = "response"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
regex = ["stream-secret"]
effect = "redact"
code = "guardrail_stream_redacted"
message = "stream redacted by guardrail"
enabled = true
"#
    .to_string()
}

pub(crate) fn redis_counter_gateway_config(node_id: &str) -> String {
    format!(
        r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "{node_id}"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "redis"
redis_url = "redis://ferrogate-e2e-redis:6379/0"
counter_timeout_millis = 500
heartbeat_interval_secs = 10
config_poll_interval_secs = 5

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "redis_rate"
name = "Redis rate limit"
key = "redis-rate-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
request_limit_per_minute = 1

[[api_keys]]
id = "redis_budget"
name = "Redis budget"
key = "redis-budget-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
monthly_token_budget = 8

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    )
}

pub(crate) fn analytics_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[analytics]
enabled = true
provider = "vector"
required = true
vector_endpoint = "http://ferrogate-e2e-vector:4319"
export_timeout_secs = 3
batch_max_events = 256
flush_interval_millis = 500
queue_capacity = 1024

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    .to_string()
}

pub(crate) fn analytics_direct_clickhouse_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[analytics]
enabled = true
provider = "clickhouse"
required = true
clickhouse_url = "http://ferrogate-e2e-clickhouse:8123"
export_timeout_secs = 3
batch_max_events = 256
flush_interval_millis = 500
queue_capacity = 1024

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    .to_string()
}

pub(crate) fn vector_clickhouse_config() -> String {
    r#"
[sources.ferrogate_analytics]
type = "http_server"
address = "0.0.0.0:4319"
framing.method = "newline_delimited"
decoding.codec = "json"

[transforms.request_logs_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "request_log"'

[transforms.trace_spans_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "trace_span"'

[transforms.usage_metrics_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "usage_metric"'

[transforms.billing_metering_events_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "billing_metering_event"'

[transforms.audit_timeline_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "audit_event"'

[sinks.request_logs]
type = "clickhouse"
inputs = ["request_logs_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_request_logs"
format = "json_each_row"
skip_unknown_fields = true

[sinks.trace_spans]
type = "clickhouse"
inputs = ["trace_spans_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_trace_spans"
format = "json_each_row"
skip_unknown_fields = true

[sinks.usage_metrics]
type = "clickhouse"
inputs = ["usage_metrics_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_usage_metrics"
format = "json_each_row"
skip_unknown_fields = true

[sinks.billing_metering_events]
type = "clickhouse"
inputs = ["billing_metering_events_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_billing_metering_events"
format = "json_each_row"
skip_unknown_fields = true

[sinks.audit_timeline]
type = "clickhouse"
inputs = ["audit_timeline_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_audit_timeline"
format = "json_each_row"
skip_unknown_fields = true
"#
    .to_string()
}
