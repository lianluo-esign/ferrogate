/**
 * The REST of `Config::validate()` — every ported rule that no other suite
 * exercised.
 *
 * Why a whole extra file: an audit of `crates/ferrogate-config/src/config/validate.rs`
 * against this package's expectations found 393 distinct `field <path>: <reason>`
 * rules in the Rust gate, of which ~150 had NO test asserting them. Roughly a
 * third of those are the `validate_tls` / `validate_acme_*` family, which is
 * deliberately NOT ported (Cloudflare terminates TLS in front of the Worker —
 * see the header of `src/validate/sections.ts`); the rest were implemented,
 * reachable, and completely unheld. A rule with no assertion is exactly the
 * failure mode this repo keeps being bitten by: correct code that could be
 * deleted without a single suite going red.
 *
 * Every case asserts the EXACT message, because a validator's identity is the
 * pair (field path, reason) — the field path is what tells an operator which
 * line to edit, and `toThrow()` alone would still pass if a rule fired on the
 * wrong field, or if some EARLIER rule fired instead and masked it.
 */
import { describe, expect, test } from "vitest";
import { configSchema } from "../src/schema/config.js";
import { validateConfig } from "../src/validate.js";

/** Run the real gate and return the first error message, or fail loudly. */
function firstError(raw: Record<string, unknown>): string {
  const config = configSchema.parse(raw);
  try {
    validateConfig(config);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected validateConfig to reject this config, but it passed");
}

type Case = [string, Record<string, unknown>, string];

const provider = (extra: Record<string, unknown> = {}) => ({
  name: "openai",
  base_url: "https://api.openai.com/v1",
  ...extra,
});
const model = (extra: Record<string, unknown> = {}) => ({
  name: "gpt",
  provider: "openai",
  provider_model: "gpt-4o",
  ...extra,
});
const apiKey = (extra: Record<string, unknown> = {}) => ({
  id: "k1",
  name: "k1",
  key_env: "K1",
  platform_operator: true,
  ...extra,
});

/** A minimal one-provider/one-model config the entity validators accept. */
const withModel = (extra: Record<string, unknown> = {}) => ({
  providers: [provider()],
  models: [model()],
  ...extra,
});

describe("Config::validate() root", () => {
  test("an unparsable admin.listen is attributed to admin.listen, not listen", () => {
    expect(firstError({ admin: { listen: "not-an-addr" } })).toBe(
      "field admin.listen: invalid admin listen address not-an-addr",
    );
  });
});

describe("validate_providers — the optional-but-set string legs", () => {
  const cases: Case[] = [
    [
      "an empty openrouter_http_referer",
      { providers: [provider({ openrouter_http_referer: "" })] },
      "field providers[0].openrouter_http_referer: cannot be empty",
    ],
    [
      "an empty openrouter_x_title",
      { providers: [provider({ openrouter_x_title: "" })] },
      "field providers[0].openrouter_x_title: cannot be empty",
    ],
    [
      "an empty region on a non-bedrock provider",
      { providers: [provider({ region: "" })] },
      "field providers[0].region: cannot be empty",
    ],
    [
      "an empty aws_access_key_id",
      { providers: [provider({ aws_access_key_id: "" })] },
      "field providers[0].aws_access_key_id: cannot be empty",
    ],
    [
      "an empty aws_secret_access_key_env",
      { providers: [provider({ aws_secret_access_key_env: "" })] },
      "field providers[0].aws_secret_access_key_env: cannot be empty",
    ],
    [
      "an empty aws_session_token_env",
      { providers: [provider({ aws_session_token_env: "" })] },
      "field providers[0].aws_session_token_env: cannot be empty",
    ],
    [
      "bedrock without a secret access key env",
      {
        providers: [provider({ kind: "bedrock", aws_access_key_id: "A", region: "us-east-1" })],
      },
      "field providers[0].aws_secret_access_key_env: required when kind = bedrock",
    ],
    [
      "an empty gcp_project_id",
      { providers: [provider({ gcp_project_id: "" })] },
      "field providers[0].gcp_project_id: cannot be empty",
    ],
    [
      "an empty gcp_access_token_env",
      { providers: [provider({ gcp_access_token_env: "" })] },
      "field providers[0].gcp_access_token_env: cannot be empty",
    ],
    [
      "vertex without an access token env",
      {
        providers: [provider({ kind: "vertex", gcp_project_id: "p", region: "us-central1" })],
      },
      "field providers[0].gcp_access_token_env: required when kind = vertex",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_models — fallback, canary and shadow routes", () => {
  const cases: Case[] = [
    [
      "a blank fallback provider_model",
      {
        providers: [provider()],
        models: [
          model({ fallbacks: [{ provider: "openai", provider_model: " ", enabled: true }] }),
        ],
      },
      "field models[0].fallbacks[0].provider_model: cannot be empty",
    ],
    [
      "a lowest_cost fallback with no price",
      {
        providers: [provider()],
        models: [
          model({
            routing_strategy: "lowest_cost",
            input_price_per_1m: 1,
            output_price_per_1m: 2,
            fallbacks: [{ provider: "openai", provider_model: "gpt-4o-mini", enabled: true }],
          }),
        ],
      },
      "field models[0].fallbacks[0]: lowest_cost requires input_price_per_1m and output_price_per_1m",
    ],
    [
      "a priced-model + unpriced-fallback pair under billing_service",
      {
        billing_service: { enabled: true },
        providers: [provider()],
        models: [
          model({
            input_price_per_1m: 1,
            output_price_per_1m: 2,
            fallbacks: [{ provider: "openai", provider_model: "gpt-4o-mini", enabled: true }],
          }),
        ],
      },
      "field models[0].fallbacks[0]: billing_service.enabled requires input_price_per_1m and " +
        "output_price_per_1m on every fallback route",
    ],
    [
      "a canary route on an unknown provider",
      {
        providers: [provider()],
        models: [model({ canary: { provider: "ghost", provider_model: "gpt-4o", percent: 5 } })],
      },
      "field models[0].canary.provider: model gpt references unknown canary provider ghost",
    ],
    [
      "a blank canary provider_model",
      {
        providers: [provider()],
        models: [model({ canary: { provider: "openai", provider_model: " ", percent: 5 } })],
      },
      "field models[0].canary.provider_model: cannot be empty",
    ],
    [
      "a blank shadow provider_model",
      {
        providers: [provider()],
        models: [model({ shadow: { provider: "openai", provider_model: "", sample_percent: 5 } })],
      },
      "field models[0].shadow.provider_model: cannot be empty",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_api_keys — credential shape and cross-references", () => {
  const cases: Case[] = [
    [
      "an empty key_env",
      { api_keys: [apiKey({ key_env: "" })] },
      "field api_keys[0].key_env: cannot be empty",
    ],
    [
      "an empty inline key",
      { api_keys: [apiKey({ key_env: null, key: "" })] },
      "field api_keys[0].key: cannot be empty",
    ],
    [
      "an empty key_hash",
      { api_keys: [apiKey({ key_env: null, key_hash: "" })] },
      "field api_keys[0].key_hash: cannot be empty",
    ],
    [
      "a denied model that does not exist",
      {
        ...withModel(),
        api_keys: [apiKey({ denied_models: ["ghost"] })],
      },
      "field api_keys[0].denied_models: api key k1 denies unknown model ghost",
    ],
    [
      "an allowed provider that does not exist",
      {
        ...withModel(),
        api_keys: [apiKey({ allowed_providers: ["ghost"] })],
      },
      "field api_keys[0].allowed_providers: api key k1 allows unknown provider ghost",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_policies + validate_gateway_configs", () => {
  const cases: Case[] = [
    [
      "a policy naming an unknown provider",
      {
        ...withModel(),
        policies: [{ name: "p1", effect: "deny", providers: ["ghost"] }],
      },
      "field policies[0].providers: policy p1 references unknown provider ghost",
    ],
    [
      "a blank gateway config id",
      { gateway_configs: [{ id: " ", name: "profile" }] },
      "field gateway_configs[0].id: cannot be empty",
    ],
    [
      "a duplicate gateway config id",
      {
        gateway_configs: [
          { id: "g1", name: "a", cache_enabled: true },
          { id: "g1", name: "b", cache_enabled: true },
        ],
      },
      "field gateway_configs[1].id: duplicate gateway config id g1",
    ],
    [
      "a blank gateway config name",
      { gateway_configs: [{ id: "g1", name: "  ", cache_enabled: true }] },
      "field gateway_configs[0].name: cannot be empty",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_agent_workflows — the positive-optional budget knobs", () => {
  const workflow = (extra: Record<string, unknown> = {}) => ({
    id: "w1",
    name: "w1",
    version: 1,
    nodes: [{ id: "n1", kind: "checkpoint" }],
    ...extra,
  });
  const cases: Case[] = [
    [
      "a blank workflow name",
      { agent_workflows: [workflow({ name: " " })] },
      "field agent_workflows[0].name: cannot be empty",
    ],
    [
      "a zero max_model_calls",
      { agent_workflows: [workflow({ max_model_calls: 0 })] },
      "field agent_workflows[0].max_model_calls: must be greater than zero",
    ],
    [
      "a zero max_tool_calls",
      { agent_workflows: [workflow({ max_tool_calls: 0 })] },
      "field agent_workflows[0].max_tool_calls: must be greater than zero",
    ],
    [
      "a zero max_parallelism",
      { agent_workflows: [workflow({ max_parallelism: 0 })] },
      "field agent_workflows[0].max_parallelism: must be greater than zero",
    ],
    [
      "a zero max_iterations",
      { agent_workflows: [workflow({ max_iterations: 0 })] },
      "field agent_workflows[0].max_iterations: must be greater than zero",
    ],
    [
      "a zero timeout_millis",
      { agent_workflows: [workflow({ timeout_millis: 0 })] },
      "field agent_workflows[0].timeout_millis: must be greater than zero",
    ],
    [
      "a zero token_budget",
      { agent_workflows: [workflow({ token_budget: 0 })] },
      "field agent_workflows[0].token_budget: must be greater than zero",
    ],
    [
      "a blank node id",
      { agent_workflows: [workflow({ nodes: [{ id: " ", kind: "checkpoint" }] })] },
      "field agent_workflows[0].nodes[0].id: cannot be empty",
    ],
    [
      "a model node with no model",
      { agent_workflows: [workflow({ nodes: [{ id: "n1", kind: "model", model: " " }] })] },
      "field agent_workflows[0].nodes[0].model: cannot be empty",
    ],
    [
      "a tool node with a blank tool",
      { agent_workflows: [workflow({ nodes: [{ id: "n1", kind: "tool", tool: " " }] })] },
      "field agent_workflows[0].nodes[0].tool: cannot be empty",
    ],
    [
      "a model node with a blank provider name",
      {
        ...withModel(),
        agent_workflows: [
          workflow({ nodes: [{ id: "n1", kind: "model", model: "gpt", providers: [" "] }] }),
        ],
      },
      "field agent_workflows[0].nodes[0].providers: provider names cannot be empty",
    ],
    [
      "a zero node max_iterations",
      {
        agent_workflows: [
          workflow({ nodes: [{ id: "n1", kind: "checkpoint", max_iterations: 0 }] }),
        ],
      },
      "field agent_workflows[0].nodes[0].max_iterations: must be greater than zero",
    ],
    [
      "a zero node token_budget",
      {
        agent_workflows: [workflow({ nodes: [{ id: "n1", kind: "checkpoint", token_budget: 0 }] })],
      },
      "field agent_workflows[0].nodes[0].token_budget: must be greater than zero",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_prompt_templates + validate_skill_packages identity legs", () => {
  const template = (extra: Record<string, unknown> = {}) => ({
    id: "t1",
    name: "t",
    model: "gpt",
    versions: [{ revision: 1, messages: [{ role: "user", content: "hi" }] }],
    ...extra,
  });
  const cases: Case[] = [
    [
      "a blank prompt template id",
      { prompt_templates: [template({ id: " " })] },
      "field prompt_templates[0].id: cannot be empty",
    ],
    [
      "a blank prompt template name",
      { prompt_templates: [template({ name: " " })] },
      "field prompt_templates[0].name: cannot be empty",
    ],
    [
      "a blank prompt template model",
      { prompt_templates: [template({ model: "  " })] },
      "field prompt_templates[0].model: cannot be empty",
    ],
    [
      "a blank prompt template variable name",
      {
        ...withModel(),
        prompt_templates: [
          {
            id: "t1",
            name: "t",
            model: "gpt",
            variables: [{ name: " " }],
            versions: [{ revision: 1, messages: [{ role: "user", content: "hi" }] }],
          },
        ],
      },
      "field prompt_templates[0].variables[0].name: cannot be empty",
    ],
    [
      "a blank skill package id",
      { skill_packages: [{ id: " ", name: "p", version: "1.0.0" }] },
      "field skill_packages[0].id: cannot be empty",
    ],
    [
      "a blank skill package name",
      { skill_packages: [{ id: "p1", name: " ", version: "1.0.0" }] },
      "field skill_packages[0].name: cannot be empty",
    ],
    [
      "a blank capability id",
      {
        skill_packages: [
          {
            id: "p1",
            name: "p",
            version: "1.0.0",
            capabilities: [{ id: " ", kind: "plugin" }],
          },
        ],
      },
      "field skill_packages[0].capabilities[0].id: cannot be empty",
    ],
    [
      "an mcp_server capability naming no known server",
      {
        skill_packages: [
          {
            id: "p1",
            name: "p",
            version: "1.0.0",
            capabilities: [{ id: "ghost", kind: "mcp_server" }],
          },
        ],
      },
      "field skill_packages[0].capabilities[0].id: skill package p1 references unknown MCP server ghost",
    ],
    [
      "an mcp_tool capability naming no known tool",
      {
        skill_packages: [
          {
            id: "p1",
            name: "p",
            version: "1.0.0",
            capabilities: [{ id: "ghost", kind: "mcp_tool" }],
          },
        ],
      },
      "field skill_packages[0].capabilities[0].id: skill package p1 references unknown MCP tool ghost",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_guardrails — identity, cross-reference and detector-runtime knobs", () => {
  const guardrail = (extra: Record<string, unknown> = {}) => ({
    id: "g1",
    name: "g1",
    keywords: ["secret"],
    ...extra,
  });
  const detector = (extra: Record<string, unknown> = {}) =>
    guardrail({
      provider: "custom_http",
      provider_endpoint: "https://detector.example/scan",
      ...extra,
    });
  const cases: Case[] = [
    [
      "a blank guardrail id",
      { guardrails: [guardrail({ id: " " })] },
      "field guardrails[0].id: cannot be empty",
    ],
    [
      "a blank guardrail name",
      { guardrails: [guardrail({ name: "  " })] },
      "field guardrails[0].name: cannot be empty",
    ],
    [
      "a blank regex",
      { guardrails: [guardrail({ keywords: [], regex: [" "] })] },
      "field guardrails[0].regex[0]: cannot be empty",
    ],
    [
      "an api key that does not exist",
      { guardrails: [guardrail({ api_key_ids: ["ghost"] })] },
      "field guardrails[0].api_key_ids: guardrail g1 references unknown api key ghost",
    ],
    [
      "a provider that does not exist",
      { guardrails: [guardrail({ providers: ["ghost"] })] },
      "field guardrails[0].providers: guardrail g1 references unknown provider ghost",
    ],
    [
      "a zero provider_max_concurrency",
      { guardrails: [detector({ provider_max_concurrency: 0 })] },
      "field guardrails[0].provider_max_concurrency: must be greater than zero",
    ],
    [
      "a provider_max_concurrency past the runtime semaphore limit",
      { guardrails: [detector({ provider_max_concurrency: 2_305_843_009_213_696_000 })] },
      "field guardrails[0].provider_max_concurrency: exceeds the runtime semaphore limit",
    ],
    [
      "a zero provider_circuit_failure_threshold",
      { guardrails: [detector({ provider_circuit_failure_threshold: 0 })] },
      "field guardrails[0].provider_circuit_failure_threshold: must be greater than zero",
    ],
    [
      "a zero provider_circuit_cooldown_ms",
      { guardrails: [detector({ provider_circuit_cooldown_ms: 0 })] },
      "field guardrails[0].provider_circuit_cooldown_ms: must be greater than zero",
    ],
    [
      "a zero provider_max_payload_bytes",
      { guardrails: [detector({ provider_max_payload_bytes: 0 })] },
      "field guardrails[0].provider_max_payload_bytes: must be greater than zero",
    ],
    [
      "a zero provider_max_response_bytes",
      { guardrails: [detector({ provider_max_response_bytes: 0 })] },
      "field guardrails[0].provider_max_response_bytes: must be greater than zero",
    ],
    [
      "a presidio detector with no endpoint",
      { guardrails: [guardrail({ provider: "presidio" })] },
      "field guardrails[0].provider_endpoint: required when provider is presidio or " +
        "llm_guard_prompt_injection",
    ],
    [
      "a blank presidio provider_language",
      {
        guardrails: [
          guardrail({
            provider: "presidio",
            provider_endpoint: "https://presidio.example/analyze",
            provider_fingerprint_secret_ref: "env://PRESIDIO_FINGERPRINT",
            provider_language: " ",
          }),
        ],
      },
      "field guardrails[0].provider_language: cannot be empty",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_plugins + validate_builtin_plugin_shape", () => {
  const cases: Case[] = [
    [
      "a blank plugin source",
      { plugins: [{ id: "p1", kind: "tool_provider", source: " " }] },
      "field plugins[0].source: cannot be empty",
    ],
    [
      "an mcp.http plugin that is not a tool_provider",
      {
        plugins: [
          {
            id: "mcp.http",
            source: "builtin",
            kind: "event_sink",
            config: { endpoint: "http://mcp.internal/rpc" },
          },
        ],
      },
      "field plugins[0].kind: mcp.http must be tool_provider",
    ],
    [
      "an mcp.http endpoint that is not a URI",
      {
        plugins: [
          {
            id: "mcp.http",
            source: "builtin",
            kind: "tool_provider",
            config: { endpoint: "not a uri" },
          },
        ],
      },
      "field plugins[0].config.endpoint: invalid URI",
    ],
    // Rust reads the host from `http::Uri::authority()`, which these two shapes
    // do not have. WHATWG `URL` disagrees: it re-parses BOTH as "http://rpc/"
    // and reports hostname "rpc", so before the fix in
    // `src/validate/plugins.ts` the gate ACCEPTED a hostless endpoint whenever
    // `permissions.network` allowed "*" (or, absurdly, the path segment) — and
    // the `must include host` branch was dead code no test could reach.
    [
      "an mcp.http endpoint with an EMPTY authority, even with network: *",
      {
        plugins: [
          {
            id: "mcp.http",
            source: "builtin",
            kind: "tool_provider",
            config: { endpoint: "http:///rpc" },
            permissions: { network: ["*"] },
          },
        ],
      },
      "field plugins[0].config.endpoint: must include host",
    ],
    [
      "an mcp.http endpoint with NO authority component at all",
      {
        plugins: [
          {
            id: "mcp.http",
            source: "builtin",
            kind: "tool_provider",
            config: { endpoint: "http:/rpc" },
            permissions: { network: ["*"] },
          },
        ],
      },
      "field plugins[0].config.endpoint: must include host",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_agent_upstreams + validate_upstreams + validate_routes", () => {
  const cases: Case[] = [
    [
      "a blank agent upstream id",
      { agent_upstreams: [{ id: " ", name: "u", endpoint: "https://a.example" }] },
      "field agent_upstreams[0].id: cannot be empty",
    ],
    [
      "a blank agent upstream endpoint",
      { agent_upstreams: [{ id: "u1", name: "u", endpoint: " " }] },
      "field agent_upstreams[0].endpoint: cannot be empty",
    ],
    [
      "a blank upstream name",
      { upstreams: [{ name: " ", url: "http://u.internal" }] },
      "field upstreams[0].name: cannot be empty",
    ],
    [
      "a blank route name",
      {
        upstreams: [{ name: "u1", url: "http://u.internal" }],
        routes: [{ name: " ", upstream: "u1" }],
      },
      "field routes[0].name: cannot be empty",
    ],
    [
      "a duplicate route name",
      {
        upstreams: [{ name: "u1", url: "http://u.internal" }],
        routes: [
          { name: "r1", upstream: "u1" },
          { name: "r1", upstream: "u1" },
        ],
      },
      "field routes[1].name: duplicate route name r1",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  // `field agent_upstreams[i].protocol: streaming capability requires A2A
  // protocol` is NOT in the table above, and cannot be: `AgentUpstreamProtocol`
  // has exactly one variant (`a2a`) in the Rust enum too, so `!matches!(protocol,
  // A2a)` is false for every value that can exist. The branch is structurally
  // unreachable on BOTH sides — the port is faithful, including the dead arm.
  // What is observable is the other half of the rule: a `stream` capability is
  // ACCEPTED, not refused.
  test("a stream capability on the only protocol there is, is accepted", () => {
    expect(() =>
      validateConfig(
        configSchema.parse({
          agent_upstreams: [
            { id: "u1", name: "u", endpoint: "https://a.example", capabilities: ["stream"] },
          ],
        }),
      ),
    ).not.toThrow();
  });
});

describe("section validators — the zero-and-blank knobs", () => {
  const cases: Case[] = [
    [
      "a blank auth_service endpoint",
      { auth_service: { enabled: true, endpoint: " " } },
      "field auth_service.endpoint: cannot be empty",
    ],
    [
      "a blank admin_api gateway_url",
      { admin_api: { gateway_url: "   " } },
      "field admin_api.gateway_url: cannot be empty",
    ],
    [
      "a blank telemetry otlp_endpoint",
      { telemetry: { otlp_endpoint: " " } },
      "field telemetry.otlp_endpoint: cannot be empty",
    ],
    [
      "a blank billing_alerts webhook_url",
      { billing_alerts: { webhook_url: " " } },
      "field billing_alerts.webhook_url: cannot be empty",
    ],
    [
      "a blank prometheus_metrics_path",
      { observability: { prometheus_metrics_path: " " } },
      "field observability.prometheus_metrics_path: cannot be empty",
    ],
    [
      "an enabled otlp exporter with no scheme",
      {
        observability: {
          enabled: true,
          provider: "otlp",
          otlp_endpoint: "collector:4317",
        },
      },
      "field observability.otlp_endpoint: must start with http:// or https://",
    ],
    [
      "a zero analytics export_timeout_secs",
      { analytics: { export_timeout_secs: 0 } },
      "field analytics.export_timeout_secs: must be greater than zero",
    ],
    [
      "a zero analytics flush_interval_millis",
      { analytics: { flush_interval_millis: 0 } },
      "field analytics.flush_interval_millis: must be greater than zero",
    ],
    [
      "a zero analytics queue_capacity",
      { analytics: { queue_capacity: 0 } },
      "field analytics.queue_capacity: must be greater than zero",
    ],
    [
      "a zero analytics request_log_retention_records",
      { analytics: { request_log_retention_records: 0 } },
      "field analytics.request_log_retention_records: must be greater than zero",
    ],
    [
      "a zero analytics audit_event_retention_records",
      { analytics: { audit_event_retention_records: 0 } },
      "field analytics.audit_event_retention_records: must be greater than zero",
    ],
    [
      "a zero analytics billing_event_retention_records",
      { analytics: { billing_event_retention_records: 0 } },
      "field analytics.billing_event_retention_records: must be greater than zero",
    ],
    [
      "a blank metering export_endpoint",
      { metering: { export_enabled: true, export_endpoint: " " } },
      "field metering.export_endpoint: cannot be empty",
    ],
    [
      "a zero metering export_timeout_secs",
      { metering: { export_timeout_secs: 0 } },
      "field metering.export_timeout_secs: must be greater than zero",
    ],
    [
      "a blank metering export_source",
      { metering: { export_source: " " } },
      "field metering.export_source: cannot be empty",
    ],
    [
      "a zero cache max_records",
      { cache: { max_records: 0 } },
      "field cache.max_records: must be greater than zero",
    ],
    [
      "turso_libsql left in the durable provider order",
      { storage: { provider_order: ["supabase", "turso_libsql"] } },
      "field storage.provider_order: turso_libsql has been removed from production durable " +
        "provider order; migrate storage.provider to supabase",
    ],
    [
      "mysql left in the durable provider order",
      { storage: { provider_order: ["supabase", "mysql"] } },
      "field storage.provider_order: mysql has been removed from production durable provider " +
        "order; migrate storage.provider to supabase",
    ],
    [
      "a zero storage admin_list_default_limit",
      { storage: { admin_list_default_limit: 0 } },
      "field storage.admin_list_default_limit: must be greater than zero",
    ],
    [
      "a zero storage admin_list_max_limit",
      { storage: { admin_list_max_limit: 0 } },
      "field storage.admin_list_max_limit: must be greater than zero",
    ],
    [
      "a zero reliability provider_dispatch_timeout_secs",
      { reliability: { provider_dispatch_timeout_secs: 0 } },
      "field reliability.provider_dispatch_timeout_secs: must be greater than zero",
    ],
    [
      "a zero reliability provider_response_body_max_bytes",
      { reliability: { provider_response_body_max_bytes: 0 } },
      "field reliability.provider_response_body_max_bytes: must be greater than zero",
    ],
    [
      "a zero reliability mcp_dispatch_timeout_secs",
      { reliability: { mcp_dispatch_timeout_secs: 0 } },
      "field reliability.mcp_dispatch_timeout_secs: must be greater than zero",
    ],
    [
      "a zero reliability graceful_shutdown_grace_period_secs",
      { reliability: { graceful_shutdown_grace_period_secs: 0 } },
      "field reliability.graceful_shutdown_grace_period_secs: must be greater than zero",
    ],
    [
      "a zero reliability graceful_shutdown_timeout_secs",
      { reliability: { graceful_shutdown_timeout_secs: 0 } },
      "field reliability.graceful_shutdown_timeout_secs: must be greater than zero",
    ],
    [
      "a blank reliability graceful_upgrade_pid_file",
      { reliability: { graceful_upgrade_pid_file: " " } },
      "field reliability.graceful_upgrade_pid_file: cannot be empty",
    ],
    [
      "a blank reliability graceful_upgrade_sock",
      { reliability: { graceful_upgrade_sock: " " } },
      "field reliability.graceful_upgrade_sock: cannot be empty",
    ],
    [
      "a zero reliability graceful_upgrade_sock_retries",
      { reliability: { graceful_upgrade_sock_retries: 0 } },
      "field reliability.graceful_upgrade_sock_retries: must be greater than zero",
    ],
    [
      "a zero agent_runtime timeout_millis",
      { agent_runtime: { timeout_millis: 0 } },
      "field agent_runtime.timeout_millis: must be greater than zero",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_cluster — the per-node identity knobs", () => {
  const cluster = (extra: Record<string, unknown> = {}) => ({
    cluster: { enabled: true, cluster_id: "c1", node_id: "n1", ...extra },
  });
  const cases: Case[] = [
    [
      "a blank node_id",
      cluster({ node_id: " " }),
      "field cluster.node_id: cannot be empty when cluster mode is enabled",
    ],
    [
      "a blank node_region",
      cluster({ node_region: " " }),
      "field cluster.node_region: cannot be empty",
    ],
    ["a blank node_zone", cluster({ node_zone: " " }), "field cluster.node_zone: cannot be empty"],
    [
      "a blank state_backend",
      cluster({ state_backend: " " }),
      "field cluster.state_backend: cannot be empty",
    ],
    [
      "a blank counter_backend",
      cluster({ counter_backend: " " }),
      "field cluster.counter_backend: cannot be empty",
    ],
    [
      "a zero counter_timeout_millis",
      cluster({ counter_timeout_millis: 0 }),
      "field cluster.counter_timeout_millis: must be greater than zero",
    ],
    [
      "a zero config_poll_interval_secs",
      cluster({ config_poll_interval_secs: 0 }),
      "field cluster.config_poll_interval_secs: must be greater than zero",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });
});

describe("validate_network_access — the CIDR parse leg keeps the offending value", () => {
  test("a malformed allowlist entry names its index AND quotes the value", () => {
    const message = firstError({ network_access: { ip_allowlist: ["10.0.0.0/64"] } });
    expect(message.startsWith("field network_access.ip_allowlist[0]: ")).toBe(true);
    expect(message.endsWith(' (value: "10.0.0.0/64")')).toBe(true);
  });
});
