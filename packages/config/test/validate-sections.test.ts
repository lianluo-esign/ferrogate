/**
 * Table-driven port checks for the SECTION validators of `Config::validate()`
 * (auth service, control-plane API, telemetry, billing alerts, observability,
 * analytics, metering, cache, storage, reliability, limits, agent runtime,
 * cluster, network access, per-provider Cloudflare AI Gateway, x402 scoped spend
 * policies).
 *
 * Each case asserts the EXACT `field <path>: <reason>`, so a check that moved to
 * the wrong field — or stopped running — reddens here.
 */
import { describe, expect, test } from "vitest";
import { configSchema } from "../src/schema/config.js";
import { validateConfig, validateConfigAsync } from "../src/validate.js";

function firstError(raw: Record<string, unknown>): string {
  const config = configSchema.parse(raw);
  try {
    validateConfig(config);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected validateConfig to reject this config, but it passed");
}

function expectAccepted(raw: Record<string, unknown>): void {
  validateConfig(configSchema.parse(raw));
}

const cloudflare = {
  account_id: "acct",
  api_token: "env://CF_API_TOKEN",
};

describe("validate_auth_service + validate_admin_api", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a zero auth-service timeout",
      { auth_service: { timeout_millis: 0 } },
      "field auth_service.timeout_millis: must be greater than zero",
    ],
    [
      "retries with no backoff",
      { auth_service: { max_retries: 2, retry_backoff_millis: 0 } },
      "field auth_service.retry_backoff_millis: must be greater than zero when " +
        "auth_service.max_retries is set",
    ],
    [
      "an enabled auth service behind https (it is an internal hop)",
      { auth_service: { enabled: true, endpoint: "https://auth.internal" } },
      "field auth_service.endpoint: must start with http://",
    ],
    [
      "a blank control-plane listen address",
      { admin_api: { listen: "  " } },
      "field admin_api.listen: cannot be empty",
    ],
    [
      "an unparsable control-plane listen address",
      { admin_api: { listen: "not-an-addr" } },
      "field admin_api.listen: invalid listen address not-an-addr",
    ],
    [
      "a https gateway_url",
      { admin_api: { gateway_url: "https://gw.internal" } },
      "field admin_api.gateway_url: must start with http:// (an internal service-to-service hop, " +
        "like auth_service.endpoint; terminate public TLS on admin_api.tls_cert_path/tls_key_path " +
        "or an Ingress instead)",
    ],
    [
      "a gateway_url with no host",
      { admin_api: { gateway_url: "http:///" } },
      "field admin_api.gateway_url: host cannot be empty",
    ],
    [
      "a zero upstream timeout",
      { admin_api: { upstream_timeout_millis: 0 } },
      "field admin_api.upstream_timeout_millis: must be greater than zero",
    ],
    [
      "a blank CORS origin",
      { admin_api: { cors_allowed_origin: " " } },
      "field admin_api.cors_allowed_origin: cannot be empty when set",
    ],
    [
      "half a TLS pair",
      { admin_api: { tls_cert_path: "/etc/cert.pem" } },
      "fields admin_api.tls_cert_path and admin_api.tls_key_path: must be set together and " +
        "non-empty to enable TLS on the admin-api listener",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a localhost listener, an http hop and a full TLS pair", () => {
    expectAccepted({
      auth_service: { enabled: true, endpoint: "http://127.0.0.1:8090" },
      admin_api: {
        listen: "localhost:8095",
        gateway_url: "http://127.0.0.1:8080",
        tls_cert_path: "/etc/cert.pem",
        tls_key_path: "/etc/key.pem",
      },
    });
  });
});

describe("validate_telemetry + validate_billing_alerts", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank service name",
      { telemetry: { service_name: " " } },
      "field telemetry.service_name: cannot be empty",
    ],
    [
      "a zero access-log sample rate",
      { telemetry: { access_log_sample_rate: 0 } },
      "field telemetry.access_log_sample_rate: must be greater than zero",
    ],
    [
      "a zero access-log error rate limit",
      { telemetry: { access_log_error_rate_limit_per_sec: 0 } },
      "field telemetry.access_log_error_rate_limit_per_sec: must be greater than zero",
    ],
    [
      "a schemeless OTLP endpoint",
      { telemetry: { otlp_endpoint: "collector:4317" } },
      "field telemetry.otlp_endpoint: must start with http:// or https://",
    ],
    [
      "a zero webhook timeout",
      { billing_alerts: { webhook_timeout_secs: 0 } },
      "field billing_alerts.webhook_timeout_secs: must be greater than zero",
    ],
    [
      "a schemeless billing webhook",
      { billing_alerts: { webhook_url: "hooks.example/billing" } },
      "field billing_alerts.webhook_url: must start with http:// or https://",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts an https OTLP endpoint and webhook", () => {
    expectAccepted({
      telemetry: { otlp_endpoint: "https://collector.example" },
      billing_alerts: { webhook_url: "https://hooks.example/billing" },
    });
  });
});

describe("validate_observability (issue #520)", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a relative metrics path",
      { observability: { prometheus_metrics_path: "metrics" } },
      "field observability.prometheus_metrics_path: must be an absolute HTTP path",
    ],
    [
      "the bare root metrics path",
      { observability: { prometheus_metrics_path: "/" } },
      "field observability.prometheus_metrics_path: must be an absolute HTTP path",
    ],
    [
      "a zero export timeout",
      { observability: { export_timeout_secs: 0 } },
      "field observability.export_timeout_secs: must be greater than zero",
    ],
    [
      "enabled with provider none",
      { observability: { enabled: true, provider: "none" } },
      "field observability.provider: cannot be none when observability is enabled",
    ],
    [
      "enabled with no OTLP endpoint",
      { observability: { enabled: true } },
      "field observability.otlp_endpoint: required when observability is enabled",
    ],
    [
      "the cloudflare provider with no collector token",
      {
        observability: { enabled: true, provider: "cloudflare", otlp_endpoint: "https://c.example" },
      },
      "field observability.cloudflare_collector_token_ref: required when observability.provider is cloudflare",
    ],
    [
      "the collector credential over plaintext http to a remote host",
      {
        observability: {
          enabled: true,
          provider: "cloudflare",
          otlp_endpoint: "http://collector.example",
          cloudflare_collector_token_ref: "env://CF_COLLECTOR",
        },
      },
      "field observability.otlp_endpoint: refusing to send the collector credential over " +
        "plaintext to `http://collector.example`; use https (loopback http is allowed for local " +
        "development)",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts loopback plaintext for local development", () => {
    expectAccepted({
      observability: {
        enabled: true,
        provider: "cloudflare",
        otlp_endpoint: "http://127.0.0.1:4318",
        cloudflare_collector_token_ref: "env://CF_COLLECTOR",
      },
    });
  });
});

describe("validate_analytics + validate_metering + validate_cache", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "required analytics that are not enabled",
      { analytics: { required: true } },
      "field analytics.required: requires analytics.enabled and a non-none provider",
    ],
    [
      "the vector provider with no endpoint",
      { analytics: { enabled: true } },
      "field analytics.vector_endpoint: required when analytics.provider is vector",
    ],
    [
      "a schemeless clickhouse url",
      { analytics: { enabled: true, provider: "clickhouse", clickhouse_url: "db.example:8123" } },
      "field analytics.clickhouse_url: must start with http:// or https://",
    ],
    [
      "clickhouse with neither url nor url env",
      { analytics: { enabled: true, provider: "clickhouse" } },
      "field analytics.clickhouse_url_env: required when analytics.provider is clickhouse unless " +
        "analytics.clickhouse_url is set",
    ],
    [
      "an enabled none provider",
      { analytics: { enabled: true, provider: "none" } },
      "field analytics.provider: none cannot be enabled",
    ],
    [
      "a zero analytics batch size",
      { analytics: { batch_max_events: 0 } },
      "field analytics.batch_max_events: must be greater than zero",
    ],
    [
      "a zero guardrail-evaluation retention",
      { analytics: { guardrail_evaluation_retention_records: 0 } },
      "field analytics.guardrail_evaluation_retention_records: must be greater than zero",
    ],
    [
      "a schemeless metering endpoint",
      { metering: { export_enabled: true, export_endpoint: "api.example/metering" } },
      "field metering.export_endpoint: must start with http:// or https://",
    ],
    [
      "metering export with no token",
      { metering: { export_enabled: true } },
      "field metering.export_token_env: required when metering export is enabled unless " +
        "metering.export_token is set",
    ],
    [
      "a blank metering event type",
      { metering: { export_event_type: " " } },
      "field metering.export_event_type: cannot be empty",
    ],
    [
      "a zero cache ttl",
      { cache: { ttl_secs: 0 } },
      "field cache.ttl_secs: must be greater than zero",
    ],
    [
      "a semantic threshold outside (0, 1]",
      { cache: { mode: "semantic", semantic_similarity_threshold: 0 } },
      "field cache.semantic_similarity_threshold: must be within (0.0, 1.0] for semantic mode",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts configured analytics, metering and semantic cache", () => {
    expectAccepted({
      analytics: { enabled: true, required: true, vector_endpoint: "http://vector:9000" },
      metering: { export_enabled: true, export_token_env: "METERING_TOKEN" },
      cache: { mode: "semantic", semantic_similarity_threshold: 1 },
    });
  });
});

describe("validate_storage", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "an empty durable provider order",
      { storage: { provider_order: [] } },
      "field storage.provider_order: must include at least one durable provider",
    ],
    [
      "memory in the durable provider order",
      { storage: { provider_order: ["memory", "supabase"] } },
      "field storage.provider_order[0]: memory is not a durable provider",
    ],
    [
      "a duplicated durable provider",
      { storage: { provider_order: ["supabase", "supabase"] } },
      "field storage.provider_order[1]: duplicate storage provider supabase",
    ],
    [
      "supabase not first in the durable provider order",
      { storage: { provider_order: ["postgres", "supabase"] } },
      "field storage.provider_order[0]: supabase must be the default commercial cloud provider",
    ],
    [
      "the removed turso_libsql provider",
      { storage: { provider: "turso_libsql" } },
      "field storage.provider: turso_libsql has been removed as a production durable provider; " +
        "migrate to storage.provider: supabase with storage.supabase_dsn_env",
    ],
    [
      "the removed mysql provider",
      { storage: { provider: "mysql" } },
      "field storage.provider: mysql has been removed as a production durable provider; migrate " +
        "to storage.provider: supabase with storage.supabase_dsn_env",
    ],
    [
      "supabase with no DSN env var",
      { storage: { provider: "supabase" } },
      "field storage.supabase_dsn_env: required when storage.provider is supabase",
    ],
    [
      "supabase over a TLS mode that does not verify",
      { storage: { provider: "supabase", supabase_dsn_env: "SUPABASE_DSN" } },
      "field storage.postgres_tls_mode: supabase requires TLS mode require, verify_ca, or verify_full",
    ],
    [
      "postgres with neither DSN nor DSN env var",
      { storage: { provider: "postgres" } },
      "field storage.postgres_dsn_env: required when storage.provider is postgres unless " +
        "storage.postgres_dsn is set",
    ],
    [
      "a zero postgres pool size",
      { storage: { provider: "postgres", postgres_dsn: "postgres://x", postgres_pool_size: 0 } },
      "field storage.postgres_pool_size: must be greater than zero",
    ],
    [
      "a postgres schema that is not an identifier",
      {
        storage: { provider: "postgres", postgres_dsn: "postgres://x", postgres_schema: "1public" },
      },
      "field storage.postgres_schema: must start with an ASCII letter or underscore",
    ],
    [
      "a search-path entry with a quote in it",
      {
        storage: {
          provider: "postgres",
          postgres_dsn: "postgres://x",
          postgres_search_path: ["public", 'evil"'],
        },
      },
      "field storage.postgres_search_path[1]: must contain only ASCII letters, digits, or underscores",
    ],
    [
      "cloudflare_d1 without a [cloudflare] block",
      { storage: { provider: "cloudflare_d1" } },
      "field storage.provider: cloudflare_d1 requires a [cloudflare] block to build the D1 REST client",
    ],
    [
      "required durable storage on the memory provider",
      { storage: { required: true } },
      "field storage.required: durable storage requires a non-memory provider",
    ],
    [
      "an admin list default above the max",
      { storage: { admin_list_default_limit: 200, admin_list_max_limit: 100 } },
      "field storage.admin_list_default_limit: must be less than or equal to storage.admin_list_max_limit",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts supabase over verify_full and D1 with a [cloudflare] block", () => {
    expectAccepted({
      storage: {
        provider: "supabase",
        supabase_dsn_env: "SUPABASE_DSN",
        postgres_tls_mode: "verify_full",
        postgres_schema: "ferrogate",
        postgres_search_path: ["ferrogate", "public"],
      },
    });
    expectAccepted({ cloudflare, storage: { provider: "cloudflare_d1" } });
  });
});

describe("validate_reliability + validate_limits", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a zero circuit-breaker threshold",
      { reliability: { provider_circuit_breaker_failure_threshold: 0 } },
      "field reliability.provider_circuit_breaker_failure_threshold: must be greater than zero",
    ],
    [
      "a threshold with no cooldown",
      { reliability: { provider_circuit_breaker_failure_threshold: 5 } },
      "field reliability.provider_circuit_breaker_cooldown_secs: required when provider circuit " +
        "breaker threshold is set",
    ],
    [
      "a cooldown with no threshold",
      { reliability: { provider_circuit_breaker_cooldown_secs: 30 } },
      "field reliability.provider_circuit_breaker_failure_threshold: required when provider " +
        "circuit breaker cooldown is set",
    ],
    [
      "a zero tool-approval timeout",
      { reliability: { tool_approval_timeout_secs: 0 } },
      "field reliability.tool_approval_timeout_secs: must be greater than zero",
    ],
    [
      "a zero MCP dispatch concurrency",
      { reliability: { mcp_dispatch_max_concurrency: 0 } },
      "field reliability.mcp_dispatch_max_concurrency: must be greater than zero",
    ],
    [
      "a zero body cap",
      { limits: { inference_body_max_bytes: 0 } },
      "field limits.inference_body_max_bytes: must be greater than zero",
    ],
    [
      "a body cap above 1 GiB",
      { limits: { admin_body_max_bytes: 1024 * 1024 * 1024 + 1 } },
      "field limits.admin_body_max_bytes: must not exceed 1073741824 bytes (1 GiB)",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a paired circuit breaker and in-range body caps", () => {
    expectAccepted({
      reliability: {
        provider_circuit_breaker_failure_threshold: 5,
        provider_circuit_breaker_cooldown_secs: 30,
      },
      limits: { inference_body_max_bytes: 1024 * 1024, admin_body_max_bytes: 1024 * 1024 * 1024 },
    });
  });
});

describe("validate_agent_runtime", () => {
  const managed = (worker: Record<string, unknown>) => ({
    agent_runtime: { enabled: true, managed_worker: worker },
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "zero max turns",
      { agent_runtime: { max_turns: 0 } },
      "field agent_runtime.max_turns: must be greater than zero",
    ],
    [
      "a plaintext external authorizer listener",
      managed({ external_action_authorizer_http_listen: "127.0.0.1:9999" }),
      "field agent_runtime.managed_worker.external_action_authorizer_http_listen: insecure " +
        'plaintext authorizer transport is unsupported; configure ' +
        "external_action_authorizer_socket in a private owner-only directory (authenticated guest " +
        'transport remains tracked in #205), got "127.0.0.1:9999"',
    ],
    [
      "a blank authorizer socket",
      managed({ external_action_authorizer_socket: " " }),
      "field agent_runtime.managed_worker.external_action_authorizer_socket: must not be empty when provided",
    ],
    [
      "a zero authorizer request budget",
      managed({ external_action_authorizer_max_requests: 0 }),
      "field agent_runtime.managed_worker.external_action_authorizer_max_requests: must be " +
        "greater than zero when provided",
    ],
    [
      "a duplicated capability action",
      managed({ allowed_actions: ["tool", "tool"] }),
      "field agent_runtime.managed_worker.allowed_actions: duplicate capability action",
    ],
    [
      "class-only actions under the deny policy mode",
      managed({ allowed_actions: ["tool"] }),
      "field agent_runtime.managed_worker.class_only_policy_mode: class-only actions require " +
        "explicit legacy_class_wide migration mode; otherwise replace them with target_grants",
    ],
    [
      "a blank policy revision",
      managed({ policy_revision: " " }),
      "field agent_runtime.managed_worker.policy_revision: must not be empty",
    ],
    [
      "a target grant with no selector id",
      managed({
        target_grants: [{ selector_id: "", permission_key: "p", action: "tool", selector: {} }],
      }),
      "field agent_runtime.managed_worker.target_grants.selector_id: must not be empty",
    ],
    [
      "a duplicated target-grant selector id",
      managed({
        target_grants: [
          { selector_id: "s1", permission_key: "p", action: "tool", selector: {} },
          { selector_id: "s1", permission_key: "q", action: "tool", selector: {} },
        ],
      }),
      "field agent_runtime.managed_worker.target_grants: duplicate selector_id s1",
    ],
    [
      "an external runtime with no command",
      { agent_runtime: { provider: "external" } },
      "field agent_runtime.external.command: must not be empty when provider is external",
    ],
    [
      "an external runtime with a zero timeout",
      { agent_runtime: { provider: "external", external: { command: "run", timeout_millis: 0 } } },
      "field agent_runtime.external.timeout_millis: must be greater than zero",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts class-only actions under the legacy migration mode", () => {
    expectAccepted(
      managed({ class_only_policy_mode: "legacy_class_wide", allowed_actions: ["tool", "cli"] }),
    );
  });
});

describe("validate_cluster", () => {
  const cluster = (extra: Record<string, unknown>) => ({ cluster: { enabled: true, ...extra } });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank cluster id",
      cluster({ cluster_id: " " }),
      "field cluster.cluster_id: cannot be empty when cluster mode is enabled",
    ],
    [
      "a zero heartbeat interval",
      cluster({ heartbeat_interval_secs: 0 }),
      "field cluster.heartbeat_interval_secs: must be greater than zero",
    ],
    [
      "the file state backend with no path",
      cluster({ state_backend: "file" }),
      "field cluster.file_state_path: required when cluster.state_backend is file",
    ],
    [
      "an unsupported state backend",
      cluster({ state_backend: "postgres" }),
      "field cluster.state_backend: only local and file are supported until database shared state lands",
    ],
    [
      "an unsupported counter backend",
      cluster({ counter_backend: "memcached" }),
      "field cluster.counter_backend: only local and redis are supported",
    ],
    [
      "the redis counter backend with no url",
      cluster({ counter_backend: "redis" }),
      "field cluster.redis_url: required when cluster.counter_backend is redis",
    ],
    [
      "a redis url with the wrong scheme",
      cluster({ counter_backend: "redis", redis_url: "http://redis:6379" }),
      "field cluster.redis_url: must start with redis:// or rediss://",
    ],
    [
      "snapshot signing with no tenant identity (#206)",
      cluster({ snapshot_signing_key: "c2VlZA==", snapshot_signing_key_id: "k1" }),
      "field cluster.snapshot_tenant_id: required when snapshot signing or verification is enabled",
    ],
    [
      "snapshot signing with no key id (#206)",
      cluster({
        snapshot_signing_key: "c2VlZA==",
        snapshot_tenant_id: "t",
        snapshot_deployment_id: "d",
      }),
      "field cluster.snapshot_signing_key_id: required when cluster.snapshot_signing_key is set",
    ],
    [
      "a zero snapshot max age while signing (#206)",
      cluster({
        snapshot_signing_key: "c2VlZA==",
        snapshot_signing_key_id: "k1",
        snapshot_tenant_id: "t",
        snapshot_deployment_id: "d",
        snapshot_max_age_secs: 0,
      }),
      "field cluster.snapshot_max_age_secs: must be greater than zero when signing is enabled",
    ],
    [
      "duplicate trusted key ids (#206)",
      cluster({
        snapshot_tenant_id: "t",
        snapshot_deployment_id: "d",
        snapshot_trusted_keys: [
          { key_id: "k1", public_key: "AAA" },
          { key_id: "k1", public_key: "BBB" },
        ],
      }),
      'field cluster.snapshot_trusted_keys: duplicate key_id "k1"',
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("a disabled cluster is a no-op even when every knob is nonsense", () => {
    expectAccepted({ cluster: { cluster_id: " ", state_backend: "postgres", counter_timeout_millis: 0 } });
  });

  test("validateConfigAsync additionally parses the snapshot key material", async () => {
    // 32 raw bytes, base64 — the Ed25519 seed shape `parseSigningKey` requires.
    const seed = Buffer.alloc(32, 7).toString("base64");
    const raw = {
      cluster: {
        enabled: true,
        snapshot_signing_key: seed,
        snapshot_signing_key_id: "k1",
        snapshot_tenant_id: "t",
        snapshot_deployment_id: "d",
      },
    };
    await expect(validateConfigAsync(configSchema.parse(raw))).resolves.toBeUndefined();

    const badSeed = { ...raw, cluster: { ...raw.cluster, snapshot_signing_key: "dG9vLXNob3J0" } };
    // Sync validation cannot see this (no WebCrypto); the async gate must.
    expectAccepted(badSeed);
    await expect(validateConfigAsync(configSchema.parse(badSeed))).rejects.toThrow(
      /cluster\.snapshot_signing_key/,
    );
  });
});

describe("validate_network_access (issue #166)", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a malformed CIDR entry",
      { network_access: { ip_allowlist: ["10.0.0.0/33"] } },
      'field network_access.ip_allowlist[0]: prefix length /33 exceeds maximum /32 for 10.0.0.0 ' +
        '(value: "10.0.0.0/33")',
    ],
    [
      "a non-IP entry",
      { network_access: { ip_allowlist: ["10.0.0.0", "example.com"] } },
      'field network_access.ip_allowlist[1]: invalid IP address: example.com (value: "example.com")',
    ],
    [
      "a zero unauthenticated rate limit",
      { network_access: { unauthenticated_rate_limit_per_minute: 0 } },
      "field network_access.unauthenticated_rate_limit_per_minute: must be greater than zero when set",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts v4 + v6 CIDRs and a positive flood limit", () => {
    expectAccepted({
      network_access: {
        ip_allowlist: ["10.0.0.0/8", "2001:db8::/32", "127.0.0.1"],
        unauthenticated_rate_limit_per_minute: 60,
      },
    });
  });
});

describe("validate_cloudflare + validate_cloudflare_ai_gateway_providers (issues #405/#406)", () => {
  const provider = (aig: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    providers: [
      { name: "openai", base_url: "https://api.openai.com/v1", cloudflare_ai_gateway: aig },
    ],
    ...extra,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "an empty cloudflare account id",
      { cloudflare: { api_token: "env://T" } },
      "field cloudflare.account_id: cannot be empty",
    ],
    [
      "an empty cloudflare api token",
      { cloudflare: { account_id: "acct" } },
      "field cloudflare.api_token: cannot be empty (an env:// reference or token)",
    ],
    [
      "a blank per-tenant token reference",
      { cloudflare: { ...cloudflare, tenant_tokens: { acme: " " } } },
      "field cloudflare.tenant_tokens.acme: token reference cannot be empty",
    ],
    [
      "a schemeless api base url",
      { cloudflare: { ...cloudflare, api_base_url: "api.cloudflare.com" } },
      "field cloudflare.api_base_url: must start with http:// or https://",
    ],
    [
      "a schemeless r2 endpoint",
      { cloudflare: { ...cloudflare, r2_s3_endpoint: "acct.r2.cloudflarestorage.com" } },
      "field cloudflare.r2_s3_endpoint: must start with http:// or https://",
    ],
    [
      "an AI Gateway provider with no [cloudflare] block",
      provider({ gateway_id: "gw" }),
      "field providers[0].cloudflare_ai_gateway: requires a top-level [cloudflare] block " +
        "(issue #405) for the account id and base URLs",
    ],
    [
      "an AI Gateway provider with a blank gateway id",
      provider({ gateway_id: " " }, { cloudflare }),
      "field providers[0].cloudflare_ai_gateway.gateway_id: cannot be empty",
    ],
    [
      "an AI Gateway token reference that is not a secret ref",
      provider({ gateway_id: "gw", aig_token_secret_ref: "raw-token" }, { cloudflare }),
      "field providers[0].cloudflare_ai_gateway.aig_token_secret_ref: unsupported secret " +
        "reference scheme (expected env://, vault://, or cf://): raw-token",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a complete [cloudflare] block + AI Gateway provider", () => {
    expectAccepted(
      provider(
        { gateway_id: "gw", mode: "unified", aig_token_secret_ref: "env://AIG_TOKEN" },
        { cloudflare: { ...cloudflare, tenant_tokens: { acme: "env://ACME_TOKEN" } } },
      ),
    );
  });
});

describe("validate_x402_spend_policies (issue #351)", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank scope id",
      { x402_spend_policies: [{ scope_type: "tenant", scope_id: "  ", policy: {} }] },
      "field x402_spend_policies: an x402 spend policy for scope tenant has an empty scope_id",
    ],
    [
      "two declarations targeting the same scope",
      {
        x402_spend_policies: [
          { scope_type: "project", scope_id: "p1", policy: {} },
          { scope_type: "project", scope_id: " p1 ", policy: {} },
        ],
      },
      'field x402_spend_policies: two x402 spend policies target the same scope project "p1"',
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts distinct scopes, and the empty default", () => {
    expectAccepted({
      x402_spend_policies: [
        { scope_type: "tenant", scope_id: "acme", policy: {} },
        { scope_type: "project", scope_id: "acme", policy: {} },
      ],
    });
    expectAccepted({});
  });
});
