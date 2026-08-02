/**
 * Section validators of `Config::validate()` (inventory §5.4): the `[...]`
 * blocks — auth service, control-plane API, telemetry, billing alerts,
 * observability, analytics, metering, cache, storage, reliability, limits,
 * agent runtime, cluster, network access, per-provider Cloudflare AI Gateway,
 * and the x402 scoped spend policies — ported 1:1 from `config/validate.rs`.
 *
 * REMOVED AS N/A ON CLOUDFLARE (not silently dropped):
 * - `validate_tls`, `validate_acme_tls`, `validate_acme_dns01_tls`,
 *   `validate_acme_http01_tls` and `validate_manual_tls_files`. Cloudflare
 *   TERMINATES TLS in front of the Worker: there is no listener to bind, no
 *   cert/key file to load (the Rust pre-flight calls pingora's
 *   `load_certs_and_key_files`, a filesystem+OpenSSL loader with no CF
 *   analogue), no `:80` HTTP-01 challenge listener a Worker can own, and no
 *   `storage_dir` to persist an ACME account in. `TlsConfig`/`TlsAcmeConfig`
 *   remain in the schema for document parity (see `schema/sections.ts`), but
 *   validating them here would assert an invariant the CF runtime can neither
 *   satisfy nor violate. Certificates are managed by Cloudflare (SSL/TLS +
 *   Custom Hostnames), not by this config.
 *   `admin_api.tls_cert_path`/`tls_key_path` are KEPT below: that check reads
 *   two strings for a both-or-neither contradiction and needs no TLS
 *   terminator or filesystem to decide.
 */
import { z } from "zod";
import { providerIsDurable, providerIsImplemented } from "@ferrogate/storage/provider";
import { BILLING_SERVICE_DEFAULT_ENDPOINT } from "../schema/sections.js";
import type { Config, StorageProviderKind } from "../schema/index.js";
import { IpCidr } from "../network-access.js";
import {
  capabilityActionAsStr,
  selectorSupportsAction,
  validateCapabilityTargetSelector,
} from "./capability-target.js";
import {
  describeX402ScopedPolicyError,
  validateScopedX402SpendPolicies,
  x402PolicyScopeKindSchema,
} from "../x402-scope.js";
import type { X402ScopedSpendPolicy } from "../x402-scope.js";
import {
  endpointProtectsCredentials,
  fail,
  hasHttpScheme,
  isBlank,
  isSetAndBlank,
  isSetAndPresent,
  isValidSocketAddr,
  validatePostgresIdentifier,
  validateSecretRef,
} from "./helpers.js";

// `StorageProviderKind::is_durable()` / `::implemented()` are OWNED by
// `@ferrogate/storage` (that is where the backends actually exist), so they are
// imported rather than re-derived: a provider that gains an implementation over
// there must not still be refused by this load-time gate.
const isDurableProvider = providerIsDurable;
const isImplementedProvider = providerIsImplemented;

/** `validate_auth_service`. */
export function validateAuthService(config: Config): void {
  const authService = config.auth_service;
  if (authService.timeout_millis === 0) {
    fail("auth_service.timeout_millis", "must be greater than zero");
  }
  if (authService.max_retries > 0 && authService.retry_backoff_millis === 0) {
    fail(
      "auth_service.retry_backoff_millis",
      "must be greater than zero when auth_service.max_retries is set",
    );
  }
  if (!authService.enabled) return;
  const endpoint = authService.endpoint.trim();
  if (endpoint.length === 0) fail("auth_service.endpoint", "cannot be empty");
  if (!endpoint.startsWith("http://")) fail("auth_service.endpoint", "must start with http://");
}

/**
 * `validate_admin_api` — `[control_api]`/`[admin_api]` (issue #315). Always
 * validated (not gated on a subcommand) so `ferrogate validate` catches a broken
 * section before either process starts.
 */
export function validateAdminApi(config: Config): void {
  const adminApi = config.admin_api;
  if (isBlank(adminApi.listen)) fail("admin_api.listen", "cannot be empty");
  if (!isValidSocketAddr(adminApi.listen)) {
    fail("admin_api.listen", `invalid listen address ${adminApi.listen}`);
  }
  const gatewayUrl = adminApi.gateway_url.trim();
  if (gatewayUrl.length === 0) fail("admin_api.gateway_url", "cannot be empty");
  if (!gatewayUrl.startsWith("http://")) {
    fail(
      "admin_api.gateway_url",
      "must start with http:// (an internal service-to-service hop, like " +
        "auth_service.endpoint; terminate public TLS on admin_api.tls_cert_path/tls_key_path or " +
        "an Ingress instead)",
    );
  }
  if (gatewayUrl.slice("http://".length).replace(/^\/+|\/+$/g, "").length === 0) {
    fail("admin_api.gateway_url", "host cannot be empty");
  }
  if (adminApi.upstream_timeout_millis === 0) {
    fail("admin_api.upstream_timeout_millis", "must be greater than zero");
  }
  if (isSetAndBlank(adminApi.cors_allowed_origin)) {
    fail("admin_api.cors_allowed_origin", "cannot be empty when set");
  }
  const cert = adminApi.tls_cert_path === null ? null : adminApi.tls_cert_path.trim();
  const key = adminApi.tls_key_path === null ? null : adminApi.tls_key_path.trim();
  const bothUnset = cert === null && key === null;
  const bothSet = cert !== null && key !== null && cert.length > 0 && key.length > 0;
  if (!bothUnset && !bothSet) {
    throw new Error(
      "fields admin_api.tls_cert_path and admin_api.tls_key_path: must be set together and " +
        "non-empty to enable TLS on the admin-api listener",
    );
  }
}

/** `validate_telemetry`. */
export function validateTelemetry(config: Config): void {
  const telemetry = config.telemetry;
  if (isBlank(telemetry.service_name)) fail("telemetry.service_name", "cannot be empty");
  if (telemetry.access_log_sample_rate === 0) {
    fail("telemetry.access_log_sample_rate", "must be greater than zero");
  }
  if (telemetry.access_log_error_rate_limit_per_sec === 0) {
    fail("telemetry.access_log_error_rate_limit_per_sec", "must be greater than zero");
  }
  if (telemetry.otlp_endpoint !== null) {
    if (isBlank(telemetry.otlp_endpoint)) fail("telemetry.otlp_endpoint", "cannot be empty");
    if (!hasHttpScheme(telemetry.otlp_endpoint)) {
      fail("telemetry.otlp_endpoint", "must start with http:// or https://");
    }
  }
}

/** `validate_billing_alerts`. */
export function validateBillingAlerts(config: Config): void {
  const alerts = config.billing_alerts;
  if (alerts.webhook_timeout_secs === 0) {
    fail("billing_alerts.webhook_timeout_secs", "must be greater than zero");
  }
  if (alerts.webhook_url !== null) {
    if (isBlank(alerts.webhook_url)) fail("billing_alerts.webhook_url", "cannot be empty");
    if (!hasHttpScheme(alerts.webhook_url)) {
      fail("billing_alerts.webhook_url", "must start with http:// or https://");
    }
  }
}

/** `validate_observability` (issue #520: fail at startup, never run silently disabled). */
export function validateObservability(config: Config): void {
  const observability = config.observability;
  if (isBlank(observability.prometheus_metrics_path)) {
    fail("observability.prometheus_metrics_path", "cannot be empty");
  }
  if (
    !observability.prometheus_metrics_path.startsWith("/") ||
    observability.prometheus_metrics_path.trim() === "/"
  ) {
    fail("observability.prometheus_metrics_path", "must be an absolute HTTP path");
  }
  if (observability.export_timeout_secs === 0) {
    fail("observability.export_timeout_secs", "must be greater than zero");
  }
  if (!observability.enabled) return;
  if (observability.provider === "none") {
    fail("observability.provider", "cannot be none when observability is enabled");
  }
  const endpoint = observability.otlp_endpoint;
  if (endpoint === null || isBlank(endpoint)) {
    fail("observability.otlp_endpoint", "required when observability is enabled");
  }
  if (!hasHttpScheme(endpoint)) {
    fail("observability.otlp_endpoint", "must start with http:// or https://");
  }
  if (observability.provider === "cloudflare") {
    if (!isSetAndPresent(observability.cloudflare_collector_token_ref)) {
      fail(
        "observability.cloudflare_collector_token_ref",
        "required when observability.provider is cloudflare",
      );
    }
    // The same rule the backend enforces before every export, so a
    // credential-leaking endpoint cannot reach the export thread.
    if (!endpointProtectsCredentials(endpoint)) {
      fail(
        "observability.otlp_endpoint",
        `refusing to send the collector credential over plaintext to \`${endpoint}\`; use https ` +
          `(loopback http is allowed for local development)`,
      );
    }
  }
}

/** `validate_analytics`. */
export function validateAnalytics(config: Config): void {
  const analytics = config.analytics;
  if (analytics.required && (!analytics.enabled || analytics.provider === "none")) {
    fail("analytics.required", "requires analytics.enabled and a non-none provider");
  }
  if (analytics.enabled) {
    switch (analytics.provider) {
      case "vector": {
        if (!isSetAndPresent(analytics.vector_endpoint)) {
          fail("analytics.vector_endpoint", "required when analytics.provider is vector");
        }
        break;
      }
      case "clickhouse": {
        const hasUrl = isSetAndPresent(analytics.clickhouse_url);
        if (analytics.clickhouse_url !== null) {
          const url = analytics.clickhouse_url.trim();
          if (url.length > 0 && !hasHttpScheme(url)) {
            fail("analytics.clickhouse_url", "must start with http:// or https://");
          }
        }
        const hasUrlEnv = isSetAndPresent(analytics.clickhouse_url_env);
        if (!hasUrl && !hasUrlEnv) {
          fail(
            "analytics.clickhouse_url_env",
            "required when analytics.provider is clickhouse unless analytics.clickhouse_url is set",
          );
        }
        break;
      }
      case "none": {
        fail("analytics.provider", "none cannot be enabled");
      }
    }
  }
  if (analytics.export_timeout_secs === 0) {
    fail("analytics.export_timeout_secs", "must be greater than zero");
  }
  if (analytics.batch_max_events === 0) fail("analytics.batch_max_events", "must be greater than zero");
  if (analytics.flush_interval_millis === 0) {
    fail("analytics.flush_interval_millis", "must be greater than zero");
  }
  if (analytics.queue_capacity === 0) fail("analytics.queue_capacity", "must be greater than zero");
  if (analytics.request_log_retention_records === 0) {
    fail("analytics.request_log_retention_records", "must be greater than zero");
  }
  if (analytics.audit_event_retention_records === 0) {
    fail("analytics.audit_event_retention_records", "must be greater than zero");
  }
  if (analytics.guardrail_evaluation_retention_records === 0) {
    fail("analytics.guardrail_evaluation_retention_records", "must be greater than zero");
  }
  if (analytics.billing_event_retention_records === 0) {
    fail("analytics.billing_event_retention_records", "must be greater than zero");
  }
}

/** `validate_metering`. */
export function validateMetering(config: Config): void {
  const metering = config.metering;
  if (metering.export_enabled) {
    if (isBlank(metering.export_endpoint)) fail("metering.export_endpoint", "cannot be empty");
    if (!hasHttpScheme(metering.export_endpoint)) {
      fail("metering.export_endpoint", "must start with http:// or https://");
    }
  }
  if (metering.export_timeout_secs === 0) {
    fail("metering.export_timeout_secs", "must be greater than zero");
  }
  if (isBlank(metering.export_event_type)) fail("metering.export_event_type", "cannot be empty");
  if (isBlank(metering.export_source)) fail("metering.export_source", "cannot be empty");
  const hasTokenEnv = isSetAndPresent(metering.export_token_env);
  const hasInlineToken = isSetAndPresent(metering.export_token);
  if (metering.export_enabled && !hasTokenEnv && !hasInlineToken) {
    fail(
      "metering.export_token_env",
      "required when metering export is enabled unless metering.export_token is set",
    );
  }
}

/** `validate_cache`. */
export function validateCache(config: Config): void {
  const cache = config.cache;
  if (cache.ttl_secs === 0) fail("cache.ttl_secs", "must be greater than zero");
  if (cache.max_records === 0) fail("cache.max_records", "must be greater than zero");
  if (cache.mode === "semantic") {
    const threshold = cache.semantic_similarity_threshold;
    if (!(threshold > 0 && threshold <= 1)) {
      fail(
        "cache.semantic_similarity_threshold",
        "must be within (0.0, 1.0] for semantic mode",
      );
    }
  }
}

/** `validate_postgres_wire_storage` — shared by the supabase and postgres arms. */
function validatePostgresWireStorage(config: Config, fieldPrefix: string): void {
  const storage = config.storage;
  if (storage.postgres_pool_size === 0) {
    fail("storage.postgres_pool_size", "must be greater than zero");
  }
  if (storage.postgres_pool_acquire_timeout_millis === 0) {
    fail("storage.postgres_pool_acquire_timeout_millis", "must be greater than zero");
  }
  if (storage.postgres_connect_timeout_secs === 0) {
    fail("storage.postgres_connect_timeout_secs", "must be greater than zero");
  }
  if (storage.postgres_statement_timeout_millis === 0) {
    fail("storage.postgres_statement_timeout_millis", "must be greater than zero");
  }
  if (isSetAndBlank(storage.postgres_tls_ca_cert_path)) {
    fail("storage.postgres_tls_ca_cert_path", "must not be empty when set");
  }
  if (storage.postgres_schema !== null) {
    validatePostgresIdentifier("storage.postgres_schema", storage.postgres_schema);
  }
  for (let index = 0; index < storage.postgres_search_path.length; index += 1) {
    validatePostgresIdentifier(
      `storage.postgres_search_path[${index}]`,
      storage.postgres_search_path[index]!,
    );
  }
  if (
    fieldPrefix === "storage.supabase" &&
    (storage.postgres_tls_mode === "disable" || storage.postgres_tls_mode === "prefer")
  ) {
    fail(
      "storage.postgres_tls_mode",
      "supabase requires TLS mode require, verify_ca, or verify_full",
    );
  }
}

/** `validate_storage`. */
export function validateStorage(config: Config): void {
  const storage = config.storage;
  if (storage.provider_order.length === 0) {
    fail("storage.provider_order", "must include at least one durable provider");
  }
  const seen = new Set<StorageProviderKind>();
  for (let index = 0; index < storage.provider_order.length; index += 1) {
    const provider = storage.provider_order[index]!;
    if (provider === "memory") {
      fail(`storage.provider_order[${index}]`, "memory is not a durable provider");
    }
    if (seen.has(provider)) {
      fail(`storage.provider_order[${index}]`, `duplicate storage provider ${provider}`);
    }
    seen.add(provider);
  }
  if (storage.provider_order[0] !== "supabase") {
    fail("storage.provider_order[0]", "supabase must be the default commercial cloud provider");
  }
  if (storage.provider_order.includes("turso_libsql")) {
    fail(
      "storage.provider_order",
      "turso_libsql has been removed from production durable provider order; migrate " +
        "storage.provider to supabase",
    );
  }
  if (storage.provider === "turso_libsql") {
    fail(
      "storage.provider",
      "turso_libsql has been removed as a production durable provider; migrate to " +
        "storage.provider: supabase with storage.supabase_dsn_env",
    );
  }
  if (storage.provider_order.includes("mysql")) {
    fail(
      "storage.provider_order",
      "mysql has been removed from production durable provider order; migrate storage.provider " +
        "to supabase",
    );
  }
  if (storage.provider === "mysql") {
    fail(
      "storage.provider",
      "mysql has been removed as a production durable provider; migrate to storage.provider: " +
        "supabase with storage.supabase_dsn_env",
    );
  }
  if (!isImplementedProvider(storage.provider)) {
    fail("storage.provider", `provider ${storage.provider} is not implemented yet`);
  }
  if (storage.provider === "supabase") {
    if (!isSetAndPresent(storage.supabase_dsn_env)) {
      fail("storage.supabase_dsn_env", "required when storage.provider is supabase");
    }
    validatePostgresWireStorage(config, "storage.supabase");
  }
  if (storage.provider === "postgres") {
    const hasInlineDsn = isSetAndPresent(storage.postgres_dsn);
    const hasDsnEnv = isSetAndPresent(storage.postgres_dsn_env);
    if (!hasInlineDsn && !hasDsnEnv) {
      fail(
        "storage.postgres_dsn_env",
        "required when storage.provider is postgres unless storage.postgres_dsn is set",
      );
    }
    validatePostgresWireStorage(config, "storage.postgres");
  }
  if (storage.provider === "cloudflare_d1" && config.cloudflare === null) {
    fail(
      "storage.provider",
      "cloudflare_d1 requires a [cloudflare] block to build the D1 REST client",
    );
  }
  if (storage.required && !isDurableProvider(storage.provider)) {
    fail("storage.required", "durable storage requires a non-memory provider");
  }
  if (storage.admin_list_default_limit === 0) {
    fail("storage.admin_list_default_limit", "must be greater than zero");
  }
  if (storage.admin_list_max_limit === 0) {
    fail("storage.admin_list_max_limit", "must be greater than zero");
  }
  if (storage.admin_list_default_limit > storage.admin_list_max_limit) {
    fail(
      "storage.admin_list_default_limit",
      "must be less than or equal to storage.admin_list_max_limit",
    );
  }
}

/** `validate_reliability`. */
export function validateReliability(config: Config): void {
  const reliability = config.reliability;
  const threshold = reliability.provider_circuit_breaker_failure_threshold;
  const cooldown = reliability.provider_circuit_breaker_cooldown_secs;
  if (threshold === 0) {
    fail("reliability.provider_circuit_breaker_failure_threshold", "must be greater than zero");
  } else if (cooldown === 0) {
    fail("reliability.provider_circuit_breaker_cooldown_secs", "must be greater than zero");
  } else if (threshold !== null && cooldown === null) {
    fail(
      "reliability.provider_circuit_breaker_cooldown_secs",
      "required when provider circuit breaker threshold is set",
    );
  } else if (threshold === null && cooldown !== null) {
    fail(
      "reliability.provider_circuit_breaker_failure_threshold",
      "required when provider circuit breaker cooldown is set",
    );
  }
  if (reliability.provider_dispatch_timeout_secs === 0) {
    fail("reliability.provider_dispatch_timeout_secs", "must be greater than zero");
  }
  if (reliability.provider_response_body_max_bytes === 0) {
    fail("reliability.provider_response_body_max_bytes", "must be greater than zero");
  }
  if (reliability.tool_approval_timeout_secs === 0) {
    fail("reliability.tool_approval_timeout_secs", "must be greater than zero");
  }
  if (reliability.mcp_dispatch_timeout_secs === 0) {
    fail("reliability.mcp_dispatch_timeout_secs", "must be greater than zero");
  }
  if (reliability.mcp_dispatch_max_concurrency === 0) {
    fail("reliability.mcp_dispatch_max_concurrency", "must be greater than zero");
  }
  if (reliability.graceful_shutdown_grace_period_secs === 0) {
    fail("reliability.graceful_shutdown_grace_period_secs", "must be greater than zero");
  }
  if (reliability.graceful_shutdown_timeout_secs === 0) {
    fail("reliability.graceful_shutdown_timeout_secs", "must be greater than zero");
  }
  // Parity-only on CF (no process to hand a listener to), but these are plain
  // string/number checks, so they are ported rather than removed.
  if (isSetAndBlank(reliability.graceful_upgrade_pid_file)) {
    fail("reliability.graceful_upgrade_pid_file", "cannot be empty");
  }
  if (isSetAndBlank(reliability.graceful_upgrade_sock)) {
    fail("reliability.graceful_upgrade_sock", "cannot be empty");
  }
  if (reliability.graceful_upgrade_sock_retries === 0) {
    fail("reliability.graceful_upgrade_sock_retries", "must be greater than zero");
  }
}

/** #312: the `[limits]` request-body caps. Zero rejects every body; >1 GiB is a mistake. */
export function validateLimits(config: Config): void {
  const MAX_BODY_CAP_BYTES = 1024 * 1024 * 1024;
  const limits = config.limits;
  const knobs: [string, number | null][] = [
    ["limits.inference_body_max_bytes", limits.inference_body_max_bytes],
    ["limits.admin_body_max_bytes", limits.admin_body_max_bytes],
    ["limits.admin_small_body_max_bytes", limits.admin_small_body_max_bytes],
    ["limits.admin_config_body_max_bytes", limits.admin_config_body_max_bytes],
    ["limits.tool_body_max_bytes", limits.tool_body_max_bytes],
    ["limits.asset_control_body_max_bytes", limits.asset_control_body_max_bytes],
    ["limits.agent_ingress_body_max_bytes", limits.agent_ingress_body_max_bytes],
    ["limits.worker_transport_body_max_bytes", limits.worker_transport_body_max_bytes],
    ["limits.guardrail_policy_body_max_bytes", limits.guardrail_policy_body_max_bytes],
  ];
  for (const [field, value] of knobs) {
    if (value === null) continue;
    if (value === 0) fail(field, "must be greater than zero");
    if (value > MAX_BODY_CAP_BYTES) {
      fail(field, `must not exceed ${MAX_BODY_CAP_BYTES} bytes (1 GiB)`);
    }
  }
}

/** `validate_managed_worker_action_list`. */
function validateManagedWorkerActionList(field: string, actions: string[]): void {
  const seen = new Set<string>();
  for (const action of actions) {
    if (seen.has(action)) fail(field, "duplicate capability action");
    seen.add(action);
  }
}

/** `validate_agent_runtime`. */
export function validateAgentRuntime(config: Config): void {
  const runtime = config.agent_runtime;
  if (runtime.max_turns === 0) fail("agent_runtime.max_turns", "must be greater than zero");
  if (runtime.timeout_millis === 0) fail("agent_runtime.timeout_millis", "must be greater than zero");
  if (runtime.provider === "managed_worker") {
    const worker = runtime.managed_worker;
    if (worker.external_action_authorizer_http_listen !== null) {
      fail(
        "agent_runtime.managed_worker.external_action_authorizer_http_listen",
        `insecure plaintext authorizer transport is unsupported; configure ` +
          `external_action_authorizer_socket in a private owner-only directory (authenticated ` +
          `guest transport remains tracked in #205), got ` +
          `${JSON.stringify(worker.external_action_authorizer_http_listen)}`,
      );
    }
    if (isSetAndBlank(worker.external_action_authorizer_socket)) {
      fail(
        "agent_runtime.managed_worker.external_action_authorizer_socket",
        "must not be empty when provided",
      );
    }
    if (worker.external_action_authorizer_max_requests === 0) {
      fail(
        "agent_runtime.managed_worker.external_action_authorizer_max_requests",
        "must be greater than zero when provided",
      );
    }
    validateManagedWorkerActionList(
      "agent_runtime.managed_worker.allowed_actions",
      worker.allowed_actions,
    );
    validateManagedWorkerActionList(
      "agent_runtime.managed_worker.approval_required_actions",
      worker.approval_required_actions,
    );
    if (
      worker.class_only_policy_mode === "deny" &&
      (worker.allowed_actions.length > 0 || worker.approval_required_actions.length > 0)
    ) {
      fail(
        "agent_runtime.managed_worker.class_only_policy_mode",
        "class-only actions require explicit legacy_class_wide migration mode; otherwise replace " +
          "them with target_grants",
      );
    }
    if (isBlank(worker.policy_revision)) {
      fail("agent_runtime.managed_worker.policy_revision", "must not be empty");
    }
    const selectorIds = new Set<string>();
    for (const grant of worker.target_grants) {
      if (isBlank(grant.selector_id)) {
        fail("agent_runtime.managed_worker.target_grants.selector_id", "must not be empty");
      }
      if (isBlank(grant.permission_key)) {
        fail("agent_runtime.managed_worker.target_grants.permission_key", "must not be empty");
      }
      if (selectorIds.has(grant.selector_id)) {
        fail(
          "agent_runtime.managed_worker.target_grants",
          `duplicate selector_id ${grant.selector_id}`,
        );
      }
      selectorIds.add(grant.selector_id);
      if (!selectorSupportsAction(grant.selector, grant.action)) {
        fail(
          "agent_runtime.managed_worker.target_grants",
          `selector ${grant.selector_id} is incompatible with action ${capabilityActionAsStr(grant.action)}`,
        );
      }
      const reason = validateCapabilityTargetSelector(grant.selector);
      if (reason !== null) {
        fail(`agent_runtime.managed_worker.target_grants selector ${grant.selector_id}`, reason);
      }
    }
  } else {
    if (isBlank(runtime.external.command)) {
      fail("agent_runtime.external.command", "must not be empty when provider is external");
    }
    if (runtime.external.timeout_millis === 0) {
      fail("agent_runtime.external.timeout_millis", "must be greater than zero");
    }
  }
}

/**
 * `validate_cluster`.
 *
 * The signed-snapshot leg: Rust runs the SAME builder the runtime uses
 * (`build_snapshot_crypto`), so a config that validates is one that constructs.
 * The TS builder is `async` (WebCrypto `importKey`), and `validateConfig` is
 * sync, so the STRUCTURAL half of that builder is mirrored here and the key
 * material itself is parsed by `validateConfigAsync`, which awaits the real
 * `buildSnapshotCrypto`. Same messages, both paths.
 */
export function validateCluster(config: Config): void {
  const cluster = config.cluster;
  if (!cluster.enabled) return;
  if (isBlank(cluster.cluster_id)) {
    fail("cluster.cluster_id", "cannot be empty when cluster mode is enabled");
  }
  if (isBlank(cluster.node_id)) {
    fail("cluster.node_id", "cannot be empty when cluster mode is enabled");
  }
  if (isSetAndBlank(cluster.node_region)) fail("cluster.node_region", "cannot be empty");
  if (isSetAndBlank(cluster.node_zone)) fail("cluster.node_zone", "cannot be empty");
  if (isBlank(cluster.state_backend)) fail("cluster.state_backend", "cannot be empty");
  if (isBlank(cluster.counter_backend)) fail("cluster.counter_backend", "cannot be empty");
  if (cluster.counter_timeout_millis === 0) {
    fail("cluster.counter_timeout_millis", "must be greater than zero");
  }
  if (cluster.heartbeat_interval_secs === 0) {
    fail("cluster.heartbeat_interval_secs", "must be greater than zero");
  }
  if (cluster.config_poll_interval_secs === 0) {
    fail("cluster.config_poll_interval_secs", "must be greater than zero");
  }
  switch (cluster.state_backend) {
    case "local":
      break;
    case "file": {
      if (!isSetAndPresent(cluster.file_state_path)) {
        fail("cluster.file_state_path", "required when cluster.state_backend is file");
      }
      break;
    }
    default:
      fail(
        "cluster.state_backend",
        "only local and file are supported until database shared state lands",
      );
  }
  if (cluster.counter_backend !== "local") {
    if (cluster.counter_backend !== "redis") {
      fail("cluster.counter_backend", "only local and redis are supported");
    }
    const redisUrl = cluster.redis_url;
    if (redisUrl === null || isBlank(redisUrl)) {
      fail("cluster.redis_url", "required when cluster.counter_backend is redis");
    }
    if (!redisUrl.startsWith("redis://") && !redisUrl.startsWith("rediss://")) {
      fail("cluster.redis_url", "must start with redis:// or rediss://");
    }
  }
  validateClusterSnapshotShape(config);
}

/**
 * The synchronous half of `build_snapshot_crypto` (#206) — identity, key-id and
 * trusted-key-list invariants that need no WebCrypto import. Messages are the
 * `SnapshotConfigError` texts verbatim so the sync and async paths agree.
 */
function validateClusterSnapshotShape(config: Config): void {
  const cluster = config.cluster;
  const signingEnabled = isSetAndPresent(cluster.snapshot_signing_key);
  const verificationEnabled = cluster.snapshot_trusted_keys.length > 0;
  if (!signingEnabled && !verificationEnabled) return;

  for (const [value, field] of [
    [cluster.snapshot_tenant_id, "cluster.snapshot_tenant_id"],
    [cluster.snapshot_deployment_id, "cluster.snapshot_deployment_id"],
  ] as const) {
    if (!isSetAndPresent(value)) {
      fail(field, "required when snapshot signing or verification is enabled");
    }
  }
  if (signingEnabled) {
    if (cluster.snapshot_max_age_secs === 0) {
      fail("cluster.snapshot_max_age_secs", "must be greater than zero when signing is enabled");
    }
    if (!isSetAndPresent(cluster.snapshot_signing_key_id)) {
      fail(
        "cluster.snapshot_signing_key_id",
        "required when cluster.snapshot_signing_key is set",
      );
    }
  }
  const keyIds = new Set<string>();
  for (const entry of cluster.snapshot_trusted_keys) {
    const keyId = entry.key_id.trim();
    if (keyId.length === 0) fail("cluster.snapshot_trusted_keys", "key_id cannot be empty");
    if (keyIds.has(keyId)) {
      fail("cluster.snapshot_trusted_keys", `duplicate key_id "${keyId}"`);
    }
    keyIds.add(keyId);
  }
}

/** `validate_network_access` (issue #166). */
export function validateNetworkAccess(config: Config): void {
  const networkAccess = config.network_access;
  for (let index = 0; index < networkAccess.ip_allowlist.length; index += 1) {
    const entry = networkAccess.ip_allowlist[index]!;
    try {
      IpCidr.parse(entry);
    } catch (error) {
      fail(
        `network_access.ip_allowlist[${index}]`,
        `${error instanceof Error ? error.message : String(error)} (value: ${JSON.stringify(entry)})`,
      );
    }
  }
  if (networkAccess.unauthenticated_rate_limit_per_minute === 0) {
    fail(
      "network_access.unauthenticated_rate_limit_per_minute",
      "must be greater than zero when set",
    );
  }
}

/**
 * The compensating control for the REMOVED `validate_tls`/`validate_acme_*`
 * family (see the module header): `[tls]` and `[tls.acme]` still DECODE so a
 * legacy TOML/Caddyfile round-trips, but nothing on this platform reads them.
 * Accepting them in silence would tell an operator that TLS is configured when
 * it is not — the exact lie `validateMcpTlsConfig` refuses to tell — so instead
 * of validating an invariant the runtime can neither satisfy nor violate, the
 * load reports the section as INERT.
 *
 * Warn-only (not a refusal) on purpose: refusing would break the Caddyfile
 * migration path, where `fromGatewayConfig` emits `[tls]` from a `tls`/`tls_acme`
 * directive and Rust accepts the same document.
 *
 * Returns the warnings; wired into `loadConfigFromObject`, which is the only
 * place a caller sees them.
 */
export function inertTlsWarnings(config: Config): string[] {
  const warnings: string[] = [];
  const tls = config.tls;
  const manual = tls.enabled || tls.cert_path !== null || tls.key_path !== null;
  if (manual) {
    warnings.push(
      "[tls] is INERT on Cloudflare: the edge terminates TLS before the Worker is invoked, so " +
        "there is no listener to bind and no cert/key file to load (cert_path/key_path are not " +
        "read). The section is kept only so a legacy config still loads -- manage certificates " +
        "with Cloudflare SSL/TLS + Custom Hostnames instead.",
    );
  }
  if (tls.acme.enabled) {
    warnings.push(
      "[tls.acme] is INERT on Cloudflare: no ACME certificate is requested or renewed. A Worker " +
        "cannot own the :80 HTTP-01 challenge listener, has no filesystem for the ACME account " +
        "storage_dir, and cannot exec a DNS-01 hook. Certificates are issued by Cloudflare.",
    );
  }
  return warnings;
}

/**
 * The compensating control for the STANDALONE BILLING SERVICE, which is not part
 * of the Cloudflare deployment topology (inventory-data-billing §2.4/§2.5; the
 * decision recorded at `@ferrogate/billing`'s `createBillingService`).
 *
 * What is REAL and stays real: `billing_service.enabled = true` still means
 * "billing reporting is on", and it still gates the issue-#146 price-completeness
 * refusal in `validate/entities.ts` — a model or fallback route with no
 * gateway-side price is rejected at load, exactly as in Rust.
 *
 * What is INERT: the HTTP-CLIENT half — `endpoint`, `timeout_millis`, `token`,
 * `token_env`. In Rust the gateway POSTs each settlement to a separate
 * `ferrogate-billing serve` process at that endpoint. On Cloudflare the gateway
 * settles IN-PROCESS (`apps/gateway/src/metering/*` calls `charge()` directly and
 * drains `billing_report_outbox`), the committed 258-operation contract carries
 * no `/v1/billing/*` operation, and nothing dials `endpoint`. The handler in
 * `@ferrogate/billing` is retained as a portable Fetch handler for a
 * self-hosted deployment; it is mounted on no Worker here.
 *
 * Warn-only, and only when a NON-DEFAULT endpoint/token is present: an operator
 * who merely flips `enabled` is using the supported in-process path and should
 * not be nagged, while one who points the section at a real host must be told
 * nothing will dial it. Silence there is the lie this exists to prevent.
 */
export function inertBillingServiceWarnings(config: Config): string[] {
  const billing = config.billing_service;
  const endpointConfigured =
    billing.endpoint.trim() !== "" && billing.endpoint !== BILLING_SERVICE_DEFAULT_ENDPOINT;
  const tokenConfigured = billing.token !== null || billing.token_env !== null;
  if (!endpointConfigured && !tokenConfigured) return [];
  return [
    "[billing_service] endpoint/token are INERT on Cloudflare: no Worker dials the standalone " +
      "billing service, and the runtime API contract carries no /v1/billing/* operation. The " +
      "gateway settles IN-PROCESS (charge() plus the billing_report_outbox drain), so " +
      "billing_service.enabled still turns reporting on and still requires a price on every " +
      "model and fallback route -- only the HTTP client half is unused.",
  ];
}

/**
 * `validate_cloudflare_ai_gateway_providers` (issue #406). Runs AFTER
 * `validate_cloudflare`, so a malformed `[cloudflare]` block is already rejected.
 */
export function validateCloudflareAiGatewayProviders(config: Config): void {
  for (let index = 0; index < config.providers.length; index += 1) {
    const routing = config.providers[index]!.cloudflare_ai_gateway;
    if (routing === null) continue;
    const at = (field: string) => `providers[${index}].cloudflare_ai_gateway${field}`;
    const cloudflare = config.cloudflare;
    if (cloudflare === null) {
      fail(
        at(""),
        "requires a top-level [cloudflare] block (issue #405) for the account id and base URLs",
      );
    }
    if (isBlank(cloudflare.account_id)) fail(at(""), "[cloudflare].account_id cannot be empty");
    if (isBlank(routing.gateway_id)) fail(at(".gateway_id"), "cannot be empty");
    if (routing.aig_token_secret_ref !== null) {
      if (isBlank(routing.aig_token_secret_ref)) {
        fail(at(".aig_token_secret_ref"), "cannot be empty");
      }
      validateSecretRef(at(".aig_token_secret_ref"), routing.aig_token_secret_ref);
    }
  }
}

/**
 * `validate_x402_spend_policies` (issue #351): money config fails at load, never
 * at the first payment.
 *
 * PORT-TODO(D: inventory §5.2) — DELIBERATE PRODUCT DECISION, not a platform gap:
 * x402/Solana is deprioritized. The per-policy `X402SpendPolicy::validate()` leg is
 * owned by `@ferrogate/policy` (wave 2; x402 is deprioritized) — see
 * `../x402-scope.ts`. The scope-shape half (blank / duplicate `(scope_type,
 * scope_id)`) is enforced here.
 */
export function validateX402SpendPolicies(config: Config): void {
  const declarationSchema = z
    .object({
      scope_type: x402PolicyScopeKindSchema,
      scope_id: z.string(),
      policy: z.unknown(),
    })
    .passthrough();
  const declared: X402ScopedSpendPolicy[] = config.x402_spend_policies.map((entry, index) => {
    const parsed = declarationSchema.safeParse(entry);
    if (!parsed.success) {
      // Rust rejects this shape during deserialization; the TS schema carries the
      // policy body opaquely (PORT-TODO above), so the shape is decided here.
      fail(`x402_spend_policies[${index}]`, parsed.error.issues[0]?.message ?? "invalid declaration");
    }
    return {
      scope_type: parsed.data.scope_type,
      scope_id: parsed.data.scope_id,
      policy: parsed.data.policy,
    };
  });
  const error = validateScopedX402SpendPolicies(declared);
  if (error !== null) fail("x402_spend_policies", describeX402ScopedPolicyError(error));
}
