// Fixture builders for the Operations cockpit tests (#322). Each returns a
// contract-shaped object with sensible defaults, overridable per test.
import type { AdminSchema } from "@/lib/gateway-client";

export function adminStatus(
  overrides: Partial<AdminSchema<"AdminStatus">> = {},
): AdminSchema<"AdminStatus"> {
  return {
    service: "ferrogate",
    version: "1.2.3",
    runtime: "pingora",
    snapshot: "snap-abc",
    providers: 4,
    enabled_providers: 3,
    models: 12,
    enabled_models: 10,
    api_keys: 7,
    prompt_templates: 2,
    upstreams: 5,
    enabled_upstreams: 4,
    routes: 9,
    enabled_routes: 8,
    plugins: 3,
    active_plugins: 2,
    extensions: 1,
    active_extensions: 1,
    tools: 6,
    auth_required: true,
    storage: {
      provider: "postgres",
      durable: true,
      implemented: true,
      required: true,
      migration_mode: "auto",
      health: "ok",
      provider_order: ["postgres", "memory"],
      contract_version: 1,
      schema: {
        engine: "postgres",
        version: 42,
        name: "ferrogate",
        checksum: "sha",
        validated: true,
      },
    },
    analytics: {
      provider: "clickhouse",
      enabled: true,
      active: true,
      required: false,
      mode: "direct_warehouse",
      sink_configured: true,
      signals: ["request_log"],
      export_timeout_secs: 5,
      batch_max_events: 100,
      flush_interval_millis: 1000,
      queue_capacity: 1000,
      request_log_retention_records: 1000,
      audit_event_retention_records: 1000,
      billing_event_retention_records: 1000,
      health: "ok",
      last_success_at_unix: 1_752_000_000,
      last_export_error: null,
      contract_version: 1,
    },
    cluster: {
      enabled: true,
      cluster_id: "cluster-1",
      node_id: "node-a",
      node_region: "us-east",
      node_zone: "a",
      state_backend: "file",
      counter_backend: "redis",
      active_revision: "rev-9",
      last_sync_at_unix: 1_752_000_000,
      last_sync_error: null,
      stale: false,
      ready: true,
      readiness_reason: "state_loaded",
      draining: false,
      accepting_new_requests: true,
    },
    observability: [],
    acme: {
      enabled: true,
      domains: ["gateway.example.com"],
      cert_path: "/certs/cert.pem",
      key_path: "/certs/key.pem",
      certificate_expires_at_unix: 1_760_000_000,
      renewal_window_secs: 2_592_000,
      renewal_due: false,
      last_renewal_status: "ok",
      last_renewal_at_unix: 1_752_000_000,
      last_renewal_error: null,
      next_check_at_unix: 1_759_000_000,
      reload_required: false,
      reload_mode: "hot",
    },
    ...overrides,
  };
}

export function drainStatus(
  overrides: Partial<AdminSchema<"AdminDrainResponse">> = {},
): AdminSchema<"AdminDrainResponse"> {
  return {
    object: "drain_status",
    draining: false,
    accepting_new_requests: true,
    drain_reason: "not_draining",
    ...overrides,
  };
}

export function providerHealth(
  overrides: Partial<AdminSchema<"ProviderHealthCheck">> = {},
): AdminSchema<"ProviderHealthCheck"> {
  const routing: AdminSchema<"ProviderRoutingHealth"> = {} as AdminSchema<"ProviderRoutingHealth">;
  return {
    name: "openai",
    kind: "openai",
    base_url: "https://api.openai.com",
    enabled: true,
    status: "ok",
    reachable: true,
    circuit_open: false,
    consecutive_failures: 0,
    checked_at_unix: 1_752_000_000,
    error: null,
    routing,
    local_observations: routing,
    cluster_observations: null,
    ...overrides,
  };
}

export function gatewayConfigProfile(
  overrides: Partial<AdminSchema<"AdminGatewayConfigProfile">> = {},
): AdminSchema<"AdminGatewayConfigProfile"> {
  return {
    id: "profile-1",
    name: "No-cache agent",
    revision: 1,
    enabled: true,
    api_key_ids: ["key_dev"],
    cache_enabled: false,
    ...overrides,
  };
}
