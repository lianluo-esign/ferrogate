/**
 * Backend selection / lifecycle types (ports the `StorageProviderKind`,
 * `PostgresTlsMode`, `PostgresStorageConfig`, `StorageProviderConfig` surface
 * from `ferrogate-storage::lib`).
 *
 * In the CF port the durable backend is **D1** (SQLite); Postgres config is
 * retained as reference metadata so a migration path and the schema-evidence
 * checks stay expressible, but a Worker holds no warm pool (see inventory §1.6,
 * the ~16-connection Supavisor cap this move eliminates).
 */

/** Which storage engine backs the control plane. Mirrors the Rust enum. */
export type StorageProviderKind =
  | "memory"
  | "supabase"
  | "turso_libsql"
  | "postgres"
  | "mysql"
  | "cloudflare_d1";

/** The default order in which a durable provider is preferred at startup. */
export const DEFAULT_DURABLE_PROVIDER_ORDER: readonly StorageProviderKind[] = [
  "supabase",
  "postgres",
];

/** True when the provider persists across process restarts (everything but `memory`). */
export function providerIsDurable(kind: StorageProviderKind): boolean {
  return kind !== "memory";
}

/**
 * Whether a real backend implementation exists for this provider. Mirrors the
 * Rust `implemented()` set: Memory, Supabase, Postgres, CloudflareD1 are live;
 * Turso/MySQL are declared but not implemented.
 */
export function providerIsImplemented(kind: StorageProviderKind): boolean {
  return (
    kind === "memory" ||
    kind === "supabase" ||
    kind === "postgres" ||
    kind === "cloudflare_d1"
  );
}

export interface StorageProviderConfig {
  kind: StorageProviderKind;
  required: boolean;
}

/** The `memory` provider config (non-durable, non-required) used for tests/dev. */
export function memoryProviderConfig(): StorageProviderConfig {
  return { kind: "memory", required: false };
}

/** libpq TLS negotiation modes. Retained for the Postgres migration reference. */
export type PostgresTlsMode = "disable" | "prefer" | "require" | "verify_ca" | "verify_full";

/**
 * Postgres/Supabase connection config (ports `PostgresStorageConfig`).
 *
 * PORT-TODO(§1.6): no CF equivalent — a Worker cannot hold a warm connection
 * pool. `poolSize` / `poolAcquireTimeoutMillis` are inert on the D1 backend and
 * kept only so a Supabase→D1 migration tool can read the source config.
 */
export interface PostgresStorageConfig {
  dsn: string;
  poolSize: number;
  poolAcquireTimeoutMillis: number;
  tlsMode: PostgresTlsMode;
  tlsCaCertPath?: string;
  connectTimeoutSecs: number;
  statementTimeoutMillis: number;
  schema?: string;
  searchPath: string[];
}

/** The Rust `default_postgres_pool_size()` (inventory §1.6). */
export const DEFAULT_POSTGRES_POOL_SIZE = 4;
/** The Rust default pool-acquire timeout (inventory §1.6). */
export const DEFAULT_POOL_ACQUIRE_TIMEOUT_MILLIS = 1000;
