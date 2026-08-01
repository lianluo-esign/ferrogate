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
 * PORT-TODO(L: §1.6) — PLATFORM LIMIT, NOT CLOSED.
 *
 * The exact limitation: **a Worker isolate cannot hold a warm TCP connection
 * pool.** `deadpool-postgres`'s whole value is a set of long-lived, recycled
 * `Verified` connections owned by a process that outlives a request; a Worker
 * isolate has no such lifetime, is evicted between requests, and its outbound
 * sockets (`connect()`) do not survive the request that opened them. There is
 * no `max_size`, no acquire queue, and therefore no `acquire_wait_micros_total`
 * to record — the metric has no referent. `PostgresTlsMode::verify_ca` /
 * `verify_full` with a `tlsCaCertPath` are separately unreachable: workerd
 * installs no ad-hoc CA roots.
 *
 * The closest behavior implemented instead: **D1 is the durable backend**
 * (`./d1/*`), where a "connection" is a deploy-time binding with no pool to
 * exhaust and no Supavisor ~16-connection deployment cap to divide between
 * instances — which is the single biggest reason the port moves off Postgres at
 * all. This type is retained as an INERT config-shape so a Supabase→D1
 * migration tool can read a Rust-era config; every field below is read by that
 * tool and by nothing on the request path.
 *
 * `test/misc.test.ts` pins the defaults and the inertness.
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
