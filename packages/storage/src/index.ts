/**
 * `@ferrogate/storage` — the control-plane store (D1 / KV / R2).
 *
 * Replaces the Rust crate `ferrogate-storage`. The Postgres/Supabase schema is
 * translated to D1 (SQLite); KV backs caches, R2 backs asset blobs.
 */
import type { Scope } from "@ferrogate/core";
import type { ErrorEnvelope } from "@ferrogate/schemas";

/** A stored record always carries the scope it belongs to. */
export interface StoredRecord {
  id: string;
  scope: Scope;
}

/** Backing store kind for a given collection. */
export type StoreBackend = "d1" | "kv" | "r2";

/** Failure shape surfaced by the store, reusing the shared error envelope. */
export type StoreError = ErrorEnvelope;

/**
 * The control-plane store: reads/writes tenancy, IAM, config, agents, billing,
 * and evidence records. Concrete D1/KV/R2 implementations are supplied per app.
 */
export interface ControlPlaneStore {
  get<T extends StoredRecord>(collection: string, id: string): Promise<T | undefined>;
  put<T extends StoredRecord>(collection: string, record: T): Promise<void>;
  delete(collection: string, id: string): Promise<void>;
}
