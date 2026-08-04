/** Shared binding discovery used by asset and inference metering. */
import type { MeteringDatabase, MeteringQueue } from "./ports.js";

export interface MeteringBindings {
  readonly BILLING_DB?: MeteringDatabase | undefined;
  readonly BILLING?: MeteringQueue | undefined;
}

function isMeteringDatabase(value: unknown): value is MeteringDatabase {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<MeteringDatabase>;
  return typeof candidate.prepare === "function" && typeof candidate.batch === "function";
}

function isMeteringQueue(value: unknown): value is MeteringQueue {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<MeteringQueue>;
  return typeof candidate.send === "function" && typeof candidate.sendBatch === "function";
}

export function meteringDatabaseFrom(env: unknown): MeteringDatabase | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as MeteringBindings).BILLING_DB;
  return isMeteringDatabase(candidate) ? candidate : undefined;
}

export function meteringQueueFrom(env: unknown): MeteringQueue | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as MeteringBindings).BILLING;
  return isMeteringQueue(candidate) ? candidate : undefined;
}
