import type { D1Database, DurableObjectNamespace } from "@cloudflare/workers-types";
import {
  type ControlDataNamespaceLike,
  controlD1ReplicaDatabase,
  controlDataObjectDatabase,
} from "@ferrogate/storage";
import { HttpError } from "./middleware/errors";

// Zero-D1 S5 (#881): the DO was the only backend. The D1 migration re-adds a
// `d1` posture — agent-runtime is a READ-ONLY control consumer, so `d1` reads
// through a `withSession("first-unconstrained")` replica session.
export const CONTROL_STORAGE_MODES = ["durable_object", "d1"] as const;
export type ControlStorageMode = (typeof CONTROL_STORAGE_MODES)[number];
export const CONTROL_STORAGE_MISCONFIGURED = "CONTROL_STORAGE_MISCONFIGURED";

type AgentRuntimeControlStorageBindings = {
  AGENT_RUNTIME_CONTROL_STORAGE?: unknown;
  CONTROL_DATA?: DurableObjectNamespace;
  CONTROL_D1?: D1Database;
};

export function parseControlStorageMode(raw: unknown): ControlStorageMode {
  if (raw === undefined || raw === null || raw === "") {
    return "durable_object";
  }
  if (raw === "durable_object" || raw === "d1") {
    return raw;
  }
  throw new HttpError(
    503,
    CONTROL_STORAGE_MISCONFIGURED,
    `Unsupported AGENT_RUNTIME_CONTROL_STORAGE value: ${String(raw)}`,
  );
}

export function controlDatabaseFrom(env: unknown): D1Database | undefined {
  // Read the posture so the env-var-drift gate sees AGENT_RUNTIME_CONTROL_STORAGE
  // consumed; an unrecognized value throws before we resolve the object.
  const mode = parseControlStorageMode(
    (env as AgentRuntimeControlStorageBindings).AGENT_RUNTIME_CONTROL_STORAGE,
  );
  if (mode === "d1") {
    const d1 = (env as AgentRuntimeControlStorageBindings).CONTROL_D1;
    return d1 ? controlD1ReplicaDatabase(d1) : undefined;
  }
  const controlData = (env as AgentRuntimeControlStorageBindings).CONTROL_DATA as unknown as
    | ControlDataNamespaceLike
    | undefined;
  return controlData ? controlDataObjectDatabase(controlData) : undefined;
}
