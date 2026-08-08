import type { D1Database, DurableObjectNamespace } from "@cloudflare/workers-types";
import { type ControlDataNamespaceLike, controlDataObjectDatabase } from "@ferrogate/storage";
import { HttpError } from "./middleware/errors";

// Zero-D1 S5 (#881): the DO is the only backend; the `d1_compat` posture and
// the `env.CONTROL_DB` fallback are gone.
export const CONTROL_STORAGE_MODES = ["durable_object"] as const;
export type ControlStorageMode = (typeof CONTROL_STORAGE_MODES)[number];
export const CONTROL_STORAGE_MISCONFIGURED = "CONTROL_STORAGE_MISCONFIGURED";

type AgentRuntimeControlStorageBindings = {
  AGENT_RUNTIME_CONTROL_STORAGE?: unknown;
  CONTROL_DATA?: DurableObjectNamespace;
};

export function parseControlStorageMode(raw: unknown): ControlStorageMode {
  if (raw === undefined || raw === null || raw === "") {
    return "durable_object";
  }
  if (raw === "durable_object") {
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
  parseControlStorageMode(
    (env as AgentRuntimeControlStorageBindings).AGENT_RUNTIME_CONTROL_STORAGE,
  );
  const controlData = (env as AgentRuntimeControlStorageBindings).CONTROL_DATA as unknown as
    | ControlDataNamespaceLike
    | undefined;
  return controlData ? controlDataObjectDatabase(controlData) : undefined;
}
