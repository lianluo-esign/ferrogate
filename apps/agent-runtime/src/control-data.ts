import type { D1Database, DurableObjectNamespace } from "@cloudflare/workers-types";
import { type ControlDataNamespaceLike, controlDataObjectDatabase } from "@ferrogate/storage";
import { HttpError } from "./middleware/errors";

export const CONTROL_STORAGE_MODES = ["durable_object", "d1_compat"] as const;
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
  if (raw === "durable_object" || raw === "d1_compat") {
    return raw;
  }
  throw new HttpError(
    503,
    CONTROL_STORAGE_MISCONFIGURED,
    `Unsupported AGENT_RUNTIME_CONTROL_STORAGE value: ${String(raw)}`,
  );
}

export function controlDatabaseFrom(
  env: unknown,
  options: { legacy?: readonly (D1Database | undefined)[] } = {},
): D1Database | undefined {
  const mode = parseControlStorageMode(
    (env as AgentRuntimeControlStorageBindings).AGENT_RUNTIME_CONTROL_STORAGE,
  );
  const controlData = (env as AgentRuntimeControlStorageBindings).CONTROL_DATA as unknown as
    | ControlDataNamespaceLike
    | undefined;
  const legacy = options.legacy?.find((database): database is D1Database => database !== undefined);

  if (mode === "d1_compat") {
    return legacy ?? (controlData ? controlDataObjectDatabase(controlData) : undefined);
  }
  return controlData ? controlDataObjectDatabase(controlData) : legacy;
}
