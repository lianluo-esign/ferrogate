/**
 * The control-plane's CONTROL storage seam (Zero-D1 S3, issue #879).
 *
 * CONTROL is a singleton Durable Object addressed as `"control"`. The
 * control-plane still receives a D1-shaped handle so its stores do not need
 * to know whether the backend is the object or the temporary D1 compatibility
 * path. This module owns the posture switch and is the only control-plane
 * module that reads `env.CONTROL_DATA`.
 */
import { type ControlDataNamespaceLike, controlDataObjectDatabase } from "@ferrogate/storage";
import type { ControlDataNamespace } from "@ferrogate/storage/durable-objects";
import { HttpError } from "./middleware/errors.js";

/** Supported CONTROL storage postures, with the safe default first. */
export type ControlStorageMode = "durable_object" | "d1_compat";

export const CONTROL_STORAGE_MODES: readonly ControlStorageMode[] = [
  "durable_object",
  "d1_compat",
] as const;

/** Stable 503 code for an absent or invalid CONTROL storage configuration. */
export const CONTROL_STORAGE_MISCONFIGURED = "control_storage_misconfigured";

/** Bindings consumed by this seam. `DB` is the legacy control-plane D1. */
export interface ControlDataBindings {
  readonly CONTROL_PLANE_CONTROL_STORAGE?: string;
  readonly CONTROL_DATA?: ControlDataNamespace;
  readonly DB?: D1Database;
}

/** Parse `CONTROL_PLANE_CONTROL_STORAGE`; empty and absent select the DO posture. */
export function parseControlStorageMode(raw: string | undefined): ControlStorageMode | undefined {
  const value = (raw ?? "").trim();
  if (value === "") return "durable_object";
  return CONTROL_STORAGE_MODES.find((mode) => mode === value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isControlDatabase(value: unknown): value is D1Database {
  return isObject(value) && typeof value.prepare === "function";
}

/**
 * Resolve one control-read database, preferring the CONTROL_DATA facade.
 *
 * The default posture uses the Durable Object when it is bound and falls back
 * to the caller's legacy D1 candidates when the binding is absent. Explicit
 * `d1_compat` skips the object entirely. An unknown posture is the one hard
 * configuration failure: the resolver refuses to guess.
 */
export function controlDatabaseFrom(
  env: unknown,
  options: { readonly legacy?: readonly unknown[] } = {},
): D1Database | undefined {
  if (!isObject(env)) return undefined;
  const bindings = env as ControlDataBindings;
  // Read through `(env as T).X` so the env-var-drift scanner sees a genuine
  // source read of CONTROL_PLANE_CONTROL_STORAGE.
  const mode = parseControlStorageMode((env as ControlDataBindings).CONTROL_PLANE_CONTROL_STORAGE);
  if (mode === undefined) {
    throw new HttpError(
      503,
      CONTROL_STORAGE_MISCONFIGURED,
      `CONTROL_PLANE_CONTROL_STORAGE = "${bindings.CONTROL_PLANE_CONTROL_STORAGE}" is not one of ` +
        `${CONTROL_STORAGE_MODES.join(", ")}; refusing to guess a control-storage posture`,
    );
  }

  // Read via `(env as T).X` so the env-var-drift scanner sees a genuine source
  // read of CONTROL_DATA (it does not follow the renamed `bindings` local).
  const controlData = (env as ControlDataBindings).CONTROL_DATA;
  if (mode === "durable_object" && controlData !== undefined) {
    return controlDataObjectDatabase(controlData as unknown as ControlDataNamespaceLike);
  }

  const legacy = options.legacy ?? [bindings.DB];
  for (const candidate of legacy) {
    if (isControlDatabase(candidate)) return candidate;
  }
  return undefined;
}
