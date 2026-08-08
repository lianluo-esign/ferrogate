/**
 * The control-plane's CONTROL storage seam (Zero-D1 S3, issue #879).
 *
 * CONTROL is a singleton Durable Object addressed as `"control"`. The
 * control-plane receives a D1-shaped handle (the `DurableObjectD1Database`
 * facade) so its stores do not need to know the backend is a Durable Object.
 * This module owns the posture switch and is the only control-plane module
 * that reads `env.CONTROL_DATA`. Since Zero-D1 S5 (#881) there is no `DB`
 * (`ferrogate-control`) fallback: the object is the only backend.
 */
import { type ControlDataNamespaceLike, controlDataObjectDatabase } from "@ferrogate/storage";
import type { ControlDataNamespace } from "@ferrogate/storage/durable-objects";
import { HttpError } from "./middleware/errors.js";

/** Supported CONTROL storage postures. Since Zero-D1 S5 the DO is the only one. */
export type ControlStorageMode = "durable_object";

export const CONTROL_STORAGE_MODES: readonly ControlStorageMode[] = ["durable_object"] as const;

/** Stable 503 code for an absent or invalid CONTROL storage configuration. */
export const CONTROL_STORAGE_MISCONFIGURED = "control_storage_misconfigured";

/** Bindings consumed by this seam. */
export interface ControlDataBindings {
  readonly CONTROL_PLANE_CONTROL_STORAGE?: string;
  readonly CONTROL_DATA?: ControlDataNamespace;
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

/**
 * Resolve one control-read database from the CONTROL_DATA facade.
 *
 * Since Zero-D1 S5 (#881) the Durable Object is the only backend: the facade
 * is returned when CONTROL_DATA is bound, and `undefined` when it is absent (a
 * unit env). An unknown posture is the one hard configuration failure: the
 * resolver refuses to guess.
 */
export function controlDatabaseFrom(env: unknown): D1Database | undefined {
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
  if (controlData !== undefined) {
    return controlDataObjectDatabase(controlData as unknown as ControlDataNamespaceLike);
  }
  return undefined;
}
