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

/**
 * Supported CONTROL storage postures.
 *
 * - `durable_object` (default): the singleton `CONTROL_DATA` Durable Object.
 * - `d1`: a real Cloudflare D1 database (`CONTROL_D1`), Tokyo primary + global
 *   read replicas. The control-plane is the SINGLE writer and holds the plain
 *   binding (primary reads/writes) so it reads its own writes unconditionally;
 *   the read-only twins use `withSession("first-unconstrained")` for replica
 *   reads. Selected per-worker via the posture var so each can flip/roll back
 *   independently without a code redeploy.
 */
export type ControlStorageMode = "durable_object" | "d1";

export const CONTROL_STORAGE_MODES: readonly ControlStorageMode[] = [
  "durable_object",
  "d1",
] as const;

/** Stable 503 code for an absent or invalid CONTROL storage configuration. */
export const CONTROL_STORAGE_MISCONFIGURED = "control_storage_misconfigured";

/** Bindings consumed by this seam. */
export interface ControlDataBindings {
  readonly CONTROL_PLANE_CONTROL_STORAGE?: string;
  readonly CONTROL_DATA?: ControlDataNamespace;
  readonly CONTROL_D1?: D1Database;
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

  // D1 posture: the control-plane is the SINGLE writer, so it holds the plain
  // `CONTROL_D1` binding (primary reads/writes) and reads its own writes with no
  // bookmark plumbing. Absent binding (a unit env) falls through to undefined.
  if (mode === "d1") {
    return (env as ControlDataBindings).CONTROL_D1;
  }

  // Read via `(env as T).X` so the env-var-drift scanner sees a genuine source
  // read of CONTROL_DATA (it does not follow the renamed `bindings` local).
  const controlData = (env as ControlDataBindings).CONTROL_DATA;
  if (controlData !== undefined) {
    return controlDataObjectDatabase(controlData as unknown as ControlDataNamespaceLike);
  }
  return undefined;
}
