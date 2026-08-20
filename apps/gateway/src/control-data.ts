/**
 * The gateway's CONTROL storage seam (Zero-D1: #878 wired the seam, #881
 * removed the D1 compatibility leg).
 *
 * CONTROL is a singleton Durable Object addressed as `"control"`. Callers
 * receive a D1-shaped handle (the `DurableObjectD1Database` facade), so the
 * stores that consume CONTROL rows do not need to know the backend is a
 * Durable Object. This module owns the posture switch and is the only gateway
 * module that reads `env.CONTROL_DATA`. There is no longer a `d1_compat`
 * fallback to `CONTROL_DB` / `BILLING_DB`: the object is the only backend.
 */
import {
  type ControlDataNamespaceLike,
  controlD1ReplicaDatabase,
  controlDataObjectDatabase,
} from "@ferrogate/storage";
import type { ControlDataNamespace } from "@ferrogate/storage/durable-objects";
import { HttpError } from "./middleware/errors.js";

/**
 * Supported CONTROL storage postures.
 *
 * - `durable_object` (default): the singleton `CONTROL_DATA` Durable Object.
 * - `d1`: a real Cloudflare D1 database (`CONTROL_D1`). The gateway is a
 *   READ-ONLY control consumer, so it reads through a
 *   `withSession("first-unconstrained")` replica session — a colo-local replica
 *   instead of a cross-region hop to the Tokyo primary. Eventual consistency is
 *   already the posture here (the per-colo `api_key_directory` KV projection,
 *   #882, sits ahead of this read and lags too).
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
  readonly GATEWAY_CONTROL_STORAGE?: string;
  readonly CONTROL_DATA?: ControlDataNamespace;
  readonly CONTROL_D1?: D1Database;
}

/** Parse `GATEWAY_CONTROL_STORAGE`; empty and absent select the DO posture. */
export function parseControlStorageMode(raw: string | undefined): ControlStorageMode | undefined {
  const value = (raw ?? "").trim();
  if (value === "") return "durable_object";
  return CONTROL_STORAGE_MODES.find((mode) => mode === value);
}

/** Read the CONTROL_DATA namespace, refusing a missing default binding by name. */
export function controlDataNamespace(env: ControlDataBindings): ControlDataNamespace {
  const namespace = env.CONTROL_DATA;
  if (namespace === undefined) {
    throw new HttpError(
      503,
      CONTROL_STORAGE_MISCONFIGURED,
      [
        "Durable Object control storage is selected but this Worker has no CONTROL_DATA",
        "namespace bound; declare the [[durable_objects.bindings]] stanza and redeploy.",
      ].join(" "),
    );
  }
  return namespace;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Resolve one control-read database from the CONTROL_DATA facade.
 *
 * Since Zero-D1 S5 (#881) the Durable Object is the ONLY backend. When
 * CONTROL_DATA is bound (the production shape) the caller gets the facade.
 * When it is NOT bound — a unit env, or a Worker the stanza has not yet
 * reached — the seam returns `undefined`, preserving the optional reads'
 * absent-binding behavior (guardrails/RBAC/budget-alerts degrade to their
 * config path rather than 503). An unrecognized `GATEWAY_CONTROL_STORAGE`
 * value is the one hard failure: we refuse to guess a posture.
 *
 * (The stricter {@link controlDataNamespace} — which 503s on an absent
 * namespace — is reserved for the mandatory paths that must not silently skip
 * control storage; the optional control reads that flow through here do not
 * use it.)
 */
export function controlDatabaseFrom(env: unknown): D1Database | undefined {
  if (!isObject(env)) return undefined;
  const bindings = env as ControlDataBindings;
  // Read via `(env as T).X` so the env-var-drift gate's source scanner sees this
  // as a genuine read of GATEWAY_CONTROL_STORAGE (it does not follow renamed locals).
  const mode = parseControlStorageMode((env as ControlDataBindings).GATEWAY_CONTROL_STORAGE);
  if (mode === undefined) {
    throw new HttpError(
      503,
      CONTROL_STORAGE_MISCONFIGURED,
      `GATEWAY_CONTROL_STORAGE = "${bindings.GATEWAY_CONTROL_STORAGE}" is not one of ` +
        `${CONTROL_STORAGE_MODES.join(", ")}; refusing to guess a control-storage posture`,
    );
  }

  // D1 posture: read-only consumer → replica session (colo-local reads). Absent
  // binding (a unit env) falls through to undefined, same as the DO leg.
  if (mode === "d1") {
    const d1 = (env as ControlDataBindings).CONTROL_D1;
    return d1 !== undefined ? controlD1ReplicaDatabase(d1) : undefined;
  }

  if (bindings.CONTROL_DATA !== undefined) {
    return controlDataObjectDatabase(bindings.CONTROL_DATA as unknown as ControlDataNamespaceLike);
  }
  return undefined;
}
