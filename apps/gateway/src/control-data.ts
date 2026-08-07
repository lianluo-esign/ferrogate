/**
 * The gateway's CONTROL storage seam (Zero-D1 S2, issue #878).
 *
 * CONTROL is a singleton Durable Object addressed as `"control"`. Callers
 * still receive a D1-shaped handle, so the stores that consume CONTROL rows do
 * not need to know whether the backend is the object or the temporary D1
 * compatibility path. This module owns the posture switch and is the only
 * gateway module that reads `env.CONTROL_DATA`.
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

/** Bindings consumed by this seam. Legacy D1 fields are compatibility inputs. */
export interface ControlDataBindings {
  readonly GATEWAY_CONTROL_STORAGE?: string;
  readonly CONTROL_DATA?: ControlDataNamespace;
  readonly CONTROL_DB?: D1Database;
  readonly BILLING_DB?: D1Database;
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
        "This request is refused rather than served from CONTROL_DB or BILLING_DB.",
      ].join(" "),
    );
  }
  return namespace;
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
 * Under the default `durable_object` posture the CONTROL_DATA namespace is the
 * FIRST candidate; when it is bound (the S2 production shape) the caller gets
 * the Durable Object facade. When it is NOT bound — a unit env, or a Worker the
 * stanza has not yet reached — the seam falls through to the caller's `legacy`
 * D1 candidates and finally `undefined`, preserving each seam's historical
 * absent-binding behavior (guardrails/RBAC/budget-alerts degrade to their
 * config path rather than 503). Under the explicit `d1_compat` posture the
 * CONTROL_DATA facade is skipped entirely and only the legacy candidates are
 * considered. An unrecognized `GATEWAY_CONTROL_STORAGE` value is the one hard
 * failure: we refuse to guess a posture.
 *
 * (The stricter {@link controlDataNamespace} — which 503s on an absent
 * namespace — is reserved for the mandatory paths that must not silently serve
 * from legacy D1; the optional control reads that flow through here do not use
 * it.)
 */
export function controlDatabaseFrom(
  env: unknown,
  options: { readonly legacy?: readonly unknown[] } = {},
): D1Database | undefined {
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

  if (mode === "durable_object" && bindings.CONTROL_DATA !== undefined) {
    return controlDataObjectDatabase(bindings.CONTROL_DATA as unknown as ControlDataNamespaceLike);
  }

  const legacy = options.legacy ?? [bindings.CONTROL_DB, bindings.BILLING_DB];
  for (const candidate of legacy) {
    if (isControlDatabase(candidate)) return candidate;
  }
  return undefined;
}
