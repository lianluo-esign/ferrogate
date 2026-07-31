/**
 * Environment access + redaction helpers shared by every backend.
 *
 * Rust reads process env directly via `std::env::var`. In a Worker there is no
 * process environment — configuration and secret bindings arrive on the request
 * `env` object at runtime. So instead of a hard `process.env` dependency, every
 * config type threads an {@link EnvLike} source (defaulting to `process.env`
 * when it exists, e.g. under Node/Bun/CLI), and callers inside a Worker pass
 * `c.env`.
 *
 * PORT-TODO(4.8): the Rust crate reads the ambient process environment; on
 * Workers there is none, so `EnvLike` is injected. `defaultEnv()` falls back to
 * `process.env` for the CLI/Node parity path and to an empty map otherwise.
 */

/** A read-only environment source: variable name → value (or unset). */
export type EnvLike = Record<string, string | undefined>;

/** The ambient environment when running under Node/Bun/CLI; `{}` on Workers. */
export function defaultEnv(): EnvLike {
  const proc = (globalThis as { process?: { env?: EnvLike } }).process;
  return proc?.env ?? {};
}

/**
 * Read `name` from `env`, treating empty/whitespace-only values as unset — the
 * exact semantics of the Rust `non_empty_env` helper and of the pre-#163
 * `key_env` behavior.
 */
export function nonEmptyEnv(
  name: string,
  env: EnvLike = defaultEnv(),
): string | undefined {
  const value = env[name];
  return value !== undefined && value.trim() !== "" ? value : undefined;
}

/**
 * Custom-inspect symbol so `console.log`/`util.inspect` of a secret-bearing
 * struct routes through its redacting representation instead of dumping fields.
 */
export const INSPECT = Symbol.for("nodejs.util.inspect.custom");
