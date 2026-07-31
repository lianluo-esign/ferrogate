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
 * PORT-TODO(4.8) — PLATFORM LIMIT, NOT CLOSED.
 *
 * The exact limitation: **workerd has no process environment.** There is no
 * `process.env`, no `getenv`, and no ambient global a module can read a
 * variable off — configuration and secret bindings arrive on the per-request
 * `env` object, which is a function ARGUMENT, not ambient state. So the Rust
 * `std::env::var(...)` call, which any function could make from anywhere, has
 * no equivalent: a Worker cannot read a variable it was not handed.
 *
 * The closest behavior implemented instead: every config type threads an
 * injected {@link EnvLike}. `defaultEnv()` returns `process.env` when it exists
 * (the CLI / Node parity path, where the Rust semantics ARE reproducible) and
 * an EMPTY map otherwise. Empty rather than a throw, because the Rust
 * `non_empty_env` treats an unset variable as `None`, and inside a Worker every
 * caller is expected to pass `c.env` explicitly.
 *
 * The residual gap is REAL: in a Worker, a call site that forgets to thread
 * `c.env` silently sees an empty environment instead of failing. Nothing in
 * this package can detect that — it is indistinguishable from a genuinely unset
 * variable. `test/platform-limits.test.ts` pins the fallback.
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
