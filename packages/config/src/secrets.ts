/**
 * Port of `ferrogate-config`'s `config/secrets.rs` (inventory §5.4, "Env
 * placeholders"): `{env.NAME}` interpolation of uppercase/digit/`_` env-var
 * names, with hard errors on unterminated/invalid/unset placeholders.
 *
 * PORT-TODO(L: inventory §5.8) — PLATFORM LIMIT (API SHAPE), NOT CLOSED.
 *
 * `std::env::var` has no workerd equivalent and cannot get one: a Worker's
 * environment is NOT ambient process state, it is the `env` object workerd hands
 * to the handler for that invocation, it only exists inside a request/alarm
 * context, and its contents differ per Worker and per deployment. There is no
 * module-scope global a library can read it from.
 *
 * CLOSEST BEHAVIOR IMPLEMENTED: the environment becomes an explicit first-class
 * ARGUMENT, so the caller passes the Worker `env` binding down. The
 * `process.env` default exists only so Node/CLI/vitest callers keep the Rust
 * call shape; inside workerd `globalThis.process` is absent, the default
 * degrades to `{}`, and every placeholder then FAILS CLOSED with
 * "environment variable `NAME` is not set" rather than silently interpolating an
 * empty string. Every rule of the Rust scanner (name charset, unterminated
 * placeholder, unset variable, never echoing the value) is ported verbatim.
 * Pinned by `platform-limits.test.ts` > "secrets: no std::env".
 */

/** The environment a placeholder resolves against. */
export type EnvSource = Record<string, string | undefined>;

function defaultEnv(): EnvSource {
  const proc = (globalThis as { process?: { env?: EnvSource } }).process;
  return proc?.env ?? {};
}

/**
 * Interpolate every `{env.NAME}` placeholder in `value`. Throws on an
 * unterminated placeholder, an invalid name, or an unset variable — the error
 * names the variable but never echoes its value.
 */
export function resolveEnvPlaceholders(value: string, env: EnvSource = defaultEnv()): string {
  let resolved = "";
  let rest = value;

  for (;;) {
    const start = rest.indexOf("{env.");
    if (start === -1) break;
    resolved += rest.slice(0, start);
    const afterStart = rest.slice(start + 5);
    const end = afterStart.indexOf("}");
    if (end === -1) {
      throw new Error("unterminated environment variable placeholder");
    }
    const name = afterStart.slice(0, end);
    if (!validEnvName(name)) {
      throw new Error(`invalid environment variable placeholder name \`${name}\``);
    }
    const envValue = env[name];
    if (envValue === undefined) {
      throw new Error(`environment variable \`${name}\` is not set`);
    }
    resolved += envValue;
    rest = afterStart.slice(end + 1);
  }

  resolved += rest;
  return resolved;
}

function validEnvName(name: string): boolean {
  return name.length > 0 && /^[A-Z0-9_]+$/.test(name);
}
