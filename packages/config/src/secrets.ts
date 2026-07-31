/**
 * Port of `ferrogate-config`'s `config/secrets.rs` (inventory §5.4, "Env
 * placeholders"): `{env.NAME}` interpolation of uppercase/digit/`_` env-var
 * names, with hard errors on unterminated/invalid/unset placeholders.
 *
 * PORT-TODO(inventory §5.8): a Worker has no `std::env`; the environment is the
 * `env` binding passed to the handler. The Rust `resolve_env_placeholders(value)`
 * read the process environment implicitly — this port takes the environment as
 * an explicit argument (defaulting to `process.env` for Node/vitest) so the
 * caller supplies the Worker `env` binding at runtime.
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
