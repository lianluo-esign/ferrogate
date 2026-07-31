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
 *
 * ## Two slot SHAPES, not one
 *
 * On Workers an `env` slot is not always a string. A `[[secrets_store_secrets]]`
 * stanza binds a {@link SecretsStoreBinding} OBJECT whose plaintext is read with
 * `await slot.get()`. Both shapes are therefore admitted by {@link EnvLike}, and
 * the readers split by capability:
 *
 *  - {@link readEnvSecret} — async, reads BOTH shapes. Every secret-VALUE read
 *    in this package goes through it.
 *  - {@link nonEmptyEnv} — synchronous, strings only. It cannot await, so a
 *    binding-shaped slot makes it THROW naming {@link readEnvSecret}. Before
 *    this split the same slot reached `value.trim()` and raised a bare
 *    `TypeError`, or (worse, at a call site that stringified first) put the
 *    literal text `[object Object]` into a credential field.
 */

/**
 * A Cloudflare Secrets Store binding — what a `[[secrets_store_secrets]]`
 * stanza puts on `env` (workerd's `SecretsStoreSecret`). The plaintext is only
 * available asynchronously, which is why {@link readEnvSecret} exists.
 *
 * Declared structurally rather than imported from `@cloudflare/workers-types`
 * so this package stays runtime-agnostic (the CLI links it too) and so a test
 * can supply `{ get: async () => "…" }`.
 */
export interface SecretsStoreBinding {
  get(): Promise<string>;
}

/**
 * Members that positively identify some OTHER Cloudflare binding. Several of
 * them also expose a `get`, so `typeof slot.get === "function"` alone is NOT a
 * safe discriminator: a Worker `env` is heterogeneous, and `env://MCP_OAUTH_KV`
 * (a typo, or a config that names a binding) would otherwise call
 * `kvNamespace.get()` with no key. A `SecretsStoreSecret` exposes `get` and
 * nothing else, so requiring the absence of these is both sufficient and
 * arity-independent — deliberately NOT `get.length === 0`, which would silently
 * stop matching if workerd ever gave `get()` an options argument.
 */
const FOREIGN_BINDING_MEMBERS = [
  "put", // KV, R2
  "list", // KV, R2, Queues-ish
  "delete", // KV, R2
  "head", // R2
  "prepare", // D1
  "batch", // D1
  "idFromName", // Durable Objects
  "fetch", // service binding / DO stub
  "writeDataPoint", // Analytics Engine
  "send", // Queues
  "run", // Workers AI / D1
] as const;

/** Narrow an `env` slot to a {@link SecretsStoreBinding}. */
export function isSecretsStoreBinding(value: unknown): value is SecretsStoreBinding {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  if (typeof candidate.get !== "function") return false;
  return !FOREIGN_BINDING_MEMBERS.some((member) => typeof candidate[member] === "function");
}

/**
 * A read-only environment source: variable name → a plain string value, a
 * Cloudflare Secrets Store binding, or unset.
 */
export type EnvLike = Record<string, string | SecretsStoreBinding | undefined>;

/** The ambient environment when running under Node/Bun/CLI; `{}` on Workers. */
export function defaultEnv(): EnvLike {
  const proc = (globalThis as { process?: { env?: EnvLike } }).process;
  return proc?.env ?? {};
}

/**
 * Read `name` from `env` as a SECRET VALUE, accepting either slot shape:
 * a plain string (`[vars]`, `wrangler secret put`, `process.env`) or a
 * {@link SecretsStoreBinding} (`[[secrets_store_secrets]]`), which is awaited.
 *
 * Empty/whitespace-only values count as unset in BOTH shapes, so the Rust
 * `non_empty_env` semantics survive the widening: an operator who binds an
 * empty Secrets Store secret gets "unset", not the empty string.
 *
 * Returns `undefined` for "not configured"; a rejection from `get()` is a
 * genuine failure and propagates.
 */
export async function readEnvSecret(
  name: string,
  env: EnvLike = defaultEnv(),
): Promise<string | undefined> {
  const slot = env[name];
  if (slot === undefined) return undefined;
  const value = isSecretsStoreBinding(slot) ? await slot.get() : slot;
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

/**
 * Read `name` from `env`, treating empty/whitespace-only values as unset — the
 * exact semantics of the Rust `non_empty_env` helper and of the pre-#163
 * `key_env` behavior.
 *
 * SYNCHRONOUS, so it can only read a STRING slot. A {@link SecretsStoreBinding}
 * slot throws rather than degrading to `undefined`: silently reporting a bound
 * secret as unset would disable a backend the operator configured, and that
 * failure is invisible at the point it is caused. Use {@link readEnvSecret}
 * from any call site that can await.
 */
export function nonEmptyEnv(
  name: string,
  env: EnvLike = defaultEnv(),
): string | undefined {
  const value = env[name];
  if (isSecretsStoreBinding(value)) {
    throw new Error(
      `environment variable ${name} is bound as a Cloudflare Secrets Store secret ` +
        `([[secrets_store_secrets]]), whose value can only be read asynchronously with ` +
        `await ${name}.get(). This reader is synchronous. Fix by either (1) reading it through ` +
        `readEnvSecret(${JSON.stringify(name)}, env) from a call site that can await, or ` +
        `(2) binding it as a plain [vars] entry / "wrangler secret put" value if a synchronous ` +
        `read is required.`,
    );
  }
  return value !== undefined && value.trim() !== "" ? value : undefined;
}

/**
 * Custom-inspect symbol so `console.log`/`util.inspect` of a secret-bearing
 * struct routes through its redacting representation instead of dumping fields.
 */
export const INSPECT = Symbol.for("nodejs.util.inspect.custom");
