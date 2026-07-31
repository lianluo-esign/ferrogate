/**
 * Worker-binding value resolution for `cf://` references (decision #423).
 *
 * Port of the Rust `cloudflare_bindings.rs`. This is the binding context the
 * registry consults BEFORE any REST call: an injected name→value map, then the
 * `FERROGATE_CF_SECRET_<NAME>` environment convention.
 *
 * PORT-TODO(4.6/4.7) — PLATFORM LIMIT, NOT CLOSED.
 *
 * The exact limitation: **Cloudflare Secrets Store values are WRITE-ONLY over
 * the REST API, and the only read path is a `[[secrets_store_secrets]]` binding
 * declared at DEPLOY time.** So a `cf://<name>` whose name is only known at
 * RUNTIME — from a tenant's stored config, from a request — cannot be resolved:
 * there is no `env.SECRETS.get(name)` over the account's store, and the REST
 * `GET` returns metadata, never the value. `env` is an ordinary object, so a
 * PRE-BOUND name can be selected at runtime by string
 * (`env[cfBindingEnvVar(name)]`), but a name with no stanza in `wrangler.toml`
 * is unresolvable, full stop.
 *
 * The closest behavior implemented instead is exactly that runtime-select-over-
 * a-deploy-time-declared-set: {@link CfSecretBindings} looks the name up in an
 * injected map and then in the env convention, and returns `null` — "not
 * configured" — when neither has it. It NEVER falls back to a REST read of the
 * value, because no such read exists; a resolver that appeared to work for
 * unbound names would be a fake.
 *
 * The operational consequence, stated plainly: onboarding a new `cf://` secret
 * requires a DEPLOY, the same coupling `EnvBindingTenantDatabaseRouter` has for
 * per-tenant D1. `test/platform-limits.test.ts` pins the refusal.
 */
import { type EnvLike, INSPECT, defaultEnv } from "./env.js";
import type { SecretResolver } from "./resolver.js";
import type { SecretRef } from "./secret-ref.js";
import { describeSecretRef } from "./secret-ref.js";

/** Prefix for the Worker-bound-secret environment-variable convention. */
export const CF_BINDING_ENV_PREFIX = "FERROGATE_CF_SECRET_";

/**
 * The environment variable exposing a Worker-bound Cloudflare secret value:
 * {@link CF_BINDING_ENV_PREFIX} + the name uppercased, every non-ASCII-
 * alphanumeric character mapped to `_`. `openai-api-key` →
 * `FERROGATE_CF_SECRET_OPENAI_API_KEY`.
 *
 * This mapping is **lossy** and only injective on canonical names (see
 * {@link cfBindingNameIsUnambiguous}); it exists so errors/docs can name the
 * exact variable an operator must set, not as a safe lookup key on its own.
 */
export function cfBindingEnvVar(secretName: string): string {
  let out = CF_BINDING_ENV_PREFIX;
  for (const ch of secretName) {
    out += /^[A-Za-z0-9]$/.test(ch) ? ch.toUpperCase() : "_";
  }
  return out;
}

/**
 * Whether {@link cfBindingEnvVar} is injective on `secretName` — true exactly
 * for the canonical shape `^[a-z0-9-]+$` (lowercase letters, digits and `-`
 * land in disjoint image sets, so distinct canonical names never collide).
 */
export function cfBindingNameIsUnambiguous(secretName: string): boolean {
  return secretName.length > 0 && /^[a-z0-9-]+$/.test(secretName);
}

/**
 * The Worker-binding context for `cf://` value resolution: an injected
 * name→value map checked first, then the {@link cfBindingEnvVar} environment
 * convention. The default (empty-map) context is always installed on the
 * registry so the env convention works with zero configuration.
 *
 * `bindings` holds **resolved plaintext secret values**. Rust hand-writes
 * `Debug` (issue #492) to render only names + count; here `toJSON` / the custom
 * inspect hook do the same so a `console.log` or thrown-error render three
 * levels up never spills a bound credential. Secret *names* are not secret
 * (they appear verbatim in config), so they are rendered.
 */
export class CfSecretBindings implements SecretResolver {
  private readonly bindings: Map<string, string>;
  private readonly env: EnvLike;

  constructor(bindings?: Map<string, string>, env: EnvLike = defaultEnv()) {
    this.bindings = bindings ?? new Map();
    this.env = env;
  }

  /** An empty binding context: only the environment convention applies. */
  static new(env: EnvLike = defaultEnv()): CfSecretBindings {
    return new CfSecretBindings(new Map(), env);
  }

  /** A context seeded from values the embedding runtime already holds. */
  static fromMap(
    bindings: Record<string, string> | Map<string, string>,
    env: EnvLike = defaultEnv(),
  ): CfSecretBindings {
    const map =
      bindings instanceof Map ? new Map(bindings) : new Map(Object.entries(bindings));
    return new CfSecretBindings(map, env);
  }

  /** Add (or replace) one injected binding value. */
  insert(secretName: string, value: string): void {
    this.bindings.set(secretName, value);
  }

  /**
   * Look up a secret's bound value: the injected map first (keyed by the
   * **exact** name, lossless), then the {@link cfBindingEnvVar} environment
   * convention. Empty/whitespace values count as unset.
   *
   * Throws — never returns a value — when `secretName` is not canonical and no
   * exact injected binding exists, because the variable such a name maps to is
   * shared with other distinct secrets; resolving it could serve a credential
   * the operator did not name.
   *
   * PORT-TODO(inventory-policy-core §4.8) — REAL GAP, NOT A PLATFORM LIMIT.
   *
   * Both paths below read a **plain string**. The CF-native read path the
   * inventory names (`§4.8`: "a `secrets_store_secrets` binding in
   * `wrangler.jsonc` exposes the value at runtime — `await env.MY_SECRET.get()`")
   * is NOT implemented, here or anywhere in the repo: `grep -r secrets_store_secrets
   * packages apps --include=*.ts` finds only prose. With a real stanza declared
   * as `FERROGATE_CF_SECRET_OPENAI_API_KEY`, `env[...]` is a `SecretsStoreSecret`
   * OBJECT, so `fromEnv.trim()` below throws `TypeError` instead of resolving —
   * i.e. the one binding shape the whole `cf://` scheme exists to serve is the
   * one shape this cannot read. Today `cf://` therefore works only from
   * {@link fromMap}/{@link insert} or a `[vars]`/`wrangler secret put` STRING,
   * both of which are `env://` by another name.
   *
   * TO CLOSE (no platform blocker; `SecretsStoreSecret` is GA):
   *   1. widen {@link EnvLike} to `string | { get(): Promise<string> } | undefined`;
   *   2. make {@link lookup} async (or add `lookupAsync`) and `await value.get()`
   *      when the slot is an object with a callable `get` — the `resolve()` seam
   *      is already `Promise`-valued, so only `lookup` changes shape;
   *   3. keep the ambiguity guard AHEAD of the read, unchanged — a non-canonical
   *      name must still refuse before touching any binding;
   *   4. extend `test/platform-limits.test.ts` > "a PRE-BOUND name resolves" with
   *      a stub `{ get: async () => "sk-bound" }` slot, and MUTATION-TEST it by
   *      deleting the `await …get()` branch (must go RED, since the stub then
   *      stringifies to `[object Object]`).
   * The genuinely unclosable half stays exactly as written above: a name with NO
   * deploy-time stanza is still unresolvable, and that is the platform limit.
   */
  lookup(secretName: string): string | null {
    // Injected map is keyed exactly (no collapsing) → consulted first, valid
    // for any name. A present-but-empty binding still short-circuits ("unset").
    if (this.bindings.has(secretName)) {
      const value = this.bindings.get(secretName) as string;
      return value.trim() === "" ? null : value;
    }
    if (!cfBindingNameIsUnambiguous(secretName)) {
      const variable = cfBindingEnvVar(secretName);
      throw new Error(
        `cf:// secret name ${JSON.stringify(secretName)} cannot be resolved from the ` +
          `Worker-binding environment convention: it is not canonical, so the variable it maps ` +
          `to (${variable}) is shared with other distinct Cloudflare secrets (e.g. ` +
          `openai-api-key, openai.api.key, openai_api_key and OpenAI-API-Key all map to ` +
          `FERROGATE_CF_SECRET_OPENAI_API_KEY) and reading it could return a credential you did ` +
          `not name. Fix by either (1) renaming the Secrets Store secret to the canonical shape ` +
          `[a-z0-9-]+ (e.g. openai-api-key) so the mapping is collision-free, or (2) injecting ` +
          `the value under its exact name via CfSecretBindings.fromMap/insert + ` +
          `SecretResolverRegistry.withCfBindings, which is keyed exactly and never collapses. ` +
          `See docs/cloudflare-secrets-resolution.md`,
      );
    }
    const fromEnv = this.env[cfBindingEnvVar(secretName)];
    return fromEnv !== undefined && fromEnv.trim() !== "" ? fromEnv : null;
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- async so both
  // the non-cf guard and the ambiguous-name guard surface as rejections.
  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "cfSecret") {
      throw new Error(
        `CfSecretBindings cannot resolve a non-cf:// reference: ${describeSecretRef(reference)}`,
      );
    }
    return this.lookup(reference.name);
  }

  private redacted(): Record<string, unknown> {
    const names = [...this.bindings.keys()].sort();
    return {
      boundSecretCount: this.bindings.size,
      boundSecretNames: names,
      boundSecretValues: "<redacted>",
    };
  }
  toJSON(): Record<string, unknown> {
    return this.redacted();
  }
  [INSPECT](): Record<string, unknown> {
    return this.redacted();
  }
}
