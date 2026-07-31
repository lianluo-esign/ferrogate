/**
 * Worker-binding value resolution for `cf://` references (decision #423).
 *
 * Port of the Rust `cloudflare_bindings.rs`. Cloudflare Secrets Store values
 * are write-only over REST — the only read path is a Workers binding at
 * runtime. This is the binding context consulted by the registry BEFORE any
 * REST call: an injected name→value map, then the `FERROGATE_CF_SECRET_<NAME>`
 * environment convention.
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
