/**
 * Worker-binding value resolution for `cf://` references (decision #423).
 *
 * Port of the Rust `cloudflare_bindings.rs`. This is the binding context the
 * registry consults BEFORE any REST call: an injected name→value map, then the
 * `FERROGATE_CF_SECRET_<NAME>` environment convention.
 *
 * The CF-NATIVE READ PATH IS NOW IMPLEMENTED (inventory-policy-core §4.8, the
 * former "REAL GAP" marker on `lookup`): a slot bound by a
 * `[[secrets_store_secrets]]` stanza is a `SecretsStoreSecret` OBJECT, and
 * {@link CfSecretBindings.lookupAsync} reads it with `await slot.get()` —
 * which is what {@link CfSecretBindings.resolve} calls. Before that, the one
 * binding shape the whole `cf://` scheme exists to serve was the one shape this
 * could not read (`slot.trim()` raised `TypeError`), so `cf://` worked only from
 * an injected map or a plain `[vars]` string, i.e. `env://` by another name.
 *
 * PORT-TODO(4.6/4.7) — PLATFORM LIMIT, NOT CLOSED (the RUNTIME-NAME half).
 *
 * The exact limitation that remains: **Cloudflare Secrets Store values are
 * WRITE-ONLY over the REST API, and the only read path is a
 * `[[secrets_store_secrets]]` binding declared at DEPLOY time.** So a
 * `cf://<name>` whose name is only known at RUNTIME — from a tenant's stored
 * config, from a request — cannot be resolved: there is no
 * `env.SECRETS.get(name)` over the account's store (the binding's `get()` takes
 * NO argument and serves exactly the one secret it was bound to), and the REST
 * `GET` returns metadata, never the value.
 *
 * The closest behavior implemented instead is runtime-select-over-a-deploy-time-
 * declared-set: `env` is an ordinary object, so a PRE-BOUND name is selected at
 * runtime by string (`env[cfBindingEnvVar(name)]`) and then read in whichever of
 * the two shapes it arrived in. A name with no stanza in `wrangler.toml` yields
 * `null` — "not configured". It NEVER falls back to a REST read of the value,
 * because no such read exists; a resolver that appeared to work for unbound
 * names would be a fake.
 *
 * The operational consequence, stated plainly: onboarding a new `cf://` secret
 * requires a DEPLOY, the same coupling `EnvBindingTenantDatabaseRouter` has for
 * per-tenant D1. `test/platform-limits.test.ts` pins both the refusal and the
 * `SecretsStoreSecret` read that now succeeds.
 */
import {
  type EnvLike,
  INSPECT,
  defaultEnv,
  isSecretsStoreBinding,
  readEnvSecret,
} from "./env.js";
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
   * SYNCHRONOUS, so it reads only a STRING slot. The CF-native read path
   * (`§4.8`: "a `secrets_store_secrets` binding exposes the value at runtime —
   * `await env.MY_SECRET.get()`") is asynchronous by construction and lives in
   * {@link lookupAsync}, which {@link resolve} uses. A binding-shaped slot makes
   * THIS method throw rather than stringify — see {@link lookupAsync} for why
   * that is the safe direction.
   */
  lookup(secretName: string): string | null {
    const injected = this.injected(secretName);
    if (injected !== undefined) return injected;
    this.assertUnambiguous(secretName);
    const variable = cfBindingEnvVar(secretName);
    const fromEnv = this.env[variable];
    if (isSecretsStoreBinding(fromEnv)) {
      throw new Error(
        `cf:// secret ${JSON.stringify(secretName)} is bound as a Cloudflare Secrets Store ` +
          `secret ([[secrets_store_secrets]] ${variable}), whose value can only be read ` +
          `asynchronously with await ${variable}.get(). Use CfSecretBindings.lookupAsync (or ` +
          `resolve(), which already awaits) instead of the synchronous lookup().`,
      );
    }
    return fromEnv !== undefined && fromEnv.trim() !== "" ? fromEnv : null;
  }

  /**
   * The asynchronous binding read — the one {@link resolve} uses, and the only
   * one that can serve a real `[[secrets_store_secrets]]` stanza.
   *
   * Order is load-bearing and identical to {@link lookup}:
   *   1. the injected map, keyed EXACTLY (lossless, valid for any name);
   *   2. the ambiguity guard — a non-canonical name refuses HERE, before any
   *      binding is touched, so a lossy variable name can never serve a
   *      credential the operator did not ask for;
   *   3. the `FERROGATE_CF_SECRET_<NAME>` slot, read as a string OR awaited
   *      through {@link SecretsStoreBinding.get}.
   *
   * Empty/whitespace is "unset" in both shapes.
   */
  async lookupAsync(secretName: string): Promise<string | null> {
    const injected = this.injected(secretName);
    if (injected !== undefined) return injected;
    this.assertUnambiguous(secretName);
    return (await readEnvSecret(cfBindingEnvVar(secretName), this.env)) ?? null;
  }

  /**
   * The injected map is keyed exactly (no collapsing) → consulted first, valid
   * for any name. A present-but-empty binding still short-circuits ("unset").
   * `undefined` means "the map does not have it", which is distinct from the
   * `null` that means "present but empty".
   */
  private injected(secretName: string): string | null | undefined {
    if (!this.bindings.has(secretName)) return undefined;
    const value = this.bindings.get(secretName) as string;
    return value.trim() === "" ? null : value;
  }

  /** The lossy-mapping ambiguity guard; throws, never returns a wrong value. */
  private assertUnambiguous(secretName: string): void {
    if (cfBindingNameIsUnambiguous(secretName)) return;
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

  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "cfSecret") {
      throw new Error(
        `CfSecretBindings cannot resolve a non-cf:// reference: ${describeSecretRef(reference)}`,
      );
    }
    // `return await`, not a bare `return`: a bare return hands back the inner
    // promise for THIS one to adopt, and workerd reports a rejection observed
    // only after adoption as an unhandled rejection even though every caller
    // awaits it. Awaiting here keeps the ambiguity-guard rejection on one
    // promise chain.
    return await this.lookupAsync(reference.name);
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
