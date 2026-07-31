/**
 * `SecretResolverRegistry` — dispatches a raw `secret_ref` string to the right
 * backend. Port of the Rust `SecretResolverRegistry`.
 *
 * Precedence (unchanged from Rust):
 *  1. `env://`  → always via {@link EnvSecretResolver}.
 *  2. `vault://` → {@link VaultSecretResolver} if configured, else a clear
 *     error naming `VAULT_ADDR`/`VAULT_TOKEN`.
 *  3. `cf://`   → the Worker-binding context first (no network), then the
 *     configured {@link CloudflareSecretResolver}; else a precise error
 *     explaining Secrets Store values are write-only over REST.
 *
 * An ambiguous (non-canonical) `cf://` name with no exact injected binding
 * errors **in the binding context, before the REST fallback**.
 */
import { type EnvLike, defaultEnv } from "./env.js";
import { CfSecretBindings } from "./cloudflare-bindings.js";
import { cfBindingEnvVar } from "./cloudflare-bindings.js";
import {
  CfSecretsStoreConfig,
  CloudflareSecretResolver,
} from "./cloudflare.js";
import { EnvSecretResolver } from "./resolver.js";
import { VaultConfig, VaultSecretResolver } from "./vault.js";
import { parseSecretRef } from "./secret-ref.js";

export class SecretResolverRegistry {
  private vault: VaultSecretResolver | null;
  private cloudflare: CloudflareSecretResolver | null;
  private cfBindings: CfSecretBindings;
  private readonly env: EnvLike;

  private constructor(
    vault: VaultSecretResolver | null,
    cloudflare: CloudflareSecretResolver | null,
    cfBindings: CfSecretBindings,
    env: EnvLike,
  ) {
    this.vault = vault;
    this.cloudflare = cloudflare;
    this.cfBindings = cfBindings;
    this.env = env;
  }

  /** An empty registry: only `env://` and the `cf://` binding convention. */
  static new(env: EnvLike = defaultEnv()): SecretResolverRegistry {
    return new SecretResolverRegistry(
      null,
      null,
      CfSecretBindings.new(env),
      env,
    );
  }

  /** A registry with the Vault backend enabled. */
  static withVault(
    vault: VaultSecretResolver,
    env: EnvLike = defaultEnv(),
  ): SecretResolverRegistry {
    return new SecretResolverRegistry(
      vault,
      null,
      CfSecretBindings.new(env),
      env,
    );
  }

  /** Enable the Cloudflare Secrets Store REST backend (builder). */
  withCloudflare(cloudflare: CloudflareSecretResolver): this {
    this.cloudflare = cloudflare;
    return this;
  }

  /** Replace the Worker-binding context consulted for `cf://` (builder). */
  withCfBindings(bindings: CfSecretBindings): this {
    this.cfBindings = bindings;
    return this;
  }

  /**
   * Build a registry with backends enabled from the environment: Vault when
   * `VAULT_ADDR` + `VAULT_TOKEN` are set, and the Cloudflare Secrets Store
   * manage plane when `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN` are set.
   * The `cf://` binding convention (`FERROGATE_CF_SECRET_*`) is always active.
   */
  static fromEnv(
    env: EnvLike = defaultEnv(),
    fetchImpl: typeof fetch = fetch,
  ): SecretResolverRegistry {
    const vaultConfig = VaultConfig.fromEnv(env);
    const vault =
      vaultConfig !== null
        ? new VaultSecretResolver(vaultConfig, fetchImpl)
        : null;

    const cfConfig = CfSecretsStoreConfig.fromEnv(env);
    let cloudflare: CloudflareSecretResolver | null = null;
    if (cfConfig !== null) {
      try {
        cloudflare = CloudflareSecretResolver.create(cfConfig, env, fetchImpl);
      } catch (error) {
        // A present-but-unbuildable client is treated as "not configured"
        // (the cf:// path then errors clearly unless a binding provides it).
        console.warn(
          "Cloudflare Secrets Store is configured but its client could not be built; " +
            `cf:// references will error: ${
              error instanceof Error ? error.message : String(error)
            }`,
        );
      }
    }

    return new SecretResolverRegistry(
      vault,
      cloudflare,
      CfSecretBindings.new(env),
      env,
    );
  }

  /** Resolve a raw `secret_ref` string; `null` = not found, throw = failure. */
  async resolve(raw: string): Promise<string | null> {
    const reference = parseSecretRef(raw);
    switch (reference.kind) {
      case "env":
        return new EnvSecretResolver(this.env).resolve(reference);
      case "vault":
        if (this.vault === null) {
          throw new Error(
            `secret reference ${raw} requires Vault, but VAULT_ADDR/VAULT_TOKEN are not configured`,
          );
        }
        return this.vault.resolve(reference);
      case "cfSecret": {
        // Decision #423: the binding context is the only path that can produce
        // a Secrets Store value (values are write-only over REST), so it is
        // consulted first — no network, no API token. An ambiguous name throws
        // here, before the REST fallback.
        const bound = await this.cfBindings.resolve(reference);
        if (bound !== null) return bound;
        if (this.cloudflare !== null) return this.cloudflare.resolve(reference);
        throw new Error(
          `cf:// secret ${raw} could not be resolved: no Worker-binding value found (checked the ` +
            `${cfBindingEnvVar(reference.name)} environment variable and the injected binding ` +
            `map; see docs/cloudflare-secrets-resolution.md), and the Cloudflare Secrets Store ` +
            `REST backend is not configured (set CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN to ` +
            `enable existence checks — note Secrets Store values are write-only over REST and can ` +
            `never be fetched at load time)`,
        );
      }
    }
  }
}
