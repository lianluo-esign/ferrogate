/**
 * HashiCorp Vault KV v2 backend for `vault://<mount>/<path>#<field>`.
 *
 * Port of the Rust `VaultConfig` + `VaultSecretResolver`. A single
 * authenticated `GET {addr}/v1/{mount}/data/{path}` reading `data.data.<field>`.
 */
import { type EnvLike, INSPECT, defaultEnv, nonEmptyEnv } from "./env.js";
import { type HttpOptions, httpGet } from "./http.js";
import type { SecretResolver } from "./resolver.js";
import type { SecretRef } from "./secret-ref.js";
import { describeSecretRef } from "./secret-ref.js";

/**
 * Connection details for a HashiCorp Vault server, sourced from the standard
 * `VAULT_ADDR` / `VAULT_TOKEN` / `VAULT_CACERT` environment variables.
 *
 * `token` is a **live Vault credential**: it reads every secret the mount
 * exposes. Rust hand-writes `Debug` to redact it (issue #492); here `toJSON`
 * and the custom inspect hook redact it so a `console.log`, `JSON.stringify`,
 * or thrown-error render never spills the token.
 */
export class VaultConfig {
  readonly address: string;
  readonly token: string;
  readonly caCertPath: string | null;
  /** Request timeout in milliseconds (Rust `Duration`, default 5s). */
  readonly timeoutMs: number;

  constructor(init: {
    address: string;
    token: string;
    caCertPath?: string | null;
    timeoutMs?: number;
  }) {
    this.address = init.address;
    this.token = init.token;
    this.caCertPath = init.caCertPath ?? null;
    this.timeoutMs = init.timeoutMs ?? 5000;
  }

  /**
   * Read `VAULT_ADDR`, `VAULT_TOKEN`, optionally `VAULT_CACERT`. Returns `null`
   * if either required value is unset/empty, so callers treat "no Vault
   * configured" as a normal, non-error case.
   */
  static fromEnv(env: EnvLike = defaultEnv()): VaultConfig | null {
    const address = nonEmptyEnv("VAULT_ADDR", env);
    const token = nonEmptyEnv("VAULT_TOKEN", env);
    if (address === undefined || token === undefined) return null;
    return new VaultConfig({
      address,
      token,
      caCertPath: nonEmptyEnv("VAULT_CACERT", env) ?? null,
      timeoutMs: 5000,
    });
  }

  private redacted(): Record<string, unknown> {
    return {
      address: this.address,
      token: "<redacted>",
      caCertPath: this.caCertPath,
      timeoutMs: this.timeoutMs,
    };
  }
  toJSON(): Record<string, unknown> {
    return this.redacted();
  }
  [INSPECT](): Record<string, unknown> {
    return this.redacted();
  }
}

/**
 * Resolves `vault://<mount>/<path>#<field>` references against a Vault KV v2
 * engine via a single authenticated `GET {mount}/data/{path}`.
 */
export class VaultSecretResolver implements SecretResolver {
  private readonly config: VaultConfig;
  private readonly fetchImpl: typeof fetch | undefined;

  constructor(config: VaultConfig, fetchImpl?: typeof fetch) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "vault") {
      throw new Error(
        `VaultSecretResolver cannot resolve a non-vault:// reference: ${describeSecretRef(reference)}`,
      );
    }
    const { mount, path, field } = reference;
    const base = this.config.address.replace(/\/+$/, "");
    const url = `${base}/v1/${mount}/data/${path}`;
    const options: HttpOptions = {
      timeoutMs: this.config.timeoutMs,
      caCertPath: this.config.caCertPath,
      fetchImpl: this.fetchImpl,
    };

    let raw: Uint8Array;
    try {
      raw = await httpGet(url, [["X-Vault-Token", this.config.token]], options);
    } catch (cause) {
      throw new Error(
        `failed to read Vault secret ${mount}/${path}: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
      );
    }

    let json: unknown;
    try {
      json = JSON.parse(new TextDecoder().decode(raw));
    } catch {
      throw new Error("invalid Vault response JSON");
    }

    const root = json as {
      errors?: unknown;
      data?: { data?: Record<string, unknown> };
    };
    if (Array.isArray(root.errors) && root.errors.length > 0) {
      throw new Error(`Vault returned errors for ${mount}/${path}: ${JSON.stringify(root.errors)}`);
    }
    const value = root.data?.data?.[field];
    return typeof value === "string" ? value : null;
  }
}
