/**
 * Cloudflare Secrets Store REST backend for `cf://` references (issue #417),
 * scoped by decision #423.
 *
 * Port of the Rust `cloudflare.rs`. Secrets Store values are **write-only over
 * REST** — no endpoint returns a value; the only read path is a Workers binding
 * at runtime. This module is therefore the *manage plane*: create/write secrets
 * plus existence checks, and NEVER value retrieval. Load-time value resolution
 * happens through {@link CfSecretBindings}.
 *
 * The Rust `block_on_cloudflare` bridge (a dedicated thread + current-thread
 * runtime to drive the async CF client from the sync `SecretResolver` trait) is
 * intentionally absent: TS is async end-to-end, so `resolve`/`createSecret` are
 * simply `async`.
 */
import { z } from "zod";
import { type EnvLike, INSPECT, defaultEnv, nonEmptyEnv } from "./env.js";
import {
  cfBindingEnvVar,
  cfBindingNameIsUnambiguous,
} from "./cloudflare-bindings.js";
import { CfSecretsCapacityPolicy } from "./cloudflare-caps.js";
import {
  CF_ACCOUNT_ID_ENV,
  CF_API_BASE_URL_ENV,
  CF_API_TOKEN_ENV,
  CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT,
} from "./cloudflare-consts.js";
import {
  type HttpTransport,
  CloudflareClient,
  CloudflareConfig,
  CloudflareError,
  EnvTokenResolver,
} from "./cloudflare-client.js";
import type { SecretResolver } from "./resolver.js";
import type { SecretRef } from "./secret-ref.js";
import { describeSecretRef } from "./secret-ref.js";

/**
 * Connection details for a Cloudflare Secrets Store, sourced from environment
 * variables (mirroring `VaultConfig.fromEnv`).
 *
 * The token is held as a **reference** (`env://CLOUDFLARE_API_TOKEN`), never a
 * value; {@link EnvTokenResolver} materializes it per request at the
 * `Authorization` header only. A recognised `env://` reference is rendered by
 * `toJSON`/inspect (it names a variable, not a credential); anything else may be
 * an inline plaintext token and is redacted (issue #492).
 */
export class CfSecretsStoreConfig {
  readonly accountId: string;
  readonly apiTokenRef: string;
  readonly apiBaseUrl: string | null;

  constructor(init: {
    accountId: string;
    apiTokenRef: string;
    apiBaseUrl?: string | null;
  }) {
    this.accountId = init.accountId;
    this.apiTokenRef = init.apiTokenRef;
    this.apiBaseUrl = init.apiBaseUrl ?? null;
  }

  /**
   * Read {@link CF_ACCOUNT_ID_ENV} and *probe* {@link CF_API_TOKEN_ENV} (its
   * value is deliberately dropped — only the reference `env://…` is stored).
   * Returns `null` if either required value is unset/empty.
   */
  static fromEnv(env: EnvLike = defaultEnv()): CfSecretsStoreConfig | null {
    const accountId = nonEmptyEnv(CF_ACCOUNT_ID_ENV, env);
    if (accountId === undefined) return null;
    // Presence probe only: the token value is not read into the struct.
    if (nonEmptyEnv(CF_API_TOKEN_ENV, env) === undefined) return null;
    return new CfSecretsStoreConfig({
      accountId,
      apiTokenRef: `env://${CF_API_TOKEN_ENV}`,
      apiBaseUrl: nonEmptyEnv(CF_API_BASE_URL_ENV, env) ?? null,
    });
  }

  private redacted(): Record<string, unknown> {
    return {
      accountId: this.accountId,
      apiTokenRef: this.apiTokenRef.startsWith("env://")
        ? this.apiTokenRef
        : "<redacted inline token>",
      apiBaseUrl: this.apiBaseUrl,
    };
  }
  toJSON(): Record<string, unknown> {
    return this.redacted();
  }
  [INSPECT](): Record<string, unknown> {
    return this.redacted();
  }
}

/** A Secrets Store list/detail item — ids and names only, never values. */
const namedResourceSchema = z.object({
  id: z.string(),
  name: z.string().default(""),
});
type CfNamedResource = z.infer<typeof namedResourceSchema>;
const namedResourceListSchema = z.array(namedResourceSchema);

/**
 * Manages `cf://<store>/<name>` secrets against a Cloudflare Secrets Store via
 * the shared {@link CloudflareClient} — **write/manage-only** (decision #423).
 * Value retrieval is unsupported by design (values are write-only over REST):
 * `resolve` walks list-stores → list-secrets and then, on a present secret,
 * throws a precise error pointing at the Worker-binding path.
 */
export class CloudflareSecretResolver implements SecretResolver {
  private readonly clientRef: CloudflareClient;
  private capacity: CfSecretsCapacityPolicy;

  constructor(client: CloudflareClient, capacity: CfSecretsCapacityPolicy) {
    this.clientRef = client;
    this.capacity = capacity;
  }

  /**
   * Build a resolver from account/token config over a real `fetch` transport.
   * The token **reference** (not the token) lands in {@link CloudflareConfig};
   * {@link EnvTokenResolver} materializes the live token per request. `env` is
   * the environment map the token resolver and capacity policy read.
   */
  static create(
    config: CfSecretsStoreConfig,
    env: EnvLike = defaultEnv(),
    fetchImpl: typeof fetch = fetch,
  ): CloudflareSecretResolver {
    const cfConfig = new CloudflareConfig(
      config.accountId,
      config.apiTokenRef,
      config.apiBaseUrl ?? undefined,
    );
    const transport = fetchTransport(fetchImpl);
    const client = new CloudflareClient(
      cfConfig,
      new EnvTokenResolver(env),
      transport,
    );
    return new CloudflareSecretResolver(
      client,
      CfSecretsCapacityPolicy.fromEnv(env),
    );
  }

  /**
   * Assemble a resolver from an already-built {@link CloudflareClient} — the
   * seam tests use to inject a scripted transport. Uses the default (beta-cap)
   * capacity policy; override with {@link withCapacityPolicy}.
   */
  static fromClient(client: CloudflareClient): CloudflareSecretResolver {
    return new CloudflareSecretResolver(
      client,
      CfSecretsCapacityPolicy.default(),
    );
  }

  /** Replace the capacity guardrail policy enforced by {@link createSecret}. */
  withCapacityPolicy(capacity: CfSecretsCapacityPolicy): this {
    this.capacity = capacity;
    return this;
  }

  /** The shared Cloudflare API client backing this resolver. */
  client(): CloudflareClient {
    return this.clientRef;
  }

  /**
   * Create (or overwrite) a secret value — the **write** side of the manage
   * plane. Guardrails run fail-fast: value-size before any network call, and
   * the secret-count budget against the store's current listing (a NEW secret
   * at the budget errors before the create; overwriting an existing name
   * consumes no slot). Returns the new secret's id.
   */
  async createSecret(
    store: string,
    name: string,
    value: string,
    comment?: string,
  ): Promise<string> {
    this.capacity.checkValueSize(store, name, value);
    if (name.length === 0) {
      throw new Error(
        "Cloudflare Secrets Store secret name must not be empty",
      );
    }
    // #417 review item 2: refusing the write is what makes the read guard's
    // premise (one canonical secret per env var) true. A non-canonical name
    // could collide with a canonical sibling under the same env var, and the
    // resolver would then refuse to read it back.
    if (!cfBindingNameIsUnambiguous(name)) {
      throw new Error(
        `Cloudflare Secrets Store secret name ${JSON.stringify(name)} is not canonical: it must ` +
          `match [a-z0-9-]+ so that exactly one secret maps to ${cfBindingEnvVar(name)}. Writing ` +
          `a non-canonical name would let it collide with a canonical sibling under the same ` +
          `environment variable, and the resolver would refuse to read it back`,
      );
    }

    const storeId = await this.resolveStoreId(store);
    if (storeId === null) {
      throw new Error(
        `Cloudflare Secrets Store ${store} not found (the beta allows ` +
          `${CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT} store per account)`,
      );
    }

    const existing = await this.listSecrets(storeId);
    const nameAlreadyExists = existing.some((s) => s.name === name);
    const warning = this.capacity.checkSecretBudget(
      store,
      name,
      existing.length,
      nameAlreadyExists,
    );
    if (warning !== null) {
      // Rust logs via `tracing::warn!`; the closest faithful behavior is a
      // structured console warning the caller/operator sees.
      console.warn(warning.toString());
    }

    const batch = [
      {
        name,
        value,
        scopes: ["workers"] as const,
        ...(comment !== undefined ? { comment } : {}),
      },
    ];
    const body = new TextEncoder().encode(JSON.stringify(batch));
    let created: CfNamedResource[];
    try {
      created = await this.clientRef.requestJson(
        "POST",
        `accounts/{account_id}/secrets_store/stores/${storeId}/secrets`,
        namedResourceListSchema,
        body,
      );
    } catch (error) {
      throw mapCfError(
        error,
        `failed to create Cloudflare secret cf://${store}/${name}`,
      );
    }
    const first = created[0];
    if (first === undefined) {
      throw new Error(
        `Cloudflare Secrets Store create for cf://${store}/${name} returned no secret id`,
      );
    }
    return first.id;
  }

  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "cfSecret") {
      throw new Error(
        `CloudflareSecretResolver cannot resolve a non-cf:// reference: ${describeSecretRef(reference)}`,
      );
    }
    const { store, name } = reference;
    const storeId = await this.resolveStoreId(store);
    if (storeId === null) return null; // store absent → "not found"
    const secretId = await this.resolveSecretId(storeId, name);
    if (secretId === null) return null; // secret absent → "not found"

    const bindingEnv = cfBindingEnvVar(name);
    throw new Error(
      `Cloudflare Secrets Store secret cf://${store}/${name} exists (id ${secretId}) but its ` +
        `value cannot be read back: Secrets Store secret values are write-only over the REST API ` +
        `and are only readable by a Worker the secret is bound to. Supported paths: (1) ` +
        `Worker-binding resolution — bind the secret to the consuming Worker and expose it to ` +
        `FerroGate via the ${bindingEnv} environment variable or an injected binding map (see ` +
        `docs/cloudflare-secrets-resolution.md); (2) for a self-hosted gateway, keep a readable ` +
        `copy in HashiCorp Vault or the environment and reference it as vault:// or env:// ` +
        `instead. FerroGate manages cf:// secrets over REST (create/write) but will not ` +
        `fabricate a value.`,
    );
  }

  private async resolveStoreId(store: string): Promise<string | null> {
    let stores: CfNamedResource[];
    try {
      stores = await this.clientRef.getJson(
        "accounts/{account_id}/secrets_store/stores",
        namedResourceListSchema,
      );
    } catch (error) {
      throw mapCfError(error, "failed to list Cloudflare Secrets Stores");
    }
    const match = stores.find((c) => c.id === store || c.name === store);
    return match?.id ?? null;
  }

  private async listSecrets(storeId: string): Promise<CfNamedResource[]> {
    try {
      return await this.clientRef.getJson(
        `accounts/{account_id}/secrets_store/stores/${storeId}/secrets`,
        namedResourceListSchema,
      );
    } catch (error) {
      throw mapCfError(
        error,
        `failed to list secrets in Cloudflare Secrets Store ${storeId}`,
      );
    }
  }

  private async resolveSecretId(
    storeId: string,
    name: string,
  ): Promise<string | null> {
    const secrets = await this.listSecrets(storeId);
    return secrets.find((c) => c.name === name)?.id ?? null;
  }

  private redacted(): Record<string, unknown> {
    return { accountId: this.clientRef.accountId() };
  }
  toJSON(): Record<string, unknown> {
    return this.redacted();
  }
  [INSPECT](): Record<string, unknown> {
    return this.redacted();
  }
}

/** Attach context to a {@link CloudflareError} while flattening to `Error`. */
function mapCfError(error: unknown, context: string): Error {
  const detail =
    error instanceof Error ? error.message : String(error);
  return new Error(`${context}: ${detail}`);
}

/** A production {@link HttpTransport} over the platform `fetch`. */
export function fetchTransport(fetchImpl: typeof fetch = fetch): HttpTransport {
  return {
    async execute(request) {
      const response = await fetchImpl(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body ?? undefined,
      });
      const retryAfterHeader = response.headers.get("retry-after");
      const retryAfterMs =
        retryAfterHeader !== null
          ? Number.parseInt(retryAfterHeader, 10) * 1000
          : undefined;
      return {
        status: response.status,
        body: await response.text(),
        ...(retryAfterMs !== undefined && Number.isFinite(retryAfterMs)
          ? { retryAfterMs }
          : {}),
      };
    },
  };
}
