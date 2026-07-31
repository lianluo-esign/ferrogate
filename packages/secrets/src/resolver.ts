/**
 * The `SecretResolver` contract + the default `env://` resolver.
 *
 * Port of the Rust `trait SecretResolver` and `struct EnvSecretResolver`.
 *
 * Rust returns `Result<Option<String>>`: `Ok(None)` = "not found / unset",
 * `Err` = genuine failure. The TS equivalent resolves to `string | null`
 * (`null` = not found) and **throws** for a genuine failure. Every backend is
 * modelled `async` because the Cloudflare and Vault backends do I/O; the env
 * and binding backends complete synchronously but keep the async signature for
 * a uniform dispatch surface.
 */
import { type EnvLike, defaultEnv, readEnvSecret } from "./env.js";
import type { SecretRef } from "./secret-ref.js";
import { describeSecretRef } from "./secret-ref.js";

/**
 * Resolves a {@link SecretRef} to its current value. Implementations return
 * `null` for "not found" (e.g. an unset env var) and throw only for genuine
 * failures (unreachable Vault, malformed response), so callers can distinguish
 * "not configured" from "broken".
 */
export interface SecretResolver {
  resolve(reference: SecretRef): Promise<string | null>;
}

/**
 * Resolves `env://NAME` references by reading the environment. The default,
 * zero-configuration resolver; preserves exactly the pre-#163
 * `key_env`/`api_key_env` behavior (empty values treated as unset).
 *
 * Reads through `readEnvSecret`, so `env://NAME` serves BOTH Worker slot shapes:
 * a plain string (`[vars]` / `wrangler secret put` / `process.env`) and a
 * `[[secrets_store_secrets]]` binding, which is awaited. An operator who binds
 * `OPENAI_API_KEY` through Secrets Store and writes `env://OPENAI_API_KEY` gets
 * the credential rather than a `TypeError` on `.trim()`; the DISTINCT thing
 * `cf://` still buys is the canonical-name mapping and its ambiguity guard.
 */
export class EnvSecretResolver implements SecretResolver {
  private readonly env: EnvLike;

  constructor(env: EnvLike = defaultEnv()) {
    this.env = env;
  }

  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "env") {
      throw new Error(
        `EnvSecretResolver cannot resolve a non-env:// reference: ${describeSecretRef(reference)}`,
      );
    }
    return (await readEnvSecret(reference.name, this.env)) ?? null;
  }
}
