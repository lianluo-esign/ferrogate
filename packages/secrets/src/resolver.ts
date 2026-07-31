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
import { type EnvLike, defaultEnv } from "./env.js";
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
 */
export class EnvSecretResolver implements SecretResolver {
  private readonly env: EnvLike;

  constructor(env: EnvLike = defaultEnv()) {
    this.env = env;
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- async so the
  // guard surfaces as a rejection, not a synchronous throw, for `.then` callers.
  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "env") {
      throw new Error(
        `EnvSecretResolver cannot resolve a non-env:// reference: ${describeSecretRef(reference)}`,
      );
    }
    const value = this.env[reference.name];
    return value !== undefined && value.trim() !== "" ? value : null;
  }
}
