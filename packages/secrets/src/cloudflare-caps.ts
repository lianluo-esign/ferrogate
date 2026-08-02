/**
 * Capacity guardrails for the Cloudflare Secrets Store write path (issue #418).
 *
 * Port of the Rust `cloudflare_caps.rs`. The Secrets Store beta caps an account
 * at 1 store, 100 secrets, and 1024 bytes/value. FerroGate makes every write
 * pay a fail-fast toll: value-size checked before any API call, and a
 * secret-count budget with a soft warning near the ceiling.
 */
import { type EnvLike, defaultEnv, nonEmptyEnv } from "./env.js";
import { CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT } from "./cloudflare-consts.js";
import { CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES } from "./cloudflare-consts.js";

/** Env override for the hard secret-count budget. */
export const CF_SECRETS_MAX_SECRETS_ENV = "FERROGATE_CF_SECRETS_MAX_SECRETS";
/** Env override for the soft warning threshold (clamped to the hard budget). */
export const CF_SECRETS_WARN_AT_ENV = "FERROGATE_CF_SECRETS_WARN_AT";
/** Env override for the per-value byte cap. */
export const CF_SECRETS_MAX_VALUE_BYTES_ENV =
  "FERROGATE_CF_SECRETS_MAX_VALUE_BYTES";

/** Default soft warning threshold: 90 of the 100-secret beta budget. */
export const DEFAULT_CF_SECRETS_WARN_AT = 90;

/** UTF-8 byte length, matching Rust `str::len()` (not UTF-16 code units). */
function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

/**
 * A soft-cap crossing on the secret-count budget: the write is allowed, but the
 * store is close enough to the hard budget that the operator should act.
 */
export class CfSecretsCapacityWarning {
  readonly usedAfterWrite: number;
  readonly maxSecrets: number;
  readonly warnAtSecrets: number;

  constructor(usedAfterWrite: number, maxSecrets: number, warnAtSecrets: number) {
    this.usedAfterWrite = usedAfterWrite;
    this.maxSecrets = maxSecrets;
    this.warnAtSecrets = warnAtSecrets;
  }

  toString(): string {
    return (
      `Cloudflare Secrets Store is approaching its secret-count budget: ` +
      `${this.usedAfterWrite} of ${this.maxSecrets} secrets used after this write ` +
      `(soft warning threshold ${this.warnAtSecrets}). Per-tenant credentials must not fan out ` +
      `into the store — see docs/cloudflare-secrets-tenancy.md`
    );
  }
}

/**
 * Fail-fast capacity thresholds enforced by
 * {@link CloudflareSecretResolver.createSecret} before it touches the API.
 * Defaults mirror the published Secrets Store beta caps.
 */
export class CfSecretsCapacityPolicy {
  readonly maxSecrets: number;
  readonly warnAtSecrets: number;
  readonly maxValueBytes: number;

  constructor(init?: {
    maxSecrets?: number;
    warnAtSecrets?: number;
    maxValueBytes?: number;
  }) {
    const maxSecrets =
      init?.maxSecrets ?? CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT;
    this.maxSecrets = maxSecrets;
    // Always clamp the warning to the hard budget.
    this.warnAtSecrets = Math.min(
      init?.warnAtSecrets ?? DEFAULT_CF_SECRETS_WARN_AT,
      maxSecrets,
    );
    this.maxValueBytes =
      init?.maxValueBytes ?? CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES;
  }

  /** The default beta-cap policy. */
  static default(): CfSecretsCapacityPolicy {
    return new CfSecretsCapacityPolicy();
  }

  /**
   * Build a policy from env overrides, falling back to the beta-cap defaults
   * for anything unset, non-numeric, or zero. `warnAtSecrets` is clamped to
   * `maxSecrets`.
   */
  static fromEnv(env: EnvLike = defaultEnv()): CfSecretsCapacityPolicy {
    const positive = (name: string): number | undefined => {
      const raw = nonEmptyEnv(name, env);
      if (raw === undefined) return undefined;
      const parsed = Number.parseInt(raw.trim(), 10);
      return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
    };
    return new CfSecretsCapacityPolicy({
      maxSecrets: positive(CF_SECRETS_MAX_SECRETS_ENV),
      warnAtSecrets: positive(CF_SECRETS_WARN_AT_ENV),
      maxValueBytes: positive(CF_SECRETS_MAX_VALUE_BYTES_ENV),
    });
  }

  /**
   * Fail fast on a value larger than the per-value byte cap — before any
   * network call — so an operator learns the exact byte count and the limit.
   */
  checkValueSize(store: string, name: string, value: string): void {
    const len = byteLength(value);
    if (len > this.maxValueBytes) {
      const label =
        this.maxValueBytes === CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES
          ? "beta"
          : "configured";
      throw new Error(
        `Cloudflare Secrets Store value for cf://${store}/${name} is ${len} bytes, exceeding the ` +
          `${label} cap of ${this.maxValueBytes} bytes per secret value; store oversized ` +
          `credentials (PEM keys, service-account JSON, …) in the readable backends instead — ` +
          `see docs/cloudflare-secrets-tenancy.md`,
      );
    }
  }

  /**
   * Enforce the secret-count budget for a write. A new secret with the hard
   * budget consumed → throws; a write landing at/above the soft threshold →
   * returns a warning to log; otherwise → `null`.
   */
  checkSecretBudget(
    store: string,
    name: string,
    existingSecretCount: number,
    nameAlreadyExists: boolean,
  ): CfSecretsCapacityWarning | null {
    if (!nameAlreadyExists && existingSecretCount >= this.maxSecrets) {
      const label =
        this.maxSecrets === CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT
          ? "beta"
          : "configured";
      throw new Error(
        `cannot create Cloudflare secret cf://${store}/${name}: the store already holds ` +
          `${existingSecretCount} secrets, meeting the ${label} budget of ${this.maxSecrets} ` +
          `secrets per account; free a slot or keep this credential in the readable backends — ` +
          `per-tenant credentials must never fan out into the store (see ` +
          `docs/cloudflare-secrets-tenancy.md)`,
      );
    }
    const usedAfterWrite = nameAlreadyExists
      ? existingSecretCount
      : existingSecretCount + 1;
    if (usedAfterWrite >= this.warnAtSecrets) {
      return new CfSecretsCapacityWarning(
        usedAfterWrite,
        this.maxSecrets,
        this.warnAtSecrets,
      );
    }
    return null;
  }
}
