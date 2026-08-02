/**
 * Per-tenant BYOK — a tenant's OWN provider credential, registered under an
 * ALIAS and resolved as `byok://<alias>` (issue #682).
 *
 * ## Why this is not just another backend
 *
 * The other three backends in this package answer "what is the value of this
 * name?" and the answer is the same for every caller. This one answers "what is
 * the value of this alias FOR THIS TENANT?", and getting the second half wrong
 * means one customer's traffic is billed to — and signed with — another
 * customer's negotiated provider agreement. So the tenant is not a parameter of
 * the reference; it is a property of the RESOLVER, fixed at construction from
 * the authenticated caller. `byok://<alias>` is deliberately incapable of naming
 * a tenant: there is no syntax for it, so there is nothing for a request to
 * forge. See {@link parseSecretRef}'s `byok://` arm, which refuses any alias
 * containing a `/` for exactly this reason.
 *
 * ## The deploy-time-binding constraint, and how the alias dodges it
 *
 * Cloudflare Secrets Store bindings (and `wrangler secret put` values) are
 * resolved at DEPLOY time: `env.OPENAI_API_KEY` exists because a deploy said so,
 * and `[[secrets_store_secrets]]`'s `get()` takes no argument, so there is no
 * `env.SECRETS.get(name)` to select one at runtime. A design that gave each
 * tenant its own binding would therefore need a deploy per tenant and a deploy
 * per rotation — precisely what #682 exists to remove.
 *
 * This module keeps the BINDING SET FIXED and moves the tenant-visible mapping
 * into DATA:
 *
 * ```text
 *   BINDINGS (deploy-time, fleet-wide, ~1 of them)
 *     FERROGATE_BYOK_MASTER_KEY      base64 32-byte AES-256 key, version 1
 *     FERROGATE_BYOK_MASTER_KEY_V2   (only when the MASTER key is rotated)
 *
 *   DATA (runtime, per tenant, unbounded, no deploy)
 *     control D1: tenant_provider_credentials(tenant_id, alias, provider,
 *                 key_version, iv, ciphertext, …)
 * ```
 *
 * Onboarding tenant #10,000 is one INSERT. Rotating their key is one UPDATE.
 * Neither touches `wrangler.toml`, and the number of bindings does not grow with
 * the number of tenants — it grows only when the FLEET's master key is rotated,
 * which is an operator event measured in years.
 *
 * ## Two fences, deliberately redundant
 *
 * 1. **Scope.** {@link TenantByokResolver} passes its OWN `tenantId` to the
 *    store, never one taken from the reference or the request.
 * 2. **Cryptography.** {@link sealTenantCredential} binds the ciphertext to
 *    `(tenantId, alias)` through AES-GCM's additional authenticated data, so a
 *    row that reaches the wrong tenant — copied by a bad admin write, a botched
 *    restore, or a future refactor that widens the SQL predicate — does not
 *    decrypt. It fails loudly rather than serving the wrong customer's key.
 *
 * Redundant on purpose: fence 1 is a predicate that a later edit can widen
 * without any test noticing, and this repository's dominant defect mode is
 * exactly that. Fence 2 cannot be widened by accident, because widening it means
 * changing the AAD, which breaks every existing row at once.
 *
 * ## Never logged
 *
 * No function here puts a credential value, or a ciphertext, into a message or a
 * thrown error. Failures are described by ALIAS and KEY VERSION, both of which
 * are configuration.
 */
import { type EnvLike, defaultEnv, readEnvSecret } from "./env.js";
import type { SecretResolver } from "./resolver.js";
import type { SecretRef } from "./secret-ref.js";
import { describeSecretRef } from "./secret-ref.js";

/** The version-1 master-key binding. Fleet-wide, deploy-time, exactly one. */
export const BYOK_MASTER_KEY_ENV = "FERROGATE_BYOK_MASTER_KEY";

/**
 * Prefix for versions ≥ 2, e.g. `FERROGATE_BYOK_MASTER_KEY_V2`.
 *
 * A master-key rotation adds ONE binding for the whole fleet and leaves the old
 * one bound so existing rows keep opening; it is not per-tenant, so it does not
 * reintroduce the deploy-per-tenant problem.
 */
export const BYOK_KEY_VERSION_ENV_PREFIX = "FERROGATE_BYOK_MASTER_KEY_V";

/** AES-256-GCM. 32 bytes of key, 12 bytes of IV — the WebCrypto defaults. */
const KEY_BYTES = 32;
const IV_BYTES = 12;

/**
 * The AAD domain tag. Versioned so a future change to what is bound into the
 * ciphertext is a deliberate, visible migration rather than a silent one.
 */
const AAD_DOMAIN = "ferrogate.byok.v1";

/**
 * One stored credential, exactly as the control-D1 row carries it.
 *
 * `value` is NOT a member: this type is the sealed form, and it is the only form
 * that is ever persisted, returned by a store, or logged. The plaintext exists
 * only as the return value of {@link openTenantCredential}.
 */
export interface SealedTenantCredential {
  /** Owning tenant. Part of the AAD, so it cannot be edited after sealing. */
  readonly tenantId: string;
  /** Tenant-chosen alias, e.g. `openai-enterprise`. Part of the AAD. */
  readonly alias: string;
  /**
   * The PROVIDER NAME this credential is for (`[[providers]].name`), so the
   * gateway can apply it only to routes that dispatch to that provider. Never
   * secret, and deliberately outside the AAD: re-pointing an alias at another
   * provider is a legitimate admin edit, whereas moving it to another tenant is
   * not.
   */
  readonly provider: string;
  /** Which master key sealed it. `1` is {@link BYOK_MASTER_KEY_ENV}. */
  readonly keyVersion: number;
  /** Base64 AES-GCM initialisation vector, unique per seal. */
  readonly iv: string;
  /** Base64 AES-GCM ciphertext (tag appended, as WebCrypto returns it). */
  readonly ciphertext: string;
}

/** The plaintext half handed to {@link sealTenantCredential}. */
export interface TenantCredentialInput {
  readonly tenantId: string;
  readonly alias: string;
  readonly provider: string;
  /** The provider API key. Never persisted, never logged, never in an error. */
  readonly value: string;
}

/**
 * Where sealed rows live. Implemented over control D1 by
 * `@ferrogate/storage`'s `D1TenantProviderCredentialStore`; declared
 * structurally here so this package keeps no database dependency and a test can
 * supply a `Map`.
 *
 * `lookup` takes the tenant as its FIRST argument, not as part of the alias,
 * because that is what makes the fence expressible: every implementation is
 * obliged to scope, and an implementation that ignored the argument is visible
 * in its own signature.
 */
export interface TenantCredentialStore {
  lookup(tenantId: string, alias: string): Promise<SealedTenantCredential | null>;
}

// ---------------------------------------------------------------------------
// Keyring
// ---------------------------------------------------------------------------

/**
 * The fleet's master keys, by version.
 *
 * Held as raw bytes rather than as `CryptoKey` because `crypto.subtle.importKey`
 * is async and this is built synchronously from the env; the import happens per
 * operation, which is cheap next to the D1 read it accompanies.
 */
export class ByokKeyring {
  private readonly keys: ReadonlyMap<number, Uint8Array>;

  constructor(keys: ReadonlyMap<number, Uint8Array>) {
    if (keys.size === 0) {
      throw new Error(
        `no BYOK master key is bound: set ${BYOK_MASTER_KEY_ENV} to a base64-encoded ` +
          `${KEY_BYTES}-byte key (one binding for the whole fleet — it is NOT per tenant)`,
      );
    }
    this.keys = keys;
  }

  /** The version new writes are sealed under: the highest bound version. */
  get currentVersion(): number {
    return Math.max(...this.keys.keys());
  }

  /** Raw key material for `version`, or `null` when that version is unbound. */
  keyFor(version: number): Uint8Array | null {
    return this.keys.get(version) ?? null;
  }
}

/** Decode a base64 master key, refusing anything that is not 32 bytes. */
function decodeKey(name: string, encoded: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    const binary = atob(encoded.trim());
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error(`${name} is not valid base64`);
  }
  if (bytes.byteLength !== KEY_BYTES) {
    // The LENGTH is safe to state; the value is not. A short key would still
    // "work" for AES-GCM-128 in some libraries, which is exactly the kind of
    // silent downgrade this refuses.
    throw new Error(
      `${name} must decode to exactly ${KEY_BYTES} bytes (got ${bytes.byteLength})`,
    );
  }
  return bytes;
}

/**
 * Build the keyring from PLAIN-STRING env slots.
 *
 * Synchronous, so it reads `[vars]` / `wrangler secret put` slots only. A
 * `[[secrets_store_secrets]]` binding needs `await get()` — use
 * {@link byokKeyringFromEnvAsync} from any call site that can await, which every
 * request-path caller can.
 */
export function byokKeyringFromEnv(env: EnvLike = defaultEnv()): ByokKeyring {
  const keys = new Map<number, Uint8Array>();
  for (const [name, slot] of Object.entries(env)) {
    if (typeof slot !== "string" || slot.trim() === "") continue;
    const version = keyVersionOfBinding(name);
    if (version === null) continue;
    keys.set(version, decodeKey(name, slot));
  }
  return new ByokKeyring(keys);
}

/**
 * The async twin, which additionally serves Secrets Store bindings. This is the
 * form the Workers request path uses, because the master key is exactly the kind
 * of credential an operator SHOULD put in Secrets Store.
 */
export async function byokKeyringFromEnvAsync(
  env: EnvLike = defaultEnv(),
): Promise<ByokKeyring> {
  const keys = new Map<number, Uint8Array>();
  for (const name of Object.keys(env)) {
    const version = keyVersionOfBinding(name);
    if (version === null) continue;
    const value = await readEnvSecret(name, env);
    if (value === undefined) continue;
    keys.set(version, decodeKey(name, value));
  }
  return new ByokKeyring(keys);
}

/** `FERROGATE_BYOK_MASTER_KEY` → 1, `…_V7` → 7, anything else → `null`. */
function keyVersionOfBinding(name: string): number | null {
  if (name === BYOK_MASTER_KEY_ENV) return 1;
  if (!name.startsWith(BYOK_KEY_VERSION_ENV_PREFIX)) return null;
  const suffix = name.slice(BYOK_KEY_VERSION_ENV_PREFIX.length);
  if (!/^[0-9]+$/.test(suffix)) return null;
  const version = Number.parseInt(suffix, 10);
  return version >= 1 ? version : null;
}

/**
 * Mint a fresh base64 master key — for `wrangler secret put` and for tests.
 *
 * Exported because an operator needs a correct key more than they need a
 * shell one-liner, and because a 31-byte key from a mistyped `head -c` is
 * refused at {@link decodeKey} with a message that arrives long after the
 * mistake.
 */
export function generateByokMasterKey(): string {
  const bytes = new Uint8Array(KEY_BYTES);
  crypto.getRandomValues(bytes);
  return encodeBase64(bytes);
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/**
 * The additional authenticated data: the domain tag, the tenant and the alias.
 *
 * `\n`-joined rather than concatenated so `(tenant="a", alias="b-c")` and
 * `(tenant="a-b", alias="c")` cannot collide — a separator-free encoding would
 * make two distinct scopes share one AAD, which is a fence with a hole in it.
 * The alias grammar already forbids `\n`, and the tenant id is an opaque
 * identifier, so the joined form is unambiguous.
 */
function additionalData(tenantId: string, alias: string): Uint8Array {
  return new TextEncoder().encode(`${AAD_DOMAIN}\n${tenantId}\n${alias}`);
}

async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    // A fresh copy: `importKey` wants an ArrayBuffer view it fully owns, and the
    // keyring's buffer is shared across calls.
    raw.slice().buffer as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Seal a credential under the keyring's CURRENT version. */
export async function sealTenantCredential(
  keyring: ByokKeyring,
  input: TenantCredentialInput,
): Promise<SealedTenantCredential> {
  const tenantId = input.tenantId.trim();
  const alias = input.alias.trim();
  if (tenantId === "") {
    throw new Error("a BYOK credential must be sealed to a non-empty tenant id");
  }
  if (input.value.trim() === "") {
    // An empty credential is a well-formed `Authorization` header, so it would
    // reach the provider and come back 401 looking like an upstream outage.
    throw new Error(`BYOK alias ${alias} was given an empty credential value`);
  }

  const version = keyring.currentVersion;
  const material = keyring.keyFor(version);
  /* c8 ignore next 3 -- currentVersion is derived from the same map */
  if (material === null) {
    throw new Error(`BYOK master key version ${version} is not bound`);
  }

  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(iv);
  const sealed = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
      additionalData: additionalData(tenantId, alias) as unknown as BufferSource,
    },
    await importKey(material),
    new TextEncoder().encode(input.value) as unknown as BufferSource,
  );

  return {
    tenantId,
    alias,
    provider: input.provider.trim(),
    keyVersion: version,
    iv: encodeBase64(iv),
    ciphertext: encodeBase64(new Uint8Array(sealed)),
  };
}

/**
 * Open a sealed credential.
 *
 * Throws — never returns `null` — when the ciphertext does not authenticate,
 * because that is not "not found": it means the row, its tenant, its alias or
 * the key disagree, and quietly falling through to the platform's own provider
 * key would bill FerroGate for traffic the tenant believes is on their own
 * agreement. The message names the alias and the key version and nothing else.
 */
export async function openTenantCredential(
  keyring: ByokKeyring,
  record: SealedTenantCredential,
): Promise<string> {
  const material = keyring.keyFor(record.keyVersion);
  if (material === null) {
    throw new Error(
      `BYOK alias ${record.alias} was sealed with master key version ` +
        `${record.keyVersion}, which is not bound; keep the old ` +
        `${BYOK_KEY_VERSION_ENV_PREFIX}${record.keyVersion} binding in place until every ` +
        "row has been re-sealed",
    );
  }

  try {
    const opened = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decodeBase64(record.iv) as unknown as BufferSource,
        additionalData: additionalData(
          record.tenantId,
          record.alias,
        ) as unknown as BufferSource,
      },
      await importKey(material),
      decodeBase64(record.ciphertext) as unknown as BufferSource,
    );
    return new TextDecoder().decode(opened);
  } catch {
    // Deliberately swallowing the cause: WebCrypto's `OperationError` carries
    // nothing useful, and re-throwing it verbatim risks a runtime some day
    // including a fragment of the input. Alias + version is everything an
    // operator can act on.
    throw new Error(
      `BYOK credential for alias ${record.alias} could not be decrypted with master key ` +
        `version ${record.keyVersion}. The row is bound to its (tenant, alias) pair, so this ` +
        "means the key is wrong or the row was moved between tenants or aliases.",
    );
  }
}

// ---------------------------------------------------------------------------
// The resolver
// ---------------------------------------------------------------------------

/** Everything {@link TenantByokResolver} needs, all of it injected. */
export interface TenantByokResolverOptions {
  /** The AUTHENTICATED caller's tenant. Never read from a request or a URI. */
  readonly tenantId: string;
  readonly store: TenantCredentialStore;
  readonly keyring: ByokKeyring;
}

/**
 * Resolves `byok://<alias>` for ONE tenant.
 *
 * The tenant is a constructor argument and there is no setter: an instance
 * cannot be re-pointed at another tenant mid-request, and a resolver built for
 * tenant A that leaked into tenant B's request would still only ever read
 * tenant A's rows — the failure mode would be a refusal, not a cross-tenant
 * read.
 *
 * `null` means "this tenant has no such alias", which is the same answer another
 * tenant's alias produces. That is intentional: a distinct "exists, but not
 * yours" would turn the resolver into an oracle for other tenants' alias names.
 */
export class TenantByokResolver implements SecretResolver {
  private readonly tenantId: string;
  private readonly store: TenantCredentialStore;
  private readonly keyring: ByokKeyring;

  constructor(options: TenantByokResolverOptions) {
    const tenantId = options.tenantId.trim();
    if (tenantId === "") {
      // A blank tenant would make the store's `WHERE tenant_id = ?` match
      // nothing (best case) or everything (if some future store treats blank as
      // a wildcard). Refuse at construction, where the caller can be fixed.
      throw new Error(
        "TenantByokResolver requires a non-empty tenant id; a byok:// reference must never " +
          "resolve outside an authenticated tenant scope",
      );
    }
    this.tenantId = tenantId;
    this.store = options.store;
    this.keyring = options.keyring;
  }

  async resolve(reference: SecretRef): Promise<string | null> {
    if (reference.kind !== "byok") {
      throw new Error(
        `TenantByokResolver cannot resolve a non-byok:// reference: ${describeSecretRef(reference)}`,
      );
    }
    return (await this.resolveBinding(reference.alias))?.value ?? null;
  }

  /**
   * The same resolution, returning the PROVIDER alongside the value.
   *
   * The gateway needs both: a credential registered for `openai` must never be
   * presented to `anthropic`, so the dispatch path has to know which provider an
   * alias belongs to. Doing it here rather than making the caller issue a second
   * store read keeps it to ONE lookup and — more importantly — keeps the tenant
   * fence in ONE place. A caller that fetched the row itself to read `.provider`
   * would be a second code path that has to remember to scope, which is exactly
   * how a fence acquires a hole.
   */
  async resolveBinding(
    alias: string,
  ): Promise<{ readonly provider: string; readonly value: string } | null> {
    // THE FENCE: `this.tenantId`, never anything off the reference or the request.
    const record = await this.store.lookup(this.tenantId, alias);
    if (record === null) return null;
    return {
      provider: record.provider,
      value: await openTenantCredential(this.keyring, record),
    };
  }
}

// ---------------------------------------------------------------------------
// base64 (no Node `Buffer` — this package runs in workerd too)
// ---------------------------------------------------------------------------

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(encoded: string): Uint8Array {
  const binary = atob(encoded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
