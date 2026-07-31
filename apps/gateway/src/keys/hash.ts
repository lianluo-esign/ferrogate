/**
 * Virtual-API-key material: prefix, hash, last4 — and the verification of a
 * presented secret against a stored hash.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/api_key.rs`
 * (`virtual_api_key_material`, `hash_virtual_api_key_secret`,
 * `virtual_api_key_prefix`, `verify_virtual_api_key_secret`) plus
 * `crates/ferrogate-auth-service/src/util.rs::encode_hex`.
 *
 * ## The construction, stated exactly
 *
 * **Keys are stored HASHED, never plaintext.** A secret has the shape
 * `fg_<48 lowercase hex chars>` (`generate_virtual_api_key_secret` =
 * `format!("fg_{}", generate_random_hex(24))` — 24 random bytes, so 192 bits of
 * entropy). Three derived values go into the `api_keys` row:
 *
 * | column       | derivation                                              |
 * |--------------|---------------------------------------------------------|
 * | `key_prefix` | the first **16 characters** of the trimmed secret        |
 * | `key_hash`   | `"sha256:" + lowercase_hex(SHA-256(trimmed secret))`     |
 * | `last4`      | the last **4 characters** of the trimmed secret          |
 *
 * `key_prefix` is the lookup index (`idx_api_keys_prefix`) — it is NOT a
 * credential: it is a public, non-secret 13-hex-char slice used only to narrow
 * the candidate set before the real check. `last4` is a cheap pre-filter, also
 * not a credential. Authentication is decided ONLY by `verifyStoredKeyHash`.
 *
 * **The hash is a bare, unsalted, single-round SHA-256 — deliberately, and it
 * matches Rust byte for byte.** It is not argon2/PBKDF2 and must not be
 * "upgraded" here: (a) the input is 192 bits of CSPRNG output, not a
 * human-chosen password, so there is nothing for a work factor to defend —
 * brute force is infeasible regardless; (b) it is a *lookup* key, computed on
 * every request in the data-plane hot path, where a deliberately slow KDF is a
 * DoS amplifier; and (c) changing the construction would invalidate every
 * existing stored row. Argon2 in this tree hashes admin-console **passwords**
 * (`util.rs::hash_password`), which is a different problem — see
 * `inventory-edge-control.md` §5.3.
 *
 * ## Character semantics
 *
 * Rust slices with `.chars()`, i.e. Unicode SCALAR VALUES, not bytes and not
 * UTF-16 code units. `[...secret]` is the JS equivalent (the string iterator
 * yields code points), so a non-ASCII secret produces the same prefix/last4
 * here as in Rust. `secret.slice(0, 16)` would NOT — it splits surrogate pairs.
 */
import { blake2b } from "./blake2b.js";

/** Rust `VIRTUAL_API_KEY_PREFIX_CHARS`. */
export const VIRTUAL_API_KEY_PREFIX_CHARS = 16;

/** Rust `generate_virtual_api_key_secret`: `fg_<hex>`. */
export const VIRTUAL_API_KEY_SECRET_PREFIX = "fg_";

/** The two stored-hash algorithms `verify_virtual_api_key_secret` accepts. */
export const SUPPORTED_KEY_HASH_ALGORITHMS = ["sha256", "blake2b"] as const;
export type KeyHashAlgorithm = (typeof SUPPORTED_KEY_HASH_ALGORITHMS)[number];

/** Rust `encode_hex` — lowercase, two chars per byte, no separator. */
export function encodeHex(bytes: Uint8Array): string {
  let encoded = "";
  for (const byte of bytes) {
    encoded += byte.toString(16).padStart(2, "0");
  }
  return encoded;
}

/**
 * Length-independent constant-time byte comparison (Rust `constant_time_eq`).
 *
 * Differing lengths short-circuit exactly as they do in Rust — the Rust
 * function returns early on a length mismatch too, so this is parity, not a
 * weakening. Digest hex strings all have the same length anyway, so the
 * early-out is unreachable for a well-formed row.
 */
export function constantTimeEqualBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= (left[i] as number) ^ (right[i] as number);
  }
  return diff === 0;
}

const UTF8 = new TextEncoder();

/** Lowercase hex SHA-256 of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", UTF8.encode(input));
  return encodeHex(new Uint8Array(digest));
}

/** Lowercase hex BLAKE2b-512 of a UTF-8 string. */
export function blake2b512Hex(input: string): string {
  return encodeHex(blake2b(UTF8.encode(input), 64));
}

/**
 * Rust `hash_virtual_api_key_secret`: `sha256:` + hex(SHA-256(trim(secret))).
 *
 * This is the WRITE construction — the only one FerroGate mints. Exported so
 * the control plane (and this module's own tests) provision rows with exactly
 * the bytes the resolver will later verify, rather than a second hand-rolled
 * copy that could drift.
 */
export async function hashVirtualApiKeySecret(secret: string): Promise<string> {
  return `sha256:${await sha256Hex(secret.trim())}`;
}

/** Rust `virtual_api_key_prefix`: first 16 chars of the trimmed secret; `null` if blank. */
export function virtualApiKeyPrefix(secret: string): string | null {
  const trimmed = secret.trim();
  if (trimmed === "") return null;
  return [...trimmed].slice(0, VIRTUAL_API_KEY_PREFIX_CHARS).join("");
}

/** Last 4 chars of the trimmed secret (Rust `virtual_api_key_material.last4`). */
export function virtualApiKeyLast4(secret: string): string {
  return [...secret.trim()].slice(-4).join("");
}

/** Rust `VirtualApiKeyMaterial`. */
export interface VirtualApiKeyMaterial {
  readonly keyPrefix: string;
  readonly keyHash: string;
  readonly last4: string;
}

/**
 * Rust `virtual_api_key_material`: everything the `api_keys` row stores about a
 * freshly-minted secret. `null` for a blank secret, exactly as Rust returns
 * `None`.
 */
export async function virtualApiKeyMaterial(secret: string): Promise<VirtualApiKeyMaterial | null> {
  const trimmed = secret.trim();
  if (trimmed === "") return null;
  const keyPrefix = virtualApiKeyPrefix(trimmed);
  if (keyPrefix === null) return null;
  return {
    keyPrefix,
    keyHash: await hashVirtualApiKeySecret(trimmed),
    last4: virtualApiKeyLast4(trimmed),
  };
}

/**
 * Rust `verify_virtual_api_key_secret`.
 *
 * Accepts `sha256:<hex>` and `blake2b:<hex>`; **anything else is `false`** —
 * including a bare hex string with no algorithm tag, and including a plaintext
 * secret accidentally written into `key_hash`. That fail-closed default is the
 * property that makes "a mis-provisioned row cannot authenticate" structural:
 * an unrecognised `key_hash` can only ever deny.
 *
 * The comparison is constant-time over the hex bytes, so a near-miss secret
 * cannot be walked out one nibble at a time by timing the response.
 */
export async function verifyStoredKeyHash(secret: string, storedHash: string): Promise<boolean> {
  if (storedHash.startsWith("sha256:")) {
    const expected = storedHash.slice("sha256:".length);
    return constantTimeEqualBytes(UTF8.encode(await sha256Hex(secret)), UTF8.encode(expected));
  }
  if (storedHash.startsWith("blake2b:")) {
    const expected = storedHash.slice("blake2b:".length);
    return constantTimeEqualBytes(UTF8.encode(blake2b512Hex(secret)), UTF8.encode(expected));
  }
  return false;
}
