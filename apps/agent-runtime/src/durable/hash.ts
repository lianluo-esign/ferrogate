/**
 * Virtual-API-key material: prefix, hash, last4 — and verification of a
 * presented secret against a stored `api_keys.key_hash`.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/api_key.rs`
 * (`virtual_api_key_material`, `hash_virtual_api_key_secret`,
 * `virtual_api_key_prefix`, `verify_virtual_api_key_secret`).
 *
 * ## The construction, stated exactly
 *
 * Keys are stored HASHED, never plaintext. A minted secret has the shape
 * `fg_<48 lowercase hex chars>` (24 CSPRNG bytes = 192 bits). Three derived
 * values go into the `api_keys` row:
 *
 * | column       | derivation                                          |
 * |--------------|-----------------------------------------------------|
 * | `key_prefix` | the first **16 characters** of the trimmed secret    |
 * | `key_hash`   | `"sha256:" + lowercase_hex(SHA-256(trimmed secret))` |
 * | `last4`      | the last **4 characters** of the trimmed secret      |
 *
 * `key_prefix` is the lookup index (`idx_api_keys_prefix`); it is NOT a
 * credential. `last4` is a cheap pre-filter, also not a credential.
 * Authentication is decided ONLY by {@link verifyStoredKeyHash}.
 *
 * The hash is a bare, unsalted, single-round SHA-256 — deliberately, and it
 * matches Rust byte for byte. The input is 192 bits of CSPRNG output, not a
 * human-chosen password, so a work factor defends nothing; and this runs on
 * every authenticated request, where a slow KDF is a DoS amplifier.
 *
 * Rust slices with `.chars()` (Unicode scalar values). `[...secret]` is the JS
 * equivalent; `secret.slice(0, 16)` is NOT — it splits surrogate pairs.
 *
 * PORT-TODO(inventory-edge-control §5.2) — KEPT, SCOPE LIMIT, NOT A PLATFORM
 * LIMIT. State the limit exactly, because it is unusual for this project:
 * BLAKE2b runs perfectly well on Workers (`apps/gateway/src/keys/blake2b.ts`
 * already does), so nothing about Cloudflare blocks this. What blocks it is
 * ownership: the honest close is to MOVE the primitive — sha256 + blake2b + the
 * constant-time compare — into a package both Workers import (`packages/core`
 * is the obvious home), and `packages/*` is not this slice's to edit. Pasting a
 * THIRD copy of BLAKE2b into this app would make the marker disappear while
 * making the divergence worse, which is the fake this rule exists to forbid.
 *
 * The divergence, concretely: Rust `verify_virtual_api_key_secret` accepts two
 * stored-hash tags, `sha256:` and `blake2b:`. Only `sha256:` is implemented
 * here and a `blake2b:`-tagged row is REFUSED (fail closed — an unrecognised
 * tag can only ever deny), while `apps/gateway/src/keys/hash.ts` accepts both.
 *
 * OPERATOR-VISIBLE CONSEQUENCE, which is why this is worth closing rather than
 * tolerating: a key whose `api_keys` row was minted by the Rust tree with a
 * `blake2b:` hash authenticates against `apps/gateway` and is rejected as
 * `invalid_api_key` against `apps/agent-runtime` — one credential, two verdicts,
 * with no error text that would explain why. It is not a security hole (the
 * strict side is the refusing one) but it is a real inconsistency.
 *
 * FerroGate itself only ever MINTS `sha256:` ({@link hashVirtualApiKeySecret}),
 * so the affected rows are exactly the ones imported from the Rust tree, not
 * keys this system can produce. Pinned in BOTH directions by
 * `test/durable/keys.spec.ts` so neither the refusal nor a future acceptance
 * can land unnoticed.
 */

/** Rust `VIRTUAL_API_KEY_PREFIX_CHARS`. */
export const VIRTUAL_API_KEY_PREFIX_CHARS = 16;

const UTF8 = new TextEncoder();

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
 * Differing lengths short-circuit exactly as they do in Rust. Digest hex
 * strings all have the same length, so the early-out is unreachable for a
 * well-formed row.
 */
export function constantTimeEqualBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= (left[i] as number) ^ (right[i] as number);
  }
  return diff === 0;
}

/** Lowercase hex SHA-256 of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", UTF8.encode(input));
  return encodeHex(new Uint8Array(digest));
}

/**
 * Rust `hash_virtual_api_key_secret`: `sha256:` + hex(SHA-256(trim(secret))).
 *
 * The WRITE construction — the only one FerroGate mints. Exported so a seeder
 * (and this app's own tests) provision rows with exactly the bytes the resolver
 * will later verify, rather than a second hand-rolled copy that could drift.
 */
export async function hashVirtualApiKeySecret(secret: string): Promise<string> {
  return `sha256:${await sha256Hex(secret.trim())}`;
}

/** Rust `virtual_api_key_prefix`: first 16 chars of the trimmed secret. */
export function virtualApiKeyPrefix(secret: string): string | null {
  const trimmed = secret.trim();
  if (trimmed === "") return null;
  return [...trimmed].slice(0, VIRTUAL_API_KEY_PREFIX_CHARS).join("");
}

/** Last 4 chars of the trimmed secret (Rust `virtual_api_key_material.last4`). */
export function virtualApiKeyLast4(secret: string): string {
  return [...secret.trim()].slice(-4).join("");
}

/**
 * Rust `verify_virtual_api_key_secret`, narrowed to the `sha256:` tag.
 *
 * ANYTHING else is `false` — including a bare hex string with no algorithm tag,
 * a `blake2b:` tag (see the module marker), and a plaintext secret accidentally
 * written into `key_hash`. That fail-closed default is what makes "a
 * mis-provisioned row cannot authenticate" structural.
 *
 * The comparison is constant-time over the hex bytes, so a near-miss secret
 * cannot be walked out one nibble at a time by timing the response.
 */
export async function verifyStoredKeyHash(secret: string, storedHash: string): Promise<boolean> {
  if (!storedHash.startsWith("sha256:")) return false;
  const expected = storedHash.slice("sha256:".length);
  return constantTimeEqualBytes(UTF8.encode(await sha256Hex(secret)), UTF8.encode(expected));
}
