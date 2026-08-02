/**
 * The console's three credential primitives: password hashing, refresh-token
 * secrets, and the id generator.
 *
 * Port of the parts of `crates/ferrogate-auth-service/src/util.rs` the session
 * surface uses (`hash_password`, `verify_password`,
 * `generate_refresh_token_secret`, `next_id`, `slugify_with_suffix`,
 * `is_valid_email`, `constant_time_eq`).
 *
 * ## Password hashing is PBKDF2-SHA256, and Rust's is Argon2id
 *
 * This is the ONE deliberate deviation in this module, and it is a platform
 * fact rather than a preference: workerd's `crypto.subtle` implements PBKDF2
 * and HKDF and nothing else memory-hard, and the alternative — shipping an
 * Argon2 WASM blob — costs a multi-hundred-kB bundle and several milliseconds
 * of CPU per login inside a Worker's CPU budget.
 *
 * What is PRESERVED is every property the surface actually depends on:
 *
 *  - the plaintext password is never stored and never derivable from the row;
 *  - each row carries its OWN random 16-byte salt, so two users with the same
 *    password have different digests and a precomputed table is useless;
 *  - verification is deliberately slow ({@link PBKDF2_ITERATIONS} iterations);
 *  - the digest comparison is constant-time
 *    (Rust `constant_time_eq` / argon2's own verify).
 *
 * The stored format is self-describing —
 * `pbkdf2-sha256$<iterations>$<salt-hex>$<digest-hex>` — so the iteration count
 * is a per-row property and can be raised for new rows without invalidating
 * old ones. An unparseable or empty hash VERIFIES AS FALSE, never as true:
 * that is what makes an SSO-only account (which Rust gives an
 * `unusable_password_hash`) unable to be logged into with a password, and it is
 * why {@link verifyPassword} has no "no hash stored ⇒ allow" branch.
 */

const UTF8 = new TextEncoder();

/** Named so a future raise is one edit and shows up in the stored rows. */
export const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_SALT_BYTES = 16;
const PBKDF2_DIGEST_BITS = 256;
const PBKDF2_SCHEME = "pbkdf2-sha256";

/** Rust `encode_hex`: lowercase, two chars per byte, no separator. */
export function encodeHex(bytes: Uint8Array): string {
  let encoded = "";
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

function decodeHex(value: string): Uint8Array | null {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/** Rust `generate_random_hex`. */
export function generateRandomHex(byteLength: number): string {
  return encodeHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** Rust `generate_refresh_token_secret`: 32 random bytes, hex. */
export function generateRefreshTokenSecret(): string {
  return generateRandomHex(32);
}

/**
 * Rust `constant_time_eq`. Length is compared first and leaks only the length,
 * exactly as the Rust helper does.
 */
export function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", UTF8.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    PBKDF2_DIGEST_BITS,
  );
  return encodeHex(new Uint8Array(bits));
}

/** Rust `hash_password`. Salted, iterated, self-describing. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const digest = await derive(password, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_SCHEME}$${PBKDF2_ITERATIONS}$${encodeHex(salt)}$${digest}`;
}

/**
 * Rust `verify_password`. FALSE for every malformed input — an unparseable
 * hash, an unknown scheme, a non-positive iteration count or a blank column
 * are all "this account has no usable password", never "any password matches".
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [scheme, iterationsText, saltHex, digestHex] = parts as [string, string, string, string];
  if (scheme !== PBKDF2_SCHEME) return false;
  const iterations = Number.parseInt(iterationsText, 10);
  if (!Number.isSafeInteger(iterations) || iterations <= 0) return false;
  const salt = decodeHex(saltHex);
  if (salt === null || salt.length === 0 || decodeHex(digestHex) === null) return false;
  const candidate = await derive(password, salt, iterations);
  return constantTimeEqual(candidate, digestHex);
}

/**
 * Rust `unusable_password_hash`: an Argon2 hash of a random, immediately
 * discarded secret, so an SSO/SCIM-provisioned account has no password that
 * can be presented. Kept here because the same account family will arrive with
 * `packages/identity`, and inventing a second convention then is how the
 * "blank hash means no password" hole gets opened.
 */
export async function unusablePasswordHash(): Promise<string> {
  return hashPassword(generateRandomHex(32));
}

/** Rust `is_valid_email`, condition for condition. */
export function isValidEmail(email: string): boolean {
  const at = email.indexOf("@");
  if (at < 0) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  return local !== "" && domain.includes(".") && !domain.startsWith(".") && !domain.endsWith(".");
}

/**
 * Rust `next_id`. The Rust version is `"{kind}-{nanos}-{pid}"`; a Worker has no
 * pid and `Date.now()` is coarsened (and, inside a request, FROZEN) by
 * Cloudflare's timer mitigation, so the uniqueness has to come from
 * `crypto.randomUUID` rather than from the clock. Two ids minted in the same
 * millisecond of the same isolate must differ — `handle_admin_register` mints
 * four in a row and they are primary keys.
 */
export function nextId(kind: string): string {
  return `${kind}-${crypto.randomUUID()}`;
}

/**
 * Rust `slugify_with_suffix`. The suffix is a HASH of the seed, not a slice of
 * it: Rust's comment records that slicing landed on the constant `pid` segment
 * and made every same-named registration in one process collide permanently on
 * `tenants.slug`, which is UNIQUE.
 */
export function slugifyWithSuffix(name: string, uniqueSeed: string): string {
  const normalized = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-");
  const base =
    normalized
      .split("-")
      .filter((segment) => segment !== "")
      .join("-") || "org";
  // FNV-1a over the seed, rendered as 16 hex chars — the same SHAPE as Rust's
  // `{:016x}` of `DefaultHasher`, whose exact algorithm is unspecified even in
  // Rust, so only the property (deterministic, seed-dependent) is portable.
  let hash = 0xcbf2_9ce4_8422_2325n;
  for (const character of uniqueSeed) {
    hash ^= BigInt(character.codePointAt(0) ?? 0);
    hash = (hash * 0x1000_0000_01b3n) & 0xffff_ffff_ffff_ffffn;
  }
  return `${base}-${hash.toString(16).padStart(16, "0")}`;
}
