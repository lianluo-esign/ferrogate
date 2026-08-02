/**
 * Secret-shaped key redaction — port of `ferrogate-core::SECRET_SHAPED_KEY_FRAGMENTS`.
 *
 * The Rust crate exposes a single shared list of key-name fragments that must
 * NEVER appear (at any nesting depth) in an admin/diagnostics response, so a
 * guard and the surface it guards cannot drift (issue #351 shipped two copies,
 * one of which had silently lost `seed` and `token`). Matching is substring,
 * case-insensitive: lowercase the key and test `contains`.
 *
 * The inventory (§1.2) directs the port to ship the shared constant PLUS a
 * recursive redaction helper (the Rust callers implement the walk at each call
 * site; we centralize it here so every admin/diagnostics surface redacts the
 * same way).
 */

/**
 * The 10 case-insensitive substrings that must never appear in any
 * admin/diagnostics response key at any depth.
 */
export const SECRET_SHAPED_KEY_FRAGMENTS = [
  "secret",
  "signer",
  "signature",
  "private",
  "keypair",
  "mnemonic",
  "seed",
  "credential",
  "password",
  "token",
] as const;

/** A single secret-shaped fragment from {@link SECRET_SHAPED_KEY_FRAGMENTS}. */
export type SecretShapedKeyFragment = (typeof SECRET_SHAPED_KEY_FRAGMENTS)[number];

/** The value a redacted key's contents are replaced with. */
export const REDACTED_PLACEHOLDER = "<redacted>";

/**
 * True when `key` (case-insensitively) contains any secret-shaped fragment.
 * Mirrors the Rust guard: `let k = key.to_lowercase(); FRAGMENTS.iter().any(|f| k.contains(f))`.
 */
export function isSecretShapedKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SECRET_SHAPED_KEY_FRAGMENTS.some((fragment) => lower.includes(fragment));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Recursively redact any value held under a secret-shaped key, returning a deep
 * copy (the input is never mutated). Once a key is secret-shaped its ENTIRE
 * value is replaced with `placeholder` and not descended into — the whole
 * subtree is what "must never appear".
 */
export function redactSecretShapedKeys<T>(value: T, placeholder: string = REDACTED_PLACEHOLDER): T {
  return redactInner(value, placeholder) as T;
}

function redactInner(value: unknown, placeholder: string): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactInner(item, placeholder));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      out[key] = isSecretShapedKey(key) ? placeholder : redactInner(child, placeholder);
    }
    return out;
  }
  return value;
}

/**
 * Collect the dotted/indexed paths of every secret-shaped key found at any
 * depth (e.g. `config.api_token`, `items[2].private_key`). Empty ⇒ the value is
 * safe to return from an admin/diagnostics surface. Useful as a test/CI guard.
 */
export function secretShapedKeyPaths(value: unknown): string[] {
  const paths: string[] = [];
  walk(value, "", paths);
  return paths;
}

/** Convenience predicate: any secret-shaped key present anywhere in `value`. */
export function hasSecretShapedKey(value: unknown): boolean {
  return secretShapedKeyPaths(value).length > 0;
}

function walk(value: unknown, prefix: string, out: string[]): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walk(item, `${prefix}[${index}]`, out));
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (isSecretShapedKey(key)) {
        out.push(path);
      }
      walk(child, path, out);
    }
  }
}
