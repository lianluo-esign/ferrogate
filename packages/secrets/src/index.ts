/**
 * `@ferrogate/secrets` — secret reference resolution (`env://`, `vault://`,
 * `cf://`).
 *
 * Replaces the Rust crate `ferrogate-secrets`. Inside a Worker a `cf://` secret
 * arrives as a Secrets Store binding (deploy-time), so resolution is a lookup,
 * never a network write.
 */
import type { Scope } from "@ferrogate/core";

/** Supported secret-reference URI schemes. */
export const SECRET_SCHEMES = ["env://", "vault://", "cf://"] as const;
export type SecretScheme = (typeof SECRET_SCHEMES)[number];

/** A secret reference string (never the secret value itself). */
export type SecretRef = `${SecretScheme}${string}`;

/** A resolver turns a `SecretRef` into a live secret value on demand. */
export interface SecretResolver {
  resolve(ref: SecretRef, scope?: Scope): Promise<string>;
}

/** Narrowing guard for a syntactically valid secret reference. */
export function isSecretRef(value: string): value is SecretRef {
  return SECRET_SCHEMES.some((scheme) => value.startsWith(scheme));
}
