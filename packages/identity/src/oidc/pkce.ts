/**
 * PKCE (RFC 7636) and the two other single-use secrets an authorize leg mints.
 */
import type { IdentityRandom } from "../ports.js";
import { bytesToBase64Url } from "./base64url.js";

/**
 * A `code_verifier` / `code_challenge` (S256) pair.
 *
 * 48 random bytes → 96 hex characters, comfortably inside RFC 7636's 43..128
 * and well past its 256-bit entropy floor. The CHALLENGE is what goes on the
 * wire; the VERIFIER is stashed server-side and presented at the token
 * exchange, which is what makes an intercepted authorization code useless to
 * anyone who did not start the flow.
 */
export async function generatePkcePair(
  random: IdentityRandom,
): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = random.hex(48);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier) as unknown as BufferSource,
  );
  return { codeVerifier, codeChallenge: bytesToBase64Url(new Uint8Array(digest)) };
}

/**
 * The opaque CSRF `state`. It is also the primary key of the pending-flow row,
 * so it must be unguessable: a predictable state lets an attacker plant a flow
 * id the victim's browser will complete.
 */
export function generateState(random: IdentityRandom): string {
  return random.hex(24);
}

/**
 * The OIDC `nonce`. Sent on the authorize leg, stashed, and required to come
 * back inside the ID token — which is what stops an attacker injecting an ID
 * token they obtained elsewhere into a victim's callback.
 *
 * PARITY NOTE: the Rust reference (`sso.rs::handle_sso_authorize`) does NOT
 * send a nonce and does not check one, so this is a deliberate hardening over
 * the reference rather than a transcription of it. It matches what the MCP
 * per-user OAuth leg (`apps/mcp/src/identity/oauth.ts`) already does, and OIDC
 * Core §3.1.2.1 makes `nonce` mandatory for the implicit flow and RECOMMENDED
 * for code — with the code flow's protection resting on PKCE plus the fact
 * that the token exchange is a back channel. FerroGate has both, and adds the
 * nonce as defence in depth.
 */
export function generateNonce(random: IdentityRandom): string {
  return random.hex(24);
}
