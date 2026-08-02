/**
 * The verifier — the whole security value of #691 is in this file.
 *
 * ## The walk, and why it is in this order
 *
 * Root → leaf, refusing at the first failure, and every step is a REFUSAL of
 * the request rather than a demotion of the chain. "Silently narrow" and
 * "silently drop the bad link" are both worse than refusing: they produce a
 * served request whose audit row describes a delegation that was never
 * authorised.
 *
 *  1. **Size, then depth.** Both before any decoding, because both are bounds
 *     on work the caller controls (`link.ts` explains the numbers).
 *  2. **Signature, per link.** Nothing below this point is believed about a
 *     link whose signature has not verified. In particular the tenant, the
 *     scope and the `prev` pointer are all attacker-controlled bytes until the
 *     HMAC says otherwise.
 *  3. **Tenant.** Every link must name the AUTHENTICATED tenant. A chain minted
 *     for another tenant is refused even though its signature is perfectly
 *     valid — the mint key is fleet-wide, so the tenant claim is the only thing
 *     that stops a valid link from one tenant being presented in another.
 *  4. **Linkage.** `link[i].prev === link[i-1].jti` AND
 *     `link[i].act === link[i-1].sub`. Without the first, links can be spliced
 *     out of two chains that share a principal; without the second, a valid
 *     link could be re-parented under a different delegator. The root, and only
 *     the root, carries no `prev`.
 *  5. **Freshness.** Per link: not expired, not issued in the future, and its
 *     own lifetime within the cap. Across links: a child may not outlive its
 *     parent, so revoking-by-expiry propagates downwards the way authority
 *     does.
 *  6. **Attenuation.** `link[i].scope ⊆ link[i-1].scope`. A link claiming MORE
 *     than its delegator refuses the chain — it is not narrowed to the
 *     delegator's set, because narrowing would serve a request under an
 *     authority nobody granted and log it as if they had.
 *  7. **Presenter binding.** The leaf's `sub_key` must be the api-key id that
 *     actually authenticated this request. This is what makes a captured header
 *     useless on its own: replaying it requires the leaf's credential too.
 *  8. **Credential ceiling.** The leaf's scope set must be held by the
 *     presenting credential. A chain may only ever narrow what the credential
 *     already has; it can never be a privilege-escalation channel that turns a
 *     read-only key into a writing one.
 *  9. **Required scope.** The operation's required scope must be in the
 *     attenuated set. Without this step attenuation would be recorded and not
 *     enforced — the defect shape this repository keeps finding.
 * 10. **Revocation.** Every `jti` and every principal in the chain, in one
 *     batched lookup. Last because it is the only step that can touch a
 *     database, and there is no reason to pay for I/O on a chain that is
 *     already refused.
 *
 * ## What a verified chain does NOT prove
 *
 * That the delegation was AUTHORISED. Not that the agent behaved, stayed on
 * task, or was not itself manipulated into asking for what it asked for. The
 * chain is an authorisation record; behavioural assurance is guardrails' job
 * and is a different control.
 */
import {
  DELEGATION_CLOCK_SKEW_SECONDS,
  DELEGATION_LINK_SEPARATOR,
  type DelegationClaims,
  MAX_DELEGATION_DEPTH,
  MAX_DELEGATION_HEADER_BYTES,
  MAX_DELEGATION_LIFETIME_SECONDS,
  delegationPath,
  parseDelegationClaims,
  splitDelegationLink,
} from "./link.js";
import { decodeBase64UrlJson } from "../oidc/base64url.js";
import type { DelegationRevocationSource } from "./revocation.js";
import { NO_DELEGATION_REVOCATIONS } from "./revocation.js";
import { delegationScopeSubset, verifyDelegationSignature } from "./sign.js";

/**
 * Every way a chain can be refused.
 *
 * These strings ARE the gateway's error `code`s — one vocabulary, so an
 * operator reading a 403 body and an operator reading this file are looking at
 * the same word. The mapping to HTTP status lives in the gateway middleware,
 * because status is a transport concern and this package has no transport.
 */
export type DelegationFailureCode =
  | "delegation_malformed"
  | "delegation_too_deep"
  | "delegation_signature_invalid"
  | "delegation_tenant_mismatch"
  | "delegation_chain_broken"
  | "delegation_expired"
  | "delegation_not_yet_valid"
  | "delegation_lifetime_excessive"
  | "delegation_outlives_delegator"
  | "delegation_scope_widened"
  | "delegation_scope_exceeds_credential"
  | "delegation_scope_denied"
  | "delegation_subject_mismatch"
  | "delegation_revoked"
  | "delegation_revocation_unavailable";

/** What the gateway learned, and what the audit trail records. */
export interface VerifiedDelegationChain {
  readonly links: readonly DelegationClaims[];
  /** The principal ultimately responsible: the ROOT link's delegator. */
  readonly rootPrincipal: string;
  /** The principal that made this call: the LEAF link's delegate. */
  readonly leafPrincipal: string;
  /** `user:u_1>agent:planner>agent:writer` — the whole chain, in one column. */
  readonly path: string;
  readonly depth: number;
  /** The attenuated authority the request actually ran under. */
  readonly effectiveScopes: readonly string[];
  /** The earliest `exp` in the chain: a chain is only as fresh as its shortest link. */
  readonly expiresAtUnix: number;
  /** The agent run the LEAF link names, when it names one. */
  readonly agentRunId?: string | undefined;
}

export type DelegationVerification =
  | { readonly ok: true; readonly chain: VerifiedDelegationChain }
  | { readonly ok: false; readonly code: DelegationFailureCode; readonly detail: string };

export interface DelegationVerificationInput {
  /** The raw `x-ferrogate-delegation` value. */
  readonly header: string;
  /** The AUTHENTICATED tenant. Never a client-declared one. */
  readonly tenantId: string;
  /** The api-key id that authenticated this request (`AuthContext.subject`). */
  readonly presenterKeyId: string;
  /** The scopes that credential holds — the ceiling the chain may not exceed. */
  readonly presenterScopes: readonly string[];
  /**
   * The scope the matched operation requires, when the caller knows it.
   *
   * `undefined` means "this call site cannot name one" and SKIPS step 9 — which
   * is only correct for a surface that has no contract scope at all. Every
   * gateway operation has one, and the middleware passes it.
   */
  readonly requiredScope?: string | undefined;
  readonly nowUnix: number;
  readonly revocations?: DelegationRevocationSource | undefined;
}

function refuse(code: DelegationFailureCode, detail: string): DelegationVerification {
  return { ok: false, code, detail };
}

/**
 * Verify a presented chain. Total: every failure is a returned refusal, so a
 * caller cannot mistake a thrown exception for a verified chain.
 */
export async function verifyDelegationChain(
  key: CryptoKey,
  input: DelegationVerificationInput,
): Promise<DelegationVerification> {
  // --- 1. size, then depth, before any decoding ---------------------------
  if (input.header.length > MAX_DELEGATION_HEADER_BYTES) {
    return refuse(
      "delegation_malformed",
      `delegation header is ${input.header.length} bytes; the limit is ${MAX_DELEGATION_HEADER_BYTES}`,
    );
  }
  const tokens = input.header.split(DELEGATION_LINK_SEPARATOR);
  if (tokens.length > MAX_DELEGATION_DEPTH) {
    return refuse(
      "delegation_too_deep",
      `delegation chain has ${tokens.length} links; the limit is ${MAX_DELEGATION_DEPTH}`,
    );
  }
  if (tokens.length === 0 || tokens.some((token) => token === "")) {
    return refuse("delegation_malformed", "delegation chain contains an empty link");
  }

  const links: DelegationClaims[] = [];
  for (const [index, token] of tokens.entries()) {
    const split = splitDelegationLink(token);
    if (split === null) {
      return refuse(
        "delegation_malformed",
        `link ${index} is not a compact delegation token with the expected alg/typ header`,
      );
    }

    // --- 2. signature BEFORE any claim is believed -----------------------
    const verified = await verifyDelegationSignature(
      key,
      split.headerSegment,
      split.payloadSegment,
      split.signature,
    );
    if (!verified) {
      return refuse("delegation_signature_invalid", `link ${index} has an invalid signature`);
    }

    const decoded = decodeBase64UrlJson(split.payloadSegment);
    const parsed = parseDelegationClaims(decoded);
    if (!parsed.ok) {
      return refuse("delegation_malformed", `link ${index} has an invalid ${parsed.field} claim`);
    }
    links.push(parsed.claims);
  }

  const root = links[0] as DelegationClaims;
  const leaf = links[links.length - 1] as DelegationClaims;

  for (const [index, link] of links.entries()) {
    // --- 3. tenant ---------------------------------------------------------
    if (link.tenant !== input.tenantId) {
      return refuse(
        "delegation_tenant_mismatch",
        `link ${index} was issued for tenant ${link.tenant}, presented by tenant ${input.tenantId}`,
      );
    }

    // --- 5a. per-link freshness -------------------------------------------
    if (link.exp + DELEGATION_CLOCK_SKEW_SECONDS < input.nowUnix) {
      return refuse("delegation_expired", `link ${index} expired at ${link.exp}`);
    }
    if (link.iat - DELEGATION_CLOCK_SKEW_SECONDS > input.nowUnix) {
      return refuse("delegation_not_yet_valid", `link ${index} is issued at ${link.iat}, in the future`);
    }
    if (link.exp - link.iat > MAX_DELEGATION_LIFETIME_SECONDS) {
      return refuse(
        "delegation_lifetime_excessive",
        `link ${index} has a ${link.exp - link.iat}s lifetime; the cap is ${MAX_DELEGATION_LIFETIME_SECONDS}s`,
      );
    }

    if (index === 0) {
      // The root, and only the root, has no delegator inside the chain.
      if (link.prev !== undefined) {
        return refuse(
          "delegation_chain_broken",
          "the root link names a parent, so the chain presented is not rooted",
        );
      }
      continue;
    }

    const parent = links[index - 1] as DelegationClaims;

    // --- 4. linkage --------------------------------------------------------
    if (link.prev !== parent.jti) {
      return refuse(
        "delegation_chain_broken",
        `link ${index} names parent ${String(link.prev)}, but the link before it is ${parent.jti}`,
      );
    }
    if (link.act !== parent.sub) {
      return refuse(
        "delegation_chain_broken",
        `link ${index} is granted by ${link.act}, who is not the delegate of link ${index - 1} (${parent.sub})`,
      );
    }

    // --- 5b. a child may not outlive its parent ---------------------------
    if (link.exp > parent.exp) {
      return refuse(
        "delegation_outlives_delegator",
        `link ${index} expires at ${link.exp}, after its delegator's ${parent.exp}`,
      );
    }

    // --- 6. ATTENUATION: narrow only, never widen -------------------------
    if (!delegationScopeSubset(link.scope, parent.scope)) {
      return refuse(
        "delegation_scope_widened",
        `link ${index} claims ${JSON.stringify(link.scope)}, which its delegator ` +
          `${parent.sub} does not hold (${JSON.stringify(parent.scope)})`,
      );
    }
  }

  // --- 7. presenter binding ------------------------------------------------
  if (leaf.sub_key !== input.presenterKeyId) {
    return refuse(
      "delegation_subject_mismatch",
      `the chain was issued to credential ${leaf.sub_key}, but was presented by ${input.presenterKeyId}`,
    );
  }

  // --- 8. the credential is the ceiling ------------------------------------
  if (!delegationScopeSubset(leaf.scope, input.presenterScopes)) {
    return refuse(
      "delegation_scope_exceeds_credential",
      `the chain claims ${JSON.stringify(leaf.scope)}, which the presenting credential does not hold`,
    );
  }

  // --- 9. attenuation is ENFORCED, not merely recorded ---------------------
  if (input.requiredScope !== undefined && !delegationScopeSubset([input.requiredScope], leaf.scope)) {
    return refuse(
      "delegation_scope_denied",
      `this delegation grants ${JSON.stringify(leaf.scope)}, which does not include the ` +
        `${input.requiredScope} this operation requires`,
    );
  }

  // --- 10. revocation ------------------------------------------------------
  const source = input.revocations ?? NO_DELEGATION_REVOCATIONS;
  // Every jti AND every principal that appears anywhere in the chain: revoking
  // a middle link, or an agent, must break the whole chain rather than just the
  // hop it names.
  const subjects = new Set<string>();
  for (const link of links) {
    subjects.add(link.jti);
    subjects.add(link.act);
    subjects.add(link.sub);
  }
  const revocation = await source.revoked(input.tenantId, [...subjects]);
  if (!revocation.ok) {
    return refuse(
      "delegation_revocation_unavailable",
      `delegation revocation state could not be read: ${revocation.detail}`,
    );
  }
  const revoked = revocation.revoked[0];
  if (revoked !== undefined) {
    return refuse("delegation_revoked", `${revoked} has been revoked`);
  }

  return {
    ok: true,
    chain: {
      links,
      rootPrincipal: root.act,
      leafPrincipal: leaf.sub,
      path: delegationPath(links),
      depth: links.length,
      effectiveScopes: leaf.scope,
      // The chain is only as fresh as its shortest link. Taking the leaf's
      // `exp` would be wrong even though step 5b bounds children by their
      // parents, because that rule is enforced link-to-link and this value is
      // read by callers who have not done the walk.
      expiresAtUnix: Math.min(...links.map((link) => link.exp)),
      ...(leaf.run === undefined ? {} : { agentRunId: leaf.run }),
    },
  };
}
