/**
 * The delegation chain's rules, unit-level (#691).
 *
 * `apps/gateway/test/delegation/chain.test.ts` drives the deployed middleware
 * chain and is the gate that the verifier is MOUNTED and wired. This file is
 * the gate that each rule is what it claims to be, at a granularity the HTTP
 * surface cannot reach: the format's allow-list, the mint's own refusals, and —
 * the one that matters most — the revocation memo, whose failure mode is a
 * cache that answers "not revoked" for a subject that is.
 *
 * ## MUTATION LOG — what was broken, and what went red
 *
 * This tree's dominant defect mode is correct code with a green test that does
 * not hold it, so every claim below was falsified against the implementation
 * before it was believed. Every mutation was reverted; `grep MUTATION-691`
 * outside this comment is empty.
 *
 * `[gw]` = `apps/gateway/test/delegation/chain.test.ts`; unmarked cases are in
 * this file.
 *
 * | # | mutation | red |
 * |---|----------|-----|
 * | M1 | `sign.ts`: `delegationScopeSubset` returns `true` unconditionally | 4 here + `refuses a link that claims more than its delegator held`, `refuses a chain that grants more than the presenting credential holds`, `ENFORCES the attenuated scope` `[gw]` |
 * | M2 | `verify.ts`: drop the `link.act !== parent.sub` check | `refuses a link re-parented under a delegator that never granted it` |
 * | M3 | `verify.ts`: drop the `leaf.sub_key !== presenterKeyId` check | `refuses a chain replayed by a credential it was not issued to` `[gw]` |
 * | M4 | `verify.ts`: ask the revocation source about the LEAF jti only | `breaks a chain through a revoked MIDDLE link`, `breaks every chain a revoked PRINCIPAL appears in` `[gw]` |
 * | M5 | `verify.ts`: verify the signature on the LEAF link only | `refuses a chain whose ROOT link was re-signed by someone else` |
 * | M6 | `verify.ts`: admit when the revocation lookup fails | `refuses when the revocation list cannot be read` |
 * | M7 | `link.ts`: take `alg`/`typ` from the token instead of the allow-list | `refuses a link whose header claims alg none`, `… a different typ` |
 * | M8 | `link.ts`: accept an EMPTY `scope` array | `refuses a link that grants no scope at all` |
 * | M9 | `revocation.ts`: memoize only the first revoked subject of a batch | `caches every subject it asked about, not just the first hit` |
 * | M10 | `revocation.ts`: key the memo on the subject alone | `never answers tenant B from tenant A's entry` |
 * | M11 | `revocation.ts`: cache an outage as a clean answer | `does not cache an outage — not as a refusal, and not as a clean answer` |
 * | M12 | `apps/gateway/src/index.ts`: unmount `delegationChain()` | 14 of the 17 `[gw]` cases |
 * | M13 | `middleware/auth.ts`: stop publishing `requiredScope` | `ENFORCES the attenuated scope` `[gw]` |
 * | M14 | `verify.ts`: drop the tenant-claim check | `refuses a chain minted for another tenant` `[gw]` |
 * | M15 | `delegation/middleware.ts`: ignore the header when unconfigured | `refuses a delegated request when no signing key is bound` `[gw]` |
 *
 * ## Three mutations SURVIVED on the first pass, and each bought a test
 *
 * Recorded because the surviving mutation is the informative one — it names a
 * rule the suite believed and did not hold:
 *
 *  - **M2 survived.** The only linkage case at the time used a `prev` that
 *    named nothing, so the `prev` check refused it before the `act` check was
 *    ever reached and the second half of the rule was unproven. Closed by
 *    `refuses a link re-parented under a delegator that never granted it`,
 *    whose `prev` is CORRECT.
 *  - **M5 survived.** Both forgery cases forged the WHOLE chain, so a
 *    leaf-only signature check still caught them — while the attack it enables
 *    is the interesting one: keep the honest leaf and re-sign only the root, so
 *    the audit row names a different principal as ultimately responsible.
 *    Closed by `refuses a chain whose ROOT link was re-signed by someone else`.
 *  - **M11 survived.** The outage test asserted only that recovery was
 *    immediate, which a cache poisoned with `{ revoked: false }` also satisfies.
 *    The dangerous half — a revoked subject admitted for a whole TTL after a
 *    blip — was invisible. The recovered read now reports the subject as
 *    REVOKED, so the poisoned cache answers `[]` and goes red.
 *
 * ## #773 — the verify-side sweep, and what it found
 *
 * The log above records mutations by the test that caught them. It does not
 * record WHERE that test lives, and that turned out to be the interesting
 * question: six of `verify.ts`'s refusals were held only by `apps/gateway`, in
 * a different workspace from the code they constrain. Running this package's
 * suite — 168 green at the time — proved nothing about any of them.
 *
 * Every guard in `verifyDelegationChain` was disarmed one at a time (`if (…)`
 * → `if (false)`) and BOTH suites were run. The `after` column is this file
 * following the cases added below; `[gw]` is
 * `apps/gateway/test/delegation/chain.test.ts`.
 *
 * | guard (verify.ts step) | before: identity | before: [gw] | after: identity |
 * |---|---|---|---|
 * | 1 header size bound     | green¹ | green | RED |
 * | 1 depth bound           | RED    | RED   | RED |
 * | 1 empty link            | green² | green | green² |
 * | 2 per-link signature    | RED    | RED   | RED |
 * | 3 tenant claim          | green  | RED   | RED |
 * | 5a expired              | green  | RED   | RED |
 * | 5a issued-in-future     | green  | green | RED |
 * | 5a lifetime cap         | RED    | green | RED |
 * | 4 headless root         | RED    | green | RED |
 * | 4 prev linkage (splice) | RED    | RED   | RED |
 * | 4 act linkage (reparent)| RED    | green | RED |
 * | 5b outlives delegator   | RED    | green | RED |
 * | **6 ATTENUATION**       | green  | RED   | RED |
 * | 7 presenter binding     | green  | RED   | RED |
 * | 8 credential ceiling    | green  | RED   | RED |
 * | 9 required scope        | RED    | RED   | RED |
 * | 10 revocation outage    | RED    | green | RED |
 * | 10 revoked subject      | green  | RED   | RED |
 *
 * ¹ The size-bound case presented a string that was not a token at all, so the
 *   TOKENISER refused it with the same `delegation_malformed` code and the
 *   assertion held with the bound disarmed. Rewritten to present an oversized
 *   chain that would otherwise VERIFY.
 *
 * ² The only mutation still surviving, and it is not a coverage hole: with the
 *   empty-link guard removed, `splitDelegationLink("")` refuses the same input
 *   with the same code one step later. It is an early exit, not a rule, and no
 *   behavioural case can separate the two. Recorded rather than papered over.
 *
 * The gateway cases all stay. The two layers answer different questions — "is
 * the rule right" here, "is the verifier mounted and wired" there — and for a
 * security property that is defence in depth, not duplication.
 */
import { describe, expect, it } from "vitest";

import {
  DELEGATION_CLOCK_SKEW_SECONDS,
  DELEGATION_FORMAT_VERSION,
  DELEGATION_JWS_HEADER,
  type DelegationClaims,
  type DelegationRevocationResolution,
  type DelegationRevocationSource,
  MAX_DELEGATION_DEPTH,
  MAX_DELEGATION_HEADER_BYTES,
  MAX_DELEGATION_LIFETIME_SECONDS,
  MIN_DELEGATION_KEY_BYTES,
  bytesToBase64Url,
  cachedDelegationRevocationSource,
  delegationScopeSubset,
  encodeDelegationChain,
  encodeSegment,
  importDelegationKey,
  mintDelegationLink,
  parseDelegationPrincipal,
  signingInput,
  verifyDelegationChain,
} from "../src/index.js";

const SECRET = "delegation-unit-secret-0123456789abcdef";
const OTHER_SECRET = "another-unit-secret-0123456789abcdefgh";
const TENANT = "tenant_a";
const NOW = 1_800_000_000;

async function key(secret = SECRET): Promise<CryptoKey> {
  const resolved = await importDelegationKey(secret);
  if (!resolved.ok) throw new Error(resolved.detail);
  return resolved.key;
}

/** Sign arbitrary claims — the compromised/buggy mint. */
async function forge(
  claims: Record<string, unknown>,
  options: { readonly secret?: string; readonly header?: unknown } = {},
): Promise<string> {
  const signer = await key(options.secret ?? SECRET);
  const headerSegment = encodeSegment(options.header ?? DELEGATION_JWS_HEADER);
  const payloadSegment = encodeSegment({
    v: DELEGATION_FORMAT_VERSION,
    iss: "unit",
    tenant: TENANT,
    ...claims,
  });
  const signature = await crypto.subtle.sign(
    "HMAC",
    signer,
    signingInput(headerSegment, payloadSegment) as unknown as ArrayBuffer,
  );
  return `${headerSegment}.${payloadSegment}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

const ROOT_CLAIMS = {
  jti: "dl_1",
  act: "user:u_1",
  sub: "agent:planner",
  sub_key: "key_planner",
  scope: ["chat.completions"],
  iat: NOW,
  exp: NOW + 600,
};

/** Verify one chain against the default presenter. */
async function verify(
  header: string,
  overrides: {
    readonly presenterKeyId?: string;
    readonly presenterScopes?: readonly string[];
    readonly requiredScope?: string;
    readonly tenantId?: string;
    readonly nowUnix?: number;
    readonly revocations?: DelegationRevocationSource;
  } = {},
): Promise<Awaited<ReturnType<typeof verifyDelegationChain>>> {
  return verifyDelegationChain(await key(), {
    header,
    tenantId: overrides.tenantId ?? TENANT,
    presenterKeyId: overrides.presenterKeyId ?? "key_planner",
    presenterScopes: overrides.presenterScopes ?? ["chat.completions", "tools.read"],
    ...(overrides.requiredScope === undefined ? {} : { requiredScope: overrides.requiredScope }),
    nowUnix: overrides.nowUnix ?? NOW,
    ...(overrides.revocations === undefined ? {} : { revocations: overrides.revocations }),
  });
}

function codeOf(result: Awaited<ReturnType<typeof verifyDelegationChain>>): string {
  return result.ok ? "ok" : result.code;
}

// ---------------------------------------------------------------------------
// The principal grammar
// ---------------------------------------------------------------------------

describe("principals are namespaced, and the namespace is a fence", () => {
  it("splits on the FIRST colon only, so a colon-bearing id cannot become a kind", () => {
    // The same rule `admission/keys.ts` enforces on counter keys: a tenant that
    // could name an agent `user:ceo` would be able to render a chain whose path
    // reads as a human's authority.
    expect(parseDelegationPrincipal("agent:user:ceo")).toEqual({ kind: "agent", id: "user:ceo" });
  });

  it("refuses an unknown kind, a blank id, and an id carrying the path separator", () => {
    expect(parseDelegationPrincipal("root:everything")).toBeNull();
    expect(parseDelegationPrincipal("user:")).toBeNull();
    expect(parseDelegationPrincipal("nocolon")).toBeNull();
    // `>` is the rendered-path separator; an id containing one would make the
    // stored `delegation_chain` unreadable back into links.
    expect(parseDelegationPrincipal("user:a>b")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Attenuation, as a predicate
// ---------------------------------------------------------------------------

describe("delegationScopeSubset", () => {
  it("lets a wildcard DELEGATOR grant anything", () => {
    expect(delegationScopeSubset(["chat.completions"], ["*"])).toBe(true);
  });

  it("does NOT let a link promote itself to the wildcard", () => {
    // The single most valuable widening an attacker could attempt.
    expect(delegationScopeSubset(["*"], ["chat.completions"])).toBe(false);
  });

  it("does not treat a scope prefix as an implication", () => {
    // `hasScope` does not imply it either, and a subset rule more generous than
    // the credential check it guards would let a chain reach an operation the
    // credential itself could not.
    expect(delegationScopeSubset(["admin.read.keys"], ["admin.read"])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The mint's own refusals
// ---------------------------------------------------------------------------

describe("mintDelegationLink refuses what it must not issue", () => {
  async function root(): Promise<DelegationClaims> {
    const minted = await mintDelegationLink(await key(), {
      jti: "dl_1",
      iss: "unit",
      tenant: TENANT,
      act: "user:u_1",
      sub: "agent:planner",
      subKey: "key_planner",
      scope: ["chat.completions"],
      issuedAtUnix: NOW,
      lifetimeSeconds: 600,
    });
    if (!minted.ok) throw new Error(minted.detail);
    return minted.claims;
  }

  async function child(
    overrides: Partial<Parameters<typeof mintDelegationLink>[1]>,
  ): Promise<ReturnType<typeof mintDelegationLink>> {
    return mintDelegationLink(await key(), {
      jti: "dl_2",
      iss: "unit",
      tenant: TENANT,
      act: "agent:planner",
      sub: "agent:writer",
      subKey: "key_writer",
      scope: ["chat.completions"],
      issuedAtUnix: NOW,
      lifetimeSeconds: 300,
      parent: await root(),
      ...overrides,
    });
  }

  it("refuses to widen", async () => {
    const result = await child({ scope: ["chat.completions", "admin.write"] });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toBe("scope_widened");
  });

  it("refuses a delegator that is not the parent's delegate", async () => {
    const result = await child({ act: "agent:someone_else" });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toBe("delegator_mismatch");
  });

  it("refuses a child that would outlive its delegator", async () => {
    const result = await child({ lifetimeSeconds: 900 });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toBe("outlives_delegator");
  });

  it("refuses a lifetime past the cap", async () => {
    const result = await child({
      parent: undefined,
      lifetimeSeconds: MAX_DELEGATION_LIFETIME_SECONDS + 1,
    });
    expect(result.ok).toBe(false);
    expect(result.ok ? "" : result.reason).toBe("lifetime_excessive");
  });

  it("refuses a key too short to be safe", async () => {
    const resolved = await importDelegationKey("x".repeat(MIN_DELEGATION_KEY_BYTES - 1));
    expect(resolved.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The format's allow-list
// ---------------------------------------------------------------------------

describe("the verifier chooses the algorithm, never the token", () => {
  it("refuses a link whose header claims alg none", async () => {
    // The classic forgery primitive. It is refused by STRUCTURE, before a key
    // is imported and before any claim is read.
    const token = await forge(ROOT_CLAIMS, {
      header: { alg: "none", typ: DELEGATION_JWS_HEADER.typ },
    });
    expect(codeOf(await verify(token))).toBe("delegation_malformed");
  });

  it("refuses a link whose header claims a different typ", async () => {
    // So a delegation link cannot be replayed anywhere an ID token is accepted,
    // and vice versa.
    const token = await forge(ROOT_CLAIMS, { header: { alg: "HS256", typ: "JWT" } });
    expect(codeOf(await verify(token))).toBe("delegation_malformed");
  });

  it("refuses a link signed with a different key", async () => {
    const token = await forge(ROOT_CLAIMS, { secret: OTHER_SECRET });
    expect(codeOf(await verify(token))).toBe("delegation_signature_invalid");
  });

  it("refuses a chain whose ROOT link was re-signed by someone else", async () => {
    // The audit forgery a leaf-only signature check would allow: keep the
    // honest leaf (its `prev` and `act` still line up), and replace ONLY the
    // root with a self-signed one naming a different principal as ultimately
    // responsible. Nothing about a link is believed before its own HMAC
    // verifies, so this is refused at link 0.
    const forgedRoot = await forge({ ...ROOT_CLAIMS, act: "user:ceo" }, { secret: OTHER_SECRET });
    const honestLeaf = await forge({
      jti: "dl_2",
      prev: "dl_1",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      exp: NOW + 600,
    });
    expect(codeOf(await verify(`${forgedRoot}~${honestLeaf}`))).toBe(
      "delegation_signature_invalid",
    );
  });

  it("refuses a version it does not know", async () => {
    // A newer version may have ADDED a constraint, and a lenient reader would
    // discard exactly the claim that made the link safe.
    const token = await forge({ ...ROOT_CLAIMS, v: DELEGATION_FORMAT_VERSION + 1 });
    expect(codeOf(await verify(token))).toBe("delegation_malformed");
  });

  it("refuses a link that grants no scope at all", async () => {
    // Neither "grants nothing" nor "grants everything": the format must not
    // contain the question, because `hasScope` already gives an empty
    // CREDENTIAL scope set a third meaning.
    const token = await forge({ ...ROOT_CLAIMS, scope: [] });
    expect(codeOf(await verify(token))).toBe("delegation_malformed");
  });
});

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

describe("bounds on work the caller controls", () => {
  it("refuses an oversized header even when every byte of it is a VALID link", async () => {
    // DELIBERATE STRENGTHENING (#773). This case used to present
    // `"a".repeat(MAX_DELEGATION_HEADER_BYTES + 1)` — a string that is not a
    // compact token at all, so `splitDelegationLink` refused it with the same
    // `delegation_malformed` code the size bound returns. The assertion held
    // with the size bound DISARMED, which made it a test of the tokeniser
    // wearing the size bound's name.
    //
    // The bound exists to cap work on bytes the caller controls, so the case
    // that exercises it is a chain that would otherwise VERIFY. Delegation
    // claims are an open set (unknown members are ignored, not refused), so a
    // padding claim inflates a perfectly good root link past the limit without
    // changing anything else about it.
    const oversized = await forge({ ...ROOT_CLAIMS, pad: "x".repeat(9_000) });
    expect(oversized.length).toBeGreaterThan(MAX_DELEGATION_HEADER_BYTES);
    expect(codeOf(await verify(oversized))).toBe("delegation_malformed");

    // …and the same link under the limit is admitted, so the refusal above is
    // attributable to the size and to nothing else about the padded claim.
    const underLimit = await forge({ ...ROOT_CLAIMS, pad: "x".repeat(16) });
    expect(underLimit.length).toBeLessThan(MAX_DELEGATION_HEADER_BYTES);
    expect(codeOf(await verify(underLimit))).toBe("ok");
  });

  it("refuses one link past the depth bound", async () => {
    const tokens: string[] = [];
    for (let index = 0; index <= MAX_DELEGATION_DEPTH; index += 1) {
      tokens.push(
        await forge({
          jti: `dl_${index}`,
          ...(index === 0 ? {} : { prev: `dl_${index - 1}` }),
          act: index === 0 ? "user:u_1" : `agent:a${index - 1}`,
          sub: `agent:a${index}`,
          sub_key: "key_planner",
          scope: ["chat.completions"],
          iat: NOW,
          exp: NOW + 600,
        }),
      );
    }
    expect(tokens).toHaveLength(MAX_DELEGATION_DEPTH + 1);
    expect(codeOf(await verify(encodeDelegationChain(tokens)))).toBe("delegation_too_deep");
  });

  it("refuses a link whose own lifetime exceeds the cap, however it was signed", async () => {
    // The mint refuses to issue one; this is the verifier re-deriving the same
    // bound from the signed bytes, which is what still holds when the mint does
    // not.
    const token = await forge({
      ...ROOT_CLAIMS,
      exp: NOW + MAX_DELEGATION_LIFETIME_SECONDS + 60,
    });
    expect(codeOf(await verify(token))).toBe("delegation_lifetime_excessive");
  });

  it("refuses a child that outlives its parent", async () => {
    const root = await forge(ROOT_CLAIMS);
    const child = await forge({
      jti: "dl_2",
      prev: "dl_1",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      // One second past the parent's `exp`.
      exp: NOW + 601,
    });
    expect(codeOf(await verify(`${root}~${child}`))).toBe("delegation_outlives_delegator");
  });

  it("refuses a link whose prev does not name the link before it", async () => {
    // Splicing: a perfectly valid link lifted out of ANOTHER chain that happens
    // to share a principal.
    const root = await forge(ROOT_CLAIMS);
    const child = await forge({
      jti: "dl_2",
      prev: "dl_some_other_root",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      exp: NOW + 600,
    });
    expect(codeOf(await verify(`${root}~${child}`))).toBe("delegation_chain_broken");
  });

  it("refuses a link re-parented under a delegator that never granted it", async () => {
    // `prev` is CORRECT here, so this isolates the second half of the linkage
    // rule: the delegator of link i must be the DELEGATE of link i-1. Without
    // it, a link granted by `agent:someone_else` could be presented under a
    // root that never delegated to `someone_else`, and the rendered path would
    // still read `user:u_1>agent:planner>agent:writer`.
    const root = await forge(ROOT_CLAIMS);
    const child = await forge({
      jti: "dl_2",
      prev: "dl_1",
      act: "agent:someone_else",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      exp: NOW + 600,
    });
    expect(codeOf(await verify(`${root}~${child}`))).toBe("delegation_chain_broken");
  });

  it("refuses a ROOT link that names a parent, so a chain cannot be presented headless", async () => {
    // Dropping the true root and presenting from link 2 onwards would erase the
    // principal ultimately responsible while leaving a chain that verifies.
    const orphan = await forge({ ...ROOT_CLAIMS, prev: "dl_0" });
    expect(codeOf(await verify(orphan))).toBe("delegation_chain_broken");
  });

  it("reports the chain's expiry as the EARLIEST link's, not the leaf's", async () => {
    const root = await forge({ ...ROOT_CLAIMS, exp: NOW + 300 });
    const child = await forge({
      jti: "dl_2",
      prev: "dl_1",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      exp: NOW + 300,
    });
    const result = await verify(`${root}~${child}`);
    expect(result.ok && result.chain.expiresAtUnix).toBe(NOW + 300);
  });
});

// ---------------------------------------------------------------------------
// The verify side of every rule the mint also enforces (#773)
// ---------------------------------------------------------------------------

/**
 * The two attenuation guards defend different things, and only one of them is
 * load-bearing against an adversary.
 *
 * `mintDelegationLink` refuses to ISSUE a link that grants more than its
 * parent (`scope_widened`, covered above). That stops US producing a bad link.
 * It stops nobody presenting one: an attacker does not use our minter, they
 * hand us bytes they signed — or captured, or spliced — and the only thing
 * between those bytes and an over-scoped request is `verifyDelegationChain`.
 *
 * The same asymmetry holds for the tenant claim, freshness, presenter binding,
 * the credential ceiling and revocation: the mint's version of each rule is a
 * courtesy to honest callers, and the verifier's version is the control. Every
 * case below therefore drives `verifyDelegationChain` over a FORGED chain —
 * one this package's own minter would have refused to produce — because that
 * is the only shape the attacker can actually present.
 *
 * Each case is written to isolate ONE guard: the chain is otherwise entirely
 * valid, so disarming that guard alone does not merely change the failure code,
 * it makes the chain VERIFY. See the mutation log at the top of this file.
 */
describe("the verifier refuses a forged chain the mint would never have issued", () => {
  /** A root the fixtures below hang a child off. Scope: `chat.completions`. */
  async function root(overrides: Record<string, unknown> = {}): Promise<string> {
    return forge({ ...ROOT_CLAIMS, ...overrides });
  }

  /** A well-formed child of `root()` — every claim correct unless overridden. */
  async function child(overrides: Record<string, unknown> = {}): Promise<string> {
    return forge({
      jti: "dl_2",
      prev: "dl_1",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      exp: NOW + 600,
      ...overrides,
    });
  }

  it("refuses a link that claims MORE than its delegator held", async () => {
    // THE case #773 was filed for. `tools.read` is deliberately a scope the
    // PRESENTING CREDENTIAL does hold, so the credential ceiling (step 8) does
    // not refuse this chain on the verifier's behalf: with the subset check at
    // step 6 disarmed, this chain verifies and the request runs under an
    // authority `user:u_1` never delegated.
    const widened = `${await root()}~${await child({ scope: ["chat.completions", "tools.read"] })}`;
    expect(codeOf(await verify(widened))).toBe("delegation_scope_widened");

    // The refusal is a REFUSAL, not a silent narrowing to the delegator's set.
    // Narrowing would serve the request and write an audit row describing a
    // delegation that was never authorised.
    const result = await verify(widened);
    expect(result.ok).toBe(false);
  });

  it("refuses a link that promotes itself to the wildcard", async () => {
    // The single most valuable widening: `*` reads as "everything" everywhere
    // else in the tree, and a delegator holding one concrete scope must not be
    // able to have a child claim it.
    const chain = `${await root()}~${await child({ scope: ["*"] })}`;
    expect(codeOf(await verify(chain, { presenterScopes: ["*"] }))).toBe(
      "delegation_scope_widened",
    );
  });

  it("refuses a chain minted for another tenant, however valid its signature", async () => {
    // The mint key is fleet-wide, so the signature on tenant B's link verifies
    // perfectly inside tenant A. The tenant CLAIM is the only thing that stops
    // a genuine link from one tenant authorising a request in another.
    const foreign = await root({ tenant: "tenant_b" });
    expect(codeOf(await verify(foreign, { tenantId: TENANT }))).toBe("delegation_tenant_mismatch");
  });

  it("refuses an expired link once the skew allowance is spent", async () => {
    const token = await root();
    // Inside the allowance the chain still verifies — this is what makes the
    // refusal below attributable to expiry rather than to the allowance being
    // absent, and it pins the skew window as a bounded thing rather than an
    // open-ended one.
    expect(
      codeOf(await verify(token, { nowUnix: NOW + 600 + DELEGATION_CLOCK_SKEW_SECONDS })),
    ).toBe("ok");
    expect(
      codeOf(await verify(token, { nowUnix: NOW + 600 + DELEGATION_CLOCK_SKEW_SECONDS + 1 })),
    ).toBe("delegation_expired");
  });

  it("refuses a link issued in the future", async () => {
    // A post-dated link is a stockpiling primitive: mint (or forge) now, hold
    // it, present it after the delegation it attenuates has been withdrawn.
    // Its own lifetime is well inside the cap, so only the `iat` check refuses
    // it.
    const postdated = await root({ iat: NOW + 3_600, exp: NOW + 3_900 });
    expect(codeOf(await verify(postdated))).toBe("delegation_not_yet_valid");
  });

  it("refuses a chain replayed by a credential it was not issued to", async () => {
    // What makes a captured `x-ferrogate-delegation` header useless on its own:
    // replaying it also requires the leaf's api key. The replaying credential
    // here holds a SUPERSET of the chain's scopes, so nothing downstream would
    // have refused it.
    const chain = `${await root()}~${await child()}`;
    expect(
      codeOf(
        await verify(chain, {
          presenterKeyId: "key_attacker",
          presenterScopes: ["chat.completions", "tools.read"],
        }),
      ),
    ).toBe("delegation_subject_mismatch");
  });

  it("refuses a chain that grants more than the presenting credential holds", async () => {
    // The chain is internally consistent — no widening between its links — and
    // it is presented by the credential it names. It still must not be a
    // privilege-escalation channel that turns a read-only key into a writing
    // one, so the credential is a ceiling over the whole chain and not just a
    // starting point for it.
    const token = await root({ scope: ["admin.write"] });
    expect(codeOf(await verify(token, { presenterScopes: ["chat.completions"] }))).toBe(
      "delegation_scope_exceeds_credential",
    );
  });

  it("breaks a chain through a revoked MIDDLE link, not only the leaf", async () => {
    // Revoking a delegation must break every chain that passes THROUGH it, or
    // revocation would only ever reach the hop that was named and an agent
    // could keep sub-delegating out of a withdrawn grant.
    const chain = `${await root()}~${await child()}`;
    const source = stubRevocations(["dl_1"]);
    expect(codeOf(await verify(chain, { revocations: source }))).toBe("delegation_revoked");
  });

  it("breaks every chain a revoked PRINCIPAL appears in", async () => {
    // Revoking an agent, rather than one of its links, is the operator action
    // during an incident: it must not require enumerating the agent's links.
    const chain = `${await root()}~${await child()}`;
    const source = stubRevocations(["agent:planner"]);
    expect(codeOf(await verify(chain, { revocations: source }))).toBe("delegation_revoked");
  });

  it("refuses a chain padded with an empty link", async () => {
    // HONEST LABEL: this case does NOT discriminate `verify.ts`'s explicit
    // empty-link guard, and it is the one case in the #773 sweep for which no
    // case can. Deleting that guard leaves the behaviour identical, because
    // `splitDelegationLink("")` returns null and the very next step refuses the
    // same input with the same `delegation_malformed` code — the guard is a
    // (worthwhile) early exit, not an independent rule. The behaviour is still
    // worth pinning: a trailing separator must never be read as "one link,
    // plus nothing".
    expect(codeOf(await verify(`${await root()}~`))).toBe("delegation_malformed");
    expect(codeOf(await verify(`~${await root()}`))).toBe("delegation_malformed");
  });
});

// ---------------------------------------------------------------------------
// The happy path, and what it reports
// ---------------------------------------------------------------------------

describe("a verified chain reports the whole path", () => {
  it("names the root delegator, the leaf delegate and the run", async () => {
    const root = await forge(ROOT_CLAIMS);
    const child = await forge({
      jti: "dl_2",
      prev: "dl_1",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: NOW,
      exp: NOW + 600,
      run: "run_7",
    });

    const result = await verify(`${root}~${child}`, { requiredScope: "chat.completions" });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.chain.path).toBe("user:u_1>agent:planner>agent:writer");
    expect(result.chain.rootPrincipal).toBe("user:u_1");
    expect(result.chain.leafPrincipal).toBe("agent:writer");
    expect(result.chain.depth).toBe(2);
    expect(result.chain.effectiveScopes).toEqual(["chat.completions"]);
    expect(result.chain.agentRunId).toBe("run_7");
  });

  it("refuses the request when the required scope is outside the attenuated set", async () => {
    const token = await forge({ ...ROOT_CLAIMS, scope: ["tools.read"] });
    expect(codeOf(await verify(token, { requiredScope: "chat.completions" }))).toBe(
      "delegation_scope_denied",
    );
  });
});

// ---------------------------------------------------------------------------
// Revocation, and the memo in front of it
// ---------------------------------------------------------------------------

/** A source that answers from a set and counts the calls it was asked to make. */
function stubRevocations(revoked: readonly string[]): DelegationRevocationSource & {
  readonly calls: string[][];
} {
  const calls: string[][] = [];
  return {
    calls,
    async revoked(
      _tenant: string,
      subjects: readonly string[],
    ): Promise<DelegationRevocationResolution> {
      calls.push([...subjects]);
      return { ok: true, revoked: subjects.filter((subject) => revoked.includes(subject)) };
    },
  };
}

describe("revocation breaks every chain through the revoked subject", () => {
  it("asks about every jti and every principal in the chain", async () => {
    const source = stubRevocations([]);
    const root = await forge(ROOT_CLAIMS);
    await verify(root, { revocations: source });
    // One batched call, and it names the link, its delegator and its delegate.
    expect(source.calls).toHaveLength(1);
    expect(new Set(source.calls[0])).toEqual(new Set(["dl_1", "user:u_1", "agent:planner"]));
  });

  it("refuses when the revocation list cannot be read", async () => {
    // Fail CLOSED: admitting on unknown state would make "flap the control
    // plane" a revocation bypass.
    const source: DelegationRevocationSource = {
      async revoked(): Promise<DelegationRevocationResolution> {
        return { ok: false, detail: "D1_ERROR" };
      },
    };
    expect(codeOf(await verify(await forge(ROOT_CLAIMS), { revocations: source }))).toBe(
      "delegation_revocation_unavailable",
    );
  });
});

describe("cachedDelegationRevocationSource", () => {
  function clock(): { now: () => number; advance: (ms: number) => void } {
    let value = 0;
    return {
      now: (): number => value,
      advance: (ms: number): void => {
        value += ms;
      },
    };
  }

  it("caches every subject it asked about, not just the first hit", async () => {
    // The bug this pins: a source that reported only the FIRST revoked subject
    // would have the memo record every OTHER revoked subject in the batch as
    // clean — revoking two links would make one of them work again for a TTL.
    const inner = stubRevocations(["a", "b"]);
    const cached = cachedDelegationRevocationSource(inner, { ttlMs: 1_000, now: clock().now });

    expect(await cached.revoked("t", ["a", "b", "c"])).toEqual({ ok: true, revoked: ["a", "b"] });
    // Second pass is served entirely from the memo, and must still say `b`.
    expect(await cached.revoked("t", ["b"])).toEqual({ ok: true, revoked: ["b"] });
    expect(inner.calls).toHaveLength(1);
  });

  it("never answers tenant B from tenant A's entry", async () => {
    // On Workers two tenants sharing a warm isolate is the normal case, so a
    // memo keyed on the subject alone is a cross-tenant control leak in both
    // directions: A's "revoked" refusing B, and A's "clean" admitting B.
    const inner: DelegationRevocationSource = {
      async revoked(tenant, subjects): Promise<DelegationRevocationResolution> {
        return { ok: true, revoked: tenant === "t_b" ? [...subjects] : [] };
      },
    };
    const cached = cachedDelegationRevocationSource(inner, { ttlMs: 1_000, now: clock().now });

    expect(await cached.revoked("t_a", ["dl_1"])).toEqual({ ok: true, revoked: [] });
    expect(await cached.revoked("t_b", ["dl_1"])).toEqual({ ok: true, revoked: ["dl_1"] });
  });

  it("re-reads once the entry expires, so revocation is not renewal-time", async () => {
    const time = clock();
    let revoked: string[] = [];
    const inner: DelegationRevocationSource = {
      async revoked(_tenant, subjects): Promise<DelegationRevocationResolution> {
        return { ok: true, revoked: subjects.filter((subject) => revoked.includes(subject)) };
      },
    };
    const cached = cachedDelegationRevocationSource(inner, { ttlMs: 5_000, now: time.now });

    expect(await cached.revoked("t", ["dl_1"])).toEqual({ ok: true, revoked: [] });
    revoked = ["dl_1"];
    // Still cached — this is the propagation window, and it is bounded.
    expect(await cached.revoked("t", ["dl_1"])).toEqual({ ok: true, revoked: [] });
    time.advance(5_001);
    expect(await cached.revoked("t", ["dl_1"])).toEqual({ ok: true, revoked: ["dl_1"] });
  });

  it("does not cache an outage — not as a refusal, and not as a clean answer", async () => {
    // Two failures live here, and the second is the dangerous one.
    //
    // Caching `{ ok: false }` would extend a one-request blip into a TTL-long
    // refusal window. Caching the ATTEMPT as "clean" is worse: a revoked
    // subject would be admitted for a whole TTL after a blip, which is exactly
    // the revocation hole the memo exists next to. So the recovered read below
    // reports the subject as REVOKED — an implementation that had written
    // `{ revoked: false }` entries during the outage answers `[]` here and goes
    // red.
    const time = clock();
    let failing = true;
    const inner: DelegationRevocationSource = {
      async revoked(): Promise<DelegationRevocationResolution> {
        return failing ? { ok: false, detail: "down" } : { ok: true, revoked: ["dl_1"] };
      },
    };
    const cached = cachedDelegationRevocationSource(inner, { ttlMs: 60_000, now: time.now });

    expect(await cached.revoked("t", ["dl_1"])).toEqual({ ok: false, detail: "down" });
    failing = false;
    expect(await cached.revoked("t", ["dl_1"])).toEqual({ ok: true, revoked: ["dl_1"] });
  });
});
