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
 */
import { describe, expect, it } from "vitest";

import {
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
    const token = await forge(ROOT_CLAIMS, { header: { alg: "none", typ: DELEGATION_JWS_HEADER.typ } });
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
  it("refuses an oversized header before it parses anything", async () => {
    const header = "a".repeat(MAX_DELEGATION_HEADER_BYTES + 1);
    expect(codeOf(await verify(header))).toBe("delegation_malformed");
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
    async revoked(_tenant: string, subjects: readonly string[]): Promise<DelegationRevocationResolution> {
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
