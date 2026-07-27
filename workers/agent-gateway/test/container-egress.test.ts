// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway. Worker-side enforcement suite for
//   the #471 governed container egress. Boots the real agent-gateway Worker AND a real
//   `AgentSandbox` Durable Object in workerd (@cloudflare/vitest-pool-workers) — no
//   Docker, no Cloudflare account.
//
//   WHAT WENT WRONG BEFORE, AND WHAT THIS SUITE DOES DIFFERENTLY. The first #471 test
//   pass asserted the side that SENDS the configuration: the Rust client proved it asked
//   for a sealed container, and nothing proved Cloudflare was ever told. Seven of seven
//   mutations to the Worker half survived, including flipping
//   `AgentSandbox { enableInternet = false }` to `true` — the line whose own comment says
//   that converts the tier from enforced to cooperative.
//
//   So every test here observes the APPLIED posture:
//     * `enableInternet` is read off a REAL Durable Object instance of the production
//       class, not off a request body;
//     * the allow/deny lists are read back through the SDK's own
//       `effectiveAllowedHosts` / `effectiveDeniedHosts` after the route ran;
//     * the verdicts come from `ContainerProxy` — CLOUDFLARE'S OWN egress decision
//       function, reached through the interceptor the SDK actually registered on the
//       container — so "denied" means Cloudflare refused the request with its documented
//       520, and anything else means the request left for the internet;
//     * the attestation the Worker returns is compared against that applied state, so a
//       Worker that lies about what it configured fails.
//
//   WHAT THE REWORK ADDED (code review of the first rework). Three things the earlier
//   pass asserted but did not hold:
//     * INSTANCE NAMES ARE REUSED. Every attestation test used a FRESH name, so the one
//       case where the Worker provably misreported — tether a name, then seal it, while
//       `allowedHostsOverride` persists on the Durable Object — was the case no test
//       constructed. It is constructed now.
//     * NO TEST EVER SENT `egressDenylist`, so both directions of "a caller can widen
//       the denylist but never shrink it" survived a green run.
//     * THE PROBES NAMED THE WRONG MECHANISM. `interceptHttps` is FALSE by default in
//       the pinned `@cloudflare/containers@0.3.7`, so `https://` probes were being
//       attributed to an interceptor that only carried plaintext HTTP. `AgentSandbox`
//       now pins it true and the suite asserts the HTTPS registration exists.
//
//   WHAT THE SECOND REWORK CHANGED (second code review). The reviewer re-derived the
//   pinned SDK line by line instead of trusting a green run — which is the only reason
//   the following were found, since this lane executes nothing:
//     * ONE ASSERTION WAS FALSE. The failed-sealed-reset test claimed the instance
//       still carried the previous grant and then read the DO's allowlist FIELD, which
//       the SDK has already emptied by the time the registration throws. It would have
//       RED on correct code. What survives a failed reset is the installed interceptor,
//       and that is what the test now measures. See that test for the derivation.
//     * TWO COMMENTS CLAIMED MORE THAN THE HARNESS CAN SEE: that probing both URL
//       schemes distinguishes two registrations (it cannot — one fetcher, and
//       `ContainerProxy` never reads the scheme), and that asserting `enableInternet`
//       proves the entrypoint exports `ContainerProxy` (it does not; that is now an
//       import plus an identity check).
//     * `egressPosture` — the caller's own posture label — had no test at all, so both
//       refusals in `containerStart` could be deleted silently. INVARIANT 3c holds them.
//
//   NOT PROVABLE HERE, AND NOT PRETENDED. `enableInternet = false` is enforced by the
//   Cloudflare platform OUTSIDE the container; whether the platform honours it, whether
//   root inside the container can defeat it, and whether the container image trusts the
//   interception CA (without which HTTPS interception fails rather than filters) are
//   live-only questions (see the LIVE-CF gate list in
//   docs/cloudflare-container-isolation.md). What this suite pins is everything up to
//   that boundary: the value the platform is handed, and what Cloudflare's own decision
//   function does with it.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import wranglerToml from "../wrangler.toml?raw";
import type { AppliedPosture, EgressVerdict, ProbeSandbox } from "./harness/worker";
import type { Env } from "../src/index";
// A VALUE import, not a type one, and load-bearing: `ctx.exports.ContainerProxy` — the
// only way `setAllowedHosts`/`setDeniedHosts` can build an interceptor — resolves through
// the Worker entrypoint's own export. Dropping `export { ContainerProxy }` from
// src/index.ts makes this module fail to resolve. See the last test in this file.
import { ContainerProxy } from "../src/index";
import { ContainerProxy as SandboxContainerProxy } from "@cloudflare/sandbox";
import {
  containerStart,
  governedEgressHosts,
  mergeProviderDenylist,
  validateEgressAllowlist,
  PROVIDER_EGRESS_DENYLIST,
} from "../src/container";

const TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";

/** The one host the suite's deployment authorizes (see vitest.config.ts). */
const GOVERNED_HOST = "gw.ferrogate.test";

/** A denied provider, and a provider matched only by a wildcard denylist entry. */
const PROVIDER = "api.anthropic.com";
const SECOND_PROVIDER = "api.openai.com";
const WILDCARD_PROVIDER = "gateway.openrouter.ai";

/** A host only the CALLER asks to deny — the Worker's own list does not carry it. */
const CALLER_DENIED_HOST = "extra.example.com";

/**
 * The size the Worker's own provider denylist must never fall below. Written as
 * a literal on purpose: every other assertion about the union compares against
 * the imported constant, and a constant compared to itself proves nothing about
 * emptying it.
 */
const PROVIDER_DENYLIST_MIN = 22;

interface StartResponse {
  ok?: boolean;
  error?: string;
  message?: string;
  egress?: {
    directPublicEgress: boolean;
    posture: string;
    allowedHosts: string[];
    deniedHosts: string[];
  };
}

/** Drive `/container/start` through the real Worker, bearer and all. */
async function start(body: Record<string, unknown>): Promise<{
  status: number;
  body: StartResponse;
}> {
  const response = await SELF.fetch(`${BASE}/container/start`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as StartResponse };
}

type SandboxNamespace = DurableObjectNamespace<ProbeSandbox>;

function sandbox(instance: string): DurableObjectStub<ProbeSandbox> {
  const ns = (env as unknown as { CONTAINER_SANDBOX: SandboxNamespace }).CONTAINER_SANDBOX;
  return ns.get(ns.idFromName(instance));
}

/** The posture actually applied to `instance`, read off the live Durable Object. */
async function appliedPosture(instance: string): Promise<AppliedPosture> {
  return runInDurableObject(sandbox(instance), async (probe) => probe.appliedPosture());
}

/** Ask Cloudflare's decision function, via the interceptor the SDK installed. */
async function decideInstalled(instance: string, url: string): Promise<EgressVerdict> {
  return runInDurableObject(sandbox(instance), async (probe) =>
    probe.decideThroughInstalledInterceptor(url),
  );
}

/** Ask Cloudflare's decision function about the instance's live posture. */
async function decideLive(instance: string, url: string): Promise<EgressVerdict> {
  return runInDurableObject(sandbox(instance), async (probe) => probe.decideFromLivePosture(url));
}

// ---------------------------------------------------------------------------
// INVARIANT 1 — `AgentSandbox { enableInternet = false }`
// ---------------------------------------------------------------------------

describe("the container class is sealed by the platform, not by convention", () => {
  it("a real AgentSandbox instance carries enableInternet = false", async () => {
    // The bound Durable Object class IS the production `AgentSandbox` (the probe
    // subclass overrides no egress member), so this reads the shipped field.
    const posture = await appliedPosture("fg.tenant-a.sess-1.sealed-field");
    expect(posture.enableInternet).toBe(false);
  });

  it("Cloudflare's egress decision function refuses a provider for that instance", async () => {
    // The applying side: `enableInternet` is fed to `ContainerProxy` exactly as
    // `applyOutboundInterception` feeds it, and Cloudflare's own logic decides. With the
    // field flipped to `true` the proxy hands the request to the real internet instead.
    const verdict = await decideLive(
      "fg.tenant-a.sess-1.sealed-decision",
      `https://${PROVIDER}/v1/messages`,
    );
    expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
  }, 30_000);

  it("refuses an ordinary host for that instance too — the seal is not provider-specific", async () => {
    const verdict = await decideLive(
      "fg.tenant-a.sess-1.sealed-any",
      "https://example.com/anything",
    );
    expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
  }, 30_000);

  it("a real AgentSandbox instance carries interceptHttps = true", async () => {
    // The SDK default is FALSE: `@cloudflare/containers@0.3.7` declares
    // `interceptHttps = false` and `@cloudflare/sandbox@0.12.4` never assigns it
    // (its one occurrence is a read). With the default, `applyOutboundInterception`
    // registers `interceptAllOutboundHttp` ONLY, so `setDeniedHosts` binds
    // PLAINTEXT HTTP and the provider denylist never sees an `https://api.anthropic.com`
    // request — the exact traffic it exists to stop. Read off the live instance, so
    // deleting the pin in src/index.ts reds this.
    const posture = await appliedPosture("fg.tenant-a.sess-1.https-field");
    expect(posture.interceptHttps).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 2 — the Worker re-enforces `direct public egress = false` itself
// ---------------------------------------------------------------------------

describe("/container/start refuses direct public egress unconditionally", () => {
  it("rejects enableInternet: true with 422 and configures nothing", async () => {
    const instance = "fg.tenant-a.sess-1.internet-true";
    const result = await start({ instance, enableInternet: true });
    expect(result.status).toBe(422);
    expect(result.body.error).toBe("invalid_spec");
    expect(result.body.egress).toBeUndefined();
    // Nothing was applied to the instance: the rejection happens before any RPC.
    const posture = await appliedPosture(instance);
    expect(posture.interceptions).toEqual([]);
    expect(posture.allowedHosts).toBeUndefined();
  });

  it("rejects directPublicEgress: true with 422", async () => {
    const result = await start({
      instance: "fg.tenant-a.sess-1.direct-true",
      directPublicEgress: true,
    });
    expect(result.status).toBe(422);
    expect(result.body.error).toBe("invalid_spec");
  });

  it("still rejects it when an otherwise-legal allowlist accompanies it", async () => {
    // The hole #471 closed: an allowlist used to make `enableInternet: true` acceptable.
    const result = await start({
      instance: "fg.tenant-a.sess-1.internet-plus-allowlist",
      enableInternet: true,
      egressAllowlist: [GOVERNED_HOST],
    });
    expect(result.status).toBe(422);
    expect(result.body.message).toContain("issue #471");
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 3 — the allowlist CONSTRAINS egress, it is not merely passed on
// ---------------------------------------------------------------------------

describe("the governed allowlist constrains what the container may reach", () => {
  const instance = "fg.tenant-a.sess-1.tethered";

  async function tetheredStart() {
    return start({ instance, egressAllowlist: [GOVERNED_HOST] });
  }

  it("applies exactly the authorized host to the live instance", async () => {
    const result = await tetheredStart();
    expect(result.status).toBe(200);
    const posture = await appliedPosture(instance);
    expect(posture.allowedHosts).toEqual([GOVERNED_HOST]);
    // The SDK promoted the container to intercept-all and registered an interceptor:
    // without this, nothing below is being decided by Cloudflare at all.
    expect(posture.interceptAll).toBe(true);
    expect(posture.interceptions).toContain("all-http:*");
    // And an HTTPS interception, which only exists because `AgentSandbox` pins
    // `interceptHttps = true`. Without it the SDK registers `all-http` ONLY, and
    // every `https://` probe below would be attributed to a mechanism that is not
    // acting on it. Pins src/index.ts `AgentSandbox { interceptHttps = true }`.
    expect(posture.interceptions).toContain("https:*");
  });

  it("denies a host that is not on the applied allowlist", async () => {
    await tetheredStart();
    const verdict = await decideInstalled(instance, "https://not-authorized.example.com/x");
    expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
  }, 30_000);

  it("denies an LLM provider through the applied denylist, whatever the URL scheme", async () => {
    await tetheredStart();
    // WHAT THE TWO URLS DO AND DO NOT SHOW. They do NOT attribute the two schemes to
    // two registrations: `decideThroughInstalledInterceptor` resolves ONE fetcher
    // (`interceptions.at(-1)`), `applyOutboundInterception` hands the SAME fetcher
    // object to every registration (`container.js:1196-1213`), and `ContainerProxy`
    // branches on `url.hostname` alone — it never reads the scheme
    // (`container.js:197-262`). So this is one decision function asked twice, and a
    // harness that could tell the `https:*` registration from the `all-http:*` one
    // would have to hold the two fetchers apart, which this one does not.
    // What it DOES pin is that the denial is a property of the HOST, so no `http://`
    // downgrade slips past a rule that was reasoned about in TLS terms. The claim
    // that an HTTPS interception exists at all is held elsewhere, on the field
    // (`interceptHttps = true`) and on the registration (`https:*`) — see the
    // `interceptHttps` test above and the `applies exactly the authorized host` one.
    for (const url of [`https://${PROVIDER}/v1/messages`, `http://${PROVIDER}/v1/messages`]) {
      const verdict = await decideInstalled(instance, url);
      expect(verdict, `${url} must be refused`).toEqual({
        verdict: "denied",
        status: 520,
        body: "Origin is disallowed",
      });
    }
  }, 30_000);

  it("lets the authorized host through — so the denials above are not vacuous", async () => {
    await tetheredStart();
    const verdict = await decideInstalled(instance, `https://${GOVERNED_HOST}/v1/chat`);
    // The gateway host is unreachable from the test runtime, so the request cannot
    // complete; what matters is that Cloudflare did NOT refuse it. A suite where every
    // probe returns 520 would pass with the allowlist logic deleted.
    expect(verdict.verdict).toBe("egress-attempted");
  }, 30_000);

  it("keeps denying providers even if the allowlist were widened to a wildcard", async () => {
    // The denylist is defence in depth: with a tight allowlist it is redundant, so this
    // is the only configuration in which it is load-bearing. The lists are the ones
    // ACTUALLY applied to the instance, so emptying PROVIDER_EGRESS_DENYLIST empties
    // this probe's denylist too.
    await tetheredStart();
    const posture = await appliedPosture(instance);
    const verdicts = await runInDurableObject(sandbox(instance), async (probe) => {
      const overBroad = { allowedHosts: ["*"], deniedHosts: posture.deniedHosts, interceptAll: true };
      return [
        await probe.decideWithProps(`https://${PROVIDER}/v1/messages`, overBroad),
        await probe.decideWithProps(`https://api.openai.com/v1/chat`, overBroad),
        await probe.decideWithProps(`https://${WILDCARD_PROVIDER}/api/v1`, overBroad),
      ];
    });
    for (const verdict of verdicts) {
      expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
    }
  }, 30_000);

  it("refuses a wildcard grant at the route", async () => {
    const result = await start({ instance: "fg.tenant-a.sess-1.wild", egressAllowlist: ["*"] });
    expect(result.status).toBe(422);
    expect(result.body.message).toContain("wildcard");
  });

  it("refuses a provider host at the route", async () => {
    const result = await start({
      instance: "fg.tenant-a.sess-1.provider",
      egressAllowlist: [PROVIDER],
    });
    expect(result.status).toBe(422);
    expect(result.body.message).toContain("LLM provider endpoint");
  });

  it("refuses a host outside CONTAINER_GOVERNED_EGRESS_HOSTS", async () => {
    const instance = "fg.tenant-a.sess-1.unauthorized";
    const result = await start({ instance, egressAllowlist: ["evil.example.com"] });
    expect(result.status).toBe(422);
    expect(result.body.message).toContain("CONTAINER_GOVERNED_EGRESS_HOSTS");
    // And the instance really is untouched, not merely reported as rejected.
    const posture = await appliedPosture(instance);
    expect(posture.allowedHosts).toBeUndefined();
    expect(posture.interceptions).toEqual([]);
  });

  it("refuses everything when no governed host is configured", async () => {
    // The default this deployment ships with. A permissive fallback here would open the
    // tier silently, so it is asserted as behaviour, not as a parser result.
    const sealedEnv = { ...env, CONTAINER_GOVERNED_EGRESS_HOSTS: undefined } as unknown as Env;
    for (const requested of [[GOVERNED_HOST], ["example.com"], [PROVIDER]]) {
      const result = await containerStart(sealedEnv, {
        instance: "fg.tenant-a.sess-1.unconfigured",
        egressAllowlist: requested,
      });
      expect(result.ok, `allowlist ${JSON.stringify(requested)} must be refused`).toBe(false);
    }
    expect(governedEgressHosts(undefined)).toEqual([]);
    expect(governedEgressHosts("")).toEqual([]);
    expect(validateEgressAllowlist([GOVERNED_HOST], []).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 3b — a caller-supplied denylist WIDENS the Worker's, never shrinks it
//
// Nothing in the previous suite ever sent `egressDenylist`, so both directions of
// this invariant survived a green run: the caller's list REPLACING the Worker's
// (a shrink), and the union being dropped altogether. `container.ts` states the
// rule ("a compromised or stale caller must not be able to shrink the denylist")
// and docs/cloudflare-container-isolation.md makes it load-bearing ("a
// caller-supplied denylist can only widen it, never shrink it … so an over-broad
// allowlist still cannot reach a provider"). These tests hold it.
// ---------------------------------------------------------------------------

describe("a caller-supplied denylist can only widen the Worker's own", () => {
  it("applies the UNION of the Worker's provider denylist and the caller's entry", async () => {
    const instance = "fg.tenant-a.sess-1.deny-union";
    const result = await start({
      instance,
      egressAllowlist: [GOVERNED_HOST],
      egressDenylist: [CALLER_DENIED_HOST],
    });
    expect(result.status).toBe(200);
    const posture = await appliedPosture(instance);

    // The list the Durable Object is ACTUALLY carrying, not the JSON we sent.
    // MUTATION M5b — drop the caller union (`denylist = PROVIDER_EGRESS_DENYLIST`):
    // the caller's host is absent and this reds.
    expect(posture.deniedHosts).toContain(CALLER_DENIED_HOST);
    // MUTATION M5a — caller's list REPLACES the Worker's (`denylist = caller`):
    // every provider is gone and these red.
    expect(posture.deniedHosts).toContain(PROVIDER);
    expect(posture.deniedHosts).toContain(SECOND_PROVIDER);
    expect(posture.deniedHosts?.length ?? 0).toBeGreaterThanOrEqual(PROVIDER_DENYLIST_MIN + 1);
    // Exactly the union, in the Worker's order then the caller's — so neither a
    // reordering nor a silent extra entry passes.
    expect(posture.deniedHosts).toEqual([...PROVIDER_EGRESS_DENYLIST, CALLER_DENIED_HOST]);
    // And the attestation reports that union rather than the caller's request.
    expect(result.body.egress?.deniedHosts).toEqual(posture.deniedHosts);
  });

  it("still denies every provider when the caller sends a SHORTER list", async () => {
    // The shrink attempt: a stale or compromised caller sends one provider and
    // nothing else, hoping the Worker takes its word for the whole list.
    const instance = "fg.tenant-a.sess-1.deny-shrink";
    const result = await start({
      instance,
      egressAllowlist: [GOVERNED_HOST],
      egressDenylist: [PROVIDER],
    });
    expect(result.status).toBe(200);
    const posture = await appliedPosture(instance);

    // MUTATION M5a reds on the first provider the caller omitted.
    for (const entry of PROVIDER_EGRESS_DENYLIST) {
      expect(posture.deniedHosts, `the caller's short list dropped ${entry}`).toContain(entry);
    }
    // De-duplicated: repeating an entry the Worker already denies adds nothing.
    expect(posture.deniedHosts).toEqual([...PROVIDER_EGRESS_DENYLIST]);
    expect(posture.deniedHosts?.length ?? 0).toBeGreaterThanOrEqual(PROVIDER_DENYLIST_MIN);

    // BEHAVIOURAL, not just structural: Cloudflare's own decision function is asked
    // what the APPLIED denylist does, with the allowlist widened to `*` so the
    // denylist is the only thing that can refuse. Under M5a the applied list is
    // `["api.anthropic.com"]`, so a provider the caller omitted comes back
    // `egress-attempted` and these red.
    const verdicts = await runInDurableObject(sandbox(instance), async (probe) => {
      const overBroad = {
        enableInternet: false,
        allowedHosts: ["*"],
        deniedHosts: posture.deniedHosts,
        interceptAll: true,
      };
      return [
        await probe.decideWithProps(`https://${SECOND_PROVIDER}/v1/chat`, overBroad),
        await probe.decideWithProps(`https://${WILDCARD_PROVIDER}/api/v1`, overBroad),
      ];
    });
    for (const verdict of verdicts) {
      expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
    }
  }, 30_000);

  it("merges as a pure function too: the union starts from the Worker's list, always", () => {
    // The route tests above are the ones that matter; this pins the unit so a
    // future caller of `mergeProviderDenylist` inherits the same guarantee.
    expect(mergeProviderDenylist([CALLER_DENIED_HOST])).toEqual([
      ...PROVIDER_EGRESS_DENYLIST,
      CALLER_DENIED_HOST,
    ]);
    // Nothing a caller can send removes an entry: not an empty list, not a
    // subset, not junk, not a non-array.
    for (const requested of [[], [PROVIDER], undefined, "api.anthropic.com", [1, 2, 3], null]) {
      const merged = mergeProviderDenylist(requested);
      for (const entry of PROVIDER_EGRESS_DENYLIST) {
        expect(merged, `${JSON.stringify(requested)} dropped ${entry}`).toContain(entry);
      }
      expect(merged.length).toBeGreaterThanOrEqual(PROVIDER_DENYLIST_MIN);
    }
    // Normalized and de-duplicated, so a caller cannot pad the applied list.
    expect(mergeProviderDenylist(["  API.Anthropic.COM  ", "", "   "])).toEqual([
      ...PROVIDER_EGRESS_DENYLIST,
    ]);
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 3c — the caller's `egressPosture` is CHECKED, never believed
//
// `containerStart` derives the posture from the validated allowlist and then refuses
// a request whose own `egressPosture` field disagrees with that derivation. Until now
// no test in this suite ever SENT `egressPosture`, so deleting both refusals left the
// suite green — the same shape as the `egressDenylist` gap above.
//
// It is the mildest of the enforcement branches, because it fails toward MORE
// restriction and `EgressPostureAttestation::verify` on the Rust side compares the
// attestation against the request independently. But it is the one branch in
// `containerStart` with no assertion at all, and "the label the caller sent is not
// what decides the posture" is exactly the confusion #471 is about.
// ---------------------------------------------------------------------------

describe("the requested egressPosture must agree with the derived one", () => {
  it("refuses a tethered label with no allowlist — the label cannot open anything", async () => {
    // The direction that matters: a caller that says "gateway-tethered" while sending
    // nothing to tether to must not be handed a posture its own label implies.
    const instance = "fg.tenant-a.sess-1.posture-echo-tethered";
    const result = await start({ instance, egressPosture: "gateway-tethered" });
    expect(result.status).toBe(422);
    expect(result.body.error).toBe("invalid_spec");
    expect(result.body.message).toContain("does not match the requested allowlist");
    // Refused BEFORE any RPC, so the instance is untouched rather than half-configured.
    const posture = await appliedPosture(instance);
    expect(posture.allowedHosts).toBeUndefined();
    expect(posture.interceptions).toEqual([]);
  });

  it("refuses a sealed label that arrives with an allowlist", async () => {
    // The mirror, so the check is not "tethered is always refused". An allowlist the
    // Worker would otherwise ACCEPT (`GOVERNED_HOST` is the one authorized host) is
    // still refused, because the label contradicts it.
    const instance = "fg.tenant-a.sess-1.posture-echo-sealed";
    const result = await start({
      instance,
      egressPosture: "sealed",
      egressAllowlist: [GOVERNED_HOST],
    });
    expect(result.status).toBe(422);
    expect(result.body.error).toBe("invalid_spec");
    expect(result.body.message).toContain("does not match the requested allowlist");
    expect((await appliedPosture(instance)).interceptions).toEqual([]);
  });

  it("refuses a posture label that is not one of the two, by name", async () => {
    // Asserted on the MESSAGE, not on the status: an unknown label is also a mismatch,
    // so deleting the vocabulary check would still produce a 422 from the mismatch
    // check below it. Only the message tells the two branches apart, so only the
    // message catches deleting the vocabulary check.
    for (const requested of ["open", "", "SEALED", "gateway_tethered", 7, null, true]) {
      const result = await start({
        instance: "fg.tenant-a.sess-1.posture-echo-junk",
        egressPosture: requested,
      });
      expect(result.status, `egressPosture ${JSON.stringify(requested)} must be refused`).toBe(422);
      expect(result.body.message).toBe("egressPosture must be sealed or gateway-tethered");
    }
  });

  it("accepts either label when it agrees — so the refusals above are not vacuous", async () => {
    // Without this, deleting the derivation and refusing EVERY request that carries an
    // `egressPosture` would pass all three tests above.
    const sealed = await start({
      instance: "fg.tenant-a.sess-1.posture-echo-ok-sealed",
      egressPosture: "sealed",
    });
    expect(sealed.status).toBe(200);
    expect(sealed.body.egress?.posture).toBe("sealed");

    const tethered = await start({
      instance: "fg.tenant-a.sess-1.posture-echo-ok-tethered",
      egressPosture: "gateway-tethered",
      egressAllowlist: [GOVERNED_HOST],
    });
    expect(tethered.status).toBe(200);
    expect(tethered.body.egress?.posture).toBe("gateway-tethered");
    // And the accepted label did not become the source of truth: the attested posture
    // is still the one derived from the allowlist and applied to the instance.
    expect(tethered.body.egress?.allowedHosts).toEqual(
      (await appliedPosture("fg.tenant-a.sess-1.posture-echo-ok-tethered")).allowedHosts,
    );
  });
});

// ---------------------------------------------------------------------------
// INVARIANT 4 — the attestation reports what was APPLIED
// ---------------------------------------------------------------------------

describe("the start attestation matches the applied posture", () => {
  it("attests the tethered lists the instance is actually carrying", async () => {
    const instance = "fg.tenant-a.sess-1.attest-tethered";
    const result = await start({ instance, egressAllowlist: [GOVERNED_HOST] });
    expect(result.status).toBe(200);
    const posture = await appliedPosture(instance);
    const attested = result.body.egress;
    expect(attested).toBeDefined();
    expect(attested?.posture).toBe("gateway-tethered");
    expect(attested?.directPublicEgress).toBe(false);
    // Not "looks plausible": the attested lists are compared to the lists the Durable
    // Object is carrying. A Worker that returns a constant fails here.
    expect(attested?.allowedHosts).toEqual(posture.allowedHosts);
    expect(attested?.deniedHosts).toEqual(posture.deniedHosts);
    expect(attested?.allowedHosts).toEqual([GOVERNED_HOST]);
    expect(attested?.deniedHosts?.length).toBeGreaterThan(0);
  });

  it("attests sealed against the lists the instance is carrying, on a FRESH name", async () => {
    const instance = "fg.tenant-a.sess-1.attest-sealed";
    const result = await start({ instance });
    expect(result.status).toBe(200);
    expect(result.body.egress).toEqual({
      directPublicEgress: false,
      posture: "sealed",
      allowedHosts: [],
      deniedHosts: [],
    });
    const posture = await appliedPosture(instance);
    // `[]`, not `undefined`: the sealed path APPLIES the empty lists rather than
    // skipping the setters, because the attested `[]` has to be true of the
    // instance and not merely true of the request. An empty allowlist is a
    // deny-by-default gate in `ContainerProxy` — it refuses every host.
    expect(posture.allowedHosts).toEqual([]);
    expect(posture.deniedHosts).toEqual([]);
    expect(posture.enableInternet).toBe(false);
    // Compared to the applied state, not to a literal, so a Worker returning a
    // constant fails here as it does on the tethered path.
    expect(result.body.egress?.allowedHosts).toEqual(posture.allowedHosts);
    expect(result.body.egress?.deniedHosts).toEqual(posture.deniedHosts);
  });

  it("seals an instance a PREVIOUS start had tethered — the reused-name case", async () => {
    // THE CASE THE PREVIOUS SUITE DID NOT CONSTRUCT, and the only one in which the
    // Worker could misreport. Instance names are addresses, not identities:
    // `fg.{tenant}.{session}.{run}` resolves a Durable Object by name, and
    // `@cloudflare/containers` keeps `allowedHostsOverride` as a live DO field that
    // it PERSISTS to storage, so it survives eviction. Tether, then seal the same
    // name: with the old sealed branch (which called NEITHER setter) the instance
    // still carried `["gw.ferrogate.test"]` and 22 provider denies while the Worker
    // attested `{"posture":"sealed","allowedHosts":[],"deniedHosts":[]}` — a false
    // attestation on the enforcement path, which `EgressPostureAttestation::verify`
    // accepts because it only compares the attestation to the REQUEST.
    const instance = "fg.tenant-a.sess-1.reused-tethered-then-sealed";

    const tethered = await start({ instance, egressAllowlist: [GOVERNED_HOST] });
    expect(tethered.status).toBe(200);
    const afterTether = await appliedPosture(instance);
    // The precondition has to be real, or the second half proves nothing.
    expect(afterTether.allowedHosts).toEqual([GOVERNED_HOST]);
    expect(afterTether.deniedHosts).toContain(PROVIDER);
    const tetheredPropCount = afterTether.props.length;

    const sealed = await start({ instance });
    expect(sealed.status).toBe(200);
    const posture = await appliedPosture(instance);

    // Pins container.ts's sealed branch (`setAllowedHosts(allowlist)` /
    // `setDeniedHosts(denylist)`). Delete either call and the instance keeps the
    // previous run's lists while the attestation below claims `[]`.
    expect(posture.allowedHosts).toEqual([]);
    expect(posture.deniedHosts).toEqual([]);
    expect(sealed.body.egress).toEqual({
      directPublicEgress: false,
      posture: "sealed",
      allowedHosts: [],
      deniedHosts: [],
    });
    // The attestation is checked against the APPLIED state, which is the property
    // the suite claims to hold and the one that was false.
    expect(sealed.body.egress?.allowedHosts).toEqual(posture.allowedHosts);
    expect(sealed.body.egress?.deniedHosts).toEqual(posture.deniedHosts);

    // BEHAVIOURAL: the host the previous run could reach is refused now, decided by
    // Cloudflare's own function through the interceptor the SDK actually installed.
    // Without the fix this comes back `egress-attempted`.
    const verdict = await decideInstalled(instance, `https://${GOVERNED_HOST}/v1/chat`);
    expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });

    // ORDER: sealing closes the allowlist FIRST. Clearing the denylist first would
    // leave the stale gateway grant reachable for the width of one RPC, and if the
    // second call then threw the instance would stay tethered while the run was
    // told it was sealed. The props the SDK published are a chronological record.
    const sealingProps = posture.props.slice(tetheredPropCount);
    expect(sealingProps.length, "the sealed start must publish two postures").toBe(2);
    expect(
      sealingProps[0].allowedHosts,
      "the first posture the sealed start published must already allow nothing",
    ).toEqual([]);
    expect(sealingProps.at(-1)?.allowedHosts).toEqual([]);
    expect(sealingProps.at(-1)?.deniedHosts).toEqual([]);
    for (const props of sealingProps) {
      expect(props.enableInternet).toBe(false);
    }
  }, 30_000);

  it("re-tethers an instance a previous start had sealed, and attests the lists back", async () => {
    // The mirror case, so the fix is not "sealed always wins" but "the attestation
    // is what is applied". Seal first, then tether the same name.
    const instance = "fg.tenant-a.sess-1.reused-sealed-then-tethered";
    expect((await start({ instance })).status).toBe(200);
    expect((await appliedPosture(instance)).allowedHosts).toEqual([]);

    const tethered = await start({ instance, egressAllowlist: [GOVERNED_HOST] });
    expect(tethered.status).toBe(200);
    const posture = await appliedPosture(instance);
    expect(posture.allowedHosts).toEqual([GOVERNED_HOST]);
    expect(posture.deniedHosts).toContain(PROVIDER);
    expect(tethered.body.egress?.allowedHosts).toEqual(posture.allowedHosts);
    expect(tethered.body.egress?.deniedHosts).toEqual(posture.deniedHosts);
    expect(tethered.body.egress?.posture).toBe("gateway-tethered");
  });

  it("never leaves the instance allowed-but-unfenced: deny is applied before allow", async () => {
    const instance = "fg.tenant-a.sess-1.order";
    await start({ instance, egressAllowlist: [GOVERNED_HOST] });
    const posture = await appliedPosture(instance);
    // Each setter re-applies the interception, so the props the SDK built are a
    // chronological record of the posture. The first one must already carry the denylist
    // and must NOT yet carry the allowlist.
    expect(posture.props.length).toBeGreaterThanOrEqual(2);
    const first = posture.props[0];
    expect(first.allowedHosts, "the first published posture must not allow anything yet").toBe(
      undefined,
    );
    expect(first.deniedHosts ?? [], "the first published posture must already deny").toContain(
      PROVIDER,
    );
    expect(posture.props.at(-1)?.allowedHosts).toEqual([GOVERNED_HOST]);
    // And `enableInternet` is false in every configuration the SDK ever published.
    for (const props of posture.props) {
      expect(props.enableInternet).toBe(false);
    }
  });

  it("reports a start whose egress configuration failed as an error, never as running", async () => {
    // A fence that could not be installed must not be attested. Cloudflare's container
    // control plane is made to reject the interception registration, so the SDK's
    // `setDeniedHosts` rejects and the Worker's catch decides what the caller sees.
    const instance = "fg.tenant-a.sess-1.apply-fails";
    await runInDurableObject(sandbox(instance), async (probe) =>
      probe.failNextInterception("container control plane unavailable"),
    );
    const result = await start({ instance, egressAllowlist: [GOVERNED_HOST] });
    expect(result.status).not.toBe(200);
    expect(result.body.ok).toBeUndefined();
    expect(result.body.egress).toBeUndefined();
    expect(result.body.error).toBe("container_error");
    // And the instance is genuinely unfenced — which is exactly why it must not be run.
    const posture = await appliedPosture(instance);
    expect(posture.interceptions).toEqual([]);
  });

  it("reports a SEALED start whose reset failed as an error, never as sealed", async () => {
    // Since the sealed path applies the empty lists, it can fail the same way — and
    // a sealed start that could not clear a previous run's grant is precisely the
    // false attestation this rework exists to remove. It must surface as an error.
    //
    // WHERE THE RESET DIES, EXACTLY. `setAllowedHosts` assigns the field and THEN
    // refreshes (`containers/dist/lib/container.js:487-490`), and the refresh builds
    // the `ContainerProxy` props before it registers anything
    // (`container.js:1184-1197`), so what the failure interrupts is the REGISTRATION
    // — `interceptOutboundHttps('*', …)` at `container.js:1208`. Two layers therefore
    // disagree, and the assertions below pin both halves:
    //   * the DO's own field is already reset (`allowedHostsOverride = []`, persisted
    //     at `container.js:1183`), so reading it would say "sealed";
    //   * the INSTALLED interceptor is still the tethered one, because the call that
    //     would have replaced it is the call that threw — so the container's live
    //     enforcement still grants the previous run's host.
    // The second is the real state of the world, and it is why the Worker must refuse
    // rather than attest. The first rework asserted the field with the second's
    // comment above it, which reds on correct code; that is fixed here.
    const instance = "fg.tenant-a.sess-1.sealed-apply-fails";
    expect((await start({ instance, egressAllowlist: [GOVERNED_HOST] })).status).toBe(200);
    const tethered = await appliedPosture(instance);
    // The precondition has to be real, or nothing below distinguishes anything.
    expect(tethered.allowedHosts).toEqual([GOVERNED_HOST]);
    expect(tethered.interceptions).toContain("all-http:*");

    await runInDurableObject(sandbox(instance), async (probe) =>
      probe.failNextInterception("container control plane unavailable"),
    );
    const result = await start({ instance });
    expect(result.status).not.toBe(200);
    expect(result.body.error).toBe("container_error");
    expect(result.body.egress).toBeUndefined();

    const posture = await appliedPosture(instance);
    // ORDER, observed on the failing path. Pins container.ts's sealed branch calling
    // `setAllowedHosts` FIRST: the allowlist field is reset even though the run then
    // failed. Reorder the two setters (deny first) or delete the allow call, and the
    // throw happens before `allowedHostsOverride` is touched — the field is still
    // `[GOVERNED_HOST]` and this reds. The tethered path's order is pinned at the
    // "deny is applied before allow" test; this is the sealed path's.
    expect(posture.allowedHosts).toEqual([]);
    // WHAT THE FAILED RESET PUBLISHED, sliced off the chronological record the same
    // way the reused-name test slices it. Exactly ONE props build, carrying the
    // emptied allowlist. Both halves of that are load-bearing:
    //   * "at least one" is what places the failure AT the registration rather than
    //     before it — the SDK reached `ctx.exports.ContainerProxy` (`container.js:1194`)
    //     and only then threw out of `interceptOutboundHttps` (`container.js:1208`).
    //     Everything the comment above derives about a stale interceptor rests on
    //     that ordering, so if a vendor bump moved the props build after the
    //     registration this must red rather than keep asserting the old story.
    //   * "exactly one" is what pins the sealed branch as fail-FAST. Wrap
    //     `setAllowedHosts` in a try/catch that goes on to attempt
    //     `setDeniedHosts` before rethrowing — a plausible "clear both lists
    //     best-effort" rewrite — and a second record appears here while every other
    //     assertion in this test stays green.
    const resetProps = posture.props.slice(tethered.props.length);
    expect(resetProps.length, "the failed sealed reset must publish exactly one posture").toBe(1);
    expect(resetProps[0]?.allowedHosts).toEqual([]);
    // ...and registered NOTHING. No interception was added, so the fetcher the
    // container is actually running behind is still the tethered one.
    expect(posture.interceptions).toEqual(tethered.interceptions);

    // THE ENFORCEMENT LAYER, which is the observable that carries the stale grant.
    // `decideThroughInstalledInterceptor` resolves `interceptions.at(-1)` — the
    // fetcher `applyOutboundInterception` installed during the tethered start, whose
    // props still read `allowedHosts: ["gw.ferrogate.test"]`. Cloudflare's own
    // decision function therefore still lets that host out. Pins
    // harness/worker.ts:261-265: rebuild those props from the instance's live state
    // (which is what `decideFromLivePosture` does) and this comes back `denied`,
    // because the DO field says `[]` — the reconstruction would hide exactly the
    // divergence this test exists to show. It is also a negative control on
    // `decide()`: collapse an unreachable host to `denied` and this reds too.
    const verdict = await decideInstalled(instance, `https://${GOVERNED_HOST}/v1/chat`);
    expect(verdict.verdict).toBe("egress-attempted");
  }, 30_000);
});

// ---------------------------------------------------------------------------
// INVARIANT 5 — deployment configuration the attestation cannot detect
// ---------------------------------------------------------------------------

describe("wrangler.toml binds the tier to the sealed class", () => {
  /** Blocks of a `[[table]]` array, as raw text. */
  function blocks(name: string): string[] {
    return wranglerToml
      .split(/^\[\[/m)
      .filter((block) => block.startsWith(`${name}]]`))
      .map((block) => block.slice(`${name}]]`.length));
  }

  function value(block: string, key: string): string | undefined {
    return new RegExp(`^\\s*${key}\\s*=\\s*"([^"]+)"`, "m").exec(block)?.[1];
  }

  it("points CONTAINER_SANDBOX at AgentSandbox", () => {
    // The one failure mode the attestation provably cannot catch: rebind the namespace
    // to a class that does not extend `AgentSandbox` and every request still reports a
    // sealed instance, while the platform default of open internet applies.
    const binding = blocks("durable_objects.bindings").find(
      (block) => value(block, "name") === "CONTAINER_SANDBOX",
    );
    expect(binding, "wrangler.toml has no CONTAINER_SANDBOX binding").toBeDefined();
    expect(value(binding as string, "class_name")).toBe("AgentSandbox");
  });

  it("backs the container image with the same class", () => {
    const container = blocks("containers")[0];
    expect(container, "wrangler.toml has no [[containers]] block").toBeDefined();
    expect(value(container, "class_name")).toBe("AgentSandbox");
  });

  it("ships CONTAINER_GOVERNED_EGRESS_HOSTS empty", () => {
    // Sealed by default: an operator opts a host in, never out.
    expect(/^CONTAINER_GOVERNED_EGRESS_HOSTS\s*=\s*""\s*$/m.test(wranglerToml)).toBe(true);
  });

  it("enables ctx.exports, without which no allow/deny list can bind", () => {
    // `setAllowedHosts`/`setDeniedHosts` resolve their interceptor through
    // `ctx.exports.ContainerProxy`. The flag is off by default before compatibility date
    // 2025-11-17, and this Worker pins 2025-06-01, so it must be requested explicitly.
    const flags = /^compatibility_flags\s*=\s*\[([^\]]*)\]/m.exec(wranglerToml)?.[1] ?? "";
    expect(flags).toContain("enable_ctx_exports");
  });

  it("re-exports the SDK's ContainerProxy from the Worker entrypoint", () => {
    // The other half of the same dependency, and a LINK-TIME one: workerd only lists an
    // entrypoint in `ctx.exports` when the ENTRY MODULE names it, so every interceptor
    // in this suite resolves through `src/index.ts`'s `export { ContainerProxy }`
    // (re-exported verbatim by test/harness/worker.ts, which sources it from
    // `../../src/index` rather than from the SDK precisely so that deleting the
    // production export breaks this build).
    //
    // The named import at the top of this file is therefore half the assertion —
    // delete the export and this module fails to resolve rather than failing an
    // expectation. The identity check is the other half: re-exporting a local class of
    // the same name would satisfy the import while every `setAllowedHosts` /
    // `setDeniedHosts` call built a fetcher that decides nothing. The previous version
    // of this test asserted `enableInternet === false`, which says nothing about any
    // export and duplicated the first test in this file.
    expect(ContainerProxy).toBe(SandboxContainerProxy);
  });
});
