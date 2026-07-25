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
//   NOT PROVABLE HERE, AND NOT PRETENDED. `enableInternet = false` is enforced by the
//   Cloudflare platform OUTSIDE the container; whether the platform honours it, and
//   whether root inside the container can defeat it, are live-only questions (see the
//   LIVE-CF gate list in docs/cloudflare-container-isolation.md). What this suite pins is
//   everything up to that boundary: the value the platform is handed, and what
//   Cloudflare's own decision function does with it.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import wranglerToml from "../wrangler.toml?raw";
import type { AppliedPosture, EgressVerdict, ProbeSandbox } from "./harness/worker";
import type { Env } from "../src/index";
import {
  containerStart,
  governedEgressHosts,
  validateEgressAllowlist,
} from "../src/container";

const TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";

/** The one host the suite's deployment authorizes (see vitest.config.ts). */
const GOVERNED_HOST = "gw.ferrogate.test";

/** A denied provider, and a provider matched only by a wildcard denylist entry. */
const PROVIDER = "api.anthropic.com";
const WILDCARD_PROVIDER = "gateway.openrouter.ai";

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
  });

  it("denies a host that is not on the applied allowlist", async () => {
    await tetheredStart();
    const verdict = await decideInstalled(instance, "https://not-authorized.example.com/x");
    expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
  }, 30_000);

  it("denies an LLM provider through the applied denylist", async () => {
    await tetheredStart();
    const verdict = await decideInstalled(instance, `https://${PROVIDER}/v1/messages`);
    expect(verdict).toEqual({ verdict: "denied", status: 520, body: "Origin is disallowed" });
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

  it("attests sealed only when the instance really was left alone", async () => {
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
    // The sealed path deliberately stays off Cloudflare's interception path: no lists,
    // no interceptor. `undefined` (never set) is not the same as `[]` (set to empty).
    expect(posture.allowedHosts).toBeUndefined();
    expect(posture.deniedHosts).toBeUndefined();
    expect(posture.interceptions).toEqual([]);
    expect(posture.enableInternet).toBe(false);
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

  it("exports ContainerProxy from the Worker entrypoint", async () => {
    // Same dependency from the runtime side: if the entrypoint stops exporting it, the
    // harness cannot resolve it and the instrumented instance refuses to construct.
    const posture = await appliedPosture("fg.tenant-a.sess-1.exports");
    expect(posture.enableInternet).toBe(false);
  });
});
