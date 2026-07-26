// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway. TEST-GATE suite for issue #475
//   acceptance box 1 — "a documented egress posture satisfying #471, with evidence of
//   what the platform actually ENFORCES".
//
//   docs/cloudflare-git-credential-broker.md picks the ALLOWLIST option and states the
//   deployment posture verbatim:
//
//       CONTAINER_GOVERNED_EGRESS_HOSTS = "<gateway host>,github.com",
//       and a run's egressAllowlist naming exactly those two.
//       api.anthropic.com and friends are unreachable by construction.
//
//   The existing #471 suite (test/container-egress.test.ts) proves the enforcement
//   machinery under a ONE-HOST deployment (`gw.ferrogate.test`). It never exercises the
//   posture #475 actually deploys, so nothing proved that adding `github.com` — the whole
//   point of #475 — keeps the #471 property. That is what this file does: it runs the
//   documented two-host posture and asks CLOUDFLARE'S OWN egress decision function, via
//   the interceptor the SDK really installed, what the container can and cannot reach.
//
//   Technique and harness are #471's (commit b2e85e9): a real `AgentSandbox` Durable
//   Object under @cloudflare/vitest-pool-workers, verdicts read out of `ContainerProxy`,
//   nothing asserted on the side that merely SENDS the configuration.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { containerStart, validateEgressAllowlist } from "../src/container";
import type { AppliedPosture, EgressVerdict, ProbeSandbox } from "./harness/worker";
import type { Env } from "../src/index";

/** The gateway host the credential helper calls back to (`/git-credential/get`). */
const GATEWAY_HOST = "gw.ferrogate.test";
/** The git remote the brokered path clones from. */
const GITHUB_HOST = "github.com";

/** The exact `CONTAINER_GOVERNED_EGRESS_HOSTS` the design record prescribes. */
const DOCUMENTED_POSTURE = `${GATEWAY_HOST},${GITHUB_HOST}`;

/** The #471 bypass this posture exists to prevent. */
const PROVIDER = "api.anthropic.com";

function governed(): Env {
  return { ...env, CONTAINER_GOVERNED_EGRESS_HOSTS: DOCUMENTED_POSTURE } as unknown as Env;
}

function sandbox(instance: string): DurableObjectStub<ProbeSandbox> {
  const ns = (env as unknown as { CONTAINER_SANDBOX: DurableObjectNamespace<ProbeSandbox> })
    .CONTAINER_SANDBOX;
  return ns.get(ns.idFromName(instance));
}

async function appliedPosture(instance: string): Promise<AppliedPosture> {
  return runInDurableObject(sandbox(instance), async (probe) => probe.appliedPosture());
}

/** Ask the interceptor the SDK ACTUALLY installed on this instance about `url`. */
async function decide(instance: string, url: string): Promise<EgressVerdict> {
  return runInDurableObject(sandbox(instance), async (probe) =>
    probe.decideThroughInstalledInterceptor(url),
  );
}

/** Start an instance under the documented two-host posture. */
async function startDocumented(instance: string, allowlist: string[]) {
  return containerStart(governed(), { instance, egressAllowlist: allowlist });
}

describe("#475 box 1 — the documented allowlist posture, as Cloudflare enforces it", () => {
  const instance = "fg.tenant-a.sess-475.documented";

  it("applies exactly the two documented hosts and nothing else", async () => {
    const result = await startDocumented(instance, [GATEWAY_HOST, GITHUB_HOST]);
    expect(result.ok, JSON.stringify(result)).toBe(true);
    if (!result.ok) return;
    expect(result.egress.posture).toBe("gateway-tethered");
    expect(result.egress.directPublicEgress).toBe(false);

    // Read off the LIVE instance, through the SDK's own accessors — not off the response.
    const posture = await appliedPosture(instance);
    expect(posture.enableInternet).toBe(false);
    expect(posture.allowedHosts).toEqual([GATEWAY_HOST, GITHUB_HOST]);
    expect(posture.deniedHosts).toContain(PROVIDER);
    // The interceptor really was registered; without it there is nothing enforcing.
    expect(posture.interceptions.length).toBeGreaterThan(0);
  });

  it("Cloudflare's decision function lets git reach github.com", async () => {
    // The #475 acceptance depends on this being reachable. If a future tightening
    // sealed it, the brokered clone would silently stop working.
    const verdict = await decide(instance, `https://${GITHUB_HOST}/acme/app.git/info/refs`);
    expect(verdict.verdict, JSON.stringify(verdict)).not.toBe("denied");
  });

  it("Cloudflare's decision function lets the helper call the gateway back", async () => {
    const verdict = await decide(instance, `https://${GATEWAY_HOST}/git-credential/get`);
    expect(verdict.verdict, JSON.stringify(verdict)).not.toBe("denied");
  });

  it("Cloudflare's decision function REFUSES the provider under that same posture", async () => {
    // This is the #471 property, evaluated against the posture #475 deploys rather than
    // against a one-host stand-in. `denied` is Cloudflare's documented 520; anything
    // else means the request left the container for the internet.
    const verdict = await decide(instance, `https://${PROVIDER}/v1/messages`);
    expect(verdict, JSON.stringify(verdict)).toMatchObject({
      verdict: "denied",
      status: 520,
      body: "Origin is disallowed",
    });
  });

  it("REFUSES api.github.com too — the brokered path needs no GitHub API from inside", async () => {
    // The mint happens in the Worker. A container that can reach api.github.com could
    // use a stolen token against the whole API surface, not just git.
    const verdict = await decide(instance, "https://api.github.com/user");
    expect(verdict, JSON.stringify(verdict)).toMatchObject({ verdict: "denied", status: 520 });
  });

  it("the decision function is not a blanket denier — the verdicts above mean something", async () => {
    // Non-vacuity control. Every "denied" above would be worthless if `ContainerProxy`
    // refused everything in this harness. Hand it a posture that DOES authorize the
    // provider and watch the same function allow it through.
    const permissive = await runInDurableObject(sandbox(instance), async (probe) =>
      probe.decideWithProps(`https://${PROVIDER}/v1/messages`, {
        enableInternet: false,
        allowedHosts: [PROVIDER],
        deniedHosts: [],
        interceptAll: true,
      }),
    );
    expect(permissive.verdict, JSON.stringify(permissive)).toBe("egress-attempted");
  });

  it("REFUSES a lookalike of the granted host", async () => {
    for (const host of ["github.com.evil.example", "raw.githubusercontent.com", "notgithub.com"]) {
      const verdict = await decide(instance, `https://${host}/x`);
      expect(verdict, `${host}: ${JSON.stringify(verdict)}`).toMatchObject({ verdict: "denied" });
    }
  });
});

describe("#475 box 1 — the allowlist gate is what stands between the two", () => {
  it("refuses a run that asks for the provider even under the #475 posture", async () => {
    // The single check the whole posture rests on. Mutating `validateEgressAllowlist` to
    // always succeed makes this test, and the decision-function tests above, go red.
    const result = await containerStart(governed(), {
      instance: "fg.tenant-a.sess-475.provider",
      egressAllowlist: [GATEWAY_HOST, GITHUB_HOST, PROVIDER],
    });
    expect(result.ok, JSON.stringify(result)).toBe(false);
    expect(validateEgressAllowlist([PROVIDER], [GATEWAY_HOST, GITHUB_HOST, PROVIDER]).ok).toBe(
      false,
    );
    // ...and the instance was never configured.
    const posture = await appliedPosture("fg.tenant-a.sess-475.provider");
    expect(posture.allowedHosts).toBeUndefined();
    expect(posture.interceptions).toEqual([]);
  });

  it("refuses a host the operator did not authorize, even one that looks like github", async () => {
    for (const host of ["github.com.evil.example", "codeload.github.com", "*.github.com"]) {
      const result = await containerStart(governed(), {
        instance: "fg.tenant-a.sess-475.unauthorized",
        egressAllowlist: [host],
      });
      expect(result.ok, `${host} must be refused`).toBe(false);
    }
  });

  it("an unconfigured deployment cannot open github.com either — sealed, not open", async () => {
    const unconfigured = { ...env, CONTAINER_GOVERNED_EGRESS_HOSTS: undefined } as unknown as Env;
    const result = await containerStart(unconfigured, {
      instance: "fg.tenant-a.sess-475.sealed",
      egressAllowlist: [GITHUB_HOST],
    });
    expect(result.ok).toBe(false);
  });
});
