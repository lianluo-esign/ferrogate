// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the container->Worker
// binding shim of the #424 PoC: the `outboundByHost` handler table that resolves
// Cloudflare bindings on behalf of a container process that cannot hold them.

import type { OutboundHandler } from "@cloudflare/containers";
import type { PocEnv } from "./env";

/**
 * Virtual hostnames the container speaks plain HTTP to.
 *
 * The container holds no binding object at all -- confirmed in
 * `docs/cloudflare-deploy-topology.md` §6. It issues `GET http://cf-kv.internal/<key>`
 * and an outbound handler running in the Workers runtime, *outside* the sandbox,
 * performs the real `env.POC_KV.get(key)`. That is why no Cloudflare SDK and no
 * API token ever enters the container image.
 */
export const SHIM_HOSTS = {
  /** Bindingless liveness probe: answers "is outbound interception installed?". */
  selftest: "cf-selftest.internal",
  /** The real binding probe: answers "does the container actually reach a binding?". */
  kv: "cf-kv.internal",
} as const;

/** Body returned by the self-test handler; asserted verbatim by runbook step P7a. */
export const SELFTEST_BODY = "outbound-intercept-ok";

/**
 * The handler table.
 *
 * Every failure path returns a *distinct* status so a red probe names its own
 * cause instead of implying "the shim is broken". This matters more than it
 * looks: P7 is the only step that empirically backs §6's bindings-beat-REST
 * decision, so a misconfiguration that read as a platform verdict would corrupt
 * the recommendation.
 */
export const OUTBOUND_BY_HOST: Record<string, OutboundHandler<PocEnv>> = {
  // P7a. Touches no binding, so it can only ever answer one question, and it
  // cannot fail for a binding reason.
  [SHIM_HOSTS.selftest]: () => new Response(SELFTEST_BODY, { status: 200 }),

  // P7b. Reaching *any* line in this function already proves interception works;
  // the statuses below then separate "binding missing" from "key missing" from
  // "read succeeded".
  [SHIM_HOSTS.kv]: async (request: Request, env: PocEnv) => {
    if (!env.POC_KV) {
      // `[[kv_namespaces]]` absent from wrangler.toml: a config gap, NOT a
      // platform gap. 501 rather than 500 so the runbook table can tell them
      // apart without reading logs.
      return new Response("POC_KV binding not declared", { status: 501 });
    }
    const key = new URL(request.url).pathname.slice(1);
    const value = await env.POC_KV.get(key);
    // Never `new Response(value)` directly: KV returns null on a miss, and
    // `new Response(null)` is a 200 with an empty body -- a miss would be
    // indistinguishable from a successful read of an empty value, which is
    // exactly the false-positive this probe exists to avoid.
    return value === null
      ? new Response(`kv miss for key: ${key}`, { status: 404 })
      : new Response(value, { status: 200 });
  },
};
