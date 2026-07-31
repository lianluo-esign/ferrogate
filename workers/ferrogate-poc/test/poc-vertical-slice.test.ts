// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the #424 PoC acceptance
// slice: a Worker booted in workerd proxying to the REAL `ferrogate` binary,
// asserting the three surfaces the issue names -- health, readiness (the
// control-plane/DB observable) and one proxied /v1/chat/completions.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { ORIGIN_TIMING_HEADER, POC_ROUTES } from "../src/origin";
import { POC_MODEL, POC_VIRTUAL_KEY, UPSTREAM_COMPLETION } from "./fixtures";

const BASE = "https://ferrogate-poc.test";

describe("#424 Containers PoC: Worker-fronted FerroGate origin", () => {
  it("declares exactly the routes this PoC claims to prove", () => {
    // Guards the claim, not the code: if a route is added to the Worker's
    // advertised surface without an assertion below, this goes red and the
    // author has to either assert it or drop it.
    expect([...POC_ROUTES]).toEqual(["/healthz", "/readyz", "/v1/chat/completions"]);
  });

  it("serves /healthz from the Pingora runtime through the Worker", async () => {
    const response = await SELF.fetch(`${BASE}/healthz`);
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    // `runtime` is the assertion that matters: it is emitted by the Pingora
    // ingress (crates/ferrogate-gateway/src/server/local.rs), so a Worker that
    // answered health checks itself could not produce it.
    expect(body.runtime).toBe("pingora");
    expect(body.service).toBe("ferrogate");
    expect(typeof body.version).toBe("string");
  });

  it("reports control-plane readiness on /readyz", async () => {
    const response = await SELF.fetch(`${BASE}/readyz`);
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      status: string;
      runtime: string;
      cluster: { ready: boolean; state_backend: string; readiness_reason: string };
    };
    expect(body.status).toBe("ready");
    expect(body.runtime).toBe("pingora");
    // Readiness is backend state, not a constant: the gateway reports the
    // control-plane backend it actually loaded from.
    expect(body.cluster.ready).toBe(true);
    expect(body.cluster.state_backend).toBe("local");
    expect(body.cluster.readiness_reason).toBe("state_loaded");
  });

  it("proxies /v1/chat/completions through Pingora to the stub upstream", async () => {
    const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${POC_VIRTUAL_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: POC_MODEL,
        messages: [{ role: "user", content: "ping" }],
      }),
    });
    expect(response.status).toBe(200);

    const body = (await response.json()) as typeof UPSTREAM_COMPLETION;
    expect(body.object).toBe("chat.completion");
    // The load-bearing assertion: these bytes exist only in the Node stub
    // upstream, so reaching them proves Worker -> Pingora -> upstream end to
    // end. A gateway that short-circuited or fabricated a reply fails here.
    expect(body.choices[0]?.message?.content).toBe(
      UPSTREAM_COMPLETION.choices[0].message.content,
    );
    expect(body.id).toBe(UPSTREAM_COMPLETION.id);
    expect(body.usage.total_tokens).toBe(UPSTREAM_COMPLETION.usage.total_tokens);
  });

  it("lets the origin, not the Worker, reject an unauthenticated inference call", async () => {
    const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: POC_MODEL,
        messages: [{ role: "user", content: "ping" }],
      }),
    });
    // 401 from FerroGate's own auth. The PoC Worker is pure transport by
    // design, so a 401 here also proves it did not silently allow the call.
    expect(response.status).toBe(401);
    // Present only because the response transited the Worker's forwarding path.
    expect(response.headers.get(ORIGIN_TIMING_HEADER)).not.toBeNull();
  });

  it("records the origin round trip that runbook step P8 reads", async () => {
    const response = await SELF.fetch(`${BASE}/healthz`);
    const elapsed = Number(response.headers.get(ORIGIN_TIMING_HEADER));
    expect(Number.isInteger(elapsed)).toBe(true);
    expect(elapsed).toBeGreaterThanOrEqual(0);
    // Deliberately no upper bound: this harness measures a loopback hop, which
    // says nothing about the Worker->DO->container hop on Cloudflare. Asserting
    // a threshold here would dress a local number up as a platform figure --
    // the exact substitution docs/cloudflare-deploy-topology.md §6 refuses to
    // make. What is proven is that the instrument works.
  });
});
