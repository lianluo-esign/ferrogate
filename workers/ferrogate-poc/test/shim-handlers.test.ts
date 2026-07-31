// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the #424 container->Worker
// shim handlers driven in workerd against a REAL KV binding. Covers the half of
// runbook step P7 that does not require Cloudflare: that the handlers resolve a
// binding and that their status discrimination is self-diagnosing.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { SELFTEST_BODY, SHIM_HOSTS } from "../src/shim";

const BASE = "https://ferrogate-poc.test";

function shimUrl(host: string, path: string): string {
  return `${BASE}/__shim/${host}${path}`;
}

describe("#424 §6 shim: outboundByHost handlers", () => {
  beforeAll(async () => {
    await (env as { POC_KV: KVNamespace }).POC_KV.put("hello", "world");
  });

  it("answers the bindingless self-test", async () => {
    const response = await SELF.fetch(shimUrl(SHIM_HOSTS.selftest, "/ping"));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(SELFTEST_BODY);
  });

  it("reads a real KV binding on the container's behalf", async () => {
    const response = await SELF.fetch(shimUrl(SHIM_HOSTS.kv, "/hello"));
    expect(response.status).toBe(200);
    // The value was written through the binding above, so this is a genuine
    // Worker-side binding resolution, not a canned string.
    expect(await response.text()).toBe("world");
  });

  it("distinguishes a KV miss from a successful read of an empty value", async () => {
    await (env as { POC_KV: KVNamespace }).POC_KV.put("empty", "");

    const miss = await SELF.fetch(shimUrl(SHIM_HOSTS.kv, "/absent"));
    expect(miss.status).toBe(404);
    expect(await miss.text()).toBe("kv miss for key: absent");

    const empty = await SELF.fetch(shimUrl(SHIM_HOSTS.kv, "/empty"));
    // This is the assertion the handler's `value === null` check exists for:
    // `new Response(null)` would also be a 200 with an empty body, so without
    // the explicit null test a miss and an empty value would be identical and
    // step P7b could report a pass it had not earned.
    expect(empty.status).toBe(200);
    expect(await empty.text()).toBe("");
  });

  it("returns 404, not a handler response, for an unregistered virtual host", async () => {
    const response = await SELF.fetch(shimUrl("cf-unregistered.internal", "/x"));
    expect(response.status).toBe(404);
  });
});
