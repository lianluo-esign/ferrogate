// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway. TEST-GATE suite for issue #475
//   acceptance box 5 — "a test proves the credential does not appear in logs, run events,
//   or agent memory".
//
//   WHY THIS FILE EXISTS ALONGSIDE test/git-credential.test.ts. The shipped no-leak
//   assertions are not falsifiable:
//
//     * Rust `no_broker_type_can_render_key_material` renders types that HAVE NO FIELD a
//       token could occupy. Its own doc-comment concedes "it cannot fail today".
//     * The Worker's `records a material-free audit row for a denied callback` asserts a
//       token is absent from an audit surface for a run where NO TOKEN WAS EVER MINTED.
//       Deleting the protection cannot turn it red, because the protected value does not
//       exist in that scenario.
//
//   So this suite puts a REAL token into the one place the system genuinely holds one —
//   `BrokerRunRecord.outstanding.token` in the run's Durable Object — and then reads back
//   every surface a token could escape through, asserting the secret's bytes are absent in
//   EVERY plausible encoding (raw, lower/upper hex, base64, base64url, decimal byte list,
//   percent-encoding, JSON-escaped, and every >=8-char substring of the entropy body).
//
//   MUTATION-PROVEN. Each assertion here was watched go RED against a deliberate break of
//   the protection it covers, then GREEN again after restore. See the gate report.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";

import {
  brokerAudit,
  brokerAudience,
  brokerAuthorize,
  brokerClose,
  brokerRecordMint,
  brokerRegister,
  capabilityFingerprint,
} from "../src/git-credential";
import type {
  BrokerGrantRecord,
  BrokerRunRecord,
  GitCredentialHost,
} from "../src/git-credential";
import type { AgentGateway, Env } from "../src/index";

const CONTROL_TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";
const NOW = 1_800_000_000;

/**
 * A GitHub App installation token in GitHub's documented shape. The `ghs_` prefix is
 * deliberately NOT what the assertions key on — a redaction that only strips a known
 * prefix would pass a prefix-only test — so ENTROPY below is checked independently.
 */
const TOKEN = "ghs_16C7e42F292c6912E7710c838347Ae178B4a";
/** The token minus its provider prefix: the part a partial redaction would leave behind. */
const ENTROPY = TOKEN.slice("ghs_".length);

function hex(value: string, upper = false): string {
  const rendered = [...new TextEncoder().encode(value)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return upper ? rendered.toUpperCase() : rendered;
}

function b64(value: string): string {
  return btoa(value);
}

function decimalBytes(value: string, separator: string): string {
  return [...new TextEncoder().encode(value)].join(separator);
}

/**
 * Every encoding the token could plausibly survive into a record in. A surface is only
 * "material-free" if NONE of these appears.
 */
function encodings(): { label: string; needle: string }[] {
  return [
    { label: "raw", needle: TOKEN },
    { label: "raw/lowercase", needle: TOKEN.toLowerCase() },
    { label: "raw/uppercase", needle: TOKEN.toUpperCase() },
    { label: "entropy-body (prefix stripped)", needle: ENTROPY },
    { label: "hex/lower", needle: hex(TOKEN) },
    { label: "hex/upper", needle: hex(TOKEN, true) },
    { label: "hex/lower entropy", needle: hex(ENTROPY) },
    { label: "base64", needle: b64(TOKEN) },
    { label: "base64/entropy", needle: b64(ENTROPY) },
    { label: "base64url", needle: b64(TOKEN).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") },
    { label: "decimal bytes, comma", needle: decimalBytes(TOKEN, ",") },
    { label: "decimal bytes, space", needle: decimalBytes(TOKEN, " ") },
    { label: "percent-encoded", needle: encodeURIComponent(TOKEN) },
    { label: "JSON-escaped", needle: JSON.stringify(TOKEN).slice(1, -1) },
  ];
}

/**
 * Assert `rendered` contains the token in no encoding, and no long substring of its
 * entropy body either — which catches a truncating "redaction" that keeps a usable
 * prefix, and a surface that splits the token across fields.
 */
function expectNoCredentialMaterial(rendered: string, what: string): void {
  const haystack = rendered.toLowerCase();
  for (const { label, needle } of encodings()) {
    expect(
      haystack.includes(needle.toLowerCase()),
      `${what} leaked the credential as ${label}`,
    ).toBe(false);
  }
  // Any 8-char window of the entropy body is already a distinguishing leak.
  for (let i = 0; i + 8 <= ENTROPY.length; i++) {
    expect(
      haystack.includes(ENTROPY.slice(i, i + 8).toLowerCase()),
      `${what} leaked an 8-char window of the credential at offset ${i}`,
    ).toBe(false);
  }
}

function grantFixture(overrides: Partial<BrokerGrantRecord> = {}): BrokerGrantRecord {
  return {
    tenantId: "tenant-a",
    runId: "run-1",
    grantId: "grant-1",
    repoId: "github:github.com/acme/app",
    host: "github.com",
    namespace: "acme",
    name: "app",
    installationId: 4242,
    permissions: { contents: "read", metadata: "read" },
    writeCapable: false,
    expiresAtUnix: NOW + 900,
    delivery: "brokered_per_operation",
    credentialFingerprint: "sha256:deadbeef",
    ...overrides,
  };
}

function callbackFixture(overrides: Record<string, unknown> = {}) {
  return {
    runId: "run-1",
    grantId: "grant-1",
    operation: "fetch",
    query: { protocol: "https", host: "github.com", path: "acme/app.git" },
    ...overrides,
  };
}

class FakeHost implements GitCredentialHost {
  record: BrokerRunRecord | undefined;
  constructor(readonly name: string) {}
  async brokerRecordGet(): Promise<BrokerRunRecord | undefined> {
    return this.record ? structuredClone(this.record) : undefined;
  }
  async brokerRecordPut(record: BrokerRunRecord): Promise<void> {
    this.record = structuredClone(record);
  }
  async brokerRecordDelete(): Promise<void> {
    this.record = undefined;
  }
}

/** Seed a run whose Durable Object holds a LIVE outstanding token. */
async function seedWithOutstandingToken(host: FakeHost, capability: string) {
  const grant = grantFixture({ runId: host.name });
  const audience = brokerAudience(grant.tenantId, grant.runId);
  const registered = await brokerRegister(host, {
    grant,
    capabilityFingerprint: await capabilityFingerprint(audience, capability),
  });
  expect(registered.ok).toBe(true);
  const authorized = await brokerAuthorize(host, callbackFixture({ runId: host.name }), capability, NOW);
  expect(authorized.ok && authorized.decision).toBe("approve");
  if (!authorized.ok || !authorized.mint) throw new Error("fixture: expected an approval");
  await brokerRecordMint(host, authorized.mint.operationId, TOKEN, NOW + 3600);
  // The premise of every assertion below: the token really is held.
  expect(host.record?.outstanding?.token).toBe(TOKEN);
  return grant;
}

function gateway(runId: string): DurableObjectStub<AgentGateway> {
  const ns = (env as unknown as Env).AGENT_GATEWAY as DurableObjectNamespace<AgentGateway>;
  return ns.get(ns.idFromName(runId));
}

describe("#475 box 5 — a held credential reaches no readable surface", () => {
  it("the audit surface stays material-free while the token IS outstanding", async () => {
    const host = new FakeHost("run-leak-audit");
    await seedWithOutstandingToken(host, "cap-leak-1");

    const audited = await brokerAudit(host);
    expect(audited.ok).toBe(true);
    // The premise again, from the other side: the record under this audit call holds it.
    expect(host.record?.outstanding?.token).toBe(TOKEN);
    expectNoCredentialMaterial(JSON.stringify(audited), "brokerAudit()");
  });

  it("an approval decision carries mint PARAMETERS, never key material", async () => {
    const host = new FakeHost("run-leak-decision");
    await seedWithOutstandingToken(host, "cap-leak-2");
    // A second callback: this is the one that supersedes, i.e. the one code path that
    // legitimately moves the previous token — it must move it to the ROUTE, and the
    // decision/audit halves must stay clean.
    const next = await brokerAuthorize(
      host,
      callbackFixture({ runId: host.name }),
      "cap-leak-2",
      NOW + 1,
    );
    expect(next.ok).toBe(true);
    if (!next.ok) return;
    // Documented and deliberate: the superseded token goes back so the route can revoke
    // it. That is the ONLY field allowed to carry material, and it is never persisted or
    // returned to a caller.
    expect(next.supersededToken).toBe(TOKEN);
    expectNoCredentialMaterial(JSON.stringify(next.audit), "the audit row");
    expectNoCredentialMaterial(JSON.stringify(next.mint), "the mint parameters");
    expectNoCredentialMaterial(JSON.stringify(next.code) + JSON.stringify(next.detail), "the decision");
    // ...and it is dropped from the record, so it cannot be surrendered twice.
    expect(host.record?.outstanding).toBeUndefined();
  });

  it("close surrenders the token to the caller but leaves no persisted copy", async () => {
    const host = new FakeHost("run-leak-close");
    await seedWithOutstandingToken(host, "cap-leak-3");
    const closed = await brokerClose(host);
    expect(closed.ok && closed.outstandingToken).toBe(TOKEN);
    expect(host.record).toBeUndefined();
    expectNoCredentialMaterial(JSON.stringify(host.record ?? null), "the persisted record after close");
  });
});

describe("#475 box 5 — end to end through the real Durable Object and routes", () => {
  const runId = "run-leak-e2e";
  const capability = "run-leak-e2e-capability-0123456789";

  it("holds a real token in the run's DO, then finds it on no route the control plane or the container can read", async () => {
    const register = await SELF.fetch(`${BASE}/git-credential/register`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CONTROL_TOKEN}` },
      body: JSON.stringify({
        grant: grantFixture({ runId }),
        capabilityFingerprint: await capabilityFingerprint(brokerAudience("tenant-a", runId), capability),
      }),
    });
    expect(register.status).toBe(200);

    // Drive a REAL approved callback through the route. The mint itself cannot succeed
    // offline (GITHUB_API_BASE_URL is api.github.invalid and the key is a placeholder),
    // so the route answers 502 — which is itself the assertion below: the failure answer
    // must not carry a GitHub response body.
    const approved = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
      body: JSON.stringify(callbackFixture({ runId })),
    });
    expect(approved.status).toBe(502);
    const approvedBody = await approved.text();
    expect(approvedBody).not.toContain("password");
    expectNoCredentialMaterial(approvedBody, "the 502 mint-failure response");

    // Now plant a real outstanding token in the run's ACTUAL Durable Object, exactly as a
    // successful mint would have.
    const recorded = await runInDurableObject(gateway(runId), async (agent) =>
      agent.gitCredentialRecordMint("op-1", TOKEN, NOW + 3600),
    );
    expect(recorded.ok).toBe(true);
    // Premise: the DO really holds it now.
    const held = await runInDurableObject(gateway(runId), async (agent) => {
      const record = await agent.brokerRecordGet();
      return record?.outstanding?.token;
    });
    expect(held).toBe(TOKEN);

    // 1. The control-plane audit route — the "run events" surface.
    const audit = await SELF.fetch(`${BASE}/git-credential/audit?runId=${runId}`, {
      headers: { authorization: `Bearer ${CONTROL_TOKEN}` },
    });
    expect(audit.status).toBe(200);
    expectNoCredentialMaterial(await audit.text(), "GET /git-credential/audit");

    // 2. The #427 agent-memory surfaces, all three layers.
    for (const [path, init] of [
      [`${BASE}/memory/state/get?runId=${runId}`, { method: "GET" }],
      [`${BASE}/memory/chat/get?runId=${runId}`, { method: "GET" }],
    ] as const) {
      const res = await SELF.fetch(path, {
        ...(init as RequestInit),
        headers: { authorization: `Bearer ${CONTROL_TOKEN}` },
      });
      expectNoCredentialMaterial(await res.text(), `agent memory: ${path}`);
    }
    const memory = await runInDurableObject(gateway(runId), async (agent) => ({
      state: await agent.memoryStateGet(),
      chat: await agent.memoryChatHistoryGet(),
    }));
    expectNoCredentialMaterial(JSON.stringify(memory), "agent memory (DO, layers 1 and 3)");

    // 3. The container-reachable callback route: a container that asks again must not be
    //    handed the outstanding token back in any field.
    const container = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
      body: JSON.stringify(
        callbackFixture({ runId, query: { protocol: "https", host: "github.com", path: "attacker/exfil" } }),
      ),
    });
    expect(container.status).toBe(403);
    expectNoCredentialMaterial(await container.text(), "POST /git-credential/get (denied)");

    // 4. Run finalize. The revoke answer reports an OUTCOME, never the token it used.
    const revoked = await SELF.fetch(`${BASE}/git-credential/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CONTROL_TOKEN}` },
      body: JSON.stringify({ runId }),
    });
    const revokedBody = await revoked.text();
    expectNoCredentialMaterial(revokedBody, "POST /git-credential/revoke");
    // NOTE: the status is deliberately NOT asserted here. What it *should* be is the
    // subject of test/git-credential-revocation.test.ts, which reproduces the box 3
    // defect: one denied callback before finalize makes this answer 200
    // `already_expired` even though the token was never confirmed revoked.

    // 5. And the grant is gone regardless, so no further token can be minted for this run.
    const afterClose = await runInDurableObject(gateway(runId), async (agent) =>
      agent.brokerRecordGet(),
    );
    expect(afterClose).toBeUndefined();
  });
});
