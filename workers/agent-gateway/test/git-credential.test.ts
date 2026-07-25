// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Worker-side tests for the brokered per-operation git credential route
//   (issue #475), written against the code-review bounce. The two load-bearing ones
//   are `refuses a grant supplied by the caller` (the security hole: the route used
//   to authorize `body.grant` against `body`, so any caller could mint a live
//   contents:write token for any repo) and `refuses the gateway control token`
//   (the container must not hold the credential that opens /control, /container,
//   /memory and /schedule). Both fail against the pre-rework route.
//
//   The mint path is NOT exercised here: vitest-pool-workers 0.18 exposes no
//   outbound fetch mock, so a successful mint would need a live GitHub. The
//   authorization, budget, audit and revocation-handle behaviour behind it is
//   covered at unit level against an in-memory `GitCredentialHost`.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

import {
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

const CONTROL_TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";
const NOW = 1_800_000_000;

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

/** In-memory `GitCredentialHost`; clones on the way in and out like DO storage. */
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

async function seed(
  host: FakeHost,
  capability: string,
  overrides: Partial<BrokerGrantRecord> = {},
) {
  const grant = grantFixture({ runId: host.name, ...overrides });
  const audience = brokerAudience(grant.tenantId, grant.runId);
  const result = await brokerRegister(host, {
    grant,
    capabilityFingerprint: await capabilityFingerprint(audience, capability),
  });
  expect(result.ok).toBe(true);
  return grant;
}

// ---------------------------------------------------------------------------
// Route level: who can reach the credential, and with what
// ---------------------------------------------------------------------------

describe("/git-credential route authorization", () => {
  it("refuses a grant supplied by the caller (the #475 review's blocker 2)", async () => {
    // Exactly the request the review demonstrated: a fabricated grant naming a
    // repo the caller has no claim to, with contents:write and a far-future
    // expiry. Against the pre-rework route this returned a LIVE installation
    // token. The grant now lives only in the run's Durable Object, so a body
    // grant is not read at all and the callback has no capability behind it.
    const res = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer forged" },
      body: JSON.stringify({
        ...callbackFixture({ runId: "victim-run", query: { protocol: "https", host: "github.com", path: "victim/private-repo" } }),
        grant: grantFixture({
          runId: "victim-run",
          namespace: "victim",
          name: "private-repo",
          permissions: { contents: "write", pull_requests: "write" },
          writeCapable: true,
          expiresAtUnix: 4_000_000_000,
        }),
      }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ error: "unauthorized" });
    expect(JSON.stringify(body)).not.toContain("password");
  });

  it("refuses the gateway control token on the callback path (blocker 3)", async () => {
    // GATEWAY_CONTROL_TOKEN opens /control, /container, /memory and /schedule.
    // The untrusted container must never be able to use it here, even for a run
    // that IS registered.
    const runId = "run-control-token";
    const register = await SELF.fetch(`${BASE}/git-credential/register`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CONTROL_TOKEN}` },
      body: JSON.stringify({
        grant: grantFixture({ runId }),
        capabilityFingerprint: await capabilityFingerprint(
          brokerAudience("tenant-a", runId),
          "the-real-run-capability",
        ),
      }),
    });
    expect(register.status).toBe(200);

    const res = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CONTROL_TOKEN}` },
      body: JSON.stringify(callbackFixture({ runId })),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "unauthorized" });
  });

  it("answers malformed JSON with 400, not an uncaught Worker exception", async () => {
    const res = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer whatever" },
      body: "{ not json",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_json" });
  });

  it("gates register/revoke/audit on the control token", async () => {
    for (const [path, init] of [
      [`${BASE}/git-credential/register`, { method: "POST", body: "{}" }],
      [`${BASE}/git-credential/revoke`, { method: "POST", body: "{}" }],
      [`${BASE}/git-credential/audit?runId=run-1`, { method: "GET" }],
    ] as const) {
      const res = await SELF.fetch(path, init as RequestInit);
      expect([401, 403]).toContain(res.status);
    }
  });

  it("records a material-free audit row for a denied callback, and revocation closes the run", async () => {
    const runId = "run-audited";
    const capability = "run-audited-capability";
    const register = await SELF.fetch(`${BASE}/git-credential/register`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CONTROL_TOKEN}` },
      body: JSON.stringify({
        grant: grantFixture({ runId }),
        capabilityFingerprint: await capabilityFingerprint(
          brokerAudience("tenant-a", runId),
          capability,
        ),
      }),
    });
    expect(register.status).toBe(200);
    expect(await register.json()).toMatchObject({
      registered: true,
      audience: `ferrogate:git-credential:tenant-a:${runId}`,
    });

    // A callback with the right capability but the wrong repo: denied, counted,
    // and audited. "Every use is counted and logged" has to be true of the path
    // that actually runs, which was the review's `Also fix` item.
    const denied = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
      body: JSON.stringify(
        callbackFixture({
          runId,
          query: { protocol: "https", host: "github.com", path: "attacker/exfil" },
        }),
      ),
    });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: "repo_not_granted" });

    const audit = await SELF.fetch(`${BASE}/git-credential/audit?runId=${runId}`, {
      headers: { authorization: `Bearer ${CONTROL_TOKEN}` },
    });
    expect(audit.status).toBe(200);
    const audited = (await audit.json()) as {
      rows: Record<string, unknown>[];
      operationsUsed: number;
    };
    expect(audited.operationsUsed).toBe(1);
    expect(audited.rows).toHaveLength(1);
    expect(audited.rows[0]).toMatchObject({
      tenantId: "tenant-a",
      runId,
      decisionCode: "repo_not_granted",
      sequence: 1,
    });
    // The audit surface is the one place a token could plausibly leak into a
    // record the control plane reads back. It cannot: there is no field for it.
    const rendered = JSON.stringify(audited);
    for (const material of ["ghs_", "ghp_", "github_pat_", "password", "BEGIN PRIVATE KEY"]) {
      expect(rendered).not.toContain(material);
    }

    // Run finalize: revocation is PERFORMED, not named. Nothing was minted for
    // this run, so no live credential remains; the grant is deleted either way.
    const revoked = await SELF.fetch(`${BASE}/git-credential/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CONTROL_TOKEN}` },
      body: JSON.stringify({ runId }),
    });
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ outcome: "already_expired", operationsUsed: 1 });

    // After close, the capability buys nothing: there is no grant to serve.
    const afterClose = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
      body: JSON.stringify(callbackFixture({ runId })),
    });
    expect(afterClose.status).toBe(403);
    expect(await afterClose.json()).toMatchObject({ error: "unauthorized" });
  });
});

// ---------------------------------------------------------------------------
// Unit level: the authoritative Durable Object verbs
// ---------------------------------------------------------------------------

describe("broker Durable Object verbs", () => {
  it("derives the capability fingerprint exactly as Rust does", async () => {
    // The same literal is pinned in
    // `crates/ferrogate-runtime/src/coding_agent/credential_broker_test.rs`
    // (`capability_fingerprint_matches_the_worker_derivation`). If the two
    // derivations ever drift, no capability verifies and the whole brokered
    // path fails closed — so the vector is asserted on both sides.
    expect(brokerAudience("tenant-a", "run-1")).toBe("ferrogate:git-credential:tenant-a:run-1");
    expect(
      await capabilityFingerprint(
        "ferrogate:git-credential:tenant-a:run-1",
        "0123456789abcdef0123456789abcdef",
      ),
    ).toBe("ee84134bacdd989b5ebaa6cabb4e28b5d73279590d78de0f63d94019ec443719");
  });

  it("approves a callback that matches the registered grant", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const result = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.decision).toBe("approve");
    expect(result.mint).toMatchObject({ installationId: 4242, repository: "app" });
    // Never longer than the grant, whatever GitHub's fixed hour says.
    expect(result.mint?.expiresAtUnix).toBe(NOW + 900);
    expect(result.audit.sequence).toBe(1);
  });

  it("rejects a capability minted for a different run or tenant (the audience is load-bearing)", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    // Same secret string, different audience: the fingerprint mixes the
    // audience in, so this is not the same capability.
    const foreign = await capabilityFingerprint(
      brokerAudience("tenant-b", "run-1"),
      "cap-1",
    );
    expect(foreign).not.toBe(host.record?.capabilityFingerprint);
    const wrongSecret = await brokerAuthorize(host, callbackFixture(), "cap-2", NOW);
    expect(wrongSecret).toMatchObject({ ok: false, code: "unauthorized" });
  });

  it("charges denials against the budget, like the Rust broker does", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    for (let i = 0; i < 3; i++) {
      await brokerAuthorize(host, callbackFixture({ grantId: "not-the-grant" }), "cap-1", NOW);
    }
    expect(host.record?.operationsUsed).toBe(3);
    const next = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(next.ok && next.audit.sequence).toBe(4);
  });

  it("exhausts the 32-operation budget", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    for (let i = 0; i < 32; i++) {
      const step = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
      expect(step.ok && step.decision).toBe("approve");
    }
    const over = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(over.ok && over.code).toBe("operation_budget_exhausted");
  });

  it("denies a non-brokered delivery (the tenth deny code the TS side used to be missing)", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1", { delivery: "ephemeral_file" });
    const result = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(result.ok && result.code).toBe("delivery_not_brokered");
  });

  it("surrenders the outstanding token at close and deletes the grant", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const authorized = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(authorized.ok).toBe(true);
    if (!authorized.ok || !authorized.mint) return;
    await brokerRecordMint(host, authorized.mint.operationId, "ghs_pretend", NOW + 3600);

    const closed = await brokerClose(host);
    expect(closed).toMatchObject({ ok: true, outstandingToken: "ghs_pretend", operationsUsed: 1 });
    expect(host.record).toBeUndefined();
    // Idempotent: run finalize runs on the success path AND the failure path.
    expect(await brokerClose(host)).toMatchObject({ ok: true, outstandingToken: null });
  });

  it("supersedes the previous operation's token so it can be revoked immediately", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const first = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(first.ok).toBe(true);
    if (!first.ok || !first.mint) return;
    await brokerRecordMint(host, first.mint.operationId, "ghs_first", NOW + 3600);
    const second = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW + 1);
    expect(second.ok && second.supersededToken).toBe("ghs_first");
    // Handed to the route for revocation and dropped from the record, so it
    // cannot be surrendered twice.
    expect(host.record?.outstanding).toBeUndefined();
  });

  it("refuses a registration that does not address its own run", async () => {
    const host = new FakeHost("run-1");
    const result = await brokerRegister(host, {
      grant: grantFixture({ runId: "some-other-run" }),
      capabilityFingerprint: await capabilityFingerprint("aud", "cap"),
    });
    expect(result).toMatchObject({ ok: false, code: "invalid_registration" });
  });
});
