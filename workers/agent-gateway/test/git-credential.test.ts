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
//
//   The `#501` block at the bottom is the type-confusion half. Each load-bearing
//   assertion in it carries a `PINS …` / `REDS AGAINST …` comment naming the line
//   of src/git-credential.ts it holds and the mutation of that line it is built to
//   catch. The trap it exists to avoid is asserting the response CODE only: the
//   original defect produced no code either — it produced an uncaught exception —
//   so a code-only assertion holds nothing, and a fix that returned 400 from the
//   route while still skipping the charge would pass it. So the block asserts what
//   was PERSISTED, read back after the call: `operationsUsed`, and the audit rows.
//
//   NOT MUTATION-VERIFIED BY THE AUTHOR. The mutations are described, not run:
//   this slice was written under a no-test-execution directive. Running them is
//   the test agent's job, and the list is in the commit body.

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
  handleGitCredential,
} from "../src/git-credential";
import type {
  BrokerGrantRecord,
  BrokerRunRecord,
  GitCredentialHost,
} from "../src/git-credential";
import type { Env } from "../src/index";

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

// ---------------------------------------------------------------------------
// Issue #501: the type boundary, and what a malformed callback COSTS
// ---------------------------------------------------------------------------

/** Register a run over the real route and hand back its capability. */
async function registerOverRoute(runId: string, capability: string) {
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
}

/** What the control plane can read back about a run: the charge AND the rows. */
async function auditOverRoute(runId: string) {
  const res = await SELF.fetch(`${BASE}/git-credential/audit?runId=${runId}`, {
    headers: { authorization: `Bearer ${CONTROL_TOKEN}` },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as { rows: Record<string, unknown>[]; operationsUsed: number };
}

describe("#501 a type-confused callback is charged and audited, not thrown", () => {
  it("charges AND audits a numeric query.protocol instead of throwing out of the DO", async () => {
    // The issue's exact repro. `(123)?.toLowerCase` is `undefined`, and calling
    // it threw a TypeError between `record.operationsUsed = sequence` and
    // `brokerRecordPut`, so nothing was persisted: free and silent.
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const result = await brokerAuthorize(
      host,
      callbackFixture({ query: { protocol: 123, host: "github.com", path: "acme/app" } }),
      "cap-1",
      NOW,
    );
    // PINS `const problem = invalidCallback(callbackCandidate)` and its branch
    // in `brokerAuthorize`. REDS AGAINST: deleting the `invalidCallback` call
    // and restoring `callback.query?.protocol?.toLowerCase()` in
    // `authorizeCallback` — the promise no longer resolves at all, it rejects.
    expect(result).toMatchObject({ ok: false, code: "invalid_callback" });

    // The two assertions that hold the SECURITY property rather than the status
    // code. `FakeHost` clones on the way out of `brokerRecordGet`, so
    // `host.record` moves ONLY when `brokerRecordPut` is called: reading it back
    // proves persistence, not an in-memory mutation. That distinction is the
    // whole defect — the original throw left `operationsUsed` mutated on a clone
    // that was never written.
    //
    // PINS `record.operationsUsed = sequence` and the `await
    // host.brokerRecordPut(record)` inside the malformed branch. REDS AGAINST
    // either of: moving the assignment below the malformed early-return, or
    // deleting that branch's `brokerRecordPut`.
    expect(host.record?.operationsUsed).toBe(1);
    // PINS `if (presentedOp) append(row(presentedOp, code))`. REDS AGAINST
    // deleting the `append`, which is exactly what the throw used to skip.
    expect(host.record?.audit).toHaveLength(1);
    expect(host.record?.audit[0]).toMatchObject({
      decisionCode: "invalid_callback",
      operation: "fetch",
      sequence: 1,
      tenantId: "tenant-a",
      runId: "run-1",
    });
    // And the charge is durable across the next callback: the sequence advanced.
    // REDS AGAINST a "fix" that returns the right code but rolls the charge back.
    const next = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(next.ok && next.audit.sequence).toBe(2);
  });

  it("does NOT charge a probe that failed the capability check", async () => {
    // The other side of the budget rule, and the reason the charge sits AFTER
    // `timingSafeEqual` rather than at the top of the method: if an unverified
    // caller could charge, anyone who guessed a run id could burn that run's 32
    // operations and strand a real agent. A malformed body makes no difference —
    // the capability is checked first, so the body is never even looked at.
    //
    // PINS the ordering of the `timingSafeEqual` early-return and
    // `record.operationsUsed = sequence`. REDS AGAINST hoisting the charge (or
    // the `brokerRecordPut`) above the capability check, which is the tempting
    // over-correction to #501.
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    for (const body of [callbackFixture(), { query: { protocol: 123 } }, null]) {
      await expect(brokerAuthorize(host, body, "wrong-capability", NOW)).resolves.toMatchObject({
        ok: false,
        code: "unauthorized",
      });
    }
    expect(host.record?.operationsUsed).toBe(0);
    expect(host.record?.audit).toHaveLength(0);
  });

  it("is total over every field the authorization touches, not just protocol", async () => {
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const confusions: Record<string, unknown>[] = [
      { query: { protocol: "https", host: 7, path: "acme/app" } },
      { query: { protocol: "https", host: "github.com", path: 7 } },
      { query: { protocol: "https", host: "github.com", path: "acme/app", username: 7 } },
      { query: "acme/app" },
      { query: ["https", "github.com"] },
      { query: null },
      { runId: 123 },
      { grantId: { $ne: null } },
      { operation: ["fetch"] },
    ];
    // PINS every `typeof … !== "string"` line in `invalidCallback`, one per
    // entry. REDS AGAINST relaxing any one of them back to an optional-chain
    // guard: `resolves` is the load-bearing word, because the pre-fix failure
    // mode is a REJECTED promise, and `operationsUsed` advancing by exactly one
    // per entry is what stops "returns 400 by throwing earlier" from passing.
    for (const [i, confusion] of confusions.entries()) {
      await expect(
        brokerAuthorize(host, callbackFixture(confusion), "cap-1", NOW),
      ).resolves.toMatchObject({ ok: false });
      expect(host.record?.operationsUsed).toBe(i + 1);
    }
    // A non-object body cannot even carry a capability check result but must
    // still not throw.
    for (const body of [null, undefined, 42, "callback", ["callback"]]) {
      await expect(brokerAuthorize(host, body, "cap-1", NOW)).resolves.toMatchObject({
        ok: false,
        code: "invalid_callback",
      });
    }
  });

  it("charges a body that names no operation, and writes NO row rather than a fabricated one", async () => {
    // `operation` is required and is not coerced: an audit row asserting
    // `fetch` for a body that never said `fetch` is a wrong value, and a wrong
    // value in the audit trail is worse than an absent row. So this is the
    // third path — charged, unaudited — and the gap in `sequence` is its trace.
    for (const operation of [undefined, "FETCH", "clone", 1, null]) {
      const host = new FakeHost("run-1");
      await seed(host, "cap-1");
      const result = await brokerAuthorize(host, callbackFixture({ operation }), "cap-1", NOW);
      // PINS `callback.operation !== "fetch" && callback.operation !== "push"`.
      // REDS AGAINST restoring the old `=== "push" ? "push" : "fetch"` coercion,
      // under which a body naming no operation was APPROVED as a fetch.
      expect(result).toMatchObject({ ok: false, code: "invalid_callback" });
      expect(host.record?.operationsUsed).toBe(1);
      // PINS the `if (presentedOp)` GUARD on the append. REDS AGAINST making the
      // append unconditional with a `presentedOp ?? "fetch"` default, which would
      // put an operation the caller never sent into the audit trail as fact.
      expect(host.record?.audit).toHaveLength(0);
      // The reconciliation rule the doc states: the charge outruns the rows,
      // and the NEXT row's sequence is where the missing one would have been.
      const next = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
      expect(next.ok && next.audit.sequence).toBe(2);
      expect(host.record?.audit).toHaveLength(1);
    }
  });

  it("lets an explicit null path through to path_missing, not invalid_callback", async () => {
    // The one place tightening the validator would have been WRONG, and the
    // reason is on the Rust side: `GitCredentialQuery` declares
    // `path: Option<String>` with `#[serde(default)]` and no
    // `skip_serializing_if`, so a serialized pathless query is `"path": null`
    // on the wire — an absent key is not what arrives. A pathless callback is
    // the single most likely real misconfiguration (`credential.useHttpPath`
    // unset), and `path_missing` is the deny code that names its fix.
    // Answering `invalid_callback` instead would charge and audit the same
    // budget unit while telling the operator nothing.
    //
    // The safety that rejecting null would have bought is bought by the type:
    // `CredentialQuery.path` is `string | null`, so `?? ""` is legitimate and a
    // future `query.path.trim()` does not compile. That half is held by tsc,
    // not by this test, and is named here so the next reader does not "tidy"
    // the `| null` away.
    //
    // PINS `value !== undefined && value !== null && typeof value !== "string"`
    // in `invalidCallback`. REDS AGAINST dropping the `value !== null` clause.
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const pathless = await brokerAuthorize(
      host,
      callbackFixture({ query: { protocol: "https", host: "github.com", path: null } }),
      "cap-1",
      NOW,
    );
    expect(pathless.ok && pathless.code).toBe("path_missing");
    // Still charged and still audited — under the RIGHT code, which is the
    // whole point of routing it here instead of to the validator.
    expect(host.record?.operationsUsed).toBe(1);
    expect(host.record?.audit).toHaveLength(1);
    expect(host.record?.audit[0]).toMatchObject({ decisionCode: "path_missing", sequence: 1 });

    // `username` is advisory and the authorization never reads it, so an
    // explicit null there is simply not an error.
    const approved = await brokerAuthorize(
      host,
      callbackFixture({
        query: { protocol: "https", host: "github.com", path: "acme/app", username: null },
      }),
      "cap-1",
      NOW,
    );
    expect(approved.ok && approved.decision).toBe("approve");

    // What DOES stay rejected is a non-string, non-null path: the `| null` in
    // the declared type widened it by exactly one value, not to `unknown`.
    const confused = await brokerAuthorize(
      host,
      callbackFixture({ query: { protocol: "https", host: "github.com", path: { $ne: null } } }),
      "cap-1",
      NOW,
    );
    expect(confused).toMatchObject({ ok: false, code: "invalid_callback" });
    expect(host.record?.operationsUsed).toBe(3);
  });

  it("REFUSES a malformed probe once the budget is spent, instead of charging it forever", async () => {
    // The cap lived only inside `authorizeCallback`, which the invalid branch
    // returns before, so `operation_budget_exhausted` was unreachable on the
    // one path that does not even have to be well-typed to reach it.
    const host = new FakeHost("run-1");
    await seed(host, "cap-1");
    const malformed = callbackFixture({
      query: { protocol: 123, host: "github.com", path: "acme/app" },
    });
    for (let i = 0; i < 32; i++) {
      expect(await brokerAuthorize(host, malformed, "cap-1", NOW)).toMatchObject({
        code: "invalid_callback",
      });
    }
    expect(host.record?.operationsUsed).toBe(32);
    // PINS `const exhausted = sequence > OPERATION_BUDGET` and the `code`/`detail`
    // it selects in the malformed branch. REDS AGAINST deleting those three
    // lines, which sends the 33rd probe back as `invalid_callback` forever.
    const over = await brokerAuthorize(host, malformed, "cap-1", NOW);
    expect(over).toMatchObject({ ok: false, code: "operation_budget_exhausted" });
    // And it is a refusal, not a relabelled acceptance: a WELL-FORMED callback
    // afterwards is refused for the same reason, and no token is mintable.
    const valid = await brokerAuthorize(host, callbackFixture(), "cap-1", NOW);
    expect(valid.ok && valid.code).toBe("operation_budget_exhausted");
    expect(valid.ok && valid.mint).toBeUndefined();
  });
});

describe("#501 at the route: 400, 413, 502 — never an uncaught Worker exception", () => {
  it("answers a type-confused body holding a VALID capability with a charged, audited 400", async () => {
    const runId = "run-501-confused";
    const capability = "run-501-confused-capability";
    await registerOverRoute(runId, capability);
    const res = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
      body: JSON.stringify(
        callbackFixture({
          runId,
          query: { protocol: 123, host: "github.com", path: "acme/app.git" },
        }),
      ),
    });
    // Before the fix this was an uncaught Worker exception (HTTP 500 / 1101).
    // PINS `const status = authorized.code === "invalid_callback" ? 400 : 403`.
    // REDS AGAINST collapsing that back to a blanket 403.
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ error: "invalid_callback" });
    expect(JSON.stringify(body)).not.toContain("password");

    // The half that is not a status code, and the reason a status-only
    // assertion would be vacuous here: a fix that returned 400 by refusing the
    // body at the ROUTE would satisfy everything above and still leave probing
    // free and silent. These three go through the real Durable Object and read
    // the charge back over the real control-plane route.
    //
    // PINS the same two lines as the unit test, across the DO boundary:
    // `record.operationsUsed = sequence`, and the malformed branch's
    // `brokerRecordPut` / `append`. REDS AGAINST moving the type check out of
    // `brokerAuthorize` and into the route.
    const audited = await auditOverRoute(runId);
    expect(audited.operationsUsed).toBe(1);
    expect(audited.rows).toHaveLength(1);
    expect(audited.rows[0]).toMatchObject({
      runId,
      decisionCode: "invalid_callback",
      operation: "fetch",
      sequence: 1,
    });
  });

  it("answers a body that names no run with a free but HONEST 400, spending neither other code", async () => {
    // A body naming no run cannot address a Durable Object, so a charge is
    // structurally impossible — the carve-out is documented rather than claimed
    // away. What it must not do is BORROW one of the two codes that mean
    // something: `run_mismatch` is a deny code the DO emits charged and audited,
    // and `invalid_callback` is the DO's code for "capability verified, body was
    // not, budget charged". `invalid_request` is the route's own vocabulary,
    // already used by `revoke` and `audit` for exactly this.
    //
    // PINS the `error: "invalid_request"` literal on the no-runId return in
    // `handleGitCredential`. REDS AGAINST either of the two tempting reuses.
    for (const body of [{}, { runId: 123 }, { runId: "  " }, { runId: null }, []]) {
      const res = await SELF.fetch(`${BASE}/git-credential/get`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer anything" },
        body: JSON.stringify(body),
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: "invalid_request" });
    }
    // With no capability presented at all it does not even get that far.
    // PINS the ORDER of the `presentedBearer` check and `parseJsonBody`. REDS
    // AGAINST moving the capability check back below the body parse, under
    // which this body answers 400 instead of 401.
    const anonymous = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({ error: "unauthorized" });
  });

  it("refuses an oversize callback BEFORE the DO RPC, so the residual throw class shrinks", async () => {
    // An oversize body throws at the RPC boundary — outside `brokerAuthorize`,
    // where no budget can be charged and no row written. The 502 catch would
    // hide it; the cap removes it.
    //
    // TWO sizes, because `parseJsonBody` has TWO guards and one size would let
    // a mutation of the second survive. 64 KiB exceeds `maxChars * 3`, so the
    // pre-read `content-length` guard fires first; 20 KiB does not (20 KiB of
    // ASCII is ~20 KB, well under the 48 KB byte bound) but does exceed
    // `maxChars` in characters, so ONLY the post-read `text.length` guard can
    // catch it.
    //
    // PINS `text.length > maxChars` (the 20 KiB case) and the pair of guards
    // together (the 64 KiB case). REDS AGAINST deleting the post-read check —
    // which is the one that actually bounds a chunked body, where no
    // `content-length` is declared at all.
    const runId = "run-501-oversize";
    const capability = "run-501-oversize-capability";
    await registerOverRoute(runId, capability);
    for (const pathChars of [20 * 1024, 64 * 1024]) {
      const res = await SELF.fetch(`${BASE}/git-credential/get`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
        body: JSON.stringify(
          callbackFixture({
            runId,
            query: { protocol: "https", host: "github.com", path: "a".repeat(pathChars) },
          }),
        ),
      });
      expect(res.status, `path of ${pathChars} chars`).toBe(413);
      expect(await res.json()).toMatchObject({ error: "body_too_large" });
    }
    // Refused BEFORE the RPC: the run's record was never touched. This is the
    // honest half of the carve-out, not a claim that the refusal is charged.
    expect(await auditOverRoute(runId)).toMatchObject({ operationsUsed: 0, rows: [] });

    // And the cap is a CAP, not a blanket refusal: a normal callback of the
    // same shape still reaches the Durable Object and is charged. Without this
    // line, `return tooLarge()` unconditionally would pass everything above.
    const ordinary = await SELF.fetch(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
      body: JSON.stringify(callbackFixture({ runId })),
    });
    expect(ordinary.status).not.toBe(413);
    expect((await auditOverRoute(runId)).operationsUsed).toBe(1);
  });

  it("turns a throw at the Durable Object RPC boundary into a typed 502, never a 1101", async () => {
    // The throw is injected at the AGENT_GATEWAY namespace, not inside a probe
    // Durable Object, for two reasons. It is the more faithful seam: nothing a
    // caller can post makes the production verb throw any more — that is the
    // fix — so the residual class this catch exists for is a throw AT or BEFORE
    // the RPC boundary (an RPC argument workerd refuses, a broken stub), which
    // is exactly here. And a real DO that throws by design also surfaces as an
    // unhandled rejection that fails the whole vitest run, which would buy a
    // weaker property at the price of a red suite.
    //
    // Everything else is the production route: a real `Request`, the real
    // `parseJsonBody`, the real `handleGitCredential`.
    const calls: string[] = [];
    const env = {
      GITHUB_APP_ID: "123456",
      GITHUB_APP_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----",
      AGENT_GATEWAY: {
        idFromName: (name: string) => ({ name }),
        get: () => ({
          // partyserver's `getServerByName` names the stub over `fetch` first.
          fetch: async () => new Response("ok"),
          gitCredentialAuthorize: async () => {
            calls.push("authorize");
            throw new Error('boom, quoting the body: {"protocol":123}');
          },
        }),
      },
    } as unknown as Env;
    const ctx = {
      waitUntil: () => {},
      passThroughOnException: () => {},
    } as unknown as ExecutionContext;

    const request = new Request(`${BASE}/git-credential/get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer a-capability" },
      body: JSON.stringify(callbackFixture()),
    });
    // Without the try this REJECTS, which in the Worker is a 1101.
    const res = await handleGitCredential(request, env, new URL(request.url), ctx);
    expect(calls).toEqual(["authorize"]);
    expect(res.status).toBe(502);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ error: "authorize_failed" });
    // The exception text is never echoed: it can quote the callback body.
    const rendered = JSON.stringify(body);
    expect(rendered).not.toContain("boom");
    expect(rendered).not.toContain("protocol");
  });
});
