/**
 * THE VERIFIABLE DELEGATION CHAIN (#691), driven through the DEPLOYED
 * middleware chain.
 *
 * ## The defect this file pins
 *
 * An agent run acts with the caller's key. When user U delegates to agent
 * `planner`, and `planner` delegates to agent `writer`, the gateway sees
 * `writer`'s credential and nothing else — so the #664 audit row and the
 * #677 cost record both name `key_writer` and cannot name U. Every audit answer
 * downstream is therefore approximate in exactly the direction that matters:
 * it names the last credential to touch the request rather than the principal
 * ultimately responsible.
 *
 * ## Why this file composes `GATEWAY_MIDDLEWARE` rather than its own list
 *
 * Same reason `test/attribution/enforcement.test.ts` does, and the same
 * evidence: deleting `meteringDrain(usage)` from the composition root once left
 * 794 tests green. A middleware that exists in `src/` and is mounted nowhere
 * enforces nothing, and "nothing verifies the chain" is a property of the chain
 * the Worker actually runs. So every case below builds the app from the
 * exported `GATEWAY_MIDDLEWARE` array — the same handlers in the same order
 * `src/index.ts` ships — and doubles only the route module and the outbound
 * provider `fetch`.
 *
 * ## What a passing suite here does NOT establish
 *
 * That an agent behaved. A verified chain proves a delegation was AUTHORISED —
 * that U authorised `planner` and `planner` authorised `writer`, and that
 * nobody widened their authority along the way. It says nothing about whether
 * `writer` did what it was asked. That is guardrails' problem and a different
 * control.
 */
import { env as poolEnv } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RequestIdFactory } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import {
  applyControlMigrations,
  controlDb,
  resetRequestLogs,
  storedRequestLogs,
} from "../requestlog/harness.js";
import { ATTACKER_SECRET, SIGNING_SECRET, chain, forge } from "./fixtures.js";

const BASE = "https://gw.test";

/**
 * `key_writer` is the LEAF agent's credential: it is what authenticates the
 * request, and the chain's leaf link is bound to it.
 *
 * `key_planner` exists so the presenter binding is falsifiable — a chain issued
 * to `key_planner` and presented by `key_writer` must be refused, and a suite
 * with one key could not tell the difference. `key_readonly_writer` holds a
 * NARROWER scope set than the chain grants, which is what makes the
 * "the credential is the ceiling" case meaningful.
 */
const KEYS = [
  {
    key: "fg_writer",
    id: "key_writer",
    tenant_id: "tenant_a",
    project_id: "project_a",
    scopes: ["chat.completions", "tools.read"],
  },
  {
    key: "fg_planner",
    id: "key_planner",
    tenant_id: "tenant_a",
    project_id: "project_a",
    scopes: ["chat.completions", "tools.read"],
  },
  // Another TENANT's key, for the cross-tenant case.
  {
    key: "fg_other_tenant",
    id: "key_writer",
    tenant_id: "tenant_c",
    project_id: "project_c",
    scopes: ["chat.completions", "tools.read"],
  },
];

/** The honest two-hop chain: user U → agent planner → agent writer. */
const ROOT = {
  jti: "dl_root",
  act: "user:u_alice",
  sub: "agent:planner",
  subKey: "key_planner",
  scope: ["chat.completions", "tools.read"],
} as const;

const LEAF = {
  jti: "dl_leaf",
  act: "agent:planner",
  sub: "agent:writer",
  subKey: "key_writer",
  scope: ["chat.completions"],
  run: "run_42",
} as const;

const EXPECTED_PATH = "user:u_alice>agent:planner>agent:writer";

function incrementingRequestIds(): RequestIdFactory {
  let next = 0;
  return {
    next: (): string => {
      next += 1;
      return `fg-${next.toString(16).padStart(16, "0")}`;
    },
  };
}

interface Harness {
  call(key: string, delegation?: string): Promise<Response>;
}

function gateway(options: { readonly signingKey?: string | null } = {}): Harness {
  const bindings = poolEnv as unknown as Record<string, unknown>;
  const env: Record<string, unknown> = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    // The REAL control database: the request-log row and the revocation lookup
    // both go through the same D1 the deployed Worker uses.
    CONTROL_DB: bindings["CONTROL_DB"],
    ...(options.signingKey === null
      ? {}
      : { DELEGATION_SIGNING_KEY: options.signingKey ?? SIGNING_SECRET }),
  };

  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([OPENAI_ROUTE]),
        requestIds: incrementingRequestIds(),
      }),
    ],
    // THE LINE UNDER TEST: the deployed chain, in the deployed order.
    middleware: GATEWAY_MIDDLEWARE,
  });

  return {
    call: async (key, delegation) =>
      app.request(
        `${BASE}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${key}`,
            "content-type": "application/json",
            ...(delegation === undefined ? {} : { "x-ferrogate-delegation": delegation }),
          },
          body: JSON.stringify({
            model: "gpt-4o-mini",
            messages: [{ role: "user", content: "hi" }],
          }),
        },
        env,
      ),
  };
}

let provider: ProviderInterceptor | undefined;

function upstreamAnswers(): ProviderInterceptor {
  provider = interceptProviderFetch(() =>
    providerJson({
      id: "chatcmpl-1",
      object: "chat.completion",
      model: "gpt-4o-mini",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    }),
  );
  return provider;
}

/** `Date.now()` in whole seconds — the unit every claim uses. */
function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * THIS request's audit row, found by the `x-request-id` the client was handed.
 *
 * By id rather than "the only row in the table" on purpose: `requestLogging()`
 * writes on `ctx.waitUntil`, and `app.request()` supplies no execution context,
 * so a previous case's row can still be settling when the next `beforeEach`
 * truncates. Asserting on a COUNT would make this suite flaky in a way that
 * says nothing about delegation; asserting on the id says exactly what is
 * meant — the row for the request that was just made.
 */
async function loggedRow(response: Response): Promise<Record<string, unknown>> {
  const requestId = response.headers.get("x-request-id");
  const rows = (await storedRequestLogs()) as unknown as Record<string, unknown>[];
  const row = rows.find((candidate) => candidate["request_id"] === requestId);
  if (row === undefined) {
    throw new Error(`no request_logs row for ${String(requestId)} (${rows.length} rows present)`);
  }
  return row;
}

async function errorCode(response: Response): Promise<string | undefined> {
  const body = (await response.json()) as { error?: { code?: string } };
  return body.error?.code;
}

beforeEach(async () => {
  await applyControlMigrations();
  await resetRequestLogs();
  await controlDb().prepare("DELETE FROM delegation_revocations").run();
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

// ---------------------------------------------------------------------------
// 1. A chain the caller can write is not a chain
// ---------------------------------------------------------------------------

describe("#691 — a presented chain is VERIFIED, never believed", () => {
  it("refuses a chain signed with a key the gateway does not hold", async () => {
    const upstream = upstreamAnswers();
    // Exactly what a caller who "just sets the header" can produce: a
    // structurally perfect chain, signed with a secret that is not ours.
    const forged = await chain(ATTACKER_SECRET, [ROOT, LEAF], nowUnix());

    const response = await gateway().call("fg_writer", forged.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_signature_invalid");
    // A refusal that still paid for a provider call would be a worse bug than
    // the unverifiable header it refused.
    expect(upstream.requests).toHaveLength(0);
  });

  it("refuses a chain whose payload was edited after signing", async () => {
    upstreamAnswers();
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());
    // Swap the leaf's payload segment for one naming a different root — the
    // signature still belongs to the original bytes.
    const leaf = (honest.tokens[1] as string).split(".");
    const tampered = await forge(ATTACKER_SECRET, { ...LEAF });
    const spliced = `${honest.tokens[0]}~${leaf[0]}.${tampered.token.split(".")[1]}.${leaf[2]}`;

    const response = await gateway().call("fg_writer", spliced);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_signature_invalid");
  });
});

// ---------------------------------------------------------------------------
// 2. The audit row names the WHOLE chain
// ---------------------------------------------------------------------------

describe("#691 — the audit row names the chain, not the last credential", () => {
  it("records the root principal, the whole path and the run on the request log", async () => {
    upstreamAnswers();
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());

    const response = await gateway().call("fg_writer", honest.header);
    expect(response.status).toBe(200);

    const row = await loggedRow(response);
    // The defect, stated as an assertion: before this change the row named
    // `key_writer` and nothing else, so an incident could not be attributed
    // past the credential.
    expect(row["api_key_id"]).toBe("key_writer");
    expect(row["delegation_chain"]).toBe(EXPECTED_PATH);
    expect(row["delegation_root"]).toBe("user:u_alice");
    // The chain feeds the attribution shape #677/#678 already built rather than
    // a second one beside it: `agent_run_id` is the column the per-request cost
    // query already groups by.
    expect(row["agent_run_id"]).toBe("run_42");
  });

  it("leaves an undelegated request completely untouched", async () => {
    upstreamAnswers();
    const response = await gateway().call("fg_writer");
    expect(response.status).toBe(200);

    const row = await loggedRow(response);
    expect(row["delegation_chain"]).toBeNull();
    expect(row["delegation_root"]).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. Attenuation is REAL
// ---------------------------------------------------------------------------

describe("#691 — attenuation: narrow only, never widen", () => {
  /**
   * The attack: `planner` was delegated `tools.read` only, and mints itself a
   * link to `writer` claiming `chat.completions` as well.
   *
   * Built with `forge`, not with the honest mint, ON PURPOSE — the honest mint
   * refuses to issue it, and a test that could only build the attack through
   * the mint would be proving the mint's check rather than the verifier's. The
   * verifier is the control: it is what still holds when the mint is
   * compromised, buggy, or a different version.
   */
  it("refuses a link that claims more than its delegator held", async () => {
    const upstream = upstreamAnswers();
    const issued = nowUnix();
    const narrowRoot = await forge(SIGNING_SECRET, {
      jti: "dl_root",
      act: "user:u_alice",
      sub: "agent:planner",
      sub_key: "key_planner",
      scope: ["tools.read"],
      iat: issued,
      exp: issued + 600,
    });
    const widened = await forge(SIGNING_SECRET, {
      jti: "dl_leaf",
      prev: "dl_root",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_writer",
      // MORE than the delegator holds.
      scope: ["tools.read", "chat.completions"],
      iat: issued,
      exp: issued + 600,
    });

    const response = await gateway().call("fg_writer", `${narrowRoot.token}~${widened.token}`);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_scope_widened");
    // NOT silently narrowed to the delegator's set, and not silently accepted:
    // both would serve a request under an authority nobody granted.
    expect(upstream.requests).toHaveLength(0);
  });

  it("refuses a chain that grants more than the presenting credential holds", async () => {
    upstreamAnswers();
    const issued = nowUnix();
    const root = await forge(SIGNING_SECRET, {
      jti: "dl_root",
      act: "user:u_alice",
      sub: "agent:writer",
      sub_key: "key_writer",
      // `admin.write` is not on `key_writer`. A chain must never be a
      // privilege-escalation channel around the credential that presents it.
      scope: ["admin.write"],
      iat: issued,
      exp: issued + 600,
    });

    const response = await gateway().call("fg_writer", root.token);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_scope_exceeds_credential");
  });

  it("ENFORCES the attenuated scope, rather than merely recording it", async () => {
    const upstream = upstreamAnswers();
    // A chain that grants only `tools.read`, presented on an operation whose
    // contract scope is `chat.completions`. The CREDENTIAL has that scope, so
    // the request passes `contractAuth`; the delegation does not, so it must
    // still be refused — otherwise attenuation is decoration.
    const narrowed = await chain(
      SIGNING_SECRET,
      [
        { ...ROOT, scope: ["tools.read"] },
        { ...LEAF, scope: ["tools.read"] },
      ],
      nowUnix(),
    );

    const response = await gateway().call("fg_writer", narrowed.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_scope_denied");
    expect(upstream.requests).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 4. Bounds: depth, freshness, and the presenter binding
// ---------------------------------------------------------------------------

describe("#691 — the bounds that stop a chain being an attack", () => {
  it("refuses a chain deeper than the verifier's bound", async () => {
    upstreamAnswers();
    const issued = nowUnix();
    const links: string[] = [];
    // Nine links: one past MAX_DELEGATION_DEPTH.
    for (let index = 0; index < 9; index += 1) {
      const forged = await forge(SIGNING_SECRET, {
        jti: `dl_${index}`,
        ...(index === 0 ? {} : { prev: `dl_${index - 1}` }),
        act: index === 0 ? "user:u_alice" : `agent:a${index - 1}`,
        sub: `agent:a${index}`,
        sub_key: index === 8 ? "key_writer" : `key_a${index}`,
        scope: ["chat.completions"],
        iat: issued,
        exp: issued + 600,
      });
      links.push(forged.token);
    }

    const response = await gateway().call("fg_writer", links.join("~"));

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_too_deep");
  });

  it("refuses an expired chain", async () => {
    upstreamAnswers();
    // Issued an hour ago with a legal lifetime: expired, not malformed.
    const stale = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix() - 3600);

    const response = await gateway().call("fg_writer", stale.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_expired");
  });

  it("refuses a chain replayed by a credential it was not issued to", async () => {
    upstreamAnswers();
    // The chain's leaf is bound to `key_writer`; `fg_planner` presents it.
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());

    const response = await gateway().call("fg_planner", honest.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_subject_mismatch");
  });

  it("refuses a chain minted for another tenant", async () => {
    upstreamAnswers();
    // `fg_other_tenant` authenticates as tenant_c with the SAME api-key id, so
    // the presenter binding passes and only the tenant claim can refuse it.
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());

    const response = await gateway().call("fg_other_tenant", honest.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_tenant_mismatch");
  });

  it("refuses a spliced chain whose links do not name each other", async () => {
    upstreamAnswers();
    const issued = nowUnix();
    const root = await forge(SIGNING_SECRET, {
      jti: "dl_root",
      act: "user:u_alice",
      sub: "agent:planner",
      sub_key: "key_planner",
      scope: ["chat.completions"],
      iat: issued,
      exp: issued + 600,
    });
    // A perfectly valid link from a DIFFERENT chain — its `prev` names a link
    // that is not the one presented before it.
    const alien = await forge(SIGNING_SECRET, {
      jti: "dl_leaf",
      prev: "dl_some_other_root",
      act: "agent:planner",
      sub: "agent:writer",
      sub_key: "key_writer",
      scope: ["chat.completions"],
      iat: issued,
      exp: issued + 600,
    });

    const response = await gateway().call("fg_writer", `${root.token}~${alien.token}`);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_chain_broken");
  });
});

// ---------------------------------------------------------------------------
// 5. Revocation breaks every chain through the revoked link, immediately
// ---------------------------------------------------------------------------

describe("#691 — revocation", () => {
  async function revoke(subject: string): Promise<void> {
    await controlDb()
      .prepare(
        "INSERT INTO delegation_revocations (tenant, subject, reason, revoked_at_unix) VALUES (?, ?, ?, ?)",
      )
      .bind("tenant_a", subject, "test", nowUnix())
      .run();
  }

  it("breaks a chain through a revoked MIDDLE link, without waiting for expiry", async () => {
    const upstream = upstreamAnswers();
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());
    // The root link is revoked; the leaf is untouched and still unexpired.
    await revoke("dl_root");

    const response = await gateway().call("fg_writer", honest.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_revoked");
    expect(upstream.requests).toHaveLength(0);
  });

  it("breaks every chain a revoked PRINCIPAL appears in", async () => {
    upstreamAnswers();
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());
    // Revoking the intermediate AGENT, not one grant: the compromised-agent
    // case, where every link it was given and every link it granted must die.
    await revoke("agent:planner");

    const response = await gateway().call("fg_writer", honest.header);

    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("delegation_revoked");
  });

  it("does not let one tenant's revocation break another tenant's chain", async () => {
    upstreamAnswers();
    await controlDb()
      .prepare(
        "INSERT INTO delegation_revocations (tenant, subject, reason, revoked_at_unix) VALUES (?, ?, ?, ?)",
      )
      .bind("tenant_zzz", "dl_root", "another tenant", nowUnix())
      .run();
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());

    const response = await gateway().call("fg_writer", honest.header);

    expect(response.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 6. "Not configured" is not a bypass
// ---------------------------------------------------------------------------

describe("#691 — a deployment that cannot verify does not pretend to", () => {
  it("refuses a delegated request when no signing key is bound", async () => {
    const upstream = upstreamAnswers();
    const honest = await chain(SIGNING_SECRET, [ROOT, LEAF], nowUnix());

    const response = await gateway({ signingKey: null }).call("fg_writer", honest.header);

    // 503, never a 200 with the header ignored: an unconfigured verifier must
    // not be a way to have a delegation treated as decoration.
    expect(response.status).toBe(503);
    expect(await errorCode(response)).toBe("delegation_verification_unavailable");
    expect(upstream.requests).toHaveLength(0);
  });

  it("serves an UNDELEGATED request on a deployment with no signing key", async () => {
    upstreamAnswers();
    const response = await gateway({ signingKey: null }).call("fg_writer");
    // Inert for everyone who has not adopted delegation.
    expect(response.status).toBe(200);
  });
});
