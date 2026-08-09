/**
 * The delegation chain feeds the SAME attribution shape #677/#678 built (#691).
 *
 * ## The requirement this file holds
 *
 * An audit row that names a chain the COST query cannot group by is half a
 * feature. Finance asks "whose spend is this" about a whole month, and the
 * answer has to arrive through the query it already runs — `GET
 * /admin/v1/cost-records`, tenant-fenced, paged, exportable — rather than
 * through a second report standing beside it.
 *
 * So this is a sibling of `cost-records-read.test.ts` and deliberately not a
 * section inside it: what it pins is one dimension of that surface, and the two
 * would otherwise share fixtures whose shape is chosen for a different question.
 *
 * ## Why the two delegated fixtures look the way they do
 *
 * They share an `agent_run_id` and root at DIFFERENT principals, and the second
 * principal's id has the first's as a PREFIX. Both choices are load-bearing:
 *
 *  - shared run id — a filter that quietly fell back to `agent_run_id` would
 *    return both rows, and a suite whose fixtures differed in both dimensions
 *    could not tell that from a correct answer;
 *  - prefix — the obvious implementation of "spend under this principal" is
 *    `delegation_chain LIKE 'user:u_alice>%'`, which collects `user:u_alice_2`'s
 *    charges too. That is one person billed for another's spend, arriving
 *    silently in a finance total.
 *
 * ## What these rows do NOT establish
 *
 * That any agent behaved. `delegation_chain` records that each delegation was
 * AUTHORISED and verified at the gateway; the writer's half is held by
 * `apps/gateway/test/delegation/chain.test.ts`, and neither says anything about
 * what the agent then did.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1, seedBillingEvents, seedRequestLogs } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

interface ListBody {
  data: Record<string, unknown>[];
}

async function readCosts(secret: string, query = ""): Promise<ListBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/cost-records${query}`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as ListBody;
}

async function ids(secret: string, query = ""): Promise<unknown[]> {
  return (await readCosts(secret, query)).data.map((row) => row.request_id);
}

const BASE_ROW = {
  tenant: "t-1",
  project: "proj-alpha",
  workspace: "ws-1",
  apiKeyId: "key_t-1",
  startedAtUnix: 1_700_000_100,
  completedAtUnix: 1_700_000_101,
  route: "openai.chat.completions",
  provider: "openai",
  logicalModel: "gpt-4o-mini",
  providerModel: "gpt-4o-mini-2024-07-18",
  statusCode: 200,
  totalTokens: 15,
} as const;

const DELEGATED_A = {
  ...BASE_ROW,
  requestId: "fg-del-a",
  agentRunId: "run-shared",
  delegationChain: "user:u_alice>agent:planner>agent:writer",
  delegationRoot: "user:u_alice",
} as const;

const DELEGATED_B = {
  ...BASE_ROW,
  requestId: "fg-del-b",
  agentRunId: "run-shared",
  delegationChain: "user:u_alice_2>agent:planner>agent:writer",
  delegationRoot: "user:u_alice_2",
} as const;

/** The undelegated control: most traffic, and it must record ABSENCE. */
const PLAIN = { ...BASE_ROW, requestId: "fg-plain", agentRunId: "run-shared" } as const;

const EVENT = {
  request_id: DELEGATED_A.requestId,
  provider_attempt_id: "attempt-0",
  provider_attempt_index: 0,
  tenant: { organization_id: "t-1", project_id: "proj-alpha", api_key_id: "key_t-1" },
  logical_model: "gpt-4o-mini",
  provider: "openai",
  provider_model: "gpt-4o-mini-2024-07-18",
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
  usage_source: "provider_usage",
  status_code: 200,
  occurred_at_unix: 1_700_000_101,
  cost_usd: 0.5,
} as const;

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1"), tenantKey("k-other", "t-2")],
    rbac: {},
  });
  await seedRequestLogs([DELEGATED_A, DELEGATED_B, PLAIN]);
  await seedBillingEvents([
    {
      id: "be-del-a",
      requestId: DELEGATED_A.requestId,
      occurredAtUnix: 1_700_000_101,
      event: EVENT,
    },
  ]);
});

describe("#691 — a delegated run is queryable by the principal responsible", () => {
  it("publishes the whole chain and its root on the cost record", async () => {
    const rows = (await readCosts(operatorKey.secret)).data;

    const delegated = rows.find((row) => row.request_id === DELEGATED_A.requestId);
    expect(delegated?.delegation_chain).toBe("user:u_alice>agent:planner>agent:writer");
    expect(delegated?.delegation_root).toBe("user:u_alice");

    // Absence, recorded as absence. `null` and not `""`: "nobody delegated" and
    // "we did not look" have to stay distinguishable in a chargeback export.
    const plain = rows.find((row) => row.request_id === PLAIN.requestId);
    expect(plain?.delegation_chain).toBeNull();
    expect(plain?.delegation_root).toBeNull();
  });

  it("groups spend by the ROOT principal, and does not over-match a prefix", async () => {
    expect(await ids(operatorKey.secret, "?delegation_root=user:u_alice")).toEqual([
      DELEGATED_A.requestId,
    ]);
    expect(await ids(operatorKey.secret, "?delegation_root=user:u_alice_2")).toEqual([
      DELEGATED_B.requestId,
    ]);
  });

  it("keeps the tenant fence in front of the delegation filter", async () => {
    // `t-2`'s admin asking for `t-1`'s principal gets the empty set. The filter
    // is AND-ed with the fence, never a replacement for it — a filter that
    // REPLACED the fence would be a one-parameter cross-tenant read of the most
    // sensitive report in the product.
    expect(await ids("k-other", "?delegation_root=user:u_alice")).toEqual([]);
  });

  it("carries both columns into the chargeback export", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/cost-record-exports?delegation_root=user:u_alice`,
      { headers: bearer(operatorKey.secret) },
    );
    expect(response.status, await response.clone().text()).toBe(200);

    const csv = await response.text();
    // RFC 4180 line endings are CRLF, so the `\r` is stripped before anchoring
    // on `$` — without this the assertion fails on a correct export, which is
    // its own kind of lie.
    const lines = csv
      .split("\n")
      .map((line) => line.replace(/\r$/, ""))
      .filter((line) => line.trim() !== "");
    expect(lines).toHaveLength(2);

    // Asserted on the RAW header and the RAW row rather than through a CSV
    // parser: the column order is a positional contract (a warehouse `COPY`
    // indexes it by position), and the two new columns must be on the END. A
    // parser keyed by name would keep passing if they were inserted in the
    // middle, which is the change that breaks every loader already in use.
    expect(lines[0]).toMatch(/,delegation_chain,delegation_root$/);
    expect(lines[1]).toMatch(/,user:u_alice>agent:planner>agent:writer,user:u_alice$/);
  });
});
