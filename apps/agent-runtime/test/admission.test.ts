/**
 * THE ADMISSION HALF OF `authenticate()` — the exploit this file closes.
 *
 * ## The defect, stated as the attack
 *
 * In the Rust tree `/v1/agent-jobs`, `/v1/agent-runs` and `/v1/agents/**` were
 * served by the SAME process as `/v1/chat/completions`, so they went through the
 * same `auth::authenticate()` → `finalize_auth` chain. Splitting the data plane
 * into five Workers moved only the CREDENTIAL half onto this app: which key,
 * which scope, which tenant. The ADMISSION half — quota scope, monthly budget,
 * wallet balance, RPM — stayed behind on `apps/gateway`.
 *
 * That is not a fidelity gap, it is a control bypass with a one-line exploit: a
 * credential that is rate-limited and budget-exhausted on
 * `POST /v1/chat/completions` was ADMITTED on `POST /v1/agent-jobs`, and an
 * agent job goes on to spend real provider money. "Call the other endpoint" was
 * the whole of it.
 *
 * ## What this file asserts
 *
 * The Rust ladder, in Rust's order (`crates/ferrogate-gateway/src/auth.rs`
 * `finalize_auth`), on the surface that was bypassable:
 *
 *   1. `denied_by`          → **403** `quota_scope_disabled`   (a deny, not a throttle)
 *   2. `monthly_budget_usd` → 429 `monthly_budget_exceeded`    (durable suite)
 *   3. wallet balance       → 429 `wallet_balance_exhausted`   (durable suite)
 *   4. `request_windows()`  → 429 `rate_limit_exceeded`
 *   †  any lookup failure   → 503, never an admission
 *
 * Steps 2 and 3 need `usage_monthly_rollups` / `wallets` rows, so they are
 * proven in `test/durable/admission.spec.ts` against REAL migrated D1
 * databases rather than against a var. Everything reachable without a database
 * is proven here.
 *
 * ## Counter isolation is a fixture property, not a lucky accident
 *
 * `@cloudflare/vitest-pool-workers` keeps ONE `workerd` instance for the whole
 * project, so every `SELF.fetch` in every file hits the same Worker and the
 * same counters. Each credential below therefore lives in its own tenant with
 * its own `subject`, and `tenant-a` / `tenant-b` are deliberately left
 * ungoverned so the other tests in this suite keep running unlimited.
 */
import { describe, expect, it } from "vitest";
import {
  INTERNAL_ROUTES,
  WORKER_A,
  bearer,
  get,
  post,
  workerEnvelopeFor,
  workerHeaders,
} from "./fixtures.js";

const HEARTBEAT = "/v1/self-hosted-workers/heartbeat";

/** `POST /v1/agent-jobs` — the money-spending verb the bypass reached. */
async function submit(key: string): Promise<Response> {
  return await post("/v1/agent-jobs", bearer(key), {
    input: "write the patch",
    required_capabilities: ["coding"],
  });
}

async function codeOf(response: Response): Promise<string> {
  const body = (await response.json()) as { error?: { code?: string } };
  return body.error?.code ?? "";
}

describe("admission: the per-credential RPM cap (TOK-12 request_limit_per_minute)", () => {
  it("REFUSES POST /v1/agent-jobs once the credential's own RPM cap is spent", async () => {
    // `sk-rpm-perkey` carries `requestLimitPerMinute: 2` and NO quota policy,
    // so this is the column on the credential itself doing the work.
    const first = await submit("sk-rpm-perkey");
    expect(first.status).toBe(202);
    const second = await submit("sk-rpm-perkey");
    expect(second.status).toBe(202);

    const third = await submit("sk-rpm-perkey");
    expect(third.status).toBe(429);
    expect(await codeOf(third)).toBe("rate_limit_exceeded");
  });

  it("charges a READ against the same window — Rust gates every authenticated request", async () => {
    // `sk-rpm-read` carries `requestLimitPerMinute: 1`. Spending it on a GET
    // must leave nothing for the submit. A port that only gated the write verb
    // would leave the poll loop free, and a poll loop is what an agent client
    // spends most of its requests on.
    const read = await get("/v1/agent-jobs/job-does-not-exist", bearer("sk-rpm-read"));
    expect(read.status).toBe(404);

    const refused = await submit("sk-rpm-read");
    expect(refused.status).toBe(429);
    expect(await codeOf(refused)).toBe("rate_limit_exceeded");
  });
});

describe("admission: the quota chain's RPM window", () => {
  it("REFUSES once a TENANT-scope rpm_limit is spent, across every key under it", async () => {
    // `tenant-quota-rpm` has `rpm_limit: 1`. The window is the TENANT's, so the
    // sibling key must find it already exhausted — that aggregate is the whole
    // point of a tenant-scope cap and the thing a per-key counter would lose.
    const first = await submit("sk-quota-rpm");
    expect(first.status).toBe(202);

    const sibling = await submit("sk-quota-rpm-sibling");
    expect(sibling.status).toBe(429);
    expect(await codeOf(sibling)).toBe("rate_limit_exceeded");
  });

  it("REFUSES every request when rpm_limit is 0 — zero is a stop, not 'unlimited'", async () => {
    const response = await submit("sk-quota-zero");
    expect(response.status).toBe(429);
    expect(await codeOf(response)).toBe("rate_limit_exceeded");
  });

  it("counts a KEY-scope rpm_limit per credential", async () => {
    const first = await submit("sk-quota-keyscope");
    expect(first.status).toBe(202);
    const second = await submit("sk-quota-keyscope");
    expect(second.status).toBe(429);
    expect(await codeOf(second)).toBe("rate_limit_exceeded");
  });
});

describe("admission: a disabled quota scope is a 403, not a 429", () => {
  it("REFUSES with quota_scope_disabled when a policy in the chain is enabled = false", async () => {
    const response = await submit("sk-quota-disabled");
    expect(response.status).toBe(403);
    expect(await codeOf(response)).toBe("quota_scope_disabled");
  });
});

describe("what admission must NOT do", () => {
  it("admits an ungoverned credential — no per-key cap, no policy row", async () => {
    // The negative control. Without it every assertion above would still pass
    // if the port simply refused everything.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await submit("sk-admission-free");
      expect(response.status, `ungoverned submit #${attempt + 1} was refused`).toBe(202);
    }
  });

  it("leaves all SIX internal worker-plane callbacks on the worker credential", async () => {
    // ROUTE-MAP invariant 2, re-proven after the change: the admission ladder
    // hangs off the BEARER leg only, so it must not have introduced a code path
    // from a tenant key to a worker-plane callback — and must not have started
    // charging a tenant's quota for a worker's heartbeat either.
    for (const path of INTERNAL_ROUTES) {
      const withTenantKey = await post(path, bearer("sk-tenant-a"), workerEnvelopeFor(path));
      expect(withTenantKey.status, `${path} admitted a tenant bearer key`).toBe(401);
      expect(await codeOf(withTenantKey)).toBe("invalid_self_hosted_worker_transport_security");
    }

    // …and the real worker credential still works on the cheapest of them.
    // 201: the heartbeat CREATES a liveness record (`contract.test.ts`).
    const asWorker = await post(HEARTBEAT, workerHeaders(), workerEnvelopeFor(HEARTBEAT, WORKER_A));
    expect(asWorker.status).toBe(201);
    const body = (await asWorker.json()) as { object?: string };
    expect(body.object).toBe("self_hosted_worker_heartbeat");
  });
});
