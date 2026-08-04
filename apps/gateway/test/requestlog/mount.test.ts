/**
 * Anti-drift gate for the REQUEST-LOG MOUNT, and the retention sweep that
 * bounds what it writes (#664).
 *
 * ## Why this file exists separately from `write.test.ts`
 *
 * `write.test.ts` builds its own app so it can pin the row's contents against a
 * one-route model registry. That is exactly the shape that let the metering
 * drain be silently unmounted once already: a suite that composes its own
 * middleware array proves the MIDDLEWARE and says nothing about whether the
 * DEPLOYED Worker mounts it. Deleting `requestLogging(requestLogs)` from
 * `src/index.ts` would leave every case in that file green while every
 * deployment recorded nothing — the same defect, one layer up.
 *
 * So there are two gates here and neither subsumes the other:
 *
 *  1. STRUCTURAL, against the exported `GATEWAY_MIDDLEWARE`. It fails if the
 *     middleware is unmounted OR REORDERED, and order is something no
 *     behavioural test can see: a request log mounted BELOW `rateLimit()` or
 *     `guardrails()` still records every successful request, and silently drops
 *     exactly the 429s and 403s an audit is for.
 *  2. BEHAVIOURAL, through `SELF.fetch` — i.e. through `export default app` in
 *     `src/index.ts`, which is what `wrangler deploy` ships — reading the row
 *     back out of the real `CONTROL_DB`. It fails if the middleware is
 *     unmounted, if `requestLogBindingsFromEnv` stops resolving, or if the
 *     upsert stops landing; the structural gate sees none of those.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import {
  REQUEST_LOG_TABLE,
  REQUEST_LOG_RETENTION_POLICIES_VAR,
  requestLogRetentionFromEnv,
  requestLogTenantDatabaseFromEnv,
  sweepRequestLogRetention,
  sweepRequestLogs,
  writeRequestLogs,
} from "../../src/requestlog/index.js";
import type { RequestLogRecord } from "../../src/requestlog/index.js";
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
} from "./harness.js";

/** Runtime names of the handlers `GATEWAY_MIDDLEWARE` is built from. */
const REQUEST_LOGGING = "requestLoggingMiddleware";
const RATE_LIMIT = "rateLimitMiddleware";
const GUARDRAILS = "guardrailsMiddleware";

describe("composition root — the request log is mounted", () => {
  const names = GATEWAY_MIDDLEWARE.map((handler) => handler.name);

  it("mounts the middleware the deployed Worker composes", () => {
    // Deleting `requestLogging(requestLogs)` from src/index.ts turns this red.
    expect(names).toContain(REQUEST_LOGGING);
  });

  it("mounts it AHEAD of every middleware that can short-circuit", () => {
    // The property: `requestLogging` wraps `await next()`, so anything below it
    // is inside its window. Below `rateLimit()` a 429 would never reach it;
    // below `guardrails()` a 403 `guardrail_*` would not either — and those are
    // precisely the decisions an incident review and an auditor are looking
    // for. An evidence surface that records only successes is the same lie this
    // issue closes, one layer down.
    const index = names.indexOf(REQUEST_LOGGING);
    expect(index).toBeGreaterThanOrEqual(0);
    expect(index).toBeLessThan(names.indexOf(RATE_LIMIT));
    // `guardrails()` returns an anonymous arrow today, so its position is
    // asserted only when it is nameable; the `rateLimit` bound above already
    // pins the middleware ahead of both in the committed array.
    const guardrailIndex = names.indexOf(GUARDRAILS);
    if (guardrailIndex >= 0) expect(index).toBeLessThan(guardrailIndex);
  });
});

// ---------------------------------------------------------------------------
// The behavioural gate — through `export default app`
// ---------------------------------------------------------------------------

const LOGICAL_MODEL = "requestlog-probe";
const PROVIDER_MODEL = "gpt-4o-mini";
const PROVIDER_KEY_VAR = "REQUESTLOG_PROBE_PROVIDER_KEY";
const UPSTREAM = "https://upstream.invalid/v1";

const bindings = env as unknown as Record<string, unknown>;
let provider: ProviderInterceptor | undefined;

/**
 * Publish a one-model registry and one scoped key onto the env the Worker
 * reads.
 *
 * `beforeAll`, before the first `SELF.fetch` in this file, because the router
 * memoizes `modelsFromEnv(env)` per env object — a var written after the first
 * request would be invisible. Confined to this file's isolate, so
 * `test/contract.test.ts`'s empty-registry assertions are untouched.
 */
beforeAll(async () => {
  await applyControlMigrations();
  bindings[PROVIDER_KEY_VAR] = "sk-requestlog-probe";
  bindings.GATEWAY_PROVIDERS = JSON.stringify([
    {
      name: "requestlog-probe-provider",
      kind: "openai",
      base_url: UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
    },
  ]);
  bindings.GATEWAY_MODELS = JSON.stringify([
    {
      name: LOGICAL_MODEL,
      provider: "requestlog-probe-provider",
      provider_model: PROVIDER_MODEL,
      capabilities: ["chat"],
    },
  ]);
  bindings.GATEWAY_NATIVE_API_KEYS = JSON.stringify([
    {
      key: "fg_probe_tenant",
      id: "key_probe",
      tenant_id: "tenant_a",
      scopes: ["chat.completions"],
    },
  ]);
});

beforeEach(resetRequestLogs);

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

const COMPLETION = {
  id: "chatcmpl-probe",
  object: "chat.completion",
  model: PROVIDER_MODEL,
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

/**
 * Wait for the row to travel the WHOLE deployed path.
 *
 * `SELF.fetch` resolves when the RESPONSE is flushed, and the durable write is
 * deliberately after that — which is the property the middleware exists to
 * have. `cloudflare:test` exposes no `waitOnExecutionContext` for a `SELF`
 * call, so the row is polled for with a bounded budget.
 *
 * The budget is SECONDS rather than milliseconds because this path really does
 * go through the Queue: `wrangler.toml` declares
 * `[[queues.producers]] REQUEST_LOG` and the matching `[[queues.consumers]]`,
 * the pool provisions BOTH, and it dispatches the delivery to `queue()` on
 * `src/worker.ts`'s default export. The wait is therefore
 * `max_batch_timeout = 5` seconds of real batching, not slack — and what it
 * buys is the only assertion in the tree that covers
 * producer → queue → consumer → D1 through the module `wrangler deploy` ships.
 * A missing `queue` handler on the default export fails HERE (the message is
 * produced and never consumed), which is a failure mode no unit test can see.
 */
async function awaitRow(budgetMs = 20000): Promise<Awaited<ReturnType<typeof storedRequestLogs>>> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const rows = await storedRequestLogs();
    if (rows.length > 0) return rows;
    if (Date.now() >= deadline) return rows;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("composition root — a request through SELF lands a row in CONTROL_DB", () => {
  it("records the completion the app the Worker exports actually served", async () => {
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const response = await SELF.fetch(`https://gw.test/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: "Bearer fg_probe_tenant",
        "content-type": "application/json",
      },
      body: JSON.stringify({ model: LOGICAL_MODEL, messages: [{ role: "user", content: "hi" }] }),
    });
    expect(response.status, await response.clone().text()).toBe(200);

    const rows = await awaitRow();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      tenant: "tenant_a",
      logical_model: LOGICAL_MODEL,
      provider_model: PROVIDER_MODEL,
      status_code: 200,
      total_tokens: 15,
    });
    expect(rows[0]?.request_id).toBe(response.headers.get("x-request-id"));
    // 25s, not the suite's 5s default: see {@link awaitRow} — the queue's
    // `max_batch_timeout` is 5 real seconds and this case waits it out on
    // purpose rather than reaching around the queue.
  }, 25_000);
});

// ---------------------------------------------------------------------------
// Retention — the answer to "and then it grows forever"
// ---------------------------------------------------------------------------

function record(requestId: string, startedAtUnix: number, tenantId?: string): RequestLogRecord {
  return {
    requestId,
    method: "POST",
    path: "/v1/chat/completions",
    statusCode: 200,
    startedAtUnix,
    completedAtUnix: startedAtUnix,
    latencyMs: 5,
    guardrailVerdict: "allowed",
    streamed: false,
    ...(tenantId === undefined ? {} : { tenantId }),
  };
}

describe("policy-driven retention", () => {
  const NOW = 1_800_000_000;
  const DAY = 86_400;

  it("prunes rows past the window and keeps the ones inside it", async () => {
    await writeRequestLogs(controlDb(), [
      record("fg-old", NOW - 40 * DAY),
      record("fg-edge", NOW - 29 * DAY),
      record("fg-new", NOW - 1 * DAY),
    ]);

    const result = await sweepRequestLogRetention(
      controlDb(),
      { policy: { maxAgeSecs: 30 * DAY, minAgeSecs: 0 } },
      NOW,
    );
    expect(result.pruned).toBe(1);
    expect((await storedRequestLogs()).map((row) => row.request_id).sort()).toEqual([
      "fg-edge",
      "fg-new",
    ]);
  });

  it("applies a per-tenant override without narrowing anyone else's window", async () => {
    await writeRequestLogs(controlDb(), [
      record("fg-acme-old", NOW - 10 * DAY, "acme"),
      record("fg-other-old", NOW - 10 * DAY, "other"),
      record("fg-platform-old", NOW - 10 * DAY),
    ]);

    await sweepRequestLogRetention(
      controlDb(),
      { tenantId: "acme", policy: { maxAgeSecs: 5 * DAY, minAgeSecs: 0 } },
      NOW,
    );

    // STRICT equality on the tenant, so the un-attributed platform row and the
    // other tenant's row are untouched by one tenant's shorter window.
    expect((await storedRequestLogs()).map((row) => row.request_id).sort()).toEqual([
      "fg-other-old",
      "fg-platform-old",
    ]);
  });

  it("KEEPS everything when nothing is configured", async () => {
    await writeRequestLogs(controlDb(), [record("fg-ancient", 0)]);
    const result = await sweepRequestLogs(controlDb(), {}, NOW);
    expect(result).toEqual({ scanned: 0, pruned: 0 });
    expect(await storedRequestLogs()).toHaveLength(1);
  });

  it("deletes the tenant object before its control projection", async () => {
    const tenantId = "retention-order-tenant";
    const old = record("retention-order-old", NOW - 10 * DAY, tenantId);
    const objectDb = requestLogTenantDatabaseFromEnv(env, tenantId);
    expect(objectDb).toBeDefined();
    await objectDb?.prepare(`DELETE FROM ${REQUEST_LOG_TABLE}`).run();
    await writeRequestLogs(controlDb(), [old]);
    await writeRequestLogs(objectDb!, [old]);

    // A failing projection batch is a mutation-backed ordering probe: if the
    // implementation deletes control first, the object row would still exist.
    const failingProjection = {
      prepare: (query: string) => controlDb().prepare(query),
      batch: async () => {
        throw new Error("control projection unavailable");
      },
    };
    const result = await sweepRequestLogs(
      failingProjection,
      {
        TENANT_DATA: env.TENANT_DATA,
        [REQUEST_LOG_RETENTION_POLICIES_VAR]: JSON.stringify({ [tenantId]: { days: 1 } }),
      },
      NOW,
    );

    expect(result.pruned).toBe(1);
    expect(
      await objectDb
        ?.prepare(`SELECT request_id FROM ${REQUEST_LOG_TABLE} WHERE request_id = ?`)
        .bind(old.requestId)
        .first(),
    ).toBeNull();
    expect(
      await controlDb()
        .prepare(`SELECT request_id FROM ${REQUEST_LOG_TABLE} WHERE request_id = ?`)
        .bind(old.requestId)
        .first(),
    ).not.toBeNull();
  });

  it("reads the fleet default and the per-tenant overrides off env", () => {
    const scopes = requestLogRetentionFromEnv({
      REQUEST_LOG_RETENTION_DAYS: "400",
      REQUEST_LOG_RETENTION_POLICIES: JSON.stringify({ acme: { days: 30 } }),
    });
    expect(scopes).toEqual([
      { policy: { maxAgeSecs: 400 * DAY, minAgeSecs: 0 } },
      { tenantId: "acme", policy: { maxAgeSecs: 30 * DAY, minAgeSecs: 0 } },
    ]);
  });

  /**
   * Every malformed shape resolves to NO policy, i.e. KEEP. A retention rule
   * that cannot be read must never be read as a shorter one — that is the
   * difference between an unapplied policy and a deleted audit trail.
   */
  it("fails SAFE on every malformed or unsupported rule", () => {
    expect(requestLogRetentionFromEnv({ REQUEST_LOG_RETENTION_DAYS: "0" })).toEqual([]);
    expect(requestLogRetentionFromEnv({ REQUEST_LOG_RETENTION_DAYS: "" })).toEqual([]);
    expect(requestLogRetentionFromEnv({ REQUEST_LOG_RETENTION_DAYS: "-1" })).toEqual([]);
    expect(requestLogRetentionFromEnv({ REQUEST_LOG_RETENTION_DAYS: "forever" })).toEqual([]);
    expect(requestLogRetentionFromEnv({ REQUEST_LOG_RETENTION_POLICIES: "{ not json" })).toEqual(
      [],
    );
    // `keep_last_n` is REFUSED rather than approximated: it is rank-based, the
    // sweep works on a bounded window, and evaluating a rank rule on a window
    // silently over-prunes. See `src/requestlog/retention.ts`.
    expect(
      requestLogRetentionFromEnv({
        REQUEST_LOG_RETENTION_POLICIES: JSON.stringify({ acme: { days: 30, keep_last_n: 10 } }),
      }),
    ).toEqual([]);
  });

  it("is wired to the committed [vars] defaults, not just to a literal", () => {
    // The var names the Cron handler reads must be the ones `wrangler.toml`
    // declares. `test/env-var-drift.test.ts` holds the two directions of that
    // contract mechanically; this asserts the committed VALUE is a live policy
    // rather than a blank that silently means "keep forever".
    const scopes = requestLogRetentionFromEnv(env);
    expect(scopes.length).toBeGreaterThanOrEqual(1);
    expect(scopes[0]?.policy.maxAgeSecs).toBeGreaterThan(180 * DAY);
  });

  it("names the table the control plane reads", () => {
    expect(REQUEST_LOG_TABLE).toBe("request_logs");
  });
});
