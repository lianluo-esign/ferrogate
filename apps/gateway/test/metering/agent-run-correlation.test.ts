/**
 * `x-ferrogate-agent-run-id` on the INFERENCE path — cutover finding **D3**.
 *
 * The finding, verbatim:
 *
 * ```
 * $ grep -rn "agent-run-id" apps/gateway/src/inference/ apps/gateway/src/metering/
 * (no output)
 * ```
 *
 * > *So the one surface that produces the actual token spend is the one surface
 * > whose spend cannot be joined back to the agent run that caused it. An
 * > operator investigating "why did this run cost $400" can see the asset pulls
 * > and the MCP tool calls but not the model calls.*
 *
 * Rust threads `agent_run_id` through the whole chat pipeline and stamps it on
 * the metering event (`state_billing_metering.rs::settle_request`), and
 * `@ferrogate/billing`'s `BillingEvent` has carried the `agent_run_id` field
 * since wave 2 — `src/metering/wire.ts:49` already serialises it into
 * `event_json`. Nothing ever SET it.
 *
 * ## What is asserted, and where it is read back from
 *
 * Every case drives one real inference request through the real composition —
 * `createGatewayApp` with `meteringDrain(sink)` outermost, a real
 * `ExecutionContext`, the real `BILLING_DB` D1 binding — and then reads the
 * `event_json` column of `billing_events` (joined to its settled
 * `billing_ledger` row) back OUT OF SQLITE, plus the message
 * the `BILLING` Queue received. Those two are the artefacts an operator's
 * investigation actually joins on; asserting on an in-memory charge object
 * would not prove either of them carries the id.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { billingEventFromUsage } from "../../src/metering/event.js";
import {
  AGENT_RUN_ID_HEADER,
  AGENT_RUN_ID_PATTERN,
  agentRunIdFor,
  chargeWithAgentRun,
  createMeteringUsageSink,
  meteringBindingsFromEnv,
  meteringDrain,
} from "../../src/metering/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import { interceptProviderFetch, providerJson } from "../inference/provider-mock.js";
import { RecordingQueue, billingDb, resetMeteringTables } from "./d1-harness.js";
import { chargeFixture, pricedBook, usageFixture } from "./fixtures.js";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

const BASE = "https://gw.test";
const db = billingDb();

beforeEach(async () => {
  await resetMeteringTables();
});

/**
 * Every settled charge's `BillingEvent` document, read back out of SQLite.
 *
 * `billing_events` is the table the `ON CONFLICT (billing_event_id) DO NOTHING`
 * claim writes in the SAME `batch()` as the `billing_ledger` row (#150), so a
 * row here is a charge that really settled — not one that was merely built.
 */
async function ledgerEvents(): Promise<Record<string, unknown>[]> {
  const result = await db
    .prepare(
      "SELECT billing_events.event_json AS event_json FROM billing_events " +
        "JOIN billing_ledger ON billing_ledger.id = billing_events.billing_event_id " +
        "ORDER BY billing_events.billing_event_id",
    )
    .all<{ event_json: string }>();
  return result.results.map((row) => JSON.parse(row.event_json) as Record<string, unknown>);
}

/**
 * One inference request through the deployed composition, with whatever
 * headers the case wants. Returns the queue so the published report can be
 * inspected alongside the durable row.
 */
async function meteredRequest(headers: Record<string, string>): Promise<{
  readonly status: number;
  readonly queue: RecordingQueue;
}> {
  const queue = new RecordingQueue();
  const sink = createMeteringUsageSink({
    priceBook: pricedBook(),
    bindings: meteringBindingsFromEnv,
  });
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([OPENAI_ROUTE]),
        usage: sink,
      }),
    ],
    // The deployed order — the drain is outermost so it sees the final response.
    middleware: [meteringDrain(sink)],
  });

  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    BILLING: queue,
    GATEWAY_STATIC_API_KEYS: JSON.stringify([
      { key: "fg_root", id: "key_root", platform_operator: true },
    ]),
  };

  const provider = interceptProviderFetch(() =>
    providerJson({
      id: "chatcmpl-1",
      object: "chat.completion",
      model: "gpt-4o-mini",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    }),
  );
  try {
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: {
          authorization: "Bearer fg_root",
          "content-type": "application/json",
          ...headers,
        },
        body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] }),
      }),
      bindings,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    return { status: response.status, queue };
  } finally {
    provider.restore();
  }
}

describe("the ledger row carries the agent run that caused the spend", () => {
  test("a declared x-ferrogate-agent-run-id reaches the settled event_json", async () => {
    const { status, queue } = await meteredRequest({
      [AGENT_RUN_ID_HEADER]: "agent-run-42",
    });
    expect(status).toBe(200);

    const events = await ledgerEvents();
    expect(events).toHaveLength(1);
    // THE assertion the finding is about: the model spend is joinable to the
    // run. Without it an investigator sees asset pulls and MCP calls only.
    expect(events[0]?.agent_run_id).toBe("agent-run-42");

    // ...and the downstream report carries it too, so a warehouse join does not
    // need the gateway's own database.
    const [message] = queue.sent;
    expect((message?.event as { agent_run_id?: string } | undefined)?.agent_run_id).toBe(
      "agent-run-42",
    );
  });

  test("an ABSENT header omits the field rather than writing null or empty", async () => {
    // serde's `skip_serializing_if = "Option::is_none"`: absence is absence. A
    // `null` or `""` would make "no run declared" indistinguishable from "a run
    // declared nothing", and would break the wire parity `wire.ts` maintains.
    const { status } = await meteredRequest({});
    expect(status).toBe(200);
    const events = await ledgerEvents();
    expect(events).toHaveLength(1);
    expect("agent_run_id" in (events[0] ?? {})).toBe(false);
  });

  test("a MALFORMED header is not stamped onto the charge", async () => {
    // The correlation id is a joined key. Admitting `run 42; DROP` or a
    // 4 KiB blob would poison the join rather than enrich it, and Rust
    // validates the same shape at ingress (`400 invalid_agent_run_id_header`).
    const { status } = await meteredRequest({ [AGENT_RUN_ID_HEADER]: "_leading-underscore" });
    expect(status).toBe(200);
    const events = await ledgerEvents();
    expect("agent_run_id" in (events[0] ?? {})).toBe(false);
  });
});

describe("agentRunIdFor — the header contract", () => {
  test("accepts the Rust #522 shape and nothing else", () => {
    for (const good of ["a", "run-42", "job_1:step.2", "A1234567890", "x".repeat(128)]) {
      expect(agentRunIdFor(good), good).toBe(good);
    }
    for (const bad of [
      "",
      "   ",
      "_leading",
      "-leading",
      ".leading",
      "has space",
      "has/slash",
      "x".repeat(129),
    ]) {
      expect(agentRunIdFor(bad), JSON.stringify(bad)).toBeUndefined();
    }
    expect(agentRunIdFor(undefined)).toBeUndefined();
    expect(agentRunIdFor(null)).toBeUndefined();
  });

  test("trims, exactly as the asset ingress does", () => {
    expect(agentRunIdFor("  run-42  ")).toBe("run-42");
  });

  test("is the SAME pattern the asset ingress enforces, character for character", () => {
    // The twin lives in `src/assets/handlers.ts` as a module-private `const`,
    // so it cannot be imported — and two implementations of one rule is the
    // failure mode this project keeps re-learning. The source is read with
    // Vite's `?raw` (the same mechanism `test/env-var-drift.test.ts` uses) and
    // the literal is compared, so a change to either side is loud.
    const sources = import.meta.glob("../../src/assets/handlers.ts", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
    const handlers = Object.values(sources)[0] ?? "";
    expect(handlers, "src/assets/handlers.ts was not readable").not.toBe("");
    expect(handlers).toContain(`const AGENT_RUN_ID = ${AGENT_RUN_ID_PATTERN.toString()};`);
  });
});

describe("chargeWithAgentRun — attribution belongs to ONE request", () => {
  test("stamps the charge whose request id the attribution names", () => {
    const charge = chargeFixture("fg-000000000000002a", 4n);
    const stamped = chargeWithAgentRun(charge, {
      requestId: charge.requestId,
      agentRunId: "run-9",
    });
    expect(stamped.event.agent_run_id).toBe("run-9");
    // The idempotency key must not move: it is the PRIMARY KEY of three tables,
    // and a charge that changed id on a retry would double-bill.
    expect(stamped.id).toBe(charge.id);
    expect(stamped.entry).toBe(charge.entry);
  });

  test("leaves a DIFFERENT request's charge alone", () => {
    // One drain pass can pick up an outbox row left behind by an earlier
    // request whose drain failed. Stamping this request's run id onto that
    // charge would attribute one run's spend to another — the same
    // under-attribution-never-mis-attribution rule `usageWriteFor` follows.
    const charge = chargeFixture("fg-000000000000002a", 4n);
    const stamped = chargeWithAgentRun(charge, {
      requestId: "fg-someone-else",
      agentRunId: "run-9",
    });
    expect(stamped).toBe(charge);
    expect(stamped.event.agent_run_id).toBeUndefined();
  });

  test("never overwrites an id the request path already threaded", () => {
    // The inference seam wins: that value was validated at ingress against the
    // Rust ladder, and is the one Rust itself stamps.
    const charge = chargeWithAgentRun(chargeFixture("fg-000000000000002a", 4n), {
      requestId: "fg-000000000000002a",
      agentRunId: "from-ingress",
    });
    const restamped = chargeWithAgentRun(charge, {
      requestId: charge.requestId,
      agentRunId: "from-drain",
    });
    expect(restamped.event.agent_run_id).toBe("from-ingress");
  });

  test("is a no-op with no attribution and with no run id", () => {
    const charge = chargeFixture("fg-000000000000002a", 4n);
    expect(chargeWithAgentRun(charge, undefined)).toBe(charge);
    expect(chargeWithAgentRun(charge, { requestId: charge.requestId })).toBe(charge);
  });
});

describe("the inference seam — Usage.agentRunId", () => {
  test("billingEventFromUsage carries an id the request path threaded", () => {
    // The ONE-LINE change documented in `src/metering/event.ts` for the
    // inference slice: `agentRunId` on the `Usage` it hands `record()`. This
    // side is ready and pinned, so the two halves cannot land out of order.
    const event = billingEventFromUsage(
      { ...usageFixture(), agentRunId: "run-from-handler" },
      { nowUnixSeconds: 1_700_000_000 },
    );
    expect(event.agent_run_id).toBe("run-from-handler");
  });

  test("...and validates it, so a malformed thread cannot poison the join", () => {
    const event = billingEventFromUsage(
      { ...usageFixture(), agentRunId: "not a valid id" },
      { nowUnixSeconds: 1_700_000_000 },
    );
    expect(event.agent_run_id).toBeUndefined();
  });

  test("omits the field entirely when the request path threaded nothing", () => {
    const event = billingEventFromUsage(usageFixture(), { nowUnixSeconds: 1_700_000_000 });
    expect("agent_run_id" in event).toBe(false);
  });
});
