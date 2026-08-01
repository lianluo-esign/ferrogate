/**
 * `POST /v1/agent-runs` — the `createAgentRun` CONTRACT (cutover HOLD item A2).
 *
 * The wave-19 verdict recorded that this route "is not the operation the
 * contract names": it answered the async-job envelope under the synchronous
 * operation's name, and `max_turns`, `timeout_millis` and `tool_calls` had **no
 * reader anywhere in `apps/agent-runtime/src`** — accepted, validated by
 * nothing, dropped.
 *
 * Everything asserted here is driven through `SELF.fetch` against the app the
 * Worker exports, so a gate that exists but is unreachable fails the file.
 *
 * ## What is NOT asserted, and why (the reasoned TS decision)
 *
 * Rust's handler runs the turn loop IN the request. It can only do that through
 * one of two providers, and BOTH are read directly in
 * `crates/ferrogate-gateway/src/server/agent_runs.rs::agent_provider`:
 *
 *   * `ManagedWorker` — **the serde default** (`AgentRuntimeProvider::default()`
 *     is `ManagedWorker`, `ferrogate-config/src/config/types.rs:1149`) — returns
 *     `Err(("agent_worker_transport_unavailable", "managed agent runtime
 *     requires the external agent-worker Firecracker microVM transport, which is
 *     not implemented yet"))`. A DEFAULT Rust deployment therefore answers
 *     **503** to every `POST /v1/agent-runs`.
 *   * `External` — `ExternalAgentProvider::with_input`, which SPAWNS A LOCAL
 *     CHILD PROCESS from `agent_runtime.external.command`.
 *
 * So the synchronous half is the unfinished half of a half-finished product,
 * and its one working backend is process spawn — which workerd does not have
 * and which `src/runs/governance.ts` already records as a platform limit. This
 * Worker keeps the dispatch model (the run is enqueued for a leased self-hosted
 * worker or the Sandbox container), which is the CF-native stand-in for
 * "external agent process" and is strictly more than Rust's default answers.
 *
 * What was portable, and is asserted below, is everything else: the validation
 * ladder, the run-id contract, the response FIELD SET a Rust-written client
 * reads, and — the part that made the fields dead — carrying the accepted run
 * plan onto the dispatch, where the executing worker can read it.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { TENANT_A_KEY, WORKER_A, bearer, drainPlane, get, pollLease, post } from "./fixtures.js";

const NOW = 1_800_000_000;

async function code(response: Response): Promise<string> {
  return ((await response.json()) as { error: { code: string } }).error.code;
}

async function createRun(
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return await post("/v1/agent-runs", { ...bearer(TENANT_A_KEY), ...headers }, body);
}

beforeEach(async () => {
  await drainPlane(WORKER_A);
});

describe("createAgentRun answers the field set the contract names", () => {
  it("carries `id`, `turns_executed`, `output` and `tool_results`", async () => {
    const response = await createRun({
      input: "write the patch",
      required_capabilities: ["coding"],
    });
    expect(response.status).toBe(202);
    const json = (await response.json()) as Record<string, unknown>;

    expect(json.object).toBe("agent_run");
    // Rust names the run `id`; the async protocol addresses it as `run_id`. A
    // client written against either must find its field, and the two must be
    // the SAME run — an `id` that disagreed with `run_id` would be worse than
    // an absent one.
    expect(typeof json.id).toBe("string");
    expect(json.id).toBe(json.run_id);
    // The three fields a Rust client reads off the response. Honest values, not
    // fabricated ones: nothing has executed yet.
    expect(json.turns_executed).toBe(0);
    expect(json.output).toBeNull();
    expect(json.tool_results).toEqual([]);
    // The ACCEPTED run plan, echoed so a caller can see the bounds that were
    // applied rather than guessing which defaults it landed on.
    expect(json.max_turns).toBe(4);
    expect(json.timeout_millis).toBe(30_000);
  });

  it("echoes a caller-supplied plan rather than the operator defaults", async () => {
    const response = await createRun({
      input: "bounded",
      required_capabilities: ["coding"],
      max_turns: 2,
      timeout_millis: 5_000,
    });
    expect(response.status).toBe(202);
    const json = (await response.json()) as Record<string, unknown>;
    expect(json.max_turns).toBe(2);
    expect(json.timeout_millis).toBe(5_000);
  });
});

describe("the createAgentRun validation ladder", () => {
  it("400 invalid_agent_run_input for a blank input", async () => {
    // Rust `agent_runs.rs:164` — its OWN code, not the generic one. A client
    // that branches on the code cannot tell an empty prompt from a malformed
    // envelope while they share `invalid_request`.
    const response = await createRun({ input: "   " });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_agent_run_input");
  });

  it.each([
    ["zero", 0],
    ["above the operator limit", 5],
  ])("400 invalid_agent_run_max_turns when max_turns is %s", async (_label, maxTurns) => {
    const response = await createRun({ input: "work", max_turns: maxTurns });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_agent_run_max_turns");
  });

  it("400 invalid_agent_run_max_turns when the plan cannot fit the scripted calls", async () => {
    // Rust `harness_config`: `tool_calls.len() + 1` turns are REQUIRED, so a
    // plan that admits fewer is refused up front rather than truncating the
    // caller's tool calls silently.
    const response = await createRun({
      input: "work",
      max_turns: 2,
      tool_calls: [{ name: "tool.echo" }, { name: "tool.echo" }],
    });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_agent_run_max_turns");
  });

  it.each([
    ["zero", 0],
    ["above the operator limit", 30_001],
  ])("400 invalid_agent_run_timeout when timeout_millis is %s", async (_label, timeout) => {
    const response = await createRun({ input: "work", timeout_millis: timeout });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_agent_run_timeout");
  });

  it.each([
    ["a blank name", { input: "work", tool_calls: [{ name: "   " }] }],
    ["a non-array", { input: "work", tool_calls: "tool.echo" }],
    ["a non-object entry", { input: "work", tool_calls: ["tool.echo"] }],
    ["a non-string name", { input: "work", tool_calls: [{ name: 7 }] }],
  ])("400 invalid_agent_tool_call for %s", async (_label, body) => {
    const response = await createRun(body as Record<string, unknown>);
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_agent_tool_call");
  });

  it("400 invalid_agent_run_id for a malformed body run_id", async () => {
    // Rust reads the run id from the header OR the body field; the body half
    // had no reader here at all, so `run_id` was accepted and ignored.
    const response = await createRun({ input: "work", run_id: "not a valid id!" });
    expect(response.status).toBe(400);
    expect(await code(response)).toBe("invalid_agent_run_id");
  });

  it("a well-formed body run_id ADDRESSES the run", async () => {
    const runId = `body-run-${Date.now()}`;
    const response = await createRun({
      input: "work",
      run_id: runId,
      required_capabilities: ["coding"],
    });
    expect(response.status).toBe(202);
    const json = (await response.json()) as Record<string, unknown>;
    expect(json.id).toBe(runId);
    expect(json.run_id).toBe(runId);
    // And it is really that run: the async verbs resolve it.
    const status = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    expect(status.status).toBe(200);
  });

  it("a refused run is NEVER created", async () => {
    const runId = `refused-run-${Date.now()}`;
    const response = await createRun({ input: "work", run_id: runId, max_turns: 0 });
    expect(response.status).toBe(400);
    const status = await get(`/v1/agent-jobs/${runId}`, bearer(TENANT_A_KEY));
    expect(status.status).toBe(404);
  });
});

describe("the accepted run plan reaches the executor", () => {
  it("rides the dispatch onto the worker's lease", async () => {
    // THE FINDING, in one assertion: `max_turns`, `timeout_millis` and
    // `tool_calls` had no reader. Validating them and then dropping them is the
    // same defect in a politer form, so they must arrive at the ONE component
    // that can act on them — the worker that leases the run.
    const runId = `plan-run-${Date.now()}`;
    const response = await createRun({
      input: "write the patch",
      run_id: runId,
      required_capabilities: ["coding"],
      max_turns: 3,
      timeout_millis: 5_000,
      tool_calls: [{ name: "tool.echo", arguments: { a: 1 }, route: "r1", session_id: "s1" }],
    });
    expect(response.status).toBe(202);

    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    expect(lease?.run_id).toBe(runId);
    expect(lease?.run_plan).toEqual({
      max_turns: 3,
      timeout_millis: 5_000,
      tool_calls: [{ name: "tool.echo", arguments: { a: 1 }, route: "r1", session_id: "s1" }],
    });
  });

  it("omits the plan entirely when the caller declared none", async () => {
    // An OMITTED key, not a fabricated default: the worker must be able to tell
    // "the caller asked for three turns" from "the caller asked for nothing".
    const runId = `plainrun-${Date.now()}`;
    const response = await createRun({
      input: "work",
      run_id: runId,
      required_capabilities: ["coding"],
    });
    expect(response.status).toBe(202);
    const lease = await pollLease(WORKER_A, { nowUnix: NOW });
    expect(lease?.run_id).toBe(runId);
    expect(Object.hasOwn(lease as object, "run_plan")).toBe(false);
  });
});
