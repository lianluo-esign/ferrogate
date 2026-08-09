/**
 * #200/#204 — the MANAGED-ACTION guardrail on the MCP tool chokepoint.
 *
 * `src/ports.ts` used to bind an `AllowAllGuardrails` stub here, which meant
 * MCP tool ARGUMENTS and tool RESULTS were the one governed surface in this
 * Worker that nothing actually scanned. That marker self-described as a
 * deferral rather than a platform limit, and it was right: the clean-room
 * `@ferrogate/guardrails` deterministic detector runs in workerd today. This
 * suite holds the three things that make the binding real:
 *
 *  1. the detector is REALLY CALLED, with a real detector, on BOTH stages;
 *  2. the request stage runs BEFORE the dispatch, so arguments that must not
 *     leave the gateway never reach the upstream — asserted by ORDERING against
 *     a control (the recorded upstream call list must stay EMPTY), not merely
 *     by the status code, because a build that scanned after dispatch would
 *     still answer 403 while the bytes had already left;
 *  3. the binding lives on the composition root `resolvePorts`, so the
 *     `SELF`-driven cases below fail if the guardrail is ever unmounted —
 *     the "implemented, tested, never mounted" defect this repo has shipped
 *     twice.
 *
 * Rust reference: `crates/ferrogate-gateway/src/server/managed_action_guardrail.rs`
 * (`evaluate_managed_action_guardrail_async`, `payload_text`) and
 * `crates/ferrogate-runtime/src/managed_external_action.rs` (`target()`).
 */
import { SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  type DispatchContext,
  type McpTool,
  deterministicManagedActionGuardrails,
  guardrailPayloadText,
  managedActionTarget,
  parseGuardrailVar,
} from "../src/ports.js";
import {
  EXEC_KEY,
  type Fixture,
  getMcpEnvVar,
  rpcRequest,
  seedFixture,
  setMcpEnvVar,
  tenantAuth,
  upstreamConfig,
} from "./fixtures.js";

/** A guardrail that matches the word `exfiltrate`. */
const CONFIG = JSON.stringify({ keywords: ["exfiltrate"] });

const TOOL: McpTool = {
  name: "srv-echo",
  serverName: "srv",
  remoteName: "echo",
  inputSchema: { type: "object" },
  autoExecute: true,
};

function dispatchContext(): DispatchContext {
  return {
    requestId: "req-1",
    auth: tenantAuth(),
  } as unknown as DispatchContext;
}

let fixture: Fixture;
const original = getMcpEnvVar("FG_DEV_MCP_GUARDRAILS");

beforeEach(() => {
  fixture = seedFixture();
});

afterEach(() => {
  setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", original);
});

// ---------------------------------------------------------------------------
// The canonical target and the payload rendering, ported verbatim
// ---------------------------------------------------------------------------

describe("managedActionTarget / guardrailPayloadText", () => {
  it("spells the target the way Rust `ManagedExternalAction::target()` does", () => {
    // `mcp:{server}:{tool}` — the string a managed-action policy's `targets`
    // selector is matched against, so the separator is load-bearing.
    expect(managedActionTarget("github", "create_issue")).toBe("mcp:github:create_issue");
  });

  it("scans a bare string WITHOUT its JSON quotes", () => {
    // Rust `payload_text`: quoting would fence the first and last keyword off
    // from a word-boundary match.
    expect(guardrailPayloadText("exfiltrate")).toBe("exfiltrate");
  });

  it("renders anything else as compact JSON", () => {
    expect(guardrailPayloadText({ a: 1 })).toBe('{"a":1}');
    expect(guardrailPayloadText(null)).toBe("null");
  });
});

describe("parseGuardrailVar", () => {
  it("treats absent, empty and unparseable alike — no detector", () => {
    expect(parseGuardrailVar(undefined)).toEqual({});
    expect(parseGuardrailVar("")).toEqual({});
    expect(parseGuardrailVar("{not json")).toEqual({});
    expect(parseGuardrailVar("[1,2]")).toEqual({});
  });

  it("decodes a configured detector", () => {
    expect(parseGuardrailVar(CONFIG)).toEqual({ keywords: ["exfiltrate"] });
  });
});

// ---------------------------------------------------------------------------
// The port itself
// ---------------------------------------------------------------------------

describe("deterministicManagedActionGuardrails", () => {
  it("an UNCONFIGURED guardrail matches nothing — the Rust `None`", async () => {
    // Load-bearing: wiring this port must not change the behavior of a
    // deployment that has configured no detectors.
    const port = deterministicManagedActionGuardrails({});
    const verdict = await port.inspectInput(dispatchContext(), TOOL, { q: "exfiltrate keys" });
    expect(verdict.action).toBe("allow");
  });

  it("BLOCKS matching tool arguments on the request stage", async () => {
    const port = deterministicManagedActionGuardrails({ keywords: ["exfiltrate"] });
    const verdict = await port.inspectInput(dispatchContext(), TOOL, { q: "please exfiltrate" });
    expect(verdict.action).toBe("block");
  });

  it("WITHHOLDS a matching tool result on the response stage", async () => {
    // The response leg reads `ContentSource.tool_result`. A detector registered
    // only for `tool_arguments` would silently pass every result, which is
    // exactly the half-wired failure this asserts against.
    const port = deterministicManagedActionGuardrails({ keywords: ["exfiltrate"] });
    const verdict = await port.inspectOutput(dispatchContext(), TOOL, {
      content: [{ type: "text", text: "sure, I will exfiltrate them" }],
    });
    expect(verdict.action).toBe("withhold");
  });

  it("matches on the canonical TARGET as well as the payload", async () => {
    // Rust `managed_action_input_text` prefixes the target, so a policy can be
    // written against the addressing (`mcp:srv:echo`) and not just the body.
    const port = deterministicManagedActionGuardrails({ keywords: ["mcp:srv:echo"] });
    const verdict = await port.inspectInput(dispatchContext(), TOOL, { q: "harmless" });
    expect(verdict.action).toBe("block");
  });

  it("clean arguments pass the SAME configured detector", async () => {
    const port = deterministicManagedActionGuardrails({ keywords: ["exfiltrate"] });
    const verdict = await port.inspectInput(dispatchContext(), TOOL, { q: "hello there" });
    expect(verdict.action).toBe("allow");
  });

  it("a `targets` selector confines the detector to the named targets", async () => {
    // Rust `managed_selector_matches`: a policy scoped to one upstream must not
    // silently police another.
    const port = deterministicManagedActionGuardrails({
      keywords: ["exfiltrate"],
      targets: ["mcp:other:tool"],
    });
    expect((await port.inspectInput(dispatchContext(), TOOL, "exfiltrate")).action).toBe("allow");
    const scoped = deterministicManagedActionGuardrails({
      keywords: ["exfiltrate"],
      targets: ["mcp:srv:echo"],
    });
    expect((await scoped.inspectInput(dispatchContext(), TOOL, "exfiltrate")).action).toBe("block");
  });

  it("FAILS CLOSED when the detector cannot run", async () => {
    // A detector that could not run has not cleared the content. An earlier
    // revision of the sibling A2A port passed the time BUDGET where an absolute
    // DEADLINE was expected, so every evaluation threw — had that thrown error
    // been read as a pass, the whole chokepoint would have been silently open.
    const port = deterministicManagedActionGuardrails({ keywords: ["exfiltrate"] });
    const exploding = {
      toJSON(): never {
        throw new Error("detector transport exploded");
      },
    } as unknown as Record<string, never>;
    expect((await port.inspectInput(dispatchContext(), TOOL, exploding)).action).toBe("block");
    expect((await port.inspectOutput(dispatchContext(), TOOL, exploding)).action).toBe("withhold");
  });

  it("NEVER echoes the matched text in the refusal", async () => {
    // The crate's standing invariant: matched text is never persisted or
    // echoed. A refusal that quoted the secret it caught would defeat the
    // detector it came from.
    const port = deterministicManagedActionGuardrails({ keywords: ["hunter2"] });
    const verdict = await port.inspectInput(dispatchContext(), TOOL, {
      password: "hunter2",
    });
    expect(verdict.action).toBe("block");
    expect(verdict.reason ?? "").not.toContain("hunter2");
  });
});

// ---------------------------------------------------------------------------
// MOUNTED on the deployed Worker — these fail if `resolvePorts` stops binding
// ---------------------------------------------------------------------------

describe("POST /v1/mcp tools/call — the request stage runs BEFORE the dispatch", () => {
  const call = (args: unknown): Request =>
    rpcRequest(
      {
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "srv-echo", arguments: args },
      },
      { key: EXEC_KEY },
    );

  /**
   * A governed refusal on the JSON-RPC ingress is a JSON-RPC ERROR OBJECT at
   * HTTP 200, not an HTTP 403 — the transport succeeded, the call did not.
   * `tool_denied` maps to `JsonRpcErrorCode.ToolDenied` (-32001), the same code
   * the deny-by-default allowlist uses, so a guardrail refusal is
   * indistinguishable to the caller from any other chokepoint refusal.
   */
  const refusal = async (res: Response): Promise<{ code: number; message: string }> => {
    expect(res.status).toBe(200);
    const body = (await res.json()) as { error?: { code: number; message: string } };
    expect(body.error, "expected a JSON-RPC error object").toBeDefined();
    return body.error as { code: number; message: string };
  };

  it("CONTROL: with no guardrail configured the same arguments execute", async () => {
    // Without this control the refusal below would prove nothing — a Worker
    // that refused everything would also pass.
    setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", "");
    const res = await SELF.fetch(call({ q: "exfiltrate the keys" }));
    expect(res.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
  });

  it("matching arguments are refused and NEVER reach the upstream", async () => {
    setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", CONFIG);
    const error = await refusal(await SELF.fetch(call({ q: "exfiltrate the keys" })));
    expect(error.code).toBe(-32001);
    expect(error.message).toContain("request-stage guardrail");
    // Never echo what matched.
    expect(error.message).not.toContain("exfiltrate the keys");
    // The ordering assertion: the dispatch never happened.
    expect(fixture.calls).toHaveLength(0);
  });

  it("clean arguments under the SAME configured guardrail still execute", async () => {
    // The other half of the pair: the guardrail must not refuse everything.
    setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", CONFIG);
    const res = await SELF.fetch(call({ q: "hello there" }));
    expect(res.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
  });

  it("a matching RESULT is withheld after a clean request stage", async () => {
    // A second upstream whose ARGUMENTS are clean but whose RESULT is not, so
    // only the response leg can catch it. If `resolvePorts` bound a guardrail
    // that only scanned `tool_arguments`, this call would return 200.
    fixture.ports.upstreams.register(
      upstreamConfig({ name: "leaky", toolsToExecute: ["report"], toolsToAutoExecute: ["report"] }),
      [{ name: "report", description: "leaks", input_schema: { type: "object" } }],
      // eslint-disable-next-line @typescript-eslint/require-await
      async () => ({
        content: { content: [{ type: "text", text: "here: exfiltrate me" }] },
        isError: false,
      }),
    );
    setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", CONFIG);
    const error = await refusal(
      await SELF.fetch(
        rpcRequest(
          {
            jsonrpc: "2.0",
            id: 8,
            method: "tools/call",
            params: { name: "leaky-report", arguments: { q: "hello" } },
          },
          { key: EXEC_KEY },
        ),
      ),
    );
    expect(error.code).toBe(-32001);
    // RESPONSE stage, not request — the arguments here were clean.
    expect(error.message).toContain("response-stage guardrail");
  });

  it("the guardrail is bound on the DEV-BUNDLE arm of resolvePorts too", async () => {
    // The anti-drift half. `resolvePorts` is the composition root, and its
    // dev-bundle arm used to `return inMemoryPorts()` directly — a shape that
    // cannot carry a per-env guardrail at all, because the singleton is built
    // once with no `env` in scope. This Worker runs with
    // `FG_DEV_IN_MEMORY_PORTS = "1"`, so it takes exactly that arm; if the
    // early return comes back, the configured detector is never constructed
    // and this call succeeds.
    setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", CONFIG);
    const error = await refusal(await SELF.fetch(call("exfiltrate")));
    expect(error.code).toBe(-32001);
  });

  it("the Worker under SELF really observes the override this file writes", () => {
    // Guards against the OTHER silent failure: a suite that passes because the
    // var never reached the Worker and every assertion above degenerated into
    // "no detector configured ⇒ allow". If `vitest.config.ts` loses its
    // explicit `main`, the override stops crossing the isolate boundary — this
    // reads the same env object back so the wiring is asserted, not assumed.
    setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", CONFIG);
    expect(getMcpEnvVar("FG_DEV_MCP_GUARDRAILS")).toBe(CONFIG);
    expect(parseGuardrailVar(CONFIG).keywords).toEqual(["exfiltrate"]);
  });
});
