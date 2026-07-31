// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Worker-side coverage for #409's acceptance criterion "the deployed server passes
//   the same list/execute E2E as an external upstream", plus the authless variant landed in
//   d1a62932 with no executable guard. Drives a REAL MCP session (initialize -> tools/list ->
//   tools/call) against the REAL Worker in workerd via @cloudflare/vitest-pool-workers, through
//   the Durable Object the deploy metadata's `new_sqlite_classes` migration declares. No Docker,
//   no Cloudflare account, no network.
//
//   WHY THIS EXISTS: bearer.test.ts stops at the front door — it proves who is admitted, never
//   that anything is behind it. Nothing executed a tool, nothing proved the per-session
//   `callCount` state the DO exists for, and the authless branch (`isAuthless`, the omitted
//   OAUTH_KV binding, the 404 for every other path) had zero coverage.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { describe, it, expect } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker, { isAuthless, type Env, type SecretsStoreSecretBinding } from "../src/index";

/** Counting Secrets Store stub (see bearer.test.ts) — used here for negatives. */
class StubStore implements SecretsStoreSecretBinding {
  reads = 0;
  async get(): Promise<string> {
    this.reads += 1;
    return "from-store";
  }
}

function testEnv(overrides: Partial<Env> = {}): Env {
  return { ...(env as unknown as Env), ...overrides };
}

/** The authless deployment: `MCP_AUTH_MODE=authless`, exactly as the deploy metadata sets it. */
function authlessEnv(overrides: Partial<Env> = {}): Env {
  return testEnv({ MCP_AUTH_MODE: "authless", ...overrides });
}

async function fetchWorker(request: Request, workerEnv: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, workerEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

interface JsonRpcResponse {
  jsonrpc: string;
  id?: number;
  result?: any;
  error?: { code: number; message: string };
}

/**
 * Read one JSON-RPC response out of a Streamable-HTTP reply, which the MCP SDK
 * frames either as `application/json` or as an SSE stream that STAYS OPEN after
 * the reply (that is the point of Streamable HTTP). So the SSE case is consumed
 * incrementally and cancelled at the first `data:` frame — `response.text()`
 * would wait for an end that never comes.
 *
 * Written by hand rather than via the SDK client so the assertions are about the
 * Worker's bytes, not about a client library's retry behaviour.
 */
async function readRpc(response: Response): Promise<JsonRpcResponse> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("text/event-stream")) {
    return JSON.parse(await response.text());
  }
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (value) buffered += decoder.decode(value, { stream: true });
      const dataLine = buffered
        .split("\n")
        .map((line) => line.trim())
        .find((line) => line.startsWith("data:"));
      if (dataLine) return JSON.parse(dataLine.slice("data:".length).trim());
      if (done) throw new Error(`stream ended with no SSE data frame: ${JSON.stringify(buffered)}`);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

const MCP_ACCEPT = "application/json, text/event-stream";

/** A live MCP session against the Worker: a session id plus a `call` helper. */
class McpSession {
  private nextId = 100;
  private constructor(
    readonly sessionId: string,
    private readonly workerEnv: Env,
  ) {}

  private static async post(
    workerEnv: Env,
    body: unknown,
    sessionId?: string,
  ): Promise<Response> {
    return fetchWorker(
      new Request("https://mcp.test/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: MCP_ACCEPT,
          ...(sessionId ? { "mcp-session-id": sessionId } : {}),
        },
        body: JSON.stringify(body),
      }),
      workerEnv,
    );
  }

  /** Perform the MCP `initialize` handshake and return the established session. */
  static async open(workerEnv: Env): Promise<McpSession> {
    const response = await McpSession.post(workerEnv, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "ferrogate-test", version: "0.0.0" },
      },
    });
    expect(response.status, `initialize failed: ${response.status}`).toBe(200);
    const sessionId = response.headers.get("mcp-session-id");
    expect(sessionId, "the transport must issue an Mcp-Session-Id").toBeTruthy();
    const initialized = await readRpc(response);
    expect(initialized.error).toBeUndefined();
    expect(initialized.result.serverInfo.name).toBe("ferrogate-mcp-server");

    await McpSession.post(
      workerEnv,
      { jsonrpc: "2.0", method: "notifications/initialized" },
      sessionId!,
    );
    return new McpSession(sessionId!, workerEnv);
  }

  async call(method: string, params: unknown = {}): Promise<JsonRpcResponse> {
    const response = await McpSession.post(
      this.workerEnv,
      { jsonrpc: "2.0", id: this.nextId++, method, params },
      this.sessionId,
    );
    expect(response.status, `${method} -> HTTP ${response.status}`).toBe(200);
    return readRpc(response);
  }

  /** The `whoami` tool's decoded payload (principal + persisted call count). */
  async whoami(): Promise<{ userId: string; callCount: number }> {
    const result = await this.call("tools/call", { name: "whoami", arguments: {} });
    expect(result.error).toBeUndefined();
    return JSON.parse(result.result.content[0].text);
  }
}

describe("the authless variant's front door", () => {
  it("serves /mcp with no credential at all", async () => {
    const response = await fetchWorker(
      new Request("https://mcp.test/mcp", {
        method: "POST",
        headers: { "content-type": "application/json", accept: MCP_ACCEPT },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      }),
      authlessEnv(),
    );

    // Positive proof it reached the transport: only code past the front door
    // emits the transport's own session-id complaint. A bare `!== 401` would be
    // satisfied by any 500.
    expect(response.status).toBe(400);
    const body = await readRpc(response);
    expect(body.error?.message ?? "").toContain("Mcp-Session-Id");
  });

  it("serves /sse with no credential and does not answer anything else", async () => {
    const sse = await fetchWorker(
      new Request("https://mcp.test/sse", { headers: { accept: "text/event-stream" } }),
      authlessEnv(),
    );
    expect(sse.status).toBe(200);
    expect(sse.headers.get("content-type") ?? "").toContain("text/event-stream");

    // The OAuth endpoints are ABSENT, not merely bypassed: an authless deploy
    // declares no OAUTH_KV binding, so routing them to the provider would 500 on
    // an undefined namespace instead of saying "no such route".
    for (const path of ["/authorize", "/token", "/register", "/", "/mcp/extra"]) {
      const response = await fetchWorker(
        new Request(`https://mcp.test${path}`, { method: "GET" }),
        authlessEnv(),
      );
      expect(response.status, `${path} must 404 in authless mode`).toBe(404);
    }
  });

  it("performs no Secrets Store read, because there is no credential to compare", async () => {
    const store = new StubStore();
    const response = await fetchWorker(
      new Request("https://mcp.test/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: MCP_ACCEPT,
          authorization: "Bearer from-store",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      }),
      authlessEnv({ MCP_BEARER_TOKEN_STORE: store }),
    );

    expect(response.status).toBe(400);
    expect(store.reads).toBe(0);
  });

  it("keeps the liveness probe answering in authless mode too", async () => {
    const response = await fetchWorker(new Request("https://mcp.test/healthz"), authlessEnv());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, worker: "ferrogate-mcp-server" });
  });

  it("fails CLOSED for anything that is not exactly the authless value", async () => {
    // An OAuth deployment whose MCP_AUTH_MODE binding was dropped by a redeploy
    // must keep its front door, not lose it.
    for (const mode of [undefined, "", "oauth", "authless-ish", "no", "0", "true"]) {
      expect(isAuthless(testEnv({ MCP_AUTH_MODE: mode })), `mode ${mode}`).toBe(false);
      const response = await fetchWorker(
        new Request("https://mcp.test/mcp", {
          method: "POST",
          headers: { "content-type": "application/json", accept: MCP_ACCEPT },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
        }),
        testEnv({ MCP_AUTH_MODE: mode, MCP_BEARER_TOKEN: undefined }),
      );
      expect(response.status, `mode ${mode} must stay behind OAuth`).toBe(401);
    }

    // …while operator-typed whitespace/case in wrangler.toml still selects it.
    for (const mode of ["authless", " authless ", "AUTHLESS", "Authless\n"]) {
      expect(isAuthless(testEnv({ MCP_AUTH_MODE: mode })), `mode ${mode}`).toBe(true);
    }
  });
});

describe("the deployed tool surface (the list/execute E2E #409 accepts on)", () => {
  it("lists exactly the FerroGate-defined base tools with usable schemas", async () => {
    const session = await McpSession.open(authlessEnv());
    const listed = await session.call("tools/list");
    expect(listed.error).toBeUndefined();

    const tools: Array<{ name: string; description?: string; inputSchema: any }> =
      listed.result.tools;
    expect(tools.map((tool) => tool.name).sort()).toEqual(["add", "echo", "whoami"]);

    // A tool a client cannot call is not a tool surface: every entry must carry a
    // description and an object input schema.
    for (const tool of tools) {
      expect(tool.description ?? "", `${tool.name} description`).not.toBe("");
      expect(tool.inputSchema?.type, `${tool.name} inputSchema`).toBe("object");
    }
    const echo = tools.find((tool) => tool.name === "echo")!;
    expect(Object.keys(echo.inputSchema.properties ?? {})).toEqual(["message"]);
    expect(echo.inputSchema.required).toEqual(["message"]);
  });

  it("executes each tool and returns its real result", async () => {
    const session = await McpSession.open(authlessEnv());

    const echoed = await session.call("tools/call", {
      name: "echo",
      arguments: { message: "hello ferrogate" },
    });
    expect(echoed.error).toBeUndefined();
    expect(echoed.result.content[0]).toEqual({ type: "text", text: "hello ferrogate" });

    const sum = await session.call("tools/call", { name: "add", arguments: { a: 2, b: 40 } });
    expect(sum.error).toBeUndefined();
    // Computed, not echoed: 42 appears in neither argument.
    expect(sum.result.content[0].text).toBe("42");
  });

  it("rejects a bad tool name and bad arguments instead of executing something", async () => {
    const session = await McpSession.open(authlessEnv());

    const unknown = await session.call("tools/call", { name: "rm-rf", arguments: {} });
    expect(unknown.result?.isError ?? unknown.error !== undefined).toBe(true);

    // `add` takes numbers; a string must not be coerced into a concatenation.
    const wrongType = await session.call("tools/call", {
      name: "add",
      arguments: { a: "2", b: 40 },
    });
    const failed = wrongType.error !== undefined || wrongType.result?.isError === true;
    expect(failed, `add("2", 40) must be refused, got ${JSON.stringify(wrongType)}`).toBe(true);
    if (!failed) return;
    expect(JSON.stringify(wrongType)).not.toContain("240");
  });

  it("persists callCount across calls in one session (this is what the DO is for)", async () => {
    const session = await McpSession.open(authlessEnv());

    // whoami reports state without bumping it, so the count reflects echo/add only.
    expect((await session.whoami()).callCount).toBe(0);

    await session.call("tools/call", { name: "echo", arguments: { message: "one" } });
    expect((await session.whoami()).callCount).toBe(1);

    await session.call("tools/call", { name: "add", arguments: { a: 1, b: 1 } });
    await session.call("tools/call", { name: "echo", arguments: { message: "three" } });
    expect((await session.whoami()).callCount).toBe(3);
  });

  it("isolates state between sessions — one DO instance per session, not per Worker", async () => {
    const workerEnv = authlessEnv();
    const first = await McpSession.open(workerEnv);
    const second = await McpSession.open(workerEnv);
    expect(first.sessionId).not.toBe(second.sessionId);

    await first.call("tools/call", { name: "echo", arguments: { message: "only mine" } });
    await first.call("tools/call", { name: "echo", arguments: { message: "also mine" } });

    expect((await first.whoami()).callCount).toBe(2);
    // A shared/global counter would read 2 here.
    expect((await second.whoami()).callCount).toBe(0);

    // …and the first session is unaffected by the second's traffic.
    await second.call("tools/call", { name: "add", arguments: { a: 1, b: 2 } });
    expect((await first.whoami()).callCount).toBe(2);
    expect((await second.whoami()).callCount).toBe(1);
  });

  it("runs the identical list/execute flow through the automation-bearer door", async () => {
    // The acceptance criterion is about the DEPLOYED server, and the deployed
    // default is OAuth mode with an automation bearer — not authless. The same
    // flow must work there, or the E2E only proves the variant nobody deploys.
    const workerEnv = testEnv({
      MCP_AUTH_MODE: "oauth",
      MCP_BEARER_TOKEN_STORE: undefined,
      MCP_BEARER_TOKEN: "automation-token",
    });
    const authorized = (body: unknown, sessionId?: string) =>
      fetchWorker(
        new Request("https://mcp.test/mcp", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: MCP_ACCEPT,
            authorization: "Bearer automation-token",
            ...(sessionId ? { "mcp-session-id": sessionId } : {}),
          },
          body: JSON.stringify(body),
        }),
        workerEnv,
      );

    const init = await authorized({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "ferrogate-test", version: "0.0.0" },
      },
    });
    expect(init.status).toBe(200);
    const sessionId = init.headers.get("mcp-session-id")!;
    expect(sessionId).toBeTruthy();
    await authorized({ jsonrpc: "2.0", method: "notifications/initialized" }, sessionId);

    const listed = await readRpc(await authorized({ jsonrpc: "2.0", id: 2, method: "tools/list" }, sessionId));
    expect(listed.result.tools.map((tool: { name: string }) => tool.name).sort()).toEqual([
      "add",
      "echo",
      "whoami",
    ]);

    const executed = await readRpc(
      await authorized(
        { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "add", arguments: { a: 20, b: 22 } } },
        sessionId,
      ),
    );
    expect(executed.error).toBeUndefined();
    expect(executed.result.content[0].text).toBe("42");

    // The session belongs to the credential-checked door: the same session id
    // presented WITHOUT the bearer must not keep working.
    const unauthenticated = await fetchWorker(
      new Request("https://mcp.test/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: MCP_ACCEPT,
          "mcp-session-id": sessionId,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list" }),
      }),
      workerEnv,
    );
    expect(unauthenticated.status).toBe(401);
  });
});
