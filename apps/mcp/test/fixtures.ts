/**
 * Shared seeding for the `SELF` integration tests.
 *
 * `apps/mcp` codes against the narrow ports in `src/ports.ts`, so an
 * integration test seeds the in-memory bundle (API keys, upstream MCP servers,
 * assets) and then drives the real Worker over HTTP — no mocking of the app's
 * own code, and the exact production routing/auth/governance path runs.
 */
import type { JsonValue } from "@ferrogate/core";

import {
  inMemoryPorts,
  resetInMemoryPorts,
  type AuthContext,
  type DispatchContext,
  type McpDispatchHeaders,
  type McpServerConfig,
  type McpTool,
} from "../src/ports.js";

export const READ_KEY = "fg_test_read_key";
export const EXEC_KEY = "fg_test_exec_key";
export const NO_SCOPE_KEY = "fg_test_no_scope_key";

export const TENANT = "tenant-1";
export const WORKSPACE = "ws-1";
export const USER = "user-1";

/** Every call the seeded upstream received, in order. */
export interface RecordedCall {
  tool: McpTool;
  args: JsonValue;
  identity: McpDispatchHeaders;
  context: DispatchContext;
}

export interface Fixture {
  ports: ReturnType<typeof inMemoryPorts>;
  calls: RecordedCall[];
}

export function tenantAuth(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    apiKeyId: "key-1",
    organizationId: TENANT,
    workspaceId: WORKSPACE,
    userId: USER,
    scopes: ["tools.read", "tools.execute", "assets.read"],
    permissions: ["mcp.execute"],
    platformOperator: false,
    ...overrides,
  };
}

export function upstreamConfig(overrides: Partial<McpServerConfig> = {}): McpServerConfig {
  return {
    name: "srv",
    transport: "streamable_http",
    url: "https://upstream.test/mcp",
    authType: "none",
    toolsToExecute: ["echo"],
    toolsToAutoExecute: ["echo"],
    timeoutMs: 5_000,
    ...overrides,
  };
}

/**
 * Reset every port and seed the standard fixture: two API keys, one upstream
 * MCP server exposing an allowlisted `echo` plus an un-allowlisted `danger`.
 */
export function seedFixture(): Fixture {
  resetInMemoryPorts();
  const ports = inMemoryPorts();
  const calls: RecordedCall[] = [];

  ports.auth
    .register(READ_KEY, tenantAuth({ scopes: ["tools.read", "assets.read"] }))
    .register(EXEC_KEY, tenantAuth())
    .register(NO_SCOPE_KEY, tenantAuth({ scopes: [] }));

  ports.upstreams.register(
    upstreamConfig(),
    [
      { name: "echo", description: "echoes its input", input_schema: { type: "object" } },
      // Present upstream but NOT allowlisted — must never be listed or callable.
      { name: "danger", description: "not allowlisted", input_schema: { type: "object" } },
    ],
    // eslint-disable-next-line @typescript-eslint/require-await
    async (tool, args, identity, context) => {
      calls.push({ tool, args, identity, context });
      return {
        content: { content: [{ type: "text", text: JSON.stringify(args) }] },
        isError: false,
      };
    },
  );

  return { ports, calls };
}

/** POST a JSON-RPC body to `/v1/mcp`. */
export function rpcRequest(
  body: Record<string, unknown>,
  init: { key?: string; headers?: Record<string, string> } = {},
): Request {
  const headers = new Headers({ "content-type": "application/json", ...init.headers });
  if (init.key !== undefined) headers.set("authorization", `Bearer ${init.key}`);
  return new Request("https://ferrogate.test/v1/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}
