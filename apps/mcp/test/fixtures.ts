/**
 * Shared seeding for the `SELF` integration tests.
 *
 * `apps/mcp` codes against the narrow ports in `src/ports.ts`, so an
 * integration test seeds the in-memory bundle (API keys, upstream MCP servers,
 * assets) and then drives the real Worker over HTTP — no mocking of the app's
 * own code, and the exact production routing/auth/governance path runs.
 */

import { env } from "cloudflare:test";
import type { JsonValue } from "@ferrogate/core";

import {
  type AuthContext,
  type DispatchContext,
  type McpDispatchHeaders,
  type McpEnv,
  type McpServerConfig,
  type McpTool,
  inMemoryPorts,
  resetInMemoryPorts,
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

export interface SeedFixtureOptions {
  readonly tenantId?: string;
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
export function seedFixture(options: SeedFixtureOptions = {}): Fixture {
  resetInMemoryPorts();
  const ports = inMemoryPorts();
  const calls: RecordedCall[] = [];
  const tenantId = options.tenantId ?? TENANT;

  const authForTenant = (overrides: Partial<AuthContext> = {}): AuthContext =>
    tenantAuth({ organizationId: tenantId, ...overrides });

  ports.auth
    .register(READ_KEY, authForTenant({ scopes: ["tools.read", "assets.read"] }))
    .register(EXEC_KEY, authForTenant())
    .register(NO_SCOPE_KEY, authForTenant({ scopes: [] }));

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

/**
 * Override an operator `[vars]` value for one test.
 *
 * `resolvePorts(c.env)` runs per request and the Worker under `SELF` shares
 * this isolate (see `vitest.config.ts`), so a var written here is read by the
 * NEXT `SELF.fetch`. Typed against {@link McpEnv} rather than `any` so a
 * renamed var fails the typecheck instead of quietly becoming a no-op. Restore
 * the original in `afterEach` — the env object is shared across test files.
 */
export function setMcpEnvVar<K extends keyof McpEnv>(key: K, value: McpEnv[K]): void {
  (env as unknown as { -readonly [P in keyof McpEnv]: McpEnv[P] })[key] = value;
}

/** Read the current value of an operator `[vars]` value. */
export function getMcpEnvVar<K extends keyof McpEnv>(key: K): McpEnv[K] {
  return (env as unknown as McpEnv)[key];
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
