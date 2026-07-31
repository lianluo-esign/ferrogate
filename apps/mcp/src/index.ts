/**
 * `ferrogate-mcp` Worker — a tenant's hosted MCP server + MCP host.
 *
 * Replaces the `ferrogate-mcp` host and the `workers/mcp-server` reference. Uses
 * `@modelcontextprotocol/sdk` + the Agents SDK (`McpAgent` Durable Object) with
 * an OAuth 2.1 front door.
 */
import { Hono } from "hono";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

// Route groups this Worker will own:
//   POST /mcp        Streamable HTTP (protocol negotiation, routing-header verify)
//   GET  /sse        legacy SSE transport
//   /oauth/*         OAuth 2.1 authorize/token/register (grants in OAUTH_KV)
//   McpAgent DO      per-session tool state (deny-by-default allowlist)

export default app;
