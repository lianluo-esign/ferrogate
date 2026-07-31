/**
 * `ferrogate-gateway` Worker — the native TS data plane.
 *
 * Replaces the Rust `ferrogate-gateway` + `ferrogate-runtime` + the Pingora
 * container (eliminated). A Hono streaming proxy for OpenAI-compatible
 * inference, tool/MCP execution, and agent invoke.
 */
import { Hono } from "hono";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

// Route groups this Worker will own (per OpenAPI runtime contract):
//   POST /v1/chat/completions           streaming LLM proxy (SSE, byte-preserving)
//   POST /v1/responses                  Responses API proxy
//   GET  /v1/models                     model catalog
//   POST /v1/embeddings                 embeddings proxy
//   POST /mcp, GET /sse                 MCP / tool execution
//   POST /v1/agents/:id/invoke          agent invoke / messaging
//   internal: rate-limit + session Durable Objects, guardrail veto, billing meter

export default app;
