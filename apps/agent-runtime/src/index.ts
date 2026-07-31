/**
 * `ferrogate-agent-runtime` Worker — the agent execution / isolation front.
 *
 * Replaces the `agent-worker` crate (CF-native path) and the
 * `workers/agent-gateway` reference. Agents SDK `Agent` Durable Object +
 * `@cloudflare/sandbox` container with sealed egress (`enable_ctx_exports`).
 */
import { Hono } from "hono";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

// Route groups this Worker will own (all bearer-gated by GATEWAY_CONTROL_TOKEN):
//   POST /control/{start,invoke,cancel,destroy}, GET /control/status
//   /memory/*          synced state / DO-SQLite / chat history
//   /schedule/*        in-DO SQLite scheduler (single alarm)
//   /container/*       per-tenant Sandbox lifecycle (enableInternet=false)
//   /git-credential/*  brokered per-op GitHub App installation tokens

export default app;
