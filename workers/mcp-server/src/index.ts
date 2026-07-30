// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: FerroGate-hosted MCP server Worker (issue #409). A tenant's OWN MCP server,
//   stood up on Cloudflare (Workers + Agents SDK `McpAgent` Durable Object) and mounted at
//   `/mcp`, exposing a FerroGate-defined base tool surface. OAuth via
//   @cloudflare/workers-oauth-provider (needs an OAUTH_KV binding), with a static bearer-token
//   fallback for automation. This is the INVERSE of #408 (consuming CF's MCP servers): here CF
//   provides the HOSTING for a FerroGate tool surface.

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import OAuthProvider, {
  type OAuthHelpers,
  type OAuthProviderOptions,
} from "@cloudflare/workers-oauth-provider";
import { z } from "zod";

/**
 * The runtime shape of a Cloudflare **Secrets Store** binding: an async accessor
 * with no name argument — `store_id` + `secret_name` are fixed at deploy time.
 *
 * Declared structurally rather than imported so the Worker typechecks against
 * the pinned `@cloudflare/workers-types` regardless of whether that version
 * ships a `SecretsStoreSecret` type; the shape is the whole contract.
 */
export interface SecretsStoreSecretBinding {
  get(): Promise<string>;
}

/**
 * Worker bindings.
 *
 * - `MCP_OBJECT` — the Durable Object namespace for the {@link FerroGateMcp}
 *   `McpAgent` class. Each MCP session is a stateful, per-session Durable Object
 *   instance (the Agents SDK keeps session state in an embedded SQLite DB, which
 *   is why the deploy migration uses `new_sqlite_classes`).
 * - `OAUTH_KV` — the KV namespace `@cloudflare/workers-oauth-provider` uses to
 *   persist issued grants / tokens / dynamically-registered clients. REQUIRED by
 *   the OAuth provider; create it once and bind it (see README).
 * - `MCP_BEARER_TOKEN_STORE` — the **preferred** source of the automation bearer:
 *   a Cloudflare Secrets Store binding declared at deploy time by FerroGate's
 *   Rust pipeline (`ferrogate_mcp::mcp_worker_deploy`). Rotating the secret in
 *   the store takes effect with no redeploy.
 * - `MCP_BEARER_TOKEN` — the same credential seeded out of band
 *   (`wrangler secret put`), kept as the fallback for deployments with no
 *   Secrets Store. Optional; when neither binding is present, OAuth is the only
 *   way in.
 * - `OAUTH_PROVIDER` — injected by {@link OAuthProvider} into the default
 *   handler; exposes `parseAuthRequest` / `completeAuthorization` / `lookupClient`.
 */
export interface Env {
  MCP_OBJECT: DurableObjectNamespace<FerroGateMcp>;
  OAUTH_KV: KVNamespace;
  MCP_BEARER_TOKEN_STORE?: SecretsStoreSecretBinding;
  MCP_BEARER_TOKEN?: string;
  OAUTH_PROVIDER: OAuthHelpers;
}

/** Persisted per-session agent state (lives in the DO's embedded SQLite). */
interface McpSessionState {
  /** Number of tool calls served by this session (demonstrates statefulness). */
  callCount: number;
}

/** Grant props threaded from the OAuth authorization into the agent. */
interface McpProps {
  /** The authenticated principal (from the OAuth grant, or the automation user). */
  userId: string;
  [key: string]: unknown;
}

/**
 * The FerroGate-defined MCP server as an Agents SDK {@link McpAgent} Durable
 * Object — stateful and per-session. Mounted at `/mcp` (Streamable HTTP) and
 * `/sse` (legacy SSE) by the default export below.
 *
 * `init()` registers the **base tool surface**. These are deliberately small,
 * dependency-free example tools that prove the hosting path end-to-end; a real
 * tenant swaps in its own tools (calling out to R2 / D1 / a backend, etc.).
 */
export class FerroGateMcp extends McpAgent<Env, McpSessionState, McpProps> {
  server = new McpServer({
    name: "ferrogate-mcp-server",
    version: "0.1.0",
  });

  initialState: McpSessionState = { callCount: 0 };

  async init(): Promise<void> {
    // Tool 1: echo — the canonical smoke-test tool.
    this.server.tool(
      "echo",
      "Echo a message back to the caller.",
      { message: z.string().describe("The text to echo back.") },
      async ({ message }) => {
        this.bump();
        return { content: [{ type: "text", text: message }] };
      },
    );

    // Tool 2: add — a pure computation, no side effects.
    this.server.tool(
      "add",
      "Add two numbers and return the sum.",
      { a: z.number(), b: z.number() },
      async ({ a, b }) => {
        this.bump();
        return { content: [{ type: "text", text: String(a + b) }] };
      },
    );

    // Tool 3: whoami — surfaces the authenticated principal + session stats,
    // demonstrating that OAuth props and per-session DO state are wired through.
    this.server.tool(
      "whoami",
      "Return the authenticated principal and this session's call count.",
      {},
      async () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              userId: this.props?.userId ?? "anonymous",
              callCount: this.state?.callCount ?? 0,
            }),
          },
        ],
      }),
    );
  }

  /** Increment the persisted per-session call counter. */
  private bump(): void {
    this.setState({ callCount: (this.state?.callCount ?? 0) + 1 });
  }
}

/** Unauthenticated liveness probe (exposes no secret). */
function healthz(): Response {
  return new Response(JSON.stringify({ ok: true, worker: "ferrogate-mcp-server" }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Length-independent constant-time bearer comparison. Returns `true` when the
 * request presents exactly the expected token.
 */
function matchesBearer(request: Request, expected: string): boolean {
  const header = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return false;
  const presented = header.slice(prefix.length);
  const enc = new TextEncoder();
  const a = enc.encode(presented);
  const b = enc.encode(expected);
  let diff = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * The automation bearer, sourced from the Secrets Store binding when one is
 * declared and falling back to the plain `secret_text` binding otherwise.
 *
 * A Secrets Store read that throws (binding present but the secret was deleted,
 * or the store is unreachable) returns `undefined` rather than propagating:
 * losing the automation shortcut degrades to "OAuth only", while a thrown error
 * here would 500 every request including the OAuth ones. The failure is logged
 * so it is diagnosable rather than silent.
 */
async function resolveAutomationBearer(env: Env): Promise<string | undefined> {
  if (env.MCP_BEARER_TOKEN_STORE) {
    try {
      const fromStore = await env.MCP_BEARER_TOKEN_STORE.get();
      if (fromStore) return fromStore;
    } catch (error) {
      console.error("MCP_BEARER_TOKEN_STORE read failed; falling back", error);
    }
  }
  return env.MCP_BEARER_TOKEN || undefined;
}

/** The MCP transport handlers (Streamable HTTP at `/mcp`, legacy SSE at `/sse`). */
const mcpHandler = FerroGateMcp.serve("/mcp");
const sseHandler = FerroGateMcp.serveSSE("/sse");

/**
 * Interactive OAuth surface (the provider's `defaultHandler`).
 *
 * `GET /authorize` parses the incoming OAuth request and completes the grant.
 * This reference **auto-approves** for a single-tenant/dev deployment; a
 * production server MUST render a consent screen (and authenticate the end user)
 * before calling `completeAuthorization`. The `props` recorded on the grant are
 * later delivered to {@link FerroGateMcp} as `this.props`.
 */
const defaultHandler: ExportedHandler<Env> = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/authorize") {
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      // PRODUCTION: render a consent page + authenticate the user here.
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: "ferrogate-user",
        metadata: {},
        scope: oauthReqInfo.scope,
        props: { userId: "ferrogate-user" } satisfies McpProps,
      });
      return Response.redirect(redirectTo, 302);
    }
    if (url.pathname === "/healthz") return healthz();
    return new Response("Not found", { status: 404 });
  },
};

/**
 * The OAuth provider is the primary front door. It protects the `/mcp` + `/sse`
 * API routes with the OAuth 2.1 flow (Cloudflare is the authorization server,
 * grants persisted in `OAUTH_KV`) and delegates the interactive
 * authorize/consent UI to {@link defaultHandler}.
 */
const oauth = new OAuthProvider({
  // The Agents SDK `serve`/`serveSSE` handlers carry a generic `fetch<Env>` that
  // does not line up structurally with the provider's `ExportedHandlerWithFetch`;
  // the runtime shape (an object with `fetch`) is exactly what it expects.
  apiHandlers: {
    "/mcp": mcpHandler as unknown as ExportedHandler,
    "/sse": sseHandler as unknown as ExportedHandler,
  } as OAuthProviderOptions["apiHandlers"],
  // The handler is typed against the concrete `Env` (so `env.OAUTH_PROVIDER` is
  // known inside); the provider types it against `unknown`, so widen at the seam.
  defaultHandler: defaultHandler as OAuthProviderOptions["defaultHandler"],
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});

/**
 * Top-level entry. An **automation bearer** (from the `MCP_BEARER_TOKEN_STORE`
 * Secrets Store binding, or the `MCP_BEARER_TOKEN` secret) short-circuits OAuth
 * and routes straight to the MCP transport — handy for CI / FerroGate's own
 * machine-to-machine calls. Everything else flows through the OAuth provider.
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") return healthz();

    // Only pay the Secrets Store read on the two routes a bearer can unlock.
    if (url.pathname === "/mcp" || url.pathname === "/sse") {
      const bearer = await resolveAutomationBearer(env);
      if (bearer && matchesBearer(request, bearer)) {
        return url.pathname === "/mcp"
          ? mcpHandler.fetch(request, env, ctx)
          : sseHandler.fetch(request, env, ctx);
      }
    }

    return oauth.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
