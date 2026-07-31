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
 * - `MCP_AUTH_MODE` — which front door this deployment enforces: `"oauth"`
 *   (default, and the value assumed when the binding is absent) or
 *   `"authless"`. A `plain_text` binding, not a secret — it carries no
 *   credential. FerroGate's Rust pipeline sets it from
 *   `McpWorkerSpec::auth_mode`, so ONE template serves both variants #409 asks
 *   for instead of two modules that can drift apart.
 * - `OAUTH_PROVIDER` — injected by {@link OAuthProvider} into the default
 *   handler; exposes `parseAuthRequest` / `completeAuthorization` / `lookupClient`.
 *   Absent in authless deployments, which never construct a grant.
 */
export interface Env {
  MCP_OBJECT: DurableObjectNamespace<FerroGateMcp>;
  OAUTH_KV: KVNamespace;
  MCP_BEARER_TOKEN_STORE?: SecretsStoreSecretBinding;
  MCP_BEARER_TOKEN?: string;
  MCP_AUTH_MODE?: string;
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

/** The one `Authorization` scheme this Worker's automation shortcut accepts. */
const BEARER_SCHEME = "bearer";

/**
 * The credential carried by an `Authorization: Bearer <token>` header, or
 * `undefined` when the request presents no bearer credential.
 *
 * The scheme is compared case-insensitively because RFC 7235 §2.1 defines it
 * that way: a client sending `authorization: bearer <token>` is presenting a
 * valid credential, and rejecting it here would have turned a spec-legal client
 * into an unexplainable 401 at the front door. The token itself is returned
 * verbatim — it is case-SENSITIVE and must never be normalised.
 */
function bearerCredential(request: Request): string | undefined {
  const header = request.headers.get("authorization");
  if (!header) return undefined;
  const space = header.indexOf(" ");
  if (space < 0) return undefined;
  if (header.slice(0, space).toLowerCase() !== BEARER_SCHEME) return undefined;
  return header.slice(space + 1);
}

/**
 * Whether the request presents a `Bearer` credential at all.
 *
 * This is the gate in front of {@link resolveAutomationBearer}, and it is a
 * security property, not an optimisation: without it **any** unauthenticated
 * request to `/mcp` or `/sse` — including an anonymous scan with no
 * `Authorization` header — drives an external Secrets Store read, and a store
 * outage turns into one `console.error` per anonymous request, drowning the only
 * diagnostic signal that path has.
 */
export function presentsBearer(request: Request): boolean {
  return bearerCredential(request) !== undefined;
}

/**
 * Length-independent constant-time bearer comparison. Returns `true` when the
 * request presents exactly the expected token.
 */
export function matchesBearer(request: Request, expected: string): boolean {
  const presented = bearerCredential(request);
  if (presented === undefined) return false;
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
 *
 * COST — read this before calling it from a new place. There is **one store read
 * per call**, deliberately un-memoised: an isolate-level cache is what would
 * break the "rotate the secret, no redeploy" property this binding exists for.
 * Callers must therefore reach it only for a request that presents a `Bearer`
 * credential ({@link presentsBearer}). An OAuth-authenticated request presents
 * one too — its token is indistinguishable from an automation token before the
 * comparison — so those still pay one read each; that is the accepted cost and
 * it is written down in `docs/cloudflare-mcp-hosting.md`.
 */
export async function resolveAutomationBearer(env: Env): Promise<string | undefined> {
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

/** The `MCP_AUTH_MODE` value selecting the authless variant. */
const AUTHLESS_MODE = "authless";

/**
 * Whether this deployment is the **authless** variant: `/mcp` + `/sse` are
 * served straight from the Durable Object with no front door at all.
 *
 * Fails CLOSED — anything other than the exact `authless` value (including an
 * absent binding, so an OAuth deployment whose binding was dropped by a
 * redeploy keeps its front door) leaves the OAuth provider in charge. The value
 * is trimmed and lower-cased only because it is operator-typed config in
 * `wrangler.toml`, not a credential.
 */
export function isAuthless(env: Env): boolean {
  return (env.MCP_AUTH_MODE ?? "").trim().toLowerCase() === AUTHLESS_MODE;
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
 * Top-level entry. In the **authless** variant ({@link isAuthless}) `/mcp` and
 * `/sse` are served with no authentication at all. Otherwise an **automation
 * bearer** (from the `MCP_BEARER_TOKEN_STORE` Secrets Store binding, or the
 * `MCP_BEARER_TOKEN` secret) short-circuits OAuth and routes straight to the MCP
 * transport — handy for CI / FerroGate's own machine-to-machine calls.
 * Everything else flows through the OAuth provider.
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") return healthz();

    // The authless variant has no front door: serve the transport directly and
    // expose NOTHING else. The OAuth endpoints are not merely bypassed but
    // absent — an authless deploy declares no `OAUTH_KV` binding
    // (`McpWorkerSpec::metadata_json` omits it), so routing to the provider here
    // would 500 on undefined KV instead of saying "no such route". No Secrets
    // Store read either: there is no credential to compare against.
    if (isAuthless(env)) {
      if (url.pathname === "/mcp") return mcpHandler.fetch(request, env, ctx);
      if (url.pathname === "/sse") return sseHandler.fetch(request, env, ctx);
      return new Response("Not found", { status: 404 });
    }

    // Only pay the Secrets Store read on the two routes a bearer can unlock, and
    // only for a request that actually presents one — an anonymous caller must
    // not be able to drive a store read (or a store-failure log line) at all.
    if ((url.pathname === "/mcp" || url.pathname === "/sse") && presentsBearer(request)) {
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
