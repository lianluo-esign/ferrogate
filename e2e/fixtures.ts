/**
 * The single source of truth shared by `playwright.config.ts` (which builds the
 * `wrangler dev` command lines) and the specs (which drive the resulting
 * servers). Ports, base URLs and the injected credential are declared ONCE so a
 * spec can never talk to a server the config did not start.
 */

// ---------------------------------------------------------------------------
// Ports
//
// Each `wrangler dev` also opens an INSPECTOR port (devtools), defaulting to
// 9229 for every instance. Two Workers started concurrently on the default
// therefore collide with `Address already in use (127.0.0.1:9229)` and the
// second one dies — observed for real while building this layer. Both the
// serving port and the inspector port must be distinct per Worker.
// ---------------------------------------------------------------------------

/** Serving port for `apps/gateway`. Deliberately not 8787 (wrangler's default,
 *  which a developer is most likely to already be occupying by hand). */
export const GATEWAY_PORT = 8877;
/** Devtools/inspector port for `apps/gateway`. */
export const GATEWAY_INSPECTOR_PORT = 9877;

/** Serving port for `apps/mcp`. */
export const MCP_PORT = 8878;
/** Devtools/inspector port for `apps/mcp`. */
export const MCP_INSPECTOR_PORT = 9878;

export const GATEWAY_BASE_URL = `http://127.0.0.1:${GATEWAY_PORT}`;
export const MCP_BASE_URL = `http://127.0.0.1:${MCP_PORT}`;

// ---------------------------------------------------------------------------
// The gateway's injected test credential
// ---------------------------------------------------------------------------

/**
 * A bearer token the local gateway will resolve.
 *
 * `apps/gateway/wrangler.toml` ships `GATEWAY_NATIVE_API_KEYS = "[]"` — the
 * fail-closed empty table — so a stock `wrangler dev` resolves NO credential and
 * every bearer answers `401 invalid_api_key` before any handler runs. Rather
 * than edit the app (its committed default is the correct production posture),
 * the config injects this table with `wrangler dev --var`, which is exactly what
 * the layer-1 vitest config does with `miniflare.bindings`.
 */
export const GATEWAY_API_KEY = "fg_e2e_gateway_key";

/**
 * `scopes: []` is load-bearing, not laziness. Per `apps/gateway/src/ports.ts`
 * `hasScope`, a durable/native key with an EMPTY scope set grants every
 * data-plane scope (`models.read`, `chat.completions`, …) and never an `admin.*`
 * one. So this one record reaches the handlers under test without becoming a
 * root credential — and without this file having to restate the scope names,
 * which would drift from the contract.
 */
export const GATEWAY_NATIVE_API_KEYS = [
  {
    key: GATEWAY_API_KEY,
    id: "key_e2e",
    tenant_id: "tenant_e2e",
    scopes: [] as readonly string[],
  },
];

/** The uniform error envelope every gateway non-2xx uses (`src/middleware/errors.ts`). */
export interface GatewayErrorEnvelope {
  error: {
    message: string;
    type: "ferrogate_error";
    code: string;
    request_id: string | null;
  };
}

/** The MCP Worker's HTTP-level (non-JSON-RPC) error envelope (`apps/mcp/src/http.ts`). */
export interface McpHttpErrorEnvelope {
  error: { code: string; message: string; request_id: string | null };
}

/** A JSON-RPC 2.0 response as this ingress renders it (absent members OMITTED). */
export interface JsonRpcResponseBody {
  jsonrpc: string;
  id?: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}
