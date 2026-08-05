/**
 * The composition seam that decides WHICH MCP host serves one request.
 *
 * ## Why this module exists at all
 *
 * `resolvePorts` (`./ports.ts`) is synchronous and runs BEFORE authentication,
 * so it cannot build the real upstream host: the upstream catalog is
 * per-TENANT (`mcp_servers` in the tenant object) and the tenant id is not
 * known until a caller has been authenticated. Binding a host at that point
 * would mean either loading every tenant's catalog — a cross-tenant read on
 * every request — or binding none, which is what the app did: `ports.upstreams`
 * was `InMemoryUpstreams` in EVERY posture, so `HttpMcpUpstreams`,
 * `loadServerCatalog` and `DurableMcpSessionStore` were fully implemented,
 * fully tested and unreachable in production. That is this repo's recurring
 * defect class, and it is what this module closes.
 *
 * ## The rule
 *
 * {@link resolveUpstreams} is called AFTER authentication, with the
 * authenticated tenant id, from the request path in `./routes/ingress.ts`. It
 * never widens what a caller can see: the catalog read is filtered by the
 * authenticated tenant, and the Durable-Object session is addressed by a name
 * that carries the same tenant id, so cross-tenant reuse is impossible by
 * construction rather than by a check.
 *
 * This module deliberately lives OUTSIDE `./ports.ts`. `./transport.ts` imports
 * values (`McpDispatchHeaders`, `McpExecutionError`) out of `./ports.ts`, so
 * importing `HttpMcpUpstreams` back into `./ports.ts` would make a real
 * value-level module cycle on the hot path. A leaf module that imports both
 * sides has none.
 */
import { loadServerCatalog } from "./durable.js";
import type { AuthContext, McpEnv, McpPorts, McpUpstreamPort } from "./ports.js";
import { DurableMcpSessionStore } from "./session.js";
import { HttpMcpUpstreams } from "./transport.js";

/**
 * The tenant whose upstream catalog an authenticated caller may read.
 *
 * ONLY `organizationId` — the tenant the credential is attributed to. There is
 * deliberately no fallback down the scope chain the way
 * `governedActionTenantKey` has one: that key exists to LABEL a metric, where a
 * less precise answer is harmless, whereas this one selects rows. Falling back
 * to `workspaceId` or `apiKeyId` here would make `tenant_id = ?` match on a
 * value from a different namespace, which is a cross-tenant read.
 *
 * `undefined` (an unattributed credential, or a platform operator, which names
 * no tenant by definition) means NO catalog is loaded — see
 * {@link resolveUpstreams}.
 */
export function upstreamCatalogTenant(auth: AuthContext): string | undefined {
  return auth.organizationId;
}

/**
 * Whether this Worker resolves upstreams through the DURABLE catalog.
 *
 * True in production (no dev bundle) and, for the dev bundle, only when
 * `FG_DEV_MCP_DURABLE_UPSTREAMS` opts in — see the field docs on
 * {@link McpEnv.FG_DEV_MCP_DURABLE_UPSTREAMS} for why that opt-in exists.
 *
 * `TENANT_DATA` is required either way: without the object namespace there is
 * no catalog to read and the honest answer is the in-memory host, not an empty
 * catalog that would report every configured upstream as missing.
 */
export function durableUpstreamsBound(env: McpEnv): boolean {
  if (env.TENANT_DATA === undefined) return false;
  if (env.FG_DEV_IN_MEMORY_PORTS === "1") return env.FG_DEV_MCP_DURABLE_UPSTREAMS === "1";
  return true;
}

/**
 * The MCP host for one authenticated tenant.
 *
 * Returns `ports.upstreams` unchanged when the durable catalog is not bound, so
 * the dev bundle and a partially-provisioned deployment keep working exactly as
 * before instead of failing on a missing binding.
 *
 * When it IS bound, the returned host is a real {@link HttpMcpUpstreams} over
 * the tenant's own `mcp_servers` rows, sharing its session state through the
 * `MCP_SESSION` Durable Object whenever that namespace is bound.
 */
export async function resolveUpstreams(
  env: McpEnv,
  ports: McpPorts,
  tenantId: string | undefined,
): Promise<McpUpstreamPort> {
  if (tenantId === undefined || tenantId === "") return ports.upstreams;
  if (!durableUpstreamsBound(env)) return ports.upstreams;
  const namespace = env.TENANT_DATA;
  if (namespace === undefined) return ports.upstreams;
  const configs = await loadServerCatalog(namespace, tenantId);
  if (env.MCP_SESSION === undefined) return new HttpMcpUpstreams(configs);
  return new HttpMcpUpstreams(configs, undefined, {
    sessions: new DurableMcpSessionStore(env.MCP_SESSION, tenantId),
  });
}

/**
 * {@link resolveUpstreams}, folded back into the port bundle the request path
 * carries.
 *
 * The whole bundle is returned rather than the host alone because every
 * downstream consumer (`tools.ts`, `dispatch.ts`, `identity/oauth.ts`) reads
 * `ports.upstreams`; handing them a bundle whose host is already the right one
 * means no call site can forget to use it.
 */
export async function withTenantUpstreams(
  env: McpEnv,
  ports: McpPorts,
  auth: AuthContext,
): Promise<McpPorts> {
  const upstreams = await resolveUpstreams(env, ports, upstreamCatalogTenant(auth));
  return upstreams === ports.upstreams ? ports : { ...ports, upstreams };
}
