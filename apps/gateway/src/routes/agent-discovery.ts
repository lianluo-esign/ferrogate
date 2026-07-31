/**
 * `GET /.well-known/agent.json` — the A2A agent-upstream discovery document.
 *
 * Clean-room port of `server/local.rs::handle_agent_discovery` +
 * `agent_upstream_visible_to_auth` + `agent_upstream_discovery`
 * (`docs/legacy/inventory-edge-control.md` §agent discovery). The Rust reads
 * `state.config.agent_upstreams` — the `[[agent_upstreams]]` config table — and
 * projects the ENABLED, caller-visible entries into an `AdminList`. There is no
 * I/O and no upstream contact: it is a pure projection of operator config, which
 * is why it ports to a Worker var one-for-one, exactly as the provider/model
 * tables in `src/inference/catalog.ts` do.
 *
 * Authentication (`bearer`, scope `agents.read`) is NOT re-implemented here.
 * `contractAuth` has already run for this operation by the time the handler is
 * reached, so this module only reads the resolved `AuthContext` for the
 * visibility filter.
 */
import type { Context } from "hono";
import type { AuthContext, GatewayEnv } from "../ports.js";

/** JSON array of `AgentUpstreamConfig` records — Rust `[[agent_upstreams]]`. */
export const AGENT_UPSTREAMS_VAR = "GATEWAY_AGENT_UPSTREAMS";

/** Bindings this module reads on top of `GatewayBindings`. */
export interface AgentDiscoveryBindings {
  readonly GATEWAY_AGENT_UPSTREAMS?: string | undefined;
}

/**
 * `ferrogate_config::AgentUpstreamProtocol`. One variant today, `#[default]`.
 * Kept as a named union rather than a bare string so a second protocol has one
 * place to land.
 */
export type AgentUpstreamProtocol = "a2a";

/** `ferrogate_config::AgentUpstreamCapability`. */
export type AgentUpstreamCapability = "invoke" | "read" | "stream" | "discover";

/** `ferrogate_config::AgentUpstreamConfig`, as it appears in the var. */
export interface AgentUpstreamRecord {
  readonly id: string;
  readonly name: string;
  readonly description?: string | null;
  /** `#[serde(default = "default_true")]`. */
  readonly enabled?: boolean;
  /** `#[serde(default)]` ⇒ `a2a`. */
  readonly protocol?: AgentUpstreamProtocol;
  readonly endpoint: string;
  /** `#[serde(default)]` ⇒ empty ⇒ visible to every caller. */
  readonly tenant_ids?: readonly string[];
  /** `#[serde(default)]` ⇒ empty. NOT defaulted to invoke+read: that default
   * belongs to `agent_upstream_from_mutation` (the admin WRITE path), and the
   * READ path serializes whatever the table holds. */
  readonly capabilities?: readonly AgentUpstreamCapability[];
}

/** `AgentUpstreamDiscovery` — the projected wire record. */
export interface AgentUpstreamDiscovery {
  readonly object: "agent_upstream";
  readonly id: string;
  readonly name: string;
  readonly description: string | null;
  readonly protocol: AgentUpstreamProtocol;
  readonly endpoint: string;
  readonly capabilities: readonly AgentUpstreamCapability[];
}

/** `AdminList::new` — `total`/`offset`/`limit` are `skip_serializing_if None`. */
export interface AgentDiscoveryDocument {
  readonly object: "list";
  readonly data: readonly AgentUpstreamDiscovery[];
}

/**
 * Parse the var, fail-closed.
 *
 * Same posture as every other gateway table (`parseJsonVar` in
 * `src/adapters.ts`): a malformed or non-array value configures NO upstreams. A
 * typo can only hide an agent, never publish one that was not declared. Records
 * missing the two REQUIRED config members (`id`, `endpoint`, `name`) are
 * dropped individually — serde would have refused the whole table, and dropping
 * is the stricter of the two for a discovery document.
 */
export function parseAgentUpstreams(raw: string | undefined): readonly AgentUpstreamRecord[] {
  if (raw === undefined || raw.trim() === "") {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed.filter((entry): entry is AgentUpstreamRecord => {
    if (typeof entry !== "object" || entry === null) return false;
    const record = entry as Record<string, unknown>;
    return (
      typeof record["id"] === "string" &&
      typeof record["name"] === "string" &&
      typeof record["endpoint"] === "string"
    );
  });
}

/**
 * `agent_upstream_visible_to_auth`.
 *
 * NOTE the field the Rust compares: `tenant_ids` is matched against
 * `auth.api_key_id`, NOT against the resolved tenant. That reads like a bug and
 * is reproduced verbatim, because it is the deployed behavior an operator's
 * `tenant_ids` list is currently tuned against — narrowing it to the tenant id
 * would silently HIDE upstreams a caller can see today, and widening it to
 * "either" would silently REVEAL upstreams. Either is a behavior change that
 * belongs in its own slice with the Rust test that pins it.
 */
export function agentUpstreamVisibleToAuth(
  upstream: AgentUpstreamRecord,
  auth: AuthContext | null,
): boolean {
  const tenantIds = upstream.tenant_ids ?? [];
  if (tenantIds.length === 0) {
    return true;
  }
  const apiKeyId = auth?.subject ?? null;
  return apiKeyId !== null && tenantIds.includes(apiKeyId);
}

/** `agent_upstream_discovery` — the config record projected onto the wire. */
export function agentUpstreamDiscovery(
  upstream: AgentUpstreamRecord,
): AgentUpstreamDiscovery {
  return {
    object: "agent_upstream",
    id: upstream.id,
    name: upstream.name,
    // `Option<&str>` serializes as an explicit `null`, not an absent member.
    description: upstream.description ?? null,
    protocol: upstream.protocol ?? "a2a",
    endpoint: upstream.endpoint,
    capabilities: upstream.capabilities ?? [],
  };
}

/** The whole projection: enabled ∧ visible, in config order. */
export function agentDiscoveryDocument(
  upstreams: readonly AgentUpstreamRecord[],
  auth: AuthContext | null,
): AgentDiscoveryDocument {
  return {
    object: "list",
    data: upstreams
      .filter((upstream) => (upstream.enabled ?? true) && agentUpstreamVisibleToAuth(upstream, auth))
      .map(agentUpstreamDiscovery),
  };
}

/** The `getAgentDiscovery` operation handler. */
export function agentDiscoveryHandler(c: Context<GatewayEnv>): Response {
  const env = c.env as AgentDiscoveryBindings | undefined;
  const upstreams = parseAgentUpstreams(env?.GATEWAY_AGENT_UPSTREAMS);
  return c.json(agentDiscoveryDocument(upstreams, c.get("auth")));
}
