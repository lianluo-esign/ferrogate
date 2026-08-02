/**
 * The MULTIPLEX contract (#687): the rules by which ONE FerroGate MCP endpoint
 * fans in to MANY upstream MCP servers over ONE client session.
 *
 * The gateway has always fanned in — `HttpMcpUpstreams` holds every configured
 * upstream and `tools/list` returns their union. What it did not have is a
 * contract for the two places where a fan-in is quietly wrong, and this module
 * is that contract, isolated from both the transport and the chokepoint so
 * neither can hold a second, divergent copy of it.
 *
 * ## 1. The flat name is NOT parseable, so stop parsing it
 *
 * A multiplexed tool is advertised as `{server}-{remote}` — a single flat token,
 * because MCP tool names are a flat namespace and every existing agent, the
 * REST transport (`POST /v1/mcp/tool/execute`) and the Rust gateway all speak
 * it. That name is EMITTED by joining. It cannot be RECOVERED by splitting:
 * `-` occurs freely in both halves, so `docs-search-v2` is `docs`+`search-v2`
 * and `docs-search`+`v2` at the same time, and `github-mcp-search` is
 * `github-mcp`+`search` and `github`+`mcp-search` at the same time.
 *
 * The tree used to split it twice, in two different ways, and both were wrong:
 *
 *  - {@link module:transport}'s `toolByName` took the LONGEST matching server
 *    prefix. With two colliding servers that silently routes every call to one
 *    of them and makes the other's tool permanently unreachable — while
 *    `tools/list` still advertises it. Discovery and invocation disagree, which
 *    is the exact defect class #685 closed for entitlements.
 *  - `tools.ts`'s `toolAuditDetails` split on the FIRST hyphen. For any server
 *    whose own name contains one — `github-mcp`, `slack-connector`, the shape
 *    an operator naturally writes — every `tool.execute`, `tool.guardrail`,
 *    `tool.approval` and `mcp.identity.use` row was filed against a server that
 *    does not exist. That destroys exactly the per-upstream attribution
 *    #677/#678 built.
 *
 * The rule this module imposes: **resolution reads the CATALOG, never the
 * string.** A flat name identifies a tool only if exactly one upstream in the
 * caller's catalogue advertises that flat name. Prefix matching survives only
 * as a way to decide WHICH upstreams are worth asking (see
 * {@link candidateServerNames}) — it never decides the answer.
 *
 * ## 2. A collision is refused, not guessed — and both tools stay callable
 *
 * When two upstreams do advertise the same flat name, the wire contract is:
 *
 *  - `tools/list` lists BOTH, each carrying `_meta["ferrogate/server"]` and
 *    `_meta["ferrogate/remoteName"]`, and reports the collision in the result's
 *    own `_meta["ferrogate/ambiguousTools"]`. Nothing is dropped and nothing is
 *    renamed: renaming would break the flat name for the server that had it
 *    first, and dropping is the silent shadowing we are fixing.
 *  - `tools/call` with the bare flat name is REFUSED (`mcp_tool_ambiguous`),
 *    naming every upstream that claims it.
 *  - `tools/call` carrying `params._meta["ferrogate/server"]` (or, on the REST
 *    transport, a top-level `server` field) is resolved against THAT upstream
 *    alone.
 *
 * Refusing rather than picking is the security half of the issue. Picking means
 * arguments a caller composed for upstream A are dispatched to upstream B, over
 * B's identity grant (`resolveMcpIdentity` keys on `tool.serverName`) and past
 * B's execute allowlist. A gateway that silently substitutes one upstream for
 * another has destroyed the per-server fence the shared session exists to
 * preserve. The cost is that a caller who never reads `tools/list` sees a new
 * error on a name that used to (mis)route; that is the correct direction for a
 * governed gateway, and the error tells it exactly how to disambiguate.
 *
 * ## 3. Partial failure is REPORTED
 *
 * One upstream being down must not blank the fan-in — it never did. But the
 * caller was told nothing, so it saw a shorter list and reasoned as if the
 * missing tools do not exist, which is strictly worse than an error: an agent
 * will happily conclude "there is no search tool" and stop. {@link McpFanIn}
 * carries the union AND the upstreams that failed, and `tools/list` surfaces
 * the latter in `_meta["ferrogate/degradedUpstreams"]` with a `degraded` audit
 * outcome.
 */
import type { JsonValue } from "@ferrogate/core";

import type { McpTool } from "./ports.js";

/**
 * The character joining an upstream's name to its remote tool name.
 *
 * Deliberately unchanged from the Rust gateway's `{server}-{tool}`. Switching
 * to an unambiguous delimiter (`::`, `__`) would make the flat name parseable
 * again, but it is a WIRE CONTRACT: every agent config, every stored
 * `toolsToExecute` allowlist and the REST transport carry the current spelling.
 * The ambiguity is closed by resolving against the catalogue instead, which
 * costs nothing on the wire.
 */
export const TOOL_NAMESPACE_SEPARATOR = "-";

/** `_meta` key naming the upstream that owns a listed tool. */
export const MULTIPLEX_SERVER_META = "ferrogate/server";

/** `_meta` key carrying the tool's name AS THE UPSTREAM KNOWS IT. */
export const MULTIPLEX_REMOTE_NAME_META = "ferrogate/remoteName";

/** `tools/list` result `_meta` key listing upstreams that could not be reached. */
export const MULTIPLEX_DEGRADED_META = "ferrogate/degradedUpstreams";

/** `tools/list` result `_meta` key listing flat names claimed by >1 upstream. */
export const MULTIPLEX_AMBIGUOUS_META = "ferrogate/ambiguousTools";

/** The namespaced name one upstream's tool is advertised under. */
export function namespacedToolName(serverName: string, remoteName: string): string {
  return `${serverName}${TOOL_NAMESPACE_SEPARATOR}${remoteName}`;
}

/** One upstream that could not be listed, and why. */
export interface McpUpstreamFailure {
  readonly server: string;
  readonly code: string;
  readonly message: string;
}

/**
 * The result of fanning in across every configured upstream.
 *
 * `tools` is the union the caller may use; `degraded` is what it did NOT get.
 * Keeping them in one value is the point — a signature returning only the tools
 * is what let the silent shortening exist.
 */
export interface McpFanIn {
  readonly tools: readonly McpTool[];
  readonly degraded: readonly McpUpstreamFailure[];
}

/** The empty fan-in (no upstream consulted), e.g. when entitlement denies MCP. */
export const EMPTY_FAN_IN: McpFanIn = Object.freeze({
  tools: Object.freeze([]) as readonly McpTool[],
  degraded: Object.freeze([]) as readonly McpUpstreamFailure[],
});

/**
 * Resolving a flat tool name against a multiplexed catalogue.
 *
 * `ambiguous` is a distinct outcome from `missing` on purpose: the caller must
 * be able to tell "no such tool" from "say which server you meant", and only
 * the second one is fixable by the caller.
 */
export type McpToolResolution =
  | { readonly kind: "resolved"; readonly tool: McpTool }
  | { readonly kind: "ambiguous"; readonly name: string; readonly servers: readonly string[] }
  | { readonly kind: "missing"; readonly name: string };

/**
 * Every upstream that COULD own this flat name, by prefix.
 *
 * This is an optimisation, not a decision: it bounds how many upstreams a
 * `tools/call` has to interrogate, and the actual answer still comes from those
 * upstreams' catalogues. It returns ALL prefix matches — taking only the
 * longest is precisely the shadowing bug.
 *
 * An empty remote half (`srv-`) is not a candidate: no upstream can advertise a
 * tool with an empty name, so it would only ever produce a phantom candidate.
 */
export function candidateServerNames(
  serverNames: Iterable<string>,
  name: string,
): ReadonlyArray<{ serverName: string; remoteName: string }> {
  const candidates: Array<{ serverName: string; remoteName: string }> = [];
  for (const serverName of serverNames) {
    const prefix = `${serverName}${TOOL_NAMESPACE_SEPARATOR}`;
    if (!name.startsWith(prefix)) continue;
    const remoteName = name.slice(prefix.length);
    if (remoteName.trim().length === 0) continue;
    candidates.push({ serverName, remoteName });
  }
  return candidates;
}

/**
 * Resolve a flat name against an already-materialised catalogue.
 *
 * `selector` — the caller's explicit `ferrogate/server` — narrows BEFORE the
 * ambiguity test, which is what keeps both colliding tools callable. A selector
 * naming an upstream that does not advertise this tool is `missing`, never a
 * fall-back to another upstream: honouring "server A" by dispatching to B is
 * the failure mode this whole module exists to prevent.
 */
export function resolveAcrossCatalog(
  tools: readonly McpTool[],
  name: string,
  selector?: string | undefined,
): McpToolResolution {
  const matches = tools.filter((tool) => tool.name === name);
  const scoped =
    selector === undefined ? matches : matches.filter((tool) => tool.serverName === selector);
  const first = scoped[0];
  if (first === undefined) return { kind: "missing", name };
  if (scoped.length === 1) return { kind: "resolved", tool: first };
  // Two tools with the same flat name AND the same owning server cannot be told
  // apart by any selector this contract offers, so they are one tool as far as
  // the wire is concerned; a genuine multi-server collision is ambiguous.
  const servers = [...new Set(scoped.map((tool) => tool.serverName))].sort();
  if (servers.length === 1) return { kind: "resolved", tool: first };
  return { kind: "ambiguous", name, servers };
}

/** Flat names claimed by more than one upstream, for the `tools/list` `_meta`. */
export function ambiguousToolNames(
  tools: readonly McpTool[],
): ReadonlyArray<{ name: string; servers: readonly string[] }> {
  const owners = new Map<string, Set<string>>();
  for (const tool of tools) {
    let set = owners.get(tool.name);
    if (set === undefined) {
      set = new Set<string>();
      owners.set(tool.name, set);
    }
    set.add(tool.serverName);
  }
  const collisions: Array<{ name: string; servers: readonly string[] }> = [];
  for (const [name, servers] of owners) {
    if (servers.size > 1) collisions.push({ name, servers: [...servers].sort() });
  }
  return collisions;
}

/**
 * The per-tool `_meta` an agent needs to build an unambiguous selector.
 *
 * Emitted for EVERY tool, not just colliding ones. A collision can appear the
 * moment an operator adds an upstream, and an agent that only learned the
 * selector for tools that were already colliding would have to re-derive it
 * exactly when the catalogue changed under it.
 */
export function toolMeta(tool: McpTool): Record<string, JsonValue> {
  return {
    [MULTIPLEX_SERVER_META]: tool.serverName,
    [MULTIPLEX_REMOTE_NAME_META]: tool.remoteName,
  };
}

/**
 * The explicit upstream selector on a `tools/call`, from
 * `params._meta["ferrogate/server"]`.
 *
 * `_meta` is the MCP-sanctioned place for implementation-defined request
 * metadata, so this does not collide with the spec's `name` / `arguments` and
 * survives a client that forwards `_meta` verbatim. A non-string is ignored
 * rather than stringified: a selector that does not name a server exactly must
 * behave as "no selector", not as a server called `[object Object]`.
 */
export function readServerSelector(params: unknown): string | undefined {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return undefined;
  const meta = (params as Record<string, unknown>)["_meta"];
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) return undefined;
  const selector = (meta as Record<string, unknown>)[MULTIPLEX_SERVER_META];
  return typeof selector === "string" && selector !== "" ? selector : undefined;
}

/** The refusal message for an ambiguous flat name. Names every claimant. */
export function ambiguousToolMessage(name: string, servers: readonly string[]): string {
  return (
    `MCP tool ${name} is advertised by ${servers.length} upstream servers ` +
    `(${servers.join(", ")}); resolve it by sending _meta.${MULTIPLEX_SERVER_META} ` +
    `on tools/call, or "server" on POST /v1/mcp/tool/execute`
  );
}

/** `_meta` rendering of a degraded upstream. */
export function degradedMeta(failures: readonly McpUpstreamFailure[]): JsonValue {
  return failures.map((failure) => ({
    server: failure.server,
    code: failure.code,
    message: failure.message,
  }));
}

/** `_meta` rendering of the colliding flat names. */
export function ambiguousMeta(
  collisions: ReadonlyArray<{ name: string; servers: readonly string[] }>,
): JsonValue {
  return collisions.map((collision) => ({
    name: collision.name,
    servers: [...collision.servers],
  }));
}
