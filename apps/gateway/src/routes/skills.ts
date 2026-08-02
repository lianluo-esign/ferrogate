/**
 * `GET /v1/skills` + `GET /v1/skills/{id}` — the tenant-facing skill-package
 * catalog.
 *
 * Clean-room port of `server/local.rs::handle_agent_skills` +
 * `skill_package_visible_to_auth` + `agent_skill_package`
 * (`docs/legacy/inventory-request-path.md` §skills).
 *
 * ## Why this replaced a 501
 *
 * `registerToolingRoutes` used to answer 501 here with the note "blocked on the
 * `skill_packages` read model in `apps/control-plane`". THAT NOTE WAS WRONG, and
 * re-reading the Rust is what found it: `handle_agent_skills` reads
 * `state.config.skill_packages` — the `[[skill_packages]]` OPERATOR CONFIG
 * TABLE — and never touches a repository. There is no control-plane read model
 * in the Rust path to be blocked on. It is a pure projection of operator config
 * with no I/O, which is exactly the shape `routes/agent-discovery.ts` already
 * ports one-for-one onto a Worker var.
 *
 * So the table is `GATEWAY_SKILL_PACKAGES`, parsed with the SAME
 * `skillPackageSchema` `@ferrogate/config` uses for the operator document —
 * not a private re-declaration that could drift from it.
 *
 * ## Auth
 *
 * `contractAuth` has already run (`bearer`, scope `skills.read`) by the time a
 * handler here is reached, so this module only READS the resolved `AuthContext`
 * for the visibility filter. It never re-implements authentication.
 */
import { type SkillPackage, skillPackageSchema } from "@ferrogate/config";
import type { Context } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { AuthContext, GatewayEnv } from "../ports.js";

/** JSON array of `SkillPackage` records — Rust `[[skill_packages]]`. */
export const SKILL_PACKAGES_VAR = "GATEWAY_SKILL_PACKAGES";

/** Bindings this module reads on top of `GatewayBindings`. */
export interface SkillCatalogBindings {
  readonly GATEWAY_SKILL_PACKAGES?: string | undefined;
}

/** `responses.rs::AgentSkillPackage` — the projected wire record. */
export interface AgentSkillPackage {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  /** `Option<String>` serializes as an explicit `null`, not an absent member. */
  readonly description: string | null;
  readonly capabilities: SkillPackage["capabilities"];
  readonly compatibility: SkillPackage["compatibility"];
}

/** `AdminList::new` — `total`/`offset`/`limit` are `skip_serializing_if None`. */
export interface AgentSkillListDocument {
  readonly object: "list";
  readonly data: readonly AgentSkillPackage[];
}

/**
 * Parse the var, fail-closed.
 *
 * Same posture as `parseAgentUpstreams` and `parseJsonVar`: a malformed or
 * non-array value configures NO skill packages, and a single entry the schema
 * refuses is dropped rather than taking the whole table with it. A typo can only
 * HIDE a package, never publish one the operator did not declare — which is the
 * safe direction for a catalog that a tenant reads.
 *
 * It deliberately does NOT answer 503 the way `routes/reverse-proxy.ts` does for
 * `GATEWAY_ROUTES`. That asymmetry is the Rust one: a broken route table means
 * traffic would be sent to the WRONG PLACE, while a broken skill table means a
 * catalog reads short. One is a safety failure, the other is a visibility one.
 */
export function parseSkillPackages(raw: string | undefined): readonly SkillPackage[] {
  if (raw === undefined || raw.trim() === "") return [];
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(decoded)) return [];
  const packages: SkillPackage[] = [];
  for (const entry of decoded) {
    const parsed = skillPackageSchema.safeParse(entry);
    if (parsed.success) packages.push(parsed.data);
  }
  return packages;
}

/**
 * `skill_package_visible_to_auth`.
 *
 * Two legs, in the Rust order:
 *   1. a DISABLED package is invisible to everyone — there is no caller who can
 *      see it, which is why this is checked before the allowlist;
 *   2. an empty `api_key_ids` is "visible to every caller"; a non-empty one is
 *      matched against `auth.api_key_id` — the KEY id, not the tenant id.
 *
 * The second comparison is reproduced verbatim including the field it uses.
 * Rust compares the API-KEY id (`AuthContext.api_key_id`, which is `subject`
 * here), so a package pinned to `key_a` is invisible to a second key of the same
 * tenant. Narrowing or widening that to the tenant would silently change which
 * packages an existing deployment's callers can see.
 */
export function skillPackageVisibleToAuth(
  pkg: SkillPackage,
  auth: AuthContext | null,
): boolean {
  if (!pkg.enabled) return false;
  if (pkg.api_key_ids.length === 0) return true;
  const apiKeyId = auth?.subject ?? null;
  return apiKeyId !== null && pkg.api_key_ids.includes(apiKeyId);
}

/**
 * `agent_skill_package` — the config record projected onto the wire.
 *
 * SIX fields, and the omissions are the point: `permissions`, `resources`,
 * `api_key_ids` and `metadata` are NOT projected. `api_key_ids` is the
 * visibility allowlist itself (echoing it would tell a caller which other keys
 * exist), `permissions` is the operator's grant sheet, and `resources` carries
 * the package's plugin/MCP/prompt payload. Rust publishes none of them on this
 * tenant-facing route and neither does this.
 */
export function agentSkillPackage(pkg: SkillPackage): AgentSkillPackage {
  return {
    id: pkg.id,
    name: pkg.name,
    version: pkg.version,
    description: pkg.description ?? null,
    capabilities: pkg.capabilities,
    compatibility: pkg.compatibility,
  };
}

/** The whole projection: visible packages, in declared order. */
export function agentSkillListDocument(
  packages: readonly SkillPackage[],
  auth: AuthContext | null,
): AgentSkillListDocument {
  return {
    object: "list",
    data: packages
      .filter((pkg) => skillPackageVisibleToAuth(pkg, auth))
      .map(agentSkillPackage),
  };
}

/** The `listAgentSkills` operation handler. */
export function listAgentSkillsHandler(c: Context<GatewayEnv>): Response {
  const env = c.env as SkillCatalogBindings | undefined;
  const packages = parseSkillPackages(env?.GATEWAY_SKILL_PACKAGES);
  return c.json(agentSkillListDocument(packages, c.get("auth")));
}

/**
 * The `getAgentSkill` operation handler.
 *
 * An INVISIBLE package is 404, not 403 — verbatim Rust, and load-bearing: the
 * `find` predicate is `id == id && visible`, so a caller who is not on the
 * allowlist cannot distinguish "this package is not for you" from "no such
 * package" and therefore cannot enumerate another key's packages by id.
 */
export function getAgentSkillHandler(c: Context<GatewayEnv>): Response {
  const env = c.env as SkillCatalogBindings | undefined;
  const id = c.req.param("id") ?? "";
  const packages = parseSkillPackages(env?.GATEWAY_SKILL_PACKAGES);
  const found = packages.find(
    (pkg) => pkg.id === id && skillPackageVisibleToAuth(pkg, c.get("auth")),
  );
  if (found === undefined) {
    throw new HttpError(404, "skill_package_not_found", `skill package ${id} was not found`);
  }
  return c.json(agentSkillPackage(found));
}
