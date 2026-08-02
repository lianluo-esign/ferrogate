/**
 * The control-plane slice of the 259-operation runtime API contract, as a
 * typed, table-driven operation table.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/api_contract.rs`
 * (which `include_str!`s the same JSON into two `matchit` radix routers) plus
 * `crates/ferrogate-admin/src/control_plane.rs` (the `/control/v1` ↔ `/admin/v1`
 * naming contract).
 *
 * Three jobs, exactly as the Rust does them:
 *
 *  1. import THE contract document (`docs/openapi/runtime-api-contract.json`) —
 *     one source of truth, no generated copy that can drift;
 *  2. validate it eagerly at module load (throw, mirroring the Rust panic);
 *  3. expose lookup by `(method, path)`, by `operation_id`, and by contract
 *     `group`, restricted to the 203 operations `ROUTE-MAP.md` assigns to
 *     `apps/control-plane`.
 *
 * `matchit`'s radix tree is re-implemented as a specificity-ranked segment
 * matcher: it resolves `/admin/v1/x402-spend-policies/effective` vs
 * `/admin/v1/x402-spend-policies/{id}`-shaped competition in favour of the
 * static segment, which `matchit` also does.
 *
 * Nothing downstream of this module names a path or a scope. Adding an
 * operation to the JSON adds its route, its guard and its RBAC check together.
 */
import contractDocument from "../../../docs/openapi/runtime-api-contract.json";

// ---------------------------------------------------------------------------
// Contract vocabulary
// ---------------------------------------------------------------------------

/** `auth.kind` — the four credential shapes the contract distinguishes. */
export const AUTH_KINDS = ["anonymous", "bearer", "internal", "method_dependent"] as const;
export type AuthKind = (typeof AUTH_KINDS)[number];

/** `visibility` — the exposure tier of an operation. */
export const VISIBILITIES = ["public", "admin", "internal"] as const;
export type Visibility = (typeof VISIBILITIES)[number];

/** Uppercase HTTP methods used by the contract. */
export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/**
 * `auth.scope_discriminator` — how a `method_dependent` operation derives its
 * required scope from the request body (Rust `ApiScopeDiscriminator`). No
 * control-plane operation uses it today; it is parsed and carried so the table
 * stays faithful to the document rather than to this app's current needs.
 */
export interface ScopeDiscriminator {
  readonly field: string;
  readonly map: Readonly<Record<string, string>>;
}

/** `auth` block of an operation (Rust `ApiOperationAuth`). */
export interface OperationAuth {
  readonly kind: AuthKind;
  /** Required scope for `bearer`; `null` for every other kind. */
  readonly scope: string | null;
  readonly scopeDiscriminator: ScopeDiscriminator | null;
}

/** One contract operation (Rust `ApiOperation`). */
export interface ApiOperation {
  /** Contract path template, e.g. `/admin/v1/quota-policies/{scope_type}/{scope_id}`. */
  readonly path: string;
  /** The same template in Hono syntax, e.g. `/admin/v1/quota-policies/:scope_type/:scope_id`. */
  readonly honoPath: string;
  readonly method: HttpMethod;
  readonly operationId: string;
  readonly visibility: Visibility;
  readonly auth: OperationAuth;
  readonly rbacAction: string | null;
  /** Route group the path belongs to (from `route_patterns`). */
  readonly group: string;
}

/** A successful `(method, path)` lookup. */
export interface OperationMatch {
  readonly operation: ApiOperation;
  readonly params: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Raw document shape
// ---------------------------------------------------------------------------

interface RawRoutePattern {
  pattern: string;
  group: string;
}

interface RawOperation {
  path: string;
  method: string;
  operation_id: string;
  visibility: string;
  auth: {
    kind: string;
    scope: string | null;
    scope_discriminator?: { field: string; map: Record<string, string> } | null;
  };
  rbac_action: string | null;
}

interface RawContract {
  version: number;
  route_patterns: RawRoutePattern[];
  operations: RawOperation[];
}

const RAW = contractDocument as unknown as RawContract;

/** Contract document version this port understands (Rust rejects anything else). */
export const SUPPORTED_CONTRACT_VERSION = 1;

/** Total operations in the document (`ROUTE-MAP.md`). */
export const EXPECTED_TOTAL_OPERATION_COUNT = 259;

/**
 * Operations `ROUTE-MAP.md` assigns to `apps/control-plane`: `/admin/v1/**`
 * (198) plus `/admin`, `/admin/`, `/admin/dashboard`, `/admin/status` and
 * `GET /metrics` (5).
 *
 * 197 -> 203. Two independent slices each added three `/admin/v1/**`
 * operations: the prompt-deployment-label surface (issue #694) and the
 * `/admin/v1/provider-credentials*` BYOK-alias surface (issue #682). Each side
 * had written 200 on its own, so this is the one pin the merge must NOT take
 * from either parent — both increments landed.
 */
export const EXPECTED_CONTROL_PLANE_OPERATION_COUNT = 203;

// ---------------------------------------------------------------------------
// Ownership predicate
// ---------------------------------------------------------------------------

/** The canonical prefix every versioned control-plane operation lives under. */
export const STABLE_PATH_PREFIX = "/admin/v1";

/** The legacy alias prefix folded onto {@link STABLE_PATH_PREFIX}. */
export const ALIAS_PATH_PREFIX = "/control/v1";

/**
 * The five un-versioned paths this Worker owns alongside `/admin/v1/**`.
 * `/metrics` is `visibility: internal` but `auth.kind: bearer` — internal
 * surface, still bearer-guarded (ROUTE-MAP invariant 5).
 */
export const CONTROL_PLANE_ROOT_PATHS: readonly string[] = [
  "/admin",
  "/admin/",
  "/admin/dashboard",
  "/admin/status",
  "/metrics",
];

/** Does `apps/control-plane` own this contract path? */
export function isControlPlanePath(path: string): boolean {
  return (
    path === STABLE_PATH_PREFIX ||
    path.startsWith(`${STABLE_PATH_PREFIX}/`) ||
    CONTROL_PLANE_ROOT_PATHS.includes(path)
  );
}

// ---------------------------------------------------------------------------
// Segment matcher (the `matchit` radix tree, re-implemented)
// ---------------------------------------------------------------------------

/** static < param < catch-all — also the specificity rank, smaller wins. */
const SEGMENT_STATIC = 0;
const SEGMENT_PARAM = 1;
const SEGMENT_CATCH_ALL = 2;
type SegmentKind = typeof SEGMENT_STATIC | typeof SEGMENT_PARAM | typeof SEGMENT_CATCH_ALL;

interface PatternSegment {
  readonly kind: SegmentKind;
  /** Literal text for `static`; parameter name for `param`/`catch-all`. */
  readonly value: string;
}

interface CompiledPattern<T> {
  readonly template: string;
  readonly segments: readonly PatternSegment[];
  readonly hasCatchAll: boolean;
  readonly value: T;
}

/**
 * Split a path into segments, dropping only the leading empty piece. A
 * *trailing* empty piece is meaningful: the contract lists `/admin` and
 * `/admin/` as two distinct operations, and they must not collapse.
 */
function splitPath(path: string): string[] {
  const segments = path.split("/");
  segments.shift();
  return segments;
}

function compileTemplate<T>(template: string, value: T): CompiledPattern<T> {
  const segments = splitPath(template).map<PatternSegment>((raw) => {
    if (raw.startsWith("{") && raw.endsWith("}")) {
      const inner = raw.slice(1, -1);
      if (inner.startsWith("*")) return { kind: SEGMENT_CATCH_ALL, value: inner.slice(1) };
      return { kind: SEGMENT_PARAM, value: inner };
    }
    return { kind: SEGMENT_STATIC, value: raw };
  });

  const catchAllAt = segments.findIndex((segment) => segment.kind === SEGMENT_CATCH_ALL);
  if (catchAllAt !== -1 && catchAllAt !== segments.length - 1) {
    throw new Error(`invalid route pattern ${template}: catch-all must be the final segment`);
  }
  return { template, segments, hasCatchAll: catchAllAt !== -1, value };
}

/** Attempt one pattern; returns captured params or `null` when it does not match. */
function matchPattern<T>(
  pattern: CompiledPattern<T>,
  requestSegments: readonly string[],
): Record<string, string> | null {
  const { segments, hasCatchAll } = pattern;
  const fixedCount = hasCatchAll ? segments.length - 1 : segments.length;

  if (hasCatchAll) {
    // `matchit` catch-alls consume one or more segments.
    if (requestSegments.length <= fixedCount) return null;
  } else if (requestSegments.length !== segments.length) {
    return null;
  }

  const params: Record<string, string> = {};
  for (let i = 0; i < fixedCount; i += 1) {
    const segment = segments[i];
    const actual = requestSegments[i];
    if (segment === undefined || actual === undefined) return null;
    if (segment.kind === SEGMENT_STATIC) {
      if (segment.value !== actual) return null;
    } else {
      // A parameter never matches an empty segment (`matchit` semantics).
      if (actual === "") return null;
      params[segment.value] = actual;
    }
  }

  if (hasCatchAll) {
    const tail = segments[segments.length - 1];
    if (tail === undefined) return null;
    params[tail.value] = requestSegments.slice(fixedCount).join("/");
  }
  return params;
}

/**
 * Specificity comparison mirroring `matchit`'s priority: the candidate whose
 * segments are static earliest wins; ties break on the shorter template.
 */
function isMoreSpecific<T>(candidate: CompiledPattern<T>, incumbent: CompiledPattern<T>): boolean {
  const length = Math.max(candidate.segments.length, incumbent.segments.length);
  for (let i = 0; i < length; i += 1) {
    const a = candidate.segments[i]?.kind ?? SEGMENT_CATCH_ALL;
    const b = incumbent.segments[i]?.kind ?? SEGMENT_CATCH_ALL;
    if (a !== b) return a < b;
  }
  return candidate.segments.length < incumbent.segments.length;
}

function bestMatch<T>(
  patterns: readonly CompiledPattern<T>[],
  path: string,
): { pattern: CompiledPattern<T>; params: Record<string, string> } | null {
  const requestSegments = splitPath(path);
  let winner: { pattern: CompiledPattern<T>; params: Record<string, string> } | null = null;
  for (const pattern of patterns) {
    const params = matchPattern(pattern, requestSegments);
    if (params === null) continue;
    if (winner === null || isMoreSpecific(pattern, winner.pattern)) winner = { pattern, params };
  }
  return winner;
}

// ---------------------------------------------------------------------------
// Parse + validate (the Rust `parse_contract`, invariant for invariant)
// ---------------------------------------------------------------------------

/** Convert a contract template to Hono syntax: `{p}` → `:p`, `{*rest}` → `*`. */
export function toHonoPath(contractPath: string): string {
  return splitPath(contractPath)
    .map((raw) => {
      if (!raw.startsWith("{") || !raw.endsWith("}")) return raw;
      const inner = raw.slice(1, -1);
      return inner.startsWith("*") ? "*" : `:${inner}`;
    })
    .map((segment) => `/${segment}`)
    .join("");
}

interface ParsedContract {
  readonly all: readonly ApiOperation[];
  readonly owned: readonly ApiOperation[];
  readonly byOperationId: ReadonlyMap<string, ApiOperation>;
  readonly byGroup: ReadonlyMap<string, readonly ApiOperation[]>;
  readonly pathPatterns: readonly CompiledPattern<ReadonlyMap<HttpMethod, ApiOperation>>[];
  readonly groupPatterns: readonly CompiledPattern<string>[];
}

function parseContract(raw: RawContract): ParsedContract {
  if (raw.version !== SUPPORTED_CONTRACT_VERSION) {
    throw new Error(
      `unsupported contract version ${raw.version}; expected ${SUPPORTED_CONTRACT_VERSION}`,
    );
  }

  const groupPatterns = raw.route_patterns.map((route) =>
    compileTemplate(route.pattern, route.group),
  );

  const byPath = new Map<string, Map<HttpMethod, ApiOperation>>();
  const byOperationId = new Map<string, ApiOperation>();
  const byGroup = new Map<string, ApiOperation[]>();
  const all: ApiOperation[] = [];
  const owned: ApiOperation[] = [];

  for (const rawOperation of raw.operations) {
    const group = bestMatch(groupPatterns, rawOperation.path);
    if (group === null) {
      throw new Error(
        `operation ${rawOperation.operation_id} path ${rawOperation.path} does not belong to a fixed route group`,
      );
    }

    const method = rawOperation.method.toUpperCase() as HttpMethod;
    if (!(HTTP_METHODS as readonly string[]).includes(method)) {
      throw new Error(
        `operation ${rawOperation.operation_id} has invalid method ${rawOperation.method}`,
      );
    }
    if (!(VISIBILITIES as readonly string[]).includes(rawOperation.visibility)) {
      throw new Error(
        `operation ${rawOperation.operation_id} has invalid visibility ${rawOperation.visibility}`,
      );
    }
    if (!(AUTH_KINDS as readonly string[]).includes(rawOperation.auth.kind)) {
      throw new Error(
        `operation ${rawOperation.operation_id} has invalid auth kind ${rawOperation.auth.kind}`,
      );
    }

    const kind = rawOperation.auth.kind as AuthKind;
    const scope = rawOperation.auth.scope ?? null;
    const rawDiscriminator = rawOperation.auth.scope_discriminator ?? null;

    // A bearer operation without a scope would authenticate and then guard
    // nothing — the Rust parser refuses the document rather than serve it.
    if (kind === "bearer" && (scope === null || scope === "")) {
      throw new Error(`operation ${rawOperation.operation_id} uses bearer auth without a scope`);
    }
    if (kind === "method_dependent" && rawDiscriminator === null) {
      throw new Error(
        `operation ${rawOperation.operation_id} uses method_dependent auth without a scope discriminator`,
      );
    }
    if (byOperationId.has(rawOperation.operation_id)) {
      throw new Error(`duplicate operation_id ${rawOperation.operation_id}`);
    }

    const operation: ApiOperation = {
      path: rawOperation.path,
      honoPath: toHonoPath(rawOperation.path),
      method,
      operationId: rawOperation.operation_id,
      visibility: rawOperation.visibility as Visibility,
      auth: {
        kind,
        scope,
        scopeDiscriminator:
          rawDiscriminator === null
            ? null
            : { field: rawDiscriminator.field, map: { ...rawDiscriminator.map } },
      },
      rbacAction: rawOperation.rbac_action ?? null,
      group: group.pattern.value,
    };

    byOperationId.set(operation.operationId, operation);
    all.push(operation);

    if (!isControlPlanePath(operation.path)) continue;

    owned.push(operation);
    const groupOps = byGroup.get(operation.group);
    if (groupOps === undefined) byGroup.set(operation.group, [operation]);
    else groupOps.push(operation);

    let methods = byPath.get(operation.path);
    if (methods === undefined) {
      methods = new Map<HttpMethod, ApiOperation>();
      byPath.set(operation.path, methods);
    }
    if (methods.has(method)) {
      throw new Error(`duplicate operation ${method} ${operation.path}`);
    }
    methods.set(method, operation);
  }

  const pathPatterns = [...byPath.entries()].map(([path, methods]) =>
    compileTemplate<ReadonlyMap<HttpMethod, ApiOperation>>(path, methods),
  );

  return { all, owned, byOperationId, byGroup, pathPatterns, groupPatterns };
}

const CONTRACT: ParsedContract = parseContract(RAW);

// ---------------------------------------------------------------------------
// Public lookup surface
// ---------------------------------------------------------------------------

/** Every operation in the document, in document order (all 259). */
export const ALL_OPERATIONS: readonly ApiOperation[] = CONTRACT.all;

/** The operations this Worker owns, in document order (203). */
export const CONTROL_PLANE_OPERATIONS: readonly ApiOperation[] = CONTRACT.owned;

/** Owned operations, keyed by contract `group` (`rbac`, `billing`, `wallets`, …). */
export const OPERATIONS_BY_GROUP: ReadonlyMap<string, readonly ApiOperation[]> = CONTRACT.byGroup;

/** Every group this Worker owns at least one operation in, sorted. */
export const CONTROL_PLANE_GROUPS: readonly string[] = [...CONTRACT.byGroup.keys()].sort();

/** Lookup by `operation_id` — across ALL 259, so a mis-assignment is visible. */
export function operationById(operationId: string): ApiOperation | undefined {
  return CONTRACT.byOperationId.get(operationId);
}

/** Every `operation_id` this Worker owns. */
export function controlPlaneOperationIds(): readonly string[] {
  return CONTROL_PLANE_OPERATIONS.map((operation) => operation.operationId);
}

/** Owned operations in one group (empty when the group belongs to another app). */
export function operationsInGroup(group: string): readonly ApiOperation[] {
  return CONTRACT.byGroup.get(group) ?? [];
}

/**
 * Lookup by `(method, path)` over the OWNED operations — the Rust
 * `api_contract::operation`, narrowed to this Worker. `method` is
 * case-insensitive; `path` must already be canonicalized (see
 * {@link canonicalRequestPath}).
 */
export function matchOperation(method: string, path: string): OperationMatch | undefined {
  const matched = bestMatch(CONTRACT.pathPatterns, path);
  if (matched === null) return undefined;
  const operation = matched.pattern.value.get(method.toUpperCase() as HttpMethod);
  if (operation === undefined) return undefined;
  return { operation, params: matched.params };
}

/** Rust `api_contract::path_is_documented`, narrowed to owned operations. */
export function pathIsDocumented(path: string): boolean {
  return bestMatch(CONTRACT.pathPatterns, path) !== null;
}

/** The methods documented for a request path (used to build a 405 `Allow`). */
export function methodsForPath(path: string): readonly HttpMethod[] {
  const matched = bestMatch(CONTRACT.pathPatterns, path);
  if (matched === null) return [];
  return [...matched.pattern.value.keys()];
}

/** Rust `api_contract::match_route_group`. */
export function matchRouteGroup(path: string): string | undefined {
  return bestMatch(CONTRACT.groupPatterns, path)?.pattern.value;
}

// ---------------------------------------------------------------------------
// `/control/v1/*` → `/admin/v1/*` (Rust `canonicalize_alias_path`)
// ---------------------------------------------------------------------------

/**
 * Fold the legacy alias prefix onto the stable one — the single source of
 * truth, ported from `ferrogate_admin::control_plane::canonicalize_alias_path`.
 *
 * **Whole-segment match only.** `/control/v1x`, `/control/v1x/y`, `/control`
 * and `/controlled/v1` are DIFFERENT resources and are never captured; an
 * already-canonical `/admin/v1/...` is left untouched (no double-rewrite).
 * Returns `null` when `path` is not an alias, exactly like the Rust `Option`.
 */
export function canonicalizeAliasPath(path: string): string | null {
  if (!path.startsWith(ALIAS_PATH_PREFIX)) return null;
  const rest = path.slice(ALIAS_PATH_PREFIX.length);
  if (rest === "" || rest.startsWith("/")) return `${STABLE_PATH_PREFIX}${rest}`;
  return null;
}

/** Apply alias canonicalization if applicable, else return `path` unchanged. */
export function canonicalRequestPath(path: string): string {
  return canonicalizeAliasPath(path) ?? path;
}
