/**
 * The 267-operation runtime API contract, as a typed, table-driven route table.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/api_contract.rs`.
 * The Rust build `include_str!`s `docs/openapi/runtime-api-contract.json`,
 * parses it into two `matchit` radix routers (route groups, and operations
 * keyed by method), and panics at first use if the document violates any of its
 * structural invariants. This module does the same three things in TS:
 *
 *  1. imports the SAME JSON document (`resolveJsonModule`) — there is exactly
 *     one source of truth and no generated copy to drift from;
 *  2. validates it eagerly at module load (throws, mirroring the Rust panic);
 *  3. exposes lookup by `(method, path)` and by `operation_id`.
 *
 * The `matchit` radix tree is re-implemented as a small specificity-ranked
 * segment matcher (`matchOperation`). `matchit` resolves a conflict such as
 * `/v1/assets/withheld` vs `/v1/assets/{asset_type}` in favour of the static
 * segment; so does this, by ranking each candidate segment-wise
 * (static < param < catch-all) and taking the lexicographically smallest rank.
 *
 * Nothing here is gateway-specific: all 267 operations are present, including
 * the ones other Workers own. Ownership is a separate concern
 * (`GATEWAY_OWNED_OPERATION_IDS` in `./routes/index.ts`).
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
 * required scope from the request body (Rust `ApiScopeDiscriminator`).
 */
export interface ScopeDiscriminator {
  /** Request-body field whose value selects the scope (today always `method`). */
  readonly field: string;
  /** Discriminator value → required scope. */
  readonly map: Readonly<Record<string, string>>;
}

/** `auth` block of an operation (Rust `ApiOperationAuth`). */
export interface OperationAuth {
  readonly kind: AuthKind;
  /** Required scope for `bearer`; `null` for every other kind. */
  readonly scope: string | null;
  /** Present only for `method_dependent`. */
  readonly scopeDiscriminator: ScopeDiscriminator | null;
}

/** One of the 267 contract operations (Rust `ApiOperation`). */
export interface ApiOperation {
  /** Contract path template, e.g. `/v1/assets/{asset_type}/{name}/{version}`. */
  readonly path: string;
  /** The same template in Hono syntax, e.g. `/v1/assets/:asset_type/:name/:version`. */
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
  /** Path parameters captured from the request path. */
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

/**
 * The number of operations the contract is expected to carry. `ROUTE-MAP.md`
 * makes this the anti-drift gate: if the JSON changes, the assertion in
 * `test/contract.test.ts` fails before any route silently disappears.
 */
export const EXPECTED_OPERATION_COUNT = 267;

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

/** Split a path into segments, dropping only the leading empty piece. */
function splitPath(path: string): string[] {
  const segments = path.split("/");
  // "/v1/models" -> ["", "v1", "models"]; "/admin/" -> ["", "admin", ""].
  // Only the leading "" is structural — a trailing "" is meaningful, because
  // the contract lists `/admin` and `/admin/` as two distinct patterns.
  segments.shift();
  return segments;
}

function compileTemplate<T>(template: string, value: T): CompiledPattern<T> {
  const segments = splitPath(template).map<PatternSegment>((raw) => {
    if (raw.startsWith("{") && raw.endsWith("}")) {
      const inner = raw.slice(1, -1);
      if (inner.startsWith("*")) {
        return { kind: SEGMENT_CATCH_ALL, value: inner.slice(1) };
      }
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
 * Specificity comparison, mirroring `matchit`'s priority: the candidate whose
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
    if (winner === null || isMoreSpecific(pattern, winner.pattern)) {
      winner = { pattern, params };
    }
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
  readonly operations: readonly ApiOperation[];
  readonly byOperationId: ReadonlyMap<string, ApiOperation>;
  /** Compiled operation paths → method table, one entry per distinct path. */
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
  const operations: ApiOperation[] = [];

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

    if (kind === "bearer" && (scope === null || scope === "")) {
      throw new Error(`operation ${rawOperation.operation_id} uses bearer auth without a scope`);
    }
    if (kind === "method_dependent") {
      if (rawDiscriminator === null) {
        throw new Error(
          `operation ${rawOperation.operation_id} uses method_dependent auth without a scope discriminator`,
        );
      }
      const entries = Object.entries(rawDiscriminator.map);
      if (
        scope !== null ||
        rawDiscriminator.field === "" ||
        entries.length === 0 ||
        entries.some(([value, mapped]) => value === "" || mapped === "")
      ) {
        throw new Error(
          `operation ${rawOperation.operation_id} has an invalid scope discriminator`,
        );
      }
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

    let methods = byPath.get(operation.path);
    if (methods === undefined) {
      methods = new Map<HttpMethod, ApiOperation>();
      byPath.set(operation.path, methods);
    }
    if (methods.has(method)) {
      throw new Error(`duplicate operation ${method} ${operation.path}`);
    }
    methods.set(method, operation);
    byOperationId.set(operation.operationId, operation);
    operations.push(operation);
  }

  const pathPatterns = [...byPath.entries()].map(([path, methods]) =>
    compileTemplate<ReadonlyMap<HttpMethod, ApiOperation>>(path, methods),
  );

  return { operations, byOperationId, pathPatterns, groupPatterns };
}

const CONTRACT: ParsedContract = parseContract(RAW);

// ---------------------------------------------------------------------------
// Public lookup surface
// ---------------------------------------------------------------------------

/** Every contract operation, in document order. */
export const OPERATIONS: readonly ApiOperation[] = CONTRACT.operations;

/** Lookup by `operation_id`. */
export function operationById(operationId: string): ApiOperation | undefined {
  return CONTRACT.byOperationId.get(operationId);
}

/** Every `operation_id` in the contract. */
export function operationIds(): readonly string[] {
  return [...CONTRACT.byOperationId.keys()];
}

/**
 * Lookup by `(method, path)` — the Rust `api_contract::operation`.
 * `method` is case-insensitive; `path` is the raw request pathname.
 */
export function matchOperation(method: string, path: string): OperationMatch | undefined {
  const matched = bestMatch(CONTRACT.pathPatterns, path);
  if (matched === null) return undefined;
  const operation = matched.pattern.value.get(method.toUpperCase() as HttpMethod);
  if (operation === undefined) return undefined;
  return { operation, params: matched.params };
}

/** Rust `api_contract::path_is_documented` — the path exists under some method. */
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

/**
 * Rust `api_contract::method_dependent_scope` — resolve the scope a
 * `method_dependent` operation requires for a given discriminator value.
 * Returns `undefined` when the contract has no mapping (which callers must
 * treat as a denial, never as "no scope required").
 */
export function methodDependentScope(
  method: string,
  path: string,
  discriminatorValue: string,
): string | undefined {
  const operation = matchOperation(method, path)?.operation;
  const map = operation?.auth.scopeDiscriminator?.map;
  if (map === undefined) return undefined;
  return Object.hasOwn(map, discriminatorValue) ? map[discriminatorValue] : undefined;
}

/**
 * `/control/v1/*` → `/admin/v1/*` canonicalization (ROUTE-MAP invariant 7,
 * Rust `ferrogate_admin::control_plane::canonicalize_alias_path`). Returns
 * `null` when `path` is not an alias, exactly like the Rust `Option`.
 */
const ALIAS_PATH_PREFIX = "/control/v1";
const STABLE_PATH_PREFIX = "/admin/v1";
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
