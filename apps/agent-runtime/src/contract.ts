/**
 * This app's slice of the 276-operation runtime API contract.
 *
 * `ROUTE-MAP.md` assigns `apps/agent-runtime` **15** operations:
 * `/v1/agent-runs` (1), `/v1/agent-jobs/**` (5), `/v1/agents/**` (3) and the six
 * `/v1/self-hosted-workers/**` worker-plane callbacks. Ownership is asserted
 * against the committed contract at module load, so a contract edit that moves,
 * renames, or re-authenticates one of these operations fails loudly here rather
 * than silently drifting from the handlers.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/api_contract.rs`
 * (which `include_str!`s the same JSON into a `matchit` radix router and panics
 * at first use on a structural violation). The radix tree is re-implemented as a
 * small specificity-ranked segment matcher: a static segment beats a parameter,
 * a parameter beats a catch-all, which is how `matchit` resolves
 * `/v1/agent-jobs/{run_id}/events` against `/v1/agent-jobs/{run_id}`.
 *
 * `ROUTE-MAP.md` invariant 1 — "port these as Hono middleware driven by the
 * contract, not as hand-written per-route guards" — is why nothing downstream
 * hard-codes a scope: `middleware/auth.ts` reads `auth.kind` / `auth.scope` off
 * the operation this table returns.
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

/** `auth` block of an operation (Rust `ApiOperationAuth`). */
export interface OperationAuth {
  readonly kind: AuthKind;
  /** Required scope for `bearer`; `null` for every other kind. */
  readonly scope: string | null;
}

/** One contract operation owned by this Worker (Rust `ApiOperation`). */
export interface ApiOperation {
  /** Contract path template, e.g. `/v1/agent-jobs/{run_id}/events`. */
  readonly path: string;
  /** The same template in Hono syntax, e.g. `/v1/agent-jobs/:run_id/events`. */
  readonly honoPath: string;
  readonly method: HttpMethod;
  readonly operationId: string;
  readonly visibility: Visibility;
  readonly auth: OperationAuth;
  readonly rbacAction: string | null;
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

interface RawOperation {
  path: string;
  method: string;
  operation_id: string;
  visibility: string;
  auth: { kind: string; scope: string | null };
  rbac_action: string | null;
}

interface RawContract {
  version: number;
  operations: RawOperation[];
}

const RAW = contractDocument as unknown as RawContract;

/** Contract document version this port understands (Rust rejects anything else). */
export const SUPPORTED_CONTRACT_VERSION = 1;

/**
 * The 15 `operation_id`s `ROUTE-MAP.md` assigns to this Worker.
 *
 * This list is the anti-drift gate: `parseOwnedContract` requires every id here
 * to exist in the JSON exactly once, and `test/contract.test.ts` requires every
 * id here to have a handler. Neither side can quietly lose an operation.
 */
export const OWNED_OPERATION_IDS = [
  // --- synchronous run create ------------------------------------------------
  "createAgentRun",
  // --- async agent-job protocol (#474) --------------------------------------
  "submitAgentJob",
  "getAgentJob",
  "listAgentJobEvents",
  "getAgentJobResult",
  "cancelAgentJob",
  // --- A2A agent ingress (#278) ---------------------------------------------
  "invokeAgent",
  "sendAgentMessage",
  "streamAgentMessage",
  // --- worker-plane callbacks (auth.kind = internal, #414) ------------------
  "recordSelfHostedWorkerHeartbeat",
  "recordSelfHostedWorkerEvent",
  "uploadSelfHostedWorkerArtifact",
  "uploadSelfHostedWorkerCheckpoint",
  "pollSelfHostedWorkerRun",
  "acknowledgeSelfHostedWorkerRun",
] as const;

export type OwnedOperationId = (typeof OWNED_OPERATION_IDS)[number];

/** How many operations this Worker owns (ROUTE-MAP: 15). */
export const EXPECTED_OWNED_OPERATION_COUNT = 15;

/**
 * The `operation_id`s whose `auth.kind` is `internal` — the worker-plane
 * callbacks a tenant bearer key must NOT be able to call (ROUTE-MAP invariant
 * 2). Derived from the contract, never hand-maintained, so a contract change
 * that downgrades one of these to `bearer` shows up as a failing assertion in
 * `parseOwnedContract` instead of a silently reachable callback.
 */
export const EXPECTED_INTERNAL_OPERATION_COUNT = 6;

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

/** Split a path into segments, dropping only the structural leading empty piece. */
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

/** `matchit` priority: static-earliest wins; ties break on the shorter template. */
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
// Parse + validate
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
  readonly pathPatterns: readonly CompiledPattern<ReadonlyMap<HttpMethod, ApiOperation>>[];
  /** Every path template in the WHOLE contract this Worker's prefixes cover. */
  readonly ownedPrefixes: readonly string[];
}

/**
 * Prefixes of the request surface this Worker answers. A request under one of
 * these that matches no owned operation is a 404/405 *from this Worker*; a
 * request outside them was routed here by mistake.
 */
const OWNED_PREFIXES = [
  "/v1/agent-runs",
  "/v1/agent-jobs",
  "/v1/agents",
  "/v1/self-hosted-workers",
];

function parseOwnedContract(raw: RawContract): ParsedContract {
  if (raw.version !== SUPPORTED_CONTRACT_VERSION) {
    throw new Error(
      `unsupported contract version ${raw.version}; expected ${SUPPORTED_CONTRACT_VERSION}`,
    );
  }

  const wanted = new Set<string>(OWNED_OPERATION_IDS);
  const byPath = new Map<string, Map<HttpMethod, ApiOperation>>();
  const byOperationId = new Map<string, ApiOperation>();
  const operations: ApiOperation[] = [];

  for (const rawOperation of raw.operations) {
    if (!wanted.has(rawOperation.operation_id)) continue;

    const method = rawOperation.method.toUpperCase() as HttpMethod;
    if (!(HTTP_METHODS as readonly string[]).includes(method)) {
      throw new Error(`operation ${rawOperation.operation_id} has invalid method ${method}`);
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
    if (kind === "bearer" && (scope === null || scope === "")) {
      throw new Error(`operation ${rawOperation.operation_id} uses bearer auth without a scope`);
    }
    // ROUTE-MAP invariant 2: an `internal` operation carries NO tenant scope.
    // A scope here would imply a tenant bearer key could satisfy it.
    if (kind === "internal" && scope !== null) {
      throw new Error(
        `internal operation ${rawOperation.operation_id} must not declare a bearer scope`,
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
      auth: { kind, scope },
      rbacAction: rawOperation.rbac_action ?? null,
    };

    let methods = byPath.get(operation.path);
    if (methods === undefined) {
      methods = new Map<HttpMethod, ApiOperation>();
      byPath.set(operation.path, methods);
    }
    if (methods.has(method)) throw new Error(`duplicate operation ${method} ${operation.path}`);
    methods.set(method, operation);
    byOperationId.set(operation.operationId, operation);
    operations.push(operation);
  }

  const missing = [...wanted].filter((id) => !byOperationId.has(id));
  if (missing.length > 0) {
    throw new Error(`contract is missing agent-runtime operations: ${missing.join(", ")}`);
  }
  if (operations.length !== EXPECTED_OWNED_OPERATION_COUNT) {
    throw new Error(
      `agent-runtime owns ${operations.length} contract operations; expected ${EXPECTED_OWNED_OPERATION_COUNT}`,
    );
  }
  const internalCount = operations.filter((o) => o.auth.kind === "internal").length;
  if (internalCount !== EXPECTED_INTERNAL_OPERATION_COUNT) {
    throw new Error(
      `agent-runtime owns ${internalCount} internal operations; expected ${EXPECTED_INTERNAL_OPERATION_COUNT}`,
    );
  }

  const pathPatterns = [...byPath.entries()].map(([path, methods]) =>
    compileTemplate<ReadonlyMap<HttpMethod, ApiOperation>>(path, methods),
  );

  return { operations, byOperationId, pathPatterns, ownedPrefixes: OWNED_PREFIXES };
}

const CONTRACT: ParsedContract = parseOwnedContract(RAW);

// ---------------------------------------------------------------------------
// Public lookup surface
// ---------------------------------------------------------------------------

/** Every operation this Worker owns, in contract document order. */
export const OPERATIONS: readonly ApiOperation[] = CONTRACT.operations;

/** Lookup by `operation_id`. */
export function operationById(operationId: string): ApiOperation | undefined {
  return CONTRACT.byOperationId.get(operationId);
}

/** The six `auth.kind: "internal"` worker-plane callbacks. */
export function internalOperations(): readonly ApiOperation[] {
  return CONTRACT.operations.filter((operation) => operation.auth.kind === "internal");
}

/**
 * Normalize a request path the way the Rust ingress does before matching:
 * strip the query, then collapse a trailing slash on anything but the root.
 * The contract has no trailing-slash template in this Worker's surface, so
 * `/v1/agent-jobs/` must resolve exactly as `/v1/agent-jobs` does.
 */
export function canonicalRequestPath(rawPath: string): string {
  const queryAt = rawPath.indexOf("?");
  const path = queryAt === -1 ? rawPath : rawPath.slice(0, queryAt);
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

/** `true` when the path falls inside this Worker's contract surface. */
export function isOwnedPath(path: string): boolean {
  return CONTRACT.ownedPrefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

/**
 * Lookup by `(method, path)`. Returns `undefined` when no owned operation has
 * this path; returns `{ operation: undefined, allowed }` semantics via
 * {@link allowedMethods} when the path matches but the method does not.
 */
export function matchOperation(method: string, path: string): OperationMatch | undefined {
  const matched = bestMatch(CONTRACT.pathPatterns, canonicalRequestPath(path));
  if (matched === null) return undefined;
  const operation = matched.pattern.value.get(method.toUpperCase() as HttpMethod);
  if (operation === undefined) return undefined;
  return { operation, params: matched.params };
}

/** Methods the contract documents for a path — the `Allow` header of a 405. */
export function allowedMethods(path: string): readonly HttpMethod[] {
  const matched = bestMatch(CONTRACT.pathPatterns, canonicalRequestPath(path));
  if (matched === null) return [];
  return [...matched.pattern.value.keys()];
}
