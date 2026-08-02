/**
 * This app's slice of the 254-operation runtime API contract.
 *
 * `docs/rewrite/ROUTE-MAP.md` assigns `apps/mcp` **6** operations
 * (`/v1/mcp`, `/v1/mcp/tool/execute`, `/v1/mcp/identity/**`) plus the **2**
 * shared operations — `/healthz` and `/readyz` — that ROUTE-MAP requires in
 * *every* Worker. Ownership is asserted against the committed
 * `docs/openapi/runtime-api-contract.json` at module load, so a contract edit
 * that moves, renames, or re-authenticates one of these fails loudly here
 * rather than silently drifting from the handlers.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/api_contract.rs`,
 * which `include_str!`s the same JSON into a `matchit` radix router and panics
 * at first use on a structural violation.
 *
 * ROUTE-MAP invariant 1 — "port these as Hono middleware driven by the
 * contract, not as hand-written per-route guards" — is why `src/routes/`
 * mounts by `operation_id` and never restates a path or a method: the path,
 * the HTTP method and the declared auth all come from this table.
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
 * `auth.scope_discriminator` — how a `method_dependent` operation resolves the
 * scope it requires. `field` names the request field that selects the scope
 * (for `POST /v1/mcp` that is the JSON-RPC `method`).
 */
export interface ScopeDiscriminator {
  readonly field: string;
  readonly map: ReadonlyMap<string, string>;
}

/** `auth` block of an operation (Rust `ApiOperationAuth`). */
export interface OperationAuth {
  readonly kind: AuthKind;
  /** Required scope for `bearer`; `null` for every other kind. */
  readonly scope: string | null;
  /** Present only on `method_dependent`. */
  readonly scopeDiscriminator?: ScopeDiscriminator;
}

/** One contract operation this Worker serves (Rust `ApiOperation`). */
export interface ApiOperation {
  /** Contract path template, e.g. `/v1/mcp/identity/{server}`. */
  readonly path: string;
  /** The same template in Hono syntax, e.g. `/v1/mcp/identity/:server`. */
  readonly honoPath: string;
  readonly method: HttpMethod;
  readonly operationId: string;
  readonly visibility: Visibility;
  readonly auth: OperationAuth;
  readonly rbacAction: string | null;
}

// ---------------------------------------------------------------------------
// Raw document shape
// ---------------------------------------------------------------------------

interface RawScopeDiscriminator {
  field: string;
  map: Record<string, string>;
}

interface RawOperation {
  path: string;
  method: string;
  operation_id: string;
  visibility: string;
  auth: { kind: string; scope: string | null; scope_discriminator?: RawScopeDiscriminator };
  rbac_action: string | null;
}

interface RawContract {
  version: number;
  operations: RawOperation[];
}

const RAW = contractDocument as unknown as RawContract;

/** Contract document version this port understands (Rust rejects anything else). */
export const SUPPORTED_CONTRACT_VERSION = 1;

// ---------------------------------------------------------------------------
// Ownership tables
// ---------------------------------------------------------------------------

/**
 * `/healthz` + `/readyz` — ROUTE-MAP's "shared" row: implemented in EVERY
 * Worker, owned by none. They are contract operations like any other, so they
 * are registered through the same router and covered by the same anti-drift
 * gate.
 */
export const SHARED_OPERATION_IDS = ["getHealthz", "getReadyz"] as const;

/** The 6 `operation_id`s ROUTE-MAP assigns to `apps/mcp`. */
export const OWNED_OPERATION_IDS = [
  "mcpJsonRpc",
  "executeMcpTool",
  "completeMcpIdentityOauth",
  "authorizeMcpIdentity",
  "getMcpIdentity",
  "revokeMcpIdentity",
] as const;

export type OwnedOperationId = (typeof OWNED_OPERATION_IDS)[number];

/** Every operation the deployed `ferrogate-mcp` Worker must serve: 6 + 2. */
export const APP_OPERATION_IDS: readonly string[] = [
  ...SHARED_OPERATION_IDS,
  ...OWNED_OPERATION_IDS,
];

/** How many operations this Worker owns (ROUTE-MAP: 6). */
export const EXPECTED_OWNED_OPERATION_COUNT = 6;
/** Owned + shared (ROUTE-MAP: 6 + 2). */
export const EXPECTED_APP_OPERATION_COUNT = 8;

/**
 * The operations in this app's slice whose `auth.kind` is `anonymous`
 * (ROUTE-MAP invariant 3). `parseAppContract` asserts the contract agrees, so a
 * contract edit that makes a fourth MCP route unauthenticated — or that
 * silently downgrades one of these — fails at module load.
 */
export const ANONYMOUS_OPERATION_IDS = [
  "getHealthz",
  "getReadyz",
  "completeMcpIdentityOauth",
] as const;

// ---------------------------------------------------------------------------
// Parse + validate
// ---------------------------------------------------------------------------

/** Split a path into segments, dropping only the structural leading empty piece. */
function splitPath(path: string): string[] {
  const segments = path.split("/");
  segments.shift();
  return segments;
}

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
}

function parseAppContract(raw: RawContract): ParsedContract {
  if (raw.version !== SUPPORTED_CONTRACT_VERSION) {
    throw new Error(
      `unsupported contract version ${raw.version}; expected ${SUPPORTED_CONTRACT_VERSION}`,
    );
  }

  const wanted = new Set<string>(APP_OPERATION_IDS);
  const byOperationId = new Map<string, ApiOperation>();
  const operations: ApiOperation[] = [];
  const seenPathMethod = new Set<string>();

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
    if (kind !== "bearer" && scope !== null) {
      throw new Error(
        `operation ${rawOperation.operation_id} declares a bearer scope on ${kind} auth`,
      );
    }
    if (byOperationId.has(rawOperation.operation_id)) {
      throw new Error(`duplicate operation_id ${rawOperation.operation_id}`);
    }
    const pathMethod = `${method} ${rawOperation.path}`;
    if (seenPathMethod.has(pathMethod)) throw new Error(`duplicate operation ${pathMethod}`);
    seenPathMethod.add(pathMethod);

    const auth: OperationAuth = { kind, scope };
    const rawDiscriminator = rawOperation.auth.scope_discriminator;
    if (kind === "method_dependent") {
      if (rawDiscriminator === undefined) {
        throw new Error(
          `method_dependent operation ${rawOperation.operation_id} has no scope_discriminator`,
        );
      }
      const entries = Object.entries(rawDiscriminator.map);
      if (entries.length === 0) {
        throw new Error(
          `method_dependent operation ${rawOperation.operation_id} has an empty scope map`,
        );
      }
      // A `Map` — never a plain object — so an inherited key such as
      // `constructor` or `toString` can NEVER resolve to a "scope".
      (auth as { scopeDiscriminator?: ScopeDiscriminator }).scopeDiscriminator = {
        field: rawDiscriminator.field,
        map: new Map(entries),
      };
    } else if (rawDiscriminator !== undefined) {
      throw new Error(
        `operation ${rawOperation.operation_id} declares a scope_discriminator on ${kind} auth`,
      );
    }

    const operation: ApiOperation = {
      path: rawOperation.path,
      honoPath: toHonoPath(rawOperation.path),
      method,
      operationId: rawOperation.operation_id,
      visibility: rawOperation.visibility as Visibility,
      auth,
      rbacAction: rawOperation.rbac_action ?? null,
    };
    byOperationId.set(operation.operationId, operation);
    operations.push(operation);
  }

  const missing = APP_OPERATION_IDS.filter((id) => !byOperationId.has(id));
  if (missing.length > 0) {
    throw new Error(`contract is missing apps/mcp operations: ${missing.join(", ")}`);
  }
  if (operations.length !== EXPECTED_APP_OPERATION_COUNT) {
    throw new Error(
      `apps/mcp serves ${operations.length} contract operations; expected ${EXPECTED_APP_OPERATION_COUNT}`,
    );
  }

  // ROUTE-MAP invariant 3 — exactly these three may skip authentication.
  const anonymous = operations
    .filter((operation) => operation.auth.kind === "anonymous")
    .map((operation) => operation.operationId)
    .sort();
  const expectedAnonymous = [...ANONYMOUS_OPERATION_IDS].sort();
  if (anonymous.join(",") !== expectedAnonymous.join(",")) {
    throw new Error(
      `apps/mcp anonymous operations drifted: got [${anonymous.join(", ")}], expected [${expectedAnonymous.join(", ")}]`,
    );
  }

  return { operations, byOperationId };
}

const CONTRACT: ParsedContract = parseAppContract(RAW);

// ---------------------------------------------------------------------------
// Public lookup surface
// ---------------------------------------------------------------------------

/** Every operation this Worker serves, in contract document order. */
export const OPERATIONS: readonly ApiOperation[] = CONTRACT.operations;

/** Lookup by `operation_id`; `undefined` when the id is not in this app's slice. */
export function operationById(operationId: string): ApiOperation | undefined {
  return CONTRACT.byOperationId.get(operationId);
}

/**
 * Resolve a `method_dependent` operation's required scope from the contract's
 * own discriminator (ROUTE-MAP invariant 4 — read the contract, never assume).
 *
 * Returns `undefined` for an unmapped value, which callers MUST treat as "no
 * scope was granted", not as "no scope is needed". Backed by a `Map`, so an
 * inherited `Object.prototype` key (`toString`, `constructor`, `__proto__`)
 * yields `undefined` like any other unmapped method.
 */
export function methodDependentScope(operationId: string, value: string): string | undefined {
  return operationById(operationId)?.auth.scopeDiscriminator?.map.get(value);
}

/**
 * The full `POST /v1/mcp` method→scope map, straight from the contract. The
 * dispatcher's own table is asserted equal to this in `test/contract.test.ts`.
 */
export function mcpJsonRpcMethodScopes(): ReadonlyMap<string, string> {
  const discriminator = operationById("mcpJsonRpc")?.auth.scopeDiscriminator;
  if (discriminator === undefined) {
    throw new Error("contract lost the mcpJsonRpc scope discriminator");
  }
  return discriminator.map;
}
