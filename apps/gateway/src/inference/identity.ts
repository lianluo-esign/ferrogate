/**
 * How the AUTHENTICATED identity and the resolved quota windows reach the
 * inference handlers.
 *
 * ## The problem this file exists to solve
 *
 * `inferenceRouteModule` delegates by calling `inner.fetch(c.req.raw, c.env,
 * ctx)`. That is deliberate — it is what keeps ROUTE-MAP invariant 1 (one
 * table-driven auth guard for all 251 operations) intact, because the inner app
 * carries no auth of its own. But `inner.fetch` starts a FRESH Hono context, so
 * everything the outer middleware chain resolved onto `c` — `c.get("auth")`
 * from `contractAuth`, the merged quota windows from `rateLimit()` — is
 * invisible on the other side of the call.
 *
 * The consequence was not theoretical. Before this module existed, the inner
 * app fell back to `defaultCallerResolver`, i.e. a PLATFORM OPERATOR with no
 * model allow/deny list, for every request the deployed Worker served. Two Rust
 * gates the inference handlers own were therefore dead in production while
 * every unit test that injected a `caller` stayed green:
 *
 *   - `AuthContext::can_use_model` → 403 `model_not_allowed`;
 *   - the tenant model-visibility filter on `GET /v1/models` and on invocation
 *     (issue #515) — a tenant could list AND invoke another tenant's private
 *     logical model, because `scopeCanSeeModel` returns `true` unconditionally
 *     for a platform operator.
 *
 * A third was dead for the same reason: `enforceTokensPerMinute` (Rust step 5,
 * the TPM window) had no way to see the windows `rateLimit()` resolved.
 *
 * ## The carrier, and why it is a `WeakMap` keyed by the `Request`
 *
 * The obvious alternatives are both wrong here:
 *
 *  - a wrapper `env` object (`{ ...c.env, auth }`) would defeat
 *    `envScopedDeps`, which memoizes the resolved ports in a `WeakMap` keyed by
 *    the env IDENTITY. A fresh object per request rebuilds the model registry
 *    per request and throws away the isolate's warm catalog;
 *  - a module-level "current request" variable is a cross-request data leak the
 *    moment two requests interleave on an `await`, which every one of these
 *    handlers does.
 *
 * The `Request` object, on the other hand, is per-request by construction, is
 * the exact value handed to `inner.fetch`, and is collected with the request —
 * so a `WeakMap` keyed by it is both isolated and leak-free. `handlers.ts` reads
 * it in the identity middleware, which runs BEFORE `readInferenceBody()`
 * replaces `c.req.raw`.
 */
import type { AuthContext } from "../ports.js";
import { callerScope } from "../ports.js";
import type { InferenceRejection } from "./errors.js";
import type { Caller } from "./ports.js";

/**
 * Rust `auth::finalize_auth` → the slice of `AuthContext` the inference
 * handlers read.
 *
 * PORT-TODO(inventory-edge-control §5.2): `allowedModels`/`deniedModels` are
 * NOT populated, because `AuthContext` in `src/ports.ts` has no fields for them
 * — see the matching PORT-TODO on `toAuthContext` in `src/keys/resolver.ts`,
 * which already LOADS `allowed_models` off the `api_keys` row and drops it for
 * want of somewhere to put it. `src/ports.ts` is the composition root's file,
 * not this slice's.
 *
 * Cross-file, not cross-platform, and the omission is scoped precisely: the
 * per-key model ALLOW/DENY list (403 `model_not_allowed`) stays unenforced for
 * durable keys, while the tenant/project visibility gate (issue #515) — which
 * reads `scope` and `projectId`, both of which DO exist here — is live. The
 * remaining change is three optional members on `AuthContext` plus two lines
 * below.
 */
export function callerFromAuth(auth: AuthContext): Caller {
  const projectId = auth.tenancy.projectId;
  return {
    // `callerScope` is the Rust `AuthContext::caller_scope`: platform-operator
    // ONLY when the credential declared it, and an unclassified credential is
    // confined to the empty-string tenant, which matches no route.
    scope: callerScope(auth),
    ...(auth.subject !== null ? { apiKeyId: auth.subject } : {}),
    ...(projectId !== null && projectId !== undefined ? { projectId } : {}),
  };
}

/**
 * The tokens-per-minute gate as the inference handlers consume it.
 *
 * Non-throwing on purpose. `enforceTokensPerMinute` throws an `HttpError` that
 * the OUTER app's `onError` renders; a throw raised inside `inner.fetch` would
 * be rendered by the INNER app instead, which has no error handler and would
 * turn the Rust 429 into a 500. So the decision is returned as the same
 * {@link InferenceRejection} every other refusal in `handlers.ts` uses, and
 * leaves through the same `errorResponse` envelope.
 */
export interface TokenGovernor {
  /**
   * Charge `estimatedTokens` against the caller's TPM window.
   *
   * Returns `null` when no TPM limit governs the request, an
   * {@link InferenceRejection} on refusal (429 `tpm_limit_exceeded`, or 503
   * `governance_counter_unavailable` when the counter backend is down — the
   * Rust `Err` arm, which is never a 429), and otherwise an opaque admission
   * handle to hand back to {@link settle}.
   */
  admit(estimatedTokens: number): Promise<TokenAdmissionHandle | InferenceRejection | null>;
  /**
   * Reconcile the admission against the response's REAL token usage.
   *
   * Opt-in (`RateLimitOptions.settleTokens`); Rust never settles a TPM window,
   * so the default no-ops and the port stays byte-identical.
   */
  settle(handle: TokenAdmissionHandle | null, actualTokens: number): Promise<void>;
}

/** Opaque to the inference module; `ratelimit/` owns its shape. */
export type TokenAdmissionHandle = { readonly __tokenAdmission: unique symbol } | object;

/** A governor for a request nothing governs. Every method is inert. */
export const unmeteredTokenGovernor: TokenGovernor = {
  admit: async () => null,
  settle: async () => {},
};

/**
 * Everything the outer composition resolved for THIS request.
 *
 * Every member is optional so an inner-app unit test (which calls
 * `createInferenceRouter` directly, with no outer app at all) keeps working
 * unchanged and falls back to the injected `InferenceDeps`.
 */
export interface InferenceRequestScope {
  /** The caller derived from `c.get("auth")` by the outer guard. */
  readonly caller?: Caller | undefined;
  /** The TPM window `rateLimit()` resolved on the outer context. */
  readonly tokens?: TokenGovernor | undefined;
}

const SCOPES = new WeakMap<Request, InferenceRequestScope>();

/** Publish the outer request scope. Called by `route-module.ts`, once. */
export function setInferenceRequestScope(request: Request, scope: InferenceRequestScope): void {
  SCOPES.set(request, scope);
}

/** Read the scope published for `request`, or `undefined` when there is none. */
export function inferenceRequestScope(request: Request): InferenceRequestScope | undefined {
  return SCOPES.get(request);
}
