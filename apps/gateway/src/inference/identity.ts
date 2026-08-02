/**
 * How the AUTHENTICATED identity and the resolved quota windows reach the
 * inference handlers.
 *
 * ## The problem this file exists to solve
 *
 * `inferenceRouteModule` delegates by calling `inner.fetch(c.req.raw, c.env,
 * ctx)`. That is deliberate — it is what keeps ROUTE-MAP invariant 1 (one
 * table-driven auth guard for all 254 operations) intact, because the inner app
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
 * ## The per-key model allowlist (was PORT-TODO inventory-edge-control §5.2 —
 * now wired)
 *
 * `AuthContext.allowedModels` is populated by `keys/resolver.ts::toAuthContext`
 * off the `api_keys` row, and it is copied onto the {@link Caller} here so
 * `ports.ts::callerCanUseModel` — i.e. `handlers.ts`'s 403 `model_not_allowed`
 * gate — actually sees it. Reading the column and never forwarding it is the
 * defect shape this wave exists to remove: the resolver's own test would stay
 * green on a key whose allowlist was enforced nowhere.
 *
 * `deniedModels` is NOT forwarded, and that is not an omission: Rust's
 * `AuthContext` carries `denied_models` as a separate `HashSet`, `AuthContext`
 * in `src/ports.ts` has no such field, and the `api_keys` row this tree reads
 * has no denylist COLUMN. Inventing one would be inventing a gate. The port
 * keeps `Caller.deniedModels` in the type — `callerCanUseModel` implements the
 * full Rust predicate, deny-wins-then-allowlist, and unit tests exercise both
 * legs — so the day a denylist column lands the only change is one more line
 * here. Absent means "no denylist", which is the Rust reading of an empty set.
 *
 * ## The per-key PROVIDER allowlist (`auth.rs:146` `can_use_provider` — now wired)
 *
 * `AuthContext.allowedProviders` comes off the same `api_keys` row
 * (`allowed_providers_json`) and had NO reader anywhere in the inference path,
 * which is the same two-hop dead-seam the model allowlist had: `keys/store.ts`
 * parsed it, `keys/resolver.ts` forwarded it, and every one of their tests
 * stayed green while a key restricted to `openai` could dispatch to any
 * provider in the catalog. It is now copied onto {@link Caller} here and read by
 * `ports.ts::callerCanUseProvider` inside `reliability.ts::dispatchWithFailover`.
 *
 * The marker that stood here proposed putting the gate in
 * `candidates.ts::routeExclusionReasons`, as a `provider_not_allowed` exclusion
 * code beside `region_not_allowed`. **That proposal was wrong and is recorded
 * here so it is not re-derived.** An EXCLUSION removes the route from the
 * eligible list and the ladder then falls through to the next candidate, so a
 * key allowed only `openai` calling a model whose primary is `anthropic` and
 * whose fallback is `openai` would be SERVED. Rust refuses it: `chat.rs:318`
 * (and the identical arms in `messages.rs:302`, `embeddings.rs:252`,
 * `images.rs:269`) checks the SELECTED candidate inside the `'routes:` loop and
 * answers `403 provider_not_allowed` with `return Ok(())` — no `continue`. The
 * gate therefore lives in the ladder, at the exact position and with the exact
 * terminality Rust gives it.
 *
 * `deniedProviders` is not forwarded, for the same reason `deniedModels` is not:
 * Rust carries `denied_providers` as its own `HashSet`, `AuthContext` in
 * `src/ports.ts` has no such field, and the row has no denylist COLUMN.
 * `callerCanUseProvider` implements the full deny-wins-then-allowlist predicate
 * and is tested on both legs, so the day the column lands this is one more line.
 */
export function callerFromAuth(auth: AuthContext): Caller {
  const projectId = auth.tenancy.projectId;
  const allowedModels = auth.allowedModels;
  const allowedProviders = auth.allowedProviders;
  return {
    // `callerScope` is the Rust `AuthContext::caller_scope`: platform-operator
    // ONLY when the credential declared it, and an unclassified credential is
    // confined to the empty-string tenant, which matches no route.
    scope: callerScope(auth),
    ...(auth.subject !== null ? { apiKeyId: auth.subject } : {}),
    ...(projectId !== null && projectId !== undefined ? { projectId } : {}),
    // Forwarded only when NON-EMPTY. `callerCanUseModel` already treats an empty
    // allowlist as unrestricted, so this is belt-and-braces in the fail-OPEN
    // direction on purpose: a credential source with no allowlist column must
    // never read as "this key may use nothing".
    ...(allowedModels !== undefined && allowedModels.length > 0 ? { allowedModels } : {}),
    // Same rule, same direction: an empty `allowed_providers` is "no allowlist"
    // in Rust (`allowed_providers.is_empty() || ...`), never "no provider".
    ...(allowedProviders !== undefined && allowedProviders.length > 0
      ? { allowedProviders }
      : {}),
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
