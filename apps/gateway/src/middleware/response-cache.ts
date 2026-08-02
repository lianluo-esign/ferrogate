/**
 * The AI response cache — exact-match, then semantic — as ingress middleware.
 *
 * Port of the cache seam inside Rust `server/chat.rs` (lookup at `:481`, store
 * at `:1976`), which is the only place `AiResponseCache` was ever consulted.
 *
 * ## Two layers, one seam
 *
 * Rust consulted the exact `AiResponseCache` and, `or_else`, the
 * `SemanticResponseCache` (#273) — both behind the SAME gate, so the semantic
 * layer inherits every opt-out rather than re-deriving any. This file
 * reproduces that shape exactly: one `identity` record builds both the exact
 * key and the semantic scope bucket (`cache/key.ts`), the semantic context is
 * built only when an exact key would be, and it is `null` outside
 * `mode = "semantic"` so the second layer is a strict no-op by default.
 *
 * ## Position, and why it is where it is
 *
 * `createGatewayApp` mounts this LAST in the middleware chain — after
 * `contractAuth`, after the caller-supplied `middleware` array (metering drain →
 * rate limit → guardrails) and immediately before the routes. That is the same
 * position the Rust cache occupies inside the handler, and each neighbour
 * matters:
 *
 *  - **after auth**, because the key is built from the authenticated identity.
 *    A cache keyed on anything a client can assert is a cross-tenant leak.
 *  - **after rate limiting**, because Rust charges the RPM/quota windows in
 *    `finalize_auth`, before the cache is consulted. A hit is still a request:
 *    if it were free, the cache would become a rate-limit bypass.
 *  - **after request-stage guardrails**, because a cache hit must not let a
 *    prompt skip screening. Rust screens the request before reaching the cache
 *    seam and this chain does the same.
 *  - **before the route**, because the entire point is not to dispatch.
 *
 * A hit therefore SKIPS only the upstream call and the RESPONSE-stage screening
 * — exactly what Rust's `return write_raw_response(...)` skips — and that is
 * safe only because the guardrail policy fingerprint is inside the key
 * (`cache/fingerprint.ts`, issue #233): tightening a redaction rule rotates
 * every key, so a body screened under the old rules can never be served under
 * the new ones.
 *
 * ## What is cacheable
 *
 * Rust: `if request.stream { None } else { ai_cache_enabled(...).then(...) }`,
 * and it stored only `if final_status.is_success()`. This adds four refusals
 * that Rust never needed because it had no shared, HTTP-shaped store:
 *
 *  1. `Cache-Control: no-store` / `no-cache` on the REQUEST — the caller
 *     explicitly opting out. Rust exposed opt-out through config only; this is
 *     strictly narrowing and it is what an HTTP client expects.
 *  2. `Cache-Control: no-store` / `private`, or a `Set-Cookie`, on the
 *     RESPONSE the gateway is about to emit. Note the scope precisely:
 *     `src/inference/handlers.ts` SYNTHESIZES its outgoing headers (it relays
 *     the upstream `content-type` and nothing else — `:983`, `:995`, `:1106`),
 *     so an upstream provider's `Cache-Control: private` does not reach this
 *     point through the inference path today. The rule governs the object
 *     actually being stored, and it covers any future handler that does relay
 *     upstream cache directives. `test/cache/middleware.test.ts` asserts it
 *     against a stub route module for exactly that reason, and states why.
 *  3. bodies over {@link MAX_CACHEABLE_BODY_BYTES} in either direction, so a
 *     single request cannot buffer an unbounded body into the isolate.
 *  4. anything whose response is `text/event-stream`, as a second line of
 *     defence behind the `stream: true` body check — a body that is a live
 *     stream must never be drained here.
 *
 * ## The `x-ferrogate-cache` header
 *
 * Rust recorded `cache_status: Some("hit") | Some("miss") | None` on the stored
 * request log (`chat.rs:1969`). There is no request-log table in this tree yet,
 * so the same three-valued fact is reported on the response instead:
 * `hit` / `miss`, and absent when the cache was not in play at all — which
 * matches Rust's `None` exactly. `bypass` is the one addition, emitted only
 * when a DECLARED cache configuration could not be used, so a misconfiguration
 * is visible to the operator who wrote it instead of looking like a cold cache.
 */
import type { Context, MiddlewareHandler } from "hono";
import {
  type ResponseCacheBindings,
  type ResponseCachePolicy,
  aiCacheEnabled,
  responseCachePolicyFromEnv,
} from "../cache/config.js";
import { guardrailPolicyFingerprint, modelRegistryFingerprint } from "../cache/fingerprint.js";
import {
  type CacheKeyInput,
  aiResponseCacheKey,
  canonicalJson,
  scopeDigest,
  semanticScopeHash,
} from "../cache/key.js";
import { recordCacheHit, recordCacheMiss, recordSemanticCacheHit } from "../cache/metrics.js";
import {
  type SemanticCacheContext,
  type SemanticResponseCache,
  embedText,
  promptTextForEmbedding,
  sharedSemanticCache,
} from "../cache/semantic.js";
import {
  CacheApiResponseStore,
  type CachedResponse,
  MemoryResponseCacheStore,
  type ResponseCacheStore,
} from "../cache/store.js";
import type { GatewayEnv } from "../ports.js";

/** Response header carrying Rust's `cache_status`. */
export const CACHE_STATUS_HEADER = "x-ferrogate-cache";

/** Rust `GATEWAY_CONFIG_HEADER` (`chat.rs:115`) — selects a config profile. */
export const GATEWAY_CONFIG_HEADER = "x-ferrogate-config";

/**
 * Neither a request nor a response larger than this is cached.
 *
 * 1 MiB is the Cache API's own comfortable range and, more importantly, the
 * point past which buffering the body to hash or store it stops being free.
 * A larger request is served normally — it is simply never keyed.
 */
export const MAX_CACHEABLE_BODY_BYTES = 1024 * 1024;

/**
 * The contract operations whose responses are cacheable.
 *
 * Exactly the AI endpoints Rust reached the cache seam from (`server/chat.rs`
 * serves all five; `listModels` is a `GET` projection of the registry and was
 * never cached). Named by `operation_id`, so a path change in the contract
 * cannot silently widen or narrow this set.
 *
 * `countMessageTokens` (issue #671) is not here: the cache exists to avoid
 * paying a provider twice for the same prompt, and counting never pays one. Its
 * answer is a few microseconds of local arithmetic, so a cache lookup — which
 * costs a body read, a hash and a Cache API round trip — would be slower than
 * the work it replaced.
 */
export const CACHEABLE_OPERATION_IDS: ReadonlySet<string> = new Set([
  "createChatCompletion",
  "createResponse",
  "createEmbedding",
  "createMessage",
  "createImage",
]);

export interface ResponseCacheOptions {
  /** Override the store. Production uses the Cache API. */
  readonly store?: ResponseCacheStore;
  /**
   * Override the SEMANTIC store. Production uses the isolate singleton, which
   * is the closest reachable form of Rust's process-global — see
   * `cache/semantic.ts` for the platform limit that makes it per-isolate.
   */
  readonly semanticStore?: SemanticResponseCache;
  /** Unix seconds, for the semantic layer's TTL. Overridden by tests. */
  readonly now?: () => number;
}

/** Decoded, bounded request body plus the fields the key needs. */
interface RequestFacts {
  readonly body: unknown;
  readonly logicalModel: string;
  readonly stream: boolean;
}

function readRequestFacts(raw: string): RequestFacts | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const body = parsed as Record<string, unknown>;
  const model = body.model;
  if (typeof model !== "string" || model.trim() === "") return null;
  return { body, logicalModel: model, stream: body.stream === true };
}

/** A request header that forbids serving OR storing a shared entry. */
function requestForbidsCache(headers: Headers): boolean {
  const control = headers.get("cache-control")?.toLowerCase() ?? "";
  return control.includes("no-store") || control.includes("no-cache");
}

/** A response the upstream marked unshareable. */
function responseForbidsCache(headers: Headers): boolean {
  if (headers.has("set-cookie")) return true;
  const control = headers.get("cache-control")?.toLowerCase() ?? "";
  return control.includes("no-store") || control.includes("private");
}

function isEventStream(headers: Headers): boolean {
  return (headers.get("content-type") ?? "").toLowerCase().includes("text/event-stream");
}

/** Serve a stored entry as the response, byte for byte. */
function respondFromCache(entry: CachedResponse): Response {
  return new Response(entry.body, {
    status: entry.statusCode,
    headers: {
      "content-type": entry.contentType,
      [CACHE_STATUS_HEADER]: "hit",
    },
  });
}

/**
 * The middleware. Inert — not merely disabled, but never even reading a body —
 * until `GATEWAY_CACHE_ENABLED` is `"true"`, which is Rust's
 * `CacheConfig::default().enabled == false`.
 */
export function responseCache(options: ResponseCacheOptions = {}): MiddlewareHandler<GatewayEnv> {
  const store =
    options.store ??
    (CacheApiResponseStore.isAvailable()
      ? new CacheApiResponseStore()
      : // No Cache API (a non-workerd host). An isolate-local store is a WEAKER
        // cache, never an incorrect one: the key is unchanged, so isolation
        // holds; only the hit rate falls.
        new MemoryResponseCacheStore());
  const semanticStore = options.semanticStore ?? sharedSemanticCache();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  return async function responseCacheMiddleware(c, next) {
    const env = (c.env ?? {}) as Record<string, unknown>;
    const policy = responseCachePolicyFromEnv(env as ResponseCacheBindings);

    if (policy.misconfiguration !== null) {
      // A DECLARED but unusable `[cache]` section. Serve normally — a broken
      // cache setting must not cost availability — but say so, or the operator
      // sees a cache that silently never fills. See `cache/config.ts`.
      await next();
      markCacheStatus(c, "bypass");
      return;
    }
    if (!policy.enabled) {
      await next();
      return;
    }

    const operation = c.get("operation");
    if (operation === null || !CACHEABLE_OPERATION_IDS.has(operation.operationId)) {
      await next();
      return;
    }
    if (requestForbidsCache(c.req.raw.headers)) {
      await next();
      return;
    }

    const auth = c.get("auth");
    if (auth === null) {
      // Unreachable in the mounted chain (`contractAuth` runs first and every
      // cacheable operation requires a credential), and fail-closed if the
      // chain is ever reordered: no identity, no shared entry.
      await next();
      return;
    }

    const raw = await readBoundedBody(c);
    if (raw === null) {
      await next();
      return;
    }
    const facts = readRequestFacts(raw);
    // Rust: `if request.stream { None }` — a streaming request is never keyed.
    if (facts === null || facts.stream) {
      await next();
      return;
    }

    const profileId = c.req.raw.headers.get(GATEWAY_CONFIG_HEADER)?.trim() || null;
    if (
      !aiCacheEnabled(policy, {
        apiKeyId: auth.subject,
        logicalModel: facts.logicalModel,
        profileId,
      })
    ) {
      await next();
      return;
    }

    // Fail CLOSED on an unreadable guardrail policy set: neither serve nor
    // store. See `cache/fingerprint.ts`.
    const guardrailFingerprint = await guardrailPolicyFingerprint(env);
    if (guardrailFingerprint === null) {
      await next();
      return;
    }

    const identity: CacheKeyInput = {
      route: operation.operationId,
      path: operation.path,
      tenantId: auth.tenancy.tenantId ?? null,
      workspaceId: auth.tenancy.workspaceId ?? null,
      projectId: auth.tenancy.projectId ?? null,
      userId: auth.tenancy.userId ?? null,
      apiKeyId: auth.subject,
      keySource: auth.source,
      platformOperator: auth.platformOperator,
      scopeDigest: scopeDigest(auth.scopes),
      logicalModel: facts.logicalModel,
      stream: false,
      requestBody: facts.body,
      guardrailPolicyFingerprint: guardrailFingerprint,
      registryFingerprint: await modelRegistryFingerprint(env),
    };
    const key = await aiResponseCacheKey(identity);

    // Rust `chat.rs:470`: the semantic context is built ONLY when an exact
    // `cache_key` exists, so it inherits the whole gating ladder above
    // (enabled + non-streaming + per-model/key/profile opt-outs + a readable
    // guardrail policy) instead of re-deriving any of it, and is `None` in
    // `exact_match` mode so the layer is a strict no-op there.
    const semantic: SemanticCacheContext | null =
      policy.mode === "semantic"
        ? {
            scope: await semanticScopeHash(identity),
            embedding: embedText(promptTextForEmbedding(facts.body, canonicalJson)),
          }
        : null;

    const hit = await store.get(key);
    if (hit !== undefined) {
      recordCacheHit();
      // Returning the Response short-circuits the chain WITHOUT calling
      // `next()`, so the route never runs and no upstream call is made — which
      // is the whole point, and is what `test/cache/middleware.test.ts` asserts
      // by counting intercepted provider requests rather than trusting a header.
      return respondFromCache(hit);
    }

    // Rust `state.lookup_ai_response_cache(key).or_else(|| semantic…)`: the
    // similarity layer sits BEHIND the exact one and is consulted only on an
    // exact miss — so a semantic hit can never be an exact hit relabelled.
    if (semantic !== null) {
      const similar = semanticStore.lookup(
        semantic.scope,
        semantic.embedding,
        policy.semanticSimilarityThreshold,
        now(),
      );
      if (similar !== undefined) {
        // Rust records BOTH: `record_semantic_cache_hit` inside the lookup, and
        // `record_ai_cache_hit` at the shared hit site (`chat.rs:485`).
        recordSemanticCacheHit();
        recordCacheHit();
        return respondFromCache(similar.response);
      }
    }
    recordCacheMiss();

    await next();

    const stored = await cacheableEntry(c.res);
    if (stored !== undefined) {
      await storeInBackground(c, store.put(key, stored, policy.ttlSeconds));
      // Rust `chat.rs:1986` — "Mirror the store into the semantic layer so a
      // later paraphrase can match this embedding." Same TTL and same
      // `max_records` as the exact store, and behind the same success check
      // (`cacheableEntry` is `undefined` for a non-2xx).
      if (semantic !== null) {
        semanticStore.insert(
          semantic.scope,
          semantic.embedding,
          stored,
          policy.ttlSeconds,
          policy.maxRecords,
          now(),
        );
      }
    }
    markCacheStatus(c, "miss");
    return;
  };
}

/**
 * Stamp `x-ferrogate-cache` on the outgoing response.
 *
 * A `Response` that came back from a `fetch()` has an IMMUTABLE header guard in
 * workerd, and `headers.set` on one throws. A cache-status label must never be
 * able to fail a request that already succeeded, so the throw is caught and the
 * response is rebuilt with mutable headers instead.
 */
function markCacheStatus(c: Context<GatewayEnv>, status: "miss" | "bypass"): void {
  try {
    c.res.headers.set(CACHE_STATUS_HEADER, status);
  } catch {
    const rebuilt = new Response(c.res.body, {
      status: c.res.status,
      statusText: c.res.statusText,
      headers: new Headers(c.res.headers),
    });
    rebuilt.headers.set(CACHE_STATUS_HEADER, status);
    c.res = rebuilt;
  }
}

/**
 * The request body, or `null` when it must not be keyed.
 *
 * `c.req.raw.clone()` is mandatory: `inferenceRouteModule` forwards
 * `c.req.raw` into a nested `fetch`, so consuming the original stream here
 * would leave the handler with an empty body. Cloning tees it instead.
 */
async function readBoundedBody(c: Context<GatewayEnv>): Promise<string | null> {
  // Only a JSON body is ever decoded. All five cacheable operations take JSON,
  // so this excludes nothing real — it stops the middleware from reading bytes
  // it could not key on anyway, and keeps binary payloads out of `text()`.
  const contentType = (c.req.raw.headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.includes("json")) return null;
  const declared = Number(c.req.raw.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_CACHEABLE_BODY_BYTES) return null;
  if (c.req.raw.body === null) return null;
  try {
    const text = await c.req.raw.clone().text();
    return text.length > MAX_CACHEABLE_BODY_BYTES ? null : text;
  } catch {
    return null;
  }
}

/**
 * Reduce a response to an entry, or `undefined` when it must not be stored.
 *
 * Rust stored only on `final_status.is_success()`; the rest of the refusals are
 * the shared-store rules listed in the header.
 */
async function cacheableEntry(response: Response): Promise<CachedResponse | undefined> {
  if (response.status < 200 || response.status >= 300) return undefined;
  if (isEventStream(response.headers)) return undefined;
  if (responseForbidsCache(response.headers)) return undefined;
  const declared = Number(response.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_CACHEABLE_BODY_BYTES) return undefined;
  if (response.body === null) return undefined;

  let body: Uint8Array;
  try {
    body = new Uint8Array(await response.clone().arrayBuffer());
  } catch {
    return undefined;
  }
  if (body.byteLength > MAX_CACHEABLE_BODY_BYTES) return undefined;

  return {
    statusCode: response.status,
    contentType: response.headers.get("content-type") ?? "application/json",
    body,
  };
}

/**
 * Hand the write to `ctx.waitUntil` so the caller is not billed the latency of
 * populating a cache they already paid the upstream for.
 *
 * `c.executionCtx` THROWS when there is no execution context (Hono's
 * `app.request(...)` in a unit test), which is why this is guarded rather than
 * called directly — and why it falls back to awaiting: a test must still see
 * the entry land, or the store would be untested.
 */
async function storeInBackground(c: Context<GatewayEnv>, write: Promise<void>): Promise<void> {
  try {
    c.executionCtx.waitUntil(write);
  } catch {
    await write;
  }
}
