/**
 * The reliability layer between "resolve a model" and "call the provider" —
 * circuit breaker, same-provider retry, and the failover ladder.
 *
 * Clean-room port of the Rust triple that `docs/rewrite/parity-audit-request-path.md`
 * records as F3/F4:
 *
 * | this module                     | Rust                                                     |
 * |---------------------------------|----------------------------------------------------------|
 * | {@link ProviderCircuitState}    | `ProviderCircuitBreaker` (`state.rs:5540`)               |
 * | {@link ProviderCircuit}         | `provider_circuit_allows` / `record_provider_{success,failure}` (`state_routing.rs:686-719`) |
 * | {@link attemptDecision}         | `ProviderAttemptDecision::{from_retryable_status,from_dispatch_error}` (`chat.rs:3163-3187`) |
 * | {@link dispatchWithFailover}    | the `'routes:` loop (`chat.rs:259-314`)                  |
 * | {@link isRetryableUpstreamStatus} | `AppState::is_provider_status_retryable`               |
 *
 * ## The retry predicate is IMPORTED, not re-implemented
 *
 * `isRetryableStatus` is a `ProviderAdapter` trait method: each family may
 * override it, so "which status is retryable" is a PROVIDER decision, not a
 * gateway constant. `@ferrogate/providers` already implements it on
 * `BaseProviderAdapter` and exposes it per-kind on `ProviderAdapterRegistry`,
 * and until this module landed it was called from nowhere in `apps/gateway`.
 * {@link isRetryableUpstreamStatus} delegates to that class — writing
 * `status === 429 || status >= 500` here would be the second implementation the
 * porting rules forbid, and it would silently stop tracking a family that
 * overrides the default.
 *
 * ## Streaming: where the point of no return is
 *
 * Every decision this module makes is taken on the upstream RESPONSE STATUS,
 * before a single body byte has been read or relayed. That is deliberate and it
 * is the only place a retry can live on a streaming request: once
 * `handlers.ts::streamResponse` has handed the client a `Response` whose body is
 * piped from the upstream, the bytes are gone and no second attempt can produce
 * a coherent stream. So:
 *
 *  - an upstream that answers `503` with SSE headers is retried/failed over,
 *    because nothing has been flushed yet;
 *  - an upstream that answers `200 text/event-stream` and then ERRORS mid-body
 *    is NOT retried. The pipe faults, the client's stream errors, and the caller
 *    sees a broken connection rather than a silently truncated (and therefore
 *    silently WRONG) completion. `test/inference/reliability.test.ts` pins that
 *    exactly-one-attempt property; re-introducing a mid-stream retry would have
 *    to delete it.
 *
 * ## Where the state lives
 *
 * The Rust breaker is an `Arc<HashMap<String, ProviderCircuitBreaker>>` — one
 * process, one map, therefore one truth. A Worker has no equivalent, so
 * {@link InMemoryProviderCircuit} is per-ISOLATE: N isolates observe N
 * independent failure counters and a threshold of 5 becomes 5·N before any of
 * them opens. The cross-isolate answer is `./circuit-do.ts`
 * ({@link ProviderCircuitDurableObject}), selected automatically by
 * `defaults.ts::providerCircuitFor` when the `PROVIDER_CIRCUIT` binding exists.
 * See the WIRING block in `./circuit-do.ts` for the three lines the integrate
 * step must add.
 */
import { ProviderAdapterRegistry } from "@ferrogate/providers";
import { z } from "zod";
import { reject } from "./errors.js";
import type { InferenceRejection } from "./errors.js";
import type { PhysicalRoute, UpstreamRequest } from "./ports.js";

/**
 * The one registry instance the retry predicate consults.
 *
 * Module scope is correct: the class holds eight stateless adapter singletons
 * and nothing per-request, exactly as the Rust `ProviderAdapterRegistry` is a
 * process-lifetime value on `AppState`.
 */
const RETRY_PREDICATE_REGISTRY = new ProviderAdapterRegistry();

/**
 * `AppState::is_provider_status_retryable` — delegated to the provider family.
 *
 * `ProviderAdapterRegistry.adapterFor` THROWS `AdapterError.unsupportedProviderKind`
 * for a kind it does not know. Rust wraps the same call in
 * `.unwrap_or(false)`, i.e. an unknown family is NOT retryable, and that is the
 * fail-closed answer here too: retrying a request whose provider family cannot
 * even be identified would double-charge an upstream for no reason. (In
 * practice the kind is always known by the time this runs — `planUpstream`
 * already answered `502 provider_adapter_error` otherwise.)
 */
export function isRetryableUpstreamStatus(providerKind: string, status: number): boolean {
  try {
    return RETRY_PREDICATE_REGISTRY.isRetryableStatus(providerKind, status);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * The Rust `[reliability]` block, as far as the inference path reads it.
 *
 * Defaults reproduce the Rust ones EXACTLY, and both of them are "off":
 * `provider_dispatch_max_retries` is `Option<u32>` read through
 * `unwrap_or_default()` (`state_routing.rs:657`) so it defaults to **0**, and
 * the circuit breaker config is `Option<ProviderCircuitConfig>` built with `?`
 * over BOTH `provider_circuit_breaker_failure_threshold` and `_cooldown_secs`
 * (`state.rs:6777`), so an operator who sets neither gets **no breaker at all**
 * (`provider_circuit_allows` then returns `true` unconditionally).
 *
 * Keeping that faithful is what makes this a wiring change rather than a
 * behavior change: with no `GATEWAY_RELIABILITY` var the main path dispatches
 * once, exactly as before. What the operator gains is that setting the var now
 * DOES something — see {@link reliabilityFromVar}, and the `wrangler.toml`
 * `[vars]` line in the WIRING block of `./circuit-do.ts`.
 */
export interface ReliabilitySettings {
  /**
   * `reliability.provider_circuit_breaker_failure_threshold`. Consecutive
   * failures before a provider's circuit opens. `0` disables the breaker.
   */
  readonly circuitFailureThreshold: number;
  /**
   * `reliability.provider_circuit_breaker_cooldown_secs`, in MILLISECONDS.
   * How long an open circuit stays open. `0` disables the breaker.
   */
  readonly circuitCooldownMs: number;
  /**
   * `reliability.provider_dispatch_max_retries`. Retries against the SAME
   * provider before falling through to the next candidate route. `0` = the
   * Rust default: no same-provider retry, straight to failover.
   */
  readonly maxDispatchRetries: number;
}

/** Rust's own defaults; see {@link ReliabilitySettings}. */
export const DEFAULT_RELIABILITY: ReliabilitySettings = {
  circuitFailureThreshold: 0,
  circuitCooldownMs: 0,
  maxDispatchRetries: 0,
};

/** The `GATEWAY_RELIABILITY` var — the JSON form of the Rust `[reliability]` block. */
const reliabilityVarSchema = z
  .object({
    provider_circuit_breaker_failure_threshold: z.number().int().positive().optional(),
    provider_circuit_breaker_cooldown_secs: z.number().int().positive().optional(),
    provider_dispatch_max_retries: z.number().int().min(0).optional(),
  })
  .strict();

/**
 * Read `[reliability]` out of the Worker vars.
 *
 * Fail-closed on a malformed var, in the same shape `catalog.ts` uses for the
 * model tables: a var that does not parse yields the DEFAULTS (breaker off, no
 * retries), never a partially-applied config. `.strict()` and the
 * `positive()`/`min(0)` bounds reproduce the Rust validator, which refuses a
 * zero threshold or cooldown outright (`validate.rs:1188-1191`) — so a
 * fat-fingered `0` disables the breaker loudly (a logged refusal) rather than
 * opening every circuit on the first failure.
 */
export function reliabilityFromVar(raw: unknown): ReliabilitySettings {
  if (typeof raw !== "string" || raw.trim() === "") {
    return DEFAULT_RELIABILITY;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.warn(`[ferrogate] GATEWAY_RELIABILITY is not valid JSON: ${detail}`);
    return DEFAULT_RELIABILITY;
  }
  const result = reliabilityVarSchema.safeParse(parsed);
  if (!result.success) {
    console.warn(
      `[ferrogate] GATEWAY_RELIABILITY is invalid: ${result.error.issues
        .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
        .join("; ")}`,
    );
    return DEFAULT_RELIABILITY;
  }
  const cooldownSecs = result.data.provider_circuit_breaker_cooldown_secs;
  return {
    circuitFailureThreshold: result.data.provider_circuit_breaker_failure_threshold ?? 0,
    circuitCooldownMs: cooldownSecs === undefined ? 0 : cooldownSecs * 1000,
    maxDispatchRetries: result.data.provider_dispatch_max_retries ?? 0,
  };
}

/**
 * `ProviderCircuitConfig` — `None` unless BOTH halves are configured.
 *
 * The Rust builder is `Some(ProviderCircuitConfig { failure_threshold: config
 * .provider_circuit_breaker_failure_threshold?, cooldown: Duration::from_secs(
 * config.provider_circuit_breaker_cooldown_secs?) })`: the `?` on each field
 * means one without the other yields `None`, and the config validator refuses a
 * zero for either (`validate.rs:1188`). Both rules are reproduced here.
 */
export function circuitEnabled(settings: ReliabilitySettings): boolean {
  return settings.circuitFailureThreshold > 0 && settings.circuitCooldownMs > 0;
}

// ---------------------------------------------------------------------------
// The breaker state machine
// ---------------------------------------------------------------------------

/** `ProviderCircuitSnapshot` — the serializable half, so a DO can persist it. */
export interface ProviderCircuitSnapshot {
  readonly consecutiveFailures: number;
  /** Unix milliseconds the circuit opened at; `null` while it is closed. */
  readonly openedAtMs: number | null;
}

/** A freshly-closed circuit. */
export function closedCircuit(): ProviderCircuitSnapshot {
  return { consecutiveFailures: 0, openedAtMs: null };
}

/**
 * `ProviderCircuitBreaker`, minus the `Mutex` (JS is single-threaded, so the
 * lock — and its poison-recovery arm — collapses to plain field access).
 *
 * This class is the executable specification of the Rust semantics and is
 * shared by BOTH circuit implementations, exactly as `ratelimit/window.ts`'s
 * `RequestWindow` is shared by `InMemoryRateLimiter` and
 * `RateLimiterDurableObject`. There is one arithmetic, in one place.
 */
export class ProviderCircuitState {
  #consecutiveFailures: number;
  #openedAtMs: number | null;

  constructor(snapshot: ProviderCircuitSnapshot = closedCircuit()) {
    this.#consecutiveFailures = snapshot.consecutiveFailures;
    this.#openedAtMs = snapshot.openedAtMs;
  }

  get snapshot(): ProviderCircuitSnapshot {
    return {
      consecutiveFailures: this.#consecutiveFailures,
      openedAtMs: this.#openedAtMs,
    };
  }

  /**
   * `allows_request` — closed circuits always allow; an open one allows again
   * once `elapsed >= cooldown`.
   *
   * The comparison is `>=`, matching Rust, and the circuit is NOT reset here:
   * Rust leaves `opened_at` set until a success clears it, so the very next
   * failure after the cooldown re-opens it immediately (the "half-open" probe
   * is implicit — one request gets through, and only its SUCCESS closes the
   * circuit). Resetting on the read would give a fully-failed provider a whole
   * fresh threshold's worth of traffic after every cooldown.
   */
  allowsRequest(cooldownMs: number, nowMs: number): boolean {
    if (this.#openedAtMs === null) {
      return true;
    }
    return nowMs - this.#openedAtMs >= cooldownMs;
  }

  /** `record_success` — clears the streak AND the open state. */
  recordSuccess(): void {
    this.#consecutiveFailures = 0;
    this.#openedAtMs = null;
  }

  /** `record_failure` — increments, and opens once the streak reaches the threshold. */
  recordFailure(failureThreshold: number, nowMs: number): void {
    this.#consecutiveFailures += 1;
    if (this.#consecutiveFailures >= failureThreshold) {
      this.#openedAtMs = nowMs;
    }
  }
}

/**
 * The breaker as the dispatch ladder consumes it.
 *
 * Every method is `async` because the production implementation is a Durable
 * Object round trip (`./circuit-do.ts`). The in-memory one resolves
 * immediately; keeping ONE signature is what lets the two be swapped at the
 * composition root without `handlers.ts` changing.
 */
export interface ProviderCircuit {
  /** `provider_circuit_allows` — may this provider be dispatched to? */
  allows(provider: string): Promise<boolean>;
  /** `record_provider_success`. */
  recordSuccess(provider: string): Promise<void>;
  /** `record_provider_failure`. */
  recordFailure(provider: string): Promise<void>;
}

/**
 * The breaker an operator has not configured: allows everything, remembers
 * nothing.
 *
 * This is `provider_circuit_config == None` in Rust, where `provider_circuit_allows`
 * returns `true` before touching the map and both recorders return early. It is
 * NOT a null-object convenience — it is the shipped default, so the wired
 * ladder is byte-identical to the pre-wiring single dispatch until the operator
 * turns the breaker on.
 */
export const NO_PROVIDER_CIRCUIT: ProviderCircuit = {
  async allows(): Promise<boolean> {
    return true;
  },
  async recordSuccess(): Promise<void> {
    /* no breaker configured */
  },
  async recordFailure(): Promise<void> {
    /* no breaker configured */
  },
};

/**
 * Per-ISOLATE {@link ProviderCircuit}.
 *
 * PORT-TODO(L: inventory-request-path §1.7 "reliability", F3): PARTIAL —
 * approximation, and the direction of the error is the safe one but it is still
 * an error. A Worker is replicated across isolates with no shared mutable
 * state, so each isolate keeps its own failure streak: with a threshold of `N`
 * and `K` live isolates a wedged provider absorbs up to `N·K` failures before
 * every isolate has opened, and each isolate re-probes on its own cooldown.
 * Traffic is still SHED (that is why this is shipped rather than refused), just
 * later and less sharply than the Rust single-process breaker sheds it.
 *
 * The exact port is {@link ProviderCircuitDurableObject} in `./circuit-do.ts`,
 * which this class is deliberately API-identical to; `providerCircuitFor` picks
 * the DO whenever the `PROVIDER_CIRCUIT` binding is present and falls back here
 * when it is not. Do NOT "fix" this by widening the Map's lifetime — there is
 * no wider lifetime on the platform than the isolate.
 *
 * **This arm is NOT the deployed one.** `apps/gateway/wrangler.toml:768-773`
 * binds `PROVIDER_CIRCUIT` (migration `v2`, `new_sqlite_classes`) and
 * `src/worker.ts:87` re-exports the class, so a configured breaker on the
 * deployed gateway is the Durable Object. This class is reached only by a
 * caller whose `env` lacks the binding — i.e. an operator who set
 * `GATEWAY_RELIABILITY` on a deployment without the DO. That combination is
 * why it is shipped rather than deleted: shedding late beats never shedding.
 * `test/inference/reliability-mount.test.ts` is the gate that keeps the two
 * arms distinguishable — it reads breaker state back out of the real namespace,
 * which a per-isolate `Map` cannot satisfy.
 */
export class InMemoryProviderCircuit implements ProviderCircuit {
  readonly #circuits = new Map<string, ProviderCircuitState>();
  readonly #settings: ReliabilitySettings;
  readonly #clock: () => number;

  constructor(settings: ReliabilitySettings, clock: () => number = () => Date.now()) {
    this.#settings = settings;
    this.#clock = clock;
  }

  #circuit(provider: string): ProviderCircuitState {
    const existing = this.#circuits.get(provider);
    if (existing !== undefined) {
      return existing;
    }
    const created = new ProviderCircuitState();
    this.#circuits.set(provider, created);
    return created;
  }

  async allows(provider: string): Promise<boolean> {
    return this.#circuit(provider).allowsRequest(this.#settings.circuitCooldownMs, this.#clock());
  }

  async recordSuccess(provider: string): Promise<void> {
    this.#circuit(provider).recordSuccess();
  }

  async recordFailure(provider: string): Promise<void> {
    this.#circuit(provider).recordFailure(
      this.#settings.circuitFailureThreshold,
      this.#clock(),
    );
  }

  /** Inspection seam for the tests; never read by the request path. */
  snapshot(provider: string): ProviderCircuitSnapshot {
    return this.#circuit(provider).snapshot;
  }
}

// ---------------------------------------------------------------------------
// The attempt ladder
// ---------------------------------------------------------------------------

/** `ProviderAttemptDecision`. */
export type ProviderAttemptDecision = "retry_provider" | "try_fallback_route" | "return_error";

/**
 * `ProviderAttemptDecision::from_retryable_status` and `::from_dispatch_error`,
 * which differ in exactly one way: a dispatch (transport) error is ALWAYS
 * treated as retryable, whereas a response only is when the provider family
 * says its status is. Passing `retryable = true` for the transport case
 * collapses them into one function without changing either.
 */
export function attemptDecision(
  retryable: boolean,
  attempt: number,
  maxDispatchRetries: number,
  hasNextCandidate: boolean,
): ProviderAttemptDecision {
  if (retryable && attempt < maxDispatchRetries) {
    return "retry_provider";
  }
  if (retryable && hasNextCandidate) {
    return "try_fallback_route";
  }
  return "return_error";
}

/** One candidate route with its already-prepared upstream request. */
export interface AttemptCandidate {
  readonly route: PhysicalRoute;
  readonly upstream: UpstreamRequest;
}

/** What one attempt produced: a provider response, or a transport rejection. */
export type AttemptResult = Response | InferenceRejection;

/** The ladder's answer. */
export type FailoverOutcome =
  | {
      readonly ok: true;
      /** The response to serve — success, OR a client-visible provider error. */
      readonly response: Response;
      readonly candidate: AttemptCandidate;
      /** 0-based index of the candidate that produced it. */
      readonly candidateIndex: number;
      /** Total upstream attempts made across every candidate. */
      readonly attempts: number;
    }
  | {
      readonly ok: false;
      readonly rejection: InferenceRejection;
      readonly attempts: number;
    };

/** Everything {@link dispatchWithFailover} needs that it does not own. */
export interface FailoverOptions {
  readonly candidates: readonly AttemptCandidate[];
  readonly circuit: ProviderCircuit;
  readonly settings: ReliabilitySettings;
  /**
   * `AuthContext::can_use_provider` for the candidate's provider.
   *
   * REQUIRED, deliberately. An optional predicate defaulting to "allow" is the
   * `real ?? fallback` shape this repo keeps getting bitten by: every ladder
   * test would pass with the gate unwired, because the fallback and a
   * permissive credential are indistinguishable from the outside. Making it
   * mandatory turns a missing wiring into a TypeScript error at the one call
   * site that matters (`handlers.ts::dispatchCandidates`).
   */
  providerAllowed(provider: string): boolean;
  /** Perform ONE upstream attempt. Supplied by `handlers.ts::dispatchUpstream`. */
  attempt(candidate: AttemptCandidate): Promise<AttemptResult>;
  /** Discriminates the transport-rejection arm of {@link AttemptResult}. */
  isRejection(value: AttemptResult): value is InferenceRejection;
}

/**
 * Release an upstream response we have decided not to serve.
 *
 * A `Response` whose body is never read holds the upstream connection open in
 * workerd. Every abandoned attempt (a retried 503, a failed-over 500) MUST be
 * cancelled or the ladder leaks one socket per retry — the exact resource bug a
 * naive retry loop ships with. Failures are swallowed: the body may already be
 * errored, and that is not this request's problem.
 */
function discard(response: Response): void {
  try {
    void response.body?.cancel();
  } catch {
    /* already errored or locked */
  }
}

/**
 * The Rust `'routes:` loop (`chat.rs:259`), ported whole.
 *
 * Order of operations per candidate, and every step of it is load-bearing:
 *
 *  1. **Circuit first.** `chat.rs:283` consults `provider_circuit_allows` BEFORE
 *     anything else touches the provider, so an open circuit costs no socket. An
 *     open circuit with a next candidate SKIPS; an open circuit on the LAST
 *     candidate is `503 provider_circuit_open`, never a 502 — the operator has
 *     to be able to tell "we refused to try" from "we tried and it failed".
 *  2. **The per-key provider allowlist, SECOND and TERMINAL.** `chat.rs:318`
 *     (identically `messages.rs:302`, `embeddings.rs:252`, `images.rs:269`)
 *     runs `auth.can_use_provider(&provider.name)` immediately after the
 *     circuit check and answers `403 provider_not_allowed` with `return Ok(())`
 *     — there is no `continue`, so a key that may not use the FIRST eligible
 *     provider is refused even when a later fallback route names a provider it
 *     may use. Both halves of that are observable and both are reproduced:
 *       - the ORDER (circuit first) means a disallowed provider whose circuit is
 *         OPEN, with a next candidate, skips to that candidate rather than
 *         403ing — so the request can still succeed;
 *       - the TERMINALITY means the same disallowed provider with a CLOSED
 *         circuit ends the request at 403 even though that next candidate
 *         exists.
 *     Modelling this as a route EXCLUSION in `candidates.ts` instead (which is
 *     what the marker on `identity.ts::callerFromAuth` used to propose) would
 *     silently SERVE the second case. That is why the gate is here.
 *  3. **Attempt.** A transport failure records a provider failure and enters the
 *     ladder with `retryable = true`.
 *  4. **Retryable status.** Recorded as a failure *only when retryable* — Rust
 *     guards `record_provider_failure` with `if retryable_status`
 *     (`chat.rs:927`), so a provider answering `400` to a malformed request
 *     never counts toward opening its circuit. That asymmetry is the whole
 *     reason the breaker does not trip on client errors.
 *  5. **Success** records a success, which clears the streak (`chat.rs:992`).
 *
 * A non-retryable error response is returned as `ok: true`: it is the
 * provider's own answer and the handler relays it verbatim, exactly as the Rust
 * `ReturnError` arm falls through to `write_json_response`.
 */
export async function dispatchWithFailover(
  options: FailoverOptions,
): Promise<FailoverOutcome> {
  const { candidates, circuit, settings, providerAllowed, attempt, isRejection } = options;
  let attempts = 0;
  let lastRejection: InferenceRejection | null = null;

  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index] as AttemptCandidate;
    const hasNext = index + 1 < candidates.length;
    const provider = candidate.route.provider;

    if (!(await circuit.allows(provider))) {
      if (hasNext) {
        continue;
      }
      return {
        ok: false,
        rejection: reject(
          503,
          "provider_circuit_open",
          `provider ${provider} circuit breaker is open`,
        ),
        attempts,
      };
    }

    // `if !auth.can_use_provider(&provider.name) { ...403...; return Ok(()) }`.
    // No `hasNext` arm on purpose — see step 2 of the doc block above. The
    // message is the Rust string verbatim so an existing client's error
    // matching keeps working.
    if (!providerAllowed(provider)) {
      return {
        ok: false,
        rejection: reject(
          403,
          "provider_not_allowed",
          `API key is not allowed to use provider ${provider}`,
        ),
        attempts,
      };
    }

    let fellThrough = false;
    for (let tries = 0; !fellThrough; tries += 1) {
      attempts += 1;
      const result = await attempt(candidate);

      if (isRejection(result)) {
        await circuit.recordFailure(provider);
        lastRejection = result;
        // `from_dispatch_error`: a transport failure is unconditionally retryable.
        switch (attemptDecision(true, tries, settings.maxDispatchRetries, hasNext)) {
          case "retry_provider":
            continue;
          case "try_fallback_route":
            fellThrough = true;
            continue;
          case "return_error":
            return { ok: false, rejection: result, attempts };
        }
      }

      const retryable =
        !result.ok && isRetryableUpstreamStatus(candidate.route.providerKind, result.status);
      if (retryable) {
        // Guarded exactly as Rust guards it: only a RETRYABLE status counts
        // against the circuit.
        await circuit.recordFailure(provider);
      }

      switch (attemptDecision(retryable, tries, settings.maxDispatchRetries, hasNext)) {
        case "retry_provider":
          discard(result);
          continue;
        case "try_fallback_route":
          discard(result);
          fellThrough = true;
          continue;
        case "return_error":
          break;
      }

      if (result.ok) {
        await circuit.recordSuccess(provider);
      }
      return { ok: true, response: result, candidate, candidateIndex: index, attempts };
    }
  }

  // Every candidate's circuit was open, or the ladder ran out mid-fallback.
  return {
    ok: false,
    rejection:
      lastRejection ??
      reject(
        503,
        "provider_circuit_open",
        `no candidate route for model ${candidates[0]?.route.logicalModel ?? "(none)"} is available`,
      ),
    attempts,
  };
}
