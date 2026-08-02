/**
 * The pure RPM counter primitive — no Durable Object, no I/O, no clock.
 *
 * Clean-room port of Rust's `ApiKeyRequestWindow`
 * (`crates/ferrogate-gateway/src/state.rs`), the fixed 60-second window
 * `ClusterCounterBackend::Local` kept in `Mutex<HashMap>` process memory.
 *
 * `now` is an ARGUMENT, exactly as Rust's `try_consume(limit, now_unix_seconds)`
 * took it, which is what makes rollover testable without sleeping.
 *
 * ## Why this file exists rather than an import
 *
 * `apps/gateway/src/ratelimit/window.ts` holds the identical arithmetic and is
 * the reference this was written against. It is NOT imported: a
 * `../../gateway/src/...` specifier would make this Worker's module graph
 * depend on another app's, and the two apps are separately bundled and
 * separately deployed. The MERGE and the counter-key derivation are a different
 * matter — those are security-critical and genuinely shared, so they are
 * imported from `@ferrogate/policy` (see `./keys.ts`) rather than re-written.
 *
 * TPM has deliberately no counterpart here. Rust charges TPM inside the AI
 * handlers (`server/chat.rs` and friends), after a token estimate exists; this
 * Worker serves no inference operation and therefore never produces one.
 */

/** The Rust window length. `ApiKeyRequestWindow` uses 60. */
export const WINDOW_SECONDS = 60;

/** Rust u64 saturating arithmetic, in a language with one number type. */
function saturatingSub(a: number, b: number): number {
  return Math.max(0, a - b);
}

/** Serializable state of a fixed window (what a Durable Object would persist). */
export interface WindowState {
  /** Unix seconds the current window opened at. `0` = never opened. */
  windowStartedAt: number;
  /** Requests charged to the current window. */
  used: number;
}

/** A fresh, never-opened window — Rust `#[derive(Default)]`. */
export function emptyWindow(): WindowState {
  return { windowStartedAt: 0, used: 0 };
}

/**
 * Roll the window over when `now` is a full {@link WINDOW_SECONDS} past its
 * start, mirroring Rust exactly:
 *
 * ```rust
 * if now_unix_seconds.saturating_sub(state.window_started_at) >= 60 {
 *     state.window_started_at = now_unix_seconds;
 *     state.count = 0;
 * }
 * ```
 *
 * A FIXED window anchored at first use, not a minute-aligned or sliding one.
 * The classic fixed-window burst (up to `2 * limit` across a boundary) is
 * inherited from Rust deliberately: changing it here would be a silent
 * behaviour change, not a port.
 */
function rollOver(state: WindowState, now: number): void {
  if (saturatingSub(now, state.windowStartedAt) >= WINDOW_SECONDS) {
    state.windowStartedAt = now;
    state.used = 0;
  }
}

/** Whole seconds until the current window expires; `0` when it already has. */
export function secondsUntilWindowReset(state: WindowState, now: number): number {
  return saturatingSub(WINDOW_SECONDS, saturatingSub(now, state.windowStartedAt));
}

/**
 * Requests-per-minute window. Rust `ApiKeyRequestWindow`.
 *
 * `limit === 0` rejects every request (`used >= 0` is immediately true), which
 * is the Rust behaviour and the reason a zero RPM policy is a hard stop rather
 * than "unlimited". Every `??`/`||` fallback in the chain above is written as an
 * explicit `undefined` check for exactly this reason.
 */
export class RequestWindow {
  constructor(readonly state: WindowState = emptyWindow()) {}

  /** Rust `try_consume(limit, now) -> bool`. Charges 1 on success. */
  tryConsume(limit: number, now: number): boolean {
    rollOver(this.state, now);
    // Rust: `if state.count >= limit { return false }`.
    if (this.state.used >= limit) return false;
    this.state.used += 1;
    return true;
  }
}
