/**
 * Async primitives for bounded detector execution: a counting semaphore
 * (bulkhead) and deadline/timeout helpers. These stand in for Rust's
 * `tokio::sync::Semaphore` and `tokio::time::timeout`; deadlines are epoch-millis
 * numbers (the TS twin of `Instant`).
 */

/** Sleep for `ms` milliseconds. */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

/** Sentinel returned by {@link withTimeout} when the deadline fires first. */
export const TIMED_OUT = Symbol("timed_out");

/**
 * Race `promise` against a `ms`-millisecond timer. Resolves to the value, or
 * {@link TIMED_OUT} if the timer wins. The timer is always cleared.
 */
export async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | typeof TIMED_OUT> {
  let handle: ReturnType<typeof setTimeout> | undefined;
  const timer = new Promise<typeof TIMED_OUT>((resolve) => {
    handle = setTimeout(() => resolve(TIMED_OUT), Math.max(0, ms));
  });
  try {
    return await Promise.race([promise, timer]);
  } finally {
    if (handle !== undefined) {
      clearTimeout(handle);
    }
  }
}

/** A FIFO counting semaphore bounded to `permits`. */
export class Semaphore {
  private available: number;
  private readonly max: number;
  private waiters: Array<() => void> = [];

  constructor(permits: number) {
    this.available = permits;
    this.max = permits;
  }

  /** Permits currently free (Rust `available_permits`). */
  availablePermits(): number {
    return this.available;
  }

  /** In-flight count = max − available. */
  inFlight(): number {
    return this.max - this.available;
  }

  /**
   * Acquire one permit, waiting up to `timeoutMs`. Resolves to a release fn, or
   * `undefined` if the wait exceeded the timeout.
   */
  async acquire(timeoutMs: number): Promise<(() => void) | undefined> {
    if (this.available > 0) {
      this.available -= 1;
      return this.makeRelease();
    }
    let resolveWaiter!: () => void;
    const waiter = new Promise<void>((resolve) => {
      resolveWaiter = resolve;
    });
    this.waiters.push(resolveWaiter);
    const outcome = await withTimeout(waiter, timeoutMs);
    if (outcome === TIMED_OUT) {
      // Remove our waiter if it is still queued; if it was already signalled,
      // hand the permit straight back so it is not leaked.
      const index = this.waiters.indexOf(resolveWaiter);
      if (index >= 0) {
        this.waiters.splice(index, 1);
      } else {
        this.release();
      }
      return undefined;
    }
    return this.makeRelease();
  }

  private makeRelease(): () => void {
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      this.release();
    };
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
    } else {
      this.available = Math.min(this.max, this.available + 1);
    }
  }
}
