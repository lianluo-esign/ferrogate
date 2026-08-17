/**
 * Per-request audit-append deferral, so a latency-critical handler can move the
 * evidence write OFF the synchronous response path onto `ctx.waitUntil`.
 *
 * Why this exists: a virtual-key mutation appends an audit-chain row to the
 * SINGLE control Durable Object (a SELECT-head then an INSERT). From a far
 * region that is ~2×180ms of serial I/O on the login critical path, and login
 * mints a gateway session key on EVERY call. The audit chain is per-tenant
 * (`chain_key = tenant_id`) and no consumer needs it durable before the response
 * returns — the KEY itself is written synchronously — so the append is deferred
 * to a background flush.
 *
 * Contract: OPT-IN and SCOPED. The store only defers while a sink is
 * {@link DeferredAuditSink.active}; a handler activates it around the exact
 * calls it wants deferred, then drains the collected work into `waitUntil`.
 * Every other endpoint (and every test without an execution context) leaves the
 * sink inactive and audits synchronously, byte-for-byte as before.
 */

/** What the store sees — collect a deferred audit-append thunk while active. */
export interface AuditSink {
  /** True only inside a handler-scoped defer window. */
  readonly active: boolean;
  /** Register audit work to run later. The thunk is NOT started until {@link DeferredAuditSink.drain}. */
  defer(work: () => Promise<void>): void;
}

/**
 * What a handler sees — the lifecycle controls the store deliberately does NOT
 * get. A handler opens a defer window with {@link activate}, performs the writes
 * it wants deferred, then {@link deactivate}s and {@link drain}s onto
 * `ctx.waitUntil`. Kept separate from {@link AuditSink} so the store cannot
 * accidentally flush or reconfigure the window it is only supposed to feed.
 */
export interface ManagedAuditSink extends AuditSink {
  activate(): void;
  deactivate(): void;
  drain(): Promise<void>;
}

export class DeferredAuditSink implements ManagedAuditSink {
  #active = false;
  readonly #pending: Array<() => Promise<void>> = [];

  get active(): boolean {
    return this.#active;
  }

  /** Begin deferring audit appends made through this sink. */
  activate(): void {
    this.#active = true;
  }

  /** Stop deferring; subsequent appends audit synchronously again. */
  deactivate(): void {
    this.#active = false;
  }

  defer(work: () => Promise<void>): void {
    this.#pending.push(work);
  }

  /** Whether anything is waiting to be flushed. */
  get pending(): boolean {
    return this.#pending.length > 0;
  }

  /**
   * Run every deferred append, SEQUENTIALLY, and clear the queue. Same-tenant
   * appends contend on the `UNIQUE (chain_key, seq)` index, so serial execution
   * avoids self-races (the `#audit` writer still retries as a backstop). Errors
   * are swallowed — `#audit` already warns-and-swallows, and a lost audit row
   * must never fail a response that has already been sent.
   */
  async drain(): Promise<void> {
    const pending = this.#pending.splice(0);
    for (const work of pending) {
      try {
        await work();
      } catch {
        // `#audit` already logged; nothing actionable on a settled response.
      }
    }
  }
}
