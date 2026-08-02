/**
 * Where a guardrail evaluation GOES, and the two rules that govern every branch
 * (#665):
 *
 *  1. **The screening path never awaits durable I/O.**
 *  2. **An evidence failure is never a request failure — but an evidence
 *     REFUSAL still fails the request closed.**
 *
 * Those two are in tension and the split between `append` and `flush` is how
 * they are resolved.
 *
 * ## Why `append` cannot write
 *
 * `GuardrailEvidenceSink.append` is called from inside `matchGuardrail`, i.e.
 * in front of the client's first byte, and its return value decides the request:
 * `false` becomes a 403 `guardrail_evidence_unavailable`
 * (`state_quota_and_policy.rs:644-646`). Doing a D1 write there would put a
 * cross-datacentre round trip on the latency-critical path of every screened
 * request, and would make a transient D1 blip refuse live traffic.
 *
 * So `append` BUFFERS, synchronously, and refuses only on CAPACITY — which is
 * the condition the Rust semaphore refused on too, and the one that really does
 * mean "this evaluation cannot be recorded". {@link DurableGuardrailEvidenceSink.flush}
 * then writes, from `ctx.waitUntil` in `./middleware.ts`, after the response
 * exists.
 *
 * ## Two destinations, one writer
 *
 * ```
 *   guardrails()                                  [middleware.ts]
 *     ├── engine.matchGuardrail → evidence.append(...)   ← buffers, no I/O
 *     └── ctx.waitUntil(evidence.flush({ env, ctx }))
 *            ├── env.REQUEST_LOG bound?  → Queue.send(wire)       ← preferred
 *            │      … later, on the consumer:
 *            │      queue(batch) → guardrailEvidenceFromWire → writeGuardrailEvidence
 *            └── else CONTROL_DB bound?  → writeGuardrailEvidence(CONTROL_DB)
 * ```
 *
 * Identical to `../requestlog/sink.ts` down to the binding names, and that is
 * the point: one queue, one consumer, one D1, one set of retry semantics.
 *
 * With NEITHER bound the sink counts a `dropped` and returns TRUE from
 * `append`. Refusing instead would take every screened request down on a
 * deployment that simply has not provisioned the evidence bindings — including
 * `wrangler dev --local` — which is a far worse failure than an unrecorded
 * evaluation. The drop is COUNTED rather than silent, because "no rows" and "no
 * writer" look identical from the admin API and that confusion is the whole
 * defect #665 exists to close.
 */
import { type GuardrailEvidenceDatabase, writeGuardrailEvidence } from "./evidence-d1.js";
import type { GuardrailEvidenceEnvelope } from "./evidence-wire.js";
import { guardrailEvidenceToWire } from "./evidence-wire.js";
import type { GuardrailCheckEvidence, GuardrailEvidence, GuardrailEvidenceSink } from "./ports.js";

/** `[[queues.producers]] binding = "REQUEST_LOG"`, structurally. */
export interface GuardrailEvidenceQueue {
  send(body: unknown, options?: unknown): Promise<void>;
  sendBatch(messages: Iterable<{ body: unknown }>, options?: unknown): Promise<void>;
}

/** What the sink has done since the isolate started. */
export interface GuardrailEvidenceStats {
  /** Evaluations handed to the Queue producer. */
  readonly queued: number;
  /** Evaluations written straight to D1 (no queue bound). */
  readonly written: number;
  /** Evaluations with nowhere to go — no queue AND no control database. */
  readonly dropped: number;
  /** Writes that were attempted and rejected. */
  readonly failed: number;
  /** Appends REFUSED for capacity, i.e. requests that failed closed. */
  readonly refused: number;
}

/** The bindings this slice reads, and nothing else. */
export interface GuardrailEvidenceBindings {
  readonly REQUEST_LOG?: unknown;
  /**
   * `[[d1_databases]] binding = "CONTROL_DB"` — the CONTROL database that owns
   * the evidence tables.
   *
   * NOT `DB`: that is the TENANT database, whose migration does not contain
   * these tables. Writing there would create nothing and read back nothing.
   */
  readonly CONTROL_DB?: unknown;
}

export interface GuardrailEvidenceDiagnostics {
  onError?(stage: "queue" | "d1", error: unknown): void;
}

export interface GuardrailEvidenceSinkOptions {
  readonly queue?: (env: unknown) => GuardrailEvidenceQueue | undefined;
  readonly database?: (env: unknown) => GuardrailEvidenceDatabase | undefined;
  readonly diagnostics?: GuardrailEvidenceDiagnostics | undefined;
  /**
   * How many un-flushed evaluations may be buffered before `append` refuses.
   *
   * The refusal is the fail-closed branch (`guardrail_evidence_unavailable`),
   * so this is a real availability knob and not a tuning detail: too small and
   * a burst refuses live traffic, too large and a Worker isolate holds evidence
   * it will never get to write. 1024 is the Rust semaphore's permit count.
   */
  readonly capacity?: number;
}

function isQueue(value: unknown): value is GuardrailEvidenceQueue {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<GuardrailEvidenceQueue>;
  return typeof candidate.send === "function" && typeof candidate.sendBatch === "function";
}

function isDatabase(value: unknown): value is GuardrailEvidenceDatabase {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<GuardrailEvidenceDatabase>;
  return typeof candidate.prepare === "function" && typeof candidate.batch === "function";
}

/**
 * `env.REQUEST_LOG`, when it really is a Queue producer binding.
 *
 * The SHAPE is checked rather than assumed because `env` is `unknown` here and
 * a plain var that happened to be called `REQUEST_LOG` would otherwise be
 * `send()`-ed — failing after the response was flushed, i.e. in the one place
 * nobody is watching.
 */
export function guardrailEvidenceQueueFrom(env: unknown): GuardrailEvidenceQueue | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as GuardrailEvidenceBindings).REQUEST_LOG;
  return isQueue(candidate) ? candidate : undefined;
}

/** `env.CONTROL_DB`, when it really is a D1 binding. */
export function guardrailEvidenceDatabaseFrom(env: unknown): GuardrailEvidenceDatabase | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as GuardrailEvidenceBindings).CONTROL_DB;
  return isDatabase(candidate) ? candidate : undefined;
}

/**
 * The production binding resolver.
 *
 * Resolved PER REQUEST from the `env` the request carries, never captured at
 * construction: workerd refuses I/O started on behalf of a different request,
 * so a module-scoped "current env" slot is a correctness bug that only appears
 * under concurrency. Same reasoning, same conclusion as
 * `../requestlog/sink.ts::requestLogBindingsFromEnv`.
 */
export const guardrailEvidenceBindingsFromEnv: Required<
  Pick<GuardrailEvidenceSinkOptions, "queue" | "database">
> = {
  queue: guardrailEvidenceQueueFrom,
  database: guardrailEvidenceDatabaseFrom,
};

export class DurableGuardrailEvidenceSink implements GuardrailEvidenceSink {
  readonly #queueOf: (env: unknown) => GuardrailEvidenceQueue | undefined;
  readonly #databaseOf: (env: unknown) => GuardrailEvidenceDatabase | undefined;
  readonly #diagnostics: GuardrailEvidenceDiagnostics | undefined;
  readonly #capacity: number;
  /**
   * Buffered by evidence id, so a re-`append` of the same
   * `(request, policy@revision, stage)` REPLACES rather than accumulates.
   *
   * That matters for streaming: `stream.ts` calls the engine once per SSE
   * frame, and a buffer that appended would send one message per frame and
   * exhaust `capacity` on a long response. A `Map` also preserves insertion
   * order, so the flush writes evaluations in the order they were decided.
   */
  readonly #pending = new Map<string, GuardrailEvidenceEnvelope>();
  #queued = 0;
  #written = 0;
  #dropped = 0;
  #failed = 0;
  #refused = 0;

  constructor(options: GuardrailEvidenceSinkOptions = {}) {
    this.#queueOf = options.queue ?? guardrailEvidenceQueueFrom;
    this.#databaseOf = options.database ?? guardrailEvidenceDatabaseFrom;
    this.#diagnostics = options.diagnostics;
    this.#capacity = options.capacity ?? 1024;
  }

  get stats(): GuardrailEvidenceStats {
    return {
      queued: this.#queued,
      written: this.#written,
      dropped: this.#dropped,
      failed: this.#failed,
      refused: this.#refused,
    };
  }

  /** How many evaluations are buffered and not yet handed to a destination. */
  get pending(): number {
    return this.#pending.size;
  }

  /**
   * Buffer one evaluation. SYNCHRONOUS, and the only thing that can make it
   * return `false` is capacity.
   *
   * `false` fails the request closed with `guardrail_evidence_unavailable`, so
   * this must not be reachable by a transient infrastructure fault — see the
   * module docblock for why "no binding configured" is a counted DROP rather
   * than a refusal.
   */
  append(evaluation: GuardrailEvidence, checks: readonly GuardrailCheckEvidence[]): boolean {
    if (!this.#pending.has(evaluation.id) && this.#pending.size >= this.#capacity) {
      this.#refused += 1;
      return false;
    }
    this.#pending.set(evaluation.id, { evaluation, checks });
    return true;
  }

  /**
   * Re-key buffered evidence onto the id the client was told — see
   * {@link GuardrailEvidenceSink.recorrelate} for WHY this exists.
   *
   * Every id in the evidence embeds the request id by construction
   * (`evidence.ts::evaluationId` is `${requestId}/${policy@rev}/${stage}`, and
   * a check's id is `${evaluationId}/${checkId}`), so the rewrite is a prefix
   * substitution rather than a field assignment. Doing it any other way would
   * leave a row whose `id` and whose `request_id` disagree, which is a worse
   * kind of unfindable than the one this fixes.
   *
   * A no-op once the buffer has been flushed, and a no-op for evidence
   * belonging to a different request: only entries whose `requestId` matches
   * `previousRequestId` move.
   */
  recorrelate(previousRequestId: string, requestId: string): void {
    if (previousRequestId === requestId || this.#pending.size === 0) return;
    const moved: [string, GuardrailEvidenceEnvelope][] = [];
    for (const [id, envelope] of this.#pending) {
      if (envelope.evaluation.requestId !== previousRequestId) continue;
      const rekey = (value: string): string =>
        value.startsWith(`${previousRequestId}/`)
          ? `${requestId}/${value.slice(previousRequestId.length + 1)}`
          : value;
      const evaluationId = rekey(envelope.evaluation.id);
      moved.push([
        id,
        {
          evaluation: { ...envelope.evaluation, id: evaluationId, requestId },
          checks: envelope.checks.map((check) => ({
            ...check,
            id: rekey(check.id),
            evaluationId,
          })),
        },
      ]);
    }
    for (const [oldId, envelope] of moved) {
      this.#pending.delete(oldId);
      this.#pending.set(envelope.evaluation.id, envelope);
    }
  }

  /**
   * Hand everything buffered to its destination. NEVER rejects.
   *
   * The buffer is drained BEFORE the first await, so a concurrent request's
   * `append` lands in the next flush rather than being written twice or lost
   * halfway. On a queue failure the same envelopes fall through to D1 rather
   * than being dropped: a queue outage should degrade the batching, not the
   * evidence.
   *
   * The promise it returns is what the caller hands to `ctx.waitUntil`, so it
   * resolves only once the write has actually landed (or failed) — returning
   * early would let the isolate be torn down mid-write, which is the failure
   * mode that produces a decision the gateway made and has no record of.
   */
  async flush(runtime: { env: unknown }): Promise<void> {
    if (this.#pending.size === 0) return;
    const envelopes = [...this.#pending.values()];
    this.#pending.clear();

    const queue = this.#queueOf(runtime.env);
    if (queue !== undefined) {
      try {
        await queue.sendBatch(
          envelopes.map((envelope) => ({ body: guardrailEvidenceToWire(envelope) })),
        );
        this.#queued += envelopes.length;
        return;
      } catch (error) {
        this.#failed += envelopes.length;
        this.#diagnostics?.onError?.("queue", error);
      }
    }

    const db = this.#databaseOf(runtime.env);
    if (db === undefined) {
      this.#dropped += envelopes.length;
      return;
    }
    try {
      await writeGuardrailEvidence(db, envelopes);
      this.#written += envelopes.length;
    } catch (error) {
      this.#failed += envelopes.length;
      this.#diagnostics?.onError?.("d1", error);
    }
  }
}

/** The composition root's constructor. */
export function createGuardrailEvidenceSink(
  options: GuardrailEvidenceSinkOptions = {},
): DurableGuardrailEvidenceSink {
  return new DurableGuardrailEvidenceSink(options);
}
