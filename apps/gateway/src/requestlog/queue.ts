/**
 * The CONSUMER half of the request-log queue — `export default { queue }` on
 * `src/worker.ts`.
 *
 * ## Why the gateway consumes its own queue
 *
 * `[[queues.producers]] BILLING` is producer-only on this Worker, and its
 * stanza says why: the consumer belongs to whoever settles wallets downstream.
 * Request logs are the opposite case. The only thing that has to happen to a
 * request-log message is an insert into the CONTROL database, and this Worker
 * already binds it (`CONTROL_DB`) because the guardrail policy source reads
 * from it. Routing the message to a second Worker would add a deploy unit, a
 * second `wrangler.toml` and a second set of credentials to be able to do
 * exactly the same statement.
 *
 * A Worker consuming a queue it produces is a supported Cloudflare topology; it
 * is a separate invocation with its own `env`, not a re-entrant call.
 *
 * ## The batch contract, and why a bad message does not poison a good one
 *
 * Queues are AT LEAST ONCE. The write is an upsert keyed on `request_id`
 * (`d1.ts`), so a redelivered message re-applies the same row instead of
 * failing on the primary key — which is what makes `retryAll()` on a partial
 * failure safe rather than a loop.
 *
 * A message whose body does not decode is `ack()`ed and counted, NOT retried:
 * it cannot become valid on redelivery, and retrying it would keep a
 * permanently-bad message in front of good evidence until it dead-lettered.
 * `requestLogFromWire` is total and returns `undefined` for exactly that case.
 *
 * The batch is written in ONE `db.batch`, so either the whole delivery lands or
 * none of it does. On failure the batch is retried whole — with the upsert, the
 * messages that had already landed are simply re-applied.
 */
import { type RequestLogDatabase, writeRequestLogs } from "./d1.js";
import { requestLogFromWire } from "./record.js";
import { requestLogDatabaseFrom } from "./sink.js";

/** The `MessageBatch` slice this consumer uses, structurally. */
export interface RequestLogMessageBatch {
  readonly queue?: string;
  readonly messages: readonly { readonly body: unknown; ack?(): void }[];
  retryAll?(options?: unknown): void;
}

/** What one delivery did, for the caller's diagnostics. */
export interface RequestLogConsumeResult {
  /** Messages decoded into a record and handed to D1. */
  readonly written: number;
  /** Messages whose body could not be decoded; acked, never retried. */
  readonly malformed: number;
  /** True when the batch was handed back for redelivery. */
  readonly retried: boolean;
}

/**
 * Apply one queue delivery to `request_logs`.
 *
 * NEVER throws: a consumer that throws gets its batch redelivered by the
 * platform anyway, so throwing would only lose the ability to say what
 * happened. Failure is reported by arming `retryAll()` and returning
 * `retried: true`.
 */
export async function consumeRequestLogBatch(
  batch: RequestLogMessageBatch,
  env: unknown,
  databaseOf: (env: unknown) => RequestLogDatabase | undefined = requestLogDatabaseFrom,
): Promise<RequestLogConsumeResult> {
  const records = [];
  let malformed = 0;
  for (const message of batch.messages) {
    const record = requestLogFromWire(message.body);
    if (record === undefined) {
      malformed += 1;
      // Ack the undecodable message explicitly so `retryAll()` below (if the
      // rest of the batch fails) does not drag it along forever.
      message.ack?.();
      continue;
    }
    records.push(record);
  }

  if (records.length === 0) {
    return { written: 0, malformed, retried: false };
  }

  const db = databaseOf(env);
  if (db === undefined) {
    // The binding is missing, which is a DEPLOY fault, not a data fault. Retry
    // rather than ack: the evidence is still in the queue when it is fixed, and
    // the dead-letter queue bounds how long that can go on.
    batch.retryAll?.();
    return { written: 0, malformed, retried: true };
  }

  try {
    await writeRequestLogs(db, records);
    return { written: records.length, malformed, retried: false };
  } catch {
    batch.retryAll?.();
    return { written: 0, malformed, retried: true };
  }
}
