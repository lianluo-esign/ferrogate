/**
 * The durable, replayable EXPORT CURSOR (#683).
 *
 * One row per (sink, stream) in `siem_export_cursors`
 * (`sql/d1-ts/control/0005_siem_export_cursors.sql`) holding the last position
 * a customer sink ACKNOWLEDGED. Everything about at-least-once delivery is in
 * the ordering of two writes and one comparison:
 *
 *  * the cursor is written only AFTER the sink acknowledges a batch, so a crash
 *    anywhere before that re-sends the batch rather than skipping it; and
 *  * the write only ever moves the cursor FORWARD, so two overlapping ticks (a
 *    cron tick that overran, a retry) cannot rewind each other into re-sending
 *    the whole history — or, worse, into a state where one tick's advance hides
 *    another's undelivered rows.
 *
 * A rewind is possible, but only through {@link applyReplay}, which is gated on
 * an epoch so that it happens exactly once per operator instruction.
 */
import type { SiemStream } from "./config.js";

export const SIEM_CURSOR_TABLE = "siem_export_cursors";

/**
 * A keyset position: the ordering timestamp plus the row id that broke the tie.
 *
 * Not an OFFSET, and the difference is the whole point. These tables are
 * append-heavy, so rows land between two ticks and shift every offset after
 * them — resuming by offset silently drops exactly the rows that arrived while
 * the pump was down. A keyset position names a ROW, so it survives inserts.
 */
export interface SiemCursorPosition {
  readonly ts: number;
  readonly id: string;
}

export interface SiemCursor {
  readonly sinkId: string;
  readonly stream: SiemStream;
  readonly tenant: string;
  readonly position: SiemCursorPosition;
  readonly delivered: number;
  readonly replayEpoch: number;
  readonly updatedAtUnix: number;
}

interface CursorRow {
  readonly sink_id: string;
  readonly stream: string;
  readonly tenant: string;
  readonly last_ts: number;
  readonly last_id: string;
  readonly delivered: number;
  readonly replay_epoch: number;
  readonly updated_at_unix: number;
}

function toCursor(row: CursorRow): SiemCursor {
  return {
    sinkId: row.sink_id,
    stream: row.stream as SiemStream,
    tenant: row.tenant,
    position: { ts: row.last_ts, id: row.last_id },
    delivered: row.delivered,
    replayEpoch: row.replay_epoch,
    updatedAtUnix: row.updated_at_unix,
  };
}

/**
 * The acknowledged position, or `null` when this sink has never delivered.
 *
 * Exported for operators and for the tests: "how far has this sink got" has to
 * be answerable without inferring it from what happens to arrive next.
 */
export async function readSiemCursor(
  db: D1Database,
  sinkId: string,
  stream: SiemStream,
): Promise<SiemCursor | null> {
  const row = await db
    .prepare(
      `SELECT sink_id, stream, tenant, last_ts, last_id, delivered, replay_epoch, updated_at_unix
         FROM ${SIEM_CURSOR_TABLE}
        WHERE sink_id = ? AND stream = ?`,
    )
    .bind(sinkId, stream)
    .first<CursorRow>();
  return row === null ? null : toCursor(row);
}

/**
 * Record an ACKNOWLEDGED batch.
 *
 * The `WHERE` on the UPDATE arm is the forward-only rule, written as a
 * predicate rather than as a read-then-compare because D1 has no interactive
 * transaction: two isolates that both read "position = X" would both write, and
 * the later write would win even if it were older. As a predicate, the older
 * write matches no row and does nothing, which is the correct outcome — the
 * batch it delivered has already been superseded, and re-delivering it is
 * at-least-once, not loss.
 *
 * `delivered` accumulates with `+ ?` in the same statement for the same reason:
 * a read-modify-write would lose a concurrent tick's count.
 */
export async function advanceSiemCursor(
  db: D1Database,
  input: {
    readonly sinkId: string;
    readonly stream: SiemStream;
    readonly tenant: string;
    readonly position: SiemCursorPosition;
    readonly rows: number;
    readonly replayEpoch: number;
    readonly now: number;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ${SIEM_CURSOR_TABLE}
         (sink_id, stream, tenant, last_ts, last_id, delivered, replay_epoch, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(sink_id, stream) DO UPDATE SET
         tenant = excluded.tenant,
         last_ts = excluded.last_ts,
         last_id = excluded.last_id,
         delivered = ${SIEM_CURSOR_TABLE}.delivered + excluded.delivered,
         replay_epoch = max(${SIEM_CURSOR_TABLE}.replay_epoch, excluded.replay_epoch),
         updated_at_unix = excluded.updated_at_unix
       WHERE excluded.last_ts > ${SIEM_CURSOR_TABLE}.last_ts
          OR (excluded.last_ts = ${SIEM_CURSOR_TABLE}.last_ts
              AND excluded.last_id > ${SIEM_CURSOR_TABLE}.last_id)`,
    )
    .bind(
      input.sinkId,
      input.stream,
      input.tenant,
      input.position.ts,
      input.position.id,
      input.rows,
      input.replayEpoch,
      input.now,
    )
    .run();
}

/**
 * Apply a replay instruction, at most once per epoch.
 *
 * Returns the position the pump should resume from. The epoch is persisted in
 * the SAME statement that rewinds the position, so a tick that crashes between
 * the two is impossible — the alternative (rewind now, record the epoch after
 * the first successful delivery) would replay the window again on every tick
 * until a delivery finally succeeded, which is exactly when a sink is least
 * able to absorb it.
 *
 * The rewind deliberately bypasses the forward-only rule in
 * {@link advanceSiemCursor}: that rule exists to stop CONCURRENT DELIVERIES
 * from rewinding each other, not to stop an operator from asking for a replay.
 */
export async function applyReplay(
  db: D1Database,
  input: {
    readonly sinkId: string;
    readonly stream: SiemStream;
    readonly tenant: string;
    readonly epoch: number;
    readonly fromUnix: number;
    readonly now: number;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ${SIEM_CURSOR_TABLE}
         (sink_id, stream, tenant, last_ts, last_id, delivered, replay_epoch, updated_at_unix)
       VALUES (?, ?, ?, ?, '', 0, ?, ?)
       ON CONFLICT(sink_id, stream) DO UPDATE SET
         last_ts = excluded.last_ts,
         last_id = excluded.last_id,
         replay_epoch = excluded.replay_epoch,
         updated_at_unix = excluded.updated_at_unix
       WHERE excluded.replay_epoch > ${SIEM_CURSOR_TABLE}.replay_epoch`,
    )
    .bind(input.sinkId, input.stream, input.tenant, input.fromUnix, input.epoch, input.now)
    .run();
}
