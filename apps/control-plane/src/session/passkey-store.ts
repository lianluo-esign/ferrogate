/** Strongly consistent credential/challenge storage, shared by D1 and CONTROL_DATA's SQL adapter. */
export interface PasskeyRow {
  id: string;
  user_id: string;
  tenant_id: string;
  user_handle: string;
  public_key: string;
  counter: number;
  transports: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
  revision: number;
}

export class PasskeyStore {
  constructor(readonly db: D1Database) {}

  async throttle(client: string): Promise<void> {
    const now = Date.now();
    const bucket = `${client}:${Math.floor(now / 300_000)}`;
    const results = await this.db.batch([
      this.db.prepare("DELETE FROM admin_passkey_challenges WHERE expires_at <= ?").bind(now),
      this.db.prepare("DELETE FROM admin_passkey_rate_limits WHERE expires_at <= ?").bind(now),
      this.db
        .prepare(`INSERT INTO admin_passkey_rate_limits (bucket, attempts, expires_at)
        VALUES (?, 1, ?) ON CONFLICT(bucket) DO UPDATE SET attempts = attempts + 1
        RETURNING attempts`)
        .bind(bucket, now + 300_000),
    ]);
    if (Number((results[2]?.results[0] as { attempts?: number } | undefined)?.attempts) > 30)
      throw new Error("rate_limit");
  }

  async challenge(kind: string, binding: string, challenge: string, userId = "", tenantId = "") {
    const id = crypto.randomUUID();
    await this.db
      .prepare(`INSERT INTO admin_passkey_challenges
      (id, challenge, binding, kind, user_id, tenant_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, challenge, binding, kind, userId, tenantId, Date.now() + 300_000)
      .run();
    return id;
  }

  async consume(id: string, kind: string, binding: string, userId = "", tenantId = "") {
    // DELETE RETURNING is one atomic statement. Two concurrent assertions cannot both win.
    return this.db
      .prepare(`DELETE FROM admin_passkey_challenges
      WHERE id = ? AND kind = ? AND binding = ? AND user_id = ? AND tenant_id = ?
      AND expires_at > ? RETURNING challenge`)
      .bind(id, kind, binding, userId, tenantId, Date.now())
      .first<{ challenge: string }>();
  }

  async list(userId: string, tenantId: string) {
    return (
      await this.db
        .prepare(
          "SELECT * FROM admin_passkeys WHERE user_id = ? AND tenant_id = ? ORDER BY created_at, id",
        )
        .bind(userId, tenantId)
        .all<PasskeyRow>()
    ).results;
  }

  async get(id: string) {
    return this.db
      .prepare("SELECT * FROM admin_passkeys WHERE id = ?")
      .bind(id)
      .first<PasskeyRow>();
  }

  async insert(row: Omit<PasskeyRow, "created_at" | "last_used_at" | "revision">) {
    // Credential IDs cannot be reassigned. The limit is checked atomically with insertion.
    return this.db
      .prepare(`INSERT INTO admin_passkeys
      (id, user_id, tenant_id, user_handle, public_key, counter, transports, name, created_at)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE
      (SELECT COUNT(*) FROM admin_passkeys WHERE user_id = ? AND tenant_id = ?) < 10
      ON CONFLICT(id) DO NOTHING RETURNING id`)
      .bind(
        row.id,
        row.user_id,
        row.tenant_id,
        row.user_handle,
        row.public_key,
        row.counter,
        row.transports,
        row.name,
        Date.now(),
        row.user_id,
        row.tenant_id,
      )
      .first<{ id: string }>();
  }

  async used(row: PasskeyRow, newCounter: number) {
    // Revision handles synchronized Apple passkeys whose signature counter stays at zero too.
    // Deletion or another authentication during verification causes this CAS to fail closed.
    return this.db
      .prepare(`UPDATE admin_passkeys SET counter = ?, last_used_at = ?, revision = revision + 1
      WHERE id = ? AND user_id = ? AND tenant_id = ? AND revision = ? RETURNING id`)
      .bind(newCounter, Date.now(), row.id, row.user_id, row.tenant_id, row.revision)
      .first<{ id: string }>();
  }

  async remove(id: string, userId: string, tenantId: string) {
    await this.db
      .prepare("DELETE FROM admin_passkeys WHERE id = ? AND user_id = ? AND tenant_id = ?")
      .bind(id, userId, tenantId)
      .run();
  }
}
