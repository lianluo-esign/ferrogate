/**
 * `D1TenantProviderCredentialStore` — the durable half of per-tenant BYOK
 * (issue #682), against the addressed tenant database.
 *
 * Read `packages/secrets/src/byok.ts` first: it owns the envelope, the alias
 * grammar and the reason the tenant is a property of the RESOLVER rather than of
 * the reference. This class owns only the rows, and it exists to hold one
 * invariant that a document store could not:
 *
 * > every statement is scoped by `tenant_id = ?`, on a table whose PRIMARY KEY
 * > leads with `tenant_id`.
 *
 * ## Why the SQL fence exists at all, given the crypto fence
 *
 * The ciphertext is already sealed to `(tenant_id, alias)`, so a row read by the
 * wrong tenant would fail to decrypt. That is a real fence and it is the one
 * that cannot be widened by accident. It is NOT sufficient on its own for two
 * reasons:
 *
 *  1. **Metadata is not encrypted.** `provider`, `last4`, `rotated_at_unix` and
 *     the alias NAME itself are plaintext columns. An unscoped `list` would leak
 *     which providers another tenant has negotiated rates with — commercially
 *     sensitive on its own, and #682 is filed by enterprises precisely because
 *     those agreements are confidential.
 *  2. **A failed decrypt is a loud error, not a silent miss.** An unscoped read
 *     would turn "tenant B has no alias `openai`" into a 5xx storm the moment
 *     tenant A registers one, which is both an outage and an oracle.
 *
 * So both fences are asserted, independently, in
 * `test/d1/provider-credential-d1.test.ts`.
 *
 * ## No `batch()`
 *
 * Every operation here is a single statement, which SQLite already runs in an
 * implicit transaction. `requireAtomicBatch` is deliberately NOT asserted —
 * same reasoning as `./site-domain-d1.ts` and `./references-d1.ts`: this store
 * is safe on any handle that can run one statement, including native D1
 * compatibility handles.
 *
 * ## The plaintext never lives here
 *
 * This module never sees a credential value. It moves sealed records, and
 * `last4` — which is derived by the caller before sealing, because deriving it
 * here would mean this module handling plaintext.
 */
import type { StorageError } from "../errors.js";
import { d1Error, optionalNumber } from "./rows.js";

/**
 * One row, as read.
 *
 * Structurally a `SealedTenantCredential` from `@ferrogate/secrets` plus the
 * lifecycle columns. Declared here rather than imported so `@ferrogate/storage`
 * keeps no dependency on `@ferrogate/secrets` — the two packages meet at the
 * composition root, and the `TenantCredentialStore` interface this class
 * satisfies is structural.
 */
export interface StoredTenantProviderCredential {
  readonly tenantId: string;
  readonly alias: string;
  readonly provider: string;
  readonly keyVersion: number;
  readonly iv: string;
  readonly ciphertext: string;
  /** Last four characters of the credential — the only part ever displayed. */
  readonly last4: string;
  readonly createdAtUnix: number;
  readonly rotatedAtUnix: number;
  /** Set ⇒ the alias is a tombstone and resolves to nothing. */
  readonly revokedAtUnix?: number | undefined;
}

/**
 * The projection an ADMIN listing may see. No `iv`, no `ciphertext`: the
 * listing surface must be incapable of returning key material even if a future
 * handler forgets to strip a field, so the type it receives simply has none.
 */
export interface TenantProviderCredentialSummary {
  readonly alias: string;
  readonly provider: string;
  readonly last4: string;
  readonly keyVersion: number;
  readonly createdAtUnix: number;
  readonly rotatedAtUnix: number;
  readonly revokedAtUnix?: number | undefined;
}

/** What {@link D1TenantProviderCredentialStore.upsert} writes. */
export interface TenantProviderCredentialWrite {
  readonly tenantId: string;
  readonly alias: string;
  readonly provider: string;
  readonly keyVersion: number;
  readonly iv: string;
  readonly ciphertext: string;
  readonly last4: string;
}

const COLUMNS =
  "tenant_id, alias, provider, key_version, iv, ciphertext, last4, " +
  "created_at_unix, rotated_at_unix, revoked_at_unix";

/**
 * The lookup the request path runs, exported so the mutation proof can assert
 * the tenant predicate is in the SQL the store ACTUALLY runs.
 *
 * A test that only exercised the outcome would still pass against a store that
 * filtered in JavaScript after fetching every tenant's rows — which is a
 * different (and worse) program with the same observable behaviour on a
 * two-tenant fixture.
 *
 * `revoked_at_unix IS NULL` is part of the same statement rather than a
 * post-filter for the same reason the site-domain cooldown is: a revocation that
 * is decided in application code after the row is already in memory is a
 * revocation with a window in it.
 */
export const LOOKUP_TENANT_PROVIDER_CREDENTIAL_SQL =
  `SELECT ${COLUMNS} FROM tenant_provider_credentials ` +
  "WHERE tenant_id = ? AND alias = ? AND revoked_at_unix IS NULL";

interface CredentialRow {
  tenant_id: string;
  alias: string;
  provider: string;
  key_version: number;
  iv: string;
  ciphertext: string;
  last4: string;
  created_at_unix: number;
  rotated_at_unix: number;
  revoked_at_unix: number | null;
}

function decode(row: CredentialRow): StoredTenantProviderCredential {
  const revokedAtUnix = optionalNumber(row.revoked_at_unix);
  return {
    tenantId: row.tenant_id,
    alias: row.alias,
    provider: row.provider,
    keyVersion: Number(row.key_version),
    iv: row.iv,
    ciphertext: row.ciphertext,
    last4: row.last4,
    createdAtUnix: Number(row.created_at_unix),
    rotatedAtUnix: Number(row.rotated_at_unix),
    ...(revokedAtUnix === undefined ? {} : { revokedAtUnix }),
  };
}

/**
 * Control-D1-backed alias store.
 *
 * Satisfies `@ferrogate/secrets`' `TenantCredentialStore` structurally. The
 * composition roots pass the database returned by the tenant object router;
 * this class has no control-D1 compatibility fallback.
 */
export class D1TenantProviderCredentialStore {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  /**
   * Resolve one alias FOR ONE TENANT. `null` for absent, revoked, or
   * another tenant's — deliberately the same answer for all three, so this is
   * not an oracle for other tenants' alias names.
   */
  async lookup(
    tenantId: string,
    alias: string,
  ): Promise<StoredTenantProviderCredential | null> {
    try {
      const row = await this.db
        .prepare(LOOKUP_TENANT_PROVIDER_CREDENTIAL_SQL)
        .bind(tenantId, alias)
        .first<CredentialRow>();
      return row === null ? null : decode(row);
    } catch (error) {
      throw this.wrap("lookup tenant provider credential", error);
    }
  }

  /**
   * Register or ROTATE an alias — the same statement, which is what makes
   * "rotate without a deploy" one round trip.
   *
   * `created_at_unix` is preserved across a rotation (`excluded` overwrites
   * everything else) so the audit trail can distinguish "registered in January,
   * rotated in June" from "registered in June". A revoked alias is
   * REVIVED by a rotation — `revoked_at_unix` resets to NULL — because the
   * alternative is a tenant permanently burning an alias name they own.
   */
  async upsert(
    write: TenantProviderCredentialWrite,
    nowUnix: number,
  ): Promise<void> {
    try {
      await this.db
        .prepare(
          "INSERT INTO tenant_provider_credentials " +
            `(${COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) ` +
            "ON CONFLICT(tenant_id, alias) DO UPDATE SET " +
            "provider = excluded.provider, key_version = excluded.key_version, " +
            "iv = excluded.iv, ciphertext = excluded.ciphertext, " +
            "last4 = excluded.last4, rotated_at_unix = excluded.rotated_at_unix, " +
            "revoked_at_unix = NULL",
        )
        .bind(
          write.tenantId,
          write.alias,
          write.provider,
          write.keyVersion,
          write.iv,
          write.ciphertext,
          write.last4,
          nowUnix,
          nowUnix,
        )
        .run();
    } catch (error) {
      throw this.wrap("upsert tenant provider credential", error);
    }
  }

  /**
   * Tombstone an alias. Returns `false` when the tenant has no such live alias,
   * so a caller can answer 404 rather than pretending to have revoked something.
   *
   * The `tenant_id = ?` predicate is what stops a tenant revoking another
   * tenant's credential — a denial-of-service that the crypto fence does NOT
   * cover, because destroying access needs no ability to read.
   */
  async revoke(tenantId: string, alias: string, nowUnix: number): Promise<boolean> {
    try {
      const result = await this.db
        .prepare(
          "UPDATE tenant_provider_credentials SET revoked_at_unix = ? " +
            "WHERE tenant_id = ? AND alias = ? AND revoked_at_unix IS NULL",
        )
        .bind(nowUnix, tenantId, alias)
        .run();
      return (result.meta?.changes ?? 0) > 0;
    } catch (error) {
      throw this.wrap("revoke tenant provider credential", error);
    }
  }

  /**
   * Every alias this tenant owns, live and revoked, as the redacted summary.
   *
   * Returns {@link TenantProviderCredentialSummary}, which has no `iv` and no
   * `ciphertext` field at all — a handler cannot leak what it was never given.
   */
  async list(tenantId: string): Promise<readonly TenantProviderCredentialSummary[]> {
    try {
      const result = await this.db
        .prepare(
          "SELECT alias, provider, last4, key_version, created_at_unix, " +
            "rotated_at_unix, revoked_at_unix FROM tenant_provider_credentials " +
            "WHERE tenant_id = ? ORDER BY alias",
        )
        .bind(tenantId)
        .all<Omit<CredentialRow, "tenant_id" | "iv" | "ciphertext">>();
      return (result.results ?? []).map((row) => {
        const revokedAtUnix = optionalNumber(row.revoked_at_unix);
        return {
          alias: row.alias,
          provider: row.provider,
          last4: row.last4,
          keyVersion: Number(row.key_version),
          createdAtUnix: Number(row.created_at_unix),
          rotatedAtUnix: Number(row.rotated_at_unix),
          ...(revokedAtUnix === undefined ? {} : { revokedAtUnix }),
        };
      });
    } catch (error) {
      throw this.wrap("list tenant provider credentials", error);
    }
  }

  private wrap(operation: string, error: unknown): StorageError {
    return d1Error(operation, error);
  }
}

/** Construct the BYOK store only after the tenant router has resolved its object. */
export function tenantProviderCredentialStoreFor(
  handle: import("../tenant-router.js").TenantDatabaseHandle,
): D1TenantProviderCredentialStore {
  return new D1TenantProviderCredentialStore(handle.db);
}

/**
 * The displayable tail of a credential.
 *
 * Lives here (next to the column it fills) rather than in a handler so every
 * writer derives it the same way. Short credentials are masked ENTIRELY rather
 * than partially: for a 6-character value, "the last 4" is most of it.
 */
export function credentialLast4(value: string): string {
  const trimmed = value.trim();
  return trimmed.length >= 8 ? trimmed.slice(-4) : "";
}
