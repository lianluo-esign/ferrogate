/**
 * The site-domain verification rate-limit CAS against REAL D1 (#488/#576).
 *
 * The claim that needs a real database is NOT "a second attempt inside the
 * cooldown is refused" — the pure `siteDomainVerificationAttemptDecision` shows
 * that, and shows it because a single JS thread serialized the two calls, which
 * is a property of the test and not of the deployed system.
 *
 * The claim under test here is that the cooldown predicate and the reservation
 * are ONE statement, so two callers that both read the same
 * `lastCheckedAtUnix` cannot both be granted. That is the whole of #576: an
 * `admin.write` credential must not be able to drive unbounded outbound DNS by
 * issuing concurrent verify calls.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  BEGIN_SITE_DOMAIN_VERIFICATION_ATTEMPT_SQL,
  D1SiteDomainVerificationStore,
  SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS,
  markCheckFailed,
  markVerified,
  pendingSiteDomainVerification,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, setupDatabases } from "./harness.js";

const NOW = 1_784_073_600;
const HOST = "app.example.com";
const COOLDOWN = SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS;

let store: D1SiteDomainVerificationStore;

beforeAll(async () => {
  await setupDatabases();
  store = new D1SiteDomainVerificationStore(env.CONTROL_DB);
});

beforeEach(async () => {
  await env.CONTROL_DB.prepare("DELETE FROM site_domain_verifications").run();
});

async function seed(
  tenantId = TENANT_A,
  hostname = HOST,
  lastCheckedAtUnix?: number,
): Promise<void> {
  const record = pendingSiteDomainVerification(tenantId, hostname, "site_1", "token_1", NOW);
  record.lastCheckedAtUnix = lastCheckedAtUnix;
  await store.upsertVerification(record);
}

describe("D1SiteDomainVerificationStore — the #576 rate-limit CAS", () => {
  test("the guard SQL carries the cooldown predicate, not just a write", () => {
    // A behavior-only assertion would pass against a read-then-write, so the
    // shape of the statement itself is pinned: the predicate has to be in the
    // UPDATE's WHERE, and it has to admit a never-checked row.
    expect(BEGIN_SITE_DOMAIN_VERIFICATION_ATTEMPT_SQL).toContain(
      "UPDATE site_domain_verifications",
    );
    expect(BEGIN_SITE_DOMAIN_VERIFICATION_ATTEMPT_SQL).toContain(
      "(last_checked_at_unix IS NULL OR ? - last_checked_at_unix >= ?)",
    );
  });

  test("the first attempt on a never-checked row is granted and RESERVES the slot", async () => {
    await seed();
    expect(await store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW, COOLDOWN)).toEqual({
      kind: "allowed",
    });
    // The reservation is the write, and it has already happened — it is not
    // deferred until after a successful DNS lookup, because a slot only taken
    // on success is a slot an attacker holds open by making lookups fail.
    const record = await store.getVerification(TENANT_A, HOST);
    expect(record?.lastCheckedAtUnix).toBe(NOW);
  });

  test("a second attempt inside the cooldown is refused with a bounded retry", async () => {
    await seed();
    await store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW, COOLDOWN);
    const second = await store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW + 5, COOLDOWN);
    expect(second).toEqual({ kind: "rate_limited", retryAfterSecs: COOLDOWN - 5 });
    // The refused caller must not have moved the reservation forward — that
    // would let a rejected attempt extend everyone else's cooldown.
    expect((await store.getVerification(TENANT_A, HOST))?.lastCheckedAtUnix).toBe(NOW);
  });

  test("an attempt after the cooldown elapses is granted again", async () => {
    await seed();
    await store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW, COOLDOWN);
    expect(
      await store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW + COOLDOWN, COOLDOWN),
    ).toEqual({ kind: "allowed" });
    expect((await store.getVerification(TENANT_A, HOST))?.lastCheckedAtUnix).toBe(NOW + COOLDOWN);
  });

  test("EXACTLY ONE of many concurrent callers is granted the slot", async () => {
    await seed();
    // The read-decide-write shape this replaces grants ALL of these: every
    // caller reads the same `lastCheckedAtUnix`, every caller is told `allowed`,
    // and every caller reaches the DNS lookup.
    const attempts = await Promise.all(
      Array.from({ length: 12 }, () =>
        store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW, COOLDOWN),
      ),
    );
    expect(attempts.filter((a) => a.kind === "allowed")).toHaveLength(1);
    expect(attempts.filter((a) => a.kind === "rate_limited")).toHaveLength(11);
  });

  test("a refused racer still gets a POSITIVE retry hint, never zero", async () => {
    await seed();
    const attempts = await Promise.all(
      Array.from({ length: 6 }, () =>
        store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW, COOLDOWN),
      ),
    );
    for (const attempt of attempts) {
      if (attempt.kind === "rate_limited") expect(attempt.retryAfterSecs).toBeGreaterThan(0);
    }
  });

  test("the gate is per (tenant, hostname): another tenant is not rate-limited by yours", async () => {
    await seed(TENANT_A);
    await seed(TENANT_B);
    await store.tryBeginVerificationAttempt(TENANT_A, HOST, NOW, COOLDOWN);
    // The key is (tenant_id, hostname), so one tenant burning its slot cannot
    // be used to deny another tenant its own verification of the same host.
    expect(await store.tryBeginVerificationAttempt(TENANT_B, HOST, NOW, COOLDOWN)).toEqual({
      kind: "allowed",
    });
  });

  test("a (tenant, hostname) with no record at all is allowed", async () => {
    // Not a bypass: the pure rule allows a first attempt too, and the caller is
    // about to create the record. Once the row exists the guard applies.
    expect(
      await store.tryBeginVerificationAttempt(TENANT_A, "unknown.test", NOW, COOLDOWN),
    ).toEqual({ kind: "allowed" });
  });
});

describe("D1SiteDomainVerificationStore — records", () => {
  test("round-trips every field, including the optional ones", async () => {
    const record = pendingSiteDomainVerification(TENANT_A, HOST, "site_1", "token_1", NOW);
    markVerified(record, NOW + 10);
    await store.upsertVerification(record);
    expect(await store.getVerification(TENANT_A, HOST)).toEqual(record);
  });

  test("a failure record keeps its reason and attempt count", async () => {
    const record = pendingSiteDomainVerification(TENANT_A, HOST, "site_1", "token_1", NOW);
    markCheckFailed(record, NOW + 10, "txt record not found");
    await store.upsertVerification(record);
    const read = await store.getVerification(TENANT_A, HOST);
    expect(read?.lastFailureReason).toBe("txt record not found");
    expect(read?.attemptCount).toBe(1);
    expect(read?.state).toBe("pending_verification");
  });

  test("an upsert does NOT discard the caller's own lastCheckedAtUnix", async () => {
    // The reservation is `tryBeginVerificationAttempt`'s job; if the upsert
    // silently rewrote or dropped this column, a caller that reserved a slot and
    // then stored its post-lookup record would reopen the burst window.
    await seed(TENANT_A, HOST, NOW - 1);
    const record = pendingSiteDomainVerification(TENANT_A, HOST, "site_1", "token_1", NOW);
    markCheckFailed(record, NOW + 3, "nope");
    await store.upsertVerification(record);
    expect((await store.getVerification(TENANT_A, HOST))?.lastCheckedAtUnix).toBe(NOW + 3);
  });

  test("an unknown persisted state FAILS CLOSED rather than defaulting to servable", async () => {
    await seed();
    await env.CONTROL_DB.prepare(
      "UPDATE site_domain_verifications SET state = 'totally_fine' WHERE tenant_id = ?",
    )
      .bind(TENANT_A)
      .run();
    await expect(store.getVerification(TENANT_A, HOST)).rejects.toThrow(
      /unknown site_domain_verifications.state totally_fine/,
    );
  });

  test("list narrows by tenant and is ordered by hostname", async () => {
    await seed(TENANT_A, "b.example.com");
    await seed(TENANT_A, "a.example.com");
    await seed(TENANT_B, "c.example.com");
    expect((await store.listVerifications(TENANT_A)).map((r) => r.hostname)).toEqual([
      "a.example.com",
      "b.example.com",
    ]);
    expect(await store.listVerifications()).toHaveLength(3);
  });

  test("delete reports whether a row was actually removed", async () => {
    await seed();
    expect(await store.deleteVerification(TENANT_A, HOST)).toBe(true);
    expect(await store.deleteVerification(TENANT_A, HOST)).toBe(false);
    expect(await store.getVerification(TENANT_A, HOST)).toBeUndefined();
  });
});
