/**
 * The coalesced durable auth read (`D1ControlDbApiKeyAuthenticator`).
 *
 * The two durable control-database lookups — `api_key_directory` and
 * `static_api_keys` — used to be two chained authenticators, each paying its own
 * round trip to the single-threaded control object. On the operator hot path
 * (a break-glass var key absent from BOTH tables) that was two always-miss
 * cross-region reads serialized ahead of the handler's own work — the wrong side
 * of the 1s SLA for the `tenant-accounts` LIST.
 *
 * This pins that both lookups now travel in ONE `batch()` round trip, for a
 * var-only operator key (both miss) AND a durable static hit — while the full
 * auth-behaviour suite (`api-keys-d1`, `operator-key`, `native-key-tenant-db`,
 * `virtual-key-credential`, `static-key-malformed`) proves ordering and
 * durable-wins are untouched.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { resolveApiKeys } from "../src/adapters.js";
import { callerScope } from "../src/ports.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { hashApiKeySecret } from "../src/store/api_keys.js";
import { db, resetD1 } from "./d1.js";
import { arm } from "./harness.js";

/** Wrap the real control DB, counting how many `batch()` round trips it makes. */
function countingControlDb(): { db: D1Database; batches: () => number } {
  const real = db();
  let batches = 0;
  const proxy = new Proxy(real, {
    get(target, prop, receiver) {
      if (prop === "batch") {
        return (statements: D1PreparedStatement[]) => {
          batches += 1;
          return target.batch(statements);
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { db: proxy as D1Database, batches: () => batches };
}

const OPERATOR_SECRET = "fg_operator_config_probe";

describe("D1ControlDbApiKeyAuthenticator — one round trip covers both durable tables", () => {
  beforeEach(async () => {
    await resetD1();
    await db().prepare("DELETE FROM static_api_keys").run();
    arm({
      store: "d1",
      staticKeys: [{ secret: OPERATOR_SECRET, id: "op-console", platform_operator: true }],
    });
  });

  it("resolves a var-only operator key having missed BOTH tables in a single batch", async () => {
    const spy = countingControlDb();
    const authenticator = resolveApiKeys(env as unknown as ControlPlaneBindings, spy.db);

    const resolution = await authenticator.authenticate(OPERATOR_SECRET);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") throw new Error("unreachable");
    expect(resolution.auth.platformOperator).toBe(true);
    expect(callerScope(resolution.auth)).toEqual({ kind: "platform_operator" });
    // The directory + static reads that used to be two round trips are now one.
    expect(spy.batches()).toBe(1);
  });

  it("serves a DURABLE static hit from that same single batch (no extra round trip)", async () => {
    const secret = "fg_tenant_static_probe";
    const now = Math.floor(Date.now() / 1000);
    await db()
      .prepare(
        `INSERT INTO static_api_keys
           (key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix,
            created_at_unix, updated_at_unix)
         VALUES (?, 'tenant-static-probe', 't-1', 0, ?, 1, NULL, ?, ?)`,
      )
      .bind(await hashApiKeySecret(secret), JSON.stringify(["admin.read"]), now, now)
      .run();

    const spy = countingControlDb();
    const authenticator = resolveApiKeys(env as unknown as ControlPlaneBindings, spy.db);

    const resolution = await authenticator.authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") throw new Error("unreachable");
    expect(resolution.auth.platformOperator).toBe(false);
    expect(callerScope(resolution.auth)).toEqual({ kind: "tenant", tenantId: "t-1" });
    expect(spy.batches()).toBe(1);
  });

  it("an unknown key still misses both tables in ONE batch, then falls through to the vars", async () => {
    const spy = countingControlDb();
    const authenticator = resolveApiKeys(env as unknown as ControlPlaneBindings, spy.db);

    const resolution = await authenticator.authenticate("fg_unknown_never_configured");
    expect(resolution.outcome).not.toBe("resolved");
    expect(spy.batches()).toBe(1);
  });
});
