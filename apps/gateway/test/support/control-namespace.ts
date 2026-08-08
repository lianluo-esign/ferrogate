/**
 * Zero-D1 S5 (#881) test support: build a `CONTROL_DATA` namespace double.
 *
 * Since the control database is the singleton `ControlDataObject`, the seam
 * `controlDatabaseFrom(env)` reads `env.CONTROL_DATA` (a namespace) and wraps
 * it in the D1-shaped facade. Tests that used to inject a fake `CONTROL_DB`
 * D1 into a `*FromEnv` resolver now inject a `CONTROL_DATA` namespace instead.
 *
 *  - {@link controlNamespaceOverD1} adapts any D1-shaped handle (a real facade,
 *    or a throwing double) into a namespace whose stub proxies `query`/`batch`
 *    to that handle — so a THROWING control D1 still surfaces as an outage
 *    through the object RPC, which is what the 503/`unavailable` paths assert.
 *  - {@link failingControlNamespace} is the common case: a namespace whose
 *    every query rejects, i.e. a control object that is unreachable.
 */

import { env } from "cloudflare:test";

/** The real `CONTROL_DATA` namespace this suite is provisioned with. */
export function controlNamespace(): unknown {
  return (env as unknown as { CONTROL_DATA: unknown }).CONTROL_DATA;
}

interface D1Bound {
  all(): Promise<{ results?: unknown[] | null }>;
}
interface D1Like {
  prepare(sql: string): { bind(...values: unknown[]): D1Bound };
  batch?(statements: D1Bound[]): Promise<{ results?: unknown[] | null }[]>;
}

/** Adapt a D1-shaped handle into a `CONTROL_DATA`-shaped namespace. */
export function controlNamespaceOverD1(db: D1Like): unknown {
  const runOne = async (sql: string, params: readonly unknown[]) => {
    const result = await db
      .prepare(sql)
      .bind(...params)
      .all();
    return { results: (result.results ?? []) as unknown[] };
  };
  const stub = {
    async query(request: { sql: string; params?: readonly unknown[] }) {
      return runOne(request.sql, request.params ?? []);
    },
    async batch(request: { statements: readonly { sql: string; params?: readonly unknown[] }[] }) {
      // Delegate to the handle's own `batch` when it has one, so a recording or
      // failing double sees ONE atomic batch exactly as the real object RPC
      // would issue it — preserving the outage-is-atomic behaviour the metering
      // sink relies on. Fall back to per-statement runs only for a bare handle.
      if (typeof db.batch === "function") {
        const prepared = request.statements.map((statement) =>
          db.prepare(statement.sql).bind(...(statement.params ?? [])),
        );
        const results = await db.batch(prepared);
        return results.map((result) => ({ results: (result.results ?? []) as unknown[] }));
      }
      const out = [];
      for (const statement of request.statements) {
        out.push(await runOne(statement.sql, statement.params ?? []));
      }
      return out;
    },
  };
  return {
    idFromName(_name: string) {
      return "control";
    },
    get(_id: unknown) {
      return stub;
    },
  };
}

/** A `CONTROL_DATA` namespace whose every read fails — an unreachable object. */
export function failingControlNamespace(message = "control object unreachable"): unknown {
  const fail = async (): Promise<never> => {
    throw new Error(message);
  };
  const stub = { query: fail, batch: fail };
  return {
    idFromName(_name: string) {
      return "control";
    },
    get(_id: unknown) {
      return stub;
    },
  };
}
