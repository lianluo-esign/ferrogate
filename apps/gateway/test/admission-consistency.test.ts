/**
 * THE CROSS-WORKER ADMISSION CONTRACT — the assertion the wave-15 certification
 * found missing, stated directly.
 *
 * ## The defect this holds closed (CUTOVER-READINESS finding D1)
 *
 * Rust served `/v1/chat/completions`, `/v1/mcp`, `tools/call` and
 * `/v1/agent-jobs` from ONE process, through ONE `authenticate()` →
 * `finalize_auth` chain. The rewrite split the data plane into five Workers and
 * carried only the CREDENTIAL half onto `apps/mcp` and `apps/agent-runtime`:
 * the quota chain, the monthly USD budget, the prepaid wallet and the RPM
 * window existed on the gateway alone. A credential exhausted on the gateway
 * was ADMITTED on the other two — and an MCP `tools/call` and an agent job both
 * spend real provider money. The exploit was "call the other endpoint".
 *
 * Wave 16 ported the ladder onto both Workers, and each app now has a
 * behavioural suite that drives its own refusals over `SELF`:
 *
 *   gateway          `test/ratelimit/*` + `test/ratelimit/enforcement.spec.ts`
 *   apps/mcp         `test/admission.test.ts` (tools/call, tools/list)
 *   apps/agent-runtime `test/admission.test.ts` + `test/durable/admission.spec.ts`
 *
 * **Three green suites are not the property.** Each proves its own Worker
 * refuses; none proves the three refuse THE SAME WAY. A client that fails over
 * from a 429 on the gateway to a 403 on MCP — or to a `rate_limited` where the
 * gateway says `rate_limit_exceeded` — is looking at three different products,
 * and a `denied_by` that is a hard 403 deny on one Worker and a retryable 429
 * throttle on another is the same admission bug wearing a different response.
 * The consistency is the fix; this file is where it is asserted.
 *
 * ## Why it is a source-text gate
 *
 * The three tables live in three SEPARATELY BUNDLED Workers, and no app may
 * import another's module graph (that coupling is what `wrangler deploy` would
 * reject and what the repo's package boundaries forbid). So the tables are read
 * as TEXT — the same `?raw` inlining `test/env-var-drift.test.ts` uses, the
 * only way a workerd test with no filesystem can read source at all — and
 * compared as data. A drift in any one of the three files fails here.
 *
 * The scan is asserted non-vacuous before it is used: all three files must
 * parse to a non-empty table, so a rename that makes the regex match nothing
 * turns this red instead of silently asserting `{} === {}`.
 */
import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

const SOURCES = {
  gateway: import.meta.glob("../src/ratelimit/ports.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
  mcp: import.meta.glob("../../mcp/src/admission/gate.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
  "agent-runtime": import.meta.glob("../../agent-runtime/src/admission/admit.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
} as const;

function sourceOf(worker: keyof typeof SOURCES): string {
  const values = Object.values(SOURCES[worker]);
  if (values.length !== 1 || typeof values[0] !== "string" || values[0].length === 0) {
    throw new Error(
      `admission-consistency: expected exactly one source file for ${worker}, got ${values.length}`,
    );
  }
  return values[0];
}

/**
 * Every `status: N` / `code: "X"` pair in a refusal table, as `code → status`.
 *
 * The two fields are adjacent in all three files and in that order (`status`
 * then `code`), which is what makes one regex enough. Written to tolerate the
 * three DIFFERENT table shapes deliberately — the gateway and agent-runtime
 * spell a refusal as an object with a `message` FUNCTION, `apps/mcp` spells it
 * as a function RETURNING an object with a `message` string — because the
 * property under test is the wire contract, not the calling convention.
 */
function refusalStatuses(source: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const m of source.matchAll(/status:\s*(\d{3}),\s*\n\s*code:\s*"([a-z_]+)"/g)) {
    out.set(m[2] as string, Number(m[1]));
  }
  return out;
}

/**
 * The refusals every data-plane Worker must be able to produce, and the exact
 * wire answer each one is.
 *
 * These four ARE the admission ladder, in Rust's evaluation order. The 403 is
 * the one most worth pinning: `finalize_auth` treats a disabled policy as a
 * hard DENY and everything else as a THROTTLE, so a Worker that answered 429
 * here would tell a client to retry a request that can never succeed.
 */
const REQUIRED: ReadonlyMap<string, number> = new Map([
  ["quota_scope_disabled", 403],
  ["monthly_budget_exceeded", 429],
  ["wallet_balance_exhausted", 429],
  ["rate_limit_exceeded", 429],
]);

/** Lookup failures. Also shared, and deliberately 503 rather than 429. */
const REQUIRED_UNAVAILABLE: ReadonlyMap<string, number> = new Map([
  ["governance_counter_unavailable", 503],
]);

const WORKERS = ["gateway", "mcp", "agent-runtime"] as const;

describe("the admission refusal contract is identical on all three data-plane Workers", () => {
  it("read a real table out of each of the three Workers", () => {
    // Non-vacuity. If a rename made any of these regexes match nothing, every
    // assertion below would compare an empty map against an empty map and pass.
    for (const worker of WORKERS) {
      expect(refusalStatuses(sourceOf(worker)).size, `${worker} refusal table`).toBeGreaterThan(3);
    }
  });

  it.each(WORKERS)("%s answers every ladder refusal with the agreed status", (worker) => {
    const table = refusalStatuses(sourceOf(worker));
    for (const [code, status] of REQUIRED) {
      expect(table.get(code), `${worker} is missing the ${code} refusal`).toBe(status);
    }
    for (const [code, status] of REQUIRED_UNAVAILABLE) {
      expect(table.get(code), `${worker} is missing the ${code} refusal`).toBe(status);
    }
  });

  it("never disagrees on the status of a code two Workers share", () => {
    // Stronger than the table above, and the half that catches a refusal NOT
    // named in `REQUIRED`: any code present on more than one Worker must carry
    // the same status on every Worker that has it.
    const seen = new Map<string, Map<string, number>>();
    for (const worker of WORKERS) {
      for (const [code, status] of refusalStatuses(sourceOf(worker))) {
        const byWorker = seen.get(code) ?? new Map<string, number>();
        byWorker.set(worker, status);
        seen.set(code, byWorker);
      }
    }
    const disagreements = [...seen.entries()]
      .filter(([, byWorker]) => new Set(byWorker.values()).size > 1)
      .map(([code, byWorker]) => `${code}: ${JSON.stringify(Object.fromEntries(byWorker))}`);
    expect(disagreements).toEqual([]);
  });

  it("uses the SAME message text for each shared refusal", () => {
    // A client that switches surfaces must not see the reason change. The
    // messages are template literals in all three files, so they are compared
    // with the interpolations left in place — `${scopeKind}` on the gateway and
    // `${scopeKind}` on MCP are the same text; a reworded sentence is not.
    const messages = (source: string): Map<string, string> => {
      const out = new Map<string, string>();
      for (const m of source.matchAll(
        /code:\s*"([a-z_]+)",\s*\n\s*message:[^\n]*?(?:=>\s*)?\n?\s*(`[^`]*`|"[^"]*")/g,
      )) {
        out.set(m[1] as string, (m[2] as string).slice(1, -1));
      }
      return out;
    };
    const perWorker = WORKERS.map((w) => [w, messages(sourceOf(w))] as const);
    for (const [worker, table] of perWorker) {
      expect(table.size, `${worker} message scan`).toBeGreaterThan(3);
    }
    for (const code of REQUIRED.keys()) {
      const texts = perWorker.map(([worker, table]) => [worker, table.get(code)] as const);
      const distinct = new Set(texts.map(([, text]) => text));
      expect(
        distinct.size,
        `${code} is worded differently across Workers: ${JSON.stringify(texts)}`,
      ).toBe(1);
    }
  });

  it("derives the counter key from the ONE @ferrogate/policy site on all three", () => {
    // The security half of "one counter". `QuotaScopeSelector.counterKey` is
    // what turns a `key` winner into `key:{api_key_id}` rather than a raw,
    // tenant-controllable id — a tenant that mints the key id `tenant:victim`
    // must not be able to address the victim tenant's aggregate window. Three
    // Workers that each re-derived it would drift, and the drift would be a
    // cross-tenant counter collision rather than a test failure.
    const derivations = {
      gateway: import.meta.glob("../src/ratelimit/keys.ts", {
        query: "?raw",
        import: "default",
        eager: true,
      }),
      mcp: import.meta.glob("../../mcp/src/admission/counters.ts", {
        query: "?raw",
        import: "default",
        eager: true,
      }),
      "agent-runtime": import.meta.glob("../../agent-runtime/src/admission/keys.ts", {
        query: "?raw",
        import: "default",
        eager: true,
      }),
    } as const;
    for (const worker of WORKERS) {
      const text = Object.values(derivations[worker])[0];
      expect(typeof text, `${worker} counter-key source`).toBe("string");
      expect(text as string).toContain("@ferrogate/policy");
      expect(text as string).toContain("counterKey");
    }
  });
});
