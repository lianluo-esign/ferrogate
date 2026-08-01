/**
 * THE FLEET-WIDE HEALTH-DOCUMENT CONTRACT, DERIVED MECHANICALLY.
 *
 * ## The defect this closes
 *
 * `docs/rewrite/cert2-dataplane.md` finding **A11** records that `/healthz`
 * omits `version` — Rust's `HealthResponse` is `{status, service, version,
 * runtime}` (`crates/ferrogate-gateway/src/responses.rs:69-74`, filled from
 * `env!("CARGO_PKG_VERSION")`) — and names **`apps/mcp`** as the one Worker
 * affected. The wave-19 boot proof (`docs/rewrite/CUTOVER-READINESS.md` §3.3)
 * found it missing on **three**: `mcp`, `control-plane` AND `telemetry`. The
 * finding was correct in kind and understated by 2×.
 *
 * That understatement is the actual thing being fixed here. Adding `version` to
 * three files is a ten-minute edit; the reason it was wrong in a certification
 * document is that **every Worker wrote its own health document by hand and
 * nothing compared them**. `apps/gateway/test/health.test.ts` pins the gateway's
 * four fields, `apps/mcp/test/health.test.ts` pins the MCP document against
 * `healthReport()` — its own function, so it agrees with itself by construction
 * — and no test in the repository had ever seen two Workers' documents at the
 * same time. A per-Worker gate cannot catch a per-Worker divergence.
 *
 * ## Why this file is not a list
 *
 * Both sides are DERIVED:
 *
 *  1. the FLEET comes from globbing `apps/*​/wrangler.toml` — a Worker is a
 *     directory with a deploy config, so a sixth Worker is covered the moment it
 *     is created, and it cannot be omitted by forgetting to add a row here;
 *  2. the DOCUMENT comes from globbing every `apps/*​/src/**​/*.ts` and pulling
 *     the object literal out of the source, so a Worker that moves its handler
 *     to a new file stays covered.
 *
 * The only hand-written things are {@link CONTRACT_HEALTH_MEMBERS} — which IS
 * the contract, transcribed from the Rust struct — and one exception list, and
 * that list is asserted with `toEqual` on the exact computed set so it cannot
 * quietly grow.
 *
 * `?raw` is a VITE transform: the file's real bytes are inlined at build time,
 * which is the only way a workerd test (no filesystem) can read another app's
 * source at all. Same mechanism as `test/env-var-drift.test.ts` and
 * `apps/gateway/test/source-nul-bytes.test.ts`.
 *
 * ## Why it lives in `apps/telemetry`
 *
 * It has to live in exactly one workspace (duplicating it five times would
 * reintroduce the per-Worker divergence it exists to prevent), and it must run
 * on `bun run test`, which is `bun run --filter '*' test`. `apps/telemetry` is
 * the smallest suite, so the cost of inlining every app's sources is paid where
 * it is cheapest. Nothing about the gate is telemetry-specific.
 *
 * ## What this gate does NOT claim
 *
 * It is a SOURCE gate, not a behavioural one: it proves the five documents are
 * declared identically, not that each is served. The behavioural half is the
 * per-app test that drives `SELF.fetch("/healthz")` and compares the response to
 * the document — `test/health.test.ts` in this app, and its sibling in each of
 * the other four. Both halves are needed and neither subsumes the other: this
 * one sees across Workers and cannot see mounting; those see mounting and cannot
 * see across Workers.
 */
import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

const WRANGLER_CONFIGS = import.meta.glob("../../*/wrangler.toml", {
  query: "?raw",
  import: "default",
  eager: true,
});

const APP_SOURCES = import.meta.glob("../../*/src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

/**
 * Rust `HealthResponse` (`crates/ferrogate-gateway/src/responses.rs:69`), in
 * its declaration order. `serde` serialises struct fields in declaration order,
 * so this is the member ORDER an operator's `curl /healthz` produced against a
 * Rust deployment, not just the member set.
 */
const CONTRACT_HEALTH_MEMBERS = ["status", "service", "version", "runtime"] as const;

/**
 * The identity members Rust's `ReadinessResponse` shares with `HealthResponse`
 * (`responses.rs:77`). Readiness additionally carries a per-Worker DETAIL member
 * (`cluster` in Rust and in the gateway, `dependencies` in agent-runtime and
 * mcp, `sink` in telemetry) which is deliberately NOT unified: the detail is the
 * thing each Worker can actually answer about itself.
 */
const CONTRACT_READINESS_IDENTITY = ["status", "service", "version", "runtime"] as const;

/**
 * The app a glob key belongs to.
 *
 * Vite normalises glob keys against the IMPORTING file, so this app's own
 * entries come back as `../wrangler.toml` and `../src/app.ts` while its
 * siblings come back as `../../mcp/src/...`. Resolving the `..` segments against
 * this file's own directory is what makes the two spellings the same thing —
 * without it `apps/telemetry` is silently absent from the fleet and its
 * documents are never checked, which is precisely the per-Worker blind spot this
 * file exists to remove.
 */
const THIS_FILE_DIRECTORY = ["apps", "telemetry", "test"] as const;

function appOf(globPath: string): string {
  const stack: string[] = [...THIS_FILE_DIRECTORY];
  for (const segment of globPath.split("/")) {
    if (segment === "..") stack.pop();
    else if (segment !== "." && segment !== "") stack.push(segment);
  }
  if (stack[0] !== "apps" || stack.length < 3) {
    throw new Error(`glob key outside apps/: ${globPath} -> ${stack.join("/")}`);
  }
  return stack[1] as string;
}

/** `apps/<name>` for every directory carrying a Worker deploy config. */
const WORKER_APPS: readonly string[] = Object.keys(WRANGLER_CONFIGS).map(appOf).sort();

// ---------------------------------------------------------------------------
// A small source reader. Enough TypeScript to find an object literal and list
// its top-level members; deliberately not a parser.
// ---------------------------------------------------------------------------

/** `true` when this line is prose — a `//` comment or a JSDoc continuation. */
function isCommentLine(line: string): boolean {
  const trimmed = line.trimStart();
  return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*");
}

/** Index just past the string literal opening at `start`. */
function skipString(source: string, start: number): number {
  const quote = source[start];
  let i = start + 1;
  while (i < source.length) {
    if (source[i] === "\\") {
      i += 2;
      continue;
    }
    if (source[i] === quote) return i + 1;
    i += 1;
  }
  return i;
}

/**
 * The object literal that ENCLOSES `anchor`, braces included.
 *
 * The anchor is always the `status:` member, and in every one of these handlers
 * only whitespace separates it from the `{` that opens the document, so walking
 * backwards to the nearest unbalanced `{` is exact rather than heuristic.
 */
function enclosingObjectLiteral(source: string, anchor: number): string {
  let depth = 0;
  let open = -1;
  for (let i = anchor; i >= 0; i -= 1) {
    const ch = source[i];
    if (ch === "}") depth += 1;
    else if (ch === "{") {
      if (depth === 0) {
        open = i;
        break;
      }
      depth -= 1;
    }
  }
  if (open === -1) throw new Error("no enclosing object literal for the health document anchor");

  let i = open + 1;
  let braces = 1;
  while (i < source.length) {
    const ch = source[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      i = skipString(source, i);
      continue;
    }
    if (ch === "/" && source[i + 1] === "/") {
      while (i < source.length && source[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && source[i + 1] === "*") {
      const end = source.indexOf("*/", i + 2);
      i = end === -1 ? source.length : end + 2;
      continue;
    }
    if (ch === "{") braces += 1;
    else if (ch === "}") {
      braces -= 1;
      if (braces === 0) return source.slice(open, i + 1);
    }
    i += 1;
  }
  throw new Error("unterminated object literal for the health document anchor");
}

/** The member names of an object literal, in source order. */
function topLevelMembers(literal: string): string[] {
  const body = literal.slice(1, -1);
  const members: string[] = [];
  let depth = 0;
  let expectKey = true;
  let i = 0;

  while (i < body.length) {
    const ch = body[i] as string;
    if (ch === '"' || ch === "'" || ch === "`") {
      i = skipString(body, i);
      continue;
    }
    if (ch === "/" && body[i + 1] === "/") {
      while (i < body.length && body[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && body[i + 1] === "*") {
      const end = body.indexOf("*/", i + 2);
      i = end === -1 ? body.length : end + 2;
      continue;
    }
    if (ch === "{" || ch === "[" || ch === "(") {
      depth += 1;
      i += 1;
      continue;
    }
    if (ch === "}" || ch === "]" || ch === ")") {
      depth -= 1;
      i += 1;
      continue;
    }
    if (depth === 0 && ch === ",") {
      expectKey = true;
      i += 1;
      continue;
    }
    if (expectKey && !/\s/.test(ch)) {
      const named = /^(?:"([^"]+)"|'([^']+)'|([A-Za-z_$][\w$]*))/.exec(body.slice(i));
      if (named) {
        members.push((named[1] ?? named[2] ?? named[3]) as string);
        i += named[0].length;
      } else {
        i += 1;
      }
      expectKey = false;
      continue;
    }
    i += 1;
  }
  return members;
}

/** Every source file of one app, as `[glob key, file bytes]`. */
function sourcesOf(app: string): [string, string][] {
  return Object.entries(APP_SOURCES).filter(([path]) => appOf(path) === app);
}

/**
 * Every object literal in one app whose `status:` member matches `anchor`,
 * with the file it came from — so a failure names the file to edit.
 *
 * Anchors match a VALUE position only. An interface declaration spells the same
 * thing with a `;` (`readonly status: "ok";`), so the type and the document
 * cannot be confused for one another, and lines that are prose are dropped
 * before matching so a JSDoc example cannot register as an implementation.
 */
function documentsIn(app: string, anchor: RegExp): { file: string; members: string[] }[] {
  const found: { file: string; members: string[] }[] = [];
  for (const [path, source] of sourcesOf(app)) {
    const scannable = source
      .split("\n")
      .map((line) => (isCommentLine(line) ? "" : line))
      .join("\n");
    const pattern = new RegExp(anchor.source, "g");
    let match = pattern.exec(scannable);
    while (match !== null) {
      found.push({
        file: path,
        members: topLevelMembers(enclosingObjectLiteral(scannable, match.index)),
      });
      match = pattern.exec(scannable);
    }
  }
  return found;
}

/** `status: "ok",` — the health document, in a value position. */
const HEALTH_ANCHOR = /status:\s*"ok"\s*,/;

/** `status: <expr> ? "ready" : "not_ready",` — the readiness document. */
const READINESS_ANCHOR = /status:\s*[^{};]*\?\s*"ready"\s*:\s*"not_ready"\s*,/;

function healthDocumentOf(app: string): { file: string; members: string[] } {
  const documents = documentsIn(app, HEALTH_ANCHOR);
  expect(documents.length, `apps/${app} must declare exactly ONE health document`).toBe(1);
  return documents[0] as { file: string; members: string[] };
}

function readinessDocumentOf(app: string): { file: string; members: string[] } {
  const documents = documentsIn(app, READINESS_ANCHOR);
  expect(documents.length, `apps/${app} must declare exactly ONE readiness document`).toBe(1);
  return documents[0] as { file: string; members: string[] };
}

// ---------------------------------------------------------------------------

describe("the fleet the gate runs over", () => {
  /**
   * Without this the whole file is vacuous: a glob that matches nothing makes
   * every `for (const app of WORKER_APPS)` body a no-op and the suite passes
   * green while checking nothing. FerroGate has shipped that exact failure —
   * see `docs/rewrite/TESTING.md` on assertions that cannot fail.
   */
  it("discovers every Worker from its deploy config, not from a list here", () => {
    expect(WORKER_APPS.length).toBeGreaterThanOrEqual(5);
    expect(Object.keys(APP_SOURCES).length).toBeGreaterThan(100);
    for (const app of WORKER_APPS) {
      expect(sourcesOf(app).length, `apps/${app} contributed no sources`).toBeGreaterThan(0);
    }
  });
});

describe("GET /healthz — one document shape for the whole fleet", () => {
  it.each(WORKER_APPS)("apps/%s declares Rust's four HealthResponse members", (app) => {
    const document = healthDocumentOf(app);
    expect(document.members, `${document.file} drifts from HealthResponse`).toEqual([
      ...CONTRACT_HEALTH_MEMBERS,
    ]);
  });

  /**
   * The A11 finding itself, stated so a regression names it. Kept SEPARATE from
   * the shape assertion above because the shape assertion would also fail for a
   * Worker that added a member, and a certification reader needs to be able to
   * tell "someone dropped `version` again" from "someone added a field".
   */
  it("no Worker omits `version` (cert2-dataplane A11)", () => {
    const omitting = WORKER_APPS.filter(
      (app) => !healthDocumentOf(app).members.includes("version"),
    );
    expect(omitting).toEqual([]);
  });
});

describe("GET /readyz — the same identity members, plus a per-Worker detail", () => {
  /**
   * A readiness probe that cannot answer `not_ready` is a constant, and a
   * constant pointed at a load balancer is worse than no probe: wave 17 fixed
   * exactly that on `apps/agent-runtime` (a flat `{"ok":true}` that "gets ready
   * from a Worker that cannot serve, forever"), and `apps/control-plane` shipped
   * the same lie as a hard-coded `status: "ready"`.
   *
   * Requiring the document to be built from a `? "ready" : "not_ready"`
   * TERNARY is what makes that unrepeatable: a Worker that hard-codes either arm
   * has no matching document at all and `readinessDocumentOf` fails.
   */
  it.each(WORKER_APPS)("apps/%s decides readiness rather than asserting it", (app) => {
    expect(readinessDocumentOf(app).members[0]).toBe("status");
  });

  it.each(WORKER_APPS)("apps/%s reports the identity members in contract order", (app) => {
    const document = readinessDocumentOf(app);
    const identity = document.members.filter((member) =>
      (CONTRACT_READINESS_IDENTITY as readonly string[]).includes(member),
    );
    // `version` is allowed to be absent ONLY for the apps named in the
    // exception assertion below; everything else about the order is exact.
    expect(identity, `${document.file} reorders or drops an identity member`).toEqual(
      CONTRACT_READINESS_IDENTITY.filter(
        (member) => member !== "version" || document.members.includes("version"),
      ),
    );
  });

  it.each(WORKER_APPS)("apps/%s carries a detail member of its own", (app) => {
    const document = readinessDocumentOf(app);
    const detail = document.members.filter(
      (member) => !(CONTRACT_READINESS_IDENTITY as readonly string[]).includes(member),
    );
    expect(detail.length, `${document.file} reports readiness with no evidence`).toBeGreaterThan(0);
  });

  /**
   * THE EXCEPTION TABLE, computed rather than declared.
   *
   * `apps/gateway`'s `/readyz` is the one document in the fleet that still omits
   * `version`: `readinessResponse` (`apps/gateway/src/routes/readiness.ts:170`)
   * answers `{status, service, runtime, cluster}` where Rust's
   * `ReadinessResponse` also carries it. That file is OUTSIDE the owned scope of
   * the slice that wrote this gate, so it is recorded here instead of edited —
   * and recorded as the exact computed set, so that
   *
   *   - a fourth Worker regressing lands in this list and fails, and
   *   - fixing the gateway ALSO fails, forcing the exception to be deleted
   *     rather than left behind as folklore.
   */
  it("records the one known gap exactly, and nothing else", () => {
    const omitting = WORKER_APPS.filter(
      (app) => !readinessDocumentOf(app).members.includes("version"),
    );
    expect(omitting).toEqual(["gateway"]);
  });
});
