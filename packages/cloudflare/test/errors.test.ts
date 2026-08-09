/**
 * The typed Cloudflare error taxonomy — ported 1:1 from
 * `crates/ferrogate-cloudflare/src/error.rs`.
 *
 * Two of these tests exist because the Rust tree got them WRONG first and paid
 * for it (`cf-crate-assessment.md` §5.4). They pin the traps, not just the
 * happy path:
 *
 *  - `10013` must NOT classify as a rate limit. It is `IncompleteBody` in R2
 *    (HTTP 400 — a truncated request body, which can never succeed on retry)
 *    and `workers.api.error.unknown` (HTTP 500) in the general `client/v4`
 *    namespace. An earlier Rust version matched it numerically, so a truncated
 *    upload was reported to the operator as "rate limited".
 *  - `10058` must not be matched numerically EITHER, even though it really is
 *    R2's `TooManyRequests`: it always arrives with HTTP 429, which already
 *    classifies it, and in Cloudflare's Lists/Bulk-Redirect namespace `10058`
 *    means "list items incompatible with list type" (HTTP 400).
 *
 * Classification precedence is `429` → missing-scope → (`401`/`403` or auth
 * codes) → generic API error.
 */
import { describe, expect, test } from "vitest";
import { AUTHENTICATION_CODES, CloudflareError, MISSING_SCOPE_CODES } from "../src/errors.js";
import { REQUIRED_TOKEN_PERMISSION_GROUPS } from "../src/scopes.js";

describe("code tables", () => {
  test("the missing-scope and authentication code sets are the Rust ones, verbatim", () => {
    expect([...MISSING_SCOPE_CODES]).toEqual([9103, 9107, 9109]);
    expect([...AUTHENTICATION_CODES]).toEqual([1000, 9106, 10000]);
  });

  test("the two audited traps are absent from both tables", () => {
    for (const table of [MISSING_SCOPE_CODES, AUTHENTICATION_CODES]) {
      expect(table).not.toContain(10013);
      expect(table).not.toContain(10058);
    }
  });
});

describe("CloudflareError.fromResponse — classification precedence", () => {
  test("429 is a rate limit and carries the server's Retry-After", () => {
    const error = CloudflareError.fromResponse(429, 7000, []);
    expect(error.kind).toBe("rate_limited");
    expect(error.retryAfterMs).toBe(7000);
  });

  test("429 wins over a missing-scope code present in the same envelope", () => {
    const error = CloudflareError.fromResponse(429, undefined, [
      { code: 9109, message: "Unauthorized to access requested resource" },
    ]);
    expect(error.kind).toBe("rate_limited");
  });

  test("a missing-scope code names every required permission group", () => {
    const error = CloudflareError.fromResponse(403, undefined, [
      { code: 9109, message: "Unauthorized to access requested resource" },
    ]);
    expect(error.kind).toBe("missing_scope");
    expect([...(error.requiredPermissionGroups ?? [])]).toEqual(
      REQUIRED_TOKEN_PERMISSION_GROUPS.map((group) => group.name),
    );
    expect(error.message).toContain("grant the token these permission groups");
    expect(error.message).toContain("Workers R2 Storage");
  });

  test("a missing-scope code beats the bare 403 status branch", () => {
    // Both branches match a 403 + 9103; precedence says missing_scope, because
    // "under-scoped" is actionable and "unauthorized" is not.
    const error = CloudflareError.fromResponse(403, undefined, [
      { code: 9103, message: "Unknown X-Auth-Key or X-Auth-Email" },
    ]);
    expect(error.kind).toBe("missing_scope");
  });

  test("401/403 with no recognised code is an authentication failure", () => {
    expect(CloudflareError.fromResponse(401, undefined, []).kind).toBe("unauthorized");
    expect(CloudflareError.fromResponse(403, undefined, []).kind).toBe("unauthorized");
  });

  test("an authentication code classifies even under a 200", () => {
    const error = CloudflareError.fromResponse(200, undefined, [
      { code: 9106, message: "Missing X-Auth-Key" },
    ]);
    expect(error.kind).toBe("unauthorized");
  });

  test("TRAP 1: 10013 under a 400 is a client error, NOT a rate limit", () => {
    const error = CloudflareError.fromResponse(400, undefined, [
      { code: 10013, message: "IncompleteBody" },
    ]);
    expect(error.kind).toBe("api");
    expect(error.status).toBe(400);
    expect(error.kind).not.toBe("rate_limited");
  });

  test("TRAP 1b: 10013 under a 500 is a generic API error, NOT a rate limit", () => {
    const error = CloudflareError.fromResponse(500, undefined, [
      { code: 10013, message: "workers.api.error.unknown" },
    ]);
    expect(error.kind).toBe("api");
  });

  test("TRAP 2: 10058 under a 400 (Lists namespace) is NOT a rate limit", () => {
    const error = CloudflareError.fromResponse(400, undefined, [
      { code: 10058, message: "list items incompatible with list type" },
    ]);
    expect(error.kind).toBe("api");
  });

  test("TRAP 2b: 10058 under its real 429 IS a rate limit — via the status alone", () => {
    const error = CloudflareError.fromResponse(429, undefined, [
      { code: 10058, message: "TooManyRequests" },
    ]);
    expect(error.kind).toBe("rate_limited");
  });

  test("an unclassified non-2xx is a generic API error carrying status and codes", () => {
    const error = CloudflareError.fromResponse(409, undefined, [
      { code: 10004, message: "The bucket you tried to create already exists, and you own it." },
    ]);
    expect(error.kind).toBe("api");
    expect(error.status).toBe(409);
    expect(error.errors.map((e) => e.code)).toEqual([10004]);
  });
});

describe("retryability", () => {
  test("only transport and rate-limit errors are retryable", () => {
    expect(CloudflareError.transport("connect reset").retryable).toBe(true);
    expect(CloudflareError.fromResponse(429, undefined, []).retryable).toBe(true);

    expect(CloudflareError.fromResponse(500, undefined, []).retryable).toBe(false);
    expect(CloudflareError.fromResponse(403, undefined, []).retryable).toBe(false);
    expect(CloudflareError.config("bad base url").retryable).toBe(false);
    expect(CloudflareError.decode("not json").retryable).toBe(false);
    expect(CloudflareError.tokenResolution("no such env var").retryable).toBe(false);
  });
});

describe("messages", () => {
  test("every variant renders the Rust message shape", () => {
    expect(CloudflareError.config("m").message).toBe("cloudflare config error: m");
    expect(CloudflareError.tokenResolution("m").message).toBe(
      "cloudflare token resolution error: m",
    );
    expect(CloudflareError.transport("m").message).toBe("cloudflare transport error: m");
    expect(CloudflareError.decode("m").message).toBe("cloudflare response decode error: m");
    expect(CloudflareError.fromResponse(500, undefined, []).message).toBe(
      "cloudflare API error (HTTP 500): no error detail",
    );
    expect(
      CloudflareError.fromResponse(500, undefined, [
        { code: 7003, message: "Could not route" },
        { code: 7000, message: "No route" },
      ]).message,
    ).toBe("cloudflare API error (HTTP 500): [7003] Could not route; [7000] No route");
  });

  test("a rate-limit message reports attempts and the retry-after in seconds", () => {
    const error = CloudflareError.rateLimited(7000, 5);
    expect(error.message).toBe("cloudflare rate limit hit after 5 attempt(s) (retry-after 7s)");
    expect(CloudflareError.rateLimited(undefined, 1).message).toBe(
      "cloudflare rate limit hit after 1 attempt(s)",
    );
  });

  test("an exhausted-retries error nests the last failure's message", () => {
    const error = CloudflareError.exhaustedRetries(3, CloudflareError.transport("timed out"));
    expect(error.kind).toBe("exhausted_retries");
    expect(error.attempts).toBe(3);
    expect(error.message).toBe(
      "cloudflare request failed after 3 attempt(s): cloudflare transport error: timed out",
    );
  });

  test("errors are real Errors and keep a stable name for instanceof-free checks", () => {
    const error = CloudflareError.config("m");
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("CloudflareError");
  });
});
