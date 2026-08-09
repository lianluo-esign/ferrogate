/**
 * The `{ success, errors, messages, result, result_info }` envelope every
 * `client/v4` endpoint wraps its payload in — ported from
 * `crates/ferrogate-cloudflare/src/envelope.rs`.
 *
 * The load-bearing part is `result_info`: dropping it is why a list call could
 * silently answer with only its first page, and "absent" then really meant "not
 * on page 1". `nextCursor` normalises the two ways Cloudflare signals a last
 * page — an absent cursor and an EMPTY one — because treating `""` as a real
 * cursor loops forever.
 */
import { describe, expect, test } from "vitest";
import {
  decodeEnvelope,
  intoAck,
  intoResult,
  intoResultWithInfo,
  nextCursor,
} from "../src/envelope.js";

describe("decodeEnvelope", () => {
  test("decodes a full envelope", () => {
    const envelope = decodeEnvelope<{ id: string }>(
      JSON.stringify({
        success: true,
        errors: [],
        messages: [{ code: 1, message: "ok" }],
        result: { id: "db_1" },
        result_info: { page: 1, per_page: 20, count: 1, total_count: 1 },
      }),
      "test",
    );
    expect(envelope.success).toBe(true);
    expect(envelope.result).toEqual({ id: "db_1" });
    expect(envelope.resultInfo?.page).toBe(1);
    expect(envelope.messages).toEqual([{ code: 1, message: "ok" }]);
  });

  test("tolerates every optional field being absent", () => {
    const envelope = decodeEnvelope<unknown>("{}", "test");
    expect(envelope.success).toBe(false);
    expect(envelope.errors).toEqual([]);
    expect(envelope.messages).toEqual([]);
    expect(envelope.result).toBeUndefined();
    expect(envelope.resultInfo).toBeUndefined();
  });

  test("a non-JSON body is a decode error naming the context", () => {
    expect(() => decodeEnvelope("<html>502 Bad Gateway</html>", "preflight")).toThrowError(
      /cloudflare response decode error: failed to decode Cloudflare preflight envelope/,
    );
  });

  test("a JSON scalar body is a decode error, not a silent empty envelope", () => {
    expect(() => decodeEnvelope("null", "test")).toThrowError(/decode error/);
    expect(() => decodeEnvelope("[]", "test")).toThrowError(/decode error/);
  });

  test("error entries default their missing halves rather than dropping the entry", () => {
    const envelope = decodeEnvelope('{"errors":[{"code":9109},{"message":"x"}]}', "test");
    expect(envelope.errors).toEqual([
      { code: 9109, message: "" },
      { code: 0, message: "x" },
    ]);
  });
});

describe("nextCursor", () => {
  test("returns a real cursor", () => {
    expect(nextCursor({ cursor: "abc" })).toBe("abc");
  });

  test("an absent OR empty cursor both mean 'last page'", () => {
    expect(nextCursor({})).toBeUndefined();
    expect(nextCursor({ cursor: "" })).toBeUndefined();
    expect(nextCursor(undefined)).toBeUndefined();
  });
});

describe("intoResult", () => {
  test("a success envelope under a 2xx yields the result", () => {
    expect(intoResult({ success: true, errors: [], messages: [], result: 42 }, 200)).toBe(42);
  });

  test("success: true with a missing result is a decode error, not undefined", () => {
    expect(() => intoResult({ success: true, errors: [], messages: [] }, 200)).toThrowError(
      /expected a `result` body but it was absent/,
    );
  });

  test("success: true under a NON-2xx is still an error", () => {
    // The status is authoritative: a body claiming success under a 500 is not a
    // success.
    expect(() =>
      intoResult({ success: true, errors: [], messages: [], result: 1 }, 500),
    ).toThrowError(/cloudflare API error \(HTTP 500\)/);
  });

  test("success: false under a 200 is an error, and the codes classify it", () => {
    // Cloudflare really does answer a duplicate R2 create with 200 + 10004.
    expect(() =>
      intoResult(
        {
          success: false,
          errors: [{ code: 10004, message: "already exists" }],
          messages: [],
        },
        200,
      ),
    ).toThrowError(/cloudflare API error \(HTTP 200\): \[10004\] already exists/);
  });

  test("the HTTP retry-after reaches the mapped rate-limit error", () => {
    try {
      intoResult({ success: false, errors: [], messages: [] }, 429, 9_000);
      throw new Error("unreachable");
    } catch (error) {
      expect((error as { retryAfterMs?: number }).retryAfterMs).toBe(9_000);
    }
  });
});

describe("intoResultWithInfo", () => {
  test("hands back the pagination metadata alongside the result", () => {
    const { result, resultInfo } = intoResultWithInfo<number>(
      {
        success: true,
        errors: [],
        messages: [],
        result: 7,
        resultInfo: { cursor: "next-page" },
      },
      200,
    );
    expect(result).toBe(7);
    expect(resultInfo?.cursor).toBe("next-page");
  });
});

describe("intoAck", () => {
  test("a success envelope with a null result is an ack, not a decode error", () => {
    expect(() => intoAck({ success: true, errors: [], messages: [] }, 200)).not.toThrow();
  });

  test("a failure envelope is still classified", () => {
    expect(() =>
      intoAck({ success: false, errors: [{ code: 9109, message: "nope" }], messages: [] }, 403),
    ).toThrowError(/missing a required permission group/);
  });
});
