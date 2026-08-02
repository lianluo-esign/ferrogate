import { describe, expect, test } from "vitest";
import {
  byteLen,
  byteMatchIndices,
  byteOffsetMap,
  byteSlice,
  isCharBoundary,
} from "../src/bytes.js";

describe("byteLen / byteSlice with multibyte text", () => {
  test("emoji byte length and slice", () => {
    const s = "aé\u{1f600}b"; // a, é (2 bytes), 😀 (4 bytes), b
    expect(byteLen(s)).toBe(1 + 2 + 4 + 1);
    // Slice out just the 'é' (bytes 1..3).
    expect(byteSlice(s, 1, 3)).toBe("é");
  });
});

describe("isCharBoundary", () => {
  test("boundaries around a 2-byte char", () => {
    const s = "éx"; // é occupies bytes 0..2
    expect(isCharBoundary(s, 0)).toBe(true);
    expect(isCharBoundary(s, 1)).toBe(false); // mid-é continuation byte
    expect(isCharBoundary(s, 2)).toBe(true);
    expect(isCharBoundary(s, 3)).toBe(true); // end
  });
});

describe("byteMatchIndices", () => {
  test("non-overlapping byte offsets, multibyte-aware", () => {
    const s = "éAKIAéAKIA"; // é (2 bytes) then AKIA, twice
    expect(byteMatchIndices(s, "AKIA")).toEqual([2, 8]);
  });

  test("empty needle yields nothing", () => {
    expect(byteMatchIndices("abc", "")).toEqual([]);
  });
});

describe("byteOffsetMap", () => {
  test("maps code-unit index to byte offset", () => {
    const s = "aéb";
    const map = byteOffsetMap(s);
    expect(map[0]).toBe(0);
    expect(map[1]).toBe(1);
    expect(map[2]).toBe(3);
    expect(map[3]).toBe(4);
  });
});
