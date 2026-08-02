import { describe, expect, test } from "vitest";
import { SamlError, formatSamlInstant, parseSamlInstant } from "../src/index.js";

function refusal(value: string, code: string): SamlError {
  let caught: unknown = null;
  try {
    parseSamlInstant(value);
  } catch (error) {
    caught = error;
  }
  expect(caught, `${value} must be REFUSED`).toBeInstanceOf(SamlError);
  const samlError = caught as SamlError;
  expect(samlError.code).toBe(code);
  return samlError;
}

describe("SAML/XSD dateTime parsing (fail-closed)", () => {
  test("UTC instants parse to the right Unix second", () => {
    expect(parseSamlInstant("1970-01-01T00:00:00Z")).toBe(0);
    expect(parseSamlInstant("2024-01-01T00:00:00Z")).toBe(1_704_067_200);
    expect(parseSamlInstant("2024-02-29T12:34:56Z")).toBe(1_709_210_096);
    expect(parseSamlInstant("2000-02-29T00:00:00Z")).toBe(951_782_400);
    expect(parseSamlInstant("1999-12-31T23:59:59Z")).toBe(946_684_799);
  });

  test("fractional seconds are tolerated and ignored", () => {
    expect(parseSamlInstant("2024-01-01T00:00:00.123Z")).toBe(1_704_067_200);
  });

  test("surrounding whitespace is trimmed", () => {
    expect(parseSamlInstant("  2024-01-01T00:00:00Z  ")).toBe(1_704_067_200);
  });

  test("a NON-UTC instant is refused rather than assumed local", () => {
    // An implementation that shrugged and treated this as UTC would silently
    // shift every validity window by the offset.
    refusal("2024-01-01T00:00:00", "saml_instant_not_utc");
    refusal("2024-01-01T00:00:00+01:00", "saml_instant_not_utc");
    refusal("2024-01-01T00:00:00-05:00", "saml_instant_not_utc");
  });

  test("a date with no time component is refused", () => {
    refusal("2024-01-01Z", "saml_instant_missing_time");
  });

  test("a missing field is refused", () => {
    refusal("2024-01T00:00:00Z", "saml_instant_missing_field");
    refusal("2024-01-01T00:00Z", "saml_instant_missing_field");
  });

  test("a non-numeric field is refused", () => {
    refusal("not-a-timestamp", "saml_instant_not_utc");
    refusal("yyyy-01-01T00:00:00Z", "saml_instant_invalid_field");
    refusal("2024-xx-01T00:00:00Z", "saml_instant_invalid_field");
  });

  test("an out-of-range month or day is refused", () => {
    refusal("2024-13-01T00:00:00Z", "saml_instant_out_of_range");
    refusal("2024-00-01T00:00:00Z", "saml_instant_out_of_range");
    refusal("2024-01-32T00:00:00Z", "saml_instant_out_of_range");
    refusal("2024-01-00T00:00:00Z", "saml_instant_out_of_range");
  });

  test("formatting is the inverse of parsing", () => {
    for (const instant of [
      "1970-01-01T00:00:00Z",
      "2024-01-01T00:00:00Z",
      "2024-02-29T12:34:56Z",
      "2099-12-31T23:59:59Z",
    ]) {
      expect(formatSamlInstant(parseSamlInstant(instant))).toBe(instant);
    }
  });

  test("formatting matches the platform Date for a spread of instants", () => {
    // The civil-days arithmetic is hand-rolled (Howard Hinnant's algorithm, as
    // in the Rust port). Cross-checking it against a completely independent
    // implementation is the only way to know it is right.
    for (let index = 0; index < 500; index += 1) {
      const unix = index * 86_413 + 1_000_000;
      expect(formatSamlInstant(unix)).toBe(`${new Date(unix * 1000).toISOString().slice(0, 19)}Z`);
      expect(parseSamlInstant(formatSamlInstant(unix))).toBe(unix);
    }
  });
});
