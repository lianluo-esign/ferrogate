import { rustDebugStr, samlError } from "./errors.js";

/**
 * SAML/XSD UTC `dateTime` handling, ported from `saml.rs`.
 *
 * `Date.parse` is deliberately NOT used. It accepts local times, offsets, and a
 * long tail of implementation-defined formats, and silently interprets a
 * missing `Z` as local time — which would slide every `NotBefore`/
 * `NotOnOrAfter` window by the runtime's offset. The Rust port refuses anything
 * without a trailing `Z`, and so does this.
 *
 * The civil-date arithmetic is Howard Hinnant's algorithm, the same one the
 * Rust port used, reproduced here rather than delegated to `Date` so the two
 * ports compute the same number from the same string. (`test/instant.test.ts`
 * cross-checks it against `Date` anyway, which is how you find out that a
 * hand-rolled calendar is wrong.)
 */

/** Days from the civil date to the Unix epoch. */
export function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor((y >= 0 ? y : y - 399) / 400);
  const yearOfEra = y - era * 400;
  const dayOfYear = Math.floor((153 * (month > 2 ? month - 3 : month + 9) + 2) / 5) + day - 1;
  const dayOfEra =
    yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}

export function civilFromDays(days: number): [number, number, number] {
  const z = days + 719_468;
  const era = Math.floor((z >= 0 ? z : z - 146_096) / 146_097);
  const dayOfEra = z - era * 146_097;
  const yearOfEra = Math.floor(
    (dayOfEra -
      Math.floor(dayOfEra / 1460) +
      Math.floor(dayOfEra / 36_524) -
      Math.floor(dayOfEra / 146_096)) /
      365,
  );
  const year = yearOfEra + era * 400;
  const dayOfYear =
    dayOfEra - (365 * yearOfEra + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100));
  const mp = Math.floor((5 * dayOfYear + 2) / 153);
  const day = dayOfYear - Math.floor((153 * mp + 2) / 5) + 1;
  const month = mp < 10 ? mp + 3 : mp - 9;
  return [month <= 2 ? year + 1 : year, month, day];
}

function pad(value: number, width: number): string {
  return String(value).padStart(width, "0");
}

/** `saml.rs::format_saml_instant` — `YYYY-MM-DDTHH:MM:SSZ`. */
export function formatSamlInstant(unix: number): string {
  const days = Math.floor(unix / 86_400);
  const seconds = unix - days * 86_400;
  const [year, month, day] = civilFromDays(days);
  const hour = Math.floor(seconds / 3600);
  const minute = Math.floor((seconds % 3600) / 60);
  const second = seconds % 60;
  return `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}T${pad(hour, 2)}:${pad(minute, 2)}:${pad(second, 2)}Z`;
}

function parseField(part: string | undefined, name: string): number {
  if (part === undefined) {
    throw samlError("saml_instant_missing_field", `SAML instant is missing the ${name}`);
  }
  // Rust's `str::parse::<i64>` accepts an optional sign and digits ONLY — no
  // whitespace, no `0x`, no exponent, no empty string. `Number.parseInt` accepts
  // all of those and stops at the first junk character, so it is not a
  // substitute: `parseInt("12abc")` is 12.
  if (!/^[+-]?[0-9]+$/.test(part)) {
    throw samlError(
      "saml_instant_invalid_field",
      `SAML instant has an invalid ${name}: invalid digit found in string`,
    );
  }
  return Number(part);
}

/**
 * `saml.rs::parse_saml_instant` — requires the trailing `Z`; fractional
 * seconds are tolerated and ignored. Fails closed on anything else.
 */
export function parseSamlInstant(value: string): number {
  const trimmed = value.trim();
  if (!trimmed.endsWith("Z")) {
    throw samlError(
      "saml_instant_not_utc",
      `SAML instant ${rustDebugStr(trimmed)} is not UTC (missing trailing Z)`,
    );
  }
  const stripped = trimmed.slice(0, -1);
  const separator = stripped.indexOf("T");
  if (separator < 0) {
    throw samlError(
      "saml_instant_missing_time",
      `SAML instant ${rustDebugStr(trimmed)} is missing the time component`,
    );
  }
  const date = stripped.slice(0, separator);
  const time = stripped.slice(separator + 1).split(".")[0] ?? "";

  const dateParts = date.split("-");
  const year = parseField(dateParts[0], "year");
  const month = parseField(dateParts[1], "month");
  const day = parseField(dateParts[2], "day");

  const timeParts = time.split(":");
  const hour = parseField(timeParts[0], "hour");
  const minute = parseField(timeParts[1], "minute");
  const second = parseField(timeParts[2], "second");

  if (month < 1 || month > 12 || day < 1 || day > 31) {
    throw samlError(
      "saml_instant_out_of_range",
      `SAML instant ${rustDebugStr(trimmed)} has an out-of-range date`,
    );
  }

  return daysFromCivil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
}
