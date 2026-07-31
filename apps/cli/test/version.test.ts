/**
 * The fail-closed contract-version gate (`src/version.ts`).
 *
 * Port of `ferrogate-control-plane-client::version`'s own unit tests plus the
 * wiring the Rust `ops_cmd::status` had at step 5. Two halves are covered:
 * the pure calendar-version algebra, and the fact that the gate is actually
 * REACHED on the status read — a gate nothing calls is the vacuous-green
 * failure mode this repo is prone to.
 */
import { describe, expect, test } from "vitest";
import { exitCode } from "../src/errors.js";
import { main } from "../src/index.js";
import {
  MIN_SUPPORTED_API_VERSION,
  checkCompatibility,
  compareCalendarVersions,
  enforceContractVersion,
  parseCalendarVersion,
} from "../src/version.js";
import { createTestRuntime, ok } from "./helpers.js";

describe("calendar version parsing", () => {
  test("parses and orders YYYY.M.D", () => {
    const older = parseCalendarVersion("2026.6.22");
    const newer = parseCalendarVersion("2026.7.9");
    expect(older).toEqual({ year: 2026, month: 6, day: 22 });
    expect(compareCalendarVersions(older, newer)).toBeLessThan(0);
    expect(compareCalendarVersions(newer, older)).toBeGreaterThan(0);
    expect(compareCalendarVersions(older, older)).toBe(0);
  });

  test("month outranks day, and year outranks both", () => {
    // 2026.7.1 is NEWER than 2026.6.30 even though its day number is smaller,
    // which a naive lexicographic or day-first comparison gets wrong.
    expect(
      compareCalendarVersions(parseCalendarVersion("2026.7.1"), parseCalendarVersion("2026.6.30")),
    ).toBeGreaterThan(0);
    expect(
      compareCalendarVersions(parseCalendarVersion("2025.12.31"), parseCalendarVersion("2026.1.1")),
    ).toBeLessThan(0);
  });

  test("a pre-release or build suffix is ignored", () => {
    expect(parseCalendarVersion("2026.7.9-rc1")).toEqual(parseCalendarVersion("2026.7.9"));
    expect(parseCalendarVersion("2026.7.9+build.5")).toEqual(parseCalendarVersion("2026.7.9"));
  });

  test.each([
    ["not-a-version", "bad year"],
    ["2026.13.1", "out-of-range month"],
    ["2026.0.1", "out-of-range month"],
    ["2026.7.9.1", "too many version components"],
    ["2026.7", "bad day"],
    ["2026.7x.9", "bad month"],
    ["", "bad year"],
  ])("'%s' is a usage error (%s)", (raw, fragment) => {
    let thrown: unknown;
    try {
      parseCalendarVersion(raw);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeDefined();
    expect((thrown as Error).message).toContain(fragment);
    expect((thrown as { exitCode(): number }).exitCode()).toBe(exitCode("usage"));
  });

  test("the compiled-in minimum is itself parseable", () => {
    expect(() => parseCalendarVersion(MIN_SUPPORTED_API_VERSION)).not.toThrow();
  });
});

describe("compatibility verdicts", () => {
  test("a server at or after the minimum is compatible", () => {
    const report = checkCompatibility("2026.6.22");
    expect(report.compatible).toBe(true);
    expect(report.serverVersion).toBe("2026.6.22");
    expect(report.minSupported).toBe(MIN_SUPPORTED_API_VERSION);
    expect(checkCompatibility(MIN_SUPPORTED_API_VERSION).compatible).toBe(true);
  });

  test("a newer server is compatible — the client must not strand an upgrade", () => {
    expect(checkCompatibility("2027.1.1").compatible).toBe(true);
  });

  test("a server older than the minimum fails closed with an actionable message", () => {
    expect(() => checkCompatibility("2026.5.31")).toThrow(/older than the minimum supported/);
    expect(() => checkCompatibility("2026.5.31")).toThrow(/upgrade the server/);
    try {
      checkCompatibility("2026.5.31");
      expect.unreachable("an incompatible server must throw");
    } catch (error) {
      expect((error as { exitCode(): number }).exitCode()).toBe(exitCode("usage"));
    }
  });
});

describe("the gate only applies where the contract version is reported", () => {
  test("a non-status operation is never gated, even carrying a 'version' field", () => {
    // `ctl assets get` returns an ASSET version — an unrelated field that
    // happens to share the name. Gating it would refuse valid documents.
    expect(() => enforceContractVersion("getAsset", { version: "1.2.3" })).not.toThrow();
  });

  test("a local verb (null operationId) is never gated", () => {
    expect(() => enforceContractVersion(null, { version: "1.2.3" })).not.toThrow();
  });

  test("a status body without a version passes — an older build must stay readable", () => {
    expect(() => enforceContractVersion("getAdminStatus", { service: "ferrogate" })).not.toThrow();
    expect(() => enforceContractVersion("getAdminStatus", { version: 20260709 })).not.toThrow();
    expect(() => enforceContractVersion("getAdminStatus", null)).not.toThrow();
    expect(() => enforceContractVersion("getAdminStatus", [])).not.toThrow();
  });

  test("a status body WITH an old version is refused", () => {
    expect(() => enforceContractVersion("getAdminStatus", { version: "2026.5.31" })).toThrow(
      /older than the minimum supported/,
    );
    expect(() => enforceContractVersion("getAdminStatusAlias", { version: "2026.5.31" })).toThrow(
      /older than the minimum supported/,
    );
  });
});

describe("the gate is reached on the real status read path", () => {
  const oldStatus = ok({ service: "ferrogate", version: "2026.5.1", runtime: "workers" });
  const goodStatus = ok({ service: "ferrogate", version: "2026.7.9", runtime: "workers" });

  test("`ops status` against a too-old server exits usage and prints NO status table", async () => {
    const runtime = createTestRuntime({ script: { "GET /admin/v1/status": oldStatus } });
    const code = await main(["ops", "status"], runtime);
    expect(code).toBe(exitCode("usage"));
    // The refusal must land BEFORE rendering: nothing of the mis-mappable
    // document may reach stdout.
    expect(runtime.stdout()).toBe("");
    expect(runtime.stderr()).toContain("older than the minimum supported");
    expect(runtime.stderr()).toContain("2026.5.1");
  });

  test("`ctl system status` is gated identically — the same document, the same rule", async () => {
    const runtime = createTestRuntime({ script: { "GET /admin/v1/status": oldStatus } });
    expect(await main(["ctl", "system", "status"], runtime)).toBe(exitCode("usage"));
    expect(runtime.stdout()).toBe("");
  });

  test("a supported server renders normally and exits 0", async () => {
    const runtime = createTestRuntime({ script: { "GET /admin/v1/status": goodStatus } });
    expect(await main(["ops", "status"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("2026.7.9");
    expect(runtime.stderr()).not.toContain("older than the minimum supported");
  });

  test("`--output json` is gated too: the JSON path is not an escape hatch", async () => {
    const runtime = createTestRuntime({ script: { "GET /admin/v1/status": oldStatus } });
    expect(await main(["ops", "status", "--output", "json"], runtime)).toBe(exitCode("usage"));
    expect(runtime.stdout()).toBe("");
  });

  test("an unrelated read carrying a 'version' field still renders", async () => {
    const runtime = createTestRuntime({
      script: { "GET /readyz": ok({ ready: true, version: "1.0.0" }) },
    });
    expect(await main(["ctl", "system", "ready"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("ready");
  });
});
