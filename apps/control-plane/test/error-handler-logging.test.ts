/**
 * Regression (2026-08-07): `controlPlaneErrorHandler` classified every throw
 * into the uniform envelope but LOGGED NOTHING. Because `classifyError`
 * deliberately never leaks an arbitrary throw's text to the client, an
 * unexpected 500 reached the operator as a bare "internal server error" with no
 * trace of the cause anywhere. Found during live testing: a wallet-adjust 500
 * (a missing `wallets` table) was undiagnosable until the cause was logged.
 *
 * A 5xx must now be logged (cause included); a 4xx (expected client error)
 * stays quiet.
 */
import { describe, expect, it } from "vitest";
import { HttpError, controlPlaneErrorHandler } from "../src/middleware/errors.js";

type FakeCtx = Parameters<typeof controlPlaneErrorHandler>[1];

function fakeCtx(): FakeCtx {
  return {
    get: (key: string) => (key === "requestId" ? "req-test-1" : undefined),
    req: { method: "POST", path: "/admin/v1/wallets/t/adjust" },
  } as unknown as FakeCtx;
}

async function withCapturedWarn<T>(
  run: () => T | Promise<T>,
): Promise<{ result: T; warnings: string[] }> {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };
  try {
    return { result: await run(), warnings };
  } finally {
    console.warn = original;
  }
}

describe("controlPlaneErrorHandler logs 5xx causes, stays quiet on 4xx", () => {
  it("logs the cause of an unclassified 500", async () => {
    const { result, warnings } = await withCapturedWarn(() =>
      controlPlaneErrorHandler(
        new Error("ensure_wallet failed: no such table: wallets"),
        fakeCtx(),
      ),
    );
    expect(result.status).toBe(500);
    expect(warnings.some((w) => w.includes("control-plane internal_error (500)"))).toBe(true);
    expect(warnings.some((w) => w.includes("no such table: wallets"))).toBe(true);
    expect(warnings.some((w) => w.includes("req-test-1"))).toBe(true);
  });

  it("does NOT log an expected 4xx client error", async () => {
    const { result, warnings } = await withCapturedWarn(() =>
      controlPlaneErrorHandler(new HttpError(404, "not_found", "wallet t not found"), fakeCtx()),
    );
    expect(result.status).toBe(404);
    expect(warnings).toEqual([]);
  });
});
