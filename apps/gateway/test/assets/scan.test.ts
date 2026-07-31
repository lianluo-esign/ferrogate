/**
 * The pluggable malware-scan backend (`src/assets/scan.ts`) — the port of the
 * Rust `asset_scan.rs`, exercised at three levels:
 *
 *  1. the pure folds (`resolveScanOutcome`, `parseHttpScanResponse`), pinned
 *     against the Rust's own message strings;
 *  2. the HTTP backend over an intercepted `globalThis.fetch`, so the request
 *     shape and every failure mode are asserted without a network;
 *  3. the REAL `AssetService` and the REAL gateway app assembled through
 *     `assetDepsFromEnv`, so a screener that is built but never MOUNTED fails
 *     this suite instead of shipping dead.
 *
 * The env-driven cases are what make level 3 an anti-drift check: they drive a
 * push over HTTP with `ASSET_SCANNER*` vars set and assert the refusal the
 * configured backend produces. Delete the `screener` line from
 * `assetDepsFromEnv` and the push is admitted by the builtin instead — those
 * tests go red.
 */
import { afterEach, describe, expect, test } from "vitest";
import { assetDepsFromEnv, assetRouteModule, buildAssetService } from "../../src/assets/handlers.js";
import {
  type AssetScreener,
  BuiltinEicarScreener,
  InMemoryAssetMetadataStore,
  InMemoryAssetObjectStore,
} from "../../src/assets/ports.js";
import {
  type AssetContentScanner,
  type ScanVerdict,
  DeferringScreener,
  HttpContentScanner,
  ScannerBackedScreener,
  assetScreenerFromEnv,
  contentScannerFromEnv,
  parseHttpScanResponse,
  resolveScanOutcome,
  unavailablePolicyFromEnv,
} from "../../src/assets/scan.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { CTX, callerFor, bytes, harness } from "./helpers.js";

const SCANNER_URL = "https://scanner.test/scan";

/** Intercept `globalThis.fetch` for one test; the scanner reads it at CALL time. */
function interceptFetch(handler: (request: Request) => Response | Promise<Response>): {
  readonly requests: Request[];
  restore(): void;
} {
  const original = globalThis.fetch;
  const requests: Request[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input as RequestInfo, init);
    requests.push(request.clone());
    return handler(request);
  }) as typeof globalThis.fetch;
  return {
    requests,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

let intercept: { restore(): void } | undefined;
afterEach(() => {
  intercept?.restore();
  intercept = undefined;
});

/** A scanner that answers a fixed verdict, so the policy fold is isolated. */
class FixedScanner implements AssetContentScanner {
  readonly backendName = "http";
  scanned = 0;
  constructor(private readonly verdict: ScanVerdict) {}
  async scan(): Promise<ScanVerdict> {
    this.scanned += 1;
    return this.verdict;
  }
}

const SCREENING_REQUEST = {
  assetId: "asset_1",
  tenantId: "tenant_a",
  assetType: "tools",
  contentType: "application/octet-stream",
  content: bytes("hello"),
  contentSha256: "abc123",
  nowUnix: 1_700_000_000,
};

// ---------------------------------------------------------------------------
// 1. the pure folds
// ---------------------------------------------------------------------------

describe("resolveScanOutcome — Rust `resolve_scan_outcome`", () => {
  test("clean admits", () => {
    expect(resolveScanOutcome({ kind: "clean" }, "fail_closed")).toEqual({ kind: "admit" });
    expect(resolveScanOutcome({ kind: "clean" }, "quarantine")).toEqual({ kind: "admit" });
  });

  test("infected ALWAYS rejects — the unavailable policy is not consulted", () => {
    for (const policy of ["fail_closed", "quarantine"] as const) {
      expect(resolveScanOutcome({ kind: "infected", signature: "Eicar-Test" }, policy)).toEqual({
        kind: "reject",
        reason: "content failed malware scan: Eicar-Test",
      });
    }
  });

  test("unavailable + fail_closed rejects; it never admits", () => {
    expect(resolveScanOutcome({ kind: "unavailable", reason: "boom" }, "fail_closed")).toEqual({
      kind: "reject",
      reason: "scanner unavailable (fail-closed): boom",
    });
  });

  test("unavailable + quarantine stores-but-withholds; it never admits", () => {
    expect(resolveScanOutcome({ kind: "unavailable", reason: "boom" }, "quarantine")).toEqual({
      kind: "quarantine",
      reason: "scanner unavailable, admitted to quarantine: boom",
    });
  });
});

describe("parseHttpScanResponse — Rust `parse_http_scan_response`", () => {
  test("clean", () => {
    expect(parseHttpScanResponse('{"verdict":"clean"}')).toEqual({ kind: "clean" });
  });

  test("infected carries the signature, and names it `unknown-signature` when absent", () => {
    expect(parseHttpScanResponse('{"verdict":"infected","signature":"Win.Test"}')).toEqual({
      kind: "infected",
      signature: "Win.Test",
    });
    expect(parseHttpScanResponse('{"verdict":"infected"}')).toEqual({
      kind: "infected",
      signature: "unknown-signature",
    });
  });

  test("a non-JSON body is UNAVAILABLE, never clean", () => {
    const verdict = parseHttpScanResponse("<html>502</html>");
    expect(verdict.kind).toBe("unavailable");
    expect(verdict.kind === "unavailable" && verdict.reason).toContain("scanner reply not JSON");
  });

  test("an unrecognised verdict is UNAVAILABLE, never clean", () => {
    expect(parseHttpScanResponse('{"verdict":"maybe"}')).toEqual({
      kind: "unavailable",
      reason: 'scanner returned unknown verdict "maybe"',
    });
    expect(parseHttpScanResponse("{}")).toEqual({
      kind: "unavailable",
      reason: 'scanner returned unknown verdict "<missing>"',
    });
    // `true` is not the string "clean": a scanner that answers a boolean has
    // not vouched for anything.
    expect(parseHttpScanResponse('{"verdict":true}').kind).toBe("unavailable");
  });
});

// ---------------------------------------------------------------------------
// 2. the HTTP backend
// ---------------------------------------------------------------------------

describe("HttpContentScanner — Rust `HttpScanner`", () => {
  test("POSTs the raw bytes as application/octet-stream to the endpoint", async () => {
    const capture = interceptFetch(() => new Response('{"verdict":"clean"}'));
    intercept = capture;
    const verdict = await new HttpContentScanner(SCANNER_URL).scan(bytes("payload-bytes"));
    expect(verdict).toEqual({ kind: "clean" });
    const request = capture.requests[0];
    expect(request?.url).toBe(SCANNER_URL);
    expect(request?.method).toBe("POST");
    expect(request?.headers.get("content-type")).toBe("application/octet-stream");
    expect(await request?.text()).toBe("payload-bytes");
  });

  test("a non-2xx status is UNAVAILABLE with the status in the reason", async () => {
    intercept = interceptFetch(() => new Response("nope", { status: 502 }));
    await expect(new HttpContentScanner(SCANNER_URL).scan(bytes("x"))).resolves.toEqual({
      kind: "unavailable",
      reason: "scanner returned status 502",
    });
  });

  test("a transport failure is UNAVAILABLE, never clean", async () => {
    intercept = interceptFetch(() => {
      throw new Error("connection refused");
    });
    const verdict = await new HttpContentScanner(SCANNER_URL).scan(bytes("x"));
    expect(verdict.kind).toBe("unavailable");
    expect(verdict.kind === "unavailable" && verdict.reason).toContain("scanner HTTP error");
    expect(verdict.kind === "unavailable" && verdict.reason).toContain("connection refused");
  });

  test("a 200 with an infected verdict is reported infected", async () => {
    intercept = interceptFetch(() => new Response('{"verdict":"infected","signature":"Sig.1"}'));
    await expect(new HttpContentScanner(SCANNER_URL).scan(bytes("x"))).resolves.toEqual({
      kind: "infected",
      signature: "Sig.1",
    });
  });
});

// ---------------------------------------------------------------------------
// 3a. the screeners, through the REAL AssetService
// ---------------------------------------------------------------------------

const REF = { assetType: "tools", name: "widget", version: "1.0.0" };

/**
 * The READ surface, addressed by exact version.
 *
 * `pullAsset` is the only download entry point on the service, and it is what
 * makes these assertions the #366 withholding check rather than a metadata
 * peek: it filters the resolution set by `isDownloadable` BEFORE resolving, so
 * a `pending_scan`/`quarantined` row answers `404 asset_not_found` — absent,
 * not "present but forbidden".
 */
function pull(service: ReturnType<typeof buildAssetService>, tenantId = "tenant_a") {
  return service.pullAsset(
    callerFor(tenantId),
    { ...REF, reference: REF.version },
    { headers: new Headers() },
  );
}

function push(service: ReturnType<typeof buildAssetService>, content: string) {
  return service.putAsset(
    callerFor("tenant_a"),
    REF,
    { content: bytes(content), contentType: "application/octet-stream" },
    CTX,
  );
}

function serviceWith(screener: AssetScreener) {
  const objects = new InMemoryAssetObjectStore();
  const metadata = new InMemoryAssetMetadataStore();
  const service = buildAssetService({ objects, metadata, screener });
  return { service, objects, metadata };
}

describe("ScannerBackedScreener through the real putAsset path", () => {
  test("infected ⇒ 422 asset_scan_rejected AND nothing is stored", async () => {
    const scanner = new FixedScanner({ kind: "infected", signature: "Eicar-Test-Signature" });
    const { service, objects, metadata } = serviceWith(new ScannerBackedScreener(scanner));
    const result = await push(service, "malware");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.status).toBe(422);
    expect(result.ok === false && result.code).toBe("asset_scan_rejected");
    expect(result.ok === false && result.message).toBe(
      "content failed malware scan: Eicar-Test-Signature",
    );
    // Screening runs BEFORE the object write and before the row create.
    expect(objects.objects.size).toBe(0);
    expect(await metadata.getAsset("tenant_a:tools:widget:1.0.0")).toBeNull();
    expect(scanner.scanned).toBe(1);
  });

  test("scanner down + fail_closed ⇒ 422, and the bytes are refused", async () => {
    const { service, objects } = serviceWith(
      new ScannerBackedScreener(new FixedScanner({ kind: "unavailable", reason: "timeout" })),
    );
    const result = await push(service, "harmless");
    expect(result.ok === false && result.status).toBe(422);
    expect(result.ok === false && result.message).toBe(
      "scanner unavailable (fail-closed): timeout",
    );
    expect(objects.objects.size).toBe(0);
  });

  test("scanner down + quarantine ⇒ stored, and WITHHELD from the read path", async () => {
    const { service } = serviceWith(
      new ScannerBackedScreener(
        new FixedScanner({ kind: "unavailable", reason: "timeout" }),
        "quarantine",
      ),
    );
    const pushed = await push(service, "harmless");
    expect(pushed.ok).toBe(true);
    expect(pushed.ok === true && pushed.body.asset.visibility).toBe("quarantined");
    // #366: unproven is indistinguishable from absent on every read surface.
    const read = await pull(service);
    expect(read.ok).toBe(false);
    expect(read.ok === false && read.status).toBe(404);
  });

  test("clean ⇒ visible and pullable", async () => {
    const { service } = serviceWith(
      new ScannerBackedScreener(new FixedScanner({ kind: "clean" })),
    );
    const pushed = await push(service, "harmless");
    expect(pushed.ok === true && pushed.body.asset.visibility).toBe("visible");
    const read = await pull(service);
    expect(read.ok).toBe(true);
  });
});

describe("DeferringScreener — Rust `should_defer_scan`", () => {
  test("over the threshold ⇒ pending_scan, withheld, and the inner scanner is NOT called", async () => {
    const inner = new FixedScanner({ kind: "clean" });
    const { service } = serviceWith(
      new DeferringScreener(new ScannerBackedScreener(inner), 4, "http"),
    );
    const pushed = await push(service, "12345");
    expect(pushed.ok === true && pushed.body.asset.visibility).toBe("pending_scan");
    expect(inner.scanned).toBe(0);
    const read = await pull(service);
    expect(read.ok === false && read.status).toBe(404);
  });

  test("at or under the threshold the wrapped screener still decides", async () => {
    const inner = new FixedScanner({ kind: "infected", signature: "Sig" });
    const { service } = serviceWith(
      new DeferringScreener(new ScannerBackedScreener(inner), 4, "http"),
    );
    const result = await push(service, "1234");
    expect(inner.scanned).toBe(1);
    expect(result.ok === false && result.code).toBe("asset_scan_rejected");
  });

  test("wrapping the BUILTIN preserves its quarantine-on-EICAR posture", async () => {
    const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const { service } = serviceWith(
      new DeferringScreener(new BuiltinEicarScreener(), 10_000, "builtin-eicar"),
    );
    const pushed = await push(service, EICAR);
    expect(pushed.ok).toBe(true);
    expect(pushed.ok === true && pushed.body.asset.visibility).toBe("quarantined");
  });

  test("a deferred asset is promotable — the only shipped source of pending_scan", async () => {
    const h = harness({ screener: new DeferringScreener(new BuiltinEicarScreener(), 4, "http") });
    const caller = callerFor("tenant_a");
    const pushed = await h.service.putAsset(
      caller,
      REF,
      { content: bytes("12345"), contentType: "application/octet-stream" },
      CTX,
    );
    expect(pushed.ok === true && pushed.body.asset.visibility).toBe("pending_scan");
    const promoted = await h.service.promoteVisibility(
      caller,
      REF,
      { scan_outcome: "clean", evidence: "out-of-band scan 42", scanner: "http" },
      CTX,
    );
    expect(promoted.ok).toBe(true);
    const read = await pull(h.service);
    expect(read.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3b. the composition root
// ---------------------------------------------------------------------------

describe("assetScreenerFromEnv / contentScannerFromEnv", () => {
  test("no vars ⇒ null, so the caller's builtin default stands", () => {
    expect(assetScreenerFromEnv({})).toBeNull();
    expect(contentScannerFromEnv({})).toBeNull();
  });

  test('ASSET_SCANNER="http" with NO endpoint ⇒ null — never a scanner pointed at nothing', () => {
    expect(contentScannerFromEnv({ ASSET_SCANNER: "http" })).toBeNull();
    expect(assetScreenerFromEnv({ ASSET_SCANNER: "http" })).toBeNull();
    expect(assetScreenerFromEnv({ ASSET_SCANNER: "http", ASSET_SCANNER_ENDPOINT: "  " })).toBeNull();
  });

  test("an unknown backend name keeps the builtin", () => {
    expect(
      contentScannerFromEnv({ ASSET_SCANNER: "clamav", ASSET_SCANNER_ENDPOINT: SCANNER_URL }),
    ).toBeNull();
  });

  test("endpoint bound ⇒ the HTTP backend", () => {
    const scanner = contentScannerFromEnv({
      ASSET_SCANNER: "http",
      ASSET_SCANNER_ENDPOINT: SCANNER_URL,
    });
    expect(scanner).toBeInstanceOf(HttpContentScanner);
    expect(scanner?.backendName).toBe("http");
    expect(
      assetScreenerFromEnv({ ASSET_SCANNER: "http", ASSET_SCANNER_ENDPOINT: SCANNER_URL }),
    ).toBeInstanceOf(ScannerBackedScreener);
  });

  test("the unavailable policy defaults to fail-closed and only `quarantine` opts out", () => {
    expect(unavailablePolicyFromEnv({})).toBe("fail_closed");
    expect(unavailablePolicyFromEnv({ ASSET_SCANNER_UNAVAILABLE: "ignore" })).toBe("fail_closed");
    expect(unavailablePolicyFromEnv({ ASSET_SCANNER_UNAVAILABLE: "quarantine" })).toBe(
      "quarantine",
    );
  });

  test("a threshold ALONE still defers, wrapping the builtin", () => {
    const screener = assetScreenerFromEnv({ ASSET_SCANNER_ASYNC_THRESHOLD_BYTES: "8" });
    expect(screener).toBeInstanceOf(DeferringScreener);
  });

  test("a malformed threshold is ignored rather than read as 0", () => {
    // `0` would defer EVERY object; a typo must not silently do that.
    expect(assetScreenerFromEnv({ ASSET_SCANNER_ASYNC_THRESHOLD_BYTES: "lots" })).toBeNull();
    expect(assetScreenerFromEnv({ ASSET_SCANNER_ASYNC_THRESHOLD_BYTES: "-1" })).toBeNull();
  });
});

/**
 * The MOUNT proof: env vars → `assetDepsFromEnv` → the service the route module
 * builds. Both cases fail if the `screener` line is dropped from
 * `assetDepsFromEnv`, because the builtin admits what the configured backend
 * refuses.
 */
describe("assetDepsFromEnv wires the configured screener into the deployed app", () => {
  const ENV = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify([
      {
        key: "fg_assets_rw",
        id: "key_rw",
        tenant_id: "tenant_a",
        scopes: ["assets.read", "assets.write"],
      },
    ]),
    ASSET_ENTITLEMENTS: JSON.stringify({ tenant_a: { asset_hosting_enabled: true } }),
    ASSET_SCANNER: "http",
    ASSET_SCANNER_ENDPOINT: SCANNER_URL,
  };

  function gateway() {
    const { app } = createGatewayApp({
      modules: [assetRouteModule({ depsFromEnv: assetDepsFromEnv })],
    });
    return (path: string, init: RequestInit, env: Record<string, unknown>) =>
      app.request(
        `https://gw.test${path}`,
        {
          ...init,
          headers: new Headers({
            authorization: "Bearer fg_assets_rw",
            ...(init.headers as Record<string, string> | undefined),
          }),
        },
        env,
      );
  }

  test("deps carry the screener the vars select", () => {
    expect(assetDepsFromEnv(ENV).screener).toBeInstanceOf(ScannerBackedScreener);
    expect(assetDepsFromEnv({}).screener).toBeUndefined();
  });

  test("an infected verdict from the configured endpoint refuses the push over HTTP", async () => {
    intercept = interceptFetch(
      () => new Response('{"verdict":"infected","signature":"Bad.Thing"}'),
    );
    const call = gateway();
    const response = await call(
      "/v1/assets/tools/widget/1.0.0",
      { method: "PUT", body: "payload" },
      ENV,
    );
    expect(response.status).toBe(422);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("asset_scan_rejected");
    expect(body.error.message).toBe("content failed malware scan: Bad.Thing");
  });

  test("a scanner outage refuses the push over HTTP (fail-closed by default)", async () => {
    intercept = interceptFetch(() => new Response("gateway timeout", { status: 504 }));
    const call = gateway();
    const response = await call(
      "/v1/assets/tools/widget/1.0.0",
      { method: "PUT", body: "payload" },
      ENV,
    );
    expect(response.status).toBe(422);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.message).toBe("scanner unavailable (fail-closed): scanner returned status 504");
  });
});
