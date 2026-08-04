/**
 * Conformance with the FINAL MCP `2026-07-28` specification, checked against
 * the PUBLISHED SCHEMA rather than against a transcription of it (#686).
 *
 * ## What this file is for, and how it differs from `spec-2026-07-28.test.ts`
 *
 * Its sibling pins four changelog clauses as PROSE in docstrings and asserts
 * behaviour against them. That coverage is not redundant and is not replaced
 * here — it holds the things a schema cannot express: the ORDER in which the
 * `iss` check runs relative to the code exchange, the refusal of an MRTR
 * interim result, the `_meta` MERGE that preserves #687's ambiguity report.
 *
 * What it cannot do is notice that the reader misread, or that upstream moved.
 * A hand-transcribed clause is a snapshot of one person's understanding on one
 * day, and the next reader cannot tell "the spec says this" from "someone
 * believed the spec said this". So this file takes the machine-readable
 * artifact the MCP project publishes — committed verbatim at
 * `spec/2026-07-28/schema.json`, provenance in `PROVENANCE.json` beside it —
 * and validates REAL responses off the deployed Worker against it.
 *
 * The idiom is `tools/sdk-conformance`'s: drive the counterparty's own
 * artifact instead of restating its behaviour in assertions of our own
 * composition. There the artifact is the official `openai` / `@anthropic-ai`
 * client; here it is the specification's JSON Schema.
 *
 * ## Every response below is REAL
 *
 * Each `it` drives `SELF.fetch` against the deployed `POST /v1/mcp` surface and
 * validates the response body EXACTLY as it came off the wire — the same
 * `JSON.parse` of the same bytes a client would receive. Nothing is
 * reconstructed for the validator, because a validator fed a hand-built object
 * proves the object, not the server. The two exceptions are named at their use
 * sites and both go through this Worker's own production renderer.
 *
 * ## The validation can fail, and that is pinned here too
 *
 * A validator wired to a schema it never actually applies reports green because
 * it is checking nothing — the shape #766 was filed for. So every group below
 * carries a NEGATIVE control: the real response is corrupted in one specific
 * way that the specification forbids, and the schema is asserted to reject it,
 * naming the keyword that bit. If someone breaks the wiring, those controls go
 * green-when-they-should-be-red and the `toContain` on the failing keyword
 * fails.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { JsonRpcErrorCode, jsonRpcError, renderJsonRpcResponse } from "../src/jsonrpc.js";
import type { InMemoryAssets } from "../src/ports.js";
import {
  MCP_METHOD_HEADER,
  MCP_NAME_HEADER,
  MCP_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION_HEADER,
  modernRequestMeta,
} from "../src/protocol.js";
import { EXEC_KEY, READ_KEY, TENANT, rpcRequest, seedFixture, type Fixture } from "./fixtures.js";
import {
  SPEC_PROVENANCE,
  VENDORED_SCHEMA_BYTES,
  expectConformsToSpec,
  specErrorCode,
  specValidationErrors,
  vendoredSchemaDigest,
} from "./spec-schema.js";

// ---------------------------------------------------------------------------
// Driving the modern surface
// ---------------------------------------------------------------------------

function modernHeaders(method: string, key: string, name?: string): Record<string, string> {
  const headers: Record<string, string> = {
    [MCP_PROTOCOL_VERSION_HEADER]: MCP_PROTOCOL_VERSION,
    [MCP_METHOD_HEADER]: method,
    authorization: `Bearer ${key}`,
  };
  if (name !== undefined) headers[MCP_NAME_HEADER] = name;
  return headers;
}

/** One modern JSON-RPC round trip, returning the body EXACTLY as parsed. */
async function modernCall(
  method: string,
  params: Record<string, unknown>,
  options: { key?: string; name?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: unknown }> {
  const res = await SELF.fetch(
    rpcRequest(
      { jsonrpc: "2.0", id: 1, method, params: { ...params, _meta: modernRequestMeta() } },
      {
        headers: options.headers ?? modernHeaders(method, options.key ?? READ_KEY, options.name),
      },
    ),
  );
  return { status: res.status, body: await res.json() };
}

type JsonRecord = Record<string, unknown>;

/** The `result` member of a response body, as a plain record. */
function resultOf(body: unknown): JsonRecord {
  return (body as { result: JsonRecord }).result;
}

/**
 * A copy of `value` with `keys` ABSENT.
 *
 * Absent, not `undefined`: JSON Schema's `required` is satisfied by a present
 * key whatever its value, so assigning `undefined` would leave every "REJECTS
 * the response with X removed" control below passing for the wrong reason.
 */
function without(value: unknown, ...keys: readonly string[]): JsonRecord {
  return Object.fromEntries(
    Object.entries(structuredClone(value) as JsonRecord).filter(([key]) => !keys.includes(key)),
  );
}

/** A copy of `value` with `patch` applied over it. */
function patched(value: unknown, patch: JsonRecord): JsonRecord {
  return { ...(structuredClone(value) as JsonRecord), ...patch };
}

/** The keywords a corrupted response tripped, for the negative controls. */
function violatedKeywords(definition: string, value: unknown): string[] {
  return specValidationErrors(definition, value).map((unit) => unit.keyword);
}

let fixture: Fixture;

beforeEach(() => {
  fixture = seedFixture();
});

// ---------------------------------------------------------------------------
// The vendored artifact itself
// ---------------------------------------------------------------------------

describe("the vendored spec artifact is the published one", () => {
  /**
   * The way a vendored schema actually dies is not upstream moving — it is
   * somebody editing the local copy so a failing assertion passes, which turns
   * "the spec says this" back into "someone believed the spec said this" with
   * extra steps. This recomputes SHA-256 over the bytes the validators below
   * are built from and compares it to what `PROVENANCE.json` recorded at fetch
   * time, so such an edit is red here, offline, with no network.
   *
   * The OTHER axis — upstream having moved since — cannot be checked from a
   * hermetic Worker suite (`docs/rewrite/TESTING.md`: every suite in this tree
   * is offline and docker-free). It is one command,
   * `bun apps/mcp/spec/refresh.mjs --check`, which compares the git BLOB sha of
   * the local file against the blob at that path on upstream `main` in a single
   * unauthenticated API call. That script's header records why it is not wired
   * into `bun run test`.
   */
  it("matches the SHA-256 and byte count recorded in PROVENANCE.json", async () => {
    expect(await vendoredSchemaDigest()).toBe(SPEC_PROVENANCE.sha256);
    expect(VENDORED_SCHEMA_BYTES).toBe(SPEC_PROVENANCE.bytes);
  });

  it("names the upstream revision, commit and URL it was taken from", () => {
    expect(SPEC_PROVENANCE.revision).toBe(MCP_PROTOCOL_VERSION);
    expect(SPEC_PROVENANCE.repository).toBe(
      "https://github.com/modelcontextprotocol/modelcontextprotocol",
    );
    expect(SPEC_PROVENANCE.path).toBe(`schema/${MCP_PROTOCOL_VERSION}/schema.json`);
    // A 40-hex commit, not a branch name: `main` moves, a commit does not, so
    // this is what a future reader diffs upstream from.
    expect(SPEC_PROVENANCE.upstreamCommit).toMatch(/^[0-9a-f]{40}$/);
    expect(SPEC_PROVENANCE.gitBlobSha).toMatch(/^[0-9a-f]{40}$/);
  });
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

describe("server/discover conforms to #/$defs/DiscoverResultResponse", () => {
  it("validates the real response off the wire", async () => {
    const { status, body } = await modernCall("server/discover", {});
    expect(status).toBe(200);
    expectConformsToSpec("DiscoverResultResponse", body);
  });

  /**
   * NEGATIVE CONTROL, and the one that earns the whole exercise.
   *
   * `DiscoverResult` in the published schema has
   * `required: [cacheScope, capabilities, resultType, supportedVersions, ttlMs]`
   * — `server/discover` IS a cacheable result. The transcription of minor
   * change 5 in `src/protocol.ts` enumerates the five cacheable methods from
   * the changelog prose and `server/discover` is not among them; the response
   * happens to carry `ttlMs`/`cacheScope` anyway because `discoverResult()`
   * writes them itself. Dropping them shows the schema notices — which is
   * exactly the class of misreading a prose docstring cannot catch.
   */
  it("REJECTS the same response with ttlMs and cacheScope removed", async () => {
    const { body } = await modernCall("server/discover", {});
    const broken = patched(body, { result: without(resultOf(body), "ttlMs", "cacheScope") });
    expect(violatedKeywords("DiscoverResultResponse", broken)).toContain("required");
  });

  /** `extensions` VALUES are per-extension settings objects (minor change 1). */
  it("REJECTS an extensions map whose value is not a settings object", async () => {
    const { body } = await modernCall("server/discover", {});
    const capabilities = patched(resultOf(body)["capabilities"], {
      extensions: { "io.modelcontextprotocol/tasks": "yes" },
    });
    const broken = patched(body, { result: patched(resultOf(body), { capabilities }) });
    expect(violatedKeywords("DiscoverResultResponse", broken)).toContain("type");
  });

  /**
   * The ENVELOPE is validated too, not only the result it wraps: `jsonrpc` is
   * `const: "2.0"`. Without this, every control in this file could be passing
   * off a validator that only ever descends into `result`.
   */
  it("REJECTS the same response on a non-2.0 JSON-RPC envelope", async () => {
    const { body } = await modernCall("server/discover", {});
    expect(violatedKeywords("DiscoverResultResponse", patched(body, { jsonrpc: "1.0" }))).toContain(
      "const",
    );
  });
});

describe("tools/list conforms to #/$defs/ListToolsResultResponse", () => {
  it("validates the real response off the wire", async () => {
    const { status, body } = await modernCall("tools/list", {});
    expect(status).toBe(200);
    // Not vacuous on an empty catalogue: the fixture's allowlisted `echo` is
    // listed, so `#/$defs/Tool` is actually exercised.
    expect((resultOf(body)["tools"] as unknown[]).length).toBeGreaterThan(0);
    expectConformsToSpec("ListToolsResultResponse", body);
  });

  /** `resultType` is mandatory on this revision (major change 8, first half). */
  it("REJECTS the same response with resultType removed", async () => {
    const { body } = await modernCall("tools/list", {});
    const broken = patched(body, { result: without(resultOf(body), "resultType") });
    expect(violatedKeywords("ListToolsResultResponse", broken)).toContain("required");
  });

  /**
   * `_meta["io.modelcontextprotocol/serverInfo"]` is typed `Implementation`
   * (major change 2), so a serverInfo that is not one is a schema violation
   * rather than a matter of taste. This is the machine-readable counterpart of
   * the `_meta`-merge test in the sibling file.
   */
  it("REJECTS a serverInfo that is not an Implementation", async () => {
    const { body } = await modernCall("tools/list", {});
    const meta = patched(resultOf(body)["_meta"], {
      "io.modelcontextprotocol/serverInfo": { name: 7, version: "1.0.0" },
    });
    const broken = patched(body, { result: patched(resultOf(body), { _meta: meta }) });
    expect(violatedKeywords("ListToolsResultResponse", broken)).toContain("type");
  });

  /** A tool without `inputSchema` is not a `#/$defs/Tool`. */
  it("REJECTS a tool entry missing inputSchema", async () => {
    const { body } = await modernCall("tools/list", {});
    const tools = (resultOf(body)["tools"] as unknown[]).map((tool) =>
      without(tool, "inputSchema"),
    );
    const broken = patched(body, { result: patched(resultOf(body), { tools }) });
    expect(violatedKeywords("ListToolsResultResponse", broken)).toContain("required");
  });
});

/**
 * ## Why `tools/call` and `resources/read` are ALSO validated against a branch
 *
 * `CallToolResultResponse.result` and `ReadResourceResultResponse.result` are
 * each an `anyOf: [InputRequiredResult, <the real result>]` — the MRTR union
 * from major change 7/8. `InputRequiredResult` requires ONLY `resultType` and
 * closes nothing, so ANY object carrying `resultType: "complete"` satisfies the
 * union no matter how mangled the rest of it is.
 *
 * That was measured here, not assumed: the first version of the three negative
 * controls below validated against the union alone and every one of them came
 * back VALID — a bare string in `content`, a `contents` entry with no `uri`, a
 * cacheable result stripped of its cache hints. A conformance gate built on the
 * union alone would have reported green on all three.
 *
 * So the envelope is validated against the union (that is the wire contract a
 * client sees) AND the result object is validated against the branch the
 * discriminator actually selects. `resultType === "complete"` is not an MRTR
 * interim result — the sibling file's MRTR tests are what hold the discriminator
 * honest — so `CallToolResult` / `ReadResourceResult` is the applicable branch,
 * and it is where the negative controls bite.
 */
describe("tools/call conforms to #/$defs/CallToolResultResponse", () => {
  async function call(args: Record<string, unknown> = {}) {
    return modernCall(
      "tools/call",
      { name: "srv-echo", arguments: args },
      { key: EXEC_KEY, name: "srv-echo" },
    );
  }

  it("validates the real response off the wire", async () => {
    const { status, body } = await call({ hello: "world" });
    expect(status).toBe(200);
    // The upstream really ran — otherwise `content` could be conformant and
    // empty for the wrong reason.
    expect(fixture.calls).toHaveLength(1);
    expectConformsToSpec("CallToolResultResponse", body);
    expect(resultOf(body)["resultType"]).toBe("complete");
    expectConformsToSpec("CallToolResult", resultOf(body));
  });

  /**
   * `CallToolResult.content` items are `#/$defs/ContentBlock`s — a five-branch
   * `anyOf`, none of which admits a bare string. This is the assertion that
   * would bite if the dispatch path ever started passing an upstream's raw
   * payload through unshaped.
   */
  it("REJECTS a content block that is not a ContentBlock", async () => {
    const { body } = await call();
    const broken = patched(resultOf(body), { content: ["plain text"] });
    expect(violatedKeywords("CallToolResult", broken)).toContain("anyOf");
  });

  /** `content` is required on a completed tool call; `resultType` too. */
  it("REJECTS a result carrying neither content nor a resultType", async () => {
    const { body } = await call();
    const broken = without(resultOf(body), "content", "resultType");
    expect(violatedKeywords("CallToolResult", broken)).toContain("required");
  });
});

describe("resources/read conforms to #/$defs/ReadResourceResultResponse", () => {
  const CONTENT = new TextEncoder().encode("echo hello");
  const URI = "asset://cli_tool/deploy/1.0.0";

  function seedAsset(): void {
    fixture.ports.assets.seed(
      TENANT,
      {
        id: "stored-assets-mcp-schema",
        assetType: "cli_tool",
        name: "deploy",
        version: "1.0.0",
        contentType: "text/plain",
        sizeBytes: CONTENT.byteLength,
        sha256: "a".repeat(64),
        downloadable: true,
      } as Parameters<InMemoryAssets["seed"]>[1],
      CONTENT,
    );
  }

  async function read() {
    seedAsset();
    return modernCall("resources/read", { uri: URI }, { name: URI });
  }

  it("validates the real response off the wire", async () => {
    const { status, body } = await read();
    expect(status).toBe(200);
    expect((resultOf(body)["contents"] as unknown[]).length).toBeGreaterThan(0);
    expectConformsToSpec("ReadResourceResultResponse", body);
    // The selected branch, for the reason in the block comment above.
    expect(resultOf(body)["resultType"]).toBe("complete");
    expectConformsToSpec("ReadResourceResult", resultOf(body));
  });

  /** Every `contents` entry needs a `uri` — a blob with no identity is not one. */
  it("REJECTS a contents entry with no uri", async () => {
    const { body } = await read();
    const contents = (resultOf(body)["contents"] as unknown[]).map((entry) =>
      without(entry, "uri"),
    );
    const broken = patched(resultOf(body), { contents });
    expect(violatedKeywords("ReadResourceResult", broken)).toContain("anyOf");
  });

  /** `resources/read` is a `CacheableResult`: `ttlMs`/`cacheScope` are required. */
  it("REJECTS the same response with the cache hints removed", async () => {
    const { body } = await read();
    const broken = without(resultOf(body), "ttlMs", "cacheScope");
    expect(violatedKeywords("ReadResourceResult", broken)).toContain("required");
  });
});

// ---------------------------------------------------------------------------
// Error shapes — minor change 12's renumbering, checked against the schema
// ---------------------------------------------------------------------------

describe("the -32020 / -32021 / -32022 partition is the schema's", () => {
  /**
   * The renumbering is asserted by READING the literal out of the vendored
   * schema and comparing it to `JsonRpcErrorCode`, rather than by writing
   * `-32020` in a test. A test that restates the number cannot notice the spec
   * renumbering it again; this one can.
   */
  it("pins each code to the constant the schema declares", () => {
    expect(specErrorCode("HeaderMismatchError")).toBe(JsonRpcErrorCode.ModernHeaderMismatch);
    expect(specErrorCode("MissingRequiredClientCapabilityError")).toBe(
      JsonRpcErrorCode.ModernMissingClientCapability,
    );
    expect(specErrorCode("UnsupportedProtocolVersionError")).toBe(
      JsonRpcErrorCode.ModernUnsupportedVersion,
    );
  });
});

describe("-32020 conforms to #/$defs/HeaderMismatchError", () => {
  /** The Mcp-Method routing header disagreeing with the body it describes. */
  async function headerMismatch(): Promise<{ status: number; body: unknown }> {
    return modernCall(
      "tools/list",
      {},
      { headers: { ...modernHeaders("resources/list", READ_KEY) } },
    );
  }

  it("validates the real refusal off the wire, at the mandated HTTP 400", async () => {
    const { status, body } = await headerMismatch();
    // The schema's own prose for this definition: "For HTTP, the response
    // status code MUST be 400 Bad Request."
    expect(status).toBe(400);
    expectConformsToSpec("HeaderMismatchError", body);
  });

  it("REJECTS the same refusal renumbered to any other code", async () => {
    const { body } = await headerMismatch();
    const error = patched((body as { error: unknown }).error, {
      code: JsonRpcErrorCode.InvalidRequest,
    });
    expect(violatedKeywords("HeaderMismatchError", patched(body, { error }))).toContain("const");
  });
});

describe("-32022 conforms to #/$defs/UnsupportedProtocolVersionError", () => {
  /**
   * A client on a revision this server does not speak. Header and body agree —
   * a disagreement would be refused as `-32020` first — so what is exercised is
   * the version check itself.
   */
  async function unsupportedVersion(): Promise<{ status: number; body: unknown }> {
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: {
            _meta: {
              "io.modelcontextprotocol/protocolVersion": "1999-01-01",
              "io.modelcontextprotocol/clientCapabilities": {},
            },
          },
        },
        {
          headers: {
            [MCP_PROTOCOL_VERSION_HEADER]: "1999-01-01",
            [MCP_METHOD_HEADER]: "tools/list",
            authorization: `Bearer ${READ_KEY}`,
          },
        },
      ),
    );
    return { status: res.status, body: await res.json() };
  }

  it("validates the real refusal, including the required data.supported list", async () => {
    const { status, body } = await unsupportedVersion();
    expect(status).toBe(400);
    // `data: { requested, supported }` is REQUIRED by this definition, so a
    // refusal that does not tell the client what to retry with is not merely
    // unhelpful — it is non-conformant, and this assertion is what says so.
    expectConformsToSpec("UnsupportedProtocolVersionError", body);
  });

  it("REJECTS the same refusal with data.supported removed", async () => {
    const { body } = await unsupportedVersion();
    const rawError = (body as { error: JsonRecord }).error;
    const error = patched(rawError, { data: without(rawError["data"], "supported") });
    expect(violatedKeywords("UnsupportedProtocolVersionError", patched(body, { error }))).toContain(
      "required",
    );
  });
});

describe("-32021 (MissingRequiredClientCapability)", () => {
  /**
   * THIS SERVER NEVER EMITS -32021, and that is a deliberate, checkable state
   * rather than an omission: it requires no client capability of anyone, so a
   * modern request declaring an EMPTY `clientCapabilities` map is SERVED. There
   * is therefore no real response to validate, and inventing one and calling it
   * real would be the dishonest move.
   *
   * What is pinned instead is the pair that makes the absence safe:
   *  - the code is unreachable today, driven end to end (this test);
   *  - and IF it is ever emitted, the schema requires
   *    `data.requiredCapabilities` — a bare `-32021` is non-conformant. That is
   *    checked below against this Worker's own error renderer, the exact
   *    function every real refusal on this surface is built by.
   */
  it("is unreachable: an empty clientCapabilities map is served, not refused", async () => {
    const { status, body } = await modernCall("tools/list", {});
    expect(status).toBe(200);
    expect((body as { error?: unknown }).error).toBeUndefined();
  });

  it("would be non-conformant without data.requiredCapabilities", () => {
    const bare = renderJsonRpcResponse(
      jsonRpcError(
        1,
        JsonRpcErrorCode.ModernMissingClientCapability,
        "Missing required client capability",
      ),
    );
    expect(violatedKeywords("MissingRequiredClientCapabilityError", bare)).toContain("required");
  });

  it("conforms once the renderer is given the capabilities it demands", () => {
    const complete = renderJsonRpcResponse(
      jsonRpcError(
        1,
        JsonRpcErrorCode.ModernMissingClientCapability,
        "Missing required client capability",
        { requiredCapabilities: { elicitation: {} } },
      ),
    );
    // The control for the test above: the renderer's ENVELOPE is conformant, so
    // the rejection there is about the missing payload and nothing else.
    expectConformsToSpec("MissingRequiredClientCapabilityError", complete);
  });
});
