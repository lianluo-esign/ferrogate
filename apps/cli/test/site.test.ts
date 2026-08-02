/**
 * `ferrogate site push ./dist` — issue #736.
 *
 * Two things are proved here and they are different things:
 *
 *  1. **The refusals that can only happen client-side.** A symlink in `dist/`
 *     must not be followed, because a followed symlink reaches the gateway
 *     indistinguishable from a real file — the server cannot make this call, so
 *     if the client does not, nobody does. Driven through the whole `main`
 *     dispatch with a fake directory tree, not by unit-calling a helper.
 *
 *  2. **The archive is what the gateway's expander reads.** The bytes the
 *     command PUTs are parsed back here with the same ustar rules
 *     `apps/gateway/src/assets/bundle.ts` applies, so a writer that produced a
 *     plausible-looking but unreadable archive fails HERE rather than in
 *     production. (The gateway suite proves the expander; this proves the two
 *     halves meet.)
 */
import { describe, expect, test } from "vitest";
import { main } from "../src/index.js";
import type { DirectoryEntry } from "../src/ports.js";
import { buildTar } from "../src/tar.js";
import { createTestRuntime } from "./helpers.js";

const CONNECT = [
  "--gateway-url",
  "https://gw.test",
  "--api-key",
  "fg_test",
  "--name",
  "docs",
  "--version",
  "1.2.3",
];

function tree(...entries: DirectoryEntry[]): Readonly<Record<string, readonly DirectoryEntry[]>> {
  return { "./dist": entries };
}

/**
 * Parse a ustar archive back into `path -> text`. Deliberately a SECOND,
 * independent reader: if `src/tar.ts` and this agreed only because they share
 * code, the round trip would prove nothing.
 */
function readTar(archive: Uint8Array): Map<string, string> {
  const out = new Map<string, string>();
  const decoder = new TextDecoder();
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const nameField = header.subarray(0, 100);
    const nameEnd = nameField.indexOf(0);
    const name = decoder.decode(nameEnd === -1 ? nameField : nameField.subarray(0, nameEnd));
    const sizeField = decoder.decode(header.subarray(124, 135)).replace(/\0.*$/, "");
    const size = Number.parseInt(sizeField, 8);
    expect(decoder.decode(header.subarray(257, 262))).toBe("ustar");
    // The checksum must be the real one, recomputed with the field as spaces.
    const stated = Number.parseInt(decoder.decode(header.subarray(148, 154)), 8);
    let sum = 0;
    for (let index = 0; index < 512; index += 1) {
      sum += index >= 148 && index < 156 ? 0x20 : (header[index] as number);
    }
    expect(sum).toBe(stated);
    out.set(name, decoder.decode(archive.subarray(offset + 512, offset + 512 + size)));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

describe("site push packs a directory into one static_site version", () => {
  test("the whole tree is PUT at the existing static_site publish operation", async () => {
    const runtime = createTestRuntime({
      directories: tree(
        { path: "index.html", kind: "file" },
        { path: "assets/app.css", kind: "file" },
      ),
      files: {
        "./dist/index.html": "<!doctype html><h1>docs</h1>",
        "./dist/assets/app.css": "body{color:red}",
      },
    });

    const code = await main(["site", "push", "./dist", ...CONNECT], runtime);

    expect(code).toBe(0);
    const sent = runtime.gatewayClient.requests[0];
    expect(sent?.request.method).toBe("PUT");
    expect(sent?.request.path).toBe("/v1/assets/static_site/docs/1.2.3");
    expect(sent?.request.contentType).toBe("application/x-tar");
    const packed = readTar(sent?.request.body as Uint8Array);
    expect([...packed.keys()]).toEqual(["assets/app.css", "index.html"]);
    expect(packed.get("index.html")).toBe("<!doctype html><h1>docs</h1>");
  });

  test("--channel is folded into the same request", async () => {
    const runtime = createTestRuntime({
      directories: tree({ path: "index.html", kind: "file" }),
      files: { "./dist/index.html": "hi" },
    });

    await main(["site", "push", "./dist", ...CONNECT, "--channel", "stable"], runtime);

    expect(runtime.gatewayClient.requests[0]?.request.query).toEqual([["channel", "stable"]]);
  });

  test("the archive is byte-identical for an unchanged directory", async () => {
    // Determinism: no mtimes, no uid/gid, sorted entries. A republish of an
    // unchanged site therefore has the same sha256 and is visibly a no-op.
    const first = buildTar([
      { path: "b.css", content: new TextEncoder().encode("b") },
      { path: "a.html", content: new TextEncoder().encode("a") },
    ]);
    const second = buildTar([
      { path: "a.html", content: new TextEncoder().encode("a") },
      { path: "b.css", content: new TextEncoder().encode("b") },
    ]);

    expect(first).toEqual(second);
  });

  test("a symlink in the directory is refused, not followed", async () => {
    const runtime = createTestRuntime({
      directories: tree({ path: "index.html", kind: "file" }, { path: "secrets", kind: "symlink" }),
      files: { "./dist/index.html": "hi", "./dist/secrets": "PRIVATE KEY" },
    });

    const code = await main(["site", "push", "./dist", ...CONNECT], runtime);

    expect(code).not.toBe(0);
    expect(runtime.stderr()).toContain("secrets");
    expect(runtime.stderr()).toContain("symlink");
    // Nothing was uploaded — the refusal is before the request, not after it.
    expect(runtime.gatewayClient.requests).toHaveLength(0);
  });

  test("a non-regular file is refused", async () => {
    const runtime = createTestRuntime({
      directories: tree({ path: "pipe", kind: "other" }),
    });

    const code = await main(["site", "push", "./dist", ...CONNECT], runtime);

    expect(code).not.toBe(0);
    expect(runtime.stderr()).toContain("only regular files");
    expect(runtime.gatewayClient.requests).toHaveLength(0);
  });

  test("an empty directory is refused rather than published as nothing", async () => {
    const runtime = createTestRuntime({ directories: tree() });

    const code = await main(["site", "push", "./dist", ...CONNECT], runtime);

    expect(code).not.toBe(0);
    expect(runtime.stderr()).toContain("found no files");
    expect(runtime.gatewayClient.requests).toHaveLength(0);
  });

  test("a path too long for the ustar name field is refused with the path named", async () => {
    const long = `${"d/".repeat(50)}index.html`; // 110 bytes > the 100-byte field
    const runtime = createTestRuntime({
      directories: tree({ path: long, kind: "file" }),
      files: { [`./dist/${long}`]: "hi" },
    });

    const code = await main(["site", "push", "./dist", ...CONNECT], runtime);

    expect(code).not.toBe(0);
    expect(runtime.stderr()).toContain(long);
    expect(runtime.gatewayClient.requests).toHaveLength(0);
  });

  test("a server refusal is surfaced with the server's own exit class", async () => {
    const runtime = createTestRuntime({
      directories: tree({ path: "index.html", kind: "file" }),
      files: { "./dist/index.html": "hi" },
      gatewayScript: {
        "PUT /v1/assets/static_site/docs/1.2.3": {
          status: 422,
          body: { error: { code: "asset_rejected", message: "payload.exe" } },
        },
      },
    });

    const code = await main(["site", "push", "./dist", ...CONNECT], runtime);

    expect(code).not.toBe(0);
    expect(runtime.stderr()).toContain("asset_rejected");
  });
});
