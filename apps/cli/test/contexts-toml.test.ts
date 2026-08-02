/**
 * `contexts.toml`: the persisted context-store format.
 *
 * The Rust CLI writes this file with `toml::to_string_pretty` over
 * `PersistedStore { current, contexts }` (`crates/ferrogate-cli/src/ctl/store.rs`).
 * These tests pin BOTH directions: the exact document this port emits, and that
 * it reads a document laid out the way the Rust binary lays one out.
 */
import { describe, expect, test } from "vitest";
import {
  CONTEXTS_FILE,
  type Context,
  type ContextStore,
  LEGACY_JSON_CONTEXTS_FILE,
  contextsPath,
  createFileContextStorage,
  legacyJsonContextsPath,
  parseContextStore,
  serializeContextStore,
} from "../src/context.js";
import { main } from "../src/index.js";
import type { Io } from "../src/ports.js";
import { parseToml, stringifyToml } from "../src/toml.js";
import { createTestRuntime } from "./helpers.js";

function fileIo(files: Map<string, string>, env: Record<string, string>): Io {
  return {
    env,
    stdout: () => {},
    stderr: () => {},
    stdoutBytes: () => {},
    readStdin: async () => "",
    readFile: async (path) => {
      const value = files.get(path);
      if (value === undefined) throw new Error(`no such file: ${path}`);
      return value;
    },
    readFileBytes: async (path) =>
      new TextEncoder().encode(await Promise.resolve(files.get(path) ?? "")),
    writeFile: async (path, contents) => {
      files.set(path, contents);
    },
    writeFileBytes: async () => {},
    fileExists: async (path) => files.has(path),
    isStdinTty: () => false,
    randomBytes: (length) => new Uint8Array(length),
    nowUnixSeconds: () => 0,
    platform: "linux",
    arch: "x64",
  };
}

const FULL: Context = {
  name: "prod",
  endpoint: "https://control.example.com",
  tenant: "acme",
  project: "checkout",
  workspace: "eu",
  caBundlePath: "/etc/ssl/corp.pem",
  tlsInsecureSkipVerify: true,
  auth: { kind: "env", var: "FERROGATE_TOKEN" },
};

describe("contexts.toml serialization", () => {
  test("emits the Rust PersistedStore document verbatim", () => {
    const store: ContextStore = { contexts: [FULL], current: "prod" };
    expect(serializeContextStore(store)).toBe(
      [
        'current = "prod"',
        "",
        "[[contexts]]",
        'name = "prod"',
        'endpoint = "https://control.example.com"',
        'tenant = "acme"',
        'project = "checkout"',
        'workspace = "eu"',
        'ca_bundle_path = "/etc/ssl/corp.pem"',
        "tls_insecure_skip_verify = true",
        "",
        "[contexts.auth]",
        'kind = "env"',
        'var = "FERROGATE_TOKEN"',
        "",
      ].join("\n"),
    );
  });

  test("`current` is emitted BEFORE [[contexts]] (a scalar after it would bind to the context)", () => {
    const text = serializeContextStore({ contexts: [FULL], current: "prod" });
    expect(text.indexOf("current =")).toBeLessThan(text.indexOf("[[contexts]]"));
    // Round-tripping proves the ordering is not merely cosmetic.
    expect(parseContextStore(parseToml(text)).current).toBe("prod");
  });

  test("omits unset optional fields rather than writing empty strings", () => {
    const text = serializeContextStore({
      contexts: [
        {
          name: "dev",
          endpoint: "http://127.0.0.1:8080",
          tlsInsecureSkipVerify: false,
          auth: { kind: "none" },
        },
      ],
    });
    expect(text).not.toContain("tenant");
    expect(text).not.toContain("project");
    expect(text).not.toContain("ca_bundle_path");
    expect(text).not.toContain("current");
    expect(text).toContain("tls_insecure_skip_verify = false");
  });

  test("round-trips every context field", () => {
    const store: ContextStore = {
      contexts: [
        FULL,
        {
          name: "dev",
          endpoint: "http://x",
          tlsInsecureSkipVerify: false,
          auth: { kind: "stdin" },
        },
      ],
      current: "dev",
    };
    expect(parseContextStore(parseToml(serializeContextStore(store)))).toEqual(store);
  });

  test("refuses to persist an inline token", () => {
    expect(() =>
      serializeContextStore({
        contexts: [
          {
            name: "x",
            endpoint: "http://x",
            tlsInsecureSkipVerify: false,
            auth: { kind: "inline", token: "sk-live" },
          },
        ],
      }),
    ).toThrow(/refusing to persist an inline token/);
  });

  test("escapes a value that would otherwise break the document", () => {
    const text = serializeContextStore({
      contexts: [
        {
          name: 'we"ird\n',
          endpoint: "http://x",
          tlsInsecureSkipVerify: false,
          auth: { kind: "none" },
        },
      ],
    });
    expect(text).toContain('name = "we\\"ird\\n"');
    expect(parseContextStore(parseToml(text)).contexts[0]?.name).toBe('we"ird\n');
  });
});

describe("contexts.toml parsing (a document the Rust binary would write)", () => {
  const rustish = `# ferrogate contexts
current = "prod"

[[contexts]]
name = "prod"
endpoint = "https://control.example.com"
tenant = "acme"
tls_insecure_skip_verify = false

[contexts.auth]
kind = "env"
var = "PROD_TOKEN"

[[contexts]]
name = "lab"
endpoint = 'http://127.0.0.1:8080'
tls_insecure_skip_verify = true

[contexts.auth]
kind = "none"
`;

  test("reads both contexts, their auth tables and the selection", () => {
    const store = parseContextStore(parseToml(rustish));
    expect(store.current).toBe("prod");
    expect(store.contexts).toHaveLength(2);
    expect(store.contexts[0]?.auth).toEqual({ kind: "env", var: "PROD_TOKEN" });
    expect(store.contexts[0]?.tlsInsecureSkipVerify).toBe(false);
    expect(store.contexts[1]?.endpoint).toBe("http://127.0.0.1:8080");
    expect(store.contexts[1]?.tlsInsecureSkipVerify).toBe(true);
    expect(store.contexts[1]?.auth).toEqual({ kind: "none" });
  });

  test("refuses a stored inline token instead of using it", () => {
    const document = `[[contexts]]\nname = "x"\nendpoint = "http://x"\n\n[contexts.auth]\nkind = "inline"\ntoken = "sk-live"\n`;
    expect(() => parseContextStore(parseToml(document))).toThrow(/inline token/);
  });
});

describe("the supported TOML subset refuses what it cannot represent", () => {
  test.each([
    ["arrays", "x = [1, 2]", /arrays are not supported/],
    ["inline tables", "x = { a = 1 }", /inline tables are not supported/],
    ["multi-line basic strings", 'x = """a"""', /multi-line basic strings/],
    ["multi-line literal strings", "x = '''a'''", /multi-line literal strings/],
    ["floats", "x = 1.5", /unsupported value/],
    ["dotted-key assignment", 'a.b = "c"', /dotted-key assignments/],
    ["a line that is not a pair", "nonsense", /expected 'key = value'/],
    ["an unterminated string", 'x = "abc', /unterminated string/],
    ["a duplicate key", 'x = "a"\nx = "b"', /duplicate key/],
    ["an unterminated table header", "[oops", /unterminated table header/],
  ])("rejects %s", (_label, document, expected) => {
    expect(() => parseToml(document)).toThrow(expected);
  });

  test("a rejection names the line so the operator can find it", () => {
    expect(() => parseToml('a = "ok"\n\nb = [1]\n')).toThrow(/line 3/);
  });

  test("comments and blank lines are ignored", () => {
    expect(parseToml('# lead\n\nx = "1" # trailing\n')).toEqual({ x: "1" });
  });

  test("the writer refuses a value shape the reader could not round-trip", () => {
    expect(() => stringifyToml({ x: 1.5 })).toThrow(/non-integer/);
    expect(() => stringifyToml({ x: ["a"] as never })).toThrow(/non-table array/);
  });
});

describe("file-backed storage", () => {
  const env = { FERROGATE_CLI_HOME: "/cfg" };

  test("writes contexts.toml at the resolved path and reads it back", async () => {
    const files = new Map<string, string>();
    const storage = createFileContextStorage(fileIo(files, env));
    expect(storage.path()).toBe(`/cfg/${CONTEXTS_FILE}`);
    await storage.save({ contexts: [FULL], current: "prod" });
    expect(files.get("/cfg/contexts.toml")).toContain("[[contexts]]");
    expect(await storage.load()).toEqual({ contexts: [FULL], current: "prod" });
  });

  test("a missing store is an empty store, not an error", async () => {
    const storage = createFileContextStorage(fileIo(new Map(), env));
    expect(await storage.load()).toEqual({ contexts: [] });
  });

  test("migrates a pre-TOML contexts.json when no contexts.toml exists", async () => {
    const files = new Map<string, string>([
      [
        `/cfg/${LEGACY_JSON_CONTEXTS_FILE}`,
        JSON.stringify({
          current: "old",
          contexts: [
            {
              name: "old",
              endpoint: "https://old",
              caBundlePath: "/old.pem",
              tlsInsecureSkipVerify: true,
              auth: { kind: "env", var: "OLD" },
            },
          ],
        }),
      ],
    ]);
    const storage = createFileContextStorage(fileIo(files, env));
    expect(legacyJsonContextsPath(env)).toBe("/cfg/contexts.json");
    const loaded = await storage.load();
    // The camelCase legacy spellings must survive the migration.
    expect(loaded.contexts[0]?.caBundlePath).toBe("/old.pem");
    expect(loaded.contexts[0]?.tlsInsecureSkipVerify).toBe(true);
    // The next save writes TOML, and never rewrites the JSON.
    await storage.save(loaded);
    expect(files.get("/cfg/contexts.toml")).toContain("ca_bundle_path");
    expect(files.get(`/cfg/${LEGACY_JSON_CONTEXTS_FILE}`)).toContain("caBundlePath");
  });

  test("contexts.toml wins over a stale contexts.json", async () => {
    const files = new Map<string, string>([
      [
        `/cfg/${CONTEXTS_FILE}`,
        'current = "new"\n\n[[contexts]]\nname = "new"\nendpoint = "https://new"\n',
      ],
      [
        `/cfg/${LEGACY_JSON_CONTEXTS_FILE}`,
        JSON.stringify({ contexts: [{ name: "old", endpoint: "https://old" }] }),
      ],
    ]);
    const storage = createFileContextStorage(fileIo(files, env));
    expect((await storage.load()).contexts.map((context) => context.name)).toEqual(["new"]);
  });

  test("a corrupt store is a usage error naming the file and the line", async () => {
    const files = new Map<string, string>([[`/cfg/${CONTEXTS_FILE}`, "nonsense\n"]]);
    const storage = createFileContextStorage(fileIo(files, env));
    await expect(storage.load()).rejects.toThrow(/\/cfg\/contexts\.toml.*line 1/s);
  });

  test("XDG and HOME fall back under a ferrogate/ directory", () => {
    expect(contextsPath({ XDG_CONFIG_HOME: "/x" })).toBe("/x/ferrogate/contexts.toml");
    expect(contextsPath({ HOME: "/home/o" })).toBe("/home/o/.config/ferrogate/contexts.toml");
    expect(() => contextsPath({})).toThrow(/FERROGATE_CLI_HOME/);
  });
});

describe("end to end through the context verbs", () => {
  test("`context create` persists TOML that `context list` reads back", async () => {
    const files = new Map<string, string>();
    const io = fileIo(files, { FERROGATE_CLI_HOME: "/cfg" });
    let out = "";
    const runtime = {
      ...createTestRuntime(),
      io: {
        ...io,
        stdout: (text: string) => {
          out += text;
        },
      },
      contextStorage: createFileContextStorage({
        ...io,
        stdout: (text: string) => {
          out += text;
        },
      }),
    };
    expect(
      await main(
        ["context", "create", "prod", "--endpoint", "https://x", "--token-env", "TOK", "--use"],
        runtime,
      ),
    ).toBe(0);
    const written = files.get("/cfg/contexts.toml") as string;
    expect(written).toContain("[[contexts]]");
    expect(written).toContain('var = "TOK"');
    expect(written).not.toContain("sk-");
    out = "";
    expect(await main(["context", "list"], runtime)).toBe(0);
    expect(out).toContain("prod");
    expect(out).toContain("env:TOK");
  });
});
