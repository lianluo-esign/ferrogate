/**
 * A fully in-memory `CliRuntime` for the tests.
 *
 * Nothing here touches a filesystem, a socket, a clock, or a real RNG, so every
 * assertion is deterministic and the suite runs offline.
 */
import type { JsonValue } from "@ferrogate/core";
import { type ContextStore, createMemoryContextStorage } from "../src/context.js";
import type {
  ConfigValidator,
  DirectoryEntry,
  FakeControlPlaneClient,
  FakeGatewayClient,
  FakeResponse,
  Io,
  KeyHasher,
} from "../src/ports.js";
import {
  createInMemoryControlPlaneClient,
  createInMemoryGatewayClient,
  createStructuralConfigValidator,
} from "../src/ports.js";
import type { CliRuntime } from "../src/runtime.js";

export interface TestRuntime extends CliRuntime {
  readonly client: FakeControlPlaneClient;
  readonly gatewayClient: FakeGatewayClient;
  readonly stdout: () => string;
  readonly stderr: () => string;
  readonly stdoutBytes: () => Uint8Array[];
}

export interface TestRuntimeOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly script?: Readonly<Record<string, FakeResponse>>;
  readonly gatewayScript?: Readonly<Record<string, FakeResponse>>;
  readonly store?: ContextStore;
  readonly files?: Readonly<Record<string, string>>;
  readonly stdin?: string;
  readonly isTty?: boolean;
  readonly configValidator?: ConfigValidator;
  readonly keyHasher?: KeyHasher;
  /** Fake directory trees for `Io.listDirectory` (#736). */
  readonly directories?: Readonly<Record<string, readonly DirectoryEntry[]>>;
}

export function createTestRuntime(options: TestRuntimeOptions = {}): TestRuntime {
  let out = "";
  let err = "";
  const bytes: Uint8Array[] = [];
  const files = new Map<string, string>(Object.entries(options.files ?? {}));
  const binaryFiles = new Map<string, Uint8Array>();

  const io: Io = {
    env: options.env ?? {},
    stdout: (text) => {
      out += text;
    },
    stderr: (text) => {
      err += text;
    },
    stdoutBytes: (value) => {
      bytes.push(value);
    },
    readStdin: async () => options.stdin ?? "",
    readFile: async (path) => {
      const value = files.get(path);
      if (value === undefined) throw new Error(`no such test file: ${path}`);
      return value;
    },
    readFileBytes: async (path) => {
      const binary = binaryFiles.get(path);
      if (binary !== undefined) return binary;
      const value = files.get(path);
      if (value === undefined) throw new Error(`no such test file: ${path}`);
      return new TextEncoder().encode(value);
    },
    writeFile: async (path, contents) => {
      files.set(path, contents);
    },
    writeFileBytes: async (path, value) => {
      binaryFiles.set(path, value);
    },
    fileExists: async (path) => files.has(path) || binaryFiles.has(path),
    // #736: `site push` walks a directory. The fake tree is declared per test
    // through `options.directories`, keyed by the path the command is given, so
    // a symlink entry can be presented WITHOUT a filesystem that supports one.
    listDirectory: async (path) => {
      const tree = (options.directories ?? {})[path.replace(/\/+$/, "")];
      if (tree === undefined) throw new Error(`no such test directory: ${path}`);
      return tree;
    },
    isStdinTty: () => options.isTty ?? false,
    // A fixed, obviously-fake byte pattern: deterministic action ids make the
    // receipt assertions exact instead of regex-shaped.
    randomBytes: (length) => new Uint8Array(length).fill(0xab),
    nowUnixSeconds: () => 1_800_000_000,
    platform: "linux",
    arch: "x64",
  };

  return {
    io,
    client: createInMemoryControlPlaneClient(options.script ?? {}),
    gatewayClient: createInMemoryGatewayClient(options.gatewayScript ?? {}),
    contextStorage: createMemoryContextStorage(options.store ?? { contexts: [] }),
    configValidator: options.configValidator ?? createStructuralConfigValidator(),
    keyHasher: options.keyHasher ?? { hash: async (secret) => `blake2b:test(${secret})` },
    stdout: () => out,
    stderr: () => err,
    stdoutBytes: () => bytes,
  };
}

/** Convenience: a 200 response carrying `body`. */
export function ok(body: JsonValue): FakeResponse {
  return { status: 200, body };
}
