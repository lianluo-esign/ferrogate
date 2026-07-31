/**
 * Narrow ports the CLI codes against (dependency inversion).
 *
 * The wave-2 library packages (`@ferrogate/config`, `storage`, `billing`, …)
 * are being rewritten concurrently, so this app declares the *shape* of what it
 * needs and ships an in-memory default for each. Only `@ferrogate/core` — which
 * is real — is imported directly.
 *
 * Everything the CLI touches that is not pure computation lives behind one of
 * these interfaces, which is also what makes the whole binary testable without
 * a filesystem, a clock, an RNG, or a socket.
 */
import type { JsonValue } from "@ferrogate/core";
import { CliError } from "./errors.js";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";

/** A fully-built request, independent of any HTTP client. */
export interface RequestSpec {
  readonly method: HttpMethod;
  readonly path: string;
  /** Ordered, repeatable query parameters (`sort` is order-significant). */
  readonly query: readonly (readonly [string, string])[];
  readonly body?: JsonValue;
}

/** What the transport needs to know about the caller for one invocation. */
export interface RequestContext {
  readonly endpoint: string;
  readonly token?: string;
  readonly timeoutMillis: number;
  readonly tenant?: string;
  /** Per-invocation action identity headers (see `action-identity.ts`). */
  readonly headers: Readonly<Record<string, string>>;
  readonly tlsInsecureSkipVerify: boolean;
  readonly caBundlePath?: string;
}

/** A decoded, structured Control Plane response. */
export interface ApiResponse {
  readonly status: number;
  readonly body: JsonValue;
  readonly requestId?: string;
  readonly traceId?: string;
  /** Server-issued time token, when the response carried one. */
  readonly timeToken?: string;
}

/** A byte-faithful export response (`request-logs export`). */
export interface RawApiResponse {
  readonly status: number;
  readonly bytes: Uint8Array;
  readonly requestId?: string;
  readonly traceId?: string;
}

/**
 * The Control Plane API client seam.
 *
 * `send` MUST throw a `CliError` built with `CliError.api(...)` for a non-2xx
 * response so the exit-class mapping stays in one place.
 */
export interface ControlPlaneClient {
  send(spec: RequestSpec, context: RequestContext): Promise<ApiResponse>;
  sendRaw(spec: RequestSpec, mediaType: string, context: RequestContext): Promise<RawApiResponse>;
}

/** A scripted response for the in-memory client. */
export interface FakeResponse {
  readonly status?: number;
  readonly body?: JsonValue;
  readonly bytes?: Uint8Array;
  readonly requestId?: string;
  readonly traceId?: string;
}

/** A request the in-memory client observed, for assertions. */
export interface RecordedRequest {
  readonly spec: RequestSpec;
  readonly context: RequestContext;
  readonly mediaType?: string;
}

export interface FakeControlPlaneClient extends ControlPlaneClient {
  readonly requests: readonly RecordedRequest[];
}

/** Build the routing key the in-memory client scripts against. */
export function requestKey(spec: RequestSpec): string {
  return `${spec.method} ${spec.path}`;
}

/**
 * The default `ControlPlaneClient`: answers from a script, records every call,
 * and never opens a socket. This is what `ferrogate` uses until the real
 * `fetch` transport is wired in `createFetchControlPlaneClient`.
 */
export function createInMemoryControlPlaneClient(
  script: Readonly<Record<string, FakeResponse>> = {},
): FakeControlPlaneClient {
  const requests: RecordedRequest[] = [];
  const lookup = (spec: RequestSpec): FakeResponse =>
    script[requestKey(spec)] ?? script[spec.path] ?? { status: 200, body: {} };

  return {
    requests,
    async send(spec, context) {
      requests.push({ spec, context });
      const scripted = lookup(spec);
      const status = scripted.status ?? 200;
      if (status < 200 || status > 299) {
        throw CliError.api({
          httpStatus: status,
          code: "scripted_error",
          message: `the in-memory control-plane client was scripted to answer ${status}`,
          ...(scripted.requestId === undefined ? {} : { requestId: scripted.requestId }),
        });
      }
      return {
        status,
        body: scripted.body ?? {},
        ...(scripted.requestId === undefined ? {} : { requestId: scripted.requestId }),
        ...(scripted.traceId === undefined ? {} : { traceId: scripted.traceId }),
      };
    },
    async sendRaw(spec, mediaType, context) {
      requests.push({ spec, context, mediaType });
      const scripted = lookup(spec);
      return {
        status: scripted.status ?? 200,
        bytes: scripted.bytes ?? new Uint8Array(),
        ...(scripted.requestId === undefined ? {} : { requestId: scripted.requestId }),
        ...(scripted.traceId === undefined ? {} : { traceId: scripted.traceId }),
      };
    },
  };
}

/**
 * The real transport: `fetch`, per `docs/rewrite/PORT-PLAN.md` (reqwest → fetch).
 *
 * Kept behind the same port so no command module ever imports it directly.
 */
export function createFetchControlPlaneClient(fetchImpl: typeof fetch = fetch): ControlPlaneClient {
  const buildUrl = (spec: RequestSpec, context: RequestContext): string => {
    const base = context.endpoint.replace(/\/+$/, "");
    const url = new URL(`${base}${spec.path}`);
    for (const [key, value] of spec.query) url.searchParams.append(key, value);
    return url.toString();
  };

  const buildHeaders = (
    context: RequestContext,
    spec: RequestSpec,
    accept: string,
  ): Record<string, string> => {
    const headers: Record<string, string> = { ...context.headers, accept };
    if (context.token !== undefined) headers.authorization = `Bearer ${context.token}`;
    if (context.tenant !== undefined) headers["x-ferrogate-tenant"] = context.tenant;
    if (spec.body !== undefined) headers["content-type"] = "application/json";
    return headers;
  };

  const send = async (
    spec: RequestSpec,
    context: RequestContext,
    accept: string,
  ): Promise<Response> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), context.timeoutMillis);
    try {
      return await fetchImpl(buildUrl(spec, context), {
        method: spec.method,
        headers: buildHeaders(context, spec, accept),
        ...(spec.body === undefined ? {} : { body: JSON.stringify(spec.body) }),
        signal: controller.signal,
      });
    } catch (error) {
      throw CliError.transport(
        `request to ${context.endpoint}${spec.path} failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    } finally {
      clearTimeout(timer);
    }
  };

  const correlation = (response: Response) => ({
    ...(response.headers.get("x-request-id") === null
      ? {}
      : { requestId: response.headers.get("x-request-id") as string }),
    ...(response.headers.get("x-trace-id") === null
      ? {}
      : { traceId: response.headers.get("x-trace-id") as string }),
  });

  return {
    async send(spec, context) {
      const response = await send(spec, context, "application/json");
      const text = await response.text();
      let body: JsonValue = null;
      if (text.trim() !== "") {
        try {
          body = JSON.parse(text) as JsonValue;
        } catch {
          body = text;
        }
      }
      if (!response.ok) {
        const envelope =
          body !== null && typeof body === "object" && !Array.isArray(body)
            ? (body as Record<string, JsonValue>)
            : {};
        const nested =
          envelope.error !== undefined &&
          typeof envelope.error === "object" &&
          envelope.error !== null &&
          !Array.isArray(envelope.error)
            ? (envelope.error as Record<string, JsonValue>)
            : envelope;
        throw CliError.api({
          httpStatus: response.status,
          code: typeof nested.code === "string" ? nested.code : "unknown",
          message: typeof nested.message === "string" ? nested.message : response.statusText,
          ...correlation(response),
          ...(nested.details === undefined ? {} : { details: nested.details }),
        });
      }
      const timeToken = response.headers.get("x-ferrogate-time-token");
      return {
        status: response.status,
        body,
        ...correlation(response),
        ...(timeToken === null ? {} : { timeToken }),
      };
    },
    async sendRaw(spec, mediaType, context) {
      const response = await send(spec, context, mediaType);
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (!response.ok) {
        throw CliError.api({
          httpStatus: response.status,
          code: "export_failed",
          message: response.statusText,
          ...correlation(response),
        });
      }
      return { status: response.status, bytes, ...correlation(response) };
    },
  };
}

// ---------------------------------------------------------------------------
// Gateway (byte-faithful) transport — `assets` / `plans`
// ---------------------------------------------------------------------------

/**
 * The legacy gateway-direct seam used by top-level `assets` and `plans`.
 *
 * These commands predate `ctl` and talk to the data-plane gateway with
 * `--gateway-url` + `--api-key`, uploading and downloading **bytes**, so they
 * cannot ride the JSON-only `ControlPlaneClient`.
 */
export interface BinaryRequest {
  readonly method: HttpMethod;
  readonly path: string;
  readonly query: readonly (readonly [string, string])[];
  readonly contentType?: string;
  readonly body?: Uint8Array;
}

export interface BinaryResponse {
  readonly status: number;
  readonly bytes: Uint8Array;
  readonly requestId?: string;
}

export interface GatewayClient {
  send(request: BinaryRequest, context: RequestContext): Promise<BinaryResponse>;
}

export interface FakeGatewayClient extends GatewayClient {
  readonly requests: readonly { request: BinaryRequest; context: RequestContext }[];
}

/** Scripted, socket-free gateway client (the default). */
export function createInMemoryGatewayClient(
  script: Readonly<Record<string, FakeResponse>> = {},
): FakeGatewayClient {
  const requests: { request: BinaryRequest; context: RequestContext }[] = [];
  return {
    requests,
    async send(request, context) {
      requests.push({ request, context });
      const scripted = script[`${request.method} ${request.path}`] ?? script[request.path] ?? {};
      const bytes =
        scripted.bytes ?? new TextEncoder().encode(JSON.stringify(scripted.body ?? { ok: true }));
      return {
        status: scripted.status ?? 200,
        bytes,
        ...(scripted.requestId === undefined ? {} : { requestId: scripted.requestId }),
      };
    },
  };
}

/** The real byte-faithful gateway client. */
export function createFetchGatewayClient(fetchImpl: typeof fetch = fetch): GatewayClient {
  return {
    async send(request, context) {
      const url = new URL(`${context.endpoint.replace(/\/+$/, "")}${request.path}`);
      for (const [key, value] of request.query) url.searchParams.append(key, value);
      const headers: Record<string, string> = { ...context.headers };
      if (context.token !== undefined) headers.authorization = `Bearer ${context.token}`;
      if (request.contentType !== undefined) headers["content-type"] = request.contentType;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), context.timeoutMillis);
      try {
        const response = await fetchImpl(url.toString(), {
          method: request.method,
          headers,
          ...(request.body === undefined ? {} : { body: request.body }),
          signal: controller.signal,
        });
        const requestId = response.headers.get("x-request-id");
        return {
          status: response.status,
          bytes: new Uint8Array(await response.arrayBuffer()),
          ...(requestId === null ? {} : { requestId }),
        };
      } catch (error) {
        throw CliError.transport(
          `request to ${context.endpoint}${request.path} failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Process seams
// ---------------------------------------------------------------------------

/** Everything the CLI reads from or writes to the outside world. */
export interface Io {
  readonly env: Readonly<Record<string, string | undefined>>;
  stdout(text: string): void;
  stderr(text: string): void;
  /** Byte-faithful stdout, used by the raw export path. */
  stdoutBytes(bytes: Uint8Array): void;
  readStdin(): Promise<string>;
  readFile(path: string): Promise<string>;
  readFileBytes(path: string): Promise<Uint8Array>;
  writeFile(path: string, contents: string): Promise<void>;
  writeFileBytes(path: string, bytes: Uint8Array): Promise<void>;
  fileExists(path: string): Promise<boolean>;
  /** True when stdin is an interactive terminal (drives the confirmation prompt). */
  isStdinTty(): boolean;
  /** Cryptographically-strong random bytes (action-id minting). */
  randomBytes(length: number): Uint8Array;
  /** Unix seconds. */
  nowUnixSeconds(): number;
  /** Platform facts folded into the client fingerprint. */
  readonly platform: string;
  readonly arch: string;
}

/** Minimal filesystem+process `Io` for the shipped binary. */
export function createNodeIo(): Io {
  // Imported lazily so unit tests never pull node:fs into the graph.
  const fs = fsPromises();
  return {
    env: process.env,
    stdout: (text) => {
      process.stdout.write(text);
    },
    stderr: (text) => {
      process.stderr.write(text);
    },
    stdoutBytes: (bytes) => {
      process.stdout.write(bytes);
    },
    readStdin: async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
      return Buffer.concat(chunks).toString("utf8");
    },
    readFile: async (path) => (await fs).readFile(path, "utf8"),
    readFileBytes: async (path) => new Uint8Array(await (await fs).readFile(path)),
    writeFile: async (path, contents) => {
      const mod = await fs;
      await mod.mkdir(dirname(path), { recursive: true });
      await mod.writeFile(path, contents, { mode: 0o600 });
    },
    writeFileBytes: async (path, bytes) => {
      const mod = await fs;
      await mod.mkdir(dirname(path), { recursive: true });
      await mod.writeFile(path, bytes);
    },
    fileExists: async (path) => {
      try {
        await (await fs).stat(path);
        return true;
      } catch {
        return false;
      }
    },
    isStdinTty: () => process.stdin.isTTY === true,
    randomBytes: (length) => {
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);
      return bytes;
    },
    nowUnixSeconds: () => Math.floor(Date.now() / 1000),
    platform: process.platform,
    arch: process.arch,
  };
}

function fsPromises(): Promise<typeof import("node:fs/promises")> {
  return import("node:fs/promises");
}

function dirname(path: string): string {
  const index = path.lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}

// ---------------------------------------------------------------------------
// Config validation (stands in for @ferrogate/config, rewritten concurrently)
// ---------------------------------------------------------------------------

/** One diagnostic from a config validation pass. */
export interface ConfigDiagnostic {
  readonly severity: "error" | "warning";
  readonly message: string;
  readonly path?: string;
}

export interface ConfigValidationReport {
  readonly configPath: string;
  readonly ok: boolean;
  readonly diagnostics: readonly ConfigDiagnostic[];
  /** Free-form facts the human renderer prints (route counts, upstreams, …). */
  readonly summary: Readonly<Record<string, string | number | boolean>>;
}

/**
 * The `validate` / `reload` seam.
 *
 * PORT-TODO(inventory-edge-control.md §1.1): swap the default for
 * `@ferrogate/config`'s real Caddyfile parser + auth-posture gate once that
 * package lands. The interface is deliberately the whole contract the CLI
 * needs, so the swap is one line in `index.ts`.
 */
export interface ConfigValidator {
  validate(configPath: string, source: string): Promise<ConfigValidationReport>;
}

/** A validator that checks the file is present and parses as a document. */
export function createStructuralConfigValidator(): ConfigValidator {
  return {
    async validate(configPath, source) {
      const diagnostics: ConfigDiagnostic[] = [];
      const trimmed = source.trim();
      if (trimmed === "") {
        diagnostics.push({ severity: "error", message: "config file is empty" });
      }
      let braces = 0;
      for (const char of source) {
        if (char === "{") braces += 1;
        if (char === "}") braces -= 1;
        if (braces < 0) break;
      }
      if (braces !== 0) {
        diagnostics.push({
          severity: "error",
          message: `unbalanced braces in ${configPath} (depth ${braces} at end of file)`,
        });
      }
      // PORT-TODO(inventory-edge-control.md §1.1): the Rust `validate` also runs
      // the auth-posture gate (refuses an admin surface with no credential
      // configured). That gate lives in @ferrogate/config and is reported here
      // as a warning until the package exposes it.
      diagnostics.push({
        severity: "warning",
        message:
          "auth-posture gate not evaluated: @ferrogate/config is still being ported (PORT-TODO §1.1)",
      });
      return {
        configPath,
        ok: !diagnostics.some((diagnostic) => diagnostic.severity === "error"),
        diagnostics,
        summary: { bytes: source.length, lines: source.split("\n").length },
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Key hashing
// ---------------------------------------------------------------------------

/**
 * `hash-key` reproduces `ferrogate_gateway::auth::hash_api_key_secret`:
 * `blake2b:<128 lowercase hex>` over BLAKE2b-512 of the UTF-8 secret.
 */
export interface KeyHasher {
  hash(secret: string): Promise<string>;
}

export function createNodeKeyHasher(): KeyHasher {
  return {
    async hash(secret) {
      const { createHash } = await import("node:crypto");
      try {
        const digest = createHash("blake2b512").update(secret, "utf8").digest("hex");
        return `blake2b:${digest}`;
      } catch (error) {
        throw CliError.transport(
          `BLAKE2b-512 is unavailable in this runtime, so the produced hash would not match the gateway's stored value; refusing to emit a wrong hash (${
            error instanceof Error ? error.message : String(error)
          })`,
        );
      }
    },
  };
}
