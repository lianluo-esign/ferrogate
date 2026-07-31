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
import { CliError, exitClassFromHttpStatus } from "./errors.js";
import { type CaBundleReader, type FetchTlsOptions, createTlsPolicy } from "./tls.js";

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
 * The scripted `ControlPlaneClient`: answers from a script, records every call,
 * and never opens a socket.
 *
 * This is the TEST client. The shipped binary wires
 * {@link createFetchControlPlaneClient} in `createDefaultRuntime()` — see
 * `test/transport.test.ts::the shipped runtime wires the real transports`,
 * which pins that so this fake cannot drift back into production.
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

// ---------------------------------------------------------------------------
// Response classification (pure) — the Rust `transport::classify`
// ---------------------------------------------------------------------------

/** Envelope fields that are the error's own identity, not resource detail. */
const ERROR_ENVELOPE_FIELDS = ["message", "type", "code", "request_id"];

function asJsonObject(value: JsonValue | undefined): Record<string, JsonValue> | undefined {
  return value !== undefined && value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, JsonValue>)
    : undefined;
}

/** Decode a body once: JSON when it parses, the raw text when it does not. */
export function decodeBody(text: string): JsonValue {
  if (text.trim() === "") return null;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    // A 2xx with a non-JSON body (a raw export) still yields a value.
    return text;
  }
}

/**
 * The synthesized `code` for a failure whose envelope carried none.
 *
 * Reproduced arm-for-arm from the Rust `default_code_for_status`, so a coded
 * error is always available to a script branching on `code` rather than on the
 * prose message.
 */
export function defaultCodeForStatus(status: number): string {
  switch (exitClassFromHttpStatus(status)) {
    case "auth":
      return "unauthorized";
    case "not_found_conflict":
      return "not_found";
    case "validation":
      return "invalid_request";
    case "transport":
      return "retryable_error";
    case "server":
      return "server_error";
    default:
      return "error";
  }
}

/** Correlation + retry metadata carried by a response's headers. */
interface Correlation {
  readonly requestId?: string;
  readonly traceId?: string;
  readonly retryAfterSecs?: number;
}

function correlationOf(headers: Headers, body: JsonValue): Correlation {
  const header = (name: string): string | undefined => headers.get(name) ?? undefined;
  // The envelope's own `request_id` is the fallback when the edge stripped the
  // header, so a correlation id is never lost between the two spellings.
  const envelopeRequestId = asJsonObject(asJsonObject(body)?.error)?.request_id;
  const requestId =
    header("x-request-id") ??
    (typeof envelopeRequestId === "string" ? envelopeRequestId : undefined);
  const traceId = header("x-trace-id");
  const retryAfterRaw = header("retry-after")?.trim();
  const retryAfter =
    retryAfterRaw !== undefined && /^\d+$/.test(retryAfterRaw) ? Number(retryAfterRaw) : undefined;
  return {
    ...(requestId === undefined ? {} : { requestId }),
    ...(traceId === undefined ? {} : { traceId }),
    ...(retryAfter === undefined ? {} : { retryAfterSecs: retryAfter }),
  };
}

/**
 * Turn a non-2xx response into the typed `CliError` the exit-class mapping
 * consumes. Pure — a port of the error half of the Rust `classify`.
 *
 * Every field of the server's envelope survives: the code, the message, the
 * request/trace ids, the `Retry-After` hint, and **every extra key** beyond the
 * four envelope-identity fields, so a resource-specific detail (which field
 * failed validation, which quota was exceeded) is not silently dropped on the
 * one path where the operator most needs it.
 */
export function classifyFailure(status: number, headers: Headers, text: string): CliError {
  const body = decodeBody(text);
  const correlation = correlationOf(headers, body);
  const errorObject = asJsonObject(asJsonObject(body)?.error);

  const rawCode = errorObject?.code;
  const rawMessage = errorObject?.message;
  const rawRequestId = errorObject?.request_id;

  const details =
    errorObject === undefined
      ? undefined
      : Object.fromEntries(
          Object.entries(errorObject).filter(([key]) => !ERROR_ENVELOPE_FIELDS.includes(key)),
        );

  return CliError.api({
    httpStatus: status,
    code: typeof rawCode === "string" ? rawCode : defaultCodeForStatus(status),
    message:
      typeof rawMessage === "string"
        ? rawMessage
        : text.trim() === ""
          ? `request failed with HTTP ${status}`
          : text.trim(),
    ...correlation,
    ...(typeof rawRequestId === "string" ? { requestId: rawRequestId } : {}),
    ...(details === undefined || Object.keys(details).length === 0 ? {} : { details }),
  });
}

/** What the real transports need from the host process. */
export interface FetchTransportOptions {
  /** Reads a `--ca-bundle` PEM. Omit and a CA-bundle context refuses. */
  readonly readFile?: CaBundleReader;
  /** Overrides the runtime probe; only a test should pass this. */
  readonly honorsFetchTls?: boolean;
}

/** `RequestInit` plus the `tls` key Bun's fetch honours (Node's ignores it). */
type TlsRequestInit = RequestInit & { tls?: FetchTlsOptions };

/**
 * The real transport: `fetch`, per `docs/rewrite/PORT-PLAN.md` (reqwest → fetch).
 *
 * Kept behind the same port so no command module ever imports it directly.
 * Honours the context's TLS policy (see `tls.ts`) and classifies failures with
 * the same rules as the Rust client so the exit-class contract is preserved.
 */
export function createFetchControlPlaneClient(
  fetchImpl: typeof fetch = fetch,
  options: FetchTransportOptions = {},
): ControlPlaneClient {
  const tlsPolicy = createTlsPolicy(options);

  const buildUrl = (spec: RequestSpec, context: RequestContext): string => {
    if (!spec.path.startsWith("/")) {
      throw CliError.usage(`internal request path must be absolute, got '${spec.path}'`);
    }
    const base = context.endpoint.replace(/\/+$/, "");
    let url: URL;
    try {
      url = new URL(`${base}${spec.path}`);
    } catch (error) {
      throw CliError.usage(
        `invalid endpoint URL '${base}${spec.path}': ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
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
    // Resolved BEFORE the socket opens: a bad CA bundle must fail the command,
    // never fall back to the system roots mid-flight.
    const tls = await tlsPolicy(context);
    const url = buildUrl(spec, context);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), context.timeoutMillis);
    try {
      const init: TlsRequestInit = {
        method: spec.method,
        headers: buildHeaders(context, spec, accept),
        ...(spec.body === undefined ? {} : { body: JSON.stringify(spec.body) }),
        signal: controller.signal,
        ...(tls === undefined ? {} : { tls }),
      };
      return await fetchImpl(url, init);
    } catch (error) {
      throw CliError.transport(
        `request to ${url} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      clearTimeout(timer);
    }
  };

  return {
    async send(spec, context) {
      const response = await send(spec, context, "application/json");
      const text = await response.text();
      if (!response.ok) throw classifyFailure(response.status, response.headers, text);
      const body = decodeBody(text);
      const { retryAfterSecs: _ignored, ...correlation } = correlationOf(response.headers, body);
      const timeToken = response.headers.get("x-ferrogate-time-token");
      return {
        status: response.status,
        body,
        ...correlation,
        ...(timeToken === null ? {} : { timeToken }),
      };
    },
    async sendRaw(spec, mediaType, context) {
      const response = await send(spec, context, mediaType);
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (!response.ok) {
        // A failed export is a normal API error envelope, not an opaque blob:
        // decode it so the operator sees the server's code and message rather
        // than a status line.
        throw classifyFailure(response.status, response.headers, new TextDecoder().decode(bytes));
      }
      const { retryAfterSecs: _ignored, ...correlation } = correlationOf(response.headers, null);
      return { status: response.status, bytes, ...correlation };
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

/**
 * The real byte-faithful gateway client.
 *
 * Shares the TLS policy with the Control Plane transport: `assets`/`plans` reach
 * the same operator's deployment, so a private CA or an explicit
 * verification skip must apply to both or the flag is only half honoured.
 * Unlike the JSON client this one RETURNS the status instead of throwing — the
 * `assets`/`plans` handlers own their own status handling because they must
 * stream bytes on success.
 */
export function createFetchGatewayClient(
  fetchImpl: typeof fetch = fetch,
  options: FetchTransportOptions = {},
): GatewayClient {
  const tlsPolicy = createTlsPolicy(options);
  return {
    async send(request, context) {
      const tls = await tlsPolicy(context);
      const url = new URL(`${context.endpoint.replace(/\/+$/, "")}${request.path}`);
      for (const [key, value] of request.query) url.searchParams.append(key, value);
      const headers: Record<string, string> = { ...context.headers };
      if (context.token !== undefined) headers.authorization = `Bearer ${context.token}`;
      if (request.contentType !== undefined) headers["content-type"] = request.contentType;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), context.timeoutMillis);
      try {
        const init: TlsRequestInit = {
          method: request.method,
          headers,
          ...(request.body === undefined ? {} : { body: request.body }),
          signal: controller.signal,
          ...(tls === undefined ? {} : { tls }),
        };
        const response = await fetchImpl(url.toString(), init);
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
// Config validation (`@ferrogate/config` + the #542 auth-posture gate)
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
 * The shipped implementation is {@link createFerrogateConfigValidator}, which
 * runs `@ferrogate/config`'s real Caddyfile parser + `validateConfig()` gate and
 * then the #542 auth-posture gate. `createStructuralConfigValidator` remains as
 * the socket-free stand-in the argument-plumbing tests use.
 */
export interface ConfigValidator {
  validate(configPath: string, source: string): Promise<ConfigValidationReport>;
}

/**
 * A document-shape-only validator: it proves the file is present and its braces
 * balance, and nothing else.
 *
 * Kept for the tests that assert *command* behaviour (flag parsing, exit codes,
 * report rendering) without dragging the whole config schema into the fixture.
 * It is NOT what the binary runs; `createDefaultRuntime` wires the real one.
 */
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
      diagnostics.push({
        severity: "warning",
        message:
          "structural check only: this validator does not load the config schema or run the " +
          "#542 auth-posture gate (the shipped binary uses createFerrogateConfigValidator)",
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

/**
 * How a config document's text becomes a raw object.
 *
 * Caddyfile and JSON are handled in-process. TOML and YAML are handed to the
 * **Bun runtime's built-in `Bun.TOML.parse` / `Bun.YAML.parse`** — the shipped
 * `ferrogate` binary is a Bun binary, and neither parser is reachable through a
 * portable cross-runtime API, so both are injected rather than assumed. A
 * runtime that supplies neither refuses the document by name instead of
 * guessing at it (see {@link createFerrogateConfigValidator}).
 */
export interface ConfigTextParsers {
  /** Parse a TOML document, or `undefined` when the runtime provides no parser. */
  readonly toml?: (text: string) => unknown;
  /** Parse a YAML document, or `undefined` when the runtime provides no parser. */
  readonly yaml?: (text: string) => unknown;
}

/** The shape of the Bun global this module reads, as much of it as it needs. */
export interface BunTextParserHost {
  readonly Bun?: {
    readonly TOML?: { readonly parse?: (text: string) => unknown };
    readonly YAML?: { readonly parse?: (text: string) => unknown };
  };
}

/**
 * `Bun.TOML.parse` / `Bun.YAML.parse` when running under Bun; empty under plain
 * Node.
 *
 * `host` is injectable ONLY so the wiring is testable: the CLI's own suite runs
 * under Node, where both globals are absent, so a test that reads the real
 * `globalThis` cannot tell "wired YAML to `Bun.YAML`" from "wired YAML to
 * `Bun.TOML`" — both produce `undefined`. Passing a stand-in host makes each
 * arm's target observable, which is what stops the two from being swapped.
 */
export function runtimeConfigTextParsers(
  host: BunTextParserHost = globalThis as BunTextParserHost,
): ConfigTextParsers {
  const toml = host.Bun?.TOML?.parse;
  const yaml = host.Bun?.YAML?.parse;
  return {
    ...(toml === undefined ? {} : { toml: (text: string) => toml(text) }),
    ...(yaml === undefined ? {} : { yaml: (text: string) => yaml(text) }),
  };
}

/**
 * The shipped `validate` / `reload` gate: `@ferrogate/config`'s real parser and
 * `validateConfig()` cross-field gate, then the #542 auth-posture gate from
 * `config-gate.ts`.
 *
 * Format dispatch mirrors the Rust `Config::load` / `parse_structured_config`:
 *   - a file named `Caddyfile` → `fromCaddyfileStr` (the real lexer + parser);
 *   - `.json` → `JSON.parse` → `loadConfigFromObject`;
 *   - `.toml` → the injected `Bun.TOML.parse` → `loadConfigFromObject`;
 *   - `.yaml` / `.yml` → the injected `Bun.YAML.parse` → `loadConfigFromObject`,
 *     matching the Rust `serde_yaml::from_str` arm.
 *
 * A runtime that supplies no parser for the named format REFUSES the document
 * rather than guessing at it — validating a guessed parse would bless a
 * document the gateway never sees. `@ferrogate/config`'s own loader keeps its
 * `PORT-TODO(inventory §5.8)` marker because *there* the limit is real: a
 * Worker has no filesystem, so on the edge TOML/YAML decoding is a build/deploy
 * step. It is not real here — `ferrogate` is a Bun process with both a
 * filesystem and `Bun.YAML`, which is why this leg is implemented rather than
 * deferred.
 *
 * `@ferrogate/config` is imported lazily so the CLI's fast paths (`ctl`,
 * `context`, `completions`) never pull the config schema into the process.
 */
export function createFerrogateConfigValidator(
  parsers: ConfigTextParsers = runtimeConfigTextParsers(),
): ConfigValidator {
  return {
    async validate(configPath, source) {
      const [config, gate] = await Promise.all([
        import("@ferrogate/config"),
        import("./config-gate.js"),
      ]);
      const diagnostics: ConfigDiagnostic[] = [];
      const fileName = configPath.split(/[\\/]/).pop() ?? configPath;
      const lowered = fileName.toLowerCase();

      let loaded: { config: import("@ferrogate/config").Config; warnings: string[] } | undefined;
      try {
        if (config.isCaddyfilePath(configPath)) {
          loaded = config.fromCaddyfileStr(source, configPath);
        } else if (lowered.endsWith(".json")) {
          loaded = config.loadConfigFromObject(JSON.parse(source) as Record<string, unknown>);
        } else if (lowered.endsWith(".toml")) {
          if (parsers.toml === undefined) {
            throw new Error(
              `cannot read ${fileName}: this runtime provides no TOML parser. The shipped ` +
                "`ferrogate` binary is a Bun binary and uses Bun.TOML; under a non-Bun runtime " +
                "pass the config as JSON (or a Caddyfile) rather than have the CLI guess at it",
            );
          }
          loaded = config.loadConfigFromObject(parsers.toml(source) as Record<string, unknown>);
        } else if (lowered.endsWith(".yaml") || lowered.endsWith(".yml")) {
          if (parsers.yaml === undefined) {
            throw new Error(
              `cannot read ${fileName}: this runtime provides no YAML parser. The shipped ` +
                "`ferrogate` binary is a Bun binary and uses Bun.YAML; under a non-Bun runtime " +
                "pass the config as JSON (or a Caddyfile) rather than have the CLI guess at it",
            );
          }
          loaded = config.loadConfigFromObject(parsers.yaml(source) as Record<string, unknown>);
        } else {
          throw new Error(
            `cannot infer the format of ${fileName}: name it 'Caddyfile' or give it a .toml, ` +
              ".yaml or .json extension",
          );
        }
      } catch (error) {
        diagnostics.push({
          severity: "error",
          message: error instanceof Error ? error.message : String(error),
          path: configPath,
        });
        return { configPath, ok: false, diagnostics, summary: {} };
      }

      for (const warning of loaded.warnings) {
        diagnostics.push({ severity: "warning", message: warning });
      }

      // The cluster snapshot key parse is the one leg that cannot be
      // synchronous on Workers (WebCrypto importKey), so `validateConfig` — run
      // inside the loader above — leaves it to `validateConfigAsync`.
      try {
        await config.validateConfigAsync(loaded.config);
      } catch (error) {
        diagnostics.push({
          severity: "error",
          message: error instanceof Error ? error.message : String(error),
          path: configPath,
        });
        return { configPath, ok: false, diagnostics, summary: {} };
      }

      const report = gate.validateReport(loaded.config);
      for (const warning of report.warnings) {
        diagnostics.push({ severity: "warning", message: warning });
      }
      if (report.refusal !== undefined) {
        diagnostics.push({ severity: "error", message: report.refusal });
      }
      return {
        configPath,
        ok: report.refusal === undefined,
        diagnostics,
        summary: { ...report.summary },
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
