/**
 * Named Control Plane API contexts and the precedence resolver.
 *
 * Clean-room port of `ferrogate-control-plane-client::context` plus the CLI's
 * `ctl/store.rs` (docs/legacy/inventory-edge-control.md §1.1 / §2.1).
 *
 * The documented contract this file owns:
 *   **flag > env > context > default**, resolved exactly once per invocation
 *   into an `EffectiveContext`. Credentials are *sources* (an env-var name or
 *   stdin) — a token value is never written to the store.
 *
 * It also owns the honesty note: `tenant` / `project` / `workspace` are
 * recorded locally but are NOT honored server-side, and the Rust CLI says so on
 * stderr. That note is preserved verbatim in spirit.
 */
import { CliError } from "./errors.js";
import type { Io } from "./ports.js";
import { type TomlTable, parseToml, stringifyToml } from "./toml.js";

/** Default endpoint when nothing else supplies one. */
export const DEFAULT_ENDPOINT = "http://127.0.0.1:8080";
/** Default request timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MILLIS = 30_000;

/** Environment variable names the resolver reads. */
export const CONTEXT_VAR = "FERROGATE_CONTEXT";
export const ENDPOINT_VAR = "FERROGATE_ENDPOINT";
export const TENANT_VAR = "FERROGATE_TENANT";
export const TIMEOUT_VAR = "FERROGATE_TIMEOUT_MILLIS";
/** Default env var a credential is read from when none is named. */
export const DEFAULT_TOKEN_VAR = "FERROGATE_TOKEN";
/** Where the context file lives when the operator overrides the location. */
export const CONFIG_HOME_VAR = "FERROGATE_CLI_HOME";
/**
 * The context store file name — `contexts.toml`, byte-compatible with the Rust
 * CLI's `ctl/store.rs` (same field names, same `current`-before-`contexts`
 * ordering). Neither Bun nor Node ships a TOML writer, so `./toml.ts`
 * implements exactly the closed subset this document can contain.
 */
export const CONTEXTS_FILE = "contexts.toml";

/**
 * The file the first TypeScript wave wrote before `contexts.toml` landed.
 *
 * Read (once) when no `contexts.toml` exists so an operator's contexts do not
 * silently vanish across the format change; the next `save` writes TOML. Never
 * written.
 */
export const LEGACY_JSON_CONTEXTS_FILE = "contexts.json";

// ---------------------------------------------------------------------------
// Credential sources
// ---------------------------------------------------------------------------

/** Where a bearer token comes from. Never the token itself, except `inline`. */
export type AuthSource =
  | { readonly kind: "none" }
  | { readonly kind: "env"; readonly var: string }
  | { readonly kind: "stdin" }
  | { readonly kind: "inline"; readonly token: string };

export const ANONYMOUS: AuthSource = { kind: "none" };

/** Human/audit spelling of a credential source; never leaks a token. */
export function describeAuth(source: AuthSource): string {
  switch (source.kind) {
    case "none":
      return "none (anonymous)";
    case "env":
      return `env:${source.var}`;
    case "stdin":
      return "stdin";
    case "inline":
      return "inline (redacted)";
  }
}

/** The `cred=` value folded into the client fingerprint (never a token). */
export function auditAuthSource(source: AuthSource): string {
  switch (source.kind) {
    case "none":
      return "none";
    case "env":
      return `env:${source.var}`;
    case "stdin":
      return "stdin";
    case "inline":
      return "inline";
  }
}

/** Resolve a credential source into a token, or `undefined` for anonymous. */
export async function resolveCredential(source: AuthSource, io: Io): Promise<string | undefined> {
  switch (source.kind) {
    case "none":
      return undefined;
    case "env": {
      const raw = io.env[source.var];
      if (raw === undefined) {
        throw CliError.auth(
          `credential source is env:${source.var} but ${source.var} is not set in the environment`,
        );
      }
      return requireNonEmptyToken(raw);
    }
    case "stdin":
      return requireNonEmptyToken((await io.readStdin()).trim());
    case "inline":
      return requireNonEmptyToken(source.token);
  }
}

function requireNonEmptyToken(token: string): string {
  if (token.trim() === "") {
    throw CliError.auth(
      "resolved an empty credential; the configured token source produced no token",
    );
  }
  return token;
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/** One named server profile. */
export interface Context {
  readonly name: string;
  readonly endpoint: string;
  readonly tenant?: string;
  readonly project?: string;
  readonly workspace?: string;
  readonly caBundlePath?: string;
  readonly tlsInsecureSkipVerify: boolean;
  readonly auth: AuthSource;
}

/** The persisted document: every context plus the selected one. */
export interface ContextStore {
  readonly contexts: readonly Context[];
  readonly current?: string;
}

export const EMPTY_STORE: ContextStore = { contexts: [] };

export function getContext(store: ContextStore, name: string): Context | undefined {
  return store.contexts.find((context) => context.name === name);
}

/** Insert or replace a context by name (order-preserving). */
export function upsertContext(store: ContextStore, context: Context): ContextStore {
  const index = store.contexts.findIndex((existing) => existing.name === context.name);
  const contexts =
    index === -1
      ? [...store.contexts, context]
      : store.contexts.map((existing, position) => (position === index ? context : existing));
  return { ...store, contexts };
}

/** Remove a context; clears `current` when it pointed at the removed one. */
export function removeContext(
  store: ContextStore,
  name: string,
): { store: ContextStore; removed: boolean } {
  const contexts = store.contexts.filter((context) => context.name !== name);
  const removed = contexts.length !== store.contexts.length;
  const current = store.current === name ? undefined : store.current;
  return {
    store: { contexts, ...(current === undefined ? {} : { current }) },
    removed,
  };
}

/** Select the current context, refusing an undefined name. */
export function setCurrentContext(store: ContextStore, name: string): ContextStore {
  if (getContext(store, name) === undefined) {
    throw CliError.usage(`no such context '${name}'; run \`context list\` to see defined contexts`);
  }
  return { ...store, current: name };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/** The file-backed store seam, so tests never touch a real filesystem. */
export interface ContextStorage {
  load(): Promise<ContextStore>;
  save(store: ContextStore): Promise<void>;
  /** Where the store lives (rendered in diagnostics). */
  path(): string;
}

/** Resolve the config directory holding the store: `$FERROGATE_CLI_HOME` > XDG > `$HOME`. */
export function contextsDirectory(env: Readonly<Record<string, string | undefined>>): string {
  const home = env[CONFIG_HOME_VAR];
  if (home !== undefined && home !== "") return home;
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg !== undefined && xdg !== "") return `${xdg}/ferrogate`;
  const userHome = env.HOME;
  if (userHome !== undefined && userHome !== "") return `${userHome}/.config/ferrogate`;
  throw CliError.usage(
    `cannot locate a config directory for contexts: set ${CONFIG_HOME_VAR}, XDG_CONFIG_HOME, or HOME`,
  );
}

/** Resolve the context file path: `<config dir>/contexts.toml`. */
export function contextsPath(env: Readonly<Record<string, string | undefined>>): string {
  return `${contextsDirectory(env)}/${CONTEXTS_FILE}`;
}

/** Resolve the pre-TOML file the first TS wave wrote, read once for migration. */
export function legacyJsonContextsPath(env: Readonly<Record<string, string | undefined>>): string {
  return `${contextsDirectory(env)}/${LEGACY_JSON_CONTEXTS_FILE}`;
}

/**
 * A `ContextStorage` backed by the injected `Io` (0600 on write).
 *
 * Reads `contexts.toml`; when that file is absent but the pre-TOML
 * `contexts.json` is present, it loads that instead so the operator's contexts
 * survive the format change. Only TOML is ever written.
 */
export function createFileContextStorage(io: Io): ContextStorage {
  const path = (): string => contextsPath(io.env);
  const parseAt = (file: string, text: string, decode: (raw: string) => unknown): ContextStore => {
    if (text.trim() === "") return EMPTY_STORE;
    try {
      return parseContextStore(decode(text));
    } catch (error) {
      throw CliError.usage(
        `failed to parse the context store at ${file}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  };
  return {
    path,
    async load() {
      const file = path();
      if (await io.fileExists(file)) {
        return parseAt(file, await io.readFile(file), parseToml);
      }
      const legacy = legacyJsonContextsPath(io.env);
      if (await io.fileExists(legacy)) {
        return parseAt(legacy, await io.readFile(legacy), (raw) => JSON.parse(raw));
      }
      return EMPTY_STORE;
    },
    async save(store) {
      await io.writeFile(path(), serializeContextStore(store));
    },
  };
}

/**
 * Render a store as `contexts.toml`, in the Rust `PersistedStore` shape:
 * snake_case field names, `current` emitted before the `[[contexts]]` array (a
 * scalar after an array-of-tables would belong to that context, not the root),
 * and optional fields omitted rather than written as empty strings.
 */
export function serializeContextStore(store: ContextStore): string {
  const document: TomlTable = {};
  if (store.current !== undefined) document.current = store.current;
  document.contexts = store.contexts.map((context) => {
    const entry: TomlTable = { name: context.name, endpoint: context.endpoint };
    if (context.tenant !== undefined) entry.tenant = context.tenant;
    if (context.project !== undefined) entry.project = context.project;
    if (context.workspace !== undefined) entry.workspace = context.workspace;
    if (context.caBundlePath !== undefined) entry.ca_bundle_path = context.caBundlePath;
    entry.tls_insecure_skip_verify = context.tlsInsecureSkipVerify;
    entry.auth = serializeAuthSource(context.auth);
    return entry;
  });
  return stringifyToml(document);
}

/**
 * The on-disk form of an `AuthSource` — the `#[serde(tag = "kind")]` shape.
 *
 * `inline` is unreachable by construction: `context create` only ever stores a
 * source (`--token-env` / `--token-stdin`), and this refuses rather than
 * writing a bearer token to disk if a future caller passes one.
 */
function serializeAuthSource(auth: AuthSource): TomlTable {
  switch (auth.kind) {
    case "none":
      return { kind: "none" };
    case "env":
      return { kind: "env", var: auth.var };
    case "stdin":
      return { kind: "stdin" };
    case "inline":
      throw CliError.usage(
        "refusing to persist an inline token to the context store; store a token SOURCE " +
          "(--token-env or --token-stdin) instead",
      );
  }
}

/** An entirely in-memory `ContextStorage` for tests and dry runs. */
export function createMemoryContextStorage(initial: ContextStore = EMPTY_STORE): ContextStorage {
  let store = initial;
  return {
    path: () => "<memory>",
    async load() {
      return store;
    },
    async save(next) {
      store = next;
    },
  };
}

/**
 * Validate a parsed document into a `ContextStore`, rejecting junk.
 *
 * Field names are the Rust `Context` serde names (`ca_bundle_path`,
 * `tls_insecure_skip_verify`), so a `contexts.toml` written by either binary
 * loads in the other. The pre-TOML camelCase spellings are still accepted so
 * the one-way `contexts.json` migration does not lose those two fields.
 */
export function parseContextStore(raw: unknown): ContextStore {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("context store must be a table");
  }
  const document = raw as Record<string, unknown>;
  const rawContexts = document.contexts ?? [];
  if (!Array.isArray(rawContexts)) throw new Error("'contexts' must be an array");
  const contexts = rawContexts.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`context #${index} must be an object`);
    }
    const value = entry as Record<string, unknown>;
    if (typeof value.name !== "string" || value.name.trim() === "") {
      throw new Error(`context #${index} is missing a name`);
    }
    if (typeof value.endpoint !== "string" || value.endpoint.trim() === "") {
      throw new Error(`context '${value.name}' is missing an endpoint`);
    }
    const optional = (...keys: readonly string[]): string | undefined => {
      for (const key of keys) {
        const found = value[key];
        if (typeof found === "string" && found !== "") return found;
      }
      return undefined;
    };
    const caBundlePath = optional("ca_bundle_path", "caBundlePath");
    const tenant = optional("tenant");
    const project = optional("project");
    const workspace = optional("workspace");
    const context: Context = {
      name: value.name,
      endpoint: value.endpoint,
      ...(tenant === undefined ? {} : { tenant }),
      ...(project === undefined ? {} : { project }),
      ...(workspace === undefined ? {} : { workspace }),
      ...(caBundlePath === undefined ? {} : { caBundlePath }),
      tlsInsecureSkipVerify:
        value.tls_insecure_skip_verify === true || value.tlsInsecureSkipVerify === true,
      auth: parseAuthSource(value.auth),
    };
    return context;
  });
  const current = typeof document.current === "string" ? document.current : undefined;
  return { contexts, ...(current === undefined ? {} : { current }) };
}

function parseAuthSource(raw: unknown): AuthSource {
  if (raw === null || raw === undefined) return ANONYMOUS;
  if (typeof raw !== "object" || Array.isArray(raw)) return ANONYMOUS;
  const value = raw as Record<string, unknown>;
  switch (value.kind) {
    case "env":
      if (typeof value.var !== "string" || value.var === "") {
        throw new Error("auth kind 'env' requires a variable name");
      }
      return { kind: "env", var: value.var };
    case "stdin":
      return { kind: "stdin" };
    case "inline":
      // A stored inline token is a credential at rest; the CLI never writes
      // one, so a store carrying one is refused rather than silently used.
      throw new Error(
        "the context store carries an inline token; store a token SOURCE (--token-env) instead",
      );
    default:
      return ANONYMOUS;
  }
}

// ---------------------------------------------------------------------------
// Precedence resolution
// ---------------------------------------------------------------------------

/** Output shape for rendered data. */
export type OutputFormat = "table" | "json";

export function parseOutputFormat(value: string): OutputFormat {
  const normalized = value.trim().toLowerCase();
  if (normalized === "table" || normalized === "text") return "table";
  if (normalized === "json") return "json";
  throw CliError.usage(`unknown output format '${normalized}'; expected one of: table, json`);
}

/** Values supplied on the command line (the highest-precedence layer). */
export interface GlobalOverrides {
  readonly context?: string;
  readonly endpoint?: string;
  readonly tenant?: string;
  readonly auth?: AuthSource;
  readonly timeoutMillis?: number;
  readonly output?: OutputFormat;
  readonly nonInteractive: boolean;
}

/** Values read from the process environment (the second layer). */
export interface EnvOverrides {
  readonly context?: string;
  readonly endpoint?: string;
  readonly tenant?: string;
  readonly timeoutMillis?: number;
}

/** Read the env layer, rejecting a non-numeric timeout rather than ignoring it. */
export function envOverrides(env: Readonly<Record<string, string | undefined>>): EnvOverrides {
  const nonEmpty = (name: string): string | undefined => {
    const value = env[name];
    return value === undefined || value.trim() === "" ? undefined : value;
  };
  const rawTimeout = nonEmpty(TIMEOUT_VAR);
  let timeoutMillis: number | undefined;
  if (rawTimeout !== undefined) {
    const parsed = Number(rawTimeout.trim());
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw CliError.usage(
        `${TIMEOUT_VAR} must be a positive integer number of milliseconds, got '${rawTimeout}'`,
      );
    }
    timeoutMillis = parsed;
  }
  const context = nonEmpty(CONTEXT_VAR);
  const endpoint = nonEmpty(ENDPOINT_VAR);
  const tenant = nonEmpty(TENANT_VAR);
  return {
    ...(context === undefined ? {} : { context }),
    ...(endpoint === undefined ? {} : { endpoint }),
    ...(tenant === undefined ? {} : { tenant }),
    ...(timeoutMillis === undefined ? {} : { timeoutMillis }),
  };
}

/** The single resolved view every command reads from. */
export interface EffectiveContext {
  readonly contextName?: string;
  readonly endpoint: string;
  readonly tenant?: string;
  readonly project?: string;
  readonly workspace?: string;
  readonly caBundlePath?: string;
  readonly tlsInsecureSkipVerify: boolean;
  readonly timeoutMillis: number;
  readonly auth: AuthSource;
  readonly output: OutputFormat;
  readonly nonInteractive: boolean;
}

/**
 * Resolve **flag > env > context > default**, exactly once per invocation.
 *
 * A named-but-undefined context is a usage error: silently falling back to the
 * default endpoint would send an admin mutation somewhere the operator did not
 * name.
 */
export function resolve(
  store: ContextStore,
  env: EnvOverrides,
  overrides: GlobalOverrides,
): EffectiveContext {
  const selectedName = overrides.context ?? env.context ?? store.current;
  let context: Context | undefined;
  if (selectedName !== undefined) {
    context = getContext(store, selectedName);
    if (context === undefined) {
      throw CliError.usage(
        `selected context '${selectedName}' is not defined; run \`context list\``,
      );
    }
  }

  const endpoint = overrides.endpoint ?? env.endpoint ?? context?.endpoint ?? DEFAULT_ENDPOINT;
  const tenant = overrides.tenant ?? env.tenant ?? context?.tenant;
  const timeoutMillis = overrides.timeoutMillis ?? env.timeoutMillis ?? DEFAULT_TIMEOUT_MILLIS;
  const auth = overrides.auth ?? context?.auth ?? ANONYMOUS;

  return {
    ...(context === undefined ? {} : { contextName: context.name }),
    endpoint,
    ...(tenant === undefined ? {} : { tenant }),
    ...(context?.project === undefined ? {} : { project: context.project }),
    ...(context?.workspace === undefined ? {} : { workspace: context.workspace }),
    ...(context?.caBundlePath === undefined ? {} : { caBundlePath: context.caBundlePath }),
    tlsInsecureSkipVerify: context?.tlsInsecureSkipVerify ?? false,
    timeoutMillis,
    auth,
    output: overrides.output ?? "table",
    nonInteractive: overrides.nonInteractive,
  };
}

/**
 * The honesty note (#1.1): `tenant`/`project`/`workspace` are recorded locally
 * but no Control Plane operation declares them, so the CLI says so rather than
 * letting the operator believe a call was narrowed.
 */
export function unhonoredScopeNotice(effective: EffectiveContext): string | undefined {
  const unsent: string[] = [];
  if (effective.project !== undefined) unsent.push("project");
  if (effective.workspace !== undefined) unsent.push("workspace");

  const parts: string[] = [];
  if (effective.tenant !== undefined) {
    parts.push(
      "note: the selected tenant is sent as the 'x-ferrogate-tenant' header, which no " +
        "Control Plane API operation declares — admin requests are scoped by the bearer " +
        "token, so this does not narrow or redirect the result. Where an operation does " +
        "accept tenant selection it is a 'tenant' query parameter: pass it as " +
        "`--filter tenant=<id>`",
    );
  }
  if (unsent.length > 0) {
    const verb = unsent.length === 1 ? "is" : "are";
    parts.push(
      `note: the selected context's ${unsent.join(" and ")} ${verb} recorded locally and ${verb} not sent with any request; scope the call with an id segment or \`--filter\` instead`,
    );
  }
  return parts.length === 0 ? undefined : parts.join("\n");
}
