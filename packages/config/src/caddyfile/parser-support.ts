/**
 * Port of the free helper functions in `ferrogate-config`'s
 * `caddyfile/parser_support.rs` (the `Parser`-method helpers live on the
 * `Parser` class in `parser.ts`).
 */

/**
 * Map a Caddy site address to `(listenAddr, hostMatch)`.
 * - `:PORT` -> bind `127.0.0.1:PORT`, no host constraint.
 * - `host:port` -> bind `<host|127.0.0.1>:port`; `0.0.0.0` never becomes a
 *   Host-header match (issue #155), `localhost` binds to `127.0.0.1`.
 * - bare `host` -> no listen override, match that host (lowercased).
 */
export function adaptSiteAddress(address: string): {
  listen: string | null;
  host: string | null;
} {
  if (address.startsWith(":")) {
    const port = address.slice(1);
    return { listen: `127.0.0.1:${port}`, host: null };
  }
  if (address.includes(":")) {
    const lastColon = address.lastIndexOf(":");
    const host = address.slice(0, lastColon) || "127.0.0.1";
    const port = address.slice(lastColon + 1) || "8080";
    const listenHost = host === "localhost" ? "127.0.0.1" : host;
    const hostMatch = host === "0.0.0.0" ? null : host.toLowerCase();
    return { listen: `${listenHost}:${port}`, host: hostMatch };
  }
  return { listen: null, host: address.toLowerCase() };
}

/** Strip a trailing `*` and `/` from a Caddy path matcher; `""` -> `/`. */
export function caddyPathToPrefix(path: string): string {
  const trimmed = path.replace(/\*+$/, "").replace(/\/+$/, "");
  return trimmed.length === 0 ? "/" : trimmed;
}

/** Whether a value looks like an upstream URL (`http://` / `https://`). */
export function looksLikeUpstream(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://");
}

/** Extract the env-var name from `env.NAME`, `{env.NAME}` or `{$NAME}`. */
export function envReference(value: string): string | null {
  let env: string | undefined;
  if (value.startsWith("env.")) {
    env = value.slice("env.".length);
  } else if (value.startsWith("{env.") && value.endsWith("}")) {
    env = value.slice("{env.".length, -1);
  } else if (value.startsWith("{$") && value.endsWith("}")) {
    env = value.slice("{$".length, -1);
  }
  return env !== undefined && env.length > 0 ? env : null;
}

/** Find the `-> <provider>:<model>` (or first `x:y`) argument of a `model` directive. */
export function modelRefArg(args: string[]): string | null {
  for (let i = 0; i + 1 < args.length; i += 1) {
    if (args[i] === "->") return args[i + 1]!;
  }
  for (const arg of args.slice(1)) {
    if (arg.includes(":")) return arg;
  }
  return null;
}

/** The suggestion text for an unsupported global directive. */
export function globalSuggestion(args: string[]): string {
  if (args.length === 0) {
    return "remove the directive or add support in ferrogate-config before using it";
  }
  return `remove the directive or map its arguments \`${args.join(" ")}\` into FerroGate typed config first`;
}
