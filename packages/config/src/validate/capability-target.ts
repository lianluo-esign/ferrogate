/**
 * `ferrogate_runtime::CapabilityTargetSelector::supports_action` and
 * `::validate()` — the two legs `Config::validate()` runs over every
 * `agent_runtime.managed_worker.target_grants` entry (inventory §5.3).
 *
 * Ported 1:1 from `crates/ferrogate-runtime/src/target_capability.rs`. Both
 * return the bare Rust reason string; `validate/sections.ts` attributes it to the
 * `field agent_runtime.managed_worker.target_grants ...` path the Rust `bail!`
 * uses.
 */
import { isIpAddress } from "../network-access.js";
import type {
  CapabilityTargetSelector,
  JsonShape,
  ManagedWorkerCapabilityAction,
} from "../schema/index.js";

/**
 * `CapabilityTargetSelector::supports_action`. The config-level
 * `ManagedWorkerCapabilityActionConfig` maps 1:1 onto
 * `ferrogate_runtime::CapabilityAction` (`as_policy_action`), so the config slug
 * is matched directly. Every pair NOT in the Rust `matches!` table is false —
 * including `tool`, `skill`, `browser`, `memory.read` and `memory.write`, which
 * no selector variant backs.
 */
export function selectorSupportsAction(
  selector: CapabilityTargetSelector,
  action: ManagedWorkerCapabilityAction,
): boolean {
  switch (selector.kind) {
    case "mcp":
      return action === "mcp_tool";
    case "filesystem":
      return action === "filesystem";
    case "network":
      return action === "rest" || action === "network_egress";
    case "secret":
      return action === "secret";
    case "cli":
      return action === "cli";
  }
}

/**
 * `CapabilityAction::as_str()` — the slug the Rust incompatibility message prints
 * (dotted, NOT the snake_case config key: `mcp_tool` renders as `mcp.tool`).
 */
const CAPABILITY_ACTION_AS_STR: Record<ManagedWorkerCapabilityAction, string> = {
  tool: "tool",
  mcp_tool: "mcp.tool",
  cli: "cli",
  skill: "skill",
  filesystem: "filesystem",
  browser: "browser",
  rest: "rest",
  secret: "secret",
  memory_read: "memory.read",
  memory_write: "memory.write",
  network_egress: "network.egress",
};

export function capabilityActionAsStr(action: ManagedWorkerCapabilityAction): string {
  return CAPABILITY_ACTION_AS_STR[action];
}

/** `canonical_identifier`. */
function canonicalIdentifier(label: string, value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0 || /\s/.test(trimmed) || /[/\\:]/.test(trimmed)) {
    return `${label} is not a canonical identifier`;
  }
  return null;
}

/** `canonical_secret_reference` (the shape half; the returned string is unused here). */
function canonicalSecretReference(namespace: string, name: string): string | null {
  const namespaceError = canonicalIdentifier("secret reference namespace", namespace);
  if (namespaceError !== null) return namespaceError;
  const nameError = canonicalIdentifier("secret reference name", name);
  if (nameError !== null) return nameError;
  const trimmed = name.trim();
  const upper = trimmed.toUpperCase();
  if (
    trimmed.startsWith("sk-") ||
    trimmed.startsWith("ghp_") ||
    upper.startsWith("AKIA") ||
    trimmed.includes("=")
  ) {
    return "secret target resembles resolved credential material";
  }
  return null;
}

/** `validate_json_shape`. */
function validateJsonShape(shape: JsonShape): string | null {
  if (shape.kind === "array") return validateJsonShape(shape.items);
  if (shape.kind === "object") {
    if (Object.keys(shape.fields).some((field) => field.length === 0)) {
      return "MCP argument object field names must not be empty";
    }
    for (const nested of Object.values(shape.fields)) {
      const error = validateJsonShape(nested);
      if (error !== null) return error;
    }
  }
  return null;
}

/** `normalize_host` — returns the normalized host, or an error reason. */
function normalizeHost(host: string): { host: string } | { error: string } {
  const value = host.trim().replace(/\.+$/, "").toLowerCase();
  // eslint-disable-next-line no-control-regex
  const asciiOnly = /^[\u0000-\u007f]*$/.test(value);
  if (value.length === 0 || !asciiOnly || value.includes("%") || /\s/.test(value)) {
    return { error: "host notation is ambiguous" };
  }
  if (isIpAddress(value)) return { host: value };
  if (value.startsWith("0x") || /^[0-9.]+$/.test(value)) {
    return { error: "alternate numeric host notation is not authorized" };
  }
  return { host: value };
}

/**
 * PORT-TODO(inventory §5.3) — PLATFORM LIMIT, NOT CLOSED.
 *
 * Two legs of `CapabilityTargetSelector::validate()` are filesystem pre-flights
 * that workerd cannot run, because a Worker isolate has NO filesystem at all —
 * there is no `std::fs::canonicalize`, no `is_dir`/`is_file`, and no
 * device/inode identity to read:
 *
 *   - `Filesystem { workspace_root }`: Rust canonicalizes the root and requires
 *     it to be an existing directory ("workspace root cannot be resolved: ...",
 *     "workspace root must be a directory").
 *   - `Cli { executable }`: `canonical_cli_executable` canonicalizes the path and
 *     requires it to be an existing file ("CLI executable cannot be resolved:
 *     ...", "CLI executable must resolve to a file").
 *
 * These paths name objects inside the `@cloudflare/sandbox` container the managed
 * runtime executes in, which does not exist at config-load time in the Worker, so
 * the check cannot merely be deferred either.
 *
 * CLOSEST BEHAVIOR IMPLEMENTED: every NON-filesystem leg of both variants is
 * ported verbatim (`path_glob`/`cwd_glob` non-empty, `operations` non-empty, the
 * argv NUL scan, the empty-env rule, the resource bounds), plus the purely
 * lexical half of `canonical_cli_executable` — "must be an absolute normalized
 * path" — which needs no filesystem. Pinned by
 * `validate-sections.test.ts` > "filesystem/cli selectors: the lexical half".
 */
export function validateCapabilityTargetSelector(
  selector: CapabilityTargetSelector,
): string | null {
  switch (selector.kind) {
    case "mcp": {
      const serverError = canonicalIdentifier("MCP server", selector.server);
      if (serverError !== null) return serverError;
      const toolError = canonicalIdentifier("MCP tool", selector.tool);
      if (toolError !== null) return toolError;
      if (selector.argument_schema.kind !== "object") {
        return "MCP argument schema root must be an object";
      }
      return validateJsonShape(selector.argument_schema);
    }
    case "filesystem": {
      // (`std::fs::canonicalize(workspace_root)` + `is_dir` omitted — see above.)
      if (selector.path_glob.trim().length === 0) {
        return "filesystem path_glob must not be empty";
      }
      if (selector.operations.length === 0) {
        return "filesystem selector requires at least one operation";
      }
      return null;
    }
    case "network": {
      const scheme = selector.scheme.trim().toLowerCase();
      if (scheme !== "http" && scheme !== "https" && scheme !== "tcp" && scheme !== "tls") {
        return "network selector scheme must be http, https, tcp, or tls";
      }
      if (selector.port === 0) return "network selector port must be greater than zero";
      if (selector.method !== null && selector.method.trim().length === 0) {
        return "network selector method must not be empty";
      }
      if (selector.path_glob.trim().length === 0) {
        return "network selector path_glob must not be empty";
      }
      const host = normalizeHost(selector.host);
      if ("error" in host) return host.error;
      if (!isIpAddress(host.host) && selector.allowed_ips.length === 0) {
        return "hostname target selector requires a non-empty operator allowed_ips allowlist";
      }
      if (selector.allow_redirects) {
        return "redirect authorization is unsupported until execution-derived hops are enforced";
      }
      return null;
    }
    case "secret": {
      const referenceError = canonicalSecretReference(
        selector.reference_namespace,
        selector.reference_name,
      );
      if (referenceError !== null) return referenceError;
      const adapterError = canonicalIdentifier(
        "secret destination adapter",
        selector.destination_adapter,
      );
      if (adapterError !== null) return adapterError;
      return canonicalIdentifier("secret destination action", selector.destination_action);
    }
    case "cli": {
      // `canonical_cli_executable`: the lexical half runs; the canonicalize +
      // `is_file` half cannot (see above).
      if (!selector.executable.startsWith("/") || selector.executable.includes("/../")) {
        return "CLI executable must be an absolute normalized path";
      }
      if (selector.argv.some((argument) => argument.includes("\u0000"))) {
        return "CLI argv contains a NUL byte";
      }
      if (Object.keys(selector.environment).length > 0) {
        return "CLI custom environment is unsupported; managed execution is empty-env";
      }
      if (selector.cwd_glob.trim().length === 0) return "CLI cwd_glob must not be empty";
      if (
        selector.max_timeout_millis === 0 ||
        selector.max_stdout_bytes === 0 ||
        selector.max_stderr_bytes === 0
      ) {
        return "CLI resource bounds must be greater than zero";
      }
      return null;
    }
  }
}
