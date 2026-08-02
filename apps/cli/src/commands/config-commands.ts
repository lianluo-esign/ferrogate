import { ClientActionIdentity, fingerprintEnvFrom } from "../action-identity.js";
/**
 * `validate` (alias `check`), `reload`, and `hash-key`.
 *
 * Ports inventory-edge-control.md §1.1's config-lifecycle verbs. `validate`
 * runs the local config gate; `reload` either validates a candidate locally or
 * hot-reloads a running gateway through its admin surface.
 */
import type { FlagSpec } from "../args.js";
import type { EffectiveContext } from "../context.js";
import { DEFAULT_TIMEOUT_MILLIS } from "../context.js";
import { CliError, exitCode } from "../errors.js";
import { renderJson } from "../output.js";
import type { ConfigValidationReport, RequestContext } from "../ports.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { CONFIG_FLAG } from "./serve.js";

function renderReport(report: ConfigValidationReport): string {
  const lines = [`config: ${report.configPath}`, `status: ${report.ok ? "ok" : "invalid"}`];
  for (const [key, value] of Object.entries(report.summary)) lines.push(`${key}: ${String(value)}`);
  for (const diagnostic of report.diagnostics) {
    const where = diagnostic.path === undefined ? "" : ` (${diagnostic.path})`;
    lines.push(`${diagnostic.severity}: ${diagnostic.message}${where}`);
  }
  return lines.join("\n");
}

async function loadAndValidate(
  runtime: CliRuntime,
  configPath: string,
): Promise<ConfigValidationReport> {
  if (!(await runtime.io.fileExists(configPath))) {
    throw CliError.usage(
      `config file '${configPath}' does not exist (set -c/--config or FERROGATE_CONFIG)`,
    );
  }
  const source = await runtime.io.readFile(configPath);
  return runtime.configValidator.validate(configPath, source);
}

export const validateCommand: CommandNode = {
  name: "validate",
  aliases: ["check"],
  about: "Validate config + auth posture; print a summary (alias: check)",
  flags: [
    CONFIG_FLAG,
    { name: "output", kind: "string", valueName: "FORMAT", help: "table (default) or json" },
  ],
  run: async (runtime, args) => {
    const configPath = args.requireString("config");
    const report = await loadAndValidate(runtime, configPath);
    const asJson = (args.getString("output") ?? "table").toLowerCase() === "json";
    runtime.io.stdout(`${asJson ? renderJson(report) : renderReport(report)}\n`);
    // A failed validation is a validation-class exit (5), not a usage error:
    // the operator typed a correct command; the document is wrong.
    return report.ok ? 0 : exitCode("validation");
  },
};

const RELOAD_FLAGS: readonly FlagSpec[] = [
  CONFIG_FLAG,
  {
    name: "admin-url",
    kind: "string",
    valueName: "URL",
    env: "FERROGATE_ADMIN_URL",
    help: "Admin surface of a running gateway; omit to validate only",
  },
  {
    name: "admin-token",
    kind: "string",
    valueName: "TOKEN",
    env: "FERROGATE_ADMIN_TOKEN",
    help: "Bearer token for the admin surface",
  },
  { name: "graceful-upgrade", kind: "boolean", help: "Request a graceful binary upgrade" },
];

export const reloadCommand: CommandNode = {
  name: "reload",
  about: "Validate a candidate config, or hot-reload a running gateway",
  flags: RELOAD_FLAGS,
  run: async (runtime, args) => {
    const configPath = args.requireString("config");
    const report = await loadAndValidate(runtime, configPath);
    if (!report.ok) {
      runtime.io.stderr(`${renderReport(report)}\n`);
      runtime.io.stderr("error: refusing to reload an invalid configuration\n");
      return exitCode("validation");
    }

    const adminUrl = args.getString("admin-url");
    if (adminUrl === undefined) {
      runtime.io.stdout(`${renderReport(report)}\n`);
      runtime.io.stderr(
        "note: no --admin-url given, so this validated the candidate config without reloading anything\n",
      );
      return 0;
    }

    const token = args.getString("admin-token");
    const effective: EffectiveContext = {
      endpoint: adminUrl,
      tlsInsecureSkipVerify: false,
      timeoutMillis: DEFAULT_TIMEOUT_MILLIS,
      auth: token === undefined ? { kind: "none" } : { kind: "inline", token },
      output: "table",
      nonInteractive: true,
    };
    const identity = ClientActionIdentity.mint(
      effective,
      runtime.io,
      fingerprintEnvFrom(runtime.io),
    );
    const requestContext: RequestContext = {
      endpoint: adminUrl,
      ...(token === undefined ? {} : { token }),
      timeoutMillis: DEFAULT_TIMEOUT_MILLIS,
      headers: identity.headers(),
      tlsInsecureSkipVerify: false,
    };
    const response = await runtime.client.send(
      {
        method: "POST",
        path: "/admin/v1/config/reload",
        query: [],
        body: {
          config_path: configPath,
          graceful_upgrade: args.getBoolean("graceful-upgrade"),
        },
      },
      requestContext,
    );
    if (response.requestId !== undefined) runtime.io.stderr(`request-id: ${response.requestId}\n`);
    runtime.io.stdout(`${renderJson(response.body)}\n`);
    return 0;
  },
};

export const hashKeyCommand: CommandNode = {
  name: "hash-key",
  about: "Hash a virtual API key secret for durable config",
  flags: [
    {
      name: "secret",
      kind: "string",
      valueName: "SECRET",
      env: "FERROGATE_KEY_SECRET",
      help: "The plaintext key secret to hash",
    },
  ],
  run: async (runtime, args) => {
    const secret = args.requireString("secret");
    runtime.io.stdout(`${await runtime.keyHasher.hash(secret)}\n`);
    return 0;
  },
};
