/**
 * The `serve` family: `run` (`gateway`), `auth serve`, `control-api serve`,
 * `admin-api serve` (deprecated), `billing serve`, and
 * `storage migrate-to-supabase`.
 *
 * PORT-TODO(inventory-edge-control.md §1.4): **the CLI's identity as a process
 * launcher does not survive the port.** On Cloudflare each of these subsystems
 * is a deployed Worker (`apps/gateway`, `apps/control-plane`, …), so there is
 * no local listener to bind. Rather than silently dropping the verbs — or worse,
 * exiting 0 as if a server had started — every `serve` verb keeps its full flag
 * surface, validates what it can, and prints the exact deploy/health command
 * that replaces it, exiting with the usage class.
 *
 * The flags are preserved verbatim (including their env vars and defaults)
 * because operators' scripts and docs reference them, and because they are the
 * inventory record of what each service needed.
 */
import type { FlagSpec } from "../args.js";
import { CliError } from "../errors.js";
import type { CliRuntime, CommandNode } from "../runtime.js";

/** `-c/--config` with the Rust default and env var. */
export const CONFIG_FLAG: FlagSpec = {
  name: "config",
  short: "c",
  kind: "string",
  valueName: "PATH",
  env: "FERROGATE_CONFIG",
  default: "Ferrogate/Caddyfile",
  help: "Gateway configuration file",
};

/** One Worker a former `serve` verb now maps onto. */
interface DeployTarget {
  readonly app: string;
  readonly what: string;
}

function serveNotAProcess(
  runtime: CliRuntime,
  command: string,
  target: DeployTarget,
  resolvedFlags: readonly (readonly [string, string])[],
): number {
  const { io } = runtime;
  io.stderr(
    `ferrogate ${command}: this build has no local listener to bind.\n  ${target.what} now runs as the Cloudflare Worker '${target.app}'.\n  deploy:  bunx wrangler deploy --config apps/${target.app}/wrangler.toml\n  dev:     bunx wrangler dev --config apps/${target.app}/wrangler.toml\n  health:  ferrogate ctl system ready --endpoint <worker-url>\n`,
  );
  if (resolvedFlags.length > 0) {
    io.stderr("  resolved settings (recorded so nothing is silently dropped):\n");
    for (const [name, value] of resolvedFlags) io.stderr(`    ${name} = ${value}\n`);
  }
  io.stderr(
    "  PORT-TODO(inventory-edge-control.md §1.4): these settings become Worker vars/secrets " +
      "and Secrets Store bindings at deploy time.\n",
  );
  return CliError.usage("").exitCode();
}

/** Collect the flags an operator actually supplied, for the echo above. */
function resolved(
  args: { getString(name: string): string | undefined; getBoolean(name: string): boolean },
  specs: readonly FlagSpec[],
): (readonly [string, string])[] {
  const out: (readonly [string, string])[] = [];
  for (const spec of specs) {
    if (spec.kind === "boolean") {
      if (args.getBoolean(spec.name)) out.push([spec.name, "true"]);
      continue;
    }
    const value = args.getString(spec.name);
    if (value !== undefined) {
      // Never echo a secret back, even one the operator typed themselves.
      const isSecret = /secret|token|dsn|password/i.test(spec.name);
      out.push([spec.name, isSecret ? "<redacted>" : value]);
    }
  }
  return out;
}

const AUTH_SERVE_FLAGS: readonly FlagSpec[] = [
  {
    name: "listen",
    kind: "string",
    valueName: "ADDR",
    env: "FERROGATE_AUTH_LISTEN",
    default: "127.0.0.1:8090",
    help: "Listen address",
  },
  {
    name: "data",
    kind: "string",
    valueName: "PATH",
    env: "FERROGATE_AUTH_DATA",
    help: "Seed YAML",
  },
  {
    name: "supabase-dsn",
    kind: "string",
    valueName: "DSN",
    env: "FERROGATE_AUTH_SUPABASE_DSN",
    help: "Supabase DSN",
  },
  {
    name: "supabase-tls-mode",
    kind: "string",
    valueName: "MODE",
    env: "FERROGATE_AUTH_SUPABASE_TLS_MODE",
    default: "require",
    help: "Supabase TLS mode",
  },
  {
    name: "supabase-tls-ca-cert-path",
    kind: "string",
    valueName: "PATH",
    env: "FERROGATE_AUTH_SUPABASE_TLS_CA_CERT_PATH",
    help: "Supabase TLS CA bundle",
  },
  {
    name: "supabase-schema",
    kind: "string",
    valueName: "SCHEMA",
    env: "FERROGATE_AUTH_SUPABASE_SCHEMA",
    default: "auth",
    help: "Supabase schema",
  },
  {
    name: "supabase-init-schema",
    kind: "boolean",
    env: "FERROGATE_AUTH_SUPABASE_INIT_SCHEMA",
    help: "Create the schema on start",
  },
  {
    name: "admin-jwt-secret",
    kind: "string",
    valueName: "SECRET",
    env: "FERROGATE_AUTH_ADMIN_JWT_SECRET",
    help: "Console session signing secret",
  },
  {
    name: "admin-jwt-secret-env",
    kind: "string",
    valueName: "VAR",
    env: "FERROGATE_AUTH_ADMIN_JWT_SECRET_ENV",
    help: "Env var holding the signing secret",
  },
  {
    name: "cors-allowed-origin",
    kind: "string",
    valueName: "ORIGIN",
    env: "FERROGATE_AUTH_CORS_ALLOWED_ORIGIN",
    help: "Admin-console allowed origin",
  },
];

const BILLING_SERVE_FLAGS: readonly FlagSpec[] = [
  {
    name: "listen",
    kind: "string",
    valueName: "ADDR",
    env: "FERROGATE_BILLING_LISTEN",
    default: "127.0.0.1:8092",
    help: "Listen address",
  },
  {
    name: "pricing",
    kind: "string",
    valueName: "PATH",
    env: "FERROGATE_BILLING_PRICING",
    help: "Pricing table",
  },
  {
    name: "credits-per-usd",
    kind: "number",
    valueName: "N",
    env: "FERROGATE_BILLING_CREDITS_PER_USD",
    help: "Credit conversion rate",
  },
  {
    name: "token",
    kind: "string",
    valueName: "TOKEN",
    env: "FERROGATE_BILLING_TOKEN",
    help: "Service bearer token",
  },
  {
    name: "token-env",
    kind: "string",
    valueName: "VAR",
    env: "FERROGATE_BILLING_TOKEN_ENV",
    help: "Env var holding the bearer token",
  },
  {
    name: "supabase-dsn",
    kind: "string",
    valueName: "DSN",
    env: "FERROGATE_BILLING_SUPABASE_DSN",
    help: "Supabase DSN",
  },
  {
    name: "supabase-tls-mode",
    kind: "string",
    valueName: "MODE",
    env: "FERROGATE_BILLING_SUPABASE_TLS_MODE",
    default: "require",
    help: "Supabase TLS mode",
  },
  {
    name: "supabase-tls-ca-cert-path",
    kind: "string",
    valueName: "PATH",
    env: "FERROGATE_BILLING_SUPABASE_TLS_CA_CERT_PATH",
    help: "Supabase TLS CA bundle",
  },
  {
    name: "supabase-schema",
    kind: "string",
    valueName: "SCHEMA",
    env: "FERROGATE_BILLING_SUPABASE_SCHEMA",
    default: "billing",
    help: "Supabase schema",
  },
  {
    name: "supabase-init-schema",
    kind: "boolean",
    env: "FERROGATE_BILLING_SUPABASE_INIT_SCHEMA",
    help: "Create the schema on start",
  },
];

const STORAGE_MIGRATE_FLAGS: readonly FlagSpec[] = [
  {
    name: "source-provider",
    kind: "string",
    valueName: "NAME",
    default: "postgres",
    help: "Source provider",
  },
  {
    name: "source-postgres-dsn",
    kind: "string",
    valueName: "DSN",
    help: "Source Postgres DSN",
    conflictsWith: ["source-postgres-dsn-env"],
  },
  {
    name: "source-postgres-dsn-env",
    kind: "string",
    valueName: "VAR",
    env: "FERROGATE_MIGRATION_SOURCE_POSTGRES_DSN_ENV",
    help: "Env var holding the source DSN",
  },
  {
    name: "target-supabase-dsn",
    kind: "string",
    valueName: "DSN",
    help: "Target Supabase DSN",
    conflictsWith: ["target-supabase-dsn-env"],
  },
  {
    name: "target-supabase-dsn-env",
    kind: "string",
    valueName: "VAR",
    env: "FERROGATE_MIGRATION_TARGET_SUPABASE_DSN_ENV",
    help: "Env var holding the target DSN",
  },
  {
    name: "postgres-schema",
    kind: "string",
    valueName: "SCHEMA",
    default: "ferrogate_control",
    help: "Source schema",
  },
  {
    name: "postgres-tls-mode",
    kind: "string",
    valueName: "MODE",
    default: "require",
    help: "Source TLS mode",
  },
  {
    name: "postgres-tls-ca-cert-path",
    kind: "string",
    valueName: "PATH",
    help: "Source TLS CA bundle",
  },
  { name: "dry-run", kind: "boolean", help: "Plan only", conflictsWith: ["execute"] },
  { name: "execute", kind: "boolean", help: "Apply the migration", conflictsWith: ["dry-run"] },
];

const RUN_FLAGS: readonly FlagSpec[] = [
  CONFIG_FLAG,
  { name: "upgrade", kind: "boolean", help: "Hand off to a new binary (graceful upgrade)" },
];

export const runCommand: CommandNode = {
  name: "run",
  aliases: ["gateway"],
  about: "Start the gateway data plane (alias: gateway)",
  flags: RUN_FLAGS,
  run: async (runtime, args) =>
    serveNotAProcess(
      runtime,
      "run",
      { app: "gateway", what: "The gateway data plane" },
      resolved(args, RUN_FLAGS),
    ),
};

export const authCommand: CommandNode = {
  name: "auth",
  about: "Identity / RBAC service",
  sub: [
    {
      name: "serve",
      about: "Run the tenant/RBAC + admin-console identity service",
      flags: AUTH_SERVE_FLAGS,
      run: async (runtime, args) =>
        serveNotAProcess(
          runtime,
          "auth serve",
          { app: "control-plane", what: "The identity service" },
          resolved(args, AUTH_SERVE_FLAGS),
        ),
    },
  ],
};

export const controlApiCommand: CommandNode = {
  name: "control-api",
  about: "Control Plane API service",
  sub: [
    {
      name: "serve",
      about: "Run the Control Plane API service",
      flags: [CONFIG_FLAG],
      run: async (runtime, args) =>
        serveNotAProcess(
          runtime,
          "control-api serve",
          { app: "control-plane", what: "The Control Plane API" },
          resolved(args, [CONFIG_FLAG]),
        ),
    },
  ],
};

/**
 * DEPRECATED alias of `control-api serve`.
 *
 * Kept — with its deprecation warning — because removing it would break
 * operators' scripts silently, which is exactly the failure the warning exists
 * to prevent.
 */
export const adminApiCommand: CommandNode = {
  name: "admin-api",
  about: "DEPRECATED alias of `control-api` (prints a deprecation warning)",
  deprecated:
    "`admin-api` is deprecated and will be removed; use `control-api` (the canonical name)",
  sub: [
    {
      name: "serve",
      about: "DEPRECATED: run the Control Plane API service",
      deprecated: "`admin-api serve` is deprecated and will be removed; use `control-api serve`",
      flags: [CONFIG_FLAG],
      run: async (runtime, args) =>
        serveNotAProcess(
          runtime,
          "admin-api serve",
          { app: "control-plane", what: "The Control Plane API" },
          resolved(args, [CONFIG_FLAG]),
        ),
    },
  ],
};

export const billingCommand: CommandNode = {
  name: "billing",
  about: "Token-usage billing service",
  sub: [
    {
      name: "serve",
      about: "Run the token-usage billing REST service",
      flags: BILLING_SERVE_FLAGS,
      run: async (runtime, args) =>
        serveNotAProcess(
          runtime,
          "billing serve",
          { app: "control-plane", what: "The billing service" },
          resolved(args, BILLING_SERVE_FLAGS),
        ),
    },
  ],
};

export const storageCommand: CommandNode = {
  name: "storage",
  about: "Durable-state maintenance",
  sub: [
    {
      name: "migrate-to-supabase",
      about: "Migrate legacy durable state into Supabase",
      flags: STORAGE_MIGRATE_FLAGS,
      run: async (runtime, args) => {
        // The Rust command refused to run without an explicit mode; preserve
        // that rather than defaulting a data migration to "execute".
        if (!args.getBoolean("dry-run") && !args.getBoolean("execute")) {
          throw CliError.usage(
            "storage migrate-to-supabase requires exactly one of --dry-run or --execute",
          );
        }
        runtime.io.stderr(
          "ferrogate storage migrate-to-supabase: Postgres/Supabase is not the durable store " +
            "in the Cloudflare build.\n" +
            "  PORT-TODO(inventory-edge-control.md §1.1): the target store is D1 " +
            "(packages/storage owns the SQLite migrations); this verb becomes a D1 import once " +
            "that package lands, and refuses now rather than touching data with a stale plan.\n",
        );
        return CliError.usage("").exitCode();
      },
    },
  ],
};
