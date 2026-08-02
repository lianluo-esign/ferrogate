/**
 * The `ferrogate validate` / `check` / `reload` pre-flight gate.
 *
 * Clean-room port of `ferrogate-gateway::lifecycle::{format_validate_report,
 * ensure_auth_posture_is_declared, ConfigSummary}` — the CLI is the only caller
 * of those three in the Rust tree (`crates/ferrogate-cli/src/lib.rs`
 * `Commands::Validate`), so they live with the CLI here.
 *
 * The rule the gate exists to keep (#542): `ferrogate check` must exit non-zero
 * for exactly the configs `ferrogate run` refuses to boot. A pre-flight that
 * prints `config OK … auth_required=true` for a deployment the gateway will
 * then refuse is worse than no pre-flight, because the one place an operator
 * can find that out is before the restart, not during it.
 */
import {
  type Config,
  authRequired,
  configSnapshotId,
  durableApiKeyStore,
  hasCredentialSource,
  tenancyPostureWarnings,
  tlsIsEnabled,
} from "@ferrogate/config";

/**
 * The gate's verdict.
 *
 * A refusal is RETURNED rather than thrown because the CLI's contract is that a
 * bad document is a validation-class exit (5) with the reason printed in the
 * report — not an exception that would land on the transport class (6). Rust
 * `bail!`s here because its caller maps the `anyhow` chain onto the same
 * report; the shape differs, the outcome does not.
 */
export interface AuthPostureVerdict {
  /** Set when the gate refuses; the operator sees this and the command exits 5. */
  readonly refusal?: string;
  /** Non-fatal posture findings the caller MUST surface. */
  readonly warnings: readonly string[];
}

/**
 * Startup gate for the deployment's authentication posture (issue #542).
 *
 * Two configs are refused before anything is reported OK, both because they
 * mean something the operator almost certainly did not intend and neither can
 * be resolved safely at request time:
 *
 * 1. **Nothing to authenticate against.** `[auth] disabled` is false (the
 *    default) but the config names no credential source at all. It does not
 *    silently flip to "refuse every request", and it emphatically does not keep
 *    admitting everyone as platform root: it stops, and the error names the
 *    switch that restores the old behaviour.
 * 2. **A contradiction.** `[auth] disabled = true` alongside a declared static
 *    credential source (`[[api_keys]]` or an enabled `[auth_service]`). Those
 *    credentials would be silently ignored and every request admitted as root —
 *    an operator who wrote both is protected by neither, and which one they
 *    meant is not ours to guess.
 *
 * A durable `[storage]` backend is not case 2, but it is not silent either: it
 * is a key store this deployment named and then switched off, so it comes back
 * as a WARNING naming the store (returned, not logged, so `check` can print it
 * and a test can assert it). Case 1 still accepts that backend as a credential
 * *source*.
 *
 * The caller must surface both the refusal and the warnings.
 */
export function ensureAuthPostureIsDeclared(config: Config): AuthPostureVerdict {
  if (config.auth.disabled) {
    const declared: string[] = [];
    if (config.api_keys.length > 0) declared.push("[[api_keys]]");
    if (config.auth_service.enabled) declared.push("[auth_service] enabled = true");
    if (declared.length > 0) {
      return {
        refusal:
          "refusing to start: [auth] disabled = true switches authentication off for every " +
          `request, but this config also declares a credential source (${declared.join(", ")}) ` +
          "that would then never be consulted -- every caller, credentialed or not, would be " +
          "admitted as an unrestricted platform operator; remove [auth] disabled or remove the " +
          "credential source",
        warnings: [],
      };
    }
    // Deliberately allowed, loudly: this is a decision, not the oversight it
    // was indistinguishable from before.
    const store = durableApiKeyStore(config);
    if (store !== null) {
      return {
        warnings: [
          "[auth] disabled = true switches authentication off for every request, but " +
            `[storage] provider = "${store}" is a durable control plane that holds virtual API ` +
            "keys: every key in it is IGNORED and every caller -- credentialed or not -- is " +
            "admitted as an unrestricted platform operator over whatever that control plane " +
            "contains. This is allowed because a durable backend also stores request logs, " +
            "audit events and routes, so having one is not by itself a statement about " +
            "authentication; if that control plane is shared with anything you care about, " +
            "remove [auth] disabled",
        ],
      };
    }
    return { warnings: [] };
  }

  if (!hasCredentialSource(config)) {
    return {
      refusal:
        "refusing to start: authentication is required (the default) but this config has no " +
        "credential source -- no [[api_keys]], no enabled [auth_service], and no durable " +
        "[storage] backend (postgres, supabase or cloudflare_d1) to hold virtual keys -- so " +
        "every request would be refused; add a credential source, or, if this gateway is " +
        "genuinely meant to be open to anyone who can reach it, say so by name. In TOML or " +
        "YAML: [auth] disabled = true. In a Caddyfile, in the global options block at the top " +
        "of the file: { auth off }. (Before FerroGate #542 that open posture was what an empty " +
        "[[api_keys]] section silently landed on, and it admitted every unauthenticated " +
        "request as an unrestricted platform operator.)",
      warnings: [],
    };
  }

  return { warnings: [] };
}

/** The metadata line `ferrogate check` prints, field for field with Rust's `ConfigSummary`. */
export interface ConfigSummary {
  readonly listen: string;
  readonly admin: string;
  readonly tls: boolean;
  readonly http2: boolean;
  readonly snapshot: string;
  readonly upstreams: number;
  readonly routes: number;
  readonly providers: number;
  readonly models: number;
  readonly api_keys: number;
  readonly auth_required: boolean;
}

export function configSummary(config: Config): ConfigSummary {
  return {
    listen: config.listen,
    admin: config.admin.listen ?? "off",
    tls: tlsIsEnabled(config.tls),
    http2: config.tls.http2,
    snapshot: configSnapshotId(config),
    upstreams: config.upstreams.length,
    routes: config.routes.length,
    providers: config.providers.length,
    models: config.models.length,
    api_keys: config.api_keys.length,
    // #542: the ONE predicate, not a third hand-copied expression. The Rust
    // copy that had drifted furthest ignored `[auth_service]` entirely, so
    // `check` reported `auth_required=false` for a deployment that
    // authenticated every request against an external service.
    auth_required: authRequired(config),
  };
}

/**
 * `format_validate_report`: run the posture gate FIRST, then report.
 *
 * Returns the summary plus every finding the operator must see. The refusal, if
 * any, comes back alongside the summary rather than instead of it — the
 * operator needs both to act.
 */
export function validateReport(config: Config): {
  summary: ConfigSummary;
  refusal?: string;
  warnings: readonly string[];
} {
  const posture = ensureAuthPostureIsDeclared(config);
  const warnings = [...posture.warnings, ...tenancyPostureWarnings(config)];
  return {
    summary: configSummary(config),
    ...(posture.refusal === undefined ? {} : { refusal: posture.refusal }),
    warnings,
  };
}
