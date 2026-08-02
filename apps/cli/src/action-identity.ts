/**
 * Per-invocation action identity (#548).
 *
 * Clean-room port of `ferrogate-control-plane-client::action_identity`
 * (inventory-edge-control.md §1.2 / §2.1).
 *
 * The contract: **one identity is minted per CLI invocation** — an OS-CSPRNG
 * `action_id`, a client fingerprint describing the client (never a digest of
 * the target, never a credential), an unverified client clock reading, and a
 * server-issued time token harvested off responses. Every request the
 * invocation issues, including every page of an `--all-pages` walk, carries the
 * same `action_id`, so a retried logical action is recognizable as one action.
 */
import type { AuthSource, EffectiveContext } from "./context.js";
import { auditAuthSource } from "./context.js";
import { CliError } from "./errors.js";
import type { Io } from "./ports.js";

export const ACTION_ID_HEADER = "x-ferrogate-action-id";
export const CLIENT_FINGERPRINT_HEADER = "x-ferrogate-client-fingerprint";
export const CLIENT_CLOCK_HEADER = "x-ferrogate-client-clock-unverified";
export const TIME_TOKEN_HEADER = "x-ferrogate-time-token";
export const CLIENT_REPORTED_IP_HEADER = "x-ferrogate-client-reported-ip";

/** Opt-in environment variables that widen the fingerprint. */
export const HOST_LABEL_ENV = "FERROGATE_CLIENT_HOST_LABEL";
export const REPORTED_IP_ENV = "FERROGATE_CLIENT_REPORTED_IP";

export const ACTION_ID_PREFIX = "fgact_";
const ACTION_ID_HEX_LEN = 32;
export const IDENTITY_SCHEMA_VERSION = "v1";
export const SERVER_TIME_AUTHORITY = "server_issued_time_token";
export const CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS = 300;

/** The fingerprint's declared field set, in render order. */
export const FINGERPRINT_FIELDS = [
  "cli",
  "os",
  "arch",
  "context",
  "cred",
  "host",
  "client_reported_ip",
] as const;

/** CLI version stamped into the fingerprint and the User-Agent. */
export const CLI_VERSION = "0.0.0";

/** Whether a string is a well-formed action id. */
export function isWellFormedActionId(value: string): boolean {
  if (!value.startsWith(ACTION_ID_PREFIX)) return false;
  const hex = value.slice(ACTION_ID_PREFIX.length);
  return hex.length === ACTION_ID_HEX_LEN && /^[0-9a-f]+$/.test(hex);
}

/** Mint an action id from the OS CSPRNG; refuse rather than issue an unauditable request. */
export function mintActionId(io: Io): string {
  let bytes: Uint8Array;
  try {
    bytes = io.randomBytes(ACTION_ID_HEX_LEN / 2);
  } catch (error) {
    throw CliError.usage(
      `could not mint an action id: the OS random source is unavailable (${
        error instanceof Error ? error.message : String(error)
      }); refusing to issue a request that cannot be audited`,
    );
  }
  if (bytes.length !== ACTION_ID_HEX_LEN / 2) {
    throw CliError.usage(
      "could not mint an action id: the random source returned the wrong number of bytes",
    );
  }
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${ACTION_ID_PREFIX}${hex}`;
}

/** What the client declares about itself. Never a token, never a target digest. */
export interface ClientFingerprint {
  readonly cliVersion: string;
  readonly os: string;
  readonly arch: string;
  readonly contextName?: string;
  readonly credentialSource: string;
  readonly hostLabel?: string;
  readonly reportedIp?: string;
}

/** Opt-in fingerprint inputs, injected so resolution is testable. */
export interface FingerprintEnv {
  readonly hostLabel?: string;
  readonly reportedIp?: string;
}

export function fingerprintEnvFrom(io: Io): FingerprintEnv {
  const read = (name: string): string | undefined => {
    const value = io.env[name];
    const trimmed = value === undefined ? "" : value.trim();
    return trimmed === "" ? undefined : trimmed;
  };
  const hostLabel = read(HOST_LABEL_ENV);
  const reportedIp = read(REPORTED_IP_ENV);
  return {
    ...(hostLabel === undefined ? {} : { hostLabel }),
    ...(reportedIp === undefined ? {} : { reportedIp }),
  };
}

export function detectFingerprint(
  context: { contextName?: string; auth: AuthSource },
  io: Io,
  env: FingerprintEnv,
): ClientFingerprint {
  return {
    cliVersion: CLI_VERSION,
    os: io.platform,
    arch: io.arch,
    ...(context.contextName === undefined ? {} : { contextName: context.contextName }),
    credentialSource: auditAuthSource(context.auth),
    ...(env.hostLabel === undefined ? {} : { hostLabel: env.hostLabel }),
    ...(env.reportedIp === undefined ? {} : { reportedIp: env.reportedIp }),
  };
}

/** Every declared field, in `FINGERPRINT_FIELDS` order. */
export function fingerprintFields(
  fingerprint: ClientFingerprint,
): readonly (readonly [string, string | undefined])[] {
  return [
    ["cli", fingerprint.cliVersion],
    ["os", fingerprint.os],
    ["arch", fingerprint.arch],
    ["context", fingerprint.contextName],
    ["cred", fingerprint.credentialSource],
    ["host", fingerprint.hostLabel],
    ["client_reported_ip", fingerprint.reportedIp],
  ];
}

/** Strip characters that cannot ride in an HTTP header value. */
function encodeHeaderValue(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, "?").replace(/[;=]/g, "_");
}

/**
 * The `x-ferrogate-client-fingerprint` value.
 *
 * `client_reported_ip` is deliberately EXCLUDED — it rides its own header so a
 * server-side sink cannot fold a client-asserted address into one blob. Absent
 * optional fields are omitted rather than rendered blank, so "not disclosed"
 * cannot be read as "disclosed as empty".
 */
export function renderFingerprint(fingerprint: ClientFingerprint): string {
  let rendered = IDENTITY_SCHEMA_VERSION;
  for (const [key, value] of fingerprintFields(fingerprint)) {
    if (key === "client_reported_ip") continue;
    if (value === undefined) continue;
    rendered += `;${key}=${encodeHeaderValue(value)}`;
  }
  return rendered;
}

/** A server-issued time token, accepted only when bound to this action. */
export interface ServerIssuedTime {
  readonly raw: string;
  readonly issuedAtUnix: number;
  readonly ttlSeconds: number;
  readonly boundActionId: string;
}

export type TimeTokenRefusal =
  | { readonly code: "time_token_malformed"; readonly detail: string }
  | {
      readonly code: "time_token_action_id_mismatch";
      readonly issuedFor: string;
      readonly presentedFor: string;
    }
  | {
      readonly code: "time_token_expired";
      readonly issuedAtUnix: number;
      readonly ttlSeconds: number;
      readonly clientReadingUnix: number;
    };

/** Parse `v1;issued_at=…;ttl=…;action_id=…;sig=…`. */
export function parseServerIssuedTime(
  raw: string,
): { ok: true; time: ServerIssuedTime } | { ok: false; refusal: TimeTokenRefusal } {
  const parts = raw.split(";");
  if (parts[0] !== IDENTITY_SCHEMA_VERSION) {
    return {
      ok: false,
      refusal: {
        code: "time_token_malformed",
        detail: `unknown schema marker '${parts[0] ?? ""}'`,
      },
    };
  }
  const fields = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    fields.set(part.slice(0, index), part.slice(index + 1));
  }
  const issuedAt = Number(fields.get("issued_at"));
  const ttl = Number(fields.get("ttl"));
  const boundActionId = fields.get("action_id");
  if (!Number.isFinite(issuedAt) || !Number.isFinite(ttl) || boundActionId === undefined) {
    return {
      ok: false,
      refusal: { code: "time_token_malformed", detail: "missing issued_at, ttl, or action_id" },
    };
  }
  return { ok: true, time: { raw, issuedAtUnix: issuedAt, ttlSeconds: ttl, boundActionId } };
}

/** The identity minted once per invocation. */
export class ClientActionIdentity {
  readonly actionId: string;
  readonly fingerprint: ClientFingerprint;
  readonly clientClockUnix: number;
  #serverTime: ServerIssuedTime | undefined;

  constructor(init: {
    actionId: string;
    fingerprint: ClientFingerprint;
    clientClockUnix: number;
    serverTime?: ServerIssuedTime;
  }) {
    this.actionId = init.actionId;
    this.fingerprint = init.fingerprint;
    this.clientClockUnix = init.clientClockUnix;
    this.#serverTime = init.serverTime;
  }

  /** Mint the identity for one operator action. Call exactly once. */
  static mint(context: EffectiveContext, io: Io, env: FingerprintEnv): ClientActionIdentity {
    return new ClientActionIdentity({
      actionId: mintActionId(io),
      fingerprint: detectFingerprint(context, io, env),
      clientClockUnix: io.nowUnixSeconds(),
    });
  }

  /** The server-issued time this action currently holds, if any. */
  serverIssuedTime(): ServerIssuedTime | undefined {
    return this.#serverTime;
  }

  /**
   * Harvest a time token off a response.
   *
   * A token that does not parse, is bound to a different action, or is outside
   * its TTL by the client's own reading is NOT stored — the held value stays
   * whatever it was and the refusal is returned for the receipt to record.
   */
  acceptTimeToken(raw: string, clientReadingUnix: number): TimeTokenRefusal | undefined {
    const parsed = parseServerIssuedTime(raw);
    if (!parsed.ok) return parsed.refusal;
    if (parsed.time.boundActionId !== this.actionId) {
      return {
        code: "time_token_action_id_mismatch",
        issuedFor: parsed.time.boundActionId,
        presentedFor: this.actionId,
      };
    }
    const age = clientReadingUnix - parsed.time.issuedAtUnix;
    if (age > parsed.time.ttlSeconds + CLIENT_CLOCK_SKEW_ALLOWANCE_SECONDS) {
      return {
        code: "time_token_expired",
        issuedAtUnix: parsed.time.issuedAtUnix,
        ttlSeconds: parsed.time.ttlSeconds,
        clientReadingUnix,
      };
    }
    this.#serverTime = parsed.time;
    return undefined;
  }

  /** The headers every request of this invocation carries. */
  headers(): Record<string, string> {
    const headers: Record<string, string> = {
      [ACTION_ID_HEADER]: this.actionId,
      [CLIENT_FINGERPRINT_HEADER]: renderFingerprint(this.fingerprint),
      [CLIENT_CLOCK_HEADER]: String(this.clientClockUnix),
      "user-agent": `ferrogate-cli/${CLI_VERSION}`,
    };
    const held = this.#serverTime;
    if (held !== undefined) headers[TIME_TOKEN_HEADER] = held.raw;
    if (this.fingerprint.reportedIp !== undefined) {
      headers[CLIENT_REPORTED_IP_HEADER] = this.fingerprint.reportedIp;
    }
    return headers;
  }
}
