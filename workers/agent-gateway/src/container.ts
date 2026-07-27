// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: FerroGate container/sandbox isolation routes (issue #415): governed
//   prepare/start/exec/stop/logs/artifacts/cleanup over a per-tenant Cloudflare
//   @cloudflare/sandbox instance. Cloudflare exposes NO public container lifecycle REST
//   API, so these bearer-gated Worker routes are the only tethered path FerroGate drives
//   the tier through, with egress deny-by-default (the `AgentSandbox` DO class pins
//   `enableInternet=false`; egress is opened only for a governed allowlist).
//
//   #471 (P1 security): the tether is now ENFORCED, not cooperative. /container/start
//   rejects enableInternet/directPublicEgress unconditionally, constrains any allowlist to
//   the operator-authorized CONTAINER_GOVERNED_EGRESS_HOSTS (empty ⇒ sealed), applies a
//   provider denylist that overrides everything in Cloudflare's egress chain, and ATTESTS
//   the applied posture so the Rust client can refuse an unfenced instance.
//
//   REWORK (gate re-test of #415): the earlier draft drove a GUESSED structural RPC
//   surface (`configureEgress`, `signal`, `runCode`/`listFiles`/`readLogs` on a hand-rolled
//   interface) that diverged from the REAL `@cloudflare/sandbox@0.12.4` API and crashed
//   live. This module now binds the ACTUAL `Sandbox` type via `getSandbox(...)` and calls
//   only real methods, so `tsc` type-checks the surface against the installed SDK.

import { getSandbox, SessionTerminatedError } from "@cloudflare/sandbox";
import type { Sandbox } from "@cloudflare/sandbox";

import { json, requireBearer } from "./auth";
import type { Env } from "./index";

// ---------------------------------------------------------------------------
// Real `@cloudflare/sandbox@0.12.4` surface these routes drive (verified against
// node_modules/@cloudflare/sandbox/dist/*.d.ts + @cloudflare/containers):
//
//   getSandbox(ns, id): Sandbox               — resolve the per-tenant DO stub.
//   sandbox.setEnvVars(env): Promise<void>    — inject governed env vars.
//   sandbox.setAllowedHosts(hosts): Promise<void>
//   sandbox.setDeniedHosts(hosts): Promise<void>   — governed egress allow/deny lists;
//         allowed hosts get egress even while enableInternet=false (Container base).
//   sandbox.exec(cmd, { timeout? }): Promise<ExecResult>   — untrusted-command path.
//   sandbox.runCode(src, { language, timeout? }): Promise<ExecutionResult>  — code path.
//   sandbox.stop(signal?: 'SIGTERM'|'SIGKILL'|'SIGINT'|number): Promise<void>  — signal.
//   sandbox.destroy(): Promise<void>          — SIGKILL teardown (coalesced; can HANG if
//         the control plane is unresponsive — callers MUST apply their own timeout).
//   sandbox.listFiles(path, opts?): Promise<ListFilesResult>   — artifact collection.
//   sandbox.getState(): Promise<State>        — inherited running/stopped status.
//
// There is NO `configureEgress` and NO `signal` method (the two live crashes).
// Egress is a Container-level property: `enableInternet` (pinned false on the
// `AgentSandbox` subclass in index.ts) + `setAllowedHosts`/`setDeniedHosts`, NOT an RPC.
// Non-zero / abnormal exits surface as a thrown `SessionTerminatedError` (a real export,
// carrying `.exitCode`) — caught below and mapped to a governed result, never a 5xx.

/** GA instance tiers (≤ 4 vCPU / 12 GiB). */
const VALID_TIERS = new Set([
  "lite",
  "basic",
  "standard-1",
  "standard-2",
  "standard-3",
  "standard-4",
]);

/** Languages accepted by the Sandbox code interpreter (`runCode`). */
const CODE_LANGUAGES = new Set(["python", "javascript", "typescript"]);
type CodeLanguage = "python" | "javascript" | "typescript";

/** Default writable workspace mount inside the instance. */
const DEFAULT_WORKSPACE = "/workspace";

/** Cap on captured stdout/stderr bytes returned over the wire. */
const DEFAULT_MAX_OUTPUT_BYTES = 1_000_000;

/**
 * Hard ceiling on how long `cleanup` waits for `destroy()` before returning.
 * `Sandbox.destroy()` coalesces concurrent teardowns and, per the SDK's own
 * docs, "can HANG until the Durable Object is evicted" when the Containers
 * control plane is unresponsive. Racing it against this timeout is THE
 * resource-leak fix: a wedged instance is reported cleaned in bounded time
 * (the platform reclaims it via idle-sleep) instead of blocking 60-90s.
 */
const CLEANUP_TIMEOUT_MS = 10_000;

/** Timeout guarding the `stop` signal so a wedged instance can't hang the route. */
const STOP_TIMEOUT_MS = 10_000;

/**
 * Resolve the per-tenant sandbox for `instance`, or `null` when no
 * CONTAINER_SANDBOX binding is configured (fail closed → `container_unbound`).
 * `getSandbox` returns the real, fully-typed `Sandbox` DO stub — every method
 * call below is checked by `tsc` against the installed SDK, not a local shape.
 */
export function resolveSandbox(env: Env, instance: string): Sandbox | null {
  const ns = env.CONTAINER_SANDBOX;
  if (!ns) return null;
  return getSandbox(ns, instance);
}

/** Parse the `CONTAINER_MAX_OUTPUT_BYTES` var, falling back to the default. */
export function containerMaxOutputBytes(raw: string | undefined): number {
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return DEFAULT_MAX_OUTPUT_BYTES;
  }
  return parsed;
}

/**
 * Race `work` against a timeout. On timeout the returned promise REJECTS with a
 * sentinel so callers can distinguish "bounded-out" from a real teardown error.
 * The underlying `work` promise is abandoned (it may still settle later inside
 * the DO), but the route no longer waits on it.
 */
const CLEANUP_TIMED_OUT = Symbol("cleanup_timed_out");
function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    work,
    new Promise<T>((_resolve, reject) => {
      setTimeout(() => reject(CLEANUP_TIMED_OUT), ms);
    }),
  ]);
}

// ---------------------------------------------------------------------------
// RPC-safe result envelope (same discipline as schedule.ts/memory.ts).
// ---------------------------------------------------------------------------

/** Error vocabulary; the route maps codes onto HTTP statuses. */
export type ContainerErrorCode =
  | "invalid_spec"
  | "container_unbound"
  | "not_running"
  | "container_error";

const ERROR_STATUS: Record<ContainerErrorCode, number> = {
  invalid_spec: 422,
  container_unbound: 501,
  not_running: 409,
  container_error: 400,
};

/** Discriminated success/failure envelope returned by every container verb. */
export type ContainerResult<T> =
  | ({ ok: true } & T)
  | { ok: false; code: ContainerErrorCode; message: string };

function fail(code: ContainerErrorCode, message: string): { ok: false; code: ContainerErrorCode; message: string } {
  return { ok: false, code, message };
}

/** Truncate captured output to the byte cap, flagging whether it was cut. */
function capOutput(value: string | undefined, max: number): { text: string; truncated: boolean } {
  const text = value ?? "";
  if (new TextEncoder().encode(text).length <= max) {
    return { text, truncated: false };
  }
  // Byte-safe truncation: slice by chars until under the cap (approximate but
  // never exceeds it).
  let cut = text;
  while (new TextEncoder().encode(cut).length > max && cut.length > 0) {
    cut = cut.slice(0, Math.floor(cut.length * 0.9));
  }
  return { text: cut, truncated: true };
}

// ---------------------------------------------------------------------------
// Verb implementations
// ---------------------------------------------------------------------------

interface PrepareBody {
  instance: string;
  container?: { image?: unknown; tier?: unknown; workspacePath?: unknown };
}

/** Validate + pin image/tier; instantiation is lazy (getSandbox creates it). */
export async function containerPrepare(
  env: Env,
  body: PrepareBody,
): Promise<ContainerResult<{ instance: string; preparedId: string }>> {
  const spec = body.container ?? {};
  if (typeof spec.image !== "string" || spec.image.trim().length === 0) {
    return fail("invalid_spec", "container.image must be a non-empty string");
  }
  if (typeof spec.tier !== "string" || !VALID_TIERS.has(spec.tier)) {
    return fail("invalid_spec", "container.tier must be one of lite..standard-4");
  }
  if (spec.workspacePath !== undefined && typeof spec.workspacePath !== "string") {
    return fail("invalid_spec", "container.workspacePath must be a string");
  }
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  // A deterministic prepared id derived from the instance name; the real
  // container image pin happens at deploy time via Wrangler.
  return { ok: true, instance: body.instance, preparedId: `prep-${body.instance}` };
}

interface StartBody {
  instance: string;
  entrypoint?: unknown;
  env?: unknown;
  enableInternet?: unknown;
  directPublicEgress?: unknown;
  egressPosture?: unknown;
  egressAllowlist?: unknown;
  egressDenylist?: unknown;
}

/**
 * The posture the Worker actually applied, returned to the Rust client, which
 * REFUSES to run an instance whose attestation does not match what it asked for
 * (issue #471). Without this the client would have to take "HTTP 200" as proof
 * that egress was configured — which it is not.
 */
interface EgressAttestation {
  directPublicEgress: false;
  posture: "sealed" | "gateway-tethered";
  allowedHosts: string[];
  deniedHosts: string[];
}

/**
 * LLM provider endpoints a governed agent container must NEVER reach directly
 * (issue #471). Cloudflare evaluates `deniedHosts` FIRST and it "overrides
 * everything else in the chain", so this survives an over-broad allowlist and a
 * per-host outbound handler alike.
 *
 * The Worker keeps its OWN copy rather than trusting the caller's `egressDenylist`:
 * a compromised or stale caller must not be able to shrink the denylist. The
 * caller's list is unioned in, never subtracted from — see {@link mergeProviderDenylist}.
 * Mirrors `PROVIDER_EGRESS_DENYLIST` in
 * `crates/ferrogate-runtime/src/cloudflare_container_egress.rs`; the Rust side
 * verifies its entries are all present (superset allowed), so the two lists may
 * drift wider but never narrower.
 *
 * Exported so `test/container-egress.test.ts` can assert the APPLIED list is the
 * union of this and the caller's, rather than restating 22 hostnames.
 */
export const PROVIDER_EGRESS_DENYLIST: readonly string[] = [
  "api.anthropic.com",
  "api.openai.com",
  "*.openai.azure.com",
  "generativelanguage.googleapis.com",
  "aiplatform.googleapis.com",
  "*.aiplatform.googleapis.com",
  "bedrock-runtime.*.amazonaws.com",
  "bedrock.*.amazonaws.com",
  "api.cohere.ai",
  "api.cohere.com",
  "api.mistral.ai",
  "api.groq.com",
  "api.deepseek.com",
  "api.x.ai",
  "api.together.xyz",
  "api.fireworks.ai",
  "api.perplexity.ai",
  "openrouter.ai",
  "*.openrouter.ai",
  "api.moonshot.cn",
  "dashscope.aliyuncs.com",
  "api.voyageai.com",
];

/**
 * Merge a caller-supplied `egressDenylist` into the Worker's own: **widen only,
 * never shrink** (issue #471).
 *
 * The result ALWAYS starts from every entry of {@link PROVIDER_EGRESS_DENYLIST},
 * so no caller — compromised, stale, or simply not the FerroGate client — can
 * remove a provider from the list by sending a shorter one. `/container/start`
 * is bearer-gated, but this route's contract is that it must not assume its
 * caller is the FerroGate client, and this is the layer advertised to catch an
 * over-broad allowlist: `docs/cloudflare-container-isolation.md` states that a
 * caller-supplied denylist "can only widen it, never shrink it".
 *
 * Two mutations survived the previous rework's suite here, which is why the
 * function exists as a named, separately assertable unit:
 *   * replacing the Worker's list with the caller's (a shrink), and
 *   * dropping the caller union entirely (a silent narrowing of what the
 *     operator asked to deny).
 * `test/container-egress.test.ts` asserts the APPLIED `deniedHosts` is exactly
 * the union, so either mutation fails.
 *
 * Caller entries are normalized (trimmed, lower-cased, blanks dropped) and
 * de-duplicated against the Worker's list, so a caller repeating a provider
 * cannot pad the applied list either.
 */
export function mergeProviderDenylist(callerEntries: unknown): string[] {
  const merged: string[] = [...PROVIDER_EGRESS_DENYLIST];
  const caller = Array.isArray(callerEntries)
    ? callerEntries.filter((entry): entry is string => typeof entry === "string")
    : [];
  for (const raw of caller) {
    const host = raw.trim().toLowerCase();
    if (host.length === 0 || merged.includes(host)) continue;
    merged.push(host);
  }
  return merged;
}

/** Bare-host shape: no scheme, path, port, credentials, wildcard or whitespace. */
const HOST_PATTERN = /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$/;

/** Glob match honoring Cloudflare's `*` ("any sequence of characters") semantics. */
export function hostMatchesPattern(host: string, pattern: string): boolean {
  const escaped = pattern
    .toLowerCase()
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`).test(host.toLowerCase());
}

/**
 * The ONLY hosts an operator has authorized this deployment to open (issue #471):
 * the `CONTAINER_GOVERNED_EGRESS_HOSTS` var, comma-separated.
 *
 * Unset or empty means **no host may be opened** — every container is sealed.
 * That is deliberate: the failure mode of a forgotten configuration must be "the
 * agent cannot reach anything", not "the agent can reach everything".
 */
export function governedEgressHosts(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
}

/**
 * Validate a requested allowlist against the governed posture rules. Returns the
 * normalized hosts, or an error message naming the first violation.
 *
 * Independent re-enforcement of what the Rust `ContainerEgressPosture` already
 * guarantees — this Worker is bearer-gated but must not assume its caller is the
 * FerroGate client.
 */
export function validateEgressAllowlist(
  requested: string[],
  authorized: string[],
): { ok: true; hosts: string[] } | { ok: false; message: string } {
  const hosts: string[] = [];
  for (const raw of requested) {
    const host = raw.trim().toLowerCase();
    if (host.includes("*")) {
      return { ok: false, message: `egressAllowlist entry ${raw} contains a wildcard; a wildcard grant is open public egress` };
    }
    if (host.length === 0 || host.length > 253 || !HOST_PATTERN.test(host)) {
      return { ok: false, message: `egressAllowlist entry ${raw} is not a bare hostname` };
    }
    if (PROVIDER_EGRESS_DENYLIST.some((pattern) => hostMatchesPattern(host, pattern))) {
      return { ok: false, message: `egressAllowlist entry ${raw} names an LLM provider endpoint; the container tier reaches providers only through the governed gateway` };
    }
    if (!authorized.includes(host)) {
      return {
        ok: false,
        message:
          authorized.length === 0
            ? `no governed egress hosts are configured (CONTAINER_GOVERNED_EGRESS_HOSTS); the container tier is sealed and cannot open ${raw}`
            : `egressAllowlist entry ${raw} is not in CONTAINER_GOVERNED_EGRESS_HOSTS`,
      };
    }
    if (!hosts.includes(host)) hosts.push(host);
  }
  return { ok: true, hosts };
}

/**
 * Configure the instance for a governed run: inject env and apply the egress
 * posture (issue #471 — enforcement, not cooperation).
 *
 * `direct_public_egress = false` is enforced at four independent points:
 *
 * 1. The `AgentSandbox` DO class pins `enableInternet = false` (index.ts), so
 *    EVERY start — including the lazy auto-start on the first `exec` — is sealed
 *    by the platform. Cloudflare enforces that outside the container (only ports
 *    80/443 + Cloudflare DNS survive), so code running INSIDE cannot undo it.
 * 2. This route rejects `enableInternet: true` / `directPublicEgress: true`
 *    **unconditionally** (422). There is no legitimate open-internet mode for a
 *    coding-agent container: previously an allowlist made `enableInternet: true`
 *    acceptable, which is exactly the hole #471 closes.
 * 3. Any requested allowlist must be a subset of the operator-authorized
 *    `CONTAINER_GOVERNED_EGRESS_HOSTS`, contain no wildcard, and name no provider
 *    endpoint. Unset config ⇒ nothing may be opened.
 * 4. Every tethered start applies {@link PROVIDER_EGRESS_DENYLIST} via
 *    `setDeniedHosts`, which Cloudflare evaluates first and which overrides the
 *    allowlist and all handlers.
 *
 * THE SEALED PATH RESETS BOTH LISTS (#471 rework). It used to call NEITHER
 * setter, on the reasoning that a fresh sealed container already denies
 * everything. That reasoning only holds for a FRESH instance, and instance names
 * are reused: `fg.{tenant}.{session}.{run}` addresses a Durable Object by name,
 * and `@cloudflare/containers` keeps `allowedHostsOverride` as a live DO field
 * that it PERSISTS to storage (`dist/lib/container.js:1065-1071`), so it survives
 * eviction. Two starts on one name — tethered, then sealed — therefore left the
 * instance carrying the gateway host while the Worker attested
 * `{"posture":"sealed","allowedHosts":[],"deniedHosts":[]}`. That is a FALSE
 * ATTESTATION on the enforcement path, and `EgressPostureAttestation::verify`
 * accepts it, so the Rust client had no way to notice. Bounded in impact — the
 * stale host can only be the operator-authorized gateway — but #428's budget and
 * tether reasoning is downstream of knowing which posture is actually live.
 *
 * There is no read-back to attest from instead: `effectiveAllowedHosts` /
 * `effectiveDeniedHosts` are `private` on the SDK's `Container`
 * (`dist/lib/container.d.ts:304-305`) and the Worker holds a DO stub, not the
 * instance. So the Worker makes the attested state true by applying it.
 *
 * ORDER IS PER-POSTURE, AND EACH ORDER IS CLOSED AT EVERY INTERMEDIATE STEP:
 *   * tethered — deny first. If `setAllowedHosts` then threw, the instance is
 *     left with the provider denylist and no fresh grant, never
 *     allowed-but-unfenced. It also matches Cloudflare's evaluation order.
 *   * sealed — ALLOW first. `setAllowedHosts([])` is a deny-by-default gate that
 *     refuses every host (`ContainerProxy` step 2 treats `[]` as a set
 *     allowlist), so it closes a stale grant immediately; clearing the denylist
 *     first would leave the stale host reachable for the width of one RPC.
 *
 * The cost is that a sealed start now needs `ctx.exports.ContainerProxy` too, so
 * a deployment missing the `enable_ctx_exports` compatibility flag fails EVERY
 * start rather than only tethered ones. That is fail-closed and loud, which is
 * the right way for that misconfiguration to surface.
 */
export async function containerStart(
  env: Env,
  body: StartBody,
): Promise<
  ContainerResult<{
    instance: string;
    instanceId: string;
    running: boolean;
    egress: EgressAttestation;
  }>
> {
  if (body.enableInternet === true || body.directPublicEgress === true) {
    return fail(
      "invalid_spec",
      "direct public egress is not available on the container agent tier; " +
        "enableInternet/directPublicEgress must be false (issue #471)",
    );
  }
  const requested = Array.isArray(body.egressAllowlist)
    ? body.egressAllowlist.filter((x): x is string => typeof x === "string")
    : [];
  const validated = validateEgressAllowlist(requested, governedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS));
  if (!validated.ok) {
    return fail("invalid_spec", validated.message);
  }
  const allowlist = validated.hosts;
  if (body.egressPosture !== undefined && body.egressPosture !== "sealed" && body.egressPosture !== "gateway-tethered") {
    return fail("invalid_spec", "egressPosture must be sealed or gateway-tethered");
  }
  const posture: "sealed" | "gateway-tethered" = allowlist.length === 0 ? "sealed" : "gateway-tethered";
  if (body.egressPosture !== undefined && body.egressPosture !== posture) {
    return fail(
      "invalid_spec",
      `egressPosture ${String(body.egressPosture)} does not match the requested allowlist`,
    );
  }
  // The Worker's own denylist wins; a caller-supplied list can only WIDEN it.
  // A sealed container refuses every host through the empty allowlist, so it
  // carries no denylist — and the Rust side compares denylists as a superset of
  // what it asked for, which for `Sealed` is nothing.
  const denylist = posture === "sealed" ? [] : mergeProviderDenylist(body.egressDenylist);

  const envVars: Record<string, string> = {};
  if (body.env && typeof body.env === "object" && !Array.isArray(body.env)) {
    for (const [k, v] of Object.entries(body.env as Record<string, unknown>)) {
      if (typeof v === "string") envVars[k] = v;
    }
  }
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    await sandbox.setEnvVars(envVars);
    if (posture === "gateway-tethered") {
      // Denylist FIRST: if `setAllowedHosts` were applied and the deny call then
      // threw, the instance would be left reachable-but-unfenced. Cloudflare
      // evaluates deniedHosts ahead of allowedHosts, so this ordering also
      // matches the enforcement order.
      await sandbox.setDeniedHosts(denylist);
      await sandbox.setAllowedHosts(allowlist);
    } else {
      // SEALED. Both lists are applied (as `[]`), not skipped: the instance name
      // may have been tethered by an earlier start and `allowedHostsOverride`
      // outlives it. Allowlist FIRST — `[]` is a deny-by-default gate that closes
      // any stale grant in one call, so there is no window in which the previous
      // run's host is still reachable. These are the same `allowlist`/`denylist`
      // values the attestation below reports, so the attestation cannot drift
      // from what was applied.
      await sandbox.setAllowedHosts(allowlist);
      await sandbox.setDeniedHosts(denylist);
    }
    return {
      ok: true,
      instance: body.instance,
      instanceId: body.instance,
      running: true,
      egress: {
        directPublicEgress: false,
        posture,
        allowedHosts: allowlist,
        deniedHosts: denylist,
      },
    };
  } catch (err) {
    // A failure applying the egress posture must NOT surface as a started
    // instance: the caller would run an agent whose fence was never installed.
    return fail("container_error", errMessage(err));
  }
}

interface ExecBody {
  instance: string;
  step?: {
    mode?: unknown;
    command?: unknown;
    language?: unknown;
    source?: unknown;
    timeoutMillis?: unknown;
  };
}

/** Execute a command or code step and capture stdout/stderr/exit. */
export async function containerExec(
  env: Env,
  body: ExecBody,
): Promise<
  ContainerResult<{
    instance: string;
    exitCode: number | null;
    stdout: string;
    stderr: string;
    truncated: boolean;
  }>
> {
  const step = body.step ?? {};
  const timeout =
    Number.isInteger(step.timeoutMillis) && (step.timeoutMillis as number) > 0
      ? (step.timeoutMillis as number)
      : undefined;
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  const max = containerMaxOutputBytes(env.CONTAINER_MAX_OUTPUT_BYTES);

  // Validate the step shape BEFORE touching the instance so a bad spec is a 422.
  let exitCode: number | null;
  let rawStdout: string;
  let rawStderr: string;
  try {
    if (step.mode === "command") {
      if (!Array.isArray(step.command) || step.command.length === 0) {
        return fail("invalid_spec", "step.command must be a non-empty argv array");
      }
      const argv = (step.command as unknown[]).map((x) => String(x));
      // SECURITY (issue #415, gate re-test — command injection on an untrusted-code
      // backend): `@cloudflare/sandbox@0.12.4` exposes ONLY a string-command exec API —
      // `Sandbox.exec(command: string, options?: ExecOptions)`
      // (node_modules/@cloudflare/sandbox/dist/sandbox-5MHau7vJ.d.ts:3044); there is NO
      // argv/string[] overload anywhere on the Sandbox surface. A naive `argv.join(" ")`
      // destroys argument boundaries AND re-subjects every token to the container shell
      // (word-splitting, globbing, and `;`/`$(...)`/backtick/redirection metacharacters) —
      // a command-injection surface. We honor the argv contract by POSIX single-quote
      // quoting each token, so it is passed literally and cannot be split or interpreted.
      const command = argv.map(shellQuote).join(" ");
      const result = await sandbox.exec(command, timeout !== undefined ? { timeout } : undefined);
      exitCode = result.exitCode;
      rawStdout = result.stdout;
      rawStderr = result.stderr;
    } else if (step.mode === "code") {
      if (typeof step.language !== "string" || !CODE_LANGUAGES.has(step.language)) {
        return fail("invalid_spec", "step.language must be one of python|javascript|typescript");
      }
      if (typeof step.source !== "string") {
        return fail("invalid_spec", "step.source must be a string");
      }
      const language = step.language as CodeLanguage;
      // `runCode` returns an ExecutionResult (interpreter logs + optional error);
      // there is no POSIX exit code, so we derive one from the error presence.
      const result = await sandbox.runCode(
        step.source,
        timeout !== undefined ? { language, timeout } : { language },
      );
      rawStdout = result.logs.stdout.join("");
      rawStderr = result.logs.stderr.join("");
      if (result.error) {
        exitCode = 1;
        const trace = result.error.traceback?.length ? `\n${result.error.traceback.join("\n")}` : "";
        rawStderr = `${rawStderr}${rawStderr ? "\n" : ""}${result.error.name}: ${result.error.message}${trace}`;
      } else {
        exitCode = 0;
      }
    } else {
      return fail("invalid_spec", "step.mode must be command or code");
    }
  } catch (err) {
    // A non-zero / abnormal exit takes the shell down and the SDK raises
    // SessionTerminatedError. This is a GOVERNED outcome, not a crash: map it to
    // a normal exec result carrying the propagated exit code so the caller sees
    // exitCode != 0 instead of a 5xx. Uniform across the DIRECT-command path (where
    // the SDK populates the structured `.exitCode`) and the SHELL-WRAPPED path — e.g.
    // `sh -c "exit N"` — where the SDK leaves `.exitCode` null but embeds the code in
    // the message ("... shell exited (exit code: N)"); `terminatedExitCode` extracts
    // both. (Issue #415 live defects: shell-wrapped `sh -c "exit N"` → {exitCode:N}.)
    if (err instanceof SessionTerminatedError) {
      const stderr = capOutput(err.message, max);
      return {
        ok: true,
        instance: body.instance,
        exitCode: terminatedExitCode(err),
        stdout: "",
        stderr: stderr.text,
        truncated: stderr.truncated,
      };
    }
    return fail("container_error", errMessage(err));
  }

  const stdout = capOutput(rawStdout, max);
  const stderr = capOutput(rawStderr, max);
  return {
    ok: true,
    instance: body.instance,
    exitCode,
    stdout: stdout.text,
    stderr: stderr.text,
    truncated: stdout.truncated || stderr.truncated,
  };
}

interface StopBody {
  instance: string;
  signal?: unknown;
}

/** Stop the running instance with SIGTERM/SIGKILL (real `Sandbox.stop(signal)`). */
export async function containerStop(
  env: Env,
  body: StopBody,
): Promise<ContainerResult<{ instance: string; signal: string; running: boolean }>> {
  const signal: "SIGTERM" | "SIGKILL" = body.signal === "SIGKILL" ? "SIGKILL" : "SIGTERM";
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    // Bounded: a wedged instance must not hang the route. `stop` sends the signal;
    // an already-stopped/terminated session is a successful no-op for our purposes.
    await withTimeout(sandbox.stop(signal), STOP_TIMEOUT_MS);
    return { ok: true, instance: body.instance, signal, running: false };
  } catch (err) {
    if (err === CLEANUP_TIMED_OUT || err instanceof SessionTerminatedError) {
      // Signal issued (or session already gone); the instance is no longer usable.
      return { ok: true, instance: body.instance, signal, running: false };
    }
    return fail("container_error", errMessage(err));
  }
}

interface LogsBody {
  instance: string;
  tail?: unknown;
}

/**
 * Collect recent instance logs. The session-based `@cloudflare/sandbox` surface
 * has no aggregate container-log tail (only per-process `getProcessLogs` /
 * `streamProcessLogs`); the governed `exec` path already returns each step's
 * stdout/stderr inline. So this verb returns an empty tail rather than inventing
 * a method that does not exist on the real SDK.
 */
export async function containerLogs(
  env: Env,
  body: LogsBody,
): Promise<ContainerResult<{ instance: string; lines: string[] }>> {
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  return { ok: true, instance: body.instance, lines: [] };
}

interface ArtifactsBody {
  instance: string;
  path?: unknown;
}

/** List artifacts under the instance workspace (default) or `path`. */
export async function containerArtifacts(
  env: Env,
  body: ArtifactsBody,
): Promise<
  ContainerResult<{
    instance: string;
    artifacts: { path: string; sizeBytes: number; contentType: string | null }[];
  }>
> {
  const path = typeof body.path === "string" && body.path.length > 0 ? body.path : DEFAULT_WORKSPACE;
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    const result = await sandbox.listFiles(path);
    const artifacts = result.files
      .filter((entry) => entry.type === "file")
      .map((entry) => ({
        path: entry.absolutePath,
        sizeBytes: typeof entry.size === "number" ? entry.size : 0,
        // FileInfo carries no MIME type; the artifact content type is unknown here.
        contentType: null as string | null,
      }));
    return { ok: true, instance: body.instance, artifacts };
  } catch (err) {
    if (err instanceof SessionTerminatedError) {
      // Session gone (e.g. after an abnormal exit): nothing to enumerate.
      return { ok: true, instance: body.instance, artifacts: [] };
    }
    return fail("container_error", errMessage(err));
  }
}

interface CleanupBody {
  instance: string;
}

/**
 * Destroy the instance and free its resources in BOUNDED time. This is the
 * resource-leak fix: the earlier draft could hang 60-90s on a wedged instance
 * (its `signal`/`configureEgress` calls crashed, leaving the container running
 * until platform idle-sleep). `destroy()` is the real SIGKILL teardown; we race
 * it against `CLEANUP_TIMEOUT_MS` and report success either way, so cleanup is
 * idempotent and never hangs on an already-dead / unresponsive instance.
 */
export async function containerCleanup(
  env: Env,
  body: CleanupBody,
): Promise<ContainerResult<{ instance: string; destroyed: boolean }>> {
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    await withTimeout(sandbox.destroy(), CLEANUP_TIMEOUT_MS);
    return { ok: true, instance: body.instance, destroyed: true };
  } catch (err) {
    if (err === CLEANUP_TIMED_OUT) {
      // Teardown did not confirm within the bound. We return success (not a 5xx)
      // so the run cleanup completes; the platform reclaims the wedged instance
      // via idle-sleep. `destroyed: false` signals "unconfirmed" to the caller.
      return { ok: true, instance: body.instance, destroyed: false };
    }
    if (err instanceof SessionTerminatedError) {
      // The session was already gone; the instance is effectively torn down.
      return { ok: true, instance: body.instance, destroyed: true };
    }
    return fail("container_error", errMessage(err));
  }
}

/** Best-effort message extraction (thrown values are not guaranteed Errors). */
function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/**
 * POSIX-safe shell quoting for a single argv token. Wrap the whole token in
 * single quotes — which suppress ALL shell interpretation — and escape any
 * embedded single-quote as the classic `'\''` idiom (close-quote, an escaped
 * literal quote, reopen-quote). Because `@cloudflare/sandbox` exec only accepts
 * a command STRING, this is how we preserve argument boundaries and keep the
 * shell from word-splitting, globbing, or interpreting metacharacters in a
 * token — the injection-safety guarantee for the argv contract.
 */
function shellQuote(token: string): string {
  return `'${token.replaceAll("'", "'\\''")}'`;
}

/**
 * Recover the exit code from a `SessionTerminatedError` uniformly across the
 * direct-command and shell-wrapped paths. The SDK populates the structured
 * `.exitCode` for a command that takes the session shell down directly; for a
 * shell-wrapped exit (`sh -c "exit N"`) it leaves `.exitCode` null but embeds
 * the code in the message ("... shell exited (exit code: N)"). Prefer the
 * structured value, else parse the message; null only if neither is present.
 */
function terminatedExitCode(err: SessionTerminatedError): number | null {
  if (typeof err.exitCode === "number") return err.exitCode;
  const match = /exit code:\s*(-?\d+)/i.exec(err.message);
  return match ? Number(match[1]) : null;
}

// ---------------------------------------------------------------------------
// Route dispatch
// ---------------------------------------------------------------------------

type ContainerResultLike =
  | { ok: true }
  | { ok: false; code: ContainerErrorCode; message: string };

function containerResponse(result: ContainerResultLike): Response {
  if (!result.ok) {
    return json({ error: result.code, message: result.message }, ERROR_STATUS[result.code]);
  }
  return json(result);
}

/**
 * Container routes (issue #415), all POST + bearer-gated. POST bodies (never
 * query strings) carry the instance name, since names embed tenant identity:
 *
 *   POST /container/prepare   { instance, container }              pin image/tier
 *   POST /container/start     { instance, entrypoint?, env?,       configure + ATTEST the
 *                               egressPosture?, egressAllowlist?,   governed egress posture
 *                               egressDenylist? }                   (#471; internet never on)
 *   POST /container/exec      { instance, step }                   run cmd/code
 *   POST /container/stop      { instance, signal }                 SIGTERM/SIGKILL
 *   POST /container/logs      { instance, tail? }                  recent logs
 *   POST /container/artifacts { instance, path? }                  list workspace
 *   POST /container/cleanup   { instance }                         destroy (bounded)
 *
 * Cloudflare has NO public container lifecycle REST API — the low-level surface
 * is only reachable from Worker code — so these routes are the sole tethered
 * path FerroGate drives the tier through, exactly like /control, /memory, and
 * /schedule. The instance name is minted by the Rust side
 * (`fg.{tenant}.{session}.{run}`); the Worker never derives names itself.
 */
export async function handleContainer(request: Request, env: Env, url: URL): Promise<Response> {
  const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
  if (denied) return denied;
  if (request.method !== "POST") {
    return json({ error: "container routes are POST-only" }, 405);
  }

  let body: { instance?: unknown } & Record<string, unknown>;
  try {
    body = (await request.json()) as { instance?: unknown } & Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const instance = body.instance;
  if (typeof instance !== "string" || instance.length === 0 || instance.length > 512) {
    return json({ error: "missing or invalid instance name" }, 400);
  }
  const withInstance = { ...body, instance } as { instance: string } & Record<string, unknown>;

  const verb = url.pathname.slice("/container/".length);
  try {
    switch (verb) {
      case "prepare":
        return containerResponse(await containerPrepare(env, withInstance as PrepareBody));
      case "start":
        return containerResponse(await containerStart(env, withInstance as StartBody));
      case "exec":
        return containerResponse(await containerExec(env, withInstance as ExecBody));
      case "stop":
        return containerResponse(await containerStop(env, withInstance as StopBody));
      case "logs":
        return containerResponse(await containerLogs(env, withInstance as LogsBody));
      case "artifacts":
        return containerResponse(await containerArtifacts(env, withInstance as ArtifactsBody));
      case "cleanup":
        return containerResponse(await containerCleanup(env, withInstance as CleanupBody));
      default:
        return json({ error: `unknown container verb: ${verb}` }, 404);
    }
  } catch (err) {
    return json({ error: `container call failed: ${errMessage(err)}` }, 502);
  }
}
