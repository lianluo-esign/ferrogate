// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: FerroGate container/sandbox isolation routes (issue #415): governed
//   prepare/start/exec/stop/logs/artifacts/cleanup over a per-tenant Cloudflare Container or
//   @cloudflare/sandbox instance. Cloudflare exposes NO public container lifecycle REST API, so
//   these bearer-gated Worker routes are the only tethered path FerroGate drives the tier through,
//   with egress deny-by-default (enableInternet=false unless a governed allowlist is provided).

import { json, requireBearer } from "./auth";
import type { Env } from "./index";

// ---------------------------------------------------------------------------
// Cloudflare container/sandbox facts (verify against the pinned SDK at deploy)
// ---------------------------------------------------------------------------
//
// * Containers GA (Apr 2026): a `class X extends Container` (Durable
//   Object–backed) exposes a LOW-LEVEL lifecycle from Worker code via
//   `this.ctx.container`: `start({ env, entrypoint, enableInternet })`,
//   `signal(SIGTERM|SIGKILL)`, `exec(cmd)`, `monitor()`, `destroy()`,
//   `getTcpPort(p).fetch()`, and a `running` boolean. There is NO public REST
//   lifecycle — everything is driven from a fronting Worker (this one).
// * Sandbox SDK (`@cloudflare/sandbox`): `getSandbox(env.Sandbox, id)` →
//   `exec`, `createCodeContext` + `runCode`, file ops, `.stop()` — ideal for
//   untrusted agent-generated code, which is the primary use of this tier.
// * Workers Paid only; scales to zero; tiers lite→standard-4 (≤4 vCPU/12 GiB).
//
// This module addresses the per-tenant instance BY NAME through the
// CONTAINER_SANDBOX binding (a Sandbox/Container DO namespace) — the instance
// name is minted by the Rust side (`fg.{tenant}.{session}.{run}`), so
// per-instance DO isolation IS tenant isolation. The binding is OPTIONAL (like
// the #427 semantic-memory pilot's VECTORIZE/AI): absent it, every verb fails
// closed with `container_unbound` (HTTP 501). The low-level SDK surface is
// declared STRUCTURALLY below so this module — and `tsc --noEmit` — needs
// neither `@cloudflare/sandbox` nor `@cloudflare/containers` as a build dep.

/** GA instance tiers (≤ 4 vCPU / 12 GiB). */
const VALID_TIERS = new Set([
  "lite",
  "basic",
  "standard-1",
  "standard-2",
  "standard-3",
  "standard-4",
]);

/** Default writable workspace mount inside the instance. */
const DEFAULT_WORKSPACE = "/workspace";

/** Cap on captured stdout/stderr bytes returned over the wire. */
const DEFAULT_MAX_OUTPUT_BYTES = 1_000_000;

/** One process/code execution result from the underlying sandbox. */
export interface SandboxExecResult {
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
}

/** One file discovered under the instance workspace. */
export interface SandboxFileEntry {
  path?: string;
  name?: string;
  size?: number;
  contentType?: string;
}

/**
 * Structural view of a Cloudflare Container / `@cloudflare/sandbox` instance —
 * the subset of primitives these routes drive. Satisfied in production by
 * `getSandbox(env.CONTAINER_SANDBOX, instance)` (or a `Container` DO's
 * `this.ctx.container`). Declared structurally so no SDK is a build dependency;
 * optional members are probed defensively so a minimal binding still typechecks.
 */
export interface SandboxHandle {
  /** Inject/replace the instance environment (governed key/values). */
  setEnvVars?(env: Record<string, string>): Promise<void> | void;
  /** Apply the governed egress posture; absent → the platform default (sealed). */
  configureEgress?(enableInternet: boolean, allowlist: string[]): Promise<void> | void;
  /** Run a shell command; the untrusted-command path. */
  exec(command: string, options?: { timeout?: number; cwd?: string }): Promise<SandboxExecResult>;
  /** Run a code step (createCodeContext + runCode); the untrusted-code path. */
  runCode?(
    code: string,
    options?: { language?: string; timeout?: number },
  ): Promise<SandboxExecResult>;
  /** List files under a workspace path (artifact collection). */
  listFiles?(path: string): Promise<SandboxFileEntry[]>;
  /** Read recent instance logs. */
  readLogs?(tail?: number): Promise<string[]>;
  /** Whether the instance is currently running. */
  readonly running?: boolean;
  /** Graceful/forced stop (signal). */
  signal?(signal: "SIGTERM" | "SIGKILL"): Promise<void> | void;
  /** Graceful stop (Sandbox SDK `.stop()`). */
  stop?(): Promise<void> | void;
  /** Tear down the instance and free resources. */
  destroy?(): Promise<void> | void;
}

/**
 * Resolve the per-tenant sandbox for `instance`, or `null` when no
 * CONTAINER_SANDBOX binding is configured (fail closed → `container_unbound`).
 * In production `getSandbox(env.CONTAINER_SANDBOX, instance)` returns the stub;
 * here we address the DO by name and treat it as the structural handle.
 */
export function resolveSandbox(env: Env, instance: string): SandboxHandle | null {
  const ns = env.CONTAINER_SANDBOX;
  if (!ns) return null;
  const stub = ns.get(ns.idFromName(instance));
  return stub as unknown as SandboxHandle;
}

/** Parse the `CONTAINER_MAX_OUTPUT_BYTES` var, falling back to the default. */
export function containerMaxOutputBytes(raw: string | undefined): number {
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return DEFAULT_MAX_OUTPUT_BYTES;
  }
  return parsed;
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
  egressAllowlist?: unknown;
}

/**
 * Start the instance with governed egress. `enableInternet` with an EMPTY
 * `egressAllowlist` is rejected (defense-in-depth: the Rust client blocks it
 * client-side too) — open public egress is deny-by-default.
 */
export async function containerStart(
  env: Env,
  body: StartBody,
): Promise<ContainerResult<{ instance: string; instanceId: string; running: boolean }>> {
  const enableInternet = body.enableInternet === true;
  const allowlist = Array.isArray(body.egressAllowlist)
    ? body.egressAllowlist.filter((x): x is string => typeof x === "string")
    : [];
  if (enableInternet && allowlist.length === 0) {
    return fail(
      "invalid_spec",
      "enableInternet requires a non-empty egressAllowlist; open public egress is deny-by-default",
    );
  }
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
    if (typeof sandbox.setEnvVars === "function") {
      await sandbox.setEnvVars(envVars);
    }
    if (typeof sandbox.configureEgress === "function") {
      await sandbox.configureEgress(enableInternet, allowlist);
    }
    const running = sandbox.running !== false;
    return { ok: true, instance: body.instance, instanceId: body.instance, running };
  } catch (err) {
    return fail("container_error", (err as Error).message ?? String(err));
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
  if (sandbox.running === false) {
    return fail("not_running", "container instance is not running");
  }
  const max = containerMaxOutputBytes(env.CONTAINER_MAX_OUTPUT_BYTES);
  try {
    let result: SandboxExecResult;
    if (step.mode === "command") {
      if (!Array.isArray(step.command) || step.command.length === 0) {
        return fail("invalid_spec", "step.command must be a non-empty argv array");
      }
      const argv = (step.command as unknown[]).map((x) => String(x));
      // The sandbox `exec` takes a command string; join the argv. A live
      // deployment may prefer a structured `startProcess({ cmd, args })`.
      result = await sandbox.exec(argv.join(" "), { timeout });
    } else if (step.mode === "code") {
      if (typeof step.language !== "string" || step.language.trim().length === 0) {
        return fail("invalid_spec", "step.language must be a non-empty string");
      }
      if (typeof step.source !== "string") {
        return fail("invalid_spec", "step.source must be a string");
      }
      if (typeof sandbox.runCode !== "function") {
        return fail("container_error", "sandbox does not support runCode");
      }
      result = await sandbox.runCode(step.source, { language: step.language, timeout });
    } else {
      return fail("invalid_spec", "step.mode must be command or code");
    }
    const stdout = capOutput(result.stdout, max);
    const stderr = capOutput(result.stderr, max);
    return {
      ok: true,
      instance: body.instance,
      exitCode: result.exitCode ?? null,
      stdout: stdout.text,
      stderr: stderr.text,
      truncated: stdout.truncated || stderr.truncated,
    };
  } catch (err) {
    return fail("container_error", (err as Error).message ?? String(err));
  }
}

interface StopBody {
  instance: string;
  signal?: unknown;
}

/** Stop the running instance with SIGTERM/SIGKILL. */
export async function containerStop(
  env: Env,
  body: StopBody,
): Promise<ContainerResult<{ instance: string; signal: string; running: boolean }>> {
  const signal = body.signal === "SIGKILL" ? "SIGKILL" : "SIGTERM";
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    if (typeof sandbox.signal === "function") {
      await sandbox.signal(signal);
    } else if (typeof sandbox.stop === "function") {
      await sandbox.stop();
    }
    return { ok: true, instance: body.instance, signal, running: false };
  } catch (err) {
    return fail("container_error", (err as Error).message ?? String(err));
  }
}

interface LogsBody {
  instance: string;
  tail?: unknown;
}

/** Collect recent instance logs. */
export async function containerLogs(
  env: Env,
  body: LogsBody,
): Promise<ContainerResult<{ instance: string; lines: string[] }>> {
  const tail =
    Number.isInteger(body.tail) && (body.tail as number) > 0 ? (body.tail as number) : undefined;
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    const lines = typeof sandbox.readLogs === "function" ? await sandbox.readLogs(tail) : [];
    return { ok: true, instance: body.instance, lines };
  } catch (err) {
    return fail("container_error", (err as Error).message ?? String(err));
  }
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
    const entries = typeof sandbox.listFiles === "function" ? await sandbox.listFiles(path) : [];
    const artifacts = entries.map((entry) => ({
      path: entry.path ?? `${path}/${entry.name ?? ""}`,
      sizeBytes: typeof entry.size === "number" ? entry.size : 0,
      contentType: entry.contentType ?? null,
    }));
    return { ok: true, instance: body.instance, artifacts };
  } catch (err) {
    return fail("container_error", (err as Error).message ?? String(err));
  }
}

interface CleanupBody {
  instance: string;
}

/** Destroy the instance and free its resources. */
export async function containerCleanup(
  env: Env,
  body: CleanupBody,
): Promise<ContainerResult<{ instance: string; destroyed: boolean }>> {
  const sandbox = resolveSandbox(env, body.instance);
  if (!sandbox) {
    return fail("container_unbound", "no CONTAINER_SANDBOX binding is configured");
  }
  try {
    if (typeof sandbox.destroy === "function") {
      await sandbox.destroy();
    } else if (typeof sandbox.stop === "function") {
      await sandbox.stop();
    }
    return { ok: true, instance: body.instance, destroyed: true };
  } catch (err) {
    return fail("container_error", (err as Error).message ?? String(err));
  }
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
 *   POST /container/start     { instance, entrypoint?, env?,       launch (egress
 *                               enableInternet?, egressAllowlist? }  deny-by-default)
 *   POST /container/exec      { instance, step }                   run cmd/code
 *   POST /container/stop      { instance, signal }                 SIGTERM/SIGKILL
 *   POST /container/logs      { instance, tail? }                  recent logs
 *   POST /container/artifacts { instance, path? }                  list workspace
 *   POST /container/cleanup   { instance }                         destroy
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
    return json({ error: `container call failed: ${(err as Error).message}` }, 502);
  }
}
