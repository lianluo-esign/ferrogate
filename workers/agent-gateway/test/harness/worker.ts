// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway. Test-only Worker entrypoint for the
//   #471 governed-egress suite. It re-exports the PRODUCTION Worker unchanged (default
//   handler, AgentGateway, AgentSandbox, ContainerProxy) and adds ONE extra Durable
//   Object class, `ProbeSandbox`, which the container binding points at while the suite
//   runs. Nothing here ships: `wrangler.toml` binds `AgentSandbox` itself, and
//   `container-egress.test.ts` asserts that it does.
//
//   WHY A SUBCLASS IS NEEDED AT ALL. `@cloudflare/containers`' `Container` constructor
//   throws unless `ctx.container` — the container platform API — is present, and workerd
//   only provides it when a real container engine is attached. There is none here, by
//   design (no Docker, no CF account). `ProbeSandbox` therefore attaches a stand-in
//   `ctx.container` and OVERRIDES NOTHING ELSE: every field and method under test —
//   `enableInternet`, `interceptHttps`, `setAllowedHosts`, `setDeniedHosts`,
//   `effectiveAllowedHosts`, `applyOutboundInterception` — is the real inherited one,
//   so flipping `AgentSandbox { enableInternet = false }` flips what these probes
//   observe, and so does dropping `AgentSandbox { interceptHttps = true }`.
//
//   The stand-in records the `Fetcher` the SDK registers as the container's outbound
//   interceptor, and the props the SDK builds for it. That fetcher is a REAL
//   `ContainerProxy` entrypoint — Cloudflare's own egress decision function — so the
//   suite can ask what the applied posture actually DOES with a request instead of
//   asserting on the JSON the Worker sent.

export * from "../../src/index";
// Re-exported EXPLICITLY (not via `export *`): workerd only lists an entrypoint in
// `ctx.exports` when the entry module names it, and `applyOutboundInterception` resolves
// the interceptor through `ctx.exports.ContainerProxy`. Sourcing it from `../../src/index`
// rather than from the SDK also means deleting the production re-export breaks this build.
export { ContainerProxy } from "../../src/index";

import { getAgentByName } from "agents";

import { AgentGateway, AgentSandbox, createHandler } from "../../src/index";
import type { AgentAddressingOptions, Env, InvokeRequest } from "../../src/index";

/**
 * Every `(name, options)` the control routes addressed an agent instance with,
 * in call order.
 *
 * The addressing OPTIONS are consumed by `getAgentByName` before any agent code
 * runs, so no response field can prove they were passed — `resolvedLocationHint`
 * is copied out of `props` on a separate code path and reports the requested hint
 * even with the options argument deleted. This is the only place the real
 * argument is observable.
 */
export const addressingCalls: Array<{ name: string; options?: AgentAddressingOptions }> = [];

/**
 * The PRODUCTION handler with exactly one dependency substituted: the addressing
 * function records its arguments and then delegates to the real
 * `getAgentByName`. Every route, guard and status mapping is the shipped one —
 * `createHandler` is called, not reimplemented.
 */
export default createHandler((namespace, name, options) => {
  addressingCalls.push({ name, options });
  return getAgentByName<Env, AgentGateway>(namespace, name, options);
});

/**
 * Post-await side effects, and observed abort reasons, per run — keyed by
 * instance name and held in MODULE scope rather than on the Durable Object.
 *
 * `destroyRun` ends in the SDK's `destroy()`, whose last step is
 * `ctx.abort("destroyed")`: the instance and everything on it is gone, so a
 * per-instance ledger read after a destroy always reads empty and "the workload
 * did not run" would pass vacuously for the one case it exists to prove. Module
 * scope outlives the aborted object, so both the presence and the absence of an
 * effect are real observations.
 */
const completedWork = new Map<string, string[]>();
const observedAbortReasons = new Map<string, string[]>();

function record(ledger: Map<string, string[]>, runRef: string, entry: string): void {
  const existing = ledger.get(runRef);
  if (existing) existing.push(entry);
  else ledger.set(runRef, [entry]);
}

/** The post-await side effects workloads on `runRef` actually performed. */
export function sideEffects(runRef: string): string[] {
  return completedWork.get(runRef) ?? [];
}

/**
 * The abort reasons workloads on `runRef` actually OBSERVED, stringified.
 *
 * Distinct from "the run stopped": a Durable Object that is torn down stops its
 * work whatever the code did, so `destroyRun`'s explicit
 * `#inFlight.abort(...)` can only be pinned by the workload having seen the
 * signal BEFORE the teardown. Deleting that line empties this ledger.
 */
export function observedAborts(runRef: string): string[] {
  return observedAbortReasons.get(runRef) ?? [];
}

/**
 * Clear all three ledgers. Call from a `beforeEach`.
 *
 * Module scope is what makes a post-destroy read real (above), but it also means
 * the ledgers accumulate for the lifetime of the isolate. Without this, every
 * assertion over them is sound only because each test happens to pick a unique
 * `runRef` — `addressingCalls.filter(...)[0]` takes the FIRST call ever recorded
 * for a name, and `sideEffects()` filters by nothing else — so a reused name or a
 * retried `start` would silently change what they assert. Isolation belongs to the
 * harness, not to the names people choose.
 */
export function resetProbeLedgers(): void {
  addressingCalls.length = 0;
  completedWork.clear();
  observedAbortReasons.clear();
}

/**
 * `AgentGateway` with a workload that can actually be caught mid-flight
 * (issue #414). The production class inherits everything that matters —
 * `start` / `cancel` / `destroyRun` / `status` / the `#inFlight` abort handle
 * are the real ones, and this subclass overrides only `dispatchWorkload`, the
 * documented seam a framework harness overrides in production.
 *
 * WHY IT IS NEEDED. "A cancelled run stops doing work" is unprovable against a
 * workload that finishes in the same tick: the minimal deployable Worker records
 * the invocation and returns, so there is no window in which to cancel it. This
 * probe supplies the window — `workloadRef: "probe:sleep"` awaits a timer,
 * observes the abort signal, and records whether it ever reached the far side.
 * `sideEffects()` is the observation that matters: if a cancelled run really
 * stopped, the post-await effect is NOT there.
 *
 * A plain `workloadRef` falls through to `super.dispatchWorkload`, so every
 * other control test still exercises the production dispatch verbatim.
 * `control.test.ts` asserts wrangler.toml binds the PRODUCTION `AgentGateway`.
 *
 * TWO PROBES, because cancellation here is COOPERATIVE and the two halves of
 * that word need different workloads to be visible:
 *
 *   * `probe:sleep` observes the signal — the well-behaved workload a cancel
 *     really does stop.
 *   * `probe:defiant` ignores it entirely — the workload a cooperative cancel
 *     CANNOT stop. It is the only shape that can tell whether `cancel` reports
 *     an outcome it did not achieve, and it is what the #428 budget kill has to
 *     escalate against.
 */
export class ProbeAgentGateway extends AgentGateway {
  protected override async dispatchWorkload(
    request: InvokeRequest,
    signal: AbortSignal,
  ): Promise<string> {
    const delayMs = Number(request.args[0] ?? "50");
    if (request.workloadRef === "probe:defiant") {
      // No signal observation anywhere: this workload runs to the far side of
      // its await no matter what was signalled.
      await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
      record(completedWork, this.name, request.workloadRef);
      return `defiant probe ran ${delayMs}ms`;
    }
    if (request.workloadRef !== "probe:sleep") {
      return super.dispatchWorkload(request, signal);
    }
    // A signal-observing await: exactly the shape `dispatchWorkload`'s contract
    // requires of a real harness. Rejecting on abort is what makes the work stop.
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      const onAbort = () => {
        clearTimeout(timer);
        // Recorded SYNCHRONOUSLY, inside the abort dispatch, so it lands before
        // a `destroyRun` that aborts and then tears the object down.
        record(observedAbortReasons, this.name, String(signal.reason));
        reject(signal.reason ?? new Error("aborted"));
      };
      if (signal.aborted) return onAbort();
      signal.addEventListener("abort", onAbort, { once: true });
    });
    // Reached ONLY when the workload was never cancelled.
    record(completedWork, this.name, request.workloadRef);
    return `probe slept ${delayMs}ms`;
  }
}

/** One outbound-interception registration the SDK made against the container API. */
interface Interception {
  kind: "all-http" | "http" | "https";
  host: string;
  fetcher: Fetcher;
}

/**
 * The props `applyOutboundInterception` built for `ContainerProxy`. Captured, never
 * reconstructed: they are what Cloudflare's decision function is actually configured
 * with, and their ORDER records the order the Worker applied the lists in.
 */
export interface CapturedProps {
  enableInternet?: boolean;
  allowedHosts?: string[];
  deniedHosts?: string[];
  interceptAll?: boolean;
}

/** What a request to the applied posture did: refused by Cloudflare, or actually left. */
export type EgressVerdict =
  | { verdict: "denied"; status: number; body: string }
  | { verdict: "egress-attempted"; detail: string }
  | { verdict: "no-interception-installed" };

interface Recorder {
  interceptions: Interception[];
  props: CapturedProps[];
  /** When set, the container API rejects interception registration with this message. */
  failInterceptionWith?: string;
}

/**
 * Stand-in for the container platform API. Only the members the egress-configuration
 * path touches are implemented; the lifecycle members throw, because a container cannot
 * be started without an engine and a silent no-op would let a test believe it had one.
 */
function stubContainerApi(recorder: Recorder): unknown {
  const unavailable = (name: string) => () => {
    throw new Error(`container.${name}() needs a live container engine; unavailable offline`);
  };
  const guard = () => {
    if (recorder.failInterceptionWith) throw new Error(recorder.failInterceptionWith);
  };
  return {
    running: false,
    async interceptAllOutboundHttp(fetcher: Fetcher) {
      guard();
      recorder.interceptions.push({ kind: "all-http", host: "*", fetcher });
    },
    async interceptOutboundHttp(host: string, fetcher: Fetcher) {
      guard();
      recorder.interceptions.push({ kind: "http", host, fetcher });
    },
    async interceptOutboundHttps(host: string, fetcher: Fetcher) {
      guard();
      recorder.interceptions.push({ kind: "https", host, fetcher });
    },
    monitor: () => new Promise(() => {}),
    start: unavailable("start"),
    destroy: unavailable("destroy"),
    signal: unavailable("signal"),
    getTcpPort: unavailable("getTcpPort"),
  };
}

/**
 * Attach the stand-in container API and a props-recording `ctx.exports` to the REAL
 * `DurableObjectState`. Mutation (not a `Proxy`) because workerd rejects a proxied state
 * object at `DurableObjectBase`. `exports.ContainerProxy` still returns the genuine
 * entrypoint fetcher — the wrapper only records the props on the way through.
 */
function instrument(ctx: DurableObjectState, recorder: Recorder): DurableObjectState {
  const mutable = ctx as unknown as Record<string, unknown>;
  mutable.container = stubContainerApi(recorder);
  const realExports = mutable.exports as
    | Record<string, (options: { props: CapturedProps }) => Fetcher>
    | undefined;
  if (realExports === undefined) {
    // Surfaces as a test failure rather than a silent skip: `ctx.exports` is off unless
    // the `enable_ctx_exports` compatibility flag is set, and without it the SDK's
    // `setAllowedHosts`/`setDeniedHosts` throw in production too (see wrangler.toml).
    throw new Error("ctx.exports is undefined: the enable_ctx_exports compat flag is missing");
  }
  mutable.exports = {
    ...realExports,
    ContainerProxy: (options: { props: CapturedProps }) => {
      recorder.props.push(options.props);
      return realExports.ContainerProxy(options);
    },
  };
  return ctx;
}

/** Structural view of the `Container` egress accessors this probe reads. */
interface ContainerEgressState {
  effectiveAllowedHosts: string[] | undefined;
  effectiveDeniedHosts: string[] | undefined;
  shouldInterceptAllOutbound(): boolean;
}

/** The posture an instance is ACTUALLY in, read off the SDK's own accessors. */
export interface AppliedPosture {
  enableInternet: boolean;
  /**
   * The SDK field that decides whether `applyOutboundInterception` registers
   * `interceptOutboundHttps` at all. `@cloudflare/containers@0.3.7` defaults it
   * FALSE, so with the default the provider denylist binds plaintext HTTP only —
   * which is not the protocol any LLM provider speaks. Read off the live
   * instance, so `AgentSandbox { interceptHttps = true }` is what this observes.
   */
  interceptHttps: boolean;
  allowedHosts: string[] | undefined;
  deniedHosts: string[] | undefined;
  interceptAll: boolean;
  interceptions: string[];
  /**
   * A SNAPSHOT of the props records published so far, in publication order.
   * Copied, not aliased — see `appliedPosture`.
   */
  props: CapturedProps[];
}

/**
 * `AgentSandbox` with an observable container platform API. Inherits the production
 * class; overrides no egress field or method.
 */
export class ProbeSandbox extends AgentSandbox {
  private readonly recorder: Recorder;

  constructor(ctx: DurableObjectState, env: unknown) {
    const recorder: Recorder = { interceptions: [], props: [] };
    // `instrument` must run before `super(...)`, which is where `Container` reads
    // `ctx.container` and throws if it is absent.
    super(instrument(ctx, recorder) as never, env as never);
    this.recorder = recorder;
  }

  private get egressState(): ContainerEgressState {
    return this as unknown as ContainerEgressState;
  }

  /**
   * RPC: make the container platform reject the next interception registration, the way
   * a real control plane can. `setDeniedHosts`/`setAllowedHosts` then reject, which is
   * the only realistic way to exercise the Worker's "configuration failed" path.
   */
  async failNextInterception(message: string): Promise<void> {
    this.recorder.failInterceptionWith = message;
  }

  /**
   * RPC: the posture actually applied to this instance.
   *
   * `props` IS A COPY, and has to be. `runInDurableObject` calls this method on the
   * real instance IN THE SAME ISOLATE, so what it hands back is not a structured
   * clone — returning `this.recorder.props` returns the recorder's LIVE array, and
   * a caller holding a "before" posture watches it grow as later starts publish
   * more records. Comparing a before to an after then compares an array to ITSELF:
   * `before.props.length` and `after.props.length` read the same number no matter
   * what happened in between, so the comparison can only ever pin `n === n`. That
   * is what made `container-egress.test.ts`'s failed-sealed-reset test read 3 where
   * it expected 3+1 (issue #471): the two-record tethered start and the one-record
   * failed reset were both being counted through the same array.
   * `interceptions` was already safe because `.map` allocates; `props` was not.
   *
   * A shallow copy is enough, and it is also why `allowedHosts` / `deniedHosts`
   * need none: the SDK builds a fresh props literal per `applyOutboundInterception`
   * call (`containers/dist/lib/container.js:1185-1194`) and never mutates a
   * published one, and `setAllowedHosts` REPLACES `allowedHostsOverride` with
   * `[...hosts]` (`container.js:487`) rather than editing the array a previous
   * reader is holding. Only the recorder's own array grows in place.
   */
  async appliedPosture(): Promise<AppliedPosture> {
    const state = this.egressState;
    return {
      enableInternet: this.enableInternet,
      interceptHttps: this.interceptHttps,
      allowedHosts: state.effectiveAllowedHosts,
      deniedHosts: state.effectiveDeniedHosts,
      interceptAll: state.shouldInterceptAllOutbound(),
      interceptions: this.recorder.interceptions.map((i) => `${i.kind}:${i.host}`),
      props: [...this.recorder.props],
    };
  }

  /**
   * RPC: ask the interceptor the SDK ACTUALLY REGISTERED on this container what it does
   * with `url`. Zero reconstruction — the fetcher is the one `applyOutboundInterception`
   * installed, carrying the props it built from this instance's live state.
   */
  async decideThroughInstalledInterceptor(url: string): Promise<EgressVerdict> {
    const installed = this.recorder.interceptions.at(-1);
    if (!installed) return { verdict: "no-interception-installed" };
    return decide(installed.fetcher, url);
  }

  /**
   * RPC: ask Cloudflare's egress decision function what it does with `url` for an
   * instance in THIS instance's live posture. Used for the sealed posture, where the
   * Worker installs no interceptor at all (by design) and `enableInternet` is the only
   * thing between the container and the internet.
   */
  async decideFromLivePosture(url: string): Promise<EgressVerdict> {
    const state = this.egressState;
    return this.decideWithProps(url, {
      enableInternet: this.enableInternet,
      allowedHosts: state.effectiveAllowedHosts,
      deniedHosts: state.effectiveDeniedHosts,
      interceptAll: state.shouldInterceptAllOutbound(),
    });
  }

  /** RPC: same, for a stated posture — used to pin what the denylist alone still stops. */
  async decideWithProps(url: string, props: CapturedProps): Promise<EgressVerdict> {
    const exports = (this.ctx as unknown as Record<string, unknown>).exports as Record<
      string,
      (options: { props: CapturedProps }) => Fetcher
    >;
    return decide(exports.ContainerProxy({ props }), url);
  }
}

/**
 * Run one request through a `ContainerProxy` fetcher and classify the outcome.
 *
 * A 520 "Origin is disallowed" is Cloudflare's documented refusal. ANYTHING else means
 * the proxy handed the request to the real internet — whether that produced a response
 * or a network error is irrelevant to the property under test, so both collapse to
 * `egress-attempted`.
 */
async function decide(fetcher: Fetcher, url: string): Promise<EgressVerdict> {
  try {
    const response = await fetcher.fetch(url, { method: "GET" });
    const body = (await response.text()).slice(0, 120);
    if (response.status === 520 && body === "Origin is disallowed") {
      return { verdict: "denied", status: response.status, body };
    }
    return { verdict: "egress-attempted", detail: `HTTP ${response.status} ${body}` };
  } catch (err) {
    return { verdict: "egress-attempted", detail: `network error: ${String(err).slice(0, 160)}` };
  }
}
