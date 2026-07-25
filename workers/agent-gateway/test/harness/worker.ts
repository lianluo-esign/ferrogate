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
//   `enableInternet`, `setAllowedHosts`, `setDeniedHosts`, `effectiveAllowedHosts`,
//   `applyOutboundInterception` — is the real inherited one, so flipping
//   `AgentSandbox { enableInternet = false }` flips what these probes observe.
//
//   The stand-in records the `Fetcher` the SDK registers as the container's outbound
//   interceptor, and the props the SDK builds for it. That fetcher is a REAL
//   `ContainerProxy` entrypoint — Cloudflare's own egress decision function — so the
//   suite can ask what the applied posture actually DOES with a request instead of
//   asserting on the JSON the Worker sent.

export * from "../../src/index";
export { default } from "../../src/index";
// Re-exported EXPLICITLY (not via `export *`): workerd only lists an entrypoint in
// `ctx.exports` when the entry module names it, and `applyOutboundInterception` resolves
// the interceptor through `ctx.exports.ContainerProxy`. Sourcing it from `../../src/index`
// rather than from the SDK also means deleting the production re-export breaks this build.
export { ContainerProxy } from "../../src/index";

import { AgentSandbox } from "../../src/index";

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
  allowedHosts: string[] | undefined;
  deniedHosts: string[] | undefined;
  interceptAll: boolean;
  interceptions: string[];
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

  /** RPC: the posture actually applied to this instance. */
  async appliedPosture(): Promise<AppliedPosture> {
    const state = this.egressState;
    return {
      enableInternet: this.enableInternet,
      allowedHosts: state.effectiveAllowedHosts,
      deniedHosts: state.effectiveDeniedHosts,
      interceptAll: state.shouldInterceptAllOutbound(),
      interceptions: this.recorder.interceptions.map((i) => `${i.kind}:${i.host}`),
      props: this.recorder.props,
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
