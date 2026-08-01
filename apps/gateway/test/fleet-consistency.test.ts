/**
 * THE FLEET CONTROL LEDGER — one capability, five Workers, one answer.
 *
 * ## The defect class this file exists to stop
 *
 * A capability implemented in MORE THAN ONE Worker, where a control applied in
 * one Worker does not apply in the others. It has shipped twice, both times on
 * security or money, and both times every per-Worker suite was green because
 * every Worker was individually correct:
 *
 *  1. **The admission bypass (wave 16).** Rust's `finalize_auth` enforced rate
 *     limit / monthly budget / wallet / quota in ONE process. The Worker split
 *     kept it in `apps/gateway` and lost it in `apps/mcp` and
 *     `apps/agent-runtime`, so a credential exhausted on
 *     `/v1/chat/completions` was ADMITTED on `/v1/agent-jobs` and MCP
 *     `tools/call` and spent real money. Exploit: "call the other endpoint."
 *     Closed by wave 16; held closed by `./admission-consistency.test.ts`,
 *     which compares the three refusal TABLES as data. This file is the same
 *     idea widened from one ladder to the whole control surface.
 *  2. **The agent-upstream withdrawal (wave 20).** `DELETE
 *     /admin/v1/agent-upstreams/{id}` withdraws from the gateway's discovery
 *     surface, and `apps/agent-runtime` still resolves its A2A dispatch
 *     catalog from its own deploy-time `AGENT_UPSTREAMS` var. Half closed.
 *
 * **Correctness per Worker does not imply correctness of the fleet.**
 *
 * ## What this file asserts, and why it is a source-text gate
 *
 * The five Workers are SEPARATELY BUNDLED and no app may import another's
 * module graph — that coupling is what `wrangler deploy` would reject and what
 * the repo's package boundaries forbid. So each Worker's source is read as
 * TEXT, with the same `?raw` inlining `./env-var-drift.test.ts` and
 * `./admission-consistency.test.ts` already use, and the five answers are
 * compared as DATA.
 *
 * Every probe runs against COMMENT-STRIPPED source. That is load-bearing, not
 * tidiness: `apps/agent-runtime/src/middleware/auth.ts` carries a prose
 * paragraph claiming "the lifecycle-suspension ladder (`tenancy_suspended`)"
 * was "already here", and it is not — the durable authority is never read on
 * that Worker. A probe that scanned comments would have believed the
 * paragraph. See {@link stripComments}.
 *
 * ## The ledger is a RATCHET, deliberately
 *
 * The recorded tables below are the MEASURED state of the fleet, not the
 * desired one. Four divergences are open today and each is recorded with its
 * finding id from `docs/rewrite/FLEET-CONSISTENCY.md`. That means this file
 * goes RED in BOTH directions:
 *
 *  * a NEW divergence — a control that stops being enforced on one Worker, or
 *    a Worker that starts resolving a shared control from a private source —
 *    is RED, which is the property the two shipped defects needed;
 *  * a divergence being CLOSED is also RED, which forces the ledger and
 *    `FLEET-CONSISTENCY.md` to be updated in the same commit as the fix. A
 *    finding without a gate rots back within two waves; a gate whose ledger can
 *    drift away from the code rots the same way, one level up.
 *
 * Nothing here weakens or replaces a behavioural suite. Each Worker's own
 * refusals are still driven over `SELF` by its own tests; this file asserts
 * the one property none of those can see.
 */
import { describe, expect, it } from "vitest";
import contractDocument from "../../../docs/openapi/runtime-api-contract.json";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/** Every `src/**` TypeScript module of every deployed Worker, as text. */
const APP_SOURCES = {
  gateway: import.meta.glob("../src/**/*.ts", { query: "?raw", import: "default", eager: true }),
  "control-plane": import.meta.glob("../../control-plane/src/**/*.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
  mcp: import.meta.glob("../../mcp/src/**/*.ts", { query: "?raw", import: "default", eager: true }),
  "agent-runtime": import.meta.glob("../../agent-runtime/src/**/*.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
  telemetry: import.meta.glob("../../telemetry/src/**/*.ts", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
} as const;

/** The three data-plane Workers' committed deploy config, as text. */
const APP_TOML = {
  gateway: import.meta.glob("../wrangler.toml", { query: "?raw", import: "default", eager: true }),
  mcp: import.meta.glob("../../mcp/wrangler.toml", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
  "agent-runtime": import.meta.glob("../../agent-runtime/wrangler.toml", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
} as const;

type App = keyof typeof APP_SOURCES;

/** Every Worker in the fleet, in the order the ledger tables list them. */
const FLEET: readonly App[] = ["gateway", "control-plane", "mcp", "agent-runtime", "telemetry"];

/**
 * The Workers that RESOLVE A TENANT CREDENTIAL and then serve tenant-scoped
 * work off it. `telemetry` is deliberately absent: it authenticates one
 * operator-issued collector token and owns no tenant state, so a control that
 * restricts a TENANT has nothing to apply to there. Saying so is the honest
 * half of this audit — a consistency requirement invented between Workers that
 * never shared a concern is noise that trains readers to skip the file.
 */
const CREDENTIAL_WORKERS: readonly App[] = ["gateway", "control-plane", "mcp", "agent-runtime"];

/**
 * The Workers that admit SPEND-PRODUCING work off a tenant credential — the
 * three the wave-16 admission ladder had to be ported onto, and the three any
 * "stop spending" control has to reach to mean what an operator thinks it
 * means.
 */
const SPEND_WORKERS: readonly App[] = ["gateway", "mcp", "agent-runtime"];

// ---------------------------------------------------------------------------
// Comment-stripped source
// ---------------------------------------------------------------------------

/**
 * Remove block comments and whole-line `//` / ` *` comments.
 *
 * Deliberately conservative: it never touches the tail of a line that has code
 * on it, so a `"https://…"` inside a string literal survives intact. The cost
 * is that a trailing `// …` comment is kept; the benefit is that no probe can
 * be turned into a false ABSENT by a stripper that ate a string. Every probe
 * below therefore matches on a QUOTED token or an SQL fragment, which prose
 * does not contain verbatim — and {@link describe} "the scan is real" asserts
 * a canary hit on each Worker so a stripper regression is RED here rather than
 * silently reporting an all-absent fleet.
 */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((line) => !/^\s*(\/\/|\*)/.test(line))
    .join("\n");
}

/** TOML: drop `#` comment lines, leaving only the stanzas that DEPLOY. */
function stripTomlComments(source: string): string {
  return source
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
}

function moduleTexts(app: App): readonly (readonly [string, string])[] {
  const glob = APP_SOURCES[app];
  const entries = Object.entries(glob);
  if (entries.length === 0) throw new Error(`fleet-consistency: no sources globbed for ${app}`);
  return entries.map(([path, text]) => {
    if (typeof text !== "string" || text.length === 0) {
      throw new Error(`fleet-consistency: ${path} inlined empty`);
    }
    return [path, stripComments(text)] as const;
  });
}

const CODE: Record<App, readonly (readonly [string, string])[]> = Object.fromEntries(
  FLEET.map((app) => [app, moduleTexts(app)]),
) as Record<App, readonly (readonly [string, string])[]>;

function tomlOf(app: keyof typeof APP_TOML): { readonly live: string; readonly full: string } {
  const values = Object.values(APP_TOML[app]);
  if (values.length !== 1 || typeof values[0] !== "string" || values[0].length === 0) {
    throw new Error(`fleet-consistency: expected one wrangler.toml for ${app}`);
  }
  const full = values[0] as string;
  return { live: stripTomlComments(full), full };
}

/** The Workers whose comment-stripped code matches `probe`, in fleet order. */
function appsMatching(probe: RegExp): App[] {
  return FLEET.filter((app) => CODE[app].some(([, code]) => probe.test(code)));
}

/** The files on one Worker that match `probe` — used to make a failure legible. */
function filesMatching(app: App, probe: RegExp): string[] {
  return CODE[app].filter(([, code]) => probe.test(code)).map(([path]) => path);
}

// ---------------------------------------------------------------------------
// The probes. Each names a CONTROL and the text only its real implementation
// can contain: a quoted refusal code, an SQL fragment naming the authority
// table, or a binding read. Never a word that appears in prose.
// ---------------------------------------------------------------------------

const PROBE = {
  /** Emits `403 tenancy_suspended` — the tenant-suspension refusal. */
  emitsTenancySuspended: /"tenancy_suspended"/,
  /** Reads the DURABLE lifecycle authority (`tenants.status`). */
  readsLifecycleAuthority: /status\s+FROM\s+tenants/i,
  /** Emits `503 node_draining` — the operator drain refusal. */
  emitsNodeDraining: /"node_draining"/,
  /** Reads the deploy-time drain var. */
  readsDrainVar: /GATEWAY_DRAIN/,
  /** Reads/writes the DURABLE drain document the admin API mutates. */
  ownsDurableDrainState: /"runtime-state"/,
  /** Reads the durable, control-plane-managed guardrail policy tables. */
  readsDurableGuardrailPolicy: /guardrail_policy_revisions|guardrail_policy_bindings/,
  /** Resolves guardrail policy from a `FG_DEV_*` deploy-time var instead. */
  readsGuardrailDevVar: /FG_DEV_(?:MCP|A2A)_GUARDRAILS/,
  /** Resolves the A2A agent-upstream catalog from the durable admin documents. */
  readsDurableAgentUpstreams: /AGENT_UPSTREAM_COLLECTION/,
  /** Resolves the A2A agent-upstream catalog from a deploy-time var. */
  readsAgentUpstreamVar: /AGENT_UPSTREAMS/,
  /** Charges the shared RPM window through the `RATE_LIMIT` DO binding. */
  readsRateLimitBinding: /\.RATE_LIMIT\b/,
  /** Evaluates the operator `[[policies]]` deny table. */
  evaluatesOperatorDenyRules: /BasicPolicyEngine/,
  /** Actually CONSULTS an RBAC authorizer (as opposed to parsing the field). */
  consultsRbacAuthorizer: /\.authorize\(auth/,
  /** Parses `rbac_action` off the shared contract table. */
  parsesRbacAction: /rbac_action/,
} as const;

// ---------------------------------------------------------------------------

describe("the scan is real", () => {
  it("globbed every Worker's source", () => {
    // Non-vacuity, part 1. A glob that silently resolved to nothing would make
    // every `appsMatching` below return `[]`, and several of the recorded
    // tables are `[]` — so the whole file could pass while reading no code.
    const counts = Object.fromEntries(FLEET.map((app) => [app, CODE[app].length]));
    expect(counts).toEqual({
      gateway: expect.any(Number),
      "control-plane": expect.any(Number),
      mcp: expect.any(Number),
      "agent-runtime": expect.any(Number),
      telemetry: expect.any(Number),
    });
    for (const app of FLEET) {
      expect(CODE[app].length, `${app} module count`).toBeGreaterThan(9);
    }
  });

  it("still finds a known token on every Worker after comment stripping", () => {
    // Non-vacuity, part 2 — the one that catches a `stripComments` regression.
    // Each canary is a quoted string in real, executed code on that Worker; if
    // the stripper ever eats string literals these go RED instead of quietly
    // turning every probe into ABSENT.
    const CANARY: Record<App, RegExp> = {
      gateway: /"quota_scope_disabled"/,
      "control-plane": /"tenancy_suspended"/,
      mcp: /"quota_scope_disabled"/,
      "agent-runtime": /"quota_scope_disabled"/,
      telemetry: /"unauthorized"|"invalid_request"|otlp/i,
    };
    for (const app of FLEET) {
      expect(
        CODE[app].some(([, code]) => CANARY[app].test(code)),
        `${app} canary token vanished — stripComments is eating code`,
      ).toBe(true);
    }
  });

  it("does NOT see a claim that only a comment makes", () => {
    // The measurement that justifies stripping at all. `apps/agent-runtime`'s
    // auth middleware asserts in prose that the lifecycle-suspension ladder is
    // "already here"; the durable authority read is nowhere on that Worker.
    // Reading the file UNSTRIPPED finds the claim; reading it stripped does
    // not. If someone deletes that paragraph this assertion is RED and should
    // simply be dropped — but while the paragraph stands, this is the proof
    // that the probes are not reading documentation.
    const rawAuth = Object.entries(APP_SOURCES["agent-runtime"]).find(([path]) =>
      path.endsWith("middleware/auth.ts"),
    );
    expect(rawAuth, "agent-runtime middleware/auth.ts").toBeDefined();
    const [, raw] = rawAuth as [string, string];
    expect(/lifecycle-suspension/.test(raw), "the prose claim").toBe(true);
    expect(/lifecycle-suspension/.test(stripComments(raw)), "after stripping").toBe(false);
  });
});

// ---------------------------------------------------------------------------
// FC-1 — the operator drain
// ---------------------------------------------------------------------------

describe("FC-1 the operator drain is applied in one Worker and enforced in another", () => {
  /**
   * `POST /admin/v1/drain {"draining": true}` answers
   * `200 {"object":"drain","draining":true}` and writes the durable
   * `runtime-state/drain` document. NOTHING on the data plane reads that
   * document: `apps/gateway` refuses the five spend-producing operations off
   * the deploy-time `GATEWAY_DRAIN` var, and `apps/mcp` /
   * `apps/agent-runtime` have no drain gate on either source.
   *
   * Recorded as MEASURED. When the join lands — the gateway reading the
   * durable document, and the two other spend Workers honouring the same
   * answer — every table here changes and this block is RED until the ledger
   * and `FLEET-CONSISTENCY.md` are updated with it.
   */
  it("only the gateway can refuse with node_draining", () => {
    expect(appsMatching(PROBE.emitsNodeDraining)).toEqual(["gateway"]);
  });

  it("only the gateway reads the drain VAR", () => {
    expect(appsMatching(PROBE.readsDrainVar)).toEqual(["gateway"]);
  });

  it("only the control plane owns the drain DOCUMENT the admin API writes", () => {
    expect(appsMatching(PROBE.ownsDurableDrainState)).toEqual(["control-plane"]);
  });

  it("no Worker joins the two, which is the defect", () => {
    // The sharp statement: the set of Workers that both hold the durable drain
    // state and enforce a drain refusal is EMPTY, so the operator action and
    // the enforcement point share no source of truth. Closing FC-1 makes this
    // set non-empty and turns the assertion RED.
    const joined = FLEET.filter(
      (app) =>
        CODE[app].some(([, code]) => PROBE.ownsDurableDrainState.test(code)) &&
        CODE[app].some(([, code]) => PROBE.emitsNodeDraining.test(code)),
    );
    expect(joined, "FC-1: a Worker now joins drain state to drain enforcement").toEqual([]);
  });

  it("two of the three spend Workers have no drain gate at all", () => {
    const withoutDrain = SPEND_WORKERS.filter(
      (app) => !CODE[app].some(([, code]) => PROBE.emitsNodeDraining.test(code)),
    );
    expect(withoutDrain).toEqual(["mcp", "agent-runtime"]);
  });

  it.todo(
    "FC-1 FIX: apps/gateway/src/routes/readiness.ts::drainStatus reads the durable " +
      "`runtime-state/drain` document from CONTROL_DB (var as the fallback, exactly as " +
      "routes/agent-upstreams.ts resolves the upstream registry), and apps/mcp + " +
      "apps/agent-runtime refuse spend-producing operations with the same 503 node_draining",
  );
});

// ---------------------------------------------------------------------------
// FC-2 — tenant suspension
// ---------------------------------------------------------------------------

describe("FC-2 tenant suspension does not reach every Worker that spends on the credential", () => {
  /**
   * The wave-16 defect wearing a different control. `apps/gateway` resolves
   * the tenant → project → workspace lifecycle chain out of `tenants.status`
   * on the CONTROL database and answers `403 tenancy_suspended`;
   * `apps/control-plane` has its own durable gate. `apps/agent-runtime` can
   * NAME the refusal but only its in-memory `FG_DEV_API_KEYS` table produces
   * it — `d1ApiKeyPort`, the port a real deployment uses, returns exactly
   * `unknown` / `key_suspended` / `resolved` / `unavailable` and never
   * `tenancy_suspended`. `apps/mcp` has no lifecycle check in any posture.
   */
  it("records which Workers emit the suspension refusal", () => {
    expect(appsMatching(PROBE.emitsTenancySuspended)).toEqual([
      "gateway",
      "control-plane",
      "agent-runtime",
    ]);
  });

  it("only the gateway reads the DURABLE lifecycle authority", () => {
    // `tenants.status`. `apps/mcp` and `apps/agent-runtime` both join `tenants`
    // for the PLAN lookup in their quota chain, so the probe is the status
    // column read specifically — joining a table is not consulting a control.
    expect(appsMatching(PROBE.readsLifecycleAuthority)).toEqual(["gateway"]);
    expect(filesMatching("gateway", PROBE.readsLifecycleAuthority)).toEqual([
      expect.stringContaining("adapters.ts"),
    ]);
  });

  it("names the spend Workers a suspension cannot stop", () => {
    // The exploit set. A tenant suspended by the operator keeps its still-valid
    // credential and calls one of these instead.
    const cannotBeStopped = SPEND_WORKERS.filter(
      (app) => !CODE[app].some(([, code]) => PROBE.readsLifecycleAuthority.test(code)),
    );
    expect(cannotBeStopped, "FC-2 exploit set").toEqual(["mcp", "agent-runtime"]);
  });

  it("every credential Worker that enforces the admission ladder is checked here", () => {
    // Guards the framing rather than the finding: if a sixth Worker starts
    // resolving tenant credentials it joins CREDENTIAL_WORKERS and must be
    // classified above rather than silently omitted.
    const ladderWorkers = FLEET.filter((app) =>
      CODE[app].some(([, code]) => /"quota_scope_disabled"/.test(code)),
    );
    for (const app of ladderWorkers) {
      expect(
        CREDENTIAL_WORKERS,
        `${app} enforces admission but is not a credential Worker`,
      ).toContain(app);
    }
  });

  it.todo(
    "FC-2 FIX: apps/mcp and apps/agent-runtime consult the same tenant lifecycle authority " +
      "the gateway does (tenants.status on the CONTROL database, ancestors included) BEFORE " +
      "the admission ladder, answering the identical 403 tenancy_suspended — a suspended " +
      "tenant must not reach quota/wallet resolution, which is where spend is authorized",
  );
});

// ---------------------------------------------------------------------------
// FC-3 — guardrail policy
// ---------------------------------------------------------------------------

describe("FC-3 an activated guardrail policy binds one Worker and no other", () => {
  /**
   * `POST /admin/v1/guardrail-policies/{policy_id}/activate` writes
   * `guardrail_policy_bindings` and the gateway merges those rows into its
   * screening source. `apps/mcp` screens MCP tool arguments and tool results
   * from `FG_DEV_MCP_GUARDRAILS` and `apps/agent-runtime` screens A2A messages
   * from `FG_DEV_A2A_GUARDRAILS` — two deploy-time vars, one of them committed
   * EMPTY, both documented in their own source as DEV/TEST ONLY.
   */
  it("only gateway and control-plane touch the durable policy tables", () => {
    expect(appsMatching(PROBE.readsDurableGuardrailPolicy)).toEqual(["gateway", "control-plane"]);
  });

  it("the two other screening Workers read a deploy-time dev var instead", () => {
    expect(appsMatching(PROBE.readsGuardrailDevVar)).toEqual(["mcp", "agent-runtime"]);
  });

  it("the two sets are disjoint, so no activated revision reaches MCP or A2A", () => {
    const durable = new Set(appsMatching(PROBE.readsDurableGuardrailPolicy));
    const varOnly = appsMatching(PROBE.readsGuardrailDevVar);
    expect(
      varOnly.filter((app) => durable.has(app)),
      "FC-3 overlap",
    ).toEqual([]);
  });

  it.todo(
    "FC-3 FIX: apps/mcp and apps/agent-runtime resolve their detector policy from the same " +
      "guardrail_policy_revisions + guardrail_policy_bindings rows the gateway merges, keeping " +
      "the var as the no-control-database fallback",
  );
});

// ---------------------------------------------------------------------------
// FC-4 — the agent-upstream catalog (wave 20, half closed)
// ---------------------------------------------------------------------------

describe("FC-4 one withdrawal reaches BOTH agent-upstream doors", () => {
  /**
   * The wave-20 finding, and the shape of its fix — kept as a FORWARD gate now
   * that both legs are in.
   *
   * Rust held ONE `[[agent_upstreams]]` table and every surface that could
   * reach an upstream read it, so `DELETE /admin/v1/agent-upstreams/{id}`
   * closed every door at once. Here the doors are in different Workers:
   * `apps/gateway` serves DISCOVERY (`GET /.well-known/agent.json`) and
   * `apps/agent-runtime` serves DISPATCH (`POST /v1/agents/{name}` and the
   * `message:*` verbs). Wave 20 gave the gateway a durable read and left the
   * agent runtime on its deploy-time `AGENT_UPSTREAMS` var, so an operator who
   * withdrew a COMPROMISED upstream saw it gone from discovery and it stayed
   * reachable for dispatch.
   *
   * Both now read the same `control_plane_resources` rows. These assertions
   * are what stops either one from drifting back to a private catalog — the
   * regression would be invisible to both Workers' own suites, which is how it
   * shipped the first time.
   */
  it("both reach paths resolve from the durable admin documents", () => {
    expect(appsMatching(PROBE.readsDurableAgentUpstreams)).toEqual(["gateway", "agent-runtime"]);
  });

  it("they name the SAME collection and the SAME table", () => {
    // Two Workers that each re-derived the constant would drift silently, and
    // the drift would be "the withdrawal did not apply here" rather than a
    // test failure. Compared as text because no app may import the other.
    for (const app of ["gateway", "agent-runtime"] as const) {
      const hits = CODE[app].filter(([, code]) => PROBE.readsDurableAgentUpstreams.test(code));
      expect(hits.length, `${app} upstream registry module`).toBeGreaterThan(0);
      const joined = hits.map(([, code]) => code).join("\n");
      expect(joined, `${app} collection constant`).toContain(
        'AGENT_UPSTREAM_COLLECTION = "agent-upstreams"',
      );
      expect(joined, `${app} resource table`).toContain('"control_plane_resources"');
    }
  });

  it("the agent runtime MOUNTS the durable port in its composition root", () => {
    // A registry module that exists but is not wired is the repo's dominant
    // defect. `resolveDeps` must hand `upstreams` the env-resolving port, not
    // the in-memory one directly.
    const ports = CODE["agent-runtime"].find(([path]) => path.endsWith("/src/ports.ts"));
    expect(ports, "agent-runtime src/ports.ts").toBeDefined();
    const [, code] = ports as [string, string];
    expect(code, "resolveDeps no longer mounts the durable upstream port").toMatch(
      /upstreams:\s*agentUpstreamPortFromEnv\(/,
    );
  });

  it("the var survives only as the no-control-database fallback, on both", () => {
    expect(appsMatching(PROBE.readsAgentUpstreamVar)).toEqual(["gateway", "agent-runtime"]);
  });
});

// ---------------------------------------------------------------------------
// FC-5 — the SHARED RPM counter must stay one namespace
// ---------------------------------------------------------------------------

describe("FC-5 the RPM window is ONE counter across the three spend Workers", () => {
  /**
   * This one is GREEN today and is a trap gate, not a finding.
   *
   * `RateLimiterDurableObject` is DEFINED by `apps/gateway` and BOUND by
   * `apps/mcp` and `apps/agent-runtime` through `script_name =
   * "ferrogate-gateway"`, so `idFromName("key:<id>")` addresses the same
   * instance from all three and a credential at 60 rpm is charged one window
   * across `/v1/chat/completions`, `tools/call` and `/v1/agent-jobs`.
   *
   * Neither of the two binding stanzas can be committed live: workerd refuses
   * to start on a cross-script DO binding under `wrangler dev --local` and
   * `@cloudflare/vitest-pool-workers`, so both are written out and commented
   * for deploy time. That leaves an obvious and catastrophic "fix" available
   * to the next person who meets the boot error: define a private
   * `RateLimiterDurableObject` in the app that fails. It compiles, deploys,
   * passes every suite — and hands that Worker its own full RPM quota, which
   * is the wave-16 bypass restored quietly. THIS is the assertion that stops
   * it.
   */
  it("all three spend Workers read the same binding name", () => {
    expect(appsMatching(PROBE.readsRateLimitBinding)).toEqual(SPEND_WORKERS);
  });

  it("only apps/gateway DEFINES the limiter class", () => {
    const definers = (["gateway", "mcp", "agent-runtime"] as const).filter((app) =>
      /new_(?:sqlite_)?classes\s*=\s*\[[^\]]*"RateLimiterDurableObject"/.test(tomlOf(app).live),
    );
    expect(definers, "a second definer is a second, private counter namespace").toEqual([
      "gateway",
    ]);
  });

  it("neither borrower declares the class in its LIVE config", () => {
    // A live `[[durable_objects.bindings]]` naming the class WITHOUT
    // `script_name` is the same private namespace by another route.
    for (const app of ["mcp", "agent-runtime"] as const) {
      expect(
        /RateLimiterDurableObject/.test(tomlOf(app).live),
        `${app} wrangler.toml declares the limiter class live`,
      ).toBe(false);
    }
  });

  it("both borrowers keep the deploy-time stanza, pointed at the gateway script", () => {
    // The stanza is the deploy instruction; deleting it is how the shared
    // counter silently stops being shared at the next deploy.
    for (const app of ["mcp", "agent-runtime"] as const) {
      const { full } = tomlOf(app);
      expect(full, `${app} lost the RATE_LIMIT deploy stanza`).toContain(
        'class_name = "RateLimiterDurableObject"',
      );
      expect(full, `${app} lost script_name — a private namespace at deploy`).toContain(
        'script_name = "ferrogate-gateway"',
      );
      expect(full, `${app} lost the RATE_LIMIT binding name`).toContain('name = "RATE_LIMIT"');
    }
  });

  it("the gateway does NOT borrow from anyone", () => {
    expect(/script_name\s*=/.test(tomlOf("gateway").live)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// FC-6 — controls that are legitimately single-Worker
// ---------------------------------------------------------------------------

describe("FC-6 single-Worker controls, pinned so they stay single-Worker or get classified", () => {
  /**
   * Not every capability that lives in one Worker is a finding, and calling
   * one would be manufacturing. These three are recorded as SINGLE-WORKER BY
   * DESIGN, with the reason. The assertions exist so that the day a second
   * Worker grows one, the divergence question gets ASKED — which is the step
   * that was skipped both times a bypass shipped.
   */
  it("the pre-auth network gate is the gateway's alone (it is the only public ingress)", () => {
    expect(appsMatching(/GATEWAY_IP_ALLOWLIST/)).toEqual(["gateway"]);
  });

  it("the response cache is the gateway's alone (nothing else serves a cacheable body)", () => {
    expect(appsMatching(/GATEWAY_CACHE_ENABLED/)).toEqual(["gateway"]);
  });

  it("the operator deny table is the gateway's alone — with a caveat, see below", () => {
    // Rust evaluated `policy_engine.evaluate(request, model, provider)` from
    // `chat.rs` only, so a MODEL/PROVIDER-scoped deny rule being inference-only
    // is parity, not drift. The caveat is real though and is recorded as an
    // OPEN QUESTION in FLEET-CONSISTENCY.md rather than asserted as a defect:
    // `expandPolicyRule` treats an empty models/providers list as a WILDCARD,
    // so `[[policies]] organization_ids = ["t"] effect = "deny"` reads to an
    // operator as "deny tenant t everything" and stops nothing on MCP or A2A.
    expect(appsMatching(PROBE.evaluatesOperatorDenyRules)).toEqual(["gateway"]);
  });
});

// ---------------------------------------------------------------------------
// FC-7 — a control that is PARSED everywhere and enforced in two places
// ---------------------------------------------------------------------------

describe("FC-7 rbac_action is carried by four Workers and consulted by two", () => {
  /**
   * `apps/mcp` and `apps/agent-runtime` both parse `rbac_action` off the shared
   * contract table into their `ApiOperation` and never read it again. That is
   * harmless TODAY and only today: every operation in
   * `docs/openapi/runtime-api-contract.json` carrying an `rbac_action` is an
   * `/admin/v1/guardrail-*` or `/admin/v1/investigations` path, which those two
   * Workers do not serve. The day one lands on a data-plane path it is silently
   * unenforced on two of five Workers — the same shape as both shipped
   * defects, pre-armed. This turns that day RED.
   */
  const operations = (contractDocument as { operations: readonly Record<string, unknown>[] })
    .operations;

  it("read a real contract table", () => {
    expect(operations.length).toBeGreaterThan(200);
  });

  it("only gateway and control-plane consult an authorizer", () => {
    expect(appsMatching(PROBE.consultsRbacAuthorizer)).toEqual(["gateway", "control-plane"]);
  });

  it("four Workers parse the field", () => {
    expect(appsMatching(PROBE.parsesRbacAction)).toEqual([
      "gateway",
      "control-plane",
      "mcp",
      "agent-runtime",
    ]);
  });

  it("every rbac-guarded operation is on an admin path the two enforcers serve", () => {
    const guarded = operations.filter((op) => (op as { rbac_action?: string }).rbac_action);
    expect(
      guarded.length,
      "no rbac_action operations found — the probe went stale",
    ).toBeGreaterThan(0);
    const offPath = guarded
      .map((op) => String((op as { path?: string }).path ?? ""))
      .filter((path) => !path.startsWith("/admin/v1/"));
    expect(
      offPath,
      "an rbac_action landed on a non-admin path; apps/mcp and apps/agent-runtime parse the " +
        "field and never consult an authorizer, so it is unenforced there",
    ).toEqual([]);
  });
});
