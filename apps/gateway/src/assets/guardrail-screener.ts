/**
 * Guardrail screening of PUBLISHED assets — issue #740.
 *
 * `apps/gateway/src/guardrails/` served the inference path only, and
 * `grep -rn guardrail apps/gateway/src/assets/` returned three comments and
 * ZERO call sites. So a tenant could publish an `mcp_manifest`, a
 * `config_file`, a `skill_bundle` or a page of prompt-injection text, and an
 * agent on a different tenant could pull it through `resources/read` or
 * `builtin.fetch_asset`, with no policy ever evaluated. That is the injection
 * path #688 closed on the inference surface, left open on the asset surface.
 *
 * ============================================================================
 * AN ASSET IS NOT A CHAT TURN — what is screened, and what honestly is not
 * ============================================================================
 *
 * #688's four hooks are about text a model will read AS INSTRUCTIONS. A
 * published artifact is a different thing, and the useful question — the one
 * #703 asked about opaque audio, where the honest answer was "the upload is
 * opaque, but its TRANSCRIPT is not" — is **which asset types have a text
 * surface a detector can actually read**.
 *
 * SCREENED, because the whole object is text or its archive members are
 * expanded into text surfaces:
 *  - `mcp_manifest` — a JSON document, and the most dangerous one on this
 *    surface: the consuming agent's MCP client reads it and acts on it.
 *  - `config_file` — JSON / YAML / TOML / plain text.
 *  - `skill_bundle` pushed as `text/plain` or `text/markdown` — a `SKILL.md` is
 *    literally a page of instructions for somebody else's agent.
 *  - `skill_bundle` pushed as an archive — expanded under the same bounded
 *    tar/zip parser, with valid UTF-8 text members screened per file and
 *    opaque members excluded from the detector surface.
 *  - `static_site` — screened PER FILE after #736's expansion, over the
 *    text-bearing files only. See {@link GuardrailAssetScreener.screenBundleFiles}.
 *
 * NOT SCREENED, stated rather than papered over — and, crucially, never
 * recorded as a PASS:
 *  - `cli_tool` and any `application/octet-stream` push. A compiled binary has
 *    no text surface; lossily decoding it into replacement characters and
 *    handing that to a keyword detector would produce an evidence row about
 *    nothing. `application/octet-stream` is the "I do not know what this is"
 *    content type and is treated as exactly that.
 *  - images and fonts inside a `static_site` bundle — with ONE exception,
 *    `image/svg+xml`, which is an XML DOCUMENT that browsers execute script
 *    inside, so it is screened as text despite the `image/` prefix.
 *  - binary members (including images and fonts) inside a `skill_bundle`
 *    archive. They count toward archive limits but contribute no detector
 *    segment; a valid extensionless UTF-8 member is treated as text.
 *
 * ============================================================================
 * PUBLISH vs FETCH
 * ============================================================================
 *
 * Screening happens at PUBLISH. The fetch side enforces the publish decision
 * and does NOT run detectors again, and that is a decision rather than an
 * omission:
 *
 *  - every read path already withholds a non-`visible` row, at ONE gate:
 *    `#resolveArtifact` filters on `isDownloadable` (so the inline pull, the
 *    `?path=` bundle-file projection and `/sites/*` are covered by the same
 *    line), `downloadUrl` refuses to sign a URL for one, and `apps/mcp`'s
 *    reader answers `not_found` for an undownloadable asset. So the case the
 *    issue names — "publish could not decide" — is a `pending_scan` row, and a
 *    `pending_scan` row is ALREADY unfetchable on all three paths. Refusing to
 *    serve is strictly stronger than screening at fetch, so adding a second
 *    detector pass there would buy nothing and cost the ETag/304/Range path
 *    O(bytes) of detector work per read.
 *  - a verdict that is re-decided per read is also not auditable: the same
 *    object would be readable or not depending on whether a detector backend
 *    answered in time, and no evidence row would explain which.
 *
 * What that leaves open, honestly: an asset admitted `visible` under one
 * policy is NOT re-screened when the policy changes. The remedy is the
 * quarantine surface #743 added, driven by an operator; this module does not
 * pretend to cover it. And a presigned download URL already issued outlives
 * any later quarantine for its TTL, because those bytes leave R2 directly and
 * the gateway is never asked again.
 *
 * ============================================================================
 * NOT A DENIAL OF SERVICE ON OURSELVES
 * ============================================================================
 *
 * {@link DEFAULT_ASSET_GUARDRAIL_MAX_SCREEN_BYTES} bounds what is DECODED and
 * handed to a detector, and it is applied the #703 way — the decision is taken
 * from a size that is already known, with NO READ AT ALL above it
 * (`inference/audio-objects.ts` refuses from `stored_assets.size_bytes` before
 * touching the bucket). Above the ceiling the outcome is `undecidable`, never
 * `clean`: under `block` that withholds. That is the same resolution
 * `content-gate.ts` already reached for an unbufferable `mcp_manifest` —
 * *"the stdio check must not become optional above a size threshold, because
 * 'too big to check' is exactly the shape an attacker would pad a manifest
 * into"*.
 *
 * ============================================================================
 * EVIDENCE WITHOUT STORING CONTENT
 * ============================================================================
 *
 * The verdict comes from {@link GuardrailEngine}, so evidence lands in the
 * SAME `guardrail_evaluations` / `guardrail_check_evaluations` rows the
 * inference path writes, with the same invariants #680 established: a keyed
 * `hmac-sha256:` input fingerprint, per-category finding counts, and
 * `redactedExcerpt` masks. No byte of the asset crosses that boundary. The
 * asset-side audit line adds only the rule id, the effect and the bundle-
 * relative PATH of the offending file — never its text.
 */
import {
  type ContentSegment,
  type GuardrailEnvelope,
  contentFingerprint,
} from "@ferrogate/guardrails";
import { GUARDRAIL_POLICY_VAR, guardrailDepsFromEnv } from "../guardrails/config.js";
import { D1GuardrailPolicyStore } from "../guardrails/d1.js";
import { GuardrailEngine } from "../guardrails/engine.js";
import type { GuardrailEvidenceSink, GuardrailMatch } from "../guardrails/ports.js";
import {
  type AssetBundleScreeningRequest,
  type AssetBundleScreeningVerdict,
  type AssetScreener,
  type AssetScreeningRejection,
  type AssetScreeningRequest,
  type AssetScreeningVerdict,
  type AssetVisibility,
  isScreeningRejection,
  strictestVisibility,
} from "./ports.js";

// ---------------------------------------------------------------------------
// Per-tenant, per-asset-type policy
// ---------------------------------------------------------------------------

/**
 * What a guardrail finding DOES to a publish, per asset type.
 *
 *  - `block` — the version is `quarantined`: stored, withheld from every read
 *    surface, and listed on `GET /v1/assets/withheld` with the evidence. It is
 *    NOT a `422`, because the issue asks for the existing quarantine lifecycle
 *    and because a refusal loses the artifact an operator has to look at.
 *  - `flag` — the version publishes, and the finding is on the push audit line
 *    and in the guardrail evidence tables. A monitoring posture.
 *  - `off` — no detector runs for this asset type and no evidence row is
 *    written. Distinct from `flag` on purpose: an evidence row for a check
 *    that did not run is the "control that read nothing" this codebase keeps
 *    catching.
 */
export type AssetGuardrailMode = "off" | "flag" | "block";

/**
 * The shipped defaults.
 *
 * `mcp_manifest` and `skill_bundle` are DEFAULT-ON at `block` because those two
 * EXECUTE ON THE CONSUMER: a manifest drives somebody else's MCP client, a
 * skill is instructions somebody else's agent will follow. `config_file` and
 * `static_site` default to `flag` — they are read, not executed, and a site
 * silently disappearing because a marketing page tripped a keyword rule is a
 * worse first experience than a flagged one an operator can then escalate with
 * one var. Every asset type absent from this table is `off`, which is the
 * correct reading of "no text surface anybody asked us to police".
 */
export const DEFAULT_ASSET_GUARDRAIL_MODES: Readonly<Record<string, AssetGuardrailMode>> = {
  mcp_manifest: "block",
  skill_bundle: "block",
  config_file: "flag",
  static_site: "flag",
};

/** Worker var holding the per-tenant override table. */
export const ASSET_GUARDRAIL_MODES_VAR = "ASSET_GUARDRAIL_MODES";
/** Worker var holding the decode/detector byte ceiling. */
export const ASSET_GUARDRAIL_MAX_SCREEN_BYTES_VAR = "ASSET_GUARDRAIL_MAX_SCREEN_BYTES";

/**
 * 1 MiB — the same figure `guardrails/middleware.ts` uses for a screened
 * request body (`DEFAULT_MAX_REQUEST_BYTES`). One number for "how much text
 * this deployment is willing to hand a detector in one evaluation", not two.
 */
export const DEFAULT_ASSET_GUARDRAIL_MAX_SCREEN_BYTES = 1024 * 1024;

/** Resolves the mode for one `(tenant, asset_type)` pair. */
export interface AssetGuardrailModeTable {
  modeFor(tenantId: string, assetType: string): AssetGuardrailMode;
}

function isMode(value: unknown): value is AssetGuardrailMode {
  return value === "off" || value === "flag" || value === "block";
}

function parseModeMap(value: unknown, where: string): Record<string, AssetGuardrailMode> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${ASSET_GUARDRAIL_MODES_VAR}.${where} must be a JSON object`);
  }
  const out: Record<string, AssetGuardrailMode> = {};
  for (const [assetType, mode] of Object.entries(value)) {
    if (!isMode(mode)) {
      throw new Error(
        `${ASSET_GUARDRAIL_MODES_VAR}.${where}.${assetType} must be "off", "flag" or "block"`,
      );
    }
    out[assetType] = mode;
  }
  return out;
}

/**
 * Parse {@link ASSET_GUARDRAIL_MODES_VAR}:
 *
 * ```json
 * { "default": { "static_site": "block" },
 *   "tenants": { "tenant_a": { "config_file": "off" } } }
 * ```
 *
 * The shape is EXPLICIT — a bare `{ "mcp_manifest": "flag" }` is refused —
 * because the convenient alternative (treat an unrecognized object as the
 * default table) makes a tenant literally named `default` silently reconfigure
 * the deployment. A malformed value THROWS at composition rather than being
 * skipped, matching `GATEWAY_GUARDRAIL_POLICIES`: silently dropping a security
 * policy is the failure mode this repo forbids.
 */
export function assetGuardrailModesFromEnv(env: Record<string, unknown>): AssetGuardrailModeTable {
  const raw = env[ASSET_GUARDRAIL_MODES_VAR];
  let fallback: Record<string, AssetGuardrailMode> = { ...DEFAULT_ASSET_GUARDRAIL_MODES };
  let perTenant: Record<string, Record<string, AssetGuardrailMode>> = {};

  if (typeof raw === "string" && raw.trim() !== "") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`${ASSET_GUARDRAIL_MODES_VAR} is not valid JSON: ${String(error)}`);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error(`${ASSET_GUARDRAIL_MODES_VAR} must be a JSON object`);
    }
    const document = parsed as { default?: unknown; tenants?: unknown };
    if (document.default !== undefined) {
      // MERGED over the shipped defaults, not replacing them: an operator who
      // sets one asset type must not silently un-govern the other three.
      fallback = { ...fallback, ...parseModeMap(document.default, "default") };
    }
    if (document.tenants !== undefined) {
      if (
        typeof document.tenants !== "object" ||
        document.tenants === null ||
        Array.isArray(document.tenants)
      ) {
        throw new Error(`${ASSET_GUARDRAIL_MODES_VAR}.tenants must be a JSON object`);
      }
      perTenant = Object.fromEntries(
        Object.entries(document.tenants).map(([tenantId, table]) => [
          tenantId,
          parseModeMap(table, `tenants.${tenantId}`),
        ]),
      );
    }
  }

  return {
    modeFor(tenantId: string, assetType: string): AssetGuardrailMode {
      return perTenant[tenantId]?.[assetType] ?? fallback[assetType] ?? "off";
    },
  };
}

// ---------------------------------------------------------------------------
// Text surfaces
// ---------------------------------------------------------------------------

/**
 * Base content types that carry text a detector can read, beyond `text/*`.
 *
 * `application/octet-stream` is deliberately ABSENT. It is the content type
 * that means "unknown bytes", and admitting it here would turn every binary
 * push into a mojibake evidence row.
 */
const TEXT_BEARING_BASE_TYPES: ReadonlySet<string> = new Set([
  "application/json",
  "application/manifest+json",
  "application/javascript",
  "application/xml",
  "application/x-yaml",
  "application/yaml",
  "application/toml",
  "application/x-sh",
  "application/x-shellscript",
  // An SVG is an XML document that a browser will execute script inside, so it
  // is a text surface despite the `image/` prefix. Every other `image/*` is
  // opaque and stays that way.
  "image/svg+xml",
]);

/** Is `contentType` something a text detector can read? Base type only. */
export function isTextBearingAssetContentType(contentType: string): boolean {
  const base = (contentType.split(";")[0] ?? contentType).trim().toLowerCase();
  return base.startsWith("text/") || TEXT_BEARING_BASE_TYPES.has(base);
}

/** One readable piece of an asset, with the location an evidence row names. */
export interface AssetTextSurface {
  /** Bundle-relative path, or `""` for a single-object asset. */
  readonly path: string;
  readonly text: string;
}

export type AssetTextSurfaceOutcome =
  | { readonly kind: "text"; readonly surfaces: readonly AssetTextSurface[] }
  /** No text surface at all — a binary, an archive, a font, an image. */
  | { readonly kind: "opaque"; readonly reason: string }
  /** Text, but more of it than this deployment will decode. NEVER read. */
  | {
      readonly kind: "undecidable";
      readonly reason: string;
    };

/**
 * The readable surface of ONE object.
 *
 * The size check is FIRST and the buffer is not touched above it — the #703
 * shape, applied to the one size that is already known here. A non-UTF-8
 * payload under a text content type is `undecidable` and not a lossy decode:
 * a detector fed replacement characters reports on a document nobody
 * published, so `block` mode must withhold it rather than admit it as opaque.
 */
export function assetTextSurface(
  contentType: string,
  content: Uint8Array,
  ceilingBytes: number,
  path = "",
): AssetTextSurfaceOutcome {
  if (!isTextBearingAssetContentType(contentType)) {
    return { kind: "opaque", reason: `content_type=${contentType}` };
  }
  if (content.byteLength > ceilingBytes) {
    return {
      kind: "undecidable",
      reason: `size_bytes=${content.byteLength}>${ceilingBytes}`,
    };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(content);
  } catch {
    return { kind: "undecidable", reason: "not_utf8" };
  }
  return { kind: "text", surfaces: [{ path, text }] };
}

// ---------------------------------------------------------------------------
// The screening stage
// ---------------------------------------------------------------------------

/** What one guardrail pass concluded, in the vocabulary the audit line uses. */
interface AssetGuardrailOutcome {
  readonly visibility: AssetVisibility;
  readonly detail: string;
}

/** The compiled engine plus the sink it appends into. */
export interface AssetGuardrailRuntime {
  readonly engine: GuardrailEngine;
  /**
   * The evidence sink the engine writes into, so this stage can COMMIT it.
   *
   * `matchGuardrail` buffers (`GuardrailEvidenceSink.append` is synchronous by
   * contract, because the inference path calls it in front of the client's
   * first byte). A publish is not that path — it already awaits an R2 write and
   * a D1 audit flush — so the commit is awaited here rather than deferred to a
   * `waitUntil` the asset route module has no access to. It MUST be the same
   * instance the engine holds; a second one would buffer nothing and flush
   * nothing, which is the "wired but writes nowhere" shape this repo keeps
   * catching.
   */
  readonly evidence?: GuardrailEvidenceSink | undefined;
}

/** Everything {@link GuardrailAssetScreener} needs, injected. */
export interface AssetGuardrailScreenerDeps {
  /**
   * The runtime, or a THUNK that builds it.
   *
   * A thunk because the durable half of the policy set is a D1 read
   * (`loadGuardrailPolicyStore`), and doing it eagerly at the composition root
   * would make every asset request — including a plain `GET` that publishes
   * nothing — pay for a policy load, and would turn a control-plane hiccup at
   * deps-build time into an unhandled rejection nothing is waiting on. It is
   * called at most once per successful load and RETRIED after a failure, the
   * same posture `guardrails/middleware.ts` takes for the same object.
   */
  readonly runtime:
    | AssetGuardrailRuntime
    | (() => AssetGuardrailRuntime | Promise<AssetGuardrailRuntime>);
  readonly modes: AssetGuardrailModeTable;
  readonly maxScreenBytes?: number | undefined;
  /** The Worker `env` a durable evidence sink resolves its bindings from. */
  readonly env?: unknown;
}

/**
 * Rust's screening order, extended by one stage: signature → scanner →
 * GUARDRAIL. A decorator for the same reason `SignatureVerifyingScreener` is
 * one — `assetScreenerFromEnv` selects between two inner screeners, and a stage
 * folded into either would have to be folded into both and would then drift.
 *
 * Composition rules, identical to the signature stage's:
 *  - it never RELAXES the inner verdict (see {@link strictestVisibility});
 *  - an inner REJECTION is returned verbatim, unscreened — nothing is stored,
 *    so there is nothing to have an opinion about.
 */
export class GuardrailAssetScreener implements AssetScreener {
  readonly #inner: AssetScreener;
  readonly #build: () => AssetGuardrailRuntime | Promise<AssetGuardrailRuntime>;
  readonly #modes: AssetGuardrailModeTable;
  readonly #maxScreenBytes: number;
  readonly #env: unknown;
  #runtime: Promise<AssetGuardrailRuntime> | undefined;

  constructor(inner: AssetScreener, deps: AssetGuardrailScreenerDeps) {
    this.#inner = inner;
    const runtime = deps.runtime;
    this.#build = typeof runtime === "function" ? runtime : () => runtime;
    this.#modes = deps.modes;
    this.#maxScreenBytes = deps.maxScreenBytes ?? DEFAULT_ASSET_GUARDRAIL_MAX_SCREEN_BYTES;
    this.#env = deps.env;
  }

  /**
   * The runtime, built at most once.
   *
   * Memoized as the PROMISE rather than as its value, so two concurrent first
   * pushes share one policy load. A REJECTED promise is dropped so the next
   * push retries instead of inheriting a permanent failure — and the `catch`
   * below only marks it handled for the runtime's unhandled-rejection tracker;
   * the `await` in {@link #match} still rejects, so a policy set that could not
   * be read fails the push CLOSED rather than admitting unscreened content.
   */
  #runtimeOnce(): Promise<AssetGuardrailRuntime> {
    if (this.#runtime === undefined) {
      const pending = Promise.resolve().then(() => this.#build());
      pending.catch(() => {
        if (this.#runtime === pending) this.#runtime = undefined;
      });
      this.#runtime = pending;
    }
    return this.#runtime;
  }

  async screen(
    request: AssetScreeningRequest,
  ): Promise<AssetScreeningVerdict | AssetScreeningRejection> {
    const verdict = await this.#inner.screen(request);
    if (isScreeningRejection(verdict)) return verdict;

    const mode = this.#modes.modeFor(request.tenantId, request.assetType);
    const surface =
      mode === "off"
        ? undefined
        : assetTextSurface(request.contentType, request.content, this.#maxScreenBytes);

    const outcome = await this.#decide({
      mode,
      surface,
      tenantId: request.tenantId,
      assetId: request.assetId,
      assetType: request.assetType,
      requestId: request.requestId,
      location: `asset:${request.assetType}/${request.assetId}`,
    });

    return {
      ...verdict,
      visibility: strictestVisibility(verdict.visibility, outcome.visibility),
      auditDetail: `${verdict.auditDetail} ${outcome.detail}`,
      manifest: { ...verdict.manifest, guardrail: outcome.detail },
    };
  }

  /**
   * The per-FILE pass over an expanded `static_site` or `skill_bundle` archive.
   *
   * ONE evaluation with one SEGMENT per text-bearing file, rather than one
   * evaluation per file. Three reasons, all of them load-bearing:
   *  - a policy's `deadline_ms` and its aggregation are declared per
   *    EVALUATION, so N evaluations would silently multiply a site's screening
   *    budget by its file count;
   *  - `GuardrailMatch.segmentId` then names the offending file, which is
   *    exactly the evidence an operator needs and costs no extra row;
   *  - the durable evidence sink upserts by evaluation id, so a 400-file site
   *    produces ONE `guardrail_evaluations` row, not 400.
   *
   * Binary files (images, fonts) contribute no segment. Files past the decode
   * budget contribute no segment either and are reported as `undecidable`,
   * which under `block` withholds the version — "too big to check" must not
   * become "checked".
   */
  async screenBundleFiles(
    request: AssetBundleScreeningRequest,
  ): Promise<AssetBundleScreeningVerdict> {
    const mode = this.#modes.modeFor(request.tenantId, request.assetType);
    if (mode === "off") {
      return { visibility: "visible", auditDetail: "guardrail=off" };
    }

    const surfaces: AssetTextSurface[] = [];
    const undecidable: string[] = [];
    let opaque = 0;
    // The AGGREGATE budget, spent across the bundle. A per-file ceiling alone
    // would let 2 048 files of 1 MiB each (#736's own limits) hand a detector
    // 2 GiB, which is a denial of service we would be running on ourselves.
    let budget = this.#maxScreenBytes;

    for (const file of request.files) {
      if (!isTextBearingAssetContentType(file.contentType)) {
        opaque += 1;
        continue;
      }
      if (file.content.byteLength > budget) {
        // NOT READ. The size is already known from the expansion, so this is
        // the #703 refusal-from-metadata shape: a file we decline to decode is
        // reported as such and never decoded to find out.
        undecidable.push(`${file.path}(size_bytes=${file.content.byteLength}>${budget})`);
        continue;
      }
      const outcome = assetTextSurface(file.contentType, file.content, budget, file.path);
      if (outcome.kind === "text") {
        surfaces.push(...outcome.surfaces);
        budget -= file.content.byteLength;
      } else if (outcome.kind === "undecidable") {
        undecidable.push(`${file.path}(${outcome.reason})`);
      } else {
        opaque += 1;
      }
    }

    const outcome = await this.#decide({
      mode,
      surface:
        undecidable.length > 0
          ? { kind: "undecidable", reason: undecidable.join(",") }
          : surfaces.length > 0
            ? { kind: "text", surfaces }
            : { kind: "opaque", reason: `files=${opaque} none_text_bearing` },
      tenantId: request.tenantId,
      assetId: request.assetId,
      assetType: request.assetType,
      requestId: request.requestId,
      location: `asset:${request.assetType}/${request.assetId}`,
      // A bundle can be BOTH partly readable and partly over budget. The
      // readable half must still be screened, so the surfaces are carried even
      // when `undecidable` decided the surface kind.
      alsoScreen: undecidable.length > 0 ? surfaces : [],
    });
    const files = `files=${request.files.length} screened=${surfaces.length} opaque=${opaque}`;
    return { visibility: outcome.visibility, auditDetail: `${outcome.detail} ${files}` };
  }

  /**
   * The one place a mode, a surface and a policy verdict become a visibility.
   *
   * `undecidable` and `opaque` are DIFFERENT and must stay so:
   *  - `undecidable` means there IS text and we chose not to read it, so under
   *    `block` the honest answer is to withhold;
   *  - `opaque` means there is no text at all, which no policy in this tree can
   *    have an opinion about, so withholding would refuse every binary a tenant
   *    ever publishes.
   */
  async #decide(params: {
    readonly mode: AssetGuardrailMode;
    readonly surface: AssetTextSurfaceOutcome | undefined;
    readonly tenantId: string;
    readonly assetId: string;
    readonly assetType: string;
    readonly requestId: string | undefined;
    readonly location: string;
    readonly alsoScreen?: readonly AssetTextSurface[];
  }): Promise<AssetGuardrailOutcome> {
    if (params.mode === "off" || params.surface === undefined) {
      return { visibility: "visible", detail: "guardrail=off" };
    }
    if (params.surface.kind === "opaque") {
      return {
        visibility: "visible",
        detail: `guardrail=not_applicable(${params.surface.reason})`,
      };
    }

    const toScreen =
      params.surface.kind === "text" ? params.surface.surfaces : (params.alsoScreen ?? []);
    const match = toScreen.length > 0 ? await this.#match(params, toScreen) : null;

    if (match !== null) {
      // A `redact` effect WITHHOLDS rather than rewriting. Patching a published
      // artifact would change its `content_hash`, break the integrity re-check
      // `pullAsset` runs on every read, and invalidate the detached publisher
      // signature — so the only two answers available on this surface are
      // "publish it" and "do not".
      const evidence = `guardrail=${params.mode === "block" ? "blocked" : "flagged"}(rule=${
        match.ruleId
      }@${match.policyRevision} effect=${match.effect} code=${match.code}${
        match.segmentId === undefined ? "" : ` at=${match.segmentId}`
      })`;
      return {
        visibility: params.mode === "block" ? "quarantined" : "visible",
        detail: evidence,
      };
    }

    if (params.surface.kind === "undecidable") {
      return {
        visibility: params.mode === "block" ? "quarantined" : "visible",
        detail: `guardrail=undecidable(${params.surface.reason})`,
      };
    }
    return { visibility: "visible", detail: "guardrail=clean" };
  }

  /** Run the engine over `surfaces` and commit the evidence it buffered. */
  async #match(
    params: {
      readonly tenantId: string;
      readonly assetType: string;
      readonly requestId: string | undefined;
      readonly location: string;
    },
    surfaces: readonly AssetTextSurface[],
  ): Promise<GuardrailMatch | null> {
    const runtime = await this.#runtimeOnce();
    const envelope: GuardrailEnvelope = {
      protocol: "asset",
      stage: "request",
      segments: surfaces.map((surface, index) =>
        assetSegment(
          index,
          `${params.location}${surface.path === "" ? "" : `#${surface.path}`}`,
          surface,
        ),
      ),
    };
    try {
      // The tenant is attributed as the ORGANIZATION, which is how every other
      // out-of-band caller in this tree selects policies (`apps/agent-runtime`
      // does the same for `a2a`) and what `GuardrailPolicySource` scopes on.
      return await runtime.engine.matchGuardrail("request", {
        requestId: params.requestId ?? "",
        tenant: { organizationId: params.tenantId },
        streaming: false,
        envelope,
      });
    } finally {
      // Never `catch`: a policy load or evidence failure must reach the caller
      // as a 5xx rather than becoming a silent pass. The flush IS guarded,
      // because a logging failure is not a request failure (the sink's own
      // contract says it must not reject).
      await runtime.evidence?.flush?.({ env: this.#env }).catch(() => undefined);
    }
  }
}

/**
 * One envelope segment per screened file.
 *
 * `source: "text_attachment"` — the trust class #703 established for a
 * transcript, and a published asset is the same thing: content that arrived
 * from outside and will be read by somebody else's agent. Labelling it `user`
 * or `assistant` would tell `injection.ts::sourceTrust` that FerroGate or its
 * caller authored it, which is precisely the provenance an injection rule
 * scores on.
 */
function assetSegment(
  index: number,
  protocolLocation: string,
  surface: AssetTextSurface,
): ContentSegment {
  return {
    segment_id: surface.path === "" ? `asset:${index}` : `asset:${index}:${surface.path}`,
    source: "text_attachment",
    protocol_location: protocolLocation,
    content_type: "text_attachment",
    text: surface.text,
    fingerprint: contentFingerprint(surface.text),
  };
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/**
 * Does this deployment have guardrail policies at all?
 *
 * Read from the BINDING/var rather than by compiling, so the check is cheap and
 * so `assetDepsFromEnv({})` keeps returning `screener: undefined` — a
 * deployment that never configured a guardrail must be byte-for-byte what it
 * was, including the shape of its deps object.
 */
export function guardrailPoliciesConfigured(env: Record<string, unknown>): boolean {
  const declared = env[GUARDRAIL_POLICY_VAR];
  if (typeof declared === "string" && declared.trim() !== "" && declared.trim() !== "[]") {
    return true;
  }
  return D1GuardrailPolicyStore.fromEnv(env) !== null;
}

function positiveInteger(raw: unknown): number | undefined {
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const parsed = Number(raw.trim());
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

/**
 * Compose the guardrail stage onto `inner`, or return `inner` BY IDENTITY.
 *
 * Identity when no guardrail policy is configured — the same device
 * `withSignatureVerification` uses, and for the same reason: it is what lets
 * `assetDepsFromEnv` keep the "no vars ⇒ no screener override" contract that
 * `test/assets/scan.test.ts` pins.
 *
 * The engine is built from `guardrailDepsFromEnv`, i.e. from exactly the same
 * policy set, evidence sink and HMAC key the inference middleware uses. Two
 * policy sources would be two things to keep in sync, and the first time they
 * drifted an operator would have a rule that governs a chat turn and not the
 * manifest that produced it.
 */
export function withAssetGuardrailScreening(
  inner: AssetScreener,
  env: Record<string, unknown>,
): AssetScreener {
  if (!guardrailPoliciesConfigured(env)) return inner;
  const maxScreenBytes = positiveInteger(env[ASSET_GUARDRAIL_MAX_SCREEN_BYTES_VAR]);
  return new GuardrailAssetScreener(inner, {
    // LAZY: `guardrailDepsFromEnv` reads the durable revision/binding tables
    // when `CONTROL_DB` is bound, and this function runs at the composition
    // root — on every request, including reads that publish nothing.
    runtime: async () => {
      const deps = await guardrailDepsFromEnv(env);
      // ONE sink object, handed to the engine and kept for the flush.
      return { engine: new GuardrailEngine(deps), evidence: deps.evidence };
    },
    modes: assetGuardrailModesFromEnv(env),
    env,
    ...(maxScreenBytes !== undefined ? { maxScreenBytes } : {}),
  });
}
