/**
 * THE DURABLE ACTIVATED REVISION, READ THE SAME WAY BY EVERY SCREENING WORKER.
 *
 * `docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-3**: an operator authors a
 * guardrail policy revision, calls
 * `POST /admin/v1/guardrail-policies/{policy_id}/activate`, sees it bound — and
 * it covers ONE of the three doors that screen content. `apps/gateway` merged
 * the durable `guardrail_policy_revisions` + `guardrail_policy_bindings` rows
 * into its detector source; `apps/mcp` screened MCP tool arguments and tool
 * RESULTS from `FG_DEV_MCP_GUARDRAILS` (committed as `""`, which parses to `{}`,
 * which matches nothing, which allows everything) and `apps/agent-runtime`
 * screened A2A messages from `FG_DEV_A2A_GUARDRAILS` (not committed at all).
 * Move the payload to another surface and the activated revision never sees it.
 *
 * This module is the shared half of the fix. It lives HERE, in the package both
 * Workers already depend on, for a reason that is structural rather than
 * stylistic: the five Workers are separately bundled and **no app may import
 * another app's module graph** (`FLEET-CONSISTENCY.md` §6.1), so "MCP and
 * agent-runtime read the policy the same way" is only expressible as a library.
 * Writing the row I/O twice, once per app, would recreate the divergence this
 * file exists to close — two implementations, one of which drifts.
 *
 * ## What it deliberately does NOT do
 *
 * It does not re-implement a detector, a circuit breaker, an SSRF check or a
 * fingerprint. Every verdict below comes out of the detector classes this
 * package already ships and this package's own suite already covers.
 *
 * It is also NOT the gateway's enforcement engine. The gateway screens model
 * CONTENT and can redact a response document in place; MCP and A2A screen a
 * tool payload and an agent message, where there is no document to patch. So
 * the projection here is narrower ON PURPOSE, and every place it is narrower it
 * is narrower in the CLOSED direction — see {@link screenGuardrailPolicies}.
 *
 * ## Preserved properties (these are what make screening trustworthy)
 *
 * 1. **Generation / CAS semantics.** These Workers are READERS. They read the
 *    binding row's `active_revision` and never write it, so the control plane's
 *    generation-guarded compare-and-swap remains the single writer of "which
 *    revision is live". A binding pointing at a revision this snapshot does not
 *    hold is SKIPPED, never faked (see {@link loadActivatedPolicyRevisions}).
 * 2. **Evidence is HMAC-fingerprinted and never persisted.** A `local` detector
 *    with `secret_patterns` cannot be built without a resolvable
 *    `fingerprint_secret_ref` — an unkeyed digest of a short secret is
 *    reversible by dictionary attack. Nothing here records `matched_text`, and
 *    a refusal carries the OPERATOR's message, never the matched content.
 * 3. **Findings stay bounded.** `MAX_FINDINGS_PER_EVALUATION` is enforced
 *    inside the detectors; this module only ever reads `findings.length`.
 * 4. **FAIL CLOSED on detector timeout or error.** Read the Rust rather than
 *    guessing, because getting this backwards is itself the vulnerability:
 *
 *      detector throws `DetectorError`
 *        -> `CheckOutcome::Error`           (`state_quota_and_policy.rs:1373`)
 *        -> `AggregateOutcome::Error`       (`aggregate_check_outcomes`)
 *        -> the policy's `on_error` actions (`state_quota_and_policy.rs:539`)
 *
 *    and `on_error` is compiled from `provider_on_error`, whose serde
 *    `#[default]` is **`Block`** (`crates/ferrogate-config/src/config/types.rs:1954`).
 *    `validatePolicyRevision` additionally refuses an EMPTY `on_error`, so "no
 *    posture declared" is unrepresentable. An unreachable or slow detector
 *    therefore DENIES unless the operator explicitly opted into `record`
 *    (fail open) or a `fallback_detector`.
 * 5. **A read failure is not an allow.** {@link loadActivatedPolicyRevisions}
 *    propagates a database error; callers turn that into a refusal, matching
 *    the posture `apps/gateway/src/ratelimit/quota.ts` argues for. A control
 *    that admits when its backend is unavailable is the bypass in a new form.
 */
// Imported from the leaf modules rather than from `./index.js`: `index.ts`
// re-exports THIS file, and a module that imports its own barrel is a cycle
// esbuild resolves by evaluation order rather than by declaration — which is
// how a `class extends undefined` boot failure reaches production.
import { LlmGuardPromptInjectionDetector } from "./adapters/llm_guard.js";
import { PresidioDetector } from "./adapters/presidio.js";
import {
  type WorkersAiBinding,
  type WorkersAiClient,
  WorkersAiLlamaGuardDetector,
  workersAiBindingClient,
} from "./adapters/workers_ai_llama_guard.js";
import {
  DetectorError,
  type DetectorInput,
  DetectorSecret,
  type DetectorStage,
  type GuardrailDetector,
} from "./contract.js";
import { CustomHttpDetector } from "./custom_http.js";
import { DeterministicDetector } from "./deterministic.js";
import { ALL_CONTENT_SOURCES, type ContentSource } from "./envelope.js";
import { PiiDetector, type PiiTokenVault, piiDetectorConfig } from "./pii.js";
import {
  type ActionKind,
  type CheckOutcome,
  type DetectorDefinition,
  type PolicyAction,
  type PolicyRevision,
  type PolicySelectionContext,
  administrativeRank,
  aggregateCheckOutcomes,
  immutableId,
  policyRevisionSchema,
  scopeMatches,
  validateDetectorDefinition,
  validatePolicyRevision,
} from "./policy.js";

// ---------------------------------------------------------------------------
// Row I/O
// ---------------------------------------------------------------------------

/** One row, as D1 hands it back. */
type Row = Record<string, unknown>;

/**
 * The statements a CALLER wants issued, when it wants to own them.
 *
 * Every field defaults to this module's own constant, so a caller that supplies
 * nothing gets the identical behaviour. The reason the seam exists at all is
 * the repo's standing convention for cross-Worker SQL, stated at length in
 * `apps/control-plane/src/store/guardrail_registry.ts`: **each Worker restates
 * the statements it issues, and the halves are joined behaviourally by a test
 * rather than textually by an import.** Two things depend on that convention
 * here, and neither is stylistic:
 *
 *  - an operator or reviewer grepping "who reads `guardrail_policy_bindings`"
 *    must find every Worker that does. Before FC-3, `apps/mcp` and
 *    `apps/agent-runtime` were absent from that grep and the answer it gave was
 *    correct — neither read it;
 *  - `apps/gateway/test/fleet-control-matrix.test.ts` derives each control's
 *    source-of-truth class by extracting table names from the SQL LITERALS in
 *    each Worker's own `src/`. A Worker that reached the rows only through a
 *    helper would be scored VAR-ONLY — the shape of every fleet control defect
 *    shipped so far — and the gate would report the divergence still open.
 *
 * The drift the convention costs is bought back by assertion:
 * `apps/mcp/test/fleet-guardrail-activation.test.ts` requires each Worker's
 * constants to equal these, and equal the gateway's.
 */
export interface GuardrailPolicySql {
  /** Every revision of every policy. */
  readonly revisionSql?: string | undefined;
  /** Every binding row, in full. */
  readonly bindingSql?: string | undefined;
  /** The cheap pointer probe — see {@link GUARDRAIL_BINDING_POINTER_SQL}. */
  readonly pointerSql?: string | undefined;
}

/**
 * The subset of `D1Database` this module reads. A live binding satisfies it
 * structurally, so nothing is cast at a composition root and nothing wraps the
 * binding.
 */
export interface GuardrailPolicyDatabase {
  prepare(sql: string): GuardrailPolicyStatement;
}

export interface GuardrailPolicyStatement {
  bind(...values: unknown[]): GuardrailPolicyStatement;
  all(): Promise<{ results?: Row[] | null }>;
}

/** The two CONTROL tables. Named so a gate can pin them rather than restate them. */
export const GUARDRAIL_REVISION_TABLE = "guardrail_policy_revisions";
export const GUARDRAIL_BINDING_TABLE = "guardrail_policy_bindings";

/**
 * Byte-identical to `apps/gateway/src/guardrails/d1.ts`.
 *
 * That is asserted, not hoped for: `apps/mcp/test/guardrails/fleet-policy-activation.test.ts`
 * compares these two constants against the gateway's exported strings. If the
 * gateway ever reads a different table or a different column, the fleet gate is
 * what says so — which is precisely the check nobody ran the two times a
 * divergence shipped.
 */
export const GUARDRAIL_REVISION_LIST_ALL_SQL =
  "SELECT revision_json FROM guardrail_policy_revisions ORDER BY policy_id ASC, revision ASC";

export const GUARDRAIL_BINDING_LIST_SQL =
  "SELECT policy_id, active_revision, generation, binding_json " +
  "FROM guardrail_policy_bindings ORDER BY policy_id ASC";

/**
 * The POINTER read: which revision of which policy is live, and at what
 * generation. One indexed scan of the smallest table in the schema, and the
 * freshness probe {@link activatedGuardrailPolicies} runs per request.
 */
export const GUARDRAIL_BINDING_POINTER_SQL =
  "SELECT policy_id, active_revision, generation " +
  "FROM guardrail_policy_bindings ORDER BY policy_id ASC";

function revisionFromRow(row: Row): unknown {
  const raw = row.revision_json;
  if (typeof raw !== "string") return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

/** The activated pointer of one policy, as these READERS need it. */
export interface ActivatedPolicyPointer {
  readonly policyId: string;
  readonly activeRevision: number | null;
  /** The control plane's CAS token. Read-only here; never written back. */
  readonly generation: number;
}

function pointerFromRow(row: Row): ActivatedPolicyPointer {
  const active = row.active_revision;
  return {
    policyId: String(row.policy_id),
    activeRevision: typeof active === "number" ? active : null,
    generation: typeof row.generation === "number" ? row.generation : 0,
  };
}

/**
 * Every policy revision the control plane has ACTIVATED, newest binding wins.
 *
 * Mirrors `apps/gateway/src/guardrails/d1.ts::loadGuardrailPolicyStore` row for
 * row, with the two skip rules that make it safe:
 *
 *  - a revision row that does not parse or does not validate is SKIPPED rather
 *    than thrown, so one legacy document written before `admitPolicyRevision`
 *    tightened cannot take every request on this Worker down at boot. Skipping
 *    is NOT fail-open, because of the next rule;
 *  - a binding pointing at a revision the snapshot does not hold is SKIPPED,
 *    never faked. A policy whose text is unknown is never activated, so no
 *    caller is ever told it was screened by rules nobody can read back.
 *
 * THROWS on a database failure. Deliberate, and it is the closed direction: the
 * caller answers a refusal rather than screening with policies silently
 * missing.
 */
export async function loadActivatedPolicyRevisions(
  db: GuardrailPolicyDatabase,
  options: GuardrailPolicySql & {
    /** Injectable so a test can drive the skip rules; defaults to the real schema parse. */
    readonly parseRevision?: (document: unknown) => PolicyRevision;
  } = {},
): Promise<readonly PolicyRevision[]> {
  const parse = options.parseRevision ?? defaultParseRevision;

  const revisionRows = await db
    .prepare(options.revisionSql ?? GUARDRAIL_REVISION_LIST_ALL_SQL)
    .all();
  const byImmutableId = new Map<string, PolicyRevision>();
  for (const row of revisionRows.results ?? []) {
    const document = revisionFromRow(row);
    if (document === undefined) continue;
    let revision: PolicyRevision;
    try {
      revision = parse(document);
      validatePolicyRevision(revision);
    } catch {
      continue;
    }
    byImmutableId.set(immutableId(revision), revision);
  }

  const bindingRows = await db.prepare(options.bindingSql ?? GUARDRAIL_BINDING_LIST_SQL).all();
  const activated: PolicyRevision[] = [];
  for (const row of bindingRows.results ?? []) {
    const pointer = pointerFromRow(row);
    if (pointer.activeRevision === null) continue;
    const revision = byImmutableId.get(`${pointer.policyId}@${pointer.activeRevision}`);
    if (revision === undefined) continue;
    activated.push(revision);
  }
  return activated;
}

function defaultParseRevision(document: unknown): PolicyRevision {
  return policyRevisionSchema.parse(document) as PolicyRevision;
}

/** The live pointer of every policy — the cheap freshness probe. */
export async function loadActivatedPolicyPointers(
  db: GuardrailPolicyDatabase,
  options: GuardrailPolicySql = {},
): Promise<readonly ActivatedPolicyPointer[]> {
  const rows = await db.prepare(options.pointerSql ?? GUARDRAIL_BINDING_POINTER_SQL).all();
  return (rows.results ?? []).map(pointerFromRow);
}

/**
 * `policy@revision#generation, …` — the identity of a POLICY SET.
 *
 * `generation` is included and it is not redundant: an `archive` followed by a
 * `restore` of the same revision returns `active_revision` to where it was
 * while advancing the generation, so a fingerprint without it would report "no
 * change" across a round trip an operator performed deliberately.
 */
export function activatedPolicyFingerprint(pointers: readonly ActivatedPolicyPointer[]): string {
  return pointers
    .map((p) => `${p.policyId}@${p.activeRevision ?? "none"}#${p.generation}`)
    .join(",");
}

// ---------------------------------------------------------------------------
// The per-isolate compiled snapshot
// ---------------------------------------------------------------------------

interface Snapshot {
  readonly fingerprint: string;
  readonly policies: readonly CompiledGuardrailPolicy[];
}

const snapshots = new WeakMap<object, Snapshot>();

/** Drop a cached snapshot. Test affordance; an isolate recycle does the same. */
export function forgetActivatedGuardrailPolicies(cacheKey: object): void {
  snapshots.delete(cacheKey);
}

/**
 * The compiled activated set for this isolate, REVALIDATED on every call.
 *
 * ## Why this is not a plain memo, and why that matters
 *
 * `apps/gateway` snapshots its guardrail source once per isolate, which is the
 * Workers shape of the Rust gateway rebuilding `AppState.guardrail_policies` on
 * config reload. On the gateway that is defensible: a Worker isolate is
 * short-lived and a reload was an operator action there too.
 *
 * For the doors this function serves it is not, and the reason is the FC-3
 * narrative itself: the promise being made to an operator is *"you activate a
 * policy and the very next request is screened by it"*. A process-lifetime memo
 * turns that into *"…once this isolate happens to recycle"*, which is precisely
 * the class of half-applied control this wave exists to close — and it is the
 * regression `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts`
 * catches by mutation on the sibling capability.
 *
 * So every call re-reads the POINTERS — one indexed scan of
 * `guardrail_policy_bindings`, the smallest table in the control schema and the
 * only MUTABLE half of the pair — and recompiles only when the
 * `(policy_id, active_revision, generation)` set moved. Revisions are immutable
 * by construction, so an unchanged pointer set provably denotes an unchanged
 * policy SET, and the compiled detectors are reused: a `CustomHttpDetector`'s
 * semaphore and circuit state survive across requests exactly as they must.
 *
 * A failure is NOT cached: the caller fails the request closed and the next
 * request retries, so one D1 blip cannot wedge an isolate into refusing.
 */
export async function activatedGuardrailPolicies(
  cacheKey: object,
  db: GuardrailPolicyDatabase,
  context: GuardrailDetectorBuildContext = {},
  sql: GuardrailPolicySql = {},
): Promise<readonly CompiledGuardrailPolicy[]> {
  const fingerprint = activatedPolicyFingerprint(await loadActivatedPolicyPointers(db, sql));
  const cached = snapshots.get(cacheKey);
  if (cached !== undefined && cached.fingerprint === fingerprint) {
    return cached.policies;
  }
  const policies = compileActivatedPolicies(await loadActivatedPolicyRevisions(db, sql), context);
  snapshots.set(cacheKey, { fingerprint, policies });
  return policies;
}

// ---------------------------------------------------------------------------
// Detector construction
// ---------------------------------------------------------------------------

/** Resolves a `secret_ref` to its value. Backed by Worker secret bindings. */
export type GuardrailSecretResolver = (ref: string) => string | undefined;

export interface GuardrailDetectorBuildContext {
  /** `env://NAME` / bare `NAME` resolution. Defaults to "nothing resolves". */
  readonly secrets?: GuardrailSecretResolver | undefined;
  /** The `AI` binding, when the Worker has one. */
  readonly workersAi?: WorkersAiBinding | undefined;
  /** Escape hatch for a non-binding Workers-AI transport (tests, REST). */
  readonly workersAiClient?: WorkersAiClient | undefined;
  /**
   * Where a REVERSIBLE PII redaction stashes its token→value mapping. Absent by
   * default, which makes `redaction: "tokenize"` a hard build error rather than
   * a silent downgrade to irreversible — see `pii.ts::piiDetectorConfig`.
   */
  readonly piiVault?: PiiTokenVault | undefined;
}

/**
 * A `GuardrailSecretResolver` over Worker bindings.
 *
 * Refs are matched in the shapes `ferrogate-secrets` accepts: `env://NAME` and
 * a bare `NAME`. `vault://` has no Workers analogue and `cf://` is deploy-time
 * only, so both resolve to `undefined` — a hard build error for that ONE
 * policy, never a silent unkeyed fingerprint.
 */
export function guardrailSecretsFromEnv(env: Record<string, unknown>): GuardrailSecretResolver {
  return (ref) => {
    const name = ref.startsWith("env://") ? ref.slice("env://".length) : ref;
    const value = env[name];
    return typeof value === "string" && value.length > 0 ? value : undefined;
  };
}

export class GuardrailDetectorBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardrailDetectorBuildError";
  }
}

function requireSecret(
  context: GuardrailDetectorBuildContext,
  ref: string | null | undefined,
  purpose: string,
): DetectorSecret {
  const value = ref === null || ref === undefined ? undefined : context.secrets?.(ref);
  if (value === undefined || value.length === 0) {
    throw new GuardrailDetectorBuildError(
      `guardrail detector ${purpose} secret ref ${ref ?? "<missing>"} did not resolve to a value`,
    );
  }
  return new DetectorSecret(value);
}

function optionalSecret(
  context: GuardrailDetectorBuildContext,
  ref: string | null | undefined,
): DetectorSecret | undefined {
  if (ref === null || ref === undefined || ref.length === 0) return undefined;
  const value = context.secrets?.(ref);
  if (value === undefined || value.length === 0) {
    throw new GuardrailDetectorBuildError(
      `guardrail detector credential secret ref ${ref} did not resolve to a value`,
    );
  }
  return new DetectorSecret(value);
}

/**
 * `DetectorDefinition` -> a live `GuardrailDetector`.
 *
 * Returns `undefined` ONLY for the graceful-disable case (Workers-AI
 * Llama-Guard with no Cloudflare transport), mirroring the Rust adapter being
 * constructible only when a `[cloudflare]` block was configured. That is not a
 * silent pass: {@link compileActivatedPolicies} marks the check DISABLED, and a
 * policy whose only check for a stage is disabled simply stops selecting that
 * stage rather than passing content it never scanned.
 */
export function buildGuardrailDetector(
  checkId: string,
  definition: DetectorDefinition,
  sources: readonly ContentSource[],
  context: GuardrailDetectorBuildContext = {},
): GuardrailDetector | undefined {
  validateDetectorDefinition(definition);
  const supportedSources = [...sources];
  const id = `${checkId}:${definition.kind}`;

  switch (definition.kind) {
    case "local": {
      const fingerprintKey =
        definition.secret_patterns.length > 0 || definition.fingerprint_secret_ref
          ? requireSecret(context, definition.fingerprint_secret_ref, "local fingerprint")
          : undefined;
      return DeterministicDetector.new({
        id,
        supported_sources: supportedSources,
        keywords: [...definition.keywords],
        regex: [...definition.regex],
        ...(definition.max_input_bytes !== null && definition.max_input_bytes !== undefined
          ? { max_input_bytes: definition.max_input_bytes }
          : {}),
        ...(definition.json !== undefined ? { json: definition.json } : {}),
        ...(definition.request !== undefined ? { request: definition.request } : {}),
        secret_patterns: [...definition.secret_patterns],
        ...(fingerprintKey !== undefined ? { fingerprint_key: fingerprintKey } : {}),
      });
    }
    case "custom_http": {
      const bearer = optionalSecret(context, definition.secret_ref);
      return CustomHttpDetector.new({
        id,
        endpoint: definition.endpoint,
        timeoutMs: definition.timeout_ms,
        maxConcurrency: definition.max_concurrency,
        circuitFailureThreshold: definition.circuit_failure_threshold,
        circuitCooldownMs: definition.circuit_cooldown_ms,
        maxRetries: definition.max_retries,
        maxPayloadBytes: definition.max_payload_bytes,
        maxResponseBytes: definition.max_response_bytes,
        allowPrivateNetwork: definition.allow_private_network,
        supportedSources,
        ...(bearer !== undefined ? { bearerToken: bearer } : {}),
      });
    }
    case "presidio": {
      const bearer = optionalSecret(context, definition.secret_ref);
      return PresidioDetector.new({
        id,
        endpoint: definition.endpoint,
        language: definition.language,
        scoreThresholdPercent: definition.score_threshold_percent,
        ...(definition.entities !== null && definition.entities !== undefined
          ? { entities: [...definition.entities] }
          : {}),
        timeoutMs: definition.timeout_ms,
        maxPayloadBytes: definition.max_payload_bytes,
        maxResponseBytes: definition.max_response_bytes,
        allowPrivateNetwork: definition.allow_private_network,
        supportedSources,
        ...(bearer !== undefined ? { bearerToken: bearer } : {}),
        fingerprintKey: requireSecret(
          context,
          definition.fingerprint_secret_ref,
          "presidio fingerprint",
        ),
      });
    }
    case "llm_guard_prompt_injection": {
      const bearer = optionalSecret(context, definition.secret_ref);
      return LlmGuardPromptInjectionDetector.new({
        id,
        endpoint: definition.endpoint,
        scoreThresholdPercent: definition.score_threshold_percent,
        timeoutMs: definition.timeout_ms,
        maxPayloadBytes: definition.max_payload_bytes,
        maxResponseBytes: definition.max_response_bytes,
        allowPrivateNetwork: definition.allow_private_network,
        supportedSources,
        ...(bearer !== undefined ? { bearerToken: bearer } : {}),
        fingerprintKey: requireSecret(
          context,
          definition.fingerprint_secret_ref,
          "llm_guard fingerprint",
        ),
      });
    }
    case "pii": {
      return PiiDetector.new(
        piiDetectorConfig(
          id,
          definition,
          supportedSources,
          requireSecret(context, definition.fingerprint_secret_ref, "pii fingerprint"),
          {
            vault: context.piiVault,
            workersAi:
              context.workersAiClient ??
              (context.workersAi !== undefined
                ? workersAiBindingClient(context.workersAi)
                : undefined),
          },
          (message) => new GuardrailDetectorBuildError(message),
        ),
      );
    }
    case "workers_ai_llama_guard": {
      const client =
        context.workersAiClient ??
        (context.workersAi !== undefined ? workersAiBindingClient(context.workersAi) : undefined);
      if (client === undefined) return undefined;
      return WorkersAiLlamaGuardDetector.withWorkersAi(
        {
          id,
          model: definition.model,
          ...(definition.categories !== null && definition.categories !== undefined
            ? { categories: [...definition.categories] }
            : {}),
          timeoutMs: definition.timeout_ms,
          maxPayloadBytes: definition.max_payload_bytes,
          supportedSources,
          fingerprintKey: requireSecret(
            context,
            definition.fingerprint_secret_ref,
            "workers_ai_llama_guard fingerprint",
          ),
        },
        client,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Compiled policies
// ---------------------------------------------------------------------------

/** One compiled check: the immutable binding plus its constructed detector(s). */
export interface CompiledGuardrailCheck {
  readonly id: string;
  readonly enabled: boolean;
  readonly stage: DetectorStage;
  readonly sources: readonly ContentSource[];
  readonly detector: GuardrailDetector;
  readonly fallbackDetector?: GuardrailDetector | undefined;
}

/** A selected policy revision plus its compiled checks. */
export interface CompiledGuardrailPolicy {
  readonly revision: PolicyRevision;
  readonly checks: readonly CompiledGuardrailCheck[];
}

/**
 * A check that cannot be evaluated because its policy did not COMPILE.
 *
 * Not a placeholder and not a disabled check: it is `enabled`, it is selected,
 * and every evaluation raises `DetectorError(unavailable)`, which lands on the
 * revision's `on_error` actions (default `block`). DROPPING an uncompilable
 * policy would leave the traffic it fences screened by nothing at all, silently
 * — the fail-OPEN direction, and the defect class this whole wave is closing.
 */
function uncompilableCheck(policyId: string, detail: string): CompiledGuardrailCheck {
  const id = `${policyId}:uncompilable`;
  const detector: GuardrailDetector = {
    descriptor: () => ({
      id,
      version: "uncompilable",
      supports_request: true,
      supports_response: true,
      supports_transform: false,
      supported_sources: [...ALL_CONTENT_SOURCES],
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: 0,
      declared_failure_modes: ["unavailable"],
    }),
    health: () => ({
      circuit_open: true,
      consecutive_failures: 1,
      in_flight: 0,
      request_total: 0,
      success_total: 0,
      failure_total: 1,
    }),
    evaluate: () =>
      Promise.reject(
        DetectorError.new(
          "unavailable",
          `guardrail policy ${policyId} could not be compiled: ${detail}`,
        ),
      ),
  };
  return { id, enabled: true, stage: "request", sources: [...ALL_CONTENT_SOURCES], detector };
}

/** Placeholder so a disabled check still has a shape; it is never evaluated. */
function disabledDetector(checkId: string): GuardrailDetector {
  return {
    descriptor: () => ({
      id: `${checkId}:disabled`,
      version: "disabled",
      supports_request: false,
      supports_response: false,
      supports_transform: false,
      supported_sources: [],
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: 0,
      declared_failure_modes: [],
    }),
    health: () => ({
      circuit_open: false,
      consecutive_failures: 0,
      in_flight: 0,
      request_total: 0,
      success_total: 0,
      failure_total: 0,
    }),
    evaluate: () =>
      Promise.reject(
        new Error("disabled guardrail check must never be evaluated (compile-time invariant)"),
      ),
  };
}

/**
 * Compile every activated revision, ONCE, in `selectPolicyRevisions` order —
 * `(administrative_rank, policy_id, revision)`, never insertion order.
 *
 * Compilation is eager so a `CustomHttpDetector`'s semaphore and circuit state
 * are shared across every request in the isolate, exactly as the Rust held one
 * `Arc<dyn GuardrailDetector>` per check on `AppState`.
 *
 * A revision that fails to compile becomes an {@link uncompilableCheck} rather
 * than throwing. Unlike the gateway — where a policy in the Worker's OWN deploy
 * config must be a hard boot error — every revision reaching this function came
 * out of the DURABLE tables, i.e. another Worker's runtime input, and a mistyped
 * `fingerprint_secret_ref` written by the control plane must not be able to take
 * a whole Worker offline. The blast radius is reduced from the fleet to the one
 * policy, and that policy still REFUSES.
 */
export function compileActivatedPolicies(
  revisions: readonly PolicyRevision[],
  context: GuardrailDetectorBuildContext = {},
): readonly CompiledGuardrailPolicy[] {
  const compiled: CompiledGuardrailPolicy[] = [];
  for (const revision of revisions) {
    try {
      compiled.push({ revision, checks: compileChecks(revision, context) });
    } catch (error) {
      compiled.push({
        revision,
        checks: [
          uncompilableCheck(
            revision.policy_id,
            error instanceof Error ? error.message : String(error),
          ),
        ],
      });
    }
  }
  return [...compiled].sort((a, b) => {
    const rank = administrativeRank(a.revision.scope) - administrativeRank(b.revision.scope);
    if (rank !== 0) return rank;
    if (a.revision.policy_id !== b.revision.policy_id) {
      return a.revision.policy_id < b.revision.policy_id ? -1 : 1;
    }
    return a.revision.revision - b.revision.revision;
  });
}

function compileChecks(
  revision: PolicyRevision,
  context: GuardrailDetectorBuildContext,
): readonly CompiledGuardrailCheck[] {
  const compiled: CompiledGuardrailCheck[] = [];
  for (const check of revision.checks) {
    const detector = buildGuardrailDetector(check.id, check.detector, check.sources, context);
    if (detector === undefined) {
      compiled.push({
        id: check.id,
        enabled: false,
        stage: check.stage,
        sources: [...check.sources],
        detector: disabledDetector(check.id),
      });
      continue;
    }
    const fallback =
      check.fallback_detector !== undefined
        ? buildGuardrailDetector(
            `${check.id}#fallback`,
            check.fallback_detector,
            check.sources,
            context,
          )
        : undefined;
    compiled.push({
      id: check.id,
      enabled: check.enabled,
      stage: check.stage,
      sources: [...check.sources],
      detector,
      ...(fallback !== undefined ? { fallbackDetector: fallback } : {}),
    });
  }
  return compiled;
}

// ---------------------------------------------------------------------------
// Screening
// ---------------------------------------------------------------------------

/**
 * The decision one screening pass produces.
 *
 * `code` and `message` come from the POLICY ACTION the operator authored, which
 * is what makes "the gateway blocks it and MCP blocks it with the same code"
 * expressible at all. The message never carries matched text — the crate's
 * standing invariant, and a refusal that quoted the secret it caught would
 * defeat the detector it came from.
 */
export type GuardrailScreeningDecision =
  | { readonly outcome: "allow" }
  | {
      readonly outcome: "deny";
      readonly code: string;
      readonly message: string;
      readonly policyId: string;
      readonly policyRevision: number;
      readonly checkId?: string | undefined;
      readonly actionKind: ActionKind;
      readonly findingCount: number;
    };

export interface GuardrailScreeningRequest {
  /** The compiled, activated set — {@link compileActivatedPolicies}. */
  readonly policies: readonly CompiledGuardrailPolicy[];
  /** Which policies apply to this caller (`scopeMatches`). */
  readonly selection: PolicySelectionContext;
  readonly stage: DetectorStage;
  /** Everything the detectors read. Built by the caller from its own envelope. */
  readonly input: DetectorInput;
  /** Whether the surface being screened is a STREAM (A2A `message:stream`). */
  readonly streaming?: boolean | undefined;
  /** Injectable clock (epoch millis). Defaults to `Date.now`. */
  readonly now?: (() => number) | undefined;
}

interface CheckEvaluation {
  readonly checkId: string;
  readonly outcome: CheckOutcome;
  readonly findingCount: number;
  readonly errored: boolean;
}

interface Candidate {
  readonly decision: Extract<GuardrailScreeningDecision, { outcome: "deny" }>;
  readonly rank: number;
}

/**
 * Evaluate every scope-matching activated policy and return the strongest
 * enforcement, or `allow`.
 *
 * Ported decision by decision from the gateway's `matchGuardrail`
 * (`crates/ferrogate-gateway/src/state_quota_and_policy.rs::match_guardrail`),
 * with three places it is deliberately NARROWER — all three in the CLOSED
 * direction:
 *
 *  - **`redact` / `quarantine` become `deny`.** The gateway can rewrite a
 *    response document through validated content patches; an MCP tool argument
 *    and an A2A message have no document to patch on these surfaces, so a
 *    redaction here could never scrub the flagged content. That is exactly the
 *    gateway's own `guardrail_invalid_redaction` branch — "a redact with no
 *    patch downgrades to deny" (`:1553-1567`) — reached unconditionally because
 *    the patch count on these surfaces is always zero. Reporting a redaction
 *    that did not happen would return the flagged content verbatim while the
 *    audit claims it was scrubbed.
 *  - **`require_approval` becomes `deny`.** #200: there is no inline approval
 *    on the content path, so it fails closed. MCP's separate human-approval
 *    queue is a different gate and runs ahead of this one.
 *  - **No evidence sink, so no "evidence unavailable" branch.** These Workers
 *    write their governance rows through their own audit sinks; this module
 *    never silently substitutes an allow for a missing evidence row.
 *
 * `shadow` mode never enforces, and `reject_streaming` denies a STREAMING
 * surface before any byte is forwarded — both verbatim from the engine.
 */
export async function screenGuardrailPolicies(
  request: GuardrailScreeningRequest,
): Promise<GuardrailScreeningDecision> {
  const now = request.now ?? ((): number => Date.now());
  let selected: Candidate | undefined;

  for (const policy of request.policies) {
    if (!scopeMatches(policy.revision.scope, request.selection)) continue;

    // Shadow observes and never enforces. Checked BEFORE the streaming
    // rejection so a shadow policy cannot refuse a stream either.
    //
    // The second disjunct is the engine's `effectiveShadow` verbatim: a policy
    // that declared `shadow_after_complete` has said the streamed RESPONSE is
    // to be evaluated only once the caller already has the bytes, so enforcing
    // it mid-stream would be stricter than the operator asked for. It is the
    // one place "narrower in the closed direction" would be wrong.
    const shadow =
      policy.revision.mode === "shadow" ||
      (request.streaming === true &&
        request.stage === "response" &&
        policy.revision.streaming === "shadow_after_complete");

    if (request.streaming === true && policy.revision.streaming === "reject_streaming") {
      if (shadow) continue;
      selected = strongest(selected, {
        outcome: "deny",
        code: "guardrail_streaming_unsupported",
        message: `guardrail policy '${policy.revision.name}' does not allow streaming`,
        policyId: policy.revision.policy_id,
        policyRevision: policy.revision.revision,
        actionKind: "block",
        findingCount: 0,
      });
      continue;
    }

    const stageChecks = policy.checks.filter((check) => check.stage === request.stage);
    if (!stageChecks.some((check) => check.enabled)) continue;

    const deadline = now() + policy.revision.deadline_ms;
    const evaluations =
      policy.revision.execution === "parallel"
        ? await Promise.all(
            stageChecks.map((check) => evaluateCheck(check, request.input, deadline)),
          )
        : await sequential(stageChecks, (check) => evaluateCheck(check, request.input, deadline));

    const aggregate = aggregateCheckOutcomes(
      policy.revision.aggregation,
      evaluations.map((evaluation) => evaluation.outcome),
    );
    const actions =
      aggregate === "pass"
        ? policy.revision.on_pass
        : aggregate === "fail"
          ? policy.revision.on_fail
          : policy.revision.on_error;

    if (shadow) continue;

    const evidence =
      aggregate === "fail"
        ? evaluations.find((evaluation) => evaluation.outcome === "fail")
        : aggregate === "error"
          ? evaluations.find((evaluation) => evaluation.outcome === "error")
          : evaluations[0];

    for (const action of actions) {
      const candidate = enforcementFor(policy, action, evidence);
      if (candidate !== undefined) selected = strongest(selected, candidate);
    }
  }

  return selected === undefined ? { outcome: "allow" } : selected.decision;
}

function enforcementFor(
  policy: CompiledGuardrailPolicy,
  action: PolicyAction,
  evidence: CheckEvaluation | undefined,
): Extract<GuardrailScreeningDecision, { outcome: "deny" }> | undefined {
  if (action.kind === "allow" || action.kind === "record") return undefined;

  const base = {
    policyId: policy.revision.policy_id,
    policyRevision: policy.revision.revision,
    ...(evidence !== undefined ? { checkId: evidence.checkId } : {}),
    actionKind: action.kind,
    findingCount: evidence?.findingCount ?? 0,
  } as const;

  if (action.kind === "redact" || action.kind === "quarantine") {
    // FAIL CLOSED, see the function docs: no patch machinery on these surfaces
    // means a redaction can never be produced, and the gateway collapses that
    // same case to a deny.
    return {
      outcome: "deny",
      code: "guardrail_invalid_redaction",
      message: `guardrail policy '${policy.revision.name}' could not produce safe redaction evidence`,
      ...base,
    };
  }

  return {
    outcome: "deny",
    code: action.code ?? "guardrail_blocked",
    message: action.message ?? "request blocked by guardrail policy",
    ...base,
  };
}

/**
 * `guardrail_enforcement_rank` (`state_quota_and_policy.rs:1583`), strictly
 * greater so ties keep the FIRST — which, given the sort in
 * {@link compileActivatedPolicies}, is the most administratively general.
 *
 * An unconditional `block` must outrank an approval-gated deny: a
 * `require_approval` still executes once a human approves, so treating the two
 * as equal would let a hard block be silently downgraded whenever an approval
 * policy co-matched and sorted first.
 */
function rankOf(decision: Extract<GuardrailScreeningDecision, { outcome: "deny" }>): number {
  return decision.actionKind === "require_approval" ? 2 : 3;
}

function strongest(
  current: Candidate | undefined,
  decision: Extract<GuardrailScreeningDecision, { outcome: "deny" }>,
): Candidate {
  const rank = rankOf(decision);
  if (current === undefined) return { decision, rank };
  return rank > current.rank ? { decision, rank } : current;
}

async function sequential<T, R>(items: readonly T[], run: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (const item of items) out.push(await run(item));
  return out;
}

/** `evaluate_guardrail_check` (`state_quota_and_policy.rs:1319`). */
async function evaluateCheck(
  check: CompiledGuardrailCheck,
  input: DetectorInput,
  deadline: number,
): Promise<CheckEvaluation> {
  if (!check.enabled) {
    return { checkId: check.id, outcome: "disabled", findingCount: 0, errored: false };
  }
  try {
    const result = await check.detector.evaluate(input, deadline);
    return {
      checkId: check.id,
      outcome: result.verdict === "pass" ? "pass" : "fail",
      findingCount: result.findings.length,
      errored: false,
    };
  } catch {
    if (check.fallbackDetector !== undefined) {
      try {
        const result = await check.fallbackDetector.evaluate(input, deadline);
        return {
          checkId: check.id,
          outcome: result.verdict === "pass" ? "pass" : "fail",
          findingCount: result.findings.length,
          errored: true,
        };
      } catch {
        // The fallback ALSO failed: the outcome is `error`, so `on_error`
        // (default block) decides. Never a pass.
      }
    }
    return { checkId: check.id, outcome: "error", findingCount: 0, errored: true };
  }
}
